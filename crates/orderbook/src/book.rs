//! The central-limit order book: deterministic price-time matching, O(1)
//! cancellation, atomic cancel-replace, cancel-all, baskets, self-trade
//! prevention, reduce-only clamping, and client idempotency.

use std::collections::{HashMap, HashSet};

use types::{AccountId, Amount, Hash, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

use crate::dedup::DedupCache;
use crate::error::OrderError;
use crate::level::{crosses, SideBook};
use crate::order::{
    BookConfig, Fill, MatchPlan, MatchReport, MatchResult, MatchSummary, NewOrder, Node,
    OrderOutcome, PlannedFill, StpCancellation, StpPolicy,
};
use crate::slab::{Slab, NIL};
use crate::{
    BookStateError, BookStateLimits, BOOK_ROOT_HOT_PATH_HASH_BUDGET_BYTES,
    BOOK_ROOT_SCHEMA_VERSION, BOOK_TRANSITION_ROOT_SCHEMA_VERSION,
};

/// Minimal fixed-width writer for the book's consensus-facing transition
/// commitment. It deliberately does not use serde enum ordinals or `usize`
/// widths, so the preimage is stable across releases and architectures.
#[derive(Default)]
struct TransitionWriter {
    bytes: Vec<u8>,
}

impl TransitionWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn len(&mut self, field: &'static str, value: usize) -> Result<(), BookStateError> {
        let value = u64::try_from(value).map_err(|_| BookStateError::NativeWidth {
            field,
            value: u64::MAX,
        })?;
        self.u64(value);
        Ok(())
    }
}

/// Fixed-width, forward-only reader for canonical book state.
#[derive(Clone, Copy)]
struct StateReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StateReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], BookStateError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if len > remaining {
            return Err(BookStateError::Truncated {
                offset: self.offset,
                needed: len,
                remaining,
            });
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..self.offset])
    }

    fn u8(&mut self) -> Result<u8, BookStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BookStateError> {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> Result<u32, BookStateError> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, BookStateError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn i64(&mut self) -> Result<i64, BookStateError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(i64::from_le_bytes(raw))
    }

    fn finish(self) -> Result<(), BookStateError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(BookStateError::TrailingBytes { remaining })
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StateShape {
    levels: usize,
    orders: usize,
    positions: usize,
    dedup_records: usize,
    fills: usize,
}

impl StateShape {
    /// Exact v3 size: fixed fields plus fixed-width repeated records.
    fn encoded_len(self) -> Result<usize, BookStateError> {
        let mut len = 59usize;
        for (field, count, width) in [
            ("price levels", self.levels, 16usize),
            ("resting orders", self.orders, 37),
            ("positions", self.positions, 12),
            ("dedup records", self.dedup_records, 29),
            ("cached fills", self.fills, 41),
        ] {
            let bytes = count
                .checked_mul(width)
                .ok_or(BookStateError::ArithmeticOverflow { field })?;
            len = len
                .checked_add(bytes)
                .ok_or(BookStateError::ArithmeticOverflow { field })?;
        }
        Ok(len)
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodedHeader {
    capacity: usize,
    stp: StpPolicy,
    dedup_capacity: usize,
    max_basket_legs: usize,
}

#[derive(Debug, Clone, Copy)]
struct ScannedState {
    header: DecodedHeader,
    shape: StateShape,
}

/// Fixed-stack aggregation state for the independent arithmetic portion of an
/// ordered match scan. Traversal and STP decisions feed this in exact FIFO
/// order; only a full block of already-decided price/quantity pairs is sent to
/// the SIMD crate.
struct SummaryBatch {
    backend: simd::Backend,
    taker_side: Side,
    prices: [i64; simd::MATCH_BATCH_LANES],
    quantities: [i64; simd::MATCH_BATCH_LANES],
    notionals: [simd::MatchNotional; simd::MATCH_BATCH_LANES],
    len: usize,
    filled: Quantity,
    worst: Option<Price>,
    notional: Amount,
    notional_ceil: Amount,
}

impl SummaryBatch {
    fn new(backend: simd::Backend, taker_side: Side) -> Self {
        Self {
            backend,
            taker_side,
            prices: [0; simd::MATCH_BATCH_LANES],
            quantities: [0; simd::MATCH_BATCH_LANES],
            notionals: [simd::MatchNotional::default(); simd::MATCH_BATCH_LANES],
            len: 0,
            filled: Quantity::ZERO,
            worst: None,
            notional: Amount::ZERO,
            notional_ceil: Amount::ZERO,
        }
    }

    fn push(&mut self, price: Price, quantity: Quantity) -> Result<(), OrderError> {
        self.prices[self.len] = price.raw();
        self.quantities[self.len] = quantity.raw();
        self.len += 1;
        if self.len == simd::MATCH_BATCH_LANES {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), OrderError> {
        if self.len == 0 {
            return Ok(());
        }
        let converted = simd::matching_notionals(
            self.backend,
            &self.prices[..self.len],
            &self.quantities[..self.len],
            &mut self.notionals[..self.len],
        );
        debug_assert!(converted, "fixed matching batch slices have equal lengths");
        if !converted {
            return Err(OrderError::Overflow);
        }
        for lane in 0..self.len {
            let price = Price::from_raw(self.prices[lane]);
            let quantity = Quantity::from_raw(self.quantities[lane]);
            self.filled = self.filled.saturating_add(quantity);
            self.notional = self
                .notional
                .checked_add(self.notionals[lane].notional)
                .map_err(|_| OrderError::Overflow)?;
            self.notional_ceil = self
                .notional_ceil
                .checked_add(self.notionals[lane].notional_ceil)
                .map_err(|_| OrderError::Overflow)?;
            self.worst = Some(match self.worst {
                None => price,
                Some(worst) => match self.taker_side {
                    Side::Bid if price.raw() > worst.raw() => price,
                    Side::Ask if price.raw() < worst.raw() => price,
                    _ => worst,
                },
            });
        }
        self.len = 0;
        Ok(())
    }

    fn finish(mut self) -> Result<MatchSummary, OrderError> {
        self.flush()?;
        Ok(MatchSummary {
            filled_quantity: self.filled,
            worst_price: self.worst,
            notional: self.notional,
            notional_ceil: self.notional_ceil,
        })
    }
}

/// Where a resting order lives, for O(1) lookup on cancel / replace.
#[derive(Debug, Clone, Copy)]
struct Locator {
    slot: u32,
    side: Side,
    account: AccountId,
}

/// A deterministic native central-limit order book.
///
/// Matching is strict price-time priority: the best price matches first and,
/// within a price, the oldest resting order matches first (FIFO). Given an
/// identical stream of commands the book reaches an identical state, committed
/// via [`OrderBook::transition_root_v3`].
///
/// [`Clone`] yields a bit-identical, independent book. Baskets use it to
/// snapshot before speculatively applying legs so a mid-basket failure can be
/// rolled back to the exact pre-command state. The clone re-reserves every
/// eagerly-sized container (slab, id index, dedup cache) back to its configured
/// capacity, so cloned books keep the warm-path no-allocation guarantee.
pub struct OrderBook {
    config: BookConfig,
    slab: Slab<Node>,
    bids: SideBook,
    asks: SideBook,
    id_index: HashMap<OrderId, Locator>,
    // Sorted per-account ids make cancel-all proportional to that account's
    // orders while retaining vector capacity across the steady-state path.
    account_orders: HashMap<AccountId, Vec<OrderId>>,
    positions: HashMap<AccountId, Quantity>,
    dedup: DedupCache,
    /// Running XOR of every resting order-leaf digest (pre-finalize aggregate).
    /// Updated only for touched orders so the hot path never rehashes the book.
    order_leaf_xor: [u8; 32],
}

impl Clone for OrderBook {
    fn clone(&self) -> Self {
        // `HashMap::clone` sizes the new table for the current entries only,
        // discarding the eager `with_capacity(config.capacity)` reservation
        // made in [`OrderBook::new`]. Restore it after cloning so warm-path
        // inserts on a cloned book (basket snapshot restore, the engine's
        // per-command transaction copy) never reallocate. Capacity is not part
        // of logical state, so the clone stays bit-identical in behavior.
        let mut id_index = self.id_index.clone();
        id_index.reserve(self.config.capacity.saturating_sub(id_index.len()));
        OrderBook {
            config: self.config,
            slab: self.slab.clone(),
            bids: self.bids.clone(),
            asks: self.asks.clone(),
            id_index,
            account_orders: self.account_orders.clone(),
            positions: self.positions.clone(),
            dedup: self.dedup.clone(),
            order_leaf_xor: self.order_leaf_xor,
        }
    }
}

impl OrderBook {
    /// Create an empty book with the given configuration.
    #[must_use]
    pub fn new(config: BookConfig) -> Self {
        OrderBook {
            slab: Slab::with_capacity(config.capacity),
            bids: SideBook::new(Side::Bid),
            asks: SideBook::new(Side::Ask),
            id_index: HashMap::with_capacity(config.capacity),
            account_orders: HashMap::new(),
            positions: HashMap::new(),
            dedup: DedupCache::with_capacity(config.dedup_capacity),
            order_leaf_xor: [0u8; 32],
            config,
        }
    }

    /// Documented hot-path hash budget (bytes) for a single no-fill insert or
    /// cancel. Exposed for tests and operators; see crate-level constant.
    #[must_use]
    pub const fn hot_path_hash_budget_bytes() -> usize {
        BOOK_ROOT_HOT_PATH_HASH_BUDGET_BYTES
    }

    /// Best (highest) resting bid price, if any.
    #[must_use]
    pub fn best_bid(&self) -> Option<Price> {
        self.bids.best_price()
    }

    /// Best (lowest) resting ask price, if any.
    #[must_use]
    pub fn best_ask(&self) -> Option<Price> {
        self.asks.best_price()
    }

    /// Number of orders currently resting on the book.
    #[must_use]
    pub fn resting_len(&self) -> usize {
        self.slab.len()
    }

    /// Whether an order with `id` is currently resting.
    #[must_use]
    pub fn contains(&self, id: OrderId) -> bool {
        self.id_index.contains_key(&id)
    }

    /// Whether a plain GTC limit can be inserted without matching or failing.
    ///
    /// This is a non-mutating preflight for the execution engine's common
    /// transaction fast path. The caller still submits normally; this method
    /// merely proves that any subsequent book delta is exactly one resting
    /// insertion, which can be undone by cancelling that id if a later
    /// subsystem commit fails.
    pub fn can_rest_without_match(&self, order: &NewOrder) -> Result<bool, OrderError> {
        if order.quantity.raw() <= 0 {
            return Err(OrderError::NonPositiveQuantity);
        }
        if order.price.raw() <= 0 {
            return Err(OrderError::NonPositivePrice);
        }
        if self.id_index.contains_key(&order.order_id) {
            return Err(OrderError::DuplicateOrderId);
        }
        if self.slab.is_full() {
            return Err(OrderError::CapacityExhausted);
        }
        let current = match order.side {
            Side::Bid => self.bids.level_total(order.price),
            Side::Ask => self.asks.level_total(order.price),
        };
        current
            .checked_add(order.quantity)
            .map_err(|_| OrderError::Overflow)?;
        Ok(!self.would_cross(order.side, order.price))
    }

    /// The account that owns the resting order `id`, if it is resting. Used by
    /// the engine to enforce that a cancel/replace targets the caller's own
    /// order.
    #[must_use]
    pub fn owner(&self, id: OrderId) -> Option<AccountId> {
        self.id_index.get(&id).map(|loc| loc.account)
    }

    /// Immutable logical fields of resting order `id`, if it is present.
    ///
    /// The returned view excludes slab links and derived indexes, so callers
    /// can reconcile external sidecars without depending on representation
    /// details or changing canonical book state.
    #[must_use]
    pub fn resting_order(&self, id: OrderId) -> Option<crate::RestingOrder> {
        let locator = self.id_index.get(&id)?;
        let node = self.slab.get(locator.slot)?;
        Some(crate::RestingOrder {
            order_id: node.order_id,
            account: node.account,
            side: node.side,
            price: node.price,
            remaining: node.remaining,
        })
    }

    /// Snapshot every resting order in ascending order-id order.
    ///
    /// This cold-path view is intended for recovery validation and coordinated
    /// external-sidecar drains. Reading it does not mutate or re-encode book
    /// state, and the returned order is independent of hash-table layout.
    #[must_use]
    pub fn resting_orders(&self) -> Vec<crate::RestingOrder> {
        let mut ids: Vec<OrderId> = self.id_index.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter()
            .filter_map(|id| self.resting_order(id))
            .collect()
    }

    /// The stubbed net position for `account` (positive long, negative short).
    /// Position tracking is external; the book consults this only for
    /// reduce-only handling.
    #[must_use]
    pub fn position(&self, account: AccountId) -> Quantity {
        self.positions
            .get(&account)
            .copied()
            .unwrap_or(Quantity::ZERO)
    }

    /// Set the stubbed net position for `account`, used by reduce-only orders.
    pub fn set_position(&mut self, account: AccountId, position: Quantity) {
        self.positions.insert(account, position);
    }

    /// Submit a new order.
    ///
    /// Duplicate submissions (same `account` + `client_id` within the dedup
    /// window) execute **exactly once**; the second and later calls replay the
    /// first result without touching the book.
    ///
    /// This book-local dedup is a convenience for callers that drive the book
    /// directly. Command-level callers that already enforce durable, payload-
    /// bound, exactly-once semantics (the execution engine) submit through
    /// [`OrderBook::place`] or [`OrderBook::place_with_report`] instead, so
    /// idempotency is decided once at the command layer rather than replayed a
    /// second time here.
    pub fn submit(&mut self, order: NewOrder) -> Result<MatchResult, OrderError> {
        if let Some(cached) = self.dedup.get(order.account, order.client_id) {
            return Ok(cached.clone());
        }
        let result = self.execute(order)?;
        self.dedup
            .insert(order.account, order.client_id, result.clone());
        Ok(result)
    }

    /// Submit a new order **without** book-local client deduplication.
    ///
    /// Idempotency for engine-sequenced commands is enforced exactly once, and
    /// durably, at the command layer (see `execution::Engine`), which binds the
    /// idempotency key to the full command digest and commits a replay watermark
    /// into the state root. Engine integrations use this non-deduplicating path
    /// (or [`OrderBook::place_with_report`]) so the book never applies a second,
    /// weaker dedup that could replay stale fills.
    pub fn place(&mut self, order: NewOrder) -> Result<MatchResult, OrderError> {
        Ok(self.place_with_report(order)?.result)
    }

    /// Submit a new order without book-local client deduplication and include
    /// transient maker cancellations performed by self-trade prevention.
    ///
    /// The report is not retained in deduplication state and does not alter the
    /// canonical v3 book schema or transition root.
    pub fn place_with_report(&mut self, order: NewOrder) -> Result<MatchReport, OrderError> {
        self.execute_with_report(order)
    }

    /// Cancel a resting order in O(1). Errors if the id is unknown.
    pub fn cancel(&mut self, id: OrderId) -> Result<(), OrderError> {
        let loc = self
            .id_index
            .get(&id)
            .copied()
            .ok_or(OrderError::UnknownOrder)?;
        self.remove_resting(loc.side, loc.slot);
        Ok(())
    }

    /// Cancel every resting order owned by `account`, returning the count.
    /// Cancellation order is deterministic (ascending order id).
    pub fn cancel_all(&mut self, account: AccountId) -> u32 {
        let targets: Vec<OrderId> = self
            .account_orders
            .get(&account)
            .map_or_else(Vec::new, Vec::clone);
        for id in &targets {
            if let Some(loc) = self.id_index.get(id).copied() {
                self.remove_resting(loc.side, loc.slot);
            }
        }
        u32::try_from(targets.len()).unwrap_or(u32::MAX)
    }

    /// Atomically cancel `id` and resubmit it as a fresh GTC limit at
    /// `(price, quantity)`.
    ///
    /// If the replacement fails validation the book is left **bit-identical** to
    /// its pre-command state: structural checks run before the original is
    /// removed, so a rejected replace never mutates the book.
    pub fn replace(
        &mut self,
        id: OrderId,
        price: Price,
        quantity: Quantity,
    ) -> Result<MatchResult, OrderError> {
        Ok(self.replace_with_report(id, price, quantity)?.result)
    }

    /// Replace a resting order and include transient maker cancellations
    /// performed by self-trade prevention while matching the replacement.
    pub fn replace_with_report(
        &mut self,
        id: OrderId,
        price: Price,
        quantity: Quantity,
    ) -> Result<MatchReport, OrderError> {
        if quantity.raw() <= 0 {
            return Err(OrderError::NonPositiveQuantity);
        }
        if price.raw() <= 0 {
            return Err(OrderError::NonPositivePrice);
        }
        let loc = self
            .id_index
            .get(&id)
            .copied()
            .ok_or(OrderError::UnknownOrder)?;
        let node = *self.slab.get(loc.slot).ok_or(OrderError::UnknownOrder)?;
        // A non-crossing replacement rests in full, so aggregate overflow is
        // the only reachable error after removing the original. Check the
        // exact post-removal level total while every index and FIFO link is
        // still untouched. Crossing replacements deliberately skip this
        // full-quantity check: fills or STP may reduce/cancel their residual,
        // and `execute_with_report` already returns those applied mutations as
        // a successful result rather than surfacing a later resting error.
        if !self.would_cross(node.side, price) {
            let book = match node.side {
                Side::Bid => &self.bids,
                Side::Ask => &self.asks,
            };
            let level_total = if node.price == price {
                book.level_total(price)
                    .checked_sub(node.remaining)
                    .map_err(|_| OrderError::Overflow)?
            } else {
                book.level_total(price)
            };
            level_total
                .checked_add(quantity)
                .map_err(|_| OrderError::Overflow)?;
        }
        // Removing the original first frees a slot, so the resubmission can never
        // exhaust capacity (net slot delta is <= 0).
        self.remove_resting(loc.side, loc.slot);
        let replacement = NewOrder {
            order_id: id,
            account: node.account,
            side: node.side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price,
            quantity,
            client_id: node.client_id,
            reduce_only: false,
        };
        self.execute_with_report(replacement)
    }

    /// Submit a basket as a single all-or-nothing unit.
    ///
    /// Structural validation runs first (size, per-leg price/quantity, duplicate
    /// ids); a failure there rejects the basket before touching the book. The
    /// legs are then applied speculatively in order. Because matching a leg
    /// mutates the book irreversibly — consuming makers and resting residuals —
    /// validation alone cannot guarantee atomicity once a later leg fails (for
    /// example on [`OrderError::CapacityExhausted`]). The book is therefore
    /// snapshotted up front and, if any leg errors, restored to that snapshot so
    /// the whole basket rolls back to a **bit-identical** pre-command state. On
    /// success no earlier leg is ever partially applied.
    pub fn submit_basket(&mut self, legs: &[NewOrder]) -> Result<Vec<MatchResult>, OrderError> {
        if legs.len() > self.config.max_basket_legs {
            return Err(OrderError::BasketTooLarge);
        }
        let mut seen: HashMap<OrderId, ()> = HashMap::with_capacity(legs.len());
        for leg in legs {
            if leg.quantity.raw() <= 0 {
                return Err(OrderError::NonPositiveQuantity);
            }
            let is_market = matches!(leg.order_type, OrderType::Market);
            if !is_market && leg.price.raw() <= 0 {
                return Err(OrderError::NonPositivePrice);
            }
            if seen.insert(leg.order_id, ()).is_some() {
                return Err(OrderError::BasketDuplicateId);
            }
            if self.id_index.contains_key(&leg.order_id) {
                return Err(OrderError::DuplicateOrderId);
            }
        }
        // Speculative apply + rollback. Snapshot before any leg runs; on the
        // first leg error, restore the snapshot (undoing earlier legs' fills and
        // rests) and surface the error, leaving the book untouched.
        let snapshot = self.clone();
        let mut out = Vec::with_capacity(legs.len());
        for leg in legs {
            match self.submit(*leg) {
                Ok(res) => out.push(res),
                Err(e) => {
                    *self = snapshot;
                    return Err(e);
                }
            }
        }
        Ok(out)
    }

    /// Incremental unordered diagnostic over all resting orders.
    ///
    /// Schema v2: each resting order contributes a domain-separated leaf over
    /// `(order_id, account, side, price, remaining, client_id)`. The book
    /// aggregate is the XOR of every leaf, finalized under
    /// [`crypto::DOMAIN_EXECUTION`] with a schema-version prefix. Insert, cancel,
    /// and partial-fill paths update only the touched leaf (constant bytes
    /// hashed — see [`Self::hot_path_hash_budget_bytes`]), never the full book.
    ///
    /// Bit-identical to [`Self::state_root_full_rebuild`] for every reachable
    /// state; the full rebuild is retained as a differential oracle in tests.
    /// This v2 XOR aggregate deliberately stays available for the documented
    /// hot-path budget, but it does not bind FIFO priority and is not an
    /// authoritative state-machine commitment. Use [`Self::transition_root_v3`]
    /// anywhere a root may be certified or persisted as state.
    #[must_use]
    pub fn state_root(&self) -> Hash {
        Self::finalize_root(&self.order_leaf_xor)
    }

    /// Full rebuild of the unordered v2 diagnostic root from every resting
    /// order. Differential oracle for the incremental path — not authoritative.
    #[must_use]
    pub fn state_root_full_rebuild(&self) -> Hash {
        let mut acc = [0u8; 32];
        self.bids.for_each_canonical(&self.slab, |n| {
            Self::xor_in(&mut acc, Self::order_leaf(n));
        });
        self.asks.for_each_canonical(&self.slab, |n| {
            Self::xor_in(&mut acc, Self::order_leaf(n));
        });
        Self::finalize_root(&acc)
    }

    /// Canonical commitment to every stored value that can change a future
    /// [`OrderBook`] result: logical configuration, price levels, exact FIFO
    /// priority, externally supplied reduce-only positions, and the dedup
    /// cache's eviction-ordered results.
    ///
    /// Schema v3 is correctness-first and performs a full ordered scan. It is
    /// intentionally separate from the O(1) v2 diagnostic until an incremental
    /// authenticated ordered structure can reproduce these bytes without
    /// weakening the transition commitment. The scan also recomputes and
    /// validates the stored v2 XOR cache because that cache feeds legacy market
    /// leaves after future mutations.
    #[must_use]
    pub fn transition_root_v3(&self) -> Hash {
        let bytes = self
            .encode_state_v3_bounded(usize::MAX)
            .expect("reachable OrderBook state must have an encodable v3 image");
        crypto::hash_domain(crypto::DOMAIN_ORDERBOOK_STATE, &bytes)
    }

    /// Encode the canonical, versioned OrderBook state used verbatim as the
    /// [`Self::transition_root_v3`] preimage.
    ///
    /// The exact encoded size is checked before allocating the output buffer.
    /// Runtime-only [`crate::MatchingBackend`] selection and representation
    /// details such as slab slots, free-list order, intrusive links, hash-table
    /// layout, and derived indexes are intentionally absent.
    pub fn encode_state_v3_bounded(&self, max_bytes: usize) -> Result<Vec<u8>, BookStateError> {
        let shape = self.state_shape_v3()?;
        let encoded_len = shape.encoded_len()?;
        if encoded_len > max_bytes {
            return Err(BookStateError::EncodedBytesLimit {
                actual: encoded_len,
                max: max_bytes,
            });
        }
        let mut writer = TransitionWriter::with_capacity(encoded_len);
        self.write_state_v3(&mut writer)?;
        if writer.bytes.len() != encoded_len {
            return Err(BookStateError::InvalidValue {
                field: "v3 state size preflight must equal the emitted fixed-width image",
            });
        }
        Ok(writer.bytes)
    }

    /// Decode and directly restore canonical OrderBook v3 state under
    /// independent resource limits.
    ///
    /// The input is scanned once without allocating to validate every declared
    /// count (including cumulative cached fills), exact fixed-width length, and
    /// basic semantics. A second pass constructs live nodes directly and
    /// rebuilds all derived indexes, links, and the v2 XOR cache; it never calls
    /// [`Self::place`], [`Self::submit`], or the matching path. Finally the
    /// rebuilt state must re-encode byte-identically and preserve the input's
    /// authoritative v3 root.
    ///
    /// This codec establishes canonical representation and bounded semantic
    /// validity only. Callers must obtain `bytes` and any expected root from an
    /// authenticated, freshness-protected checkpoint or manifest.
    pub fn decode_state_v3_bounded(
        bytes: &[u8],
        limits: &BookStateLimits,
        matching_backend: crate::MatchingBackend,
    ) -> Result<Self, BookStateError> {
        let scanned = Self::scan_state_v3(bytes, limits)?;
        let expected_len = scanned.shape.encoded_len()?;
        if expected_len != bytes.len() {
            return Err(if expected_len < bytes.len() {
                BookStateError::TrailingBytes {
                    remaining: bytes.len() - expected_len,
                }
            } else {
                BookStateError::Truncated {
                    offset: bytes.len(),
                    needed: expected_len - bytes.len(),
                    remaining: 0,
                }
            });
        }
        let rebuilt = Self::restore_state_v3(bytes, scanned, matching_backend)?;
        let canonical = rebuilt.encode_state_v3_bounded(limits.max_encoded_bytes)?;
        if canonical != bytes {
            return Err(BookStateError::CanonicalEncodingMismatch);
        }
        let expected_root = crypto::hash_domain(crypto::DOMAIN_ORDERBOOK_STATE, bytes);
        let rebuilt_root = crypto::hash_domain(crypto::DOMAIN_ORDERBOOK_STATE, &canonical);
        if rebuilt_root != expected_root {
            return Err(BookStateError::RootMismatch);
        }
        Ok(rebuilt)
    }

    /// Validate all transition-relevant and mutation-relevant OrderBook state.
    ///
    /// This cold-path check is total over corrupt in-memory representations:
    /// intrusive and free-list walks are explicitly bounded and every failure
    /// is returned as a typed [`BookStateError`]. It deliberately does not call
    /// canonical iterators, transition-root helpers, or other fail-stop APIs.
    pub fn validate_transition_invariants(&self) -> Result<(), BookStateError> {
        let shape = self.state_shape_v3()?;
        self.validate_book_graph(None)?;
        let validated_fills = self.validate_dedup_results(None)?;
        if validated_fills != shape.fills {
            return Err(BookStateError::InvalidValue {
                field: "validated cached-fill count must match the v3 shape preflight",
            });
        }
        Ok(())
    }

    fn state_shape_v3(&self) -> Result<StateShape, BookStateError> {
        let capacity = Self::usize_as_u64("capacity", self.config.capacity)?;
        if capacity > u64::from(u32::MAX) {
            return Err(BookStateError::NativeWidth {
                field: "slab capacity",
                value: capacity,
            });
        }
        self.slab.validate_representation(self.config.capacity)?;
        self.dedup
            .validate_representation(self.config.dedup_capacity)?;
        Self::usize_as_u64("dedup capacity", self.config.dedup_capacity)?;
        Self::usize_as_u64("basket legs", self.config.max_basket_legs)?;
        let levels = self
            .bids
            .level_count()
            .checked_add(self.asks.level_count())
            .ok_or(BookStateError::ArithmeticOverflow {
                field: "price levels",
            })?;
        let mut fills = 0usize;
        self.dedup.try_for_each_in_eviction_order(|_, _, result| {
            fills = fills.checked_add(result.fills.len()).ok_or(
                BookStateError::ArithmeticOverflow {
                    field: "cached fills",
                },
            )?;
            Ok(())
        })?;

        for (field, value) in [
            ("price levels", levels),
            ("resting orders", self.slab.len()),
            ("positions", self.positions.len()),
            ("dedup records", self.dedup.record_count()),
            ("cached fills", fills),
        ] {
            Self::usize_as_u64(field, value)?;
        }
        let shape = StateShape {
            levels,
            orders: self.slab.len(),
            positions: self.positions.len(),
            dedup_records: self.dedup.record_count(),
            fills,
        };
        let _ = shape.encoded_len()?;
        Ok(shape)
    }

    fn validate_book_graph(
        &self,
        writer: Option<&mut TransitionWriter>,
    ) -> Result<(), BookStateError> {
        let writer = std::cell::RefCell::new(writer);
        let mut reachable_slots = HashSet::with_capacity(self.slab.len());
        let mut reachable_ids = HashSet::with_capacity(self.slab.len());
        let mut expected_accounts: HashMap<AccountId, Vec<OrderId>> = HashMap::new();
        let mut recomputed_order_leaf_xor = [0u8; 32];

        let mut visit_level = |price: Price, count: u32| -> Result<(), BookStateError> {
            if let Some(writer) = writer.borrow_mut().as_deref_mut() {
                writer.i64(price.raw());
                writer.u64(u64::from(count));
            }
            Ok(())
        };
        let mut visit_node = |slot: u32, node: &Node| -> Result<(), BookStateError> {
            if !reachable_slots.insert(slot) {
                return Err(BookStateError::InvalidValue {
                    field: "live slab node must be reachable from exactly one price level",
                });
            }
            if !reachable_ids.insert(node.order_id) {
                return Err(BookStateError::NonCanonical {
                    field: "resting order ids must be globally unique",
                });
            }
            let locator =
                self.id_index
                    .get(&node.order_id)
                    .ok_or(BookStateError::InvalidValue {
                        field: "live node must have an order-id locator",
                    })?;
            if locator.slot != slot {
                return Err(BookStateError::InvalidValue {
                    field: "order-id locator points to wrong slot",
                });
            }
            if locator.side != node.side {
                return Err(BookStateError::InvalidValue {
                    field: "order-id locator side mismatch",
                });
            }
            if locator.account != node.account {
                return Err(BookStateError::InvalidValue {
                    field: "order-id locator account mismatch",
                });
            }
            expected_accounts
                .entry(node.account)
                .or_default()
                .push(node.order_id);
            Self::xor_in(&mut recomputed_order_leaf_xor, Self::order_leaf(node));
            if let Some(writer) = writer.borrow_mut().as_deref_mut() {
                writer.u64(node.order_id.get());
                writer.u32(node.account.get());
                writer.u8(Self::side_tag(node.side));
                writer.i64(node.price.raw());
                writer.i64(node.remaining.raw());
                writer.u64(node.client_id);
            }
            Ok(())
        };

        if let Some(writer) = writer.borrow_mut().as_deref_mut() {
            writer.len("bid price levels", self.bids.level_count())?;
        }
        let bid_orders = self.bids.validate_reachable(
            &self.slab,
            Side::Bid,
            &mut visit_level,
            &mut visit_node,
        )?;
        if let Some(writer) = writer.borrow_mut().as_deref_mut() {
            writer.len("ask price levels", self.asks.level_count())?;
        }
        let ask_orders = self.asks.validate_reachable(
            &self.slab,
            Side::Ask,
            &mut visit_level,
            &mut visit_node,
        )?;
        let reachable_count =
            bid_orders
                .checked_add(ask_orders)
                .ok_or(BookStateError::ArithmeticOverflow {
                    field: "resting orders",
                })?;
        if reachable_count != self.slab.len() {
            return Err(BookStateError::InvalidValue {
                field: "every live slab node must be reachable from exactly one price level",
            });
        }
        self.slab.try_for_each_occupied(|slot, _| {
            if reachable_slots.contains(&slot) {
                Ok(())
            } else {
                Err(BookStateError::InvalidValue {
                    field: "occupied slab node is unreachable from the price-level graph",
                })
            }
        })?;
        if self
            .bids
            .best_price()
            .zip(self.asks.best_price())
            .is_some_and(|(bid, ask)| bid.raw() >= ask.raw())
        {
            return Err(BookStateError::InvalidValue {
                field: "resting bid and ask books must not be crossed or locked",
            });
        }
        if self.id_index.len() != self.slab.len() {
            return Err(BookStateError::InvalidValue {
                field: "order-id index must cover every live slab node exactly once",
            });
        }
        for (order_id, locator) in &self.id_index {
            let node = self
                .slab
                .get(locator.slot)
                .ok_or(BookStateError::InvalidValue {
                    field: "order-id locator must reference a live slab node",
                })?;
            if node.order_id != *order_id {
                return Err(BookStateError::InvalidValue {
                    field: "order-id locator key does not match its slab node",
                });
            }
            if node.side != locator.side || node.account != locator.account {
                return Err(BookStateError::InvalidValue {
                    field: "order-id locator metadata does not match its slab node",
                });
            }
        }
        for orders in expected_accounts.values_mut() {
            orders.sort_unstable();
        }
        let mut mirrored_orders = 0usize;
        for (account, orders) in &self.account_orders {
            if orders.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(BookStateError::NonCanonical {
                    field: "account-order ids must be strictly ascending and unique",
                });
            }
            let expected = expected_accounts
                .get(account)
                .map_or(&[][..], Vec::as_slice);
            if orders.as_slice() != expected {
                return Err(BookStateError::InvalidValue {
                    field: "account-order index must exactly mirror live owned orders",
                });
            }
            mirrored_orders = mirrored_orders.checked_add(orders.len()).ok_or(
                BookStateError::ArithmeticOverflow {
                    field: "account-order index",
                },
            )?;
        }
        for (account, expected) in &expected_accounts {
            if self.account_orders.get(account).map(Vec::as_slice) != Some(expected.as_slice()) {
                return Err(BookStateError::InvalidValue {
                    field: "live node must appear in its account-order index",
                });
            }
        }
        if mirrored_orders != self.slab.len() {
            return Err(BookStateError::InvalidValue {
                field: "account-order index must cover every live slab node exactly once",
            });
        }
        if recomputed_order_leaf_xor != self.order_leaf_xor {
            return Err(BookStateError::InvalidValue {
                field: "incremental order-leaf XOR must match the canonical live-order scan",
            });
        }
        Ok(())
    }

    fn validate_dedup_results(
        &self,
        writer: Option<&mut TransitionWriter>,
    ) -> Result<usize, BookStateError> {
        let writer = std::cell::RefCell::new(writer);
        if let Some(writer) = writer.borrow_mut().as_deref_mut() {
            writer.len("dedup records", self.dedup.record_count())?;
        }
        let mut fills = 0usize;
        self.dedup
            .try_for_each_in_eviction_order(|account, client_id, result| {
                Self::validate_cached_match_result(account, result)?;
                fills = fills.checked_add(result.fills.len()).ok_or(
                    BookStateError::ArithmeticOverflow {
                        field: "cached fills",
                    },
                )?;
                if let Some(writer) = writer.borrow_mut().as_deref_mut() {
                    writer.u32(account);
                    writer.u64(client_id);
                    Self::write_match_result(writer, result)?;
                }
                Ok(())
            })?;
        Ok(fills)
    }

    fn write_state_v3(&self, writer: &mut TransitionWriter) -> Result<(), BookStateError> {
        writer.u16(BOOK_TRANSITION_ROOT_SCHEMA_VERSION);
        writer.len("capacity", self.config.capacity)?;
        writer.u8(Self::stp_tag(self.config.stp));
        writer.len("dedup capacity", self.config.dedup_capacity)?;
        writer.len("basket legs", self.config.max_basket_legs)?;

        self.validate_book_graph(Some(writer))?;

        let mut positions: Vec<(u32, i64)> = self
            .positions
            .iter()
            .map(|(account, quantity)| (account.get(), quantity.raw()))
            .collect();
        positions.sort_unstable();
        writer.len("positions", positions.len())?;
        for (account, quantity) in positions {
            writer.u32(account);
            writer.i64(quantity);
        }

        let _ = self.validate_dedup_results(Some(writer))?;
        Ok(())
    }

    /// Deterministic dry-run of matching `order` against current depth.
    ///
    /// Does not mutate the book. Honors STP, price collars (including market
    /// protection prices), and the requested quantity. Used by pre-trade risk
    /// so market-order margin is derived from executable depth.
    pub fn plan_match(&self, order: &NewOrder) -> Result<MatchPlan, OrderError> {
        let mut fills = Vec::new();
        let summary = self.scan_match(order, |fill| {
            fills.push(fill);
            Ok(())
        })?;
        Ok(MatchPlan {
            fills,
            filled_quantity: summary.filled_quantity,
            worst_price: summary.worst_price,
            notional: summary.notional,
            notional_ceil: summary.notional_ceil,
        })
    }

    /// Allocation-free aggregate dry-run of matching `order` against depth.
    ///
    /// Matching order, collars, STP boundaries, rounding, and overflow errors
    /// are identical to [`Self::plan_match`]. The difference is ownership: no
    /// per-maker records are retained, so pre-trade risk can scan depth in one
    /// pass with no temporary price or fill vectors. On a vector-capable host,
    /// blocks of already-ordered fixed-point products use the configured SIMD
    /// backend; FIFO traversal, quantity clamps, STP, rounding, checked
    /// accumulation, and mutation remain scalar.
    pub fn plan_match_summary(&self, order: &NewOrder) -> Result<MatchSummary, OrderError> {
        self.plan_match_summary_with_backend(order, self.config.matching_backend)
    }

    /// Explicit-backend counterpart to [`Self::plan_match_summary`].
    ///
    /// Intended for paired qualification and deterministic differential tests.
    /// An unavailable backend safely executes the scalar arithmetic reference;
    /// operator forcing remains fail-closed through [`simd::Backend::force`].
    pub fn plan_match_summary_with_backend(
        &self,
        order: &NewOrder,
        backend: simd::Backend,
    ) -> Result<MatchSummary, OrderError> {
        if matches!(backend, simd::Backend::Scalar) {
            self.scan_match(order, |_| Ok(()))
        } else {
            self.scan_match_summary_batched(order, backend)
        }
    }

    fn scan_match_summary_batched(
        &self,
        order: &NewOrder,
        backend: simd::Backend,
    ) -> Result<MatchSummary, OrderError> {
        if order.quantity.raw() <= 0 {
            return Err(OrderError::NonPositiveQuantity);
        }
        let is_market = matches!(order.order_type, OrderType::Market);
        if !is_market && order.price.raw() <= 0 {
            return Err(OrderError::NonPositivePrice);
        }

        let mut remaining = order.quantity.raw();
        let mut batch = SummaryBatch::new(backend, order.side);
        let mut scan_error = None;
        let maker_side = order.side.opposite();
        let book = match maker_side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        };

        book.for_each_level_best_first(|price, head| {
            if remaining <= 0 || !crosses(order.side, is_market, order.price, price) {
                return false;
            }
            let mut cur = head;
            while cur != crate::slab::NIL && remaining > 0 {
                let maker = match self.slab.get(cur) {
                    Some(node) => *node,
                    None => return false,
                };
                if maker.account == order.account {
                    match self.config.stp {
                        StpPolicy::CancelMaker => {
                            cur = maker.next;
                            continue;
                        }
                        StpPolicy::CancelTaker | StpPolicy::CancelBoth => return false,
                    }
                }
                let fill_qty = remaining.min(maker.remaining.raw());
                if let Err(error) = batch.push(price, Quantity::from_raw(fill_qty)) {
                    scan_error = Some(error);
                    return false;
                }
                remaining = remaining.saturating_sub(fill_qty);
                cur = maker.next;
            }
            remaining > 0
        });
        if let Some(error) = scan_error {
            return Err(error);
        }
        batch.finish()
    }

    fn scan_match<F>(&self, order: &NewOrder, mut on_fill: F) -> Result<MatchSummary, OrderError>
    where
        F: FnMut(PlannedFill) -> Result<(), OrderError>,
    {
        if order.quantity.raw() <= 0 {
            return Err(OrderError::NonPositiveQuantity);
        }
        let is_market = matches!(order.order_type, OrderType::Market);
        if !is_market && order.price.raw() <= 0 {
            return Err(OrderError::NonPositivePrice);
        }
        let mut remaining = order.quantity.raw();
        let mut notional = Amount::ZERO;
        let mut notional_ceil = Amount::ZERO;
        let mut filled = Quantity::ZERO;
        let mut worst: Option<Price> = None;
        let mut scan_error = None;
        let maker_side = order.side.opposite();
        let book = match maker_side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        };

        book.for_each_level_best_first(|price, head| {
            if remaining <= 0 {
                return false;
            }
            if !crosses(order.side, is_market, order.price, price) {
                return false;
            }
            let mut cur = head;
            while cur != crate::slab::NIL && remaining > 0 {
                let maker = match self.slab.get(cur) {
                    Some(n) => *n,
                    None => return false,
                };
                if maker.account == order.account {
                    match self.config.stp {
                        StpPolicy::CancelMaker => {
                            cur = maker.next;
                            continue;
                        }
                        StpPolicy::CancelTaker | StpPolicy::CancelBoth => return false,
                    }
                }
                let fill_qty = remaining.min(maker.remaining.raw());
                let planned = PlannedFill {
                    maker_order: maker.order_id,
                    maker_account: maker.account,
                    price: maker.price,
                    quantity: Quantity::from_raw(fill_qty),
                };
                let quantity = planned.quantity;
                let update = (|| {
                    filled = filled.saturating_add(quantity);
                    notional = notional.checked_add(price.notional(quantity)?)?;
                    notional_ceil = notional_ceil.checked_add(price.notional_ceil(quantity)?)?;
                    worst = Some(match worst {
                        None => price,
                        Some(w) => match order.side {
                            Side::Bid if price.raw() > w.raw() => price,
                            Side::Ask if price.raw() < w.raw() => price,
                            _ => w,
                        },
                    });
                    on_fill(planned)
                })();
                if let Err(error) = update {
                    scan_error = Some(error);
                    return false;
                }
                remaining = remaining.saturating_sub(fill_qty);
                cur = maker.next;
            }
            remaining > 0
        });
        if let Some(error) = scan_error {
            return Err(error);
        }
        Ok(MatchSummary {
            filled_quantity: filled,
            worst_price: worst,
            notional,
            notional_ceil,
        })
    }

    /// Total resting quantity across both sides, for tests / introspection.
    #[must_use]
    pub fn total_resting_quantity(&self) -> Quantity {
        self.bids
            .sum_remaining(&self.slab)
            .saturating_add(self.asks.sum_remaining(&self.slab))
    }

    /// Aggregate resting quantity at `(side, price)`, for tests / introspection.
    #[must_use]
    pub fn level_quantity(&self, side: Side, price: Price) -> Quantity {
        let book = match side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        };
        book.level_total(price)
    }

    // ----- internals -------------------------------------------------------

    fn usize_as_u64(field: &'static str, value: usize) -> Result<u64, BookStateError> {
        u64::try_from(value).map_err(|_| BookStateError::NativeWidth {
            field,
            value: u64::MAX,
        })
    }

    fn u64_as_usize(field: &'static str, value: u64) -> Result<usize, BookStateError> {
        usize::try_from(value).map_err(|_| BookStateError::NativeWidth { field, value })
    }

    fn limit_as_u64(limit: usize) -> u64 {
        u64::try_from(limit).unwrap_or(u64::MAX)
    }

    fn check_limit(
        resource: &'static str,
        actual: u64,
        limit: usize,
    ) -> Result<(), BookStateError> {
        let max = Self::limit_as_u64(limit);
        if actual > max {
            Err(BookStateError::ResourceLimit {
                resource,
                actual,
                max,
            })
        } else {
            Ok(())
        }
    }

    fn add_count(
        current: &mut usize,
        amount: u64,
        resource: &'static str,
        limit: usize,
    ) -> Result<usize, BookStateError> {
        let amount = Self::u64_as_usize(resource, amount)?;
        *current = current
            .checked_add(amount)
            .ok_or(BookStateError::ArithmeticOverflow { field: resource })?;
        Self::check_limit(resource, Self::usize_as_u64(resource, *current)?, limit)?;
        Ok(amount)
    }

    fn scan_state_v3(
        bytes: &[u8],
        limits: &BookStateLimits,
    ) -> Result<ScannedState, BookStateError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(BookStateError::EncodedBytesLimit {
                actual: bytes.len(),
                max: limits.max_encoded_bytes,
            });
        }
        let mut reader = StateReader::new(bytes);
        let version = reader.u16()?;
        if version != BOOK_TRANSITION_ROOT_SCHEMA_VERSION {
            return Err(BookStateError::UnsupportedVersion {
                found: version,
                expected: BOOK_TRANSITION_ROOT_SCHEMA_VERSION,
            });
        }

        let capacity_raw = reader.u64()?;
        Self::check_limit("capacity", capacity_raw, limits.max_capacity)?;
        if capacity_raw > u64::from(u32::MAX) {
            return Err(BookStateError::NativeWidth {
                field: "slab capacity",
                value: capacity_raw,
            });
        }
        let capacity = Self::u64_as_usize("capacity", capacity_raw)?;
        let stp = match reader.u8()? {
            0 => StpPolicy::CancelMaker,
            1 => StpPolicy::CancelTaker,
            2 => StpPolicy::CancelBoth,
            value => {
                return Err(BookStateError::InvalidTag {
                    field: "self-trade prevention policy",
                    value,
                })
            }
        };
        let dedup_capacity_raw = reader.u64()?;
        Self::check_limit(
            "dedup capacity",
            dedup_capacity_raw,
            limits.max_dedup_capacity,
        )?;
        let dedup_capacity = Self::u64_as_usize("dedup capacity", dedup_capacity_raw)?;
        let max_basket_legs_raw = reader.u64()?;
        Self::check_limit("basket legs", max_basket_legs_raw, limits.max_basket_legs)?;
        let max_basket_legs = Self::u64_as_usize("basket legs", max_basket_legs_raw)?;

        let mut shape = StateShape::default();
        let (_, best_bid) =
            Self::scan_state_side(&mut reader, Side::Bid, capacity, limits, &mut shape)?;
        let (best_ask, _) =
            Self::scan_state_side(&mut reader, Side::Ask, capacity, limits, &mut shape)?;
        if best_bid
            .zip(best_ask)
            .is_some_and(|(bid, ask)| bid.raw() >= ask.raw())
        {
            return Err(BookStateError::InvalidValue {
                field: "resting bid and ask books must not be crossed or locked",
            });
        }

        let position_count = reader.u64()?;
        let mut positions = 0usize;
        Self::add_count(
            &mut positions,
            position_count,
            "positions",
            limits.max_positions,
        )?;
        shape.positions = positions;
        let mut previous_account = None;
        for _ in 0..shape.positions {
            let account = reader.u32()?;
            if previous_account.is_some_and(|previous| account <= previous) {
                return Err(BookStateError::NonCanonical {
                    field: "positions must be strictly ordered by account",
                });
            }
            previous_account = Some(account);
            let _quantity = reader.i64()?;
        }

        let dedup_count = reader.u64()?;
        let mut dedup_records = 0usize;
        Self::add_count(
            &mut dedup_records,
            dedup_count,
            "dedup records",
            limits.max_dedup_records,
        )?;
        shape.dedup_records = dedup_records;
        if shape.dedup_records > dedup_capacity {
            return Err(BookStateError::InvalidValue {
                field: "dedup record count exceeds logical dedup capacity",
            });
        }
        for _ in 0..shape.dedup_records {
            let account = reader.u32()?;
            let _client_id = reader.u64()?;
            Self::scan_match_result(&mut reader, account, limits, &mut shape.fills)?;
        }
        reader.finish()?;
        if shape.encoded_len()? != bytes.len() {
            return Err(BookStateError::NonCanonical {
                field: "fixed-width v3 image length does not match its declared counts",
            });
        }

        Ok(ScannedState {
            header: DecodedHeader {
                capacity,
                stp,
                dedup_capacity,
                max_basket_legs,
            },
            shape,
        })
    }

    fn scan_state_side(
        reader: &mut StateReader<'_>,
        expected_side: Side,
        capacity: usize,
        limits: &BookStateLimits,
        shape: &mut StateShape,
    ) -> Result<(Option<Price>, Option<Price>), BookStateError> {
        let declared_levels = reader.u64()?;
        let level_count = Self::add_count(
            &mut shape.levels,
            declared_levels,
            "price levels",
            limits.max_price_levels,
        )?;
        let mut first_price = None;
        let mut previous_price = None;
        for _ in 0..level_count {
            let price = Price::from_raw(reader.i64()?);
            if price.raw() <= 0 {
                return Err(BookStateError::InvalidValue {
                    field: "resting level price must be strictly positive",
                });
            }
            if previous_price.is_some_and(|previous: Price| price.raw() <= previous.raw()) {
                return Err(BookStateError::NonCanonical {
                    field: "price levels must be strictly ascending",
                });
            }
            first_price.get_or_insert(price);
            previous_price = Some(price);

            let declared_orders = reader.u64()?;
            if declared_orders == 0 {
                return Err(BookStateError::InvalidValue {
                    field: "price levels must contain at least one resting order",
                });
            }
            let order_count = Self::add_count(
                &mut shape.orders,
                declared_orders,
                "resting orders",
                limits.max_resting_orders,
            )?;
            if shape.orders > capacity {
                return Err(BookStateError::InvalidValue {
                    field: "resting order count exceeds logical capacity",
                });
            }
            let mut level_quantity = 0i64;
            for _ in 0..order_count {
                let _order_id = reader.u64()?;
                let _account = reader.u32()?;
                let side_tag = reader.u8()?;
                let side = Self::decode_side_tag(side_tag)?;
                if side != expected_side {
                    return Err(BookStateError::InvalidValue {
                        field: "resting node side does not match its side book",
                    });
                }
                let node_price = reader.i64()?;
                if node_price != price.raw() {
                    return Err(BookStateError::InvalidValue {
                        field: "resting node price does not match its level",
                    });
                }
                let remaining = reader.i64()?;
                if remaining <= 0 {
                    return Err(BookStateError::InvalidValue {
                        field: "resting quantity must be strictly positive",
                    });
                }
                level_quantity = level_quantity.checked_add(remaining).ok_or(
                    BookStateError::ArithmeticOverflow {
                        field: "price-level aggregate quantity",
                    },
                )?;
                let _client_id = reader.u64()?;
            }
        }
        Ok((first_price, previous_price))
    }

    fn scan_match_result(
        reader: &mut StateReader<'_>,
        dedup_account: u32,
        limits: &BookStateLimits,
        total_fills: &mut usize,
    ) -> Result<(), BookStateError> {
        let declared_fills = reader.u64()?;
        Self::check_limit(
            "fills per dedup result",
            declared_fills,
            limits.max_fills_per_result,
        )?;
        let fill_count = Self::add_count(
            total_fills,
            declared_fills,
            "total cached fills",
            limits.max_total_fills,
        )?;
        let mut taker_order = None;
        let mut taker_account = None;
        let mut taker_side = None;
        let mut previous_price = None;
        let mut filled_quantity = 0i64;
        for _ in 0..fill_count {
            let maker_order = reader.u64()?;
            let current_taker_order = reader.u64()?;
            let maker_account = reader.u32()?;
            let current_taker_account = reader.u32()?;
            let price = reader.i64()?;
            let quantity = reader.i64()?;
            let current_taker_side = Self::decode_side_tag(reader.u8()?)?;
            if price <= 0 {
                return Err(BookStateError::InvalidValue {
                    field: "cached fill price must be strictly positive",
                });
            }
            if quantity <= 0 {
                return Err(BookStateError::InvalidValue {
                    field: "cached fill quantity must be strictly positive",
                });
            }
            if maker_order == current_taker_order {
                return Err(BookStateError::InvalidValue {
                    field: "cached fill maker and taker order ids must differ",
                });
            }
            if maker_account == current_taker_account {
                return Err(BookStateError::InvalidValue {
                    field: "cached self-trade fill is not reachable",
                });
            }
            if current_taker_account != dedup_account {
                return Err(BookStateError::InvalidValue {
                    field: "cached fill taker account must match its dedup key account",
                });
            }
            if taker_order.is_some_and(|expected| expected != current_taker_order)
                || taker_account.is_some_and(|expected| expected != current_taker_account)
                || taker_side.is_some_and(|expected| expected != current_taker_side)
            {
                return Err(BookStateError::InvalidValue {
                    field: "cached result fills must share one taker",
                });
            }
            if let Some(previous) = previous_price {
                let out_of_order = match current_taker_side {
                    Side::Bid => price < previous,
                    Side::Ask => price > previous,
                };
                if out_of_order {
                    return Err(BookStateError::InvalidValue {
                        field: "cached fills must retain canonical execution order",
                    });
                }
            }
            taker_order = Some(current_taker_order);
            taker_account = Some(current_taker_account);
            taker_side = Some(current_taker_side);
            previous_price = Some(price);
            filled_quantity = filled_quantity.checked_add(quantity).ok_or(
                BookStateError::ArithmeticOverflow {
                    field: "cached filled quantity",
                },
            )?;
        }

        let outcome_tag = reader.u8()?;
        let outcome_quantity = reader.i64()?;
        match outcome_tag {
            0 if fill_count == 0 && outcome_quantity > 0 => {}
            1 if fill_count > 0 && outcome_quantity == 0 => {}
            2 if fill_count > 0 && outcome_quantity > 0 => {
                filled_quantity.checked_add(outcome_quantity).ok_or(
                    BookStateError::ArithmeticOverflow {
                        field: "cached original quantity",
                    },
                )?;
            }
            3 if fill_count > 0
                && outcome_quantity == filled_quantity
                && filled_quantity < i64::MAX => {}
            4 if fill_count == 0 && outcome_quantity == 0 => {}
            0..=4 => {
                return Err(BookStateError::InvalidValue {
                    field: "cached result outcome is inconsistent with its fills or quantity",
                })
            }
            value => {
                return Err(BookStateError::InvalidTag {
                    field: "order outcome",
                    value,
                })
            }
        }
        Ok(())
    }

    fn validate_cached_match_result(
        dedup_account: u32,
        result: &MatchResult,
    ) -> Result<(), BookStateError> {
        Self::usize_as_u64("cached fills", result.fills.len())?;
        let mut makers = HashSet::with_capacity(result.fills.len());
        let mut taker_order = None;
        let mut taker_account = None;
        let mut taker_side = None;
        let mut previous_price = None;
        let mut filled_quantity = 0i64;
        for fill in &result.fills {
            if fill.price.raw() <= 0 {
                return Err(BookStateError::InvalidValue {
                    field: "cached fill price must be strictly positive",
                });
            }
            if fill.quantity.raw() <= 0 {
                return Err(BookStateError::InvalidValue {
                    field: "cached fill quantity must be strictly positive",
                });
            }
            if fill.maker_order == fill.taker_order {
                return Err(BookStateError::InvalidValue {
                    field: "cached fill maker and taker order ids must differ",
                });
            }
            if fill.maker_account == fill.taker_account {
                return Err(BookStateError::InvalidValue {
                    field: "cached self-trade fill is not reachable",
                });
            }
            if fill.taker_account.get() != dedup_account {
                return Err(BookStateError::InvalidValue {
                    field: "cached fill taker account must match its dedup key account",
                });
            }
            if taker_order.is_some_and(|expected| expected != fill.taker_order)
                || taker_account.is_some_and(|expected| expected != fill.taker_account)
                || taker_side.is_some_and(|expected| expected != fill.taker_side)
            {
                return Err(BookStateError::InvalidValue {
                    field: "cached result fills must share one taker",
                });
            }
            if previous_price.is_some_and(|previous: Price| match fill.taker_side {
                Side::Bid => fill.price.raw() < previous.raw(),
                Side::Ask => fill.price.raw() > previous.raw(),
            }) {
                return Err(BookStateError::InvalidValue {
                    field: "cached fills must retain canonical execution order",
                });
            }
            if !makers.insert(fill.maker_order) {
                return Err(BookStateError::InvalidValue {
                    field: "cached result cannot fill one maker order twice",
                });
            }
            filled_quantity = filled_quantity.checked_add(fill.quantity.raw()).ok_or(
                BookStateError::ArithmeticOverflow {
                    field: "cached filled quantity",
                },
            )?;
            taker_order = Some(fill.taker_order);
            taker_account = Some(fill.taker_account);
            taker_side = Some(fill.taker_side);
            previous_price = Some(fill.price);
        }

        let valid_outcome = match result.outcome {
            OrderOutcome::Resting { remaining } => result.fills.is_empty() && remaining.raw() > 0,
            OrderOutcome::FullyFilled => !result.fills.is_empty(),
            OrderOutcome::PartiallyFilledResting { remaining } => {
                !result.fills.is_empty()
                    && remaining.raw() > 0
                    && filled_quantity.checked_add(remaining.raw()).is_some()
            }
            OrderOutcome::PartiallyFilledCancelled { filled } => {
                !result.fills.is_empty()
                    && filled.raw() == filled_quantity
                    && filled_quantity < i64::MAX
            }
            OrderOutcome::Rejected => result.fills.is_empty(),
        };
        if !valid_outcome {
            return Err(BookStateError::InvalidValue {
                field: "cached result outcome is inconsistent with its fills or quantity",
            });
        }
        Ok(())
    }

    fn restore_state_v3(
        bytes: &[u8],
        scanned: ScannedState,
        matching_backend: crate::MatchingBackend,
    ) -> Result<Self, BookStateError> {
        let mut reader = StateReader::new(bytes);
        let _version = reader.u16()?;
        let _capacity = reader.u64()?;
        let _stp = reader.u8()?;
        let _dedup_capacity = reader.u64()?;
        let _max_basket_legs = reader.u64()?;

        let mut book = Self::new(BookConfig {
            capacity: scanned.header.capacity,
            stp: scanned.header.stp,
            dedup_capacity: scanned.header.dedup_capacity,
            max_basket_legs: scanned.header.max_basket_legs,
            matching_backend,
        });
        let mut seen_order_ids = HashSet::with_capacity(scanned.shape.orders);
        Self::restore_state_side(&mut reader, &mut book, Side::Bid, &mut seen_order_ids)?;
        Self::restore_state_side(&mut reader, &mut book, Side::Ask, &mut seen_order_ids)?;
        for orders in book.account_orders.values_mut() {
            orders.sort_unstable();
        }

        let position_count = Self::u64_as_usize("positions", reader.u64()?)?;
        for _ in 0..position_count {
            let account = AccountId::new(reader.u32()?);
            let quantity = Quantity::from_raw(reader.i64()?);
            if book.positions.insert(account, quantity).is_some() {
                return Err(BookStateError::NonCanonical {
                    field: "duplicate position account",
                });
            }
        }

        let dedup_count = Self::u64_as_usize("dedup records", reader.u64()?)?;
        let mut seen_dedup_keys = HashSet::with_capacity(dedup_count);
        for _ in 0..dedup_count {
            let account_raw = reader.u32()?;
            let client_id = reader.u64()?;
            if !seen_dedup_keys.insert((account_raw, client_id)) {
                return Err(BookStateError::NonCanonical {
                    field: "dedup FIFO contains a duplicate key",
                });
            }
            let result = Self::decode_match_result(&mut reader)?;
            book.dedup
                .insert(AccountId::new(account_raw), client_id, result);
        }
        reader.finish()?;
        Ok(book)
    }

    fn restore_state_side(
        reader: &mut StateReader<'_>,
        book: &mut Self,
        expected_side: Side,
        seen_order_ids: &mut HashSet<OrderId>,
    ) -> Result<(), BookStateError> {
        let level_count = Self::u64_as_usize("price levels", reader.u64()?)?;
        for _ in 0..level_count {
            let level_price = Price::from_raw(reader.i64()?);
            let order_count = Self::u64_as_usize("resting orders", reader.u64()?)?;
            for _ in 0..order_count {
                let order_id = OrderId::new(reader.u64()?);
                let account = AccountId::new(reader.u32()?);
                let side = Self::decode_side_tag(reader.u8()?)?;
                let price = Price::from_raw(reader.i64()?);
                let remaining = Quantity::from_raw(reader.i64()?);
                let client_id = reader.u64()?;
                if side != expected_side {
                    return Err(BookStateError::InvalidValue {
                        field: "resting node side does not match its side book",
                    });
                }
                if price != level_price {
                    return Err(BookStateError::InvalidValue {
                        field: "resting node price does not match its level",
                    });
                }
                if remaining.raw() <= 0 {
                    return Err(BookStateError::InvalidValue {
                        field: "resting quantity must be strictly positive",
                    });
                }
                if !seen_order_ids.insert(order_id) {
                    return Err(BookStateError::NonCanonical {
                        field: "resting order ids must be globally unique",
                    });
                }
                let node = Node {
                    order_id,
                    account,
                    side,
                    price,
                    remaining,
                    client_id,
                    prev: NIL,
                    next: NIL,
                };
                let slot = book
                    .slab
                    .insert(node)
                    .map_err(|_| BookStateError::InvalidValue {
                        field: "resting order count exceeds slab capacity",
                    })?;
                match expected_side {
                    Side::Bid => book.bids.push_back(&mut book.slab, slot),
                    Side::Ask => book.asks.push_back(&mut book.slab, slot),
                }
                let stored = *book.slab.get(slot).ok_or(BookStateError::InvalidValue {
                    field: "restored slab slot is not live",
                })?;
                book.auth_insert(&stored);
                if book
                    .id_index
                    .insert(
                        order_id,
                        Locator {
                            slot,
                            side,
                            account,
                        },
                    )
                    .is_some()
                {
                    return Err(BookStateError::NonCanonical {
                        field: "resting order ids must be globally unique",
                    });
                }
                book.account_orders
                    .entry(account)
                    .or_default()
                    .push(order_id);
            }
        }
        Ok(())
    }

    fn decode_match_result(reader: &mut StateReader<'_>) -> Result<MatchResult, BookStateError> {
        let fill_count = Self::u64_as_usize("cached fills", reader.u64()?)?;
        let mut fills = Vec::with_capacity(fill_count);
        let mut makers = HashSet::with_capacity(fill_count);
        for _ in 0..fill_count {
            let fill = Fill {
                maker_order: OrderId::new(reader.u64()?),
                taker_order: OrderId::new(reader.u64()?),
                maker_account: AccountId::new(reader.u32()?),
                taker_account: AccountId::new(reader.u32()?),
                price: Price::from_raw(reader.i64()?),
                quantity: Quantity::from_raw(reader.i64()?),
                taker_side: Self::decode_side_tag(reader.u8()?)?,
            };
            if !makers.insert(fill.maker_order) {
                return Err(BookStateError::InvalidValue {
                    field: "cached result cannot fill one maker order twice",
                });
            }
            fills.push(fill);
        }
        let outcome_tag = reader.u8()?;
        let quantity = Quantity::from_raw(reader.i64()?);
        let outcome = match outcome_tag {
            0 => OrderOutcome::Resting {
                remaining: quantity,
            },
            1 => OrderOutcome::FullyFilled,
            2 => OrderOutcome::PartiallyFilledResting {
                remaining: quantity,
            },
            3 => OrderOutcome::PartiallyFilledCancelled { filled: quantity },
            4 => OrderOutcome::Rejected,
            value => {
                return Err(BookStateError::InvalidTag {
                    field: "order outcome",
                    value,
                })
            }
        };
        Ok(MatchResult { fills, outcome })
    }

    fn decode_side_tag(value: u8) -> Result<Side, BookStateError> {
        match value {
            0 => Ok(Side::Bid),
            1 => Ok(Side::Ask),
            value => Err(BookStateError::InvalidTag {
                field: "side",
                value,
            }),
        }
    }

    fn write_match_result(
        writer: &mut TransitionWriter,
        result: &MatchResult,
    ) -> Result<(), BookStateError> {
        writer.len("cached fills", result.fills.len())?;
        for fill in &result.fills {
            writer.u64(fill.maker_order.get());
            writer.u64(fill.taker_order.get());
            writer.u32(fill.maker_account.get());
            writer.u32(fill.taker_account.get());
            writer.i64(fill.price.raw());
            writer.i64(fill.quantity.raw());
            writer.u8(Self::side_tag(fill.taker_side));
        }
        let (tag, quantity) = match result.outcome {
            OrderOutcome::Resting { remaining } => (0, remaining.raw()),
            OrderOutcome::FullyFilled => (1, 0),
            OrderOutcome::PartiallyFilledResting { remaining } => (2, remaining.raw()),
            OrderOutcome::PartiallyFilledCancelled { filled } => (3, filled.raw()),
            OrderOutcome::Rejected => (4, 0),
        };
        writer.u8(tag);
        writer.i64(quantity);
        Ok(())
    }

    const fn side_tag(side: Side) -> u8 {
        match side {
            Side::Bid => 0,
            Side::Ask => 1,
        }
    }

    const fn stp_tag(policy: StpPolicy) -> u8 {
        match policy {
            StpPolicy::CancelMaker => 0,
            StpPolicy::CancelTaker => 1,
            StpPolicy::CancelBoth => 2,
        }
    }

    fn order_leaf(n: &Node) -> Hash {
        let mut buf = [0u8; 48];
        buf[0..8].copy_from_slice(&n.order_id.get().to_le_bytes());
        buf[8..12].copy_from_slice(&n.account.get().to_le_bytes());
        buf[12] = match n.side {
            Side::Bid => 0,
            Side::Ask => 1,
        };
        buf[13..21].copy_from_slice(&n.price.raw().to_le_bytes());
        buf[21..29].copy_from_slice(&n.remaining.raw().to_le_bytes());
        buf[29..37].copy_from_slice(&n.client_id.to_le_bytes());
        // bytes 37..48 reserved (zero) for schema expansion without reshuffle.
        crypto::hash_domain(crypto::DOMAIN_EXECUTION, &buf)
    }

    fn xor_in(acc: &mut [u8; 32], leaf: Hash) {
        let b = leaf.as_bytes();
        for i in 0..32 {
            acc[i] ^= b[i];
        }
    }

    fn finalize_root(acc: &[u8; 32]) -> Hash {
        let mut preimage = [0u8; 33];
        preimage[0] = BOOK_ROOT_SCHEMA_VERSION;
        preimage[1..].copy_from_slice(acc);
        crypto::hash_domain(crypto::DOMAIN_EXECUTION, &preimage)
    }

    fn auth_insert(&mut self, n: &Node) {
        Self::xor_in(&mut self.order_leaf_xor, Self::order_leaf(n));
    }

    fn auth_remove(&mut self, n: &Node) {
        // XOR is involutive: removing a leaf is identical to inserting it again.
        Self::xor_in(&mut self.order_leaf_xor, Self::order_leaf(n));
    }

    fn auth_update_remaining(&mut self, slot: u32, new_remaining: Quantity) {
        if let Some(n) = self.slab.get(slot).copied() {
            self.auth_remove(&n);
            if let Some(m) = self.slab.get_mut(slot) {
                m.remaining = new_remaining;
            }
            if let Some(n2) = self.slab.get(slot).copied() {
                self.auth_insert(&n2);
            }
        }
    }

    fn execute(&mut self, order: NewOrder) -> Result<MatchResult, OrderError> {
        Ok(self.execute_with_report(order)?.result)
    }

    fn execute_with_report(&mut self, order: NewOrder) -> Result<MatchReport, OrderError> {
        if order.quantity.raw() <= 0 {
            return Err(OrderError::NonPositiveQuantity);
        }
        let is_market = matches!(order.order_type, OrderType::Market);
        if !is_market && order.price.raw() <= 0 {
            return Err(OrderError::NonPositivePrice);
        }
        if self.id_index.contains_key(&order.order_id) {
            return Err(OrderError::DuplicateOrderId);
        }

        // Reduce-only: reject when there is no reducible position; otherwise
        // clamp the quantity to the position magnitude.
        let mut qty = order.quantity;
        let reduce = order.reduce_only || matches!(order.order_type, OrderType::ReduceOnly);
        if reduce {
            let pos = self.position(order.account).raw();
            match order.side {
                Side::Ask => {
                    if pos <= 0 {
                        return Ok(MatchReport {
                            result: MatchResult::rejected(),
                            stp_cancelled: Vec::new(),
                        });
                    }
                    if qty.raw() > pos {
                        qty = Quantity::from_raw(pos);
                    }
                }
                Side::Bid => {
                    if pos >= 0 {
                        return Ok(MatchReport {
                            result: MatchResult::rejected(),
                            stp_cancelled: Vec::new(),
                        });
                    }
                    let avail = pos.saturating_neg();
                    if qty.raw() > avail {
                        qty = Quantity::from_raw(avail);
                    }
                }
            }
        }

        // Post-only never takes: reject if it would cross, else rest in full.
        if matches!(order.order_type, OrderType::PostOnly) {
            if self.would_cross(order.side, order.price) {
                return Ok(MatchReport {
                    result: MatchResult::rejected(),
                    stp_cancelled: Vec::new(),
                });
            }
            self.rest_order(&order, qty)?;
            return Ok(MatchReport {
                result: MatchResult {
                    fills: Vec::new(),
                    outcome: OrderOutcome::Resting { remaining: qty },
                },
                stp_cancelled: Vec::new(),
            });
        }

        // Fill-or-kill: verify full liquidity *before* mutating the book.
        if matches!(order.tif, TimeInForce::Fok) {
            let avail = self.crossable_qty(&order, is_market, qty.raw());
            if avail < qty.raw() {
                return Ok(MatchReport {
                    result: MatchResult::rejected(),
                    stp_cancelled: Vec::new(),
                });
            }
        }

        let mut fills = Vec::new();
        let mut stp_cancelled = Vec::new();
        let (remaining, stopped) =
            self.run_match(&order, is_market, qty, &mut fills, &mut stp_cancelled);
        let filled = qty.saturating_sub(remaining);

        if remaining.raw() == 0 {
            return Ok(MatchReport {
                result: MatchResult {
                    fills,
                    outcome: OrderOutcome::FullyFilled,
                },
                stp_cancelled,
            });
        }

        let will_rest = !is_market
            && !stopped
            && matches!(order.tif, TimeInForce::Gtc)
            && !matches!(order.order_type, OrderType::Market);
        if will_rest {
            match self.rest_order(&order, remaining) {
                Ok(()) => {
                    let outcome = if filled.raw() > 0 {
                        OrderOutcome::PartiallyFilledResting { remaining }
                    } else {
                        OrderOutcome::Resting { remaining }
                    };
                    Ok(MatchReport {
                        result: MatchResult { fills, outcome },
                        stp_cancelled,
                    })
                }
                // A fill or an STP maker cancellation is irreversible: matching
                // already reduced or removed makers, so we must never surface an
                // `Err` that would suppress those deltas from the caller. When a
                // residual cannot rest, cancel it like an IOC remainder and
                // return every fill and cancellation. With neither fills nor STP
                // cancellations, `rest_order` failed before mutation, so the book
                // is bit-identical to its pre-command state and the error is safe
                // to propagate.
                Err(e) => {
                    if filled.raw() > 0 {
                        Ok(MatchReport {
                            result: MatchResult {
                                fills,
                                outcome: OrderOutcome::PartiallyFilledCancelled { filled },
                            },
                            stp_cancelled,
                        })
                    } else if !stp_cancelled.is_empty() {
                        Ok(MatchReport {
                            result: MatchResult {
                                fills,
                                outcome: OrderOutcome::Rejected,
                            },
                            stp_cancelled,
                        })
                    } else {
                        Err(e)
                    }
                }
            }
        } else {
            let outcome = if filled.raw() > 0 {
                OrderOutcome::PartiallyFilledCancelled { filled }
            } else {
                OrderOutcome::Rejected
            };
            Ok(MatchReport {
                result: MatchResult { fills, outcome },
                stp_cancelled,
            })
        }
    }

    /// True if a limit at `(side, price)` would cross the opposite best.
    fn would_cross(&self, side: Side, price: Price) -> bool {
        match side {
            Side::Bid => self
                .asks
                .best_price()
                .is_some_and(|a| price.raw() >= a.raw()),
            Side::Ask => self
                .bids
                .best_price()
                .is_some_and(|b| price.raw() <= b.raw()),
        }
    }

    /// Liquidity that the taker could execute against, honoring the STP policy.
    fn crossable_qty(&self, taker: &NewOrder, is_market: bool, need: i64) -> i64 {
        let book = match taker.side.opposite() {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        };
        book.crossable_qty(
            &self.slab,
            taker.side,
            taker.account,
            taker.price,
            is_market,
            self.config.stp,
            need,
        )
    }

    /// The core matching loop. Consumes crossing liquidity best-first, FIFO
    /// within a level, and returns `(residual, stopped_by_stp)`.
    fn run_match(
        &mut self,
        taker: &NewOrder,
        is_market: bool,
        start_qty: Quantity,
        fills: &mut Vec<Fill>,
        stp_cancelled: &mut Vec<StpCancellation>,
    ) -> (Quantity, bool) {
        let maker_side = taker.side.opposite();
        let mut remaining = start_qty;
        let mut stopped = false;

        'outer: loop {
            if remaining.raw() <= 0 {
                break;
            }
            let opp_price = {
                let book = match maker_side {
                    Side::Bid => &self.bids,
                    Side::Ask => &self.asks,
                };
                match book.best_price() {
                    Some(p) => p,
                    None => break,
                }
            };
            if !crosses(taker.side, is_market, taker.price, opp_price) {
                break;
            }
            loop {
                if remaining.raw() <= 0 {
                    break 'outer;
                }
                let head = {
                    let book = match maker_side {
                        Side::Bid => &self.bids,
                        Side::Ask => &self.asks,
                    };
                    match book.head_at(opp_price) {
                        Some(h) => h,
                        None => break,
                    }
                };
                let maker = match self.slab.get(head) {
                    Some(n) => *n,
                    None => break,
                };
                if maker.account == taker.account {
                    match self.config.stp {
                        StpPolicy::CancelMaker => {
                            stp_cancelled.push(StpCancellation {
                                order_id: maker.order_id,
                                account: maker.account,
                                side: maker.side,
                                price: maker.price,
                                remaining: maker.remaining,
                            });
                            self.remove_resting(maker_side, head);
                            continue;
                        }
                        StpPolicy::CancelTaker => {
                            stopped = true;
                            break 'outer;
                        }
                        StpPolicy::CancelBoth => {
                            stp_cancelled.push(StpCancellation {
                                order_id: maker.order_id,
                                account: maker.account,
                                side: maker.side,
                                price: maker.price,
                                remaining: maker.remaining,
                            });
                            self.remove_resting(maker_side, head);
                            stopped = true;
                            break 'outer;
                        }
                    }
                }
                let fill_qty = if remaining.raw() <= maker.remaining.raw() {
                    remaining
                } else {
                    maker.remaining
                };
                fills.push(Fill {
                    maker_order: maker.order_id,
                    taker_order: taker.order_id,
                    maker_account: maker.account,
                    taker_account: taker.account,
                    price: maker.price,
                    quantity: fill_qty,
                    taker_side: taker.side,
                });
                remaining = remaining.saturating_sub(fill_qty);
                let new_rem = maker.remaining.saturating_sub(fill_qty);
                if new_rem.raw() == 0 {
                    self.remove_resting(maker_side, head);
                } else {
                    // Partial fill: update the cached v2 diagnostic leaf for the
                    // new remaining. The v3 transition root scans stored state.
                    self.auth_update_remaining(head, new_rem);
                    let book = match maker_side {
                        Side::Bid => &mut self.bids,
                        Side::Ask => &mut self.asks,
                    };
                    book.reduce_level_qty(opp_price, fill_qty);
                }
            }
        }
        (remaining, stopped)
    }

    /// Insert `order` onto the book as a resting maker.
    fn rest_order(&mut self, order: &NewOrder, remaining: Quantity) -> Result<(), OrderError> {
        let current = match order.side {
            Side::Bid => self.bids.level_total(order.price),
            Side::Ask => self.asks.level_total(order.price),
        };
        current
            .checked_add(remaining)
            .map_err(|_| OrderError::Overflow)?;
        let node = Node::new(order, remaining);
        let slot = self
            .slab
            .insert(node)
            .map_err(|_| OrderError::CapacityExhausted)?;
        let book = match order.side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        };
        book.push_back(&mut self.slab, slot);
        // Authenticate after the node is in the slab so leaf bytes match storage.
        if let Some(n) = self.slab.get(slot).copied() {
            self.auth_insert(&n);
        }
        self.id_index.insert(
            order.order_id,
            Locator {
                slot,
                side: order.side,
                account: order.account,
            },
        );
        let per_book_capacity = self.config.capacity;
        let ids = self
            .account_orders
            .entry(order.account)
            .or_insert_with(|| Vec::with_capacity(per_book_capacity));
        let position = ids.binary_search(&order.order_id).unwrap_or_else(|p| p);
        ids.insert(position, order.order_id);
        Ok(())
    }

    /// Unlink and free a resting order in O(1), keeping the id index consistent.
    fn remove_resting(&mut self, side: Side, slot: u32) {
        let (oid, account, leaf_node) = match self.slab.get(slot) {
            Some(n) => (n.order_id, n.account, *n),
            None => return,
        };
        self.auth_remove(&leaf_node);
        let book = match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        };
        book.unlink(&mut self.slab, slot);
        let _ = self.slab.remove(slot);
        self.id_index.remove(&oid);
        if let Some(ids) = self.account_orders.get_mut(&account) {
            if let Ok(position) = ids.binary_search(&oid) {
                ids.remove(position);
            }
            // Retain the bounded per-account buffer after the final cancel so
            // a later order from this warmed account does not allocate again.
        }
    }
}

#[cfg(test)]
mod tests {
    include!("book_tests.rs");
}
