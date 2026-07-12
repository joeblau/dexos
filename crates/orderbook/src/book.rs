//! The central-limit order book: deterministic price-time matching, O(1)
//! cancellation, atomic cancel-replace, cancel-all, baskets, self-trade
//! prevention, reduce-only clamping, and client idempotency.

use std::collections::HashMap;

use types::{AccountId, Amount, Hash, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

use crate::dedup::DedupCache;
use crate::error::OrderError;
use crate::level::{crosses, SideBook};
use crate::order::{
    BookConfig, Fill, MatchPlan, MatchResult, NewOrder, Node, OrderOutcome, PlannedFill, StpPolicy,
};
use crate::slab::Slab;
use crate::{BOOK_ROOT_HOT_PATH_HASH_BUDGET_BYTES, BOOK_ROOT_SCHEMA_VERSION};

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
/// identical stream of commands the book reaches an identical state, verifiable
/// via [`OrderBook::state_root`].
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

    /// The account that owns the resting order `id`, if it is resting. Used by
    /// the engine to enforce that a cancel/replace targets the caller's own
    /// order.
    #[must_use]
    pub fn owner(&self, id: OrderId) -> Option<AccountId> {
        self.id_index.get(&id).map(|loc| loc.account)
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
    /// [`OrderBook::place`] instead, so idempotency is decided once at the
    /// command layer rather than replayed a second time here.
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
    /// into the state root. The engine submits through this path so the book
    /// never applies a second, weaker dedup that could replay stale fills.
    pub fn place(&mut self, order: NewOrder) -> Result<MatchResult, OrderError> {
        self.execute(order)
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
        self.execute(replacement)
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

    /// Incremental authenticated commitment over all resting orders.
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
    #[must_use]
    pub fn state_root(&self) -> Hash {
        Self::finalize_root(&self.order_leaf_xor)
    }

    /// Canonical full rebuild of the book root from every resting order.
    /// Differential oracle for the incremental path — not used on the hot path.
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

    /// Deterministic dry-run of matching `order` against current depth.
    ///
    /// Does not mutate the book. Honors STP, price collars (including market
    /// protection prices), and the requested quantity. Used by pre-trade risk
    /// so market-order margin is derived from executable depth.
    pub fn plan_match(&self, order: &NewOrder) -> Result<MatchPlan, OrderError> {
        if order.quantity.raw() <= 0 {
            return Err(OrderError::NonPositiveQuantity);
        }
        let is_market = matches!(order.order_type, OrderType::Market);
        if !is_market && order.price.raw() <= 0 {
            return Err(OrderError::NonPositivePrice);
        }
        let mut fills = Vec::new();
        let mut remaining = order.quantity.raw();
        let maker_side = order.side.opposite();
        let book = match maker_side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        };

        // Walk levels best-first; for bids of the maker book iterate high→low.
        let mut level_prices: Vec<Price> = Vec::new();
        book.for_each_level_price(|p| level_prices.push(p));
        // for_each_level_price yields ascending; maker bids need descending.
        if matches!(maker_side, Side::Bid) {
            level_prices.reverse();
        }

        'levels: for price in level_prices {
            if remaining <= 0 {
                break;
            }
            if !crosses(order.side, is_market, order.price, price) {
                break;
            }
            let head = match book.head_at(price) {
                Some(h) => h,
                None => continue,
            };
            let mut cur = head;
            while cur != crate::slab::NIL && remaining > 0 {
                let maker = match self.slab.get(cur) {
                    Some(n) => *n,
                    None => break,
                };
                if maker.account == order.account {
                    match self.config.stp {
                        StpPolicy::CancelMaker => {
                            cur = maker.next;
                            continue;
                        }
                        StpPolicy::CancelTaker | StpPolicy::CancelBoth => break 'levels,
                    }
                }
                let fill_qty = remaining.min(maker.remaining.raw());
                fills.push(PlannedFill {
                    maker_order: maker.order_id,
                    maker_account: maker.account,
                    price: maker.price,
                    quantity: Quantity::from_raw(fill_qty),
                });
                remaining = remaining.saturating_sub(fill_qty);
                cur = maker.next;
            }
        }

        let mut notional = Amount::ZERO;
        let mut notional_ceil = Amount::ZERO;
        let mut filled = Quantity::ZERO;
        let mut worst: Option<Price> = None;
        for f in &fills {
            filled = filled.saturating_add(f.quantity);
            notional = notional.checked_add(f.price.notional(f.quantity)?)?;
            notional_ceil = notional_ceil.checked_add(f.price.notional_ceil(f.quantity)?)?;
            worst = Some(match worst {
                None => f.price,
                Some(w) => match order.side {
                    // Bid: worst is highest pay; Ask: worst is lowest receive.
                    Side::Bid if f.price.raw() > w.raw() => f.price,
                    Side::Ask if f.price.raw() < w.raw() => f.price,
                    _ => w,
                },
            });
        }
        Ok(MatchPlan {
            fills,
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
                        return Ok(MatchResult::rejected());
                    }
                    if qty.raw() > pos {
                        qty = Quantity::from_raw(pos);
                    }
                }
                Side::Bid => {
                    if pos >= 0 {
                        return Ok(MatchResult::rejected());
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
                return Ok(MatchResult::rejected());
            }
            self.rest_order(&order, qty)?;
            return Ok(MatchResult {
                fills: Vec::new(),
                outcome: OrderOutcome::Resting { remaining: qty },
            });
        }

        // Fill-or-kill: verify full liquidity *before* mutating the book.
        if matches!(order.tif, TimeInForce::Fok) {
            let avail = self.crossable_qty(&order, is_market, qty.raw());
            if avail < qty.raw() {
                return Ok(MatchResult::rejected());
            }
        }

        let mut fills = Vec::new();
        let (remaining, stopped) = self.run_match(&order, is_market, qty, &mut fills);
        let filled = qty.saturating_sub(remaining);

        if remaining.raw() == 0 {
            return Ok(MatchResult {
                fills,
                outcome: OrderOutcome::FullyFilled,
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
                    Ok(MatchResult { fills, outcome })
                }
                // A fill is irreversible: matching already reduced or removed
                // makers, so we must never surface an `Err` that would strand
                // those fills (the caller applies fills only on `Ok`, so an
                // `Err` here would diverge the book from risk/ledger). When a
                // residual produced by real fills cannot rest, cancel it like an
                // IOC remainder and return the fills. With no fills, `rest_order`
                // never mutated the book (its `insert` fails first), so the book
                // is bit-identical to its pre-command state and the capacity
                // error is safe to propagate.
                Err(e) => {
                    if filled.raw() > 0 {
                        Ok(MatchResult {
                            fills,
                            outcome: OrderOutcome::PartiallyFilledCancelled { filled },
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
            Ok(MatchResult { fills, outcome })
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
                            self.remove_resting(maker_side, head);
                            continue;
                        }
                        StpPolicy::CancelTaker => {
                            stopped = true;
                            break 'outer;
                        }
                        StpPolicy::CancelBoth => {
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
                    // Partial fill: update authenticated leaf for the new remaining.
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
        let ids = self.account_orders.entry(order.account).or_default();
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
            if ids.is_empty() {
                self.account_orders.remove(&account);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    include!("book_tests.rs");
}
