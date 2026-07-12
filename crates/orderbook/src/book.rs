//! The central-limit order book: deterministic price-time matching, O(1)
//! cancellation, atomic cancel-replace, cancel-all, baskets, self-trade
//! prevention, reduce-only clamping, and client idempotency.

use std::collections::HashMap;

use types::{AccountId, Hash, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

use crate::dedup::DedupCache;
use crate::error::OrderError;
use crate::level::{crosses, SideBook};
use crate::order::{BookConfig, Fill, MatchResult, NewOrder, Node, OrderOutcome, StpPolicy};
use crate::slab::Slab;

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
/// rolled back to the exact pre-command state.
#[derive(Clone)]
pub struct OrderBook {
    config: BookConfig,
    slab: Slab<Node>,
    bids: SideBook,
    asks: SideBook,
    id_index: HashMap<OrderId, Locator>,
    positions: HashMap<AccountId, Quantity>,
    dedup: DedupCache,
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
            positions: HashMap::new(),
            dedup: DedupCache::with_capacity(config.dedup_capacity),
            config,
        }
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
    pub fn submit(&mut self, order: NewOrder) -> Result<MatchResult, OrderError> {
        if let Some(cached) = self.dedup.get(order.account, order.client_id) {
            return Ok(cached.clone());
        }
        let result = self.execute(order)?;
        self.dedup
            .insert(order.account, order.client_id, result.clone());
        Ok(result)
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
        let mut targets: Vec<OrderId> = self
            .id_index
            .iter()
            .filter_map(|(id, loc)| (loc.account == account).then_some(*id))
            .collect();
        targets.sort_unstable();
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

    /// A deterministic 32-byte commitment over all resting orders. Identical
    /// book states produce identical roots; any resting-order difference (price,
    /// quantity, ownership, or FIFO order) produces a different root.
    #[must_use]
    pub fn state_root(&self) -> Hash {
        let mut buf: Vec<u8> = Vec::new();
        self.serialize_side(&self.bids, &mut buf);
        self.serialize_side(&self.asks, &mut buf);
        crypto::hash_domain(crypto::DOMAIN_EXECUTION, &buf)
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

    fn serialize_side(&self, book: &SideBook, buf: &mut Vec<u8>) {
        book.for_each_canonical(&self.slab, |n| {
            buf.extend_from_slice(&n.order_id.get().to_le_bytes());
            buf.extend_from_slice(&n.account.get().to_le_bytes());
            buf.push(match n.side {
                Side::Bid => 0,
                Side::Ask => 1,
            });
            buf.extend_from_slice(&n.price.raw().to_le_bytes());
            buf.extend_from_slice(&n.remaining.raw().to_le_bytes());
            buf.extend_from_slice(&n.client_id.to_le_bytes());
        });
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
                    if let Some(n) = self.slab.get_mut(head) {
                        n.remaining = new_rem;
                    }
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
        self.id_index.insert(
            order.order_id,
            Locator {
                slot,
                side: order.side,
                account: order.account,
            },
        );
        Ok(())
    }

    /// Unlink and free a resting order in O(1), keeping the id index consistent.
    fn remove_resting(&mut self, side: Side, slot: u32) {
        let oid = match self.slab.get(slot) {
            Some(n) => n.order_id,
            None => return,
        };
        let book = match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        };
        book.unlink(&mut self.slab, slot);
        let _ = self.slab.remove(slot);
        self.id_index.remove(&oid);
    }
}

#[cfg(test)]
mod tests {
    include!("book_tests.rs");
}
