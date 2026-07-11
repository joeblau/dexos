//! Price levels and the per-side level index.
//!
//! Each price maps to a [`Level`] holding the head and tail slab indices of an
//! intrusive doubly-linked FIFO queue, plus aggregate quantity and count. The
//! per-side index is a [`BTreeMap`] keyed by price so best-bid / best-ask are
//! O(log L) in the number of levels and iteration is deterministic.
//!
//! Cancellation is O(1) and independent of level depth: because every node
//! carries its own `prev`/`next` links, unlinking touches only the node and its
//! two neighbours regardless of how many orders share the level.

use std::collections::BTreeMap;

use types::{AccountId, Price, Quantity, Side};

use crate::order::{Node, StpPolicy};
use crate::slab::{Slab, NIL};

/// True if a taker at `(taker_side, taker_price)` crosses an opposite level at
/// `opp`. Market takers cross unconditionally. Boundary (equal price) crosses.
#[inline]
pub(crate) fn crosses(taker_side: Side, is_market: bool, taker_price: Price, opp: Price) -> bool {
    if is_market {
        return true;
    }
    match taker_side {
        Side::Bid => taker_price.raw() >= opp.raw(),
        Side::Ask => taker_price.raw() <= opp.raw(),
    }
}

/// Outcome of scanning one level while summing crossable liquidity.
enum Scan {
    /// Keep scanning further levels.
    Continue,
    /// Stop the whole scan (enough found, or an STP boundary reached).
    Stop,
}

fn accumulate_level(
    slab: &Slab<Node>,
    head: u32,
    taker_account: AccountId,
    stp: StpPolicy,
    total: &mut i64,
    need: i64,
) -> Scan {
    let mut cur = head;
    while cur != NIL {
        let node = match slab.get(cur) {
            Some(n) => n,
            None => return Scan::Stop,
        };
        if node.account == taker_account {
            match stp {
                // Own maker is cancelled during matching; it contributes nothing.
                StpPolicy::CancelMaker => {
                    cur = node.next;
                    continue;
                }
                // Taker would stop at its own resting order.
                StpPolicy::CancelTaker | StpPolicy::CancelBoth => return Scan::Stop,
            }
        }
        *total = total.saturating_add(node.remaining.raw());
        if *total >= need {
            return Scan::Stop;
        }
        cur = node.next;
    }
    Scan::Continue
}

/// Aggregate state for one price level.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Level {
    /// Oldest order in the FIFO (matched first). [`NIL`] when empty.
    head: u32,
    /// Newest order in the FIFO (appended last). [`NIL`] when empty.
    tail: u32,
    /// Sum of `remaining` across the level's orders.
    total_qty: Quantity,
    /// Number of orders at this level.
    count: u32,
}

impl Level {
    fn empty() -> Self {
        Level {
            head: NIL,
            tail: NIL,
            total_qty: Quantity::ZERO,
            count: 0,
        }
    }
}

/// One side of the book: a price-ordered index of levels over a shared slab.
pub(crate) struct SideBook {
    side: Side,
    levels: BTreeMap<Price, Level>,
}

impl SideBook {
    pub(crate) fn new(side: Side) -> Self {
        SideBook {
            side,
            levels: BTreeMap::new(),
        }
    }

    /// Best price on this side: highest for bids, lowest for asks.
    pub(crate) fn best_price(&self) -> Option<Price> {
        match self.side {
            Side::Bid => self.levels.keys().next_back().copied(),
            Side::Ask => self.levels.keys().next().copied(),
        }
    }

    /// Append `slot` to the tail of its price level (FIFO time priority).
    ///
    /// The node's `price` field must already be set. Creates the level if it
    /// does not yet exist.
    pub(crate) fn push_back(&mut self, slab: &mut Slab<Node>, slot: u32) {
        let (price, qty) = match slab.get(slot) {
            Some(node) => (node.price, node.remaining),
            None => return,
        };
        let level = self.levels.entry(price).or_insert_with(Level::empty);
        let old_tail = level.tail;
        if old_tail == NIL {
            level.head = slot;
            level.tail = slot;
            if let Some(n) = slab.get_mut(slot) {
                n.prev = NIL;
                n.next = NIL;
            }
        } else {
            if let Some(t) = slab.get_mut(old_tail) {
                t.next = slot;
            }
            if let Some(n) = slab.get_mut(slot) {
                n.prev = old_tail;
                n.next = NIL;
            }
            level.tail = slot;
        }
        level.count = level.count.saturating_add(1);
        level.total_qty = level.total_qty.saturating_add(qty);
    }

    /// Unlink `slot` from its level in O(1). The caller still owns freeing the
    /// slab slot. Empty levels are removed from the index.
    pub(crate) fn unlink(&mut self, slab: &mut Slab<Node>, slot: u32) {
        let (price, prev, next, qty) = {
            let node = match slab.get(slot) {
                Some(n) => n,
                None => return,
            };
            (node.price, node.prev, node.next, node.remaining)
        };
        let level = match self.levels.get_mut(&price) {
            Some(l) => l,
            None => return,
        };
        if prev != NIL {
            if let Some(p) = slab.get_mut(prev) {
                p.next = next;
            }
        } else {
            level.head = next;
        }
        if next != NIL {
            if let Some(n) = slab.get_mut(next) {
                n.prev = prev;
            }
        } else {
            level.tail = prev;
        }
        if let Some(n) = slab.get_mut(slot) {
            n.prev = NIL;
            n.next = NIL;
        }
        level.count = level.count.saturating_sub(1);
        level.total_qty = level.total_qty.saturating_sub(qty);
        if level.count == 0 {
            self.levels.remove(&price);
        }
    }

    /// Reduce the recorded aggregate quantity of a level after a partial fill
    /// of its head order (the node's own `remaining` is updated by the caller).
    pub(crate) fn reduce_level_qty(&mut self, price: Price, delta: Quantity) {
        if let Some(level) = self.levels.get_mut(&price) {
            level.total_qty = level.total_qty.saturating_sub(delta);
        }
    }

    /// Sum of remaining quantity across every resting order on this side.
    pub(crate) fn sum_remaining(&self, slab: &Slab<Node>) -> Quantity {
        let mut total = Quantity::ZERO;
        self.for_each_canonical(slab, |n| total = total.saturating_add(n.remaining));
        total
    }

    /// Aggregate resting quantity at `price` (zero if the level is absent).
    pub(crate) fn level_total(&self, price: Price) -> Quantity {
        self.levels
            .get(&price)
            .map_or(Quantity::ZERO, |l| l.total_qty)
    }

    /// Sum of crossable liquidity a taker could execute, honoring the STP
    /// policy. Iterates best-first and stops early once `need` is reached or an
    /// STP boundary is hit. Allocation-free.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn crossable_qty(
        &self,
        slab: &Slab<Node>,
        taker_side: Side,
        taker_account: AccountId,
        taker_price: Price,
        is_market: bool,
        stp: StpPolicy,
        need: i64,
    ) -> i64 {
        let mut total: i64 = 0;
        // `self.side` is the maker side; iterate it best-first.
        match self.side {
            Side::Ask => {
                for (price, level) in self.levels.iter() {
                    if !crosses(taker_side, is_market, taker_price, *price) {
                        break;
                    }
                    if let Scan::Stop =
                        accumulate_level(slab, level.head, taker_account, stp, &mut total, need)
                    {
                        break;
                    }
                }
            }
            Side::Bid => {
                for (price, level) in self.levels.iter().rev() {
                    if !crosses(taker_side, is_market, taker_price, *price) {
                        break;
                    }
                    if let Scan::Stop =
                        accumulate_level(slab, level.head, taker_account, stp, &mut total, need)
                    {
                        break;
                    }
                }
            }
        }
        total
    }

    /// The head slot index at `price`, if the level exists and is non-empty.
    pub(crate) fn head_at(&self, price: Price) -> Option<u32> {
        self.levels
            .get(&price)
            .map(|l| l.head)
            .filter(|&h| h != NIL)
    }

    /// Iterate resting nodes in canonical order (price ascending, FIFO within a
    /// level), invoking `f` for each. Used for state hashing and cancel-all.
    pub(crate) fn for_each_canonical<F: FnMut(&Node)>(&self, slab: &Slab<Node>, mut f: F) {
        for level in self.levels.values() {
            let mut cur = level.head;
            while cur != NIL {
                if let Some(node) = slab.get(cur) {
                    f(node);
                    cur = node.next;
                } else {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order::NewOrder;
    use types::{AccountId, OrderId, OrderType, TimeInForce};

    fn node(slab: &mut Slab<Node>, id: u64, price: i64, qty: i64) -> u32 {
        let o = NewOrder {
            order_id: OrderId::new(id),
            account: AccountId::new(1),
            side: Side::Bid,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price::from_raw(price),
            quantity: Quantity::from_raw(qty),
            client_id: id,
            reduce_only: false,
        };
        slab.insert(Node::new(&o, Quantity::from_raw(qty))).unwrap()
    }

    #[test]
    fn fifo_time_priority_within_level() {
        let mut slab: Slab<Node> = Slab::with_capacity(8);
        let mut book = SideBook::new(Side::Bid);
        let a = node(&mut slab, 1, 100, 5);
        let b = node(&mut slab, 2, 100, 5);
        let c = node(&mut slab, 3, 100, 5);
        book.push_back(&mut slab, a);
        book.push_back(&mut slab, b);
        book.push_back(&mut slab, c);
        let mut order = Vec::new();
        book.for_each_canonical(&slab, |n| order.push(n.order_id.get()));
        assert_eq!(order, [1u64, 2, 3]);
    }

    #[test]
    fn o1_cancel_from_head_middle_tail() {
        for target in 0..3u64 {
            let mut slab: Slab<Node> = Slab::with_capacity(8);
            let mut book = SideBook::new(Side::Bid);
            let slots = [
                node(&mut slab, 1, 100, 5),
                node(&mut slab, 2, 100, 5),
                node(&mut slab, 3, 100, 5),
            ];
            for &s in &slots {
                book.push_back(&mut slab, s);
            }
            let idx = usize::try_from(target).unwrap();
            book.unlink(&mut slab, slots[idx]);
            slab.remove(slots[idx]).unwrap();
            let mut remaining = Vec::new();
            book.for_each_canonical(&slab, |n| remaining.push(n.order_id.get()));
            let expected: Vec<u64> = (1..=3u64).filter(|&x| x != target + 1).collect();
            assert_eq!(remaining, expected);
        }
    }

    #[test]
    fn best_price_bid_is_highest_ask_is_lowest() {
        let mut slab: Slab<Node> = Slab::with_capacity(8);
        let mut bids = SideBook::new(Side::Bid);
        let mut asks = SideBook::new(Side::Ask);
        let b1 = node(&mut slab, 1, 100, 5);
        let b2 = node(&mut slab, 2, 105, 5);
        bids.push_back(&mut slab, b1);
        bids.push_back(&mut slab, b2);
        assert_eq!(bids.best_price(), Some(Price::from_raw(105)));
        let a1 = node(&mut slab, 3, 110, 5);
        let a2 = node(&mut slab, 4, 108, 5);
        asks.push_back(&mut slab, a1);
        asks.push_back(&mut slab, a2);
        assert_eq!(asks.best_price(), Some(Price::from_raw(108)));
    }

    #[test]
    fn level_removed_when_empty() {
        let mut slab: Slab<Node> = Slab::with_capacity(8);
        let mut book = SideBook::new(Side::Bid);
        let a = node(&mut slab, 1, 100, 5);
        book.push_back(&mut slab, a);
        assert_eq!(book.best_price(), Some(Price::from_raw(100)));
        book.unlink(&mut slab, a);
        slab.remove(a).unwrap();
        assert_eq!(book.best_price(), None);
    }
}
