//! Hierarchical byte budgets for transport queue memory.
//!
//! Frame-count limits alone cannot bound retained memory: 1,024 frames of up to
//! [`codec::MAX_FRAME_PAYLOAD`] (16 MiB) each is 16 GiB *per class*. A
//! [`ByteBudget`] bounds the actual *bytes* held in the reliable priority queues
//! and composes as a parent → child tree so a single scope caps both its own
//! reservation **and** a shared ancestor:
//!
//! * a **node-wide (process)** root budget ([`ByteBudget::root`]) caps the total
//!   reliable bytes any peer can make the process retain; and
//! * a **per-peer** child budget ([`ByteBudget::child`]) caps one peer's share,
//!   so one peer cannot consume the whole node-wide budget and starve honest
//!   peers — a child reservation must fit under the child's own limit *and* every
//!   ancestor's, or it is rejected and rolled back atomically.
//!
//! Reservations are taken by the shedable enqueue path
//! ([`crate::channel::AsyncPriorityChannel::try_send`]) and released when the
//! frame is dequeued, so the budget tracks live queued bytes. A reservation is
//! only ever attached to a channel filled via `try_send`, never to the
//! `send`-awaiting inbound reliable path, so an exhausted budget sheds (returns
//! backpressure to the *sender's* own flow control) and never silently drops a
//! reliable frame the far side already observed as delivered.
//!
//! High-water marks are retained so operators can size ceilings and alert on
//! sustained pressure at every scope.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A shared, hierarchical byte reservation with a fixed ceiling.
///
/// Cheap to clone via [`Arc`]; all clones of one budget share its counters. A
/// [`child`](ByteBudget::child) additionally debits its parent on every
/// reservation, giving simultaneous per-scope and aggregate ceilings.
#[derive(Debug)]
pub struct ByteBudget {
    limit: usize,
    used: AtomicUsize,
    high_water: AtomicUsize,
    parent: Option<Arc<ByteBudget>>,
}

impl ByteBudget {
    /// A root (node-wide) budget capped at `limit` bytes.
    pub fn root(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            parent: None,
        })
    }

    /// A child budget capped at `limit` bytes whose reservations also debit
    /// `parent`. A reservation succeeds only if it fits under this limit *and*
    /// every ancestor's.
    pub fn child(limit: usize, parent: Arc<ByteBudget>) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            parent: Some(parent),
        })
    }

    /// This scope's byte ceiling.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Bytes currently reserved in this scope.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// The high-water mark of [`used`](ByteBudget::used) over this scope's life.
    pub fn high_water(&self) -> usize {
        self.high_water.load(Ordering::Acquire)
    }

    /// Reserve `n` bytes in this scope alone, updating the high-water mark.
    ///
    /// Admits the reservation when it fits under `limit`, or unconditionally when
    /// the scope is currently empty — so a single frame larger than the whole
    /// limit still makes progress and never wedges the queue — otherwise returns
    /// `false` without mutating `used`.
    fn reserve_local(&self, n: usize) -> bool {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            // Always admit at least one reservation into an empty scope so a lone
            // oversized frame cannot deadlock forward progress.
            if cur != 0 && cur.saturating_add(n) > self.limit {
                return false;
            }
            let next = cur.saturating_add(n);
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    self.high_water.fetch_max(next, Ordering::Relaxed);
                    return true;
                }
                Err(observed) => cur = observed,
            }
        }
    }

    /// Release `n` bytes from this scope alone (saturating, so a defensive
    /// double-release can never underflow).
    fn release_local(&self, n: usize) {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(n);
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Try to reserve `n` bytes in this scope and every ancestor, atomically.
    ///
    /// Returns `true` only if the reservation fits at every level; a failure at
    /// any ancestor rolls back the reservations already taken below it, so the
    /// tree is never left in a partially-charged state.
    pub fn try_reserve(&self, n: usize) -> bool {
        if !self.reserve_local(n) {
            return false;
        }
        if let Some(parent) = &self.parent {
            if !parent.try_reserve(n) {
                // Roll back our own reservation: the ancestor rejected it.
                self.release_local(n);
                return false;
            }
        }
        true
    }

    /// Release `n` bytes previously reserved via [`try_reserve`](Self::try_reserve),
    /// crediting this scope and every ancestor.
    pub fn release(&self, n: usize) {
        if n == 0 {
            return;
        }
        if let Some(parent) = &self.parent {
            parent.release(n);
        }
        self.release_local(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_release_tracks_used_and_high_water() {
        let b = ByteBudget::root(1000);
        assert!(b.try_reserve(400));
        assert!(b.try_reserve(300));
        assert_eq!(b.used(), 700);
        assert_eq!(b.high_water(), 700);
        b.release(400);
        assert_eq!(b.used(), 300);
        // High-water is a peak, not the live value.
        assert_eq!(b.high_water(), 700);
    }

    #[test]
    fn reservation_over_limit_is_rejected_without_charging() {
        let b = ByteBudget::root(1000);
        assert!(b.try_reserve(800));
        // 800 + 300 > 1000 and the scope is non-empty: rejected, no partial charge.
        assert!(!b.try_reserve(300));
        assert_eq!(b.used(), 800);
        // A reservation that still fits is admitted.
        assert!(b.try_reserve(200));
        assert_eq!(b.used(), 1000);
    }

    #[test]
    fn empty_scope_always_admits_one_oversized_reservation() {
        let b = ByteBudget::root(100);
        // A lone frame larger than the whole limit still makes progress.
        assert!(b.try_reserve(10_000));
        assert_eq!(b.used(), 10_000);
        // But a second reservation while non-empty is rejected.
        assert!(!b.try_reserve(1));
    }

    #[test]
    fn child_is_bounded_by_its_own_limit_and_the_shared_parent() {
        // Node-wide root of 1000; two per-peer children each capped at 800.
        let node = ByteBudget::root(1000);
        let peer_a = ByteBudget::child(800, node.clone());
        let peer_b = ByteBudget::child(800, node.clone());

        // Peer A reserves up to its own 800 cap; the node now holds 800.
        assert!(peer_a.try_reserve(800));
        assert_eq!(node.used(), 800);
        // Peer A cannot exceed its own per-peer cap even though the node has room.
        assert!(!peer_a.try_reserve(1));

        // Peer B (honest) can still use the node's remaining 200 headroom...
        assert!(peer_b.try_reserve(200));
        assert_eq!(node.used(), 1000);
        // ...but B is throttled by the *node* ceiling, not by its own 800 cap:
        // one peer cannot consume the whole node-wide budget and starve another.
        assert!(!peer_b.try_reserve(1));
        assert_eq!(peer_b.used(), 200);

        // Releasing A returns capacity to the shared node budget for B to use.
        peer_a.release(800);
        assert_eq!(node.used(), 200);
        assert!(peer_b.try_reserve(600));
        assert_eq!(peer_b.used(), 800);
        assert_eq!(node.used(), 800);
    }

    #[test]
    fn parent_rejection_rolls_back_child_reservation() {
        let node = ByteBudget::root(500);
        let peer = ByteBudget::child(10_000, node.clone());
        // Fill the node to its cap through a sibling so the parent rejects.
        let other = ByteBudget::child(10_000, node.clone());
        assert!(other.try_reserve(500));

        // The child's local reserve would succeed, but the parent is full and
        // non-empty; the whole reservation is rejected and rolled back.
        assert!(!peer.try_reserve(200));
        assert_eq!(
            peer.used(),
            0,
            "child reservation rolled back on parent reject"
        );
        assert_eq!(node.used(), 500);
    }

    #[test]
    fn release_credits_every_ancestor() {
        let node = ByteBudget::root(1000);
        let peer = ByteBudget::child(1000, node.clone());
        assert!(peer.try_reserve(400));
        assert_eq!(peer.used(), 400);
        assert_eq!(node.used(), 400);
        peer.release(400);
        assert_eq!(peer.used(), 0);
        assert_eq!(node.used(), 0, "release must credit the parent too");
    }
}
