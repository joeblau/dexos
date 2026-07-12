//! Lock-free scalar metrics: a monotonic [`Counter`] and a settable [`Gauge`].
//!
//! Both are thin wrappers over a single atomic. Every mutating method is a
//! single relaxed atomic read-modify-write (or store) — no locks, no
//! allocation, no branching that touches the heap. They are safe to share
//! across threads via `Arc` and are the primitive the [`MetricsRegistry`]
//! hands out to the hot path.
//!
//! [`MetricsRegistry`]: crate::MetricsRegistry

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// A monotonically increasing, lock-free `u64` counter.
///
/// Counters only ever go up (there is no `dec`), which makes their snapshot
/// value meaningful even when read concurrently with writers: the observed
/// value is a lower bound on the true count at the moment of the read.
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    /// Creates a counter starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    /// Increments the counter by one. Single relaxed atomic add.
    #[inline]
    pub fn inc(&self) {
        self.add(1);
    }

    /// Increments the counter by `n`. Single relaxed atomic add.
    #[inline]
    pub fn add(&self, n: u64) {
        let _ = self
            .value
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(n))
            });
    }

    /// Reads the current value. Not a synchronization point.
    #[inline]
    #[must_use]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A lock-free `i64` gauge supporting set / add / sub semantics.
///
/// Unlike a [`Counter`], a gauge can move in either direction, which is why it
/// is signed: transient negative deltas (e.g. a dequeue racing an enqueue in a
/// best-effort depth estimate) never wrap into an enormous positive value.
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicI64,
}

impl Gauge {
    /// Creates a gauge starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            value: AtomicI64::new(0),
        }
    }

    /// Overwrites the gauge with `v`. Single relaxed atomic store.
    #[inline]
    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    /// Adds `delta` (which may be negative). Single relaxed atomic add.
    #[inline]
    pub fn add(&self, delta: i64) {
        self.value.fetch_add(delta, Ordering::Relaxed);
    }

    /// Subtracts `delta`. Single relaxed atomic sub.
    #[inline]
    pub fn sub(&self, delta: i64) {
        self.value.fetch_sub(delta, Ordering::Relaxed);
    }

    /// Increments the gauge by one.
    #[inline]
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the gauge by one.
    #[inline]
    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    /// Records `v` as the new maximum if it exceeds the current value.
    #[inline]
    pub fn set_max(&self, v: i64) {
        self.value.fetch_max(v, Ordering::Relaxed);
    }

    /// Reads the current value. Not a synchronization point.
    #[inline]
    #[must_use]
    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Atomically increments when the current value is below `upper`.
    #[inline]
    pub fn try_inc_below(&self, upper: i64) -> bool {
        self.value
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (v < upper).then(|| v.saturating_add(1))
            })
            .is_ok()
    }

    /// Atomically decrements when the current value is positive.
    #[inline]
    pub fn try_dec_positive(&self) -> bool {
        self.value
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (v > 0).then(|| v - 1)
            })
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_is_monotonic() {
        let c = Counter::new();
        assert_eq!(c.get(), 0);
        c.inc();
        c.add(9);
        assert_eq!(c.get(), 10);
    }

    #[test]
    fn counter_saturates_at_u64_max() {
        let c = Counter::new();
        c.value.store(u64::MAX - 1, Ordering::Relaxed);
        c.add(10);
        assert_eq!(c.get(), u64::MAX);
        c.inc();
        assert_eq!(c.get(), u64::MAX);
    }

    #[test]
    fn gauge_set_add_sub() {
        let g = Gauge::new();
        g.set(5);
        assert_eq!(g.get(), 5);
        g.add(3);
        assert_eq!(g.get(), 8);
        g.sub(10);
        assert_eq!(g.get(), -2);
        g.inc();
        g.inc();
        assert_eq!(g.get(), 0);
        g.set_max(7);
        assert_eq!(g.get(), 7);
        g.set_max(3);
        assert_eq!(g.get(), 7);
    }
}
