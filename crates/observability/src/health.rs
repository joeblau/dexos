//! Subsystem-health instrumentation: bounded-queue depth/drop tracking, peer
//! RTT / packet-loss gauges, and integer lag/age helpers.
//!
//! These are thin, hot-path-safe wrappers over [`Counter`] and [`Gauge`]. All
//! arithmetic is integer and saturating, so sequence gaps and monotonic-clock
//! reads never produce a panic or a wrapped value.

use std::sync::Arc;

use types::SequenceNumber;

use crate::counter::{Counter, Gauge};

/// Depth and drop instrumentation for one bounded queue.
///
/// The gauge tracks current depth; the counter accumulates drops. [`try_push`]
/// models the queue's admission decision so a full queue increments the drop
/// counter **without blocking** — recording is atomic-only.
///
/// [`try_push`]: QueueMetrics::try_push
#[derive(Debug, Clone)]
pub struct QueueMetrics {
    depth: Arc<Gauge>,
    dropped: Arc<Counter>,
    capacity: u64,
}

impl QueueMetrics {
    /// Builds queue metrics over shared depth/drop handles and a fixed
    /// capacity.
    #[must_use]
    pub fn new(depth: Arc<Gauge>, dropped: Arc<Counter>, capacity: u64) -> Self {
        Self {
            depth,
            dropped,
            capacity,
        }
    }

    /// Records an admission attempt. If there is room, increments depth and
    /// returns `true`; otherwise increments the drop counter and returns
    /// `false`. Never blocks.
    #[inline]
    pub fn try_push(&self) -> bool {
        let cap = i64::try_from(self.capacity).unwrap_or(i64::MAX);
        if self.depth.try_inc_below(cap) {
            true
        } else {
            self.dropped.inc();
            false
        }
    }

    /// Records a dequeue, decrementing depth but never going below zero.
    #[inline]
    pub fn pop(&self) {
        self.depth.try_dec_positive();
    }

    /// Directly sets the reported depth (for callers that own the real count).
    #[inline]
    pub fn set_depth(&self, depth: i64) {
        self.depth.set(depth);
    }

    /// Explicitly records a drop.
    #[inline]
    pub fn record_drop(&self) {
        self.dropped.inc();
    }

    /// Current reported depth.
    #[must_use]
    pub fn depth(&self) -> i64 {
        self.depth.get()
    }

    /// Total drops observed.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.get()
    }

    /// Configured capacity.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
}

/// RTT and packet-loss gauges for one peer link.
///
/// RTT is stored in microseconds; packet loss is stored in parts-per-million
/// (an integer fixed-point ratio) so no floating point is needed.
#[derive(Debug, Clone)]
pub struct PeerMetrics {
    rtt_us: Arc<Gauge>,
    loss_ppm: Arc<Gauge>,
}

impl PeerMetrics {
    /// Builds peer metrics over shared RTT and loss gauges.
    #[must_use]
    pub fn new(rtt_us: Arc<Gauge>, loss_ppm: Arc<Gauge>) -> Self {
        Self { rtt_us, loss_ppm }
    }

    /// Sets the current round-trip time in microseconds.
    #[inline]
    pub fn set_rtt_us(&self, rtt_us: i64) {
        self.rtt_us.set(rtt_us);
    }

    /// Sets the current packet loss in parts-per-million (0..=1_000_000).
    #[inline]
    pub fn set_loss_ppm(&self, loss_ppm: i64) {
        self.loss_ppm.set(loss_ppm);
    }

    /// Current RTT in microseconds.
    #[must_use]
    pub fn rtt_us(&self) -> i64 {
        self.rtt_us.get()
    }

    /// Current packet loss in parts-per-million.
    #[must_use]
    pub fn loss_ppm(&self) -> i64 {
        self.loss_ppm.get()
    }
}

/// Sequence lag: how far `tail` trails `head`, saturating at zero so a
/// stale/regressed tail (a sequence gap) reports `0` rather than wrapping.
#[must_use]
pub fn sequence_lag(head: SequenceNumber, tail: SequenceNumber) -> u64 {
    head.get().saturating_sub(tail.get())
}

/// Monotonic age: `now - earlier` for two monotonic-clock reads in the same
/// unit. Saturating, so a non-monotonic pair (`now < earlier`) reports `0`.
#[must_use]
pub fn age_ticks(now: u64, earlier: u64) -> u64 {
    now.saturating_sub(earlier)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(capacity: u64) -> QueueMetrics {
        QueueMetrics::new(Arc::new(Gauge::new()), Arc::new(Counter::new()), capacity)
    }

    #[test]
    fn filling_raises_depth() {
        let q = queue(3);
        assert!(q.try_push());
        assert!(q.try_push());
        assert_eq!(q.depth(), 2);
        q.pop();
        assert_eq!(q.depth(), 1);
    }

    #[test]
    fn overflow_drops_without_blocking() {
        let q = queue(2);
        assert!(q.try_push());
        assert!(q.try_push());
        assert!(!q.try_push()); // full -> dropped
        assert!(!q.try_push());
        assert_eq!(q.depth(), 2);
        assert_eq!(q.dropped(), 2);
    }

    #[test]
    fn pop_never_underflows() {
        let q = queue(2);
        q.pop();
        q.pop();
        assert_eq!(q.depth(), 0);
    }

    #[test]
    fn concurrent_depth_stays_bounded() {
        use std::thread;
        let q = queue(7);
        thread::scope(|scope| {
            for _ in 0..16 {
                let q = q.clone();
                scope.spawn(move || {
                    for _ in 0..10_000 {
                        if q.try_push() {
                            q.pop();
                        } else {
                            q.pop();
                        }
                    }
                });
            }
        });
        assert!((0..=7).contains(&q.depth()));
        for _ in 0..100 {
            q.pop();
        }
        assert_eq!(q.depth(), 0);
    }

    #[test]
    fn peer_metrics_track_rtt_and_loss() {
        let p = PeerMetrics::new(Arc::new(Gauge::new()), Arc::new(Gauge::new()));
        p.set_rtt_us(1500);
        p.set_loss_ppm(2500);
        assert_eq!(p.rtt_us(), 1500);
        assert_eq!(p.loss_ppm(), 2500);
    }

    #[test]
    fn lag_and_age_saturate_on_gaps() {
        let head = SequenceNumber::new(100);
        let tail = SequenceNumber::new(90);
        assert_eq!(sequence_lag(head, tail), 10);
        // Regressed tail (gap) -> saturates to 0, no wrap.
        assert_eq!(sequence_lag(tail, head), 0);
        assert_eq!(age_ticks(500, 200), 300);
        assert_eq!(age_ticks(200, 500), 0);
    }
}
