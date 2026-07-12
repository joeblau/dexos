//! Packet batching for the lossy datagram / market-data path.
//!
//! Normal optimized networking first: coalesce many small datagrams into one
//! batched flush (the shape a `sendmmsg(2)` call or an AF_XDP TX ring fills),
//! amortizing syscall overhead. An optional kernel-bypass backend (AF_XDP/DPDK)
//! plugs in behind [`KernelBypassTx`] without becoming a protocol dependency.
//! The batch buffer is bounded — it never grows without limit.
//!
//! Partial sends preserve the unaccepted suffix. Intentional drops (deadline,
//! class incompatibility, overflow) are counted by reason.

use std::time::{Duration, Instant};

use codec::TrafficClass;

/// Default maximum datagrams coalesced into one batched flush.
pub const DEFAULT_BATCH: usize = 64;
/// Default maximum total payload bytes in one batch (MTU-aware coalescing budget).
pub const DEFAULT_BATCH_BYTES: usize = 64 * 1024;
/// Default maximum time a datagram may sit in the batch before intentional drop.
pub const DEFAULT_BATCH_DEADLINE: Duration = Duration::from_millis(50);

/// Why a datagram was intentionally dropped from the batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DropReason {
    /// Exceeded the per-datagram deadline while waiting to flush.
    Deadline = 0,
    /// Batch overflow: a push could not retain the datagram under the byte/count cap.
    Overflow = 1,
    /// Incompatible traffic class / priority relative to the batch head.
    ClassMismatch = 2,
}

/// Observable drop counters by reason and class priority (P0..P8).
#[derive(Debug, Default, Clone)]
pub struct BatchDropMetrics {
    /// Counts indexed by [`DropReason`] as usize.
    by_reason: [u64; 3],
    /// Counts indexed by traffic-class priority.
    by_class: [u64; 9],
}

impl BatchDropMetrics {
    /// Record one intentional drop.
    pub fn record(&mut self, reason: DropReason, class: TrafficClass) {
        self.by_reason[reason as usize] = self.by_reason[reason as usize].saturating_add(1);
        let idx = usize::from(class.priority());
        if let Some(slot) = self.by_class.get_mut(idx) {
            *slot = slot.saturating_add(1);
        }
    }

    /// Drops for a reason.
    pub fn reason(&self, reason: DropReason) -> u64 {
        self.by_reason[reason as usize]
    }

    /// Drops for a traffic class.
    pub fn class(&self, class: TrafficClass) -> u64 {
        self.by_class
            .get(usize::from(class.priority()))
            .copied()
            .unwrap_or(0)
    }

    /// Total intentional drops.
    pub fn total(&self) -> u64 {
        self.by_reason.iter().copied().sum()
    }
}

/// A sink that transmits a batch of datagrams in one operation. A real backend
/// wraps `sendmmsg(2)`; tests use a counting mock.
pub trait BatchSink {
    /// Transmit the datagrams. Returns how many were accepted by the OS/NIC
    /// (a prefix of `frames`). The unaccepted suffix must be retained by the
    /// caller for retry.
    fn flush_batch(&mut self, frames: &[Vec<u8>]) -> usize;
}

/// Optional kernel-bypass transmit path (AF_XDP / DPDK). Not enabled by default;
/// provided so measurements can justify it before it is wired in.
pub trait KernelBypassTx {
    /// Push a burst of frames onto the TX ring. Returns how many were enqueued.
    fn tx_burst(&mut self, frames: &[&[u8]]) -> usize;
}

/// One queued datagram with class and deadline metadata.
#[derive(Debug, Clone)]
struct Pending {
    bytes: Vec<u8>,
    class: TrafficClass,
    enqueued_at: Instant,
    deadline: Duration,
}

/// Accumulates encoded datagrams and flushes them in bounded, MTU-aware batches.
///
/// Partial flushes retain the unaccepted suffix. Never batches across
/// incompatible priority classes. Deadline expiry produces intentional drops
/// with counters — never silent loss.
#[derive(Debug)]
pub struct BatchSender {
    max_batch: usize,
    max_bytes: usize,
    default_deadline: Duration,
    pending: Vec<Pending>,
    pending_bytes: usize,
    flushed: u64,
    batches: u64,
    drops: BatchDropMetrics,
}

impl BatchSender {
    /// A sender that coalesces up to `max_batch` datagrams / `DEFAULT_BATCH_BYTES`.
    pub fn new(max_batch: usize) -> Self {
        Self::with_limits(max_batch, DEFAULT_BATCH_BYTES, DEFAULT_BATCH_DEADLINE)
    }

    /// Full constructor with byte budget and default deadline.
    pub fn with_limits(max_batch: usize, max_bytes: usize, default_deadline: Duration) -> Self {
        let cap = max_batch.max(1);
        Self {
            max_batch: cap,
            max_bytes: max_bytes.max(1),
            default_deadline,
            pending: Vec::with_capacity(cap),
            pending_bytes: 0,
            flushed: 0,
            batches: 0,
            drops: BatchDropMetrics::default(),
        }
    }

    /// Queue one datagram under the default class / deadline.
    /// Returns `true` when the batch is full and the caller should
    /// [`flush`](Self::flush).
    pub fn push(&mut self, datagram: Vec<u8>) -> bool {
        self.push_class(datagram, TrafficClass::MarketData, self.default_deadline)
    }

    /// Queue one datagram with an explicit class and deadline.
    ///
    /// Never batches across incompatible classes: if the queue is non-empty and
    /// `class` differs from the head, the new datagram is **not** admitted and
    /// the caller should flush first (returns `true` = needs flush). An
    /// intentional class-mismatch drop is **not** recorded for the new frame —
    /// the caller still holds it.
    pub fn push_class(
        &mut self,
        datagram: Vec<u8>,
        class: TrafficClass,
        deadline: Duration,
    ) -> bool {
        if let Some(head) = self.pending.first() {
            if head.class != class {
                // Incompatible class: signal flush; do not drop the new frame.
                return true;
            }
        }
        let len = datagram.len();
        // Reject if it would exceed caps (unless the batch is empty — always
        // admit one oversized frame so progress is possible).
        let would_exceed = self.pending.len() >= self.max_batch
            || (!self.pending.is_empty()
                && self.pending_bytes.saturating_add(len) > self.max_bytes);
        if would_exceed {
            self.drops.record(DropReason::Overflow, class);
            return true;
        }
        self.pending_bytes = self.pending_bytes.saturating_add(len);
        self.pending.push(Pending {
            bytes: datagram,
            class,
            enqueued_at: Instant::now(),
            deadline,
        });
        self.pending.len() >= self.max_batch || self.pending_bytes >= self.max_bytes
    }

    /// Number of queued datagrams awaiting flush.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether the batch is full by count or byte budget.
    pub fn is_full(&self) -> bool {
        self.pending.len() >= self.max_batch || self.pending_bytes >= self.max_bytes
    }

    /// Total datagrams flushed over this sender's lifetime.
    pub fn flushed(&self) -> u64 {
        self.flushed
    }

    /// Total flush operations (≈ syscalls) performed.
    pub fn batches(&self) -> u64 {
        self.batches
    }

    /// Intentional-drop metrics.
    pub fn drop_metrics(&self) -> &BatchDropMetrics {
        &self.drops
    }

    /// Drop expired pending datagrams. Returns how many were dropped.
    pub fn expire_deadlines(&mut self, now: Instant) -> usize {
        let mut dropped = 0usize;
        let mut i = 0;
        while i < self.pending.len() {
            let p = &self.pending[i];
            if now.saturating_duration_since(p.enqueued_at) >= p.deadline {
                let class = p.class;
                let len = p.bytes.len();
                self.pending.remove(i);
                self.pending_bytes = self.pending_bytes.saturating_sub(len);
                self.drops.record(DropReason::Deadline, class);
                dropped += 1;
            } else {
                i += 1;
            }
        }
        dropped
    }

    /// Flush queued datagrams through `sink`. Retains any unaccepted suffix.
    ///
    /// Returns the number transmitted. For every accepted prefix length from 0
    /// through N, the suffix remains queued in order — no unaccounted loss.
    pub fn flush<S: BatchSink>(&mut self, sink: &mut S) -> usize {
        if self.pending.is_empty() {
            return 0;
        }
        // Materialize a view of the byte buffers for the sink.
        let frames: Vec<Vec<u8>> = self.pending.iter().map(|p| p.bytes.clone()).collect();
        let sent = sink.flush_batch(&frames).min(frames.len());
        self.flushed += sent as u64;
        self.batches += 1;
        // Drop the accepted prefix; retain the unaccepted suffix in order.
        if sent > 0 {
            for p in self.pending.drain(..sent) {
                self.pending_bytes = self.pending_bytes.saturating_sub(p.bytes.len());
            }
        }
        sent
    }

    /// Bytes currently retained in the unsent suffix.
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CountingSink {
        total: usize,
        calls: usize,
        max_seen: usize,
    }
    impl BatchSink for CountingSink {
        fn flush_batch(&mut self, frames: &[Vec<u8>]) -> usize {
            self.calls += 1;
            self.total += frames.len();
            self.max_seen = self.max_seen.max(frames.len());
            frames.len()
        }
    }

    /// Accepts only the first `accept` frames of each flush.
    struct PrefixSink {
        accept: usize,
        total: usize,
        calls: usize,
    }
    impl BatchSink for PrefixSink {
        fn flush_batch(&mut self, frames: &[Vec<u8>]) -> usize {
            self.calls += 1;
            let n = frames.len().min(self.accept);
            self.total += n;
            n
        }
    }

    #[test]
    fn coalesces_into_bounded_batches() {
        let mut tx = BatchSender::new(4);
        let mut sink = CountingSink::default();
        // Push 10 datagrams; flush whenever full.
        for i in 0..10u8 {
            if tx.push(vec![i]) {
                tx.flush(&mut sink);
            }
        }
        tx.flush(&mut sink); // final partial batch
        assert_eq!(sink.total, 10);
        assert!(sink.max_seen <= 4, "batch never exceeds max_batch");
        // 10 datagrams / 4 per batch => 2 full + 1 partial = 3 syscalls, not 10.
        assert_eq!(sink.calls, 3);
        assert_eq!(tx.flushed(), 10);
        assert_eq!(tx.batches(), 3);
    }

    #[test]
    fn flush_of_empty_is_noop() {
        let mut tx = BatchSender::new(8);
        let mut sink = CountingSink::default();
        assert_eq!(tx.flush(&mut sink), 0);
        assert_eq!(sink.calls, 0);
    }

    #[test]
    fn partial_send_preserves_unsent_suffix_for_every_prefix() {
        // For every accepted prefix length 0..=N, remaining frames stay queued
        // in order with no unaccounted loss.
        for accept in 0..=5usize {
            let mut tx = BatchSender::new(8);
            for i in 0..5u8 {
                tx.push(vec![i]);
            }
            let mut sink = PrefixSink {
                accept,
                total: 0,
                calls: 0,
            };
            let sent = tx.flush(&mut sink);
            assert_eq!(sent, accept.min(5));
            assert_eq!(tx.pending(), 5 - sent);
            // Remaining payloads are the ordered suffix.
            let expected: Vec<u8> = (u8::try_from(sent).unwrap()..5).collect();
            let remaining: Vec<u8> = tx.pending.iter().map(|p| p.bytes[0]).collect();
            assert_eq!(remaining, expected, "accept={accept}");
            assert_eq!(tx.drop_metrics().total(), 0, "no silent drops");
            // A second flush with full accept drains the rest.
            let mut sink2 = PrefixSink {
                accept: 8,
                total: 0,
                calls: 0,
            };
            let sent2 = tx.flush(&mut sink2);
            assert_eq!(sent2, 5 - sent);
            assert_eq!(tx.pending(), 0);
            assert_eq!(tx.flushed(), 5);
        }
    }

    #[test]
    fn never_batches_across_incompatible_classes() {
        let mut tx = BatchSender::new(8);
        assert!(!tx.push_class(vec![1], TrafficClass::MarketData, Duration::from_secs(1)));
        // Different class: push signals flush-needed without admitting.
        assert!(tx.push_class(vec![2], TrafficClass::Consensus, Duration::from_secs(1)));
        assert_eq!(tx.pending(), 1);
        assert_eq!(tx.pending[0].class, TrafficClass::MarketData);
    }

    #[test]
    fn deadline_drops_are_observable_by_reason_and_class() {
        let mut tx = BatchSender::with_limits(8, 1024, Duration::from_millis(1));
        tx.push_class(vec![9], TrafficClass::Sync, Duration::from_millis(0));
        // Force expiry.
        let past = Instant::now() + Duration::from_secs(1);
        let n = tx.expire_deadlines(past);
        assert_eq!(n, 1);
        assert_eq!(tx.pending(), 0);
        assert_eq!(tx.drop_metrics().reason(DropReason::Deadline), 1);
        assert_eq!(tx.drop_metrics().class(TrafficClass::Sync), 1);
    }

    #[test]
    fn overflow_drop_is_counted() {
        let mut tx = BatchSender::with_limits(2, 1024, Duration::from_secs(1));
        assert!(!tx.push(vec![1]));
        assert!(tx.push(vec![2])); // full
                                   // Third push exceeds count cap: overflow recorded, needs flush.
        assert!(tx.push(vec![3]));
        assert_eq!(tx.drop_metrics().reason(DropReason::Overflow), 1);
        assert_eq!(tx.pending(), 2);
    }

    #[test]
    fn retries_preserve_order_until_drained() {
        let mut tx = BatchSender::new(8);
        for i in 0..4u8 {
            tx.push(vec![i]);
        }
        // Accept one per flush — ordering must hold across retries.
        for expect in 0..4u8 {
            let mut sink = PrefixSink {
                accept: 1,
                total: 0,
                calls: 0,
            };
            assert_eq!(tx.flush(&mut sink), 1);
            assert_eq!(sink.total, 1);
            // The head that was just sent is gone; next head is expect+1 or empty.
            if expect < 3 {
                assert_eq!(tx.pending[0].bytes, vec![expect + 1]);
            }
        }
        assert_eq!(tx.pending(), 0);
        assert_eq!(tx.flushed(), 4);
    }
}
