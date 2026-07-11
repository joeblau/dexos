//! Packet batching for the lossy datagram / market-data path.
//!
//! Normal optimized networking first: coalesce many small datagrams into one
//! batched flush (the shape a `sendmmsg(2)` call or an AF_XDP TX ring fills),
//! amortizing syscall overhead. An optional kernel-bypass backend (AF_XDP/DPDK)
//! plugs in behind [`KernelBypassTx`] without becoming a protocol dependency.
//! The batch buffer is bounded — it never grows without limit.

/// Default maximum datagrams coalesced into one batched flush.
pub const DEFAULT_BATCH: usize = 64;

/// A sink that transmits a batch of datagrams in one operation. A real backend
/// wraps `sendmmsg(2)`; tests use a counting mock.
pub trait BatchSink {
    /// Transmit the datagrams. Returns how many were accepted by the OS/NIC.
    fn flush_batch(&mut self, frames: &[Vec<u8>]) -> usize;
}

/// Optional kernel-bypass transmit path (AF_XDP / DPDK). Not enabled by default;
/// provided so measurements can justify it before it is wired in.
pub trait KernelBypassTx {
    /// Push a burst of frames onto the TX ring. Returns how many were enqueued.
    fn tx_burst(&mut self, frames: &[&[u8]]) -> usize;
}

/// Accumulates encoded datagrams and flushes them in bounded batches.
#[derive(Debug)]
pub struct BatchSender {
    max_batch: usize,
    pending: Vec<Vec<u8>>,
    flushed: u64,
    batches: u64,
}

impl BatchSender {
    /// A sender that coalesces up to `max_batch` datagrams per flush.
    pub fn new(max_batch: usize) -> Self {
        let cap = max_batch.max(1);
        Self {
            max_batch: cap,
            pending: Vec::with_capacity(cap),
            flushed: 0,
            batches: 0,
        }
    }

    /// Queue one datagram. Returns `true` when the batch is full and the caller
    /// should [`flush`](Self::flush).
    pub fn push(&mut self, datagram: Vec<u8>) -> bool {
        self.pending.push(datagram);
        self.pending.len() >= self.max_batch
    }

    /// Number of queued datagrams awaiting flush.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether the batch is full.
    pub fn is_full(&self) -> bool {
        self.pending.len() >= self.max_batch
    }

    /// Total datagrams flushed over this sender's lifetime.
    pub fn flushed(&self) -> u64 {
        self.flushed
    }

    /// Total flush operations (≈ syscalls) performed.
    pub fn batches(&self) -> u64 {
        self.batches
    }

    /// Flush all queued datagrams through `sink` in one batched operation.
    /// Returns the number transmitted.
    pub fn flush<S: BatchSink>(&mut self, sink: &mut S) -> usize {
        if self.pending.is_empty() {
            return 0;
        }
        let sent = sink.flush_batch(&self.pending);
        self.flushed += sent as u64;
        self.batches += 1;
        self.pending.clear();
        sent
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
}
