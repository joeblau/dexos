//! Strict-priority scheduler with bounded per-class queues.
//!
//! Nine traffic classes (P0 consensus .. P8 sync) each get an independent
//! bounded FIFO queue. [`PriorityScheduler::dequeue`] always drains the
//! highest-priority non-empty class first, so a saturated low-priority backlog
//! (market data, historical sync) can never starve or delay P0 consensus
//! traffic. Enqueue into a full class fails fast with
//! [`TransportError::Backpressure`] — queues never grow past their configured
//! capacity, bounding memory under overload.
//!
//! This type is deliberately synchronous and allocation-transparent so it can be
//! exercised by deterministic property tests; the async wiring lives in
//! [`crate::channel`].

use std::collections::VecDeque;

use codec::{Frame, TrafficClass};

use crate::error::TransportError;

/// Number of priority classes (P0..P8 inclusive).
pub const NUM_CLASSES: usize = 9;

/// A strict-priority, bounded, multi-class frame queue.
#[derive(Debug)]
pub struct PriorityScheduler {
    /// One FIFO per class; index 0 == P0 (highest priority).
    queues: [VecDeque<Frame>; NUM_CLASSES],
    /// Maximum frames retained per class.
    capacity_per_class: usize,
    /// Total frames currently buffered across all classes.
    len: usize,
}

impl PriorityScheduler {
    /// Create a scheduler bounding each class to `capacity_per_class` frames.
    /// A capacity of zero rejects every enqueue (useful only in tests).
    pub fn new(capacity_per_class: usize) -> Self {
        Self {
            queues: std::array::from_fn(|_| VecDeque::new()),
            capacity_per_class,
            len: 0,
        }
    }

    /// Per-class capacity.
    pub fn capacity_per_class(&self) -> usize {
        self.capacity_per_class
    }

    /// Total frames currently buffered across all classes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether all class queues are empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Frames currently buffered in a single class.
    pub fn class_len(&self, class: TrafficClass) -> usize {
        self.queues[usize::from(class.priority())].len()
    }

    /// Enqueue a frame into its class queue.
    ///
    /// Returns [`TransportError::Backpressure`] if that class is already at
    /// capacity; the scheduler's memory footprint is therefore bounded by
    /// `NUM_CLASSES * capacity_per_class` frames.
    pub fn enqueue(&mut self, frame: Frame) -> Result<(), TransportError> {
        let idx = usize::from(frame.class.priority());
        // `priority()` is always 0..=8 for a valid `TrafficClass`, so `idx` is
        // in range; guard defensively rather than index out of bounds.
        let queue = self
            .queues
            .get_mut(idx)
            .ok_or(TransportError::Backpressure { class: frame.class })?;
        if queue.len() >= self.capacity_per_class {
            return Err(TransportError::Backpressure { class: frame.class });
        }
        queue.push_back(frame);
        self.len += 1;
        Ok(())
    }

    /// Remove and return the highest-priority buffered frame, if any.
    ///
    /// Classes are scanned from P0 to P8; the first non-empty class yields its
    /// oldest frame. Lower-priority frames are never returned while a
    /// higher-priority frame is pending.
    pub fn dequeue(&mut self) -> Option<Frame> {
        for queue in &mut self.queues {
            if let Some(frame) = queue.pop_front() {
                self.len -= 1;
                return Some(frame);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(class: TrafficClass, seq: u64) -> Frame {
        Frame {
            class,
            msg_type: 0,
            sequence: seq,
            payload: vec![class.priority()],
        }
    }

    #[test]
    fn traffic_class_ordinal_ordering_is_total_and_stable() {
        let order = [
            TrafficClass::Consensus,
            TrafficClass::RiskReducing,
            TrafficClass::Liquidation,
            TrafficClass::NewOrder,
            TrafficClass::ExecutionReceipt,
            TrafficClass::OracleCert,
            TrafficClass::Checkpoint,
            TrafficClass::MarketData,
            TrafficClass::Sync,
        ];
        // Priorities are exactly 0..=8, strictly increasing (P0 highest).
        for (i, c) in order.iter().enumerate() {
            assert_eq!(usize::from(c.priority()), i);
        }
        for w in order.windows(2) {
            assert!(w[0] < w[1], "ordering must be total and strict");
        }
        // Round-trips through the raw byte encoding.
        for c in order {
            assert_eq!(TrafficClass::from_u8(c.priority()), Some(c));
        }
    }

    #[test]
    fn dequeue_is_strict_priority() {
        let mut s = PriorityScheduler::new(1024);
        // Enqueue a large low-priority backlog first...
        for i in 0..500 {
            s.enqueue(frame(TrafficClass::MarketData, i)).unwrap();
        }
        // ...then a single P0 consensus vote.
        s.enqueue(frame(TrafficClass::Consensus, 9999)).unwrap();

        // The consensus vote must come out first, ahead of the entire backlog.
        let first = s.dequeue().unwrap();
        assert_eq!(first.class, TrafficClass::Consensus);
        assert_eq!(first.sequence, 9999);

        // Everything after it is the market-data backlog, in FIFO order.
        for i in 0..500 {
            let f = s.dequeue().unwrap();
            assert_eq!(f.class, TrafficClass::MarketData);
            assert_eq!(f.sequence, i);
        }
        assert!(s.dequeue().is_none());
    }

    #[test]
    fn bounded_queue_applies_backpressure() {
        let mut s = PriorityScheduler::new(4);
        for i in 0..4 {
            s.enqueue(frame(TrafficClass::NewOrder, i)).unwrap();
        }
        // The fifth enqueue into a full class is rejected, not buffered.
        let err = s.enqueue(frame(TrafficClass::NewOrder, 4)).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Backpressure {
                class: TrafficClass::NewOrder
            }
        ));
        assert_eq!(s.class_len(TrafficClass::NewOrder), 4);
        // A different, higher-priority class is unaffected by the full backlog.
        s.enqueue(frame(TrafficClass::Consensus, 0)).unwrap();
        assert_eq!(s.dequeue().unwrap().class, TrafficClass::Consensus);
    }

    #[test]
    fn p0_never_starved_under_saturation_property() {
        // Deterministic LCG drives an adversarial interleave of enqueues and
        // dequeues; we assert the invariant "no lower-priority frame is
        // dequeued while a higher-priority frame is pending".
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        let cap = 64;
        let mut s = PriorityScheduler::new(cap);

        for _ in 0..20_000 {
            let r = next();
            if r & 1 == 0 {
                // Enqueue a random class (ignore backpressure rejections).
                let classes = u64::try_from(NUM_CLASSES).unwrap();
                let class_byte = u8::try_from((r >> 8) % classes).unwrap_or(0);
                if let Some(class) = TrafficClass::from_u8(class_byte) {
                    let _ = s.enqueue(frame(class, r));
                }
            } else if let Some(f) = s.dequeue() {
                // The dequeued frame must be from the highest-priority non-empty
                // class at this instant: no higher-priority class may hold a
                // pending frame.
                let taken = f.class.priority();
                for p in 0..taken {
                    let c = TrafficClass::from_u8(p).unwrap();
                    assert_eq!(
                        s.class_len(c),
                        0,
                        "class {c:?} still had frames when a lower-priority frame was dequeued",
                    );
                }
            }
        }
    }
}
