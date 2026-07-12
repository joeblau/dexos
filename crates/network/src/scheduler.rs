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
//! Each class is bounded by **both** a frame count *and* a byte ceiling
//! ([`PriorityScheduler::with_byte_cap`]). A frame count alone cannot bound
//! memory — 1,024 frames of up to [`codec::MAX_FRAME_PAYLOAD`] (16 MiB) each is
//! 16 GiB per class — so accumulation is additionally capped by the total
//! payload bytes retained per class. A lone frame is always admitted into an
//! empty class (even if it alone exceeds the byte cap) so forward progress and
//! the reliable, never-shed inbound path can never wedge.
//!
//! This type is deliberately synchronous and allocation-transparent so it can be
//! exercised by deterministic property tests; the async wiring lives in
//! [`crate::channel`].

use std::collections::VecDeque;

use codec::{Frame, TrafficClass};

use crate::error::TransportError;

/// Number of priority classes (P0..P8 inclusive).
pub const NUM_CLASSES: usize = 9;

/// The byte cost charged against the queue for one frame: its retained payload
/// bytes. Frame-struct overhead is bounded separately by the per-class frame
/// count, so payload length is the memory dimension worth metering.
pub(crate) fn frame_cost(frame: &Frame) -> usize {
    frame.payload.len()
}

/// A strict-priority, bounded, multi-class frame queue.
#[derive(Debug)]
pub struct PriorityScheduler {
    /// One FIFO per class; index 0 == P0 (highest priority).
    queues: [VecDeque<Frame>; NUM_CLASSES],
    /// Maximum frames retained per class.
    capacity_per_class: usize,
    /// Maximum payload bytes retained per class (accumulation ceiling).
    capacity_bytes_per_class: usize,
    /// Total frames currently buffered across all classes.
    len: usize,
    /// Payload bytes currently buffered per class.
    class_bytes: [usize; NUM_CLASSES],
    /// Total payload bytes currently buffered across all classes.
    bytes: usize,
    /// High-water mark of [`bytes`](Self::bytes) over this scheduler's life.
    bytes_high_water: usize,
}

impl PriorityScheduler {
    /// Create a scheduler bounding each class to `capacity_per_class` frames and
    /// leaving the per-class byte ceiling unbounded ([`usize::MAX`]).
    /// A capacity of zero rejects every enqueue (useful only in tests).
    pub fn new(capacity_per_class: usize) -> Self {
        Self::with_byte_cap(capacity_per_class, usize::MAX)
    }

    /// Create a scheduler bounding each class to `capacity_per_class` frames
    /// **and** `capacity_bytes_per_class` retained payload bytes.
    pub fn with_byte_cap(capacity_per_class: usize, capacity_bytes_per_class: usize) -> Self {
        Self {
            queues: std::array::from_fn(|_| VecDeque::new()),
            capacity_per_class,
            capacity_bytes_per_class,
            len: 0,
            class_bytes: [0; NUM_CLASSES],
            bytes: 0,
            bytes_high_water: 0,
        }
    }

    /// Per-class frame capacity.
    pub fn capacity_per_class(&self) -> usize {
        self.capacity_per_class
    }

    /// Per-class byte ceiling.
    pub fn capacity_bytes_per_class(&self) -> usize {
        self.capacity_bytes_per_class
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

    /// Payload bytes currently buffered in a single class.
    pub fn class_bytes(&self, class: TrafficClass) -> usize {
        self.class_bytes[usize::from(class.priority())]
    }

    /// Total payload bytes currently buffered across all classes.
    pub fn queued_bytes(&self) -> usize {
        self.bytes
    }

    /// High-water mark of [`queued_bytes`](Self::queued_bytes) over this
    /// scheduler's life.
    pub fn queued_bytes_high_water(&self) -> usize {
        self.bytes_high_water
    }

    /// Whether a frame in `class` costing `cost` bytes could be admitted right
    /// now, mirroring [`enqueue`](Self::enqueue)'s accept rule exactly.
    fn can_admit(&self, idx: usize, cost: usize) -> bool {
        let Some(queue) = self.queues.get(idx) else {
            return false;
        };
        if queue.len() >= self.capacity_per_class {
            return false;
        }
        // Always admit at least one frame into an empty class so a lone frame
        // larger than the byte cap still makes progress and the reliable,
        // never-shed inbound path cannot wedge.
        if queue.is_empty() {
            return true;
        }
        self.class_bytes[idx].saturating_add(cost) <= self.capacity_bytes_per_class
    }

    /// Whether `frame` could be enqueued right now without backpressure.
    pub fn has_capacity_for(&self, frame: &Frame) -> bool {
        self.can_admit(usize::from(frame.class.priority()), frame_cost(frame))
    }

    /// Enqueue a frame into its class queue.
    ///
    /// Returns [`TransportError::Backpressure`] if that class is already at its
    /// frame-count or byte ceiling; the scheduler's memory footprint is
    /// therefore bounded by `NUM_CLASSES * capacity_bytes_per_class` payload
    /// bytes (plus at most one in-flight frame per class).
    pub fn enqueue(&mut self, frame: Frame) -> Result<(), TransportError> {
        let idx = usize::from(frame.class.priority());
        let cost = frame_cost(&frame);
        // `priority()` is always 0..=8 for a valid `TrafficClass`, so `idx` is
        // in range; `can_admit` guards defensively rather than indexing out of
        // bounds.
        if !self.can_admit(idx, cost) {
            return Err(TransportError::Backpressure { class: frame.class });
        }
        let Some(queue) = self.queues.get_mut(idx) else {
            return Err(TransportError::Backpressure { class: frame.class });
        };
        queue.push_back(frame);
        self.len += 1;
        self.class_bytes[idx] = self.class_bytes[idx].saturating_add(cost);
        self.bytes = self.bytes.saturating_add(cost);
        self.bytes_high_water = self.bytes_high_water.max(self.bytes);
        Ok(())
    }

    /// Remove and return the highest-priority buffered frame, if any.
    ///
    /// Classes are scanned from P0 to P8; the first non-empty class yields its
    /// oldest frame. Lower-priority frames are never returned while a
    /// higher-priority frame is pending.
    pub fn dequeue(&mut self) -> Option<Frame> {
        for (idx, queue) in self.queues.iter_mut().enumerate() {
            if let Some(frame) = queue.pop_front() {
                let cost = frame_cost(&frame);
                self.len -= 1;
                self.class_bytes[idx] = self.class_bytes[idx].saturating_sub(cost);
                self.bytes = self.bytes.saturating_sub(cost);
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
    fn byte_cap_bounds_class_accumulation_independently_of_frame_count() {
        // Generous frame count, tight byte cap: accumulation is bounded by bytes.
        let mut s = PriorityScheduler::with_byte_cap(1024, 250);
        let hundred = || Frame {
            class: TrafficClass::MarketData,
            msg_type: 0,
            sequence: 0,
            payload: vec![0u8; 100],
        };
        // Two 100-byte frames fit (200 <= 250); a third would be 300 > 250.
        s.enqueue(hundred()).unwrap();
        s.enqueue(hundred()).unwrap();
        assert_eq!(s.class_bytes(TrafficClass::MarketData), 200);
        assert_eq!(s.queued_bytes(), 200);
        let err = s.enqueue(hundred()).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Backpressure {
                class: TrafficClass::MarketData
            }
        ));
        // The frame count is well under the 1024 cap: bytes, not count, rejected.
        assert_eq!(s.class_len(TrafficClass::MarketData), 2);

        // Draining frees bytes and the high-water mark is retained.
        let f = s.dequeue().unwrap();
        assert_eq!(f.payload.len(), 100);
        assert_eq!(s.queued_bytes(), 100);
        assert_eq!(s.queued_bytes_high_water(), 200);
        // With headroom again, a further 100-byte frame is admitted.
        s.enqueue(hundred()).unwrap();
        assert_eq!(s.queued_bytes(), 200);
    }

    #[test]
    fn empty_class_always_admits_one_oversized_frame() {
        // A byte cap smaller than a single frame must not wedge the queue: a lone
        // frame is always admitted into an empty class.
        let mut s = PriorityScheduler::with_byte_cap(1024, 10);
        let big = Frame {
            class: TrafficClass::Sync,
            msg_type: 0,
            sequence: 0,
            payload: vec![0u8; 1000],
        };
        assert!(s.has_capacity_for(&big));
        s.enqueue(big).unwrap();
        assert_eq!(s.queued_bytes(), 1000);
        // But a second frame while over the byte cap is rejected.
        let more = Frame {
            class: TrafficClass::Sync,
            msg_type: 0,
            sequence: 1,
            payload: vec![0u8; 5],
        };
        assert!(!s.has_capacity_for(&more));
        assert!(matches!(
            s.enqueue(more),
            Err(TransportError::Backpressure {
                class: TrafficClass::Sync
            })
        ));
    }

    #[test]
    fn byte_caps_are_independent_per_class() {
        // Filling one class's byte cap must not affect a different class.
        let mut s = PriorityScheduler::with_byte_cap(1024, 150);
        let payload = |class| Frame {
            class,
            msg_type: 0,
            sequence: 0,
            payload: vec![7u8; 100],
        };
        // MarketData: the first 100-byte frame fits; a second (200 > 150) is
        // rejected on the byte ceiling.
        s.enqueue(payload(TrafficClass::MarketData)).unwrap();
        assert!(s.enqueue(payload(TrafficClass::MarketData)).is_err());
        // A different, higher-priority class has its own independent byte budget
        // and is unaffected by MarketData's saturation.
        s.enqueue(payload(TrafficClass::Consensus)).unwrap();
        assert_eq!(s.class_bytes(TrafficClass::Consensus), 100);
        assert_eq!(s.class_bytes(TrafficClass::MarketData), 100);
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
