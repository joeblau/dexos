//! Discrete-event scheduler with a monotonic virtual clock.
//!
//! Time is modeled as a logical `u64` nanosecond counter — there is no wall
//! clock, no async runtime, and no sleeping. Events are ordered by
//! `(logical_time_ns, tie_break_seq)`, where `tie_break_seq` is a globally
//! monotonic counter assigned at insertion. This makes the dispatch order a
//! *total* order that is identical for a given sequence of insertions, which is
//! the backbone of deterministic replay.
//!
//! # Invariants
//!
//! - The clock never moves backward: [`Scheduler::pop`] advances `now` to the
//!   dispatched event's time, and inserting an event whose time is in the past
//!   clamps it to `now` (so it dispatches immediately, never before already
//!   dispatched events).
//! - Two events at the same time dispatch in insertion order (FIFO), because
//!   `tie_break_seq` increases with each insertion.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Logical time in nanoseconds.
pub type Time = u64;

/// An event pulled from the scheduler, with the time it was dispatched at and
/// the tie-break sequence it was inserted with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatched<E> {
    /// Logical dispatch time.
    pub time: Time,
    /// Global insertion order used to break ties at equal times.
    pub tie_break: u64,
    /// The user event payload.
    pub event: E,
}

/// Internal heap entry ordered as a min-heap over `(time, tie_break)`.
#[derive(Debug)]
struct Entry<E> {
    time: Time,
    tie_break: u64,
    event: E,
}

impl<E> PartialEq for Entry<E> {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.tie_break == other.tie_break
    }
}
impl<E> Eq for Entry<E> {}

impl<E> Ord for Entry<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so `BinaryHeap` (a max-heap) yields the smallest key first.
        other
            .time
            .cmp(&self.time)
            .then_with(|| other.tie_break.cmp(&self.tie_break))
    }
}
impl<E> PartialOrd for Entry<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A deterministic discrete-event scheduler.
#[derive(Debug)]
pub struct Scheduler<E> {
    heap: BinaryHeap<Entry<E>>,
    seq: u64,
    now: Time,
    dispatched: u64,
}

impl<E> Default for Scheduler<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> Scheduler<E> {
    /// Create an empty scheduler with the clock at time `0`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            seq: 0,
            now: 0,
            dispatched: 0,
        }
    }

    /// The current logical time (the time of the most recently dispatched
    /// event, or `0` before the first dispatch).
    #[must_use]
    pub fn now(&self) -> Time {
        self.now
    }

    /// Number of events still pending.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Total number of events dispatched so far.
    #[must_use]
    pub fn dispatched_count(&self) -> u64 {
        self.dispatched
    }

    /// Schedule `event` at an absolute logical `time`. Times in the past are
    /// clamped to `now`, guaranteeing monotonic dispatch. Returns the assigned
    /// tie-break sequence number.
    pub fn schedule_at(&mut self, time: Time, event: E) -> u64 {
        let tie_break = self.seq;
        self.seq += 1;
        self.heap.push(Entry {
            time: time.max(self.now),
            tie_break,
            event,
        });
        tie_break
    }

    /// Schedule `event` `delay` nanoseconds after `now` (saturating).
    pub fn schedule_after(&mut self, delay: Time, event: E) -> u64 {
        self.schedule_at(self.now.saturating_add(delay), event)
    }

    /// Peek at the time of the next event without dispatching it.
    #[must_use]
    pub fn peek_time(&self) -> Option<Time> {
        self.heap.peek().map(|e| e.time)
    }

    /// Dispatch and remove the next event, advancing the clock to its time.
    pub fn pop(&mut self) -> Option<Dispatched<E>> {
        let entry = self.heap.pop()?;
        // Monotonic: `entry.time >= self.now` because insertion clamps to `now`
        // and the heap always yields the minimum remaining time.
        self.now = entry.time.max(self.now);
        self.dispatched += 1;
        Some(Dispatched {
            time: self.now,
            tie_break: entry.tie_break,
            event: entry.event,
        })
    }
}
