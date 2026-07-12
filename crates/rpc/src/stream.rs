//! Binary streaming subscription protocol.
//!
//! Every channel is a [`Topic`]; every emitted [`StreamEvent`] carries a
//! monotonically increasing [`SequenceNumber`] so a consumer can detect a gap
//! and recover via a snapshot plus subsequent deltas. Fan-out uses a **bounded**
//! `tokio::broadcast` channel so a slow subscriber can never block a producer or
//! grow memory without bound — it is instead lagged (lossy) and recovers.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use types::{AccountId, MarketId, SequenceNumber};

use crate::error::RpcError;
use crate::session::session_may_read;
use crate::wire::{
    Book, BookDelta, Checkpoint, ExecutionReceipt, Funding, MarkPrice, MarketLifecycleEvent,
    NetworkStatus, OraclePrice, Order, Position, Trade,
};

/// A subscription channel. Account-scoped topics are private and gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Topic {
    /// Order-book deltas for a market (public).
    Book(MarketId),
    /// Trade prints for a market (public).
    Trades(MarketId),
    /// Mark-price updates for a market (public).
    MarkPrice(MarketId),
    /// Oracle-price updates for a market (public).
    OraclePrice(MarketId),
    /// Funding updates for a market (public).
    Funding(MarketId),
    /// Position updates for an account (private).
    Positions(AccountId),
    /// Order updates for an account (private).
    Orders(AccountId),
    /// Execution receipts for an account (private).
    ExecutionReceipts(AccountId),
    /// Finalized checkpoint headers (public).
    Checkpoints,
    /// Market lifecycle transitions (public).
    MarketLifecycle,
    /// Peer / network health (public).
    NetworkHealth,
}

impl Topic {
    /// The owning account for a private topic, or `None` for public topics.
    pub fn account(self) -> Option<AccountId> {
        match self {
            Topic::Positions(a) | Topic::Orders(a) | Topic::ExecutionReceipts(a) => Some(a),
            _ => None,
        }
    }

    /// Whether the topic is account-private and must be session-gated.
    pub fn is_private(self) -> bool {
        self.account().is_some()
    }
}

/// Whether an event is a full snapshot (a recovery baseline) or an incremental
/// delta relative to the previous sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A self-contained snapshot; resets a consumer's sequence baseline.
    Snapshot,
    /// An incremental update relative to the previous sequence.
    Delta,
}

/// The payload carried by a [`StreamEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamPayload {
    /// A full order-book snapshot.
    Book(Book),
    /// An incremental book update.
    BookDelta(BookDelta),
    /// A trade print.
    Trade(Trade),
    /// A mark-price update.
    MarkPrice(MarkPrice),
    /// An oracle-price update.
    OraclePrice(OraclePrice),
    /// A funding update.
    Funding(Funding),
    /// A position update.
    Position(Position),
    /// An order update.
    Order(Order),
    /// An execution receipt.
    ExecutionReceipt(ExecutionReceipt),
    /// A checkpoint header.
    Checkpoint(Checkpoint),
    /// A market lifecycle transition.
    MarketLifecycle(MarketLifecycleEvent),
    /// A peer / network health snapshot.
    NetworkHealth(NetworkStatus),
}

/// A sequenced stream event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamEvent {
    /// The topic the event belongs to.
    pub topic: Topic,
    /// Monotonic per-topic sequence number.
    pub sequence: SequenceNumber,
    /// Snapshot vs delta.
    pub kind: EventKind,
    /// The event body.
    pub payload: StreamPayload,
}

/// A detected gap in a stream: `got` arrived where `expected` was due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// The sequence number that was expected next.
    pub expected: u64,
    /// The sequence number that actually arrived.
    pub got: u64,
}

/// The result of observing a sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// A new, contiguous event was applied.
    Applied,
    /// An already-seen (duplicate or reordered-old) sequence; safely ignored.
    Duplicate,
}

/// Per-consumer sequence state for gap detection and idempotent (duplicate-safe)
/// application.
#[derive(Debug, Clone, Copy, Default)]
pub struct SequenceTracker {
    last: Option<u64>,
}

impl SequenceTracker {
    /// A fresh tracker with no observed sequence.
    pub fn new() -> Self {
        SequenceTracker { last: None }
    }

    /// Adopt `seq` as a new baseline (used when a snapshot is applied). Any
    /// prior gap is cleared.
    pub fn reset(&mut self, seq: SequenceNumber) {
        self.last = Some(seq.get());
    }

    /// The last contiguous sequence applied.
    pub fn last(&self) -> Option<SequenceNumber> {
        self.last.map(SequenceNumber::new)
    }

    /// Observe the next delta sequence. Returns [`Progress::Applied`] for a
    /// contiguous advance, [`Progress::Duplicate`] for a repeated/old sequence
    /// (idempotent), or a [`Gap`] when one or more sequences are missing. On a
    /// gap the baseline is not advanced, so the consumer can trigger recovery.
    pub fn observe(&mut self, seq: SequenceNumber) -> Result<Progress, Gap> {
        let s = seq.get();
        match self.last {
            None => {
                self.last = Some(s);
                Ok(Progress::Applied)
            }
            Some(l) if s <= l => Ok(Progress::Duplicate),
            Some(l) if s == l + 1 => {
                self.last = Some(s);
                Ok(Progress::Applied)
            }
            Some(l) => Err(Gap {
                expected: l + 1,
                got: s,
            }),
        }
    }
}

/// Delivery guarantee for a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    /// Ordered with gap detection; the consumer recovers on a gap/lag.
    Reliable,
    /// Best-effort: lagged/dropped events are silently skipped.
    Lossy,
}

/// An error while receiving from a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// A gap was detected between contiguous deltas; recover from `from`.
    #[error("gap detected: expected {expected}, got {got}")]
    Gap {
        /// The expected next sequence.
        expected: u64,
        /// The sequence that actually arrived.
        got: u64,
    },
    /// The consumer fell behind the bounded buffer and skipped `0` events count
    /// unknown precisely; recover from the last applied sequence.
    #[error("subscriber lagged by {0} events")]
    Lagged(u64),
    /// No event is currently buffered.
    #[error("no event available")]
    Empty,
    /// The channel has been closed (all producers dropped).
    #[error("stream closed")]
    Closed,
}

/// The outcome of a recovery request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// The missing events were still within the retained window; apply these
    /// deltas in order to catch up.
    Deltas(Vec<StreamEvent>),
    /// The gap is beyond the retained window; the consumer must fetch a fresh
    /// snapshot and reset its baseline.
    SnapshotRequired,
}

struct TopicChannel {
    sender: broadcast::Sender<StreamEvent>,
    next_seq: u64,
    history: VecDeque<StreamEvent>,
    window: usize,
}

impl TopicChannel {
    fn new(capacity: usize) -> Self {
        let (sender, _rx) = broadcast::channel(capacity);
        TopicChannel {
            sender,
            next_seq: 0,
            history: VecDeque::with_capacity(capacity),
            window: capacity,
        }
    }
}

/// Default ceiling on distinct live topics in a [`StreamHub`].
///
/// Bounds the hub's topic map so a flood of distinct topic keys cannot grow
/// memory without limit. Idle topics are GC'd first; if still at capacity the
/// topic with the lowest live receiver count is evicted.
pub const DEFAULT_MAX_TOPICS: usize = 4096;

/// A bounded fan-out registry mapping topics to broadcast channels, with a
/// retained per-topic history window for delta backfill recovery.
///
/// The number of distinct topics is capped at [`StreamHub::max_topics`] (default
/// [`DEFAULT_MAX_TOPICS`]). Creating a topic past the cap GCs idle channels and,
/// if still full, evicts the topic with the fewest live receivers so the map
/// never grows unbounded.
pub struct StreamHub {
    capacity: usize,
    max_topics: usize,
    channels: Mutex<HashMap<Topic, TopicChannel>>,
}

impl StreamHub {
    /// Create a hub whose per-topic broadcast buffer and recovery window each
    /// hold `capacity` events, with a topic map capped at [`DEFAULT_MAX_TOPICS`].
    /// `capacity` is clamped to at least 1.
    pub fn new(capacity: usize) -> Self {
        Self::with_limits(capacity, DEFAULT_MAX_TOPICS)
    }

    /// Create a hub with an explicit per-topic buffer capacity and a hard cap
    /// on the number of distinct topics. Both limits are clamped to at least 1.
    pub fn with_limits(capacity: usize, max_topics: usize) -> Self {
        StreamHub {
            capacity: capacity.max(1),
            max_topics: max_topics.max(1),
            channels: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe to a public topic with a delivery guarantee. Private topics
    /// must go through [`StreamHub::subscribe_private`].
    pub fn subscribe(
        &self,
        topic: Topic,
        reliability: Reliability,
    ) -> Result<Subscription, RpcError> {
        if topic.is_private() {
            return Err(RpcError::Unauthorized);
        }
        Ok(self.subscribe_unchecked(topic, reliability))
    }

    /// Subscribe to a private (account-scoped) topic. The session, bound to
    /// `bound_account` at authorization time, must own the topic and be
    /// unexpired at `now`.
    pub fn subscribe_private(
        &self,
        topic: Topic,
        bound_account: AccountId,
        session_expiry: u64,
        now: u64,
        reliability: Reliability,
    ) -> Result<Subscription, RpcError> {
        match topic.account() {
            Some(owner) => {
                session_may_read(bound_account, owner, session_expiry, now)?;
                Ok(self.subscribe_unchecked(topic, reliability))
            }
            // A public topic through the private path is allowed.
            None => Ok(self.subscribe_unchecked(topic, reliability)),
        }
    }

    fn subscribe_unchecked(&self, topic: Topic, reliability: Reliability) -> Subscription {
        let mut guard = self.lock();
        let entry = Self::topic_entry(&mut guard, topic, self.capacity, self.max_topics);
        Subscription {
            topic,
            rx: entry.sender.subscribe(),
            tracker: SequenceTracker::new(),
            reliability,
        }
    }

    /// Publish a snapshot event, assigning the next sequence for the topic.
    pub fn publish_snapshot(&self, topic: Topic, payload: StreamPayload) -> SequenceNumber {
        self.publish(topic, EventKind::Snapshot, payload)
    }

    /// Publish a delta event, assigning the next sequence for the topic.
    pub fn publish_delta(&self, topic: Topic, payload: StreamPayload) -> SequenceNumber {
        self.publish(topic, EventKind::Delta, payload)
    }

    fn publish(&self, topic: Topic, kind: EventKind, payload: StreamPayload) -> SequenceNumber {
        let mut guard = self.lock();
        let entry = Self::topic_entry(&mut guard, topic, self.capacity, self.max_topics);
        entry.next_seq = entry.next_seq.saturating_add(1);
        let sequence = SequenceNumber::new(entry.next_seq);
        let event = StreamEvent {
            topic,
            sequence,
            kind,
            payload,
        };
        if entry.history.len() >= entry.window {
            entry.history.pop_front();
        }
        entry.history.push_back(event.clone());
        // A send with no receivers returns Err; that is not a failure here.
        let _ = entry.sender.send(event);
        sequence
    }

    /// Attempt to backfill the events after `from_seq` for `topic`. Returns the
    /// retained deltas if the gap is within the window, or
    /// [`Recovery::SnapshotRequired`] if the consumer has fallen too far behind.
    pub fn recover(&self, topic: Topic, from_seq: u64) -> Recovery {
        let guard = self.lock();
        let Some(entry) = guard.get(&topic) else {
            return Recovery::SnapshotRequired;
        };
        let Some(front) = entry.history.front() else {
            return Recovery::SnapshotRequired;
        };
        let earliest = front.sequence.get();
        // We can backfill iff the next needed sequence is still retained.
        if earliest <= from_seq.saturating_add(1) {
            let deltas: Vec<StreamEvent> = entry
                .history
                .iter()
                .filter(|e| e.sequence.get() > from_seq)
                .cloned()
                .collect();
            Recovery::Deltas(deltas)
        } else {
            Recovery::SnapshotRequired
        }
    }

    /// The number of live subscribers for a topic.
    pub fn subscriber_count(&self, topic: Topic) -> usize {
        let guard = self.lock();
        guard.get(&topic).map_or(0, |c| c.sender.receiver_count())
    }

    /// The configured per-topic buffer / window capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The hard cap on distinct topics this hub will retain.
    pub fn max_topics(&self) -> usize {
        self.max_topics
    }

    /// Number of distinct topics currently retained (for tests / metrics).
    pub fn topic_count(&self) -> usize {
        self.lock().len()
    }

    /// Obtain (or create) the channel for `topic`, GCing idle topics and
    /// never growing the map past `max_topics`.
    ///
    /// 1. If `topic` already exists, return it.
    /// 2. If at capacity, drop topics with zero live receivers.
    /// 3. If still at capacity, evict the topic with the lowest
    ///    `receiver_count` (ties broken by first match) until there is room.
    fn topic_entry<'a>(
        channels: &'a mut HashMap<Topic, TopicChannel>,
        topic: Topic,
        capacity: usize,
        max_topics: usize,
    ) -> &'a mut TopicChannel {
        if channels.contains_key(&topic) {
            return channels.get_mut(&topic).expect("topic just checked");
        }
        if channels.len() >= max_topics {
            // Prefer reclaiming idle (zero-receiver) topics first.
            channels.retain(|_, ch| ch.sender.receiver_count() > 0);
        }
        while channels.len() >= max_topics {
            // Evict the least-subscribed topic so the map never grows past max.
            let victim = channels
                .iter()
                .min_by_key(|(_, ch)| ch.sender.receiver_count())
                .map(|(t, _)| *t);
            match victim {
                Some(t) => {
                    channels.remove(&t);
                }
                None => break,
            }
        }
        channels
            .entry(topic)
            .or_insert_with(|| TopicChannel::new(capacity))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Topic, TopicChannel>> {
        // The lock is only ever held for short, panic-free critical sections, so
        // poisoning cannot occur; recover the guard either way rather than panic.
        self.channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A live subscription to one topic. Applies gap detection and duplicate
/// suppression for reliable delivery; skips lagged events for lossy delivery.
pub struct Subscription {
    topic: Topic,
    rx: broadcast::Receiver<StreamEvent>,
    tracker: SequenceTracker,
    reliability: Reliability,
}

impl Subscription {
    /// The subscribed topic.
    pub fn topic(&self) -> Topic {
        self.topic
    }

    /// The last contiguous sequence this subscription applied.
    pub fn last_sequence(&self) -> Option<SequenceNumber> {
        self.tracker.last()
    }

    /// Receive the next event asynchronously, applying the delivery policy.
    pub async fn recv(&mut self) -> Result<StreamEvent, StreamError> {
        loop {
            match self.rx.recv().await {
                Ok(event) => {
                    if let Some(out) = self.apply(event)? {
                        return Ok(out);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    if matches!(self.reliability, Reliability::Reliable) {
                        return Err(StreamError::Lagged(n));
                    }
                    // Lossy: skip the lost window and keep going.
                }
                Err(broadcast::error::RecvError::Closed) => return Err(StreamError::Closed),
            }
        }
    }

    /// Non-blocking receive of the next event, applying the delivery policy.
    /// Returns [`StreamError::Empty`] when nothing is buffered.
    pub fn try_recv(&mut self) -> Result<StreamEvent, StreamError> {
        loop {
            match self.rx.try_recv() {
                Ok(event) => {
                    if let Some(out) = self.apply(event)? {
                        return Ok(out);
                    }
                }
                Err(broadcast::error::TryRecvError::Empty) => return Err(StreamError::Empty),
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    if matches!(self.reliability, Reliability::Reliable) {
                        return Err(StreamError::Lagged(n));
                    }
                }
                Err(broadcast::error::TryRecvError::Closed) => return Err(StreamError::Closed),
            }
        }
    }

    /// Apply an event to the tracker. Returns `Ok(Some(event))` to yield it,
    /// `Ok(None)` to suppress a duplicate and keep receiving, or a
    /// [`StreamError::Gap`] for reliable delivery on a missing sequence.
    fn apply(&mut self, event: StreamEvent) -> Result<Option<StreamEvent>, StreamError> {
        match self.reliability {
            Reliability::Lossy => Ok(Some(event)),
            Reliability::Reliable => {
                if matches!(event.kind, EventKind::Snapshot) {
                    self.tracker.reset(event.sequence);
                    return Ok(Some(event));
                }
                match self.tracker.observe(event.sequence) {
                    Ok(Progress::Applied) => Ok(Some(event)),
                    Ok(Progress::Duplicate) => Ok(None),
                    Err(gap) => Err(StreamError::Gap {
                        expected: gap.expected,
                        got: gap.got,
                    }),
                }
            }
        }
    }
}
