//! Binary streaming subscription protocol.
//!
//! Every channel is a [`Topic`]; every emitted [`StreamEvent`] carries a
//! monotonically increasing [`SequenceNumber`] so a consumer can detect a gap
//! and recover via a snapshot plus subsequent deltas.
//!
//! # Fan-out design
//!
//! * Events are published as [`Arc`]`<`[`StreamEvent`]`>` so allocations do not
//!   scale with subscriber count (broadcast clones the Arc, not the payload).
//! * Per-topic history and broadcast capacity are **byte-bounded**, not merely
//!   event-count bounded, so one large event cannot exhaust the process.
//! * Topic state is sharded across independent mutexes so a hot topic cannot
//!   block publish/subscribe on unrelated topics.
//! * Slow subscribers are lagged (lossy or reliable-with-gap); every shed is
//!   observable via [`StreamError::Lagged`] / [`StreamError::Gap`] /
//!   [`Recovery::SnapshotRequired`] / [`StreamStats`].

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use types::{AccountId, MarketId, SequenceNumber};

use crate::error::RpcError;
use crate::session::{authorize_private_topic, session_may_read, SessionLookup};
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

/// Shared, immutable published event. Fan-out clones the [`Arc`], not the body.
pub type SharedEvent = Arc<StreamEvent>;

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
    /// The consumer fell behind the bounded buffer and skipped events; recover
    /// from the last applied sequence (or fetch a snapshot).
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

/// Observable shed / occupancy counters for a topic (and process-wide via
/// `StreamHub::stats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamStats {
    /// Events published.
    pub published: u64,
    /// Times a publish found zero live receivers (not an error).
    pub no_receivers: u64,
    /// Times history dropped the oldest event to stay within the byte budget.
    pub history_shed: u64,
    /// Current history occupancy in bytes.
    pub history_bytes: usize,
    /// Current number of live subscribers.
    pub subscribers: usize,
}

/// Default ceiling on distinct live topics in a [`StreamHub`].
pub const DEFAULT_MAX_TOPICS: usize = 4096;

/// Default per-topic history / broadcast byte budget (1 MiB).
pub const DEFAULT_TOPIC_BYTE_BUDGET: usize = 1024 * 1024;

/// Default broadcast channel length in events (still required by
/// `tokio::broadcast`; the byte budget is the memory ceiling).
pub const DEFAULT_BROADCAST_CAPACITY: usize = 256;

/// Number of independent topic-map shards. Power of two for cheap masking.
const SHARD_COUNT: usize = 16;

/// Estimate the resident size of an event for budget accounting. Prefers a
/// cheap structural estimate over a full encode so publish stays allocation-
/// light; the estimate is a lower bound that still bounds large payloads.
fn estimate_event_bytes(event: &StreamEvent) -> usize {
    // Base envelope + a payload-specific floor. Nested Vec lengths dominate.
    let payload = match &event.payload {
        StreamPayload::Book(b) => 64 + (b.bids.len() + b.asks.len()) * 32,
        StreamPayload::BookDelta(_) => 48,
        StreamPayload::Trade(_) => 64,
        StreamPayload::MarkPrice(_) => 48,
        StreamPayload::OraclePrice(_) => 64,
        StreamPayload::Funding(_) => 48,
        StreamPayload::Position(_) => 64,
        StreamPayload::Order(_) => 96,
        StreamPayload::ExecutionReceipt(r) => 128 + r.fills.len() * 48,
        StreamPayload::Checkpoint(c) => {
            96 + c
                .quorum_certificate
                .as_ref()
                .map_or(0, |q| q.signatures.len() * 64)
        }
        StreamPayload::MarketLifecycle(_) => 64,
        StreamPayload::NetworkHealth(_) => 48,
    };
    64 + payload
}

struct TopicChannel {
    sender: broadcast::Sender<SharedEvent>,
    next_seq: u64,
    history: VecDeque<(usize, SharedEvent)>,
    history_bytes: usize,
    max_history_bytes: usize,
    /// Event-count recovery window (matches the historical `capacity` API so a
    /// `StreamHub::new(4)` still retains at most 4 deltas for backfill).
    max_history_events: usize,
    stats: StreamStats,
}

impl TopicChannel {
    fn new(broadcast_capacity: usize, max_history_bytes: usize) -> Self {
        let cap = broadcast_capacity.max(1);
        let (sender, _rx) = broadcast::channel(cap);
        TopicChannel {
            sender,
            next_seq: 0,
            history: VecDeque::new(),
            history_bytes: 0,
            max_history_bytes: max_history_bytes.max(1),
            max_history_events: cap,
            stats: StreamStats::default(),
        }
    }

    fn push_history(&mut self, bytes: usize, event: SharedEvent) {
        // Evict from the front until both the byte budget and the event-count
        // window have room (or history is empty).
        while self.history.len() >= self.max_history_events
            || self.history_bytes.saturating_add(bytes) > self.max_history_bytes
        {
            match self.history.pop_front() {
                Some((b, _)) => {
                    self.history_bytes = self.history_bytes.saturating_sub(b);
                    self.stats.history_shed = self.stats.history_shed.saturating_add(1);
                }
                None => break,
            }
        }
        // A single event larger than the budget is retained alone so recovery
        // still has a baseline, but the shed counter records the pressure.
        if bytes > self.max_history_bytes {
            self.stats.history_shed = self.stats.history_shed.saturating_add(1);
        }
        self.history_bytes = self.history_bytes.saturating_add(bytes);
        self.history.push_back((bytes, event));
        self.stats.history_bytes = self.history_bytes;
    }
}

struct Shard {
    channels: HashMap<Topic, TopicChannel>,
}

/// A sharded, byte-bounded fan-out registry mapping topics to broadcast
/// channels with a retained per-topic history window for delta backfill.
pub struct StreamHub {
    broadcast_capacity: usize,
    topic_byte_budget: usize,
    max_topics: usize,
    shards: [Mutex<Shard>; SHARD_COUNT],
}

impl StreamHub {
    /// Create a hub with default broadcast capacity, byte budget, and topic cap.
    pub fn new(capacity: usize) -> Self {
        // `capacity` historically meant event-count window. Honour it as the
        // broadcast channel length and derive a proportional byte budget so
        // existing tests keep their lag semantics.
        let broadcast_capacity = capacity.max(1);
        let topic_byte_budget =
            DEFAULT_TOPIC_BYTE_BUDGET.max(broadcast_capacity.saturating_mul(256));
        Self::with_limits(broadcast_capacity, topic_byte_budget, DEFAULT_MAX_TOPICS)
    }

    /// Create a hub with explicit broadcast capacity (events), per-topic byte
    /// budget, and a hard cap on distinct topics.
    pub fn with_limits(
        broadcast_capacity: usize,
        topic_byte_budget: usize,
        max_topics: usize,
    ) -> Self {
        // Mutex is not Copy, so build the shard array without requiring Copy.
        let shards = std::array::from_fn(|_| {
            Mutex::new(Shard {
                channels: HashMap::new(),
            })
        });
        StreamHub {
            broadcast_capacity: broadcast_capacity.max(1),
            topic_byte_budget: topic_byte_budget.max(1),
            max_topics: max_topics.max(1),
            shards,
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

    /// Subscribe to a private (account-scoped) topic using a **server-installed**
    /// session binding looked up by `session_pubkey`. Client-supplied account
    /// or expiry claims are never trusted.
    pub fn subscribe_private(
        &self,
        topic: Topic,
        session_pubkey: &[u8; 32],
        sessions: &dyn SessionLookup,
        now: u64,
        reliability: Reliability,
    ) -> Result<Subscription, RpcError> {
        match topic.account() {
            Some(owner) => {
                authorize_private_topic(sessions, session_pubkey, owner, now)?;
                Ok(self.subscribe_unchecked(topic, reliability))
            }
            // A public topic through the private path is allowed.
            None => Ok(self.subscribe_unchecked(topic, reliability)),
        }
    }

    /// Legacy path that trusts a pre-resolved binding. Prefer
    /// [`Self::subscribe_private`] with a [`SessionLookup`]. Kept for callers
    /// that already resolved the session via the server.
    pub fn subscribe_private_bound(
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
            None => Ok(self.subscribe_unchecked(topic, reliability)),
        }
    }

    fn subscribe_unchecked(&self, topic: Topic, reliability: Reliability) -> Subscription {
        let mut guard = self.lock_shard(topic);
        let entry = self.topic_entry(&mut guard, topic);
        Subscription {
            topic,
            rx: entry.sender.subscribe(),
            tracker: SequenceTracker::new(),
            reliability,
        }
    }

    /// Publish a snapshot event, assigning the next sequence for the topic.
    /// Returns the shared event so callers can observe the Arc without cloning
    /// the body.
    pub fn publish_snapshot(&self, topic: Topic, payload: StreamPayload) -> SharedEvent {
        self.publish(topic, EventKind::Snapshot, payload)
    }

    /// Publish a delta event, assigning the next sequence for the topic.
    pub fn publish_delta(&self, topic: Topic, payload: StreamPayload) -> SharedEvent {
        self.publish(topic, EventKind::Delta, payload)
    }

    /// Sequence number of a just-published shared event (convenience).
    pub fn sequence_of(event: &SharedEvent) -> SequenceNumber {
        event.sequence
    }

    fn publish(&self, topic: Topic, kind: EventKind, payload: StreamPayload) -> SharedEvent {
        let mut guard = self.lock_shard(topic);
        let entry = self.topic_entry(&mut guard, topic);
        entry.next_seq = entry.next_seq.saturating_add(1);
        let sequence = SequenceNumber::new(entry.next_seq);
        let event = Arc::new(StreamEvent {
            topic,
            sequence,
            kind,
            payload,
        });
        let bytes = estimate_event_bytes(&event);
        entry.push_history(bytes, Arc::clone(&event));
        entry.stats.published = entry.stats.published.saturating_add(1);
        entry.stats.subscribers = entry.sender.receiver_count();
        // A send with no receivers returns Err; that is not a failure here.
        if entry.sender.send(Arc::clone(&event)).is_err() {
            entry.stats.no_receivers = entry.stats.no_receivers.saturating_add(1);
        }
        event
    }

    /// Attempt to backfill the events after `from_seq` for `topic`. Returns the
    /// retained deltas if the gap is within the window, or
    /// [`Recovery::SnapshotRequired`] if the consumer has fallen too far behind.
    pub fn recover(&self, topic: Topic, from_seq: u64) -> Recovery {
        let guard = self.lock_shard(topic);
        let Some(entry) = guard.channels.get(&topic) else {
            return Recovery::SnapshotRequired;
        };
        let Some((_, front)) = entry.history.front() else {
            return Recovery::SnapshotRequired;
        };
        let earliest = front.sequence.get();
        // We can backfill iff the next needed sequence is still retained.
        if earliest <= from_seq.saturating_add(1) {
            let deltas: Vec<StreamEvent> = entry
                .history
                .iter()
                .filter(|(_, e)| e.sequence.get() > from_seq)
                .map(|(_, e)| (**e).clone())
                .collect();
            Recovery::Deltas(deltas)
        } else {
            Recovery::SnapshotRequired
        }
    }

    /// The number of live subscribers for a topic.
    pub fn subscriber_count(&self, topic: Topic) -> usize {
        let guard = self.lock_shard(topic);
        guard
            .channels
            .get(&topic)
            .map_or(0, |c| c.sender.receiver_count())
    }

    /// The configured broadcast buffer capacity (events).
    pub fn capacity(&self) -> usize {
        self.broadcast_capacity
    }

    /// Per-topic history byte budget.
    pub fn topic_byte_budget(&self) -> usize {
        self.topic_byte_budget
    }

    /// The hard cap on distinct topics this hub will retain.
    pub fn max_topics(&self) -> usize {
        self.max_topics
    }

    /// Number of distinct topics currently retained (for tests / metrics).
    pub fn topic_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .channels
                    .len()
            })
            .sum()
    }

    /// Snapshot stats for a single topic.
    pub fn topic_stats(&self, topic: Topic) -> StreamStats {
        let guard = self.lock_shard(topic);
        guard
            .channels
            .get(&topic)
            .map(|c| {
                let mut s = c.stats;
                s.subscribers = c.sender.receiver_count();
                s.history_bytes = c.history_bytes;
                s
            })
            .unwrap_or_default()
    }

    fn topic_entry<'a>(&self, shard: &'a mut Shard, topic: Topic) -> &'a mut TopicChannel {
        if shard.channels.contains_key(&topic) {
            return shard.channels.get_mut(&topic).expect("topic just checked");
        }
        // Cap is process-wide; approximate by per-shard share so we do not need
        // a global lock. Idle GC + lowest-receiver eviction stay local.
        let per_shard_cap = self.max_topics.div_ceil(SHARD_COUNT).max(1);
        if shard.channels.len() >= per_shard_cap {
            shard
                .channels
                .retain(|_, ch| ch.sender.receiver_count() > 0);
        }
        while shard.channels.len() >= per_shard_cap {
            let victim = shard
                .channels
                .iter()
                .min_by_key(|(_, ch)| ch.sender.receiver_count())
                .map(|(t, _)| *t);
            match victim {
                Some(t) => {
                    shard.channels.remove(&t);
                }
                None => break,
            }
        }
        let budget = self.topic_byte_budget;
        let cap = self.broadcast_capacity;
        shard
            .channels
            .entry(topic)
            .or_insert_with(|| TopicChannel::new(cap, budget))
    }

    fn lock_shard(&self, topic: Topic) -> std::sync::MutexGuard<'_, Shard> {
        let idx = shard_index(&topic);
        self.shards[idx]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

fn shard_index(topic: &Topic) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    topic.hash(&mut h);
    // Mask to shard count (power of two); low bits of the hash are enough.
    // Truncation of the u64 hash is intentional and loss-free under the mask.
    #[allow(clippy::cast_possible_truncation)]
    {
        (h.finish() as usize) & (SHARD_COUNT - 1)
    }
}

/// A live subscription to one topic. Applies gap detection and duplicate
/// suppression for reliable delivery; skips lagged events for lossy delivery.
pub struct Subscription {
    topic: Topic,
    rx: broadcast::Receiver<SharedEvent>,
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

    /// Receive the next shared event (zero-copy relative to publish).
    pub async fn recv_shared(&mut self) -> Result<SharedEvent, StreamError> {
        loop {
            match self.rx.recv().await {
                Ok(event) => {
                    if let Some(out) = self.apply_shared(event)? {
                        return Ok(out);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    if matches!(self.reliability, Reliability::Reliable) {
                        return Err(StreamError::Lagged(n));
                    }
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

    /// Non-blocking shared receive.
    pub fn try_recv_shared(&mut self) -> Result<SharedEvent, StreamError> {
        loop {
            match self.rx.try_recv() {
                Ok(event) => {
                    if let Some(out) = self.apply_shared(event)? {
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

    fn apply(&mut self, event: SharedEvent) -> Result<Option<StreamEvent>, StreamError> {
        Ok(self.apply_shared(event)?.map(|e| (*e).clone()))
    }

    fn apply_shared(&mut self, event: SharedEvent) -> Result<Option<SharedEvent>, StreamError> {
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
