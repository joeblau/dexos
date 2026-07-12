//! Binary streaming subscription protocol — the wire **types**.
//!
//! Every channel is a [`Topic`]; every emitted [`StreamEvent`] carries a
//! monotonically increasing [`SequenceNumber`] so a consumer can detect a gap
//! and recover via a snapshot plus subsequent deltas. These types are
//! transport-free; the sharded async fan-out registry that publishes and
//! delivers them (`StreamHub`, `Subscription`) lives in `rpc::stream`.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use types::{AccountId, MarketId, SequenceNumber};

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
    /// deltas in order to catch up. Each element is a shared handle
    /// ([`SharedEvent`]) to the retained event, so backfill never clones
    /// event bodies.
    Deltas(Vec<SharedEvent>),
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

/// Default ceiling on distinct live topics in a `StreamHub`.
pub const DEFAULT_MAX_TOPICS: usize = 4096;

/// Default per-topic history / broadcast byte budget (1 MiB).
pub const DEFAULT_TOPIC_BYTE_BUDGET: usize = 1024 * 1024;

/// Default broadcast channel length in events (still required by
/// `tokio::broadcast`; the byte budget is the memory ceiling).
pub const DEFAULT_BROADCAST_CAPACITY: usize = 256;
