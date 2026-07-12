//! The [`Connection`] handle: the uniform send/receive surface shared by every
//! transport implementation.
//!
//! A connection carries two logical streams to one authenticated peer:
//!
//! * a **reliable, strictly-prioritized** stream ([`Connection::send_priority`]
//!   / [`Connection::recv`]) backed by an [`AsyncPriorityChannel`]; and
//! * a **best-effort datagram** stream ([`Connection::send_datagram`] /
//!   [`Connection::recv_datagram`]) backed by a bounded `mpsc` channel that
//!   sheds (returns backpressure) rather than growing under overload.
//!
//! The **datagram** stream stamps a monotonic per-stream sequence and applies a
//! sliding [`ReplayWindow`] on receive, so duplicates and stale replays of the
//! best-effort, unordered path are suppressed.
//!
//! The **reliable** stream is different: each [`TrafficClass`] is an independent
//! strict-FIFO sub-stream (the priority scheduler never reorders within a class,
//! and the transport never sheds a reliable frame), so its per-class sequence
//! must arrive contiguously from zero. Receive therefore does exact per-class
//! gap detection ([`ReliableOrder`]): a duplicate is suppressed, but a *skipped*
//! sequence means a frame vanished and is surfaced as
//! [`TransportError::ReliableGap`] with the link torn down — never hidden.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use codec::{Frame, TrafficClass, MAX_FRAME_PAYLOAD};
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use crate::channel::AsyncPriorityChannel;
use crate::class_auth::{authorize_class, PeerRole};
use crate::error::TransportError;
use crate::peer::PeerId;
use crate::reconnect::ReconnectPolicy;
use crate::replay::{PeerDedup, ReplayWindow};
use crate::scheduler::NUM_CLASSES;

/// Reserved `msg_type` marking a frame as an unreliable datagram on transports
/// that multiplex both streams over one wire (e.g. TCP). Application reliable
/// messages must not use this value.
pub const MSG_TYPE_DATAGRAM: u16 = 0xFFFF;

/// The outcome of admitting one reliable frame into [`ReliableOrder`].
#[derive(Debug)]
enum Admit {
    /// A fresh, in-order frame; deliver it.
    Fresh,
    /// A duplicate or already-superseded sequence; suppress it.
    Duplicate,
    /// A sequence was skipped on an ordered class: `expected` was due next but
    /// `got` arrived, so a reliable frame was lost.
    Gap { expected: u64, got: u64 },
}

/// Per-class, in-order tracking for the reliable stream: duplicate suppression
/// plus exact gap detection.
///
/// Each reliable [`TrafficClass`] is an independent strict-FIFO sub-stream, so a
/// class's per-class sequence must arrive contiguously starting at zero. A
/// duplicate/old sequence is suppressed; a *skipped* sequence is reported as a
/// [`Admit::Gap`] so the caller can tear the link down and resync rather than
/// silently proceeding past a lost frame.
#[derive(Debug)]
struct ReliableOrder {
    /// Last contiguously-accepted sequence per class (`None` before the first).
    last: [Option<u64>; NUM_CLASSES],
}

impl ReliableOrder {
    fn new() -> Self {
        Self {
            last: [None; NUM_CLASSES],
        }
    }

    /// Test-and-record `seq` on `class`.
    fn admit(&mut self, class: TrafficClass, seq: u64) -> Admit {
        let idx = usize::from(class.priority());
        // `priority()` is always 0..=8 for a valid class; guard defensively
        // rather than index out of bounds, suppressing an impossible class.
        let Some(slot) = self.last.get_mut(idx) else {
            return Admit::Duplicate;
        };
        // The next contiguous sequence for this class. Once `u64::MAX` has been
        // accepted the 2^64 space is exhausted: every possible sequence has
        // already been delivered, so any further arrival is a duplicate/replay
        // (never a fresh re-accept of `u64::MAX`, which would double-deliver).
        let expected = match slot {
            None => 0,
            Some(last) => match last.checked_add(1) {
                Some(next) => next,
                None => return Admit::Duplicate,
            },
        };
        if seq == expected {
            *slot = Some(seq);
            Admit::Fresh
        } else if slot.is_some_and(|l| seq <= l) {
            Admit::Duplicate
        } else {
            Admit::Gap { expected, got: seq }
        }
    }
}

/// Default capacity of the loopback accept/admission queue
/// ([`TransportConfig::accept_queue_capacity`]).
pub const DEFAULT_ACCEPT_QUEUE: usize = 64;

/// Default per-class retained-byte ceiling
/// ([`TransportConfig::max_class_bytes`]): 4 MiB. With nine classes this bounds
/// one direction of one connection to ~36 MiB of reliable payload plus at most
/// one in-flight frame per class.
pub const DEFAULT_MAX_CLASS_BYTES: usize = 4 * 1024 * 1024;

/// Default per-peer reliable-byte ceiling ([`TransportConfig::max_peer_bytes`]):
/// 64 MiB. One peer cannot retain more than this across all its reliable
/// classes and directions, so it cannot consume the node-wide budget.
pub const DEFAULT_MAX_PEER_BYTES: usize = 64 * 1024 * 1024;

/// Default node-wide reliable-byte ceiling
/// ([`TransportConfig::max_node_bytes`]): 1 GiB across every peer.
pub const DEFAULT_MAX_NODE_BYTES: usize = 1024 * 1024 * 1024;

/// Default maximum datagram payload ([`TransportConfig::datagram_max_bytes`]):
/// 64 KiB. Combined with the datagram frame-count capacity this bounds the
/// best-effort path's memory without a per-byte channel.
pub const DEFAULT_DATAGRAM_MAX_BYTES: usize = 64 * 1024;

/// Default per-class semantic payload ceilings, indexed by
/// [`TrafficClass::priority`] (P0..P8).
///
/// Votes, cancels, and orders carry small fixed-shape messages, so their
/// ceilings are far below [`MAX_FRAME_PAYLOAD`]; historical sync is expected to
/// be chunked/streamed by the application and keeps the full frame ceiling. A
/// peer cannot smuggle a bulk payload into a high-priority class: an inbound
/// reliable frame over its class ceiling is a protocol violation.
pub const DEFAULT_SEMANTIC_MAX: [usize; NUM_CLASSES] = [
    64 * 1024,         // P0 Consensus — votes / quorum certificates
    16 * 1024,         // P1 RiskReducing — cancels / risk-reducing commands
    64 * 1024,         // P2 Liquidation
    32 * 1024,         // P3 NewOrder
    64 * 1024,         // P4 ExecutionReceipt
    128 * 1024,        // P5 OracleCert
    1024 * 1024,       // P6 Checkpoint
    256 * 1024,        // P7 MarketData
    MAX_FRAME_PAYLOAD, // P8 Sync — chunked/streamed by the application
];

/// Default handshake I/O deadline (5 s). Stalled half-open peers are dropped.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Default maximum concurrent handshakes in flight on one transport.
pub const DEFAULT_MAX_HANDSHAKES: usize = 64;
/// Default TCP keepalive idle time before probes begin (30 s).
pub const DEFAULT_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
/// Default TCP keepalive probe interval (10 s).
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Default application-level idle timeout (120 s without authenticated traffic).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Default deployment / network identity (0 = unspecified / any).
pub const DEFAULT_NETWORK_ID: u64 = 0;
/// Default minimum supported wire protocol version.
pub const DEFAULT_MIN_WIRE_VERSION: u16 = 1;
/// Default maximum supported wire protocol version.
pub const DEFAULT_MAX_WIRE_VERSION: u16 = 1;
/// Default capability bitset (bit0 = encrypted session, bit1 = multipath dedup).
pub const DEFAULT_CAPABILITIES: u64 = 0b11;
/// Default max concurrent connections per remote peer identity.
pub const DEFAULT_CONN_BUDGET_PER_PEER: usize = 4;
/// Default max forward sequence jump on the datagram / multipath window.
pub const DEFAULT_MAX_SEQ_JUMP: u64 = 1024;
/// Default per-validator outstanding consensus-byte permit.
pub const DEFAULT_CONSENSUS_PEER_BYTES: usize = 4 * 1024 * 1024;
/// Default node-wide outstanding consensus-byte permit budget.
pub const DEFAULT_CONSENSUS_NODE_BYTES: usize = 64 * 1024 * 1024;

/// Tunables shared by all transports.
#[derive(Debug, Clone, Copy)]
pub struct TransportConfig {
    /// Per-class reliable queue capacity (frames). Bounds frame count per class.
    pub queue_capacity: usize,
    /// Datagram channel capacity (frames).
    pub datagram_capacity: usize,
    /// Anti-replay window width (sequence numbers) per stream.
    pub dedup_window: u64,
    /// Maximum application payload accepted per message.
    pub max_payload: usize,
    /// Capacity of the listener's pending-accept queue (loopback admission).
    /// A full queue causes [`crate::Transport::connect`] to return
    /// [`TransportError::Backpressure`] rather than grow memory without bound.
    pub accept_queue_capacity: usize,
    /// Per-class retained-byte ceiling: accumulation in one reliable class is
    /// capped by total payload bytes, not just frame count.
    pub max_class_bytes: usize,
    /// Per-peer reliable-byte ceiling across all classes and directions.
    pub max_peer_bytes: usize,
    /// Node-wide (process) reliable-byte ceiling across every peer.
    pub max_node_bytes: usize,
    /// Maximum accepted datagram payload. On QUIC this is additionally clamped
    /// per connection to the path's negotiated max datagram frame size (minus
    /// the frame header), so [`Connection::send_datagram`] fails typed for
    /// anything the wire cannot carry; `0` disables datagram sends entirely.
    pub datagram_max_bytes: usize,
    /// Per-class semantic payload ceilings, indexed by
    /// [`TrafficClass::priority`]. Oversized semantic messages are rejected
    /// before a payload-sized allocation on send and before being copied into
    /// the queue on receive.
    pub semantic_max: [usize; NUM_CLASSES],
    /// Deadline for the authenticated handshake I/O (both connect and accept).
    pub handshake_timeout: Duration,
    /// Maximum concurrent handshakes (limits FD / task pin under flood).
    pub max_concurrent_handshakes: usize,
    /// TCP keepalive idle time before the first probe (SO_KEEPALIVE).
    pub keepalive_time: Duration,
    /// TCP keepalive probe interval.
    pub keepalive_interval: Duration,
    /// Application-level idle timeout (no authenticated frame traffic).
    pub idle_timeout: Duration,
    /// Deployment / network identity negotiated in the handshake. `0` accepts
    /// any remote id (dev); non-zero requires an exact match.
    pub network_id: u64,
    /// Minimum wire protocol version this node supports.
    pub min_wire_version: u16,
    /// Maximum wire protocol version this node supports.
    pub max_wire_version: u16,
    /// Capability bits advertised in the handshake.
    pub capabilities: u64,
    /// Maximum concurrent live connections per remote peer identity.
    pub connection_budget_per_peer: usize,
    /// Maximum forward sequence jump accepted by multipath / datagram windows
    /// before the frame is treated as a resync-required gap.
    pub max_seq_jump: u64,
    /// Per-validator outstanding consensus payload permits (bytes).
    pub consensus_peer_bytes: usize,
    /// Node-wide outstanding consensus payload permits (bytes).
    pub consensus_node_bytes: usize,
    /// Reconnect backoff policy used by dial helpers.
    pub reconnect: ReconnectPolicy,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            datagram_capacity: 1024,
            dedup_window: crate::replay::DEFAULT_WINDOW,
            max_payload: MAX_FRAME_PAYLOAD,
            accept_queue_capacity: DEFAULT_ACCEPT_QUEUE,
            max_class_bytes: DEFAULT_MAX_CLASS_BYTES,
            max_peer_bytes: DEFAULT_MAX_PEER_BYTES,
            max_node_bytes: DEFAULT_MAX_NODE_BYTES,
            datagram_max_bytes: DEFAULT_DATAGRAM_MAX_BYTES,
            semantic_max: DEFAULT_SEMANTIC_MAX,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_concurrent_handshakes: DEFAULT_MAX_HANDSHAKES,
            keepalive_time: DEFAULT_KEEPALIVE_TIME,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            network_id: DEFAULT_NETWORK_ID,
            min_wire_version: DEFAULT_MIN_WIRE_VERSION,
            max_wire_version: DEFAULT_MAX_WIRE_VERSION,
            capabilities: DEFAULT_CAPABILITIES,
            connection_budget_per_peer: DEFAULT_CONN_BUDGET_PER_PEER,
            max_seq_jump: DEFAULT_MAX_SEQ_JUMP,
            consensus_peer_bytes: DEFAULT_CONSENSUS_PEER_BYTES,
            consensus_node_bytes: DEFAULT_CONSENSUS_NODE_BYTES,
            reconnect: ReconnectPolicy::default(),
        }
    }
}

impl TransportConfig {
    /// The semantic payload ceiling for `class` (its per-class byte contract).
    pub fn semantic_max_for(&self, class: TrafficClass) -> usize {
        self.semantic_max
            .get(usize::from(class.priority()))
            .copied()
            .unwrap_or(self.max_payload)
    }
}

/// An authenticated, priority-aware connection to a single peer.
///
/// Cheap to hold but not `Clone`: dropping it closes the outbound reliable
/// channel (signalling the peer) and aborts any background I/O tasks.
#[derive(Debug)]
pub struct Connection {
    peer: PeerId,
    /// Connection epoch: increments on each new session to the same logical
    /// peer so multipath/reconnect sequences cannot replay under a stale epoch.
    epoch: u64,
    /// Authenticated role used to authorize inbound traffic classes.
    role: PeerRole,
    /// Negotiated wire protocol version for this session.
    wire_version: u16,
    /// Negotiated capability intersection.
    capabilities: u64,
    out_reliable: Arc<AsyncPriorityChannel>,
    in_reliable: Arc<AsyncPriorityChannel>,
    out_datagram: mpsc::Sender<Frame>,
    in_datagram: AsyncMutex<mpsc::Receiver<Frame>>,
    /// Per-class outbound sequence counters: the last sequence stamped on each
    /// reliable class (`None` before the first send). Advanced only when the
    /// frame is actually enqueued, so a backpressured send never tears a hole
    /// the receiver would read as a lost frame. Each class owns an independent
    /// sequence space, so the strict-priority scheduler reordering a low-priority
    /// class behind a burst of a higher-priority class can never make either
    /// class's contiguous sequence look lost or replayed.
    seq_reliable: Mutex<[Option<u64>; NUM_CLASSES]>,
    seq_datagram: AtomicU64,
    order_reliable: Mutex<ReliableOrder>,
    dedup_datagram: Mutex<ReplayWindow>,
    /// Shared multipath dedup table (optional — TCP wires this; loopback may not).
    peer_dedup: Option<Arc<Mutex<PeerDedup>>>,
    max_payload: usize,
    /// Per-class semantic payload ceilings (indexed by priority). Enforced
    /// before a payload-sized allocation on send.
    semantic_max: [usize; NUM_CLASSES],
    /// Maximum datagram payload accepted on send.
    datagram_max: usize,
    /// Reserved per-peer connection slot; owning it here ties the slot's
    /// release (its `Drop`) to this connection's lifetime.
    _conn_slot: Option<ConnSlot>,
    tasks: Vec<JoinHandle<()>>,
}

/// RAII guard over one reserved per-peer connection slot.
///
/// A transport's `reserve_conn_slot` hands one out after a successful
/// handshake, and the resulting [`Connection`] owns it, so the per-peer
/// connection budget counts *live* connections rather than lifetime totals.
/// Dropping the guard decrements (saturating) the peer's entry in the shared
/// count map and removes the entry once it reaches zero, keeping the map
/// bounded by the number of peers with live connections.
#[derive(Debug)]
pub(crate) struct ConnSlot {
    peer: PeerId,
    counts: Arc<Mutex<HashMap<PeerId, usize>>>,
}

impl ConnSlot {
    /// Wrap an already-incremented count for `peer` in a releasing guard.
    pub(crate) fn new(peer: PeerId, counts: Arc<Mutex<HashMap<PeerId, usize>>>) -> Self {
        Self { peer, counts }
    }

    /// Reserve one connection slot for `peer` against the per-peer `budget`.
    ///
    /// Returns a guard that releases the reservation when dropped, so the
    /// budget tracks live connections rather than lifetime totals. A refused
    /// reservation never inserts an entry, keeping the map bounded.
    pub(crate) fn reserve(
        counts: &Arc<Mutex<HashMap<PeerId, usize>>>,
        budget: usize,
        peer: PeerId,
    ) -> Result<Self, TransportError> {
        let mut guard = counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = guard.get(&peer).copied().unwrap_or(0);
        if count >= budget {
            return Err(TransportError::Backpressure {
                class: TrafficClass::Sync,
            });
        }
        guard.insert(peer, count + 1);
        drop(guard);
        Ok(Self::new(peer, counts.clone()))
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.peer);
            }
        }
    }
}

/// Options that transports pass when assembling a [`Connection`].
#[derive(Debug)]
pub(crate) struct ConnectionOpts {
    pub epoch: u64,
    pub role: PeerRole,
    pub wire_version: u16,
    pub capabilities: u64,
    pub peer_dedup: Option<Arc<Mutex<PeerDedup>>>,
    /// Reserved per-peer connection slot, released when the connection drops.
    pub conn_slot: Option<ConnSlot>,
}

impl Default for ConnectionOpts {
    fn default() -> Self {
        Self {
            epoch: 0,
            role: PeerRole::Validator,
            wire_version: DEFAULT_MAX_WIRE_VERSION,
            capabilities: DEFAULT_CAPABILITIES,
            peer_dedup: None,
            conn_slot: None,
        }
    }
}

impl Connection {
    /// Assemble a connection from its wired channels. Internal to the transports.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        peer: PeerId,
        out_reliable: Arc<AsyncPriorityChannel>,
        in_reliable: Arc<AsyncPriorityChannel>,
        out_datagram: mpsc::Sender<Frame>,
        in_datagram: mpsc::Receiver<Frame>,
        cfg: &TransportConfig,
        tasks: Vec<JoinHandle<()>>,
    ) -> Self {
        Self::new_with_opts(
            peer,
            out_reliable,
            in_reliable,
            out_datagram,
            in_datagram,
            cfg,
            tasks,
            ConnectionOpts::default(),
        )
    }

    /// Assemble a connection with explicit epoch / role / multipath dedup.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_opts(
        peer: PeerId,
        out_reliable: Arc<AsyncPriorityChannel>,
        in_reliable: Arc<AsyncPriorityChannel>,
        out_datagram: mpsc::Sender<Frame>,
        in_datagram: mpsc::Receiver<Frame>,
        cfg: &TransportConfig,
        tasks: Vec<JoinHandle<()>>,
        opts: ConnectionOpts,
    ) -> Self {
        Self {
            peer,
            epoch: opts.epoch,
            role: opts.role,
            wire_version: opts.wire_version,
            capabilities: opts.capabilities,
            out_reliable,
            in_reliable,
            out_datagram,
            in_datagram: AsyncMutex::new(in_datagram),
            seq_reliable: Mutex::new([None; NUM_CLASSES]),
            seq_datagram: AtomicU64::new(0),
            order_reliable: Mutex::new(ReliableOrder::new()),
            dedup_datagram: Mutex::new(ReplayWindow::with_max_jump(
                cfg.dedup_window,
                cfg.max_seq_jump,
            )),
            peer_dedup: opts.peer_dedup,
            max_payload: cfg.max_payload.min(MAX_FRAME_PAYLOAD),
            semantic_max: cfg.semantic_max,
            datagram_max: cfg.datagram_max_bytes,
            _conn_slot: opts.conn_slot,
            tasks,
        }
    }

    /// Connection epoch for this session.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Authenticated peer role used for class authorization.
    pub fn role(&self) -> PeerRole {
        self.role
    }

    /// Negotiated wire protocol version.
    pub fn wire_version(&self) -> u16 {
        self.wire_version
    }

    /// Negotiated capability intersection.
    pub fn capabilities(&self) -> u64 {
        self.capabilities
    }

    /// The semantic payload ceiling for `class` (bounded by `max_payload`).
    fn semantic_limit(&self, class: TrafficClass) -> usize {
        self.semantic_max
            .get(usize::from(class.priority()))
            .copied()
            .unwrap_or(self.max_payload)
            .min(self.max_payload)
    }

    /// The authenticated identity of the peer on the far end.
    pub fn peer_id(&self) -> PeerId {
        self.peer
    }

    /// Enqueue a reliable message in the given priority class.
    ///
    /// Non-blocking: returns [`TransportError::Backpressure`] if that class's
    /// bounded queue is full (the message is not buffered), or
    /// [`TransportError::MessageTooLarge`] if it exceeds the payload cap. A full
    /// low-priority class never blocks a higher-priority send.
    pub fn send_priority(&self, class: TrafficClass, message: &[u8]) -> Result<(), TransportError> {
        self.send_typed(class, 0, message)
    }

    /// Like [`Connection::send_priority`] but with an application `msg_type` tag.
    pub fn send_typed(
        &self,
        class: TrafficClass,
        msg_type: u16,
        message: &[u8],
    ) -> Result<(), TransportError> {
        // Reject an over-contract message *before* the payload-sized `to_vec`
        // copy below: an oversized semantic message never allocates a frame.
        if message.len() > self.semantic_limit(class) {
            return Err(TransportError::MessageTooLarge);
        }
        let idx = usize::from(class.priority());
        let mut counters = self
            .seq_reliable
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // `priority()` is always 0..=8 for a valid class; guard defensively.
        let slot = counters
            .get_mut(idx)
            .ok_or(TransportError::Backpressure { class })?;
        // The next contiguous sequence for this class. A class that has already
        // stamped `u64::MAX` has exhausted its 2^64 sequence space: refuse to
        // reuse it (the receiver would drop the reused frame as a duplicate,
        // silently losing a reliable message) and surface a typed error so the
        // caller re-keys / resyncs the link.
        let sequence = match slot {
            None => 0,
            Some(last) => last
                .checked_add(1)
                .ok_or(TransportError::SequenceExhausted { class })?,
        };
        let frame = Frame {
            class,
            msg_type,
            sequence,
            payload: message.to_vec(),
        };
        // Advance the per-class counter only after the frame is actually
        // enqueued: a rejected (backpressured) send must not consume a sequence,
        // or the receiver would later see a gap where nothing was ever lost.
        self.out_reliable.try_send(frame)?;
        *slot = Some(sequence);
        Ok(())
    }

    /// Send a best-effort datagram (unreliable, unordered).
    ///
    /// Returns [`TransportError::Backpressure`] if the bounded datagram channel
    /// is full (the datagram is shed, not buffered) — lossy delivery never
    /// touches the reliable priority queues.
    ///
    /// Returns [`TransportError::MessageTooLarge`] if the payload exceeds the
    /// datagram ceiling. On QUIC that ceiling is clamped per connection to the
    /// path's negotiated max datagram frame size, so a payload the wire cannot
    /// carry is rejected here, synchronously — never accepted and then
    /// silently shed by the datagram writer.
    pub fn send_datagram(&self, message: &[u8]) -> Result<(), TransportError> {
        // Reject before the payload-sized copy. The datagram cap is far below
        // `max_payload`, so the best-effort path's memory is bounded by
        // `datagram_capacity * datagram_max_bytes` without a per-byte channel.
        if message.len() > self.datagram_max.min(self.max_payload) {
            return Err(TransportError::MessageTooLarge);
        }
        let sequence = self.seq_datagram.fetch_add(1, Ordering::Relaxed);
        let frame = Frame {
            class: TrafficClass::MarketData,
            msg_type: MSG_TYPE_DATAGRAM,
            sequence,
            payload: message.to_vec(),
        };
        match self.out_datagram.try_send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(TransportError::Backpressure {
                class: TrafficClass::MarketData,
            }),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportError::ConnectionClosed),
        }
    }

    /// Await the next reliable message, in strict priority order.
    ///
    /// A duplicate/replayed frame is suppressed and receiving continues. A
    /// **gap** in a class's contiguous sequence means a reliable frame was lost:
    /// the inbound stream is closed and [`TransportError::ReliableGap`] is
    /// returned so the caller resyncs instead of silently proceeding past the
    /// hole. Returns [`TransportError::ConnectionClosed`] once the link ends.
    ///
    /// When a shared [`PeerDedup`] is wired (TCP multipath), dual delivery of
    /// the same `(peer, epoch, class, seq)` across paths is rejected here.
    pub async fn recv(&self) -> Result<Frame, TransportError> {
        loop {
            let frame = self
                .in_reliable
                .recv()
                .await
                .ok_or(TransportError::ConnectionClosed)?;
            // Class authorization: non-validators cannot smuggle P0 etc.
            if let Err(err) = authorize_class(self.role, frame.class) {
                self.in_reliable.close();
                return Err(err);
            }
            // Multipath at-most-once across connections sharing this peer/epoch.
            if let Some(dedup) = &self.peer_dedup {
                let fresh = dedup
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .accept_class(self.peer, self.epoch, frame.class, frame.sequence)?;
                if !fresh {
                    continue;
                }
            }
            let admit = self
                .order_reliable
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .admit(frame.class, frame.sequence);
            match admit {
                Admit::Fresh => return Ok(frame),
                // Duplicate / replay: suppress and wait for the next frame.
                Admit::Duplicate => {}
                Admit::Gap { expected, got } => {
                    // A reliable frame vanished. Never deliver past the hole:
                    // close the inbound stream so the link tears down and the
                    // caller can resync.
                    self.in_reliable.close();
                    return Err(TransportError::ReliableGap {
                        class: frame.class,
                        expected,
                        got,
                    });
                }
            }
        }
    }

    /// Await the next fresh datagram payload, after duplicate/replay
    /// suppression. Suppressed datagrams are skipped, never surfaced.
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let mut rx = self.in_datagram.lock().await;
        loop {
            let frame = rx.recv().await.ok_or(TransportError::ConnectionClosed)?;
            if let Some(dedup) = &self.peer_dedup {
                let fresh = dedup
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .accept_class(self.peer, self.epoch, frame.class, frame.sequence)?;
                if !fresh {
                    continue;
                }
            }
            let fresh = self
                .dedup_datagram
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .check(frame.sequence);
            if fresh {
                return Ok(frame.payload);
            }
        }
    }

    /// Reliable frames currently buffered outbound (for tests / metrics).
    pub fn pending_outbound(&self) -> usize {
        self.out_reliable.pending()
    }

    /// Reliable payload bytes currently buffered outbound to this peer.
    pub fn outbound_queued_bytes(&self) -> usize {
        self.out_reliable.queued_bytes()
    }

    /// High-water mark of [`outbound_queued_bytes`](Self::outbound_queued_bytes).
    pub fn outbound_queued_bytes_high_water(&self) -> usize {
        self.out_reliable.queued_bytes_high_water()
    }

    /// Reliable payload bytes currently buffered inbound from this peer.
    pub fn inbound_queued_bytes(&self) -> usize {
        self.in_reliable.queued_bytes()
    }

    /// High-water mark of [`inbound_queued_bytes`](Self::inbound_queued_bytes).
    pub fn inbound_queued_bytes_high_water(&self) -> usize {
        self.in_reliable.queued_bytes_high_water()
    }

    /// Total reliable payload bytes currently retained for this peer across both
    /// directions (the per-peer queued-byte metric).
    pub fn queued_bytes(&self) -> usize {
        self.out_reliable
            .queued_bytes()
            .saturating_add(self.in_reliable.queued_bytes())
    }

    /// Reliable payload bytes currently buffered inbound in one class (proves a
    /// per-class flood cannot spill into another class).
    pub fn inbound_class_bytes(&self, class: TrafficClass) -> usize {
        self.in_reliable.class_bytes(class)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Closing our outbound reliable channel signals EOF to the peer's
        // `recv()` (in loopback the two share one channel).
        self.out_reliable.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::PriorityScheduler;

    fn conn_with_inbound(in_reliable: Arc<AsyncPriorityChannel>) -> Connection {
        let out_reliable = Arc::new(AsyncPriorityChannel::new(16));
        let (out_dtx, _out_drx) = mpsc::channel(4);
        let (_in_dtx, in_drx) = mpsc::channel(4);
        Connection::new(
            PeerId::from([9u8; 32]),
            out_reliable,
            in_reliable,
            out_dtx,
            in_drx,
            &TransportConfig::default(),
            Vec::new(),
        )
    }

    fn rframe(class: TrafficClass, sequence: u64) -> Frame {
        Frame {
            class,
            msg_type: 0,
            sequence,
            payload: sequence.to_le_bytes().to_vec(),
        }
    }

    #[test]
    fn conn_slot_drop_releases_count_and_removes_zero_entries() {
        let peer = PeerId::from([7u8; 32]);
        let counts: Arc<Mutex<HashMap<PeerId, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(peer, 2);

        // Dropping one guard decrements the live count by exactly one.
        drop(ConnSlot::new(peer, counts.clone()));
        assert_eq!(
            counts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&peer)
                .copied(),
            Some(1)
        );

        // The entry is removed (not left at 0) when the last slot releases,
        // so the map stays bounded by peers with live connections.
        drop(ConnSlot::new(peer, counts.clone()));
        assert!(counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty());

        // Releasing with no entry present saturates: no panic, no underflow,
        // and no phantom entry is created.
        drop(ConnSlot::new(peer, counts.clone()));
        assert!(counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty());
    }

    #[test]
    fn reliable_order_fresh_duplicate_and_gap_per_class() {
        let mut o = ReliableOrder::new();
        // A class must start contiguously at 0.
        assert!(matches!(o.admit(TrafficClass::Consensus, 0), Admit::Fresh));
        // Replays of accepted-or-older sequences are suppressed.
        assert!(matches!(
            o.admit(TrafficClass::Consensus, 0),
            Admit::Duplicate
        ));
        assert!(matches!(o.admit(TrafficClass::Consensus, 1), Admit::Fresh));
        assert!(matches!(
            o.admit(TrafficClass::Consensus, 1),
            Admit::Duplicate
        ));
        // A skipped sequence is a hard gap (2 was due, 4 arrived).
        assert!(matches!(
            o.admit(TrafficClass::Consensus, 4),
            Admit::Gap {
                expected: 2,
                got: 4
            }
        ));
        // Classes are independent: NewOrder still expects its own 0 first.
        assert!(matches!(o.admit(TrafficClass::NewOrder, 0), Admit::Fresh));
        // A nonzero first frame on a fresh class is itself a gap.
        assert!(matches!(
            o.admit(TrafficClass::MarketData, 5),
            Admit::Gap {
                expected: 0,
                got: 5
            }
        ));
    }

    #[tokio::test]
    async fn recv_detects_reliable_gap_and_closes_stream() {
        let inbound = Arc::new(AsyncPriorityChannel::new(16));
        let conn = conn_with_inbound(inbound.clone());
        // Deliver seq 0 then seq 2 on the same class: sequence 1 is skipped.
        inbound
            .try_send(rframe(TrafficClass::Consensus, 0))
            .unwrap();
        inbound
            .try_send(rframe(TrafficClass::Consensus, 2))
            .unwrap();

        // The contiguous frame is delivered.
        assert_eq!(conn.recv().await.unwrap().sequence, 0);
        // The skip is surfaced as a hard, typed gap error, never hidden.
        let err = conn.recv().await.unwrap_err();
        assert!(matches!(
            err,
            TransportError::ReliableGap {
                class: TrafficClass::Consensus,
                expected: 1,
                got: 2
            }
        ));
        // The stream is now closed: further receives report closure.
        assert!(matches!(
            conn.recv().await,
            Err(TransportError::ConnectionClosed)
        ));
    }

    #[tokio::test]
    async fn recv_suppresses_duplicates_without_gap() {
        let inbound = Arc::new(AsyncPriorityChannel::new(16));
        let conn = conn_with_inbound(inbound.clone());
        // A duplicate of seq 0 is interposed before the contiguous seq 1.
        for seq in [0u64, 0, 1] {
            inbound
                .try_send(rframe(TrafficClass::Consensus, seq))
                .unwrap();
        }
        assert_eq!(conn.recv().await.unwrap().sequence, 0);
        // The duplicate is swallowed; the next delivered frame is seq 1.
        assert_eq!(conn.recv().await.unwrap().sequence, 1);
    }

    #[tokio::test]
    async fn backpressured_send_does_not_open_a_sequence_gap() {
        // Capacity of one frame per class: the second same-class send is rejected
        // and must not consume a sequence number.
        let out = Arc::new(AsyncPriorityChannel::new(1));
        let (out_dtx, _out_drx) = mpsc::channel(4);
        let (_in_dtx, in_drx) = mpsc::channel(4);
        let conn = Connection::new(
            PeerId::from([7u8; 32]),
            out.clone(),
            Arc::new(AsyncPriorityChannel::new(16)),
            out_dtx,
            in_drx,
            &TransportConfig::default(),
            Vec::new(),
        );

        conn.send_priority(TrafficClass::NewOrder, b"a").unwrap();
        // The class is full: this send backpressures (sequence not consumed).
        assert!(matches!(
            conn.send_priority(TrafficClass::NewOrder, b"b"),
            Err(TransportError::Backpressure {
                class: TrafficClass::NewOrder
            })
        ));
        // Drain the first frame, freeing the slot, then send again.
        let first = out.recv().await.unwrap();
        assert_eq!(first.sequence, 0);
        conn.send_priority(TrafficClass::NewOrder, b"b").unwrap();
        // The retried send reuses sequence 1 (contiguous), not 2 — no gap.
        let second = out.recv().await.unwrap();
        assert_eq!(second.sequence, 1);
    }

    #[tokio::test]
    async fn poisoned_order_mutex_recovers_without_task_panic() {
        let inbound = Arc::new(AsyncPriorityChannel::new(16));
        let conn = conn_with_inbound(inbound.clone());
        // Intentionally poison the order mutex; recv must recover the guard
        // rather than panicking the connection task.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = conn.order_reliable.lock().unwrap();
            panic!("intentional order mutex poison");
        }));
        inbound
            .try_send(rframe(TrafficClass::Consensus, 0))
            .unwrap();
        assert_eq!(conn.recv().await.unwrap().sequence, 0);
    }

    /// Build a default config mutated by `f` (routed through a call so the
    /// `field_reassign_with_default` lint does not fire on a bare `default()`).
    fn cfg_with(f: impl FnOnce(&mut TransportConfig)) -> TransportConfig {
        let mut cfg = TransportConfig::default();
        f(&mut cfg);
        cfg
    }

    fn conn_with_cfg(cfg: &TransportConfig) -> (Connection, Arc<AsyncPriorityChannel>) {
        let out = Arc::new(AsyncPriorityChannel::new(64));
        let (out_dtx, _out_drx) = mpsc::channel(4);
        let (_in_dtx, in_drx) = mpsc::channel(4);
        let conn = Connection::new(
            PeerId::from([5u8; 32]),
            out.clone(),
            Arc::new(AsyncPriorityChannel::new(64)),
            out_dtx,
            in_drx,
            cfg,
            Vec::new(),
        );
        (conn, out)
    }

    #[test]
    fn oversized_semantic_message_rejected_before_allocation() {
        // A tight per-class semantic ceiling on the high-priority Consensus class.
        let cfg = cfg_with(|c| {
            c.semantic_max[usize::from(TrafficClass::Consensus.priority())] = 8;
        });
        let (conn, out) = conn_with_cfg(&cfg);

        // A message over the class ceiling is rejected and never enqueued.
        let err = conn
            .send_priority(TrafficClass::Consensus, &[0u8; 9])
            .unwrap_err();
        assert!(matches!(err, TransportError::MessageTooLarge));
        assert_eq!(out.pending(), 0, "rejected message must not be buffered");

        // A message within the ceiling still sends.
        conn.send_priority(TrafficClass::Consensus, &[0u8; 8])
            .unwrap();
        assert_eq!(out.pending(), 1);

        // A different class keeps its own (larger, default) ceiling.
        conn.send_priority(TrafficClass::MarketData, &[0u8; 9])
            .unwrap();
        assert_eq!(out.pending(), 2);
    }

    #[test]
    fn oversized_datagram_rejected_before_allocation() {
        let cfg = cfg_with(|c| c.datagram_max_bytes = 16);
        let out = Arc::new(AsyncPriorityChannel::new(16));
        let (out_dtx, _out_drx) = mpsc::channel(4);
        let (_in_dtx, in_drx) = mpsc::channel(4);
        let conn = Connection::new(
            PeerId::from([6u8; 32]),
            out,
            Arc::new(AsyncPriorityChannel::new(16)),
            out_dtx,
            in_drx,
            &cfg,
            Vec::new(),
        );
        assert!(matches!(
            conn.send_datagram(&[0u8; 17]),
            Err(TransportError::MessageTooLarge)
        ));
        // At the cap it is accepted.
        conn.send_datagram(&[0u8; 16]).unwrap();
    }

    #[test]
    fn zero_datagram_cap_fails_every_datagram_send_typed() {
        // The QUIC transport clamps `datagram_max_bytes` per connection to the
        // path's max datagram size, and to 0 when the peer does not support
        // datagrams at all — in which case every send must fail typed rather
        // than be accepted and silently shed on the wire (#415).
        let cfg = cfg_with(|c| c.datagram_max_bytes = 0);
        let out = Arc::new(AsyncPriorityChannel::new(16));
        let (out_dtx, _out_drx) = mpsc::channel(4);
        let (_in_dtx, in_drx) = mpsc::channel(4);
        let conn = Connection::new(
            PeerId::from([7u8; 32]),
            out,
            Arc::new(AsyncPriorityChannel::new(16)),
            out_dtx,
            in_drx,
            &cfg,
            Vec::new(),
        );
        assert!(matches!(
            conn.send_datagram(&[0u8; 1]),
            Err(TransportError::MessageTooLarge)
        ));
        // Only the empty payload fits a zero ceiling.
        conn.send_datagram(&[]).unwrap();
    }

    #[test]
    fn connection_reports_queued_bytes_and_high_water() {
        let cfg = TransportConfig::default();
        let (conn, _out) = conn_with_cfg(&cfg);
        assert_eq!(conn.outbound_queued_bytes(), 0);
        conn.send_priority(TrafficClass::NewOrder, &[0u8; 100])
            .unwrap();
        conn.send_priority(TrafficClass::NewOrder, &[0u8; 50])
            .unwrap();
        assert_eq!(conn.outbound_queued_bytes(), 150);
        assert_eq!(conn.outbound_queued_bytes_high_water(), 150);
        assert_eq!(conn.queued_bytes(), 150);
    }

    #[test]
    fn poisoned_sequence_mutex_recovers_on_send() {
        let out = Arc::new(AsyncPriorityChannel::new(16));
        let (out_dtx, _out_drx) = mpsc::channel(4);
        let (_in_dtx, in_drx) = mpsc::channel(4);
        let conn = Connection::new(
            PeerId::from([3u8; 32]),
            out.clone(),
            Arc::new(AsyncPriorityChannel::new(16)),
            out_dtx,
            in_drx,
            &TransportConfig::default(),
            Vec::new(),
        );
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = conn.seq_reliable.lock().unwrap();
            panic!("intentional sequence mutex poison");
        }));
        // Send recovers the poisoned sequence mutex without a task panic.
        conn.send_priority(TrafficClass::NewOrder, b"ok").unwrap();
        assert_eq!(conn.pending_outbound(), 1);
        // A second send still works (sequence advanced through the recovered guard).
        conn.send_priority(TrafficClass::NewOrder, b"ok2").unwrap();
        assert_eq!(conn.pending_outbound(), 2);
    }

    fn conn_with_inbound_cap(cap: usize) -> (Connection, Arc<AsyncPriorityChannel>) {
        let inbound = Arc::new(AsyncPriorityChannel::new(cap));
        (conn_with_inbound(inbound.clone()), inbound)
    }

    /// Acceptance criterion: a valid low-priority reliable frame overtaken by a
    /// higher-priority burst *wider than the replay window* is still delivered,
    /// and every reliable frame is delivered exactly once.
    ///
    /// The strict-priority inbound channel drains the entire P0 (`Consensus`)
    /// burst before it ever yields the single P8 (`Sync`) frame, so on a *global*
    /// sequence space the P8 frame — overtaken by ~1.5x the window — would have
    /// slid out and been silently discarded. Per-class sequence spaces make the
    /// P8 frame contiguous on its *own* class regardless of cross-class ordering.
    #[tokio::test]
    async fn low_priority_overtaken_by_more_than_window_still_delivers_exactly_once() {
        // A burst larger than the default replay window (1024).
        let burst = crate::replay::DEFAULT_WINDOW + 500;
        let cap = usize::try_from(burst).unwrap() + 8;
        let (conn, inbound) = conn_with_inbound_cap(cap);

        // Enqueue one low-priority frame first, then overtake it with the burst.
        inbound.try_send(rframe(TrafficClass::Sync, 0)).unwrap();
        for seq in 0..burst {
            inbound
                .try_send(rframe(TrafficClass::Consensus, seq))
                .unwrap();
        }

        // Strict priority drains all of Consensus first, contiguously 0..burst.
        for seq in 0..burst {
            let f = conn.recv().await.unwrap();
            assert_eq!(f.class, TrafficClass::Consensus);
            assert_eq!(f.sequence, seq, "consensus delivered in order, none lost");
        }
        // The overtaken low-priority frame is delivered last — never discarded as
        // a stale replay despite being overtaken by more than the window width.
        let tail = conn.recv().await.unwrap();
        assert_eq!(tail.class, TrafficClass::Sync);
        assert_eq!(tail.sequence, 0);
    }

    /// Acceptance criterion: gaps trigger explicit resync, never a "harmless
    /// replay". A forward jump larger than any dedup window is a hard gap, not an
    /// in-window duplicate — the distinction a global replay window would erase.
    #[test]
    fn large_forward_jump_is_a_gap_not_a_replay() {
        let mut o = ReliableOrder::new();
        assert!(matches!(o.admit(TrafficClass::Consensus, 0), Admit::Fresh));
        // A jump far beyond the widest supported replay window.
        let jump = crate::replay::MAX_WINDOW * 4 + 7;
        assert!(matches!(
            o.admit(TrafficClass::Consensus, jump),
            Admit::Gap { expected: 1, got } if got == jump
        ));
    }

    /// Acceptance criterion (wrap/exhaustion boundary): once a class has accepted
    /// `u64::MAX` its space is exhausted; a repeat of `u64::MAX` is a duplicate,
    /// never a fresh re-accept that would double-deliver.
    #[test]
    fn receive_sequence_exhaustion_is_not_a_double_delivery() {
        let mut o = ReliableOrder::new();
        // Drive the class to the top of its space (private field, same module).
        o.last[usize::from(TrafficClass::Consensus.priority())] = Some(u64::MAX);
        // The final sequence is already delivered: replays are suppressed.
        assert!(matches!(
            o.admit(TrafficClass::Consensus, u64::MAX),
            Admit::Duplicate
        ));
        assert!(matches!(
            o.admit(TrafficClass::Consensus, u64::MAX - 1),
            Admit::Duplicate
        ));
        // A different class is unaffected and still starts contiguously at 0.
        assert!(matches!(o.admit(TrafficClass::NewOrder, 0), Admit::Fresh));
    }

    /// Acceptance criterion (wrap/exhaustion boundary): the sender stamps the
    /// final `u64::MAX` sequence, then refuses to reuse it — surfacing a typed
    /// error instead of silently re-stamping a sequence the receiver would drop.
    #[tokio::test]
    async fn send_refuses_to_reuse_exhausted_sequence_space() {
        let (conn, _inbound) = conn_with_inbound_cap(4);
        // Prime the class one below the top: the next send stamps `u64::MAX`.
        {
            let mut counters = conn
                .seq_reliable
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            counters[usize::from(TrafficClass::Consensus.priority())] = Some(u64::MAX - 1);
        }
        // The final, still-valid `u64::MAX` sequence is stamped and enqueued.
        conn.send_priority(TrafficClass::Consensus, b"last")
            .unwrap();
        assert_eq!(conn.pending_outbound(), 1);
        let last = conn.out_reliable.recv().await.unwrap();
        assert_eq!(
            last.sequence,
            u64::MAX,
            "final sequence stamped exactly once"
        );

        // The space is now exhausted: a further send is refused, not silent.
        let err = conn
            .send_priority(TrafficClass::Consensus, b"overflow")
            .unwrap_err();
        assert!(matches!(
            err,
            TransportError::SequenceExhausted {
                class: TrafficClass::Consensus
            }
        ));
        // No phantom frame was enqueued by the refused send.
        assert_eq!(conn.pending_outbound(), 0);
        // A different class is unaffected by the exhausted one.
        conn.send_priority(TrafficClass::NewOrder, b"ok").unwrap();
        assert_eq!(conn.pending_outbound(), 1);
    }

    /// Acceptance criterion: reconnect starts a fresh per-class sequence space.
    /// A new [`Connection`] (a new epoch in the sense of #283) tracks ordering
    /// independently, so the previous epoch's accepted sequences neither leak
    /// into nor gap the new one. Wire-level `(epoch, seq)` negotiation across a
    /// shared window is tracked in #283; this proves the sequence-space reset the
    /// separation relies on.
    #[tokio::test]
    async fn reconnect_resets_per_class_sequence_spaces() {
        // First epoch: deliver a contiguous prefix, then tear down.
        let first = Arc::new(AsyncPriorityChannel::new(16));
        {
            let conn = conn_with_inbound(first.clone());
            for seq in 0..3u64 {
                first
                    .try_send(rframe(TrafficClass::Consensus, seq))
                    .unwrap();
            }
            for seq in 0..3u64 {
                assert_eq!(conn.recv().await.unwrap().sequence, seq);
            }
        }
        // Second epoch (reconnect): a brand-new connection expects its own 0
        // again — the old epoch's advanced sequences do not carry over, and a
        // fresh 0 is delivered rather than being suppressed as an old replay.
        let second = Arc::new(AsyncPriorityChannel::new(16));
        let conn = conn_with_inbound(second.clone());
        second.try_send(rframe(TrafficClass::Consensus, 0)).unwrap();
        assert_eq!(conn.recv().await.unwrap().sequence, 0);
    }

    /// Acceptance criterion: property test over arbitrary priority interleavings.
    /// A deterministic LCG drives an adversarial mix of per-class contiguous
    /// enqueues and strict-priority dequeues; the receiver-side [`ReliableOrder`]
    /// must admit every dequeued frame as `Fresh`, in per-class order, and never
    /// manufacture a false gap or duplicate. Total delivered == total produced.
    #[test]
    fn arbitrary_priority_interleaving_delivers_each_class_exactly_once_property() {
        let mut state: u64 = 0xC0FF_EE12_3456_789A;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        // Capacity comfortably above the worst-case per-class backlog so the
        // interleave, not backpressure, drives ordering.
        let mut sched = PriorityScheduler::new(1 << 16);
        let mut send_seq = [0u64; NUM_CLASSES];
        let mut expect_recv = [0u64; NUM_CLASSES];
        let mut order = ReliableOrder::new();
        let mut produced = 0usize;
        let mut delivered = 0usize;

        for _ in 0..40_000 {
            let r = next();
            if r & 1 == 0 {
                let classes = u64::try_from(NUM_CLASSES).unwrap();
                let class_byte = u8::try_from((r >> 8) % classes).unwrap_or(0);
                if let Some(class) = TrafficClass::from_u8(class_byte) {
                    let idx = usize::from(class.priority());
                    let frame = Frame {
                        class,
                        msg_type: 0,
                        sequence: send_seq[idx],
                        payload: Vec::new(),
                    };
                    // On backpressure, don't advance: a not-enqueued frame must
                    // not consume a sequence (no manufactured gap).
                    if sched.enqueue(frame).is_ok() {
                        send_seq[idx] += 1;
                        produced += 1;
                    }
                }
            } else if let Some(frame) = sched.dequeue() {
                let idx = usize::from(frame.class.priority());
                match order.admit(frame.class, frame.sequence) {
                    Admit::Fresh => {
                        assert_eq!(frame.sequence, expect_recv[idx]);
                        expect_recv[idx] += 1;
                        delivered += 1;
                    }
                    other => panic!(
                        "priority interleaving manufactured {other:?} for class {:?} seq {}",
                        frame.class, frame.sequence
                    ),
                }
            }
        }
        // Drain the remainder: still exactly-once, still in per-class order.
        while let Some(frame) = sched.dequeue() {
            let idx = usize::from(frame.class.priority());
            assert!(matches!(
                order.admit(frame.class, frame.sequence),
                Admit::Fresh
            ));
            assert_eq!(frame.sequence, expect_recv[idx]);
            expect_recv[idx] += 1;
            delivered += 1;
        }
        assert_eq!(
            produced, delivered,
            "every reliable frame delivered exactly once across arbitrary interleavings"
        );
        assert!(produced > 1000, "property exercised a meaningful volume");
    }
}
