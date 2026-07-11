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
//! Both directions stamp a monotonic per-stream sequence number and apply a
//! [`ReplayWindow`] on receive, so duplicates and stale replays are suppressed
//! and each `(sequence)` is delivered at most once.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use codec::{Frame, TrafficClass, MAX_FRAME_PAYLOAD};
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use crate::channel::AsyncPriorityChannel;
use crate::error::TransportError;
use crate::peer::PeerId;
use crate::replay::ReplayWindow;

/// Reserved `msg_type` marking a frame as an unreliable datagram on transports
/// that multiplex both streams over one wire (e.g. TCP). Application reliable
/// messages must not use this value.
pub const MSG_TYPE_DATAGRAM: u16 = 0xFFFF;

/// Tunables shared by all transports.
#[derive(Debug, Clone, Copy)]
pub struct TransportConfig {
    /// Per-class reliable queue capacity (frames). Bounds memory per class.
    pub queue_capacity: usize,
    /// Datagram channel capacity (frames).
    pub datagram_capacity: usize,
    /// Anti-replay window width (sequence numbers) per stream.
    pub dedup_window: u64,
    /// Maximum application payload accepted per message.
    pub max_payload: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            datagram_capacity: 1024,
            dedup_window: crate::replay::DEFAULT_WINDOW,
            max_payload: MAX_FRAME_PAYLOAD,
        }
    }
}

/// An authenticated, priority-aware connection to a single peer.
///
/// Cheap to hold but not `Clone`: dropping it closes the outbound reliable
/// channel (signalling the peer) and aborts any background I/O tasks.
#[derive(Debug)]
pub struct Connection {
    peer: PeerId,
    out_reliable: Arc<AsyncPriorityChannel>,
    in_reliable: Arc<AsyncPriorityChannel>,
    out_datagram: mpsc::Sender<Frame>,
    in_datagram: AsyncMutex<mpsc::Receiver<Frame>>,
    seq_reliable: AtomicU64,
    seq_datagram: AtomicU64,
    dedup_reliable: Mutex<ReplayWindow>,
    dedup_datagram: Mutex<ReplayWindow>,
    max_payload: usize,
    tasks: Vec<JoinHandle<()>>,
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
        Self {
            peer,
            out_reliable,
            in_reliable,
            out_datagram,
            in_datagram: AsyncMutex::new(in_datagram),
            seq_reliable: AtomicU64::new(0),
            seq_datagram: AtomicU64::new(0),
            dedup_reliable: Mutex::new(ReplayWindow::new(cfg.dedup_window)),
            dedup_datagram: Mutex::new(ReplayWindow::new(cfg.dedup_window)),
            max_payload: cfg.max_payload.min(MAX_FRAME_PAYLOAD),
            tasks,
        }
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
        if message.len() > self.max_payload {
            return Err(TransportError::MessageTooLarge);
        }
        let sequence = self.seq_reliable.fetch_add(1, Ordering::Relaxed);
        let frame = Frame {
            class,
            msg_type,
            sequence,
            payload: message.to_vec(),
        };
        self.out_reliable.try_send(frame)
    }

    /// Send a best-effort datagram (unreliable, unordered).
    ///
    /// Returns [`TransportError::Backpressure`] if the bounded datagram channel
    /// is full (the datagram is shed, not buffered) — lossy delivery never
    /// touches the reliable priority queues.
    pub fn send_datagram(&self, message: &[u8]) -> Result<(), TransportError> {
        if message.len() > self.max_payload {
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

    /// Await the next reliable message, in strict priority order, after
    /// duplicate/replay suppression. Returns the delivered [`Frame`].
    pub async fn recv(&self) -> Result<Frame, TransportError> {
        loop {
            let frame = self
                .in_reliable
                .recv()
                .await
                .ok_or(TransportError::ConnectionClosed)?;
            let fresh = self
                .dedup_reliable
                .lock()
                .expect("dedup mutex poisoned")
                .check(frame.sequence);
            if fresh {
                return Ok(frame);
            }
            // Duplicate / replay: suppress and wait for the next frame.
        }
    }

    /// Await the next fresh datagram payload, after duplicate/replay
    /// suppression. Suppressed datagrams are skipped, never surfaced.
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let mut rx = self.in_datagram.lock().await;
        loop {
            let frame = rx.recv().await.ok_or(TransportError::ConnectionClosed)?;
            let fresh = self
                .dedup_datagram
                .lock()
                .expect("dedup mutex poisoned")
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
