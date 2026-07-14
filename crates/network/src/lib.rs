//! `network` — DexOS authenticated peer transport with priority traffic classes.
//!
//! This crate provides the node-to-node transport layer: an authenticated,
//! priority-aware, backpressured, replay-protected message pipe between peers.
//! It sits above [`codec`] (wire framing + [`TrafficClass`]), [`crypto`]
//! (ed25519 identity + handshake signatures), and [`types`], and is driven by
//! `tokio` async I/O.
//!
//! # Architecture
//!
//! * [`Transport`] — the pluggable transport trait ([`Transport::connect`] /
//!   [`Transport::accept`]).
//! * [`Connection`] — the per-peer handle exposing [`Connection::send_priority`],
//!   [`Connection::send_datagram`], [`Connection::recv`], and
//!   [`Connection::recv_datagram`].
//! * [`PriorityScheduler`] — strict-priority, bounded per-class queues; a
//!   saturated P8 sync backlog never starves or delays P0 consensus traffic, and
//!   a full class applies backpressure instead of growing without bound.
//! * [`ReplayWindow`] / [`PeerDedup`] — sliding-window duplicate/replay
//!   suppression, per stream and (for multipath / connection migration) per
//!   logical peer.
//!
//! # Implementations
//!
//! * [`LoopbackTransport`] — in-process, tokio-mpsc-backed, deterministic;
//!   used by the simulator and tests.
//! * [`TcpTransport`] — real sockets with length-prefixed [`codec::Frame`]
//!   framing and a mutually-authenticated ed25519 handshake. **Reduced
//!   guarantees vs QUIC:** every traffic class and the application "datagram"
//!   path share one ordered TCP byte stream, so a large P8 sync frame can
//!   head-of-line-block P0 consensus for the full transmit time of the payload.
//! * [`QuicTransport`] *(feature = `"quic"`)* — quinn/rustls QUIC with
//!   independent bidirectional streams per [`TrafficClass`], native RFC 9221
//!   DATAGRAM frames for lossy market data, and stream/connection flow-control
//!   sized so sync credit cannot starve consensus. Mutually authenticated via
//!   the same ed25519 handshake as TCP on a control stream.
//!
//! Compile-time availability is advertised by [`quic_supported`]. Production
//! configs that set `enable_quic` / `enable_datagrams` must be built with the
//! `quic` feature; the node composition root rejects those flags fail-closed
//! when the feature is absent (never a silent no-op).
//!
//! # Safety & robustness
//!
//! No `unsafe`, no floating point. Every decode path over untrusted bytes is
//! total (typed [`TransportError`], never a panic); inbound length headers are
//! bounded before allocation; and all queues are bounded with explicit
//! backpressure.

mod authenticated_order_batch;
pub mod batch;
mod budget;
mod channel;
mod class_auth;
mod connection;
mod disconnect;
mod error;
mod framing;
mod loopback;
mod order_batch;
mod order_batch_receipt;
mod peer;
mod reconnect;
mod replay;
mod scheduler;
mod session;
mod tcp;
mod transport;
mod util;

#[cfg(feature = "quic")]
mod quic;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "network";

/// Application message tag for a versioned compressed packed-order envelope.
pub const MSG_TYPE_ORDER_BATCH: u16 = 0x0101;
/// Application message tag for a correlated packed-batch lifecycle receipt.
pub const MSG_TYPE_ORDER_BATCH_RECEIPT: u16 = 0x0102;

/// Whether this build includes a real QUIC transport (`quinn`).
///
/// Used by the node config loader to fail closed when `enable_quic` /
/// `enable_datagrams` are requested without the `quic` feature.
#[must_use]
pub const fn quic_supported() -> bool {
    cfg!(feature = "quic")
}

// Re-export the wire types callers need so they need not depend on `codec`
// directly for the common path.
pub use codec::{Frame, TrafficClass};

pub use authenticated_order_batch::{
    decode_authenticated_order_batch_frame_into, inspect_authenticated_order_batch,
    AuthenticatedOrderBatchCodec, AuthenticatedOrderBatchError, AuthenticatedOrderBatchFrameError,
    AuthenticatedOrderBatchHeader, EncodedAuthenticatedOrderBatch, OrderBatchBinding,
    OrderBatchReplayGuard, VerifiedAuthenticatedOrderBatch, AUTHENTICATED_ORDER_BATCH_HEADER_LEN,
    AUTHENTICATED_ORDER_BATCH_MAX_WIRE, AUTHENTICATED_ORDER_BATCH_SIGNATURE_LEN,
    AUTHENTICATED_ORDER_BATCH_VERSION,
};
pub use batch::{BatchDropMetrics, BatchFrame, BatchSender, BatchSink, DropReason, DEFAULT_BATCH};
pub use budget::ByteBudget;
pub use class_auth::{authorize_class, ConsensusPermits, PeerRole};
pub use connection::{
    Connection, TransportConfig, DEFAULT_ACCEPT_QUEUE, DEFAULT_CAPABILITIES,
    DEFAULT_CONN_BUDGET_PER_PEER, DEFAULT_CONSENSUS_NODE_BYTES, DEFAULT_CONSENSUS_PEER_BYTES,
    DEFAULT_DATAGRAM_MAX_BYTES, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_IDLE_TIMEOUT,
    DEFAULT_KEEPALIVE_INTERVAL, DEFAULT_KEEPALIVE_TIME, DEFAULT_MAX_CLASS_BYTES,
    DEFAULT_MAX_HANDSHAKES, DEFAULT_MAX_NODE_BYTES, DEFAULT_MAX_PEER_BYTES, DEFAULT_MAX_SEQ_JUMP,
    DEFAULT_MAX_WIRE_VERSION, DEFAULT_MIN_WIRE_VERSION, DEFAULT_NETWORK_ID, DEFAULT_SEMANTIC_MAX,
    MSG_TYPE_DATAGRAM,
};
pub use disconnect::{classify_disconnect, DisconnectMetrics, DisconnectReason};
pub use error::TransportError;
pub use loopback::{LoopbackFabric, LoopbackTransport};
pub use order_batch::{
    DecodedOrderBatch, DecodedPackedOrderBatch, EncodedOrderBatch, OrderBatchCodec,
    OrderBatchError, OrderBatchStats, ORDER_BATCH_HEADER_LEN, ORDER_BATCH_MAX_UNCOMPRESSED,
    ORDER_BATCH_MAX_WIRE, ORDER_BATCH_VERSION,
};
pub use order_batch_receipt::{
    decode_order_batch_receipt_frame, encode_order_batch_receipt_frame, OrderBatchReceipt,
    OrderBatchReceiptError, OrderBatchReceiptStage, MAX_PENDING_ORDER_BATCH_FINALITY,
    ORDER_BATCH_RECEIPT_LEN, ORDER_BATCH_RECEIPT_VERSION,
};
pub use peer::{Peer, PeerId};
pub use reconnect::{
    ReconnectBackoff, ReconnectPolicy, DEFAULT_INITIAL_MS, DEFAULT_MAX_MS, DEFAULT_MULTIPLIER_DEN,
    DEFAULT_MULTIPLIER_NUM,
};
pub use replay::{
    PeerDedup, ReplayAdmit, ReplayWindow, DEFAULT_MAX_JUMP, DEFAULT_WINDOW, MAX_WINDOW,
};
pub use scheduler::{
    PriorityScheduler, DEFAULT_CLASS_WEIGHTS, DEFAULT_P0_QUANTUM_BYTES, NUM_CLASSES,
};
pub use tcp::{Membership, TcpTransport};
pub use transport::Transport;

#[cfg(feature = "quic")]
pub use quic::QuicTransport;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "network");
    }

    #[test]
    fn public_surface_is_reachable() {
        // A compile-time smoke check that the public API is wired up.
        assert_eq!(NUM_CLASSES, 9);
        assert_eq!(MSG_TYPE_DATAGRAM, 0xFFFF);
        let _cfg = TransportConfig::default();
        let _peer = Peer::loopback(PeerId::from([0u8; 32]));
        let _class = TrafficClass::Consensus;
    }

    #[test]
    fn quic_supported_matches_feature_flag() {
        assert_eq!(quic_supported(), cfg!(feature = "quic"));
    }
}
