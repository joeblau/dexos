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
//!   framing and a mutually-authenticated ed25519 handshake.
//!
//! ## Future: QUIC adapter
//!
//! A QUIC transport (native multiplexed streams for the reliable classes plus a
//! true unreliable datagram path, 0-RTT resumption, and connection migration) is
//! a planned future implementation behind the very same [`Transport`] trait. It
//! is intentionally **not** built yet: no `quinn`/QUIC dependency is introduced
//! at this phase. The [`Connection`] surface (priority send, datagram send,
//! per-peer dedup) was shaped so a QUIC backend drops in without changing
//! callers — the [`TcpTransport`] multiplexes both streams over one ordered
//! connection today; QUIC would map them onto independent streams natively.
//!
//! # Safety & robustness
//!
//! No `unsafe`, no floating point. Every decode path over untrusted bytes is
//! total (typed [`TransportError`], never a panic); inbound length headers are
//! bounded before allocation; and all queues are bounded with explicit
//! backpressure.

pub mod batch;
mod budget;
mod channel;
mod connection;
mod error;
mod framing;
mod loopback;
mod peer;
mod replay;
mod scheduler;
mod session;
mod tcp;
mod transport;
mod util;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "network";

// Re-export the wire types callers need so they need not depend on `codec`
// directly for the common path.
pub use codec::{Frame, TrafficClass};

pub use budget::ByteBudget;
pub use connection::{
    Connection, TransportConfig, DEFAULT_ACCEPT_QUEUE, DEFAULT_DATAGRAM_MAX_BYTES,
    DEFAULT_MAX_CLASS_BYTES, DEFAULT_MAX_NODE_BYTES, DEFAULT_MAX_PEER_BYTES, DEFAULT_SEMANTIC_MAX,
    MSG_TYPE_DATAGRAM,
};
pub use error::TransportError;
pub use loopback::{LoopbackFabric, LoopbackTransport};
pub use peer::{Peer, PeerId};
pub use replay::{PeerDedup, ReplayWindow, DEFAULT_WINDOW, MAX_WINDOW};
pub use scheduler::{PriorityScheduler, NUM_CLASSES};
pub use tcp::TcpTransport;
pub use transport::Transport;

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
}
