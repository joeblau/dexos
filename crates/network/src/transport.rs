//! The [`Transport`] trait: the pluggable authenticated peer-transport surface.
//!
//! Implementations: [`crate::LoopbackTransport`] (in-process, deterministic) and
//! [`crate::TcpTransport`] (real sockets, authenticated handshake, length-prefixed
//! framing). A QUIC adapter is a documented future implementation behind this
//! same trait — see the crate docs — and deliberately not built yet (no `quinn`
//! dependency is introduced).
//!
//! The per-message send / receive operations live on the [`Connection`] handle
//! returned by [`Transport::connect`] / [`Transport::accept`], so a caller can
//! multiplex many peers over one transport and address each independently.

use crate::connection::Connection;
use crate::error::TransportError;
use crate::peer::Peer;

/// An authenticated peer transport.
///
/// `async fn` in a public trait is intentional here; callers use concrete
/// transport types (or generics over `T: Transport`) rather than trait objects,
/// so the auto-trait-leakage caveat does not apply. Boxing for `dyn Transport`
/// can be layered on top if ever needed.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Dial `peer`, performing any authenticated handshake, and return a
    /// connection handle. Fails with a typed [`TransportError`] (never a panic)
    /// on unreachable peers or handshake/identity failure.
    async fn connect(&self, peer: &Peer) -> Result<Connection, TransportError>;

    /// Await the next inbound connection, performing any authenticated
    /// handshake, and return its connection handle.
    async fn accept(&self) -> Result<Connection, TransportError>;
}
