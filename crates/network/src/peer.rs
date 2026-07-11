//! Peer identity and dialing descriptors.

use std::net::SocketAddr;

/// A peer's stable network identity: its 32-byte ed25519 public key.
///
/// Two connections that authenticate to the same `PeerId` are the *same logical
/// peer*, even if they arrive over different addresses/paths — this is the key
/// used for multipath de-duplication and connection migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct a peer id from raw public-key bytes.
    pub const fn new(public_key: [u8; 32]) -> Self {
        Self(public_key)
    }

    /// The raw public-key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PeerId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// A dialing descriptor: who to connect to, and (for network transports) where.
///
/// The loopback transport uses only [`Peer::id`]. The TCP transport requires
/// [`Peer::addr`] to dial and uses [`Peer::id`] as the *expected* identity: the
/// handshake is rejected with [`crate::TransportError::AuthFailed`] if the peer
/// on the far end presents a different public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// The expected authenticated identity of the peer.
    pub id: PeerId,
    /// The address to dial. `None` for in-process transports.
    pub addr: Option<SocketAddr>,
}

impl Peer {
    /// A loopback peer, addressed purely by identity.
    pub const fn loopback(id: PeerId) -> Self {
        Self { id, addr: None }
    }

    /// A network peer with an address and expected identity.
    pub const fn dial(id: PeerId, addr: SocketAddr) -> Self {
        Self {
            id,
            addr: Some(addr),
        }
    }
}
