//! Peer identity and dialing descriptors.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// A peer's stable network identity: its 32-byte ed25519 public key.
///
/// Two connections that authenticate to the same `PeerId` are the *same logical
/// peer*, even if they arrive over different addresses/paths — this is the key
/// used for multipath de-duplication and connection migration.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct a peer id from raw public-key bytes.
    pub const fn new(public_key: [u8; 32]) -> Self {
        Self(public_key)
    }

    /// Derive the canonical identity from an authenticated ed25519 public key.
    ///
    /// The identity deliberately retains the public-key bytes. Discovery and
    /// transport can therefore compare the same value directly without a
    /// second, hash-derived `NodeId` namespace or an ambiguous conversion.
    pub const fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self(*public_key)
    }

    /// Construct an identity from its canonical wire bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
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
