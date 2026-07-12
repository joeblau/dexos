//! An ergonomic control-command signer.
//!
//! Delegates entirely to [`proto::ControlMeta::signed`] — it never re-derives the
//! `dexos.rpc.control.v1` preimage — and mirrors the proven `crates/client`
//! signer shape (a stable client id, a keypair, an optional session pubkey, and
//! a monotonic nonce).

use core::sync::atomic::{AtomicU64, Ordering};

use crypto::KeyPair;
use proto::{Command, ControlMeta, RpcError};

/// Signs control commands with a monotonically increasing nonce.
pub struct Signer {
    client_id: u64,
    keypair: KeyPair,
    session_pubkey: Option<[u8; 32]>,
    nonce: AtomicU64,
}

impl Signer {
    /// A signer that authorizes with an account's root key (no session key).
    pub fn root(client_id: u64, keypair: KeyPair, start_nonce: u64) -> Self {
        Self {
            client_id,
            keypair,
            session_pubkey: None,
            nonce: AtomicU64::new(start_nonce),
        }
    }

    /// A signer that authorizes with a delegated session key. The session key's
    /// public key is bound into every envelope's signing preimage.
    pub fn with_session(client_id: u64, session: KeyPair, start_nonce: u64) -> Self {
        let pk = session.public();
        Self {
            client_id,
            keypair: session,
            session_pubkey: Some(pk),
            nonce: AtomicU64::new(start_nonce),
        }
    }

    /// The client id this signer stamps into every envelope.
    pub fn client_id(&self) -> u64 {
        self.client_id
    }

    /// The next nonce this signer would consume (for observability / tests).
    pub fn peek_nonce(&self) -> u64 {
        self.nonce.load(Ordering::SeqCst)
    }

    /// Sign `command`, consuming one nonce, and return the control envelope.
    pub fn sign(&self, command: &Command) -> Result<ControlMeta, RpcError> {
        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);
        ControlMeta::signed(
            self.client_id,
            nonce,
            self.session_pubkey,
            &self.keypair,
            command,
        )
    }
}
