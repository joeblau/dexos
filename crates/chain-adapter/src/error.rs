//! Typed error surface for chain adapters and the observation machinery.

use crate::codec::CodecError;
use thiserror::Error;

/// Fallible outcomes of adapter and certificate operations.
///
/// Every variant is a controlled, recoverable condition; no adapter path
/// panics on adversarial input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdapterError {
    /// The referenced transaction is not known to the (mock) chain.
    #[error("unknown transaction")]
    UnknownTx,
    /// The transaction exists but has not reached the finality threshold.
    #[error("insufficient finality: {have} of {need} confirmations")]
    NotFinal {
        /// Confirmations observed so far.
        have: u32,
        /// Confirmations required by the per-chain finality policy.
        need: u32,
    },
    /// A finality witness was empty or its header chain was not contiguous and
    /// hash-linked from the including block to the head.
    #[error("malformed finality witness")]
    InvalidWitness,
    /// A deposit's Merkle inclusion proof did not verify against the base
    /// block's committed root.
    #[error("deposit inclusion proof failed")]
    InvalidInclusion,
    /// A `(chain, tx, event)` triple was observed and credited already.
    #[error("duplicate observation (replay protection)")]
    DuplicateObservation,
    /// A withdrawal request's `expires_at` is at or before the current time.
    #[error("withdrawal request expired")]
    Expired,
    /// The withdrawal nonce was already consumed for this account.
    #[error("withdrawal nonce already used")]
    ReplayedNonce,
    /// The asset is not supported by this adapter.
    #[error("unsupported asset")]
    UnsupportedAsset,
    /// The request is structurally invalid (e.g. non-positive amount, empty
    /// destination address).
    #[error("invalid request")]
    InvalidRequest,
    /// A user/owner signature failed verification.
    #[error("invalid signature")]
    InvalidSignature,
    /// A withdrawal status transition was not a legal edge.
    #[error("illegal status transition")]
    IllegalTransition,
    /// A bounded ingress queue rejected work rather than growing unbounded.
    #[error("ingress capacity exceeded")]
    CapacityExceeded,
    /// The observer/finality quorum was not satisfied.
    #[error("quorum not satisfied")]
    QuorumNotMet,
    /// A fixed-point arithmetic operation overflowed or went out of range.
    #[error("arithmetic error")]
    Arithmetic,
    /// Byte-level decode failure.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
}

impl From<types::ArithError> for AdapterError {
    fn from(_: types::ArithError) -> Self {
        AdapterError::Arithmetic
    }
}
