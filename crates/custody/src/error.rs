//! The single typed error surface for the custody edge.
//!
//! Every fallible operation in this crate returns [`CustodyError`]. It is total:
//! decoding and verification of arbitrary/adversarial bytes yields an `Err`,
//! never a panic. Errors from the foundation crates are wrapped, and the
//! custody-specific conditions get dedicated, matchable variants.

use crypto::{CryptoError, QuorumError};
use types::ArithError;

/// A custody-edge failure.
///
/// Variants are grouped by subsystem: wallet binding, scoped sessions, the
/// threshold signer set, independent certificate verification, and the custody
/// controller (rotation / halt / policy / duplicate suppression).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    // ---- wallet binding ---------------------------------------------------
    /// An address had the wrong length or an unknown chain tag.
    #[error("malformed wallet address or chain tag")]
    MalformedAddress,
    /// A public key could not be parsed.
    #[error("malformed public key")]
    MalformedKey,
    /// A signature could not be parsed.
    #[error("malformed signature")]
    MalformedSignature,
    /// A signature did not verify against the key and message.
    #[error("invalid signature")]
    InvalidSignature,
    /// The address derived from the proof key did not match the claimed address.
    #[error("proof key does not derive the claimed address")]
    AddressMismatch,
    /// The (account, address) pair is already actively bound.
    #[error("wallet already bound to this account")]
    DuplicateBinding,
    /// The (account, nonce) binding was already consumed (replay).
    #[error("binding nonce already consumed")]
    ReplayedBinding,
    /// Binding would exceed the per-account wallet cap.
    #[error("per-account binding cap exceeded")]
    BindingCapExceeded,
    /// No active binding for the requested (account, address).
    #[error("wallet is not bound to this account")]
    UnknownWallet,
    /// The account has no master wallet, or the proof did not match it.
    #[error("no matching master wallet")]
    NotMaster,
    /// The wallet is not flagged for withdrawal authorization.
    #[error("wallet is not permitted to authorize withdrawals")]
    WithdrawalNotAllowed,

    // ---- scoped sessions --------------------------------------------------
    /// No session key for the requested (account, session key).
    #[error("unknown session key")]
    UnknownSession,
    /// The session's expiry sequence has passed.
    #[error("session expired")]
    SessionExpired,
    /// The session was revoked at or before this sequence.
    #[error("session revoked")]
    SessionRevoked,
    /// The requested action falls outside the session's granted scope.
    #[error("request outside session scope")]
    OutOfScope,

    // ---- threshold signer set --------------------------------------------
    /// `threshold == 0`, `threshold > n`, `n == 0`, or `n > 64`.
    #[error("invalid signer-set threshold or size")]
    InvalidThreshold,
    /// Fewer than `threshold` distinct valid shares were supplied.
    #[error("threshold not met")]
    ThresholdNotMet,
    /// A share referenced a signer index outside the set.
    #[error("unknown signer index")]
    UnknownSigner,

    // ---- certificate verification ----------------------------------------
    /// `withdrawal_id` did not equal the id derived from the request.
    #[error("withdrawal id mismatch")]
    MismatchedWithdrawalId,
    /// The certificate is not marked finalized.
    #[error("certificate not finalized")]
    NotFinalized,
    /// The ledger reservation for the withdrawal is not satisfied.
    #[error("missing ledger reservation")]
    MissingLedgerReserve,
    /// The certificate is past its validity window.
    #[error("certificate expired")]
    Expired,
    /// The quorum certificate did not verify over the finalizing checkpoint.
    #[error("bad quorum signature over checkpoint")]
    BadQuorumSignature,

    // ---- custody controller ----------------------------------------------
    /// Signing is blocked because the subsystem is in emergency halt.
    #[error("emergency halt engaged")]
    EmergencyHalt,
    /// This withdrawal id has already been signed once.
    #[error("withdrawal already signed")]
    DuplicateSign,
    /// No policy is configured for the certificate's chain id.
    #[error("unknown chain id")]
    UnknownChain,
    /// A per-chain withdrawal policy limit was violated.
    #[error("per-chain policy violation")]
    PolicyViolation,
    /// A rotation targeted an epoch not strictly newer than the current one.
    #[error("rotation epoch is not newer than current")]
    StaleEpoch,

    // ---- arithmetic / wire ------------------------------------------------
    /// A fixed-point accumulation overflowed.
    #[error("arithmetic overflow")]
    Overflow,
    /// A byte payload was truncated, over-long, or otherwise malformed.
    #[error("malformed encoded payload")]
    Decode,
}

impl From<CryptoError> for CustodyError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::MalformedKey => Self::MalformedKey,
            CryptoError::MalformedSignature => Self::MalformedSignature,
            CryptoError::InvalidSignature => Self::InvalidSignature,
        }
    }
}

impl From<QuorumError> for CustodyError {
    fn from(_: QuorumError) -> Self {
        Self::BadQuorumSignature
    }
}

impl From<ArithError> for CustodyError {
    fn from(_: ArithError) -> Self {
        Self::Overflow
    }
}
