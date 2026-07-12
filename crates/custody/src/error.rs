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
    /// The wallet address is already owned by (bound to) a different account.
    /// A wallet address is permanently owned by the first account it binds to;
    /// cross-account reuse is prohibited.
    #[error("wallet address is already bound to a different account")]
    CrossAccountReuse,
    /// A genesis master could not be established because the account already has
    /// a binding (its master, and possibly more). Later wallets attach through
    /// [`WalletRegistry::bind`], which requires the current master's signature.
    #[error("account already has an established master wallet")]
    AccountAlreadyEstablished,
    /// The genesis (first) binding for an account must designate its master.
    #[error("the first binding must designate a master wallet")]
    MasterRequired,
    /// The active master wallet cannot be revoked directly; the master must be
    /// rotated to another wallet first (so the account is never master-less).
    #[error("the active master cannot be revoked; rotate the master first")]
    MasterNotRevocable,
    /// The (account, nonce) binding was already consumed (replay).
    #[error("binding nonce already consumed")]
    ReplayedBinding,
    /// The (account, nonce) session authorization was already consumed (replay).
    /// Distinct from [`Self::ReplayedBinding`] so ops can separate wallet-bind
    /// replays from session-authorize replays in metrics and alerts.
    #[error("session authorization nonce already consumed")]
    ReplayedSession,
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
    /// No key is provisioned in the HSM / KMS backend for the given handle.
    #[error("no key provisioned for the given handle")]
    UnknownKeyHandle,
    /// The HSM-reported public key did not match the ceremony-published key a
    /// rotation attested against (a key-substitution attempt).
    #[error("HSM public key does not match the published key")]
    KeyAttestationFailed,

    // ---- certificate verification ----------------------------------------
    /// `withdrawal_id` did not equal the id derived from the request.
    #[error("withdrawal id mismatch")]
    MismatchedWithdrawalId,
    /// The reservation does not cover the requested amount.
    #[error("missing ledger reservation")]
    MissingLedgerReserve,
    /// The withdrawal authorization digest is not committed under the finalizing
    /// checkpoint (the inclusion proof did not verify against the signed root).
    #[error("withdrawal authorization not proven under finalizing checkpoint")]
    UnprovenAuthorization,
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
