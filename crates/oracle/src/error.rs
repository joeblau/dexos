//! Typed error surface for the oracle subsystem.
//!
//! Every fallible operation in this crate returns [`OracleError`] rather than
//! panicking. Decoding of untrusted bytes and verification of adversarial
//! certificates are total: they yield an `Err`, never a panic.

use crypto::{CryptoError, QuorumError};
use types::ArithError;

/// A failure in observation verification, aggregation, certificate handling, or
/// the oracle engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OracleError {
    /// The observation/certificate signature bytes were malformed.
    #[error("malformed signature")]
    MalformedSignature,
    /// The signature did not verify against the named signer and canonical bytes.
    #[error("invalid signature")]
    InvalidSignature,
    /// The named signer key was malformed (not a valid ed25519 public key).
    #[error("malformed signer key")]
    MalformedSigner,
    /// A producer-registry entry was rejected (source id out of range, a negative
    /// confidence cap, or a duplicate signer).
    #[error("invalid producer registry entry")]
    InvalidProducer,
    /// No observations remained to aggregate (all filtered, or none supplied).
    #[error("no observations to aggregate")]
    NoObservations,
    /// Fewer usable observations than the configured minimum after filtering.
    #[error("too few observations: have {have}, need {need}")]
    TooFewObservations {
        /// Observations that survived filtering.
        have: usize,
        /// Configured minimum.
        need: usize,
    },
    /// Fewer distinct venue sources than the configured minimum.
    #[error("too few distinct sources: have {have}, need {need}")]
    TooFewSources {
        /// Distinct sources present (union popcount).
        have: u32,
        /// Configured minimum distinct sources.
        need: u32,
    },
    /// An applied certificate did not advance the per-market sequence.
    #[error("stale sequence: have {have}, got {got}")]
    StaleSequence {
        /// Sequence currently committed.
        have: u64,
        /// Sequence carried by the rejected update.
        got: u64,
    },
    /// A certificate's quorum message did not equal the recomputed digest.
    #[error("certificate digest mismatch")]
    DigestMismatch,
    /// The underlying quorum certificate failed to verify.
    #[error("quorum verification failed: {0}")]
    Quorum(#[from] QuorumError),
    /// A fixed-point arithmetic failure occurred during aggregation.
    #[error("arithmetic failure: {0}")]
    Arith(#[from] ArithError),
    /// Binary (de)serialization failed.
    #[error("codec failure")]
    Codec,
}

impl From<CryptoError> for OracleError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::MalformedKey => OracleError::MalformedSigner,
            CryptoError::MalformedSignature => OracleError::MalformedSignature,
            CryptoError::InvalidSignature => OracleError::InvalidSignature,
        }
    }
}
