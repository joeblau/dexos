//! Typed error surface for the light client.
//!
//! Every fallible operation returns a [`LightClientError`]; nothing panics on
//! adversarial checkpoint, proof, or RPC input. Operations a light node must
//! never perform (order entry, deposits, voting, execution) surface as
//! [`LightClientError::Unsupported`] with a specific [`UnsupportedOp`], so the
//! refusal is explicit and machine-readable rather than a silent no-op.

use core::fmt;

use consensus::CheckpointError;
use types::ShardId;

/// An operation a light node is structurally forbidden from performing.
///
/// A light node ingests and verifies checkpoints and answers read-only,
/// proof-backed queries. It does not vote, execute canonical state, or accept
/// order entry — every such request is refused with one of these tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedOp {
    /// Submitting a new order to the matching engine.
    SubmitOrder,
    /// Cancelling a resting order.
    CancelOrder,
    /// Amending a resting order.
    AmendOrder,
    /// Depositing collateral / funds.
    Deposit,
    /// Withdrawing collateral / funds.
    Withdraw,
    /// Casting a consensus vote.
    Vote,
    /// Executing canonical state transitions.
    Execute,
    /// Persisting the full command log / journal.
    PersistCommandLog,
}

impl fmt::Display for UnsupportedOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            UnsupportedOp::SubmitOrder => "submit_order",
            UnsupportedOp::CancelOrder => "cancel_order",
            UnsupportedOp::AmendOrder => "amend_order",
            UnsupportedOp::Deposit => "deposit",
            UnsupportedOp::Withdraw => "withdraw",
            UnsupportedOp::Vote => "vote",
            UnsupportedOp::Execute => "execute",
            UnsupportedOp::PersistCommandLog => "persist_command_log",
        };
        f.write_str(name)
    }
}

/// A light-client failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LightClientError {
    /// The underlying checkpoint verification (QC / hash / range) failed.
    #[error("checkpoint verification failed: {0}")]
    Checkpoint(#[from] CheckpointError),
    /// No validator set is registered for the checkpoint's epoch, so its quorum
    /// certificate cannot be verified against a trusted committee.
    #[error("no validator set is known for epoch {epoch}")]
    UnknownValidatorSet {
        /// The epoch whose validator set is missing.
        epoch: u64,
    },
    /// The checkpoint targets a different shard than this sync tracks.
    #[error("checkpoint for shard {got} but this client tracks shard {expected}")]
    ShardMismatch {
        /// The shard this client is following.
        expected: u16,
        /// The shard the checkpoint claims.
        got: u16,
    },
    /// The first accepted checkpoint did not chain onto the trusted root.
    #[error("checkpoint does not link to the trusted root")]
    UntrustedRoot,
    /// A next-in-line checkpoint's `previous_state_root` did not match the
    /// verified tip's `new_state_root`.
    #[error("broken ancestry linkage from the verified tip")]
    BrokenAncestry,
    /// A checkpoint conflicts with one already accepted for the same range.
    #[error("equivocating checkpoint over range [{first}, {last}]")]
    Equivocation {
        /// First sequence of the conflicting range.
        first: u64,
        /// Last sequence of the conflicting range.
        last: u64,
    },
    /// A checkpoint conflicts with territory that has been pruned from local
    /// history; peers must supply slash/equivocation evidence rather than the
    /// light client silently treating it as a stale duplicate.
    #[error("pruned-history conflict over range [{first}, {last}]")]
    PrunedHistoryConflict {
        /// First sequence of the conflicting range.
        first: u64,
        /// Last sequence of the conflicting range.
        last: u64,
    },
    /// Host attempted to replace a validator set without a quorum-proven
    /// transition (or without weak-subjectivity bootstrap).
    #[error("unsolicited validator-set install for epoch {epoch}")]
    UnsolicitedValidatorSet {
        /// Epoch the host tried to install.
        epoch: u64,
    },
    /// A bootstrap set did not use Minimmit's canonical L threshold.
    #[error("validator set for epoch {epoch} is not a canonical Minimmit L-set")]
    NonCanonicalValidatorSet {
        /// Epoch the invalid bootstrap attempted to install.
        epoch: u64,
    },
    /// A validator-set transition certificate failed verification or was
    /// malformed (wrong epochs, wrong digest, below-threshold QC).
    #[error("invalid validator-set transition {old_epoch} -> {new_epoch}")]
    InvalidValidatorSetTransition {
        /// Prior epoch.
        old_epoch: u64,
        /// Claimed new epoch.
        new_epoch: u64,
    },
    /// A query requiring a verified state root was made before any checkpoint
    /// had been verified.
    #[error("no verified checkpoint is available yet")]
    NoVerifiedCheckpoint,
    /// A write / control operation forbidden in light mode was requested.
    #[error("operation `{0}` is not supported by a light node")]
    Unsupported(UnsupportedOp),
}

impl LightClientError {
    /// Construct a shard-mismatch error from the typed ids.
    #[must_use]
    pub fn shard_mismatch(expected: ShardId, got: ShardId) -> Self {
        LightClientError::ShardMismatch {
            expected: expected.get(),
            got: got.get(),
        }
    }
}
