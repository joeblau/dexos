//! Bounded Minimmit admission errors and slash-evidence types.
//!
//! The HotStuff vote/timeout collectors were deleted in Phase 5. This module
//! retains only shared safety primitives used by the Minimmit reactor and the
//! node's evidence-gossip seam.

use serde::{Deserialize, Serialize};
use types::Hash;

/// Maximum committee size, bounded by the certificate's 16-bit signer bitmap.
pub const MAX_VALIDATORS: usize = crypto::MAX_VALIDATORS;
/// Maximum number of views admitted ahead of the reactor's current view.
pub const DEFAULT_VIEW_HORIZON: u64 = 64;
/// Bound on retained slash/equivocation evidence.
pub const DEFAULT_EVIDENCE_LIMIT: usize = 256;
/// Per-validator bound on retained Minimmit votes.
pub const DEFAULT_VOTE_QUOTA: usize = 8192;

/// Verifiable evidence that a validator signed conflicting values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equivocation {
    /// The offending validator index.
    pub validator_index: u32,
    /// Epoch of the conflict.
    pub epoch: u64,
    /// View of the conflict.
    pub view: u64,
    /// Height of the conflict.
    pub height: u64,
    /// First block observed.
    pub first_block: Hash,
    /// Second conflicting block observed.
    pub second_block: Hash,
    /// Signature over the first value.
    #[serde(default, with = "crate::sig64::opt")]
    pub first_signature: Option<[u8; 64]>,
    /// Signature over the second value.
    #[serde(default, with = "crate::sig64::opt")]
    pub second_signature: Option<[u8; 64]>,
}

/// Slash evidence ready for gossip and operator hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashEvidence {
    /// Kind of misbehavior.
    pub kind: SlashKind,
    /// Conflicting signed values.
    pub equivocation: Option<Equivocation>,
    /// Epoch of the active committee when evidence was recorded.
    pub epoch: u64,
}

/// Classification of slashable Minimmit misbehavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashKind {
    /// Two conflicting notarize votes in the same view.
    NotarizeEquivocation,
    /// Two conflicting authenticated proposals at the same view.
    ProposalFork,
}

/// Callback invoked when slashable evidence is recorded.
pub trait SlashHook: Send {
    /// Handle newly recorded slash evidence.
    fn on_equivocation(&mut self, evidence: &SlashEvidence);
}

/// A no-op slash hook.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSlashHook;

impl SlashHook for NoopSlashHook {
    fn on_equivocation(&mut self, _evidence: &SlashEvidence) {}
}

/// A Minimmit vote/certificate admission failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VoteError {
    /// The signer index is outside the committee.
    #[error("foreign or out-of-range signer index {0}")]
    ForeignSigner(u32),
    /// The signature failed to verify.
    #[error("invalid consensus signature")]
    InvalidSignature,
    /// The committee is empty.
    #[error("empty committee")]
    EmptyCommittee,
    /// The committee exceeds the signer bitmap capacity.
    #[error("committee exceeds 16 validators")]
    TooManyValidators,
    /// Membership is noncanonical or contains an invalid key/weight.
    #[error("invalid validator set membership")]
    InvalidValidatorSet,
    /// The committee violates `W >= 5B + 1` or strict `M < L` separation.
    #[error(
        "committee weight {total_weight} cannot tolerate byzantine weight {byzantine_weight}: \
         minimmit requires W >= 5B + 1 with M < L"
    )]
    InsufficientSizing {
        /// Total committee voting weight.
        total_weight: u64,
        /// Byzantine weight bound.
        byzantine_weight: u64,
    },
    /// Vote epoch does not match the active committee.
    #[error("vote epoch mismatch")]
    EpochMismatch,
    /// Vote view is outside the admitted window.
    #[error("vote outside admitted window")]
    OutsideWindow,
    /// The validator exceeded its retained-vote quota.
    #[error("validator {0} exceeded its retained-vote quota")]
    QuotaExceeded(u32),
    /// The validator has been halted for prior equivocation.
    #[error("validator {0} is halted for equivocation")]
    HaltedOffender(u32),
}
