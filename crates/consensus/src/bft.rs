//! Consensus commitments and migration-stable evidence shared by Minimmit.
//!
//! The former HotStuff lifecycle engine lived in this module. Phase 5 removes
//! that engine while retaining the execution-certificate digest and the small
//! data structures consumed by checkpoint, epoch, and operator layers.

use serde::{Deserialize, Serialize};

use crypto::{hash_domain, Validator};
use types::Hash;

/// Domain tag for the execution-commitment digest an execution certificate signs.
pub const DOMAIN_EXEC_COMMIT: &[u8] = b"dexos:consensus:exec-commit:v1";

/// The canonical digest an execution certificate signs, binding a finalized
/// block to the deterministic execution root it produced.
#[must_use]
pub fn execution_commitment_digest(
    epoch: u64,
    view: u64,
    height: u64,
    block_hash: Hash,
    execution_root: Hash,
) -> Hash {
    let mut buf = [0u8; 8 * 3 + 32 + 32];
    buf[0..8].copy_from_slice(&epoch.to_le_bytes());
    buf[8..16].copy_from_slice(&view.to_le_bytes());
    buf[16..24].copy_from_slice(&height.to_le_bytes());
    buf[24..56].copy_from_slice(block_hash.as_bytes());
    buf[56..88].copy_from_slice(execution_root.as_bytes());
    hash_domain(DOMAIN_EXEC_COMMIT, &buf)
}

/// Verifiable evidence of a fork: two distinct blocks proposed at the same
/// height and view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fork {
    /// The conflicted height.
    pub height: u64,
    /// The conflicted view.
    pub view: u64,
    /// First block observed.
    pub first_block: Hash,
    /// Second, conflicting block observed.
    pub second_block: Hash,
}

/// An explicit validator-set change that activates at an epoch boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetUpdate {
    /// The epoch at which the new set becomes active.
    pub activation_epoch: u64,
    /// The new validator set (with weights).
    pub validators: Vec<Validator>,
}
