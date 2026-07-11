//! Checkpoints: canonical range commitments, quorum verification, ancestry, and
//! threshold witness receipts.
//!
//! A [`Checkpoint`] commits a shard's state transition over a contiguous
//! sequence range. Its signed content is the [`CheckpointHeader`]; the
//! [`checkpoint_hash`] is domain-separated and architecture-independent. A
//! checkpoint verifies against a [`crypto::ValidatorSet`] when its embedded
//! [`QuorumCertificate`] signs exactly the recomputed header hash and meets the
//! set's threshold.
//!
//! [`WitnessReceipt`]s let independent witnesses attest that an executed range
//! produced a given `execution_root`; a threshold of distinct receipts is
//! collected into a [`QuorumCertificate`] via [`WitnessCollector`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crypto::{hash_domain, merkle_root, verify_ed25519, QuorumCertificate, ValidatorSet};
use state_tree::checkpoint_root;
use types::{Hash, ShardId, StateRoot};

use crate::vote::{Committee, MAX_VALIDATORS};

/// Domain tag for checkpoint header hashing.
pub const DOMAIN_CHECKPOINT: &[u8] = b"dexos:checkpoint:header:v1";
/// Domain tag for witness-receipt digests.
pub const DOMAIN_WITNESS: &[u8] = b"dexos:checkpoint:witness:v1";

/// The signed content of a checkpoint (everything except the quorum
/// certificate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHeader {
    /// Epoch the checkpoint was produced in.
    pub epoch: u64,
    /// The shard this checkpoint covers.
    pub shard_id: ShardId,
    /// First sequence covered (inclusive).
    pub first_sequence: u64,
    /// Last sequence covered (inclusive).
    pub last_sequence: u64,
    /// State root before applying the range.
    pub previous_state_root: Hash,
    /// State root after applying the range.
    pub new_state_root: Hash,
    /// Merkle root over the range's command hashes.
    pub command_root: Hash,
    /// Merkle root over the range's execution-result hashes.
    pub execution_root: Hash,
    /// Root committing to the oracle inputs used.
    pub oracle_root: Hash,
    /// Producer timestamp (opaque, monotonic per shard).
    pub timestamp: u64,
}

impl CheckpointHeader {
    /// The canonical, domain-separated checkpoint hash.
    ///
    /// Deterministic and architecture-independent: every field is encoded
    /// little-endian in a fixed order and hashed under [`DOMAIN_CHECKPOINT`].
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 * 4 + 2 + 32 * 5);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.shard_id.get().to_le_bytes());
        buf.extend_from_slice(&self.first_sequence.to_le_bytes());
        buf.extend_from_slice(&self.last_sequence.to_le_bytes());
        buf.extend_from_slice(self.previous_state_root.as_bytes());
        buf.extend_from_slice(self.new_state_root.as_bytes());
        buf.extend_from_slice(self.command_root.as_bytes());
        buf.extend_from_slice(self.execution_root.as_bytes());
        buf.extend_from_slice(self.oracle_root.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        hash_domain(DOMAIN_CHECKPOINT, &buf)
    }
}

/// A full, quorum-signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Epoch the checkpoint was produced in.
    pub epoch: u64,
    /// The shard this checkpoint covers.
    pub shard_id: ShardId,
    /// First sequence covered (inclusive).
    pub first_sequence: u64,
    /// Last sequence covered (inclusive).
    pub last_sequence: u64,
    /// State root before applying the range.
    pub previous_state_root: Hash,
    /// State root after applying the range.
    pub new_state_root: Hash,
    /// Merkle root over the range's command hashes.
    pub command_root: Hash,
    /// Merkle root over the range's execution-result hashes.
    pub execution_root: Hash,
    /// Root committing to the oracle inputs used.
    pub oracle_root: Hash,
    /// Producer timestamp.
    pub timestamp: u64,
    /// Quorum certificate over [`Checkpoint::header`]'s hash.
    pub quorum_certificate: QuorumCertificate,
}

impl Checkpoint {
    /// The signed header view of this checkpoint (drops the QC).
    #[must_use]
    pub fn header(&self) -> CheckpointHeader {
        CheckpointHeader {
            epoch: self.epoch,
            shard_id: self.shard_id,
            first_sequence: self.first_sequence,
            last_sequence: self.last_sequence,
            previous_state_root: self.previous_state_root,
            new_state_root: self.new_state_root,
            command_root: self.command_root,
            execution_root: self.execution_root,
            oracle_root: self.oracle_root,
            timestamp: self.timestamp,
        }
    }

    /// The canonical checkpoint hash (of the header).
    #[must_use]
    pub fn hash(&self) -> Hash {
        self.header().hash()
    }
}

/// The canonical checkpoint hash of a header (free-function form).
#[must_use]
pub fn checkpoint_hash(header: &CheckpointHeader) -> Hash {
    header.hash()
}

/// A checkpoint-layer failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    /// `last_sequence < first_sequence`.
    #[error("range out of order: [{first}, {last}]")]
    RangeOutOfOrder {
        /// Requested start.
        first: u64,
        /// Requested end.
        last: u64,
    },
    /// The number of per-item hashes did not match the range width.
    #[error("range width {width} does not match {items} items")]
    LengthMismatch {
        /// Expected number of items (`last - first + 1`).
        width: u64,
        /// Number of items provided.
        items: u64,
    },
    /// The QC does not sign the recomputed header hash.
    #[error("quorum certificate does not match checkpoint hash")]
    HashMismatch,
    /// The QC failed verification (bad signer / signature / below threshold).
    #[error("quorum verification failed")]
    Quorum,
    /// Ancestry linkage between two checkpoints is broken.
    #[error("broken checkpoint ancestry")]
    BrokenAncestry,
    /// A witness index is outside the committee (or beyond bitmap capacity).
    #[error("foreign or out-of-range witness index {0}")]
    ForeignWitness(u32),
    /// A witness signature failed to verify.
    #[error("invalid witness signature")]
    InvalidWitnessSignature,
    /// Two conflicting receipts from the same witness for the same range.
    #[error("witness equivocation")]
    WitnessEquivocation,
    /// Not enough distinct witness weight to reach threshold.
    #[error("witness receipts below threshold")]
    BelowThreshold,
}

/// Build a [`CheckpointHeader`] over an executed sequence range.
///
/// `command_hashes` / `execution_hashes` are the per-item hashes over the
/// inclusive range `[first_sequence, last_sequence]`; their Merkle roots become
/// the header's `command_root` / `execution_root`. Requires the two slices to be
/// equal-length and to match the range width.
#[allow(clippy::too_many_arguments)]
pub fn build_checkpoint_header(
    epoch: u64,
    shard_id: ShardId,
    first_sequence: u64,
    last_sequence: u64,
    previous_state_root: Hash,
    new_state_root: Hash,
    command_hashes: &[Hash],
    execution_hashes: &[Hash],
    oracle_root: Hash,
    timestamp: u64,
) -> Result<CheckpointHeader, CheckpointError> {
    if last_sequence < first_sequence {
        return Err(CheckpointError::RangeOutOfOrder {
            first: first_sequence,
            last: last_sequence,
        });
    }
    let width = last_sequence
        .checked_sub(first_sequence)
        .and_then(|d| d.checked_add(1))
        .ok_or(CheckpointError::RangeOutOfOrder {
            first: first_sequence,
            last: last_sequence,
        })?;
    let cmd_items = u64::try_from(command_hashes.len()).unwrap_or(u64::MAX);
    let exec_items = u64::try_from(execution_hashes.len()).unwrap_or(u64::MAX);
    if cmd_items != width {
        return Err(CheckpointError::LengthMismatch {
            width,
            items: cmd_items,
        });
    }
    if exec_items != width {
        return Err(CheckpointError::LengthMismatch {
            width,
            items: exec_items,
        });
    }
    Ok(CheckpointHeader {
        epoch,
        shard_id,
        first_sequence,
        last_sequence,
        previous_state_root,
        new_state_root,
        command_root: merkle_root(command_hashes),
        execution_root: merkle_root(execution_hashes),
        oracle_root,
        timestamp,
    })
}

/// Attach a quorum certificate to a header, producing a full [`Checkpoint`].
#[must_use]
pub fn seal_checkpoint(
    header: CheckpointHeader,
    quorum_certificate: QuorumCertificate,
) -> Checkpoint {
    Checkpoint {
        epoch: header.epoch,
        shard_id: header.shard_id,
        first_sequence: header.first_sequence,
        last_sequence: header.last_sequence,
        previous_state_root: header.previous_state_root,
        new_state_root: header.new_state_root,
        command_root: header.command_root,
        execution_root: header.execution_root,
        oracle_root: header.oracle_root,
        timestamp: header.timestamp,
        quorum_certificate,
    }
}

/// Verify a checkpoint against a validator set.
///
/// Rejects (in order) an out-of-order range, a QC whose message is not the
/// recomputed header hash (catches any tampered root), and a QC that fails the
/// set's quorum verification (bad signers or below threshold).
pub fn verify_checkpoint(
    checkpoint: &Checkpoint,
    set: &ValidatorSet,
) -> Result<(), CheckpointError> {
    if checkpoint.last_sequence < checkpoint.first_sequence {
        return Err(CheckpointError::RangeOutOfOrder {
            first: checkpoint.first_sequence,
            last: checkpoint.last_sequence,
        });
    }
    let expected = checkpoint.hash();
    if checkpoint.quorum_certificate.message != expected {
        return Err(CheckpointError::HashMismatch);
    }
    set.verify(&checkpoint.quorum_certificate)
        .map_err(|_| CheckpointError::Quorum)
}

/// Whether `child` chains directly onto `parent`: same shard, contiguous
/// sequence ranges, and `child.previous_state_root == parent.new_state_root`.
#[must_use]
pub fn links_to(child: &Checkpoint, parent: &Checkpoint) -> bool {
    child.shard_id == parent.shard_id
        && child.previous_state_root == parent.new_state_root
        && child.first_sequence == parent.last_sequence.wrapping_add(1)
}

/// Verify an ancestry-linked chain of checkpoints against `set`.
///
/// Each checkpoint must verify individually and chain onto its predecessor.
pub fn verify_chain(chain: &[Checkpoint], set: &ValidatorSet) -> Result<(), CheckpointError> {
    for (i, cp) in chain.iter().enumerate() {
        verify_checkpoint(cp, set)?;
        if i > 0 && !links_to(cp, &chain[i - 1]) {
            return Err(CheckpointError::BrokenAncestry);
        }
    }
    Ok(())
}

/// Detect a checkpoint fork: two checkpoints for the same shard and range that
/// commit to different new state roots.
#[must_use]
pub fn detect_checkpoint_fork(a: &Checkpoint, b: &Checkpoint) -> bool {
    a.shard_id == b.shard_id
        && a.first_sequence == b.first_sequence
        && a.last_sequence == b.last_sequence
        && a.new_state_root != b.new_state_root
}

/// A new state root over a set of per-shard roots, via
/// [`state_tree::checkpoint_root`]. Useful when a checkpoint spans shard roots.
#[must_use]
pub fn state_root_over_shards(shard_roots: &[(ShardId, StateRoot)]) -> StateRoot {
    checkpoint_root(shard_roots)
}

/// A witness's attestation that an executed range produced `execution_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// Epoch of the committee the witness belongs to.
    pub epoch: u64,
    /// Shard the range belongs to.
    pub shard_id: ShardId,
    /// First sequence attested (inclusive).
    pub first_sequence: u64,
    /// Last sequence attested (inclusive).
    pub last_sequence: u64,
    /// The execution root the witness observed.
    pub execution_root: Hash,
    /// Index of the signing witness within the committee.
    pub witness_index: u32,
    /// ed25519 signature over [`WitnessReceipt::digest`].
    #[serde(with = "crate::sig64")]
    pub signature: [u8; 64],
}

/// The canonical digest a witness signs (binds the whole range + root).
#[must_use]
pub fn witness_digest(
    epoch: u64,
    shard_id: ShardId,
    first_sequence: u64,
    last_sequence: u64,
    execution_root: Hash,
) -> Hash {
    let mut buf = Vec::with_capacity(8 + 2 + 8 + 8 + 32);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&shard_id.get().to_le_bytes());
    buf.extend_from_slice(&first_sequence.to_le_bytes());
    buf.extend_from_slice(&last_sequence.to_le_bytes());
    buf.extend_from_slice(execution_root.as_bytes());
    hash_domain(DOMAIN_WITNESS, &buf)
}

impl WitnessReceipt {
    /// The digest this receipt signs.
    #[must_use]
    pub fn digest(&self) -> Hash {
        witness_digest(
            self.epoch,
            self.shard_id,
            self.first_sequence,
            self.last_sequence,
            self.execution_root,
        )
    }

    /// The `(shard, first, last)` range identity used for equivocation checks.
    #[must_use]
    pub fn range_key(&self) -> (u16, u64, u64) {
        (self.shard_id.get(), self.first_sequence, self.last_sequence)
    }

    /// Verify this receipt against `public_key`.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), CheckpointError> {
        verify_ed25519(public_key, self.digest().as_bytes(), &self.signature)
            .map_err(|_| CheckpointError::InvalidWitnessSignature)
    }
}

/// Collects witness receipts for a single range and certifies them once a
/// threshold of distinct, valid witnesses attest to the same execution root.
#[derive(Debug, Clone, Default)]
pub struct WitnessCollector {
    // digest -> (witness_index -> signature)
    receipts: BTreeMap<Hash, BTreeMap<u32, [u8; 64]>>,
    // (witness_index, shard, first, last) -> execution_root seen
    seen: BTreeMap<(u32, u16, u64, u64), Hash>,
}

impl WitnessCollector {
    /// A fresh, empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a receipt. Verifies membership + signature and rejects a witness
    /// that already signed a *different* root for the same range (equivocation).
    pub fn add_receipt(
        &mut self,
        committee: &Committee,
        receipt: &WitnessReceipt,
    ) -> Result<(), CheckpointError> {
        let idx = usize::try_from(receipt.witness_index)
            .map_err(|_| CheckpointError::ForeignWitness(receipt.witness_index))?;
        if idx >= committee.len() || idx >= MAX_VALIDATORS {
            return Err(CheckpointError::ForeignWitness(receipt.witness_index));
        }
        let public_key = committee
            .public_key(receipt.witness_index)
            .ok_or(CheckpointError::ForeignWitness(receipt.witness_index))?;
        receipt.verify(&public_key)?;

        let key = (
            receipt.witness_index,
            receipt.shard_id.get(),
            receipt.first_sequence,
            receipt.last_sequence,
        );
        if let Some(prev_root) = self.seen.get(&key) {
            if *prev_root != receipt.execution_root {
                return Err(CheckpointError::WitnessEquivocation);
            }
        } else {
            self.seen.insert(key, receipt.execution_root);
        }

        self.receipts
            .entry(receipt.digest())
            .or_default()
            .insert(receipt.witness_index, receipt.signature);
        Ok(())
    }

    /// Certify a range: form a [`QuorumCertificate`] over the witness digest
    /// once `>= threshold` distinct witness weight has attested to the same root.
    pub fn certify(
        &self,
        committee: &Committee,
        digest: Hash,
    ) -> Result<QuorumCertificate, CheckpointError> {
        let per_digest = self
            .receipts
            .get(&digest)
            .ok_or(CheckpointError::BelowThreshold)?;
        let mut bitmap: u64 = 0;
        let mut signatures: Vec<[u8; 64]> = Vec::with_capacity(per_digest.len());
        let mut weight: u64 = 0;
        for (&index, signature) in per_digest {
            bitmap |= 1u64 << index;
            signatures.push(*signature);
            weight = weight.saturating_add(
                committee
                    .weight(index)
                    .ok_or(CheckpointError::ForeignWitness(index))?,
            );
        }
        if weight < committee.threshold() {
            return Err(CheckpointError::BelowThreshold);
        }
        let qc = QuorumCertificate {
            message: digest,
            signer_bitmap: bitmap,
            signatures,
        };
        committee
            .validator_set()
            .verify(&qc)
            .map_err(|_| CheckpointError::Quorum)?;
        Ok(qc)
    }
}
