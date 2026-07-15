//! `consensus` — the deterministic Minimmit consensus reactor for DexOS.
//!
//! The core is pure and synchronous: no wall clock, networking, I/O, or async
//! runtime. A node delivers [`Input`] values and translates returned [`Effect`]s
//! into timers, P0 frames, block verification, execution, and persistence.
//! Minimmit advances views at `M = 2B + 1`, finalizes ordering at `L = W - B`,
//! and reaches execution finality only after the matching L execution
//! certificate. Checkpoints and epoch transitions bind the canonical L-set.
//!
//! Modules:
//! - [`minimmit`]: committee, wire types, digests, and the R1–R7 reactor.
//! - [`checkpoint`]: canonical L-certified checkpoints and witness receipts.
//! - [`sequencer`]: gap-free command sequencing and monotone lifecycle state.
//! - [`bft`]: migration-stable execution commitment and evidence data types.
//! - [`vote`]: bounded Minimmit admission errors and slash evidence.

pub mod bft;
pub mod checkpoint;
pub mod minimmit;
pub mod sequencer;
pub mod vote;

pub(crate) mod sig64;

pub use bft::{execution_commitment_digest, Fork, ValidatorSetUpdate, DOMAIN_EXEC_COMMIT};
pub use checkpoint::{
    build_checkpoint_header, checkpoint_hash, detect_checkpoint_fork, links_to, seal_checkpoint,
    seal_minimmit_checkpoint, state_root_over_shards, verify_chain, verify_checkpoint,
    verify_minimmit_chain, verify_minimmit_checkpoint, witness_digest, Checkpoint, CheckpointError,
    CheckpointHeader, WitnessCollector, WitnessReceipt, DEFAULT_WITNESS_MAX_ENTRIES,
    DEFAULT_WITNESS_SEQUENCE_HORIZON, DOMAIN_CHECKPOINT, DOMAIN_WITNESS,
};
pub use minimmit::{
    notarize_digest, nullify_digest, propose_auth, BlockHeader, Certificate, ConsensusMessage,
    Effect, Effect as MinimmitEffect, EpochError, ExecAttest, FinalityStage, Input,
    Input as MinimmitInput, MinimmitCertificateError, MinimmitCommittee, MinimmitReplica,
    Notarization, Notarize, Nullification, Nullify, ParentRef, Proof, Propose, Tally, TallyOutcome,
    ThresholdKind, WireError, BOTTOM_VIEW, DOMAIN_BLOCK, DOMAIN_NOTARIZE, DOMAIN_NULLIFY,
    DOMAIN_PROPOSE,
};
pub use sequencer::{detect_gap, CommandRecord, CommandStatus, Sequencer, SequencerError};
pub use vote::{
    Equivocation, NoopSlashHook, SlashEvidence, SlashHook, SlashKind, VoteError,
    DEFAULT_EVIDENCE_LIMIT, DEFAULT_VIEW_HORIZON, DEFAULT_VOTE_QUOTA, MAX_VALIDATORS,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "consensus";

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{KeyPair, ThresholdSigners};
    use types::{Hash, SequenceNumber, ShardId};

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "consensus");
    }

    #[test]
    fn sequencing_is_gap_free_and_forward_only() {
        let mut sequencer = Sequencer::new(ShardId::new(0));
        let first = sequencer.accept(Hash::from_bytes([1; 32])).unwrap();
        let second = sequencer.accept(Hash::from_bytes([2; 32])).unwrap();
        assert_eq!(first, SequenceNumber::new(0));
        assert_eq!(second, SequenceNumber::new(1));
        sequencer.advance(first, CommandStatus::Executed).unwrap();
        assert!(sequencer.advance(first, CommandStatus::Accepted).is_err());
    }

    #[test]
    fn checkpoint_requires_the_minimmit_l_threshold() {
        let signers = ThresholdSigners::from_seeds(
            &[[0; 32], [1; 32], [2; 32], [3; 32], [4; 32], [5; 32]],
            5,
        );
        let committee =
            MinimmitCommittee::new_unit(0, signers.validator_set().validators().to_vec()).unwrap();
        let header = build_checkpoint_header(
            0,
            ShardId::new(0),
            0,
            0,
            Hash::ZERO,
            Hash::from_bytes([9; 32]),
            &[Hash::from_bytes([1; 32])],
            &[Hash::from_bytes([2; 32])],
            Hash::ZERO,
            0,
        )
        .unwrap();
        let weak = signers.sign(header.hash(), vec![0, 1, 2]);
        assert_eq!(
            seal_minimmit_checkpoint(header.clone(), weak, &committee),
            Err(CheckpointError::Quorum)
        );
        let strong = signers.sign(header.hash(), vec![0, 1, 2, 3, 4]);
        assert!(seal_minimmit_checkpoint(header, strong, &committee).is_ok());
    }

    #[test]
    fn execution_commitment_binds_every_field() {
        let block = Hash::from_bytes([3; 32]);
        let root = Hash::from_bytes([4; 32]);
        let digest = execution_commitment_digest(1, 2, 3, block, root);
        assert_ne!(digest, execution_commitment_digest(1, 2, 4, block, root));
        let key = KeyPair::from_seed(&[7; 32]);
        assert!(crypto::verify_ed25519(
            &key.public(),
            digest.as_bytes(),
            &key.sign(digest.as_bytes())
        )
        .is_ok());
    }

    #[test]
    fn checkpoint_ancestry_never_wraps_sequence_space() {
        let signers = ThresholdSigners::from_seeds(
            &[[0; 32], [1; 32], [2; 32], [3; 32], [4; 32], [5; 32]],
            5,
        );
        let shard = ShardId::new(0);
        let parent_root = Hash::from_bytes([7; 32]);
        let item = Hash::from_bytes([8; 32]);
        let parent_header = build_checkpoint_header(
            0,
            shard,
            u64::MAX,
            u64::MAX,
            Hash::ZERO,
            parent_root,
            &[item],
            &[item],
            Hash::ZERO,
            0,
        )
        .unwrap();
        let parent_qc = signers.sign(parent_header.hash(), vec![0, 1, 2, 3, 4]);
        let parent = seal_checkpoint(parent_header, parent_qc);

        let wrapped_header = build_checkpoint_header(
            0,
            shard,
            0,
            0,
            parent_root,
            Hash::from_bytes([9; 32]),
            &[item],
            &[item],
            Hash::ZERO,
            1,
        )
        .unwrap();
        let wrapped_qc = signers.sign(wrapped_header.hash(), vec![0, 1, 2, 3, 4]);
        let wrapped = seal_checkpoint(wrapped_header, wrapped_qc);

        assert!(!links_to(&wrapped, &parent));
    }
}
