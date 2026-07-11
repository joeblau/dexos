//! `consensus` — deterministic BFT sequencing, pipelined HotStuff-style
//! consensus, and quorum-signed checkpoints for the DexOS kernel.
//!
//! This crate is a **pure, synchronous state machine**: no async runtime, no
//! networking, no I/O, no floating point. The network crate carries messages;
//! consensus runs on a pinned thread and, given identical inputs, produces
//! bit-identical certified / finalized decisions and checkpoint hashes.
//!
//! # Modules
//!
//! - [`sequencer`]: continuous, gap-free command sequencing with
//!   `Accepted -> Executed -> Certified -> Finalized` lifecycle transitions.
//! - [`vote`]: HotStuff-style votes, committees, deterministic leader selection,
//!   Byzantine quorum-certificate formation, and equivocation detection.
//! - [`bft`]: the pipelined leader-based lifecycle driver. In
//!   `ByzantineFaultTolerant` mode it enforces the full HotStuff pipeline —
//!   chained Prepare/PreCommit/Commit quorum certificates, high-QC locking,
//!   parent/ancestry validation, timeout-certificate view changes, and
//!   execution-certified finalization; in `CrashTolerant` (demo) mode it runs a
//!   single-phase Commit path. Also epoch / validator-set transitions and fork
//!   detection.
//! - [`checkpoint`]: canonical checkpoint construction, hashing, quorum + root +
//!   ancestry verification, and threshold witness receipts.
//!
//! # Determinism
//!
//! Every wire type serializes through `codec` (postcard), every digest is
//! domain-separated and little-endian, and every quorum threshold is computed
//! from the validator set — so replay across nodes and architectures is exact.

pub mod bft;
pub mod checkpoint;
pub mod sequencer;
pub mod vote;

pub(crate) mod sig64;

pub use bft::{
    execution_commitment_digest, proposal_digest, BftEngine, BftError, ConsensusMode, Fork,
    Proposal, ProposalOutcome, ValidatorSetUpdate, DOMAIN_EXEC_COMMIT, DOMAIN_PROPOSAL,
};
pub use checkpoint::{
    build_checkpoint_header, checkpoint_hash, detect_checkpoint_fork, links_to, seal_checkpoint,
    state_root_over_shards, verify_chain, verify_checkpoint, witness_digest, Checkpoint,
    CheckpointError, CheckpointHeader, WitnessCollector, WitnessReceipt, DOMAIN_CHECKPOINT,
    DOMAIN_WITNESS,
};
pub use sequencer::{detect_gap, CommandRecord, CommandStatus, Sequencer, SequencerError};
pub use vote::{
    timeout_digest, vote_digest, Committee, Equivocation, TimeoutCertificate, TimeoutCollector,
    TimeoutVote, Vote, VoteCollector, VoteError, VoteOutcome, VotePhase, DOMAIN_TIMEOUT,
    DOMAIN_VOTE, MAX_VALIDATORS,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "consensus";

#[cfg(test)]
mod tests {
    use super::*;

    use crypto::{KeyPair, QuorumCertificate, ThresholdSigners, Validator};
    use types::{Hash, SequenceNumber, ShardId};

    // ---- deterministic in-test LCG (no external rng) ----------------------

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn hash(&mut self) -> Hash {
            let mut b = [0u8; 32];
            for chunk in b.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes());
            }
            Hash::from_bytes(b)
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            let mut v = Vec::with_capacity(len);
            while v.len() < len {
                v.extend_from_slice(&self.next().to_le_bytes());
            }
            v.truncate(len);
            v
        }
    }

    // ---- helpers ----------------------------------------------------------

    fn committee(n: u32, epoch: u64) -> (Committee, Vec<KeyPair>) {
        let mut kps = Vec::new();
        let mut vals = Vec::new();
        for i in 0..n {
            let kp = KeyPair::from_seed(&[u8::try_from(i).unwrap(); 32]);
            vals.push(Validator {
                public_key: kp.public(),
                weight: 1,
            });
            kps.push(kp);
        }
        (Committee::new_bft(epoch, vals).unwrap(), kps)
    }

    fn validators_of(kps: &[KeyPair]) -> Vec<Validator> {
        kps.iter()
            .map(|kp| Validator {
                public_key: kp.public(),
                weight: 1,
            })
            .collect()
    }

    fn signed_vote(
        kp: &KeyPair,
        epoch: u64,
        view: u64,
        height: u64,
        phase: VotePhase,
        block: Hash,
        idx: u32,
    ) -> Vote {
        let d = vote_digest(epoch, view, height, phase, block);
        Vote {
            epoch,
            view,
            height,
            phase,
            block_hash: block,
            validator_index: idx,
            signature: kp.sign(d.as_bytes()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_proposal(
        kp: &KeyPair,
        epoch: u64,
        view: u64,
        height: u64,
        block: Hash,
        parent: Hash,
        first: u64,
        last: u64,
        proposer: u32,
    ) -> Proposal {
        let d = proposal_digest(epoch, view, height, block, parent, first, last);
        Proposal {
            epoch,
            view,
            height,
            block_hash: block,
            parent_hash: parent,
            first_sequence: first,
            last_sequence: last,
            proposer_index: proposer,
            signature: kp.sign(d.as_bytes()),
        }
    }

    fn signed_timeout(kp: &KeyPair, epoch: u64, view: u64, idx: u32) -> TimeoutVote {
        let d = timeout_digest(epoch, view);
        TimeoutVote {
            epoch,
            view,
            validator_index: idx,
            signature: kp.sign(d.as_bytes()),
        }
    }

    /// Assemble a quorum certificate over `message` from `indices` (used for the
    /// execution-commitment certificates the BFT finalize path requires).
    fn quorum_over(kps: &[KeyPair], indices: &[u32], message: Hash) -> QuorumCertificate {
        let mut idxs = indices.to_vec();
        idxs.sort_unstable();
        idxs.dedup();
        let mut signer_bitmap = 0u64;
        let mut signatures = Vec::new();
        for &i in &idxs {
            signer_bitmap |= 1u64 << i;
            signatures.push(kps[usize::try_from(i).unwrap()].sign(message.as_bytes()));
        }
        QuorumCertificate {
            message,
            signer_bitmap,
            signatures,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn phase_votes(
        kps: &[KeyPair],
        voters: &[u32],
        epoch: u64,
        view: u64,
        height: u64,
        phase: VotePhase,
        block: Hash,
    ) -> Vec<Vote> {
        voters
            .iter()
            .map(|&i| {
                signed_vote(
                    &kps[usize::try_from(i).unwrap()],
                    epoch,
                    view,
                    height,
                    phase,
                    block,
                    i,
                )
            })
            .collect()
    }

    fn add_votes_to_all(engines: &mut [BftEngine], votes: &[Vote]) {
        for e in engines.iter_mut() {
            for v in votes {
                let _ = e.add_vote(v);
            }
        }
    }

    // ---- crate identity ---------------------------------------------------

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "consensus");
    }

    // ---- sequencing -------------------------------------------------------

    #[test]
    fn sequencing_is_monotonic_and_gap_free() {
        let mut seq = Sequencer::new(ShardId::new(0));
        let mut prev: Option<u64> = None;
        for i in 0..100u64 {
            let s = seq
                .accept(Hash::from_bytes([u8::try_from(i % 256).unwrap(); 32]))
                .unwrap();
            assert_eq!(s.get(), i);
            if let Some(p) = prev {
                assert_eq!(s.get(), p + 1);
            }
            prev = Some(s.get());
        }
        assert_eq!(seq.len(), 100);
    }

    #[test]
    fn ingest_detects_gaps() {
        let mut seq = Sequencer::new(ShardId::new(1));
        seq.ingest(SequenceNumber::new(0), Hash::ZERO).unwrap();
        seq.ingest(SequenceNumber::new(1), Hash::ZERO).unwrap();
        // Skipping 2 -> gap.
        let err = seq.ingest(SequenceNumber::new(3), Hash::ZERO).unwrap_err();
        assert_eq!(
            err,
            SequencerError::Gap {
                expected: 2,
                got: 3
            }
        );
        // Duplicate (re-presenting 0) also surfaces as a gap.
        let err2 = seq.ingest(SequenceNumber::new(0), Hash::ZERO).unwrap_err();
        assert_eq!(
            err2,
            SequencerError::Gap {
                expected: 2,
                got: 0
            }
        );
    }

    #[test]
    fn detect_gap_free_function() {
        let contiguous = [
            SequenceNumber::new(5),
            SequenceNumber::new(6),
            SequenceNumber::new(7),
        ];
        assert_eq!(detect_gap(SequenceNumber::new(5), &contiguous), None);
        let broken = [SequenceNumber::new(5), SequenceNumber::new(7)];
        assert_eq!(detect_gap(SequenceNumber::new(5), &broken), Some((6, 7)));
    }

    #[test]
    fn status_transitions_are_forward_only() {
        let mut seq = Sequencer::new(ShardId::new(0));
        let s = seq.accept(Hash::ZERO).unwrap();
        assert_eq!(seq.status(s), Some(CommandStatus::Accepted));
        seq.mark_executed(s).unwrap();
        seq.mark_certified(s).unwrap();
        seq.mark_finalized(s).unwrap();
        assert_eq!(seq.status(s), Some(CommandStatus::Finalized));
        // Backwards is rejected.
        assert!(matches!(
            seq.mark_executed(s),
            Err(SequencerError::InvalidTransition { .. })
        ));
        // Unknown sequence.
        assert!(matches!(
            seq.mark_executed(SequenceNumber::new(999)),
            Err(SequencerError::UnknownSequence(999))
        ));
    }

    #[test]
    fn command_root_is_deterministic_over_range() {
        let build = || {
            let mut seq = Sequencer::new(ShardId::new(0));
            for i in 0..8u64 {
                seq.accept(Hash::from_bytes([u8::try_from(i).unwrap(); 32]))
                    .unwrap();
            }
            seq.command_root(SequenceNumber::new(2), SequenceNumber::new(5))
                .unwrap()
        };
        assert_eq!(build(), build());
        // Out-of-order range is rejected.
        let mut seq = Sequencer::new(ShardId::new(0));
        seq.accept(Hash::ZERO).unwrap();
        assert!(matches!(
            seq.command_root(SequenceNumber::new(5), SequenceNumber::new(2)),
            Err(SequencerError::RangeOutOfOrder { .. })
        ));
    }

    // ---- leader selection -------------------------------------------------

    #[test]
    fn leader_selection_is_deterministic_round_robin() {
        let (c1, _) = committee(4, 3);
        let (c2, _) = committee(4, 3);
        for view in 0..20u64 {
            // All honest replicas agree.
            assert_eq!(c1.leader(view), c2.leader(view));
            // Round-robin by (epoch + view) mod n.
            let expected = u32::try_from((3 + view) % 4).unwrap();
            assert_eq!(c1.leader(view), expected);
        }
    }

    // ---- quorum / finalization -------------------------------------------

    #[test]
    fn quorum_finalizes_at_threshold_not_below() {
        let (comm, kps) = committee(4, 0); // 3f+1 with f=1, threshold 3
        assert_eq!(comm.threshold(), 3);
        let block = Hash::from_bytes([7; 32]);
        let parent = Hash::ZERO;
        let mut engine = BftEngine::new(comm);

        let prop = signed_proposal(&kps[0], 0, 0, 1, block, parent, 0, 9, 0);
        assert_eq!(
            engine.receive_proposal(prop).unwrap(),
            ProposalOutcome::Accepted
        );
        engine.execute(1).unwrap();
        assert_eq!(engine.status(1), Some(CommandStatus::Executed));

        // Two votes: below threshold, no QC.
        for i in 0..2u32 {
            let v = signed_vote(&kps[i as usize], 0, 0, 1, VotePhase::Commit, block, i);
            engine.add_vote(&v).unwrap();
        }
        assert!(engine.try_certify(1, VotePhase::Commit).unwrap().is_none());
        assert!(matches!(engine.finalize(1), Err(BftError::NotCertified(1))));

        // Third vote reaches 2f+1 -> QC forms -> finalize.
        let v = signed_vote(&kps[2], 0, 0, 1, VotePhase::Commit, block, 2);
        engine.add_vote(&v).unwrap();
        assert!(engine.try_certify(1, VotePhase::Commit).unwrap().is_some());
        assert_eq!(engine.status(1), Some(CommandStatus::Certified));
        assert_eq!(engine.finalize(1).unwrap(), block);
        assert_eq!(engine.status(1), Some(CommandStatus::Finalized));

        // The stored QC verifies against the set.
        let qc = engine.quorum_certificate(1).unwrap();
        assert!(engine.committee().validator_set().verify(qc).is_ok());
    }

    #[test]
    fn foreign_and_invalid_votes_rejected() {
        let (comm, kps) = committee(4, 0);
        let block = Hash::from_bytes([1; 32]);
        let mut collector = VoteCollector::new();
        // Foreign signer index.
        let foreign = signed_vote(&kps[0], 0, 0, 1, VotePhase::Commit, block, 9);
        assert!(matches!(
            collector.add_vote(&comm, &foreign),
            Err(VoteError::ForeignSigner(9))
        ));
        // Wrong key for the claimed index -> invalid signature.
        let bad = signed_vote(&kps[1], 0, 0, 1, VotePhase::Commit, block, 0);
        assert!(matches!(
            collector.add_vote(&comm, &bad),
            Err(VoteError::InvalidSignature)
        ));
    }

    // ---- double-sign / equivocation --------------------------------------

    #[test]
    fn double_sign_is_detected() {
        let (comm, kps) = committee(4, 0);
        let a = Hash::from_bytes([1; 32]);
        let b = Hash::from_bytes([2; 32]);
        let mut collector = VoteCollector::new();
        let v1 = signed_vote(&kps[1], 0, 0, 1, VotePhase::Commit, a, 1);
        let v2 = signed_vote(&kps[1], 0, 0, 1, VotePhase::Commit, b, 1);
        assert_eq!(
            collector.add_vote(&comm, &v1).unwrap(),
            VoteOutcome::Accepted
        );
        match collector.add_vote(&comm, &v2).unwrap() {
            VoteOutcome::Equivocated(e) => {
                assert_eq!(e.validator_index, 1);
                assert_eq!(e.first_block, a);
                assert_eq!(e.second_block, b);
            }
            other => panic!("expected equivocation, got {other:?}"),
        }
        assert!(collector.has_equivocation());
        // Re-submitting the identical vote is idempotent.
        assert_eq!(
            collector.add_vote(&comm, &v1).unwrap(),
            VoteOutcome::Duplicate
        );
    }

    // ---- pipelining -------------------------------------------------------

    #[test]
    fn pipeline_does_not_stall_on_unfinalized_prior() {
        let (comm, kps) = committee(4, 0);
        let mut engine = BftEngine::new(comm);
        let b1 = Hash::from_bytes([1; 32]);
        let b2 = Hash::from_bytes([2; 32]);
        engine
            .receive_proposal(signed_proposal(&kps[0], 0, 0, 1, b1, Hash::ZERO, 0, 4, 0))
            .unwrap();
        engine
            .receive_proposal(signed_proposal(&kps[0], 0, 0, 2, b2, b1, 5, 9, 0))
            .unwrap();
        // Execute height 2 while height 1 remains merely Accepted — no stall.
        engine.execute(2).unwrap();
        assert_eq!(engine.status(1), Some(CommandStatus::Accepted));
        assert_eq!(engine.status(2), Some(CommandStatus::Executed));
        assert_eq!(engine.pipeline_len(), 2);
    }

    // ---- fork detection ---------------------------------------------------

    #[test]
    fn conflicting_proposals_flag_a_fork() {
        let (comm, kps) = committee(4, 0);
        let mut engine = BftEngine::new(comm);
        let a = Hash::from_bytes([1; 32]);
        let b = Hash::from_bytes([2; 32]);
        engine
            .receive_proposal(signed_proposal(&kps[0], 0, 0, 1, a, Hash::ZERO, 0, 4, 0))
            .unwrap();
        let outcome = engine
            .receive_proposal(signed_proposal(&kps[0], 0, 0, 1, b, Hash::ZERO, 0, 4, 0))
            .unwrap();
        assert!(matches!(outcome, ProposalOutcome::Forked(_)));
        assert_eq!(engine.forks().len(), 1);
        // A non-leader proposer is rejected outright.
        let notleader = signed_proposal(&kps[1], 0, 0, 3, a, Hash::ZERO, 0, 4, 1);
        assert!(matches!(
            engine.receive_proposal(notleader),
            Err(BftError::NotLeader { .. })
        ));
    }

    // ---- timeout / view rotation -----------------------------------------

    #[test]
    fn timeout_rotates_leader() {
        let (comm, _) = committee(4, 0);
        let mut engine = BftEngine::new(comm);
        assert_eq!(engine.view(), 0);
        assert_eq!(engine.leader(), 0);
        assert_eq!(engine.on_timeout(), 1);
        assert_eq!(engine.leader(), 1); // (0 + 1) % 4
        engine.on_timeout();
        assert_eq!(engine.leader(), 2);
    }

    // ---- epoch / validator-set transition --------------------------------

    #[test]
    fn epoch_transition_updates_threshold_and_leader_domain() {
        let (comm0, kps0) = committee(4, 0);
        assert_eq!(comm0.threshold(), 3);
        let mut engine = BftEngine::new(comm0);

        // Grow from 4 to 7 validators, activating at epoch 1.
        let mut kps7 = kps0;
        for i in 4..7u32 {
            kps7.push(KeyPair::from_seed(&[u8::try_from(i).unwrap(); 32]));
        }
        engine.schedule_update(ValidatorSetUpdate {
            activation_epoch: 1,
            validators: validators_of(&kps7),
        });
        assert!(engine.has_pending_update());
        // Activating at the wrong epoch is rejected and keeps the update.
        assert!(matches!(
            engine.activate_epoch(2),
            Err(BftError::WrongActivationEpoch { .. })
        ));
        engine.activate_epoch(1).unwrap();
        assert_eq!(engine.epoch(), 1);
        assert_eq!(engine.committee().len(), 7);
        assert_eq!(engine.committee().threshold(), 5); // 2f+1 with f=2
        assert_eq!(engine.view(), 0);
        // Leader domain now spans 7: (1 + view) % 7.
        assert_eq!(engine.committee().leader(0), 1);
        assert_eq!(engine.committee().leader(6), 0);
    }

    // ---- checkpoints ------------------------------------------------------

    fn sample_header(first: u64, last: u64, prev: Hash, new: Hash) -> CheckpointHeader {
        let width = usize::try_from(last - first + 1).unwrap();
        let cmds: Vec<Hash> = (0..width)
            .map(|i| Hash::from_bytes([u8::try_from(i).unwrap(); 32]))
            .collect();
        let execs: Vec<Hash> = (0..width)
            .map(|i| Hash::from_bytes([u8::try_from(i + 100).unwrap(); 32]))
            .collect();
        build_checkpoint_header(
            0,
            ShardId::new(0),
            first,
            last,
            prev,
            new,
            &cmds,
            &execs,
            Hash::from_bytes([9; 32]),
            42,
        )
        .unwrap()
    }

    #[test]
    fn checkpoint_build_verify_accept_and_reject() {
        let ts = ThresholdSigners::from_seeds(&[[0; 32], [1; 32], [2; 32], [3; 32]], 3);
        let set = ts.validator_set();
        let header = sample_header(0, 3, Hash::ZERO, Hash::from_bytes([5; 32]));
        let h = header.hash();
        let qc = ts.sign(h, vec![0, 1, 2]);
        let cp = seal_checkpoint(header, qc);
        assert!(verify_checkpoint(&cp, &set).is_ok());

        // Tampered root -> hash mismatch.
        let mut tampered = cp.clone();
        tampered.new_state_root = Hash::from_bytes([6; 32]);
        assert_eq!(
            verify_checkpoint(&tampered, &set),
            Err(CheckpointError::HashMismatch)
        );

        // Insufficient QC (2 of 4, threshold 3) -> quorum failure.
        let header2 = sample_header(0, 3, Hash::ZERO, Hash::from_bytes([5; 32]));
        let weak_qc = ts.sign(header2.hash(), vec![0, 1]);
        let weak = seal_checkpoint(header2, weak_qc);
        assert_eq!(verify_checkpoint(&weak, &set), Err(CheckpointError::Quorum));

        // Length mismatch on construction.
        assert!(matches!(
            build_checkpoint_header(
                0,
                ShardId::new(0),
                0,
                3,
                Hash::ZERO,
                Hash::from_bytes([5; 32]),
                &[Hash::ZERO],
                &[Hash::ZERO],
                Hash::ZERO,
                0,
            ),
            Err(CheckpointError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn checkpoint_ancestry_and_fork() {
        let ts = ThresholdSigners::from_seeds(&[[0; 32], [1; 32], [2; 32], [3; 32]], 3);
        let set = ts.validator_set();
        let root_a = Hash::from_bytes([10; 32]);
        let root_b = Hash::from_bytes([11; 32]);

        let h1 = sample_header(0, 3, Hash::ZERO, root_a);
        let cp1 = seal_checkpoint(h1.clone(), ts.sign(h1.hash(), vec![0, 1, 2]));
        // cp2 chains: previous == cp1.new, first == cp1.last + 1.
        let h2 = sample_header(4, 7, root_a, root_b);
        let cp2 = seal_checkpoint(h2.clone(), ts.sign(h2.hash(), vec![0, 1, 2]));

        assert!(links_to(&cp2, &cp1));
        assert!(verify_chain(&[cp1.clone(), cp2.clone()], &set).is_ok());

        // Broken ancestry: wrong previous_state_root.
        let h_bad = sample_header(4, 7, Hash::from_bytes([99; 32]), root_b);
        let cp_bad = seal_checkpoint(h_bad.clone(), ts.sign(h_bad.hash(), vec![0, 1, 2]));
        assert_eq!(
            verify_chain(&[cp1.clone(), cp_bad], &set),
            Err(CheckpointError::BrokenAncestry)
        );

        // Fork: same range, different new root.
        let h_fork = sample_header(0, 3, Hash::ZERO, root_b);
        let cp_fork = seal_checkpoint(h_fork.clone(), ts.sign(h_fork.hash(), vec![0, 1, 2]));
        assert!(detect_checkpoint_fork(&cp1, &cp_fork));
        assert!(!detect_checkpoint_fork(&cp1, &cp2));
    }

    // ---- witness receipts -------------------------------------------------

    #[test]
    fn witness_receipts_certify_reject_and_equivocate() {
        let (comm, kps) = committee(4, 0);
        let exec_root = Hash::from_bytes([21; 32]);
        let digest = witness_digest(0, ShardId::new(0), 0, 9, exec_root);

        let receipt = |i: u32, root: Hash| {
            let d = witness_digest(0, ShardId::new(0), 0, 9, root);
            WitnessReceipt {
                epoch: 0,
                shard_id: ShardId::new(0),
                first_sequence: 0,
                last_sequence: 9,
                execution_root: root,
                witness_index: i,
                signature: kps[usize::try_from(i).unwrap()].sign(d.as_bytes()),
            }
        };

        // Below threshold: only 2 of 4.
        let mut collector = WitnessCollector::new();
        collector
            .add_receipt(&comm, &receipt(0, exec_root))
            .unwrap();
        collector
            .add_receipt(&comm, &receipt(1, exec_root))
            .unwrap();
        assert!(matches!(
            collector.certify(&comm, digest),
            Err(CheckpointError::BelowThreshold)
        ));
        // Third receipt reaches threshold -> certificate verifies.
        collector
            .add_receipt(&comm, &receipt(2, exec_root))
            .unwrap();
        let qc = collector.certify(&comm, digest).unwrap();
        assert!(comm.validator_set().verify(&qc).is_ok());
        assert_eq!(qc.message, digest);

        // Equivocation: same witness, same range, different root.
        let mut collector2 = WitnessCollector::new();
        collector2
            .add_receipt(&comm, &receipt(0, exec_root))
            .unwrap();
        assert_eq!(
            collector2.add_receipt(&comm, &receipt(0, Hash::from_bytes([99; 32]))),
            Err(CheckpointError::WitnessEquivocation)
        );

        // Foreign witness index.
        let mut collector3 = WitnessCollector::new();
        let mut foreign = receipt(0, exec_root);
        foreign.witness_index = 99;
        assert!(matches!(
            collector3.add_receipt(&comm, &foreign),
            Err(CheckpointError::ForeignWitness(99))
        ));
    }

    // ---- determinism property test (LCG) ---------------------------------

    #[test]
    fn property_deterministic_qc_and_checkpoint_hash() {
        let (comm, kps) = committee(4, 0);
        let mut rng = Lcg(0xC0FF_EE00_1234_5678);
        for _ in 0..500 {
            let block = rng.hash();
            let height = rng.next() % 1000;

            // Build a QC twice from the same votes; results must be identical.
            let form = || {
                let mut collector = VoteCollector::new();
                for i in 0..3u32 {
                    let v = signed_vote(
                        &kps[usize::try_from(i).unwrap()],
                        0,
                        0,
                        height,
                        VotePhase::Commit,
                        block,
                        i,
                    );
                    collector.add_vote(&comm, &v).unwrap();
                }
                let digest = vote_digest(0, 0, height, VotePhase::Commit, block);
                collector.try_form_qc(&comm, digest).unwrap()
            };
            let qc1 = form();
            let qc2 = form();
            assert_eq!(codec::encode(&qc1).unwrap(), codec::encode(&qc2).unwrap());
            assert!(comm.validator_set().verify(&qc1).is_ok());

            // Checkpoint hash is a pure function of the header.
            let first = rng.next() % 100;
            let last = first + (rng.next() % 8);
            let h1 = sample_header(first, last, rng.hash(), rng.hash());
            let h2 = h1.clone();
            assert_eq!(checkpoint_hash(&h1), checkpoint_hash(&h2));
            assert_eq!(h1.hash(), checkpoint_hash(&h1));
        }
    }

    // ---- never panics on arbitrary bytes ---------------------------------

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut rng = Lcg(0xDEAD_BEEF_CAFE_0001);
        for _ in 0..2000 {
            let len = usize::try_from(rng.next() % 256).unwrap();
            let bytes = rng.bytes(len);
            // Every untrusted decode path is total: it returns Result, never panics.
            let _ = codec::decode::<Checkpoint>(&bytes);
            let _ = codec::decode::<CheckpointHeader>(&bytes);
            let _ = codec::decode::<Vote>(&bytes);
            let _ = codec::decode::<Proposal>(&bytes);
            let _ = codec::decode::<WitnessReceipt>(&bytes);
            let _ = codec::decode::<ValidatorSetUpdate>(&bytes);
            let _ = codec::decode::<CommandRecord>(&bytes);
        }
    }

    #[test]
    fn wire_types_round_trip_through_codec() {
        let (_, kps) = committee(4, 0);
        let vote = signed_vote(
            &kps[0],
            1,
            2,
            3,
            VotePhase::PreCommit,
            Hash::from_bytes([4; 32]),
            0,
        );
        let bytes = codec::encode(&vote).unwrap();
        let back: Vote = codec::decode(&bytes).unwrap();
        assert_eq!(vote, back);

        let header = sample_header(0, 3, Hash::ZERO, Hash::from_bytes([5; 32]));
        let hb = codec::encode(&header).unwrap();
        let header_back: CheckpointHeader = codec::decode(&hb).unwrap();
        assert_eq!(header, header_back);
    }

    // ---- true BFT: chained QCs, locking, and execution-certified finalize --

    #[test]
    fn crash_tolerant_mode_is_single_phase_and_rotates() {
        // The demo (crash-tolerant) mode certifies on a single Commit QC and
        // finalizes without an execution certificate, and its timeout is a
        // simple view rotation — the documented ≤3-node failover.
        let (comm, kps) = committee(3, 0);
        let mut engine = BftEngine::new(comm);
        assert_eq!(engine.mode(), ConsensusMode::CrashTolerant);
        assert!(!engine.is_bft());
        let block = Hash::from_bytes([5; 32]);
        engine
            .receive_proposal(signed_proposal(
                &kps[0],
                0,
                0,
                1,
                block,
                Hash::ZERO,
                0,
                0,
                0,
            ))
            .unwrap();
        engine.execute(1).unwrap();
        for i in 0..3u32 {
            let v = signed_vote(&kps[i as usize], 0, 0, 1, VotePhase::Commit, block, i);
            engine.add_vote(&v).unwrap();
        }
        assert!(engine.try_certify(1, VotePhase::Commit).unwrap().is_some());
        // No execution certificate required in the demo mode.
        assert_eq!(engine.finalize(1).unwrap(), block);
        // Simple crash-failover rotation advances the view without a certificate.
        assert_eq!(engine.on_timeout(), 1);
        assert_eq!(engine.view(), 1);
    }

    #[test]
    fn bft_pipeline_chains_locks_and_finalizes() {
        let (comm, kps) = committee(4, 0); // 3f+1, threshold 3
        let mut engine = BftEngine::new_byzantine(comm);
        assert!(engine.is_bft());
        let block = Hash::from_bytes([7; 32]);
        engine
            .receive_proposal(signed_proposal(
                &kps[0],
                0,
                0,
                1,
                block,
                Hash::ZERO,
                0,
                9,
                0,
            ))
            .unwrap();
        engine.execute(1).unwrap();

        // Three Commit votes exist, but Commit cannot certify before the
        // Prepare -> PreCommit chain is in place.
        for i in 0..3u32 {
            let v = signed_vote(&kps[i as usize], 0, 0, 1, VotePhase::Commit, block, i);
            engine.add_vote(&v).unwrap();
        }
        assert!(matches!(
            engine.try_certify(1, VotePhase::Commit),
            Err(BftError::PhaseNotChained {
                height: 1,
                phase: VotePhase::Commit
            })
        ));
        assert!(matches!(
            engine.try_certify(1, VotePhase::PreCommit),
            Err(BftError::PhaseNotChained {
                height: 1,
                phase: VotePhase::PreCommit
            })
        ));

        // Chain Prepare then PreCommit; the PreCommit QC installs a lock.
        for phase in [VotePhase::Prepare, VotePhase::PreCommit] {
            add_votes_to_all(
                std::slice::from_mut(&mut engine),
                &phase_votes(&kps, &[0, 1, 2], 0, 0, 1, phase, block),
            );
            assert!(engine.try_certify(1, phase).unwrap().is_some());
        }
        assert_eq!(engine.locked_block(1), Some(block));
        assert_eq!(engine.high_qc_view(), Some(0));

        // Now Commit chains and certifies.
        assert!(engine.try_certify(1, VotePhase::Commit).unwrap().is_some());
        assert_eq!(engine.status(1), Some(CommandStatus::Certified));

        // Finalize is refused without a certified execution commitment...
        assert!(matches!(
            engine.finalize(1),
            Err(BftError::MissingExecutionCertificate(1))
        ));
        // ...and a certificate over the wrong root does not verify.
        let bad = quorum_over(
            &kps,
            &[0, 1, 2],
            execution_commitment_digest(0, 0, 1, block, Hash::from_bytes([0xAA; 32])),
        );
        assert!(matches!(
            engine.certify_execution(1, Hash::from_bytes([0xBB; 32]), &bad),
            Err(BftError::InvalidExecutionCertificate(1))
        ));
        assert!(matches!(
            engine.finalize(1),
            Err(BftError::MissingExecutionCertificate(1))
        ));

        // A correct execution certificate unlocks finalization.
        let exec = Hash::from_bytes([21; 32]);
        let cert = quorum_over(
            &kps,
            &[0, 1, 2],
            execution_commitment_digest(0, 0, 1, block, exec),
        );
        engine.certify_execution(1, exec, &cert).unwrap();
        assert_eq!(engine.execution_root(1), Some(exec));
        assert_eq!(engine.finalize(1).unwrap(), block);
        assert_eq!(engine.status(1), Some(CommandStatus::Finalized));
    }

    #[test]
    fn bft_parent_ancestry_is_enforced() {
        let (comm, kps) = committee(4, 0);
        let mut engine = BftEngine::new_byzantine(comm);
        let b1 = Hash::from_bytes([1; 32]);
        engine
            .receive_proposal(signed_proposal(&kps[0], 0, 0, 1, b1, Hash::ZERO, 0, 4, 0))
            .unwrap();
        // Height 2 with a parent that does not link to the block at height 1.
        let wrong = signed_proposal(
            &kps[0],
            0,
            0,
            2,
            Hash::from_bytes([2; 32]),
            Hash::from_bytes([9; 32]),
            5,
            9,
            0,
        );
        assert!(matches!(
            engine.receive_proposal(wrong),
            Err(BftError::AncestryMismatch { height: 2 })
        ));
        // The correctly-linked proposal is admitted.
        let good = signed_proposal(&kps[0], 0, 0, 2, Hash::from_bytes([2; 32]), b1, 5, 9, 0);
        assert_eq!(
            engine.receive_proposal(good).unwrap(),
            ProposalOutcome::Accepted
        );
    }

    #[test]
    fn bft_lock_rejects_conflicting_block_across_view_change() {
        let (comm, kps) = committee(4, 0);
        let mut engine = BftEngine::new_byzantine(comm);
        let a = Hash::from_bytes([1; 32]);
        engine
            .receive_proposal(signed_proposal(&kps[0], 0, 0, 1, a, Hash::ZERO, 0, 4, 0))
            .unwrap();
        engine.execute(1).unwrap();
        for phase in [VotePhase::Prepare, VotePhase::PreCommit] {
            add_votes_to_all(
                std::slice::from_mut(&mut engine),
                &phase_votes(&kps, &[0, 1, 2], 0, 0, 1, phase, a),
            );
            assert!(engine.try_certify(1, phase).unwrap().is_some());
        }
        assert_eq!(engine.locked_block(1), Some(a));

        // Advance to view 1 with a timeout certificate.
        for i in 0..3u32 {
            engine
                .add_timeout(&signed_timeout(&kps[i as usize], 0, 0, i))
                .unwrap();
        }
        let tc = engine.try_form_timeout_certificate(0).unwrap();
        assert_eq!(engine.advance_view(&tc).unwrap(), 1);

        // A conflicting block at the locked height is refused...
        let b = Hash::from_bytes([2; 32]);
        assert!(matches!(
            engine.receive_proposal(signed_proposal(&kps[1], 0, 1, 1, b, Hash::ZERO, 0, 4, 1)),
            Err(BftError::Locked { height: 1 })
        ));
        // ...but re-proposing the locked block at the new view is allowed.
        assert_eq!(
            engine
                .receive_proposal(signed_proposal(&kps[1], 0, 1, 1, a, Hash::ZERO, 0, 4, 1))
                .unwrap(),
            ProposalOutcome::Accepted
        );
    }

    #[test]
    fn bft_view_change_requires_timeout_certificate() {
        let (comm, kps) = committee(4, 0);
        let mut engine = BftEngine::new_byzantine(comm);
        assert_eq!(engine.view(), 0);
        // A bare timeout does NOT advance the view in BFT mode.
        assert_eq!(engine.on_timeout(), 0);
        assert_eq!(engine.view(), 0);
        // Below threshold, no certificate can form.
        engine
            .add_timeout(&signed_timeout(&kps[0], 0, 0, 0))
            .unwrap();
        engine
            .add_timeout(&signed_timeout(&kps[1], 0, 0, 1))
            .unwrap();
        assert!(engine.try_form_timeout_certificate(0).is_none());
        // The third timeout reaches the quorum.
        engine
            .add_timeout(&signed_timeout(&kps[2], 0, 0, 2))
            .unwrap();
        let tc = engine.try_form_timeout_certificate(0).unwrap();

        // A certificate for the wrong view is rejected.
        let wrong_view = TimeoutCertificate {
            epoch: 0,
            view: 5,
            quorum: tc.quorum.clone(),
        };
        assert!(matches!(
            engine.advance_view(&wrong_view),
            Err(BftError::WrongViewChange {
                expected: 0,
                got: 5
            })
        ));
        // A certificate whose aggregate signs the wrong digest is rejected.
        let tampered = TimeoutCertificate {
            epoch: 0,
            view: 0,
            quorum: quorum_over(&kps, &[0, 1, 2], Hash::from_bytes([0xEE; 32])),
        };
        assert!(matches!(
            engine.advance_view(&tampered),
            Err(BftError::Vote(VoteError::TimeoutDigestMismatch))
        ));

        // The valid certificate advances the view and rotates the leader.
        assert_eq!(engine.advance_view(&tc).unwrap(), 1);
        assert_eq!(engine.view(), 1);
        assert_eq!(engine.leader(), 1); // (0 + 1) % 4
        assert!(engine.last_view_change().is_some());
    }

    #[test]
    fn bft_forked_round_halts_certification_then_recovers() {
        let (comm, kps) = committee(4, 0);
        let mut engine = BftEngine::new_byzantine(comm);
        let a = Hash::from_bytes([1; 32]);
        let b = Hash::from_bytes([2; 32]);
        // Leader 0 equivocates at (height 1, view 0): two conflicting blocks.
        engine
            .receive_proposal(signed_proposal(&kps[0], 0, 0, 1, a, Hash::ZERO, 0, 4, 0))
            .unwrap();
        assert!(matches!(
            engine
                .receive_proposal(signed_proposal(&kps[0], 0, 0, 1, b, Hash::ZERO, 0, 4, 0))
                .unwrap(),
            ProposalOutcome::Forked(_)
        ));
        // Even with a Prepare quorum for A, the forked round refuses to certify.
        add_votes_to_all(
            std::slice::from_mut(&mut engine),
            &phase_votes(&kps, &[0, 1, 2], 0, 0, 1, VotePhase::Prepare, a),
        );
        assert!(matches!(
            engine.try_certify(1, VotePhase::Prepare),
            Err(BftError::ForkedRound { height: 1, view: 0 })
        ));

        // A timeout certificate carries the height to view 1 under an honest leader.
        for i in 0..3u32 {
            engine
                .add_timeout(&signed_timeout(&kps[i as usize], 0, 0, i))
                .unwrap();
        }
        let tc = engine.try_form_timeout_certificate(0).unwrap();
        engine.advance_view(&tc).unwrap();
        engine
            .receive_proposal(signed_proposal(&kps[1], 0, 1, 1, a, Hash::ZERO, 0, 4, 1))
            .unwrap();
        engine.execute(1).unwrap();
        for phase in [VotePhase::Prepare, VotePhase::PreCommit, VotePhase::Commit] {
            add_votes_to_all(
                std::slice::from_mut(&mut engine),
                &phase_votes(&kps, &[0, 1, 2], 0, 1, 1, phase, a),
            );
            assert!(engine.try_certify(1, phase).unwrap().is_some());
        }
        let exec = Hash::from_bytes([9; 32]);
        let cert = quorum_over(
            &kps,
            &[0, 1, 2],
            execution_commitment_digest(0, 1, 1, a, exec),
        );
        engine.certify_execution(1, exec, &cert).unwrap();
        assert_eq!(engine.finalize(1).unwrap(), a);
    }

    // ---- safety property: partition + Byzantine leader (multi-replica) -----

    #[test]
    fn bft_safety_under_partition_and_byzantine_leader() {
        let (comm, kps) = committee(4, 0);
        let mut engines: Vec<BftEngine> = (0..4)
            .map(|_| BftEngine::new_byzantine(comm.clone()))
            .collect();
        let a = Hash::from_bytes([0xAA; 32]);
        let b = Hash::from_bytes([0xBB; 32]);

        // View 0: a Byzantine leader equivocates across a 2/2 partition, sending
        // block A to {0,1} and block B to {2,3}. No replica sees both, so the
        // conflict is not locally detectable, yet neither block can reach quorum.
        let pa = signed_proposal(&kps[0], 0, 0, 1, a, Hash::ZERO, 0, 0, 0);
        let pb = signed_proposal(&kps[0], 0, 0, 1, b, Hash::ZERO, 0, 0, 0);
        engines[0].receive_proposal(pa.clone()).unwrap();
        engines[1].receive_proposal(pa).unwrap();
        engines[2].receive_proposal(pb.clone()).unwrap();
        engines[3].receive_proposal(pb).unwrap();
        for e in engines.iter_mut() {
            e.execute(1).unwrap();
        }

        // Prepare votes stay within each partition (two each) — below threshold.
        let va = phase_votes(&kps, &[0, 1], 0, 0, 1, VotePhase::Prepare, a);
        let vb = phase_votes(&kps, &[2, 3], 0, 0, 1, VotePhase::Prepare, b);
        for (i, e) in engines.iter_mut().enumerate() {
            let votes = if i < 2 { &va } else { &vb };
            for v in votes {
                let _ = e.add_vote(v);
            }
            assert!(
                e.try_certify(1, VotePhase::Prepare).unwrap().is_none(),
                "no QC may form under the partition"
            );
        }
        // Safety under the split: nothing finalized, nothing locked.
        for e in &engines {
            assert_ne!(e.status(1), Some(CommandStatus::Finalized));
            assert_eq!(e.locked_block(1), None);
        }

        // Heal + view change: all four replicas time out view 0, each forms the
        // certificate, and advances to view 1.
        let timeouts: Vec<TimeoutVote> = (0..4u32)
            .map(|i| signed_timeout(&kps[usize::try_from(i).unwrap()], 0, 0, i))
            .collect();
        for e in engines.iter_mut() {
            for t in &timeouts {
                e.add_timeout(t).unwrap();
            }
            let tc = e
                .try_form_timeout_certificate(0)
                .expect("timeout certificate forms at quorum");
            assert_eq!(e.advance_view(&tc).unwrap(), 1);
        }

        // View 1: the honest leader proposes block A to everyone; a full chained
        // certification with all four honest votes follows.
        let p1 = signed_proposal(&kps[1], 0, 1, 1, a, Hash::ZERO, 0, 0, 1);
        for e in engines.iter_mut() {
            assert_eq!(
                e.receive_proposal(p1.clone()).unwrap(),
                ProposalOutcome::Accepted
            );
            e.execute(1).unwrap();
        }
        for phase in [VotePhase::Prepare, VotePhase::PreCommit, VotePhase::Commit] {
            let votes = phase_votes(&kps, &[0, 1, 2, 3], 0, 1, 1, phase, a);
            add_votes_to_all(&mut engines, &votes);
            for e in engines.iter_mut() {
                e.try_certify(1, phase)
                    .unwrap()
                    .expect("QC forms with a full honest quorum");
            }
        }
        let exec = Hash::from_bytes([0xCC; 32]);
        let cert = quorum_over(
            &kps,
            &[0, 1, 2, 3],
            execution_commitment_digest(0, 1, 1, a, exec),
        );
        for e in engines.iter_mut() {
            e.certify_execution(1, exec, &cert).unwrap();
            assert_eq!(e.finalize(1).unwrap(), a);
        }

        // Agreement: every honest replica finalized the SAME block, never B, and
        // no replica observed a quorum fork.
        let commit_digest = vote_digest(0, 1, 1, VotePhase::Commit, a);
        for e in &engines {
            assert_eq!(e.status(1), Some(CommandStatus::Finalized));
            assert_eq!(
                e.quorum_certificate(1).map(|q| q.message),
                Some(commit_digest)
            );
            assert!(e.quorum_forks().is_empty());
        }
    }
}
