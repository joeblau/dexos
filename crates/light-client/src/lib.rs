//! `light-client` — light-node sync, checkpoint verification, and account/market
//! proofs for the DexOS decentralized market operating system.
//!
//! A light node is a *verifier, not a participant*. It does not vote, execute
//! canonical state, or accept order entry. It ingests quorum-signed checkpoints,
//! verifies each one against the epoch's trusted [`crypto::ValidatorSet`] and the
//! checkpoint chain's ancestry, and tracks the **highest verified checkpoint**
//! (height + state root) per shard. It then answers read-only queries — account
//! balances / positions and market state — by verifying incremental Merkle
//! proofs against a verified state root.
//!
//! # No trusted proxy
//!
//! The defining invariant is that a light node never presents unverified data as
//! trusted. Every response is a [`VerifiedValue<T>`] carrying an explicit
//! [`Verification`] tag ([`Verification::Verified`], [`Verification::Stale`], or
//! [`Verification::Unverified`]), and there is no constructor that upgrades an
//! unverified value. Any operation a light node must not perform — order entry,
//! deposits, voting, execution, journaling — is refused with a typed
//! [`LightClientError::Unsupported`].
//!
//! # Modules
//!
//! - [`verification`]: the [`Verification`] status and [`VerifiedValue`] wrapper.
//! - [`sync`]: the per-shard checkpoint-chain state machine ([`ShardSync`]) —
//!   in-order acceptance, gap buffering / backfill, duplicate handling,
//!   equivocation and ancestry rejection.
//! - [`proofs`]: account / market inclusion and non-inclusion proof verification.
//! - [`discovery`]: bounded peer / market discovery ingestion.
//! - [`cache`]: a bounded, insertion-ordered cache with counted eviction.
//! - [`driver`]: a bounded, non-blocking (`tokio`) ingress that sheds load under
//!   bursts with counted drops.
//! - [`rpc`]: the read-only RPC request / response surface.
//! - [`client`]: the composed [`LightClient`].

pub mod cache;
pub mod client;
pub mod discovery;
pub mod driver;
pub mod error;
pub mod proofs;
pub mod rpc;
pub mod sync;
pub mod verification;

pub use cache::BoundedCache;
pub use client::{LightClient, LightConfig, DEFAULT_ACCOUNT_CACHE, DEFAULT_CHECKPOINT_CACHE};
pub use discovery::{
    Discovery, MarketAdvertisement, PeerAdvertisement, DEFAULT_MARKET_LIMIT, DEFAULT_PEER_LIMIT,
};
pub use driver::{BoundedIngress, Ingress};
pub use error::{LightClientError, UnsupportedOp};
pub use proofs::{
    verify_account_absence, verify_account_value, verify_market_absence, verify_market_value,
};
pub use rpc::{RpcRequest, RpcResponse};
pub use sync::{
    IngestOutcome, ShardSync, VerifiedTip, DEFAULT_BUFFER_LIMIT, DEFAULT_HISTORY_LIMIT,
};
pub use verification::{Verification, VerifiedValue};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "light-client";

#[cfg(test)]
mod tests {
    use super::*;

    use consensus::{
        build_checkpoint_header, seal_checkpoint, Checkpoint, CheckpointError, CheckpointHeader,
    };
    use crypto::ThresholdSigners;
    use state_tree::StateTree;
    use types::{AccountId, Hash, MarketId, MarketType, ShardId};

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

    fn signers() -> ThresholdSigners {
        // 4 validators, threshold weight 3 (2f+1 with f=1).
        ThresholdSigners::from_seeds(&[[0; 32], [1; 32], [2; 32], [3; 32]], 3)
    }

    #[allow(clippy::too_many_arguments)]
    fn make_checkpoint(
        ts: &ThresholdSigners,
        shard: ShardId,
        epoch: u64,
        first: u64,
        last: u64,
        prev: Hash,
        new: Hash,
        signer_indices: &[usize],
    ) -> Checkpoint {
        let width = usize::try_from(last - first + 1).unwrap();
        let cmds: Vec<Hash> = (0..width)
            .map(|i| Hash::from_bytes([u8::try_from(i % 256).unwrap(); 32]))
            .collect();
        let execs = cmds.clone();
        let header: CheckpointHeader = build_checkpoint_header(
            epoch,
            shard,
            first,
            last,
            prev,
            new,
            &cmds,
            &execs,
            Hash::ZERO,
            0,
        )
        .unwrap();
        let qc = ts.sign(header.hash(), signer_indices.to_vec());
        seal_checkpoint(header, qc)
    }

    fn fresh_client(ts: &ThresholdSigners, shard: ShardId, trusted: Hash) -> LightClient {
        let mut c = LightClient::with_defaults();
        c.follow_shard(shard, trusted);
        c.register_validator_set(shard, 0, ts.validator_set())
            .unwrap();
        c
    }

    // ---- crate identity ---------------------------------------------------

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "light-client");
    }

    // ---- valid chain verifies and advances height -------------------------

    #[test]
    fn valid_chain_verifies_and_advances() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());

        let r1 = Hash::from_bytes([1; 32]);
        let r2 = Hash::from_bytes([2; 32]);
        let cp1 = make_checkpoint(&ts, shard, 0, 0, 3, Hash::ZERO, r1, &[0, 1, 2]);
        let cp2 = make_checkpoint(&ts, shard, 0, 4, 7, r1, r2, &[0, 1, 2]);

        assert_eq!(
            sync.ingest(cp1).unwrap(),
            IngestOutcome::Advanced {
                height: 3,
                state_root: r1
            }
        );
        assert_eq!(sync.verified_height(), Some(3));
        assert_eq!(
            sync.ingest(cp2).unwrap(),
            IngestOutcome::Advanced {
                height: 7,
                state_root: r2
            }
        );
        assert_eq!(sync.verified_height(), Some(7));
        assert_eq!(sync.verified_root(), Some(r2));
        assert_eq!(sync.next_expected_sequence(), Some(8));
    }

    // ---- tampered / insufficient QC rejected ------------------------------

    #[test]
    fn tampered_checkpoint_rejected() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());

        let mut cp = make_checkpoint(
            &ts,
            shard,
            0,
            0,
            3,
            Hash::ZERO,
            Hash::from_bytes([1; 32]),
            &[0, 1, 2],
        );
        // Tamper the committed root: the QC no longer signs the recomputed hash.
        cp.new_state_root = Hash::from_bytes([9; 32]);
        assert_eq!(
            sync.ingest(cp),
            Err(LightClientError::Checkpoint(CheckpointError::HashMismatch))
        );
        assert_eq!(sync.verified_tip(), None);
    }

    #[test]
    fn insufficient_qc_rejected() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());

        // Only 2 of 4 sign; threshold is 3.
        let cp = make_checkpoint(
            &ts,
            shard,
            0,
            0,
            3,
            Hash::ZERO,
            Hash::from_bytes([1; 32]),
            &[0, 1],
        );
        assert_eq!(
            sync.ingest(cp),
            Err(LightClientError::Checkpoint(CheckpointError::Quorum))
        );
    }

    // ---- unknown / wrong-epoch validator set ------------------------------

    #[test]
    fn unknown_epoch_validator_set_rejected() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        // Register only epoch 0; checkpoint claims epoch 1.
        sync.register_validator_set(0, ts.validator_set());
        let cp = make_checkpoint(
            &ts,
            shard,
            1,
            0,
            3,
            Hash::ZERO,
            Hash::from_bytes([1; 32]),
            &[0, 1, 2],
        );
        assert_eq!(
            sync.ingest(cp),
            Err(LightClientError::UnknownValidatorSet { epoch: 1 })
        );
    }

    #[test]
    fn wrong_committee_for_epoch_rejected() {
        let ts = signers();
        // A different committee registered for epoch 0.
        let other = ThresholdSigners::from_seeds(&[[9; 32], [8; 32], [7; 32], [6; 32]], 3);
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, other.validator_set());

        let cp = make_checkpoint(
            &ts,
            shard,
            0,
            0,
            3,
            Hash::ZERO,
            Hash::from_bytes([1; 32]),
            &[0, 1, 2],
        );
        assert_eq!(
            sync.ingest(cp),
            Err(LightClientError::Checkpoint(CheckpointError::Quorum))
        );
    }

    // ---- broken ancestry --------------------------------------------------

    #[test]
    fn broken_ancestry_rejected() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());

        let r1 = Hash::from_bytes([1; 32]);
        let cp1 = make_checkpoint(&ts, shard, 0, 0, 3, Hash::ZERO, r1, &[0, 1, 2]);
        sync.ingest(cp1).unwrap();

        // cp2 is next-in-line but its previous root does not match the tip.
        let bad = make_checkpoint(
            &ts,
            shard,
            0,
            4,
            7,
            Hash::from_bytes([99; 32]),
            Hash::from_bytes([2; 32]),
            &[0, 1, 2],
        );
        assert_eq!(sync.ingest(bad), Err(LightClientError::BrokenAncestry));

        // First checkpoint that does not chain onto the trusted root.
        let mut sync2 = ShardSync::new(shard, Hash::from_bytes([42; 32]));
        sync2.register_validator_set(0, ts.validator_set());
        let cp = make_checkpoint(&ts, shard, 0, 0, 3, Hash::ZERO, r1, &[0, 1, 2]);
        assert_eq!(sync2.ingest(cp), Err(LightClientError::UntrustedRoot));
    }

    // ---- equivocation -----------------------------------------------------

    #[test]
    fn equivocating_checkpoint_rejected() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());

        let r1 = Hash::from_bytes([1; 32]);
        let cp1 = make_checkpoint(&ts, shard, 0, 0, 3, Hash::ZERO, r1, &[0, 1, 2]);
        sync.ingest(cp1).unwrap();
        // Advance so the range [0,3] is strictly in the past.
        let cp2 = make_checkpoint(
            &ts,
            shard,
            0,
            4,
            7,
            r1,
            Hash::from_bytes([2; 32]),
            &[0, 1, 2],
        );
        sync.ingest(cp2).unwrap();

        // A conflicting checkpoint over the already-accepted range [0,3].
        let fork = make_checkpoint(
            &ts,
            shard,
            0,
            0,
            3,
            Hash::ZERO,
            Hash::from_bytes([77; 32]),
            &[0, 1, 2],
        );
        assert_eq!(
            sync.ingest(fork),
            Err(LightClientError::Equivocation { first: 0, last: 3 })
        );
    }

    // ---- shard continuity -------------------------------------------------

    #[test]
    fn shard_mismatch_rejected() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());
        let cp = make_checkpoint(
            &ts,
            ShardId::new(1),
            0,
            0,
            3,
            Hash::ZERO,
            Hash::from_bytes([1; 32]),
            &[0, 1, 2],
        );
        assert_eq!(
            sync.ingest(cp),
            Err(LightClientError::ShardMismatch {
                expected: 0,
                got: 1
            })
        );
    }

    // ---- out-of-order gap -> backfill -> recovery -------------------------

    #[test]
    fn gapped_delivery_buffers_then_backfills() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());

        let r1 = Hash::from_bytes([1; 32]);
        let r2 = Hash::from_bytes([2; 32]);
        let r3 = Hash::from_bytes([3; 32]);
        let cp1 = make_checkpoint(&ts, shard, 0, 0, 3, Hash::ZERO, r1, &[0, 1, 2]);
        let cp2 = make_checkpoint(&ts, shard, 0, 4, 7, r1, r2, &[0, 1, 2]);
        let cp3 = make_checkpoint(&ts, shard, 0, 8, 11, r2, r3, &[0, 1, 2]);

        sync.ingest(cp1).unwrap();
        // Deliver cp3 before cp2: it is ahead -> buffered, backfill needed.
        assert_eq!(
            sync.ingest(cp3).unwrap(),
            IngestOutcome::Buffered {
                need_from: 4,
                got_from: 8
            }
        );
        assert_eq!(sync.verified_height(), Some(3));
        assert_eq!(sync.buffered_len(), 1);

        // Backfill cp2: draining pulls cp3 in behind it -> tip jumps to 11.
        assert_eq!(
            sync.ingest(cp2).unwrap(),
            IngestOutcome::Advanced {
                height: 7,
                state_root: r2
            }
        );
        assert_eq!(sync.verified_height(), Some(11));
        assert_eq!(sync.verified_root(), Some(r3));
        assert_eq!(sync.buffered_len(), 0);
    }

    #[test]
    fn duplicate_delivery_is_idempotent() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());

        let r1 = Hash::from_bytes([1; 32]);
        let cp1 = make_checkpoint(&ts, shard, 0, 0, 3, Hash::ZERO, r1, &[0, 1, 2]);
        sync.ingest(cp1.clone()).unwrap();
        assert_eq!(sync.ingest(cp1.clone()).unwrap(), IngestOutcome::Duplicate);
        assert_eq!(sync.ingest(cp1).unwrap(), IngestOutcome::Duplicate);
        assert_eq!(sync.verified_height(), Some(3));
        assert_eq!(sync.accepted_count(), 1);
    }

    // ---- deterministic replay: two streams, identical tip -----------------

    #[test]
    fn deterministic_replay_same_tip() {
        let ts = signers();
        let shard = ShardId::new(0);

        // Build a 6-checkpoint chain.
        let mut roots = vec![Hash::ZERO];
        let mut rng = Lcg(0x5151_5151);
        for _ in 0..6 {
            roots.push(rng.hash());
        }
        let mut chain = Vec::new();
        for i in 0..6u64 {
            let first = i * 4;
            let last = first + 3;
            chain.push(make_checkpoint(
                &ts,
                shard,
                0,
                first,
                last,
                roots[usize::try_from(i).unwrap()],
                roots[usize::try_from(i + 1).unwrap()],
                &[0, 1, 2],
            ));
        }

        let run = |order: &[usize]| {
            let mut sync = ShardSync::new(shard, Hash::ZERO);
            sync.register_validator_set(0, ts.validator_set());
            for &i in order {
                let _ = sync.ingest(chain[i].clone());
            }
            (sync.verified_tip(), sync.accepted_count())
        };

        // In-order and a shuffled-but-eventually-complete order converge.
        let in_order = run(&[0, 1, 2, 3, 4, 5]);
        let shuffled = run(&[0, 2, 1, 4, 3, 5]);
        assert_eq!(in_order, shuffled);
        assert_eq!(in_order.0.unwrap().height, 23);
        assert_eq!(in_order.0.unwrap().state_root, roots[6]);
    }

    // ---- property: any verifying chain has contiguous linkage -------------

    #[test]
    fn property_verifying_chain_is_contiguous() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut rng = Lcg(0xABC1_2345);

        for _ in 0..200 {
            let n = 1 + usize::try_from(rng.next() % 8).unwrap();
            let mut roots = vec![Hash::ZERO];
            for _ in 0..n {
                roots.push(rng.hash());
            }
            let mut sync = ShardSync::new(shard, Hash::ZERO);
            sync.register_validator_set(0, ts.validator_set());

            let mut expected_first = 0u64;
            let mut prev_root = Hash::ZERO;
            for i in 0..n {
                let width = 1 + (rng.next() % 4);
                let first = expected_first;
                let last = first + width - 1;
                let new = roots[i + 1];
                let cp = make_checkpoint(&ts, shard, 0, first, last, prev_root, new, &[0, 1, 2]);
                let out = sync.ingest(cp).unwrap();
                assert_eq!(
                    out,
                    IngestOutcome::Advanced {
                        height: last,
                        state_root: new
                    }
                );
                // Contiguous linkage invariant.
                assert_eq!(sync.next_expected_sequence(), Some(last + 1));
                assert_eq!(sync.verified_root(), Some(new));
                expected_first = last + 1;
                prev_root = new;
            }
            // The verified tip chains all the way back to the trusted root.
            assert_eq!(sync.verified_root(), Some(prev_root));
        }
    }

    // ---- SIMD-vs-scalar batch signature equivalence -----------------------

    #[test]
    fn batch_and_scalar_signature_verification_agree() {
        // The checkpoint QC's member signatures verified via crypto's batch path
        // (SIMD candidate) must be bit-identical to the scalar reference path.
        let ts = signers();
        let shard = ShardId::new(0);
        let cp = make_checkpoint(
            &ts,
            shard,
            0,
            0,
            3,
            Hash::ZERO,
            Hash::from_bytes([1; 32]),
            &[0, 1, 2],
        );
        let msg = cp.hash();
        let set_seeds: [[u8; 32]; 4] = [[0; 32], [1; 32], [2; 32], [3; 32]];
        let keys: Vec<crypto::KeyPair> = set_seeds.iter().map(crypto::KeyPair::from_seed).collect();

        // Batch input: the three signers over the same message.
        let mut batch = Vec::new();
        let sigs = &cp.quorum_certificate.signatures;
        for (i, sig) in sigs.iter().enumerate() {
            batch.push((keys[i].public(), msg.as_bytes().to_vec(), *sig));
        }
        let batch_results = crypto::batch_verify_ed25519(&batch);
        let scalar_results: Vec<bool> = batch
            .iter()
            .map(|(pk, m, sig)| crypto::verify_ed25519(pk, m, sig).is_ok())
            .collect();
        assert_eq!(batch_results, scalar_results);
        assert!(batch_results.iter().all(|&b| b));
    }

    // ---- account & market proofs ------------------------------------------

    fn tree_checkpoint(
        ts: &ThresholdSigners,
        shard: ShardId,
        first: u64,
        last: u64,
        prev: Hash,
        tree: &StateTree,
    ) -> Checkpoint {
        make_checkpoint(ts, shard, 0, first, last, prev, tree.root(), &[0, 1, 2])
    }

    #[test]
    fn account_proof_verifies_and_tamper_fails() {
        let ts = signers();
        let shard = ShardId::new(0);

        let mut tree = StateTree::new(64, 64);
        tree.set_account(AccountId::new(7), b"balance:100").unwrap();
        tree.set_market(MarketId::new(2), b"mkt").unwrap();
        let cp = tree_checkpoint(&ts, shard, 0, 0, Hash::ZERO, &tree);

        let mut client = fresh_client(&ts, shard, Hash::ZERO);
        client.ingest_checkpoint(cp).unwrap();

        let proof = tree.account_proof(AccountId::new(7)).unwrap();
        let good = client
            .get_account_proof(shard, AccountId::new(7), b"balance:100", &proof)
            .unwrap();
        assert!(good.is_verified());
        assert_eq!(
            good.verification(),
            Verification::Verified {
                checkpoint_height: 0
            }
        );
        assert_eq!(good.value(), b"balance:100");

        // Tampered leaf -> not verified.
        let bad_leaf = client
            .get_account_proof(shard, AccountId::new(7), b"balance:999", &proof)
            .unwrap();
        assert_eq!(bad_leaf.verification(), Verification::Unverified);

        // Tampered proof path -> not verified.
        let mut tampered = proof.clone();
        let mut b = *tampered[0].as_bytes();
        b[0] ^= 0x01;
        tampered[0] = Hash::from_bytes(b);
        let bad_proof = client
            .get_account_proof(shard, AccountId::new(7), b"balance:100", &tampered)
            .unwrap();
        assert_eq!(bad_proof.verification(), Verification::Unverified);

        // Market proof round trip.
        let mp = tree.market_proof(MarketId::new(2)).unwrap();
        let m = client
            .get_market_proof(shard, MarketId::new(2), b"mkt", &mp)
            .unwrap();
        assert!(m.is_verified());
    }

    #[test]
    fn property_any_single_proof_mutation_fails() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut tree = StateTree::new(32, 32);
        for i in 0..16u32 {
            tree.set_account(AccountId::new(i), format!("acct-{i}").as_bytes())
                .unwrap();
        }
        let cp = tree_checkpoint(&ts, shard, 0, 0, Hash::ZERO, &tree);
        let mut client = fresh_client(&ts, shard, Hash::ZERO);
        client.ingest_checkpoint(cp).unwrap();

        for i in 0..16u32 {
            let leaf = format!("acct-{i}");
            let proof = tree.account_proof(AccountId::new(i)).unwrap();
            assert!(client
                .get_account_proof(shard, AccountId::new(i), leaf.as_bytes(), &proof)
                .unwrap()
                .is_verified());
            for j in 0..proof.len() {
                let mut t = proof.clone();
                let mut b = *t[j].as_bytes();
                b[0] ^= 0x01;
                t[j] = Hash::from_bytes(b);
                assert_eq!(
                    client
                        .get_account_proof(shard, AccountId::new(i), leaf.as_bytes(), &t)
                        .unwrap()
                        .verification(),
                    Verification::Unverified
                );
            }
        }
    }

    #[test]
    fn non_inclusion_proof_distinguished_from_inclusion() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut tree = StateTree::new(32, 32);
        tree.set_account(AccountId::new(3), b"present").unwrap();
        // Account 9 is never set -> absent (empty leaf).
        let cp = tree_checkpoint(&ts, shard, 0, 0, Hash::ZERO, &tree);
        let mut client = fresh_client(&ts, shard, Hash::ZERO);
        client.ingest_checkpoint(cp).unwrap();
        let sync = client.shard(shard).unwrap();

        // Absence proof for the absent account verifies.
        let absent_proof = tree.account_proof(AccountId::new(9)).unwrap();
        let absent = verify_account_absence(sync, AccountId::new(9), &absent_proof);
        assert!(absent.is_verified());
        assert!(*absent.value());

        // An inclusion proof for the *present* account does NOT satisfy absence.
        let present_proof = tree.account_proof(AccountId::new(3)).unwrap();
        let not_absent = verify_account_absence(sync, AccountId::new(3), &present_proof);
        assert_eq!(not_absent.verification(), Verification::Unverified);

        // And an inclusion query for the absent account (claiming bytes) fails.
        let inclusion = verify_account_value(sync, AccountId::new(9), b"present", &absent_proof);
        assert_eq!(inclusion.verification(), Verification::Unverified);
    }

    #[test]
    fn stale_root_labeled_stale_never_verified() {
        let ts = signers();
        let shard = ShardId::new(0);

        // State A -> root r1.
        let mut tree_a = StateTree::new(32, 32);
        tree_a.set_account(AccountId::new(4), b"old").unwrap();
        let r1 = tree_a.root();
        // State B -> root r2 (advance).
        let mut tree_b = StateTree::new(32, 32);
        tree_b.set_account(AccountId::new(4), b"new").unwrap();
        let r2 = tree_b.root();

        let cp1 = make_checkpoint(&ts, shard, 0, 0, 3, Hash::ZERO, r1, &[0, 1, 2]);
        let cp2 = make_checkpoint(&ts, shard, 0, 4, 7, r1, r2, &[0, 1, 2]);

        let mut client = fresh_client(&ts, shard, Hash::ZERO);
        client.ingest_checkpoint(cp1).unwrap();
        client.ingest_checkpoint(cp2).unwrap();

        // A proof against the OLD root r1 verifies only as Stale, never Verified.
        let old_proof = tree_a.account_proof(AccountId::new(4)).unwrap();
        let v = client
            .get_account_proof(shard, AccountId::new(4), b"old", &old_proof)
            .unwrap();
        assert_eq!(
            v.verification(),
            Verification::Stale {
                checkpoint_height: 3
            }
        );
        assert!(!v.is_verified());

        // The current-root proof is Verified.
        let new_proof = tree_b.account_proof(AccountId::new(4)).unwrap();
        let cur = client
            .get_account_proof(shard, AccountId::new(4), b"new", &new_proof)
            .unwrap();
        assert_eq!(
            cur.verification(),
            Verification::Verified {
                checkpoint_height: 7
            }
        );
    }

    #[test]
    fn unverifiable_query_is_unverified_not_verified() {
        let ts = signers();
        let shard = ShardId::new(0);
        // No checkpoint ingested yet.
        let mut client = fresh_client(&ts, shard, Hash::ZERO);
        let v = client
            .get_account_proof(shard, AccountId::new(1), b"x", &[Hash::ZERO])
            .unwrap();
        assert_eq!(v.verification(), Verification::Unverified);
        assert!(client.get_latest_checkpoint(shard).is_err());
    }

    // ---- write refusals & RPC surface -------------------------------------

    #[test]
    fn write_methods_are_refused() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut client = fresh_client(&ts, shard, Hash::ZERO);

        assert_eq!(
            client.submit_order(),
            Err(LightClientError::Unsupported(UnsupportedOp::SubmitOrder))
        );
        assert_eq!(
            client.cancel_order(),
            Err(LightClientError::Unsupported(UnsupportedOp::CancelOrder))
        );
        assert_eq!(
            client.deposit(),
            Err(LightClientError::Unsupported(UnsupportedOp::Deposit))
        );
        assert_eq!(
            client.withdraw(),
            Err(LightClientError::Unsupported(UnsupportedOp::Withdraw))
        );
        assert!(!client.persists_command_log());
        assert!(!client.spawns_consensus());

        // Via the RPC surface, every write method is refused.
        for req in [
            RpcRequest::SubmitOrder,
            RpcRequest::CancelOrder,
            RpcRequest::AmendOrder,
            RpcRequest::Deposit,
            RpcRequest::Withdraw,
        ] {
            assert!(req.is_write());
            assert!(matches!(
                client.handle(req),
                Err(LightClientError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn every_read_rpc_carries_verification_status() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut tree = StateTree::new(32, 32);
        tree.set_account(AccountId::new(1), b"v").unwrap();
        let cp = tree_checkpoint(&ts, shard, 0, 0, Hash::ZERO, &tree);
        let mut client = fresh_client(&ts, shard, Hash::ZERO);
        client.ingest_checkpoint(cp).unwrap();
        client.ingest_market_advertisement(MarketAdvertisement {
            market_id: MarketId::new(1),
            shard_id: shard,
            market_type: MarketType::Perpetual,
            checkpoint_height: 0,
        });

        let proof = tree.account_proof(AccountId::new(1)).unwrap();
        let reads = [
            RpcRequest::GetLatestCheckpoint { shard: 0 },
            RpcRequest::GetAccountProof {
                shard: 0,
                account: 1,
                leaf: b"v".to_vec(),
                proof: proof.clone(),
            },
            RpcRequest::GetDiscoveredMarkets,
        ];
        for req in reads {
            assert!(!req.is_write());
            let resp = client.handle(req).unwrap();
            // Every read response exposes a verification status.
            let _ = resp.verification();
        }

        // Discovered-markets is unverified metadata; latest-checkpoint is verified.
        let disc = client.handle(RpcRequest::GetDiscoveredMarkets).unwrap();
        assert_eq!(disc.verification(), Verification::Unverified);
        let latest = client
            .handle(RpcRequest::GetLatestCheckpoint { shard: 0 })
            .unwrap();
        assert!(latest.verification().is_verified());
    }

    // ---- discovery & caches -----------------------------------------------

    #[test]
    fn discovery_and_market_listing() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut client = fresh_client(&ts, shard, Hash::ZERO);
        client.ingest_market_advertisement(MarketAdvertisement {
            market_id: MarketId::new(42),
            shard_id: shard,
            market_type: MarketType::Perpetual,
            checkpoint_height: 5,
        });
        client.ingest_peer_advertisement(PeerAdvertisement {
            peer_id: 1,
            shard_id: shard,
            tip_height: 5,
        });
        assert!(client.discovery().knows_market(MarketId::new(42)));
        let markets = client.get_discovered_markets();
        assert_eq!(markets.verification(), Verification::Unverified);
        assert_eq!(markets.value().len(), 1);
        assert_eq!(client.discovery().peer_count(), 1);
    }

    #[test]
    fn bounded_cache_never_exceeds_capacity_and_counts_eviction() {
        let mut cache: BoundedCache<u32, u32> = BoundedCache::new(4);
        for i in 0..100u32 {
            cache.insert(i, i);
            assert!(cache.len() <= 4);
        }
        assert_eq!(cache.len(), 4);
        assert!(cache.evicted() >= 96);
        // Newest keys survive (FIFO eviction).
        assert!(cache.contains(&99));
        assert!(!cache.contains(&0));
    }

    #[test]
    fn tip_advance_invalidates_stale_cache_entries() {
        let ts = signers();
        let shard = ShardId::new(0);

        let mut tree_a = StateTree::new(32, 32);
        tree_a.set_account(AccountId::new(2), b"a").unwrap();
        let r1 = tree_a.root();
        let mut tree_b = StateTree::new(32, 32);
        tree_b.set_account(AccountId::new(2), b"b").unwrap();
        let r2 = tree_b.root();

        let cp1 = make_checkpoint(&ts, shard, 0, 0, 3, Hash::ZERO, r1, &[0, 1, 2]);
        let cp2 = make_checkpoint(&ts, shard, 0, 4, 7, r1, r2, &[0, 1, 2]);
        let mut client = fresh_client(&ts, shard, Hash::ZERO);
        client.ingest_checkpoint(cp1).unwrap();

        // Cache a verified account response at height 3.
        let proof = tree_a.account_proof(AccountId::new(2)).unwrap();
        let v = client
            .get_account_proof(shard, AccountId::new(2), b"a", &proof)
            .unwrap();
        assert!(v.is_verified());
        assert!(client.cached_account(shard, AccountId::new(2)).is_some());

        // Advancing the tip invalidates the now-stale cached entry.
        client.ingest_checkpoint(cp2).unwrap();
        assert!(client.cached_account(shard, AccountId::new(2)).is_none());
    }

    // ---- bounded, non-blocking ingress ------------------------------------

    #[tokio::test]
    async fn bounded_ingress_drops_under_burst_without_blocking() {
        let (ingress, _rx) = BoundedIngress::<u64>::new(8);
        // Nothing consumes; a burst of 200 must not block and must drop the excess.
        let mut accepted = 0u64;
        for i in 0..200u64 {
            if ingress.offer(i) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 8);
        assert_eq!(ingress.dropped(), 192);
        assert_eq!(ingress.capacity(), 8);
    }

    // ---- never panics on arbitrary bytes ----------------------------------

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let ts = signers();
        let shard = ShardId::new(0);
        let mut sync = ShardSync::new(shard, Hash::ZERO);
        sync.register_validator_set(0, ts.validator_set());
        let mut client = fresh_client(&ts, shard, Hash::ZERO);

        let mut rng = Lcg(0xDEAD_0BAD_F00D_0001);
        for _ in 0..3000 {
            let len = usize::try_from(rng.next() % 300).unwrap();
            let bytes = rng.bytes(len);

            // Wire decodes are total.
            if let Ok(cp) = codec::decode::<Checkpoint>(&bytes) {
                let _ = sync.ingest(cp.clone());
                let _ = client.ingest_checkpoint(cp);
            }
            let _ = codec::decode::<CheckpointHeader>(&bytes);
            if let Ok(req) = codec::decode::<RpcRequest>(&bytes) {
                let _ = client.handle(req);
            }
            let _ = codec::decode::<MarketAdvertisement>(&bytes);
            let _ = codec::decode::<PeerAdvertisement>(&bytes);

            // Arbitrary proof bytes as a Hash path never panic verification.
            let plen = usize::try_from(rng.next() % 40).unwrap();
            let proof: Vec<Hash> = (0..plen).map(|_| rng.hash()).collect();
            let id = AccountId::new(u32::try_from(rng.next() & 0xffff).unwrap());
            let leaf_len = usize::try_from(rng.next() % 24).unwrap();
            let leaf = rng.bytes(leaf_len);
            let _ = verify_account_value(&sync, id, &leaf, &proof);
            let _ = verify_account_absence(&sync, id, &proof);
            let _ = verify_market_value(&sync, MarketId::new(id.get()), &leaf, &proof);
            let _ = verify_market_absence(&sync, MarketId::new(id.get()), &proof);
        }
    }

    // ---- RpcRequest round-trips through codec -----------------------------

    #[test]
    fn rpc_request_round_trips() {
        let req = RpcRequest::GetAccountProof {
            shard: 0,
            account: 7,
            leaf: b"leaf".to_vec(),
            proof: vec![Hash::from_bytes([1; 32]), Hash::from_bytes([2; 32])],
        };
        let bytes = codec::encode(&req).unwrap();
        let back: RpcRequest = codec::decode(&bytes).unwrap();
        assert_eq!(req, back);
    }
}
