//! Behavioral tests for [`super::MockSvmAdapter`], exercising the full
//! header-chain finality path end to end.

use super::{MockSvmAdapter, SvmCommit, SVM_ADDRESS_LEN};
use chain_adapter::{
    certify_deposit, run_conformance, verify_finality, AdapterError, AssetId, BlockHeader,
    ChainAdapter, ChainCommit, ChainId, ConformanceFixture, DepositEvent, DepositTracker,
    FinalityPolicy, FinalityWitness, InclusionProof, TxId, VerifiedDeposit, WithdrawalRequest,
    WithdrawalStatus,
};
use crypto::ThresholdSigners;
use types::{AccountId, Amount, Hash};

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn small_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() % 5).unwrap_or_default()
    }
}

fn sample_deposit(tx: u8, amount: i128) -> DepositEvent {
    DepositEvent {
        source_chain: ChainId::new(900),
        source_tx: TxId::new(vec![tx; 64]),
        source_event_index: 0,
        asset: AssetId::new(3),
        amount: Amount::from_raw(amount),
        destination_account: AccountId::new(8),
    }
}

fn sample_withdrawal() -> WithdrawalRequest {
    WithdrawalRequest {
        account_id: AccountId::new(8),
        destination_chain: ChainId::new(900),
        destination_address: vec![0xCD; SVM_ADDRESS_LEN],
        asset: AssetId::new(3),
        amount: Amount::from_raw(2_000_000),
        nonce: 1,
        expires_at: 1_000,
        user_signature: vec![9; 64],
    }
}

#[test]
fn spl_deposit_reaches_commitment_and_certifies() {
    let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(32));
    let ev = sample_deposit(1, 2_000_000);
    let tx = ev.source_tx.clone();
    a.inject_deposit(ev, 5_000);

    // 16 slots total (5000..=5015): below the 32-slot commitment.
    a.advance_head(15);
    assert!(matches!(
        a.verify_deposit(&tx),
        Err(AdapterError::NotFinal { have: 16, need: 32 })
    ));
    assert!(a.observe_deposits().unwrap().is_empty());

    // Reach commitment: 32 slots total (5000..=5031).
    a.advance_head(16);
    let vd = a.verify_deposit(&tx).unwrap();
    assert_eq!(vd.finality_proof.confirmations, 32);
    assert_eq!(vd.finality_proof.block_number, 5_000);
    assert_eq!(a.observe_deposits().unwrap().len(), 1);

    let signers = ThresholdSigners::from_seeds(&[[4u8; 32], [5u8; 32], [6u8; 32]], 2);
    let cert = certify_deposit(&vd, &signers, vec![0, 1, 2]);
    cert.verify(&signers.validator_set(), &a.policy())
        .expect("certificate verifies");

    let mut tracker = DepositTracker::new(a.policy());
    assert!(tracker.accept(&vd).is_ok());
    assert_eq!(tracker.accept(&vd), Err(AdapterError::DuplicateObservation));
}

#[test]
fn confirmations_are_derived_not_asserted() {
    let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(3));
    let ev = sample_deposit(2, 500);
    let tx = ev.source_tx.clone();
    a.inject_deposit(ev.clone(), 100);
    assert!(matches!(
        a.verify_deposit(&tx),
        Err(AdapterError::NotFinal { have: 1, need: 3 })
    ));

    // Forge a witness claiming depth 3 with a tampered base inclusion root.
    let leaf = SvmCommit.deposit_leaf(&ev);
    let mut headers: Vec<BlockHeader> = Vec::new();
    let mut parent = Hash::ZERO;
    for i in 0..3u64 {
        let root = if i == 0 {
            // Wrong root: does not commit to the real leaf.
            Hash::from_bytes([0x77; 32])
        } else {
            Hash::ZERO
        };
        let h = BlockHeader {
            number: 100 + i,
            parent_hash: parent,
            inclusion_root: root,
        };
        parent = SvmCommit.header_hash(&h);
        headers.push(h);
    }
    let _ = leaf;
    let forged = FinalityWitness {
        headers,
        inclusion: InclusionProof {
            leaf_index: 0,
            siblings: vec![],
        },
    };
    // Header chain links, but inclusion against the forged root fails.
    assert_eq!(
        verify_finality(&SvmCommit, &ev, &forged, FinalityPolicy::new(3)),
        Err(AdapterError::InvalidInclusion)
    );
}

#[test]
fn unknown_deposit_is_reported() {
    let a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(1));
    assert_eq!(
        a.verify_deposit(&TxId::new(vec![0xFF; 64])),
        Err(AdapterError::UnknownTx)
    );
}

#[test]
fn withdrawal_reaches_finalized_at_commitment() {
    let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(2));
    a.support_asset(AssetId::new(3));
    a.set_now(10);
    let req = sample_withdrawal();

    let unsigned = a.build_withdrawal(&req).unwrap();
    assert_eq!(a.build_withdrawal(&req).unwrap(), unsigned);
    assert_eq!(unsigned.withdrawal_id, req.id());

    let tx = a.broadcast_withdrawal(&unsigned);
    assert_eq!(
        a.observe_withdrawal(&tx).unwrap(),
        WithdrawalStatus::Pending
    );
    a.advance_withdrawal(&tx, 1);
    assert_eq!(
        a.observe_withdrawal(&tx).unwrap(),
        WithdrawalStatus::Confirming { confirmations: 1 }
    );
    a.advance_withdrawal(&tx, 1);
    assert_eq!(
        a.observe_withdrawal(&tx).unwrap(),
        WithdrawalStatus::Finalized
    );
}

#[test]
fn withdrawal_rejections() {
    let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(2));
    a.set_now(10);
    let req = sample_withdrawal();

    assert_eq!(
        a.build_withdrawal(&req),
        Err(AdapterError::UnsupportedAsset)
    );
    a.support_asset(AssetId::new(3));

    let mut expired = req.clone();
    expired.expires_at = 5;
    assert_eq!(a.build_withdrawal(&expired), Err(AdapterError::Expired));

    a.consume_nonce(req.account_id.get(), req.nonce);
    assert_eq!(a.build_withdrawal(&req), Err(AdapterError::ReplayedNonce));
}

#[test]
fn failed_withdrawal_reported() {
    let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(2));
    a.support_asset(AssetId::new(3));
    a.set_now(0);
    let unsigned = a.build_withdrawal(&sample_withdrawal()).unwrap();
    let tx = a.broadcast_withdrawal(&unsigned);
    a.fail_withdrawal(&tx);
    assert_eq!(a.observe_withdrawal(&tx).unwrap(), WithdrawalStatus::Failed);
}

#[test]
fn deterministic_replay_of_event_log() {
    let build = || {
        let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(32));
        for (tx, amt, slot) in [(1u8, 100i128, 1_000u64), (2, 200, 1_000), (3, 300, 5_000)] {
            a.inject_deposit(sample_deposit(tx, amt), slot);
        }
        // Head sits at slot 5_000 (the deepest injected slot). The slot-1000
        // deposits are thousands of slots deep (final at 32), while the
        // slot-5000 deposit has only 1 confirmation and is withheld.
        a.observe_deposits().unwrap()
    };
    let first = build();
    let second = build();
    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
}

#[test]
fn conformance_suite_passes() {
    let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(2));
    a.support_asset(AssetId::new(3));
    a.set_now(0);
    let ev = sample_deposit(9, 500);
    let tx = ev.source_tx.clone();
    a.inject_deposit(ev, 1);
    a.advance_head(1); // slots 1..=2 => 2 confirmations.

    let fixture = ConformanceFixture {
        adapter: &a,
        finalized_deposit_tx: tx,
        unknown_tx: TxId::new(vec![0xFF; 64]),
        valid_withdrawal: sample_withdrawal(),
    };
    run_conformance(&fixture).expect("adapter conforms");
}

#[test]
fn property_random_confirmation_sequences() {
    let mut lcg = Lcg::new(0x5701_5EED_0000_0002);
    for _ in 0..200 {
        let min = 1 + lcg.small_u32();
        let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(min));
        a.support_asset(AssetId::new(3));
        a.set_now(0);
        let unsigned = a.build_withdrawal(&sample_withdrawal()).unwrap();
        let tx = a.broadcast_withdrawal(&unsigned);

        let mut total = 0u32;
        let mut finalized = false;
        for _ in 0..8 {
            let delta = lcg.small_u32();
            a.advance_withdrawal(&tx, delta);
            total = total.saturating_add(delta);
            match a.observe_withdrawal(&tx).unwrap() {
                WithdrawalStatus::Finalized => {
                    assert!(total >= min);
                    finalized = true;
                }
                WithdrawalStatus::Confirming { confirmations } => {
                    assert_eq!(confirmations, total);
                    assert!((1..min).contains(&total));
                    assert!(!finalized);
                }
                WithdrawalStatus::Pending => {
                    assert_eq!(total, 0);
                    assert!(!finalized);
                }
                WithdrawalStatus::Failed => unreachable!("no failure injected"),
            }
        }
    }
}

#[test]
fn property_deposit_depth_matches_policy() {
    let mut lcg = Lcg::new(0x00DE_9051_7000_0003);
    for _ in 0..200 {
        let min = 1 + lcg.small_u32();
        let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(min));
        let ev = sample_deposit(u8::try_from(lcg.next_u64() % 250).unwrap_or(1), 42);
        let tx = ev.source_tx.clone();
        let base = lcg.next_u64() % 10_000;
        a.inject_deposit(ev, base);

        let mut depth = 1u32;
        for _ in 0..8 {
            match a.verify_deposit(&tx) {
                Ok(vd) => {
                    assert!(vd.finality_proof.confirmations >= min);
                    assert_eq!(vd.finality_proof.confirmations, depth);
                }
                Err(AdapterError::NotFinal { have, need }) => {
                    assert_eq!(have, depth);
                    assert_eq!(need, min);
                    assert!(depth < min);
                }
                Err(other) => unreachable!("unexpected error: {other}"),
            }
            let delta = lcg.small_u32();
            a.advance_head(u64::from(delta));
            depth = depth.saturating_add(delta);
        }
    }
}

#[test]
fn tracker_credits_verified_deposit_once() {
    let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(2));
    let ev = sample_deposit(3, 777);
    let tx = ev.source_tx.clone();
    a.inject_deposit(ev, 10);
    a.advance_head(1);
    let vd: VerifiedDeposit = a.verify_deposit(&tx).unwrap();
    let mut tracker = DepositTracker::new(a.policy());
    assert!(tracker.accept(&vd).is_ok());
    assert_eq!(tracker.accept(&vd), Err(AdapterError::DuplicateObservation));
}
