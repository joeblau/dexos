//! Behavioral tests for [`super::MockEvmAdapter`]. These run whenever the crate
//! is tested (the mock is compiled under `cfg(test)`), and exercise the full
//! header-chain finality path end to end.

use super::{EvmCommit, MockEvmAdapter, EVM_ADDRESS_LEN};
use chain_adapter::{
    certify_deposit, run_conformance, verify_finality, AdapterError, AssetId, ChainAdapter,
    ChainCommit, ChainId, ConformanceFixture, DepositEvent, DepositTracker, FinalityPolicy,
    FinalityWitness, InclusionProof, TxId, VerifiedDeposit, WalletBinding, WalletScheme,
    WithdrawalRequest, WithdrawalStatus,
};
use crypto::{EvmKeyPair, ThresholdSigners};
use types::{AccountId, Amount, Hash};

/// The account whose withdrawals these tests authorize.
const WITHDRAWAL_ACCOUNT: u32 = 5;

/// A deterministic EVM wallet keypair for the withdrawal account.
fn wallet() -> EvmKeyPair {
    EvmKeyPair::from_seed(&[0x11; 32]).expect("valid scalar")
}

/// Bind [`wallet`] to [`WITHDRAWAL_ACCOUNT`] and support the sample asset.
fn setup_withdrawals(a: &mut MockEvmAdapter) {
    a.support_asset(AssetId::new(7));
    a.bind_wallet(WalletBinding {
        account: AccountId::new(WITHDRAWAL_ACCOUNT),
        scheme: WalletScheme::Secp256k1Evm,
        public_key: wallet().public_sec1(),
    });
}

/// A well-formed withdrawal for [`WITHDRAWAL_ACCOUNT`] with a valid signature by
/// [`wallet`] over its authorization digest.
fn signed_withdrawal(nonce: u64) -> WithdrawalRequest {
    let mut req = WithdrawalRequest {
        account_id: AccountId::new(WITHDRAWAL_ACCOUNT),
        destination_chain: ChainId::new(1),
        destination_address: vec![0xAB; EVM_ADDRESS_LEN],
        asset: AssetId::new(7),
        amount: Amount::from_raw(1_000_000),
        nonce,
        expires_at: 1_000,
        user_signature: vec![],
    };
    req.user_signature = wallet()
        .sign_evm(req.signing_hash().as_bytes())
        .expect("sign")
        .to_vec();
    req
}

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
        source_chain: ChainId::new(1),
        source_tx: TxId::new(vec![tx; 32]),
        source_event_index: 0,
        asset: AssetId::new(7),
        amount: Amount::from_raw(amount),
        destination_account: AccountId::new(5),
    }
}

#[test]
fn erc20_deposit_reaches_finality_and_certifies() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(12));
    let ev = sample_deposit(1, 1_000_000);
    let tx = ev.source_tx.clone();
    // Landed at block 100 => 1 confirmation (its own block).
    a.inject_deposit(ev, 100);

    // Below finality: withheld. 5 blocks total (100..=104).
    a.advance_head(4);
    assert!(matches!(
        a.verify_deposit(&tx),
        Err(AdapterError::NotFinal { have: 5, need: 12 })
    ));
    assert!(a.observe_deposits().unwrap().is_empty());

    // Reach finality: 12 blocks total (100..=111).
    a.advance_head(7);
    let vd = a.verify_deposit(&tx).unwrap();
    assert_eq!(vd.finality_proof.confirmations, 12);
    assert_eq!(vd.finality_proof.block_number, 100);
    assert_eq!(a.observe_deposits().unwrap().len(), 1);

    // Assemble and verify a quorum certificate for the deposit.
    let signers = ThresholdSigners::from_seeds(&[[1u8; 32], [2u8; 32], [3u8; 32]], 2);
    let cert = certify_deposit(&vd, &signers, vec![0, 1, 2]);
    cert.verify(&signers.validator_set(), &a.policy())
        .expect("certificate verifies");

    // Replay protection via the tracker: credited exactly once.
    let mut tracker = DepositTracker::new(a.policy());
    assert!(tracker.accept(&vd).is_ok());
    assert_eq!(tracker.accept(&vd), Err(AdapterError::DuplicateObservation));
}

#[test]
fn confirmations_are_derived_not_asserted() {
    // A forged witness with an inflated header count but a broken hash-link must
    // be rejected: an observer cannot simply claim more confirmations.
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
    let ev = sample_deposit(2, 500);
    let tx = ev.source_tx.clone();
    a.inject_deposit(ev.clone(), 100);
    // Only 1 block so far; genuinely not final.
    assert!(matches!(
        a.verify_deposit(&tx),
        Err(AdapterError::NotFinal { have: 1, need: 3 })
    ));

    // Hand-build a witness claiming depth 3 but with unlinked headers.
    let leaf = EvmCommit.deposit_leaf(&ev);
    let base = crypto::merkle_root(&[leaf]);
    let headers = (0..3u64)
        .map(|i| chain_adapter::BlockHeader {
            number: 100 + i,
            parent_hash: Hash::from_bytes([0xCC; 32]),
            inclusion_root: if i == 0 { base } else { Hash::ZERO },
        })
        .collect();
    let forged = FinalityWitness {
        headers,
        inclusion: InclusionProof {
            leaf_index: 0,
            siblings: vec![],
        },
    };
    assert_eq!(
        verify_finality(&EvmCommit, &ev, &forged, FinalityPolicy::new(3)),
        Err(AdapterError::InvalidWitness)
    );
}

#[test]
fn multiple_deposits_in_one_block_each_prove_inclusion() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(2));
    let evs: Vec<DepositEvent> = (0..4u8)
        .map(|i| sample_deposit(i, 1_000 + i128::from(i)))
        .collect();
    for ev in &evs {
        a.inject_deposit(ev.clone(), 50);
    }
    a.advance_head(1); // blocks 50..=51 => 2 confirmations.
    let verified = a.observe_deposits().unwrap();
    assert_eq!(verified.len(), 4);
    for ev in &evs {
        let vd = a.verify_deposit(&ev.source_tx).unwrap();
        assert_eq!(vd.amount, ev.amount);
        assert_eq!(vd.finality_proof.confirmations, 2);
    }
}

#[test]
fn unknown_deposit_is_reported() {
    let a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(1));
    assert_eq!(
        a.verify_deposit(&TxId::new(vec![0xFF; 32])),
        Err(AdapterError::UnknownTx)
    );
}

#[test]
fn withdrawal_reaches_finalized_after_confirmations() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
    setup_withdrawals(&mut a);
    a.set_now(10);
    let req = signed_withdrawal(1);

    // Reserve the nonce, then build the deterministic unsigned tx.
    assert!(a.reserve_withdrawal(&req).unwrap().fresh);
    let unsigned = a.build_withdrawal(&req).unwrap();
    assert_eq!(a.build_withdrawal(&req).unwrap(), unsigned);
    assert_eq!(unsigned.withdrawal_id, req.id());

    let tx = a.broadcast_withdrawal(&unsigned).unwrap();
    assert_eq!(
        a.observe_withdrawal(&tx).unwrap(),
        WithdrawalStatus::Pending
    );
    a.advance_withdrawal(&tx, 1);
    assert_eq!(
        a.observe_withdrawal(&tx).unwrap(),
        WithdrawalStatus::Confirming { confirmations: 1 }
    );
    a.advance_withdrawal(&tx, 2);
    assert_eq!(
        a.observe_withdrawal(&tx).unwrap(),
        WithdrawalStatus::Finalized
    );

    // Finalizing consumes the nonce permanently: a *different* request reusing
    // nonce 1 is rejected (the identical request would be an idempotent no-op).
    a.finalize_withdrawal(req.id()).unwrap();
    let mut reused = signed_withdrawal(1);
    reused.amount = Amount::from_raw(2_000_000);
    reused.user_signature = wallet()
        .sign_evm(reused.signing_hash().as_bytes())
        .unwrap()
        .to_vec();
    assert_eq!(
        a.reserve_withdrawal(&reused),
        Err(AdapterError::ReplayedNonce)
    );
}

#[test]
fn withdrawal_rejections() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
    a.set_now(10);
    let req = signed_withdrawal(1);

    // Asset not yet supported.
    assert_eq!(
        a.build_withdrawal(&req),
        Err(AdapterError::UnsupportedAsset)
    );
    setup_withdrawals(&mut a);

    // Expired.
    let mut expired = signed_withdrawal(1);
    expired.expires_at = 5;
    expired.user_signature = wallet()
        .sign_evm(expired.signing_hash().as_bytes())
        .unwrap()
        .to_vec();
    assert_eq!(a.build_withdrawal(&expired), Err(AdapterError::Expired));

    // Empty (wrong-length) destination address.
    let mut bad = signed_withdrawal(2);
    bad.destination_address = vec![];
    bad.user_signature = wallet()
        .sign_evm(bad.signing_hash().as_bytes())
        .unwrap()
        .to_vec();
    assert_eq!(a.build_withdrawal(&bad), Err(AdapterError::InvalidRequest));

    // Empty and random signatures fail authorization.
    let mut unsigned = signed_withdrawal(3);
    unsigned.user_signature = vec![];
    assert_eq!(
        a.build_withdrawal(&unsigned),
        Err(AdapterError::InvalidSignature)
    );
    let mut random = signed_withdrawal(3);
    random.user_signature = vec![0x42; 64];
    assert_eq!(
        a.build_withdrawal(&random),
        Err(AdapterError::InvalidSignature)
    );

    // Unbound account (wrong account) is unauthorized.
    let mut foreign = signed_withdrawal(4);
    foreign.account_id = AccountId::new(6);
    assert_eq!(
        a.build_withdrawal(&foreign),
        Err(AdapterError::Unauthorized)
    );

    // Wrong destination chain.
    let mut wrong_chain = signed_withdrawal(5);
    wrong_chain.destination_chain = ChainId::new(2);
    wrong_chain.user_signature = wallet()
        .sign_evm(wrong_chain.signing_hash().as_bytes())
        .unwrap()
        .to_vec();
    assert_eq!(
        a.build_withdrawal(&wrong_chain),
        Err(AdapterError::WrongChain)
    );

    // Reserving one nonce blocks a distinct request on the same nonce.
    assert!(a.reserve_withdrawal(&signed_withdrawal(6)).unwrap().fresh);
    let mut collide = signed_withdrawal(6);
    collide.amount = Amount::from_raw(2_000_000);
    collide.user_signature = wallet()
        .sign_evm(collide.signing_hash().as_bytes())
        .unwrap()
        .to_vec();
    assert_eq!(
        a.reserve_withdrawal(&collide),
        Err(AdapterError::ReplayedNonce)
    );
}

#[test]
fn crash_retry_returns_same_tx_without_double_send() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
    setup_withdrawals(&mut a);
    let req = signed_withdrawal(1);
    a.reserve_withdrawal(&req).unwrap();
    let unsigned = a.build_withdrawal(&req).unwrap();

    let tx1 = a.broadcast_withdrawal(&unsigned).unwrap();
    // A retry (e.g. after a crash) rebuilds and rebroadcasts: same identity, and
    // the withdrawal is still tracked exactly once.
    let unsigned2 = a.build_withdrawal(&req).unwrap();
    let tx2 = a.broadcast_withdrawal(&unsigned2).unwrap();
    assert_eq!(tx1, tx2);
    assert_eq!(
        a.observe_withdrawal(&tx1).unwrap(),
        WithdrawalStatus::Pending
    );
}

#[test]
fn broadcast_requires_reservation() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
    setup_withdrawals(&mut a);
    let req = signed_withdrawal(1);
    let unsigned = a.build_withdrawal(&req).unwrap();
    // Building alone does not reserve; broadcast without a reservation fails.
    assert_eq!(
        a.broadcast_withdrawal(&unsigned),
        Err(AdapterError::UnknownTx)
    );
}

#[test]
fn release_frees_nonce_for_retry() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
    setup_withdrawals(&mut a);
    let req = signed_withdrawal(1);
    a.reserve_withdrawal(&req).unwrap();
    // A not-yet-broadcast reservation can be released, freeing the nonce.
    a.release_withdrawal(req.id()).unwrap();
    assert!(a.reserve_withdrawal(&req).unwrap().fresh);
    // Once broadcast, release is refused (would risk a double-send).
    let unsigned = a.build_withdrawal(&req).unwrap();
    a.broadcast_withdrawal(&unsigned).unwrap();
    assert_eq!(
        a.release_withdrawal(req.id()),
        Err(AdapterError::IllegalTransition)
    );
}

#[test]
fn failed_withdrawal_reported() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
    setup_withdrawals(&mut a);
    a.set_now(0);
    let req = signed_withdrawal(1);
    a.reserve_withdrawal(&req).unwrap();
    let unsigned = a.build_withdrawal(&req).unwrap();
    let tx = a.broadcast_withdrawal(&unsigned).unwrap();
    a.fail_withdrawal(&tx);
    assert_eq!(a.observe_withdrawal(&tx).unwrap(), WithdrawalStatus::Failed);
}

#[test]
fn deterministic_replay_of_event_log() {
    let build = || {
        let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(6));
        // tx1/tx2 land deep in block 1; tx3 lands late in block 5.
        for (tx, amt, block) in [(1u8, 100i128, 1u64), (2, 200, 1), (3, 300, 5)] {
            a.inject_deposit(sample_deposit(tx, amt), block);
        }
        // Head reaches block 6: block-1 deposits have 6 confirmations (final),
        // the block-5 deposit only has 2 (withheld).
        a.advance_head(1);
        a.observe_deposits().unwrap()
    };
    let first = build();
    let second = build();
    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
}

#[test]
fn conformance_suite_passes() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(2));
    setup_withdrawals(&mut a);
    a.set_now(0);
    let ev = sample_deposit(9, 500);
    let tx = ev.source_tx.clone();
    a.inject_deposit(ev, 1);
    a.advance_head(1); // blocks 1..=2 => 2 confirmations.

    let fixture = ConformanceFixture {
        adapter: &a,
        finalized_deposit_tx: tx,
        unknown_tx: TxId::new(vec![0xFF; 32]),
        valid_withdrawal: signed_withdrawal(1),
    };
    run_conformance(&fixture).expect("adapter conforms");
}

#[test]
fn property_random_confirmation_sequences() {
    let mut lcg = Lcg::new(0xE711_5EED_0000_0001);
    for _ in 0..200 {
        let min = 1 + lcg.small_u32();
        let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(min));
        setup_withdrawals(&mut a);
        a.set_now(0);
        let req = signed_withdrawal(1);
        a.reserve_withdrawal(&req).unwrap();
        let unsigned = a.build_withdrawal(&req).unwrap();
        let tx = a.broadcast_withdrawal(&unsigned).unwrap();

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
    let mut lcg = Lcg::new(0xD3B0_51CE_0000_0007);
    for _ in 0..200 {
        let min = 1 + lcg.small_u32();
        let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(min));
        let ev = sample_deposit(u8::try_from(lcg.next_u64() % 250).unwrap_or(1), 42);
        let tx = ev.source_tx.clone();
        let base = lcg.next_u64() % 1000;
        a.inject_deposit(ev, base);

        let mut depth = 1u32; // its own block
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

// Route a genuine `VerifiedDeposit` through the tracker to prove the credit path
// consumes verification output, never a raw count.
#[test]
fn tracker_credits_verified_deposit_once() {
    let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(2));
    let ev = sample_deposit(3, 777);
    let tx = ev.source_tx.clone();
    a.inject_deposit(ev, 10);
    a.advance_head(1);
    let vd: VerifiedDeposit = a.verify_deposit(&tx).unwrap();
    let mut tracker = DepositTracker::new(a.policy());
    assert!(tracker.accept(&vd).is_ok());
    assert_eq!(tracker.accept(&vd), Err(AdapterError::DuplicateObservation));
}
