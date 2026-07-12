//! `chain-adapter` — the DexOS custody edge: the [`ChainAdapter`] trait, canonical
//! deposit/withdrawal certificate types, and the deterministic deposit
//! observation state machine (per-chain finality policy + exactly-once
//! `(chain, tx, event)` replay protection + observer quorum).
//!
//! Ledger semantics (debit/reserve before custody signs) live in
//! execution/custody; this crate provides only the observation and certificate
//! machinery. It is integer-only (no floating point), forbids unsafe, and every
//! decoder is total (typed [`CodecError`] on malformed input, never a panic).
#![forbid(unsafe_code)]

pub mod adapter;
pub mod authorization;
pub mod codec;
pub mod conformance;
pub mod deposit;
pub mod error;
pub mod finality;
pub mod ids;
pub mod policy;
pub mod reservation;
pub mod wire;
pub mod withdrawal;

pub use adapter::ChainAdapter;
pub use authorization::{verify_withdrawal_authorization, WalletBinding, WalletScheme};
pub use codec::{Codec, CodecError, Reader, Writer};
pub use conformance::{run_conformance, ConformanceFixture};
pub use deposit::{
    certify_deposit, DepositCertificate, DepositEvent, FinalityProof, SourceKey, VerifiedDeposit,
    DOMAIN_DEPOSIT,
};
pub use error::AdapterError;
pub use finality::{
    verify_finality, BlockHeader, ChainCommit, FinalityWitness, InclusionProof,
    MAX_INCLUSION_DEPTH, MAX_WITNESS_HEADERS,
};
pub use ids::{AssetId, ChainId, TxId, MAX_TXID_LEN};
pub use policy::{DepositTracker, FinalityPolicy, DEFAULT_TRACKER_CAPACITY};
pub use reservation::{ReservationState, WithdrawalLedger, WithdrawalReservation};
pub use withdrawal::{
    certify_withdrawal, UnsignedTx, WithdrawalCertificate, WithdrawalId, WithdrawalRequest,
    WithdrawalStatus, DOMAIN_WITHDRAWAL_CERT, DOMAIN_WITHDRAWAL_ID, MAX_ADDRESS_LEN,
    MAX_USER_SIG_LEN,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "chain-adapter";

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ThresholdSigners;
    use types::{AccountId, Amount, Hash};

    /// Deterministic in-test linear congruential generator (no external crates).
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
        fn next_u32(&mut self) -> u32 {
            u32::try_from(self.next_u64() >> 32).unwrap_or_default()
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next_byte()).collect()
        }
        fn next_byte(&mut self) -> u8 {
            u8::try_from(self.next_u64() & 0xFF).unwrap_or_default()
        }
        fn boundary_i128(&mut self) -> i128 {
            match self.next_u64() % 6 {
                0 => i128::MIN,
                1 => i128::MAX,
                2 => 0,
                3 => -1,
                4 => i128::from(self.next_u32()),
                _ => -i128::from(self.next_u32()),
            }
        }
    }

    fn array64(lcg: &mut Lcg) -> [u8; 64] {
        let mut a = [0u8; 64];
        for b in &mut a {
            *b = lcg.next_byte();
        }
        a
    }

    fn array32(lcg: &mut Lcg) -> [u8; 32] {
        let mut a = [0u8; 32];
        for b in &mut a {
            *b = lcg.next_byte();
        }
        a
    }

    fn rand_quorum(lcg: &mut Lcg) -> crypto::QuorumCertificate {
        let count = usize::try_from(lcg.next_u64() % 4).unwrap_or_default();
        let signatures = (0..count).map(|_| array64(lcg)).collect();
        crypto::QuorumCertificate {
            message: Hash::from_bytes(array32(lcg)),
            signer_bitmap: lcg.next_u64(),
            signatures,
        }
    }

    fn rand_finality(lcg: &mut Lcg) -> FinalityProof {
        FinalityProof {
            block_number: lcg.next_u64(),
            block_hash: Hash::from_bytes(array32(lcg)),
            confirmations: lcg.next_u32(),
        }
    }

    fn rand_txlen(lcg: &mut Lcg) -> usize {
        usize::try_from(lcg.next_u64() % 40).unwrap_or_default()
    }

    fn rand_deposit_cert(lcg: &mut Lcg) -> DepositCertificate {
        let n = rand_txlen(lcg);
        DepositCertificate {
            source_chain: ChainId::new(lcg.next_u64()),
            source_tx: TxId::new(lcg.bytes(n)),
            source_event_index: lcg.next_u32(),
            asset: AssetId::new(lcg.next_u32()),
            amount: Amount::from_raw(lcg.boundary_i128()),
            destination_account: AccountId::new(lcg.next_u32()),
            finality_proof: rand_finality(lcg),
            observer_bitmap: lcg.next_u64(),
            quorum_signature: rand_quorum(lcg),
        }
    }

    fn rand_withdrawal_req(lcg: &mut Lcg) -> WithdrawalRequest {
        let a = rand_txlen(lcg);
        let s = rand_txlen(lcg);
        WithdrawalRequest {
            account_id: AccountId::new(lcg.next_u32()),
            destination_chain: ChainId::new(lcg.next_u64()),
            destination_address: lcg.bytes(a),
            asset: AssetId::new(lcg.next_u32()),
            amount: Amount::from_raw(lcg.boundary_i128()),
            nonce: lcg.next_u64(),
            expires_at: lcg.next_u64(),
            user_signature: lcg.bytes(s),
        }
    }

    fn rand_withdrawal_cert(lcg: &mut Lcg) -> WithdrawalCertificate {
        let n = rand_txlen(lcg);
        WithdrawalCertificate {
            withdrawal_id: rand_withdrawal_req(lcg).id(),
            destination_chain: ChainId::new(lcg.next_u64()),
            destination_tx: TxId::new(lcg.bytes(n)),
            asset: AssetId::new(lcg.next_u32()),
            amount: Amount::from_raw(lcg.boundary_i128()),
            finality_proof: rand_finality(lcg),
            observer_bitmap: lcg.next_u64(),
            quorum_signature: rand_quorum(lcg),
        }
    }

    fn rand_status(lcg: &mut Lcg) -> WithdrawalStatus {
        match lcg.next_u64() % 4 {
            0 => WithdrawalStatus::Pending,
            1 => WithdrawalStatus::Confirming {
                confirmations: lcg.next_u32(),
            },
            2 => WithdrawalStatus::Finalized,
            _ => WithdrawalStatus::Failed,
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "chain-adapter");
    }

    #[test]
    fn construct_every_type() {
        let event = DepositEvent {
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![1, 2, 3]),
            source_event_index: 0,
            asset: AssetId::new(7),
            amount: Amount::from_raw(1_000_000),
            destination_account: AccountId::new(4),
        };
        let proof = FinalityProof {
            block_number: 10,
            block_hash: Hash::from_bytes([1u8; 32]),
            confirmations: 12,
        };
        let vd = VerifiedDeposit::new(event.clone(), proof);
        assert_eq!(vd.source_key(), event.source_key());

        let signers = ThresholdSigners::from_seeds(&[[1u8; 32], [2u8; 32], [3u8; 32]], 2);
        let cert = certify_deposit(&vd, &signers, vec![0, 1]);
        cert.verify(&signers.validator_set(), &FinalityPolicy::new(6))
            .expect("valid certificate verifies");
    }

    #[test]
    fn deposit_certificate_below_quorum_rejected() {
        let event = DepositEvent {
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![9, 9]),
            source_event_index: 1,
            asset: AssetId::new(2),
            amount: Amount::from_raw(500),
            destination_account: AccountId::new(3),
        };
        let proof = FinalityProof {
            block_number: 5,
            block_hash: Hash::from_bytes([2u8; 32]),
            confirmations: 6,
        };
        let vd = VerifiedDeposit::new(event, proof);
        let signers = ThresholdSigners::from_seeds(&[[1u8; 32], [2u8; 32], [3u8; 32]], 2);
        // Only one signer — below the k=2 threshold.
        let cert = certify_deposit(&vd, &signers, vec![0]);
        assert_eq!(
            cert.verify(&signers.validator_set(), &FinalityPolicy::new(6)),
            Err(AdapterError::QuorumNotMet)
        );
    }

    #[test]
    fn deposit_certificate_below_finality_rejected() {
        let event = DepositEvent {
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![4]),
            source_event_index: 0,
            asset: AssetId::new(2),
            amount: Amount::from_raw(1),
            destination_account: AccountId::new(3),
        };
        let proof = FinalityProof {
            block_number: 5,
            block_hash: Hash::ZERO,
            confirmations: 3,
        };
        let vd = VerifiedDeposit::new(event, proof);
        let signers = ThresholdSigners::from_seeds(&[[1u8; 32], [2u8; 32]], 2);
        let cert = certify_deposit(&vd, &signers, vec![0, 1]);
        assert!(matches!(
            cert.verify(&signers.validator_set(), &FinalityPolicy::new(6)),
            Err(AdapterError::NotFinal { have: 3, need: 6 })
        ));
    }

    #[test]
    fn tampered_certificate_rejected() {
        let event = DepositEvent {
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![4]),
            source_event_index: 0,
            asset: AssetId::new(2),
            amount: Amount::from_raw(100),
            destination_account: AccountId::new(3),
        };
        let proof = FinalityProof {
            block_number: 5,
            block_hash: Hash::ZERO,
            confirmations: 6,
        };
        let vd = VerifiedDeposit::new(event, proof);
        let signers = ThresholdSigners::from_seeds(&[[1u8; 32], [2u8; 32]], 2);
        let mut cert = certify_deposit(&vd, &signers, vec![0, 1]);
        // Mutate the amount after signing: message hash no longer matches.
        cert.amount = Amount::from_raw(999);
        assert_eq!(
            cert.verify(&signers.validator_set(), &FinalityPolicy::new(6)),
            Err(AdapterError::QuorumNotMet)
        );
    }

    #[test]
    fn tracker_credits_once_and_rejects_replay() {
        let mut tracker = DepositTracker::new(FinalityPolicy::new(6));
        let event = DepositEvent {
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![0xAB; 32]),
            source_event_index: 0,
            asset: AssetId::new(2),
            amount: Amount::from_raw(1_000_000),
            destination_account: AccountId::new(5),
        };
        // Below finality: withheld.
        let low = FinalityProof {
            block_number: 1,
            block_hash: Hash::ZERO,
            confirmations: 2,
        };
        assert_eq!(tracker.observe(&event, low), Ok(None));
        assert_eq!(tracker.credited_count(), 0);

        // Final: credited exactly once.
        let high = FinalityProof {
            block_number: 1,
            block_hash: Hash::ZERO,
            confirmations: 6,
        };
        let vd = tracker.observe(&event, high).unwrap();
        assert!(vd.is_some());
        assert_eq!(tracker.credited_count(), 1);

        // Replay of the same (chain, tx, event) is rejected.
        assert_eq!(
            tracker.observe(&event, high),
            Err(AdapterError::DuplicateObservation)
        );
        assert_eq!(tracker.credited_count(), 1);
    }

    #[test]
    fn tracker_capacity_backpressures() {
        let mut tracker = DepositTracker::with_capacity(FinalityPolicy::new(1), 1);
        let proof = FinalityProof {
            block_number: 1,
            block_hash: Hash::ZERO,
            confirmations: 1,
        };
        let make = |tx: u8| DepositEvent {
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![tx]),
            source_event_index: 0,
            asset: AssetId::new(1),
            amount: Amount::from_raw(1),
            destination_account: AccountId::new(1),
        };
        assert!(tracker.observe(&make(1), proof).unwrap().is_some());
        assert_eq!(
            tracker.observe(&make(2), proof),
            Err(AdapterError::CapacityExceeded)
        );
    }

    #[test]
    fn withdrawal_id_is_deterministic_and_collision_free() {
        let base = WithdrawalRequest {
            account_id: AccountId::new(1),
            destination_chain: ChainId::new(1),
            destination_address: vec![7, 7, 7],
            asset: AssetId::new(2),
            amount: Amount::from_raw(1_000),
            nonce: 3,
            expires_at: 100,
            user_signature: vec![],
        };
        // Deterministic and independent of the signature bytes.
        let mut with_sig = base.clone();
        with_sig.user_signature = vec![1, 2, 3, 4];
        assert_eq!(base.id(), with_sig.id());
        assert_eq!(base.id(), WithdrawalId::of(&base));

        // Distinct inputs -> distinct ids.
        let mut other = base.clone();
        other.nonce = 4;
        assert_ne!(base.id(), other.id());
        let mut other2 = base.clone();
        other2.amount = Amount::from_raw(1_001);
        assert_ne!(base.id(), other2.id());
    }

    #[test]
    fn withdrawal_certificate_certify_and_verify() {
        let req = WithdrawalRequest {
            account_id: AccountId::new(1),
            destination_chain: ChainId::new(1),
            destination_address: vec![7, 7, 7],
            asset: AssetId::new(2),
            amount: Amount::from_raw(1_000),
            nonce: 3,
            expires_at: 100,
            user_signature: vec![],
        };
        let proof = FinalityProof {
            block_number: 9,
            block_hash: Hash::ZERO,
            confirmations: 6,
        };
        let signers = ThresholdSigners::from_seeds(&[[1u8; 32], [2u8; 32]], 2);
        let cert = certify_withdrawal(
            req.id(),
            ChainId::new(1),
            TxId::new(vec![0xEE; 32]),
            AssetId::new(2),
            Amount::from_raw(1_000),
            proof,
            &signers,
            vec![0, 1],
        );
        let policy = FinalityPolicy::new(6);
        cert.verify(&signers.validator_set(), &policy)
            .expect("certificate verifies");

        // Round-trips and a tampered amount is rejected.
        assert_eq!(WithdrawalCertificate::decode(&cert.encode()).unwrap(), cert);
        let mut bad = cert.clone();
        bad.amount = Amount::from_raw(2_000);
        assert_eq!(
            bad.verify(&signers.validator_set(), &policy),
            Err(AdapterError::QuorumNotMet)
        );
    }

    #[test]
    fn withdrawal_status_transitions_only_legal_edges() {
        use WithdrawalStatus::{Confirming, Failed, Finalized, Pending};
        assert!(Pending.can_transition_to(Confirming { confirmations: 1 }));
        assert!(Pending.can_transition_to(Finalized));
        assert!(Confirming { confirmations: 1 }.can_transition_to(Finalized));
        assert!(Confirming { confirmations: 1 }.can_transition_to(Failed));
        // Illegal edges.
        assert!(!Confirming { confirmations: 2 }.can_transition_to(Pending));
        assert_eq!(
            Finalized.advance(Pending),
            Err(AdapterError::IllegalTransition)
        );
        assert_eq!(
            Failed.advance(Finalized),
            Err(AdapterError::IllegalTransition)
        );
        assert_eq!(Finalized.advance(Finalized), Ok(Finalized));
    }

    #[test]
    fn finality_policy_confirmation_status() {
        let p = FinalityPolicy::new(6);
        assert_eq!(p.confirmation_status(0), WithdrawalStatus::Pending);
        assert_eq!(
            p.confirmation_status(3),
            WithdrawalStatus::Confirming { confirmations: 3 }
        );
        assert_eq!(p.confirmation_status(6), WithdrawalStatus::Finalized);
        assert_eq!(p.confirmation_status(9), WithdrawalStatus::Finalized);
    }

    #[test]
    fn property_codec_round_trips() {
        let mut lcg = Lcg::new(0xC0FF_EE00_1234_5678);
        for _ in 0..512 {
            let dc = rand_deposit_cert(&mut lcg);
            assert_eq!(DepositCertificate::decode(&dc.encode()).unwrap(), dc);

            let wr = rand_withdrawal_req(&mut lcg);
            assert_eq!(WithdrawalRequest::decode(&wr.encode()).unwrap(), wr);

            let wc = rand_withdrawal_cert(&mut lcg);
            assert_eq!(WithdrawalCertificate::decode(&wc.encode()).unwrap(), wc);

            let n = rand_txlen(&mut lcg);
            let vd = VerifiedDeposit::new(
                DepositEvent {
                    source_chain: ChainId::new(lcg.next_u64()),
                    source_tx: TxId::new(lcg.bytes(n)),
                    source_event_index: lcg.next_u32(),
                    asset: AssetId::new(lcg.next_u32()),
                    amount: Amount::from_raw(lcg.boundary_i128()),
                    destination_account: AccountId::new(lcg.next_u32()),
                },
                rand_finality(&mut lcg),
            );
            assert_eq!(VerifiedDeposit::decode(&vd.encode()).unwrap(), vd);

            let st = rand_status(&mut lcg);
            assert_eq!(WithdrawalStatus::decode(&st.encode()).unwrap(), st);
        }
    }

    #[test]
    fn fuzz_decoders_never_panic_on_arbitrary_bytes() {
        let mut lcg = Lcg::new(0xDEAD_BEEF_F00D_1337);
        for _ in 0..4096 {
            let len = usize::try_from(lcg.next_u64() % 300).unwrap_or_default();
            let bytes = lcg.bytes(len);
            // None of these may panic; malformed input -> typed error.
            let _ = DepositCertificate::decode(&bytes);
            let _ = WithdrawalRequest::decode(&bytes);
            let _ = WithdrawalCertificate::decode(&bytes);
            let _ = VerifiedDeposit::decode(&bytes);
            let _ = WithdrawalStatus::decode(&bytes);
            let _ = UnsignedTx::decode(&bytes);
            let _ = DepositEvent::decode(&bytes);
        }
    }

    #[test]
    fn fuzz_prefix_truncations_never_panic() {
        let mut lcg = Lcg::new(1);
        let full = rand_deposit_cert(&mut lcg).encode();
        for cut in 0..full.len() {
            let _ = DepositCertificate::decode(&full[..cut]);
        }
    }

    // A trivial in-test adapter proving the trait is object-safe and usable as
    // `dyn ChainAdapter`.
    struct NullAdapter;
    impl ChainAdapter for NullAdapter {
        fn chain_id(&self) -> ChainId {
            ChainId::new(42)
        }
        fn observe_deposits(&self) -> Result<Vec<VerifiedDeposit>, AdapterError> {
            Ok(vec![])
        }
        fn verify_deposit(&self, _tx: &TxId) -> Result<VerifiedDeposit, AdapterError> {
            Err(AdapterError::UnknownTx)
        }
        fn build_withdrawal(&self, _w: &WithdrawalRequest) -> Result<UnsignedTx, AdapterError> {
            Err(AdapterError::UnsupportedAsset)
        }
        fn reserve_withdrawal(
            &mut self,
            _w: &WithdrawalRequest,
        ) -> Result<WithdrawalReservation, AdapterError> {
            Err(AdapterError::UnsupportedAsset)
        }
        fn observe_withdrawal(&self, _tx: &TxId) -> Result<WithdrawalStatus, AdapterError> {
            Err(AdapterError::UnknownTx)
        }
        fn finalize_withdrawal(&mut self, _id: WithdrawalId) -> Result<(), AdapterError> {
            Err(AdapterError::UnknownTx)
        }
        fn release_withdrawal(&mut self, _id: WithdrawalId) -> Result<(), AdapterError> {
            Err(AdapterError::UnknownTx)
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let a: Box<dyn ChainAdapter> = Box::new(NullAdapter);
        assert_eq!(a.chain_id(), ChainId::new(42));
        assert_eq!(a.observe_deposits().unwrap().len(), 0);
        assert_eq!(
            a.verify_deposit(&TxId::new(vec![1])),
            Err(AdapterError::UnknownTx)
        );
    }
}
