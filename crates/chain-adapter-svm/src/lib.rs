//! `chain-adapter-svm` — a deterministic, self-contained mock SVM
//! [`ChainAdapter`]. It models an in-memory chain (a map of transaction
//! signatures to deposit events plus a set of broadcast withdrawals with slot
//! confirmation counters) and follows SVM conventions: 32-byte ed25519 public
//! keys as addresses (base58 is only a display encoding) and 64-byte transaction
//! signatures as ids.
//!
//! There is no networking or RPC: deposits are injected and slot confirmations
//! are advanced explicitly, so every observation is reproducible.
#![forbid(unsafe_code)]

use chain_adapter::{
    AdapterError, AssetId, ChainAdapter, ChainId, DepositEvent, FinalityPolicy, FinalityProof,
    TxId, UnsignedTx, VerifiedDeposit, WithdrawalRequest, WithdrawalStatus, Writer,
    MAX_ADDRESS_LEN,
};
use crypto::hash_domain;
use std::collections::{BTreeMap, BTreeSet};
use types::{Amount, Hash};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "chain-adapter-svm";

/// Length of an SVM address (ed25519 public key) in bytes.
pub const SVM_ADDRESS_LEN: usize = 32;

/// Domain separators for deterministic mock SVM hashing.
const DOMAIN_SVM_BLOCK: &[u8] = b"dexos.mock.svm.block";
const DOMAIN_SVM_SIG_HI: &[u8] = b"dexos.mock.svm.sig.hi";
const DOMAIN_SVM_SIG_LO: &[u8] = b"dexos.mock.svm.sig.lo";

/// An SVM address is the raw 32-byte ed25519 public key; base58 is a display
/// concern handled elsewhere.
#[must_use]
pub fn svm_address_from_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    *pubkey
}

/// Deterministic mock SVM 64-byte transaction signature for a logical transfer.
#[must_use]
pub fn svm_tx_signature(nonce: u64, to: &[u8], amount: Amount) -> [u8; 64] {
    let mut body = Vec::with_capacity(8 + to.len() + 16);
    body.extend_from_slice(&nonce.to_be_bytes());
    body.extend_from_slice(to);
    body.extend_from_slice(&amount.raw().to_be_bytes());
    let hi = hash_domain(DOMAIN_SVM_SIG_HI, &body);
    let lo = hash_domain(DOMAIN_SVM_SIG_LO, &body);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(hi.as_bytes());
    sig[32..].copy_from_slice(lo.as_bytes());
    sig
}

struct MockDeposit {
    event: DepositEvent,
    slot: u64,
    confirmations: u32,
}

struct MockWithdrawal {
    confirmations: u32,
    failed: bool,
}

/// A deterministic in-memory mock of an SVM chain implementing [`ChainAdapter`].
pub struct MockSvmAdapter {
    chain_id: ChainId,
    policy: FinalityPolicy,
    now: u64,
    supported_assets: BTreeSet<AssetId>,
    deposits: BTreeMap<Vec<u8>, MockDeposit>,
    withdrawals: BTreeMap<Vec<u8>, MockWithdrawal>,
    consumed_nonces: BTreeSet<(u32, u64)>,
}

impl MockSvmAdapter {
    /// Create an empty adapter for `chain_id` under `policy` (slot commitment).
    #[must_use]
    pub fn new(chain_id: ChainId, policy: FinalityPolicy) -> Self {
        Self {
            chain_id,
            policy,
            now: 0,
            supported_assets: BTreeSet::new(),
            deposits: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            consumed_nonces: BTreeSet::new(),
        }
    }

    /// The finality (slot-commitment) policy in force.
    #[must_use]
    pub const fn policy(&self) -> FinalityPolicy {
        self.policy
    }

    /// Register `asset` as supported for withdrawals.
    pub fn support_asset(&mut self, asset: AssetId) {
        self.supported_assets.insert(asset);
    }

    /// Set the mock clock used for withdrawal-expiry checks.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// Inject a deposit event landed in `slot` with zero confirmations.
    ///
    /// The event's `source_chain` is normalized to this adapter's chain.
    pub fn inject_deposit(&mut self, mut event: DepositEvent, slot: u64) {
        event.source_chain = self.chain_id;
        let key = event.source_tx.as_bytes().to_vec();
        self.deposits.insert(
            key,
            MockDeposit {
                event,
                slot,
                confirmations: 0,
            },
        );
    }

    /// Advance the slot-confirmation count of an injected deposit.
    pub fn advance_deposit(&mut self, tx: &TxId, delta: u32) {
        if let Some(d) = self.deposits.get_mut(tx.as_bytes()) {
            d.confirmations = d.confirmations.saturating_add(delta);
        }
    }

    /// Broadcast an unsigned withdrawal, returning the deterministic 64-byte
    /// transaction signature as its id.
    pub fn broadcast_withdrawal(&mut self, tx: &UnsignedTx) -> TxId {
        let sig = svm_tx_signature(tx.nonce, &tx.to, tx.amount);
        let key = sig.to_vec();
        self.withdrawals.insert(
            key.clone(),
            MockWithdrawal {
                confirmations: 0,
                failed: false,
            },
        );
        TxId::new(key)
    }

    /// Advance the slot-confirmation count of a broadcast withdrawal.
    pub fn advance_withdrawal(&mut self, tx: &TxId, delta: u32) {
        if let Some(w) = self.withdrawals.get_mut(tx.as_bytes()) {
            w.confirmations = w.confirmations.saturating_add(delta);
        }
    }

    /// Mark a broadcast withdrawal as failed on-chain.
    pub fn fail_withdrawal(&mut self, tx: &TxId) {
        if let Some(w) = self.withdrawals.get_mut(tx.as_bytes()) {
            w.failed = true;
        }
    }

    /// Record a `(account, nonce)` as already used.
    pub fn consume_nonce(&mut self, account: u32, nonce: u64) {
        self.consumed_nonces.insert((account, nonce));
    }

    fn deposit_proof(&self, d: &MockDeposit) -> FinalityProof {
        FinalityProof {
            block_number: d.slot,
            block_hash: svm_block_hash(self.chain_id, d.event.source_tx.as_bytes(), d.slot),
            confirmations: d.confirmations,
        }
    }
}

fn svm_block_hash(chain: ChainId, tx: &[u8], slot: u64) -> Hash {
    let mut buf = Vec::with_capacity(8 + tx.len() + 8);
    buf.extend_from_slice(&chain.get().to_be_bytes());
    buf.extend_from_slice(tx);
    buf.extend_from_slice(&slot.to_be_bytes());
    hash_domain(DOMAIN_SVM_BLOCK, &buf)
}

/// Deterministic SPL-transfer-like instruction data for a withdrawal payload.
fn svm_transfer_payload(to: &[u8], asset: AssetId, amount: Amount) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(3); // mock SPL-token `Transfer` instruction index
    w.bytes(to);
    w.u32(asset.get());
    w.i128(amount.raw());
    w.into_bytes()
}

impl ChainAdapter for MockSvmAdapter {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn observe_deposits(&self) -> Result<Vec<VerifiedDeposit>, AdapterError> {
        let mut out = Vec::new();
        for d in self.deposits.values() {
            if self.policy.is_final(d.confirmations) {
                out.push(VerifiedDeposit::new(d.event.clone(), self.deposit_proof(d)));
            }
        }
        Ok(out)
    }

    fn verify_deposit(&self, tx: &TxId) -> Result<VerifiedDeposit, AdapterError> {
        let d = self
            .deposits
            .get(tx.as_bytes())
            .ok_or(AdapterError::UnknownTx)?;
        if !self.policy.is_final(d.confirmations) {
            return Err(AdapterError::NotFinal {
                have: d.confirmations,
                need: self.policy.min_confirmations(),
            });
        }
        Ok(VerifiedDeposit::new(d.event.clone(), self.deposit_proof(d)))
    }

    fn build_withdrawal(&self, w: &WithdrawalRequest) -> Result<UnsignedTx, AdapterError> {
        if w.amount.raw() <= 0 {
            return Err(AdapterError::InvalidRequest);
        }
        if w.destination_address.is_empty() || w.destination_address.len() > MAX_ADDRESS_LEN {
            return Err(AdapterError::InvalidRequest);
        }
        if !self.supported_assets.contains(&w.asset) {
            return Err(AdapterError::UnsupportedAsset);
        }
        if w.expires_at <= self.now {
            return Err(AdapterError::Expired);
        }
        if self
            .consumed_nonces
            .contains(&(w.account_id.get(), w.nonce))
        {
            return Err(AdapterError::ReplayedNonce);
        }
        Ok(UnsignedTx {
            destination_chain: w.destination_chain,
            withdrawal_id: w.id(),
            to: w.destination_address.clone(),
            asset: w.asset,
            amount: w.amount,
            nonce: w.nonce,
            payload: svm_transfer_payload(&w.destination_address, w.asset, w.amount),
        })
    }

    fn observe_withdrawal(&self, tx: &TxId) -> Result<WithdrawalStatus, AdapterError> {
        let w = self
            .withdrawals
            .get(tx.as_bytes())
            .ok_or(AdapterError::UnknownTx)?;
        if w.failed {
            return Ok(WithdrawalStatus::Failed);
        }
        Ok(self.policy.confirmation_status(w.confirmations))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_adapter::{certify_deposit, run_conformance, ConformanceFixture, DepositTracker};
    use crypto::ThresholdSigners;
    use types::AccountId;

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
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "chain-adapter-svm");
    }

    #[test]
    fn address_and_signature_conventions() {
        assert_eq!(svm_address_from_pubkey(&[5u8; 32]).len(), SVM_ADDRESS_LEN);
        assert_eq!(
            svm_tx_signature(1, &[0xCD; 32], Amount::from_raw(1)).len(),
            64
        );
    }

    #[test]
    fn spl_deposit_reaches_commitment_and_certifies() {
        let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(32));
        let ev = sample_deposit(1, 2_000_000);
        let tx = ev.source_tx.clone();
        a.inject_deposit(ev, 5_000);

        a.advance_deposit(&tx, 16);
        assert!(matches!(
            a.verify_deposit(&tx),
            Err(AdapterError::NotFinal { have: 16, need: 32 })
        ));
        assert!(a.observe_deposits().unwrap().is_empty());

        a.advance_deposit(&tx, 16);
        let vd = a.verify_deposit(&tx).unwrap();
        assert_eq!(vd.finality_proof.confirmations, 32);
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
    fn deterministic_replay_of_event_log() {
        let build = || {
            let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(32));
            for (tx, amt, conf) in [(1u8, 100i128, 32u32), (2, 200, 32), (3, 300, 8)] {
                let ev = sample_deposit(tx, amt);
                let id = ev.source_tx.clone();
                a.inject_deposit(ev, u64::from(tx) * 1000);
                a.advance_deposit(&id, conf);
            }
            a.observe_deposits().unwrap()
        };
        assert_eq!(build(), build());
        assert_eq!(build().len(), 2);
    }

    #[test]
    fn conformance_suite_passes() {
        let mut a = MockSvmAdapter::new(ChainId::new(900), FinalityPolicy::new(2));
        a.support_asset(AssetId::new(3));
        a.set_now(0);
        let ev = sample_deposit(9, 500);
        let tx = ev.source_tx.clone();
        a.inject_deposit(ev, 1);
        a.advance_deposit(&tx, 2);

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
}
