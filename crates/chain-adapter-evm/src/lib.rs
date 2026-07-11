//! `chain-adapter-evm` — a deterministic, self-contained mock EVM
//! [`ChainAdapter`]. It models an in-memory chain (a map of transactions to
//! deposit events plus a set of broadcast withdrawals with confirmation
//! counters) and follows EVM conventions: secp256k1/keccak256 20-byte addresses
//! and 32-byte keccak transaction hashes.
//!
//! There is no networking or RPC: deposits are injected and confirmations are
//! advanced explicitly, so every observation is reproducible.
#![forbid(unsafe_code)]

use chain_adapter::{
    AdapterError, AssetId, ChainAdapter, ChainId, DepositEvent, FinalityPolicy, FinalityProof,
    TxId, UnsignedTx, VerifiedDeposit, WithdrawalRequest, WithdrawalStatus, Writer,
    MAX_ADDRESS_LEN,
};
use crypto::keccak256;
use std::collections::{BTreeMap, BTreeSet};
use types::{Amount, Hash};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "chain-adapter-evm";

/// Length of an EVM address in bytes.
pub const EVM_ADDRESS_LEN: usize = 20;

/// Derive a 20-byte EVM address from a 64-byte uncompressed secp256k1 public key
/// (keccak256 of the key, low 20 bytes) — the standard Ethereum convention.
#[must_use]
pub fn evm_address_from_pubkey(pubkey: &[u8; 64]) -> [u8; 20] {
    let digest = keccak256(pubkey);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..32]);
    addr
}

/// Deterministic mock EVM transaction hash for a logical transfer.
#[must_use]
pub fn evm_tx_hash(nonce: u64, to: &[u8], amount: Amount) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + to.len() + 16);
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.extend_from_slice(to);
    buf.extend_from_slice(&amount.raw().to_be_bytes());
    keccak256(&buf)
}

struct MockDeposit {
    event: DepositEvent,
    block_number: u64,
    confirmations: u32,
}

struct MockWithdrawal {
    confirmations: u32,
    failed: bool,
}

/// A deterministic in-memory mock of an EVM chain implementing [`ChainAdapter`].
pub struct MockEvmAdapter {
    chain_id: ChainId,
    policy: FinalityPolicy,
    now: u64,
    supported_assets: BTreeSet<AssetId>,
    deposits: BTreeMap<Vec<u8>, MockDeposit>,
    withdrawals: BTreeMap<Vec<u8>, MockWithdrawal>,
    consumed_nonces: BTreeSet<(u32, u64)>,
}

impl MockEvmAdapter {
    /// Create an empty adapter for `chain_id` under `policy`.
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

    /// The finality policy in force.
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

    /// Inject a deposit event included in `block_number` with zero confirmations.
    ///
    /// The event's `source_chain` is normalized to this adapter's chain.
    pub fn inject_deposit(&mut self, mut event: DepositEvent, block_number: u64) {
        event.source_chain = self.chain_id;
        let key = event.source_tx.as_bytes().to_vec();
        self.deposits.insert(
            key,
            MockDeposit {
                event,
                block_number,
                confirmations: 0,
            },
        );
    }

    /// Advance the confirmation count of an injected deposit.
    pub fn advance_deposit(&mut self, tx: &TxId, delta: u32) {
        if let Some(d) = self.deposits.get_mut(tx.as_bytes()) {
            d.confirmations = d.confirmations.saturating_add(delta);
        }
    }

    /// Broadcast an unsigned withdrawal, returning the deterministic destination
    /// transaction id.
    pub fn broadcast_withdrawal(&mut self, tx: &UnsignedTx) -> TxId {
        let hash = evm_tx_hash(tx.nonce, &tx.to, tx.amount);
        let key = hash.to_vec();
        self.withdrawals.insert(
            key.clone(),
            MockWithdrawal {
                confirmations: 0,
                failed: false,
            },
        );
        TxId::new(key)
    }

    /// Advance the confirmation count of a broadcast withdrawal.
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

    /// Record a `(account, nonce)` as already used (e.g. by prior settlement).
    pub fn consume_nonce(&mut self, account: u32, nonce: u64) {
        self.consumed_nonces.insert((account, nonce));
    }

    fn deposit_proof(&self, d: &MockDeposit) -> FinalityProof {
        FinalityProof {
            block_number: d.block_number,
            block_hash: evm_block_hash(self.chain_id, d.event.source_tx.as_bytes(), d.block_number),
            confirmations: d.confirmations,
        }
    }
}

fn evm_block_hash(chain: ChainId, tx: &[u8], block_number: u64) -> Hash {
    let mut buf = Vec::with_capacity(8 + tx.len() + 8);
    buf.extend_from_slice(&chain.get().to_be_bytes());
    buf.extend_from_slice(tx);
    buf.extend_from_slice(&block_number.to_be_bytes());
    Hash::from_bytes(keccak256(&buf))
}

/// Deterministic ERC-20-transfer-like calldata for a withdrawal payload.
fn evm_transfer_payload(to: &[u8], asset: AssetId, amount: Amount) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(0xa905_9cbb); // mock `transfer(address,uint256)` selector
    w.bytes(to);
    w.u32(asset.get());
    w.i128(amount.raw());
    w.into_bytes()
}

impl ChainAdapter for MockEvmAdapter {
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
            payload: evm_transfer_payload(&w.destination_address, w.asset, w.amount),
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
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![tx; 32]),
            source_event_index: 0,
            asset: AssetId::new(7),
            amount: Amount::from_raw(amount),
            destination_account: AccountId::new(5),
        }
    }

    fn sample_withdrawal() -> WithdrawalRequest {
        WithdrawalRequest {
            account_id: AccountId::new(5),
            destination_chain: ChainId::new(1),
            destination_address: vec![0xAB; EVM_ADDRESS_LEN],
            asset: AssetId::new(7),
            amount: Amount::from_raw(1_000_000),
            nonce: 1,
            expires_at: 1_000,
            user_signature: vec![9; 65],
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "chain-adapter-evm");
    }

    #[test]
    fn address_derivation_is_20_bytes() {
        let addr = evm_address_from_pubkey(&[7u8; 64]);
        assert_eq!(addr.len(), EVM_ADDRESS_LEN);
    }

    #[test]
    fn erc20_deposit_reaches_finality_and_certifies() {
        let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(12));
        let ev = sample_deposit(1, 1_000_000);
        let tx = ev.source_tx.clone();
        a.inject_deposit(ev, 100);

        // Below finality: withheld.
        a.advance_deposit(&tx, 5);
        assert!(matches!(
            a.verify_deposit(&tx),
            Err(AdapterError::NotFinal { have: 5, need: 12 })
        ));
        assert!(a.observe_deposits().unwrap().is_empty());

        // Reach finality.
        a.advance_deposit(&tx, 7);
        let vd = a.verify_deposit(&tx).unwrap();
        assert_eq!(vd.finality_proof.confirmations, 12);
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
    fn withdrawal_reaches_finalized_after_confirmations() {
        let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
        a.support_asset(AssetId::new(7));
        a.set_now(10);
        let req = sample_withdrawal();

        let unsigned = a.build_withdrawal(&req).unwrap();
        // Deterministic build.
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
        a.advance_withdrawal(&tx, 2);
        assert_eq!(
            a.observe_withdrawal(&tx).unwrap(),
            WithdrawalStatus::Finalized
        );
    }

    #[test]
    fn withdrawal_rejections() {
        let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(3));
        a.set_now(10);
        let req = sample_withdrawal();

        // Unsupported asset (none registered yet).
        assert_eq!(
            a.build_withdrawal(&req),
            Err(AdapterError::UnsupportedAsset)
        );
        a.support_asset(AssetId::new(7));

        // Expired.
        let mut expired = req.clone();
        expired.expires_at = 5;
        assert_eq!(a.build_withdrawal(&expired), Err(AdapterError::Expired));

        // Replayed nonce.
        a.consume_nonce(req.account_id.get(), req.nonce);
        assert_eq!(a.build_withdrawal(&req), Err(AdapterError::ReplayedNonce));

        // Empty destination address.
        let mut bad = sample_withdrawal();
        bad.nonce = 2;
        bad.destination_address = vec![];
        assert_eq!(a.build_withdrawal(&bad), Err(AdapterError::InvalidRequest));
    }

    #[test]
    fn deterministic_replay_of_event_log() {
        let build = || {
            let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(6));
            for (tx, amt, conf) in [(1u8, 100i128, 6u32), (2, 200, 6), (3, 300, 3)] {
                let ev = sample_deposit(tx, amt);
                let id = ev.source_tx.clone();
                a.inject_deposit(ev, u64::from(tx));
                a.advance_deposit(&id, conf);
            }
            a.observe_deposits().unwrap()
        };
        assert_eq!(build(), build());
        // tx 3 (3 confs) is withheld; only tx1 and tx2 are final.
        assert_eq!(build().len(), 2);
    }

    #[test]
    fn conformance_suite_passes() {
        let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(2));
        a.support_asset(AssetId::new(7));
        a.set_now(0);
        let ev = sample_deposit(9, 500);
        let tx = ev.source_tx.clone();
        a.inject_deposit(ev, 1);
        a.advance_deposit(&tx, 2);

        let fixture = ConformanceFixture {
            adapter: &a,
            finalized_deposit_tx: tx,
            unknown_tx: TxId::new(vec![0xFF; 32]),
            valid_withdrawal: sample_withdrawal(),
        };
        run_conformance(&fixture).expect("adapter conforms");
    }

    #[test]
    fn property_random_confirmation_sequences() {
        let mut lcg = Lcg::new(0xE711_5EED_0000_0001);
        for _ in 0..200 {
            let min = 1 + lcg.small_u32();
            let mut a = MockEvmAdapter::new(ChainId::new(1), FinalityPolicy::new(min));
            a.support_asset(AssetId::new(7));
            a.set_now(0);
            let unsigned = a.build_withdrawal(&sample_withdrawal()).unwrap();
            let tx = a.broadcast_withdrawal(&unsigned);

            let mut total = 0u32;
            let mut finalized = false;
            for _ in 0..8 {
                let delta = lcg.small_u32();
                a.advance_withdrawal(&tx, delta);
                total = total.saturating_add(delta);
                let status = a.observe_withdrawal(&tx).unwrap();
                match status {
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
