//! `chain-adapter-svm` — SVM chain-commitment primitives plus a feature-gated,
//! deterministic in-memory mock [`ChainAdapter`].
//!
//! The always-compiled surface is the production verification primitive
//! [`SvmCommit`]: it implements [`ChainCommit`] with SVM conventions — 32-byte
//! ed25519 public keys as addresses (base58 is only a display encoding), 64-byte
//! transaction signatures as ids, and domain-separated SHA-256 header/leaf
//! hashing (modelling the bank/slot commitment). Deposit finality is proven
//! through [`chain_adapter::verify_finality`] against a hash-linked header chain,
//! never a self-asserted slot-confirmation count.
//!
//! [`MockSvmAdapter`] and the `inject_deposit`/`advance_head` scaffolding are
//! behind the `mock` feature (and the crate's own test build). They are *not*
//! compiled into the production node binary, which depends on this crate without
//! that feature.
#![forbid(unsafe_code)]

use chain_adapter::{BlockHeader, ChainCommit, Codec, DepositEvent};
use crypto::hash_domain;
use types::Hash;

#[cfg(any(feature = "mock", test))]
use types::Amount;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "chain-adapter-svm";

/// Length of an SVM address (ed25519 public key) in bytes.
pub const SVM_ADDRESS_LEN: usize = 32;

/// Domain separators for the SVM commitment scheme.
const DOMAIN_SVM_HEADER: &[u8] = b"dexos.svm.header";
const DOMAIN_SVM_DEPOSIT_LEAF: &[u8] = b"dexos.svm.deposit.leaf";

/// An SVM address is the raw 32-byte ed25519 public key; base58 is a display
/// concern handled elsewhere.
#[must_use]
pub fn svm_address_from_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    *pubkey
}

/// SVM chain-commitment scheme: domain-separated SHA-256 header and
/// deposit-leaf hashing.
///
/// This is the production primitive used to verify deposit finality. Header
/// hashing binds `(number, parent_hash, inclusion_root)`, so a successor slot
/// can only be forged by reproducing the exact digest of its predecessor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SvmCommit;

impl ChainCommit for SvmCommit {
    fn header_hash(&self, header: &BlockHeader) -> Hash {
        hash_domain(DOMAIN_SVM_HEADER, &header.encode())
    }

    fn deposit_leaf(&self, event: &DepositEvent) -> Hash {
        hash_domain(DOMAIN_SVM_DEPOSIT_LEAF, &event.encode())
    }
}

/// Deterministic mock SVM 64-byte transaction signature for a logical transfer.
#[cfg(any(feature = "mock", test))]
#[must_use]
pub fn svm_tx_signature(nonce: u64, to: &[u8], amount: Amount) -> [u8; 64] {
    const DOMAIN_SIG_HI: &[u8] = b"dexos.mock.svm.sig.hi";
    const DOMAIN_SIG_LO: &[u8] = b"dexos.mock.svm.sig.lo";
    let mut body = Vec::with_capacity(8 + to.len() + 16);
    body.extend_from_slice(&nonce.to_be_bytes());
    body.extend_from_slice(to);
    body.extend_from_slice(&amount.raw().to_be_bytes());
    let hi = hash_domain(DOMAIN_SIG_HI, &body);
    let lo = hash_domain(DOMAIN_SIG_LO, &body);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(hi.as_bytes());
    sig[32..].copy_from_slice(lo.as_bytes());
    sig
}

#[cfg(any(feature = "mock", test))]
mod mock {
    use super::SvmCommit;
    use chain_adapter::{
        verify_finality, verify_withdrawal_authorization, AdapterError, AssetId, BlockHeader,
        ChainAdapter, ChainCommit, ChainId, DepositEvent, FinalityPolicy, FinalityWitness,
        InclusionProof, TxId, UnsignedTx, VerifiedDeposit, WalletBinding, WithdrawalId,
        WithdrawalLedger, WithdrawalRequest, WithdrawalReservation, WithdrawalStatus, Writer,
    };
    use crypto::{merkle_root, MerkleTree};
    use std::collections::{BTreeMap, BTreeSet};
    use types::{Amount, Hash};

    struct MockDeposit {
        event: DepositEvent,
        slot: u64,
    }

    struct MockWithdrawal {
        confirmations: u32,
        failed: bool,
    }

    /// A deterministic in-memory mock of an SVM chain implementing
    /// [`ChainAdapter`]. Deposits credit only through
    /// [`chain_adapter::verify_finality`] against a real SHA-256 header chain.
    pub struct MockSvmAdapter {
        chain_id: ChainId,
        policy: FinalityPolicy,
        now: u64,
        head: u64,
        supported_assets: BTreeSet<AssetId>,
        deposits: BTreeMap<Vec<u8>, MockDeposit>,
        withdrawals: BTreeMap<Vec<u8>, MockWithdrawal>,
        bindings: BTreeMap<u32, WalletBinding>,
        ledger: WithdrawalLedger,
    }

    impl MockSvmAdapter {
        /// Create an empty adapter for `chain_id` under `policy` (slot commitment).
        #[must_use]
        pub fn new(chain_id: ChainId, policy: FinalityPolicy) -> Self {
            Self {
                chain_id,
                policy,
                now: 0,
                head: 0,
                supported_assets: BTreeSet::new(),
                deposits: BTreeMap::new(),
                withdrawals: BTreeMap::new(),
                bindings: BTreeMap::new(),
                ledger: WithdrawalLedger::new(),
            }
        }

        /// The finality (slot-commitment) policy in force.
        #[must_use]
        pub const fn policy(&self) -> FinalityPolicy {
            self.policy
        }

        /// The current mock chain-head slot.
        #[must_use]
        pub const fn head(&self) -> u64 {
            self.head
        }

        /// Register `asset` as supported for withdrawals.
        pub fn support_asset(&mut self, asset: AssetId) {
            self.supported_assets.insert(asset);
        }

        /// Bind `binding.account` to an authorized SVM (ed25519) wallet. A
        /// withdrawal is only buildable/reservable if its account has a binding
        /// and its user signature verifies under that wallet.
        pub fn bind_wallet(&mut self, binding: WalletBinding) {
            self.bindings.insert(binding.account.get(), binding);
        }

        /// Set the mock clock used for withdrawal-expiry checks.
        pub fn set_now(&mut self, now: u64) {
            self.now = now;
        }

        /// Inject a deposit event landed in `slot`. The chain head advances to
        /// at least this slot, so the deposit starts with one confirmation.
        ///
        /// The event's `source_chain` is normalized to this adapter's chain.
        pub fn inject_deposit(&mut self, mut event: DepositEvent, slot: u64) {
            event.source_chain = self.chain_id;
            let key = event.source_tx.as_bytes().to_vec();
            self.deposits.insert(key, MockDeposit { event, slot });
            self.head = self.head.max(slot);
        }

        /// Produce `delta` further slots on top of the current head, deepening
        /// every pending deposit by `delta` confirmations.
        pub fn advance_head(&mut self, delta: u64) {
            self.head = self.head.saturating_add(delta);
        }

        /// Broadcast a reserved withdrawal, returning the durable 64-byte
        /// transaction signature as its id.
        ///
        /// Idempotent and reservation-gated: the withdrawal must have been
        /// reserved via [`ChainAdapter::reserve_withdrawal`] first, and a
        /// crash/retry returns the same [`TxId`] without producing a second
        /// broadcast.
        ///
        /// # Errors
        /// - [`AdapterError::UnknownTx`] if the withdrawal was never reserved.
        /// - [`AdapterError::IllegalTransition`] if it is already finalized or a
        ///   conflicting identity is presented.
        pub fn broadcast_withdrawal(&mut self, tx: &UnsignedTx) -> Result<TxId, AdapterError> {
            let sig = super::svm_tx_signature(tx.nonce, &tx.to, tx.amount);
            let txid = self
                .ledger
                .record_broadcast(tx.withdrawal_id, TxId::new(sig.to_vec()))?;
            // Track the broadcast tx for observation exactly once.
            self.withdrawals
                .entry(txid.as_bytes().to_vec())
                .or_insert(MockWithdrawal {
                    confirmations: 0,
                    failed: false,
                });
            Ok(txid)
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

        /// Validate a withdrawal request without side effects: positive amount,
        /// supported asset, unexpired, and an authorized bound-wallet signature
        /// under this chain's scheme (which also enforces the destination chain
        /// and exact address format).
        fn validate(&self, w: &WithdrawalRequest) -> Result<(), AdapterError> {
            if w.amount.raw() <= 0 {
                return Err(AdapterError::InvalidRequest);
            }
            if !self.supported_assets.contains(&w.asset) {
                return Err(AdapterError::UnsupportedAsset);
            }
            if w.expires_at <= self.now {
                return Err(AdapterError::Expired);
            }
            let binding = self
                .bindings
                .get(&w.account_id.get())
                .ok_or(AdapterError::Unauthorized)?;
            verify_withdrawal_authorization(w, self.chain_id, binding)
        }

        /// SHA-256 deposit leaves for every deposit landed in `slot`, in the
        /// deterministic key order used to build the slot's inclusion tree.
        fn slot_leaves(&self, slot: u64) -> Vec<Hash> {
            self.deposits
                .iter()
                .filter(|(_, d)| d.slot == slot)
                .map(|(_, d)| SvmCommit.deposit_leaf(&d.event))
                .collect()
        }

        /// Index of `tx` among the deposits in its slot (matches leaf order).
        fn leaf_index_in_slot(&self, slot: u64, tx: &[u8]) -> Option<usize> {
            self.deposits
                .iter()
                .filter(|(_, d)| d.slot == slot)
                .position(|(k, _)| k.as_slice() == tx)
        }

        /// Assemble the finality witness (hash-linked headers base..head plus the
        /// inclusion proof) for a known deposit `tx`.
        fn finality_witness(&self, tx: &TxId) -> Option<(DepositEvent, FinalityWitness)> {
            let d = self.deposits.get(tx.as_bytes())?;
            let slot = d.slot;
            let leaf_index = self.leaf_index_in_slot(slot, tx.as_bytes())?;
            let leaves = self.slot_leaves(slot);
            let mut tree = MerkleTree::new(leaves.len().max(1));
            for (i, l) in leaves.iter().enumerate() {
                tree.set(i, *l).ok()?;
            }
            let siblings = tree.proof(leaf_index).ok()?;
            let inclusion = InclusionProof {
                leaf_index: u32::try_from(leaf_index).ok()?,
                siblings,
            };

            let mut headers = Vec::new();
            let mut parent = Hash::ZERO;
            for h in slot..=self.head {
                let inclusion_root = merkle_root(&self.slot_leaves(h));
                let header = BlockHeader {
                    number: h,
                    parent_hash: parent,
                    inclusion_root,
                };
                parent = SvmCommit.header_hash(&header);
                headers.push(header);
            }
            Some((d.event.clone(), FinalityWitness { headers, inclusion }))
        }
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
            for key in self.deposits.keys() {
                let tx = TxId::new(key.clone());
                let Some((event, witness)) = self.finality_witness(&tx) else {
                    continue;
                };
                match verify_finality(&SvmCommit, &event, &witness, self.policy) {
                    Ok(proof) => out.push(VerifiedDeposit::new(event, proof)),
                    Err(AdapterError::NotFinal { .. }) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(out)
        }

        fn verify_deposit(&self, tx: &TxId) -> Result<VerifiedDeposit, AdapterError> {
            let (event, witness) = self.finality_witness(tx).ok_or(AdapterError::UnknownTx)?;
            let proof = verify_finality(&SvmCommit, &event, &witness, self.policy)?;
            Ok(VerifiedDeposit::new(event, proof))
        }

        fn build_withdrawal(&self, w: &WithdrawalRequest) -> Result<UnsignedTx, AdapterError> {
            self.validate(w)?;
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

        fn reserve_withdrawal(
            &mut self,
            w: &WithdrawalRequest,
        ) -> Result<WithdrawalReservation, AdapterError> {
            self.validate(w)?;
            self.ledger.reserve(w)
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

        fn finalize_withdrawal(&mut self, id: WithdrawalId) -> Result<(), AdapterError> {
            self.ledger.finalize(id)
        }

        fn release_withdrawal(&mut self, id: WithdrawalId) -> Result<(), AdapterError> {
            self.ledger.release(id)
        }
    }
}

#[cfg(any(feature = "mock", test))]
pub use mock::MockSvmAdapter;

#[cfg(test)]
#[path = "mock_tests.rs"]
mod mock_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use chain_adapter::{AssetId, ChainId, TxId};
    use types::AccountId;

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

    /// Known-answer fixtures pinning the SVM commitment scheme. Immutable
    /// regression anchors — the analog of conformance against fixed slot data.
    #[test]
    fn svm_commitment_golden_vectors() {
        let header = BlockHeader {
            number: 0x0102_0304_0506_0708,
            parent_hash: Hash::from_bytes([0x11; 32]),
            inclusion_root: Hash::from_bytes([0x22; 32]),
        };
        assert_eq!(
            SvmCommit.header_hash(&header),
            Hash::from_bytes(GOLDEN_SVM_HEADER_HASH)
        );

        let event = DepositEvent {
            source_chain: ChainId::new(900),
            source_tx: TxId::new(vec![0xCD; 64]),
            source_event_index: 3,
            asset: AssetId::new(3),
            amount: Amount::from_raw(2_000_000),
            destination_account: AccountId::new(8),
        };
        assert_eq!(
            SvmCommit.deposit_leaf(&event),
            Hash::from_bytes(GOLDEN_SVM_DEPOSIT_LEAF)
        );
    }

    // Frozen from a one-time run; regression anchors for the commitment scheme.
    const GOLDEN_SVM_HEADER_HASH: [u8; 32] = [
        174, 228, 209, 189, 108, 218, 84, 150, 218, 101, 156, 241, 42, 108, 147, 156, 125, 28, 1,
        94, 151, 131, 252, 165, 102, 164, 172, 163, 193, 221, 11, 35,
    ];
    const GOLDEN_SVM_DEPOSIT_LEAF: [u8; 32] = [
        236, 213, 191, 117, 243, 222, 95, 177, 2, 120, 84, 125, 56, 231, 97, 200, 7, 187, 101, 91,
        83, 32, 162, 219, 187, 100, 35, 194, 61, 115, 28, 178,
    ];
}
