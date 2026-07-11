//! `chain-adapter-evm` — EVM chain-commitment primitives plus a feature-gated,
//! deterministic in-memory mock [`ChainAdapter`].
//!
//! The always-compiled surface is the production verification primitive
//! [`EvmCommit`]: it implements [`ChainCommit`] with EVM conventions —
//! secp256k1/keccak256 20-byte addresses, 32-byte keccak transaction hashes, and
//! keccak-256 header/leaf hashing. Deposit finality is proven through
//! [`chain_adapter::verify_finality`] against a hash-linked header chain, never a
//! self-asserted confirmation count.
//!
//! [`MockEvmAdapter`] and the `inject_deposit`/`advance_head` scaffolding are
//! behind the `mock` feature (and the crate's own test build). They are *not*
//! compiled into the production node binary, which depends on this crate without
//! that feature.
#![forbid(unsafe_code)]

use chain_adapter::{BlockHeader, ChainCommit, Codec, DepositEvent};
use crypto::keccak256;
use types::Hash;

#[cfg(any(feature = "mock", test))]
use types::Amount;

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

/// EVM chain-commitment scheme: keccak-256 header and deposit-leaf hashing.
///
/// This is the production primitive used to verify deposit finality. Header
/// hashing binds `(number, parent_hash, inclusion_root)`, so a successor block
/// can only be forged by reproducing the exact keccak digest of its predecessor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvmCommit;

impl ChainCommit for EvmCommit {
    fn header_hash(&self, header: &BlockHeader) -> Hash {
        let mut buf = Vec::with_capacity(8 + 32 + 32);
        buf.extend_from_slice(&header.number.to_be_bytes());
        buf.extend_from_slice(header.parent_hash.as_bytes());
        buf.extend_from_slice(header.inclusion_root.as_bytes());
        Hash::from_bytes(keccak256(&buf))
    }

    fn deposit_leaf(&self, event: &DepositEvent) -> Hash {
        // keccak over the canonical event encoding models a receipt/log digest.
        Hash::from_bytes(keccak256(&event.encode()))
    }
}

/// Deterministic mock EVM transaction hash for a logical transfer.
#[cfg(any(feature = "mock", test))]
#[must_use]
pub fn evm_tx_hash(nonce: u64, to: &[u8], amount: Amount) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + to.len() + 16);
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.extend_from_slice(to);
    buf.extend_from_slice(&amount.raw().to_be_bytes());
    keccak256(&buf)
}

#[cfg(any(feature = "mock", test))]
mod mock {
    use super::EvmCommit;
    use chain_adapter::{
        verify_finality, AdapterError, AssetId, BlockHeader, ChainAdapter, ChainCommit, ChainId,
        DepositEvent, FinalityPolicy, FinalityWitness, InclusionProof, TxId, UnsignedTx,
        VerifiedDeposit, WithdrawalRequest, WithdrawalStatus, Writer, MAX_ADDRESS_LEN,
    };
    use crypto::{merkle_root, MerkleTree};
    use std::collections::{BTreeMap, BTreeSet};
    use types::{Amount, Hash};

    struct MockDeposit {
        event: DepositEvent,
        block_number: u64,
    }

    struct MockWithdrawal {
        confirmations: u32,
        failed: bool,
    }

    /// A deterministic in-memory mock of an EVM chain implementing
    /// [`ChainAdapter`]. Deposits credit only through
    /// [`chain_adapter::verify_finality`] against a real keccak header chain.
    pub struct MockEvmAdapter {
        chain_id: ChainId,
        policy: FinalityPolicy,
        now: u64,
        head: u64,
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
                head: 0,
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

        /// The current mock chain-head height.
        #[must_use]
        pub const fn head(&self) -> u64 {
            self.head
        }

        /// Register `asset` as supported for withdrawals.
        pub fn support_asset(&mut self, asset: AssetId) {
            self.supported_assets.insert(asset);
        }

        /// Set the mock clock used for withdrawal-expiry checks.
        pub fn set_now(&mut self, now: u64) {
            self.now = now;
        }

        /// Inject a deposit event included in `block_number`. The chain head
        /// advances to at least this block, so the deposit starts with one
        /// confirmation (its own block).
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
                },
            );
            self.head = self.head.max(block_number);
        }

        /// Produce `delta` further blocks on top of the current head, deepening
        /// every pending deposit by `delta` confirmations.
        pub fn advance_head(&mut self, delta: u64) {
            self.head = self.head.saturating_add(delta);
        }

        /// Broadcast an unsigned withdrawal, returning the deterministic
        /// destination transaction id.
        pub fn broadcast_withdrawal(&mut self, tx: &UnsignedTx) -> TxId {
            let hash = super::evm_tx_hash(tx.nonce, &tx.to, tx.amount);
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

        /// Keccak deposit leaves for every deposit landed in `block`, in the
        /// deterministic key order used to build the block's inclusion tree.
        fn block_leaves(&self, block: u64) -> Vec<Hash> {
            self.deposits
                .iter()
                .filter(|(_, d)| d.block_number == block)
                .map(|(_, d)| EvmCommit.deposit_leaf(&d.event))
                .collect()
        }

        /// Index of `tx` among the deposits in its block (matches leaf order).
        fn leaf_index_in_block(&self, block: u64, tx: &[u8]) -> Option<usize> {
            self.deposits
                .iter()
                .filter(|(_, d)| d.block_number == block)
                .position(|(k, _)| k.as_slice() == tx)
        }

        /// Assemble the finality witness (hash-linked headers base..head plus the
        /// inclusion proof) for a known deposit `tx`.
        fn finality_witness(&self, tx: &TxId) -> Option<(DepositEvent, FinalityWitness)> {
            let d = self.deposits.get(tx.as_bytes())?;
            let block = d.block_number;
            let leaf_index = self.leaf_index_in_block(block, tx.as_bytes())?;
            let leaves = self.block_leaves(block);
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
            for h in block..=self.head {
                let inclusion_root = merkle_root(&self.block_leaves(h));
                let header = BlockHeader {
                    number: h,
                    parent_hash: parent,
                    inclusion_root,
                };
                parent = EvmCommit.header_hash(&header);
                headers.push(header);
            }
            Some((d.event.clone(), FinalityWitness { headers, inclusion }))
        }
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
            for key in self.deposits.keys() {
                let tx = TxId::new(key.clone());
                let Some((event, witness)) = self.finality_witness(&tx) else {
                    continue;
                };
                match verify_finality(&EvmCommit, &event, &witness, self.policy) {
                    Ok(proof) => out.push(VerifiedDeposit::new(event, proof)),
                    Err(AdapterError::NotFinal { .. }) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(out)
        }

        fn verify_deposit(&self, tx: &TxId) -> Result<VerifiedDeposit, AdapterError> {
            let (event, witness) = self.finality_witness(tx).ok_or(AdapterError::UnknownTx)?;
            let proof = verify_finality(&EvmCommit, &event, &witness, self.policy)?;
            Ok(VerifiedDeposit::new(event, proof))
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
}

#[cfg(any(feature = "mock", test))]
pub use mock::MockEvmAdapter;

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
        assert_eq!(CRATE_NAME, "chain-adapter-evm");
    }

    #[test]
    fn address_derivation_is_20_bytes() {
        let addr = evm_address_from_pubkey(&[7u8; 64]);
        assert_eq!(addr.len(), EVM_ADDRESS_LEN);
    }

    /// Known-answer fixtures pinning the EVM commitment scheme. If the header or
    /// leaf encoding ever changes, these immutable vectors fail — the analog of
    /// conformance against fixed on-chain block/receipt data.
    #[test]
    fn evm_commitment_golden_vectors() {
        let header = BlockHeader {
            number: 0x0102_0304_0506_0708,
            parent_hash: Hash::from_bytes([0x11; 32]),
            inclusion_root: Hash::from_bytes([0x22; 32]),
        };
        assert_eq!(
            EvmCommit.header_hash(&header),
            Hash::from_bytes(GOLDEN_EVM_HEADER_HASH)
        );

        let event = DepositEvent {
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![0xAB; 32]),
            source_event_index: 7,
            asset: AssetId::new(9),
            amount: Amount::from_raw(1_000_000),
            destination_account: AccountId::new(5),
        };
        assert_eq!(
            EvmCommit.deposit_leaf(&event),
            Hash::from_bytes(GOLDEN_EVM_DEPOSIT_LEAF)
        );
    }

    // Frozen from a one-time run; regression anchors for the commitment scheme.
    const GOLDEN_EVM_HEADER_HASH: [u8; 32] = [
        119, 188, 35, 194, 226, 14, 103, 147, 238, 63, 22, 102, 129, 31, 184, 117, 94, 196, 227,
        130, 48, 64, 153, 135, 76, 119, 87, 77, 136, 57, 232, 86,
    ];
    const GOLDEN_EVM_DEPOSIT_LEAF: [u8; 32] = [
        75, 2, 123, 208, 202, 2, 59, 60, 186, 22, 88, 55, 116, 251, 163, 199, 159, 54, 209, 223, 5,
        147, 226, 236, 16, 191, 249, 140, 39, 23, 22, 54,
    ];
}
