//! Structural finality verification for chain deposits.
//!
//! The custody edge must never credit a deposit on an observer-supplied
//! confirmation counter — any observer can claim an arbitrary integer. Instead,
//! confirmation depth is *derived* from a contiguous, hash-linked run of block
//! headers, and the deposit itself must be proven included in the base block's
//! commitment root via a Merkle inclusion proof. Producing a [`FinalityProof`]
//! this way requires reproducing every block hash on the path from the including
//! block to the chain head, so an observer cannot simply assert a larger number.
//!
//! Header *validity* under a chain's consensus rules (PoW/PoS/stake weight) is
//! attested separately by the observer quorum ([`crate::DepositCertificate`]);
//! this module supplies the structural half of that defense in depth. The
//! per-chain hashing rules live behind the [`ChainCommit`] trait, implemented by
//! `chain-adapter-evm` (keccak-256) and `chain-adapter-svm` (domain SHA-256).

use crate::codec::{Codec, CodecError, Reader, Writer};
use crate::deposit::{DepositEvent, FinalityProof};
use crate::error::AdapterError;
use crate::policy::FinalityPolicy;
use crypto::verify_proof;
use serde::{Deserialize, Serialize};
use types::Hash;

/// Upper bound on the number of headers a single witness may carry, guarding
/// allocation on decode. A confirmation policy never sensibly approaches this.
pub const MAX_WITNESS_HEADERS: usize = 4096;

/// Upper bound on inclusion-proof depth: a binary tree over `2^64` leaves needs
/// at most 64 sibling hashes.
pub const MAX_INCLUSION_DEPTH: usize = 64;

/// A minimal, chain-agnostic block header: exactly the fields needed to
/// hash-link a chain and commit to the deposits it includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height (EVM block number / SVM slot).
    pub number: u64,
    /// Hash of the parent header under the chain's [`ChainCommit`] rules.
    pub parent_hash: Hash,
    /// Commitment to the deposit leaves included at this height (an EVM
    /// receipts/log root, or an SVM bank-accumulator root).
    pub inclusion_root: Hash,
}

impl Codec for BlockHeader {
    fn write(&self, w: &mut Writer) {
        w.u64(self.number);
        self.parent_hash.write(w);
        self.inclusion_root.write(w);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            number: r.u64()?,
            parent_hash: Hash::read(r)?,
            inclusion_root: Hash::read(r)?,
        })
    }
}

/// A per-chain commitment scheme: how block headers are hashed into a chain and
/// how a deposit event is hashed into a leaf under a block's `inclusion_root`.
///
/// EVM hashes with keccak-256 (matching Ethereum block/receipt encoding); SVM
/// uses domain-separated SHA-256 (matching its bank commitment). Interior nodes
/// of the inclusion tree always use the shared [`crypto::hash_node`], so the
/// same [`crypto::verify_proof`] verifies both.
pub trait ChainCommit {
    /// The canonical block hash of `header` under this chain's rules.
    fn header_hash(&self, header: &BlockHeader) -> Hash;

    /// The canonical inclusion-tree leaf hash for `event`.
    fn deposit_leaf(&self, event: &DepositEvent) -> Hash;
}

/// A Merkle inclusion proof of a deposit leaf against a block's `inclusion_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the deposit leaf within the block's inclusion tree.
    pub leaf_index: u32,
    /// Sibling hashes from the leaf up to the root.
    pub siblings: Vec<Hash>,
}

impl Codec for InclusionProof {
    fn write(&self, w: &mut Writer) {
        w.u32(self.leaf_index);
        w.len(self.siblings.len());
        for s in &self.siblings {
            s.write(w);
        }
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let leaf_index = r.u32()?;
        let count = r.len()?;
        if count > MAX_INCLUSION_DEPTH {
            return Err(CodecError::LengthOutOfRange);
        }
        let mut siblings = Vec::with_capacity(count);
        for _ in 0..count {
            siblings.push(Hash::read(r)?);
        }
        Ok(Self {
            leaf_index,
            siblings,
        })
    }
}

/// Everything needed to verify a deposit reached finality without trusting any
/// observer-supplied counter: a contiguous, hash-linked run of headers from the
/// including block (`headers[0]`) to the chain head (`headers[last]`), plus a
/// proof the deposit is included in the base block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityWitness {
    /// Contiguous headers, base first, head last.
    pub headers: Vec<BlockHeader>,
    /// Inclusion proof against `headers[0].inclusion_root`.
    pub inclusion: InclusionProof,
}

impl FinalityWitness {
    /// The including (base) block header, if the witness is non-empty.
    #[must_use]
    pub fn base(&self) -> Option<&BlockHeader> {
        self.headers.first()
    }

    /// The chain-head header, if the witness is non-empty.
    #[must_use]
    pub fn head(&self) -> Option<&BlockHeader> {
        self.headers.last()
    }
}

impl Codec for FinalityWitness {
    fn write(&self, w: &mut Writer) {
        w.len(self.headers.len());
        for h in &self.headers {
            h.write(w);
        }
        self.inclusion.write(w);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let count = r.len()?;
        if count > MAX_WITNESS_HEADERS {
            return Err(CodecError::LengthOutOfRange);
        }
        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            headers.push(BlockHeader::read(r)?);
        }
        let inclusion = InclusionProof::read(r)?;
        Ok(Self { headers, inclusion })
    }
}

/// Verify a deposit reached finality and return a [`FinalityProof`] whose
/// `confirmations` is the *derived* depth of the presented chain, never a
/// trusted input.
///
/// The check is threefold:
/// 1. the headers form a contiguous, hash-linked chain — `child.number ==
///    parent.number + 1` and `child.parent_hash == commit.header_hash(parent)`;
/// 2. `event` is Merkle-included in the base block's `inclusion_root`;
/// 3. the derived depth (`headers.len()`, equal to `head.number - base.number +
///    1` on a contiguous chain) satisfies `policy`.
///
/// The returned proof's `block_hash` is the recomputed base-block hash, not a
/// caller-supplied value.
///
/// # Errors
/// - [`AdapterError::InvalidWitness`] on an empty or discontinuous header chain.
/// - [`AdapterError::InvalidInclusion`] if the inclusion proof does not verify
///   against the base block's committed root.
/// - [`AdapterError::NotFinal`] if the verified depth is below policy.
pub fn verify_finality<C: ChainCommit>(
    commit: &C,
    event: &DepositEvent,
    witness: &FinalityWitness,
    policy: FinalityPolicy,
) -> Result<FinalityProof, AdapterError> {
    let base = witness
        .headers
        .first()
        .ok_or(AdapterError::InvalidWitness)?;

    // 1. Contiguous, hash-linked headers from base to head. An observer cannot
    //    inflate the depth without producing a real successor header whose
    //    `parent_hash` reproduces the predecessor's block hash bit-for-bit.
    for pair in witness.headers.windows(2) {
        let parent = &pair[0];
        let child = &pair[1];
        let expected = parent
            .number
            .checked_add(1)
            .ok_or(AdapterError::InvalidWitness)?;
        if child.number != expected {
            return Err(AdapterError::InvalidWitness);
        }
        if child.parent_hash != commit.header_hash(parent) {
            return Err(AdapterError::InvalidWitness);
        }
    }

    // 2. Deposit inclusion in the base block's committed root.
    let leaf = commit.deposit_leaf(event);
    let index = usize::try_from(witness.inclusion.leaf_index)
        .map_err(|_| AdapterError::InvalidInclusion)?;
    if !verify_proof(
        base.inclusion_root,
        index,
        leaf,
        &witness.inclusion.siblings,
    ) {
        return Err(AdapterError::InvalidInclusion);
    }

    // 3. Derived confirmation depth vs. policy. `len` is bounded by the decoder,
    //    so this `try_from` cannot realistically fail, but we surface it as a
    //    typed error rather than narrow with `as`.
    let confirmations =
        u32::try_from(witness.headers.len()).map_err(|_| AdapterError::InvalidWitness)?;
    if !policy.is_final(confirmations) {
        return Err(AdapterError::NotFinal {
            have: confirmations,
            need: policy.min_confirmations(),
        });
    }

    Ok(FinalityProof {
        block_number: base.number,
        block_hash: commit.header_hash(base),
        confirmations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AssetId, ChainId, TxId};
    use crypto::{hash_domain, merkle_root, MerkleTree};
    use types::{AccountId, Amount};

    /// A reference commitment scheme for the core tests, independent of the
    /// EVM/SVM crates: domain-separated SHA-256 over the canonical encodings.
    struct RefCommit;
    impl ChainCommit for RefCommit {
        fn header_hash(&self, header: &BlockHeader) -> Hash {
            hash_domain(b"dexos.test.header", &header.encode())
        }
        fn deposit_leaf(&self, event: &DepositEvent) -> Hash {
            hash_domain(b"dexos.test.leaf", &event.encode())
        }
    }

    fn event(tx: u8, amount: i128) -> DepositEvent {
        DepositEvent {
            source_chain: ChainId::new(1),
            source_tx: TxId::new(vec![tx; 32]),
            source_event_index: 0,
            asset: AssetId::new(7),
            amount: Amount::from_raw(amount),
            destination_account: AccountId::new(5),
        }
    }

    /// Build a valid witness: the deposit at `leaf_index` sits in a block with
    /// `block_leaves` total deposits, at height `base`, under a chain whose head
    /// is `head`.
    fn witness(
        commit: &RefCommit,
        block_leaves: &[Hash],
        leaf_index: usize,
        base: u64,
        head: u64,
    ) -> FinalityWitness {
        let mut tree = MerkleTree::new(block_leaves.len().max(1));
        for (i, l) in block_leaves.iter().enumerate() {
            tree.set(i, *l).unwrap();
        }
        let siblings = tree.proof(leaf_index).unwrap();
        let inclusion = InclusionProof {
            leaf_index: u32::try_from(leaf_index).unwrap(),
            siblings,
        };
        let mut headers = Vec::new();
        let mut parent = Hash::ZERO;
        for h in base..=head {
            let root = if h == base {
                merkle_root(block_leaves)
            } else {
                Hash::ZERO
            };
            let header = BlockHeader {
                number: h,
                parent_hash: parent,
                inclusion_root: root,
            };
            parent = commit.header_hash(&header);
            headers.push(header);
        }
        FinalityWitness { headers, inclusion }
    }

    #[test]
    fn valid_witness_derives_confirmations_from_chain_length() {
        let commit = RefCommit;
        let ev = event(1, 1_000);
        let leaves = vec![commit.deposit_leaf(&ev)];
        // base=100, head=111 => 12 contiguous headers => 12 confirmations.
        let w = witness(&commit, &leaves, 0, 100, 111);
        let proof = verify_finality(&commit, &ev, &w, FinalityPolicy::new(12)).unwrap();
        assert_eq!(proof.confirmations, 12);
        assert_eq!(proof.block_number, 100);
        assert_eq!(proof.block_hash, commit.header_hash(w.base().unwrap()));
    }

    #[test]
    fn short_chain_is_not_final() {
        let commit = RefCommit;
        let ev = event(2, 500);
        let leaves = vec![commit.deposit_leaf(&ev)];
        // Only 5 headers, policy needs 12.
        let w = witness(&commit, &leaves, 0, 100, 104);
        assert!(matches!(
            verify_finality(&commit, &ev, &w, FinalityPolicy::new(12)),
            Err(AdapterError::NotFinal { have: 5, need: 12 })
        ));
    }

    #[test]
    fn observer_cannot_fake_confirmations_by_appending_unlinked_header() {
        let commit = RefCommit;
        let ev = event(3, 500);
        let leaves = vec![commit.deposit_leaf(&ev)];
        let mut w = witness(&commit, &leaves, 0, 100, 104);
        // Attacker tries to reach depth 12 by appending headers whose
        // parent_hash is forged (not the real predecessor hash).
        let last_number = w.headers.last().unwrap().number;
        for i in 1..=7u64 {
            w.headers.push(BlockHeader {
                number: last_number + i,
                parent_hash: Hash::from_bytes([0xAA; 32]),
                inclusion_root: Hash::ZERO,
            });
        }
        assert_eq!(
            verify_finality(&commit, &ev, &w, FinalityPolicy::new(12)),
            Err(AdapterError::InvalidWitness)
        );
    }

    #[test]
    fn non_contiguous_height_is_rejected() {
        let commit = RefCommit;
        let ev = event(4, 500);
        let leaves = vec![commit.deposit_leaf(&ev)];
        let mut w = witness(&commit, &leaves, 0, 100, 111);
        // Skip a height while keeping the hash linkage superficially intact.
        w.headers[6].number += 1;
        assert_eq!(
            verify_finality(&commit, &ev, &w, FinalityPolicy::new(1)),
            Err(AdapterError::InvalidWitness)
        );
    }

    #[test]
    fn empty_witness_is_rejected() {
        let commit = RefCommit;
        let ev = event(5, 500);
        let w = FinalityWitness {
            headers: vec![],
            inclusion: InclusionProof {
                leaf_index: 0,
                siblings: vec![],
            },
        };
        assert_eq!(
            verify_finality(&commit, &ev, &w, FinalityPolicy::new(1)),
            Err(AdapterError::InvalidWitness)
        );
    }

    #[test]
    fn deposit_not_in_block_fails_inclusion() {
        let commit = RefCommit;
        let ev = event(6, 500);
        // Block commits to a *different* deposit; the proof cannot cover `ev`.
        let other = event(0xEE, 999);
        let leaves = vec![commit.deposit_leaf(&other)];
        let w = witness(&commit, &leaves, 0, 100, 111);
        assert_eq!(
            verify_finality(&commit, &ev, &w, FinalityPolicy::new(12)),
            Err(AdapterError::InvalidInclusion)
        );
    }

    #[test]
    fn tampered_amount_breaks_inclusion() {
        let commit = RefCommit;
        let ev = event(7, 500);
        let leaves = vec![commit.deposit_leaf(&ev)];
        let w = witness(&commit, &leaves, 0, 100, 111);
        // Same tx/index, but the credited amount is altered post-inclusion.
        let mut tampered = ev.clone();
        tampered.amount = Amount::from_raw(999_999);
        assert_eq!(
            verify_finality(&commit, &tampered, &w, FinalityPolicy::new(12)),
            Err(AdapterError::InvalidInclusion)
        );
    }

    #[test]
    fn multi_deposit_block_proves_each_leaf() {
        let commit = RefCommit;
        let evs: Vec<DepositEvent> = (0..5u8).map(|i| event(i, 100 + i128::from(i))).collect();
        let leaves: Vec<Hash> = evs.iter().map(|e| commit.deposit_leaf(e)).collect();
        for (idx, ev) in evs.iter().enumerate() {
            let w = witness(&commit, &leaves, idx, 10, 21);
            let proof = verify_finality(&commit, ev, &w, FinalityPolicy::new(12)).unwrap();
            assert_eq!(proof.confirmations, 12);
            // A proof for one leaf must not validate a *different* deposit.
            let wrong = &evs[(idx + 1) % evs.len()];
            assert_eq!(
                verify_finality(&commit, wrong, &w, FinalityPolicy::new(12)),
                Err(AdapterError::InvalidInclusion)
            );
        }
    }

    #[test]
    fn codec_round_trips() {
        let h = BlockHeader {
            number: 42,
            parent_hash: Hash::from_bytes([1u8; 32]),
            inclusion_root: Hash::from_bytes([2u8; 32]),
        };
        assert_eq!(BlockHeader::decode(&h.encode()).unwrap(), h);

        let ip = InclusionProof {
            leaf_index: 3,
            siblings: vec![Hash::from_bytes([4u8; 32]), Hash::from_bytes([5u8; 32])],
        };
        assert_eq!(InclusionProof::decode(&ip.encode()).unwrap(), ip);

        let w = FinalityWitness {
            headers: vec![h, h],
            inclusion: ip,
        };
        assert_eq!(FinalityWitness::decode(&w.encode()).unwrap(), w);
    }

    #[test]
    fn oversized_witness_and_proof_rejected() {
        // Header count over the bound trips before allocation.
        let mut buf = Writer::new();
        buf.len(MAX_WITNESS_HEADERS + 1);
        assert_eq!(
            FinalityWitness::decode(&buf.into_bytes()),
            Err(CodecError::LengthOutOfRange)
        );

        let mut buf = Writer::new();
        buf.u32(0);
        buf.len(MAX_INCLUSION_DEPTH + 1);
        assert_eq!(
            InclusionProof::decode(&buf.into_bytes()),
            Err(CodecError::LengthOutOfRange)
        );
    }

    #[test]
    fn decoders_never_panic_on_arbitrary_bytes() {
        // Deterministic LCG, no external crates.
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };
        for _ in 0..4096 {
            let len = usize::try_from(next() % 260).unwrap_or_default();
            let bytes: Vec<u8> = (0..len)
                .map(|_| u8::try_from(next() & 0xFF).unwrap())
                .collect();
            let _ = BlockHeader::decode(&bytes);
            let _ = InclusionProof::decode(&bytes);
            let _ = FinalityWitness::decode(&bytes);
        }
    }
}
