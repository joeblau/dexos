//! `state-tree` — incremental state commitments and Merkle roots.
//!
//! Part of the DexOS deterministic execution core: no async runtime, no
//! networking, no floating point — fixed-point integers and byte-canonical
//! hashing only.
//!
//! # Overview
//!
//! - [`leaf`]: domain-separated, versioned leaf hashing ([`hash_account_leaf`],
//!   [`hash_market_leaf`]) and a canonical field encoder/decoder
//!   ([`LeafWriter`] / [`LeafReader`]) that never silently narrows `i64`/`i128`.
//! - [`tree`]: [`StateTree`], a per-shard commitment over account and market
//!   sub-trees with incremental updates, a lazily-cached shard root, and
//!   light-client inclusion proofs ([`verify_account`], [`verify_market`]).
//! - [`checkpoint`]: [`checkpoint_root`], a shard-order-invariant commitment
//!   over a set of per-shard roots for consensus.
//!
//! # Guarantees
//!
//! - The incremental shard root is bit-identical to a from-scratch rebuild over
//!   the same leaves (property-tested).
//! - Replaying an identical set-sequence yields identical roots on every run.
//! - Light clients verify a leaf against the shard root with a proof.
//! - Out-of-range ids return [`StateError`], never panic; proof verification and
//!   leaf decoding are total on adversarial input.

pub mod checkpoint;
pub mod leaf;
pub mod tree;

pub use checkpoint::checkpoint_root;
pub use leaf::{
    hash_account_leaf, hash_leaf_of, hash_market_leaf, LeafError, LeafKind, LeafReader, LeafWriter,
    LEAF_ENCODING_VERSION,
};
pub use tree::{verify_account, verify_market, StateError, StateTree};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "state-tree";

#[cfg(test)]
mod tests {
    use super::*;
    use types::{AccountId, MarketId};

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "state-tree");
    }

    #[test]
    fn end_to_end_commit_and_prove() {
        // A small end-to-end flow exercising the re-exported surface together.
        let mut tree = StateTree::new(64, 64);

        let acct_payload = LeafWriter::new()
            .field_u32(1)
            .field_i128(1_000_000)
            .finish();
        tree.set_account(AccountId::new(1), &acct_payload).unwrap();

        let mkt_payload = LeafWriter::new().field_u32(2).field_i64(-5).finish();
        tree.set_market(MarketId::new(2), &mkt_payload).unwrap();

        let root = tree.root();

        let ap = tree.account_proof(AccountId::new(1)).unwrap();
        assert!(verify_account(root, AccountId::new(1), &acct_payload, &ap));

        let mp = tree.market_proof(MarketId::new(2)).unwrap();
        assert!(verify_market(root, MarketId::new(2), &mkt_payload, &mp));

        // A checkpoint over this single shard is stable and non-zero.
        let cp = checkpoint_root(&[(types::ShardId::new(0), root)]);
        assert!(!cp.is_zero());
    }
}
