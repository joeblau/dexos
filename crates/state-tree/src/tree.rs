//! Incremental per-shard state tree over account and market sub-trees.
//!
//! A [`StateTree`] holds two fixed-capacity [`crypto::MerkleTree`]s — one for
//! account leaves, one for market leaves — and commits to both with a single
//! shard root: `root = hash_node(account_root, market_root)`.
//!
//! Updates are incremental: setting one leaf touches only the O(log n) nodes on
//! its root path inside the relevant sub-tree, and the combined shard root is
//! recomputed lazily (cached, invalidated on any mutation). The incremental
//! shard root is bit-identical to a from-scratch rebuild over the same leaves.
//!
//! Light clients verify a leaf against the shard root with a proof produced by
//! [`StateTree::account_proof`] / [`StateTree::market_proof`] and the free
//! functions [`verify_account`] / [`verify_market`], which are total on
//! adversarial input.

use core::cell::Cell;

use crypto::{hash_node, MerkleTree};
use types::{AccountId, Hash, MarketId, StateRoot};

use crate::leaf::{hash_account_leaf, hash_market_leaf};

/// A state-tree mutation or query failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// The id maps to an index beyond the sub-tree's capacity.
    #[error("id is out of range for the tree capacity")]
    IdOutOfRange,
    /// A stored incremental Merkle representation is malformed or stale.
    #[error("state tree merkle representation: {0}")]
    Merkle(#[from] crypto::MerkleError),
    /// The optional combined-root cache disagrees with the two sub-tree roots.
    #[error("state tree cached root disagrees with its sub-tree roots")]
    CachedRootMismatch,
}

/// An incremental per-shard state commitment.
#[derive(Debug, Clone)]
pub struct StateTree {
    accounts: MerkleTree,
    markets: MerkleTree,
    /// Lazily-recomputed combined shard root; `None` when dirty.
    cached_root: Cell<Option<Hash>>,
}

impl StateTree {
    /// Build a tree sized for at least `account_capacity` account leaves and
    /// `market_capacity` market leaves (each rounded up to a power of two).
    #[must_use]
    pub fn new(account_capacity: usize, market_capacity: usize) -> Self {
        Self {
            accounts: MerkleTree::new(account_capacity.max(1)),
            markets: MerkleTree::new(market_capacity.max(1)),
            cached_root: Cell::new(None),
        }
    }

    /// Account sub-tree leaf capacity (a power of two).
    #[must_use]
    pub fn account_capacity(&self) -> usize {
        self.accounts.capacity()
    }

    /// Market sub-tree leaf capacity (a power of two).
    #[must_use]
    pub fn market_capacity(&self) -> usize {
        self.markets.capacity()
    }

    /// Commit `leaf_bytes` as account `id`'s leaf (hashed under `DOMAIN_ACCOUNT`).
    ///
    /// Recomputes only the account sub-tree path for `id` and marks the shard
    /// root dirty. Returns [`StateError::IdOutOfRange`] rather than panicking.
    pub fn set_account(&mut self, id: AccountId, leaf_bytes: &[u8]) -> Result<(), StateError> {
        let index = id.index().map_err(|_| StateError::IdOutOfRange)?;
        let leaf = hash_account_leaf(leaf_bytes);
        self.accounts
            .set(index, leaf)
            .map_err(|_| StateError::IdOutOfRange)?;
        self.cached_root.set(None);
        Ok(())
    }

    /// Commit `leaf_bytes` as market `id`'s leaf (hashed under `DOMAIN_MARKET`).
    pub fn set_market(&mut self, id: MarketId, leaf_bytes: &[u8]) -> Result<(), StateError> {
        let index = id.index().map_err(|_| StateError::IdOutOfRange)?;
        let leaf = hash_market_leaf(leaf_bytes);
        self.markets
            .set(index, leaf)
            .map_err(|_| StateError::IdOutOfRange)?;
        self.cached_root.set(None);
        Ok(())
    }

    /// Logically delete account `id` by resetting its leaf to the empty
    /// (`Hash::ZERO`) value. Incremental, like [`Self::set_account`].
    pub fn clear_account(&mut self, id: AccountId) -> Result<(), StateError> {
        let index = id.index().map_err(|_| StateError::IdOutOfRange)?;
        self.accounts
            .set(index, Hash::ZERO)
            .map_err(|_| StateError::IdOutOfRange)?;
        self.cached_root.set(None);
        Ok(())
    }

    /// Logically delete market `id` by resetting its leaf to the empty value.
    pub fn clear_market(&mut self, id: MarketId) -> Result<(), StateError> {
        let index = id.index().map_err(|_| StateError::IdOutOfRange)?;
        self.markets
            .set(index, Hash::ZERO)
            .map_err(|_| StateError::IdOutOfRange)?;
        self.cached_root.set(None);
        Ok(())
    }

    /// The account sub-tree root.
    #[must_use]
    pub fn account_root(&self) -> Hash {
        self.accounts.root()
    }

    /// The market sub-tree root.
    #[must_use]
    pub fn market_root(&self) -> Hash {
        self.markets.root()
    }

    /// The combined shard state root, recomputed lazily and cached.
    ///
    /// `root = hash_node(account_root, market_root)`. The steady-state call is
    /// allocation-free: it either returns the cache or performs a single
    /// `hash_node`.
    #[must_use]
    pub fn root(&self) -> StateRoot {
        if let Some(cached) = self.cached_root.get() {
            return cached;
        }
        let root = hash_node(self.accounts.root(), self.markets.root());
        self.cached_root.set(Some(root));
        root
    }

    /// Validate every stored value read by a future incremental update.
    ///
    /// Both Merkle node arrays must be exact bottom-up derivations of their
    /// leaves, and a populated combined-root cache must agree with the sub-tree
    /// roots. Cache absence remains non-logical and is accepted.
    pub fn validate_transition_invariants(&self) -> Result<(), StateError> {
        self.accounts.validate_invariants()?;
        self.markets.validate_invariants()?;
        let recomputed_root = hash_node(self.accounts.root(), self.markets.root());
        if self
            .cached_root
            .get()
            .is_some_and(|cached_root| cached_root != recomputed_root)
        {
            return Err(StateError::CachedRootMismatch);
        }
        Ok(())
    }

    /// An inclusion proof for account `id` against the shard [`Self::root`].
    ///
    /// The returned vector is the account sub-tree sibling path (leaf → sub-root)
    /// with the market sub-tree root appended as the final sibling, so a light
    /// client can reconstruct the combined shard root. Verify with
    /// [`verify_account`].
    pub fn account_proof(&self, id: AccountId) -> Result<Vec<Hash>, StateError> {
        let index = id.index().map_err(|_| StateError::IdOutOfRange)?;
        let mut proof = self
            .accounts
            .proof(index)
            .map_err(|_| StateError::IdOutOfRange)?;
        proof.push(self.markets.root());
        Ok(proof)
    }

    /// An inclusion proof for market `id` against the shard [`Self::root`].
    ///
    /// Market leaves live in the right sub-tree, so the account sub-tree root is
    /// appended as the final sibling. Verify with [`verify_market`].
    pub fn market_proof(&self, id: MarketId) -> Result<Vec<Hash>, StateError> {
        let index = id.index().map_err(|_| StateError::IdOutOfRange)?;
        let mut proof = self
            .markets
            .proof(index)
            .map_err(|_| StateError::IdOutOfRange)?;
        proof.push(self.accounts.root());
        Ok(proof)
    }
}

/// Fold a leaf up through its sibling path to a sub-tree root.
///
/// Total: returns `None` for a path that cannot address `index` rather than
/// panicking or indexing out of bounds.
fn fold_subtree(index: usize, leaf: Hash, siblings: &[Hash]) -> Option<Hash> {
    // A path of `d` siblings addresses `2^d` leaves; `usize::BITS` siblings is
    // already unrepresentable.
    if siblings.len() >= usize::BITS as usize {
        return None;
    }
    if index >> siblings.len() != 0 {
        return None;
    }
    let mut current = leaf;
    let mut idx = index;
    for sibling in siblings {
        current = if idx & 1 == 0 {
            hash_node(current, *sibling)
        } else {
            hash_node(*sibling, current)
        };
        idx >>= 1;
    }
    Some(current)
}

/// Verify an account inclusion proof against a shard `root`. Never panics.
///
/// Returns `false` for a malformed proof, a wrong root, a tampered leaf, or an
/// out-of-range id.
#[must_use]
pub fn verify_account(root: StateRoot, id: AccountId, leaf_bytes: &[u8], proof: &[Hash]) -> bool {
    let Ok(index) = id.index() else {
        return false;
    };
    // The final sibling is the market sub-tree root; the rest is the account path.
    let Some((market_root, subtree_path)) = proof.split_last() else {
        return false;
    };
    let leaf = hash_account_leaf(leaf_bytes);
    let Some(account_root) = fold_subtree(index, leaf, subtree_path) else {
        return false;
    };
    // Accounts are the left child of the shard combine.
    hash_node(account_root, *market_root) == root
}

/// Verify a market inclusion proof against a shard `root`. Never panics.
#[must_use]
pub fn verify_market(root: StateRoot, id: MarketId, leaf_bytes: &[u8], proof: &[Hash]) -> bool {
    let Ok(index) = id.index() else {
        return false;
    };
    // The final sibling is the account sub-tree root; the rest is the market path.
    let Some((account_root, subtree_path)) = proof.split_last() else {
        return false;
    };
    let leaf = hash_market_leaf(leaf_bytes);
    let Some(market_root) = fold_subtree(index, leaf, subtree_path) else {
        return false;
    };
    // Markets are the right child of the shard combine.
    hash_node(*account_root, market_root) == root
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic in-test LCG (no external rng crate).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn next_usize(&mut self, bound: usize) -> usize {
            let b = u64::try_from(bound.max(1)).unwrap_or(u64::MAX);
            usize::try_from(self.next() % b).unwrap_or(0)
        }
        fn leaf_bytes(&mut self) -> Vec<u8> {
            let n = self.next_usize(24);
            (0..n)
                .map(|_| u8::try_from(self.next() & 0xff).unwrap_or(0))
                .collect()
        }
    }

    #[test]
    fn insert_update_delete_change_the_root() {
        let mut tree = StateTree::new(16, 16);
        let empty = tree.root();

        // Insert.
        tree.set_account(AccountId::new(3), b"balance:100").unwrap();
        let after_insert = tree.root();
        assert_ne!(empty, after_insert);

        // Update the same leaf.
        tree.set_account(AccountId::new(3), b"balance:200").unwrap();
        let after_update = tree.root();
        assert_ne!(after_insert, after_update);

        // Logical delete returns to the empty root.
        tree.clear_account(AccountId::new(3)).unwrap();
        assert_eq!(tree.root(), empty);
    }

    #[test]
    fn out_of_range_ids_error_not_panic() {
        let mut tree = StateTree::new(4, 4); // capacity rounds to 4
        assert_eq!(
            tree.set_account(AccountId::new(4), b"x"),
            Err(StateError::IdOutOfRange)
        );
        assert_eq!(
            tree.set_market(MarketId::new(9), b"x"),
            Err(StateError::IdOutOfRange)
        );
        assert_eq!(
            tree.account_proof(AccountId::new(100)),
            Err(StateError::IdOutOfRange)
        );
        assert_eq!(
            tree.clear_market(MarketId::new(4)),
            Err(StateError::IdOutOfRange)
        );
    }

    #[test]
    fn incremental_equals_from_scratch_rebuild() {
        // Property: after a random op stream, the incrementally-maintained root
        // equals a fresh tree replaying only the final leaf values.
        let mut rng = Lcg(0xABCD_1234);
        let (acap, mcap) = (32usize, 32usize);
        let mut tree = StateTree::new(acap, mcap);
        let mut acc_final: Vec<Option<Vec<u8>>> = vec![None; acap];
        let mut mkt_final: Vec<Option<Vec<u8>>> = vec![None; mcap];

        for _ in 0..3_000 {
            if rng.next() & 1 == 0 {
                let i = rng.next_usize(acap);
                if rng.next().is_multiple_of(5) {
                    tree.clear_account(AccountId::from_index(i).unwrap())
                        .unwrap();
                    acc_final[i] = None;
                } else {
                    let bytes = rng.leaf_bytes();
                    tree.set_account(AccountId::from_index(i).unwrap(), &bytes)
                        .unwrap();
                    acc_final[i] = Some(bytes);
                }
            } else {
                let i = rng.next_usize(mcap);
                if rng.next().is_multiple_of(5) {
                    tree.clear_market(MarketId::from_index(i).unwrap()).unwrap();
                    mkt_final[i] = None;
                } else {
                    let bytes = rng.leaf_bytes();
                    tree.set_market(MarketId::from_index(i).unwrap(), &bytes)
                        .unwrap();
                    mkt_final[i] = Some(bytes);
                }
            }

            // Rebuild from scratch over the current final leaf set.
            let mut fresh = StateTree::new(acap, mcap);
            for (i, v) in acc_final.iter().enumerate() {
                if let Some(bytes) = v {
                    fresh
                        .set_account(AccountId::from_index(i).unwrap(), bytes)
                        .unwrap();
                }
            }
            for (i, v) in mkt_final.iter().enumerate() {
                if let Some(bytes) = v {
                    fresh
                        .set_market(MarketId::from_index(i).unwrap(), bytes)
                        .unwrap();
                }
            }
            assert_eq!(tree.root(), fresh.root());
            assert_eq!(tree.validate_transition_invariants(), Ok(()));
        }
    }

    #[test]
    fn transition_validator_rejects_corrupt_combined_root_cache() {
        let mut tree = StateTree::new(8, 8);
        tree.set_account(AccountId::new(1), b"account").unwrap();
        tree.set_market(MarketId::new(2), b"market").unwrap();
        let correct_root = tree.root();
        assert_eq!(tree.validate_transition_invariants(), Ok(()));

        tree.cached_root.set(Some(Hash::from_bytes([0xCC; 32])));
        assert_eq!(
            tree.validate_transition_invariants(),
            Err(StateError::CachedRootMismatch)
        );

        tree.cached_root.set(None);
        assert_eq!(tree.validate_transition_invariants(), Ok(()));
        assert_eq!(tree.root(), correct_root);
    }

    #[test]
    fn deterministic_replay_yields_identical_roots() {
        let ops: [(bool, usize, &[u8]); 6] = [
            (true, 0, b"a"),
            (false, 1, b"b"),
            (true, 5, b"cc"),
            (false, 3, b"ddd"),
            (true, 5, b"updated"),
            (false, 1, b"changed"),
        ];
        let run = || {
            let mut t = StateTree::new(8, 8);
            for &(is_acc, i, bytes) in &ops {
                if is_acc {
                    t.set_account(AccountId::from_index(i).unwrap(), bytes)
                        .unwrap();
                } else {
                    t.set_market(MarketId::from_index(i).unwrap(), bytes)
                        .unwrap();
                }
            }
            t.root()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn proof_round_trip_and_tamper_rejection() {
        let mut tree = StateTree::new(16, 16);
        tree.set_account(AccountId::new(7), b"acct-7").unwrap();
        tree.set_market(MarketId::new(2), b"mkt-2").unwrap();
        let root = tree.root();

        // Account round trip.
        let ap = tree.account_proof(AccountId::new(7)).unwrap();
        assert!(verify_account(root, AccountId::new(7), b"acct-7", &ap));
        // Tampered leaf fails.
        assert!(!verify_account(root, AccountId::new(7), b"acct-8", &ap));
        // Wrong root fails.
        assert!(!verify_account(
            Hash::from_bytes([9; 32]),
            AccountId::new(7),
            b"acct-7",
            &ap
        ));

        // Market round trip.
        let mp = tree.market_proof(MarketId::new(2)).unwrap();
        assert!(verify_market(root, MarketId::new(2), b"mkt-2", &mp));
        assert!(!verify_market(root, MarketId::new(2), b"mkt-x", &mp));
    }

    #[test]
    fn property_any_single_proof_mutation_fails() {
        let mut tree = StateTree::new(16, 16);
        for i in 0..16u32 {
            tree.set_account(AccountId::new(i), format!("acct-{i}").as_bytes())
                .unwrap();
        }
        let root = tree.root();

        for i in 0..16u32 {
            let leaf = format!("acct-{i}");
            let proof = tree.account_proof(AccountId::new(i)).unwrap();
            assert!(verify_account(
                root,
                AccountId::new(i),
                leaf.as_bytes(),
                &proof
            ));
            // Mutate each sibling; verification must fail.
            for j in 0..proof.len() {
                let mut tampered = proof.clone();
                let mut b = *tampered[j].as_bytes();
                b[0] ^= 0x01;
                tampered[j] = Hash::from_bytes(b);
                assert!(!verify_account(
                    root,
                    AccountId::new(i),
                    leaf.as_bytes(),
                    &tampered
                ));
            }
        }
    }

    #[test]
    fn verify_never_panics_on_arbitrary_input() {
        let mut rng = Lcg(0xFEED_BEEF);
        for _ in 0..20_000 {
            let id = AccountId::new(u32::try_from(rng.next() & 0xffff_ffff).unwrap_or(0));
            let plen = rng.next_usize(70);
            let proof: Vec<Hash> = (0..plen)
                .map(|_| {
                    let mut b = [0u8; 32];
                    for chunk in b.chunks_mut(8) {
                        chunk.copy_from_slice(&rng.next().to_le_bytes());
                    }
                    Hash::from_bytes(b)
                })
                .collect();
            let leaf = rng.leaf_bytes();
            let mut rb = [0u8; 32];
            for chunk in rb.chunks_mut(8) {
                chunk.copy_from_slice(&rng.next().to_le_bytes());
            }
            let root = Hash::from_bytes(rb);
            // Must return a bool, never panic.
            let _ = verify_account(root, id, &leaf, &proof);
            let _ = verify_market(root, MarketId::new(id.get()), &leaf, &proof);
        }
    }
}
