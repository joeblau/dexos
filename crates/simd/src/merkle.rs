//! Batched Merkle-update helper kernels.
//!
//! State-root maintenance applies a batch of `(index, leaf)` updates to a dense
//! Merkle tree and reads back the new root. This module wraps the canonical
//! [`crypto::MerkleTree`] with `{scalar, dispatched}` entry points so root
//! recomputation participates in the dispatch framework, and adds a from-scratch
//! [`crypto::merkle_root`] batch helper.
//!
//! Deterministic replay guarantee: the root produced here is exactly the
//! [`crypto`] scalar root regardless of the selected [`Backend`], so a replay
//! under any backend yields identical state roots.

use crate::backend::Backend;
use crypto::{merkle_root, MerkleError, MerkleTree};
use types::Hash;

/// Apply a batch of `(index, leaf)` updates in order and return the new root.
///
/// An out-of-range index leaves the tree unchanged for that update and returns
/// [`MerkleError::IndexOutOfRange`]; updates already applied before the failure
/// remain in place (callers wanting all-or-nothing should validate indices
/// against [`crypto::MerkleTree::capacity`] first). Never panics.
pub fn apply_updates(
    tree: &mut MerkleTree,
    updates: &[(usize, Hash)],
) -> Result<Hash, MerkleError> {
    for &(index, leaf) in updates {
        tree.set(index, leaf)?;
    }
    Ok(tree.root())
}

/// Scalar reference: from-scratch root over a full leaf vector.
#[must_use]
pub fn batch_merkle_root_scalar(leaves: &[Hash]) -> Hash {
    merkle_root(leaves)
}

/// From-scratch root via an explicit [`Backend`]. Bit-identical across backends
/// (a future vectorized node-hash kernel would slot in behind this selector).
#[must_use]
pub fn batch_merkle_root(_backend: Backend, leaves: &[Hash]) -> Hash {
    batch_merkle_root_scalar(leaves)
}

/// From-scratch root on the best available backend.
#[must_use]
pub fn batch_merkle_root_dispatch(leaves: &[Hash]) -> Hash {
    batch_merkle_root(crate::detect(), leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn bound(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % (bound as u64)).unwrap_or(0)
        }
        fn leaf(&mut self) -> Hash {
            let mut b = [0u8; 32];
            for chunk in b.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes());
            }
            Hash::from_bytes(b)
        }
    }

    #[test]
    fn incremental_updates_match_from_scratch() {
        let leaves: Vec<Hash> = (0..8u8).map(|i| Hash::from_bytes([i; 32])).collect();
        let mut tree = MerkleTree::new(8);
        let updates: Vec<(usize, Hash)> = leaves.iter().copied().enumerate().collect();
        let root = apply_updates(&mut tree, &updates).unwrap();
        assert_eq!(root, batch_merkle_root_scalar(&leaves));
    }

    #[test]
    fn empty_root_is_zero_on_every_backend() {
        assert!(batch_merkle_root_scalar(&[]).is_zero());
        for b in [
            Backend::Scalar,
            Backend::Avx2,
            Backend::Avx512,
            Backend::Neon,
        ] {
            assert!(batch_merkle_root(b, &[]).is_zero());
        }
    }

    #[test]
    fn out_of_range_update_returns_error_without_panic() {
        let mut tree = MerkleTree::new(4);
        let err = apply_updates(
            &mut tree,
            &[(0, Hash::from_bytes([1; 32])), (99, Hash::ZERO)],
        );
        assert_eq!(err, Err(MerkleError::IndexOutOfRange));
        // The in-range update before the failure still took effect.
        assert!(!tree.root().is_zero());
    }

    #[test]
    fn dispatched_equals_scalar_over_lcg_corpus() {
        let mut r = Lcg(0x1357_9bdf_2468_ace0);
        for _ in 0..500 {
            let n = 1 + r.bound(64);
            let leaves: Vec<Hash> = (0..n).map(|_| r.leaf()).collect();
            assert_eq!(
                batch_merkle_root_scalar(&leaves),
                batch_merkle_root_dispatch(&leaves)
            );
        }
    }

    #[test]
    fn replay_under_any_backend_is_identical() {
        let mut r = Lcg(42);
        let cap = 32usize;
        let updates: Vec<(usize, Hash)> = (0..80).map(|_| (r.bound(cap), r.leaf())).collect();

        let mut a = MerkleTree::new(cap);
        let mut b = MerkleTree::new(cap);
        let root_a = apply_updates(&mut a, &updates).unwrap();
        let root_b = apply_updates(&mut b, &updates).unwrap();
        assert_eq!(root_a, root_b);
        // And it equals a from-scratch root over the final leaf image.
        let mut image = vec![Hash::ZERO; cap];
        for &(i, h) in &updates {
            image[i] = h;
        }
        assert_eq!(root_a, batch_merkle_root_dispatch(&image));
    }

    #[test]
    fn never_panics_on_arbitrary_updates() {
        let mut r = Lcg(0xc0ff_ee00);
        for _ in 0..2_000 {
            let cap = 1usize << r.bound(6);
            let mut tree = MerkleTree::new(cap);
            let count = r.bound(20);
            // Indices deliberately span past capacity to exercise the error path.
            let updates: Vec<(usize, Hash)> = (0..count)
                .map(|_| (r.bound(cap * 4 + 1), r.leaf()))
                .collect();
            let _ = apply_updates(&mut tree, &updates);
        }
    }
}
