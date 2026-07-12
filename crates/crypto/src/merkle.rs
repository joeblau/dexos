//! Dense binary Merkle tree with incremental updates and inclusion proofs.
//!
//! A fixed-capacity segment-tree layout: setting one leaf recomputes only the
//! O(log n) nodes on its root path. Full construction from a leaf slice is
//! bottom-up O(N) (not O(N log N) per-leaf inserts). The incremental root is
//! identical to a from-scratch recomputation over the same leaves.

use crate::hash::hash_node;
use types::Hash;

/// A Merkle error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MerkleError {
    /// Leaf index is beyond the tree capacity.
    #[error("merkle leaf index out of range")]
    IndexOutOfRange,
}

/// A fixed-capacity incremental Merkle tree.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    capacity: usize,
    // Level-order nodes: index 1 is the root, leaves live at [capacity, 2*capacity).
    nodes: Vec<Hash>,
}

impl MerkleTree {
    /// Build a tree with capacity rounded up to a power of two ≥ `min_leaves`.
    ///
    /// All leaves start as [`Hash::ZERO`]; internal nodes are filled bottom-up
    /// in O(capacity).
    pub fn new(min_leaves: usize) -> Self {
        let capacity = min_leaves.max(1).next_power_of_two();
        let mut tree = Self {
            capacity,
            nodes: vec![Hash::ZERO; capacity * 2],
        };
        tree.recompute_all_parents();
        tree
    }

    /// Build a tree from `leaves` in a single bottom-up pass: O(N).
    ///
    /// Capacity is the next power of two ≥ `leaves.len()` (minimum 1). Missing
    /// trailing leaves are [`Hash::ZERO`], matching [`Self::new`] + repeated
    /// [`Self::set`].
    pub fn from_leaves(leaves: &[Hash]) -> Self {
        let capacity = leaves.len().max(1).next_power_of_two();
        let mut nodes = vec![Hash::ZERO; capacity * 2];
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[capacity + i] = *leaf;
        }
        // Bottom-up: parents of the leaf layer through the root.
        for j in (1..capacity).rev() {
            nodes[j] = hash_node(nodes[2 * j], nodes[2 * j + 1]);
        }
        Self { capacity, nodes }
    }

    /// Leaf capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Set a leaf and recompute its root path (O(log n)).
    pub fn set(&mut self, index: usize, leaf: Hash) -> Result<(), MerkleError> {
        if index >= self.capacity {
            return Err(MerkleError::IndexOutOfRange);
        }
        let mut i = self.capacity + index;
        self.nodes[i] = leaf;
        i /= 2;
        while i >= 1 {
            self.nodes[i] = hash_node(self.nodes[2 * i], self.nodes[2 * i + 1]);
            i /= 2;
        }
        Ok(())
    }

    /// The current root (O(1)).
    pub fn root(&self) -> Hash {
        self.nodes[1]
    }

    /// An inclusion proof (sibling hashes from leaf to root) for `index`.
    pub fn proof(&self, index: usize) -> Result<Vec<Hash>, MerkleError> {
        if index >= self.capacity {
            return Err(MerkleError::IndexOutOfRange);
        }
        let mut proof = Vec::new();
        let mut i = self.capacity + index;
        while i > 1 {
            proof.push(self.nodes[i ^ 1]);
            i /= 2;
        }
        Ok(proof)
    }

    /// Rebuild every internal node from the current leaves (O(capacity)).
    fn recompute_all_parents(&mut self) {
        for j in (1..self.capacity).rev() {
            self.nodes[j] = hash_node(self.nodes[2 * j], self.nodes[2 * j + 1]);
        }
    }
}

/// From-scratch root over a leaf slice (empty slice hashes to the zero root).
///
/// Built bottom-up in O(N); bit-identical to inserting each leaf via
/// [`MerkleTree::set`] into a fresh tree of the same capacity.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::ZERO;
    }
    MerkleTree::from_leaves(leaves).root()
}

/// Verify an inclusion proof. Total (never panics) on adversarial input; returns
/// `false` for an index that does not fit the proof depth.
pub fn verify_proof(root: Hash, index: usize, leaf: Hash, proof: &[Hash]) -> bool {
    if proof.len() >= usize::BITS as usize {
        return false;
    }
    if index >> proof.len() != 0 {
        return false;
    }
    let mut current = leaf;
    let mut idx = index;
    for sibling in proof {
        current = if idx & 1 == 0 {
            hash_node(current, *sibling)
        } else {
            hash_node(*sibling, current)
        };
        idx >>= 1;
    }
    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }
        fn next_usize(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % bound as u64).unwrap_or(0)
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
    fn incremental_equals_from_scratch() {
        let mut r = Lcg(7);
        for cap_log in 0..7 {
            let n = 1usize << cap_log;
            let mut leaves = vec![Hash::ZERO; n];
            let mut tree = MerkleTree::new(n);
            for _ in 0..(n * 3) {
                let idx = r.next_usize(n);
                let leaf = r.leaf();
                leaves[idx] = leaf;
                tree.set(idx, leaf).unwrap();
                assert_eq!(tree.root(), merkle_root(&leaves), "n={n}");
            }
        }
    }

    #[test]
    fn from_leaves_matches_set_loop_and_is_bottom_up() {
        let mut r = Lcg(99);
        for n in [0usize, 1, 2, 3, 5, 8, 15, 16, 17, 64, 100] {
            let leaves: Vec<Hash> = (0..n).map(|_| r.leaf()).collect();
            let bottom_up = MerkleTree::from_leaves(&leaves);
            let mut via_set = MerkleTree::new(leaves.len().max(1));
            for (i, l) in leaves.iter().enumerate() {
                via_set.set(i, *l).unwrap();
            }
            if leaves.is_empty() {
                // from_leaves([]) has capacity 1 of ZERO; merkle_root([]) is ZERO.
                assert_eq!(merkle_root(&leaves), Hash::ZERO);
                assert_eq!(bottom_up.root(), Hash::ZERO);
            } else {
                assert_eq!(bottom_up.root(), via_set.root(), "n={n}");
                assert_eq!(merkle_root(&leaves), via_set.root(), "n={n}");
            }
        }
    }

    #[test]
    fn proofs_verify_and_reject_tampering() {
        let mut tree = MerkleTree::new(8);
        let leaves: Vec<Hash> = (0..8u8).map(|i| Hash::from_bytes([i; 32])).collect();
        for (i, l) in leaves.iter().enumerate() {
            tree.set(i, *l).unwrap();
        }
        let root = tree.root();
        for (i, l) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(verify_proof(root, i, *l, &proof));
            // Tampered leaf fails.
            assert!(!verify_proof(root, i, Hash::from_bytes([99; 32]), &proof));
        }
    }

    #[test]
    fn verify_proof_never_panics_on_arbitrary_input() {
        let mut r = Lcg(123);
        for _ in 0..20_000 {
            let index = usize::try_from(r.next()).unwrap_or(0);
            let plen = r.next_usize(70);
            let proof: Vec<Hash> = (0..plen).map(|_| r.leaf()).collect();
            let _ = verify_proof(r.leaf(), index, r.leaf(), &proof);
        }
    }
}
