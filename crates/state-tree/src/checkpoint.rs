//! Checkpoint roots over a set of per-shard state roots for consensus.
//!
//! A checkpoint commits to every shard's root under a canonical (shard-id
//! sorted) ordering, so the result is invariant to the order the shards are
//! presented and changes if and only if some covered shard root changes.

use crypto::{hash_leaf, merkle_root};
use types::{ShardId, StateRoot};

/// Compute the checkpoint root over `(ShardId, StateRoot)` pairs.
///
/// The pairs are sorted by shard id into a canonical order, each pair is bound
/// into a leaf `hash_leaf(shard_id_le || root)`, and the checkpoint is the
/// Merkle root over those leaves. An empty input yields `Hash::ZERO`.
///
/// Binding the shard id into the leaf means two shards with coincidentally equal
/// roots still commit distinctly, and reordering the input cannot change the
/// result.
#[must_use]
pub fn checkpoint_root(shard_roots: &[(ShardId, StateRoot)]) -> StateRoot {
    let mut sorted: Vec<(ShardId, StateRoot)> = shard_roots.to_vec();
    sorted.sort_by_key(|(id, _)| id.get());

    let leaves: Vec<StateRoot> = sorted
        .iter()
        .map(|(id, root)| {
            let mut buf = Vec::with_capacity(2 + 32);
            buf.extend_from_slice(&id.get().to_le_bytes());
            buf.extend_from_slice(root.as_bytes());
            hash_leaf(&buf)
        })
        .collect();

    merkle_root(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash;

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
        fn hash(&mut self) -> Hash {
            let mut b = [0u8; 32];
            for chunk in b.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes());
            }
            Hash::from_bytes(b)
        }
        fn shard(&mut self) -> ShardId {
            ShardId::new(u16::try_from(self.next() & 0xffff).unwrap_or(0))
        }
    }

    #[test]
    fn empty_is_zero_root() {
        assert_eq!(checkpoint_root(&[]), Hash::ZERO);
    }

    #[test]
    fn invariant_to_input_ordering() {
        let a = (ShardId::new(0), Hash::from_bytes([1; 32]));
        let b = (ShardId::new(1), Hash::from_bytes([2; 32]));
        let c = (ShardId::new(2), Hash::from_bytes([3; 32]));
        let forward = checkpoint_root(&[a, b, c]);
        let shuffled = checkpoint_root(&[c, a, b]);
        let reversed = checkpoint_root(&[c, b, a]);
        assert_eq!(forward, shuffled);
        assert_eq!(forward, reversed);
    }

    #[test]
    fn changes_iff_a_covered_root_changes() {
        let base = [
            (ShardId::new(0), Hash::from_bytes([1; 32])),
            (ShardId::new(1), Hash::from_bytes([2; 32])),
        ];
        let same = base;
        assert_eq!(checkpoint_root(&base), checkpoint_root(&same));

        let mut changed = base;
        changed[1].1 = Hash::from_bytes([9; 32]);
        assert_ne!(checkpoint_root(&base), checkpoint_root(&changed));
    }

    #[test]
    fn shard_id_is_bound_into_the_commitment() {
        // Same roots but re-labelled shard ids commit differently.
        let root = Hash::from_bytes([7; 32]);
        let a = checkpoint_root(&[(ShardId::new(0), root), (ShardId::new(1), root)]);
        let b = checkpoint_root(&[(ShardId::new(0), root), (ShardId::new(2), root)]);
        assert_ne!(a, b);
    }

    #[test]
    fn property_permutation_invariance_random() {
        let mut rng = Lcg(0x5151_5151);
        for _ in 0..1_000 {
            let n = usize::try_from(rng.next() % 12).unwrap_or(0) + 1;
            let mut pairs: Vec<(ShardId, StateRoot)> = Vec::new();
            let mut used: Vec<u16> = Vec::new();
            while pairs.len() < n {
                let s = rng.shard();
                if used.contains(&s.get()) {
                    continue; // keep shard ids distinct for a clean canonical order
                }
                used.push(s.get());
                pairs.push((s, rng.hash()));
            }
            let expected = checkpoint_root(&pairs);

            // Reverse the input; canonical sort must reproduce the same root.
            let mut rev = pairs.clone();
            rev.reverse();
            assert_eq!(checkpoint_root(&rev), expected);
        }
    }
}
