//! Batch message-digest / signature pre-hashing kernels.
//!
//! Batch signature verification first reduces every message to a fixed digest.
//! That per-message work is embarrassingly parallel: each output depends on
//! exactly one input. This module exposes the batch as a kernel with matching
//! `{scalar, dispatched}` entry points over the canonical [`crypto`] hashes, so
//! it composes with the runtime dispatch framework like the arithmetic kernels.
//!
//! The hashes themselves ([`crypto::keccak256`], [`crypto::hash_domain`]) are the
//! bit-exact scalar reference; this crate does not re-implement the compression
//! function, so the dispatched path is *identical* to the scalar path (a future
//! `core::arch` multi-lane SHA/Keccak kernel would slot in behind the same
//! `Backend` selector without changing any result).

use crate::backend::Backend;
use crypto::{hash_domain, hash_leaf, keccak256};
use types::Hash;

/// Scalar reference: Keccak-256 digest of every message.
#[must_use]
pub fn batch_keccak256_scalar(messages: &[&[u8]]) -> Vec<[u8; 32]> {
    messages.iter().map(|&m| keccak256(m)).collect()
}

/// Keccak-256 batch via an explicit [`Backend`]. Bit-identical across backends.
#[must_use]
pub fn batch_keccak256(_backend: Backend, messages: &[&[u8]]) -> Vec<[u8; 32]> {
    // Per-message independence makes every backend identical; the parameter
    // exists so callers dispatch uniformly with the other kernels.
    batch_keccak256_scalar(messages)
}

/// Keccak-256 batch on the best available backend.
#[must_use]
pub fn batch_keccak256_dispatch(messages: &[&[u8]]) -> Vec<[u8; 32]> {
    batch_keccak256(crate::detect(), messages)
}

/// Scalar reference: domain-separated SHA-256 digest of every message.
#[must_use]
pub fn batch_hash_domain_scalar(domain: &[u8], messages: &[&[u8]]) -> Vec<Hash> {
    messages.iter().map(|&m| hash_domain(domain, m)).collect()
}

/// Domain-hash batch via an explicit [`Backend`].
#[must_use]
pub fn batch_hash_domain(_backend: Backend, domain: &[u8], messages: &[&[u8]]) -> Vec<Hash> {
    batch_hash_domain_scalar(domain, messages)
}

/// Domain-hash batch on the best available backend.
#[must_use]
pub fn batch_hash_domain_dispatch(domain: &[u8], messages: &[&[u8]]) -> Vec<Hash> {
    batch_hash_domain(crate::detect(), domain, messages)
}

/// Scalar reference: Merkle-leaf digest of every payload.
#[must_use]
pub fn batch_hash_leaves_scalar(payloads: &[&[u8]]) -> Vec<Hash> {
    payloads.iter().map(|&p| hash_leaf(p)).collect()
}

/// Leaf-hash batch via an explicit [`Backend`].
#[must_use]
pub fn batch_hash_leaves(_backend: Backend, payloads: &[&[u8]]) -> Vec<Hash> {
    batch_hash_leaves_scalar(payloads)
}

/// Leaf-hash batch on the best available backend.
#[must_use]
pub fn batch_hash_leaves_dispatch(payloads: &[&[u8]]) -> Vec<Hash> {
    batch_hash_leaves(crate::detect(), payloads)
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
        fn len(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % (bound as u64 + 1)).unwrap_or(0)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n)
                .map(|_| {
                    let b = self.next().to_le_bytes();
                    b[0]
                })
                .collect()
        }
    }

    #[test]
    fn matches_per_item_reference() {
        let msgs: Vec<&[u8]> = vec![b"a", b"bb", b"", b"ccc"];
        let batch = batch_keccak256_scalar(&msgs);
        assert_eq!(batch.len(), 4);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(batch[i], keccak256(m));
        }
        // Known-answer for the empty message.
        assert_eq!(
            batch[2],
            keccak256(b""),
            "empty keccak must equal the reference"
        );
    }

    #[test]
    fn empty_batch_is_empty() {
        assert!(batch_keccak256_scalar(&[]).is_empty());
        assert!(batch_hash_domain_scalar(b"d", &[]).is_empty());
        assert!(batch_hash_leaves_scalar(&[]).is_empty());
    }

    #[test]
    fn dispatched_equals_scalar_over_lcg_corpus() {
        let mut r = Lcg(0xa5a5_5a5a_1234_9999);
        for _ in 0..500 {
            let count = r.len(16);
            let owned: Vec<Vec<u8>> = (0..count)
                .map(|_| {
                    let n = r.len(48);
                    r.bytes(n)
                })
                .collect();
            let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();

            assert_eq!(
                batch_keccak256_scalar(&refs),
                batch_keccak256_dispatch(&refs)
            );
            assert_eq!(
                batch_hash_domain_scalar(b"dom", &refs),
                batch_hash_domain_dispatch(b"dom", &refs)
            );
            assert_eq!(
                batch_hash_leaves_scalar(&refs),
                batch_hash_leaves_dispatch(&refs)
            );
            // Every explicit backend agrees too.
            for b in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                assert_eq!(batch_keccak256(b, &refs), batch_keccak256_scalar(&refs));
            }
        }
    }

    #[test]
    fn never_panics_on_odd_and_empty_payloads() {
        let mut r = Lcg(7);
        for _ in 0..1_000 {
            let count = r.len(9);
            let owned: Vec<Vec<u8>> = (0..count)
                .map(|_| {
                    let n = r.len(33);
                    r.bytes(n)
                })
                .collect();
            let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
            let _ = batch_keccak256_dispatch(&refs);
            let _ = batch_hash_domain_dispatch(b"x", &refs);
            let _ = batch_hash_leaves_dispatch(&refs);
        }
    }
}
