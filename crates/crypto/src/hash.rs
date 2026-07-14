//! Domain-separated canonical hashing. Byte-canonical and endianness-independent.

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use types::Hash;

// Domain tags live in [`crate::domain`] (single catalog). Re-export the ones
// historically defined here so existing `use crypto::hash::DOMAIN_*` paths keep
// compiling.
pub use crate::domain::{
    DOMAIN_ACCOUNT, DOMAIN_COMMAND, DOMAIN_DECISION, DOMAIN_EXECUTION, DOMAIN_LEAF, DOMAIN_MARKET,
    DOMAIN_NODE, DOMAIN_ORACLE, DOMAIN_VALIDATOR_SET,
};

fn finalize(h: Sha256) -> Hash {
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Hash::from_bytes(bytes)
}

/// Length-prefixed, domain-separated SHA-256 over `data`. Distinct domains can
/// never collide because each field is length-prefixed.
pub fn hash_domain(domain: &[u8], data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    finalize(h)
}

/// Length-prefixed domain hash over logically concatenated borrowed parts.
/// Produces bytes identical to [`hash_domain`] over their concatenation without
/// allocating a temporary buffer.
pub fn hash_domain_parts(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let total_len = parts.iter().fold(0u64, |total, part| {
        total.saturating_add(u64::try_from(part.len()).unwrap_or(u64::MAX))
    });
    let mut h = Sha256::new();
    h.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    h.update(domain);
    h.update(total_len.to_le_bytes());
    for part in parts {
        h.update(part);
    }
    finalize(h)
}

/// Hash a Merkle leaf payload.
pub fn hash_leaf(data: &[u8]) -> Hash {
    hash_domain(DOMAIN_LEAF, data)
}

/// Combine two child hashes into a parent (order-sensitive, domain-separated).
///
/// Routes through [`hash_domain`] with [`DOMAIN_NODE`] over the concatenation of
/// the two 32-byte children (64 bytes total). Length-prefixing on the domain and
/// data fields matches every other domain-separated hash in this crate and
/// prevents concatenation ambiguity with other domain tags.
pub fn hash_node(left: Hash, right: Hash) -> Hash {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left.as_bytes());
    data[32..].copy_from_slice(right.as_bytes());
    hash_domain(DOMAIN_NODE, &data)
}

/// Keccak-256, for EVM-style message digests.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let out = Keccak256::digest(data);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation_prevents_collision() {
        // Same data, different domains -> different hashes.
        assert_ne!(
            hash_domain(DOMAIN_ACCOUNT, b"x"),
            hash_domain(DOMAIN_MARKET, b"x")
        );
        // Length prefixing prevents concatenation ambiguity.
        assert_ne!(hash_domain(b"ab", b"c"), hash_domain(b"a", b"bc"));
    }

    #[test]
    fn hashing_is_deterministic_and_canonical() {
        assert_eq!(hash_leaf(b"hello"), hash_leaf(b"hello"));
        assert_ne!(hash_leaf(b"hello"), hash_leaf(b"world"));
        // Known-answer: keccak256("") is the well-known empty digest.
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn hash_node_uses_length_prefixed_domain_over_64_byte_children() {
        let left = Hash::from_bytes([1u8; 32]);
        let right = Hash::from_bytes([2u8; 32]);
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(left.as_bytes());
        data[32..].copy_from_slice(right.as_bytes());
        assert_eq!(hash_node(left, right), hash_domain(DOMAIN_NODE, &data));
        // Order-sensitive.
        assert_ne!(hash_node(left, right), hash_node(right, left));
        // Distinct from a raw leaf over the same bytes.
        assert_ne!(hash_node(left, right), hash_leaf(&data));
    }

    #[test]
    fn borrowed_parts_are_identical_to_concatenation() {
        let mut joined = Vec::new();
        joined.extend_from_slice(b"alpha");
        joined.extend_from_slice(b"beta");
        assert_eq!(
            hash_domain_parts(b"domain", &[b"alpha", b"beta"]),
            hash_domain(b"domain", &joined)
        );
    }
}
