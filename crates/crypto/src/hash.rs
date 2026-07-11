//! Domain-separated canonical hashing. Byte-canonical and endianness-independent.

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use types::Hash;

/// Domain tag for a Merkle leaf.
pub const DOMAIN_LEAF: &[u8] = b"dexos:leaf:v1";
/// Domain tag for a Merkle internal node.
pub const DOMAIN_NODE: &[u8] = b"dexos:node:v1";
/// Domain tag for a per-account commitment.
pub const DOMAIN_ACCOUNT: &[u8] = b"dexos:account:v1";
/// Domain tag for a per-market commitment.
pub const DOMAIN_MARKET: &[u8] = b"dexos:market:v1";
/// Domain tag for a command.
pub const DOMAIN_COMMAND: &[u8] = b"dexos:command:v1";
/// Domain tag for an execution receipt.
pub const DOMAIN_EXECUTION: &[u8] = b"dexos:execution:v1";
/// Domain tag for an oracle observation.
pub const DOMAIN_ORACLE: &[u8] = b"dexos:oracle:v1";

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

/// Hash a Merkle leaf payload.
pub fn hash_leaf(data: &[u8]) -> Hash {
    hash_domain(DOMAIN_LEAF, data)
}

/// Combine two child hashes into a parent (order-sensitive, domain-separated).
pub fn hash_node(left: Hash, right: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(DOMAIN_NODE);
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    finalize(h)
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
}
