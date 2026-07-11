//! Small dependency-free helpers: a stable content hash and JSON string escaping.
//!
//! The hash is FNV-1a (64-bit). It is used to fold a generated command stream into a
//! single fingerprint so reproduction tests can assert two seeded runs are identical,
//! and to derive stable dedup keys. It is not collision-resistant and must never be
//! used where the cryptographic `crypto` crate is appropriate.

/// FNV-1a 64-bit offset basis.
const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

/// Compute the FNV-1a 64-bit hash of `bytes`.
#[must_use]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Fold a `u64` into an existing running hash (order-sensitive).
#[must_use]
pub fn fold_u64(acc: u64, value: u64) -> u64 {
    let mut h = acc;
    for &b in &value.to_le_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Escape a string for inclusion in a JSON document.
#[must_use]
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Control characters escape as \u00XX.
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_known_vector() {
        // FNV-1a of the empty string is the offset basis.
        assert_eq!(fnv1a_64(b""), FNV_OFFSET);
        // Distinct inputs hash differently.
        assert_ne!(fnv1a_64(b"a"), fnv1a_64(b"b"));
    }

    #[test]
    fn fold_is_order_sensitive() {
        let a = fold_u64(fold_u64(0, 1), 2);
        let b = fold_u64(fold_u64(0, 2), 1);
        assert_ne!(a, b);
    }

    #[test]
    fn json_escape_handles_specials() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
        assert_eq!(json_escape("\u{0001}"), "\\u0001");
    }
}
