//! The single audited money/byte converter shared by every language binding.
//!
//! `i128` (the [`Amount`] repr) has no `wasm-bindgen` support and no natural JS
//! number, so money crosses the FFI boundary as a canonical fixed-6dp decimal
//! string produced by exactly one function. Every binding calls through here;
//! `conformance/vectors.json` pins the string form so no language can drift.

use types::{format_amount, parse_amount, Amount};

/// `i128` has no wasm-bindgen support -> cross as a canonical fixed-6dp decimal
/// string. ONE site. Verified: `format_amount` is fixed 6dp -> `"1.500000"`,
/// `"-0.000001"`, `"0.000000"` (crates/types/src/decimal.rs).
pub fn amount_to_decimal(a: Amount) -> String {
    format_amount(a) // e.g. Amount::from_raw(1_500_000) -> "1.500000"
}

/// Parse a decimal string (max 6 fractional digits) back to an [`Amount`].
pub fn amount_from_decimal(s: &str) -> Result<Amount, &'static str> {
    parse_amount(s).map_err(|_| "invalid decimal amount (max 6 fractional digits)")
}

/// Validate a slice back to a fixed 32-byte array (seeds, pubkeys, hashes).
pub fn bytes32(v: &[u8]) -> Result<[u8; 32], &'static str> {
    <[u8; 32]>::try_from(v).map_err(|_| "expected 32 bytes")
}

/// Validate a slice back to a fixed 64-byte array (ed25519 signatures).
pub fn bytes64(v: &[u8]) -> Result<[u8; 64], &'static str> {
    <[u8; 64]>::try_from(v).map_err(|_| "expected 64 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_six_dp_is_canonical() {
        assert_eq!(amount_to_decimal(Amount::from_raw(1_500_000)), "1.500000");
        assert_eq!(amount_from_decimal("1.5").unwrap(), Amount::from_raw(1_500_000));
        assert_eq!(amount_to_decimal(Amount::from_raw(-1)), "-0.000001");
        assert_eq!(amount_to_decimal(Amount::from_raw(0)), "0.000000");
    }

    #[test]
    fn byte_arrays_validate_length() {
        assert!(bytes32(&[0u8; 32]).is_ok());
        assert!(bytes32(&[0u8; 31]).is_err());
        assert!(bytes64(&[0u8; 64]).is_ok());
        assert!(bytes64(&[0u8; 63]).is_err());
    }
}
