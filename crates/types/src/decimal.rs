//! Non-hot-path stablecoin decimal parsing and formatting at 6-decimal scale.
//!
//! This is for RPC/config/display boundaries only — never called from the
//! deterministic hot path. Integer-only: parsing builds an `i128` with checked
//! arithmetic; over-precision or overflowing input is rejected, never truncated.

use crate::fixed::{Amount, AMOUNT_SCALE};

/// Number of fractional decimal places for stablecoin amounts.
pub const DECIMALS: u32 = 6;

/// A decimal parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecimalError {
    /// The string was empty or structurally invalid.
    #[error("malformed decimal")]
    Malformed,
    /// More than [`DECIMALS`] fractional digits were supplied.
    #[error("too many fractional digits (max {DECIMALS})")]
    TooPrecise,
    /// The value overflows [`Amount`].
    #[error("decimal value out of range")]
    Overflow,
}

/// Parse a decimal string (e.g. `"1234.560000"`, `"-0.5"`, `"42"`) into an
/// [`Amount`] at 6-dp scale. Rejects malformed, over-precision, and overflowing
/// input with a typed error — never panics, never truncates.
pub fn parse_amount(s: &str) -> Result<Amount, DecimalError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(DecimalError::Malformed);
    }
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if rest.is_empty() {
        return Err(DecimalError::Malformed);
    }
    let (int_part, frac_part) = match rest.split_once('.') {
        Some((i, f)) => (i, f),
        None => (rest, ""),
    };
    // Integer part may be empty only if there is a fractional part (".5").
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(DecimalError::Malformed);
    }
    if frac_part.len() > DECIMALS as usize {
        return Err(DecimalError::TooPrecise);
    }
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(DecimalError::Malformed);
    }

    let mut units: i128 = 0;
    for b in int_part.bytes() {
        units = units
            .checked_mul(10)
            .and_then(|u| u.checked_add(i128::from(b - b'0')))
            .ok_or(DecimalError::Overflow)?;
    }
    units = units
        .checked_mul(AMOUNT_SCALE)
        .ok_or(DecimalError::Overflow)?;

    // Right-pad the fractional part to DECIMALS, then add.
    let mut frac: i128 = 0;
    for i in 0..DECIMALS as usize {
        let digit = frac_part
            .as_bytes()
            .get(i)
            .map(|b| i128::from(b - b'0'))
            .unwrap_or(0);
        frac = frac * 10 + digit;
    }
    units = units.checked_add(frac).ok_or(DecimalError::Overflow)?;

    Ok(Amount::from_raw(if neg { -units } else { units }))
}

/// Format an [`Amount`] as a fixed 6-dp decimal string (canonical form).
pub fn format_amount(amount: Amount) -> String {
    let raw = amount.raw();
    let neg = raw < 0;
    // Use unsigned magnitude to avoid overflow at i128::MIN.
    let mag = raw.unsigned_abs();
    let scale = AMOUNT_SCALE.unsigned_abs();
    let int = mag / scale;
    let frac = mag % scale;
    format!("{}{}.{:06}", if neg { "-" } else { "" }, int, frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_format_round_trip() {
        for s in [
            "0.000000",
            "1.000000",
            "1234.560000",
            "-0.500000",
            "42.000000",
        ] {
            let a = parse_amount(s).unwrap();
            assert_eq!(format_amount(a), s);
        }
    }

    #[test]
    fn parse_accepts_shorthands() {
        assert_eq!(parse_amount("42").unwrap(), Amount::from_raw(42_000_000));
        assert_eq!(parse_amount(".5").unwrap(), Amount::from_raw(500_000));
        assert_eq!(parse_amount("+1.5").unwrap(), Amount::from_raw(1_500_000));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(parse_amount(""), Err(DecimalError::Malformed));
        assert_eq!(parse_amount("abc"), Err(DecimalError::Malformed));
        assert_eq!(parse_amount("1.2.3"), Err(DecimalError::Malformed));
        assert_eq!(parse_amount("1.2345678"), Err(DecimalError::TooPrecise));
        assert_eq!(parse_amount("-"), Err(DecimalError::Malformed));
        // Huge integer part overflows i128.
        assert_eq!(parse_amount(&"9".repeat(60)), Err(DecimalError::Overflow));
    }

    #[test]
    fn golden_values() {
        assert_eq!(format_amount(Amount::from_raw(1_500_000)), "1.500000");
        assert_eq!(format_amount(Amount::from_raw(-1)), "-0.000001");
        assert_eq!(format_amount(Amount::ZERO), "0.000000");
    }

    #[test]
    fn parser_never_panics_on_arbitrary_bytes() {
        let mut state: u64 = 0xabcd_1234;
        for _ in 0..20_000 {
            let mut buf = String::new();
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = usize::try_from(state % 24).unwrap();
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let byte = u8::try_from(state % 96).unwrap() + 0x20;
                buf.push(char::from(byte));
            }
            let _ = parse_amount(&buf);
        }
    }
}
