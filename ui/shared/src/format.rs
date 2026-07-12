//! Integer-only formatting for the fixed-point wire scalars.
//!
//! The wire types carry `Price`/`Quantity` as scaled integers (see
//! `types::fixed`). Rendering them must not route through `f64` — a float would
//! reintroduce exactly the rounding nondeterminism the engine forbids — so these
//! helpers build the decimal string directly from the raw integer and its scale.

use types::{Price, Quantity, PRICE_SCALE, QTY_SCALE};

/// Format a raw scaled integer against `scale` (a power of ten) as a fixed
/// decimal string, e.g. `raw = 123_450_000`, `scale = 1_000_000` → `"123.45"`.
///
/// Trailing zeros in the fractional part are trimmed; an all-zero fraction drops
/// the decimal point entirely. Negative values keep their sign.
fn format_scaled(raw: i128, scale: i64) -> String {
    debug_assert!(scale > 0, "scale must be positive");
    let scale = i128::from(scale);
    let negative = raw < 0;
    let magnitude = raw.unsigned_abs();
    let scale_mag = scale.unsigned_abs();
    let int_part = magnitude / scale_mag;
    let frac_part = magnitude % scale_mag;

    let sign = if negative { "-" } else { "" };
    if frac_part == 0 {
        return format!("{sign}{int_part}");
    }

    // Width of the fractional field is the number of decimal digits in `scale`
    // (10^n has n+1 chars → n zeros); pad the fraction to that width, then trim.
    let width = scale_mag.to_string().len() - 1;
    let frac = format!("{frac_part:0>width$}");
    let frac = frac.trim_end_matches('0');
    format!("{sign}{int_part}.{frac}")
}

/// Render a [`Price`] as a decimal string (quote per base unit).
pub fn price(p: Price) -> String {
    format_scaled(i128::from(p.raw()), PRICE_SCALE)
}

/// Render a [`Quantity`] as a decimal string (base units).
pub fn quantity(q: Quantity) -> String {
    format_scaled(i128::from(q.raw()), QTY_SCALE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_numbers_drop_the_fraction() {
        assert_eq!(price(Price::ONE), "1");
        assert_eq!(quantity(Quantity::ZERO), "0");
        assert_eq!(price(Price::from_raw(42 * PRICE_SCALE)), "42");
    }

    #[test]
    fn fractional_values_trim_trailing_zeros() {
        // 123.45 at PRICE_SCALE (1e6) = 123_450_000 raw.
        assert_eq!(price(Price::from_raw(123_450_000)), "123.45");
        // One millionth is the smallest representable price step.
        assert_eq!(price(Price::from_raw(1)), "0.000001");
    }

    #[test]
    fn negatives_keep_their_sign() {
        assert_eq!(price(Price::from_raw(-1_500_000)), "-1.5");
        assert_eq!(quantity(Quantity::from_raw(-QTY_SCALE)), "-1");
    }
}
