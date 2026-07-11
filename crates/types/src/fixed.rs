//! Fixed-point integer scalar types.
//!
//! All monetary and market quantities are integers at a fixed decimal scale.
//! There is no floating point anywhere in this module. Every fallible operation
//! returns [`ArithError`] rather than panicking or silently truncating.
//!
//! | Type       | Repr | Scale (units per 1.0) | Meaning                    |
//! |------------|------|-----------------------|----------------------------|
//! | [`Price`]  | i64  | 1_000_000 (6 dp)      | quote currency per 1 base  |
//! | [`Quantity`]| i64 | 1_000_000 (6 dp)      | base units                 |
//! | [`Amount`] | i128 | 1_000_000 (6 dp)      | stablecoin micro-units     |
//! | [`Ratio`]  | i64  | 1_000_000 (6 dp)      | dimensionless fraction     |

use serde::{Deserialize, Serialize};

/// Decimal scale for [`Price`] (6 decimal places).
pub const PRICE_SCALE: i64 = 1_000_000;
/// Decimal scale for [`Quantity`] (6 decimal places).
pub const QTY_SCALE: i64 = 1_000_000;
/// Decimal scale for [`Amount`] (6 decimal places — USDC-like).
pub const AMOUNT_SCALE: i128 = 1_000_000;
/// Decimal scale for [`Ratio`] (6 decimal places; `1_000_000` == 1.0).
pub const RATIO_SCALE: i64 = 1_000_000;

/// A fixed-point arithmetic failure. Returned instead of panicking or truncating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArithError {
    /// The result did not fit in the destination integer type.
    #[error("fixed-point overflow")]
    Overflow,
    /// Division (or ratio application) by zero.
    #[error("division by zero")]
    DivByZero,
    /// A widening/narrowing conversion would lose information.
    #[error("value does not fit destination type")]
    OutOfRange,
}

macro_rules! define_scalar {
    ($name:ident, $repr:ty, $scale:expr, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Integer-only fixed-point value. See the module table for its scale.
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Default,
            Serialize,
            Deserialize,
        )]
        #[repr(transparent)]
        #[serde(transparent)]
        pub struct $name(pub $repr);

        impl $name {
            /// The additive identity (0.0).
            pub const ZERO: Self = Self(0);
            /// The value 1.0 at this type's scale.
            pub const ONE: Self = Self($scale);
            /// The most negative representable value.
            pub const MIN: Self = Self(<$repr>::MIN);
            /// The largest representable value.
            pub const MAX: Self = Self(<$repr>::MAX);

            /// Construct from raw scaled units.
            #[inline]
            pub const fn from_raw(raw: $repr) -> Self {
                Self(raw)
            }

            /// The raw scaled integer.
            #[inline]
            pub const fn raw(self) -> $repr {
                self.0
            }

            /// True if strictly less than zero.
            #[inline]
            pub const fn is_negative(self) -> bool {
                self.0 < 0
            }

            /// Checked addition. `Err(Overflow)` on wrap.
            #[inline]
            pub fn checked_add(self, rhs: Self) -> Result<Self, ArithError> {
                self.0
                    .checked_add(rhs.0)
                    .map(Self)
                    .ok_or(ArithError::Overflow)
            }

            /// Checked subtraction. `Err(Overflow)` on wrap.
            #[inline]
            pub fn checked_sub(self, rhs: Self) -> Result<Self, ArithError> {
                self.0
                    .checked_sub(rhs.0)
                    .map(Self)
                    .ok_or(ArithError::Overflow)
            }

            /// Saturating addition (clamps at bounds instead of wrapping).
            #[inline]
            pub const fn saturating_add(self, rhs: Self) -> Self {
                Self(self.0.saturating_add(rhs.0))
            }

            /// Saturating subtraction (clamps at bounds instead of wrapping).
            #[inline]
            pub const fn saturating_sub(self, rhs: Self) -> Self {
                Self(self.0.saturating_sub(rhs.0))
            }
        }
    };
}

define_scalar!(
    Price,
    i64,
    PRICE_SCALE,
    "A price: quote currency per one base unit."
);
define_scalar!(Quantity, i64, QTY_SCALE, "A quantity in base units.");
define_scalar!(
    Amount,
    i128,
    AMOUNT_SCALE,
    "A stablecoin amount in micro-units."
);
define_scalar!(
    Ratio,
    i64,
    RATIO_SCALE,
    "A dimensionless fixed-point ratio (1_000_000 == 1.0)."
);

impl Amount {
    /// Multiply an amount by a [`Ratio`], rounding toward zero (truncation of the
    /// fractional micro-unit). `Err(Overflow)` if the intermediate product does
    /// not fit in `i128`.
    #[inline]
    pub fn mul_ratio(self, ratio: Ratio) -> Result<Amount, ArithError> {
        let product = self
            .0
            .checked_mul(i128::from(ratio.0))
            .ok_or(ArithError::Overflow)?;
        Ok(Amount(product / i128::from(RATIO_SCALE)))
    }

    /// Widen a [`Quantity`] into an [`Amount`] at the same 6-dp scale.
    #[inline]
    pub const fn from_quantity(q: Quantity) -> Amount {
        Amount(q.0 as i128)
    }
}

impl Price {
    /// Notional value of `qty` at this price: `price * qty`, rescaled to
    /// [`Amount`] units and rounded toward zero. Uses `i128` internally so no
    /// intermediate overflow for realistic i64 operands; `Err(Overflow)` only at
    /// extreme magnitudes.
    ///
    /// Scale: `(PRICE_SCALE * QTY_SCALE) / AMOUNT_SCALE == 1_000_000` divisor.
    #[inline]
    pub fn notional(self, qty: Quantity) -> Result<Amount, ArithError> {
        let product = i128::from(self.0)
            .checked_mul(i128::from(qty.0))
            .ok_or(ArithError::Overflow)?;
        // product scale is PRICE_SCALE*QTY_SCALE (1e12); Amount scale is 1e6.
        let divisor = i128::from(PRICE_SCALE) * i128::from(QTY_SCALE) / AMOUNT_SCALE;
        Ok(Amount(product / divisor))
    }
}

impl Ratio {
    /// Build a ratio from a basis-point value (1 bps == 0.0001). 10_000 bps == 1.0.
    #[inline]
    pub fn from_bps(bps: i64) -> Result<Ratio, ArithError> {
        bps.checked_mul(RATIO_SCALE / 10_000)
            .map(Ratio)
            .ok_or(ArithError::Overflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic LCG so "property" tests are reproducible bit-for-bit.
    struct Lcg(u64);
    impl Lcg {
        fn next_i64(&mut self) -> i64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            i64::from_le_bytes(self.0.to_le_bytes())
        }
    }

    #[test]
    fn scale_constants_and_identities() {
        assert_eq!(Price::ONE.raw(), PRICE_SCALE);
        assert_eq!(Amount::ONE.raw(), AMOUNT_SCALE);
        assert_eq!(Amount::ZERO.raw(), 0);
        assert_eq!(Amount::MAX.raw(), i128::MAX);
        assert_eq!(Quantity::MIN.raw(), i64::MIN);
        assert!(Amount(-1).is_negative());
    }

    #[test]
    fn checked_add_saturates_and_errors_at_bounds() {
        assert_eq!(
            Amount::MAX.checked_add(Amount(1)),
            Err(ArithError::Overflow)
        );
        assert_eq!(Amount::MAX.saturating_add(Amount(1)), Amount::MAX);
        assert_eq!(Amount::MIN.saturating_sub(Amount(1)), Amount::MIN);
        assert_eq!(Amount(5).checked_add(Amount(7)), Ok(Amount(12)));
    }

    #[test]
    fn add_is_commutative_over_random_corpus() {
        let mut r = Lcg(0x1234_5678);
        for _ in 0..50_000 {
            let a = Amount(i128::from(r.next_i64()));
            let b = Amount(i128::from(r.next_i64()));
            assert_eq!(a.checked_add(b), b.checked_add(a));
        }
    }

    #[test]
    fn notional_scales_correctly_and_rounds_toward_zero() {
        // price 2.5, qty 4.0 -> 10.0
        let p = Price(2_500_000);
        let q = Quantity(4_000_000);
        assert_eq!(p.notional(q), Ok(Amount(10_000_000)));
        // price 0.000001 (1 micro), qty 0.5 -> 0.0000005 -> rounds to 0
        assert_eq!(Price(1).notional(Quantity(500_000)), Ok(Amount(0)));
    }

    #[test]
    fn mul_ratio_half_and_bps() {
        let half = Ratio(RATIO_SCALE / 2);
        assert_eq!(Amount(10_000_000).mul_ratio(half), Ok(Amount(5_000_000)));
        // 50 bps of 1_000_000 micro (=1.0) is 0.005 = 5000 micro
        let fifty_bps = Ratio::from_bps(50).unwrap();
        assert_eq!(Amount(1_000_000).mul_ratio(fifty_bps), Ok(Amount(5_000)));
    }

    #[test]
    fn arithmetic_never_panics_on_extremes() {
        let mut r = Lcg(0xdead_beef);
        for _ in 0..50_000 {
            let a = Amount(i128::from(r.next_i64()) * i128::from(r.next_i64()));
            let b = Amount(i128::from(r.next_i64()));
            let _ = a.checked_add(b);
            let _ = a.checked_sub(b);
            let _ = a.saturating_add(b);
            let _ = a.mul_ratio(Ratio(r.next_i64()));
        }
        // extremes explicitly
        let _ = Amount::MIN.checked_sub(Amount::MAX);
        let _ = Price::MIN.notional(Quantity::MAX);
    }

    #[test]
    fn deterministic_corpus_is_bit_identical() {
        fn run() -> Vec<i128> {
            let mut r = Lcg(42);
            let mut out = Vec::new();
            for _ in 0..1000 {
                let a = Amount(i128::from(r.next_i64()));
                let b = Amount(i128::from(r.next_i64()));
                out.push(a.saturating_add(b).raw());
            }
            out
        }
        assert_eq!(run(), run());
    }
}
