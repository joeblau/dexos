//! Scalar (range) markets: map a resolved value in `[lower, upper]` to a payout
//! fraction using exact fixed-point integer arithmetic (no floating point).

use serde::{Deserialize, Serialize};
use types::{Amount, Ratio, RATIO_SCALE};

/// Scalar payout-computation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScalarError {
    /// `upper` was not strictly greater than `lower`.
    #[error("scalar range requires lower < upper")]
    InvalidRange,
    /// A fixed-point product overflowed `i128`.
    #[error("scalar arithmetic overflow")]
    Overflow,
}

/// An inclusive scalar settlement range `[lower, upper]` with `lower < upper`.
///
/// A resolved value maps to the LONG-outcome fraction
/// `f = (clamp(v) - lower) / (upper - lower)` in `[0, 1]`; the SHORT outcome
/// takes the complement `1 - f`, so the two fractions always sum to exactly 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalarRange {
    lower: Amount,
    upper: Amount,
}

impl ScalarRange {
    /// Construct, requiring `lower < upper`.
    pub fn new(lower: Amount, upper: Amount) -> Result<Self, ScalarError> {
        if lower.raw() >= upper.raw() {
            return Err(ScalarError::InvalidRange);
        }
        Ok(Self { lower, upper })
    }

    /// The lower bound.
    #[inline]
    pub fn lower(&self) -> Amount {
        self.lower
    }

    /// The upper bound.
    #[inline]
    pub fn upper(&self) -> Amount {
        self.upper
    }

    /// The LONG-outcome payout fraction for a resolved value.
    ///
    /// Values outside `[lower, upper]` clamp deterministically to the bound. The
    /// division floors toward zero; the discarded sub-micro-unit is at most one
    /// `Ratio` unit and is recovered by the SHORT complement in [`Self::fractions`].
    pub fn long_fraction(&self, value: Amount) -> Result<Ratio, ScalarError> {
        let lo = self.lower.raw();
        let hi = self.upper.raw();
        // Guard the invariant explicitly: a value deserialized straight from bytes
        // bypasses `new`, so `lower < upper` is re-checked here to keep `clamp`
        // (which panics when `min > max`) and the division safe.
        if lo >= hi {
            return Err(ScalarError::InvalidRange);
        }
        // Clamp into range (deterministic saturation at the bounds).
        let v = value.raw().clamp(lo, hi);
        let span = hi.checked_sub(lo).ok_or(ScalarError::Overflow)?;
        // `span > 0` guaranteed by construction.
        let numer = v
            .checked_sub(lo)
            .ok_or(ScalarError::Overflow)?
            .checked_mul(i128::from(RATIO_SCALE))
            .ok_or(ScalarError::Overflow)?;
        let raw = numer / span; // floor toward zero; numer >= 0, span > 0
        let raw = i64::try_from(raw).map_err(|_| ScalarError::Overflow)?;
        Ok(Ratio::from_raw(raw))
    }

    /// The fraction pair for a resolved value in canonical
    /// [`types::ScalarOutcome`] order: `[LONG, SHORT]` (LONG at index 0, SHORT at
    /// index 1). The pair always sums to exactly `RATIO_SCALE` (1.0) — the SHORT
    /// side absorbs any floor remainder, guaranteeing value conservation.
    pub fn fractions(&self, value: Amount) -> Result<[Ratio; 2], ScalarError> {
        let long = self.long_fraction(value)?;
        let short = Ratio::from_raw(RATIO_SCALE - long.raw());
        Ok([long, short])
    }
}
