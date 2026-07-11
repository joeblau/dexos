//! Small conservative fixed-point helpers shared across risk modules.
//!
//! Every helper is integer-only and total: it returns [`RiskError::Arith`]
//! instead of panicking at the `i128` boundary. Rounding, where it occurs,
//! defers to the `types` primitives (toward zero) which is conservative for the
//! protocol because it never over-credits a trader.

use types::{Amount, ArithError};

use crate::error::RiskError;

/// Absolute value of an [`Amount`], erroring at `i128::MIN` rather than
/// wrapping to a negative value.
#[inline]
pub(crate) fn abs_amount(a: Amount) -> Result<Amount, RiskError> {
    if a.is_negative() {
        Amount::ZERO.checked_sub(a).map_err(RiskError::from)
    } else {
        Ok(a)
    }
}

/// Negate an [`Amount`], erroring at `i128::MIN`.
#[inline]
pub(crate) fn neg_amount(a: Amount) -> Result<Amount, RiskError> {
    Amount::ZERO
        .checked_sub(a)
        .map_err(|_| RiskError::Arith(ArithError::Overflow))
}

/// The larger of two amounts.
#[inline]
pub(crate) fn max_amount(a: Amount, b: Amount) -> Amount {
    if a.raw() >= b.raw() {
        a
    } else {
        b
    }
}

/// The smaller of two amounts.
#[inline]
pub(crate) fn min_amount(a: Amount, b: Amount) -> Amount {
    if a.raw() <= b.raw() {
        a
    } else {
        b
    }
}
