//! Small conversion helpers that avoid narrowing `as` casts.
//!
//! Under `clippy -D warnings` the `cast_possible_truncation` lint is an error, so
//! we never narrow with `as`. These helpers use `TryFrom` with a saturating
//! fallback (never panics) for the widening/narrowing length conversions that
//! pepper index math.

/// Convert a `u64` to `usize`, saturating to `usize::MAX` if it does not fit.
#[inline]
pub(crate) fn as_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Convert a `usize` to `u64`, saturating to `u64::MAX` if it does not fit.
#[inline]
pub(crate) fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
