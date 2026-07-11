//! Payout-fraction model and the resolution kinds that produce one.
//!
//! Every resolution normalizes to a **fraction vector** of length `N` (one
//! `Ratio` per outcome) whose raw values sum to exactly `RATIO_SCALE` (1.0).
//! Because the complete-set invariant makes each outcome's total outstanding
//! claims equal to the locked collateral, a fraction vector summing to 1.0 is
//! exactly value-conserving: `sum_i (collateral * f_i) == collateral`.

use serde::{Deserialize, Serialize};
use types::{Ratio, MAX_OUTCOMES, RATIO_SCALE};

use crate::outcome::{OutcomeId, OutcomeSet};
use crate::scalar::{ScalarError, ScalarRange};

/// Settlement / payout-vector failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettlementError {
    /// A payout vector had zero entries.
    #[error("payout vector must have at least one outcome")]
    Empty,
    /// A payout vector exceeded [`MAX_OUTCOMES`].
    #[error("payout vector exceeds the maximum of {MAX_OUTCOMES} outcomes")]
    TooMany,
    /// A fraction was negative.
    #[error("payout fraction must be non-negative")]
    NegativeFraction,
    /// The fractions summed to more than 1.0 (over-allocation of collateral).
    #[error("payout fractions sum to more than 1.0")]
    OverAllocated,
    /// The vector length did not match the market's outcome count.
    #[error("payout vector length does not match outcome count")]
    Dimension,
    /// A dead-heat set was empty.
    #[error("dead-heat set must name at least one outcome")]
    EmptyDeadHeat,
    /// A referenced outcome was not a member of the set.
    #[error("resolution references an unknown outcome")]
    UnknownOutcome,
    /// A scalar market was not exactly two outcomes.
    #[error("scalar resolution requires a two-outcome market")]
    NotScalarShaped,
    /// A fixed-point operation overflowed.
    #[error("settlement arithmetic overflow")]
    Overflow,
    /// Credits did not conserve the locked collateral (invariant violation).
    #[error("settlement did not conserve locked collateral")]
    NotConserved,
    /// Underlying scalar mapping failed.
    #[error("scalar mapping error: {0}")]
    Scalar(#[from] ScalarError),
}

/// A partial payout vector: a non-negative `Ratio` per outcome whose raw values
/// sum to **at most** `RATIO_SCALE`. Any shortfall `(1.0 - sum)` is refunded
/// equally across all outcomes when [`Self::normalized`] is applied — this is
/// how partial vectors and the invalid (full-refund) case are expressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutFractions {
    fractions: Vec<Ratio>,
}

impl PayoutFractions {
    /// Construct, validating non-empty, bounded length, non-negative entries, and
    /// a total of at most 1.0.
    pub fn new(fractions: Vec<Ratio>) -> Result<Self, SettlementError> {
        if fractions.is_empty() {
            return Err(SettlementError::Empty);
        }
        if fractions.len() > MAX_OUTCOMES {
            return Err(SettlementError::TooMany);
        }
        let mut sum: i128 = 0;
        for f in &fractions {
            if f.raw() < 0 {
                return Err(SettlementError::NegativeFraction);
            }
            sum = sum
                .checked_add(i128::from(f.raw()))
                .ok_or(SettlementError::Overflow)?;
        }
        if sum > i128::from(RATIO_SCALE) {
            return Err(SettlementError::OverAllocated);
        }
        Ok(Self { fractions })
    }

    /// The number of outcomes covered.
    #[inline]
    pub fn len(&self) -> usize {
        self.fractions.len()
    }

    /// Whether the vector is empty (never true for a constructed value).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.fractions.is_empty()
    }

    /// The raw fractions (may sum to less than 1.0).
    #[inline]
    pub fn fractions(&self) -> &[Ratio] {
        &self.fractions
    }

    /// Re-validate an instance (e.g. one produced by deserialization, which
    /// bypasses [`Self::new`]): all fractions non-negative and total at most 1.0.
    pub fn validate(&self) -> Result<(), SettlementError> {
        let mut sum: i128 = 0;
        for f in &self.fractions {
            if f.raw() < 0 {
                return Err(SettlementError::NegativeFraction);
            }
            sum = sum
                .checked_add(i128::from(f.raw()))
                .ok_or(SettlementError::Overflow)?;
        }
        if sum > i128::from(RATIO_SCALE) {
            return Err(SettlementError::OverAllocated);
        }
        Ok(())
    }

    /// Normalize to a fraction vector summing to exactly `RATIO_SCALE`, refunding
    /// any shortfall equally across every outcome (largest-remainder to the first
    /// outcomes so the sum is exact).
    ///
    /// Robust against untrusted input: sums are accumulated in `i128` so a
    /// deserialized instance can never trigger integer-overflow panics. If the
    /// raw total already meets or exceeds 1.0 the fractions are returned as-is
    /// (settlement then rejects any non-conserving vector).
    pub fn normalized(&self) -> Vec<Ratio> {
        let n = self.fractions.len();
        let mut out: Vec<i64> = self.fractions.iter().map(|f| f.raw()).collect();
        let sum: i128 = out.iter().map(|v| i128::from(*v)).sum();
        let shortfall = i128::from(RATIO_SCALE) - sum;
        if shortfall > 0 && n > 0 {
            let n_i128 = i128::try_from(n).unwrap_or(i128::MAX);
            let base = shortfall / n_i128;
            let rem = shortfall - base * n_i128;
            let base_i64 = i64::try_from(base).unwrap_or(0);
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = slot.saturating_add(base_i64);
                // give one extra micro-unit to the first `rem` outcomes
                if i128::try_from(i).unwrap_or(i128::MAX) < rem {
                    *slot = slot.saturating_add(1);
                }
            }
        }
        out.into_iter().map(Ratio::from_raw).collect()
    }
}

/// A market resolution. Each variant maps to a normalized fraction vector via
/// [`Resolution::to_fractions`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// Winner-take-all: the named outcome takes the whole collateral.
    Winner(OutcomeId),
    /// Dead heat: split the collateral equally across the tied outcomes.
    DeadHeat(Vec<OutcomeId>),
    /// An explicit payout vector; any shortfall is refunded equally.
    Vector(PayoutFractions),
    /// A custom payout rule expressed as an explicit vector (semantic alias of
    /// [`Resolution::Vector`]).
    Custom(PayoutFractions),
    /// A scalar market resolving to `value` within `range`.
    Scalar {
        /// The `[lower, upper]` settlement range.
        range: ScalarRange,
        /// The resolved value (clamped into range).
        value: types::Amount,
    },
    /// Invalid resolution: refund complete sets equally (each outcome `1/N`).
    Invalid,
}

impl Resolution {
    /// Produce the normalized fraction vector (raw sum == `RATIO_SCALE`) for this
    /// resolution against `outcomes`.
    pub fn to_fractions(&self, outcomes: &OutcomeSet) -> Result<Vec<Ratio>, SettlementError> {
        let n = outcomes.len();
        match self {
            Resolution::Winner(id) => {
                let idx = outcomes
                    .index_of(*id)
                    .map_err(|_| SettlementError::UnknownOutcome)?;
                Ok(equal_split(RATIO_SCALE, &[idx], n))
            }
            Resolution::DeadHeat(ids) => {
                if ids.is_empty() {
                    return Err(SettlementError::EmptyDeadHeat);
                }
                let mut idxs = Vec::with_capacity(ids.len());
                for id in ids {
                    let idx = outcomes
                        .index_of(*id)
                        .map_err(|_| SettlementError::UnknownOutcome)?;
                    if idxs.contains(&idx) {
                        return Err(SettlementError::UnknownOutcome);
                    }
                    idxs.push(idx);
                }
                idxs.sort_unstable();
                Ok(equal_split(RATIO_SCALE, &idxs, n))
            }
            Resolution::Vector(pf) | Resolution::Custom(pf) => {
                if pf.len() != n {
                    return Err(SettlementError::Dimension);
                }
                // Re-validate: `pf` may have been deserialized (bypassing `new`).
                pf.validate()?;
                Ok(pf.normalized())
            }
            Resolution::Scalar { range, value } => {
                if n != 2 {
                    return Err(SettlementError::NotScalarShaped);
                }
                let [long, short] = range.fractions(*value)?;
                Ok(vec![long, short])
            }
            Resolution::Invalid => {
                let all: Vec<usize> = (0..n).collect();
                Ok(equal_split(RATIO_SCALE, &all, n))
            }
        }
    }
}

/// Distribute `total` raw ratio units equally across the outcome positions in
/// `indices` (assumed unique, sorted, and `< n`), giving one extra unit to the
/// earliest positions so the returned vector's raw sum is exactly `total`.
/// Positions not in `indices` receive zero.
fn equal_split(total: i64, indices: &[usize], n: usize) -> Vec<Ratio> {
    let mut out = vec![0i64; n];
    let k = indices.len();
    if k == 0 {
        return out.into_iter().map(Ratio::from_raw).collect();
    }
    // k <= n <= MAX_OUTCOMES so this fits an i64 exactly.
    let k_i64 = i64::try_from(k).unwrap_or(i64::MAX);
    let base = total / k_i64;
    let rem = total - base * k_i64;
    let rem_us = usize::try_from(rem).unwrap_or(0);
    for (j, &idx) in indices.iter().enumerate() {
        if idx < n {
            out[idx] = base;
            // give one extra micro-unit to the first `rem` positions
            if j < rem_us {
                out[idx] = out[idx].saturating_add(1);
            }
        }
    }
    out.into_iter().map(Ratio::from_raw).collect()
}

/// The synthetic-NO payout fraction for outcome position `i`: `1 - f_i`, i.e. the
/// combined YES fractions of every other outcome. Returns `None` if `i` is out of
/// range.
pub fn no_claim_fraction(normalized: &[Ratio], i: usize) -> Option<Ratio> {
    normalized
        .get(i)
        .map(|f| Ratio::from_raw(RATIO_SCALE - f.raw()))
}
