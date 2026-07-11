//! Integer-only statistical primitives used by aggregation.
//!
//! No floating point. Medians use the deterministic *lower median* convention
//! (element at index `(n-1)/2` of the ascending sort) so results are exact
//! integers and never require averaging two central values.

use types::{Ratio, RATIO_SCALE};

/// A single price sample with a non-negative weight (confidence / liquidity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sample {
    /// Raw price value (`Price::raw()`).
    pub price: i64,
    /// Weight; negative weights are clamped to zero when aggregating.
    pub weight: i128,
}

/// Lower median of an ascending-sorted slice. `None` if empty.
pub(crate) fn lower_median<T: Copy>(sorted: &[T]) -> Option<T> {
    if sorted.is_empty() {
        return None;
    }
    Some(sorted[(sorted.len() - 1) / 2])
}

/// Weight-weighted median of `samples` (order-independent). Falls back to the
/// unweighted lower median of prices when the total weight is non-positive.
/// `None` only if `samples` is empty.
pub(crate) fn weighted_median(samples: &[Sample]) -> Option<i64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted: Vec<Sample> = samples.to_vec();
    sorted.sort_by(|a, b| a.price.cmp(&b.price).then(a.weight.cmp(&b.weight)));

    let total: i128 = sorted
        .iter()
        .fold(0i128, |acc, s| acc.saturating_add(s.weight.max(0)));

    if total <= 0 {
        // No usable weight: unweighted lower median of the (already sorted) prices.
        return Some(sorted[(sorted.len() - 1) / 2].price);
    }

    let mut acc: i128 = 0;
    for s in &sorted {
        acc = acc.saturating_add(s.weight.max(0));
        // `acc * 2 >= total`, rearranged to avoid overflow (both sides ≥ 0, acc ≤ total).
        if acc >= total - acc {
            return Some(s.price);
        }
    }
    // Unreachable in practice; return the largest as a safe default.
    sorted.last().map(|s| s.price)
}

/// Median absolute deviation from `center`, computed in `i128` so that
/// `price - center` can never overflow `i64`.
pub(crate) fn median_absolute_deviation(prices: &[i64], center: i64) -> i128 {
    if prices.is_empty() {
        return 0;
    }
    let mut devs: Vec<i128> = prices
        .iter()
        .map(|&p| (i128::from(p) - i128::from(center)).abs())
        .collect();
    devs.sort_unstable();
    lower_median(&devs).unwrap_or(0)
}

/// Scale a deviation value by ratio `k` (`k * value`), rounding toward zero.
/// Saturates rather than overflowing.
pub(crate) fn scale_by_ratio(value: i128, k: Ratio) -> i128 {
    value
        .saturating_mul(i128::from(k.raw()))
        .saturating_div(i128::from(RATIO_SCALE))
}

/// Relative dispersion of `mad` around `center`, in basis points (`mad/|center| * 10_000`).
/// Returns `i64::MAX` when `center` is zero (undefined / maximally dispersed).
pub(crate) fn dispersion_bps(mad: i128, center: i64) -> i64 {
    if center == 0 {
        return i64::MAX;
    }
    let denom = i128::from(center).abs();
    let bps = mad.saturating_mul(10_000).saturating_div(denom);
    i64::try_from(bps).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_median_odd_and_even() {
        assert_eq!(lower_median(&[1, 2, 3]), Some(2));
        // even length -> lower of the two central values (index (4-1)/2 = 1)
        assert_eq!(lower_median(&[1, 2, 3, 4]), Some(2));
        assert_eq!(lower_median::<i64>(&[]), None);
    }

    #[test]
    fn weighted_median_hand_computed() {
        // prices 10,20,30 with weights 1,1,5 -> mass concentrates at 30.
        let s = [
            Sample {
                price: 10,
                weight: 1,
            },
            Sample {
                price: 20,
                weight: 1,
            },
            Sample {
                price: 30,
                weight: 5,
            },
        ];
        assert_eq!(weighted_median(&s), Some(30));
        // equal weights -> ordinary lower median.
        let s2 = [
            Sample {
                price: 10,
                weight: 2,
            },
            Sample {
                price: 20,
                weight: 2,
            },
            Sample {
                price: 30,
                weight: 2,
            },
        ];
        assert_eq!(weighted_median(&s2), Some(20));
    }

    #[test]
    fn weighted_median_is_permutation_invariant() {
        let base = [
            Sample {
                price: 5,
                weight: 3,
            },
            Sample {
                price: 7,
                weight: 1,
            },
            Sample {
                price: 9,
                weight: 4,
            },
            Sample {
                price: 2,
                weight: 2,
            },
        ];
        let mut rev = base;
        rev.reverse();
        assert_eq!(weighted_median(&base), weighted_median(&rev));
    }

    #[test]
    fn mad_hand_computed() {
        // prices 2,4,6,8,10 median 6; deviations 4,2,0,2,4 sorted 0,2,2,4,4 -> median 2.
        assert_eq!(median_absolute_deviation(&[2, 4, 6, 8, 10], 6), 2);
    }

    #[test]
    fn zero_weight_falls_back_to_unweighted() {
        let s = [
            Sample {
                price: 100,
                weight: 0,
            },
            Sample {
                price: 200,
                weight: 0,
            },
            Sample {
                price: 300,
                weight: 0,
            },
        ];
        assert_eq!(weighted_median(&s), Some(200));
    }
}
