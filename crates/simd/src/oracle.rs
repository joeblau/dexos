//! Oracle normalization and outlier filtering: integer median / MAD and a
//! lane-structured outlier mask.
//!
//! Given a set of price observations from independent reporters, a robust
//! aggregate rejects outliers using the **median absolute deviation** (MAD): the
//! median of `|xᵢ − median|`. An observation is flagged when its deviation
//! exceeds `k · MAD`. Everything here is integer-only:
//!
//! * The **median** is the lower median (element at index `(n − 1) / 2` after a
//!   stable ordering) — deterministic and free of averaging/rounding.
//! * Deviations are computed in `i128` so `|i64::MIN − center|` cannot overflow.
//! * The **outlier mask** is a pure per-element map, so its vectorized form is
//!   bit-identical to the scalar reference for free.

use crate::backend::Backend;

/// Number of independent lanes in the vectorized mask computation.
const LANES: usize = 8;

/// The lower median of `vals` (index `(n − 1) / 2` after sorting). `None` if empty.
pub fn median_i64(vals: &[i64]) -> Option<i64> {
    if vals.is_empty() {
        return None;
    }
    let mut sorted = vals.to_vec();
    sorted.sort_unstable();
    Some(sorted[(sorted.len() - 1) / 2])
}

/// Median absolute deviation about the lower median. Computed in `i128` to hold
/// the full deviation range. `None` if `vals` is empty.
pub fn mad_i64(vals: &[i64]) -> Option<i128> {
    let center = median_i64(vals)?;
    let mut dev: Vec<i128> = vals.iter().map(|&x| abs_dev(x, center)).collect();
    dev.sort_unstable();
    Some(dev[(dev.len() - 1) / 2])
}

/// `|x − center|` widened to `i128` so `i64::MIN` inputs never overflow.
#[inline]
fn abs_dev(x: i64, center: i64) -> i128 {
    (i128::from(x) - i128::from(center)).abs()
}

/// Scalar reference outlier mask: `mask[i] == (|vals[i] − center| > max_dev)`.
#[must_use]
pub fn outlier_mask_scalar(vals: &[i64], center: i64, max_dev: i128) -> Vec<bool> {
    let mut out = Vec::with_capacity(vals.len());
    for &x in vals {
        out.push(abs_dev(x, center) > max_dev);
    }
    out
}

/// Vectorized outlier mask. Lane-structured over `LANES` elements at a time;
/// bit-identical to [`outlier_mask_scalar`] because each output element is an
/// independent, side-effect-free function of one input element.
#[must_use]
pub fn outlier_mask_vectorized(vals: &[i64], center: i64, max_dev: i128) -> Vec<bool> {
    let mut out = vec![false; vals.len()];
    let mut chunks = vals.chunks_exact(LANES);
    let mut base = 0usize;
    for chunk in &mut chunks {
        // A fixed-width inner loop the optimizer can lower to vector compares.
        let mut lane_out = [false; LANES];
        for lane in 0..LANES {
            lane_out[lane] = abs_dev(chunk[lane], center) > max_dev;
        }
        out[base..base + LANES].copy_from_slice(&lane_out);
        base += LANES;
    }
    for (offset, &x) in chunks.remainder().iter().enumerate() {
        out[base + offset] = abs_dev(x, center) > max_dev;
    }
    out
}

/// Compute the outlier mask via an explicitly chosen [`Backend`].
#[must_use]
pub fn outlier_mask(backend: Backend, vals: &[i64], center: i64, max_dev: i128) -> Vec<bool> {
    if backend.is_vectorized() {
        outlier_mask_vectorized(vals, center, max_dev)
    } else {
        outlier_mask_scalar(vals, center, max_dev)
    }
}

/// Compute the outlier mask on the best available backend.
#[must_use]
pub fn outlier_mask_dispatch(vals: &[i64], center: i64, max_dev: i128) -> Vec<bool> {
    outlier_mask(crate::detect(), vals, center, max_dev)
}

/// Result of a full robust-filter pass over a set of observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleFilter {
    /// The lower median used as the robust center.
    pub median: i64,
    /// The median absolute deviation about `median`.
    pub mad: i128,
    /// The acceptance threshold `k · MAD` (saturating).
    pub threshold: i128,
    /// Per-observation outlier flags (true == rejected).
    pub outliers: Vec<bool>,
}

/// End-to-end normalization: compute the median, MAD, threshold `k · MAD`, and
/// the outlier mask via `backend`. Returns `None` for an empty observation set.
///
/// `k` is a non-negative integer multiplier; the threshold uses
/// [`i128::saturating_mul`] so a huge MAD cannot overflow. A negative `k` is
/// treated as `0` (nothing is outside a zero threshold except strictly positive
/// deviations), keeping the function total.
pub fn filter_outliers(backend: Backend, vals: &[i64], k: i128) -> Option<OracleFilter> {
    let median = median_i64(vals)?;
    let mad = mad_i64(vals)?;
    let threshold = mad.saturating_mul(k.max(0));
    let outliers = outlier_mask(backend, vals, median, threshold);
    Some(OracleFilter {
        median,
        mad,
        threshold,
        outliers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn i64(&mut self) -> i64 {
            i64::from_le_bytes(self.next().to_le_bytes())
        }
        fn len(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % (bound as u64 + 1)).unwrap_or(0)
        }
    }

    #[test]
    fn hand_computed_median_and_mad() {
        // sorted: [1,2,3,4,100]; lower median index (5-1)/2 = 2 -> 3.
        let vals = [3i64, 1, 100, 2, 4];
        assert_eq!(median_i64(&vals), Some(3));
        // deviations |x-3|: [0,2,97,1,1] sorted [0,1,1,2,97]; median idx 2 -> 1.
        assert_eq!(mad_i64(&vals), Some(1));
        // even length lower median: [10,20,30,40] -> index (4-1)/2=1 -> 20.
        assert_eq!(median_i64(&[40, 10, 30, 20]), Some(20));
    }

    #[test]
    fn hand_computed_outlier_mask() {
        let vals = [10i64, 11, 9, 1000, 12];
        let mask = outlier_mask_scalar(&vals, 11, 5);
        assert_eq!(mask, vec![false, false, false, true, false]);
        assert_eq!(outlier_mask_vectorized(&vals, 11, 5), mask);
    }

    #[test]
    fn filter_flags_the_expected_candidate() {
        let vals = [100i64, 101, 99, 100, 5_000];
        let f = filter_outliers(Backend::Scalar, &vals, 3).unwrap();
        // Only the 5_000 reporter should be rejected.
        assert_eq!(f.outliers, vec![false, false, false, false, true]);
        // Same verdict under a vector backend.
        assert_eq!(filter_outliers(Backend::Neon, &vals, 3).unwrap(), f);
    }

    #[test]
    fn empty_returns_none_everywhere() {
        assert!(median_i64(&[]).is_none());
        assert!(mad_i64(&[]).is_none());
        assert!(filter_outliers(Backend::Avx512, &[], 3).is_none());
        assert!(outlier_mask_scalar(&[], 0, 0).is_empty());
        assert!(outlier_mask_vectorized(&[], 0, 0).is_empty());
    }

    #[test]
    fn saturation_boundary_min_center() {
        // i64::MIN vs a positive center must not overflow (i128 widening).
        let vals = [i64::MIN, i64::MAX, 0];
        let f = filter_outliers(Backend::Avx2, &vals, i128::MAX).unwrap();
        // Threshold saturates but stays finite; no panic, mask well-defined.
        assert_eq!(f.outliers.len(), 3);
    }

    #[test]
    fn scalar_vs_vectorized_bit_identical_over_lcg_corpus() {
        let mut r = Lcg(0xfeed_face_cafe_babe);
        for _ in 0..5_000 {
            let n = r.len(200);
            let vals: Vec<i64> = (0..n).map(|_| r.i64()).collect();
            let center = r.i64();
            let max_dev = i128::from(r.i64());
            assert_eq!(
                outlier_mask_scalar(&vals, center, max_dev),
                outlier_mask_vectorized(&vals, center, max_dev),
                "mask divergence at len {n}"
            );
            // Full filter equivalence across backends.
            let k = i128::from(r.next() % 8);
            assert_eq!(
                filter_outliers(Backend::Scalar, &vals, k),
                filter_outliers(Backend::Avx512, &vals, k),
            );
        }
    }

    #[test]
    fn all_lengths_across_lane_boundary_match() {
        let mut r = Lcg(5);
        for n in 0..(LANES * 4 + 3) {
            let vals: Vec<i64> = (0..n).map(|_| r.i64()).collect();
            assert_eq!(
                outlier_mask_scalar(&vals, 0, 1000),
                outlier_mask_vectorized(&vals, 0, 1000),
                "len {n}"
            );
        }
    }

    #[test]
    fn negative_test_wrong_mask_is_detected() {
        // A deliberately inverted comparison must diverge from the reference.
        fn wrong(vals: &[i64], center: i64, max_dev: i128) -> Vec<bool> {
            vals.iter()
                .map(|&x| abs_dev(x, center) >= max_dev)
                .collect()
        }
        let vals = [0i64, 5, 10];
        // With max_dev == 5, element at deviation exactly 5 differs: > vs >=.
        assert_ne!(outlier_mask_scalar(&vals, 0, 5), wrong(&vals, 0, 5));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut r = Lcg(0x0bad_c0de);
        for _ in 0..2_000 {
            let n = r.len(41);
            let vals: Vec<i64> = (0..n).map(|_| r.i64()).collect();
            let center = r.i64();
            let max_dev = i128::from(r.i64());
            let _ = median_i64(&vals);
            let _ = mad_i64(&vals);
            let _ = outlier_mask_scalar(&vals, center, max_dev);
            let _ = outlier_mask_vectorized(&vals, center, max_dev);
            let _ = filter_outliers(Backend::Scalar, &vals, i128::from(r.i64()));
        }
    }
}
