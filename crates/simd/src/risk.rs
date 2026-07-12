//! Risk scenario-vector evaluation: a reduction (sum / min / max) over an
//! `i128` payout scan.
//!
//! Risk engines evaluate a candidate account against a fan of stress scenarios,
//! each producing a signed payout (an [`Amount`]-scale `i128`). The hot summary
//! is: total payout, worst case (min), best case (max). This module provides a
//! scalar reference and a lane-structured vectorized reduction that is
//! **bit-identical** to it.
//!
//! # NOT for solvency / margin decisions
//!
//! **Do not feed [`ScenarioStats::sum`] (or any wrapping kernel in this module)
//! into solvency, margin, liquidation, or other fund-safety decisions.** The sum
//! uses [`i128::wrapping_add`] so vectorized and scalar paths stay bit-identical
//! across lane widths; on overflow the sum wraps silently and can understate
//! exposure. Checked / saturating arithmetic in the `risk` crate remains the
//! authoritative path for anything that can freeze, seize, or move collateral.
//! Use these kernels only for filters, ranking, telemetry, or other
//! non-authoritative stats where a wrap is acceptable noise.
//!
//! ## Determinism of the sum
//!
//! The vectorized path accumulates strided lanes and combines them at the end.
//! To keep the result independent of lane count and element order, the sum uses
//! [`i128::wrapping_add`], which is associative and commutative — so any grouping
//! yields the same bit pattern. This means the sum **wraps** on `i128` overflow
//! rather than saturating (saturation is *not* associative and would diverge
//! between lane widths). Callers who need overflow detection should widen or
//! bound their inputs upstream; [`ScenarioStats::min`]/[`ScenarioStats::max`]
//! bracket the range and never wrap.

use crate::backend::Backend;
use types::Amount;

/// Number of independent accumulator lanes in the vectorized reduction.
///
/// Eight lanes is a good width for the optimizer to map onto real SIMD registers
/// while staying trivially correct for any input length.
const LANES: usize = 8;

/// Summary statistics of a scenario payout scan.
///
/// **Warning:** [`Self::sum`] is a *wrapping* total. It is **not** safe as a
/// solvency or margin input — see the module-level docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScenarioStats {
    /// Wrapping sum of all payouts (see module docs on wrapping semantics).
    /// **Not** for solvency / margin decisions.
    pub sum: i128,
    /// Minimum (worst-case) payout in the scan.
    pub min: i128,
    /// Maximum (best-case) payout in the scan.
    pub max: i128,
}

/// Scalar reference reduction. Returns `None` for an empty scan.
pub fn scenario_stats_scalar(payouts: &[i128]) -> Option<ScenarioStats> {
    if payouts.is_empty() {
        return None;
    }
    let mut sum: i128 = 0;
    let mut min: i128 = i128::MAX;
    let mut max: i128 = i128::MIN;
    for &p in payouts {
        sum = sum.wrapping_add(p);
        if p < min {
            min = p;
        }
        if p > max {
            max = p;
        }
    }
    Some(ScenarioStats { sum, min, max })
}

/// Vectorized reduction. Lane-structured over [`LANES`] independent accumulators;
/// bit-identical to [`scenario_stats_scalar`] because `wrapping_add`, `min` and
/// `max` are associative and commutative.
pub fn scenario_stats_vectorized(payouts: &[i128]) -> Option<ScenarioStats> {
    if payouts.is_empty() {
        return None;
    }
    let mut sum = [0i128; LANES];
    let mut min = [i128::MAX; LANES];
    let mut max = [i128::MIN; LANES];

    let mut chunks = payouts.chunks_exact(LANES);
    for chunk in &mut chunks {
        for lane in 0..LANES {
            let v = chunk[lane];
            sum[lane] = sum[lane].wrapping_add(v);
            if v < min[lane] {
                min[lane] = v;
            }
            if v > max[lane] {
                max[lane] = v;
            }
        }
    }
    let remainder = chunks.remainder();

    // Fold the lanes into a single accumulator (identity elements make untouched
    // lanes inert), then absorb the sub-lane tail.
    let mut s: i128 = 0;
    let mut mn: i128 = i128::MAX;
    let mut mx: i128 = i128::MIN;
    for lane in 0..LANES {
        s = s.wrapping_add(sum[lane]);
        if min[lane] < mn {
            mn = min[lane];
        }
        if max[lane] > mx {
            mx = max[lane];
        }
    }
    for &v in remainder {
        s = s.wrapping_add(v);
        if v < mn {
            mn = v;
        }
        if v > mx {
            mx = v;
        }
    }
    Some(ScenarioStats {
        sum: s,
        min: mn,
        max: mx,
    })
}

/// Reduce using an explicitly chosen [`Backend`]. Scalar runs the reference;
/// every vector backend runs the (identical-result) vectorized kernel.
pub fn scenario_stats(backend: Backend, payouts: &[i128]) -> Option<ScenarioStats> {
    if backend.is_vectorized() {
        scenario_stats_vectorized(payouts)
    } else {
        scenario_stats_scalar(payouts)
    }
}

/// Reduce using the best backend the host provides (see [`crate::detect`]).
pub fn scenario_stats_dispatch(payouts: &[i128]) -> Option<ScenarioStats> {
    scenario_stats(crate::detect(), payouts)
}

/// Convenience wrapper over [`Amount`] payouts. Reduces the raw `i128` units and
/// returns the raw stats (wrapping sum semantics as documented above).
pub fn scenario_stats_amounts(backend: Backend, payouts: &[Amount]) -> Option<ScenarioStats> {
    // A dep-free map to raw units without allocating an intermediate Vec is not
    // possible through the slice kernels, so materialize the raw view once.
    let raw: Vec<i128> = payouts.iter().map(|a| a.raw()).collect();
    scenario_stats(backend, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic linear-congruential generator for property corpora.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn i128(&mut self) -> i128 {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&self.next().to_le_bytes());
            bytes[8..].copy_from_slice(&self.next().to_le_bytes());
            i128::from_le_bytes(bytes)
        }
        fn len(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % (bound as u64 + 1)).unwrap_or(0)
        }
    }

    #[test]
    fn hand_computed() {
        let data = [3i128, -5, 10, 2, -5];
        let s = scenario_stats_scalar(&data).unwrap();
        assert_eq!(s.sum, 5);
        assert_eq!(s.min, -5);
        assert_eq!(s.max, 10);
        assert_eq!(scenario_stats_vectorized(&data).unwrap(), s);
    }

    #[test]
    fn empty_is_none_on_every_backend() {
        assert!(scenario_stats_scalar(&[]).is_none());
        assert!(scenario_stats_vectorized(&[]).is_none());
        for b in [
            Backend::Scalar,
            Backend::Avx2,
            Backend::Avx512,
            Backend::Neon,
        ] {
            assert!(scenario_stats(b, &[]).is_none());
        }
    }

    #[test]
    fn overflow_boundaries_wrap_identically() {
        // Sum wraps; both paths must wrap the same way.
        let data = [i128::MAX, 1, i128::MIN, -1, i128::MAX, i128::MAX];
        assert_eq!(
            scenario_stats_scalar(&data),
            scenario_stats_vectorized(&data)
        );
        let extremes = [i128::MIN, i128::MAX];
        let s = scenario_stats_scalar(&extremes).unwrap();
        assert_eq!(s.min, i128::MIN);
        assert_eq!(s.max, i128::MAX);
    }

    #[test]
    fn scalar_vs_vectorized_bit_identical_over_lcg_corpus() {
        let mut r = Lcg(0x1234_5678_9abc_def0);
        for _ in 0..5_000 {
            let n = r.len(200);
            let data: Vec<i128> = (0..n).map(|_| r.i128()).collect();
            assert_eq!(
                scenario_stats_scalar(&data),
                scenario_stats_vectorized(&data),
                "divergence at len {n}"
            );
            // Dispatch must also match the scalar reference.
            assert_eq!(scenario_stats_scalar(&data), scenario_stats_dispatch(&data));
        }
    }

    #[test]
    fn all_lengths_across_lane_boundary_match() {
        let mut r = Lcg(99);
        // Exercise every length up to a few full lanes plus tails.
        for n in 0..(LANES * 4 + 3) {
            let data: Vec<i128> = (0..n).map(|_| r.i128()).collect();
            assert_eq!(
                scenario_stats_scalar(&data),
                scenario_stats_vectorized(&data),
                "len {n}"
            );
        }
    }

    #[test]
    fn negative_test_wrong_kernel_is_detected() {
        // Prove the equivalence check has teeth: a deliberately wrong kernel
        // (drops the last element) must diverge from the reference.
        fn wrong(payouts: &[i128]) -> Option<ScenarioStats> {
            let n = payouts.len();
            if n <= 1 {
                return scenario_stats_scalar(payouts);
            }
            scenario_stats_scalar(&payouts[..n - 1])
        }
        let data = [1i128, 2, 3, 4, 5];
        assert_ne!(scenario_stats_scalar(&data), wrong(&data));
    }

    #[test]
    fn amount_wrapper_matches_raw() {
        let amounts = [
            Amount::from_raw(7),
            Amount::from_raw(-3),
            Amount::from_raw(9),
        ];
        let raw = [7i128, -3, 9];
        assert_eq!(
            scenario_stats_amounts(Backend::Avx2, &amounts),
            scenario_stats_scalar(&raw)
        );
    }

    #[test]
    fn never_panics_on_arbitrary_lengths() {
        let mut r = Lcg(0xdead_beef);
        for _ in 0..2_000 {
            let n = r.len(37);
            let data: Vec<i128> = (0..n).map(|_| r.i128()).collect();
            let _ = scenario_stats_scalar(&data);
            let _ = scenario_stats_vectorized(&data);
            let _ = scenario_stats_dispatch(&data);
        }
    }

    #[test]
    fn wrapping_sum_diverges_from_checked_add_on_overflow() {
        // Document why these kernels must not drive solvency: on overflow the
        // wrapping sum disagrees with a checked accumulation that reports error.
        let data = [i128::MAX, 1];
        let stats = scenario_stats_scalar(&data).unwrap();
        // wrapping: MAX + 1 -> MIN
        assert_eq!(stats.sum, i128::MIN);
        // checked path refuses to produce a silent wrong total.
        let mut checked: Result<i128, ()> = Ok(0);
        for &p in &data {
            checked = checked.and_then(|acc| acc.checked_add(p).ok_or(()));
        }
        assert!(
            checked.is_err(),
            "checked accumulation must signal overflow"
        );
        assert_ne!(
            Ok(stats.sum),
            checked,
            "wrapping SIMD sum must not be treated as the checked total"
        );
        // Scalar and vectorized still agree with each other (bit-identical wrap).
        assert_eq!(
            scenario_stats_scalar(&data),
            scenario_stats_vectorized(&data)
        );
    }
}
