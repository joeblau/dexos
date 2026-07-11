//! Batch normalization / outlier kernels, bit-identical to the scalar reference.
//!
//! These are the vectorization-ready hot loops of aggregation, kept in an
//! isolated module. They contain **no `unsafe` and no SIMD intrinsics**: the
//! deterministic execution core forbids `unsafe`, so the kernels are written as
//! portable integer loops that a compiler can auto-vectorize while remaining
//! provably equal, element-for-element, to the scalar reference. The
//! equivalence tests below pin that guarantee.

use crate::math::scale_by_ratio;
use types::Ratio;

/// Scalar reference: signed deviation of each price from `center`, in `i128`.
pub fn deviations_scalar(prices: &[i64], center: i64) -> Vec<i128> {
    prices
        .iter()
        .map(|&p| i128::from(p) - i128::from(center))
        .collect()
}

/// Batch form of [`deviations_scalar`]; must be bit-identical.
pub fn deviations_batch(prices: &[i64], center: i64) -> Vec<i128> {
    let c = i128::from(center);
    let mut out = vec![0i128; prices.len()];
    for (o, &p) in out.iter_mut().zip(prices.iter()) {
        *o = i128::from(p) - c;
    }
    out
}

/// Scalar reference: `true` where a sample is kept (within `center ± k·MAD`).
/// When `mad == 0` all samples are kept (no dispersion to reject against).
pub fn outlier_mask_scalar(prices: &[i64], center: i64, mad: i128, k: Ratio) -> Vec<bool> {
    let band = scale_by_ratio(mad, k);
    prices
        .iter()
        .map(|&p| mad == 0 || (i128::from(p) - i128::from(center)).abs() <= band)
        .collect()
}

/// Batch form of [`outlier_mask_scalar`]; must be bit-identical.
pub fn outlier_mask_batch(prices: &[i64], center: i64, mad: i128, k: Ratio) -> Vec<bool> {
    let band = scale_by_ratio(mad, k);
    let c = i128::from(center);
    let keep_all = mad == 0;
    let mut out = vec![false; prices.len()];
    for (o, &p) in out.iter_mut().zip(prices.iter()) {
        *o = keep_all || (i128::from(p) - c).abs() <= band;
    }
    out
}

/// Scalar reference: summed non-negative weight of the kept samples.
pub fn kept_weight_scalar(weights: &[i128], keep: &[bool]) -> i128 {
    weights
        .iter()
        .zip(keep.iter())
        .filter(|(_, &k)| k)
        .fold(0i128, |acc, (w, _)| acc.saturating_add((*w).max(0)))
}

/// Batch form of [`kept_weight_scalar`]; must be bit-identical.
pub fn kept_weight_batch(weights: &[i128], keep: &[bool]) -> i128 {
    let mut acc = 0i128;
    for (w, &k) in weights.iter().zip(keep.iter()) {
        if k {
            acc = acc.saturating_add((*w).max(0));
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::RATIO_SCALE;

    // Deterministic LCG (no external rand crate).
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn next_i64(&mut self) -> i64 {
            i64::from_le_bytes(self.next_u64().to_le_bytes())
        }
    }

    #[test]
    fn deviations_batch_equals_scalar_boundary() {
        let prices = [i64::MIN, i64::MAX, 0, -1, 1, 12345, -98765];
        for &c in &[i64::MIN, i64::MAX, 0, 7] {
            assert_eq!(deviations_scalar(&prices, c), deviations_batch(&prices, c));
        }
    }

    #[test]
    fn kernels_bit_identical_property() {
        let mut r = Lcg(0xABCD_1234);
        let k = Ratio::from_raw(3 * RATIO_SCALE);
        for _ in 0..5_000 {
            let n = usize::try_from(r.next_u64() % 17).unwrap();
            let prices: Vec<i64> = (0..n).map(|_| r.next_i64()).collect();
            let center = r.next_i64();
            let mad = i128::from(r.next_i64()).abs();
            assert_eq!(
                deviations_scalar(&prices, center),
                deviations_batch(&prices, center)
            );
            let ms = outlier_mask_scalar(&prices, center, mad, k);
            let mb = outlier_mask_batch(&prices, center, mad, k);
            assert_eq!(ms, mb);

            let weights: Vec<i128> = prices.iter().map(|_| i128::from(r.next_i64())).collect();
            assert_eq!(
                kept_weight_scalar(&weights, &ms),
                kept_weight_batch(&weights, &mb)
            );
        }
    }

    #[test]
    fn mad_zero_keeps_all() {
        let prices = [1, 2, 3, 1000];
        let mask = outlier_mask_batch(&prices, 2, 0, Ratio::from_raw(RATIO_SCALE));
        assert!(mask.iter().all(|&k| k));
    }
}
