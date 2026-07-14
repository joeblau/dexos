//! Batched fixed-point notional products for allocation-free match planning.
//!
//! Price-time traversal, STP decisions, quantity clamps, and maker mutation stay
//! scalar in the order book. Once those ordered decisions have produced an
//! independent block of `(price, fill quantity)` pairs, this kernel multiplies
//! the common non-negative 32-bit representation with real vector instructions.
//! Any signed or wider lane takes the full-width `i128` scalar reference path.
//!
//! Division, directed rounding, and checked accumulation remain scalar and in
//! fill order. Consequently the selected backend cannot change an economic
//! result or the first observable arithmetic error.

use types::{Amount, AMOUNT_SCALE, PRICE_SCALE, QTY_SCALE};

use crate::Backend;

/// Number of fill pairs retained in the order book's fixed stack batch.
pub const MATCH_BATCH_LANES: usize = 8;

/// Exact toward-zero and toward-positive-infinity notionals for one fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MatchNotional {
    /// `price * quantity`, rescaled to [`Amount`] and rounded toward zero.
    pub notional: Amount,
    /// The same non-negative product rounded toward positive infinity.
    pub notional_ceil: Amount,
}

const NOTIONAL_DIVISOR: i128 = (PRICE_SCALE as i128) * (QTY_SCALE as i128) / AMOUNT_SCALE;

#[inline]
fn from_product(product: i128) -> MatchNotional {
    let quotient = product / NOTIONAL_DIVISOR;
    let remainder = product % NOTIONAL_DIVISOR;
    MatchNotional {
        notional: Amount::from_raw(quotient),
        notional_ceil: Amount::from_raw(if remainder > 0 {
            // An i64 × i64 quotient is far below i128::MAX.
            quotient + 1
        } else {
            quotient
        }),
    }
}

/// Full-width scalar reference for a batch of fixed-point fill notionals.
///
/// Returns `false` without writing when the three slices have different
/// lengths. An `i64 × i64` product always fits in `i128`.
pub fn matching_notionals_scalar(
    prices: &[i64],
    quantities: &[i64],
    output: &mut [MatchNotional],
) -> bool {
    if prices.len() != quantities.len() || prices.len() != output.len() {
        return false;
    }
    for ((price, quantity), slot) in prices.iter().zip(quantities).zip(output) {
        *slot = from_product(i128::from(*price) * i128::from(*quantity));
    }
    true
}

/// Backend-selected, allocation-free fixed-point notional batch.
///
/// Vector backends execute real lane multiplies for blocks whose non-negative
/// raw values fit in `u32`, which covers the production six-decimal envelope.
/// Boundary, signed, unavailable-backend, and tail lanes use the bit-identical
/// full-width scalar reference.
pub fn matching_notionals(
    backend: Backend,
    prices: &[i64],
    quantities: &[i64],
    output: &mut [MatchNotional],
) -> bool {
    if prices.len() != quantities.len() || prices.len() != output.len() {
        return false;
    }

    let mut at = 0usize;
    match backend {
        #[cfg(target_arch = "x86_64")]
        Backend::Avx512 if Backend::Avx512.is_available() => {
            while prices.len().saturating_sub(at) >= 8 {
                if chunk_fits_u32(&prices[at..at + 8], &quantities[at..at + 8]) {
                    multiply_avx512(
                        &prices[at..at + 8],
                        &quantities[at..at + 8],
                        &mut output[at..at + 8],
                    );
                } else {
                    matching_notionals_scalar(
                        &prices[at..at + 8],
                        &quantities[at..at + 8],
                        &mut output[at..at + 8],
                    );
                }
                at += 8;
            }
        }
        #[cfg(target_arch = "x86_64")]
        Backend::Avx2 if Backend::Avx2.is_available() => {
            while prices.len().saturating_sub(at) >= 4 {
                if chunk_fits_u32(&prices[at..at + 4], &quantities[at..at + 4]) {
                    multiply_avx2(
                        &prices[at..at + 4],
                        &quantities[at..at + 4],
                        &mut output[at..at + 4],
                    );
                } else {
                    matching_notionals_scalar(
                        &prices[at..at + 4],
                        &quantities[at..at + 4],
                        &mut output[at..at + 4],
                    );
                }
                at += 4;
            }
        }
        #[cfg(target_arch = "aarch64")]
        Backend::Neon => {
            while prices.len().saturating_sub(at) >= 4 {
                if chunk_fits_u32(&prices[at..at + 4], &quantities[at..at + 4]) {
                    multiply_neon(
                        &prices[at..at + 4],
                        &quantities[at..at + 4],
                        &mut output[at..at + 4],
                    );
                } else {
                    matching_notionals_scalar(
                        &prices[at..at + 4],
                        &quantities[at..at + 4],
                        &mut output[at..at + 4],
                    );
                }
                at += 4;
            }
        }
        _ => {}
    }

    matching_notionals_scalar(&prices[at..], &quantities[at..], &mut output[at..])
}

#[inline]
fn chunk_fits_u32(prices: &[i64], quantities: &[i64]) -> bool {
    prices
        .iter()
        .zip(quantities)
        .all(|(price, quantity)| u32::try_from(*price).is_ok() && u32::try_from(*quantity).is_ok())
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(always)]
fn multiply_neon(prices: &[i64], quantities: &[i64], output: &mut [MatchNotional]) {
    // SAFETY: aarch64 guarantees NEON, and the dispatcher proves four input and
    // output lanes whose values fit in u32.
    unsafe { multiply_neon_inner(prices, quantities, output) }
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(always)]
unsafe fn multiply_neon_inner(prices: &[i64], quantities: &[i64], output: &mut [MatchNotional]) {
    use core::arch::aarch64::{vget_high_u32, vget_low_u32, vld1q_u32, vmull_u32, vst1q_u64};

    let price_lanes = [
        u32::try_from(prices[0]).unwrap_or(0),
        u32::try_from(prices[1]).unwrap_or(0),
        u32::try_from(prices[2]).unwrap_or(0),
        u32::try_from(prices[3]).unwrap_or(0),
    ];
    let quantity_lanes = [
        u32::try_from(quantities[0]).unwrap_or(0),
        u32::try_from(quantities[1]).unwrap_or(0),
        u32::try_from(quantities[2]).unwrap_or(0),
        u32::try_from(quantities[3]).unwrap_or(0),
    ];
    let mut products = [0u64; 4];
    // SAFETY: all arrays have the exact lane counts used by the loads/stores.
    unsafe {
        let price = vld1q_u32(price_lanes.as_ptr());
        let quantity = vld1q_u32(quantity_lanes.as_ptr());
        let low = vmull_u32(vget_low_u32(price), vget_low_u32(quantity));
        let high = vmull_u32(vget_high_u32(price), vget_high_u32(quantity));
        vst1q_u64(products.as_mut_ptr(), low);
        vst1q_u64(products.as_mut_ptr().add(2), high);
    }
    for (slot, product) in output.iter_mut().zip(products) {
        *slot = from_product(i128::from(product));
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn multiply_avx2(prices: &[i64], quantities: &[i64], output: &mut [MatchNotional]) {
    // SAFETY: AVX2 availability and four u32-compatible lanes are proven by the
    // dispatcher. The target function stores into an exact four-lane array.
    unsafe { multiply_avx2_inner(prices, quantities, output) }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx2")]
#[inline(never)]
unsafe fn multiply_avx2_inner(prices: &[i64], quantities: &[i64], output: &mut [MatchNotional]) {
    use core::arch::x86_64::{_mm256_loadu_si256, _mm256_mul_epu32, _mm256_storeu_si256};

    let price_lanes = [
        u64::from(u32::try_from(prices[0]).unwrap_or(0)),
        u64::from(u32::try_from(prices[1]).unwrap_or(0)),
        u64::from(u32::try_from(prices[2]).unwrap_or(0)),
        u64::from(u32::try_from(prices[3]).unwrap_or(0)),
    ];
    let quantity_lanes = [
        u64::from(u32::try_from(quantities[0]).unwrap_or(0)),
        u64::from(u32::try_from(quantities[1]).unwrap_or(0)),
        u64::from(u32::try_from(quantities[2]).unwrap_or(0)),
        u64::from(u32::try_from(quantities[3]).unwrap_or(0)),
    ];
    let mut products = [0u64; 4];
    // SAFETY: each stack array is exactly 32 bytes and unaligned operations are
    // used. `_mm256_mul_epu32` multiplies the low u32 of every u64 lane.
    unsafe {
        let price = _mm256_loadu_si256(price_lanes.as_ptr().cast());
        let quantity = _mm256_loadu_si256(quantity_lanes.as_ptr().cast());
        let product = _mm256_mul_epu32(price, quantity);
        _mm256_storeu_si256(products.as_mut_ptr().cast(), product);
    }
    for (slot, product) in output.iter_mut().zip(products) {
        *slot = from_product(i128::from(product));
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn multiply_avx512(prices: &[i64], quantities: &[i64], output: &mut [MatchNotional]) {
    // SAFETY: AVX-512F availability and eight u32-compatible lanes are proven
    // by the dispatcher. The target function uses exact eight-lane arrays.
    unsafe { multiply_avx512_inner(prices, quantities, output) }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx512f")]
#[inline(never)]
unsafe fn multiply_avx512_inner(prices: &[i64], quantities: &[i64], output: &mut [MatchNotional]) {
    use core::arch::x86_64::{_mm512_loadu_si512, _mm512_mul_epu32, _mm512_storeu_si512};

    let mut price_lanes = [0u64; 8];
    let mut quantity_lanes = [0u64; 8];
    for lane in 0..8 {
        price_lanes[lane] = u64::from(u32::try_from(prices[lane]).unwrap_or(0));
        quantity_lanes[lane] = u64::from(u32::try_from(quantities[lane]).unwrap_or(0));
    }
    let mut products = [0u64; 8];
    // SAFETY: each stack array is exactly 64 bytes and unaligned operations are
    // used. `_mm512_mul_epu32` multiplies the low u32 of every u64 lane.
    unsafe {
        let price = _mm512_loadu_si512(price_lanes.as_ptr().cast());
        let quantity = _mm512_loadu_si512(quantity_lanes.as_ptr().cast());
        let product = _mm512_mul_epu32(price, quantity);
        _mm512_storeu_si512(products.as_mut_ptr().cast(), product);
    }
    for (slot, product) in output.iter_mut().zip(products) {
        *slot = from_product(i128::from(product));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(prices: &[i64], quantities: &[i64]) -> Vec<MatchNotional> {
        let mut out = vec![MatchNotional::default(); prices.len()];
        assert!(matching_notionals_scalar(prices, quantities, &mut out));
        out
    }

    #[test]
    fn invalid_lengths_fail_without_writing() {
        let sentinel = MatchNotional {
            notional: Amount::from_raw(7),
            notional_ceil: Amount::from_raw(9),
        };
        let mut out = [sentinel; 2];
        assert!(!matching_notionals(
            Backend::Scalar,
            &[1, 2],
            &[3],
            &mut out
        ));
        assert_eq!(out, [sentinel; 2]);
    }

    #[test]
    fn rounding_width_boundaries_and_signed_fallback_are_exact() {
        let prices = [
            0,
            1,
            2,
            i64::from(u32::MAX),
            i64::from(u32::MAX) + 1,
            i64::MAX,
            -1,
            i64::MIN,
            1_000_001,
        ];
        let quantities = [
            7,
            500_000,
            i64::from(u32::MAX),
            i64::from(u32::MAX),
            3,
            i64::MAX,
            500_001,
            -1,
            1_000_001,
        ];
        let expected = reference(&prices, &quantities);
        for backend in [
            Backend::Scalar,
            Backend::Avx2,
            Backend::Avx512,
            Backend::Neon,
        ] {
            let mut actual = vec![MatchNotional::default(); prices.len()];
            assert!(matching_notionals(
                backend,
                &prices,
                &quantities,
                &mut actual
            ));
            assert_eq!(actual, expected, "backend={backend:?}");
        }
    }

    #[test]
    fn every_tail_lane_count_matches_scalar_over_deterministic_corpus() {
        let mut state = 0x5720_5720_5720_5720u64;
        for len in 0..=33usize {
            let mut prices = Vec::with_capacity(len);
            let mut quantities = Vec::with_capacity(len);
            for lane in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let lane_u64 = u64::try_from(lane).unwrap_or(0);
                prices.push(i64::try_from((state ^ lane_u64) % 4_000_000_000).unwrap_or(0));
                state = state.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
                quantities.push(i64::try_from(state % 4_000_000_000).unwrap_or(0));
            }
            let expected = reference(&prices, &quantities);
            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut actual = vec![MatchNotional::default(); len];
                assert!(matching_notionals(
                    backend,
                    &prices,
                    &quantities,
                    &mut actual
                ));
                assert_eq!(actual, expected, "len={len} backend={backend:?}");
            }
        }
    }
}
