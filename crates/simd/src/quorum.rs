//! Allocation-free signer-bitmap weight accumulation for Minimmit QCs.
//!
//! Signature verification and bad-signer attribution remain scalar and ordered.
//! This kernel handles only the independent, commutative reduction of canonical
//! committee weights selected by a 16-bit certificate bitmap. Invalid bits are
//! rejected before dispatch, and every vector implementation widens to `u64`
//! before reduction so weighted committees cannot wrap.

use crate::Backend;

/// Maximum signer lanes represented by the Minimmit certificate bitmap.
pub const QUORUM_WEIGHT_LANES: usize = 16;

/// Checked scalar oracle for a signer-bitmap weight reduction.
///
/// Returns `None` when `committee_len` exceeds 16 or the bitmap names a lane
/// outside the committee. All selected `u32` weights are accumulated in `u64`.
#[must_use]
pub fn selected_weight_scalar(
    signer_bitmap: u16,
    weights: &[u32; QUORUM_WEIGHT_LANES],
    committee_len: usize,
) -> Option<u64> {
    let valid_mask = valid_mask(committee_len)?;
    if signer_bitmap & !valid_mask != 0 {
        return None;
    }
    let mut total = 0u64;
    for (index, weight) in weights.iter().enumerate().take(committee_len) {
        if signer_bitmap & (1u16 << index) != 0 {
            total = total.checked_add(u64::from(*weight))?;
        }
    }
    Some(total)
}

/// Backend-selected signer-bitmap weight reduction.
///
/// Unavailable architecture tags use the checked scalar oracle. Production
/// callers select a runnable backend once at startup; forced operator backends
/// are validated by [`Backend::force`](crate::Backend::force).
#[must_use]
pub fn selected_weight(
    backend: Backend,
    signer_bitmap: u16,
    weights: &[u32; QUORUM_WEIGHT_LANES],
    committee_len: usize,
) -> Option<u64> {
    let valid_mask = valid_mask(committee_len)?;
    if signer_bitmap & !valid_mask != 0 {
        return None;
    }

    match backend {
        #[cfg(target_arch = "aarch64")]
        Backend::Neon => Some(selected_weight_neon(signer_bitmap, weights)),
        #[cfg(target_arch = "x86_64")]
        Backend::Avx512 if Backend::Avx512.is_available() => {
            Some(selected_weight_avx512(signer_bitmap, weights))
        }
        #[cfg(target_arch = "x86_64")]
        Backend::Avx2 if Backend::Avx2.is_available() => {
            Some(selected_weight_avx2(signer_bitmap, weights))
        }
        _ => selected_weight_scalar(signer_bitmap, weights, committee_len),
    }
}

fn valid_mask(committee_len: usize) -> Option<u16> {
    match committee_len {
        0..=15 => Some((1u16 << committee_len) - 1),
        16 => Some(u16::MAX),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(always)]
fn selected_weight_neon(signer_bitmap: u16, weights: &[u32; QUORUM_WEIGHT_LANES]) -> u64 {
    // SAFETY: aarch64 guarantees NEON. Both arrays contain exactly 16 lanes;
    // the inner function loads four lanes at each of offsets 0, 4, 8, and 12.
    unsafe { selected_weight_neon_inner(signer_bitmap, weights) }
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(always)]
unsafe fn selected_weight_neon_inner(
    signer_bitmap: u16,
    weights: &[u32; QUORUM_WEIGHT_LANES],
) -> u64 {
    use core::arch::aarch64::{
        vaddvq_u64, vandq_u32, vceqq_u32, vdupq_n_u32, vld1q_u32, vpaddlq_u32,
    };

    const BIT_LANES: [u32; QUORUM_WEIGHT_LANES] = [
        0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400,
        0x0800, 0x1000, 0x2000, 0x4000, 0x8000,
    ];
    let bitmap = vdupq_n_u32(u32::from(signer_bitmap));
    let mut total = 0u64;
    for at in (0..QUORUM_WEIGHT_LANES).step_by(4) {
        // SAFETY: `at` is one of 0, 4, 8, 12 and both arrays have 16 lanes.
        let lane_weights = unsafe { vld1q_u32(weights.as_ptr().add(at)) };
        // SAFETY: same exact four-lane bounds as the weight load.
        let lane_bits = unsafe { vld1q_u32(BIT_LANES.as_ptr().add(at)) };
        let selected_mask = vceqq_u32(vandq_u32(bitmap, lane_bits), lane_bits);
        let selected = vandq_u32(lane_weights, selected_mask);
        total += vaddvq_u64(vpaddlq_u32(selected));
    }
    total
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn selected_weight_avx2(signer_bitmap: u16, weights: &[u32; QUORUM_WEIGHT_LANES]) -> u64 {
    // SAFETY: dispatch proved AVX2 support and the inner function performs two
    // unaligned eight-lane loads from the exact 16-lane input.
    unsafe { selected_weight_avx2_inner(signer_bitmap, weights) }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx2")]
#[inline(never)]
unsafe fn selected_weight_avx2_inner(
    signer_bitmap: u16,
    weights: &[u32; QUORUM_WEIGHT_LANES],
) -> u64 {
    use core::arch::x86_64::{
        _mm256_add_epi64, _mm256_and_si256, _mm256_castsi256_si128, _mm256_cmpeq_epi32,
        _mm256_cvtepu32_epi64, _mm256_extracti128_si256, _mm256_loadu_si256, _mm256_set1_epi32,
        _mm256_setr_epi32, _mm256_storeu_si256,
    };

    let bitmap = _mm256_set1_epi32(i32::from(signer_bitmap));
    let low_bits = _mm256_setr_epi32(1, 2, 4, 8, 16, 32, 64, 128);
    let high_bits = _mm256_setr_epi32(256, 512, 1024, 2048, 4096, 8192, 16384, 32768);
    // SAFETY: each load reads eight u32 values from offsets 0 and 8.
    let low_weights = unsafe { _mm256_loadu_si256(weights.as_ptr().cast()) };
    let high_weights = unsafe { _mm256_loadu_si256(weights.as_ptr().add(8).cast()) };
    let low_selected = _mm256_and_si256(
        low_weights,
        _mm256_cmpeq_epi32(_mm256_and_si256(bitmap, low_bits), low_bits),
    );
    let high_selected = _mm256_and_si256(
        high_weights,
        _mm256_cmpeq_epi32(_mm256_and_si256(bitmap, high_bits), high_bits),
    );

    let low_sum = _mm256_add_epi64(
        _mm256_cvtepu32_epi64(_mm256_castsi256_si128(low_selected)),
        _mm256_cvtepu32_epi64(_mm256_extracti128_si256::<1>(low_selected)),
    );
    let high_sum = _mm256_add_epi64(
        _mm256_cvtepu32_epi64(_mm256_castsi256_si128(high_selected)),
        _mm256_cvtepu32_epi64(_mm256_extracti128_si256::<1>(high_selected)),
    );
    let combined = _mm256_add_epi64(low_sum, high_sum);
    let mut lanes = [0u64; 4];
    // SAFETY: `lanes` is exactly one 256-bit vector wide.
    unsafe { _mm256_storeu_si256(lanes.as_mut_ptr().cast(), combined) };
    lanes.into_iter().sum()
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn selected_weight_avx512(signer_bitmap: u16, weights: &[u32; QUORUM_WEIGHT_LANES]) -> u64 {
    // SAFETY: dispatch proved AVX-512F support and the inner function performs
    // one unaligned load from the exact 16-lane input.
    unsafe { selected_weight_avx512_inner(signer_bitmap, weights) }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx512f")]
#[inline(never)]
unsafe fn selected_weight_avx512_inner(
    signer_bitmap: u16,
    weights: &[u32; QUORUM_WEIGHT_LANES],
) -> u64 {
    use core::arch::x86_64::{
        _mm512_add_epi64, _mm512_cvtepu32_epi64, _mm512_maskz_loadu_epi32, _mm512_storeu_si512,
    };

    // SAFETY: the masked load has an exact 16-lane backing array.
    let selected = unsafe { _mm512_maskz_loadu_epi32(signer_bitmap, weights.as_ptr().cast()) };
    let low = core::arch::x86_64::_mm512_castsi512_si256(selected);
    let high = core::arch::x86_64::_mm512_extracti64x4_epi64::<1>(selected);
    let widened = _mm512_add_epi64(_mm512_cvtepu32_epi64(low), _mm512_cvtepu32_epi64(high));
    let mut lanes = [0u64; 8];
    // SAFETY: `lanes` is exactly one 512-bit vector wide.
    unsafe { _mm512_storeu_si512(lanes.as_mut_ptr().cast(), widened) };
    lanes.into_iter().sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_and_invalid_bits_are_checked() {
        let weights = core::array::from_fn(|index| u32::try_from(index + 1).unwrap_or(0));
        assert_eq!(selected_weight_scalar(0, &weights, 0), Some(0));
        assert_eq!(selected_weight_scalar(1, &weights, 0), None);
        assert_eq!(selected_weight_scalar(u16::MAX, &weights, 16), Some(136));
        assert_eq!(selected_weight_scalar(1, &weights, 17), None);
        assert_eq!(selected_weight_scalar(1 << 6, &weights, 6), None);
    }

    #[test]
    fn every_bitmap_and_backend_matches_full_width_scalar() {
        let weights = [
            0,
            1,
            2,
            3,
            5,
            8,
            13,
            21,
            u32::MAX,
            34,
            55,
            89,
            144,
            233,
            377,
            610,
        ];
        for committee_len in 0..=QUORUM_WEIGHT_LANES {
            for signer_bitmap in 0..=u16::MAX {
                let reference = selected_weight_scalar(signer_bitmap, &weights, committee_len);
                for backend in [
                    Backend::Scalar,
                    Backend::Avx2,
                    Backend::Avx512,
                    Backend::Neon,
                ] {
                    assert_eq!(
                        selected_weight(backend, signer_bitmap, &weights, committee_len),
                        reference,
                        "backend={backend:?} len={committee_len} bitmap={signer_bitmap:#06x}"
                    );
                }
            }
        }
    }
}
