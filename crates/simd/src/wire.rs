//! Fixed-width wire load/store kernels for packed records.
//!
//! Economic validation and enum decoding remain scalar. These kernels only
//! move already-canonical little-endian 64-bit lanes, so vector width cannot
//! change bytes or error decisions. Supported hot records use five (40-byte)
//! or seven (56-byte) lanes.

use crate::Backend;

/// Store five or seven canonical `u64` lanes into caller-owned wire storage.
/// Returns `false` for any other lane count or an undersized destination.
pub fn store_u64_le(backend: Backend, words: &[u64], out: &mut [u8]) -> bool {
    let bytes = match words.len().checked_mul(8) {
        Some(bytes) if matches!(words.len(), 5 | 7) && out.len() >= bytes => bytes,
        _ => return false,
    };
    match backend {
        Backend::Scalar => store_scalar(words, &mut out[..bytes]),
        #[cfg(target_arch = "x86_64")]
        Backend::Avx2 if Backend::Avx2.is_available() => store_avx2(words, &mut out[..bytes]),
        #[cfg(target_arch = "x86_64")]
        Backend::Avx512 if Backend::Avx512.is_available() => {
            store_avx512(words, &mut out[..bytes]);
        }
        #[cfg(target_arch = "aarch64")]
        Backend::Neon => store_neon(words, &mut out[..bytes]),
        _ => store_scalar(words, &mut out[..bytes]),
    }
    true
}

/// Load five or seven canonical `u64` lanes from wire storage into caller-owned
/// stack storage. Returns `false` for invalid widths or truncated input.
pub fn load_u64_le(backend: Backend, input: &[u8], words: &mut [u64]) -> bool {
    let bytes = match words.len().checked_mul(8) {
        Some(bytes) if matches!(words.len(), 5 | 7) && input.len() >= bytes => bytes,
        _ => return false,
    };
    match backend {
        Backend::Scalar => load_scalar(&input[..bytes], words),
        #[cfg(target_arch = "x86_64")]
        Backend::Avx2 if Backend::Avx2.is_available() => load_avx2(&input[..bytes], words),
        #[cfg(target_arch = "x86_64")]
        Backend::Avx512 if Backend::Avx512.is_available() => {
            load_avx512(&input[..bytes], words);
        }
        #[cfg(target_arch = "aarch64")]
        Backend::Neon => load_neon(&input[..bytes], words),
        _ => load_scalar(&input[..bytes], words),
    }
    for word in words {
        *word = u64::from_le(*word);
    }
    true
}

fn store_scalar(words: &[u64], out: &mut [u8]) {
    for (word, chunk) in words.iter().zip(out.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

fn load_scalar(input: &[u8], words: &mut [u64]) {
    for (chunk, word) in input.chunks_exact(8).zip(words) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        *word = u64::from_le_bytes(bytes).to_le();
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(never)]
fn store_neon(words: &[u64], out: &mut [u8]) {
    use core::arch::asm;

    // SAFETY: width is 5 or 7, so each listed 16-byte load/store is in bounds;
    // aarch64 permits unaligned vector accesses. Explicit assembly prevents LLVM
    // from folding the qualified kernel back into a scalar/memcpy call, keeping
    // the disassembly gate meaningful.
    unsafe {
        if words.len() == 5 {
            asm!(
                "ldr q0, [{src}]",
                "str q0, [{dst}]",
                "ldr q0, [{src}, #16]",
                "str q0, [{dst}, #16]",
                "ldr x9, [{src}, #32]",
                "str x9, [{dst}, #32]",
                src = in(reg) words.as_ptr(),
                dst = in(reg) out.as_mut_ptr(),
                out("v0") _,
                out("x9") _,
                options(nostack, preserves_flags),
            );
        } else {
            asm!(
                "ldr q0, [{src}]",
                "str q0, [{dst}]",
                "ldr q0, [{src}, #16]",
                "str q0, [{dst}, #16]",
                "ldr q0, [{src}, #32]",
                "str q0, [{dst}, #32]",
                "ldr x9, [{src}, #48]",
                "str x9, [{dst}, #48]",
                src = in(reg) words.as_ptr(),
                dst = in(reg) out.as_mut_ptr(),
                out("v0") _,
                out("x9") _,
                options(nostack, preserves_flags),
            );
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(never)]
fn load_neon(input: &[u8], words: &mut [u64]) {
    use core::arch::asm;

    // SAFETY: source/destination were checked for five/seven lanes and do not
    // overlap. See `store_neon` for why this is explicit assembly.
    unsafe {
        if words.len() == 5 {
            asm!(
                "ldr q0, [{src}]",
                "str q0, [{dst}]",
                "ldr q0, [{src}, #16]",
                "str q0, [{dst}, #16]",
                "ldr x9, [{src}, #32]",
                "str x9, [{dst}, #32]",
                src = in(reg) input.as_ptr(),
                dst = in(reg) words.as_mut_ptr(),
                out("v0") _,
                out("x9") _,
                options(nostack, preserves_flags),
            );
        } else {
            asm!(
                "ldr q0, [{src}]",
                "str q0, [{dst}]",
                "ldr q0, [{src}, #16]",
                "str q0, [{dst}, #16]",
                "ldr q0, [{src}, #32]",
                "str q0, [{dst}, #32]",
                "ldr x9, [{src}, #48]",
                "str x9, [{dst}, #48]",
                src = in(reg) input.as_ptr(),
                dst = in(reg) words.as_mut_ptr(),
                out("v0") _,
                out("x9") _,
                options(nostack, preserves_flags),
            );
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn store_avx2(words: &[u64], out: &mut [u8]) {
    // SAFETY: feature availability and five/seven-lane bounds are checked by the
    // public dispatcher; the target function uses unaligned loads/stores.
    unsafe { store_avx2_inner(words, out) }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx2")]
unsafe fn store_avx2_inner(words: &[u64], out: &mut [u8]) {
    use core::arch::x86_64::{
        _mm256_loadu_si256, _mm256_storeu_si256, _mm_loadu_si128, _mm_storeu_si128,
    };

    // SAFETY: caller proves at least 32 bytes on both sides.
    unsafe {
        let head = _mm256_loadu_si256(words.as_ptr().cast());
        _mm256_storeu_si256(out.as_mut_ptr().cast(), head);
        if words.len() == 7 {
            let tail = _mm_loadu_si128(words.as_ptr().add(4).cast());
            _mm_storeu_si128(out.as_mut_ptr().add(32).cast(), tail);
        }
        let last = words.as_ptr().add(words.len() - 1).read();
        out.as_mut_ptr()
            .add((words.len() - 1) * 8)
            .cast::<u64>()
            .write_unaligned(last);
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn load_avx2(input: &[u8], words: &mut [u64]) {
    // SAFETY: feature availability and slice bounds are checked by dispatcher.
    unsafe { load_avx2_inner(input, words) }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx2")]
unsafe fn load_avx2_inner(input: &[u8], words: &mut [u64]) {
    use core::arch::x86_64::{
        _mm256_loadu_si256, _mm256_storeu_si256, _mm_loadu_si128, _mm_storeu_si128,
    };

    // SAFETY: caller proves at least 32 bytes on both sides.
    unsafe {
        let head = _mm256_loadu_si256(input.as_ptr().cast());
        _mm256_storeu_si256(words.as_mut_ptr().cast(), head);
        if words.len() == 7 {
            let tail = _mm_loadu_si128(input.as_ptr().add(32).cast());
            _mm_storeu_si128(words.as_mut_ptr().add(4).cast(), tail);
        }
        let last = input
            .as_ptr()
            .add((words.len() - 1) * 8)
            .cast::<u64>()
            .read_unaligned();
        words.as_mut_ptr().add(words.len() - 1).write(last);
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn store_avx512(words: &[u64], out: &mut [u8]) {
    // SAFETY: AVX-512F availability and bounds are checked by dispatcher.
    unsafe { store_avx512_inner(words, out) }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx512f")]
unsafe fn store_avx512_inner(words: &[u64], out: &mut [u8]) {
    use core::arch::x86_64::{_mm512_mask_storeu_epi64, _mm512_maskz_loadu_epi64};

    let mask = if words.len() == 5 { 0x1f } else { 0x7f };
    // SAFETY: the mask touches exactly five/seven checked 64-bit lanes.
    unsafe {
        let value = _mm512_maskz_loadu_epi64(mask, words.as_ptr().cast());
        _mm512_mask_storeu_epi64(out.as_mut_ptr().cast(), mask, value);
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn load_avx512(input: &[u8], words: &mut [u64]) {
    // SAFETY: AVX-512F availability and bounds are checked by dispatcher.
    unsafe { load_avx512_inner(input, words) }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx512f")]
unsafe fn load_avx512_inner(input: &[u8], words: &mut [u64]) {
    use core::arch::x86_64::{_mm512_mask_storeu_epi64, _mm512_maskz_loadu_epi64};

    let mask = if words.len() == 5 { 0x1f } else { 0x7f };
    // SAFETY: the mask touches exactly five/seven checked 64-bit lanes.
    unsafe {
        let value = _mm512_maskz_loadu_epi64(mask, input.as_ptr().cast());
        _mm512_mask_storeu_epi64(words.as_mut_ptr().cast(), mask, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_backend_is_byte_identical_for_five_and_seven_unaligned_lanes() {
        for count in [5usize, 7] {
            let source = [
                0x0102_0304_0506_0708,
                u64::MAX,
                0,
                0x8877_6655_4433_2211,
                7,
                9,
                11,
            ];
            let mut scalar = [0u8; 57];
            assert!(store_u64_le(
                Backend::Scalar,
                &source[..count],
                &mut scalar[1..]
            ));
            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut encoded = [0u8; 57];
                assert!(store_u64_le(backend, &source[..count], &mut encoded[1..]));
                assert_eq!(encoded, scalar);
                let mut decoded = [0u64; 7];
                assert!(load_u64_le(backend, &encoded[1..], &mut decoded[..count]));
                assert_eq!(&decoded[..count], &source[..count]);
            }
        }
    }

    #[test]
    fn invalid_widths_and_short_buffers_fail_without_writes() {
        let mut out = [0xabu8; 56];
        assert!(!store_u64_le(Backend::Scalar, &[1, 2, 3], &mut out));
        assert!(!store_u64_le(Backend::Scalar, &[0; 7], &mut out[..55]));
        assert_eq!(out, [0xab; 56]);
        let mut words = [7u64; 7];
        assert!(!load_u64_le(Backend::Scalar, &out[..55], &mut words));
        assert_eq!(words, [7; 7]);
    }
}
