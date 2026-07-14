//! Runtime-qualified LZ4 block decompression.
//!
//! The parser is shared by the scalar reference and every vector backend, so
//! metadata validation and error decisions cannot diverge. Architecture code is
//! limited to non-overlapping fixed-width copies after the parser has proved
//! source/destination bounds. Short or overlapping matches retain the canonical
//! byte-at-a-time LZ4 semantics.

use crate::Backend;

const MIN_MATCH: usize = 4;
const HASH_LOG: u32 = 14;
const HASH_SIZE: usize = 1usize << HASH_LOG;
const MAX_OFFSET: usize = 65_535;

#[derive(Debug, Clone, Copy, Default)]
struct HashEntry {
    position: u32,
    generation: u32,
}

/// Reusable bounded LZ4 block compressor state.
///
/// Construction allocates the fixed hash table once. Calls only mutate that
/// table and caller-owned output; generation tags avoid clearing it per batch.
pub struct Lz4Compressor {
    table: Box<[HashEntry]>,
    generation: u32,
}

impl Lz4Compressor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: vec![HashEntry::default(); HASH_SIZE].into_boxed_slice(),
            generation: 0,
        }
    }

    /// Compress one raw LZ4 block, emitting identical bytes on every backend.
    pub fn compress_into(
        &mut self,
        backend: Backend,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Lz4CompressError> {
        self.advance_generation();
        compress(
            qualified_backend(backend),
            input,
            output,
            &mut self.table,
            self.generation,
        )
    }

    fn advance_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.table.fill(HashEntry::default());
            self.generation = 1;
        }
    }
}

impl Default for Lz4Compressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller-capacity or input-limit failure while encoding an LZ4 block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Lz4CompressError {
    #[error("LZ4 input exceeds the 64 KiB raw-block envelope")]
    InputTooLarge,
    #[error("LZ4 output buffer is too small")]
    OutputTooSmall,
}

/// A malformed LZ4 block or undersized caller-owned output buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Lz4DecompressError {
    #[error("LZ4 block ended before the next required byte")]
    Truncated,
    #[error("LZ4 length extension overflowed usize")]
    LengthOverflow,
    #[error("LZ4 literal section exceeds the compressed block")]
    LiteralOutOfBounds,
    #[error("LZ4 output buffer has {available} bytes, needs at least {needed}")]
    OutputTooSmall { needed: usize, available: usize },
    #[error("LZ4 match offset is zero")]
    OffsetZero,
    #[error("LZ4 match offset exceeds produced output")]
    OffsetOutOfBounds,
}

fn compress(
    backend: Backend,
    input: &[u8],
    output: &mut [u8],
    table: &mut [HashEntry],
    generation: u32,
) -> Result<usize, Lz4CompressError> {
    if input.len() > 64 * 1024 {
        return Err(Lz4CompressError::InputTooLarge);
    }
    let mut input_pos = 0usize;
    let mut anchor = 0usize;
    let mut output_pos = 0usize;

    while input_pos.saturating_add(MIN_MATCH) <= input.len() {
        let sequence = u32::from_le_bytes(
            input[input_pos..input_pos + MIN_MATCH]
                .try_into()
                .unwrap_or([0; MIN_MATCH]),
        );
        let hash = hash_sequence(sequence);
        let previous_entry = table[hash];
        table[hash] = HashEntry {
            position: u32::try_from(input_pos).unwrap_or(u32::MAX),
            generation,
        };
        let previous = usize::try_from(previous_entry.position).unwrap_or(usize::MAX);
        let offset = input_pos.saturating_sub(previous);
        let matches = previous_entry.generation == generation
            && previous < input_pos
            && offset <= MAX_OFFSET
            && input[previous..previous + MIN_MATCH] == input[input_pos..input_pos + MIN_MATCH];
        if !matches {
            input_pos += 1;
            continue;
        }

        let match_len = MIN_MATCH
            + common_suffix_len(
                backend,
                &input[previous + MIN_MATCH..],
                &input[input_pos + MIN_MATCH..],
            );
        emit_sequence(
            output,
            &mut output_pos,
            &input[anchor..input_pos],
            u16::try_from(offset).map_err(|_| Lz4CompressError::InputTooLarge)?,
            match_len,
        )?;
        input_pos += match_len;
        anchor = input_pos;

        // Seed the position immediately before the next probe. This improves
        // adjacent-record compression without an O(match_len) table update.
        if input_pos >= 2 && input_pos.saturating_add(2) <= input.len() {
            let seed_pos = input_pos - 2;
            let seed = u32::from_le_bytes(
                input[seed_pos..seed_pos + MIN_MATCH]
                    .try_into()
                    .unwrap_or([0; MIN_MATCH]),
            );
            table[hash_sequence(seed)] = HashEntry {
                position: u32::try_from(seed_pos).unwrap_or(u32::MAX),
                generation,
            };
        }
    }

    emit_last_literals(output, &mut output_pos, &input[anchor..])?;
    Ok(output_pos)
}

const fn hash_sequence(sequence: u32) -> usize {
    (sequence.wrapping_mul(2_654_435_761) >> (32 - HASH_LOG)) as usize
}

fn common_suffix_len(backend: Backend, left: &[u8], right: &[u8]) -> usize {
    let available = left.len().min(right.len());
    let width = vector_width(backend);
    let vector_bytes = available.checked_div(width).unwrap_or(0) * width;
    let mut matched = 0usize;
    while matched < vector_bytes {
        // SAFETY: both slices contain the checked vector-width chunk. This reads
        // only, and the runtime-qualified backend determines the instruction set.
        #[allow(unsafe_code)]
        let equal = unsafe {
            vectors_equal(
                backend,
                left.as_ptr().add(matched),
                right.as_ptr().add(matched),
            )
        };
        if !equal {
            break;
        }
        matched += width;
    }
    while matched < available && left[matched] == right[matched] {
        matched += 1;
    }
    matched
}

fn emit_sequence(
    output: &mut [u8],
    output_pos: &mut usize,
    literals: &[u8],
    offset: u16,
    match_len: usize,
) -> Result<(), Lz4CompressError> {
    let encoded_match_len = match_len.saturating_sub(MIN_MATCH);
    let needed = 1usize
        .checked_add(extension_len(literals.len()))
        .and_then(|n| n.checked_add(literals.len()))
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_add(extension_len(encoded_match_len)))
        .ok_or(Lz4CompressError::OutputTooSmall)?;
    ensure_compress_output(*output_pos, needed, output.len())?;
    output[*output_pos] = (u8::try_from(literals.len().min(15)).unwrap_or(15) << 4)
        | u8::try_from(encoded_match_len.min(15)).unwrap_or(15);
    *output_pos += 1;
    emit_length(output, output_pos, literals.len());
    let literal_end = *output_pos + literals.len();
    output[*output_pos..literal_end].copy_from_slice(literals);
    *output_pos = literal_end;
    output[*output_pos..*output_pos + 2].copy_from_slice(&offset.to_le_bytes());
    *output_pos += 2;
    emit_length(output, output_pos, encoded_match_len);
    Ok(())
}

fn emit_last_literals(
    output: &mut [u8],
    output_pos: &mut usize,
    literals: &[u8],
) -> Result<(), Lz4CompressError> {
    let needed = 1usize
        .checked_add(extension_len(literals.len()))
        .and_then(|n| n.checked_add(literals.len()))
        .ok_or(Lz4CompressError::OutputTooSmall)?;
    ensure_compress_output(*output_pos, needed, output.len())?;
    output[*output_pos] = u8::try_from(literals.len().min(15)).unwrap_or(15) << 4;
    *output_pos += 1;
    emit_length(output, output_pos, literals.len());
    let end = *output_pos + literals.len();
    output[*output_pos..end].copy_from_slice(literals);
    *output_pos = end;
    Ok(())
}

const fn extension_len(length: usize) -> usize {
    if length < 15 {
        0
    } else {
        (length - 15) / 255 + 1
    }
}

fn emit_length(output: &mut [u8], output_pos: &mut usize, length: usize) {
    if length < 15 {
        return;
    }
    let mut remaining = length - 15;
    while remaining >= usize::from(u8::MAX) {
        output[*output_pos] = u8::MAX;
        *output_pos += 1;
        remaining -= usize::from(u8::MAX);
    }
    output[*output_pos] = u8::try_from(remaining).unwrap_or(u8::MAX);
    *output_pos += 1;
}

fn ensure_compress_output(
    output_pos: usize,
    additional: usize,
    capacity: usize,
) -> Result<(), Lz4CompressError> {
    if output_pos
        .checked_add(additional)
        .is_some_and(|needed| needed <= capacity)
    {
        Ok(())
    } else {
        Err(Lz4CompressError::OutputTooSmall)
    }
}

/// Decode an LZ4 raw block with the selected backend into caller-owned memory.
///
/// An unavailable architecture tag runs the scalar reference. Operator forcing
/// must go through [`Backend::force`](crate::Backend::force), which fails closed.
pub fn decompress_lz4_block_into(
    backend: Backend,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, Lz4DecompressError> {
    decompress(qualified_backend(backend), input, output, false)
}

/// Decode when the caller knows the exact uncompressed length and supplies a
/// slice of exactly that size. This enables bounded vector wild copies inside
/// the logical output range; malformed blocks still fail closed.
pub fn decompress_lz4_block_into_exact(
    backend: Backend,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, Lz4DecompressError> {
    decompress(qualified_backend(backend), input, output, true)
}

/// Checked scalar reference for differential qualification.
pub fn decompress_lz4_block_into_scalar(
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, Lz4DecompressError> {
    decompress(Backend::Scalar, input, output, false)
}

fn qualified_backend(backend: Backend) -> Backend {
    if backend.is_available() {
        backend
    } else {
        Backend::Scalar
    }
}

fn decompress(
    backend: Backend,
    input: &[u8],
    output: &mut [u8],
    exact_output: bool,
) -> Result<usize, Lz4DecompressError> {
    let mut input_pos = 0usize;
    let mut output_pos = 0usize;

    loop {
        let token = *input.get(input_pos).ok_or(Lz4DecompressError::Truncated)?;
        input_pos += 1;

        let literal_len = read_length(input, &mut input_pos, usize::from(token >> 4))?;
        let literal_end = input_pos
            .checked_add(literal_len)
            .ok_or(Lz4DecompressError::LengthOverflow)?;
        if literal_end > input.len() {
            return Err(Lz4DecompressError::LiteralOutOfBounds);
        }
        let output_after_literals = output_pos
            .checked_add(literal_len)
            .ok_or(Lz4DecompressError::LengthOverflow)?;
        ensure_output(output_after_literals, output.len())?;
        copy_literals(
            backend,
            &input[input_pos..],
            literal_len,
            &mut output[output_pos..],
            exact_output,
        );
        input_pos = literal_end;
        output_pos = output_after_literals;

        // A canonical LZ4 block terminates with its final literal sequence.
        if input_pos == input.len() {
            return Ok(output_pos);
        }

        let offset_bytes = input
            .get(input_pos..input_pos.saturating_add(2))
            .ok_or(Lz4DecompressError::Truncated)?;
        let offset = usize::from(u16::from_le_bytes([offset_bytes[0], offset_bytes[1]]));
        input_pos += 2;
        if offset == 0 {
            return Err(Lz4DecompressError::OffsetZero);
        }
        if offset > output_pos {
            return Err(Lz4DecompressError::OffsetOutOfBounds);
        }

        let encoded_match = usize::from(token & 0x0f);
        let match_without_min = read_length(input, &mut input_pos, encoded_match)?;
        let match_len = match_without_min
            .checked_add(MIN_MATCH)
            .ok_or(Lz4DecompressError::LengthOverflow)?;
        let output_after_match = output_pos
            .checked_add(match_len)
            .ok_or(Lz4DecompressError::LengthOverflow)?;
        ensure_output(output_after_match, output.len())?;
        copy_match(backend, output, output_pos, offset, match_len, exact_output);
        output_pos = output_after_match;
    }
}

fn read_length(
    input: &[u8],
    input_pos: &mut usize,
    nibble: usize,
) -> Result<usize, Lz4DecompressError> {
    if nibble != 15 {
        return Ok(nibble);
    }
    let mut length = nibble;
    loop {
        let extra = *input.get(*input_pos).ok_or(Lz4DecompressError::Truncated)?;
        *input_pos += 1;
        length = length
            .checked_add(usize::from(extra))
            .ok_or(Lz4DecompressError::LengthOverflow)?;
        if extra != u8::MAX {
            return Ok(length);
        }
    }
}

fn ensure_output(needed: usize, available: usize) -> Result<(), Lz4DecompressError> {
    if needed <= available {
        Ok(())
    } else {
        Err(Lz4DecompressError::OutputTooSmall { needed, available })
    }
}

fn copy_literals(
    backend: Backend,
    input: &[u8],
    literal_len: usize,
    output: &mut [u8],
    exact_output: bool,
) {
    debug_assert!(input.len() >= literal_len);
    debug_assert!(output.len() >= literal_len);
    let width = vector_width(backend);
    let floor = literal_len.checked_div(width).unwrap_or(0) * width;
    let rounded = literal_len
        .checked_add(width.saturating_sub(1))
        .and_then(|n| n.checked_div(width))
        .and_then(|n| n.checked_mul(width))
        .unwrap_or(floor);
    let vector_bytes = if exact_output && rounded <= input.len() && rounded <= output.len() {
        rounded
    } else {
        floor
    };
    let mut at = 0usize;
    while at < vector_bytes {
        // SAFETY: the parser proved the complete literal source and destination
        // ranges. This loop advances one non-overlapping vector width at a time.
        #[allow(unsafe_code)]
        unsafe {
            copy_vector(backend, input.as_ptr().add(at), output.as_mut_ptr().add(at));
        }
        at += width;
    }
    if at < literal_len {
        output[at..literal_len].copy_from_slice(&input[at..literal_len]);
    }
}

fn copy_match(
    backend: Backend,
    output: &mut [u8],
    output_pos: usize,
    offset: usize,
    match_len: usize,
    exact_output: bool,
) {
    let width = vector_width(backend);
    let mut copied = 0usize;
    let mut vector_offset = offset;

    // Seed a whole-number count of the short overlap period. Thereafter that
    // seeded region is itself a non-overlapping vector-width back-reference,
    // preserving the original phase for offsets such as 3 or 5.
    if width != 0 && offset < width {
        let periods = width.div_ceil(offset);
        let seed = periods.saturating_mul(offset).min(match_len);
        while copied < seed {
            let byte = output[output_pos - offset + copied];
            output[output_pos + copied] = byte;
            copied += 1;
        }
        if copied == match_len {
            return;
        }
        vector_offset = seed;
    }

    let remaining = match_len - copied;
    let floor = remaining.checked_div(width).unwrap_or(0) * width;
    let rounded = remaining
        .checked_add(width.saturating_sub(1))
        .and_then(|n| n.checked_div(width))
        .and_then(|n| n.checked_mul(width))
        .unwrap_or(floor);
    let vector_bytes = if vector_offset >= width
        && exact_output
        && output_pos
            .checked_add(copied)
            .and_then(|pos| pos.checked_add(rounded))
            .is_some_and(|end| end <= output.len())
    {
        rounded
    } else if vector_offset >= width {
        floor
    } else {
        0
    };
    let vector_end = copied + vector_bytes;
    while copied < vector_end {
        // SAFETY: the parser proved the match source starts in initialized
        // output and the destination range is in bounds. `offset >= width`
        // makes each vector source/destination pair non-overlapping. Earlier
        // iterations are complete before later LZ4 back-references observe them.
        #[allow(unsafe_code)]
        unsafe {
            let source = output.as_ptr().add(output_pos + copied - vector_offset);
            let destination = output.as_mut_ptr().add(output_pos + copied);
            copy_vector(backend, source, destination);
        }
        copied += width;
    }
    while copied < match_len {
        let byte = output[output_pos - offset + copied];
        output[output_pos + copied] = byte;
        copied += 1;
    }
}

const fn vector_width(backend: Backend) -> usize {
    match backend {
        Backend::Scalar => 0,
        #[cfg(target_arch = "aarch64")]
        Backend::Neon => 16,
        #[cfg(target_arch = "x86_64")]
        Backend::Avx2 => 32,
        #[cfg(target_arch = "x86_64")]
        Backend::Avx512 => 64,
        _ => 0,
    }
}

/// Copy exactly the qualified backend width from non-overlapping valid ranges.
#[allow(unsafe_code)]
unsafe fn copy_vector(backend: Backend, source: *const u8, destination: *mut u8) {
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let _ = (source, destination);
    match backend {
        #[cfg(target_arch = "aarch64")]
        Backend::Neon => {
            // SAFETY: caller proves readable/writable non-overlapping 16-byte ranges.
            unsafe { copy_neon(source, destination) };
        }
        #[cfg(target_arch = "x86_64")]
        Backend::Avx2 => {
            // SAFETY: runtime qualification and 32-byte ranges are proven upstream.
            unsafe { copy_avx2(source, destination) };
        }
        #[cfg(target_arch = "x86_64")]
        Backend::Avx512 => {
            // SAFETY: runtime qualification and 64-byte ranges are proven upstream.
            unsafe { copy_avx512(source, destination) };
        }
        _ => unreachable!("copy_vector called without a qualified vector backend"),
    }
}

/// Compare exactly the qualified backend width from two valid ranges.
#[allow(unsafe_code)]
unsafe fn vectors_equal(backend: Backend, left: *const u8, right: *const u8) -> bool {
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let _ = (left, right);
    match backend {
        #[cfg(target_arch = "aarch64")]
        Backend::Neon => {
            // SAFETY: caller proves two readable 16-byte ranges.
            unsafe { equal_neon(left, right) }
        }
        #[cfg(target_arch = "x86_64")]
        Backend::Avx2 => {
            // SAFETY: runtime qualification and 32-byte ranges are proven upstream.
            unsafe { equal_avx2(left, right) }
        }
        #[cfg(target_arch = "x86_64")]
        Backend::Avx512 => {
            // SAFETY: runtime qualification and 64-byte ranges are proven upstream.
            unsafe { equal_avx512(left, right) }
        }
        _ => unreachable!("vectors_equal called without a qualified vector backend"),
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(always)]
unsafe fn equal_neon(left: *const u8, right: *const u8) -> bool {
    use core::arch::aarch64::{vceqq_u8, vld1q_u8, vminvq_u8};

    // SAFETY: caller proves two readable 16-byte ranges; NEON is mandatory on
    // aarch64 and the unaligned loads are permitted.
    unsafe {
        let lhs = vld1q_u8(left);
        let rhs = vld1q_u8(right);
        vminvq_u8(vceqq_u8(lhs, rhs)) == u8::MAX
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx2")]
unsafe fn equal_avx2(left: *const u8, right: *const u8) -> bool {
    use core::arch::x86_64::{_mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8};

    // SAFETY: caller proves two readable 32-byte ranges.
    unsafe {
        let lhs = _mm256_loadu_si256(left.cast());
        let rhs = _mm256_loadu_si256(right.cast());
        _mm256_movemask_epi8(_mm256_cmpeq_epi8(lhs, rhs)) == -1
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx512f")]
unsafe fn equal_avx512(left: *const u8, right: *const u8) -> bool {
    use core::arch::x86_64::{_mm512_cmpeq_epi64_mask, _mm512_maskz_loadu_epi64};

    // SAFETY: caller proves two readable 64-byte ranges.
    unsafe {
        let lhs = _mm512_maskz_loadu_epi64(0xff, left.cast());
        let rhs = _mm512_maskz_loadu_epi64(0xff, right.cast());
        _mm512_cmpeq_epi64_mask(lhs, rhs) == 0xff
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(always)]
unsafe fn copy_neon(source: *const u8, destination: *mut u8) {
    use core::arch::asm;

    // SAFETY: caller proves one readable and one writable 16-byte range.
    unsafe {
        asm!(
            "ldr q0, [{source}]",
            "str q0, [{destination}]",
            source = in(reg) source,
            destination = in(reg) destination,
            out("v0") _,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx2")]
unsafe fn copy_avx2(source: *const u8, destination: *mut u8) {
    use core::arch::x86_64::{_mm256_loadu_si256, _mm256_storeu_si256};

    // SAFETY: caller proves one readable and one writable 32-byte range.
    unsafe {
        let value = _mm256_loadu_si256(source.cast());
        _mm256_storeu_si256(destination.cast(), value);
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[target_feature(enable = "avx512f")]
unsafe fn copy_avx512(source: *const u8, destination: *mut u8) {
    use core::arch::x86_64::{_mm512_mask_storeu_epi64, _mm512_maskz_loadu_epi64};

    // SAFETY: caller proves one readable and one writable 64-byte range.
    unsafe {
        let value = _mm512_maskz_loadu_epi64(0xff, source.cast());
        _mm512_mask_storeu_epi64(destination.cast(), 0xff, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lz4_flex::block::{compress, decompress_into, get_maximum_output_size};

    fn corpus(len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for i in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let repeated = i >= 96 && i % 5 != 0;
            bytes.push(if repeated {
                bytes[i - 48]
            } else {
                state.to_le_bytes()[0]
            });
        }
        bytes
    }

    #[test]
    fn scalar_and_every_backend_decode_lz4_flex_blocks_bit_identically() {
        for len in [1, 3, 15, 16, 31, 32, 47, 48, 63, 64, 127, 1024, 6144] {
            let original = corpus(len);
            let compressed = compress(&original);
            let mut expected = vec![0xa5; len + 17];
            let expected_len = decompress_into(&compressed, &mut expected).unwrap();
            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut actual = vec![0xa5; len + 17];
                let actual_len =
                    decompress_lz4_block_into(backend, &compressed, &mut actual).unwrap();
                assert_eq!(actual_len, expected_len, "backend={backend:?} len={len}");
                assert_eq!(
                    &actual[..actual_len],
                    &expected[..expected_len],
                    "backend={backend:?} len={len}"
                );
                assert!(actual[actual_len..].iter().all(|&byte| byte == 0xa5));
            }
        }
    }

    #[test]
    fn scalar_and_every_backend_compress_to_identical_valid_lz4_blocks() {
        for len in [1, 3, 15, 16, 31, 32, 47, 48, 63, 64, 127, 1024, 6144] {
            let original = corpus(len);
            let mut scalar_codec = Lz4Compressor::new();
            let mut scalar = vec![0xa5; get_maximum_output_size(len)];
            let scalar_len = scalar_codec
                .compress_into(Backend::Scalar, &original, &mut scalar)
                .unwrap();
            let mut decoded = vec![0; len];
            assert_eq!(
                decompress_into(&scalar[..scalar_len], &mut decoded).unwrap(),
                len
            );
            assert_eq!(decoded, original);

            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut codec = Lz4Compressor::new();
                let mut actual = vec![0xa5; get_maximum_output_size(len)];
                let actual_len = codec
                    .compress_into(backend, &original, &mut actual)
                    .unwrap();
                assert_eq!(actual_len, scalar_len, "backend={backend:?} len={len}");
                assert_eq!(
                    &actual[..actual_len],
                    &scalar[..scalar_len],
                    "backend={backend:?} len={len}"
                );
                assert!(actual[actual_len..].iter().all(|&byte| byte == 0xa5));
            }
        }
    }

    #[test]
    fn compressor_reuses_generation_table_and_enforces_bounds() {
        let mut codec = Lz4Compressor::new();
        for round in 0..100 {
            let original = if round % 2 == 0 {
                corpus(4096)
            } else {
                vec![u8::try_from(round).unwrap_or(0); 4096]
            };
            let mut compressed = vec![0; get_maximum_output_size(original.len())];
            let written = codec
                .compress_into(Backend::Scalar, &original, &mut compressed)
                .unwrap();
            let mut decoded = vec![0; original.len()];
            decompress_into(&compressed[..written], &mut decoded).unwrap();
            assert_eq!(decoded, original);
        }

        let mut short = [0u8; 1];
        assert_eq!(
            codec.compress_into(Backend::Scalar, &corpus(1024), &mut short),
            Err(Lz4CompressError::OutputTooSmall)
        );
        let oversized = vec![0; 64 * 1024 + 1];
        assert_eq!(
            codec.compress_into(Backend::Scalar, &oversized, &mut []),
            Err(Lz4CompressError::InputTooLarge)
        );
    }

    #[test]
    fn randomized_compress_corpus_is_backend_identical_and_reference_decodable() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for case in 0..512usize {
            let len = case * 37 % 8193;
            let mut original = vec![0u8; len];
            for index in 0..original.len() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                original[index] = if index >= 64 && (state & 3) != 0 {
                    original[index - 48]
                } else {
                    state.to_le_bytes()[0]
                };
            }
            let capacity = get_maximum_output_size(len);
            let mut scalar_codec = Lz4Compressor::new();
            let mut scalar = vec![0; capacity];
            let scalar_len = scalar_codec
                .compress_into(Backend::Scalar, &original, &mut scalar)
                .unwrap();
            let mut decoded = vec![0; len];
            assert_eq!(
                decompress_into(&scalar[..scalar_len], &mut decoded).unwrap(),
                len
            );
            assert_eq!(decoded, original);
            for backend in [Backend::Avx2, Backend::Avx512, Backend::Neon] {
                let mut codec = Lz4Compressor::new();
                let mut actual = vec![0; capacity];
                let actual_len = codec
                    .compress_into(backend, &original, &mut actual)
                    .unwrap();
                assert_eq!(actual_len, scalar_len, "backend={backend:?} case={case}");
                assert_eq!(
                    &actual[..actual_len],
                    &scalar[..scalar_len],
                    "backend={backend:?} case={case}"
                );
            }
        }
    }

    #[test]
    fn arbitrary_compressed_bytes_never_panic_or_diverge_by_backend() {
        let mut state = 0x1319_8a2e_0370_7344u64;
        for case in 0..2048usize {
            let len = case % 257;
            let mut input = vec![0u8; len];
            for byte in &mut input {
                state = state
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
                *byte = state.to_le_bytes()[0];
            }
            let mut scalar_output = [0xa5; 512];
            let scalar = decompress_lz4_block_into_scalar(&input, &mut scalar_output);
            for backend in [Backend::Avx2, Backend::Avx512, Backend::Neon] {
                let mut actual_output = [0xa5; 512];
                let actual = decompress_lz4_block_into(backend, &input, &mut actual_output);
                assert_eq!(actual, scalar, "backend={backend:?} case={case}");
                assert_eq!(
                    actual_output, scalar_output,
                    "backend={backend:?} case={case}"
                );
            }
        }
    }

    #[test]
    fn overlap_offsets_and_long_length_extensions_match_reference() {
        for original in [
            vec![b'x'; 8192],
            b"abcabcabcabcabcabcabcabcabcabcabcabc".to_vec(),
            (0..8192).map(|i| (i % 251) as u8).collect(),
        ] {
            let compressed = compress(&original);
            let mut reference = vec![0; original.len()];
            decompress_into(&compressed, &mut reference).unwrap();
            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut actual = vec![0; original.len()];
                let written = decompress_lz4_block_into(backend, &compressed, &mut actual).unwrap();
                assert_eq!(written, original.len());
                assert_eq!(actual, reference, "backend={backend:?}");
            }
        }
    }

    #[test]
    fn malformed_blocks_fail_without_panicking_on_every_backend() {
        let cases: &[&[u8]] = &[
            &[],
            &[0xf0],
            &[0x00, 0x00],
            &[0x00, 0x00, 0x00],
            &[0x10],
            &[0x1f, b'x', 1, 0],
            &[0xf0, 255, 255],
        ];
        for input in cases {
            let mut scalar_out = [0xa5; 128];
            let scalar = decompress_lz4_block_into_scalar(input, &mut scalar_out);
            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut actual_out = [0xa5; 128];
                let actual = decompress_lz4_block_into(backend, input, &mut actual_out);
                assert_eq!(actual, scalar, "backend={backend:?} input={input:?}");
                assert_eq!(
                    actual_out, scalar_out,
                    "backend={backend:?} input={input:?}"
                );
            }
        }
    }

    #[test]
    fn output_cap_is_enforced_before_any_out_of_bounds_write() {
        let original = corpus(1024);
        let compressed = compress(&original);
        let mut short = [0xa5; 31];
        assert!(matches!(
            decompress_lz4_block_into(Backend::Scalar, &compressed, &mut short),
            Err(Lz4DecompressError::OutputTooSmall { .. })
        ));
    }
}
