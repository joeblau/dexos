//! Bounded pooled LZ4 envelopes for 32-128 authenticated packed order records.

use codec::PackedOrder;
use lz4_flex::block::{compress_into_with_table, get_maximum_output_size, CompressTable};
use simd::Backend;

const MAGIC: u16 = 0xB417;
/// Initial order-batch envelope version.
pub const ORDER_BATCH_VERSION: u8 = 1;
/// Fixed envelope bytes before the raw/LZ4 payload.
pub const ORDER_BATCH_HEADER_LEN: usize = 20;
/// Hard decompression ceiling. Packed v1's maximum is 128*56 = 7168 bytes;
/// the larger ceiling leaves bounded room for negotiated future records.
pub const ORDER_BATCH_MAX_UNCOMPRESSED: usize = 64 * 1024;
/// Maximum inner envelope length using the LZ4 block worst-case bound.
pub const ORDER_BATCH_MAX_WIRE: usize =
    ORDER_BATCH_HEADER_LEN + ORDER_BATCH_MAX_UNCOMPRESSED + ORDER_BATCH_MAX_UNCOMPRESSED / 255 + 16;
const FLAG_RAW: u8 = 1 << 0;
const FLAG_PARTIAL: u8 = 1 << 1;
const KNOWN_FLAGS: u8 = FLAG_RAW | FLAG_PARTIAL;
const BACKEND_RAW_OR_LEGACY_SCALAR: u8 = 0;
const BACKEND_LZ4_RUNTIME_SIMD: u8 = 1;

/// Reusable worker-local encoder. Its table and wire buffer allocate at startup.
pub struct OrderBatchCodec {
    compressor: simd::Lz4Compressor,
    scalar_table: CompressTable,
    wire: Vec<u8>,
    stats: OrderBatchStats,
}

impl OrderBatchCodec {
    /// Preallocate enough memory for every accepted envelope.
    #[must_use]
    pub fn new() -> Self {
        let payload_cap = get_maximum_output_size(ORDER_BATCH_MAX_UNCOMPRESSED);
        let wire = vec![0; ORDER_BATCH_HEADER_LEN.saturating_add(payload_cap)];
        Self {
            compressor: simd::Lz4Compressor::new(),
            scalar_table: CompressTable::large(),
            wire,
            stats: OrderBatchStats::default(),
        }
    }

    /// Compress a canonical packed-record sequence, retaining raw bytes when LZ4
    /// would not reduce payload length. The returned bytes borrow the pooled buffer.
    pub fn encode(
        &mut self,
        record_count: u8,
        partial: bool,
        records: &[u8],
    ) -> Result<EncodedOrderBatch<'_>, OrderBatchError> {
        self.encode_with_backend(record_count, partial, records, simd::detect())
    }

    /// Encode with an explicit qualified backend for scalar/SIMD differential
    /// tests and paired production-size benchmarks.
    pub fn encode_with_backend(
        &mut self,
        record_count: u8,
        partial: bool,
        records: &[u8],
        backend: Backend,
    ) -> Result<EncodedOrderBatch<'_>, OrderBatchError> {
        validate_count(record_count, partial)?;
        if records.is_empty() || records.len() > ORDER_BATCH_MAX_UNCOMPRESSED {
            return Err(OrderBatchError::UncompressedLengthOutOfRange(records.len()));
        }
        validate_records(records, record_count)?;
        // The fixed match finder is qualified at 32 records. At 64/128 its
        // extra probing cost outweighed its vector match-extension win on the
        // production corpus, so those sizes deliberately retain the mature
        // scalar compressor while still using SIMD decode.
        let compressed = if record_count == 32 {
            self.compressor
                .compress_into(backend, records, &mut self.wire[ORDER_BATCH_HEADER_LEN..])
                .map_err(|_| OrderBatchError::Compression)?
        } else {
            compress_into_with_table(
                records,
                &mut self.wire[ORDER_BATCH_HEADER_LEN..],
                &mut self.scalar_table,
            )
            .map_err(|_| OrderBatchError::Compression)?
        };
        let raw = compressed >= records.len();
        let payload_len = if raw {
            self.wire[ORDER_BATCH_HEADER_LEN..ORDER_BATCH_HEADER_LEN + records.len()]
                .copy_from_slice(records);
            records.len()
        } else {
            compressed
        };
        let flags = (u8::from(raw) * FLAG_RAW) | (u8::from(partial) * FLAG_PARTIAL);
        let backend = if raw {
            BACKEND_RAW_OR_LEGACY_SCALAR
        } else {
            BACKEND_LZ4_RUNTIME_SIMD
        };
        write_header(
            &mut self.wire[..ORDER_BATCH_HEADER_LEN],
            flags,
            backend,
            record_count,
            records.len(),
            payload_len,
            crc32(records),
        )?;
        let wire_len = ORDER_BATCH_HEADER_LEN + payload_len;
        self.stats.input_bytes = self
            .stats
            .input_bytes
            .saturating_add(u64::try_from(records.len()).unwrap_or(u64::MAX));
        self.stats.wire_bytes = self
            .stats
            .wire_bytes
            .saturating_add(u64::try_from(wire_len).unwrap_or(u64::MAX));
        if partial {
            self.stats.partial_batches = self.stats.partial_batches.saturating_add(1);
        } else {
            self.stats.full_batches = self.stats.full_batches.saturating_add(1);
        }
        if raw {
            self.stats.raw_batches = self.stats.raw_batches.saturating_add(1);
        } else {
            self.stats.compressed_batches = self.stats.compressed_batches.saturating_add(1);
        }
        Ok(EncodedOrderBatch {
            bytes: &self.wire[..wire_len],
            record_count,
            raw,
            partial,
            uncompressed_len: records.len(),
        })
    }

    /// Observable full/partial and raw/compressed counters.
    #[must_use]
    pub const fn stats(&self) -> OrderBatchStats {
        self.stats
    }

    /// Read and validate the signed inner header's record count without
    /// decompressing. Full decode still validates lengths, integrity, and records.
    pub fn inspect_record_count(envelope: &[u8]) -> Result<u8, OrderBatchError> {
        let header = parse_header(envelope)?;
        validate_count(header.record_count, header.partial)?;
        let end = ORDER_BATCH_HEADER_LEN
            .checked_add(header.payload_len)
            .ok_or(OrderBatchError::LengthOutOfRange)?;
        if end != envelope.len() {
            return Err(if end > envelope.len() {
                OrderBatchError::Truncated
            } else {
                OrderBatchError::TrailingBytes
            });
        }
        Ok(header.record_count)
    }

    /// Strictly decode into caller-owned bounded memory.
    pub fn decode_into<'a>(
        envelope: &'a [u8],
        output: &'a mut [u8],
    ) -> Result<DecodedOrderBatch<'a>, OrderBatchError> {
        Self::decode_into_with_backend(envelope, output, simd::detect())
    }

    /// Decode with an explicit qualified CPU backend. This is public so paired
    /// scalar/SIMD benchmarks and differential gates exercise identical envelopes.
    pub fn decode_into_with_backend<'a>(
        envelope: &'a [u8],
        output: &'a mut [u8],
        backend: Backend,
    ) -> Result<DecodedOrderBatch<'a>, OrderBatchError> {
        let decoded = Self::decode_payload_into_with_backend(envelope, output, backend)?;
        validate_records(decoded.records, decoded.record_count)?;
        Ok(decoded)
    }

    /// Decode, integrity-check, and materialize typed records in one validation
    /// pass. This avoids parsing every packed record once in the network layer
    /// and again at shard admission while retaining the same fail-closed checks.
    pub fn decode_records_into_with_backend<'records>(
        envelope: &[u8],
        output: &mut [u8],
        records: &'records mut [PackedOrder],
        backend: Backend,
    ) -> Result<DecodedPackedOrderBatch<'records>, OrderBatchError> {
        let decoded = Self::decode_payload_into_with_backend(envelope, output, backend)?;
        let count = usize::from(decoded.record_count);
        let available = records.len();
        let target = records
            .get_mut(..count)
            .ok_or(OrderBatchError::RecordOutputTooSmall {
                needed: count,
                available,
            })?;
        let mut at = 0usize;
        for slot in target.iter_mut() {
            let remaining = decoded
                .records
                .get(at..)
                .ok_or(OrderBatchError::InvalidRecord(
                    codec::PackedOrderError::Truncated,
                ))?;
            let (view, consumed) = PackedOrder::decode_ref_with_backend(decoded.backend, remaining)
                .map_err(OrderBatchError::InvalidRecord)?;
            *slot = view.record();
            at = at
                .checked_add(consumed)
                .ok_or(OrderBatchError::LengthOutOfRange)?;
        }
        if at != decoded.records.len() {
            return Err(OrderBatchError::InvalidRecord(
                codec::PackedOrderError::TrailingBytes,
            ));
        }
        Ok(DecodedPackedOrderBatch {
            records: target,
            raw: decoded.raw,
            partial: decoded.partial,
            backend: decoded.backend,
        })
    }

    /// Runtime-dispatched typed form of [`Self::decode_records_into_with_backend`].
    pub fn decode_records_into<'records>(
        envelope: &[u8],
        output: &mut [u8],
        records: &'records mut [PackedOrder],
    ) -> Result<DecodedPackedOrderBatch<'records>, OrderBatchError> {
        Self::decode_records_into_with_backend(envelope, output, records, simd::detect())
    }

    fn decode_payload_into_with_backend<'a>(
        envelope: &'a [u8],
        output: &'a mut [u8],
        backend: Backend,
    ) -> Result<DecodedOrderBatch<'a>, OrderBatchError> {
        let header = parse_header(envelope)?;
        validate_count(header.record_count, header.partial)?;
        if header.uncompressed_len == 0 || header.uncompressed_len > ORDER_BATCH_MAX_UNCOMPRESSED {
            return Err(OrderBatchError::UncompressedLengthOutOfRange(
                header.uncompressed_len,
            ));
        }
        let end = ORDER_BATCH_HEADER_LEN
            .checked_add(header.payload_len)
            .ok_or(OrderBatchError::LengthOutOfRange)?;
        if end != envelope.len() {
            return Err(if end > envelope.len() {
                OrderBatchError::Truncated
            } else {
                OrderBatchError::TrailingBytes
            });
        }
        let payload = &envelope[ORDER_BATCH_HEADER_LEN..end];
        let decoded = if header.raw {
            if header.payload_len != header.uncompressed_len {
                return Err(OrderBatchError::RawLengthMismatch);
            }
            payload
        } else {
            let available = output.len();
            let target = output.get_mut(..header.uncompressed_len).ok_or(
                OrderBatchError::OutputTooSmall {
                    needed: header.uncompressed_len,
                    available,
                },
            )?;
            let written = simd::decompress_lz4_block_into_exact(backend, payload, target)
                .map_err(|_| OrderBatchError::InvalidCompressedPayload)?;
            if written != header.uncompressed_len {
                return Err(OrderBatchError::DecompressedLengthMismatch {
                    expected: header.uncompressed_len,
                    actual: written,
                });
            }
            &target[..written]
        };
        if crc32(decoded) != header.crc32 {
            return Err(OrderBatchError::IntegrityMismatch);
        }
        Ok(DecodedOrderBatch {
            records: decoded,
            record_count: header.record_count,
            raw: header.raw,
            partial: header.partial,
            backend: if header.raw {
                Backend::Scalar
            } else if backend.is_available() {
                backend
            } else {
                Backend::Scalar
            },
        })
    }
}

impl Default for OrderBatchCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowed encoded envelope plus visible fallback classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedOrderBatch<'a> {
    pub bytes: &'a [u8],
    pub record_count: u8,
    pub raw: bool,
    pub partial: bool,
    pub uncompressed_len: usize,
}

/// Borrowed validated record sequence. It points at the input for raw envelopes
/// or at caller-owned output for compressed envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedOrderBatch<'a> {
    pub records: &'a [u8],
    pub record_count: u8,
    pub raw: bool,
    pub partial: bool,
    /// Backend that performed LZ4 decode; raw payloads report scalar.
    pub backend: Backend,
}

/// Caller-owned typed records decoded and validated exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedPackedOrderBatch<'a> {
    pub records: &'a [PackedOrder],
    pub raw: bool,
    pub partial: bool,
    /// Backend used for LZ4 and packed-lane decoding.
    pub backend: Backend,
}

/// Counters needed to prove full-load batching and expose fallbacks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OrderBatchStats {
    pub full_batches: u64,
    pub partial_batches: u64,
    pub compressed_batches: u64,
    pub raw_batches: u64,
    pub input_bytes: u64,
    pub wire_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OrderBatchError {
    #[error("order batch header is truncated")]
    Truncated,
    #[error("bad order batch magic")]
    BadMagic,
    #[error("unsupported order batch version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown order batch flags {0:#04x}")]
    UnknownFlags(u8),
    #[error("unknown order batch compression backend {0}")]
    UnknownBackend(u8),
    #[error("reserved order batch header bytes are nonzero")]
    ReservedHeader,
    #[error("full/partial batch record count {0} is invalid")]
    RecordCountOutOfRange(u8),
    #[error("batch contains {actual} packed records, expected {expected}")]
    RecordCountMismatch { expected: u8, actual: u8 },
    #[error("uncompressed length {0} is outside the cap")]
    UncompressedLengthOutOfRange(usize),
    #[error("payload length is out of range")]
    LengthOutOfRange,
    #[error("raw payload and uncompressed lengths differ")]
    RawLengthMismatch,
    #[error("envelope has trailing bytes")]
    TrailingBytes,
    #[error("output buffer has {available} bytes, needs {needed}")]
    OutputTooSmall { needed: usize, available: usize },
    #[error("typed record output has {available} slots, needs {needed}")]
    RecordOutputTooSmall { needed: usize, available: usize },
    #[error("LZ4 compression failed")]
    Compression,
    #[error("invalid LZ4 payload")]
    InvalidCompressedPayload,
    #[error("decompressed {actual} bytes, expected {expected}")]
    DecompressedLengthMismatch { expected: usize, actual: usize },
    #[error("order batch integrity check failed")]
    IntegrityMismatch,
    #[error("invalid packed record in order batch: {0}")]
    InvalidRecord(codec::PackedOrderError),
}

#[derive(Debug, Clone, Copy)]
struct Header {
    raw: bool,
    partial: bool,
    record_count: u8,
    uncompressed_len: usize,
    payload_len: usize,
    crc32: u32,
}

fn validate_count(count: u8, partial: bool) -> Result<(), OrderBatchError> {
    let valid = if partial {
        (1..32).contains(&count)
    } else {
        (32..=128).contains(&count)
    };
    if valid {
        Ok(())
    } else {
        Err(OrderBatchError::RecordCountOutOfRange(count))
    }
}

fn validate_records(bytes: &[u8], expected: u8) -> Result<(), OrderBatchError> {
    let mut at = 0usize;
    let mut actual = 0u8;
    while at < bytes.len() {
        let (_, consumed) =
            PackedOrder::decode_ref(&bytes[at..]).map_err(OrderBatchError::InvalidRecord)?;
        at = at
            .checked_add(consumed)
            .ok_or(OrderBatchError::LengthOutOfRange)?;
        actual = actual
            .checked_add(1)
            .ok_or(OrderBatchError::RecordCountMismatch {
                expected,
                actual: u8::MAX,
            })?;
    }
    if actual == expected {
        Ok(())
    } else {
        Err(OrderBatchError::RecordCountMismatch { expected, actual })
    }
}

fn write_header(
    out: &mut [u8],
    flags: u8,
    backend: u8,
    record_count: u8,
    uncompressed_len: usize,
    payload_len: usize,
    crc: u32,
) -> Result<(), OrderBatchError> {
    out[0..2].copy_from_slice(&MAGIC.to_le_bytes());
    out[2] = ORDER_BATCH_VERSION;
    out[3] = flags;
    out[4] = backend;
    out[5] = record_count;
    out[6..8].fill(0);
    out[8..12].copy_from_slice(
        &u32::try_from(uncompressed_len)
            .map_err(|_| OrderBatchError::LengthOutOfRange)?
            .to_le_bytes(),
    );
    out[12..16].copy_from_slice(
        &u32::try_from(payload_len)
            .map_err(|_| OrderBatchError::LengthOutOfRange)?
            .to_le_bytes(),
    );
    out[16..20].copy_from_slice(&crc.to_le_bytes());
    Ok(())
}

fn parse_header(bytes: &[u8]) -> Result<Header, OrderBatchError> {
    let h = bytes
        .get(..ORDER_BATCH_HEADER_LEN)
        .ok_or(OrderBatchError::Truncated)?;
    if u16::from_le_bytes([h[0], h[1]]) != MAGIC {
        return Err(OrderBatchError::BadMagic);
    }
    if h[2] != ORDER_BATCH_VERSION {
        return Err(OrderBatchError::UnsupportedVersion(h[2]));
    }
    if h[3] & !KNOWN_FLAGS != 0 {
        return Err(OrderBatchError::UnknownFlags(h[3]));
    }
    if !matches!(
        h[4],
        BACKEND_RAW_OR_LEGACY_SCALAR | BACKEND_LZ4_RUNTIME_SIMD
    ) {
        return Err(OrderBatchError::UnknownBackend(h[4]));
    }
    if h[6] != 0 || h[7] != 0 {
        return Err(OrderBatchError::ReservedHeader);
    }
    Ok(Header {
        raw: h[3] & FLAG_RAW != 0,
        partial: h[3] & FLAG_PARTIAL != 0,
        record_count: h[5],
        uncompressed_len: u32::from_le_bytes(h[8..12].try_into().unwrap_or([0; 4])) as usize,
        payload_len: u32::from_le_bytes(h[12..16].try_into().unwrap_or([0; 4])) as usize,
        crc32: u32::from_le_bytes(h[16..20].try_into().unwrap_or([0; 4])),
    })
}

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    let mut seed = 0u32;
    while i < table.len() {
        let mut value = seed;
        let mut bit = 0;
        while bit < 8 {
            let mask = 0u32.wrapping_sub(value & 1);
            value = (value >> 1) ^ (0xEDB8_8320 & mask);
            bit += 1;
        }
        table[i] = value;
        i += 1;
        seed += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_slicing_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    tables[0] = CRC32_TABLE;
    let mut slice = 1usize;
    while slice < tables.len() {
        let mut byte = 0usize;
        while byte < 256 {
            let previous = tables[slice - 1][byte];
            tables[slice][byte] = (previous >> 8) ^ CRC32_TABLE[(previous & 0xff) as usize];
            byte += 1;
        }
        slice += 1;
    }
    tables
}

const CRC32_SLICING: [[u32; 256]; 8] = crc32_slicing_tables();

/// Dependency-free reflected IEEE CRC-32 over the uncompressed canonical bytes.
/// The table is generated at compile time; the hot loop performs one cached
/// lookup per byte instead of eight data-dependent polynomial rounds.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let first = u32::from_le_bytes(chunk[..4].try_into().unwrap_or([0; 4])) ^ crc;
        let second = u32::from_le_bytes(chunk[4..].try_into().unwrap_or([0; 4]));
        crc = CRC32_SLICING[7][usize::try_from(first & 0xff).unwrap_or(0)]
            ^ CRC32_SLICING[6][usize::try_from((first >> 8) & 0xff).unwrap_or(0)]
            ^ CRC32_SLICING[5][usize::try_from((first >> 16) & 0xff).unwrap_or(0)]
            ^ CRC32_SLICING[4][usize::try_from(first >> 24).unwrap_or(0)]
            ^ CRC32_SLICING[3][usize::try_from(second & 0xff).unwrap_or(0)]
            ^ CRC32_SLICING[2][usize::try_from((second >> 8) & 0xff).unwrap_or(0)]
            ^ CRC32_SLICING[1][usize::try_from((second >> 16) & 0xff).unwrap_or(0)]
            ^ CRC32_SLICING[0][usize::try_from(second >> 24).unwrap_or(0)];
    }
    for &byte in chunks.remainder() {
        let index = usize::try_from((crc ^ u32::from(byte)) & 0xff).unwrap_or(0);
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::PackedOrder;
    use types::{AccountId, MarketId, OrderId};

    fn records(count: u8, varying: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(usize::from(count) * 32);
        for i in 0..count {
            let record = PackedOrder::Cancel {
                session_ref: 7,
                nonce: if varying { u64::from(i) + 1 } else { 1 },
                client_id: u64::from(i) + 100,
                account: AccountId::new(if varying { u32::from(i) + 1 } else { 1 }),
                market: MarketId::new(2),
                order_id: OrderId::new(u64::from(i) + 1),
            };
            let start = out.len();
            out.resize(start + record.encoded_len(), 0);
            record.encode_into(&mut out[start..]).unwrap();
        }
        out
    }

    #[test]
    fn full_32_64_128_batches_round_trip() {
        for count in [32, 64, 128] {
            let input = records(count, false);
            let mut codec = OrderBatchCodec::new();
            let encoded = codec.encode(count, false, &input).unwrap();
            assert!(!encoded.partial);
            let mut output = vec![0; ORDER_BATCH_MAX_UNCOMPRESSED];
            let decoded = OrderBatchCodec::decode_into(encoded.bytes, &mut output).unwrap();
            assert_eq!(decoded.records, input);
            assert_eq!(decoded.record_count, count);
            assert_eq!(decoded.backend, simd::detect());
        }
    }

    #[test]
    fn fused_typed_decode_matches_validated_byte_decode() {
        let placeholder = PackedOrder::Cancel {
            session_ref: 0,
            nonce: 0,
            client_id: 0,
            account: AccountId::new(0),
            market: MarketId::new(0),
            order_id: OrderId::new(1),
        };
        for count in [32, 64, 128] {
            let input = records(count, true);
            let mut codec = OrderBatchCodec::new();
            let envelope = codec.encode(count, false, &input).unwrap().bytes.to_vec();
            let mut byte_output = vec![0; ORDER_BATCH_MAX_UNCOMPRESSED];
            let bytes = OrderBatchCodec::decode_into(&envelope, &mut byte_output)
                .unwrap()
                .records
                .to_vec();
            let mut typed_output = [placeholder; 128];
            let mut typed_bytes = vec![0; ORDER_BATCH_MAX_UNCOMPRESSED];
            let typed = OrderBatchCodec::decode_records_into(
                &envelope,
                &mut typed_bytes,
                &mut typed_output,
            )
            .unwrap();
            assert_eq!(typed.records.len(), usize::from(count));
            let mut reencoded = vec![0; bytes.len()];
            let written = codec::encode_batch_into(typed.records, &mut reencoded).unwrap();
            assert_eq!(&reencoded[..written], bytes);

            let mut too_small = [placeholder; 31];
            assert_eq!(
                OrderBatchCodec::decode_records_into(&envelope, &mut typed_bytes, &mut too_small,),
                Err(OrderBatchError::RecordOutputTooSmall {
                    needed: usize::from(count),
                    available: 31,
                })
            );
        }
    }

    #[test]
    fn scalar_and_runtime_backends_are_identical_at_every_batch_size() {
        for count in [32, 64, 128] {
            let input = records(count, false);
            let mut codec = OrderBatchCodec::new();
            let envelope = codec.encode(count, false, &input).unwrap().bytes.to_vec();
            let mut scalar_output = vec![0xa5; ORDER_BATCH_MAX_UNCOMPRESSED];
            let scalar_records = {
                let scalar = OrderBatchCodec::decode_into_with_backend(
                    &envelope,
                    &mut scalar_output,
                    Backend::Scalar,
                )
                .unwrap();
                assert_eq!(scalar.backend, Backend::Scalar);
                scalar.records.to_vec()
            };
            let scalar_len = scalar_records.len();
            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut actual_output = vec![0xa5; ORDER_BATCH_MAX_UNCOMPRESSED];
                let (actual_records, actual_backend) = {
                    let actual = OrderBatchCodec::decode_into_with_backend(
                        &envelope,
                        &mut actual_output,
                        backend,
                    )
                    .unwrap();
                    (actual.records.to_vec(), actual.backend)
                };
                assert_eq!(actual_records, scalar_records, "backend={backend:?}");
                assert_eq!(
                    &actual_output[..scalar_len],
                    &scalar_output[..scalar_len],
                    "backend={backend:?}"
                );
                let expected_backend = if backend.is_available() {
                    backend
                } else {
                    Backend::Scalar
                };
                assert_eq!(actual_backend, expected_backend);
            }
        }
    }

    #[test]
    fn scalar_and_runtime_encoders_emit_identical_envelopes() {
        for count in [32, 64, 128] {
            let input = records(count, false);
            let mut scalar_codec = OrderBatchCodec::new();
            let scalar = scalar_codec
                .encode_with_backend(count, false, &input, Backend::Scalar)
                .unwrap()
                .bytes
                .to_vec();
            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut actual_codec = OrderBatchCodec::new();
                let actual = actual_codec
                    .encode_with_backend(count, false, &input, backend)
                    .unwrap()
                    .bytes
                    .to_vec();
                assert_eq!(actual, scalar, "backend={backend:?} count={count}");
            }
        }
    }

    #[test]
    fn malformed_lz4_has_identical_error_and_output_on_every_backend() {
        let input = records(32, false);
        let mut codec = OrderBatchCodec::new();
        let original = codec.encode(32, false, &input).unwrap().bytes.to_vec();
        assert_eq!(original[4], BACKEND_LZ4_RUNTIME_SIMD);
        for cut in ORDER_BATCH_HEADER_LEN..original.len() {
            let envelope = &original[..cut];
            let mut scalar_output = vec![0xa5; ORDER_BATCH_MAX_UNCOMPRESSED];
            let scalar = OrderBatchCodec::decode_into_with_backend(
                envelope,
                &mut scalar_output,
                Backend::Scalar,
            )
            .unwrap_err();
            for backend in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                let mut actual_output = vec![0xa5; ORDER_BATCH_MAX_UNCOMPRESSED];
                let actual = OrderBatchCodec::decode_into_with_backend(
                    envelope,
                    &mut actual_output,
                    backend,
                )
                .unwrap_err();
                assert_eq!(actual, scalar, "backend={backend:?} cut={cut}");
                assert_eq!(
                    actual_output, scalar_output,
                    "backend={backend:?} cut={cut}"
                );
            }
        }
    }

    #[test]
    fn legacy_scalar_backend_tag_and_unknown_tags_fail_compatibly() {
        let input = records(32, false);
        let mut codec = OrderBatchCodec::new();
        let mut envelope = codec.encode(32, false, &input).unwrap().bytes.to_vec();
        envelope[4] = BACKEND_RAW_OR_LEGACY_SCALAR;
        let mut output = vec![0; ORDER_BATCH_MAX_UNCOMPRESSED];
        assert_eq!(
            OrderBatchCodec::decode_into(&envelope, &mut output)
                .unwrap()
                .records,
            input
        );
        envelope[4] = 0xff;
        assert_eq!(
            OrderBatchCodec::decode_into(&envelope, &mut output),
            Err(OrderBatchError::UnknownBackend(0xff))
        );
    }

    #[test]
    fn incompressible_fallback_and_partial_are_visible() {
        let record = PackedOrder::Cancel {
            session_ref: 0x89ab_cdef,
            nonce: 0x0123_4567_89ab_cdef,
            client_id: 0xf0e1_d2c3_b4a5_9687,
            account: AccountId::new(0x1357_9bdf),
            market: MarketId::new(0x2468_ace0),
            order_id: OrderId::new(0xfedc_ba98_7654_3210),
        };
        let mut input = vec![0; record.encoded_len()];
        record.encode_into(&mut input).unwrap();
        let mut codec = OrderBatchCodec::new();
        let encoded = codec.encode(1, true, &input).unwrap();
        assert!(encoded.partial);
        assert!(
            encoded.raw,
            "a single 32-byte record must not be expanded by LZ4"
        );
        let mut output = vec![0; ORDER_BATCH_MAX_UNCOMPRESSED];
        let decoded = OrderBatchCodec::decode_into(encoded.bytes, &mut output).unwrap();
        assert_eq!(decoded.records, input);
        let stats = codec.stats();
        assert_eq!(stats.partial_batches, 1);
        assert_eq!(stats.raw_batches, 1);
    }

    #[test]
    fn malformed_lengths_counts_payloads_and_bombs_fail_before_growth() {
        let input = records(32, false);
        let mut codec = OrderBatchCodec::new();
        let original = codec.encode(32, false, &input).unwrap().bytes.to_vec();
        let mut output = vec![0; ORDER_BATCH_MAX_UNCOMPRESSED];

        let mut bad = original.clone();
        bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            OrderBatchCodec::decode_into(&bad, &mut output),
            Err(OrderBatchError::UncompressedLengthOutOfRange(_))
        ));

        bad = original.clone();
        bad[5] = 31;
        assert_eq!(
            OrderBatchCodec::decode_into(&bad, &mut output),
            Err(OrderBatchError::RecordCountOutOfRange(31))
        );

        bad = original.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(OrderBatchCodec::decode_into(&bad, &mut output).is_err());

        bad = original;
        bad.truncate(bad.len() - 1);
        assert_eq!(
            OrderBatchCodec::decode_into(&bad, &mut output),
            Err(OrderBatchError::Truncated)
        );
    }

    #[test]
    fn raw_flag_with_mismatched_lengths_is_rejected() {
        let input = records(32, false);
        let mut codec = OrderBatchCodec::new();
        let mut encoded = codec.encode(32, false, &input).unwrap().bytes.to_vec();
        encoded[3] |= FLAG_RAW;
        encoded[12..16].copy_from_slice(&1u32.to_le_bytes());
        encoded.truncate(ORDER_BATCH_HEADER_LEN + 1);
        let mut output = vec![0; ORDER_BATCH_MAX_UNCOMPRESSED];
        assert_eq!(
            OrderBatchCodec::decode_into(&encoded, &mut output),
            Err(OrderBatchError::RawLengthMismatch)
        );
    }

    #[test]
    fn count_policy_rejects_full_under_32_and_partial_at_32() {
        let input = records(31, false);
        let mut codec = OrderBatchCodec::new();
        assert_eq!(
            codec.encode(31, false, &input),
            Err(OrderBatchError::RecordCountOutOfRange(31))
        );
        let input = records(32, false);
        assert_eq!(
            codec.encode(32, true, &input),
            Err(OrderBatchError::RecordCountOutOfRange(32))
        );
    }

    #[test]
    fn crc32_known_answer_is_stable() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
