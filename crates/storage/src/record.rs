//! On-wire framing for a single command-log record.
//!
//! A record frames an OPAQUE command payload (the storage layer never
//! interprets the payload bytes) with the following little-endian layout:
//!
//! ```text
//! | length(u32) | protocol_version(u16) | sequence(u64) |
//! | timestamp(u64) | command_type(u16) | payload(bytes) | checksum(u32) |
//! ```
//!
//! * `length` is the total encoded size of the record in bytes, including the
//!   `length` field itself and the trailing `checksum`. It lets a reader walk a
//!   segment byte buffer one record at a time and reject truncated tails.
//! * `checksum` is a CRC-32 over every byte between `length` and `checksum`
//!   (i.e. the header fields plus the payload). Any single-bit flip in the
//!   header or payload therefore fails verification on read.
//!
//! Decoding never panics on arbitrary input: every length and bound is checked
//! and surfaced as a typed [`RecordError`]. Hostile declared lengths that exceed
//! the configured max are rejected **before** payload allocation.

use crate::crc::crc32;
use crate::limits::DEFAULT_MAX_RECORD_BYTES;

/// Protocol version stamped into every record this build writes.
pub const PROTOCOL_VERSION: u16 = 1;

const LEN_SIZE: usize = 4; // length: u32
const PVER_SIZE: usize = 2; // protocol_version: u16
const SEQ_SIZE: usize = 8; // sequence: u64
const TS_SIZE: usize = 8; // timestamp: u64
const CMD_SIZE: usize = 2; // command_type: u16
const CRC_SIZE: usize = 4; // checksum: u32

/// Header bytes that follow the `length` field and are covered by the checksum,
/// excluding the payload.
const HEADER_AFTER_LEN: usize = PVER_SIZE + SEQ_SIZE + TS_SIZE + CMD_SIZE;

/// Fixed per-record overhead: everything except the payload bytes.
pub const FRAME_OVERHEAD: usize = LEN_SIZE + HEADER_AFTER_LEN + CRC_SIZE;

/// Errors produced while encoding or decoding a [`Record`].
///
/// Decoding is applied to untrusted, possibly corrupt or truncated bytes, so
/// every failure mode is represented here rather than via a panic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The buffer is smaller than the minimum framed record size.
    #[error("record buffer too short: have {have} bytes, need at least {need}")]
    TooShort {
        /// Bytes available in the buffer.
        have: usize,
        /// Minimum bytes required.
        need: usize,
    },
    /// The declared `length` field is inconsistent with the buffer.
    #[error("record declared length {declared} invalid for buffer of {available} bytes")]
    BadLength {
        /// Length declared in the record header.
        declared: usize,
        /// Bytes actually available in the buffer.
        available: usize,
    },
    /// The declared length exceeds the operational maximum (hostile / misconfigured).
    #[error("record declared length {declared} exceeds max {max}")]
    ExceedsMax {
        /// Length declared in the record header.
        declared: usize,
        /// Configured maximum encoded record size.
        max: usize,
    },
    /// The payload is larger than can be framed in a `u32` length field.
    #[error("payload of {0} bytes exceeds maximum framable record size")]
    PayloadTooLarge(usize),
    /// The stored checksum did not match the recomputed checksum (corruption).
    #[error("checksum mismatch: stored {stored:#010x}, computed {computed:#010x}")]
    ChecksumMismatch {
        /// Checksum read from the record.
        stored: u32,
        /// Checksum recomputed over the record bytes.
        computed: u32,
    },
    /// The record's protocol version is not understood by this build.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
}

/// A decoded command-log record with an opaque payload.
///
/// The `payload` bytes are never interpreted by the storage layer; they are the
/// serialized command as produced by a higher layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Protocol version the record was written with.
    pub protocol_version: u16,
    /// Global, monotonically increasing sequence number.
    pub sequence: u64,
    /// Opaque application timestamp (units defined by the caller).
    pub timestamp: u64,
    /// Opaque command discriminant (defined by the caller).
    pub command_type: u16,
    /// Opaque serialized command bytes.
    pub payload: Vec<u8>,
}

/// Borrowed view of a decoded record (no payload allocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordRef<'a> {
    /// Protocol version the record was written with.
    pub protocol_version: u16,
    /// Global, monotonically increasing sequence number.
    pub sequence: u64,
    /// Opaque application timestamp (units defined by the caller).
    pub timestamp: u64,
    /// Opaque command discriminant (defined by the caller).
    pub command_type: u16,
    /// Opaque serialized command bytes.
    pub payload: &'a [u8],
}

impl RecordRef<'_> {
    /// Copy into an owned [`Record`].
    #[must_use]
    pub fn to_owned(&self) -> Record {
        Record {
            protocol_version: self.protocol_version,
            sequence: self.sequence,
            timestamp: self.timestamp,
            command_type: self.command_type,
            payload: self.payload.to_vec(),
        }
    }

    /// Encode this record view, appending the framed bytes into `buf`.
    ///
    /// Produces bytes identical to [`Record::encode_into`] for the same field
    /// values (including the trailing CRC), without requiring an owned payload.
    /// This is the allocation-free encode path used by the append hot paths.
    ///
    /// # Errors
    /// Returns [`RecordError::PayloadTooLarge`] if the framed record would not
    /// fit within the `u32` length field.
    pub fn encode_into(&self, buf: &mut Vec<u8>) -> Result<(), RecordError> {
        let total = Record::encoded_len(self.payload.len());
        let length =
            u32::try_from(total).map_err(|_| RecordError::PayloadTooLarge(self.payload.len()))?;

        let start = buf.len();
        buf.reserve(total);
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(&self.protocol_version.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.command_type.to_le_bytes());
        buf.extend_from_slice(self.payload);

        // Checksum covers the header (after `length`) and the payload.
        let checksum = crc32(&buf[start + LEN_SIZE..]);
        buf.extend_from_slice(&checksum.to_le_bytes());
        debug_assert_eq!(buf.len() - start, total);
        Ok(())
    }
}

impl Record {
    /// Total encoded size, in bytes, of a record carrying `payload_len` payload
    /// bytes.
    #[must_use]
    pub const fn encoded_len(payload_len: usize) -> usize {
        FRAME_OVERHEAD + payload_len
    }

    /// Encode this record to its framed byte representation.
    ///
    /// # Errors
    /// Returns [`RecordError::PayloadTooLarge`] if the framed record would not
    /// fit within the `u32` length field.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let total = Self::encoded_len(self.payload.len());
        let mut buf = Vec::with_capacity(total);
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// Encode this record, appending the framed bytes into `buf`.
    ///
    /// Delegates to [`RecordRef::encode_into`] over a borrowed view, so both
    /// paths produce byte-identical framing and CRC.
    ///
    /// # Errors
    /// Returns [`RecordError::PayloadTooLarge`] if the framed record would not
    /// fit within the `u32` length field.
    pub fn encode_into(&self, buf: &mut Vec<u8>) -> Result<(), RecordError> {
        self.as_record_ref().encode_into(buf)
    }

    /// Borrow this record as a [`RecordRef`] (no payload copy).
    #[must_use]
    pub fn as_record_ref(&self) -> RecordRef<'_> {
        RecordRef {
            protocol_version: self.protocol_version,
            sequence: self.sequence,
            timestamp: self.timestamp,
            command_type: self.command_type,
            payload: &self.payload,
        }
    }

    /// Decode a single record from the front of `bytes` using
    /// [`DEFAULT_MAX_RECORD_BYTES`].
    ///
    /// On success returns the decoded [`Record`] and the number of bytes it
    /// consumed, so a caller can decode the next record at `&bytes[consumed..]`.
    ///
    /// # Errors
    /// Returns a [`RecordError`] describing the first structural or integrity
    /// problem encountered.
    pub fn decode(bytes: &[u8]) -> Result<(Record, usize), RecordError> {
        Self::decode_bounded(bytes, DEFAULT_MAX_RECORD_BYTES)
    }

    /// Decode a single record, rejecting declared lengths above `max_record_bytes`
    /// before allocating the payload.
    ///
    /// # Errors
    /// Returns a [`RecordError`] describing the first structural or integrity
    /// problem encountered.
    pub fn decode_bounded(
        bytes: &[u8],
        max_record_bytes: usize,
    ) -> Result<(Record, usize), RecordError> {
        let (rref, consumed) = decode_ref_bounded(bytes, max_record_bytes)?;
        Ok((rref.to_owned(), consumed))
    }
}

/// Decode a borrowed record view without allocating the payload.
///
/// Declared lengths above `max_record_bytes` fail with
/// [`RecordError::ExceedsMax`] before any large allocation.
///
/// # Errors
/// Returns a [`RecordError`] on structural or integrity failure.
pub fn decode_ref_bounded(
    bytes: &[u8],
    max_record_bytes: usize,
) -> Result<(RecordRef<'_>, usize), RecordError> {
    if bytes.len() < FRAME_OVERHEAD {
        return Err(RecordError::TooShort {
            have: bytes.len(),
            need: FRAME_OVERHEAD,
        });
    }

    let length_bytes: [u8; 4] =
        bytes[0..LEN_SIZE]
            .try_into()
            .map_err(|_| RecordError::TooShort {
                have: bytes.len(),
                need: FRAME_OVERHEAD,
            })?;
    let declared = u32::from_le_bytes(length_bytes);
    let total = usize::try_from(declared).map_err(|_| RecordError::BadLength {
        declared: usize::MAX,
        available: bytes.len(),
    })?;

    // Reject hostile lengths before any payload-sized allocation.
    if total > max_record_bytes {
        return Err(RecordError::ExceedsMax {
            declared: total,
            max: max_record_bytes,
        });
    }

    if total < FRAME_OVERHEAD || total > bytes.len() {
        return Err(RecordError::BadLength {
            declared: total,
            available: bytes.len(),
        });
    }

    let crc_start = total - CRC_SIZE;
    let stored_bytes: [u8; 4] =
        bytes[crc_start..total]
            .try_into()
            .map_err(|_| RecordError::BadLength {
                declared: total,
                available: bytes.len(),
            })?;
    let stored = u32::from_le_bytes(stored_bytes);
    let computed = crc32(&bytes[LEN_SIZE..crc_start]);
    if stored != computed {
        return Err(RecordError::ChecksumMismatch { stored, computed });
    }

    // Fields live in the checksum-covered region between `length` and `crc`.
    let region = &bytes[LEN_SIZE..crc_start];
    let pver = u16::from_le_bytes(read2(region, 0)?);
    let sequence = u64::from_le_bytes(read8(region, PVER_SIZE)?);
    let timestamp = u64::from_le_bytes(read8(region, PVER_SIZE + SEQ_SIZE)?);
    let command_type = u16::from_le_bytes(read2(region, PVER_SIZE + SEQ_SIZE + TS_SIZE)?);

    if pver != PROTOCOL_VERSION {
        return Err(RecordError::UnsupportedVersion(pver));
    }

    let payload = &region[HEADER_AFTER_LEN..];
    Ok((
        RecordRef {
            protocol_version: pver,
            sequence,
            timestamp,
            command_type,
            payload,
        },
        total,
    ))
}

/// Peek only the declared length field (4 bytes), without allocating.
///
/// Returns `None` if fewer than 4 bytes are available.
#[must_use]
pub fn peek_declared_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < LEN_SIZE {
        return None;
    }
    let declared = u32::from_le_bytes(bytes[0..LEN_SIZE].try_into().ok()?);
    usize::try_from(declared).ok()
}

/// Read a little-endian `u16`-sized slice at `off`, checked.
fn read2(region: &[u8], off: usize) -> Result<[u8; 2], RecordError> {
    region
        .get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or(RecordError::TooShort {
            have: region.len(),
            need: off + 2,
        })
}

/// Read a little-endian `u64`-sized slice at `off`, checked.
fn read8(region: &[u8], off: usize) -> Result<[u8; 8], RecordError> {
    region
        .get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or(RecordError::TooShort {
            have: region.len(),
            need: off + 8,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seq: u64, payload: &[u8]) -> Record {
        Record {
            protocol_version: PROTOCOL_VERSION,
            sequence: seq,
            timestamp: 42,
            command_type: 7,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn round_trip_identical_payload() {
        let rec = sample(9, b"place-order-payload");
        let bytes = rec.encode().unwrap();
        assert_eq!(bytes.len(), Record::encoded_len(rec.payload.len()));
        let (back, consumed) = Record::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(back, rec);
        assert_eq!(back.payload, rec.payload);
    }

    #[test]
    fn empty_payload_round_trips() {
        let rec = sample(0, b"");
        let bytes = rec.encode().unwrap();
        let (back, _) = Record::decode(&bytes).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn encode_into_matches_encode() {
        let rec = sample(3, b"xyz");
        let a = rec.encode().unwrap();
        let mut b = Vec::new();
        rec.encode_into(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn record_ref_encode_into_matches_record_byte_for_byte() {
        // Byte-identity between the borrowed and owned encode paths — the
        // durability wire format must not change under the RecordRef path.
        for payload in [&b""[..], b"x", b"place-order-payload", &[0u8; 1024]] {
            let rec = sample(11, payload);
            let mut owned = Vec::new();
            rec.encode_into(&mut owned).unwrap();

            let rref = RecordRef {
                protocol_version: rec.protocol_version,
                sequence: rec.sequence,
                timestamp: rec.timestamp,
                command_type: rec.command_type,
                payload,
            };
            let mut borrowed = Vec::new();
            rref.encode_into(&mut borrowed).unwrap();

            assert_eq!(owned, borrowed, "framed bytes must be identical");
            // Same trailing CRC in particular.
            assert_eq!(
                &owned[owned.len() - CRC_SIZE..],
                &borrowed[borrowed.len() - CRC_SIZE..]
            );
            // And the borrowed encoding decodes back to the same record.
            let (back, consumed) = Record::decode(&borrowed).unwrap();
            assert_eq!(consumed, borrowed.len());
            assert_eq!(back, rec);
        }
    }

    #[test]
    fn as_record_ref_borrows_all_fields() {
        let rec = sample(5, b"abc");
        let rref = rec.as_record_ref();
        assert_eq!(rref.protocol_version, rec.protocol_version);
        assert_eq!(rref.sequence, rec.sequence);
        assert_eq!(rref.timestamp, rec.timestamp);
        assert_eq!(rref.command_type, rec.command_type);
        assert_eq!(rref.payload, rec.payload.as_slice());
        assert_eq!(rref.to_owned(), rec);
    }

    #[test]
    fn flipped_payload_bit_fails_checksum() {
        let rec = sample(3, b"hello");
        let mut bytes = rec.encode().unwrap();
        let last = bytes.len() - CRC_SIZE - 1; // last payload byte
        bytes[last] ^= 0x01;
        match Record::decode(&bytes) {
            Err(RecordError::ChecksumMismatch { .. }) => {}
            other => panic!("expected checksum mismatch, got {other:?}"),
        }
    }

    #[test]
    fn flipped_header_bit_fails_checksum() {
        let rec = sample(3, b"hello");
        let mut bytes = rec.encode().unwrap();
        // Flip a bit inside the sequence field (header, checksum-covered).
        bytes[LEN_SIZE + PVER_SIZE] ^= 0x80;
        assert!(matches!(
            Record::decode(&bytes),
            Err(RecordError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn truncated_buffer_is_typed_error() {
        let rec = sample(1, b"abcdefgh");
        let bytes = rec.encode().unwrap();
        for cut in 0..bytes.len() {
            // Any truncation must return a typed error, never a panic.
            let _ = Record::decode(&bytes[..cut]);
        }
        assert!(Record::decode(&bytes[..FRAME_OVERHEAD - 1]).is_err());
    }

    #[test]
    fn declared_length_beyond_buffer_rejected() {
        let rec = sample(1, b"xyz");
        let mut bytes = rec.encode().unwrap();
        // Inflate the declared length to point past the buffer.
        let huge = u32::try_from(bytes.len() + 100).unwrap();
        bytes[0..4].copy_from_slice(&huge.to_le_bytes());
        assert!(matches!(
            Record::decode(&bytes),
            Err(RecordError::BadLength { .. })
        ));
    }

    #[test]
    fn hostile_declared_length_fails_before_payload_alloc() {
        // Only 4 bytes of length + tiny rest: declared length is huge.
        let mut bytes = [0u8; FRAME_OVERHEAD];
        let hostile = u32::try_from(DEFAULT_MAX_RECORD_BYTES.saturating_add(1)).unwrap();
        bytes[0..4].copy_from_slice(&hostile.to_le_bytes());
        // Pad so buffer is large enough that BadLength wouldn't trip first if
        // we didn't cap — we only have FRAME_OVERHEAD bytes, so both checks
        // apply; force a buffer that would otherwise look long enough.
        let mut long = vec![0u8; 64];
        long[0..4].copy_from_slice(&hostile.to_le_bytes());
        match Record::decode_bounded(&long, 32) {
            Err(RecordError::ExceedsMax { declared, max }) => {
                assert_eq!(declared, DEFAULT_MAX_RECORD_BYTES + 1);
                assert_eq!(max, 32);
            }
            other => panic!("expected ExceedsMax, got {other:?}"),
        }
    }

    #[test]
    fn decode_ref_borrows_payload() {
        let rec = sample(1, b"borrow-me");
        let bytes = rec.encode().unwrap();
        let (rref, n) = decode_ref_bounded(&bytes, DEFAULT_MAX_RECORD_BYTES).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(rref.payload, b"borrow-me");
        assert_eq!(rref.to_owned(), rec);
    }
}
