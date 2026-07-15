//! Operational caps for untrusted on-disk frames.
//!
//! Decode paths read length fields from attacker-controlled or crash-torn bytes.
//! These caps ensure a hostile `u32` length cannot force multi-gigabyte
//! allocations before integrity checks complete.

/// Default maximum encoded record size, including framing overhead (1 MiB).
pub const DEFAULT_MAX_RECORD_BYTES: usize = 1024 * 1024;

/// Default maximum opaque snapshot state size (64 MiB).
pub const DEFAULT_MAX_SNAPSHOT_STATE_BYTES: usize = 64 * 1024 * 1024;

/// Default sparse index stride: one index entry every N records inside a segment.
///
/// Find/recovery binary-searches this sparse map then scans at most `stride`
/// records locally.
pub const DEFAULT_INDEX_STRIDE: usize = 64;

/// Magic bytes written at the end of a sealed durable segment (`DXSG`).
pub const SEGMENT_TRAILER_MAGIC: [u8; 4] = *b"DXSG";

/// On-disk trailer format version.
pub const SEGMENT_TRAILER_VERSION: u16 = 1;

/// Integrity algorithm id: domain-separated chain-hash over framed records.
pub const INTEGRITY_CHAIN_HASH: u16 = 1;

/// Fixed trailer size (bytes) appended after the record region of a sealed segment.
///
/// Layout (little-endian):
/// ```text
/// magic[4] | version:u16 | integrity:u16 | record_count:u64 |
/// base_sequence:u64 | last_sequence:u64 | records_len:u64 |
/// chain_tip:[u8;32] | trailer_crc:u32
/// ```
pub const SEGMENT_TRAILER_LEN: usize = 4 + 2 + 2 + 8 + 8 + 8 + 8 + 32 + 4;

/// Default hard cap for one complete segment file, including its trailer.
///
/// This is deliberately separate from the soft rotation budget: changing that
/// policy does not change this cap. The same (or a sufficiently large) hard cap
/// must be supplied when reopening WALs created with a non-default larger cap.
/// The default accepts a segment written at the 64 MiB default budget plus its
/// trailer.
pub const DEFAULT_MAX_SEGMENT_FILE_BYTES: usize = 64 * 1024 * 1024 + SEGMENT_TRAILER_LEN;
