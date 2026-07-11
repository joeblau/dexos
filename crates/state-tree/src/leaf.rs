//! Domain-separated, versioned leaf hashing and canonical field encoding.
//!
//! Every state leaf is committed with a domain tag (`DOMAIN_ACCOUNT` /
//! `DOMAIN_MARKET`) so that an account leaf and a market leaf with identical
//! payload bytes can never collide. Payloads are built with [`LeafWriter`],
//! which prepends a [`LEAF_ENCODING_VERSION`] tag and encodes each field at its
//! full integer width (little-endian) — `i64` and `i128` values are never
//! silently narrowed. [`LeafReader`] is the total, panic-free inverse used to
//! round-trip and to fuzz arbitrary bytes.

use crypto::{hash_domain, DOMAIN_ACCOUNT, DOMAIN_MARKET};
use types::Hash;

/// Version tag prepended to every canonically-encoded leaf payload.
///
/// Bump this whenever the field layout changes so the committed golden vectors
/// (and any deployed light client) detect the encoding change.
pub const LEAF_ENCODING_VERSION: u16 = 1;

/// A leaf-decoding failure. Returned instead of panicking on malformed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LeafError {
    /// The buffer's version tag does not match [`LEAF_ENCODING_VERSION`].
    #[error("leaf encoding version mismatch")]
    VersionMismatch,
    /// The buffer ended before a field could be fully read.
    #[error("unexpected end of leaf buffer")]
    UnexpectedEof,
    /// A length prefix would overflow `usize` or exceed the remaining buffer.
    #[error("leaf length prefix out of range")]
    LengthOutOfRange,
    /// Bytes remain after the final field was decoded.
    #[error("trailing bytes after decoding leaf")]
    TrailingBytes,
}

/// The kind of state leaf, selecting its hashing domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeafKind {
    /// A per-account commitment (`DOMAIN_ACCOUNT`).
    Account,
    /// A per-market commitment (`DOMAIN_MARKET`).
    Market,
}

impl LeafKind {
    /// The crypto domain tag used to commit a leaf of this kind.
    #[must_use]
    pub fn domain(self) -> &'static [u8] {
        match self {
            LeafKind::Account => DOMAIN_ACCOUNT,
            LeafKind::Market => DOMAIN_MARKET,
        }
    }
}

/// Commit an account leaf payload under `DOMAIN_ACCOUNT`.
#[must_use]
pub fn hash_account_leaf(data: &[u8]) -> Hash {
    hash_domain(DOMAIN_ACCOUNT, data)
}

/// Commit a market leaf payload under `DOMAIN_MARKET`.
#[must_use]
pub fn hash_market_leaf(data: &[u8]) -> Hash {
    hash_domain(DOMAIN_MARKET, data)
}

/// Commit a leaf payload under the domain for `kind`.
#[must_use]
pub fn hash_leaf_of(kind: LeafKind, data: &[u8]) -> Hash {
    hash_domain(kind.domain(), data)
}

/// Canonical, versioned encoder for leaf field bytes.
///
/// Fields are appended in declaration order at full width; byte fields are
/// length-prefixed with a `u64`. The output is stable across runs and
/// platforms, so a golden hex vector detects any layout change.
#[derive(Debug, Clone)]
pub struct LeafWriter {
    buf: Vec<u8>,
}

impl Default for LeafWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl LeafWriter {
    /// A new writer seeded with the encoding-version tag.
    #[must_use]
    pub fn new() -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(&LEAF_ENCODING_VERSION.to_le_bytes());
        Self { buf }
    }

    /// Append a `u32` field (4 bytes, little-endian).
    pub fn field_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append an `i64` field (8 bytes, little-endian) at full width.
    pub fn field_i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append an `i128` field (16 bytes, little-endian) at full width.
    pub fn field_i128(&mut self, v: i128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a length-prefixed byte field.
    pub fn field_bytes(&mut self, v: &[u8]) -> &mut Self {
        // `usize` -> `u64` is widening on all supported targets; the fallback is
        // unreachable and exists only to avoid a narrowing `as` cast.
        let len = u64::try_from(v.len()).unwrap_or(u64::MAX);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(v);
        self
    }

    /// The encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// The encoded bytes, cloned out of the writer.
    ///
    /// Takes `&self` (rather than consuming `self`) so it composes with the
    /// chained builder methods, which return `&mut Self`.
    #[must_use]
    pub fn finish(&self) -> Vec<u8> {
        self.buf.clone()
    }
}

/// Total, panic-free decoder that is the exact inverse of [`LeafWriter`].
#[derive(Debug, Clone)]
pub struct LeafReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> LeafReader<'a> {
    /// Create a reader, validating the version tag. Never panics.
    pub fn new(buf: &'a [u8]) -> Result<Self, LeafError> {
        let mut reader = Self { buf, pos: 0 };
        let version = u16::from_le_bytes(reader.take_array::<2>()?);
        if version != LEAF_ENCODING_VERSION {
            return Err(LeafError::VersionMismatch);
        }
        Ok(reader)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], LeafError> {
        let end = self.pos.checked_add(n).ok_or(LeafError::LengthOutOfRange)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(LeafError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], LeafError> {
        let slice = self.take(N)?;
        // `slice` is exactly `N` bytes by construction; the map guards anyway.
        <[u8; N]>::try_from(slice).map_err(|_| LeafError::UnexpectedEof)
    }

    /// Read a `u32` field.
    pub fn field_u32(&mut self) -> Result<u32, LeafError> {
        Ok(u32::from_le_bytes(self.take_array::<4>()?))
    }

    /// Read an `i64` field at full width.
    pub fn field_i64(&mut self) -> Result<i64, LeafError> {
        Ok(i64::from_le_bytes(self.take_array::<8>()?))
    }

    /// Read an `i128` field at full width.
    pub fn field_i128(&mut self) -> Result<i128, LeafError> {
        Ok(i128::from_le_bytes(self.take_array::<16>()?))
    }

    /// Read a length-prefixed byte field.
    pub fn field_bytes(&mut self) -> Result<&'a [u8], LeafError> {
        let len_u64 = u64::from_le_bytes(self.take_array::<8>()?);
        let len = usize::try_from(len_u64).map_err(|_| LeafError::LengthOutOfRange)?;
        self.take(len)
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Assert the buffer was fully consumed.
    pub fn finish(self) -> Result<(), LeafError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(LeafError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic in-test LCG (no external rng crate).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn byte(&mut self) -> u8 {
            u8::try_from(self.next() & 0xff).unwrap_or(0)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.byte()).collect()
        }
        fn next_u32(&mut self) -> u32 {
            u32::try_from(self.next() & 0xffff_ffff).unwrap_or(0)
        }
        fn next_i64(&mut self) -> i64 {
            i64::from_le_bytes(self.next().to_le_bytes())
        }
    }

    #[test]
    fn golden_encoding_vector_is_stable() {
        // Committed golden vector: any change to the field layout or version tag
        // flips this hex string, catching silent encoding drift.
        let mut w = LeafWriter::new();
        w.field_u32(7)
            .field_i64(-1)
            .field_i128(1_000_000)
            .field_bytes(b"gm");
        let bytes = w.finish();
        let expected = "0100\
                        07000000\
                        ffffffffffffffff\
                        40420f00000000000000000000000000\
                        0200000000000000\
                        676d";
        assert_eq!(hex::encode(&bytes), expected);
    }

    #[test]
    fn account_and_market_golden_leaf_hashes_are_deterministic() {
        // The hashes themselves are deterministic across runs (self-consistent
        // golden check); the encoding golden above pins the pre-image bytes.
        let payload = LeafWriter::new().field_u32(42).field_i128(-9).finish();
        assert_eq!(hash_account_leaf(&payload), hash_account_leaf(&payload));
        assert_eq!(hash_market_leaf(&payload), hash_market_leaf(&payload));
        assert_eq!(
            hash_leaf_of(LeafKind::Account, &payload),
            hash_account_leaf(&payload)
        );
        assert_eq!(
            hash_leaf_of(LeafKind::Market, &payload),
            hash_market_leaf(&payload)
        );
    }

    #[test]
    fn domain_separation_holds_across_kinds() {
        // Same payload, different kind -> different commitment.
        let payload = LeafWriter::new().field_u32(1).finish();
        assert_ne!(hash_account_leaf(&payload), hash_market_leaf(&payload));
    }

    #[test]
    fn round_trip_is_exact() {
        let mut w = LeafWriter::new();
        w.field_u32(0xDEAD_BEEF)
            .field_i64(i64::MIN)
            .field_i128(i128::MAX)
            .field_bytes(b"hello world");
        let bytes = w.finish();

        let mut r = LeafReader::new(&bytes).unwrap();
        assert_eq!(r.field_u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.field_i64().unwrap(), i64::MIN);
        assert_eq!(r.field_i128().unwrap(), i128::MAX);
        assert_eq!(r.field_bytes().unwrap(), b"hello world");
        r.finish().unwrap();
    }

    #[test]
    fn full_width_values_never_truncate() {
        // i128 / i64 extremes survive a round trip bit-for-bit.
        for &v in &[
            i128::MIN,
            i128::MAX,
            -1,
            0,
            1,
            1_000_000,
            i128::from(i64::MIN),
        ] {
            let bytes = LeafWriter::new().field_i128(v).finish();
            let mut r = LeafReader::new(&bytes).unwrap();
            assert_eq!(r.field_i128().unwrap(), v);
            r.finish().unwrap();
        }
    }

    #[test]
    fn property_single_field_change_changes_hash() {
        // Two leaves differing in exactly one field produce different hashes.
        let mut rng = Lcg(0x1234_5678);
        for _ in 0..2_000 {
            let a = rng.next_u32();
            let b = rng.next_u32();
            let base = LeafWriter::new().field_u32(a).finish();
            let changed = LeafWriter::new().field_u32(b).finish();
            if a == b {
                assert_eq!(hash_account_leaf(&base), hash_account_leaf(&changed));
            } else {
                assert_ne!(hash_account_leaf(&base), hash_account_leaf(&changed));
            }
        }
    }

    #[test]
    fn property_encode_decode_round_trips() {
        let mut rng = Lcg(99);
        for _ in 0..5_000 {
            let f1 = rng.next_u32();
            let f2 = rng.next_i64();
            let n = usize::try_from(rng.next() % 24).unwrap();
            let blob = rng.bytes(n);
            let bytes = LeafWriter::new()
                .field_u32(f1)
                .field_i64(f2)
                .field_bytes(&blob)
                .finish();
            let mut r = LeafReader::new(&bytes).unwrap();
            assert_eq!(r.field_u32().unwrap(), f1);
            assert_eq!(r.field_i64().unwrap(), f2);
            assert_eq!(r.field_bytes().unwrap(), blob.as_slice());
            assert!(r.finish().is_ok());
        }
    }

    #[test]
    fn reader_never_panics_on_arbitrary_bytes() {
        let mut rng = Lcg(0xC0FF_EE00);
        for _ in 0..20_000 {
            let n = usize::try_from(rng.next() % 40).unwrap();
            let blob = rng.bytes(n);
            // Attempt a schedule of reads; each returns a Result, never panics.
            if let Ok(mut r) = LeafReader::new(&blob) {
                let _ = r.field_u32();
                let _ = r.field_i64();
                let _ = r.field_i128();
                let _ = r.field_bytes();
                let _ = r.finish();
            }
        }
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let mut bytes = LeafWriter::new().field_u32(1).finish();
        bytes[0] ^= 0xFF; // corrupt version tag
        match LeafReader::new(&bytes) {
            Err(e) => assert_eq!(e, LeafError::VersionMismatch),
            Ok(_) => panic!("expected version mismatch to be rejected"),
        }
    }
}
