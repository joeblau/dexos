//! Deterministic, self-describing-free binary codec for custody-edge types.
//!
//! This is a tiny hand-rolled big-endian codec. It exists so the crate depends
//! only on `types` + `crypto` (plus `serde`/`thiserror`) and owns its exact wire
//! layout. Every decoder is total: it returns a typed [`CodecError`] on malformed
//! input and never panics, never allocates on an unchecked length, and never
//! narrows an integer with `as`.
//!
//! Encoding is infallible and deterministic: the same value always produces the
//! same bytes, and length prefixes are fixed-width `u64` big-endian.

use thiserror::Error;

/// Errors produced while decoding bytes into a typed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CodecError {
    /// The buffer ended before a full value could be read.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// Bytes remained after a top-level value was fully decoded.
    #[error("trailing bytes after value")]
    TrailingBytes,
    /// An enum discriminant tag was not a known variant.
    #[error("invalid enum tag {0}")]
    InvalidTag(u8),
    /// A length prefix exceeded the remaining buffer or `usize` range.
    #[error("length prefix out of range")]
    LengthOutOfRange,
}

/// Append-only deterministic byte writer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Create an empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume the writer, returning the accumulated bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Write a single byte.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a big-endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a big-endian `u32`.
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a big-endian `u64`.
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a big-endian `i128` (used for [`types::Amount`] raw values).
    pub fn i128(&mut self, v: i128) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a length prefix (`u64` big-endian).
    ///
    /// `usize -> u64` is widening on all supported (<= 64-bit) targets; the
    /// `unwrap_or(u64::MAX)` guard keeps this infallible without a narrowing
    /// `as` cast and never triggers for the bounded collections used here.
    pub fn len(&mut self, n: usize) {
        self.u64(u64::try_from(n).unwrap_or(u64::MAX));
    }

    /// Write a length-prefixed byte slice.
    pub fn bytes(&mut self, b: &[u8]) {
        self.len(b.len());
        self.buf.extend_from_slice(b);
    }

    /// Write a fixed 32-byte array with no length prefix.
    pub fn array32(&mut self, a: &[u8; 32]) {
        self.buf.extend_from_slice(a);
    }

    /// Write a fixed 64-byte array with no length prefix.
    pub fn array64(&mut self, a: &[u8; 64]) {
        self.buf.extend_from_slice(a);
    }
}

/// Cursor-based deterministic byte reader. Every method is total.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(CodecError::LengthOutOfRange)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read a single byte.
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    /// Read a big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, CodecError> {
        let a: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(u16::from_be_bytes(a))
    }

    /// Read a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let a: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(u32::from_be_bytes(a))
    }

    /// Read a big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let a: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(u64::from_be_bytes(a))
    }

    /// Read a big-endian `i128`.
    pub fn i128(&mut self) -> Result<i128, CodecError> {
        let a: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(i128::from_be_bytes(a))
    }

    /// Read a length prefix, validating it against the remaining buffer so no
    /// unchecked allocation can occur. (This decodes a length field; it is not a
    /// collection length, so no `is_empty` counterpart applies.)
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&mut self) -> Result<usize, CodecError> {
        let raw = self.u64()?;
        let n = usize::try_from(raw).map_err(|_| CodecError::LengthOutOfRange)?;
        if n > self.buf.len().saturating_sub(self.pos) {
            return Err(CodecError::LengthOutOfRange);
        }
        Ok(n)
    }

    /// Read a length-prefixed byte vector.
    pub fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let n = self.len()?;
        Ok(self.take(n)?.to_vec())
    }

    /// Read a fixed 32-byte array.
    pub fn array32(&mut self) -> Result<[u8; 32], CodecError> {
        self.take(32)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)
    }

    /// Read a fixed 64-byte array.
    pub fn array64(&mut self) -> Result<[u8; 64], CodecError> {
        self.take(64)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)
    }

    /// Assert the buffer was fully consumed.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

/// A value with a canonical, deterministic byte encoding.
pub trait Codec: Sized {
    /// Serialize `self` into a fresh byte vector (infallible, deterministic).
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_bytes()
    }

    /// Deserialize from an exact byte slice, rejecting trailing bytes.
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let v = Self::read(&mut r)?;
        r.finish()?;
        Ok(v)
    }

    /// Write the body of `self` into `w`.
    fn write(&self, w: &mut Writer);

    /// Read the body of a value from `r`.
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_round_trip() {
        let mut w = Writer::new();
        w.u8(7);
        w.u16(0xBEEF);
        w.u32(0xDEAD_BEEF);
        w.u64(u64::MAX);
        w.i128(i128::MIN);
        w.bytes(&[1, 2, 3]);
        w.array32(&[9u8; 32]);
        w.array64(&[5u8; 64]);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u16().unwrap(), 0xBEEF);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        assert_eq!(r.i128().unwrap(), i128::MIN);
        assert_eq!(r.bytes().unwrap(), vec![1, 2, 3]);
        assert_eq!(r.array32().unwrap(), [9u8; 32]);
        assert_eq!(r.array64().unwrap(), [5u8; 64]);
        r.finish().unwrap();
    }

    #[test]
    fn truncated_reads_error_not_panic() {
        assert_eq!(Reader::new(&[]).u64(), Err(CodecError::UnexpectedEof));
        assert_eq!(
            Reader::new(&[0, 0, 1]).u32(),
            Err(CodecError::UnexpectedEof)
        );
    }

    #[test]
    fn oversized_length_rejected() {
        // A length prefix claiming 1000 bytes with none present.
        let mut w = Writer::new();
        w.len(1000);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.len(), Err(CodecError::LengthOutOfRange));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.finish(), Err(CodecError::TrailingBytes));
    }
}
