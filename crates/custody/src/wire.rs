//! A tiny, total little-endian byte codec used for deterministic hashing
//! (state roots, withdrawal ids, audit roots) and for the decode surfaces that
//! the fuzz / never-panics tests drive.
//!
//! The crate deliberately does not depend on `codec`/`postcard`: the wire shapes
//! here are small and fixed, and keeping the reader in-crate lets every decode
//! path be bounds-checked by hand so that arbitrary input can never panic. All
//! integer widths are explicit, so decoding never narrows with `as`.

use crate::error::CustodyError;

/// A forward-only byte writer producing canonical little-endian encodings.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A new empty writer.
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append one byte.
    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Append a little-endian `u32`.
    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `i128`.
    pub(crate) fn i128(&mut self, v: i128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append raw bytes with no length prefix.
    pub(crate) fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Append a `u32` length prefix followed by the bytes.
    pub(crate) fn var_bytes(&mut self, b: &[u8]) -> Result<(), CustodyError> {
        let len = u32::try_from(b.len()).map_err(|_| CustodyError::Decode)?;
        self.u32(len);
        self.buf.extend_from_slice(b);
        Ok(())
    }

    /// Consume the writer, yielding the accumulated bytes.
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// A forward-only, bounds-checked byte reader. Every method returns a
/// [`CustodyError::Decode`] on underflow; it never panics on any input.
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Borrow the next `n` bytes, advancing the cursor.
    fn take(&mut self, n: usize) -> Result<&'a [u8], CustodyError> {
        let end = self.pos.checked_add(n).ok_or(CustodyError::Decode)?;
        if end > self.buf.len() {
            return Err(CustodyError::Decode);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Read a fixed-size byte array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], CustodyError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// Read one byte.
    pub(crate) fn u8(&mut self) -> Result<u8, CustodyError> {
        Ok(self.array::<1>()?[0])
    }

    /// Read a little-endian `u32`.
    pub(crate) fn u32(&mut self) -> Result<u32, CustodyError> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    /// Read a little-endian `u64`.
    pub(crate) fn u64(&mut self) -> Result<u64, CustodyError> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }

    /// Read a little-endian `i128`.
    pub(crate) fn i128(&mut self) -> Result<i128, CustodyError> {
        Ok(i128::from_le_bytes(self.array::<16>()?))
    }

    /// Read a `u32`-length-prefixed byte vector.
    pub(crate) fn var_bytes(&mut self) -> Result<Vec<u8>, CustodyError> {
        let len = usize::try_from(self.u32()?).map_err(|_| CustodyError::Decode)?;
        Ok(self.take(len)?.to_vec())
    }

    /// Bytes not yet consumed. Useful to bound a length-prefixed allocation.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Consume and return all remaining bytes.
    pub(crate) fn tail(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    /// Assert the whole buffer was consumed. Rejects trailing garbage so that a
    /// decode is a strict, canonical round-trip.
    pub(crate) fn finish(self) -> Result<(), CustodyError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CustodyError::Decode)
        }
    }
}
