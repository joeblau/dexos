//! Compact identifiers used across the custody edge.

use crate::codec::{Codec, CodecError, Reader, Writer};
use serde::{Deserialize, Serialize};

/// Maximum transaction-id length accepted by the codec (guards allocation).
///
/// EVM tx hashes are 32 bytes; SVM signatures are 64 bytes. 96 leaves headroom.
pub const MAX_TXID_LEN: usize = 96;

/// Identifier of an external chain (e.g. an EVM chain-id or an SVM cluster id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChainId(u64);

impl ChainId {
    /// Construct from a raw value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Codec for ChainId {
    fn write(&self, w: &mut Writer) {
        w.u64(self.0);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(r.u64()?))
    }
}

/// Canonical DexOS asset identifier (registry index shared with execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssetId(u32);

impl AssetId {
    /// Construct from a raw value.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Codec for AssetId {
    fn write(&self, w: &mut Writer) {
        w.u32(self.0);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(r.u32()?))
    }
}

/// An opaque external-chain transaction identifier (hash or signature bytes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TxId(Vec<u8>);

impl TxId {
    /// Wrap raw transaction-id bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Codec for TxId {
    fn write(&self, w: &mut Writer) {
        w.bytes(&self.0);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let bytes = r.bytes()?;
        if bytes.len() > MAX_TXID_LEN {
            return Err(CodecError::LengthOutOfRange);
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip() {
        let c = ChainId::new(1);
        assert_eq!(ChainId::decode(&c.encode()).unwrap(), c);
        let a = AssetId::new(42);
        assert_eq!(AssetId::decode(&a.encode()).unwrap(), a);
        let t = TxId::new(vec![0xAB; 32]);
        assert_eq!(TxId::decode(&t.encode()).unwrap(), t);
    }

    #[test]
    fn oversized_txid_rejected() {
        let mut w = Writer::new();
        w.bytes(&[0u8; MAX_TXID_LEN + 1]);
        assert_eq!(
            TxId::decode(&w.into_bytes()),
            Err(CodecError::LengthOutOfRange)
        );
    }
}
