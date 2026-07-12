//! serde adapter for `[u8; 64]` signatures.
//!
//! serde's built-in array impls stop at 32 bytes, so ed25519 signatures need a
//! small adapter. Mirrors the approach in `crypto::quorum` (serialize as a byte
//! sequence, decode back into a fixed array) so the wire encoding is uniform.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serialize a 64-byte signature as a byte sequence.
pub(crate) fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    v.as_slice().serialize(s)
}

/// Decode a byte sequence back into a fixed 64-byte signature.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
    let v: Vec<u8> = Vec::deserialize(d)?;
    <[u8; 64]>::try_from(v.as_slice())
        .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))
}

/// Optional 64-byte signature adapter (`None` ↔ absent / null).
pub(crate) mod opt {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        v: &Option<[u8; 64]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(sig) => super::serialize(sig, s),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<[u8; 64]>, D::Error> {
        let v: Option<Vec<u8>> = Option::deserialize(d)?;
        match v {
            None => Ok(None),
            Some(bytes) => {
                let arr = <[u8; 64]>::try_from(bytes.as_slice())
                    .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))?;
                Ok(Some(arr))
            }
        }
    }
}
