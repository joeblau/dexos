//! Deterministic binary (de)serialization for oracle wire types.
//!
//! Uses `postcard` — a compact, canonical, no-float binary format. Decoding is
//! total: arbitrary bytes yield [`OracleError::Codec`], never a panic.

use serde::{de::DeserializeOwned, Serialize};

use crate::error::OracleError;

/// Encode a value to canonical binary bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, OracleError> {
    postcard::to_stdvec(value).map_err(|_| OracleError::Codec)
}

/// Decode a value from binary bytes. Never panics on arbitrary input.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, OracleError> {
    postcard::from_bytes(bytes).map_err(|_| OracleError::Codec)
}

/// serde adapter for a fixed 64-byte signature (`serde` has no built-in impl
/// for arrays longer than 32 bytes).
pub(crate) mod sig64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes = <&[u8]>::deserialize(d)?;
        <[u8; 64]>::try_from(bytes)
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))
    }
}
