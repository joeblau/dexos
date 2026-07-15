//! `codec` — the compact binary wire codec for DexOS.
//!
//! A deterministic length-prefixed binary format (postcard) plus a priority-tagged
//! frame envelope for the peer protocol. No JSON anywhere. All decode paths are
//! total: adversarial or truncated bytes return a typed [`CodecError`], never a panic.

use serde::de::DeserializeOwned;
use serde::Serialize;

mod packed_order;

pub use packed_order::{
    batch_auth_preimage_into, decode_batch_into, decode_batch_with_backend, encode_batch_into,
    encode_batch_with_backend, negotiate_packed_order_version, PackedBatchBinding, PackedOrder,
    PackedOrderError, PackedOrderView, PACKED_CANCEL_LEN, PACKED_ORDER_VERSION, PACKED_REPLACE_LEN,
    PACKED_SUBMIT_LEN,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "codec";

/// Wire magic for a DexOS frame.
pub const FRAME_MAGIC: u16 = 0xDE05;
/// Current frame protocol version.
pub const FRAME_VERSION: u16 = 1;
/// Fixed frame header length: magic(2)+version(2)+class(1)+msg_type(2)+sequence(8)+len(4).
pub const FRAME_HEADER_LEN: usize = 19;
/// Maximum payload accepted by the peer-protocol frame decoder (16 MiB) —
/// bounds allocation for historical sync / large snapshot chunks.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// Default maximum payload for the public RPC control plane (256 KiB).
///
/// Trading API request/response frames are far smaller than peer-sync chunks;
/// a lower default caps concurrent allocations under adversarial clients while
/// remaining configurable per process via the RPC server config.
pub const MAX_RPC_FRAME_PAYLOAD: usize = 256 * 1024;

/// A codec failure.
///
/// Variants stay unit-like (or tiny scalars) on the wire so the error surface is
/// stable and does not embed serializer internals. Enable the `debug_codec`
/// feature to print postcard error sources to stderr and expose
/// [`CodecError::detail`] diagnostics during local debugging.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Serialization failed.
    #[error("serialize error")]
    Serialize,
    /// Deserialization failed (malformed/truncated payload).
    #[error("deserialize error")]
    Deserialize,
    /// The frame was shorter than its declared structure.
    #[error("truncated frame")]
    Truncated,
    /// The frame magic did not match.
    #[error("bad frame magic")]
    BadMagic,
    /// Unsupported frame version.
    #[error("unsupported frame version {0}")]
    UnsupportedVersion(u16),
    /// The declared payload length is implausible or exceeds the cap.
    #[error("payload length out of range")]
    LengthOutOfRange,
    /// The traffic-class byte was not a known class.
    #[error("unknown traffic class {0}")]
    UnknownClass(u8),
    /// A caller-provided hot-path buffer was too small; it is never resized
    /// implicitly because that would hide an allocation.
    #[error("buffer too small: required {required} bytes, available {available}")]
    BufferTooSmall { required: usize, available: usize },
}

impl CodecError {
    /// Optional diagnostic detail for operators.
    ///
    /// Always returns [`None`] unless the crate is built with the `debug_codec`
    /// feature. Production code paths must not depend on this string.
    pub fn detail(&self) -> Option<&'static str> {
        #[cfg(feature = "debug_codec")]
        {
            Some(match self {
                CodecError::Serialize => "postcard serialization failed (see stderr)",
                CodecError::Deserialize => "postcard deserialization failed (see stderr)",
                CodecError::Truncated => "frame shorter than declared structure",
                CodecError::BadMagic => "frame magic mismatch",
                CodecError::UnsupportedVersion(_) => "unsupported frame protocol version",
                CodecError::LengthOutOfRange => "payload length out of range",
                CodecError::UnknownClass(_) => "unknown traffic class byte",
                CodecError::BufferTooSmall { .. } => "caller-provided buffer too small",
            })
        }
        #[cfg(not(feature = "debug_codec"))]
        {
            let _ = self;
            None
        }
    }
}

/// Encode a value to compact binary.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    postcard::to_allocvec(value).map_err(|err| {
        #[cfg(feature = "debug_codec")]
        eprintln!("codec serialize error: {err}");
        #[cfg(not(feature = "debug_codec"))]
        let _ = err;
        CodecError::Serialize
    })
}

/// Encode into a caller-provided initialized slice and return the number of bytes
/// written. This never allocates or resizes.
pub fn encode_to_slice<T: Serialize>(value: &T, out: &mut [u8]) -> Result<usize, CodecError> {
    postcard::to_slice(value, out)
        .map(|used| used.len())
        .map_err(|err| {
            #[cfg(feature = "debug_codec")]
            eprintln!("codec in-place serialize error: {err}");
            #[cfg(not(feature = "debug_codec"))]
            let _ = err;
            CodecError::Serialize
        })
}

/// Decode a value from compact binary. Total on adversarial input.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    postcard::from_bytes(bytes).map_err(|err| {
        #[cfg(feature = "debug_codec")]
        eprintln!("codec deserialize error: {err}");
        #[cfg(not(feature = "debug_codec"))]
        let _ = err;
        CodecError::Deserialize
    })
}

/// Priority traffic classes (P0 highest). State sync and market data must never
/// starve consensus or order traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrafficClass {
    /// P0 — consensus votes and quorum certificates.
    Consensus = 0,
    /// P1 — cancels and risk-reducing commands.
    RiskReducing = 1,
    /// P2 — liquidations.
    Liquidation = 2,
    /// P3 — new orders.
    NewOrder = 3,
    /// P4 — execution receipts.
    ExecutionReceipt = 4,
    /// P5 — oracle certificates.
    OracleCert = 5,
    /// P6 — checkpoint dissemination.
    Checkpoint = 6,
    /// P7 — market data.
    MarketData = 7,
    /// P8 — historical sync and snapshots.
    Sync = 8,
}

impl TrafficClass {
    /// Map a raw priority byte to a class.
    pub fn from_u8(v: u8) -> Option<TrafficClass> {
        Some(match v {
            0 => TrafficClass::Consensus,
            1 => TrafficClass::RiskReducing,
            2 => TrafficClass::Liquidation,
            3 => TrafficClass::NewOrder,
            4 => TrafficClass::ExecutionReceipt,
            5 => TrafficClass::OracleCert,
            6 => TrafficClass::Checkpoint,
            7 => TrafficClass::MarketData,
            8 => TrafficClass::Sync,
            _ => return None,
        })
    }

    /// The numeric priority (0 == highest).
    pub fn priority(self) -> u8 {
        self as u8
    }
}

/// A framed peer-protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Traffic class / priority.
    pub class: TrafficClass,
    /// Application message type tag.
    pub msg_type: u16,
    /// Per-connection message sequence number (replay/dup detection).
    pub sequence: u64,
    /// Serialized payload.
    pub payload: Vec<u8>,
}

/// A decoded frame whose payload borrows from the input buffer.
///
/// Produced by [`Frame::decode_ref`] / [`Frame::decode_ref_with_max`] for
/// callers that already hold the full contiguous frame in an owned buffer and
/// only need to read the payload (e.g. a follow-up typed [`decode`]). Skips
/// the payload copy that [`Frame::decode`] performs.
#[derive(Debug, PartialEq, Eq)]
pub struct FrameRef<'a> {
    /// Traffic class / priority.
    pub class: TrafficClass,
    /// Application message type tag.
    pub msg_type: u16,
    /// Per-connection message sequence number (replay/dup detection).
    pub sequence: u64,
    /// Serialized payload, borrowed from the decoded buffer.
    pub payload: &'a [u8],
}

impl FrameRef<'_> {
    /// Copy the borrowed payload into an owned [`Frame`].
    pub fn to_owned(&self) -> Frame {
        Frame {
            class: self.class,
            msg_type: self.msg_type,
            sequence: self.sequence,
            payload: self.payload.to_vec(),
        }
    }
}

impl Frame {
    /// Encode the frame with its header, capped at [`MAX_FRAME_PAYLOAD`].
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.encode_with_max(MAX_FRAME_PAYLOAD)
    }

    /// Encode the frame, refusing payloads larger than `max_payload`.
    pub fn encode_with_max(&self, max_payload: usize) -> Result<Vec<u8>, CodecError> {
        if self.payload.len() > max_payload {
            return Err(CodecError::LengthOutOfRange);
        }
        let plen = u32::try_from(self.payload.len()).map_err(|_| CodecError::LengthOutOfRange)?;
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
        out.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        out.push(self.class.priority());
        out.extend_from_slice(&self.msg_type.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&plen.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Encode into a preallocated vector without growing it. The vector is cleared
    /// first; insufficient capacity returns a typed error and performs no resize.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<usize, CodecError> {
        Self::encode_parts_into(
            self.class,
            self.msg_type,
            self.sequence,
            &self.payload,
            out,
            MAX_FRAME_PAYLOAD,
        )
    }

    /// Frame a borrowed payload into a preallocated vector without constructing an
    /// owned [`Frame`] or allocating a payload copy.
    pub fn encode_parts_into(
        class: TrafficClass,
        msg_type: u16,
        sequence: u64,
        payload: &[u8],
        out: &mut Vec<u8>,
        max_payload: usize,
    ) -> Result<usize, CodecError> {
        if payload.len() > max_payload {
            return Err(CodecError::LengthOutOfRange);
        }
        let required = FRAME_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(CodecError::LengthOutOfRange)?;
        if out.capacity() < required {
            return Err(CodecError::BufferTooSmall {
                required,
                available: out.capacity(),
            });
        }
        let plen = u32::try_from(payload.len()).map_err(|_| CodecError::LengthOutOfRange)?;
        out.clear();
        out.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
        out.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        out.push(class.priority());
        out.extend_from_slice(&msg_type.to_le_bytes());
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(&plen.to_le_bytes());
        out.extend_from_slice(payload);
        Ok(required)
    }

    /// Decode one frame, returning it and the number of bytes consumed. Total.
    /// Payload length is capped at [`MAX_FRAME_PAYLOAD`].
    pub fn decode(bytes: &[u8]) -> Result<(Frame, usize), CodecError> {
        Self::decode_with_max(bytes, MAX_FRAME_PAYLOAD)
    }

    /// Decode one frame with an explicit payload ceiling (e.g. the lower RPC
    /// control-plane cap). Total on adversarial input.
    ///
    /// Byte-identical to [`Frame::decode_ref_with_max`] followed by
    /// [`FrameRef::to_owned`]; use the borrowed form to skip the payload copy.
    pub fn decode_with_max(bytes: &[u8], max_payload: usize) -> Result<(Frame, usize), CodecError> {
        Self::decode_ref_with_max(bytes, max_payload)
            .map(|(frame, consumed)| (frame.to_owned(), consumed))
    }

    /// Decode one frame without copying the payload, returning a borrowed
    /// [`FrameRef`] and the number of bytes consumed. Total. Payload length is
    /// capped at [`MAX_FRAME_PAYLOAD`].
    pub fn decode_ref(bytes: &[u8]) -> Result<(FrameRef<'_>, usize), CodecError> {
        Self::decode_ref_with_max(bytes, MAX_FRAME_PAYLOAD)
    }

    /// Decode one frame with an explicit payload ceiling, borrowing the
    /// payload from `bytes` instead of copying it. The fail-closed checks
    /// (magic, version, class, length cap, truncation) are identical to
    /// [`Frame::decode_with_max`]. Total on adversarial input.
    pub fn decode_ref_with_max(
        bytes: &[u8],
        max_payload: usize,
    ) -> Result<(FrameRef<'_>, usize), CodecError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(CodecError::Truncated);
        }
        let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        if magic != FRAME_MAGIC {
            return Err(CodecError::BadMagic);
        }
        let version = u16::from_le_bytes([bytes[2], bytes[3]]);
        if version != FRAME_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let class = TrafficClass::from_u8(bytes[4]).ok_or(CodecError::UnknownClass(bytes[4]))?;
        let msg_type = u16::from_le_bytes([bytes[5], bytes[6]]);
        let sequence = u64::from_le_bytes([
            bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
        ]);
        let plen = u32::from_le_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]) as usize;
        if plen > max_payload {
            return Err(CodecError::LengthOutOfRange);
        }
        let end = FRAME_HEADER_LEN
            .checked_add(plen)
            .ok_or(CodecError::LengthOutOfRange)?;
        let payload = bytes
            .get(FRAME_HEADER_LEN..end)
            .ok_or(CodecError::Truncated)?;
        Ok((
            FrameRef {
                class,
                msg_type,
                sequence,
                payload,
            },
            end,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        a: u64,
        b: Vec<u8>,
        c: String,
    }

    #[test]
    fn value_round_trip() {
        let m = Msg {
            a: 42,
            b: vec![1, 2, 3],
            c: "hello".into(),
        };
        let bytes = encode(&m).unwrap();
        let back: Msg = decode(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn frame_round_trip_and_consumed_len() {
        let f = Frame {
            class: TrafficClass::NewOrder,
            msg_type: 7,
            sequence: 123,
            payload: vec![9; 100],
        };
        let bytes = f.encode().unwrap();
        let (back, consumed) = Frame::decode(&bytes).unwrap();
        assert_eq!(f, back);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn in_place_value_and_frame_encoding_match_allocating_api() {
        let message = Msg {
            a: 7,
            b: vec![1, 2, 3],
            c: "in-place".to_string(),
        };
        let expected_payload = encode(&message).unwrap();
        let mut payload = [0u8; 128];
        let payload_len = encode_to_slice(&message, &mut payload).unwrap();
        assert_eq!(&payload[..payload_len], expected_payload);

        let frame = Frame {
            class: TrafficClass::NewOrder,
            msg_type: 9,
            sequence: 11,
            payload: expected_payload,
        };
        let expected = frame.encode().unwrap();
        let mut out = Vec::with_capacity(expected.len());
        let len = frame.encode_into(&mut out).unwrap();
        assert_eq!(len, expected.len());
        assert_eq!(out, expected);
        let capacity = out.capacity();
        for _ in 0..1000 {
            frame.encode_into(&mut out).unwrap();
            assert_eq!(out.capacity(), capacity);
        }
    }

    #[test]
    fn in_place_frame_rejects_resize() {
        let frame = Frame {
            class: TrafficClass::NewOrder,
            msg_type: 1,
            sequence: 1,
            payload: vec![0; 100],
        };
        let mut out = Vec::with_capacity(10);
        assert!(matches!(
            frame.encode_into(&mut out),
            Err(CodecError::BufferTooSmall { .. })
        ));
        assert_eq!(out.capacity(), 10);
        assert!(out.is_empty());
    }

    #[test]
    fn frame_ref_decode_matches_owned_and_borrows_payload() {
        let f = Frame {
            class: TrafficClass::NewOrder,
            msg_type: 7,
            sequence: 123,
            payload: vec![9; 100],
        };
        let bytes = f.encode().unwrap();
        let (borrowed, consumed) = Frame::decode_ref(&bytes).unwrap();
        assert_eq!(borrowed.class, f.class);
        assert_eq!(borrowed.msg_type, f.msg_type);
        assert_eq!(borrowed.sequence, f.sequence);
        assert_eq!(borrowed.payload, f.payload.as_slice());
        assert_eq!(consumed, bytes.len());
        // The payload is the input buffer's own region — no copy.
        assert!(std::ptr::eq(
            borrowed.payload,
            &bytes[FRAME_HEADER_LEN..consumed]
        ));
        // Materializing the borrowed frame reproduces the owned decode exactly.
        assert_eq!(borrowed.to_owned(), f);
        let (owned, owned_consumed) = Frame::decode(&bytes).unwrap();
        assert_eq!(owned, f);
        assert_eq!(owned_consumed, consumed);
    }

    /// `decode_ref_with_max` must fail closed with the SAME typed errors as
    /// `decode_with_max` for every header-check arm (magic, version, class,
    /// length cap, overdeclared length, short header).
    #[test]
    fn frame_ref_decode_errors_match_owned_decode() {
        let frame = Frame {
            class: TrafficClass::RiskReducing,
            msg_type: 42,
            sequence: 9,
            payload: vec![1, 2, 3, 4],
        };
        let bytes = frame.encode().unwrap();

        let mut bad_magic = bytes.clone();
        bad_magic[0..2].copy_from_slice(&0u16.to_le_bytes());

        let mut bad_version = bytes.clone();
        bad_version[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes());

        let mut bad_class = bytes.clone();
        bad_class[4] = 9;

        let mut oversized = bytes.clone();
        let over_cap = u32::try_from(MAX_FRAME_PAYLOAD + 1).unwrap();
        oversized[15..19].copy_from_slice(&over_cap.to_le_bytes());

        let mut overdeclared = bytes.clone();
        let one_past = u32::try_from(frame.payload.len() + 1).unwrap();
        overdeclared[15..19].copy_from_slice(&one_past.to_le_bytes());

        let short_header = bytes[..FRAME_HEADER_LEN - 1].to_vec();

        let cases: Vec<(Vec<u8>, CodecError)> = vec![
            (bad_magic, CodecError::BadMagic),
            (bad_version, CodecError::UnsupportedVersion(0xFFFF)),
            (bad_class, CodecError::UnknownClass(9)),
            (oversized, CodecError::LengthOutOfRange),
            (overdeclared, CodecError::Truncated),
            (short_header, CodecError::Truncated),
        ];
        for (case, expected) in cases {
            assert_eq!(
                Frame::decode_ref_with_max(&case, MAX_FRAME_PAYLOAD)
                    .map(|(r, n)| (r.to_owned(), n)),
                Err(expected.clone()),
            );
            assert_eq!(
                Frame::decode_with_max(&case, MAX_FRAME_PAYLOAD),
                Err(expected),
            );
        }
    }

    #[test]
    fn traffic_class_priority_ordering() {
        assert!(TrafficClass::Consensus < TrafficClass::NewOrder);
        assert!(TrafficClass::NewOrder < TrafficClass::MarketData);
        assert_eq!(TrafficClass::Consensus.priority(), 0);
        assert_eq!(TrafficClass::from_u8(9), None);
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let mut state: u64 = 0xC0DEC;
        for _ in 0..50_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = usize::try_from(state % 40).unwrap();
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                buf.push(state.to_le_bytes()[0]);
            }
            let _ = Frame::decode(&buf);
            let _ = decode::<Msg>(&buf);
        }
    }

    /// Structure-aware companion to `decode_never_panics_on_arbitrary_bytes`.
    ///
    /// The random fuzz above almost never passes the magic check (2^-16 per
    /// buffer), so it exercises only the `BadMagic` arm. This test starts from
    /// a valid `Frame::encode()` output and patches specific header bytes so
    /// every later decode check is reached and returns its exact typed error.
    #[test]
    fn structured_header_mutations_yield_exact_typed_errors() {
        let msg = Msg {
            a: 7,
            b: vec![1, 2, 3],
            c: "payload".into(),
        };
        let frame = Frame {
            class: TrafficClass::RiskReducing,
            msg_type: 42,
            sequence: 9,
            payload: encode(&msg).unwrap(),
        };
        let bytes = frame.encode().unwrap();
        assert!(Frame::decode(&bytes).is_ok(), "baseline frame must decode");

        // Version word (bytes[2..4]): any value other than FRAME_VERSION is
        // rejected with the exact offending version.
        for version in [0u16, 2, 0xFFFF] {
            let mut mutated = bytes.clone();
            mutated[2..4].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                Frame::decode(&mutated),
                Err(CodecError::UnsupportedVersion(version))
            );
        }

        // Traffic-class byte (bytes[4]): 9 is the first unassigned priority.
        for class in [9u8, 0xFF] {
            let mut mutated = bytes.clone();
            mutated[4] = class;
            assert_eq!(
                Frame::decode(&mutated),
                Err(CodecError::UnknownClass(class))
            );
        }

        // Declared payload length (bytes[15..19]) above MAX_FRAME_PAYLOAD.
        let mut oversized = bytes.clone();
        let over_cap = u32::try_from(MAX_FRAME_PAYLOAD + 1).unwrap();
        oversized[15..19].copy_from_slice(&over_cap.to_le_bytes());
        assert_eq!(Frame::decode(&oversized), Err(CodecError::LengthOutOfRange));

        // Declared payload length within the cap but past the buffer end.
        let mut overdeclared = bytes.clone();
        let one_past = u32::try_from(frame.payload.len() + 1).unwrap();
        overdeclared[15..19].copy_from_slice(&one_past.to_le_bytes());
        assert_eq!(Frame::decode(&overdeclared), Err(CodecError::Truncated));

        // Buffer shorter than the fixed header.
        assert_eq!(
            Frame::decode(&bytes[..FRAME_HEADER_LEN - 1]),
            Err(CodecError::Truncated)
        );

        // Magic corruption (bytes[0..2]).
        let mut bad_magic = bytes.clone();
        bad_magic[0..2].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(Frame::decode(&bad_magic), Err(CodecError::BadMagic));

        // Payload corruption: the header stays intact so the frame itself
        // decodes, but the truncated postcard body fails typed deserialization.
        let mut msg_bytes = encode(&msg).unwrap();
        msg_bytes.pop();
        let framed = Frame {
            payload: msg_bytes,
            ..frame
        }
        .encode()
        .unwrap();
        let (back, _) = Frame::decode(&framed).unwrap();
        assert_eq!(decode::<Msg>(&back.payload), Err(CodecError::Deserialize));
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        let f = Frame {
            class: TrafficClass::Consensus,
            msg_type: 1,
            sequence: 0,
            payload: vec![1, 2],
        };
        let mut bytes = f.encode().unwrap();
        bytes[0] ^= 0xFF;
        assert_eq!(Frame::decode(&bytes), Err(CodecError::BadMagic));
        assert_eq!(Frame::decode(&bytes[..5]), Err(CodecError::Truncated));
    }

    #[test]
    fn detail_is_none_without_debug_codec_feature() {
        // Default builds keep unit variants opaque: detail() is always None.
        #[cfg(not(feature = "debug_codec"))]
        {
            assert_eq!(CodecError::Serialize.detail(), None);
            assert_eq!(CodecError::Deserialize.detail(), None);
            assert_eq!(CodecError::Truncated.detail(), None);
        }
        #[cfg(feature = "debug_codec")]
        {
            assert!(CodecError::Serialize.detail().is_some());
        }
    }
}
