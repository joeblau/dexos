//! Transport error taxonomy.

use codec::TrafficClass;

/// A transport-layer failure.
///
/// Every fallible transport operation returns this typed error. Adversarial or
/// malformed wire input is always surfaced here, never as a panic.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// A bounded per-class queue was full; the caller must back off or shed.
    /// The transport never grows a queue past its configured capacity.
    #[error("backpressure: bounded queue for class {class:?} is full")]
    Backpressure {
        /// The traffic class whose queue rejected the enqueue.
        class: TrafficClass,
    },

    /// The connection has been closed by the local or remote side.
    #[error("connection closed")]
    ConnectionClosed,

    /// The peer is not reachable (not registered on the loopback fabric, or no
    /// listener at the target address).
    #[error("peer unreachable")]
    PeerUnreachable,

    /// The requested peer has no network address configured.
    #[error("no address configured for peer")]
    NoAddress,

    /// The authenticated handshake failed: the peer could not prove ownership of
    /// its claimed identity, or its identity did not match what was expected.
    #[error("authentication failed")]
    AuthFailed,

    /// The handshake was malformed or ended prematurely.
    #[error("handshake protocol violation")]
    HandshakeFailed,

    /// An encrypted record failed AEAD authentication (tamper, truncation,
    /// reorder, or wrong session key). The link must be torn down.
    #[error("session decryption failed")]
    Decrypt,

    /// A message exceeded the maximum frame payload.
    #[error("message exceeds maximum frame payload")]
    MessageTooLarge,

    /// A duplicate or replayed message was suppressed.
    #[error("duplicate or replayed message suppressed")]
    Duplicate,

    /// A reliable ordered sub-stream skipped a sequence number: a frame was lost
    /// permanently. The link is torn down so the caller resyncs rather than
    /// silently proceeding past the hole. `expected` was due next on `class`;
    /// `got` arrived instead.
    #[error("reliable sequence gap on class {class:?}: expected {expected}, got {got}")]
    ReliableGap {
        /// The traffic class whose ordered sub-stream skipped a sequence.
        class: TrafficClass,
        /// The sequence number that was due next on that class.
        expected: u64,
        /// The sequence number that actually arrived.
        got: u64,
    },

    /// A reliable class exhausted its 2^64 per-class sequence space: `u64::MAX`
    /// has already been stamped, so there is no further contiguous sequence to
    /// assign. Reusing it would make the receiver drop the frame as a duplicate,
    /// silently losing a reliable message; the send is refused so the caller
    /// re-keys / resyncs the link instead.
    #[error("reliable sequence space exhausted on class {class:?}")]
    SequenceExhausted {
        /// The traffic class whose per-class sequence space is exhausted.
        class: TrafficClass,
    },

    /// The bounded dedup / path table is at capacity and cannot admit a new key.
    #[error("dedup table capacity exceeded")]
    DedupCapacity,

    /// A wire codec failure (bad magic, truncation, unsupported version, ...).
    #[error("codec error: {0}")]
    Codec(#[from] codec::CodecError),

    /// An underlying I/O failure (TCP transport only).
    #[error("i/o error: {0}")]
    Io(String),
}

impl From<std::io::Error> for TransportError {
    fn from(value: std::io::Error) -> Self {
        TransportError::Io(value.to_string())
    }
}
