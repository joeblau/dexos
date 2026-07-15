//! Bounded canonical session-registry state-codec limits and errors.

use thiserror::Error;

/// Independent resource limits for canonical [`super::SessionRegistry`] state.
///
/// Counts are bounded separately from the complete byte image because nested
/// market and consumed-nonce collections have distinct allocation and future
/// execution costs. These are recovery-policy limits, not command-time
/// consensus limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStateLimits {
    /// Maximum complete encoded image size.
    pub max_encoded_bytes: usize,
    /// Maximum sessions in one registry.
    pub max_sessions: usize,
    /// Maximum distinct explicit markets authorized by one session.
    pub max_markets_per_session: usize,
    /// Maximum distinct explicit market entries across all sessions.
    pub max_total_markets: usize,
    /// Maximum consumed nonces retained by one session.
    pub max_consumed_nonces_per_session: usize,
    /// Maximum consumed nonce entries across all sessions.
    pub max_total_consumed_nonces: usize,
}

impl Default for SessionStateLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 256 * 1024 * 1024,
            max_sessions: 1 << 20,
            max_markets_per_session: 1 << 16,
            max_total_markets: 1 << 20,
            max_consumed_nonces_per_session: 1 << 20,
            max_total_consumed_nonces: 1 << 24,
        }
    }
}

/// Typed failure from canonical SessionRegistry v1 state encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SessionStateError {
    /// The complete input or output exceeds its independent byte limit.
    #[error("session state is {actual} bytes, exceeding the {max}-byte limit")]
    EncodedBytesLimit {
        /// Complete encoded size.
        actual: usize,
        /// Configured byte limit.
        max: usize,
    },
    /// One independently bounded count exceeds its configured limit.
    #[error("session state {resource} count {actual} exceeds limit {max}")]
    ResourceLimit {
        /// Stable resource name.
        resource: &'static str,
        /// Declared or accumulated count.
        actual: u64,
        /// Configured limit.
        max: u64,
    },
    /// The image uses a state schema this release does not understand.
    #[error("unsupported SessionRegistry state version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Version found in the image.
        found: u16,
        /// Version understood by this decoder.
        expected: u16,
    },
    /// A fixed-width field extends beyond the input.
    #[error(
        "truncated session state at byte {offset}: need {needed} bytes, only {remaining} remain"
    )]
    Truncated {
        /// Byte offset at which the field starts.
        offset: usize,
        /// Width of the requested field or minimum remaining structure.
        needed: usize,
        /// Bytes remaining at that offset.
        remaining: usize,
    },
    /// Bytes remain after the one canonical state image.
    #[error("session state has {remaining} trailing bytes")]
    TrailingBytes {
        /// Unconsumed suffix length.
        remaining: usize,
    },
    /// A scope discriminant is not defined by schema v1.
    #[error("invalid {field} tag {value} in session state")]
    InvalidTag {
        /// Tagged field name.
        field: &'static str,
        /// Unknown tag.
        value: u8,
    },
    /// A canonical unsigned value cannot be represented by this implementation.
    #[error("session state field {field} value {value} does not fit this implementation")]
    NativeWidth {
        /// Field name.
        field: &'static str,
        /// Canonical unsigned value.
        value: u64,
    },
    /// Checked arithmetic failed while sizing or validating the image.
    #[error("arithmetic overflow while processing session state field {field}")]
    ArithmeticOverflow {
        /// Field or aggregate name.
        field: &'static str,
    },
    /// The input uses a different representation for equivalent logical state.
    #[error("noncanonical session state: {field}")]
    NonCanonical {
        /// Canonical-ordering, uniqueness, or framing rule that failed.
        field: &'static str,
    },
    /// The image describes state the transition machine cannot continue from.
    #[error("invalid session state: {field}")]
    InvalidValue {
        /// Semantic rule that failed.
        field: &'static str,
    },
    /// A bounded allocation request failed.
    #[error("could not allocate bounded session state resource: {resource}")]
    AllocationFailed {
        /// Resource whose fallible reserve failed.
        resource: &'static str,
    },
    /// Direct reconstruction changed the canonical encoding.
    #[error("rebuilt SessionRegistry state does not re-encode byte-identically")]
    CanonicalEncodingMismatch,
    /// Direct reconstruction changed the authoritative transition root.
    #[error("rebuilt SessionRegistry state does not preserve its v1 transition root")]
    RootMismatch,
}
