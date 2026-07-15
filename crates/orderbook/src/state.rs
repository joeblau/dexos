//! Bounded canonical OrderBook v3 state-codec limits and errors.

use thiserror::Error;

/// Independent resource limits applied while decoding canonical book state.
///
/// These limits are deliberately separate from the logical capacities encoded
/// in the state. A hostile image cannot use a large configured capacity, a
/// large number of sparse levels, or deeply nested cached fill vectors to
/// obtain an unbounded allocation from the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookStateLimits {
    /// Maximum complete encoded image size.
    pub max_encoded_bytes: usize,
    /// Maximum logical resting-order capacity.
    pub max_capacity: usize,
    /// Maximum logical book-local dedup capacity.
    pub max_dedup_capacity: usize,
    /// Maximum logical basket-leg limit.
    pub max_basket_legs: usize,
    /// Maximum total bid plus ask price levels.
    pub max_price_levels: usize,
    /// Maximum total resting orders.
    pub max_resting_orders: usize,
    /// Maximum externally supplied position entries.
    pub max_positions: usize,
    /// Maximum retained dedup records.
    pub max_dedup_records: usize,
    /// Maximum fills in any one cached match result.
    pub max_fills_per_result: usize,
    /// Maximum fills across all cached match results.
    pub max_total_fills: usize,
}

impl Default for BookStateLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 64 * 1024 * 1024,
            max_capacity: 1 << 16,
            max_dedup_capacity: 1 << 12,
            max_basket_legs: 64,
            max_price_levels: 1 << 16,
            max_resting_orders: 1 << 16,
            max_positions: 1 << 16,
            max_dedup_records: 1 << 12,
            max_fills_per_result: 1 << 16,
            max_total_fills: 1 << 20,
        }
    }
}

/// Typed failure from canonical OrderBook v3 state encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BookStateError {
    /// The complete input or output exceeds its independent byte limit.
    #[error("book state is {actual} bytes, exceeding the {max}-byte limit")]
    EncodedBytesLimit {
        /// Complete encoded size.
        actual: usize,
        /// Configured byte limit.
        max: usize,
    },
    /// One independently bounded count or logical capacity exceeds its limit.
    #[error("book state {resource} count {actual} exceeds limit {max}")]
    ResourceLimit {
        /// Stable resource name.
        resource: &'static str,
        /// Declared or accumulated count.
        actual: u64,
        /// Configured limit.
        max: u64,
    },
    /// The image uses a state schema this release does not understand.
    #[error("unsupported OrderBook state version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Version found in the input.
        found: u16,
        /// Version understood by this decoder.
        expected: u16,
    },
    /// A fixed-width field extends beyond the input.
    #[error(
        "truncated OrderBook state at byte {offset}: need {needed} bytes, only {remaining} remain"
    )]
    Truncated {
        /// Byte offset at which the field starts.
        offset: usize,
        /// Width of the requested field.
        needed: usize,
        /// Bytes remaining at that offset.
        remaining: usize,
    },
    /// Bytes remain after the one canonical state image.
    #[error("OrderBook state has {remaining} trailing bytes")]
    TrailingBytes {
        /// Unconsumed suffix length.
        remaining: usize,
    },
    /// An enum discriminant is not defined by schema v3.
    #[error("invalid {field} tag {value} in OrderBook state")]
    InvalidTag {
        /// Enum field name.
        field: &'static str,
        /// Unknown tag.
        value: u8,
    },
    /// A value cannot be represented safely by the local implementation.
    #[error("OrderBook state field {field} value {value} does not fit this implementation")]
    NativeWidth {
        /// Field name.
        field: &'static str,
        /// Canonical unsigned value.
        value: u64,
    },
    /// Checked arithmetic failed while sizing or validating the state.
    #[error("arithmetic overflow while processing OrderBook state field {field}")]
    ArithmeticOverflow {
        /// Field or aggregate name.
        field: &'static str,
    },
    /// The input uses a different representation for equivalent logical state.
    #[error("noncanonical OrderBook state: {field}")]
    NonCanonical {
        /// Canonical-ordering or uniqueness rule that failed.
        field: &'static str,
    },
    /// The image describes state that the OrderBook transition machine cannot
    /// produce or safely continue from.
    #[error("invalid OrderBook state: {field}")]
    InvalidValue {
        /// Semantic rule that failed.
        field: &'static str,
    },
    /// Rebuilding derived indexes changed the canonical encoding.
    #[error("rebuilt OrderBook state does not re-encode byte-identically")]
    CanonicalEncodingMismatch,
    /// Rebuilding derived state changed the authoritative v3 transition root.
    #[error("rebuilt OrderBook state does not preserve its v3 transition root")]
    RootMismatch,
}
