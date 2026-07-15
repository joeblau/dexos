//! Typed failures for canonical bounded Engine state encoding.

use thiserror::Error;

use crate::error::ExecutionError;
use crate::idempotency::ReplayStateError;
use crate::ledger::LedgerStateError;
use crate::session::SessionStateError;

/// Typed failure from canonical Engine v1 state encoding.
///
/// This error currently describes encoding only. A future decoder may extend
/// the taxonomy without weakening the one-way encoder's output-byte bound.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EngineStateError {
    /// The checked output size or a proven lower bound exceeds its independent
    /// byte limit.
    #[error(
        "Engine state requires at least {required_at_least} bytes, exceeding the {max}-byte limit"
    )]
    EncodedBytesLimit {
        /// Exact size when all children have been encoded, otherwise the
        /// checked lower bound reached before retaining another child image.
        required_at_least: usize,
        /// Configured byte limit.
        max: usize,
    },
    /// A native-width value cannot be represented by the canonical u64 field.
    #[error("Engine state field {field} value {value} does not fit canonical u64 encoding")]
    NativeWidth {
        /// Stable field name.
        field: &'static str,
        /// Native-width value that could not be represented.
        value: usize,
    },
    /// Checked arithmetic failed while sizing the state image.
    #[error("arithmetic overflow while processing Engine state field {field}")]
    ArithmeticOverflow {
        /// Stable field or aggregate name.
        field: &'static str,
    },
    /// A bounded outer buffer or ordering workspace could not reserve storage.
    #[error("unable to allocate Engine state resource {resource}")]
    Allocation {
        /// Output or ordering workspace that failed to reserve storage.
        resource: &'static str,
    },
    /// The source Engine violates a transition or recovery invariant.
    #[error("invalid source Engine state: {0}")]
    InvalidEngine(#[from] ExecutionError),
    /// Canonical Ledger child encoding failed.
    #[error("Ledger child state: {0}")]
    Ledger(#[from] LedgerStateError),
    /// Canonical SessionRegistry child encoding failed.
    #[error("SessionRegistry child state: {0}")]
    Session(#[from] SessionStateError),
    /// Canonical RiskEngine child encoding failed.
    #[error("RiskEngine child state: {0}")]
    Risk(#[from] risk::RiskStateError),
    /// Canonical ReplayGuard child encoding failed.
    #[error("ReplayGuard child state: {0}")]
    Replay(#[from] ReplayStateError),
    /// One keyed canonical OrderBook child encoding failed.
    #[error("OrderBook child state for market {market}, instrument {instrument}: {source}")]
    Book {
        /// Owning market identifier.
        market: u32,
        /// Instrument identifier within the market.
        instrument: u16,
        /// Typed child-codec failure.
        #[source]
        source: orderbook::BookStateError,
    },
    /// The checked size preflight disagreed with the emitted image.
    #[error("Engine state size preflight expected {expected} bytes but emitted {actual}")]
    EncodingSizeMismatch {
        /// Exact size computed before allocating the output.
        expected: usize,
        /// Bytes actually emitted.
        actual: usize,
    },
}
