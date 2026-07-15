//! Limits and typed failures for the canonical bounded Ledger v1 codec.

use thiserror::Error;

/// Independent resource limits applied before restoring canonical Ledger state.
///
/// The byte and account-slot limits are operational policy, not consensus
/// fields. A checkpoint may only allocate after its complete fixed-width image
/// has passed both limits and the allocation-free validation scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerStateLimits {
    /// Maximum complete encoded image size.
    pub max_encoded_bytes: usize,
    /// Maximum number of densely allocated account slots.
    pub max_account_slots: usize,
}

impl Default for LedgerStateLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 128 * 1024 * 1024,
            max_account_slots: 1 << 20,
        }
    }
}

/// Typed failure from canonical Ledger v1 state encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LedgerStateError {
    /// The complete input or output exceeds its independent byte limit.
    #[error("ledger state is {actual} bytes, exceeding the {max}-byte limit")]
    EncodedBytesLimit {
        /// Complete encoded size.
        actual: usize,
        /// Configured byte limit.
        max: usize,
    },
    /// The dense account count exceeds the independent decoder limit.
    #[error("ledger state account-slot count {actual} exceeds limit {max}")]
    AccountSlotsLimit {
        /// Declared account-slot count.
        actual: u64,
        /// Configured account-slot limit.
        max: u64,
    },
    /// The image uses a state schema this release does not understand.
    #[error("unsupported Ledger state version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Version found in the input.
        found: u16,
        /// Version understood by this decoder.
        expected: u16,
    },
    /// A fixed-width field extends beyond the input.
    #[error(
        "truncated Ledger state at byte {offset}: need {needed} bytes, only {remaining} remain"
    )]
    Truncated {
        /// Byte offset at which the field starts.
        offset: usize,
        /// Width of the requested field or missing image suffix.
        needed: usize,
        /// Bytes remaining at that offset.
        remaining: usize,
    },
    /// Bytes remain after the one canonical state image.
    #[error("Ledger state has {remaining} trailing bytes")]
    TrailingBytes {
        /// Unconsumed suffix length.
        remaining: usize,
    },
    /// A fixed-width value cannot be represented by the local implementation.
    #[error("Ledger state field {field} value {value} does not fit this implementation")]
    NativeWidth {
        /// Field name.
        field: &'static str,
        /// Canonical unsigned value.
        value: u64,
    },
    /// The dense shape cannot be addressed by [`types::AccountId`].
    #[error("Ledger state has {account_slots} account slots outside the AccountId namespace")]
    AccountIdNamespace {
        /// Declared or encoded account-slot count.
        account_slots: u64,
    },
    /// A row identifier itself is outside the [`types::AccountId`] namespace.
    #[error("Ledger state row id {row} is outside the AccountId namespace")]
    AccountIdRowNamespace {
        /// Encoded row identifier.
        row: u64,
    },
    /// Checked arithmetic failed while sizing or validating the state.
    #[error("arithmetic overflow while processing Ledger state field {field}")]
    ArithmeticOverflow {
        /// Field or aggregate name.
        field: &'static str,
    },
    /// One dense stored-state column does not have the canonical row count.
    #[error("Ledger state column {column} has {actual} rows; expected {expected}")]
    StateShape {
        /// Misaligned column.
        column: &'static str,
        /// Canonical row count.
        expected: usize,
        /// Observed row count.
        actual: usize,
    },
    /// The image uses a different representation for equivalent logical state.
    #[error("noncanonical Ledger state: {field}")]
    NonCanonical {
        /// Canonical representation rule that failed.
        field: &'static str,
    },
    /// The image describes state that the Ledger transition machine cannot
    /// safely continue from.
    #[error("invalid Ledger state: {field}")]
    InvalidValue {
        /// Semantic rule that failed.
        field: &'static str,
    },
    /// A bounded output or restored column could not reserve its exact storage.
    #[error("unable to allocate Ledger state resource {resource}")]
    Allocation {
        /// Output or column that failed to reserve.
        resource: &'static str,
    },
    /// Direct restoration did not reproduce the input image byte-for-byte.
    #[error("rebuilt Ledger state does not re-encode byte-identically")]
    CanonicalEncodingMismatch,
    /// Direct restoration did not preserve the authoritative transition root.
    #[error("rebuilt Ledger state does not preserve its v1 transition root")]
    RootMismatch,
}
