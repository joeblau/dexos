//! Limits and typed failures for the canonical bounded ReplayGuard v1 codec.

use thiserror::Error;

/// Independent resource limits applied before restoring canonical replay state.
///
/// The logical replay window is bounded independently from the number of
/// currently retained records. A small watermark-only image with an enormous
/// window would otherwise make a later [`super::ReplayGuard::prepare_window`]
/// attempt an enormous allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayStateLimits {
    /// Maximum complete encoded image size.
    pub(crate) max_encoded_bytes: usize,
    /// Maximum logical receipt window restored into the guard.
    pub(crate) max_window: usize,
    /// Maximum number of principal/domain watermarks.
    pub(crate) max_watermarks: usize,
    /// Maximum number of retained records and FIFO entries.
    pub(crate) max_records: usize,
}

impl Default for ReplayStateLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 128 * 1024 * 1024,
            max_window: 1 << 20,
            max_watermarks: 1 << 20,
            max_records: 1 << 20,
        }
    }
}

/// Typed failure from canonical ReplayGuard v1 state encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReplayStateError {
    /// The complete input or output exceeds its independent byte limit.
    #[error("replay state is {actual} bytes, exceeding the {max}-byte limit")]
    EncodedBytesLimit {
        /// Complete encoded size.
        actual: usize,
        /// Configured byte limit.
        max: usize,
    },
    /// One independently bounded count or logical capacity exceeds its limit.
    #[error("replay state {resource} count {actual} exceeds limit {max}")]
    ResourceLimit {
        /// Stable resource name.
        resource: &'static str,
        /// Declared count or logical capacity.
        actual: u64,
        /// Configured limit.
        max: u64,
    },
    /// The image uses a state schema this release does not understand.
    #[error("unsupported ReplayGuard state version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Version found in the input.
        found: u16,
        /// Version understood by this decoder.
        expected: u16,
    },
    /// A fixed-width field extends beyond the input.
    #[error(
        "truncated ReplayGuard state at byte {offset}: need {needed} bytes, only {remaining} remain"
    )]
    Truncated {
        /// Byte offset at which the field starts.
        offset: usize,
        /// Width of the requested field or minimum remaining image.
        needed: usize,
        /// Bytes remaining at that offset.
        remaining: usize,
    },
    /// Bytes remain after the one canonical state image.
    #[error("ReplayGuard state has {remaining} trailing bytes")]
    TrailingBytes {
        /// Unconsumed suffix length.
        remaining: usize,
    },
    /// An enum or canonical boolean discriminant is not defined by schema v1.
    #[error("invalid {field} tag {value} in ReplayGuard state")]
    InvalidTag {
        /// Enum or boolean field name.
        field: &'static str,
        /// Unknown tag.
        value: u8,
    },
    /// A fixed-width value cannot be represented by the local implementation.
    #[error("ReplayGuard state field {field} value {value} does not fit this implementation")]
    NativeWidth {
        /// Field name.
        field: &'static str,
        /// Canonical unsigned value.
        value: u64,
    },
    /// Checked arithmetic failed while sizing or validating the state.
    #[error("arithmetic overflow while processing ReplayGuard state field {field}")]
    ArithmeticOverflow {
        /// Field or aggregate name.
        field: &'static str,
    },
    /// The input uses a different representation for equivalent logical state.
    #[error("noncanonical ReplayGuard state: {field}")]
    NonCanonical {
        /// Canonical ordering or uniqueness rule that failed.
        field: &'static str,
    },
    /// The image describes state that the replay transition machine cannot
    /// safely continue from.
    #[error("invalid ReplayGuard state: {field}")]
    InvalidValue {
        /// Semantic rule that failed.
        field: &'static str,
    },
    /// A bounded output or restored collection could not reserve its storage.
    #[error("unable to allocate ReplayGuard state resource {resource}")]
    Allocation {
        /// Output or collection that failed to reserve.
        resource: &'static str,
    },
    /// Direct restoration did not reproduce the input image byte-for-byte.
    #[error("rebuilt ReplayGuard state does not re-encode byte-identically")]
    CanonicalEncodingMismatch,
    /// Direct restoration did not preserve the authoritative transition root.
    #[error("rebuilt ReplayGuard state does not preserve its v1 transition root")]
    RootMismatch,
}
