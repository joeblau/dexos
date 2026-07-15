//! Bounded canonical RiskEngine v1 state-codec limits and errors.

use thiserror::Error;

use crate::{RiskError, DEFAULT_MAX_ACCOUNTS, DEFAULT_MAX_MARKETS};

/// Independent resource limits applied while decoding canonical risk state.
///
/// These limits are deliberately separate from the capacities encoded in the
/// state. A small image with a large logical capacity can authorize a later
/// dense allocation, while nested position and payout counts can amplify work
/// independently of the account-slot count. Both forms are bounded here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskStateLimits {
    /// Maximum complete encoded image size.
    pub max_encoded_bytes: usize,
    /// Maximum configured/effective account capacity.
    pub max_account_capacity: usize,
    /// Maximum configured/effective market capacity.
    pub max_market_capacity: usize,
    /// Maximum currently allocated dense account slots.
    pub max_account_slots: usize,
    /// Maximum currently allocated dense market slots.
    pub max_market_slots: usize,
    /// Maximum perp positions retained by any one account.
    pub max_perp_positions_per_account: usize,
    /// Maximum perp positions across every account.
    pub max_total_perp_positions: usize,
    /// Maximum payout positions retained by any one account.
    pub max_payout_positions_per_account: usize,
    /// Maximum payout positions across every account.
    pub max_total_payout_positions: usize,
    /// Maximum outcomes in any one payout vector.
    pub max_outcomes_per_payout: usize,
    /// Maximum payout-vector values across every payout position.
    pub max_total_payout_values: usize,
    /// Maximum accounts in any one market's holder index.
    pub max_holders_per_market: usize,
    /// Maximum holder-index entries across every market.
    pub max_total_market_holders: usize,
    /// Maximum entries in each liquidation-queue representation.
    pub max_liquidation_entries: usize,
}

impl Default for RiskStateLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 256 * 1024 * 1024,
            max_account_capacity: DEFAULT_MAX_ACCOUNTS,
            max_market_capacity: DEFAULT_MAX_MARKETS,
            max_account_slots: DEFAULT_MAX_ACCOUNTS,
            max_market_slots: DEFAULT_MAX_MARKETS,
            max_perp_positions_per_account: DEFAULT_MAX_MARKETS,
            max_total_perp_positions: DEFAULT_MAX_ACCOUNTS,
            max_payout_positions_per_account: 1 << 16,
            max_total_payout_positions: DEFAULT_MAX_ACCOUNTS,
            max_outcomes_per_payout: types::MAX_OUTCOMES,
            max_total_payout_values: DEFAULT_MAX_ACCOUNTS,
            max_holders_per_market: DEFAULT_MAX_ACCOUNTS,
            max_total_market_holders: DEFAULT_MAX_ACCOUNTS,
            max_liquidation_entries: DEFAULT_MAX_ACCOUNTS,
        }
    }
}

/// Typed failure from canonical RiskEngine v1 state encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RiskStateError {
    /// The complete input or output exceeds its independent byte limit.
    #[error("risk state is {actual} bytes, exceeding the {max}-byte limit")]
    EncodedBytesLimit {
        /// Complete encoded size.
        actual: usize,
        /// Configured byte limit.
        max: usize,
    },
    /// One independently bounded count or logical capacity exceeds its limit.
    #[error("risk state {resource} count {actual} exceeds limit {max}")]
    ResourceLimit {
        /// Stable resource name.
        resource: &'static str,
        /// Declared or accumulated count.
        actual: u64,
        /// Configured limit.
        max: u64,
    },
    /// The image uses a state schema this release does not understand.
    #[error("unsupported RiskEngine state version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Version found in the input.
        found: u16,
        /// Version understood by this decoder.
        expected: u16,
    },
    /// A fixed-width field extends beyond the input.
    #[error("truncated risk state at byte {offset}: need {needed} bytes, only {remaining} remain")]
    Truncated {
        /// Byte offset at which the field starts.
        offset: usize,
        /// Width of the requested field.
        needed: usize,
        /// Bytes remaining at that offset.
        remaining: usize,
    },
    /// Bytes remain after the one canonical state image.
    #[error("risk state has {remaining} trailing bytes")]
    TrailingBytes {
        /// Unconsumed suffix length.
        remaining: usize,
    },
    /// A boolean, enum, or option discriminant is not defined by schema v1.
    #[error("invalid {field} tag {value} in risk state")]
    InvalidTag {
        /// Enum or option field name.
        field: &'static str,
        /// Unknown tag.
        value: u8,
    },
    /// A canonical unsigned value cannot be represented by this implementation.
    #[error("risk state field {field} value {value} does not fit this implementation")]
    NativeWidth {
        /// Field name.
        field: &'static str,
        /// Canonical unsigned value.
        value: u64,
    },
    /// Checked arithmetic failed while sizing or validating the state.
    #[error("arithmetic overflow while processing risk state field {field}")]
    ArithmeticOverflow {
        /// Field or aggregate name.
        field: &'static str,
    },
    /// The input uses a different representation for equivalent logical state.
    #[error("noncanonical risk state: {field}")]
    NonCanonical {
        /// Canonical-ordering or uniqueness rule that failed.
        field: &'static str,
    },
    /// The image describes state that the transition machine cannot continue.
    #[error("invalid risk state: {field}")]
    InvalidValue {
        /// Semantic rule that failed.
        field: &'static str,
    },
    /// Recomputed primary/derived state failed the engine's authoritative checks.
    #[error("invalid RiskEngine state: {0}")]
    RiskInvariant(#[from] RiskError),
    /// Rebuilding derived state changed the canonical encoding.
    #[error("rebuilt RiskEngine state does not re-encode byte-identically")]
    CanonicalEncodingMismatch,
    /// Rebuilding derived state changed the authoritative v1 transition root.
    #[error("rebuilt RiskEngine state does not preserve its v1 transition root")]
    RootMismatch,
}
