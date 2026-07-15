//! Typed error surface for the risk engine.
//!
//! No operation in library code panics on adversarial input; every fallible
//! path returns a [`RiskError`]. Arithmetic overflow from the fixed-point core
//! is folded into [`RiskError::Arith`], identifier conversion issues into
//! [`RiskError::Id`], and payout-vector construction issues into
//! [`RiskError::Payout`].

use types::{Amount, ArithError, IdError, PayoutVectorError};

/// Every way a risk-engine operation can fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RiskError {
    /// The referenced account was never opened.
    #[error("account is not known to the risk engine")]
    UnknownAccount,
    /// Attempted to open an account slot that is already occupied.
    #[error("account already exists")]
    AccountExists,
    /// The account exists but has been closed (e.g. bankrupted via liquidation).
    #[error("account is closed")]
    AccountClosed,
    /// The order would leave the account below its initial-margin requirement.
    #[error("insufficient margin: require {required:?}, available {available:?}")]
    InsufficientMargin {
        /// Initial margin required after the order.
        required: Amount,
        /// Equity available to post as margin.
        available: Amount,
    },
    /// The order would push notional exposure past `equity * max_leverage`.
    #[error("order exceeds maximum leverage")]
    LeverageExceeded,
    /// The order would push total account notional past the portfolio cap.
    #[error("order exceeds portfolio notional limit")]
    PortfolioLimitExceeded,
    /// The order would push a single market's notional past its cap.
    #[error("order exceeds per-market notional limit")]
    MarketLimitExceeded,
    /// A reduce-only order was submitted against an account with no exposure.
    #[error("reduce-only order has no exposure to reduce")]
    NothingToReduce,
    /// A debit/withdraw exceeded the account's free collateral.
    #[error("insufficient free collateral")]
    InsufficientCollateral,
    /// The requested amount was negative where only non-negative is allowed.
    #[error("amount must be non-negative")]
    NegativeAmount,
    /// An account or market identifier lies at or beyond the engine's configured
    /// dense-slot capacity; admitting it would demand an unbounded allocation, so
    /// the id is rejected before any column is grown.
    #[error("identifier index {index} exceeds configured capacity {capacity}")]
    CapacityExceeded {
        /// The slab index derived from the offending identifier.
        index: usize,
        /// The configured capacity the index met or exceeded.
        capacity: usize,
    },
    /// A configured capacity was zero or above the engine's hard resource budget.
    #[error("configured capacity {requested} outside permitted range 1..={budget}")]
    CapacityConfig {
        /// The requested capacity.
        requested: usize,
        /// The hard resource-budget ceiling.
        budget: usize,
    },
    /// Stored Structure-of-Arrays columns disagree about their slot count.
    /// A transition root cannot safely represent such malformed state.
    #[error("risk {section} column {column} has length {actual}, expected {expected}")]
    StateShape {
        /// Whether the malformed column is account- or market-indexed.
        section: &'static str,
        /// Name of the malformed column.
        column: &'static str,
        /// Slot count established by the section's primary column.
        expected: usize,
        /// Actual length of the malformed column.
        actual: usize,
    },
    /// A native-width slot index or sequence length cannot be represented by
    /// the v1 fixed-width commitment format.
    #[error("state value {value} does not fit the transition-root u64 encoding")]
    StateEncodingOverflow {
        /// Native-width value that could not be encoded.
        value: usize,
    },
    /// Stored risk state violates a relation required for deterministic future
    /// transitions, such as cache equality or reverse-index consistency.
    #[error("risk state invariant violated: {0}")]
    StateInvariant(&'static str),
    /// A fixed-point arithmetic step overflowed or divided by zero.
    #[error("fixed-point arithmetic error: {0}")]
    Arith(#[from] ArithError),
    /// An identifier could not be converted to an index.
    #[error("identifier error: {0}")]
    Id(#[from] IdError),
    /// A payout vector was malformed.
    #[error("payout vector error: {0}")]
    Payout(#[from] PayoutVectorError),
}
