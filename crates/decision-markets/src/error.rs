//! Typed error surface for the decision-market engine.
//!
//! No operation panics on adversarial input; every fallible path returns one of
//! these variants. Arithmetic and identifier failures from `types` are wrapped
//! so callers can match on a single error type.

use types::{ArithError, IdError};

use crate::lifecycle::DecisionPhase;

/// Any failure raised by the decision-market engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecisionMarketError {
    /// The market definition supplied zero actions.
    #[error("a decision market requires at least one action")]
    NoActions,
    /// The market definition supplied more actions than [`crate::MAX_ACTIONS`].
    #[error("too many actions (max {max})")]
    TooManyActions {
        /// The configured maximum.
        max: usize,
    },
    /// The market definition supplied zero outcomes.
    #[error("a decision market requires at least one outcome")]
    NoOutcomes,
    /// The market definition supplied more outcomes than allowed.
    #[error("too many outcomes (max {max})")]
    TooManyOutcomes {
        /// The configured maximum.
        max: usize,
    },
    /// The utility function length does not match the outcome count.
    #[error("utility function length {got} does not match outcome count {expected}")]
    UtilityLengthMismatch {
        /// Expected length (outcome count).
        expected: usize,
        /// Length supplied.
        got: usize,
    },
    /// A time window had non-positive duration (`end <= start`).
    #[error("time window must have strictly positive duration")]
    EmptyWindow,
    /// The selection and evaluation windows overlap or are out of order.
    #[error("evaluation window must not start before the selection window ends")]
    WindowOrdering,
    /// A label was empty or exceeded the byte bound.
    #[error("label must be non-empty and at most {max} bytes")]
    InvalidLabel {
        /// The configured maximum label length in bytes.
        max: usize,
    },
    /// The collateral (par) value per complete set was not strictly positive.
    #[error("collateral per complete set must be strictly positive")]
    NonPositiveCollateral,
    /// An action index was out of range for this market.
    #[error("unknown action index")]
    UnknownAction,
    /// An outcome index was out of range for this market.
    #[error("unknown outcome index")]
    UnknownOutcome,
    /// A share-reducing operation exceeded an account's holdings.
    #[error("insufficient shares for the requested operation")]
    InsufficientShares,
    /// A non-positive size was supplied to mint/redeem/trade.
    #[error("size must be strictly positive")]
    NonPositiveSize,
    /// An operation was attempted in the wrong lifecycle phase.
    #[error("operation not permitted in phase {phase:?}")]
    WrongPhase {
        /// The current phase.
        phase: DecisionPhase,
    },
    /// A lifecycle transition from `from` to `to` is not allowed.
    #[error("illegal lifecycle transition from {from:?} to {to:?}")]
    IllegalTransition {
        /// Source phase.
        from: DecisionPhase,
        /// Attempted target phase.
        to: DecisionPhase,
    },
    /// A price tick arrived out of chronological order.
    #[error("price observation is out of chronological order")]
    OutOfOrderTick,
    /// No priced interval fell within the window, so no TWAP exists.
    #[error("no observations covered the window")]
    NoObservations,
    /// A contingent market held less collateral than the minimum liquidity floor.
    #[error("market liquidity is below the required minimum")]
    LiquidityTooThin,
    /// A single account exceeded the concentration limit for a valid decision.
    #[error("position concentration exceeds the allowed limit")]
    ConcentrationExceeded,
    /// An externally supplied confirmation payload was malformed.
    #[error("malformed external confirmation payload")]
    MalformedConfirmation,
    /// An externally supplied confirmation replayed or reused a stale sequence.
    #[error("stale or replayed external confirmation")]
    StaleConfirmation,
    /// A serialized definition could not be decoded from bytes.
    #[error("malformed decision-market definition bytes")]
    MalformedDefinition,
    /// A settlement was requested before an action was selected/resolved.
    #[error("market has no selected action")]
    NotSelected,
    /// A settlement was requested before the winning outcome was resolved.
    #[error("market has no resolved outcome")]
    NotResolved,
    /// A fixed-point computation overflowed or divided by zero.
    #[error("arithmetic error: {0}")]
    Arithmetic(#[from] ArithError),
    /// A compact identifier could not be represented.
    #[error("identifier error: {0}")]
    Id(#[from] IdError),
    /// A value did not fit its destination integer width.
    #[error("value does not fit destination integer type")]
    Truncation,
}
