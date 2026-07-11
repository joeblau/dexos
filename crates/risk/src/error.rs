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
