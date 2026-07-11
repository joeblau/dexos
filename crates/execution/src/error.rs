//! Exhaustive execution error taxonomy. No engine path panics on untrusted input.

use types::ArithError;

/// An error from applying a [`crate::Command`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionError {
    /// Referenced account does not exist.
    #[error("unknown account")]
    UnknownAccount,
    /// Account already exists at that id.
    #[error("account already exists")]
    AccountExists,
    /// Available balance is insufficient for the operation.
    #[error("insufficient available balance: need {required}, have {available}")]
    InsufficientAvailable {
        /// Required micro-units.
        required: i128,
        /// Available micro-units.
        available: i128,
    },
    /// Reserved/locked balance is insufficient to release.
    #[error("insufficient reserved/locked balance")]
    InsufficientReserved,
    /// A negative amount was supplied where non-negative is required.
    #[error("amount must be non-negative")]
    NegativeAmount,
    /// A deposit certificate with this (chain, tx, event) was already credited.
    #[error("duplicate deposit")]
    DuplicateDeposit,
    /// Referenced withdrawal id is unknown.
    #[error("unknown withdrawal")]
    UnknownWithdrawal,
    /// Withdrawal already finalized.
    #[error("withdrawal already finalized")]
    WithdrawalAlreadyFinalized,
    /// A session key was not found.
    #[error("unknown session")]
    UnknownSession,
    /// The session has expired.
    #[error("session expired")]
    SessionExpired,
    /// The nonce was already consumed (replay) or is outside the session range.
    #[error("nonce replay or out of range")]
    BadNonce,
    /// The session is not authorized for the target market.
    #[error("session not authorized for market")]
    MarketNotAuthorized,
    /// The order notional exceeds the session's max notional.
    #[error("order exceeds session notional limit")]
    NotionalExceeded,
    /// Referenced market does not exist.
    #[error("unknown market")]
    UnknownMarket,
    /// Market already exists at that id.
    #[error("market already exists")]
    MarketExists,
    /// Redeem attempted without holding a complete set.
    #[error("incomplete set: cannot redeem")]
    IncompleteSet,
    /// A signature failed verification.
    #[error("invalid signature")]
    InvalidSignature,
    /// A downstream order-book error.
    #[error("order book: {0}")]
    Order(#[from] orderbook::OrderError),
    /// A downstream risk error.
    #[error("risk: {0}")]
    Risk(#[from] risk::RiskError),
    /// A downstream state-tree error.
    #[error("state tree: {0}")]
    State(#[from] state_tree::StateError),
    /// A fixed-point arithmetic error.
    #[error("arithmetic: {0}")]
    Arith(#[from] ArithError),
    /// A capability implemented in a later phase.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}
