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
    /// A scoped session key was presented to authorize a withdrawal. Session
    /// keys are trading-only; only the account master key may withdraw funds.
    #[error("session keys cannot authorize withdrawals")]
    SessionCannotWithdraw,
    /// A cancel/replace targeted a resting order owned by a different account.
    #[error("order is not owned by the requesting account")]
    OrderNotOwned,
    /// A liquidation was requested for an account that is not at or below its
    /// maintenance-margin threshold.
    #[error("account is not liquidatable")]
    AccountNotLiquidatable,
    /// A command arrived with a sequence number that did not strictly advance
    /// the engine's last applied sequence (replay or out-of-order delivery).
    #[error("non-monotonic sequence: last {last}, got {got}")]
    NonMonotonicSequence {
        /// Last sequence the engine applied.
        last: u64,
        /// Sequence just presented.
        got: u64,
    },
    /// A retry reused an idempotency key (`client_id` / withdrawal `nonce`) with
    /// a different canonical payload than the command originally committed under
    /// that key. Never re-applied: the first command stands.
    #[error("idempotency conflict: key reused with a different payload")]
    IdempotencyConflict,
    /// A retry targeted an idempotency key that was already processed but whose
    /// receipt has aged out of the bounded replay window (or refers to a stale,
    /// lower-than-watermark key). The original effect stands and is never
    /// re-applied; the caller must observe the outcome out of band.
    #[error("idempotency replay expired: key already processed, receipt evicted")]
    ReplayExpired,
    /// Two distinct authenticated withdrawal requests derived the same withdrawal
    /// id (a digest collision). Surfaced rather than silently overwriting the
    /// existing withdrawal.
    #[error("withdrawal id collision")]
    WithdrawalIdCollision,
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
    /// A protocol upgrade tried to move to a non-greater version.
    #[error("protocol downgrade rejected: current {current}, requested {requested}")]
    ProtocolDowngrade {
        /// Current active version.
        current: u16,
        /// Requested version.
        requested: u16,
    },
    /// Market lifecycle does not accept new risk (not Open).
    #[error("market not open for trading")]
    MarketNotOpen,
    /// Oracle health freezes or halts new risk.
    #[error("oracle health rejects new risk")]
    OracleRiskFrozen,
    /// Funding epoch was already applied or is not sequential.
    #[error("funding epoch not sequential")]
    FundingEpochConflict,
    /// Operation is incompatible with the market's committed instrument type.
    #[error("operation incompatible with market type")]
    IncompatibleMarketType,
    /// Instrument / outcome coordinate is out of range for the market.
    #[error("instrument out of range for market")]
    InvalidInstrument,
    /// Seller lacks sufficient outcome claims for the fill.
    #[error("insufficient outcome claims")]
    InsufficientClaims,
    /// Market order is missing a positive protection collar / notional cap.
    #[error("market order requires a positive protection price collar")]
    MarketOrderCollarRequired,
    /// Executable depth notional exceeds the market order's protection collar.
    #[error("market order depth exceeds protection collar notional")]
    MarketOrderDepthExceeded,
    /// Market is not in a state that accepts this lifecycle operation.
    #[error("market lifecycle rejects operation")]
    LifecycleRejected,
    /// Market has no committed resolution to settle.
    #[error("market is not resolved")]
    MarketNotResolved,
}
