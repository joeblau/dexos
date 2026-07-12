//! `types` — shared fixed-point scalar types, compact IDs, and domain enums.
//!
//! This is the root of the deterministic execution core. It is pure and
//! integer-only: no floating point, no async runtime, no networking, no storage.
//! Every arithmetic operation documents its scale, precision, overflow behavior,
//! rounding direction, and saturation behavior.
#![forbid(unsafe_code)]

pub mod decimal;
pub mod domain;
pub mod fixed;
pub mod ids;

pub use decimal::{format_amount, parse_amount, DecimalError};
pub use domain::{
    Hash, MarketLifecycle, MarketType, OracleHealth, OrderType, PayoutVector, PayoutVectorError,
    ScalarOutcome, Side, StateRoot, TimeInForce, MAX_OUTCOMES,
};
pub use fixed::{
    Amount, ArithError, Price, Quantity, Ratio, AMOUNT_SCALE, PRICE_SCALE, QTY_SCALE, RATIO_SCALE,
};
pub use ids::{
    AccountId, IdError, MarketId, OrderId, SequenceError, SequenceNumber, ShardId, SponsorId,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "types";
