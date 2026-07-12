//! `orderbook` — deterministic native CLOB plus a conditional/triggered order
//! engine.
//!
//! Part of the DexOS deterministic execution core: no async runtime, no
//! networking, no floating point, fixed-point integers only.
//!
//! # Order book
//! [`OrderBook`] is a central-limit order book with strict price-time priority,
//! O(1)-average cancel-by-id lookup plus O(1) intrusive unlink, intrusive FIFO price levels,
//! and a fixed-capacity slab arena with a free list (no per-operation heap
//! allocation on the warm path). It supports Limit / Market / PostOnly /
//! ReduceOnly order types, Gtc / Ioc / Fok time-in-force, self-trade
//! prevention, client-assigned idempotency keys, atomic cancel-replace,
//! baskets, and cancel-all.
//! Cancel-all uses a per-account ordered index and costs O(K log K) for that
//! account's K orders; it never scans all N orders in the book. Hash-table
//! lookup is amortized, while the unlink itself has a strict constant bound.
//!
//! # Conditional engine
//! [`ConditionalEngine`] evaluates stop-loss, take-profit, trailing-stop, OCO,
//! and TWAP triggers against a mark price and emits canonical [`OrderIntent`]s.
//! It never mutates the book directly.
#![forbid(unsafe_code)]

mod book;
mod conditional;
mod dedup;
mod error;
mod level;
mod order;
mod slab;

pub use book::OrderBook;
pub use conditional::{
    decode_conditional, ConditionalConfig, ConditionalEngine, ConditionalId, ConditionalStatus,
    DecodedConditional, ExecutionAck, OcoLeg, OrderIntent, PlaceTemplate, TrailDirection, Trailing,
    TriggerKind, ENCODED_CONDITIONAL_LEN,
};
pub use error::{ConditionalError, OrderError, SlabError};
pub use order::{
    BookConfig, Fill, MatchPlan, MatchResult, NewOrder, OrderOutcome, PlannedFill, StpPolicy,
};

/// Authenticated book-root schema version (v2 = multiset of per-order leaves).
///
/// Hot-path mutations update only the touched order leaf and re-finalize the
/// cached aggregate; they never re-serialize the full resting set. See
/// [`OrderBook::state_root`] and [`OrderBook::state_root_full_rebuild`].
pub const BOOK_ROOT_SCHEMA_VERSION: u8 = 2;

/// Documented hot-path hashing budget for a no-fill insert or cancel of one
/// resting order: one order-leaf preimage (≤ 48 bytes of fields) under
/// [`crypto::DOMAIN_EXECUTION`], XOR into the 32-byte aggregate, then one
/// finalize hash over `1 + 32` bytes (schema version + aggregate). Independent
/// of resting-book size — p99 bytes hashed stays flat from 1K to 65K orders.
pub const BOOK_ROOT_HOT_PATH_HASH_BUDGET_BYTES: usize = 48 + 33;
pub use slab::Slab;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "orderbook";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "orderbook");
    }
}
