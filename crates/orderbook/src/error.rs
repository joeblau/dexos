//! Typed error enums for the order book and its supporting stores.
//!
//! Every fallible operation in this crate returns one of these instead of
//! panicking. Adversarial input (negative prices, zero quantities, exhausted
//! capacity, unknown ids) is always surfaced as a typed error.

use thiserror::Error;

/// A failure from the fixed-capacity slab allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SlabError {
    /// No free slot remains; the arena is at its configured capacity.
    #[error("slab capacity exhausted")]
    CapacityExhausted,
    /// The slot index is out of bounds for this slab.
    #[error("slab slot index out of range")]
    InvalidSlot,
    /// The slot referenced was already free (double free / use-after-free).
    #[error("slab slot was not occupied")]
    NotOccupied,
}

/// A failure from an order-book operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OrderError {
    /// The order quantity was zero or negative.
    #[error("order quantity must be strictly positive")]
    NonPositiveQuantity,
    /// The order price was zero or negative (limit / post-only orders).
    #[error("order price must be strictly positive")]
    NonPositivePrice,
    /// The book's slab is full and the order cannot rest.
    #[error("order book at capacity")]
    CapacityExhausted,
    /// No resting order exists with the referenced id.
    #[error("unknown order id")]
    UnknownOrder,
    /// A cancel/replace targeted an order owned by a different account.
    #[error("order not owned by caller")]
    NotOwner,
    /// A fixed-point arithmetic operation overflowed.
    #[error("arithmetic overflow")]
    Overflow,
    /// A basket exceeded the configured maximum number of legs.
    #[error("basket exceeds maximum legs")]
    BasketTooLarge,
    /// A basket contained a duplicate order id across its legs.
    #[error("basket contains duplicate order id")]
    BasketDuplicateId,
    /// An order id collided with one already resting on the book.
    #[error("order id already in use")]
    DuplicateOrderId,
}

impl From<types::ArithError> for OrderError {
    fn from(_: types::ArithError) -> Self {
        OrderError::Overflow
    }
}

/// A failure from the conditional / triggered order engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConditionalError {
    /// The engine is at its configured capacity for pending conditionals.
    #[error("conditional engine at capacity")]
    CapacityExhausted,
    /// A TWAP order requested zero slices.
    #[error("twap slice count must be strictly positive")]
    ZeroSlices,
    /// A quantity was zero or negative.
    #[error("quantity must be strictly positive")]
    NonPositiveQuantity,
    /// A trailing-stop offset was zero or negative.
    #[error("trailing offset must be strictly positive")]
    NonPositiveOffset,
    /// An encoded conditional order could not be decoded.
    #[error("malformed encoded conditional order")]
    Malformed,
    /// An arithmetic operation overflowed.
    #[error("arithmetic overflow")]
    Overflow,
}

impl From<types::ArithError> for ConditionalError {
    fn from(_: types::ArithError) -> Self {
        ConditionalError::Overflow
    }
}
