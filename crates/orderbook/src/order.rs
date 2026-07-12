//! Public order-submission and match-result types, plus the internal node
//! stored in the slab.

use serde::{Deserialize, Serialize};
use types::{AccountId, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

use crate::slab::NIL;

/// A request to place a new order onto the book.
///
/// `client_id` is a caller-assigned idempotency key: two submissions from the
/// same account with the same `client_id` are treated as duplicates and the
/// first result is replayed for the second (see [`crate::OrderBook::submit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewOrder {
    /// Exchange-assigned unique id for this order.
    pub order_id: OrderId,
    /// Owning account.
    pub account: AccountId,
    /// Buy (`Bid`) or sell (`Ask`).
    pub side: Side,
    /// Execution style (Limit / Market / PostOnly / ReduceOnly).
    pub order_type: OrderType,
    /// Time-in-force policy (Gtc / Ioc / Fok).
    pub tif: TimeInForce,
    /// Limit price. Ignored for `Market` orders.
    pub price: Price,
    /// Requested quantity in base units.
    pub quantity: Quantity,
    /// Caller-assigned idempotency key (unique per account per intent).
    pub client_id: u64,
    /// When true, the order may only reduce the account's existing position.
    pub reduce_only: bool,
}

/// A single maker/taker match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fill {
    /// Resting (maker) order id.
    pub maker_order: OrderId,
    /// Incoming (taker) order id.
    pub taker_order: OrderId,
    /// Account that owned the resting order.
    pub maker_account: AccountId,
    /// Account that submitted the incoming order.
    pub taker_account: AccountId,
    /// Execution price (always the resting maker's price).
    pub price: Price,
    /// Executed quantity.
    pub quantity: Quantity,
    /// Side of the taker (aggressor).
    pub taker_side: Side,
}

/// One planned (not yet applied) maker fill from a dry-run depth scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedFill {
    /// Resting (maker) order id.
    pub maker_order: OrderId,
    /// Account that owns the resting order.
    pub maker_account: AccountId,
    /// Execution price (resting maker's price).
    pub price: Price,
    /// Quantity that would execute against this maker.
    pub quantity: Quantity,
}

/// Deterministic match plan built from executable depth without mutating the book.
///
/// Used by pre-trade risk so market orders are margined from worst executable
/// prices inside the caller's collar, never from an ignored placeholder price.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchPlan {
    /// Planned fills in deterministic match order (best price, then FIFO).
    pub fills: Vec<PlannedFill>,
    /// Total quantity that would fill.
    pub filled_quantity: Quantity,
    /// Worst (least favorable for the taker) price among planned fills.
    pub worst_price: Option<Price>,
    /// Sum of `price.notional(qty)` over planned fills (toward zero).
    pub notional: types::Amount,
    /// Sum of `price.notional_ceil(qty)` — conservative margin base.
    pub notional_ceil: types::Amount,
}

/// The disposition of a submitted order after matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderOutcome {
    /// Did not cross; the whole order now rests on the book.
    Resting {
        /// Quantity resting.
        remaining: Quantity,
    },
    /// Fully executed against the book; nothing rests.
    FullyFilled,
    /// Partially executed; the residual now rests on the book.
    PartiallyFilledResting {
        /// Quantity resting.
        remaining: Quantity,
    },
    /// Partially executed; the residual was cancelled (IOC / Market).
    PartiallyFilledCancelled {
        /// Quantity that executed before the residual was cancelled.
        filled: Quantity,
    },
    /// Rejected without any execution (post-only cross, FOK kill,
    /// reduce-only with no reducible position, or an empty market order).
    Rejected,
}

/// The result of submitting or replacing an order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResult {
    /// Fills produced, in deterministic match order (oldest maker first).
    pub fills: Vec<Fill>,
    /// Final disposition of the incoming order.
    pub outcome: OrderOutcome,
}

impl MatchResult {
    /// A rejection with no fills.
    #[must_use]
    pub(crate) fn rejected() -> Self {
        MatchResult {
            fills: Vec::new(),
            outcome: OrderOutcome::Rejected,
        }
    }

    /// Total executed quantity across all fills.
    #[must_use]
    pub fn filled_quantity(&self) -> Quantity {
        let mut total = Quantity::ZERO;
        for f in &self.fills {
            total = total.saturating_add(f.quantity);
        }
        total
    }
}

/// Self-trade-prevention policy applied when an incoming order would match a
/// resting order owned by the same account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StpPolicy {
    /// Cancel the resting (maker) order and keep matching the taker onward.
    CancelMaker,
    /// Stop the taker at the self-match; any remainder is cancelled/rested per TIF.
    CancelTaker,
    /// Cancel the resting order and stop the taker.
    CancelBoth,
}

/// Static configuration for an [`crate::OrderBook`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookConfig {
    /// Maximum number of simultaneously-resting orders (slab capacity).
    pub capacity: usize,
    /// Self-trade-prevention policy.
    pub stp: StpPolicy,
    /// Number of recent `(account, client_id)` keys retained for idempotency.
    pub dedup_capacity: usize,
    /// Maximum legs in a single basket submission.
    pub max_basket_legs: usize,
}

impl Default for BookConfig {
    fn default() -> Self {
        BookConfig {
            capacity: 1 << 16,
            stp: StpPolicy::CancelMaker,
            dedup_capacity: 1 << 12,
            max_basket_legs: 64,
        }
    }
}

/// A resting order plus its intrusive FIFO links inside a price level.
///
/// `prev`/`next` are slab slot indices ([`NIL`] at the ends). Storing the links
/// in the node itself is what makes cancellation O(1): given a slot we unlink it
/// directly without scanning the level.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Node {
    pub(crate) order_id: OrderId,
    pub(crate) account: AccountId,
    pub(crate) side: Side,
    pub(crate) price: Price,
    /// Remaining (unfilled) quantity.
    pub(crate) remaining: Quantity,
    pub(crate) client_id: u64,
    pub(crate) prev: u32,
    pub(crate) next: u32,
}

impl Node {
    pub(crate) fn new(o: &NewOrder, remaining: Quantity) -> Self {
        Node {
            order_id: o.order_id,
            account: o.account,
            side: o.side,
            price: o.price,
            remaining,
            client_id: o.client_id,
            prev: NIL,
            next: NIL,
        }
    }
}
