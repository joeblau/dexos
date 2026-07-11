//! Conditional / triggered order engine.
//!
//! This engine watches a reference (mark) price and, when a pending trigger's
//! threshold is crossed, emits canonical [`OrderIntent`]s. It never touches the
//! order book directly — the caller applies the emitted intents. Supported
//! kinds: stop-loss, take-profit, trailing-stop, one-cancels-the-other (OCO),
//! and time-weighted average price (TWAP).
//!
//! Evaluation is deterministic: entries are processed in a stable order and a
//! fired entry is removed, so a duplicated price tick never re-emits and an
//! identical price stream always produces an identical intent stream.

use serde::{Deserialize, Serialize};
use types::{AccountId, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

use crate::error::ConditionalError;

/// A canonical, book-agnostic instruction emitted by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderIntent {
    /// Place a new order.
    Place {
        /// Exchange order id to assign.
        order_id: OrderId,
        /// Owning account.
        account: AccountId,
        /// Buy or sell.
        side: Side,
        /// Execution style.
        order_type: OrderType,
        /// Time in force.
        tif: TimeInForce,
        /// Limit price (ignored for market orders).
        price: Price,
        /// Quantity.
        quantity: Quantity,
        /// Idempotency key.
        client_id: u64,
        /// Reduce-only flag.
        reduce_only: bool,
    },
    /// Cancel a resting order by id (used by OCO to cancel a sibling).
    Cancel {
        /// Order to cancel.
        order_id: OrderId,
    },
}

/// A reusable template describing the order to place when a trigger fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceTemplate {
    /// Base order id (TWAP derives per-slice ids from this).
    pub order_id: OrderId,
    /// Owning account.
    pub account: AccountId,
    /// Buy or sell.
    pub side: Side,
    /// Execution style.
    pub order_type: OrderType,
    /// Time in force.
    pub tif: TimeInForce,
    /// Limit price.
    pub price: Price,
    /// Quantity (parent quantity for TWAP).
    pub quantity: Quantity,
    /// Base idempotency key (TWAP derives per-slice keys from this).
    pub client_id: u64,
    /// Reduce-only flag.
    pub reduce_only: bool,
}

impl PlaceTemplate {
    fn into_intent(self, order_id: OrderId, client_id: u64, quantity: Quantity) -> OrderIntent {
        OrderIntent::Place {
            order_id,
            account: self.account,
            side: self.side,
            order_type: self.order_type,
            tif: self.tif,
            price: self.price,
            quantity,
            client_id,
            reduce_only: self.reduce_only,
        }
    }
}

/// A static price trigger. Boundary values (equal price) fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerKind {
    /// Fire when the mark price is at or above `threshold`.
    Above(Price),
    /// Fire when the mark price is at or below `threshold`.
    Below(Price),
}

impl TriggerKind {
    /// Stop-loss for a protective order on `side`: a protective sell (long
    /// position) fires on a drop; a protective buy (short position) fires on a
    /// rise.
    #[must_use]
    pub fn stop_loss(side: Side, trigger: Price) -> Self {
        match side {
            Side::Ask => TriggerKind::Below(trigger),
            Side::Bid => TriggerKind::Above(trigger),
        }
    }

    /// Take-profit for an order on `side`: a profit-taking sell fires on a rise;
    /// a profit-taking buy fires on a drop.
    #[must_use]
    pub fn take_profit(side: Side, trigger: Price) -> Self {
        match side {
            Side::Ask => TriggerKind::Above(trigger),
            Side::Bid => TriggerKind::Below(trigger),
        }
    }

    /// Whether `price` crosses the threshold.
    #[inline]
    #[must_use]
    pub fn fires(self, price: Price) -> bool {
        match self {
            TriggerKind::Above(t) => price.raw() >= t.raw(),
            TriggerKind::Below(t) => price.raw() <= t.raw(),
        }
    }
}

/// Direction of a trailing stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrailDirection {
    /// Protective sell: tracks the highest price seen; fires when price falls
    /// `offset` below that high. The threshold only ratchets upward.
    SellStop,
    /// Protective buy: tracks the lowest price seen; fires when price rises
    /// `offset` above that low. The threshold only ratchets downward.
    BuyStop,
}

/// A trailing-stop's live state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trailing {
    direction: TrailDirection,
    offset: i64,
    extremum: i64,
    threshold: i64,
}

impl Trailing {
    fn new(direction: TrailDirection, offset: Price, reference: Price) -> Self {
        let mut t = Trailing {
            direction,
            offset: offset.raw(),
            extremum: reference.raw(),
            threshold: 0,
        };
        t.recompute();
        t
    }

    fn recompute(&mut self) {
        self.threshold = match self.direction {
            TrailDirection::SellStop => self.extremum.saturating_sub(self.offset),
            TrailDirection::BuyStop => self.extremum.saturating_add(self.offset),
        };
    }

    /// Advance the trailing extremum/threshold with a new price. The threshold
    /// is monotonic (never moves backward).
    fn update(&mut self, price: Price) {
        match self.direction {
            TrailDirection::SellStop => {
                if price.raw() > self.extremum {
                    self.extremum = price.raw();
                    self.recompute();
                }
            }
            TrailDirection::BuyStop => {
                if price.raw() < self.extremum {
                    self.extremum = price.raw();
                    self.recompute();
                }
            }
        }
    }

    fn fires(&self, price: Price) -> bool {
        match self.direction {
            TrailDirection::SellStop => price.raw() <= self.threshold,
            TrailDirection::BuyStop => price.raw() >= self.threshold,
        }
    }

    /// The current trigger threshold (for reference / testing).
    #[must_use]
    pub fn threshold(&self) -> Price {
        Price::from_raw(self.threshold)
    }
}

/// One leg of an OCO group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcoLeg {
    /// The trigger that activates this leg.
    pub trigger: TriggerKind,
    /// The order to place when this leg activates (if any).
    pub place: Option<PlaceTemplate>,
    /// The resting sibling order to cancel when *this* leg activates (if any).
    pub cancel_order_id: Option<OrderId>,
}

/// TWAP working state: emit one child slice per evaluation tick until the parent
/// quantity has been fully sliced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct TwapState {
    place: PlaceTemplate,
    total_slices: u32,
    emitted: u32,
    parent: i64,
}

/// A single pending conditional.
#[derive(Debug, Clone, Copy)]
enum EntryKind {
    Simple {
        trigger: TriggerKind,
        place: PlaceTemplate,
    },
    Trailing {
        trail: Trailing,
        place: PlaceTemplate,
    },
    Oco {
        leg_a: OcoLeg,
        leg_b: OcoLeg,
    },
    Twap(TwapState),
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    kind: EntryKind,
}

/// Deterministic per-slice quantity for a TWAP: the first `parent % slices`
/// slices carry one extra base unit so the slices sum exactly to the parent.
#[must_use]
fn twap_slice_qty(parent: i64, slices: u32, index: u32) -> i64 {
    let n = i64::from(slices);
    let base = parent / n;
    let rem = parent % n;
    if i64::from(index) < rem {
        base + 1
    } else {
        base
    }
}

impl Entry {
    /// Evaluate against `price`, appending intents; return `true` to keep the
    /// entry pending, `false` to remove it (it fired / completed).
    fn evaluate(&mut self, price: Price, out: &mut Vec<OrderIntent>) -> bool {
        match &mut self.kind {
            EntryKind::Simple { trigger, place } => {
                if trigger.fires(price) {
                    out.push(place.into_intent(place.order_id, place.client_id, place.quantity));
                    false
                } else {
                    true
                }
            }
            EntryKind::Trailing { trail, place } => {
                trail.update(price);
                if trail.fires(price) {
                    out.push(place.into_intent(place.order_id, place.client_id, place.quantity));
                    false
                } else {
                    true
                }
            }
            EntryKind::Oco { leg_a, leg_b } => {
                // Leg A has priority if both cross on the same tick; the group is
                // removed either way, so the sibling is cancelled exactly once.
                if leg_a.trigger.fires(price) {
                    Self::emit_oco(leg_a, out);
                    false
                } else if leg_b.trigger.fires(price) {
                    Self::emit_oco(leg_b, out);
                    false
                } else {
                    true
                }
            }
            EntryKind::Twap(state) => {
                let idx = state.emitted;
                let qty = twap_slice_qty(state.parent, state.total_slices, idx);
                let order_id =
                    OrderId::new(state.place.order_id.get().wrapping_add(u64::from(idx)));
                let client_id = state.place.client_id.wrapping_add(u64::from(idx));
                out.push(
                    state
                        .place
                        .into_intent(order_id, client_id, Quantity::from_raw(qty)),
                );
                state.emitted += 1;
                state.emitted < state.total_slices
            }
        }
    }

    /// Emit the fired leg's placement (if any) and cancel its sibling resting
    /// order (if any). Called exactly once because the OCO entry is then removed.
    fn emit_oco(fired: &OcoLeg, out: &mut Vec<OrderIntent>) {
        if let Some(place) = fired.place {
            out.push(place.into_intent(place.order_id, place.client_id, place.quantity));
        }
        if let Some(order_id) = fired.cancel_order_id {
            out.push(OrderIntent::Cancel { order_id });
        }
    }
}

/// Configuration for a [`ConditionalEngine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionalConfig {
    /// Maximum number of simultaneously-pending conditionals.
    pub capacity: usize,
}

impl Default for ConditionalConfig {
    fn default() -> Self {
        ConditionalConfig { capacity: 1 << 14 }
    }
}

/// Identifier for a pending conditional.
pub type ConditionalId = u64;

/// The conditional / triggered order engine.
pub struct ConditionalEngine {
    config: ConditionalConfig,
    entries: Vec<Entry>,
    next_id: u64,
}

impl ConditionalEngine {
    /// Create an engine with the given configuration.
    #[must_use]
    pub fn new(config: ConditionalConfig) -> Self {
        ConditionalEngine {
            entries: Vec::with_capacity(config.capacity.min(1 << 12)),
            next_id: 0,
            config,
        }
    }

    /// Number of pending conditionals.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.entries.len()
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn push(&mut self, kind: EntryKind) -> Result<ConditionalId, ConditionalError> {
        if self.entries.len() >= self.config.capacity {
            return Err(ConditionalError::CapacityExhausted);
        }
        let id = self.alloc_id();
        self.entries.push(Entry { kind });
        Ok(id)
    }

    /// Register a stop-loss / take-profit style static trigger.
    pub fn add_stop(
        &mut self,
        place: PlaceTemplate,
        trigger: TriggerKind,
    ) -> Result<ConditionalId, ConditionalError> {
        if place.quantity.raw() <= 0 {
            return Err(ConditionalError::NonPositiveQuantity);
        }
        self.push(EntryKind::Simple { trigger, place })
    }

    /// Register a trailing stop tracking from `reference` with the given
    /// `offset`.
    pub fn add_trailing(
        &mut self,
        place: PlaceTemplate,
        direction: TrailDirection,
        offset: Price,
        reference: Price,
    ) -> Result<ConditionalId, ConditionalError> {
        if place.quantity.raw() <= 0 {
            return Err(ConditionalError::NonPositiveQuantity);
        }
        if offset.raw() <= 0 {
            return Err(ConditionalError::NonPositiveOffset);
        }
        let trail = Trailing::new(direction, offset, reference);
        self.push(EntryKind::Trailing { trail, place })
    }

    /// Register a one-cancels-the-other group. Whichever leg triggers first
    /// emits its placement and cancels the sibling exactly once.
    pub fn add_oco(
        &mut self,
        leg_a: OcoLeg,
        leg_b: OcoLeg,
    ) -> Result<ConditionalId, ConditionalError> {
        self.push(EntryKind::Oco { leg_a, leg_b })
    }

    /// Register a TWAP order that emits `slices` child orders (one per tick)
    /// whose quantities sum exactly to `place.quantity`.
    pub fn add_twap(
        &mut self,
        place: PlaceTemplate,
        slices: u32,
    ) -> Result<ConditionalId, ConditionalError> {
        if slices == 0 {
            return Err(ConditionalError::ZeroSlices);
        }
        if place.quantity.raw() <= 0 {
            return Err(ConditionalError::NonPositiveQuantity);
        }
        self.push(EntryKind::Twap(TwapState {
            place,
            total_slices: slices,
            emitted: 0,
            parent: place.quantity.raw(),
        }))
    }

    /// Evaluate all pending conditionals against a new mark `price`, appending
    /// emitted intents to `out`. The scan itself allocates nothing (entries are
    /// compacted in place); only `out.push` may grow the caller's buffer.
    pub fn evaluate_into(&mut self, price: Price, out: &mut Vec<OrderIntent>) {
        let mut write = 0usize;
        let mut read = 0usize;
        let len = self.entries.len();
        while read < len {
            let mut entry = self.entries[read];
            let keep = entry.evaluate(price, out);
            if keep {
                self.entries[write] = entry;
                write += 1;
            }
            read += 1;
        }
        self.entries.truncate(write);
    }

    /// Evaluate against a new mark `price`, returning the emitted intents.
    #[must_use]
    pub fn on_mark_price(&mut self, price: Price) -> Vec<OrderIntent> {
        let mut out = Vec::new();
        self.evaluate_into(price, &mut out);
        out
    }
}

/// A decoded conditional order (a single static trigger + placement). Used by
/// the wire decoder to consume untrusted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedConditional {
    /// The placement to emit on fire.
    pub place: PlaceTemplate,
    /// The firing condition.
    pub trigger: TriggerKind,
}

/// Fixed on-wire length of an encoded conditional order.
pub const ENCODED_CONDITIONAL_LEN: usize = 37;

fn read_i64(bytes: &[u8], at: usize) -> Result<i64, ConditionalError> {
    let end = at.checked_add(8).ok_or(ConditionalError::Malformed)?;
    let slice = bytes.get(at..end).ok_or(ConditionalError::Malformed)?;
    let arr: [u8; 8] = slice.try_into().map_err(|_| ConditionalError::Malformed)?;
    Ok(i64::from_le_bytes(arr))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, ConditionalError> {
    let end = at.checked_add(8).ok_or(ConditionalError::Malformed)?;
    let slice = bytes.get(at..end).ok_or(ConditionalError::Malformed)?;
    let arr: [u8; 8] = slice.try_into().map_err(|_| ConditionalError::Malformed)?;
    Ok(u64::from_le_bytes(arr))
}

/// Decode a conditional order from an untrusted byte buffer.
///
/// The layout is: `[side:1][order_type:1][tif:1][dir:1][price:8][quantity:8]
/// [threshold:8][client_id:8][reduce_only:1]` (little-endian). Every malformed
/// input yields a typed [`ConditionalError`]; this function never panics and
/// never truncates.
pub fn decode_conditional(bytes: &[u8]) -> Result<DecodedConditional, ConditionalError> {
    if bytes.len() < ENCODED_CONDITIONAL_LEN {
        return Err(ConditionalError::Malformed);
    }
    let side = match bytes[0] {
        0 => Side::Bid,
        1 => Side::Ask,
        _ => return Err(ConditionalError::Malformed),
    };
    let order_type = match bytes[1] {
        0 => OrderType::Limit,
        1 => OrderType::Market,
        2 => OrderType::PostOnly,
        3 => OrderType::ReduceOnly,
        _ => return Err(ConditionalError::Malformed),
    };
    let tif = match bytes[2] {
        0 => TimeInForce::Gtc,
        1 => TimeInForce::Ioc,
        2 => TimeInForce::Fok,
        _ => return Err(ConditionalError::Malformed),
    };
    let price = Price::from_raw(read_i64(bytes, 4)?);
    let quantity_raw = read_i64(bytes, 12)?;
    if quantity_raw <= 0 {
        return Err(ConditionalError::NonPositiveQuantity);
    }
    let threshold = Price::from_raw(read_i64(bytes, 20)?);
    let client_id = read_u64(bytes, 28)?;
    let reduce_only = match bytes[36] {
        0 => false,
        1 => true,
        _ => return Err(ConditionalError::Malformed),
    };
    let trigger = match bytes[3] {
        0 => TriggerKind::Above(threshold),
        1 => TriggerKind::Below(threshold),
        _ => return Err(ConditionalError::Malformed),
    };
    let place = PlaceTemplate {
        order_id: OrderId::new(client_id),
        account: AccountId::new(0),
        side,
        order_type,
        tif,
        price,
        quantity: Quantity::from_raw(quantity_raw),
        client_id,
        reduce_only,
    };
    Ok(DecodedConditional { place, trigger })
}

#[cfg(test)]
mod tests {
    include!("conditional_tests.rs");
}
