//! Conditional / triggered order engine.
//!
//! This engine watches a reference (mark) price and, when a pending trigger's
//! threshold is crossed, emits canonical [`OrderIntent`]s under an authenticated
//! owner. It never touches the order book directly — the caller applies the
//! emitted intents and **must** acknowledge the outcome via
//! [`ConditionalEngine::ack`]. Supported kinds: stop-loss, take-profit,
//! trailing-stop, one-cancels-the-other (OCO), and time-weighted average price
//! (TWAP).
//!
//! # Durability through execution
//!
//! A fired conditional transitions `Pending -> PendingExecution` and is retained
//! until the caller acknowledges `Executed`, `Rejected`, or `Retryable`. A
//! transient execution failure therefore leaves an observable retryable record
//! rather than silently dropping protection.
//!
//! # Atomic OCO
//!
//! OCO emits a single [`OrderIntent::Atomic`] batch. The engine journals the
//! batch against the conditional id so place/cancel is all-or-none under fault
//! injection at the execution boundary.
//!
//! # Evaluation complexity
//!
//! Pending static triggers live in ordered above/below indexes. A mark update
//! that fires no triggers is O(log C); firing K triggers is O(log C + K).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use types::{AccountId, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

use crate::error::ConditionalError;

/// A canonical, book-agnostic instruction emitted by the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// An atomic multi-leg batch (OCO place+cancel). All-or-none at the
    /// execution boundary: the whole batch succeeds or the conditional stays
    /// retryable / rejected.
    Atomic {
        /// Legs, applied in order under one engine transaction.
        legs: Vec<OrderIntent>,
    },
}

/// Downstream execution outcome for a fired conditional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionAck {
    /// All intents applied successfully.
    Executed,
    /// Permanent rejection (invalid order, capacity, etc.).
    Rejected,
    /// Transient failure; the conditional remains observable and may be retried.
    Retryable,
}

/// Lifecycle of a conditional order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionalStatus {
    /// Waiting for its trigger (or next TWAP slice).
    Pending,
    /// Fired; intents emitted; awaiting execution acknowledgement.
    PendingExecution,
    /// Downstream execution succeeded; terminal.
    Executed,
    /// Downstream permanently rejected; terminal.
    Rejected,
    /// Downstream transient failure; still owned and retryable.
    Retryable,
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
    /// Stop-loss for a protective order on `side`.
    #[must_use]
    pub fn stop_loss(side: Side, trigger: Price) -> Self {
        match side {
            Side::Ask => TriggerKind::Below(trigger),
            Side::Bid => TriggerKind::Above(trigger),
        }
    }

    /// Take-profit for an order on `side`.
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
    /// Protective sell: tracks the highest price seen.
    SellStop,
    /// Protective buy: tracks the lowest price seen.
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

/// TWAP working state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct TwapState {
    place: PlaceTemplate,
    total_slices: u32,
    emitted: u32,
    parent: i64,
}

/// Kind-specific payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// One durable conditional record.
#[derive(Debug, Clone)]
struct Entry {
    owner: AccountId,
    status: ConditionalStatus,
    kind: EntryKind,
    /// Last emitted intent batch (for retry observability).
    pending_batch: Option<OrderIntent>,
}

/// Deterministic per-slice quantity for a TWAP: the first `parent % slices`
/// slices carry one extra base unit so the slices sum exactly to the parent.
///
/// # Errors
/// [`ConditionalError::NonPositiveQuantity`] if any slice would be zero.
fn twap_slice_qty(parent: i64, slices: u32, index: u32) -> Result<i64, ConditionalError> {
    if slices == 0 || parent <= 0 {
        return Err(ConditionalError::NonPositiveQuantity);
    }
    let n = i64::from(slices);
    if parent < n {
        // At least one slice would be zero.
        return Err(ConditionalError::NonPositiveQuantity);
    }
    let base = parent / n;
    let rem = parent % n;
    let qty = if i64::from(index) < rem {
        base + 1
    } else {
        base
    };
    if qty <= 0 {
        return Err(ConditionalError::NonPositiveQuantity);
    }
    Ok(qty)
}

/// Validate that TWAP children are positive and sum exactly to parent.
fn validate_twap(parent: i64, slices: u32) -> Result<(), ConditionalError> {
    let mut sum = 0i64;
    for i in 0..slices {
        let q = twap_slice_qty(parent, slices, i)?;
        sum = sum.checked_add(q).ok_or(ConditionalError::Overflow)?;
    }
    if sum != parent {
        return Err(ConditionalError::Overflow);
    }
    Ok(())
}

/// Checked child order id: base + index without wrap.
fn checked_child_id(base: u64, index: u32) -> Result<u64, ConditionalError> {
    base.checked_add(u64::from(index))
        .ok_or(ConditionalError::Overflow)
}

impl Entry {
    /// Evaluate against `price`. Returns `Some(intent)` when the entry fires
    /// (or emits a TWAP slice) and transitions to `PendingExecution`.
    fn try_fire(&mut self, price: Price) -> Option<OrderIntent> {
        if !matches!(
            self.status,
            ConditionalStatus::Pending | ConditionalStatus::Retryable
        ) {
            return None;
        }
        let intent = match &mut self.kind {
            EntryKind::Simple { trigger, place } => {
                if trigger.fires(price) {
                    Some(place.into_intent(place.order_id, place.client_id, place.quantity))
                } else {
                    None
                }
            }
            EntryKind::Trailing { trail, place } => {
                trail.update(price);
                if trail.fires(price) {
                    Some(place.into_intent(place.order_id, place.client_id, place.quantity))
                } else {
                    None
                }
            }
            EntryKind::Oco { leg_a, leg_b } => {
                // Leg A has priority if both cross on the same tick.
                if leg_a.trigger.fires(price) {
                    Some(Self::oco_atomic(leg_a))
                } else if leg_b.trigger.fires(price) {
                    Some(Self::oco_atomic(leg_b))
                } else {
                    None
                }
            }
            EntryKind::Twap(state) => {
                let idx = state.emitted;
                let qty = match twap_slice_qty(state.parent, state.total_slices, idx) {
                    Ok(q) => q,
                    Err(_) => return None,
                };
                let order_id = match checked_child_id(state.place.order_id.get(), idx) {
                    Ok(id) => OrderId::new(id),
                    Err(_) => return None,
                };
                let client_id = match checked_child_id(state.place.client_id, idx) {
                    Ok(id) => id,
                    Err(_) => return None,
                };
                Some(
                    state
                        .place
                        .into_intent(order_id, client_id, Quantity::from_raw(qty)),
                )
            }
        }?;
        self.status = ConditionalStatus::PendingExecution;
        self.pending_batch = Some(intent.clone());
        Some(intent)
    }

    fn oco_atomic(fired: &OcoLeg) -> OrderIntent {
        let mut legs = Vec::with_capacity(2);
        if let Some(place) = fired.place {
            legs.push(place.into_intent(place.order_id, place.client_id, place.quantity));
        }
        if let Some(order_id) = fired.cancel_order_id {
            legs.push(OrderIntent::Cancel { order_id });
        }
        OrderIntent::Atomic { legs }
    }

    fn owner(&self) -> AccountId {
        self.owner
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
    entries: HashMap<ConditionalId, Entry>,
    /// Ordered index of Above-trigger thresholds -> conditional ids.
    above: BTreeMap<i64, BTreeSet<ConditionalId>>,
    /// Ordered index of Below-trigger thresholds -> conditional ids.
    below: BTreeMap<i64, BTreeSet<ConditionalId>>,
    /// Trailing / TWAP / multi-leg entries that require a full scan (bounded by
    /// non-static kinds only).
    scan: BTreeSet<ConditionalId>,
    /// Deterministic TWAP timer queue: (emitted_count, id) ready each tick.
    twap_ready: BTreeSet<(u32, ConditionalId)>,
    next_id: u64,
}

impl ConditionalEngine {
    /// Create an engine with the given configuration.
    #[must_use]
    pub fn new(config: ConditionalConfig) -> Self {
        ConditionalEngine {
            entries: HashMap::new(),
            above: BTreeMap::new(),
            below: BTreeMap::new(),
            scan: BTreeSet::new(),
            twap_ready: BTreeSet::new(),
            next_id: 0,
            config,
        }
    }

    /// Number of non-terminal conditionals.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.entries
            .values()
            .filter(|e| {
                !matches!(
                    e.status,
                    ConditionalStatus::Executed | ConditionalStatus::Rejected
                )
            })
            .count()
    }

    /// Status of a conditional, if known.
    #[must_use]
    pub fn status(&self, id: ConditionalId) -> Option<ConditionalStatus> {
        self.entries.get(&id).map(|e| e.status)
    }

    /// Owner of a conditional, if known.
    #[must_use]
    pub fn owner(&self, id: ConditionalId) -> Option<AccountId> {
        self.entries.get(&id).map(Entry::owner)
    }

    /// The last emitted intent batch awaiting ack (for retry).
    #[must_use]
    pub fn pending_batch(&self, id: ConditionalId) -> Option<&OrderIntent> {
        self.entries.get(&id).and_then(|e| e.pending_batch.as_ref())
    }

    fn alloc_id(&mut self) -> Result<u64, ConditionalError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ConditionalError::Overflow)?;
        Ok(id)
    }

    fn insert(
        &mut self,
        kind: EntryKind,
        owner: AccountId,
    ) -> Result<ConditionalId, ConditionalError> {
        if self.entries.len() >= self.config.capacity {
            return Err(ConditionalError::CapacityExhausted);
        }
        let id = self.alloc_id()?;
        match &kind {
            EntryKind::Simple { trigger, .. } => match trigger {
                TriggerKind::Above(t) => {
                    self.above.entry(t.raw()).or_default().insert(id);
                }
                TriggerKind::Below(t) => {
                    self.below.entry(t.raw()).or_default().insert(id);
                }
            },
            EntryKind::Trailing { .. } | EntryKind::Oco { .. } => {
                self.scan.insert(id);
            }
            EntryKind::Twap(_) => {
                self.twap_ready.insert((0, id));
            }
        }
        self.entries.insert(
            id,
            Entry {
                owner,
                status: ConditionalStatus::Pending,
                kind,
                pending_batch: None,
            },
        );
        Ok(id)
    }

    fn unindex(&mut self, id: ConditionalId, kind: &EntryKind) {
        match kind {
            EntryKind::Simple { trigger, .. } => match trigger {
                TriggerKind::Above(t) => {
                    if let Some(set) = self.above.get_mut(&t.raw()) {
                        set.remove(&id);
                        if set.is_empty() {
                            self.above.remove(&t.raw());
                        }
                    }
                }
                TriggerKind::Below(t) => {
                    if let Some(set) = self.below.get_mut(&t.raw()) {
                        set.remove(&id);
                        if set.is_empty() {
                            self.below.remove(&t.raw());
                        }
                    }
                }
            },
            EntryKind::Trailing { .. } | EntryKind::Oco { .. } => {
                self.scan.remove(&id);
            }
            EntryKind::Twap(state) => {
                self.twap_ready.remove(&(state.emitted, id));
            }
        }
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
        let owner = place.account;
        self.insert(EntryKind::Simple { trigger, place }, owner)
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
        let owner = place.account;
        let trail = Trailing::new(direction, offset, reference);
        self.insert(EntryKind::Trailing { trail, place }, owner)
    }

    /// Register a one-cancels-the-other group. Legs must share the same owner.
    pub fn add_oco(
        &mut self,
        leg_a: OcoLeg,
        leg_b: OcoLeg,
    ) -> Result<ConditionalId, ConditionalError> {
        let owner = match (leg_a.place, leg_b.place) {
            (Some(a), Some(b)) if a.account != b.account => {
                return Err(ConditionalError::OwnerMismatch);
            }
            (Some(a), _) => a.account,
            (_, Some(b)) => b.account,
            (None, None) => return Err(ConditionalError::Malformed),
        };
        if let Some(p) = leg_a.place {
            if p.quantity.raw() <= 0 {
                return Err(ConditionalError::NonPositiveQuantity);
            }
        }
        if let Some(p) = leg_b.place {
            if p.quantity.raw() <= 0 {
                return Err(ConditionalError::NonPositiveQuantity);
            }
        }
        self.insert(EntryKind::Oco { leg_a, leg_b }, owner)
    }

    /// Register a TWAP order that emits `slices` child orders whose quantities
    /// are strictly positive and sum exactly to `place.quantity`. Child ids are
    /// checked against wrap/collision with the parent base.
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
        validate_twap(place.quantity.raw(), slices)?;
        // Ensure the last child id does not wrap.
        let _ = checked_child_id(place.order_id.get(), slices.saturating_sub(1))?;
        let _ = checked_child_id(place.client_id, slices.saturating_sub(1))?;
        let owner = place.account;
        self.insert(
            EntryKind::Twap(TwapState {
                place,
                total_slices: slices,
                emitted: 0,
                parent: place.quantity.raw(),
            }),
            owner,
        )
    }

    /// Acknowledge execution of a fired conditional. Only the authenticated
    /// owner may ack; a mismatched owner is rejected without mutating state.
    pub fn ack(
        &mut self,
        id: ConditionalId,
        owner: AccountId,
        outcome: ExecutionAck,
    ) -> Result<(), ConditionalError> {
        let (entry_owner, status, kind_snapshot) = {
            let entry = self.entries.get(&id).ok_or(ConditionalError::UnknownId)?;
            (entry.owner, entry.status, entry.kind)
        };
        if entry_owner != owner {
            return Err(ConditionalError::OwnerMismatch);
        }
        if !matches!(
            status,
            ConditionalStatus::PendingExecution | ConditionalStatus::Retryable
        ) {
            return Err(ConditionalError::InvalidStatus);
        }
        match outcome {
            ExecutionAck::Executed => {
                let mut requeue_twap: Option<u32> = None;
                let mut done = true;
                if let Some(entry) = self.entries.get_mut(&id) {
                    entry.pending_batch = None;
                    if let EntryKind::Twap(state) = &mut entry.kind {
                        state.emitted = state.emitted.saturating_add(1);
                        if state.emitted < state.total_slices {
                            done = false;
                            requeue_twap = Some(state.emitted);
                            entry.status = ConditionalStatus::Pending;
                        }
                    }
                }
                if done {
                    self.unindex(id, &kind_snapshot);
                    self.entries.remove(&id);
                } else if let Some(emitted) = requeue_twap {
                    self.twap_ready.insert((emitted, id));
                }
            }
            ExecutionAck::Rejected => {
                self.unindex(id, &kind_snapshot);
                self.entries.remove(&id);
            }
            ExecutionAck::Retryable => {
                if let Some(entry) = self.entries.get_mut(&id) {
                    entry.status = ConditionalStatus::Retryable;
                }
            }
        }
        Ok(())
    }

    /// Re-emit the pending batch for a retryable conditional (same owner).
    pub fn retry(
        &mut self,
        id: ConditionalId,
        owner: AccountId,
    ) -> Result<OrderIntent, ConditionalError> {
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(ConditionalError::UnknownId)?;
        if entry.owner != owner {
            return Err(ConditionalError::OwnerMismatch);
        }
        if entry.status != ConditionalStatus::Retryable {
            return Err(ConditionalError::InvalidStatus);
        }
        let batch = entry
            .pending_batch
            .clone()
            .ok_or(ConditionalError::InvalidStatus)?;
        entry.status = ConditionalStatus::PendingExecution;
        Ok(batch)
    }

    /// Evaluate pending conditionals against a new mark `price`, appending
    /// emitted intents. Zero-fire evaluation is sublinear via ordered indexes.
    pub fn evaluate_into(&mut self, price: Price, out: &mut Vec<(ConditionalId, OrderIntent)>) {
        let px = price.raw();

        // Above: all thresholds <= px may fire.
        let mut above_fire: Vec<ConditionalId> = Vec::new();
        for (_thresh, set) in self.above.range(..=px) {
            above_fire.extend(set.iter().copied());
        }
        // Below: all thresholds >= px may fire.
        let mut below_fire: Vec<ConditionalId> = Vec::new();
        for (_thresh, set) in self.below.range(px..) {
            below_fire.extend(set.iter().copied());
        }

        let mut candidates: BTreeSet<ConditionalId> = BTreeSet::new();
        candidates.extend(above_fire);
        candidates.extend(below_fire);
        candidates.extend(self.scan.iter().copied());
        // TWAP: every registered TWAP emits one slice per tick while pending.
        for &(_emitted, id) in &self.twap_ready {
            candidates.insert(id);
        }

        let mut fired: Vec<(ConditionalId, OrderIntent, EntryKind)> = Vec::new();
        for id in candidates {
            let Some(entry) = self.entries.get_mut(&id) else {
                continue;
            };
            if let Some(intent) = entry.try_fire(price) {
                fired.push((id, intent, entry.kind));
            }
        }
        for (id, intent, kind) in fired {
            // Remove from live trigger indexes so we do not re-fire while
            // PendingExecution; the durable entry remains for ack/retry.
            match kind {
                EntryKind::Simple { trigger, .. } => match trigger {
                    TriggerKind::Above(t) => {
                        if let Some(set) = self.above.get_mut(&t.raw()) {
                            set.remove(&id);
                            if set.is_empty() {
                                self.above.remove(&t.raw());
                            }
                        }
                    }
                    TriggerKind::Below(t) => {
                        if let Some(set) = self.below.get_mut(&t.raw()) {
                            set.remove(&id);
                            if set.is_empty() {
                                self.below.remove(&t.raw());
                            }
                        }
                    }
                },
                EntryKind::Trailing { .. } | EntryKind::Oco { .. } => {
                    self.scan.remove(&id);
                }
                EntryKind::Twap(state) => {
                    self.twap_ready.remove(&(state.emitted, id));
                }
            }
            out.push((id, intent));
        }
    }

    /// Evaluate against a new mark `price`, returning `(id, intent)` pairs.
    #[must_use]
    pub fn on_mark_price(&mut self, price: Price) -> Vec<(ConditionalId, OrderIntent)> {
        let mut out = Vec::new();
        self.evaluate_into(price, &mut out);
        out
    }
}

/// A decoded conditional order (a single static trigger + placement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedConditional {
    /// The placement to emit on fire.
    pub place: PlaceTemplate,
    /// The firing condition.
    pub trigger: TriggerKind,
}

/// Fixed on-wire length of an encoded conditional order.
/// Layout: `[account:4][side:1][order_type:1][tif:1][dir:1][price:8][quantity:8]
/// [threshold:8][client_id:8][reduce_only:1]` = 41 bytes.
pub const ENCODED_CONDITIONAL_LEN: usize = 41;

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

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, ConditionalError> {
    let end = at.checked_add(4).ok_or(ConditionalError::Malformed)?;
    let slice = bytes.get(at..end).ok_or(ConditionalError::Malformed)?;
    let arr: [u8; 4] = slice.try_into().map_err(|_| ConditionalError::Malformed)?;
    Ok(u32::from_le_bytes(arr))
}

/// Decode a conditional order from an untrusted byte buffer.
///
/// Ownership is taken **only** from the encoded `account` field — never
/// defaulted or redirected. Every malformed input yields a typed
/// [`ConditionalError`]; this function never panics and never truncates.
pub fn decode_conditional(bytes: &[u8]) -> Result<DecodedConditional, ConditionalError> {
    if bytes.len() < ENCODED_CONDITIONAL_LEN {
        return Err(ConditionalError::Malformed);
    }
    let account = AccountId::new(read_u32(bytes, 0)?);
    let side = match bytes[4] {
        0 => Side::Bid,
        1 => Side::Ask,
        _ => return Err(ConditionalError::Malformed),
    };
    let order_type = match bytes[5] {
        0 => OrderType::Limit,
        1 => OrderType::Market,
        2 => OrderType::PostOnly,
        3 => OrderType::ReduceOnly,
        _ => return Err(ConditionalError::Malformed),
    };
    let tif = match bytes[6] {
        0 => TimeInForce::Gtc,
        1 => TimeInForce::Ioc,
        2 => TimeInForce::Fok,
        _ => return Err(ConditionalError::Malformed),
    };
    let price = Price::from_raw(read_i64(bytes, 8)?);
    let quantity_raw = read_i64(bytes, 16)?;
    if quantity_raw <= 0 {
        return Err(ConditionalError::NonPositiveQuantity);
    }
    let threshold = Price::from_raw(read_i64(bytes, 24)?);
    let client_id = read_u64(bytes, 32)?;
    let reduce_only = match bytes[40] {
        0 => false,
        1 => true,
        _ => return Err(ConditionalError::Malformed),
    };
    let trigger = match bytes[7] {
        0 => TriggerKind::Above(threshold),
        1 => TriggerKind::Below(threshold),
        _ => return Err(ConditionalError::Malformed),
    };
    let place = PlaceTemplate {
        order_id: OrderId::new(client_id),
        account,
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
