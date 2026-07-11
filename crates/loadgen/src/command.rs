//! Generated virtual-user commands and the per-session state that emits them.
//!
//! Each session keeps a strictly monotonic nonce and a private order-id space, so
//! nonces never regress and every logical order gets a unique idempotency key. A
//! command carries a stable content hash used both for the reproduction fingerprint
//! and for the dedup key that collapses duplicate transmissions back to one logical
//! order.

use serde::{Deserialize, Serialize};
use types::{MarketId, OrderId, OrderType, Price, Quantity, Side};

use crate::config::{LoadScenario, OrderMix};
use crate::rng::Lcg;
use crate::util::{fnv1a_64, fold_u64};

/// The kind of action a generated command performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandKind {
    /// Create a new resting or taking order.
    NewOrder,
    /// Cancel a previously created order.
    Cancel,
    /// Cancel-and-replace a previously created order.
    Replace,
}

/// A single command a virtual user submits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedCommand {
    /// Owning session id.
    pub session: u32,
    /// Strictly monotonic per-session nonce.
    pub nonce: u64,
    /// Globally-unique-per-logical-order idempotency key.
    pub idempotency_key: u128,
    /// Target market.
    pub market: MarketId,
    /// Action kind.
    pub kind: CommandKind,
    /// Order side.
    pub side: Side,
    /// Order type (meaningful for `NewOrder`/`Replace`).
    pub order_type: OrderType,
    /// Limit price.
    pub price: Price,
    /// Order quantity.
    pub quantity: Quantity,
    /// Referenced order for `Cancel`/`Replace`, else `None`.
    pub target_order: Option<OrderId>,
}

impl GeneratedCommand {
    /// Stable content hash over every field, independent of process address space.
    #[must_use]
    pub fn content_hash(&self) -> u64 {
        let mut h = fnv1a_64(b"dexos.loadgen.command.v1");
        h = fold_u64(h, u64::from(self.session));
        h = fold_u64(h, self.nonce);
        // u128 idempotency key folds as two words.
        h = fold_u64(h, u64::try_from(self.idempotency_key >> 64).unwrap_or(0));
        h = fold_u64(
            h,
            u64::try_from(self.idempotency_key & u128::from(u64::MAX)).unwrap_or(0),
        );
        h = fold_u64(h, u64::from(self.market.get()));
        h = fold_u64(h, kind_code(self.kind));
        h = fold_u64(h, side_code(self.side));
        h = fold_u64(h, order_type_code(self.order_type));
        h = fold_u64(h, u64::from_le_bytes(self.price.raw().to_le_bytes()));
        h = fold_u64(h, u64::from_le_bytes(self.quantity.raw().to_le_bytes()));
        h = fold_u64(h, self.target_order.map_or(0, |o| o.get()));
        h
    }

    /// Dedup key: identical for every transmission of the same logical order, so a
    /// duplicate-collapsing set treats them as one. Distinct logical orders differ
    /// because the idempotency key is unique per `(session, nonce)`.
    #[must_use]
    pub fn dedup_key(&self) -> u128 {
        self.idempotency_key
    }
}

/// Stable numeric code for a command kind (hash input; avoids `enum as int`).
const fn kind_code(kind: CommandKind) -> u64 {
    match kind {
        CommandKind::NewOrder => 0,
        CommandKind::Cancel => 1,
        CommandKind::Replace => 2,
    }
}

/// Stable numeric code for an order side.
const fn side_code(side: Side) -> u64 {
    match side {
        Side::Bid => 0,
        Side::Ask => 1,
    }
}

/// Stable numeric code for an order type.
const fn order_type_code(ty: OrderType) -> u64 {
    match ty {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
        OrderType::ReduceOnly => 3,
    }
}

/// Per-session generator state. Owns the monotonic nonce and order-id space.
#[derive(Debug, Clone)]
pub struct SessionState {
    session: u32,
    next_nonce: u64,
    /// Order ids this session has created, for cancels/replaces to reference.
    live_orders: Vec<OrderId>,
    order_seq: u64,
}

impl SessionState {
    /// Create a session with the given id.
    #[must_use]
    pub fn new(session: u32) -> Self {
        Self {
            session,
            next_nonce: 0,
            live_orders: Vec::new(),
            order_seq: 0,
        }
    }

    /// The session id.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.session
    }

    /// The next nonce that will be issued.
    #[must_use]
    pub const fn peek_nonce(&self) -> u64 {
        self.next_nonce
    }

    fn issue_nonce(&mut self) -> u64 {
        let n = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1);
        n
    }

    /// Derive the idempotency key for a `(session, nonce)` pair. Unique per logical
    /// order because nonces are strictly monotonic within a session.
    #[must_use]
    pub fn idempotency_key(session: u32, nonce: u64) -> u128 {
        (u128::from(session) << 64) | u128::from(nonce)
    }

    /// Generate the next command for this session, choosing action and parameters
    /// deterministically from `rng` and the scenario's mix and ratios.
    pub fn next_command(&mut self, rng: &mut Lcg, scenario: &LoadScenario) -> GeneratedCommand {
        let nonce = self.issue_nonce();
        let key = Self::idempotency_key(self.session, nonce);

        // Decide the action. Cancel/replace require a live order; otherwise fall back
        // to a new order so the mix is honoured only when it is actionable.
        let can_reference = !self.live_orders.is_empty();
        let cancel = can_reference && rng.chance(scenario.cancel_ratio);
        let replace = !cancel && can_reference && rng.chance(scenario.replace_ratio);

        let market_raw = if scenario.market_count == 0 {
            0
        } else {
            u32::try_from(rng.below(u64::from(scenario.market_count))).unwrap_or(0)
        };
        let market = MarketId::new(market_raw);
        let side = if rng.next_u64() & 1 == 0 {
            Side::Bid
        } else {
            Side::Ask
        };

        // Price in a plausible band; quantity in [1, 1000] units (scaled).
        let price_raw = i64::try_from(10_000 + rng.below(10_000)).unwrap_or(10_000);
        let qty_raw = i64::try_from(1 + rng.below(1000)).unwrap_or(1);
        let price = Price::from_raw(price_raw.saturating_mul(1_000_000));
        let quantity = Quantity::from_raw(qty_raw.saturating_mul(1_000_000));

        if cancel {
            let target = self.pick_live_order(rng);
            GeneratedCommand {
                session: self.session,
                nonce,
                idempotency_key: key,
                market,
                kind: CommandKind::Cancel,
                side,
                order_type: OrderType::Limit,
                price,
                quantity,
                target_order: target,
            }
        } else if replace {
            let target = self.pick_live_order(rng);
            GeneratedCommand {
                session: self.session,
                nonce,
                idempotency_key: key,
                market,
                kind: CommandKind::Replace,
                side,
                order_type: OrderMix::pick(&scenario.order_mix, rng),
                price,
                quantity,
                target_order: target,
            }
        } else {
            let order = self.mint_order();
            GeneratedCommand {
                session: self.session,
                nonce,
                idempotency_key: key,
                market,
                kind: CommandKind::NewOrder,
                side,
                order_type: OrderMix::pick(&scenario.order_mix, rng),
                price,
                quantity,
                target_order: Some(order),
            }
        }
    }

    fn mint_order(&mut self) -> OrderId {
        // Order id namespaced by session so ids are globally distinct.
        let id = (u64::from(self.session) << 40) | (self.order_seq & 0xFF_FFFF_FFFF);
        self.order_seq = self.order_seq.wrapping_add(1);
        let order = OrderId::new(id);
        // Bound the live set so a long run does not grow without limit.
        if self.live_orders.len() < 1024 {
            self.live_orders.push(order);
        }
        order
    }

    fn pick_live_order(&mut self, rng: &mut Lcg) -> Option<OrderId> {
        if self.live_orders.is_empty() {
            return None;
        }
        let len = u64::try_from(self.live_orders.len()).unwrap_or(u64::MAX);
        let idx = usize::try_from(rng.below(len)).unwrap_or(0);
        Some(self.live_orders[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Ratio;

    fn scenario() -> LoadScenario {
        LoadScenario::default()
    }

    #[test]
    fn nonces_are_strictly_monotonic() {
        let mut s = SessionState::new(3);
        let mut rng = Lcg::new(11);
        let sc = scenario();
        let mut prev = None;
        for _ in 0..1000 {
            let cmd = s.next_command(&mut rng, &sc);
            if let Some(p) = prev {
                assert_eq!(cmd.nonce, p + 1);
            }
            prev = Some(cmd.nonce);
        }
    }

    #[test]
    fn idempotency_keys_unique_per_logical_order() {
        let mut s = SessionState::new(7);
        let mut rng = Lcg::new(5);
        let sc = scenario();
        let mut keys = std::collections::HashSet::new();
        for _ in 0..2000 {
            let cmd = s.next_command(&mut rng, &sc);
            assert!(keys.insert(cmd.idempotency_key), "duplicate key");
        }
    }

    #[test]
    fn duplicate_transmission_shares_dedup_key() {
        let cmd = GeneratedCommand {
            session: 1,
            nonce: 9,
            idempotency_key: SessionState::idempotency_key(1, 9),
            market: MarketId::new(0),
            kind: CommandKind::NewOrder,
            side: Side::Bid,
            order_type: OrderType::Limit,
            price: Price::from_raw(1),
            quantity: Quantity::from_raw(1),
            target_order: None,
        };
        let copy = cmd;
        assert_eq!(cmd.dedup_key(), copy.dedup_key());
        assert_eq!(cmd.content_hash(), copy.content_hash());
    }

    #[test]
    fn cancel_ratio_honored_when_orders_exist() {
        let mut sc = scenario();
        sc.cancel_ratio = Ratio::from_raw(600_000); // 0.6
        let mut s = SessionState::new(1);
        let mut rng = Lcg::new(99);
        // Warm up so there are live orders to cancel.
        for _ in 0..50 {
            let _ = s.next_command(&mut rng, &sc);
        }
        let mut cancels = 0u32;
        let total = 50_000u32;
        for _ in 0..total {
            if s.next_command(&mut rng, &sc).kind == CommandKind::Cancel {
                cancels += 1;
            }
        }
        // Roughly 60% of actionable events; allow a generous tolerance because
        // replaces and warm-up shift the exact fraction slightly.
        assert!(cancels > 25_000, "cancels={cancels}");
        assert!(cancels < 35_000, "cancels={cancels}");
    }
}
