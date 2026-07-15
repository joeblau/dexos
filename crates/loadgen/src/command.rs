//! Generated virtual-user commands and the per-session state that emits them.
//!
//! Each session keeps a strictly monotonic nonce and a private order-id space, so
//! nonces never regress and every logical order gets a unique idempotency key. A
//! command carries a stable content hash used both for the reproduction fingerprint
//! and for the dedup key that collapses duplicate transmissions back to one logical
//! order.

use serde::{Deserialize, Serialize};
use types::{MarketId, OrderId, OrderType, Price, Quantity, Side, TimeInForce, RATIO_SCALE};

use crate::config::{LoadScenario, OrderMix};
use crate::market::{
    parse_replay, pick_market_index, pick_quantity, pick_side, pick_time_in_force, MarketModel,
    ReplayEvent, SyntheticBbo,
};
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
    /// Time-in-force for new orders.
    pub time_in_force: TimeInForce,
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
        h = fold_u64(h, time_in_force_code(self.time_in_force));
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

const fn time_in_force_code(tif: TimeInForce) -> u64 {
    match tif {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    }
}

/// Accepted order ownership retained for valid cancel/replace selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveOrder {
    pub order_id: OrderId,
    pub market: MarketId,
    pub side: Side,
    pub price: Price,
    pub quantity: Quantity,
    pub accepted_nonce: u64,
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
    live_orders: Vec<LiveOrder>,
    /// Live orders with an in-flight cancel/replace. This is transport bookkeeping,
    /// not accepted order state, and prevents conflicting requests in one pipeline.
    reserved_orders: Vec<OrderId>,
    order_seq: u64,
    rng: Lcg,
    market_ids: Vec<MarketId>,
    market_models: Vec<MarketModel>,
    replay_events: Vec<ReplayEvent>,
    replay_cursor: usize,
    live_capacity: usize,
    auto_accept: bool,
}

impl SessionState {
    /// Create a session with the given id.
    #[must_use]
    pub fn new(session: u32) -> Self {
        Self {
            session,
            next_nonce: 0,
            live_orders: Vec::new(),
            reserved_orders: Vec::new(),
            order_seq: 0,
            rng: Lcg::new(fold_u64(
                fnv1a_64(b"dexos.loadgen.session.v2"),
                u64::from(session),
            )),
            market_ids: Vec::new(),
            market_models: Vec::new(),
            replay_events: Vec::new(),
            replay_cursor: 0,
            live_capacity: 1024,
            auto_accept: true,
        }
    }

    /// Construct a schedule-independent session RNG/model partition.
    #[must_use]
    pub fn with_partition(
        session: u32,
        scenario: &LoadScenario,
        agent: &str,
        worker: u16,
        auto_accept: bool,
    ) -> Self {
        let mut seed = fnv1a_64(b"dexos.loadgen.partition.v2");
        seed = fold_u64(seed, scenario.seed);
        seed = fold_u64(seed, fnv1a_64(agent.as_bytes()));
        seed = fold_u64(seed, u64::from(worker));
        seed = fold_u64(seed, u64::from(session));
        let market_ids = scenario
            .effective_market_ids()
            .into_iter()
            .map(MarketId::new)
            .collect::<Vec<_>>();
        let market_models = market_ids
            .iter()
            .map(|_| MarketModel::new(&scenario.market_model))
            .collect();
        let replay_events = if scenario.market_model.replay_file.is_empty() {
            Vec::new()
        } else {
            std::fs::read_to_string(&scenario.market_model.replay_file)
                .ok()
                .and_then(|text| {
                    parse_replay(
                        &text,
                        scenario.market_model.max_replay_events,
                        scenario.market_model.tick_size_raw,
                    )
                    .ok()
                })
                .unwrap_or_default()
        };
        Self {
            session,
            next_nonce: scenario.nonce_base,
            live_orders: Vec::with_capacity(scenario.order_flow.live_orders_per_session),
            reserved_orders: Vec::with_capacity(scenario.order_flow.live_orders_per_session),
            order_seq: 0,
            rng: Lcg::new(seed),
            market_ids,
            market_models,
            replay_events,
            replay_cursor: 0,
            live_capacity: scenario.order_flow.live_orders_per_session,
            auto_accept,
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
    pub fn next_command(&mut self, _rng: &mut Lcg, scenario: &LoadScenario) -> GeneratedCommand {
        self.ensure_models(scenario);
        let nonce = self.issue_nonce();
        let key = Self::idempotency_key(self.session, nonce);

        // One exact categorical draw (rather than sequential Bernoulli trials) makes
        // configured new/cancel/replace proportions independently testable.
        let can_reference = !self.live_orders.is_empty()
            && (self.auto_accept
                || self
                    .live_orders
                    .iter()
                    .any(|order| !self.reserved_orders.contains(&order.order_id)));
        let mix = scenario.effective_operation_mix();
        let draw =
            i64::try_from(self.rng.below(u64::try_from(RATIO_SCALE).unwrap_or(1))).unwrap_or(0);
        let cancel =
            can_reference && draw >= mix.new.raw() && draw < mix.new.raw() + mix.cancel.raw();
        let replace = can_reference && draw >= mix.new.raw() + mix.cancel.raw();

        if cancel {
            let index = self.pick_live_order_index(nonce, scenario);
            let live = self.live_orders[index];
            let command = GeneratedCommand {
                session: self.session,
                nonce,
                idempotency_key: key,
                market: live.market,
                kind: CommandKind::Cancel,
                side: live.side,
                order_type: OrderType::Limit,
                time_in_force: TimeInForce::Gtc,
                price: live.price,
                quantity: live.quantity,
                target_order: Some(live.order_id),
            };
            if self.auto_accept {
                self.live_orders.swap_remove(index);
            } else {
                self.reserved_orders.push(live.order_id);
            }
            command
        } else if replace {
            let index = self.pick_live_order_index(nonce, scenario);
            let live = self.live_orders[index];
            let model_index = self
                .market_ids
                .iter()
                .position(|market| *market == live.market)
                .unwrap_or(0);
            let bbo = self.next_bbo(model_index);
            let price = self.market_models[model_index].order_price(
                bbo,
                live.side,
                &scenario.order_flow,
                &mut self.rng,
            );
            let quantity = pick_quantity(&scenario.order_flow, &mut self.rng);
            let command = GeneratedCommand {
                session: self.session,
                nonce,
                idempotency_key: key,
                market: live.market,
                kind: CommandKind::Replace,
                side: live.side,
                order_type: OrderMix::pick(&scenario.order_mix, &mut self.rng),
                time_in_force: TimeInForce::Gtc,
                price,
                quantity,
                target_order: Some(live.order_id),
            };
            if self.auto_accept {
                self.live_orders[index].price = price;
                self.live_orders[index].quantity = quantity;
            } else {
                self.reserved_orders.push(live.order_id);
            }
            command
        } else {
            let market_index =
                pick_market_index(&scenario.order_flow, self.market_ids.len(), &mut self.rng);
            let market = self.market_ids[market_index];
            let side = pick_side(&scenario.order_flow, &mut self.rng);
            let bbo = self.next_bbo(market_index);
            let price = self.market_models[market_index].order_price(
                bbo,
                side,
                &scenario.order_flow,
                &mut self.rng,
            );
            let quantity = pick_quantity(&scenario.order_flow, &mut self.rng);
            let time_in_force = pick_time_in_force(&scenario.order_flow, &mut self.rng);
            let command = GeneratedCommand {
                session: self.session,
                nonce,
                idempotency_key: key,
                market,
                kind: CommandKind::NewOrder,
                side,
                order_type: OrderMix::pick(&scenario.order_mix, &mut self.rng),
                time_in_force,
                price,
                quantity,
                target_order: None,
            };
            if self.auto_accept {
                let order = self.mint_order();
                self.accept_new_order(order, &command);
            }
            command
        }
    }

    fn mint_order(&mut self) -> OrderId {
        // Order id namespaced by session so ids are globally distinct.
        let id = (u64::from(self.session) << 40) | (self.order_seq & 0xFF_FFFF_FFFF);
        self.order_seq = self.order_seq.wrapping_add(1);
        OrderId::new(id)
    }

    fn ensure_models(&mut self, scenario: &LoadScenario) {
        if self.market_ids.is_empty() {
            self.market_ids = scenario
                .effective_market_ids()
                .into_iter()
                .map(MarketId::new)
                .collect();
            self.market_models = self
                .market_ids
                .iter()
                .map(|_| MarketModel::new(&scenario.market_model))
                .collect();
            self.live_capacity = scenario.order_flow.live_orders_per_session;
            if !scenario.market_model.replay_file.is_empty() {
                self.replay_events = std::fs::read_to_string(&scenario.market_model.replay_file)
                    .ok()
                    .and_then(|text| {
                        parse_replay(
                            &text,
                            scenario.market_model.max_replay_events,
                            scenario.market_model.tick_size_raw,
                        )
                        .ok()
                    })
                    .unwrap_or_default();
            }
        }
    }

    fn next_bbo(&mut self, market_index: usize) -> SyntheticBbo {
        let market = self.market_ids[market_index];
        if !self.replay_events.is_empty() {
            for offset in 0..self.replay_events.len() {
                let index = (self.replay_cursor + offset) % self.replay_events.len();
                let event = self.replay_events[index];
                if event.market != market {
                    continue;
                }
                self.replay_cursor = (index + 1) % self.replay_events.len();
                let depth_total = event
                    .bid_depth
                    .raw()
                    .saturating_add(event.ask_depth.raw())
                    .max(1);
                return SyntheticBbo {
                    best_bid: event.best_bid,
                    best_ask: event.best_ask,
                    bid_depth: event.bid_depth,
                    ask_depth: event.ask_depth,
                    imbalance: event
                        .bid_depth
                        .raw()
                        .saturating_sub(event.ask_depth.raw())
                        .saturating_mul(1_000_000)
                        / depth_total,
                };
            }
        }
        self.market_models[market_index].advance(&mut self.rng)
    }

    fn pick_live_order_index(&mut self, nonce: u64, scenario: &LoadScenario) -> usize {
        // Age and distance from the configured anchor both raise selection weight.
        // The bounded O(live-capacity) scan allocates nothing and never selects an
        // order outside this owning session/market pool.
        let tick = scenario.market_model.tick_size_raw.max(1);
        let anchor = scenario.market_model.initial_mid_raw;
        let total = self.live_orders.iter().fold(0u64, |sum, live| {
            if !self.auto_accept && self.reserved_orders.contains(&live.order_id) {
                return sum;
            }
            let age = nonce.saturating_sub(live.accepted_nonce).saturating_add(1);
            let distance = u64::try_from((live.price.raw() - anchor).abs() / tick).unwrap_or(0);
            sum.saturating_add(age.saturating_add(distance).max(1))
        });
        let draw = self.rng.below(total.max(1));
        let mut cumulative = 0u64;
        for (index, live) in self.live_orders.iter().enumerate() {
            if !self.auto_accept && self.reserved_orders.contains(&live.order_id) {
                continue;
            }
            let age = nonce.saturating_sub(live.accepted_nonce).saturating_add(1);
            let distance = u64::try_from((live.price.raw() - anchor).abs() / tick).unwrap_or(0);
            cumulative = cumulative.saturating_add(age.saturating_add(distance).max(1));
            if draw < cumulative {
                return index;
            }
        }
        self.live_orders.len() - 1
    }

    /// Release transport-only ownership after an acknowledgement or terminal
    /// failure. Accepted order state remains exclusively acknowledgement-driven.
    pub fn release_pending(&mut self, command: &GeneratedCommand) {
        let Some(order_id) = command.target_order else {
            return;
        };
        if let Some(index) = self
            .reserved_orders
            .iter()
            .position(|reserved| *reserved == order_id)
        {
            self.reserved_orders.swap_remove(index);
        }
    }

    /// Update live state only from an accepted submit acknowledgement in live mode.
    pub fn accept_new_order(&mut self, order_id: OrderId, command: &GeneratedCommand) -> bool {
        if command.session != self.session
            || command.kind != CommandKind::NewOrder
            || self.live_orders.len() >= self.live_capacity
        {
            return false;
        }
        self.live_orders.push(LiveOrder {
            order_id,
            market: command.market,
            side: command.side,
            price: command.price,
            quantity: command.quantity,
            accepted_nonce: command.nonce,
        });
        true
    }

    /// Remove an order only when an accepted cancel matches this session and market.
    pub fn accept_cancel(&mut self, order_id: OrderId, market: MarketId) -> bool {
        let Some(index) = self
            .live_orders
            .iter()
            .position(|order| order.order_id == order_id && order.market == market)
        else {
            return false;
        };
        self.live_orders.swap_remove(index);
        true
    }

    /// Apply an accepted replacement to the owned live order.
    pub fn accept_replace(&mut self, command: &GeneratedCommand) -> bool {
        let Some(order_id) = command.target_order else {
            return false;
        };
        let Some(order) = self
            .live_orders
            .iter_mut()
            .find(|order| order.order_id == order_id && order.market == command.market)
        else {
            return false;
        };
        order.price = command.price;
        order.quantity = command.quantity;
        true
    }

    #[must_use]
    pub fn live_orders(&self) -> &[LiveOrder] {
        &self.live_orders
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
            time_in_force: TimeInForce::Gtc,
            price: Price::from_raw(1),
            quantity: Quantity::from_raw(1),
            target_order: None,
        };
        let copy = cmd;
        assert_eq!(cmd.dedup_key(), copy.dedup_key());
        assert_eq!(cmd.content_hash(), copy.content_hash());
    }

    #[test]
    fn action_and_order_type_ratios_match_over_one_million_actions() {
        let mut sc = scenario();
        sc.operation_mix = Some(crate::config::OperationMix {
            new: Ratio::from_raw(600_000),
            cancel: Ratio::from_raw(300_000),
            replace: Ratio::from_raw(100_000),
        });
        sc.order_flow.live_orders_per_session = 64;
        let mut s = SessionState::with_partition(1, &sc, "ratio-test", 0, true);
        let mut rng = Lcg::new(99);
        let mut kinds = [0u64; 3];
        let mut order_types = [0u64; 4];
        let total = 1_000_000u64;
        for _ in 0..total {
            let command = s.next_command(&mut rng, &sc);
            match command.kind {
                CommandKind::NewOrder => {
                    kinds[0] += 1;
                    order_types
                        [usize::try_from(order_type_code(command.order_type)).unwrap_or(0)] += 1;
                }
                CommandKind::Cancel => kinds[1] += 1,
                CommandKind::Replace => kinds[2] += 1,
            }
        }
        for (actual, expected) in kinds.into_iter().zip([600_000, 300_000, 100_000]) {
            assert!(actual.abs_diff(expected) < 5_000, "actual={actual}");
        }
        let new_total = order_types.iter().sum::<u64>();
        for (actual, weight) in order_types.into_iter().zip([70, 20, 8, 2]) {
            let expected = new_total * weight / 100;
            assert!(
                actual.abs_diff(expected) < new_total / 100,
                "actual={actual}"
            );
        }
    }

    #[test]
    fn partitioned_streams_are_schedule_independent() {
        let sc = LoadScenario {
            seed: 1234,
            operation_mix: Some(crate::config::OperationMix {
                new: Ratio::from_raw(700_000),
                cancel: Ratio::from_raw(200_000),
                replace: Ratio::from_raw(100_000),
            }),
            ..scenario()
        };
        let mut a0 = SessionState::with_partition(10, &sc, "agent-a", 3, true);
        let mut a1 = SessionState::with_partition(11, &sc, "agent-a", 3, true);
        let mut b0 = SessionState::with_partition(10, &sc, "agent-a", 3, true);
        let mut b1 = SessionState::with_partition(11, &sc, "agent-a", 3, true);
        let mut ignored = Lcg::new(0);
        let mut left = [0u64; 2];
        let mut right = [0u64; 2];
        for _ in 0..10_000 {
            left[0] = fold_u64(left[0], a0.next_command(&mut ignored, &sc).content_hash());
            left[1] = fold_u64(left[1], a1.next_command(&mut ignored, &sc).content_hash());
        }
        for step in 0..20_000 {
            let index = step & 1;
            let command = if index == 0 {
                b0.next_command(&mut ignored, &sc)
            } else {
                b1.next_command(&mut ignored, &sc)
            };
            right[index] = fold_u64(right[index], command.content_hash());
        }
        assert_eq!(left, right);
    }

    #[test]
    fn live_state_uses_only_accepted_owned_market_orders() {
        let mut sc = LoadScenario {
            market_ids: vec![7, 9],
            operation_mix: Some(crate::config::OperationMix {
                new: Ratio::from_raw(1_000_000),
                cancel: Ratio::ZERO,
                replace: Ratio::ZERO,
            }),
            ..scenario()
        };
        let mut session = SessionState::with_partition(4, &sc, "agent", 0, false);
        let mut ignored = Lcg::new(0);
        let new_order = session.next_command(&mut ignored, &sc);
        assert!(session.live_orders().is_empty(), "not accepted yet");
        let acknowledged_id = OrderId::new(9001);
        assert!(session.accept_new_order(acknowledged_id, &new_order));

        sc.operation_mix = Some(crate::config::OperationMix {
            new: Ratio::ZERO,
            cancel: Ratio::from_raw(1_000_000),
            replace: Ratio::ZERO,
        });
        let cancel = session.next_command(&mut ignored, &sc);
        assert_eq!(cancel.kind, CommandKind::Cancel);
        assert_eq!(cancel.target_order, Some(acknowledged_id));
        assert_eq!(cancel.market, new_order.market);
        assert!(session.accept_cancel(acknowledged_id, new_order.market));
        assert!(session.live_orders().is_empty());
    }

    #[test]
    fn validated_replay_bbo_drives_order_placement() {
        let path = std::env::temp_dir().join(format!(
            "dexos-loadgen-replay-{}-{}.csv",
            std::process::id(),
            fnv1a_64(b"command-replay-test")
        ));
        std::fs::write(
            &path,
            "timestamp_ns,market_id,best_bid_raw,best_ask_raw,bid_depth_raw,ask_depth_raw\n1,7,9999000000,10001000000,2000000,1000000\n",
        )
        .unwrap();
        let mut sc = LoadScenario {
            market_ids: vec![7],
            operation_mix: Some(crate::config::OperationMix {
                new: Ratio::from_raw(1_000_000),
                cancel: Ratio::ZERO,
                replace: Ratio::ZERO,
            }),
            ..scenario()
        };
        sc.market_model.replay_file = path.display().to_string();
        sc.market_model.max_replay_events = 1;
        sc.order_flow.bid_weight = 1;
        sc.order_flow.ask_weight = 0;
        sc.order_flow.passive_weight = 0;
        sc.order_flow.at_touch_weight = 1;
        sc.order_flow.aggressive_weight = 0;
        sc.validate().unwrap();
        let mut session = SessionState::with_partition(1, &sc, "replay", 0, true);
        let command = session.next_command(&mut Lcg::new(0), &sc);
        assert_eq!(command.market, MarketId::new(7));
        assert_eq!(command.side, Side::Bid);
        assert_eq!(command.price.raw(), 9_999_000_000);
        let _ = std::fs::remove_file(path);
    }
}
