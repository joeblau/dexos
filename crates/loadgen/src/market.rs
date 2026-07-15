//! Deterministic fixed-point market evolution and bounded replay parsing.

use types::{MarketId, Price, Quantity, Side, TimeInForce};

use crate::config::{MarketModelConfig, MarketRegime, OrderFlowConfig};
use crate::rng::Lcg;

/// Synthetic top-of-book/depth snapshot used to place realistic orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticBbo {
    pub best_bid: Price,
    pub best_ask: Price,
    pub bid_depth: Quantity,
    pub ask_depth: Quantity,
    /// Signed imbalance in millionths: positive means more bid depth.
    pub imbalance: i64,
}

/// Per-market deterministic evolution state. It contains no floating point.
#[derive(Debug, Clone)]
pub struct MarketModel {
    config: MarketModelConfig,
    mid_raw: i64,
    current_volatility_ticks: u32,
    last_move_ticks: i64,
    step: u64,
}

impl MarketModel {
    #[must_use]
    pub fn new(config: &MarketModelConfig) -> Self {
        Self {
            config: config.clone(),
            mid_raw: config.initial_mid_raw,
            current_volatility_ticks: config.volatility_ticks.max(1),
            last_move_ticks: 0,
            step: 0,
        }
    }

    /// Advance one logical step and return a positive, tick-aligned BBO.
    pub fn advance(&mut self, rng: &mut Lcg) -> SyntheticBbo {
        let noise = signed_draw(rng, self.current_volatility_ticks);
        let anchor_delta_ticks =
            (self.config.initial_mid_raw - self.mid_raw) / self.config.tick_size_raw.max(1);
        let mut movement = match self.config.regime {
            MarketRegime::Steady => noise,
            MarketRegime::MeanReverting => {
                noise + anchor_delta_ticks / i64::from(self.config.mean_reversion_divisor.max(1))
            }
            MarketRegime::Trending => noise + i64::from(self.config.trend_ticks_per_step),
            MarketRegime::VolatilityClustering => {
                let observed = self.last_move_ticks.unsigned_abs().max(1);
                let base = u64::from(self.config.volatility_ticks.max(1));
                let next = (u64::from(self.current_volatility_ticks)
                    .saturating_mul(3)
                    .saturating_add(observed))
                    / 4;
                self.current_volatility_ticks =
                    u32::try_from(next.clamp(1, base.saturating_mul(16))).unwrap_or(u32::MAX);
                noise
            }
            MarketRegime::JumpShock => noise,
        };
        if self.config.regime == MarketRegime::JumpShock
            && self.config.shock_interval != 0
            && self.step != 0
            && self.step.is_multiple_of(self.config.shock_interval)
        {
            let direction = if (self.step / self.config.shock_interval) & 1 == 0 {
                1
            } else {
                -1
            };
            movement = movement.saturating_add(direction * i64::from(self.config.shock_ticks));
        }
        self.last_move_ticks = movement;
        let movement_raw = movement.saturating_mul(self.config.tick_size_raw);
        let minimum_mid = self
            .config
            .tick_size_raw
            .saturating_mul(i64::from(self.config.spread_ticks).saturating_add(2));
        self.mid_raw = align_down(
            self.mid_raw.saturating_add(movement_raw).max(minimum_mid),
            self.config.tick_size_raw,
        );
        self.step = self.step.saturating_add(1);

        let spread_ticks = i64::from(self.config.spread_ticks.max(1));
        let half_spread_ticks = spread_ticks.saturating_add(1) / 2;
        let half_spread = half_spread_ticks.saturating_mul(self.config.tick_size_raw);
        let best_bid = align_down(
            self.mid_raw
                .saturating_sub(half_spread)
                .max(self.config.tick_size_raw),
            self.config.tick_size_raw,
        );
        let best_ask = align_up(
            self.mid_raw.saturating_add(half_spread),
            self.config.tick_size_raw,
        )
        .max(best_bid.saturating_add(self.config.tick_size_raw));
        let imbalance = i64::try_from(rng.below(2_000_001)).unwrap_or(1_000_000) - 1_000_000;
        let base_depth = i64::from(self.config.depth_levels).saturating_mul(10_000_000);
        let bid_depth = base_depth.saturating_add(base_depth.saturating_mul(imbalance) / 2_000_000);
        let ask_depth = base_depth.saturating_sub(base_depth.saturating_mul(imbalance) / 2_000_000);
        SyntheticBbo {
            best_bid: Price::from_raw(best_bid),
            best_ask: Price::from_raw(best_ask),
            bid_depth: Quantity::from_raw(bid_depth.max(1)),
            ask_depth: Quantity::from_raw(ask_depth.max(1)),
            imbalance,
        }
    }

    /// Pick a positive tick-aligned price relative to the current BBO.
    pub fn order_price(
        &self,
        bbo: SyntheticBbo,
        side: Side,
        flow: &OrderFlowConfig,
        rng: &mut Lcg,
    ) -> Price {
        let total = u64::from(flow.passive_weight)
            + u64::from(flow.at_touch_weight)
            + u64::from(flow.aggressive_weight);
        let draw = rng.below(total.max(1));
        let passive = draw < u64::from(flow.passive_weight);
        let at_touch =
            !passive && draw < u64::from(flow.passive_weight) + u64::from(flow.at_touch_weight);
        let distance = i64::try_from(1 + rng.below(u64::from(self.config.depth_levels.max(1))))
            .unwrap_or(1)
            .saturating_mul(self.config.tick_size_raw);
        let raw = match (side, passive, at_touch) {
            (Side::Bid, true, _) => bbo.best_bid.raw().saturating_sub(distance),
            (Side::Bid, false, true) => bbo.best_bid.raw(),
            (Side::Bid, false, false) => bbo.best_ask.raw().saturating_add(distance),
            (Side::Ask, true, _) => bbo.best_ask.raw().saturating_add(distance),
            (Side::Ask, false, true) => bbo.best_ask.raw(),
            (Side::Ask, false, false) => bbo.best_bid.raw().saturating_sub(distance),
        };
        Price::from_raw(align_down(
            raw.max(self.config.tick_size_raw),
            self.config.tick_size_raw,
        ))
    }
}

#[must_use]
pub fn pick_side(flow: &OrderFlowConfig, rng: &mut Lcg) -> Side {
    let total = u64::from(flow.bid_weight) + u64::from(flow.ask_weight);
    if rng.below(total.max(1)) < u64::from(flow.bid_weight) {
        Side::Bid
    } else {
        Side::Ask
    }
}

#[must_use]
pub fn pick_time_in_force(flow: &OrderFlowConfig, rng: &mut Lcg) -> TimeInForce {
    let total =
        u64::from(flow.gtc_weight) + u64::from(flow.ioc_weight) + u64::from(flow.fok_weight);
    let draw = rng.below(total.max(1));
    if draw < u64::from(flow.gtc_weight) {
        TimeInForce::Gtc
    } else if draw < u64::from(flow.gtc_weight) + u64::from(flow.ioc_weight) {
        TimeInForce::Ioc
    } else {
        TimeInForce::Fok
    }
}

#[must_use]
pub fn pick_quantity(flow: &OrderFlowConfig, rng: &mut Lcg) -> Quantity {
    let span = u64::try_from(
        flow.max_quantity_raw
            .saturating_sub(flow.min_quantity_raw)
            .saturating_add(1),
    )
    .unwrap_or(1);
    let offset = i64::try_from(rng.below(span.max(1))).unwrap_or(0);
    Quantity::from_raw(flow.min_quantity_raw.saturating_add(offset))
}

#[must_use]
pub fn pick_market_index(flow: &OrderFlowConfig, market_count: usize, rng: &mut Lcg) -> usize {
    if market_count <= 1 {
        return 0;
    }
    if flow.market_weights.len() != market_count {
        return usize::try_from(rng.below(u64::try_from(market_count).unwrap_or(1))).unwrap_or(0);
    }
    let total = flow
        .market_weights
        .iter()
        .fold(0u64, |sum, weight| sum.saturating_add(u64::from(*weight)));
    let draw = rng.below(total.max(1));
    let mut cumulative = 0u64;
    for (index, weight) in flow.market_weights.iter().enumerate() {
        cumulative = cumulative.saturating_add(u64::from(*weight));
        if draw < cumulative {
            return index;
        }
    }
    market_count - 1
}

/// One validated timestamped market-data replay event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayEvent {
    pub timestamp_ns: u64,
    pub market: MarketId,
    pub best_bid: Price,
    pub best_ask: Price,
    pub bid_depth: Quantity,
    pub ask_depth: Quantity,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("replay input exceeds the configured event/byte bound")]
    TooLarge,
    #[error("invalid replay line {line}: {reason}")]
    Invalid { line: usize, reason: String },
}

/// Parse `timestamp_ns,market_id,best_bid_raw,best_ask_raw,bid_depth_raw,ask_depth_raw`.
/// The parser treats replay input as untrusted: line length, total bytes, event count,
/// ordering, positivity, BBO relation, and tick alignment are all bounded/validated.
pub fn parse_replay(
    text: &str,
    max_events: usize,
    tick_size_raw: i64,
) -> Result<Vec<ReplayEvent>, ReplayError> {
    let max_bytes = max_events.checked_mul(256).ok_or(ReplayError::TooLarge)?;
    if max_events == 0 || text.len() > max_bytes {
        return Err(ReplayError::TooLarge);
    }
    let mut events = Vec::with_capacity(max_events.min(4096));
    let mut last_timestamp = 0u64;
    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("timestamp_ns,") {
            continue;
        }
        if line.len() > 1024 || events.len() >= max_events {
            return Err(ReplayError::TooLarge);
        }
        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() != 6 {
            return Err(ReplayError::Invalid {
                line: line_number,
                reason: "expected exactly six comma-separated integers".to_string(),
            });
        }
        let parse_u64 = |index: usize, name: &str| {
            fields[index]
                .parse::<u64>()
                .map_err(|_| ReplayError::Invalid {
                    line: line_number,
                    reason: format!("{name} is not an unsigned integer"),
                })
        };
        let parse_i64 = |index: usize, name: &str| {
            fields[index]
                .parse::<i64>()
                .map_err(|_| ReplayError::Invalid {
                    line: line_number,
                    reason: format!("{name} is not a signed integer"),
                })
        };
        let timestamp_ns = parse_u64(0, "timestamp_ns")?;
        let market_raw = parse_u64(1, "market_id")?;
        let market = u32::try_from(market_raw).map_err(|_| ReplayError::Invalid {
            line: line_number,
            reason: "market_id exceeds u32".to_string(),
        })?;
        let bid = parse_i64(2, "best_bid_raw")?;
        let ask = parse_i64(3, "best_ask_raw")?;
        let bid_depth = parse_i64(4, "bid_depth_raw")?;
        let ask_depth = parse_i64(5, "ask_depth_raw")?;
        if timestamp_ns < last_timestamp {
            return Err(ReplayError::Invalid {
                line: line_number,
                reason: "timestamps must be nondecreasing".to_string(),
            });
        }
        if bid <= 0 || ask <= bid || bid_depth <= 0 || ask_depth <= 0 {
            return Err(ReplayError::Invalid {
                line: line_number,
                reason: "prices/depth must be positive and best_ask must exceed best_bid"
                    .to_string(),
            });
        }
        if tick_size_raw <= 0 || bid % tick_size_raw != 0 || ask % tick_size_raw != 0 {
            return Err(ReplayError::Invalid {
                line: line_number,
                reason: "BBO prices are not tick-aligned".to_string(),
            });
        }
        last_timestamp = timestamp_ns;
        events.push(ReplayEvent {
            timestamp_ns,
            market: MarketId::new(market),
            best_bid: Price::from_raw(bid),
            best_ask: Price::from_raw(ask),
            bid_depth: Quantity::from_raw(bid_depth),
            ask_depth: Quantity::from_raw(ask_depth),
        });
    }
    Ok(events)
}

fn signed_draw(rng: &mut Lcg, magnitude: u32) -> i64 {
    let magnitude = u64::from(magnitude);
    i64::try_from(rng.below(magnitude.saturating_mul(2).saturating_add(1))).unwrap_or(0)
        - i64::try_from(magnitude).unwrap_or(i64::MAX)
}

fn align_down(value: i64, tick: i64) -> i64 {
    value - value.rem_euclid(tick.max(1))
}

fn align_up(value: i64, tick: i64) -> i64 {
    let tick = tick.max(1);
    let remainder = value.rem_euclid(tick);
    if remainder == 0 {
        value
    } else {
        value.saturating_add(tick - remainder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_regime_stays_positive_tick_aligned_and_reproducible() {
        for regime in [
            MarketRegime::Steady,
            MarketRegime::MeanReverting,
            MarketRegime::Trending,
            MarketRegime::VolatilityClustering,
            MarketRegime::JumpShock,
        ] {
            let config = MarketModelConfig {
                regime,
                shock_interval: 10,
                ..MarketModelConfig::default()
            };
            let mut left = MarketModel::new(&config);
            let mut right = MarketModel::new(&config);
            let mut left_rng = Lcg::new(42);
            let mut right_rng = Lcg::new(42);
            for _ in 0..10_000 {
                let a = left.advance(&mut left_rng);
                let b = right.advance(&mut right_rng);
                assert_eq!(a, b);
                assert!(a.best_bid.raw() > 0);
                assert!(a.best_ask.raw() > a.best_bid.raw());
                assert_eq!(a.best_bid.raw() % config.tick_size_raw, 0);
                assert_eq!(a.best_ask.raw() % config.tick_size_raw, 0);
            }
        }
    }

    #[test]
    fn order_prices_are_relative_to_bbo_and_tick_aligned() {
        let config = MarketModelConfig::default();
        let mut model = MarketModel::new(&config);
        let mut rng = Lcg::new(9);
        let bbo = model.advance(&mut rng);
        for side in [Side::Bid, Side::Ask] {
            for _ in 0..1000 {
                let price = model.order_price(bbo, side, &OrderFlowConfig::default(), &mut rng);
                assert!(price.raw() > 0);
                assert_eq!(price.raw() % config.tick_size_raw, 0);
            }
        }
    }

    #[test]
    fn replay_parser_is_bounded_and_validates_invariants() {
        let valid =
            "timestamp_ns,market_id,best_bid_raw,best_ask_raw,bid_depth_raw,ask_depth_raw\n\
                     1,7,100,110,5,6\n2,7,110,120,7,8\n";
        let events = parse_replay(valid, 2, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].market, MarketId::new(7));
        assert!(matches!(
            parse_replay(valid, 1, 10),
            Err(ReplayError::TooLarge)
        ));
        assert!(parse_replay("2,1,100,110,1,1\n1,1,100,110,1,1", 2, 10).is_err());
        assert!(parse_replay("1,1,101,110,1,1", 2, 10).is_err());
    }
}
