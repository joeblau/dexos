//! Load-generation configuration surface.
//!
//! [`LoadConfig`] is the small, backwards-compatible plan the `market-loadgen` CLI
//! constructs directly. [`LoadScenario`] is the full, richly-configurable plan that
//! the engine actually executes: multiple regions, order mix, burst pattern, network
//! impairment, adversarial behaviour, oracle and market-data workloads, and a chosen
//! clock-synchronisation method. Every knob is fixed-point or integer so a scenario
//! round-trips through TOML bit-identically.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use types::{OrderType, Ratio, RATIO_SCALE};

use crate::rng::Lcg;

/// Errors from parsing or validating a scenario.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A numeric field was outside its permitted range.
    #[error("invalid field `{field}`: {reason}")]
    Invalid {
        /// The offending field name.
        field: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// The TOML document could not be parsed.
    #[error("malformed TOML: {0}")]
    Toml(String),
}

impl ConfigError {
    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        ConfigError::Invalid {
            field,
            reason: reason.into(),
        }
    }
}

/// The clock-synchronisation method used to correct cross-region timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ClockMethod {
    /// Single local monotonic clock; no cross-region correction needed.
    LocalMonotonic,
    /// PTP-style offset correction (sub-microsecond).
    #[default]
    PtpOffset,
    /// NTP-style offset correction (millisecond class).
    NtpOffset,
}

impl ClockMethod {
    /// Human-readable label recorded in the results artifact.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ClockMethod::LocalMonotonic => "local-monotonic",
            ClockMethod::PtpOffset => "ptp-offset",
            ClockMethod::NtpOffset => "ntp-offset",
        }
    }
}

/// A single region's generator topology and timing characteristics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegionConfig {
    /// Region identifier (e.g. `us-east`).
    pub name: String,
    /// Number of virtual users / persistent sessions in this region.
    pub users: u32,
    /// Whether this region is remote from the sequencer (drives latency class).
    pub cross_region: bool,
    /// One-way client-to-gateway network latency, microseconds.
    pub base_latency_us: u64,
    /// Uniform network jitter span, microseconds.
    pub jitter_us: u64,
    /// Local clock offset versus the global timebase, microseconds (can be negative).
    pub clock_offset_us: i64,
}

impl Default for RegionConfig {
    fn default() -> Self {
        Self {
            name: "local".to_string(),
            users: 100,
            cross_region: false,
            base_latency_us: 200,
            jitter_us: 50,
            clock_offset_us: 0,
        }
    }
}

/// Relative weights for the order-type mix among newly-created orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OrderMix {
    /// Weight of plain limit orders.
    pub limit: u32,
    /// Weight of market orders.
    pub market: u32,
    /// Weight of post-only orders.
    pub post_only: u32,
    /// Weight of reduce-only orders.
    pub reduce_only: u32,
}

impl Default for OrderMix {
    fn default() -> Self {
        Self {
            limit: 70,
            market: 20,
            post_only: 8,
            reduce_only: 2,
        }
    }
}

impl OrderMix {
    /// Sum of all weights.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.limit as u64 + self.market as u64 + self.post_only as u64 + self.reduce_only as u64
    }

    /// Deterministically pick an order type according to the weights. When all
    /// weights are zero this falls back to [`OrderType::Limit`].
    pub fn pick(&self, rng: &mut Lcg) -> OrderType {
        let total = self.total();
        if total == 0 {
            return OrderType::Limit;
        }
        let draw = rng.below(total);
        let mut acc = u64::from(self.limit);
        if draw < acc {
            return OrderType::Limit;
        }
        acc += u64::from(self.market);
        if draw < acc {
            return OrderType::Market;
        }
        acc += u64::from(self.post_only);
        if draw < acc {
            return OrderType::PostOnly;
        }
        OrderType::ReduceOnly
    }
}

/// Shape of the offered load over time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BurstKind {
    /// Constant rate.
    Steady,
    /// Alternating peak/idle windows.
    Bursty,
    /// Linear ramp from zero to full rate over the run.
    Ramp,
}

/// Burst pattern parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BurstPattern {
    /// Which shape to apply.
    pub kind: BurstKind,
    /// Peak multiplier over the base rate during a burst window (>= 1).
    pub peak_multiplier: u32,
    /// Length of a burst window, seconds (Bursty only).
    pub burst_secs: u64,
    /// Length of an idle window, seconds (Bursty only).
    pub idle_secs: u64,
}

impl Default for BurstPattern {
    fn default() -> Self {
        Self {
            kind: BurstKind::Steady,
            peak_multiplier: 1,
            burst_secs: 1,
            idle_secs: 1,
        }
    }
}

impl BurstPattern {
    /// Target order count for a given whole second, given the base per-second rate
    /// and the total run duration. Deterministic and integer-only.
    #[must_use]
    pub fn rate_at(&self, second: u64, base_rate: u64, duration_secs: u64) -> u64 {
        match self.kind {
            BurstKind::Steady => base_rate,
            BurstKind::Bursty => {
                let period = self.burst_secs.saturating_add(self.idle_secs).max(1);
                let phase = second % period;
                if phase < self.burst_secs {
                    base_rate.saturating_mul(u64::from(self.peak_multiplier.max(1)))
                } else {
                    0
                }
            }
            BurstKind::Ramp => {
                if duration_secs <= 1 {
                    return base_rate;
                }
                // Linear ramp: rate grows from 0 at second 0 to base_rate at the end.
                base_rate.saturating_mul(second) / (duration_secs - 1)
            }
        }
    }
}

/// Network-impairment injection parameters (all fixed-point ratios or integers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Impairment {
    /// Fraction of packets dropped.
    pub loss_ratio: Ratio,
    /// Fraction of packets duplicated (re-sent once).
    pub dup_ratio: Ratio,
    /// Fraction of packets reordered (delayed by one slot).
    pub reorder_ratio: Ratio,
    /// Additional fixed one-way latency injected, microseconds.
    pub extra_latency_us: u64,
    /// Additional uniform latency jitter injected, microseconds.
    pub latency_jitter_us: u64,
}

/// Adversarial frame-generation parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Adversarial {
    /// Whether adversarial frames are emitted at all.
    pub enabled: bool,
    /// Fraction of adversarial frames that are structurally malformed.
    pub malformed_ratio: Ratio,
    /// Fraction that claim an oversized payload length.
    pub oversized_ratio: Ratio,
    /// Maximum length of random garbage payloads.
    pub max_garbage_len: usize,
}

impl Default for Adversarial {
    fn default() -> Self {
        Self {
            enabled: false,
            malformed_ratio: Ratio::from_raw(RATIO_SCALE / 2),
            oversized_ratio: Ratio::from_raw(RATIO_SCALE / 10),
            max_garbage_len: 64,
        }
    }
}

/// Oracle-update workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OracleWorkload {
    /// Oracle price updates emitted per second.
    pub updates_per_second: u64,
}

/// Market-data subscriber workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MarketDataWorkload {
    /// Number of market-data subscribers.
    pub subscribers: u32,
    /// Market-data messages published per second.
    pub updates_per_second: u64,
}

/// The full, executable load-generation scenario.
///
/// Field order matters for TOML serialization: the `toml` crate requires every scalar
/// value to be emitted before any table or array-of-tables at the same level, so all
/// scalar knobs are declared first, then the sub-tables, and `regions` (an array of
/// tables) last.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoadScenario {
    /// Seed for the deterministic RNG. Identical seeds reproduce identical runs.
    pub seed: u64,
    /// Target node address (informational in simulation mode).
    pub target: String,
    /// Number of distinct markets traded (>= 1).
    pub market_count: u32,
    /// Aggregate base order rate across all regions, orders per second.
    pub orders_per_second: u64,
    /// Fraction of actions that are cancels (fixed-point).
    pub cancel_ratio: Ratio,
    /// Fraction of actions that are replaces (fixed-point).
    pub replace_ratio: Ratio,
    /// Clock-synchronisation method for timestamp correction.
    pub clock_method: ClockMethod,
    /// Total run duration, seconds.
    pub duration_secs: u64,
    /// Fixed capacity of each latency sample buffer (overflow is counted, not grown).
    pub sample_capacity: usize,
    /// Order-type mix among new orders.
    pub order_mix: OrderMix,
    /// Offered-load shape over time.
    pub burst: BurstPattern,
    /// Network impairment injection.
    pub impairment: Impairment,
    /// Adversarial behaviour injection.
    pub adversarial: Adversarial,
    /// Oracle-update workload.
    pub oracle: OracleWorkload,
    /// Market-data subscriber workload.
    pub market_data: MarketDataWorkload,
    /// Regions that generate load. Never empty after validation. Declared last so
    /// TOML serialization emits it as a trailing array of tables.
    pub regions: Vec<RegionConfig>,
}

impl Default for LoadScenario {
    fn default() -> Self {
        Self {
            seed: 0,
            target: "127.0.0.1:9000".to_string(),
            regions: vec![RegionConfig::default()],
            market_count: 1,
            orders_per_second: 1000,
            cancel_ratio: Ratio::ZERO,
            replace_ratio: Ratio::ZERO,
            order_mix: OrderMix::default(),
            burst: BurstPattern::default(),
            impairment: Impairment::default(),
            adversarial: Adversarial::default(),
            oracle: OracleWorkload::default(),
            market_data: MarketDataWorkload::default(),
            clock_method: ClockMethod::default(),
            duration_secs: 60,
            sample_capacity: 65_536,
        }
    }
}

impl LoadScenario {
    /// Parse a scenario from a TOML document, filling omitted fields with defaults.
    ///
    /// # Errors
    /// Returns [`ConfigError::Toml`] on a syntax error and [`ConfigError::Invalid`]
    /// if a validated field is out of range.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let scenario: LoadScenario =
            toml::from_str(text).map_err(|e| ConfigError::Toml(e.to_string()))?;
        scenario.validate()?;
        Ok(scenario)
    }

    /// Serialize the scenario to TOML. Round-trips bit-identically with [`from_toml`].
    ///
    /// [`from_toml`]: LoadScenario::from_toml
    ///
    /// # Errors
    /// Returns [`ConfigError::Toml`] if serialization fails (should not happen for a
    /// valid scenario).
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string(self).map_err(|e| ConfigError::Toml(e.to_string()))
    }

    /// Total configured users across all regions.
    #[must_use]
    pub fn total_users(&self) -> u64 {
        self.regions.iter().map(|r| u64::from(r.users)).sum()
    }

    /// Total planned actions across the run under a steady interpretation of the
    /// base rate (bursts redistribute but conserve nothing, so this is the steady
    /// upper reference used by [`LoadConfig::planned_orders`]).
    #[must_use]
    pub fn planned_actions(&self) -> u64 {
        self.orders_per_second.saturating_mul(self.duration_secs)
    }

    /// Validate ranges and normalise empty collections. Ratios are clamped-checked
    /// but not mutated; regions and market count are floored to sane minimums.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] when a ratio is negative or exceeds 1.0, or
    /// when there are no users to drive load.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_unit_ratio("cancel_ratio", self.cancel_ratio)?;
        check_unit_ratio("replace_ratio", self.replace_ratio)?;
        check_unit_ratio("impairment.loss_ratio", self.impairment.loss_ratio)?;
        check_unit_ratio("impairment.dup_ratio", self.impairment.dup_ratio)?;
        check_unit_ratio("impairment.reorder_ratio", self.impairment.reorder_ratio)?;
        let combined = self
            .cancel_ratio
            .raw()
            .saturating_add(self.replace_ratio.raw());
        if combined > RATIO_SCALE {
            return Err(ConfigError::invalid(
                "cancel_ratio+replace_ratio",
                "combined cancel and replace fractions exceed 1.0",
            ));
        }
        if self.regions.is_empty() {
            return Err(ConfigError::invalid(
                "regions",
                "at least one region required",
            ));
        }
        if self.total_users() == 0 {
            return Err(ConfigError::invalid("regions.users", "no users configured"));
        }
        if self.market_count == 0 {
            return Err(ConfigError::invalid("market_count", "must be >= 1"));
        }
        if self.sample_capacity == 0 {
            return Err(ConfigError::invalid("sample_capacity", "must be >= 1"));
        }
        Ok(())
    }
}

/// Backwards-compatible flat load plan constructed by the CLI.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadConfig {
    /// Target node address.
    pub target: String,
    /// Number of simulated users / persistent sessions.
    pub users: u64,
    /// Market symbol to trade.
    pub market: String,
    /// Aggregate order submission rate.
    pub orders_per_second: u64,
    /// Fraction of orders that are cancels, in `[0.0, 1.0]`.
    pub cancel_ratio: f64,
    /// Total run duration.
    pub duration: Duration,
}

impl LoadConfig {
    /// Validate the plan without running it.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] on an out-of-range cancel ratio, zero users,
    /// or an empty target.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(0.0..=1.0).contains(&self.cancel_ratio) || self.cancel_ratio.is_nan() {
            return Err(ConfigError::invalid(
                "cancel_ratio",
                format!("{} must be within [0.0, 1.0]", self.cancel_ratio),
            ));
        }
        if self.users == 0 {
            return Err(ConfigError::invalid("users", "must be greater than zero"));
        }
        if self.target.is_empty() {
            return Err(ConfigError::invalid("target", "must not be empty"));
        }
        Ok(())
    }

    /// Orders the plan would submit over its duration.
    #[must_use]
    pub fn planned_orders(&self) -> u64 {
        self.orders_per_second
            .saturating_mul(self.duration.as_secs())
    }

    /// Expand this flat plan into a full single-region [`LoadScenario`].
    #[must_use]
    pub fn to_scenario(&self) -> LoadScenario {
        let region = RegionConfig {
            name: "primary".to_string(),
            users: u32::try_from(self.users.min(u64::from(u32::MAX))).unwrap_or(u32::MAX),
            cross_region: false,
            base_latency_us: 200,
            jitter_us: 50,
            clock_offset_us: 0,
        };
        LoadScenario {
            seed: 0,
            target: self.target.clone(),
            regions: vec![region],
            market_count: 1,
            orders_per_second: self.orders_per_second,
            cancel_ratio: ratio_from_unit_f64(self.cancel_ratio),
            replace_ratio: Ratio::ZERO,
            duration_secs: self.duration.as_secs(),
            ..LoadScenario::default()
        }
    }
}

/// Convert a unit-interval `f64` (e.g. a CLI `--cancel-ratio 0.7`) into a fixed-point
/// [`Ratio`]. The value is clamped to `[0.0, 1.0]` before scaling, so the rounded
/// product is provably within `[0, RATIO_SCALE]` and the narrowing conversion cannot
/// truncate meaningfully. This is the single float→int boundary in the crate; the
/// deterministic engine operates entirely on the resulting fixed-point value.
#[must_use]
pub fn ratio_from_unit_f64(x: f64) -> Ratio {
    let clamped = if x.is_nan() { 0.0 } else { x.clamp(0.0, 1.0) };
    // Bounded to [0.0, 1_000_000.0]; rounding keeps it within i64 range.
    let scaled = (clamped * (RATIO_SCALE as f64)).round();
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY(range): `scaled` is in [0.0, 1_000_000.0], far inside i64.
    let raw = scaled as i64;
    Ratio::from_raw(raw)
}

fn check_unit_ratio(field: &'static str, r: Ratio) -> Result<(), ConfigError> {
    if r.raw() < 0 {
        return Err(ConfigError::invalid(field, "must not be negative"));
    }
    if r.raw() > RATIO_SCALE {
        return Err(ConfigError::invalid(field, "must not exceed 1.0"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scenario_validates() {
        assert!(LoadScenario::default().validate().is_ok());
    }

    #[test]
    fn toml_round_trips_bit_identically() {
        let s = LoadScenario {
            cancel_ratio: Ratio::from_raw(700_000),
            replace_ratio: Ratio::from_raw(50_000),
            orders_per_second: 123_456,
            ..LoadScenario::default()
        };
        let text = s.to_toml().unwrap();
        let parsed = LoadScenario::from_toml(&text).unwrap();
        assert_eq!(parsed, s);
        // Re-serialise and compare the text itself.
        let text2 = parsed.to_toml().unwrap();
        assert_eq!(text, text2);
    }

    #[test]
    fn ratio_fields_round_trip_exact() {
        let s = "cancel_ratio = 700000\nreplace_ratio = 125000\n";
        let parsed = LoadScenario::from_toml(s).unwrap();
        assert_eq!(parsed.cancel_ratio.raw(), 700_000);
        assert_eq!(parsed.replace_ratio.raw(), 125_000);
        let back = parsed.to_toml().unwrap();
        let reparsed = LoadScenario::from_toml(&back).unwrap();
        assert_eq!(reparsed.cancel_ratio, parsed.cancel_ratio);
        assert_eq!(reparsed.replace_ratio, parsed.replace_ratio);
    }

    #[test]
    fn full_toml_scenario_maps_every_field() {
        let text = r#"
seed = 99
target = "10.0.0.5:9000"
market_count = 4
orders_per_second = 50000
cancel_ratio = 300000
replace_ratio = 100000
clock_method = "NtpOffset"
duration_secs = 120
sample_capacity = 1024

[[regions]]
name = "us-east"
users = 500
cross_region = false
base_latency_us = 150
jitter_us = 40
clock_offset_us = 10

[[regions]]
name = "eu-west"
users = 300
cross_region = true
base_latency_us = 4000
jitter_us = 300
clock_offset_us = -2500

[order_mix]
limit = 60
market = 30
post_only = 5
reduce_only = 5

[burst]
kind = "Bursty"
peak_multiplier = 3
burst_secs = 2
idle_secs = 8

[impairment]
loss_ratio = 10000
dup_ratio = 5000
reorder_ratio = 2000
extra_latency_us = 100
latency_jitter_us = 50

[adversarial]
enabled = true
malformed_ratio = 500000
oversized_ratio = 100000
max_garbage_len = 128

[oracle]
updates_per_second = 5

[market_data]
subscribers = 20
updates_per_second = 1000
"#;
        let s = LoadScenario::from_toml(text).unwrap();
        assert_eq!(s.seed, 99);
        assert_eq!(s.target, "10.0.0.5:9000");
        assert_eq!(s.market_count, 4);
        assert_eq!(s.orders_per_second, 50_000);
        assert_eq!(s.cancel_ratio.raw(), 300_000);
        assert_eq!(s.replace_ratio.raw(), 100_000);
        assert_eq!(s.clock_method, ClockMethod::NtpOffset);
        assert_eq!(s.duration_secs, 120);
        assert_eq!(s.sample_capacity, 1024);
        assert_eq!(s.regions.len(), 2);
        assert_eq!(s.regions[0].name, "us-east");
        assert_eq!(s.regions[0].users, 500);
        assert!(s.regions[1].cross_region);
        assert_eq!(s.regions[1].clock_offset_us, -2500);
        assert_eq!(s.order_mix.limit, 60);
        assert_eq!(s.burst.kind, BurstKind::Bursty);
        assert_eq!(s.burst.peak_multiplier, 3);
        assert_eq!(s.impairment.loss_ratio.raw(), 10_000);
        assert!(s.adversarial.enabled);
        assert_eq!(s.adversarial.max_garbage_len, 128);
        assert_eq!(s.oracle.updates_per_second, 5);
        assert_eq!(s.market_data.subscribers, 20);
    }

    #[test]
    fn rejects_out_of_range_ratio() {
        let text = "cancel_ratio = 2000000\n";
        assert!(LoadScenario::from_toml(text).is_err());
    }

    #[test]
    fn rejects_cancel_plus_replace_over_one() {
        let s = LoadScenario {
            cancel_ratio: Ratio::from_raw(700_000),
            replace_ratio: Ratio::from_raw(400_000),
            ..LoadScenario::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn malformed_toml_is_typed_error() {
        let err = LoadScenario::from_toml("this is not = = toml").unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)));
    }

    #[test]
    fn f64_ratio_conversion_clamps() {
        assert_eq!(ratio_from_unit_f64(0.7).raw(), 700_000);
        assert_eq!(ratio_from_unit_f64(-1.0).raw(), 0);
        assert_eq!(ratio_from_unit_f64(5.0).raw(), RATIO_SCALE);
        assert_eq!(ratio_from_unit_f64(f64::NAN).raw(), 0);
    }

    #[test]
    fn load_config_expands_to_scenario() {
        let c = LoadConfig {
            target: "host:1".to_string(),
            users: 250,
            market: "BTC-PERP".to_string(),
            orders_per_second: 1000,
            cancel_ratio: 0.5,
            duration: Duration::from_secs(30),
        };
        let s = c.to_scenario();
        assert_eq!(s.total_users(), 250);
        assert_eq!(s.cancel_ratio.raw(), 500_000);
        assert_eq!(s.duration_secs, 30);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn order_mix_pick_honors_weights() {
        let mix = OrderMix {
            limit: 80,
            market: 20,
            post_only: 0,
            reduce_only: 0,
        };
        let mut rng = Lcg::new(1);
        let (mut limit, mut market) = (0u32, 0u32);
        for _ in 0..100_000 {
            match mix.pick(&mut rng) {
                OrderType::Limit => limit += 1,
                OrderType::Market => market += 1,
                _ => panic!("unexpected type"),
            }
        }
        // ~80/20 split, 3% tolerance.
        assert!((78_000..82_000).contains(&limit), "limit={limit}");
        assert!((18_000..22_000).contains(&market), "market={market}");
    }

    #[test]
    fn burst_ramp_and_bursty_shape_rate() {
        let ramp = BurstPattern {
            kind: BurstKind::Ramp,
            ..BurstPattern::default()
        };
        assert_eq!(ramp.rate_at(0, 100, 11), 0);
        assert_eq!(ramp.rate_at(10, 100, 11), 100);
        let bursty = BurstPattern {
            kind: BurstKind::Bursty,
            peak_multiplier: 4,
            burst_secs: 2,
            idle_secs: 3,
        };
        assert_eq!(bursty.rate_at(0, 100, 100), 400);
        assert_eq!(bursty.rate_at(1, 100, 100), 400);
        assert_eq!(bursty.rate_at(2, 100, 100), 0);
        assert_eq!(bursty.rate_at(4, 100, 100), 0);
        assert_eq!(bursty.rate_at(5, 100, 100), 400);
    }
}
