//! Load-generation configuration surface.
//!
//! [`LoadConfig`] is the small, backwards-compatible plan the `market-loadgen` CLI
//! constructs directly. [`LoadScenario`] is the full, richly-configurable plan that
//! the engine actually executes: multiple regions, order mix, burst pattern, network
//! impairment, adversarial behaviour, oracle and market-data workloads, and a chosen
//! clock-synchronisation method. Every knob is fixed-point or integer so a scenario
//! round-trips through TOML bit-identically.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
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
        field: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The TOML document could not be parsed.
    #[error("malformed TOML: {0}")]
    Toml(String),
}

impl ConfigError {
    fn invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        ConfigError::Invalid {
            field: field.into(),
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

/// Data-plane mode. Reports retain this value so sink and simulation results cannot
/// be presented as validator capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RunMode {
    /// Deterministic, socket-free planning and testing.
    #[default]
    Simulate,
    /// A live DexOS validator or gateway using production RPC types.
    Validator,
    /// The protocol-conformant test-only reference sink.
    Sink,
}

/// Process role used to execute a resolved scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RunRole {
    /// Execute the agent engine in this process without a control-plane server.
    #[default]
    Local,
    /// Wait for an authenticated plan from a controller.
    Agent,
    /// Partition and coordinate work across remote agents.
    Controller,
}

/// What an endpoint represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TargetKind {
    /// A DexOS validator or gateway.
    #[default]
    Validator,
    /// A test-only loadgen reference sink.
    ReferenceSink,
}

/// TLS 1.3 client settings. File contents are loaded only by the agent during
/// preflight; reports and resolved-plan output redact private-key references.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsClientConfig {
    /// Require TLS. `false` is allowed only for explicit development plaintext.
    pub enabled: bool,
    /// DNS identity expected in the server certificate.
    pub server_name: String,
    /// PEM trust roots.
    pub ca_file: String,
    /// Optional PEM client certificate chain for mTLS.
    pub client_cert_file: String,
    /// Optional PKCS#8 client private key for mTLS.
    pub client_key_file: String,
}

/// One explicit weighted validator, gateway, or reference-sink address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EndpointConfig {
    /// Stable name used in metrics and artifacts.
    pub name: String,
    /// Explicit `host:port`, IPv4, or bracketed IPv6 socket address.
    pub address: String,
    /// Relative share of offered rate and connections.
    pub weight: u32,
    /// Persistent connections opened for every configured source IP.
    pub connections_per_source_ip: u32,
    /// Prevents reference-sink output from being labelled as validator output.
    pub target_kind: TargetKind,
    /// TLS/mTLS client settings.
    pub tls: TlsClientConfig,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            name: "local-validator".to_string(),
            address: "127.0.0.1:9000".to_string(),
            weight: 1,
            connections_per_source_ip: 1,
            target_kind: TargetKind::Validator,
            tls: TlsClientConfig::default(),
        }
    }
}

/// Exact fixed-point proportions of logical trading actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OperationMix {
    /// New-order proportion.
    pub new: Ratio,
    /// Cancel proportion.
    pub cancel: Ratio,
    /// Replace proportion.
    pub replace: Ratio,
}

impl Default for OperationMix {
    fn default() -> Self {
        Self {
            new: Ratio::from_raw(700_000),
            cancel: Ratio::from_raw(200_000),
            replace: Ratio::from_raw(100_000),
        }
    }
}

impl OperationMix {
    /// Sum in millionths. A valid explicit mix equals [`RATIO_SCALE`].
    #[must_use]
    pub const fn total_raw(self) -> i64 {
        self.new
            .raw()
            .saturating_add(self.cancel.raw())
            .saturating_add(self.replace.raw())
    }
}

/// References to funded account/session material. These are references, never
/// embedded private keys or tokens.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountMaterial {
    /// Numeric account id.
    pub account_id: u64,
    /// Signing key file read locally by an agent.
    pub signing_key_file: String,
    /// Optional delegated session public-key file.
    pub session_public_key_file: String,
    /// Optional bearer/control token file.
    pub token_file: String,
}

/// Automated pass/fail gates. A zero throughput/latency value disables that gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdConfig {
    /// Minimum socket-written rate in every steady interval.
    pub minimum_written_per_second: u64,
    /// Minimum acknowledged rate in every steady interval.
    pub minimum_acknowledged_per_second: u64,
    /// Maximum request-to-ack p99 in nanoseconds.
    pub maximum_p99_ns: u64,
    /// Maximum terminal failure ratio in millionths.
    pub maximum_failure_ratio: i64,
}

/// Report destinations and live display options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Artifact directory.
    pub directory: String,
    /// Emit one JSON object per interval.
    pub interval_jsonl: bool,
    /// Emit concise human-readable interval lines.
    pub human: bool,
}

/// Authenticated distributed control-plane settings. Order traffic never traverses
/// this listener; agents connect directly to allow-listed data-plane endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    pub listen: String,
    /// Shared authentication secret file; redacted from resolved output.
    pub token_file: String,
    pub heartbeat_ms: u64,
    pub agent_timeout_ms: u64,
    pub start_delay_ms: u64,
    /// Expected agent control addresses for controller mode.
    pub agents: Vec<String>,
    /// Local data-plane allow-list enforced by agents.
    pub allowed_endpoints: Vec<String>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9910".to_string(),
            token_file: String::new(),
            heartbeat_ms: 1_000,
            agent_timeout_ms: 5_000,
            start_delay_ms: 5_000,
            agents: Vec::new(),
            allowed_endpoints: Vec::new(),
        }
    }
}

/// Deterministic fixed-point market evolution regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum MarketRegime {
    #[default]
    Steady,
    MeanReverting,
    Trending,
    VolatilityClustering,
    JumpShock,
}

/// Synthetic BBO/depth evolution or bounded replay input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MarketModelConfig {
    pub regime: MarketRegime,
    /// Positive fixed-point starting mid price.
    pub initial_mid_raw: i64,
    /// Positive price tick in raw fixed-point units.
    pub tick_size_raw: i64,
    /// Initial spread width in ticks.
    pub spread_ticks: u32,
    /// Synthetic displayed depth levels on each side.
    pub depth_levels: u16,
    /// Base random movement in ticks per logical step.
    pub volatility_ticks: u32,
    /// Signed trend in ticks per logical step.
    pub trend_ticks_per_step: i32,
    /// Mean-reversion divisor; smaller values revert more strongly.
    pub mean_reversion_divisor: u32,
    /// Jump interval in logical steps (`0` disables jumps).
    pub shock_interval: u64,
    /// Absolute jump size in ticks.
    pub shock_ticks: u32,
    /// Optional timestamped CSV replay file.
    pub replay_file: String,
    /// Hard event bound for untrusted replay input.
    pub max_replay_events: usize,
}

impl Default for MarketModelConfig {
    fn default() -> Self {
        Self {
            regime: MarketRegime::Steady,
            initial_mid_raw: 10_000_000_000,
            tick_size_raw: 1_000_000,
            spread_ticks: 2,
            depth_levels: 10,
            volatility_ticks: 2,
            trend_ticks_per_step: 1,
            mean_reversion_divisor: 16,
            shock_interval: 10_000,
            shock_ticks: 100,
            replay_file: String::new(),
            max_replay_events: 1_000_000,
        }
    }
}

/// Realistic side, size, time-in-force, aggressiveness, and market popularity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OrderFlowConfig {
    pub bid_weight: u32,
    pub ask_weight: u32,
    /// Inclusive fixed-point quantity range.
    pub min_quantity_raw: i64,
    pub max_quantity_raw: i64,
    pub gtc_weight: u32,
    pub ioc_weight: u32,
    pub fok_weight: u32,
    /// Price selection relative to BBO.
    pub passive_weight: u32,
    pub at_touch_weight: u32,
    pub aggressive_weight: u32,
    /// Optional per-market weights aligned with `market_ids`.
    pub market_weights: Vec<u32>,
    /// Maximum bounded accepted live orders retained per session.
    pub live_orders_per_session: usize,
}

impl Default for OrderFlowConfig {
    fn default() -> Self {
        Self {
            bid_weight: 1,
            ask_weight: 1,
            min_quantity_raw: 1_000_000,
            max_quantity_raw: 1_000_000_000,
            gtc_weight: 90,
            ioc_weight: 9,
            fok_weight: 1,
            passive_weight: 60,
            at_touch_weight: 30,
            aggressive_weight: 10,
            market_weights: Vec::new(),
            live_orders_per_session: 1024,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            directory: "artifacts/loadgen".to_string(),
            interval_jsonl: true,
            human: true,
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
    /// Local IPv4/IPv6 addresses used for explicit source binding.
    pub source_ips: Vec<String>,
    /// Explicit weighted target endpoints for this region.
    pub endpoints: Vec<EndpointConfig>,
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
            source_ips: Vec::new(),
            endpoints: Vec::new(),
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
    /// Scenario schema. Version 1 is the legacy simulation shape; version 2 adds
    /// production endpoints, identity partitions, phases, and distributed roles.
    pub schema_version: u32,
    /// Data-plane claim/mode.
    pub mode: RunMode,
    /// Process role.
    pub role: RunRole,
    /// Seed for the deterministic RNG. Identical seeds reproduce identical runs.
    pub seed: u64,
    /// Legacy single target. It remains simulation-compatible but is never used to
    /// infer live endpoints in schema version 2.
    pub target: String,
    /// Number of distinct markets traded (>= 1).
    pub market_count: u32,
    /// Explicit market IDs for live production plans.
    pub market_ids: Vec<u32>,
    /// Aggregate base order rate across all regions, orders per second.
    pub orders_per_second: u64,
    /// Fraction of actions that are cancels (fixed-point).
    pub cancel_ratio: Ratio,
    /// Fraction of actions that are replaces (fixed-point).
    pub replace_ratio: Ratio,
    /// Clock-synchronisation method for timestamp correction.
    pub clock_method: ClockMethod,
    /// Measured upper bound for wall-clock synchronization uncertainty. Request
    /// latency remains agent-local and monotonic.
    pub clock_uncertainty_ns: u64,
    /// Total run duration, seconds.
    pub duration_secs: u64,
    /// Warm-up duration before the measured phase.
    pub warm_up_secs: u64,
    /// Maximum bounded drain duration.
    pub drain_timeout_secs: u64,
    /// Post-drain snapshot/reconciliation duration.
    pub cool_down_secs: u64,
    /// Fixed data-plane worker count per agent.
    pub worker_count: u16,
    /// Fixed request queue capacity per connection shard.
    pub connection_queue_capacity: usize,
    /// Maximum correlated requests in flight on one connection.
    pub in_flight_per_connection: u32,
    /// Bounded reconnect attempts after a data-plane transport failure.
    pub reconnect_max_attempts: u16,
    /// Initial deterministic exponential reconnect delay.
    pub reconnect_base_delay_ms: u64,
    /// Maximum reconnect delay including deterministic jitter.
    pub reconnect_max_delay_ms: u64,
    /// Base of this plan's disjoint client-id namespace.
    pub client_id_base: u64,
    /// Initial nonce within each assigned client namespace.
    pub nonce_base: u64,
    /// Stable agent identity included in reports and RNG derivation.
    pub agent_id: String,
    /// Authenticated controller address for agent mode.
    pub controller_address: String,
    /// Optional CPU indices for worker affinity.
    pub cpu_affinity: Vec<u16>,
    /// Fixed capacity of each latency sample buffer (overflow is counted, not grown).
    pub sample_capacity: usize,
    /// Exact new/cancel/replace mix for production plans. `None` selects the legacy
    /// cancel/replace fields for backwards-compatible simulation.
    pub operation_mix: Option<OperationMix>,
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
    /// Fixed-point synthetic market/replay settings.
    pub market_model: MarketModelConfig,
    /// Realistic order-flow distributions.
    pub order_flow: OrderFlowConfig,
    /// Automated pass/fail gates.
    pub thresholds: ThresholdConfig,
    /// Artifact/report output settings.
    pub output: OutputConfig,
    /// Distributed controller/agent authentication, heartbeat, and allow-list.
    pub control: ControlPlaneConfig,
    /// Funded account/session references loaded locally by agents.
    pub accounts: Vec<AccountMaterial>,
    /// Regions that generate load. Never empty after validation. Declared last so
    /// TOML serialization emits it as a trailing array of tables.
    pub regions: Vec<RegionConfig>,
}

impl Default for LoadScenario {
    fn default() -> Self {
        Self {
            schema_version: 1,
            mode: RunMode::Simulate,
            role: RunRole::Local,
            seed: 0,
            target: "127.0.0.1:9000".to_string(),
            regions: vec![RegionConfig::default()],
            market_count: 1,
            market_ids: Vec::new(),
            orders_per_second: 1000,
            cancel_ratio: Ratio::ZERO,
            replace_ratio: Ratio::ZERO,
            order_mix: OrderMix::default(),
            burst: BurstPattern::default(),
            impairment: Impairment::default(),
            adversarial: Adversarial::default(),
            oracle: OracleWorkload::default(),
            market_data: MarketDataWorkload::default(),
            market_model: MarketModelConfig::default(),
            order_flow: OrderFlowConfig::default(),
            clock_method: ClockMethod::default(),
            clock_uncertainty_ns: 0,
            duration_secs: 60,
            warm_up_secs: 0,
            drain_timeout_secs: 10,
            cool_down_secs: 0,
            worker_count: 1,
            connection_queue_capacity: 1024,
            in_flight_per_connection: 1,
            reconnect_max_attempts: 5,
            reconnect_base_delay_ms: 10,
            reconnect_max_delay_ms: 1_000,
            client_id_base: 0,
            nonce_base: 0,
            agent_id: "local".to_string(),
            controller_address: String::new(),
            cpu_affinity: Vec::new(),
            sample_capacity: 65_536,
            operation_mix: None,
            thresholds: ThresholdConfig::default(),
            output: OutputConfig::default(),
            control: ControlPlaneConfig::default(),
            accounts: Vec::new(),
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

    /// Explicit market IDs, or the legacy dense `0..market_count` simulation set.
    #[must_use]
    pub fn effective_market_ids(&self) -> Vec<u32> {
        if self.market_ids.is_empty() {
            (0..self.market_count).collect()
        } else {
            self.market_ids.clone()
        }
    }

    /// Exact operation mix, translating the legacy cancel/replace fields when needed.
    #[must_use]
    pub fn effective_operation_mix(&self) -> OperationMix {
        self.operation_mix.unwrap_or_else(|| OperationMix {
            new: Ratio::from_raw(
                RATIO_SCALE.saturating_sub(
                    self.cancel_ratio
                        .raw()
                        .saturating_add(self.replace_ratio.raw()),
                ),
            ),
            cancel: self.cancel_ratio,
            replace: self.replace_ratio,
        })
    }

    /// Total persistent connections in an explicit production topology.
    #[must_use]
    pub fn total_connections(&self) -> u64 {
        self.regions
            .iter()
            .map(|region| {
                let sources = u64::try_from(region.source_ips.len()).unwrap_or(u64::MAX);
                region.endpoints.iter().fold(0u64, |sum, endpoint| {
                    sum.saturating_add(
                        sources.saturating_mul(u64::from(endpoint.connections_per_source_ip)),
                    )
                })
            })
            .fold(0u64, u64::saturating_add)
    }

    /// Serialize the resolved plan with every private-key/token reference redacted.
    /// This is safe for dry-run output and report provenance.
    pub fn to_redacted_toml(&self) -> Result<String, ConfigError> {
        let mut redacted = self.clone();
        for account in &mut redacted.accounts {
            if !account.signing_key_file.is_empty() {
                account.signing_key_file = "<redacted-signing-key>".to_string();
            }
            if !account.session_public_key_file.is_empty() {
                account.session_public_key_file = "<redacted-session-key>".to_string();
            }
            if !account.token_file.is_empty() {
                account.token_file = "<redacted-token>".to_string();
            }
        }
        if !redacted.control.token_file.is_empty() {
            redacted.control.token_file = "<redacted-control-token>".to_string();
        }
        for region in &mut redacted.regions {
            for endpoint in &mut region.endpoints {
                if !endpoint.tls.client_key_file.is_empty() {
                    endpoint.tls.client_key_file = "<redacted-client-key>".to_string();
                }
            }
        }
        redacted.to_toml()
    }

    /// Validate ranges and normalise empty collections. Ratios are clamped-checked
    /// but not mutated; regions and market count are floored to sane minimums.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] when a ratio is negative or exceeds 1.0, or
    /// when there are no users to drive load.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=2).contains(&self.schema_version) {
            return Err(ConfigError::invalid(
                "schema_version",
                format!(
                    "unsupported version {}; expected 1 or 2",
                    self.schema_version
                ),
            ));
        }
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
        let mix = self.effective_operation_mix();
        check_unit_ratio("operation_mix.new", mix.new)?;
        check_unit_ratio("operation_mix.cancel", mix.cancel)?;
        check_unit_ratio("operation_mix.replace", mix.replace)?;
        if mix.total_raw() != RATIO_SCALE {
            return Err(ConfigError::invalid(
                "operation_mix",
                format!(
                    "new+cancel+replace must total exactly {RATIO_SCALE}; got {}",
                    mix.total_raw()
                ),
            ));
        }
        if self.mode != RunMode::Simulate && self.operation_mix.is_none() {
            return Err(ConfigError::invalid(
                "operation_mix",
                "live schema requires explicit new/cancel/replace ratios",
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
        if self.mode != RunMode::Simulate && self.market_ids.is_empty() {
            return Err(ConfigError::invalid(
                "market_ids",
                "live plans require at least one explicit market ID",
            ));
        }
        let mut market_ids = HashSet::new();
        for (index, market_id) in self.market_ids.iter().enumerate() {
            if !market_ids.insert(*market_id) {
                return Err(ConfigError::invalid(
                    format!("market_ids[{index}]"),
                    format!("duplicate market ID {market_id}"),
                ));
            }
        }
        if self.worker_count == 0 {
            return Err(ConfigError::invalid("worker_count", "must be >= 1"));
        }
        if self.connection_queue_capacity == 0 {
            return Err(ConfigError::invalid(
                "connection_queue_capacity",
                "must be >= 1",
            ));
        }
        if self.in_flight_per_connection == 0 {
            return Err(ConfigError::invalid(
                "in_flight_per_connection",
                "must be >= 1",
            ));
        }
        if self.reconnect_max_attempts != 0
            && (self.reconnect_base_delay_ms == 0
                || self.reconnect_max_delay_ms < self.reconnect_base_delay_ms)
        {
            return Err(ConfigError::invalid(
                "reconnect_base_delay_ms/reconnect_max_delay_ms",
                "enabled reconnect requires 0 < base delay <= maximum delay",
            ));
        }
        if self.duration_secs == 0 {
            return Err(ConfigError::invalid("duration_secs", "must be >= 1"));
        }
        if self.drain_timeout_secs == 0 {
            return Err(ConfigError::invalid("drain_timeout_secs", "must be >= 1"));
        }
        if self.sample_capacity == 0 {
            return Err(ConfigError::invalid("sample_capacity", "must be >= 1"));
        }
        validate_market_and_order_flow(self)?;
        check_unit_ratio(
            "thresholds.maximum_failure_ratio",
            Ratio::from_raw(self.thresholds.maximum_failure_ratio),
        )?;
        if self.role == RunRole::Agent && self.controller_address.is_empty() {
            return Err(ConfigError::invalid(
                "controller_address",
                "agent role requires an authenticated controller address",
            ));
        }
        if self.role != RunRole::Local {
            if self.control.token_file.is_empty() {
                return Err(ConfigError::invalid(
                    "control.token_file",
                    "distributed roles require an authentication secret file",
                ));
            }
            if self.control.heartbeat_ms == 0
                || self.control.agent_timeout_ms < self.control.heartbeat_ms.saturating_mul(2)
            {
                return Err(ConfigError::invalid(
                    "control.heartbeat_ms/agent_timeout_ms",
                    "timeout must be at least two heartbeat intervals",
                ));
            }
            if self.control.start_delay_ms == 0 {
                return Err(ConfigError::invalid(
                    "control.start_delay_ms",
                    "distributed runs require a future synchronized start",
                ));
            }
            let endpoints = self
                .regions
                .iter()
                .flat_map(|region| region.endpoints.iter().map(|endpoint| &endpoint.address));
            for endpoint in endpoints {
                if !self.control.allowed_endpoints.contains(endpoint) {
                    return Err(ConfigError::invalid(
                        "control.allowed_endpoints",
                        format!("configured target `{endpoint}` is not agent-allow-listed"),
                    ));
                }
            }
        }
        if self.mode == RunMode::Validator && self.accounts.is_empty() {
            return Err(ConfigError::invalid(
                "accounts",
                "validator mode requires at least one account/session reference",
            ));
        }
        let mut account_ids = HashSet::new();
        for (index, account) in self.accounts.iter().enumerate() {
            if !account_ids.insert(account.account_id) {
                return Err(ConfigError::invalid(
                    format!("accounts[{index}].account_id"),
                    format!("duplicate account ID {}", account.account_id),
                ));
            }
            if account.signing_key_file.is_empty() {
                return Err(ConfigError::invalid(
                    format!("accounts[{index}].signing_key_file"),
                    "must reference signing material",
                ));
            }
        }
        validate_regions(self)?;
        Ok(())
    }
}

fn validate_market_and_order_flow(scenario: &LoadScenario) -> Result<(), ConfigError> {
    let market = &scenario.market_model;
    if market.initial_mid_raw <= 0 {
        return Err(ConfigError::invalid(
            "market_model.initial_mid_raw",
            "must be positive",
        ));
    }
    if market.tick_size_raw <= 0 {
        return Err(ConfigError::invalid(
            "market_model.tick_size_raw",
            "must be positive",
        ));
    }
    if market.initial_mid_raw % market.tick_size_raw != 0 {
        return Err(ConfigError::invalid(
            "market_model.initial_mid_raw",
            "must be aligned to tick_size_raw",
        ));
    }
    if market.spread_ticks == 0 || market.depth_levels == 0 {
        return Err(ConfigError::invalid(
            "market_model",
            "spread_ticks and depth_levels must be >= 1",
        ));
    }
    if market.mean_reversion_divisor == 0 {
        return Err(ConfigError::invalid(
            "market_model.mean_reversion_divisor",
            "must be >= 1",
        ));
    }
    if !market.replay_file.is_empty() && market.max_replay_events == 0 {
        return Err(ConfigError::invalid(
            "market_model.max_replay_events",
            "replay input requires a nonzero hard event bound",
        ));
    }
    if !market.replay_file.is_empty() {
        let text = std::fs::read_to_string(&market.replay_file).map_err(|error| {
            ConfigError::invalid(
                "market_model.replay_file",
                format!("cannot read replay input: {error}"),
            )
        })?;
        let events =
            crate::market::parse_replay(&text, market.max_replay_events, market.tick_size_raw)
                .map_err(|error| {
                    ConfigError::invalid("market_model.replay_file", error.to_string())
                })?;
        if events.is_empty() {
            return Err(ConfigError::invalid(
                "market_model.replay_file",
                "replay input contains no events",
            ));
        }
        let markets = scenario.effective_market_ids();
        if let Some(event) = events
            .iter()
            .find(|event| !markets.contains(&event.market.get()))
        {
            return Err(ConfigError::invalid(
                "market_model.replay_file",
                format!(
                    "event references unconfigured market {}",
                    event.market.get()
                ),
            ));
        }
    }

    let flow = &scenario.order_flow;
    if u64::from(flow.bid_weight) + u64::from(flow.ask_weight) == 0 {
        return Err(ConfigError::invalid(
            "order_flow.bid_weight+ask_weight",
            "at least one side must have nonzero weight",
        ));
    }
    if flow.min_quantity_raw <= 0 || flow.max_quantity_raw < flow.min_quantity_raw {
        return Err(ConfigError::invalid(
            "order_flow.min_quantity_raw/max_quantity_raw",
            "quantity range must be positive and ordered",
        ));
    }
    if u64::from(flow.gtc_weight) + u64::from(flow.ioc_weight) + u64::from(flow.fok_weight) == 0 {
        return Err(ConfigError::invalid(
            "order_flow.*_weight",
            "at least one time-in-force weight must be nonzero",
        ));
    }
    if u64::from(flow.passive_weight)
        + u64::from(flow.at_touch_weight)
        + u64::from(flow.aggressive_weight)
        == 0
    {
        return Err(ConfigError::invalid(
            "order_flow.*aggressiveness_weight",
            "at least one aggressiveness weight must be nonzero",
        ));
    }
    if flow.live_orders_per_session == 0 {
        return Err(ConfigError::invalid(
            "order_flow.live_orders_per_session",
            "must be >= 1",
        ));
    }
    if !flow.market_weights.is_empty() {
        let markets = scenario.effective_market_ids();
        if flow.market_weights.len() != markets.len() {
            return Err(ConfigError::invalid(
                "order_flow.market_weights",
                format!(
                    "expected one weight for each of {} markets; got {}",
                    markets.len(),
                    flow.market_weights.len()
                ),
            ));
        }
        if flow.market_weights.iter().all(|weight| *weight == 0) {
            return Err(ConfigError::invalid(
                "order_flow.market_weights",
                "at least one market weight must be nonzero",
            ));
        }
    }
    Ok(())
}

fn validate_regions(scenario: &LoadScenario) -> Result<(), ConfigError> {
    let mut region_names = HashSet::new();
    let mut endpoint_names = HashSet::new();
    let mut source_addresses = HashSet::new();
    let mut affinity = HashSet::new();

    if scenario.agent_id.trim().is_empty() {
        return Err(ConfigError::invalid("agent_id", "must not be empty"));
    }
    for (index, cpu) in scenario.cpu_affinity.iter().enumerate() {
        if !affinity.insert(*cpu) {
            return Err(ConfigError::invalid(
                format!("cpu_affinity[{index}]"),
                format!("duplicate CPU index {cpu}"),
            ));
        }
    }

    for (region_index, region) in scenario.regions.iter().enumerate() {
        if region.name.trim().is_empty() {
            return Err(ConfigError::invalid(
                format!("regions[{region_index}].name"),
                "must not be empty",
            ));
        }
        if !region_names.insert(region.name.clone()) {
            return Err(ConfigError::invalid(
                format!("regions[{region_index}].name"),
                format!("duplicate region `{}`", region.name),
            ));
        }

        if scenario.mode != RunMode::Simulate && region.source_ips.is_empty() {
            return Err(ConfigError::invalid(
                format!("regions[{region_index}].source_ips"),
                "live regions require at least one explicit source IP",
            ));
        }
        for (source_index, source) in region.source_ips.iter().enumerate() {
            let ip: IpAddr = source.parse().map_err(|_| {
                ConfigError::invalid(
                    format!("regions[{region_index}].source_ips[{source_index}]"),
                    format!("`{source}` is not an IPv4 or IPv6 address"),
                )
            })?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(ConfigError::invalid(
                    format!("regions[{region_index}].source_ips[{source_index}]"),
                    "unspecified and multicast addresses cannot be source-bound",
                ));
            }
            if !source_addresses.insert(ip) {
                return Err(ConfigError::invalid(
                    format!("regions[{region_index}].source_ips[{source_index}]"),
                    format!("duplicate source IP {ip}"),
                ));
            }
        }

        if scenario.mode != RunMode::Simulate && region.endpoints.is_empty() {
            return Err(ConfigError::invalid(
                format!("regions[{region_index}].endpoints"),
                "live regions require explicit endpoints; validators.toml is never inferred",
            ));
        }
        for (endpoint_index, endpoint) in region.endpoints.iter().enumerate() {
            let prefix = format!("regions[{region_index}].endpoints[{endpoint_index}]");
            if endpoint.name.trim().is_empty() {
                return Err(ConfigError::invalid(
                    format!("{prefix}.name"),
                    "must not be empty",
                ));
            }
            if !endpoint_names.insert(endpoint.name.clone()) {
                return Err(ConfigError::invalid(
                    format!("{prefix}.name"),
                    format!("duplicate endpoint name `{}`", endpoint.name),
                ));
            }
            validate_endpoint_address(&format!("{prefix}.address"), &endpoint.address)?;
            if endpoint.weight == 0 {
                return Err(ConfigError::invalid(
                    format!("{prefix}.weight"),
                    "must be >= 1",
                ));
            }
            if endpoint.connections_per_source_ip == 0 {
                return Err(ConfigError::invalid(
                    format!("{prefix}.connections_per_source_ip"),
                    "must be >= 1",
                ));
            }
            let expected_kind = match scenario.mode {
                RunMode::Sink => Some(TargetKind::ReferenceSink),
                RunMode::Validator => Some(TargetKind::Validator),
                RunMode::Simulate => None,
            };
            if expected_kind.is_some_and(|kind| endpoint.target_kind != kind) {
                return Err(ConfigError::invalid(
                    format!("{prefix}.target_kind"),
                    "endpoint kind does not match scenario mode",
                ));
            }
            if endpoint.tls.enabled {
                if endpoint.tls.server_name.trim().is_empty() {
                    return Err(ConfigError::invalid(
                        format!("{prefix}.tls.server_name"),
                        "TLS requires an expected server name",
                    ));
                }
                if endpoint.tls.ca_file.trim().is_empty() {
                    return Err(ConfigError::invalid(
                        format!("{prefix}.tls.ca_file"),
                        "TLS requires explicit trust roots",
                    ));
                }
            }
            let has_cert = !endpoint.tls.client_cert_file.is_empty();
            let has_key = !endpoint.tls.client_key_file.is_empty();
            if has_cert != has_key {
                return Err(ConfigError::invalid(
                    format!("{prefix}.tls"),
                    "mTLS client certificate and private key must be configured together",
                ));
            }
        }
    }
    Ok(())
}

fn validate_endpoint_address(field: &str, address: &str) -> Result<(), ConfigError> {
    if address.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    let Some((host, port)) = address.rsplit_once(':') else {
        return Err(ConfigError::invalid(
            field,
            "expected an explicit host:port or [IPv6]:port",
        ));
    };
    if host.trim().is_empty() || host.contains(':') {
        return Err(ConfigError::invalid(
            field,
            "IPv6 addresses must be bracketed and every endpoint requires a host",
        ));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| ConfigError::invalid(field, "port must be an integer in 1..=65535"))?;
    if port == 0 {
        return Err(ConfigError::invalid(field, "port 0 is not a usable target"));
    }
    Ok(())
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
            ..RegionConfig::default()
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

    #[test]
    fn production_schema_round_trips_every_surface() {
        let scenario = LoadScenario {
            schema_version: 2,
            mode: RunMode::Validator,
            role: RunRole::Agent,
            seed: 99,
            market_ids: vec![7, 11],
            orders_per_second: 20_000_000,
            operation_mix: Some(OperationMix {
                new: Ratio::from_raw(600_000),
                cancel: Ratio::from_raw(250_000),
                replace: Ratio::from_raw(150_000),
            }),
            warm_up_secs: 30,
            duration_secs: 300,
            drain_timeout_secs: 20,
            cool_down_secs: 5,
            worker_count: 16,
            connection_queue_capacity: 4096,
            in_flight_per_connection: 8,
            client_id_base: 10_000,
            nonce_base: 500,
            agent_id: "agent-west-1".to_string(),
            controller_address: "controller.example:9444".to_string(),
            cpu_affinity: vec![2, 4, 6],
            thresholds: ThresholdConfig {
                minimum_written_per_second: 19_000_000,
                minimum_acknowledged_per_second: 1,
                maximum_p99_ns: 20_000_000,
                maximum_failure_ratio: 100,
            },
            output: OutputConfig {
                directory: "artifacts/test".to_string(),
                interval_jsonl: true,
                human: false,
            },
            control: ControlPlaneConfig {
                token_file: "secret/control.token".to_string(),
                allowed_endpoints: vec!["validator.example:9443".to_string()],
                ..ControlPlaneConfig::default()
            },
            accounts: vec![AccountMaterial {
                account_id: 42,
                signing_key_file: "secret/root.key".to_string(),
                session_public_key_file: "secret/session.pub".to_string(),
                token_file: "secret/token".to_string(),
            }],
            regions: vec![RegionConfig {
                name: "west".to_string(),
                users: 100,
                source_ips: vec!["127.0.0.2".to_string(), "::1".to_string()],
                endpoints: vec![EndpointConfig {
                    name: "validator-a".to_string(),
                    address: "validator.example:9443".to_string(),
                    weight: 2,
                    connections_per_source_ip: 50,
                    target_kind: TargetKind::Validator,
                    tls: TlsClientConfig {
                        enabled: true,
                        server_name: "validator.example".to_string(),
                        ca_file: "ca.pem".to_string(),
                        client_cert_file: "client.pem".to_string(),
                        client_key_file: "secret/client.key".to_string(),
                    },
                }],
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        };
        scenario.validate().unwrap();
        assert_eq!(scenario.total_connections(), 100);
        let text = scenario.to_toml().unwrap();
        let decoded = LoadScenario::from_toml(&text).unwrap();
        assert_eq!(decoded, scenario);
        let redacted = scenario.to_redacted_toml().unwrap();
        assert!(!redacted.contains("secret/root.key"));
        assert!(!redacted.contains("secret/session.pub"));
        assert!(!redacted.contains("secret/token"));
        assert!(!redacted.contains("secret/client.key"));
        assert!(!redacted.contains("secret/control.token"));
        assert!(redacted.contains("<redacted-signing-key>"));
    }

    #[test]
    fn live_validation_reports_exact_nested_field() {
        let mut scenario = LoadScenario {
            schema_version: 2,
            mode: RunMode::Sink,
            operation_mix: Some(OperationMix::default()),
            market_ids: vec![1],
            regions: vec![RegionConfig {
                name: "west".to_string(),
                users: 1,
                source_ips: vec!["127.0.0.2".to_string()],
                endpoints: vec![EndpointConfig {
                    name: "sink".to_string(),
                    address: "missing-port".to_string(),
                    target_kind: TargetKind::ReferenceSink,
                    ..EndpointConfig::default()
                }],
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        };
        let err = scenario.validate().unwrap_err().to_string();
        assert!(err.contains("regions[0].endpoints[0].address"), "{err}");

        scenario.regions[0].endpoints[0].address = "127.0.0.1:9000".to_string();
        scenario.market_ids.push(1);
        let err = scenario.validate().unwrap_err().to_string();
        assert!(err.contains("market_ids[1]"), "{err}");
    }

    #[test]
    fn reference_20m_scenario_is_valid_and_explicit() {
        let text = include_str!("../../../config/loadgen/reference-20m.toml");
        let scenario = LoadScenario::from_toml(text).unwrap();
        assert_eq!(scenario.mode, RunMode::Sink);
        assert_eq!(scenario.role, RunRole::Controller);
        assert_eq!(scenario.duration_secs, 300);
        assert_eq!(scenario.warm_up_secs, 30);
        assert!(scenario.total_connections() >= 10_000);
        assert!(scenario
            .regions
            .iter()
            .all(|region| !region.endpoints.is_empty() && !region.source_ips.is_empty()));
    }
}
