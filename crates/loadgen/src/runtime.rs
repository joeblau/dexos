//! Tokio non-blocking live runner using persistent source-bound connections.

use std::collections::HashMap;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use codec::{FRAME_HEADER_LEN, MAX_RPC_FRAME_PAYLOAD};
use futures_util::stream::{FuturesUnordered, StreamExt};
use proto::{decode_response, RpcError, RpcOk, RpcResponse};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use crate::command::{GeneratedCommand, SessionState};
use crate::config::{EndpointConfig, LoadScenario, RunMode};
use crate::metrics::{
    ActionCounters, ActionHistograms, ConservationError, HistogramMergeError, HistogramSummary,
    LatencyHistogram, OutcomeCounters,
};
use crate::protocol::{ProtocolAdapter, ProtocolSlot};
use crate::scheduler::{OpenLoopScheduler, NANOS_PER_SECOND};
use crate::topology::{
    partition_weighted, preflight_topology, ConnectionAssignment, TopologyError,
};
use crate::Lcg;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const SIGNING_SCRATCH: usize = 4096;
const RPC_SCRATCH: usize = 4096;
const FRAME_CAPACITY: usize = 8192;

trait LiveIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> LiveIo for T {}
type LiveStream = Box<dyn LiveIo>;

#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    #[error("live scenario must use Validator or Sink mode")]
    WrongMode,
    #[error("topology preflight failed: {0}")]
    Topology(#[from] TopologyError),
    #[error("connection {endpoint} from {source_ip} failed: {reason}")]
    Connect {
        endpoint: String,
        source_ip: std::net::IpAddr,
        reason: String,
    },
    #[error("TLS setup failed for `{endpoint}`: {reason}")]
    Tls { endpoint: String, reason: String },
    #[error("live I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("live protocol failed: {0}")]
    Protocol(String),
    #[error("counter conservation failed: {0}")]
    Conservation(#[from] ConservationError),
    #[error("histogram merge failed: {0}")]
    Histogram(#[from] HistogramMergeError),
    #[error("connection task failed: {0}")]
    Task(String),
    #[error("agent topology has {available} connections but partition requires {required}")]
    InsufficientConnections { available: u64, required: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveReport {
    pub mode: RunMode,
    pub target_label: &'static str,
    pub connections: u64,
    pub counters: OutcomeCounters,
    pub rejection_reasons: RejectionCounters,
    pub actions: ActionCounters,
    pub action_queue_delay: ActionLatencyReport,
    pub action_request_to_ack: ActionLatencyReport,
    pub queue_delay: HistogramSummary,
    pub request_to_ack: HistogramSummary,
    pub scheduler_rate_debt: u64,
    pub elapsed_ns: u64,
    pub warmup_socket_written: u64,
    pub warmup_acknowledged: u64,
    pub warmup_failed: u64,
    pub interrupted: bool,
    /// Raw compatible buckets retained for distributed merge and artifacts.
    pub queue_delay_raw: Vec<u64>,
    pub request_to_ack_raw: Vec<u64>,
    pub histogram_max_trackable_ns: u64,
    pub intervals: Vec<IntervalCounters>,
    /// Complete mergeable one-second reports retained for local artifacts and
    /// reconstructed from the distributed agent stream by controllers.
    pub interval_reports: Vec<IntervalReport>,
    pub interval_metrics_lost: u64,
    pub dimensions: Vec<MetricDimension>,
}

/// Exact one-second steady-state deltas. Qualification checks each socket-write
/// interval independently instead of accepting a misleading final average.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct IntervalCounters {
    pub second: u64,
    pub offered: u64,
    pub generated: u64,
    pub queued: u64,
    pub socket_written: u64,
    pub acknowledged: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub timed_out: u64,
    pub generator_failed: u64,
    pub transport_failed_before_write: u64,
    pub transport_failed_after_write: u64,
    pub protocol_failed: u64,
    pub failures: u64,
    pub locally_dropped: u64,
    pub overflow: u64,
}

/// Bounded typed classification of acknowledged protocol rejections. These are
/// diagnostic subsets of `OutcomeCounters::rejected`, not additional terminal
/// outcome buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RejectionCounters {
    pub not_found: u64,
    pub read_only: u64,
    pub backpressure: u64,
    pub invalid_request: u64,
    pub authentication: u64,
    pub internal: u64,
    pub nonce_reused: u64,
    pub overflow: u64,
}

impl RejectionCounters {
    fn record(&mut self, error: &RpcError) {
        let counter = match error {
            RpcError::NotFound => &mut self.not_found,
            RpcError::ReadOnly => &mut self.read_only,
            RpcError::Backpressure => &mut self.backpressure,
            RpcError::MessageTooLarge
            | RpcError::InvalidRequest(_)
            | RpcError::Codec(_)
            | RpcError::UnknownMethod => &mut self.invalid_request,
            RpcError::Unauthorized
            | RpcError::InvalidSignature
            | RpcError::SessionExpired
            | RpcError::OutOfScope
            | RpcError::OverNotional
            | RpcError::OverLeverage => &mut self.authentication,
            RpcError::Internal(_) => &mut self.internal,
            RpcError::NonceReused => &mut self.nonce_reused,
        };
        match counter.checked_add(1) {
            Some(value) => *counter = value,
            None => self.overflow = self.overflow.saturating_add(1),
        }
    }

    pub(crate) fn merge(&mut self, other: &Self) {
        macro_rules! add {
            ($field:ident) => {
                match self.$field.checked_add(other.$field) {
                    Some(value) => self.$field = value,
                    None => {
                        self.$field = u64::MAX;
                        self.overflow = self.overflow.saturating_add(1);
                    }
                }
            };
        }
        add!(not_found);
        add!(read_only);
        add!(backpressure);
        add!(invalid_request);
        add!(authentication);
        add!(internal);
        add!(nonce_reused);
        self.overflow = self.overflow.saturating_add(other.overflow);
    }

    #[must_use]
    pub const fn total(&self) -> u64 {
        self.not_found
            .saturating_add(self.read_only)
            .saturating_add(self.backpressure)
            .saturating_add(self.invalid_request)
            .saturating_add(self.authentication)
            .saturating_add(self.internal)
            .saturating_add(self.nonce_reused)
    }
}

/// Complete off-hot-path interval snapshot. Raw buckets are carried to distributed
/// controllers; human output reads only `counters` and derived summaries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntervalReport {
    pub counters: IntervalCounters,
    pub actions: ActionCounters,
    pub queue_delay: HistogramReport,
    pub request_to_ack: HistogramReport,
    pub action_queue_delay: ActionLatencyReport,
    pub action_request_to_ack: ActionLatencyReport,
    pub dimensions: Vec<MetricDimension>,
}

impl IntervalReport {
    pub(crate) fn valid(&self) -> bool {
        self.queue_delay.rehydrate().is_ok()
            && self.request_to_ack.rehydrate().is_ok()
            && self.queue_delay.summary.overflow == 0
            && self.queue_delay.summary.saturated == 0
            && self.request_to_ack.summary.overflow == 0
            && self.request_to_ack.summary.saturated == 0
            && self.action_queue_delay.valid()
            && self.action_request_to_ack.valid()
            && self
                .actions
                .new_order
                .socket_written
                .saturating_add(self.actions.cancel.socket_written)
                .saturating_add(self.actions.replace.socket_written)
                == self.counters.socket_written
            && self
                .action_queue_delay
                .new_order
                .summary
                .count
                .saturating_add(self.action_queue_delay.cancel.summary.count)
                .saturating_add(self.action_queue_delay.replace.summary.count)
                == self.queue_delay.summary.count
            && self
                .action_request_to_ack
                .new_order
                .summary
                .count
                .saturating_add(self.action_request_to_ack.cancel.summary.count)
                .saturating_add(self.action_request_to_ack.replace.summary.count)
                == self.request_to_ack.summary.count
            && self.dimensions.iter().all(|dimension| {
                dimension.queue_delay.rehydrate().is_ok()
                    && dimension.request_to_ack.rehydrate().is_ok()
                    && dimension.queue_delay.summary.overflow == 0
                    && dimension.queue_delay.summary.saturated == 0
                    && dimension.request_to_ack.summary.overflow == 0
                    && dimension.request_to_ack.summary.saturated == 0
            })
            && dimensions_total(&self.dimensions) == outcome_delta_from_interval(&self.counters)
            && self.dimensions.iter().fold(0u64, |total, dimension| {
                total.saturating_add(dimension.queue_delay.summary.count)
            }) == self.queue_delay.summary.count
            && self.dimensions.iter().fold(0u64, |total, dimension| {
                total.saturating_add(dimension.request_to_ack.summary.count)
            }) == self.request_to_ack.summary.count
    }

    /// Compact artifact form: percentile summaries stay readable while the raw
    /// merge blocks remain on the authenticated control stream.
    #[must_use]
    pub fn to_json(&self) -> String {
        let counters = self.counters;
        let actions = format!(
            "{{\"new\":{},\"cancel\":{},\"replace\":{}}}",
            compact_counter_json(&self.actions.new_order),
            compact_counter_json(&self.actions.cancel),
            compact_counter_json(&self.actions.replace),
        );
        let dimensions = self
            .dimensions
            .iter()
            .map(|dimension| {
                format!(
                    "{{\"region\":\"{}\",\"endpoint\":\"{}\",\"counters\":{},\"queue_delay\":{},\"request_to_ack\":{}}}",
                    crate::util::json_escape(&dimension.region),
                    crate::util::json_escape(&dimension.endpoint),
                    compact_counter_json(&dimension.counters),
                    compact_histogram_json(&dimension.queue_delay.summary),
                    compact_histogram_json(&dimension.request_to_ack.summary),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"second\":{},\"offered\":{},\"generated\":{},\"queued\":{},\"socket_written\":{},\"acknowledged\":{},\"accepted\":{},\"rejected\":{},\"timed_out\":{},\"generator_failed\":{},\"transport_failed_before_write\":{},\"transport_failed_after_write\":{},\"protocol_failed\":{},\"failures\":{},\"locally_dropped\":{},\"overflow\":{},\"queue_delay\":{},\"request_to_ack\":{},\"actions\":{},\"action_queue_delay\":{},\"action_request_to_ack\":{},\"dimensions\":[{}]}}",
            counters.second,
            counters.offered,
            counters.generated,
            counters.queued,
            counters.socket_written,
            counters.acknowledged,
            counters.accepted,
            counters.rejected,
            counters.timed_out,
            counters.generator_failed,
            counters.transport_failed_before_write,
            counters.transport_failed_after_write,
            counters.protocol_failed,
            counters.failures,
            counters.locally_dropped,
            counters.overflow,
            compact_histogram_json(&self.queue_delay.summary),
            compact_histogram_json(&self.request_to_ack.summary),
            actions,
            action_latency_json(&self.action_queue_delay),
            action_latency_json(&self.action_request_to_ack),
            dimensions,
        )
    }
}

/// Serializable raw histogram plus its derived summary. Raw buckets remain the
/// authority whenever workers or agents merge this metric.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistogramReport {
    pub summary: HistogramSummary,
    pub raw: Vec<u64>,
    pub max_trackable_ns: u64,
}

impl HistogramReport {
    pub(crate) fn from_histogram(histogram: &LatencyHistogram) -> Self {
        Self {
            summary: histogram.summary(),
            raw: histogram.raw_buckets().to_vec(),
            max_trackable_ns: histogram.max_trackable_ns(),
        }
    }

    pub(crate) fn rehydrate(&self) -> Result<LatencyHistogram, HistogramMergeError> {
        LatencyHistogram::from_raw_parts(
            self.max_trackable_ns,
            &self.raw,
            self.summary.count,
            self.summary.max,
            self.summary.saturated,
            self.summary.overflow,
        )
    }
}

/// Queue and acknowledgement latency for one action split.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActionLatencyReport {
    pub new_order: HistogramReport,
    pub cancel: HistogramReport,
    pub replace: HistogramReport,
}

impl ActionLatencyReport {
    pub(crate) fn from_histograms(histograms: &ActionHistograms) -> Self {
        Self {
            new_order: HistogramReport::from_histogram(&histograms.new_order),
            cancel: HistogramReport::from_histogram(&histograms.cancel),
            replace: HistogramReport::from_histogram(&histograms.replace),
        }
    }

    fn valid(&self) -> bool {
        [&self.new_order, &self.cancel, &self.replace]
            .into_iter()
            .all(|report| {
                report.summary.overflow == 0
                    && report.summary.saturated == 0
                    && report.rehydrate().is_ok()
            })
    }

    pub(crate) fn rehydrate(&self) -> Result<ActionHistograms, HistogramMergeError> {
        Ok(ActionHistograms {
            new_order: self.new_order.rehydrate()?,
            cancel: self.cancel.rehydrate()?,
            replace: self.replace.rehydrate()?,
        })
    }
}

/// Final counter dimension keyed by stable logical region and endpoint names.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetricDimension {
    pub region: String,
    pub endpoint: String,
    pub counters: OutcomeCounters,
    pub queue_delay: HistogramReport,
    pub request_to_ack: HistogramReport,
}

impl LiveReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.counters.validate_conservation().is_ok()
            && self.rejection_reasons.overflow == 0
            && self.rejection_reasons.total() == self.counters.rejected
            && self
                .dimensions
                .iter()
                .all(|dimension| dimension.counters.validate_conservation().is_ok())
            && dimensions_total(&self.dimensions) == self.counters
            && self.action_queue_delay.valid()
            && self.action_request_to_ack.valid()
            && self.dimensions.iter().all(|dimension| {
                dimension.queue_delay.rehydrate().is_ok()
                    && dimension.request_to_ack.rehydrate().is_ok()
                    && dimension.queue_delay.summary.overflow == 0
                    && dimension.queue_delay.summary.saturated == 0
                    && dimension.request_to_ack.summary.overflow == 0
                    && dimension.request_to_ack.summary.saturated == 0
            })
            && self.queue_delay.overflow == 0
            && self.queue_delay.saturated == 0
            && self.request_to_ack.overflow == 0
            && self.request_to_ack.saturated == 0
            && self.interval_reports.iter().all(IntervalReport::valid)
            && (self.interrupted || self.interval_reports.len() == self.intervals.len())
            && self.interval_metrics_lost == 0
            && self.warmup_failed == 0
            && !self.interrupted
    }

    #[must_use]
    pub fn passes_thresholds(&self, scenario: &LoadScenario) -> bool {
        let seconds = scenario.duration_secs.max(1);
        let written_rate = self.counters.socket_written / seconds;
        let acknowledged_rate = self.counters.acknowledged / seconds;
        let failures = self
            .counters
            .timed_out
            .saturating_add(self.counters.generator_failed)
            .saturating_add(self.counters.transport_failed_before_write)
            .saturating_add(self.counters.transport_failed_after_write)
            .saturating_add(self.counters.protocol_failed)
            .saturating_add(self.counters.locally_dropped);
        let failure_ratio = if self.counters.offered == 0 {
            0
        } else {
            u128::from(failures).saturating_mul(1_000_000) / u128::from(self.counters.offered)
        };
        let every_interval_passes = self.intervals.len()
            == usize::try_from(scenario.duration_secs).unwrap_or(usize::MAX)
            && self.intervals.iter().all(|interval| {
                let interval_failure_ratio = if interval.offered == 0 {
                    0
                } else {
                    u128::from(interval.failures).saturating_mul(1_000_000)
                        / u128::from(interval.offered)
                };
                (scenario.thresholds.minimum_written_per_second == 0
                    || interval.socket_written >= scenario.thresholds.minimum_written_per_second)
                    && (scenario.thresholds.minimum_acknowledged_per_second == 0
                        || interval.acknowledged
                            >= scenario.thresholds.minimum_acknowledged_per_second)
                    && interval_failure_ratio
                        <= u128::try_from(scenario.thresholds.maximum_failure_ratio).unwrap_or(0)
            });
        self.passed()
            && every_interval_passes
            && (scenario.thresholds.minimum_written_per_second == 0
                || written_rate >= scenario.thresholds.minimum_written_per_second)
            && (scenario.thresholds.minimum_acknowledged_per_second == 0
                || acknowledged_rate >= scenario.thresholds.minimum_acknowledged_per_second)
            && (scenario.thresholds.maximum_p99_ns == 0
                || self.request_to_ack.p99 <= scenario.thresholds.maximum_p99_ns)
            && failure_ratio
                <= u128::try_from(scenario.thresholds.maximum_failure_ratio).unwrap_or(0)
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        let actions = format!(
            "{{\"new\":{},\"cancel\":{},\"replace\":{}}}",
            compact_counter_json(&self.actions.new_order),
            compact_counter_json(&self.actions.cancel),
            compact_counter_json(&self.actions.replace),
        );
        let dimensions = self
            .dimensions
            .iter()
            .map(|dimension| {
                format!(
                    "{{\"region\":\"{}\",\"endpoint\":\"{}\",\"counters\":{},\"queue_delay\":{},\"request_to_ack\":{}}}",
                    crate::util::json_escape(&dimension.region),
                    crate::util::json_escape(&dimension.endpoint),
                    compact_counter_json(&dimension.counters),
                    compact_histogram_json(&dimension.queue_delay.summary),
                    compact_histogram_json(&dimension.request_to_ack.summary),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"mode\":\"{}\",\"target\":\"{}\",\"connections\":{},\
             \"offered\":{},\"generated\":{},\"queued\":{},\"socket_written\":{},\
             \"acknowledged\":{},\"accepted\":{},\"rejected\":{},\"timed_out\":{},\
             \"generator_failed\":{},\"transport_failed_before_write\":{},\
             \"transport_failed_after_write\":{},\"protocol_failed\":{},\
             \"locally_dropped\":{},\"scheduler_rate_debt\":{},\"elapsed_ns\":{},\
             \"interval_count\":{},\"interval_metrics_lost\":{},\
             \"warmup_socket_written\":{},\"warmup_acknowledged\":{},\"warmup_failed\":{},\
             \"interrupted\":{},\"rejection_reasons\":{},\
             \"actions\":{},\
             \"action_queue_delay\":{},\"action_request_to_ack\":{},\
             \"dimensions\":[{}],\
             \"queue_delay\":{},\"request_to_ack\":{}}}",
            match self.mode {
                RunMode::Sink => "sink",
                RunMode::Validator => "validator",
                RunMode::Simulate => "simulate",
            },
            self.target_label,
            self.connections,
            self.counters.offered,
            self.counters.generated,
            self.counters.queued,
            self.counters.socket_written,
            self.counters.acknowledged,
            self.counters.accepted,
            self.counters.rejected,
            self.counters.timed_out,
            self.counters.generator_failed,
            self.counters.transport_failed_before_write,
            self.counters.transport_failed_after_write,
            self.counters.protocol_failed,
            self.counters.locally_dropped,
            self.scheduler_rate_debt,
            self.elapsed_ns,
            self.intervals.len(),
            self.interval_metrics_lost,
            self.warmup_socket_written,
            self.warmup_acknowledged,
            self.warmup_failed,
            self.interrupted,
            rejection_reason_json(&self.rejection_reasons),
            actions,
            action_latency_json(&self.action_queue_delay),
            action_latency_json(&self.action_request_to_ack),
            dimensions,
            compact_histogram_json(&self.queue_delay),
            compact_histogram_json(&self.request_to_ack),
        )
    }
}

fn rejection_reason_json(reasons: &RejectionCounters) -> String {
    format!(
        "{{\"not_found\":{},\"read_only\":{},\"backpressure\":{},\"invalid_request\":{},\"authentication\":{},\"internal\":{},\"nonce_reused\":{},\"overflow\":{}}}",
        reasons.not_found,
        reasons.read_only,
        reasons.backpressure,
        reasons.invalid_request,
        reasons.authentication,
        reasons.internal,
        reasons.nonce_reused,
        reasons.overflow,
    )
}

fn compact_histogram_json(summary: &HistogramSummary) -> String {
    format!(
        "{{\"count\":{},\"p50\":{},\"p95\":{},\"p99\":{},\"p999\":{},\"max\":{},\"saturated\":{},\"overflow\":{}}}",
        summary.count,
        summary.p50,
        summary.p95,
        summary.p99,
        summary.p999,
        summary.max,
        summary.saturated,
        summary.overflow,
    )
}

fn action_latency_json(report: &ActionLatencyReport) -> String {
    format!(
        "{{\"new\":{},\"cancel\":{},\"replace\":{}}}",
        compact_histogram_json(&report.new_order.summary),
        compact_histogram_json(&report.cancel.summary),
        compact_histogram_json(&report.replace.summary),
    )
}

fn compact_counter_json(counters: &OutcomeCounters) -> String {
    format!(
        "{{\"offered\":{},\"generated\":{},\"queued\":{},\"socket_written\":{},\"acknowledged\":{},\"accepted\":{},\"rejected\":{},\"timed_out\":{},\"generator_failed\":{},\"transport_failed_before_write\":{},\"transport_failed_after_write\":{},\"protocol_failed\":{},\"locally_dropped\":{}}}",
        counters.offered,
        counters.generated,
        counters.queued,
        counters.socket_written,
        counters.acknowledged,
        counters.accepted,
        counters.rejected,
        counters.timed_out,
        counters.generator_failed,
        counters.transport_failed_before_write,
        counters.transport_failed_after_write,
        counters.protocol_failed,
        counters.locally_dropped,
    )
}

struct ConnectionReport {
    counters: OutcomeCounters,
    rejection_reasons: RejectionCounters,
    actions: ActionCounters,
    action_queue_delay: Box<ActionHistograms>,
    action_request_to_ack: Box<ActionHistograms>,
    queue_delay: LatencyHistogram,
    request_to_ack: LatencyHistogram,
    rate_debt: u64,
    intervals: Vec<IntervalCounters>,
    warmup_socket_written: u64,
    warmup_acknowledged: u64,
    warmup_failed: u64,
    dimensions: Vec<ConnectionDimension>,
}

#[derive(Debug, Clone)]
struct ConnectionDimension {
    region_index: usize,
    endpoint_index: usize,
    counters: OutcomeCounters,
    queue_delay: LatencyHistogram,
    request_to_ack: LatencyHistogram,
}

/// A startup-resolved route for one logical connection. Alternatives stay within
/// the configured region and source-address family, so failover never performs DNS
/// or local-interface discovery during the timed phase.
#[derive(Debug, Clone)]
struct EndpointRoute {
    assignment: ConnectionAssignment,
    endpoint: EndpointConfig,
}

struct Pending {
    request_id: u64,
    command: GeneratedCommand,
    slot: ProtocolSlot,
    written_at: Instant,
}

#[derive(Debug, Clone, Copy, Default)]
struct WarmupStats {
    socket_written: u64,
    acknowledged: u64,
    failed: u64,
}

#[derive(Debug, Clone)]
struct ConnectionInterval {
    delta: IntervalCounters,
    actions: ActionCounters,
    queue_delay: Box<LatencyHistogram>,
    request_to_ack: Box<LatencyHistogram>,
    action_queue_delay: Box<ActionHistograms>,
    action_request_to_ack: Box<ActionHistograms>,
    region_index: usize,
    endpoint_index: usize,
    complete: bool,
}

struct IntervalCollection {
    reports: Vec<IntervalReport>,
    lost: u64,
}

/// Execute one local live run. The same function is used by distributed agents after
/// their plan is partitioned; it never invokes the deterministic simulator.
pub async fn run_local_live(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
) -> Result<LiveReport, LiveError> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_live_with_connection_limit(scenario, adapter, None, shutdown_rx, None).await
}

/// Cooperatively stop offering new operations when signalled, then use the normal
/// bounded drain and final counter reconciliation path.
pub async fn run_local_live_with_shutdown(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
    shutdown: watch::Receiver<bool>,
) -> Result<LiveReport, LiveError> {
    run_live_with_connection_limit(scenario, adapter, None, shutdown, None).await
}

/// Local runner with bounded, aggregate one-second snapshots delivered while the
/// steady phase is still running. A full output channel is treated as metric loss.
pub async fn run_local_live_with_progress(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
    shutdown: watch::Receiver<bool>,
    progress: mpsc::Sender<IntervalReport>,
) -> Result<LiveReport, LiveError> {
    run_live_with_connection_limit(scenario, adapter, None, shutdown, Some(progress)).await
}

/// Run an agent's exact connection partition using its local topology. Local files,
/// source addresses, credentials, and endpoint allow-lists never cross the control
/// plane; the controller assigns only a bounded count and identity/rate namespace.
pub async fn run_partitioned_live(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
    connection_count: u64,
) -> Result<LiveReport, LiveError> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_live_with_connection_limit(scenario, adapter, Some(connection_count), shutdown_rx, None)
        .await
}

/// Distributed-agent variant with the same cooperative stop and bounded-drain
/// behavior used by local mode.
pub async fn run_partitioned_live_with_shutdown(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
    connection_count: u64,
    shutdown: watch::Receiver<bool>,
) -> Result<LiveReport, LiveError> {
    run_live_with_connection_limit(scenario, adapter, Some(connection_count), shutdown, None).await
}

/// Partitioned runner with live interval snapshots for the controller stream.
pub async fn run_partitioned_live_with_progress(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
    connection_count: u64,
    shutdown: watch::Receiver<bool>,
    progress: mpsc::Sender<IntervalReport>,
) -> Result<LiveReport, LiveError> {
    run_live_with_connection_limit(
        scenario,
        adapter,
        Some(connection_count),
        shutdown,
        Some(progress),
    )
    .await
}

async fn run_live_with_connection_limit(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
    connection_count: Option<u64>,
    shutdown: watch::Receiver<bool>,
    progress: Option<mpsc::Sender<IntervalReport>>,
) -> Result<LiveReport, LiveError> {
    scenario
        .validate()
        .map_err(|error| LiveError::Protocol(error.to_string()))?;
    if scenario.mode == RunMode::Simulate {
        return Err(LiveError::WrongMode);
    }
    let mut topology = preflight_topology(scenario)?;
    if let Some(required) = connection_count {
        let available = u64::try_from(topology.connections.len()).unwrap_or(u64::MAX);
        if available < required {
            return Err(LiveError::InsufficientConnections {
                available,
                required,
            });
        }
        let required = usize::try_from(required).unwrap_or(usize::MAX);
        if required < topology.connections.len() {
            let available = topology.connections.len();
            let mut selected = Vec::with_capacity(required);
            let mut source = topology.connections.into_iter();
            let mut next = source.next();
            for index in 0..available {
                let Some(assignment) = next.take() else { break };
                let lower = index.saturating_mul(required) / available;
                let upper = index.saturating_add(1).saturating_mul(required) / available;
                if upper > lower {
                    selected.push(assignment);
                }
                next = source.next();
            }
            topology.connections = selected;
        }
    }
    let started = Instant::now();
    let rates = connection_rates(scenario, &topology.connections)?;
    let interval_capacity = topology.connections.len().saturating_mul(2).max(1);
    let (interval_tx, interval_rx) = mpsc::channel(interval_capacity);
    let interval_collector = tokio::spawn(collect_connection_intervals(
        interval_rx,
        Arc::new(scenario.clone()),
        u64::try_from(topology.connections.len()).unwrap_or(u64::MAX),
        progress,
    ));
    let worker_count = usize::from(scenario.worker_count)
        .min(topology.connections.len())
        .max(1);
    let route_templates = topology
        .connections
        .iter()
        .map(|assignment| {
            (
                (
                    assignment.region_index,
                    assignment.endpoint_index,
                    assignment.source_ip,
                ),
                assignment.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut shards = (0..worker_count)
        .map(|_| Vec::new())
        .collect::<Vec<Vec<(usize, Vec<EndpointRoute>)>>>();
    for (index, assignment) in topology.connections.into_iter().enumerate() {
        let mut routes =
            Vec::with_capacity(scenario.regions[assignment.region_index].endpoints.len());
        routes.push(EndpointRoute {
            endpoint: scenario.regions[assignment.region_index].endpoints
                [assignment.endpoint_index]
                .clone(),
            assignment: assignment.clone(),
        });
        for (endpoint_index, endpoint) in scenario.regions[assignment.region_index]
            .endpoints
            .iter()
            .enumerate()
        {
            if endpoint_index == assignment.endpoint_index {
                continue;
            }
            let Some(template) = route_templates.get(&(
                assignment.region_index,
                endpoint_index,
                assignment.source_ip,
            )) else {
                continue;
            };
            let mut fallback = template.clone();
            fallback.connection_index = assignment.connection_index;
            routes.push(EndpointRoute {
                assignment: fallback,
                endpoint: endpoint.clone(),
            });
        }
        shards[index % worker_count].push((index, routes));
    }
    let shared_scenario = Arc::new(scenario.clone());
    let mut tasks = JoinSet::new();
    for shard in shards {
        let local_scenario = Arc::clone(&shared_scenario);
        let local_adapter = adapter.clone();
        let local_rates = rates.clone();
        let local_shutdown = shutdown.clone();
        let local_interval_tx = interval_tx.clone();
        tasks.spawn(async move {
            run_worker(
                shard,
                local_scenario,
                local_adapter,
                &local_rates,
                local_shutdown,
                local_interval_tx,
            )
            .await
        });
    }
    drop(interval_tx);

    let mut counters = OutcomeCounters::default();
    let mut rejection_reasons = RejectionCounters::default();
    let mut actions = ActionCounters::default();
    let mut action_queue_delay = Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND));
    let mut action_request_to_ack = Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND));
    let mut queue_delay = LatencyHistogram::new(60 * NANOS_PER_SECOND);
    let mut request_to_ack = LatencyHistogram::new(60 * NANOS_PER_SECOND);
    let mut rate_debt = 0u64;
    let mut warmup_socket_written = 0u64;
    let mut warmup_acknowledged = 0u64;
    let mut warmup_failed = 0u64;
    let mut dimensions = Vec::new();
    let mut intervals =
        vec![IntervalCounters::default(); usize::try_from(scenario.duration_secs).unwrap_or(0)];
    for (second, interval) in intervals.iter_mut().enumerate() {
        interval.second = u64::try_from(second).unwrap_or(u64::MAX);
    }
    while let Some(result) = tasks.join_next().await {
        let report = result.map_err(|error| LiveError::Task(error.to_string()))??;
        counters.merge(&report.counters);
        rejection_reasons.merge(&report.rejection_reasons);
        actions.new_order.merge(&report.actions.new_order);
        actions.cancel.merge(&report.actions.cancel);
        actions.replace.merge(&report.actions.replace);
        action_queue_delay.merge(&report.action_queue_delay)?;
        action_request_to_ack.merge(&report.action_request_to_ack)?;
        queue_delay.merge(&report.queue_delay)?;
        request_to_ack.merge(&report.request_to_ack)?;
        rate_debt = rate_debt.saturating_add(report.rate_debt);
        warmup_socket_written = warmup_socket_written.saturating_add(report.warmup_socket_written);
        warmup_acknowledged = warmup_acknowledged.saturating_add(report.warmup_acknowledged);
        warmup_failed = warmup_failed.saturating_add(report.warmup_failed);
        for dimension in report.dimensions {
            merge_connection_dimension(&mut dimensions, dimension)?;
        }
        for delta in report.intervals {
            merge_interval(&mut intervals, delta);
        }
    }
    if scenario.cool_down_secs != 0 {
        tokio::time::sleep(Duration::from_secs(scenario.cool_down_secs)).await;
    }
    counters.validate_conservation()?;
    let dimensions = dimensions
        .into_iter()
        .map(|dimension| MetricDimension {
            region: scenario.regions[dimension.region_index].name.clone(),
            endpoint: scenario.regions[dimension.region_index].endpoints[dimension.endpoint_index]
                .name
                .clone(),
            counters: dimension.counters,
            queue_delay: HistogramReport::from_histogram(&dimension.queue_delay),
            request_to_ack: HistogramReport::from_histogram(&dimension.request_to_ack),
        })
        .collect();
    let mut interval_collection = interval_collector
        .await
        .map_err(|error| LiveError::Task(error.to_string()))?;
    if interval_collection
        .reports
        .iter()
        .map(|report| report.counters)
        .collect::<Vec<_>>()
        != intervals
    {
        interval_collection.lost = interval_collection.lost.saturating_add(1);
    }
    Ok(LiveReport {
        mode: scenario.mode,
        target_label: match scenario.mode {
            RunMode::Sink => "reference-sink-test-only",
            RunMode::Validator => "validator",
            RunMode::Simulate => "simulation",
        },
        connections: u64::try_from(rates.len()).unwrap_or(u64::MAX),
        counters,
        rejection_reasons,
        actions,
        action_queue_delay: ActionLatencyReport::from_histograms(&action_queue_delay),
        action_request_to_ack: ActionLatencyReport::from_histograms(&action_request_to_ack),
        queue_delay: queue_delay.summary(),
        request_to_ack: request_to_ack.summary(),
        scheduler_rate_debt: rate_debt,
        elapsed_ns: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        queue_delay_raw: queue_delay.raw_buckets().to_vec(),
        request_to_ack_raw: request_to_ack.raw_buckets().to_vec(),
        histogram_max_trackable_ns: queue_delay.max_trackable_ns(),
        intervals,
        interval_reports: interval_collection.reports,
        interval_metrics_lost: interval_collection.lost,
        warmup_socket_written,
        warmup_acknowledged,
        warmup_failed,
        interrupted: *shutdown.borrow(),
        dimensions,
    })
}

fn connection_rates(
    scenario: &LoadScenario,
    assignments: &[ConnectionAssignment],
) -> Result<Vec<u64>, LiveError> {
    if assignments.is_empty() {
        return Err(LiveError::Protocol("no connection assignments".to_string()));
    }
    let mut output = vec![0u64; assignments.len()];
    let region_weights = scenario
        .regions
        .iter()
        .enumerate()
        .map(|(region, config)| {
            if assignments
                .iter()
                .any(|assignment| assignment.region_index == region)
            {
                u64::from(config.users)
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    let region_rates = partition_weighted(scenario.orders_per_second, &region_weights)?;
    for (region_index, region) in scenario.regions.iter().enumerate() {
        let endpoint_weights = region
            .endpoints
            .iter()
            .enumerate()
            .map(|(endpoint, config)| {
                if assignments.iter().any(|assignment| {
                    assignment.region_index == region_index && assignment.endpoint_index == endpoint
                }) {
                    u64::from(config.weight)
                } else {
                    0
                }
            })
            .collect::<Vec<_>>();
        if endpoint_weights.iter().all(|weight| *weight == 0) {
            continue;
        }
        let endpoint_rates = partition_weighted(region_rates[region_index], &endpoint_weights)?;
        for (endpoint_index, endpoint_rate) in endpoint_rates.into_iter().enumerate() {
            let indices = assignments
                .iter()
                .enumerate()
                .filter_map(|(index, assignment)| {
                    (assignment.region_index == region_index
                        && assignment.endpoint_index == endpoint_index)
                        .then_some(index)
                })
                .collect::<Vec<_>>();
            if indices.is_empty() {
                continue;
            }
            let shares = partition_weighted(endpoint_rate, &vec![1; indices.len()])?;
            for (index, share) in indices.into_iter().zip(shares) {
                output[index] = share;
            }
        }
    }
    if output.iter().sum::<u64>() != scenario.orders_per_second {
        return Err(LiveError::Protocol(
            "connection rate partition lost a remainder".to_string(),
        ));
    }
    Ok(output)
}

async fn run_worker(
    shard: Vec<(usize, Vec<EndpointRoute>)>,
    scenario: Arc<LoadScenario>,
    adapter: ProtocolAdapter,
    rates: &[u64],
    shutdown: watch::Receiver<bool>,
    interval_tx: mpsc::Sender<ConnectionInterval>,
) -> Result<ConnectionReport, LiveError> {
    let mut connections = FuturesUnordered::new();
    for (index, routes) in shard {
        connections.push(run_connection(
            routes,
            Arc::clone(&scenario),
            adapter.clone(),
            rates[index],
            u32::try_from(index).unwrap_or(u32::MAX),
            shutdown.clone(),
            interval_tx.clone(),
        ));
    }
    let mut counters = OutcomeCounters::default();
    let mut rejection_reasons = RejectionCounters::default();
    let mut actions = ActionCounters::default();
    let mut action_queue_delay = Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND));
    let mut action_request_to_ack = Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND));
    let mut queue_delay = LatencyHistogram::new(60 * NANOS_PER_SECOND);
    let mut request_to_ack = LatencyHistogram::new(60 * NANOS_PER_SECOND);
    let mut rate_debt = 0u64;
    let mut warmup_socket_written = 0u64;
    let mut warmup_acknowledged = 0u64;
    let mut warmup_failed = 0u64;
    let mut dimensions = Vec::new();
    let mut intervals =
        vec![IntervalCounters::default(); usize::try_from(scenario.duration_secs).unwrap_or(0)];
    for (second, interval) in intervals.iter_mut().enumerate() {
        interval.second = u64::try_from(second).unwrap_or(u64::MAX);
    }
    while let Some(report) = connections.next().await {
        let report = report?;
        counters.merge(&report.counters);
        rejection_reasons.merge(&report.rejection_reasons);
        actions.new_order.merge(&report.actions.new_order);
        actions.cancel.merge(&report.actions.cancel);
        actions.replace.merge(&report.actions.replace);
        action_queue_delay.merge(&report.action_queue_delay)?;
        action_request_to_ack.merge(&report.action_request_to_ack)?;
        queue_delay.merge(&report.queue_delay)?;
        request_to_ack.merge(&report.request_to_ack)?;
        rate_debt = rate_debt.saturating_add(report.rate_debt);
        warmup_socket_written = warmup_socket_written.saturating_add(report.warmup_socket_written);
        warmup_acknowledged = warmup_acknowledged.saturating_add(report.warmup_acknowledged);
        warmup_failed = warmup_failed.saturating_add(report.warmup_failed);
        for dimension in report.dimensions {
            merge_connection_dimension(&mut dimensions, dimension)?;
        }
        for delta in report.intervals {
            merge_interval(&mut intervals, delta);
        }
    }
    counters.validate_conservation()?;
    Ok(ConnectionReport {
        counters,
        rejection_reasons,
        actions,
        action_queue_delay,
        action_request_to_ack,
        queue_delay,
        request_to_ack,
        rate_debt,
        intervals,
        warmup_socket_written,
        warmup_acknowledged,
        warmup_failed,
        dimensions,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    routes: Vec<EndpointRoute>,
    scenario: Arc<LoadScenario>,
    adapter: ProtocolAdapter,
    rate: u64,
    connection_id: u32,
    shutdown: watch::Receiver<bool>,
    interval_tx: mpsc::Sender<ConnectionInterval>,
) -> Result<ConnectionReport, LiveError> {
    let primary = routes
        .first()
        .ok_or_else(|| LiveError::Protocol("connection has no endpoint routes".to_string()))?;
    let stream = connect_endpoint(&primary.assignment, &primary.endpoint).await?;
    drive_connection(
        stream,
        routes,
        scenario,
        adapter,
        rate,
        connection_id,
        shutdown,
        interval_tx,
    )
    .await
}

async fn connect_endpoint(
    assignment: &ConnectionAssignment,
    endpoint: &EndpointConfig,
) -> Result<LiveStream, LiveError> {
    let tcp = connect_source_bound(assignment).await?;
    if endpoint.tls.enabled {
        let connector = tls_connector(endpoint)?;
        let name = ServerName::try_from(endpoint.tls.server_name.clone()).map_err(|error| {
            LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: error.to_string(),
            }
        })?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
            .await
            .map_err(|_| LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: "handshake timeout".to_string(),
            })?
            .map_err(|error| LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: error.to_string(),
            })?;
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(tcp))
    }
}

async fn reconnect_endpoint(
    routes: &[EndpointRoute],
    active_route: usize,
    scenario: &LoadScenario,
    connection_id: u32,
) -> Option<(LiveStream, usize)> {
    // Once an established route becomes unhealthy, alternatives are tried first.
    // The former route is retried last, bounding failover to
    // routes.len() * reconnect_max_attempts and avoiding an endless flap loop.
    for offset in 1..=routes.len() {
        let route_index = active_route.saturating_add(offset) % routes.len();
        let route = &routes[route_index];
        for attempt in 0..scenario.reconnect_max_attempts {
            let exponent = u32::from(attempt.min(20));
            let exponential = scenario
                .reconnect_base_delay_ms
                .saturating_mul(1u64 << exponent)
                .min(scenario.reconnect_max_delay_ms);
            let jitter_window = scenario.reconnect_base_delay_ms.saturating_add(1);
            let jitter = (u64::from(connection_id)
                .wrapping_mul(0x9E37_79B9)
                .wrapping_add(u64::from(attempt).wrapping_mul(0x85EB_CA6B))
                .wrapping_add(u64::try_from(route_index).unwrap_or(u64::MAX)))
                % jitter_window;
            tokio::time::sleep(Duration::from_millis(
                exponential
                    .saturating_add(jitter)
                    .min(scenario.reconnect_max_delay_ms),
            ))
            .await;
            if let Ok(stream) = connect_endpoint(&route.assignment, &route.endpoint).await {
                return Some((stream, route_index));
            }
        }
    }
    None
}

async fn connect_source_bound(assignment: &ConnectionAssignment) -> Result<TcpStream, LiveError> {
    let socket = if assignment.source_ip.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|error| LiveError::Connect {
        endpoint: assignment.endpoint_name.clone(),
        source_ip: assignment.source_ip,
        reason: error.to_string(),
    })?;
    socket
        .bind(SocketAddr::new(assignment.source_ip, 0))
        .map_err(|error| LiveError::Connect {
            endpoint: assignment.endpoint_name.clone(),
            source_ip: assignment.source_ip,
            reason: format!("source bind: {error}"),
        })?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(assignment.target))
        .await
        .map_err(|_| LiveError::Connect {
            endpoint: assignment.endpoint_name.clone(),
            source_ip: assignment.source_ip,
            reason: "connect timeout".to_string(),
        })?
        .map_err(|error| LiveError::Connect {
            endpoint: assignment.endpoint_name.clone(),
            source_ip: assignment.source_ip,
            reason: error.to_string(),
        })?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

#[allow(clippy::too_many_arguments)]
async fn prime_connection(
    stream: &mut LiveStream,
    scenario: &LoadScenario,
    adapter: &ProtocolAdapter,
    session: &mut SessionState,
    ignored_rng: &mut Lcg,
    rate: u64,
    next_request_id: &mut u64,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<WarmupStats, LiveError> {
    let duration = Duration::from_secs(scenario.warm_up_secs);
    if duration.is_zero() {
        return Ok(WarmupStats::default());
    }
    if rate == 0 {
        tokio::select! {
            () = tokio::time::sleep(duration) => {}
            _ = shutdown.changed() => {}
        }
        return Ok(WarmupStats::default());
    }
    let mut stats = WarmupStats::default();
    let mut slot = ProtocolSlot::new(SIGNING_SCRATCH, RPC_SCRATCH, FRAME_CAPACITY);
    let mut read_buffer = Vec::with_capacity(FRAME_HEADER_LEN + MAX_RPC_FRAME_PAYLOAD);
    let started = Instant::now();
    let deadline = started + duration;
    let spacing = Duration::from_nanos(NANOS_PER_SECOND.checked_div(rate).unwrap_or(1).max(1));
    let mut scheduled = started;
    while Instant::now() < deadline {
        if *shutdown.borrow() {
            break;
        }
        let now = Instant::now();
        if scheduled > now {
            tokio::select! {
                () = tokio::time::sleep(scheduled.duration_since(now)) => {}
                _ = shutdown.changed() => continue,
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        let command = session.next_command(ignored_rng, scenario);
        if adapter
            .encode_into_slot(*next_request_id, &command, &mut slot)
            .is_err()
        {
            session.release_pending(&command);
            stats.failed = stats.failed.saturating_add(1);
            *next_request_id = next_request_id.saturating_add(1);
            scheduled += spacing;
            continue;
        }
        if let Err(error) = stream.write_all(slot.frame()).await {
            session.release_pending(&command);
            return Err(LiveError::Io(error));
        }
        stats.socket_written = stats.socket_written.saturating_add(1);
        let response = tokio::time::timeout(ACK_TIMEOUT, read_response(stream, &mut read_buffer))
            .await
            .map_err(|_| LiveError::Protocol("warm-up acknowledgement timeout".to_string()))??;
        if response.request_id != *next_request_id {
            session.release_pending(&command);
            return Err(LiveError::Protocol(format!(
                "warm-up response correlation mismatch: expected {}, got {}",
                *next_request_id, response.request_id
            )));
        }
        match response.result {
            Ok(RpcOk::CommandAck(ack)) => {
                stats.acknowledged = stats.acknowledged.saturating_add(1);
                if adapter
                    .apply_accepted_command(session, &command, &ack)
                    .is_err()
                {
                    stats.failed = stats.failed.saturating_add(1);
                }
            }
            Err(_) => {
                session.release_pending(&command);
                stats.acknowledged = stats.acknowledged.saturating_add(1);
                stats.failed = stats.failed.saturating_add(1);
            }
            Ok(_) => {
                session.release_pending(&command);
                stats.failed = stats.failed.saturating_add(1);
            }
        }
        *next_request_id = next_request_id.saturating_add(1);
        scheduled += spacing;
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
async fn drive_connection(
    mut stream: LiveStream,
    routes: Vec<EndpointRoute>,
    scenario: Arc<LoadScenario>,
    adapter: ProtocolAdapter,
    rate: u64,
    connection_id: u32,
    mut shutdown: watch::Receiver<bool>,
    interval_tx: mpsc::Sender<ConnectionInterval>,
) -> Result<ConnectionReport, LiveError> {
    let mut active_route = 0usize;
    let depth = usize::try_from(scenario.in_flight_per_connection)
        .unwrap_or(1)
        .min(scenario.connection_queue_capacity)
        .max(1);
    let mut free = Vec::with_capacity(depth);
    for _ in 0..depth {
        free.push(ProtocolSlot::new(
            SIGNING_SCRATCH,
            RPC_SCRATCH,
            FRAME_CAPACITY,
        ));
    }
    let mut pending = Vec::with_capacity(depth);
    let session_id = connection_id;
    let mut session = SessionState::with_partition(
        session_id,
        &scenario,
        &scenario.agent_id,
        u16::try_from(connection_id % u32::from(scenario.worker_count.max(1))).unwrap_or(0),
        false,
    );
    let mut ignored_rng = Lcg::new(0);
    let mut next_request_id = (u64::from(connection_id) << 32).saturating_add(1);
    let warmup = prime_connection(
        &mut stream,
        &scenario,
        &adapter,
        &mut session,
        &mut ignored_rng,
        rate,
        &mut next_request_id,
        &mut shutdown,
    )
    .await?;
    let epoch = Instant::now();
    let mut scheduler = OpenLoopScheduler::new(0, rate, scenario.duration_secs, scenario.burst);
    let mut counters = OutcomeCounters::default();
    let mut rejection_reasons = RejectionCounters::default();
    let mut actions = ActionCounters::default();
    let mut action_queue_delay = Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND));
    let mut action_request_to_ack = Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND));
    let mut queue_delay = LatencyHistogram::new(60 * NANOS_PER_SECOND);
    let mut request_to_ack = LatencyHistogram::new(60 * NANOS_PER_SECOND);
    let mut dimension_previous = OutcomeCounters::default();
    let mut dimension_queue_delay = LatencyHistogram::new(60 * NANOS_PER_SECOND);
    let mut dimension_request_to_ack = LatencyHistogram::new(60 * NANOS_PER_SECOND);
    let mut dimensions = Vec::new();
    let mut interval_queue_delay = Box::new(LatencyHistogram::new(60 * NANOS_PER_SECOND));
    let mut interval_request_to_ack = Box::new(LatencyHistogram::new(60 * NANOS_PER_SECOND));
    let mut interval_action_queue_delay = Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND));
    let mut interval_action_request_to_ack = Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND));
    let mut read_buffer: Vec<u8> = Vec::with_capacity(FRAME_HEADER_LEN + MAX_RPC_FRAME_PAYLOAD);
    let end_ns = scenario.duration_secs.saturating_mul(NANOS_PER_SECOND);
    let poll = Duration::from_millis(1);
    let mut intervals = Vec::with_capacity(usize::try_from(scenario.duration_secs).unwrap_or(0));
    let mut interval_previous = OutcomeCounters::default();
    let mut interval_action_previous = ActionCounters::default();
    let mut interval_second = 0u64;

    'steady: loop {
        if *shutdown.borrow() {
            break;
        }
        let elapsed_ns = u64::try_from(epoch.elapsed().as_nanos())
            .unwrap_or(u64::MAX)
            .min(end_ns);
        let elapsed_second = elapsed_ns / NANOS_PER_SECOND;
        while interval_second.saturating_add(1) < scenario.duration_secs
            && interval_second < elapsed_second
        {
            capture_interval(
                interval_second,
                &counters,
                &mut interval_previous,
                &actions,
                &mut interval_action_previous,
                &mut intervals,
                &interval_tx,
                &mut interval_queue_delay,
                &mut interval_request_to_ack,
                &mut interval_action_queue_delay,
                &mut interval_action_request_to_ack,
                &routes[active_route],
                true,
            );
            interval_second = interval_second.saturating_add(1);
        }
        let batch = scheduler.poll(elapsed_ns, u64::try_from(free.len()).unwrap_or(u64::MAX));
        counters.offered = counters.offered.saturating_add(batch.offered);
        counters.locally_dropped = counters
            .locally_dropped
            .saturating_add(batch.locally_dropped);
        for operation_index in 0..batch.emit {
            let command = session.next_command(&mut ignored_rng, &scenario);
            let action = actions.for_kind_mut(command.kind);
            action.offered = action.offered.saturating_add(1);
            counters.generated = counters.generated.saturating_add(1);
            action.generated = action.generated.saturating_add(1);
            let Some(mut slot) = free.pop() else {
                counters.locally_dropped = counters.locally_dropped.saturating_add(1);
                action.locally_dropped = action.locally_dropped.saturating_add(1);
                continue;
            };
            if adapter
                .encode_into_slot(next_request_id, &command, &mut slot)
                .is_err()
            {
                session.release_pending(&command);
                counters.generator_failed = counters.generator_failed.saturating_add(1);
                action.generator_failed = action.generator_failed.saturating_add(1);
                free.push(slot);
                next_request_id = next_request_id.saturating_add(1);
                continue;
            }
            counters.queued = counters.queued.saturating_add(1);
            action.queued = action.queued.saturating_add(1);
            let scheduled_ns = batch
                .first_due_ns
                .saturating_add(operation_index.saturating_mul(batch.spacing_ns));
            let write_started_ns = u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let queue_delay_ns = write_started_ns.saturating_sub(scheduled_ns);
            queue_delay.record(queue_delay_ns);
            dimension_queue_delay.record(queue_delay_ns);
            interval_queue_delay.record(queue_delay_ns);
            action_queue_delay
                .for_kind_mut(command.kind)
                .record(queue_delay_ns);
            interval_action_queue_delay
                .for_kind_mut(command.kind)
                .record(queue_delay_ns);
            if let Err(error) = stream.write_all(slot.frame()).await {
                session.release_pending(&command);
                counters.transport_failed_before_write =
                    counters.transport_failed_before_write.saturating_add(1);
                action.transport_failed_before_write =
                    action.transport_failed_before_write.saturating_add(1);
                free.push(slot);
                fail_pending_transport(
                    &mut session,
                    &mut pending,
                    &mut free,
                    &mut counters,
                    &mut actions,
                );
                let _ = error;
                account_unattempted_batch(
                    batch.emit.saturating_sub(operation_index).saturating_sub(1),
                    &mut session,
                    &mut ignored_rng,
                    &scenario,
                    &mut counters,
                    &mut actions,
                );
                if let Some((reconnected, route_index)) =
                    reconnect_endpoint(&routes, active_route, &scenario, connection_id).await
                {
                    capture_interval(
                        interval_second,
                        &counters,
                        &mut interval_previous,
                        &actions,
                        &mut interval_action_previous,
                        &mut intervals,
                        &interval_tx,
                        &mut interval_queue_delay,
                        &mut interval_request_to_ack,
                        &mut interval_action_queue_delay,
                        &mut interval_action_request_to_ack,
                        &routes[active_route],
                        false,
                    );
                    capture_connection_dimension(
                        &mut dimensions,
                        &routes[active_route],
                        &counters,
                        &mut dimension_previous,
                        &mut dimension_queue_delay,
                        &mut dimension_request_to_ack,
                    )?;
                    active_route = route_index;
                    stream = reconnected;
                    continue 'steady;
                }
                capture_interval(
                    interval_second,
                    &counters,
                    &mut interval_previous,
                    &actions,
                    &mut interval_action_previous,
                    &mut intervals,
                    &interval_tx,
                    &mut interval_queue_delay,
                    &mut interval_request_to_ack,
                    &mut interval_action_queue_delay,
                    &mut interval_action_request_to_ack,
                    &routes[active_route],
                    true,
                );
                capture_connection_dimension(
                    &mut dimensions,
                    &routes[active_route],
                    &counters,
                    &mut dimension_previous,
                    &mut dimension_queue_delay,
                    &mut dimension_request_to_ack,
                )?;
                return finish_connection(
                    counters,
                    rejection_reasons,
                    actions,
                    action_queue_delay,
                    action_request_to_ack,
                    queue_delay,
                    request_to_ack,
                    scheduler,
                    intervals,
                    warmup,
                    dimensions,
                );
            }
            counters.socket_written = counters.socket_written.saturating_add(1);
            action.socket_written = action.socket_written.saturating_add(1);
            pending.push(Pending {
                request_id: next_request_id,
                command,
                slot,
                written_at: Instant::now(),
            });
            next_request_id = next_request_id.saturating_add(1);
        }
        if elapsed_ns >= end_ns {
            break;
        }
        if pending.is_empty() {
            tokio::select! {
                () = tokio::time::sleep(poll) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break 'steady; }
                }
            }
        } else {
            tokio::select! {
                response = read_response(&mut stream, &mut read_buffer) => {
                    match response {
                        Ok(response) => handle_response(
                            response,
                            &adapter,
                            &mut session,
                            &mut pending,
                            &mut free,
                            &mut counters,
                            &mut rejection_reasons,
                            &mut actions,
                            &mut request_to_ack,
                            &mut action_request_to_ack,
                            &mut interval_request_to_ack,
                            &mut interval_action_request_to_ack,
                            &mut dimension_request_to_ack,
                        ),
                        Err(_) => {
                            fail_pending_transport(
                                &mut session,
                                &mut pending,
                                &mut free,
                                &mut counters,
                                &mut actions,
                            );
                            if let Some((reconnected, route_index)) = reconnect_endpoint(
                                &routes,
                                active_route,
                                &scenario,
                                connection_id,
                            )
                            .await
                            {
                                capture_interval(
                                    interval_second,
                                    &counters,
                                    &mut interval_previous,
                                    &actions,
                                    &mut interval_action_previous,
                                    &mut intervals,
                                    &interval_tx,
                                    &mut interval_queue_delay,
                                    &mut interval_request_to_ack,
                                    &mut interval_action_queue_delay,
                                    &mut interval_action_request_to_ack,
                                    &routes[active_route],
                                    false,
                                );
                                capture_connection_dimension(
                                    &mut dimensions,
                                    &routes[active_route],
                                    &counters,
                                    &mut dimension_previous,
                                    &mut dimension_queue_delay,
                                    &mut dimension_request_to_ack,
                                )?;
                                active_route = route_index;
                                stream = reconnected;
                                continue 'steady;
                            }
                            capture_interval(
                                interval_second,
                                &counters,
                                &mut interval_previous,
                                &actions,
                                &mut interval_action_previous,
                                &mut intervals,
                                &interval_tx,
                                &mut interval_queue_delay,
                                &mut interval_request_to_ack,
                                &mut interval_action_queue_delay,
                                &mut interval_action_request_to_ack,
                                &routes[active_route],
                                true,
                            );
                            capture_connection_dimension(
                                &mut dimensions,
                                &routes[active_route],
                                &counters,
                                &mut dimension_previous,
                                &mut dimension_queue_delay,
                                &mut dimension_request_to_ack,
                            )?;
                            return finish_connection(
                                counters,
                                rejection_reasons,
                                actions,
                                action_queue_delay,
                                action_request_to_ack,
                                queue_delay,
                                request_to_ack,
                                scheduler,
                                intervals,
                                warmup,
                                dimensions,
                            );
                        }
                    }
                }
                () = tokio::time::sleep(poll) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break 'steady; }
                }
            }
            expire_pending(
                &mut session,
                &mut pending,
                &mut free,
                &mut counters,
                &mut actions,
                ACK_TIMEOUT,
            );
        }
    }

    let drain_deadline = Instant::now() + Duration::from_secs(scenario.drain_timeout_secs);
    while !pending.is_empty() && Instant::now() < drain_deadline {
        let remaining = drain_deadline.saturating_duration_since(Instant::now());
        receive_one(
            &mut stream,
            &adapter,
            &mut session,
            &mut pending,
            &mut free,
            &mut counters,
            &mut rejection_reasons,
            &mut actions,
            &mut request_to_ack,
            &mut action_request_to_ack,
            &mut interval_request_to_ack,
            &mut interval_action_request_to_ack,
            &mut dimension_request_to_ack,
            &mut read_buffer,
            remaining.min(ACK_TIMEOUT),
        )
        .await;
    }
    for pending_item in pending.drain(..) {
        session.release_pending(&pending_item.command);
        counters.timed_out = counters.timed_out.saturating_add(1);
        actions.for_kind_mut(pending_item.command.kind).timed_out = actions
            .for_kind_mut(pending_item.command.kind)
            .timed_out
            .saturating_add(1);
        free.push(pending_item.slot);
    }
    capture_interval(
        interval_second,
        &counters,
        &mut interval_previous,
        &actions,
        &mut interval_action_previous,
        &mut intervals,
        &interval_tx,
        &mut interval_queue_delay,
        &mut interval_request_to_ack,
        &mut interval_action_queue_delay,
        &mut interval_action_request_to_ack,
        &routes[active_route],
        true,
    );
    capture_connection_dimension(
        &mut dimensions,
        &routes[active_route],
        &counters,
        &mut dimension_previous,
        &mut dimension_queue_delay,
        &mut dimension_request_to_ack,
    )?;
    finish_connection(
        counters,
        rejection_reasons,
        actions,
        action_queue_delay,
        action_request_to_ack,
        queue_delay,
        request_to_ack,
        scheduler,
        intervals,
        warmup,
        dimensions,
    )
}

#[allow(clippy::too_many_arguments)]
async fn receive_one<S: AsyncRead + Unpin>(
    stream: &mut S,
    adapter: &ProtocolAdapter,
    session: &mut SessionState,
    pending: &mut Vec<Pending>,
    free: &mut Vec<ProtocolSlot>,
    counters: &mut OutcomeCounters,
    rejection_reasons: &mut RejectionCounters,
    actions: &mut ActionCounters,
    request_to_ack: &mut LatencyHistogram,
    action_request_to_ack: &mut ActionHistograms,
    interval_request_to_ack: &mut LatencyHistogram,
    interval_action_request_to_ack: &mut ActionHistograms,
    dimension_request_to_ack: &mut LatencyHistogram,
    read_buffer: &mut Vec<u8>,
    timeout: Duration,
) {
    let response = tokio::time::timeout(timeout, read_response(stream, read_buffer)).await;
    let response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => {
            fail_pending_transport(session, pending, free, counters, actions);
            return;
        }
        Err(_) => {
            if let Some(item) = pending.pop() {
                session.release_pending(&item.command);
                counters.timed_out = counters.timed_out.saturating_add(1);
                let action = actions.for_kind_mut(item.command.kind);
                action.timed_out = action.timed_out.saturating_add(1);
                free.push(item.slot);
            }
            return;
        }
    };
    handle_response(
        response,
        adapter,
        session,
        pending,
        free,
        counters,
        rejection_reasons,
        actions,
        request_to_ack,
        action_request_to_ack,
        interval_request_to_ack,
        interval_action_request_to_ack,
        dimension_request_to_ack,
    );
}

#[allow(clippy::too_many_arguments)]
fn handle_response(
    response: RpcResponse,
    adapter: &ProtocolAdapter,
    session: &mut SessionState,
    pending: &mut Vec<Pending>,
    free: &mut Vec<ProtocolSlot>,
    counters: &mut OutcomeCounters,
    rejection_reasons: &mut RejectionCounters,
    actions: &mut ActionCounters,
    request_to_ack: &mut LatencyHistogram,
    action_request_to_ack: &mut ActionHistograms,
    interval_request_to_ack: &mut LatencyHistogram,
    interval_action_request_to_ack: &mut ActionHistograms,
    dimension_request_to_ack: &mut LatencyHistogram,
) {
    let Some(index) = pending
        .iter()
        .position(|item| item.request_id == response.request_id)
    else {
        if let Some(item) = pending.pop() {
            session.release_pending(&item.command);
            counters.protocol_failed = counters.protocol_failed.saturating_add(1);
            let action = actions.for_kind_mut(item.command.kind);
            action.protocol_failed = action.protocol_failed.saturating_add(1);
            free.push(item.slot);
        }
        return;
    };
    let item = pending.swap_remove(index);
    let latency = u64::try_from(item.written_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
    request_to_ack.record(latency);
    interval_request_to_ack.record(latency);
    dimension_request_to_ack.record(latency);
    action_request_to_ack
        .for_kind_mut(item.command.kind)
        .record(latency);
    interval_action_request_to_ack
        .for_kind_mut(item.command.kind)
        .record(latency);
    counters.acknowledged = counters.acknowledged.saturating_add(1);
    let action = actions.for_kind_mut(item.command.kind);
    action.acknowledged = action.acknowledged.saturating_add(1);
    match response.result {
        Ok(RpcOk::CommandAck(ack)) => {
            if adapter
                .apply_accepted_command(session, &item.command, &ack)
                .is_ok()
            {
                counters.accepted = counters.accepted.saturating_add(1);
                action.accepted = action.accepted.saturating_add(1);
            } else {
                counters.acknowledged = counters.acknowledged.saturating_sub(1);
                action.acknowledged = action.acknowledged.saturating_sub(1);
                counters.protocol_failed = counters.protocol_failed.saturating_add(1);
                action.protocol_failed = action.protocol_failed.saturating_add(1);
            }
        }
        Ok(_) => {
            session.release_pending(&item.command);
            counters.acknowledged = counters.acknowledged.saturating_sub(1);
            action.acknowledged = action.acknowledged.saturating_sub(1);
            counters.protocol_failed = counters.protocol_failed.saturating_add(1);
            action.protocol_failed = action.protocol_failed.saturating_add(1);
        }
        Err(error) => {
            session.release_pending(&item.command);
            counters.rejected = counters.rejected.saturating_add(1);
            rejection_reasons.record(&error);
            action.rejected = action.rejected.saturating_add(1);
        }
    }
    free.push(item.slot);
}

fn expire_pending(
    session: &mut SessionState,
    pending: &mut Vec<Pending>,
    free: &mut Vec<ProtocolSlot>,
    counters: &mut OutcomeCounters,
    actions: &mut ActionCounters,
    timeout: Duration,
) {
    let mut index = 0;
    while index < pending.len() {
        if pending[index].written_at.elapsed() < timeout {
            index += 1;
            continue;
        }
        let item = pending.swap_remove(index);
        session.release_pending(&item.command);
        counters.timed_out = counters.timed_out.saturating_add(1);
        let action = actions.for_kind_mut(item.command.kind);
        action.timed_out = action.timed_out.saturating_add(1);
        free.push(item.slot);
    }
}

fn fail_pending_transport(
    session: &mut SessionState,
    pending: &mut Vec<Pending>,
    free: &mut Vec<ProtocolSlot>,
    counters: &mut OutcomeCounters,
    actions: &mut ActionCounters,
) {
    for item in pending.drain(..) {
        session.release_pending(&item.command);
        counters.transport_failed_after_write =
            counters.transport_failed_after_write.saturating_add(1);
        let action = actions.for_kind_mut(item.command.kind);
        action.transport_failed_after_write = action.transport_failed_after_write.saturating_add(1);
        free.push(item.slot);
    }
}

fn account_unattempted_batch(
    count: u64,
    session: &mut SessionState,
    rng: &mut Lcg,
    scenario: &LoadScenario,
    counters: &mut OutcomeCounters,
    actions: &mut ActionCounters,
) {
    for _ in 0..count {
        let command = session.next_command(rng, scenario);
        session.release_pending(&command);
        counters.generated = counters.generated.saturating_add(1);
        counters.locally_dropped = counters.locally_dropped.saturating_add(1);
        let action = actions.for_kind_mut(command.kind);
        action.offered = action.offered.saturating_add(1);
        action.generated = action.generated.saturating_add(1);
        action.locally_dropped = action.locally_dropped.saturating_add(1);
    }
}

fn capture_connection_dimension(
    dimensions: &mut Vec<ConnectionDimension>,
    route: &EndpointRoute,
    current: &OutcomeCounters,
    previous: &mut OutcomeCounters,
    queue_delay: &mut LatencyHistogram,
    request_to_ack: &mut LatencyHistogram,
) -> Result<(), HistogramMergeError> {
    let counters = outcome_delta(current, previous);
    let max_trackable_ns = queue_delay.max_trackable_ns();
    let queue_delay = std::mem::replace(queue_delay, LatencyHistogram::new(max_trackable_ns));
    let request_to_ack = std::mem::replace(request_to_ack, LatencyHistogram::new(max_trackable_ns));
    *previous = *current;
    merge_connection_dimension(
        dimensions,
        ConnectionDimension {
            region_index: route.assignment.region_index,
            endpoint_index: route.assignment.endpoint_index,
            counters,
            queue_delay,
            request_to_ack,
        },
    )
}

fn outcome_delta(current: &OutcomeCounters, previous: &OutcomeCounters) -> OutcomeCounters {
    OutcomeCounters {
        offered: current.offered.saturating_sub(previous.offered),
        generated: current.generated.saturating_sub(previous.generated),
        queued: current.queued.saturating_sub(previous.queued),
        socket_written: current
            .socket_written
            .saturating_sub(previous.socket_written),
        acknowledged: current.acknowledged.saturating_sub(previous.acknowledged),
        accepted: current.accepted.saturating_sub(previous.accepted),
        rejected: current.rejected.saturating_sub(previous.rejected),
        timed_out: current.timed_out.saturating_sub(previous.timed_out),
        generator_failed: current
            .generator_failed
            .saturating_sub(previous.generator_failed),
        transport_failed_before_write: current
            .transport_failed_before_write
            .saturating_sub(previous.transport_failed_before_write),
        transport_failed_after_write: current
            .transport_failed_after_write
            .saturating_sub(previous.transport_failed_after_write),
        protocol_failed: current
            .protocol_failed
            .saturating_sub(previous.protocol_failed),
        locally_dropped: current
            .locally_dropped
            .saturating_sub(previous.locally_dropped),
        overflow: current.overflow.saturating_sub(previous.overflow),
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_connection(
    counters: OutcomeCounters,
    rejection_reasons: RejectionCounters,
    actions: ActionCounters,
    action_queue_delay: Box<ActionHistograms>,
    action_request_to_ack: Box<ActionHistograms>,
    queue_delay: LatencyHistogram,
    request_to_ack: LatencyHistogram,
    scheduler: OpenLoopScheduler,
    intervals: Vec<IntervalCounters>,
    warmup: WarmupStats,
    dimensions: Vec<ConnectionDimension>,
) -> Result<ConnectionReport, LiveError> {
    counters.validate_conservation()?;
    Ok(ConnectionReport {
        counters,
        rejection_reasons,
        actions,
        action_queue_delay,
        action_request_to_ack,
        queue_delay,
        request_to_ack,
        rate_debt: scheduler.cumulative_rate_debt(),
        intervals,
        warmup_socket_written: warmup.socket_written,
        warmup_acknowledged: warmup.acknowledged,
        warmup_failed: warmup.failed,
        dimensions,
    })
}

fn merge_connection_dimension(
    dimensions: &mut Vec<ConnectionDimension>,
    incoming: ConnectionDimension,
) -> Result<(), HistogramMergeError> {
    if let Some(existing) = dimensions.iter_mut().find(|dimension| {
        dimension.region_index == incoming.region_index
            && dimension.endpoint_index == incoming.endpoint_index
    }) {
        existing.counters.merge(&incoming.counters);
        existing.queue_delay.merge(&incoming.queue_delay)?;
        existing.request_to_ack.merge(&incoming.request_to_ack)?;
    } else {
        dimensions.push(incoming);
    }
    Ok(())
}

fn interval_delta(
    second: u64,
    current: &OutcomeCounters,
    previous: &mut OutcomeCounters,
) -> IntervalCounters {
    let delta = IntervalCounters {
        second,
        offered: current.offered.saturating_sub(previous.offered),
        generated: current.generated.saturating_sub(previous.generated),
        queued: current.queued.saturating_sub(previous.queued),
        socket_written: current
            .socket_written
            .saturating_sub(previous.socket_written),
        acknowledged: current.acknowledged.saturating_sub(previous.acknowledged),
        accepted: current.accepted.saturating_sub(previous.accepted),
        rejected: current.rejected.saturating_sub(previous.rejected),
        timed_out: current.timed_out.saturating_sub(previous.timed_out),
        generator_failed: current
            .generator_failed
            .saturating_sub(previous.generator_failed),
        transport_failed_before_write: current
            .transport_failed_before_write
            .saturating_sub(previous.transport_failed_before_write),
        transport_failed_after_write: current
            .transport_failed_after_write
            .saturating_sub(previous.transport_failed_after_write),
        protocol_failed: current
            .protocol_failed
            .saturating_sub(previous.protocol_failed),
        failures: terminal_failures(current).saturating_sub(terminal_failures(previous)),
        locally_dropped: current
            .locally_dropped
            .saturating_sub(previous.locally_dropped),
        overflow: current.overflow.saturating_sub(previous.overflow),
    };
    *previous = *current;
    delta
}

fn merge_interval(intervals: &mut [IntervalCounters], delta: IntervalCounters) {
    let Some(interval) = usize::try_from(delta.second)
        .ok()
        .and_then(|index| intervals.get_mut(index))
    else {
        return;
    };
    interval.offered = interval.offered.saturating_add(delta.offered);
    interval.generated = interval.generated.saturating_add(delta.generated);
    interval.queued = interval.queued.saturating_add(delta.queued);
    interval.socket_written = interval.socket_written.saturating_add(delta.socket_written);
    interval.acknowledged = interval.acknowledged.saturating_add(delta.acknowledged);
    interval.accepted = interval.accepted.saturating_add(delta.accepted);
    interval.rejected = interval.rejected.saturating_add(delta.rejected);
    interval.timed_out = interval.timed_out.saturating_add(delta.timed_out);
    interval.generator_failed = interval
        .generator_failed
        .saturating_add(delta.generator_failed);
    interval.transport_failed_before_write = interval
        .transport_failed_before_write
        .saturating_add(delta.transport_failed_before_write);
    interval.transport_failed_after_write = interval
        .transport_failed_after_write
        .saturating_add(delta.transport_failed_after_write);
    interval.protocol_failed = interval
        .protocol_failed
        .saturating_add(delta.protocol_failed);
    interval.failures = interval.failures.saturating_add(delta.failures);
    interval.locally_dropped = interval
        .locally_dropped
        .saturating_add(delta.locally_dropped);
    interval.overflow = interval.overflow.saturating_add(delta.overflow);
}

#[allow(clippy::too_many_arguments)]
fn capture_interval(
    second: u64,
    current: &OutcomeCounters,
    previous: &mut OutcomeCounters,
    current_actions: &ActionCounters,
    previous_actions: &mut ActionCounters,
    intervals: &mut Vec<IntervalCounters>,
    sender: &mpsc::Sender<ConnectionInterval>,
    queue_delay: &mut Box<LatencyHistogram>,
    request_to_ack: &mut Box<LatencyHistogram>,
    action_queue_delay: &mut Box<ActionHistograms>,
    action_request_to_ack: &mut Box<ActionHistograms>,
    route: &EndpointRoute,
    complete: bool,
) {
    let delta = interval_delta(second, current, previous);
    let action_delta = action_counter_delta(current_actions, previous_actions);
    let queue_max = queue_delay.max_trackable_ns();
    let ack_max = request_to_ack.max_trackable_ns();
    let queue_delta = std::mem::replace(queue_delay, Box::new(LatencyHistogram::new(queue_max)));
    let ack_delta = std::mem::replace(request_to_ack, Box::new(LatencyHistogram::new(ack_max)));
    let action_queue_delta = std::mem::replace(
        action_queue_delay,
        Box::new(ActionHistograms::new(queue_max)),
    );
    let action_ack_delta = std::mem::replace(
        action_request_to_ack,
        Box::new(ActionHistograms::new(ack_max)),
    );
    let _ = sender.try_send(ConnectionInterval {
        delta,
        actions: action_delta,
        queue_delay: queue_delta,
        request_to_ack: ack_delta,
        action_queue_delay: action_queue_delta,
        action_request_to_ack: action_ack_delta,
        region_index: route.assignment.region_index,
        endpoint_index: route.assignment.endpoint_index,
        complete,
    });
    intervals.push(delta);
}

fn action_counter_delta(current: &ActionCounters, previous: &mut ActionCounters) -> ActionCounters {
    let delta = ActionCounters {
        new_order: outcome_delta(&current.new_order, &previous.new_order),
        cancel: outcome_delta(&current.cancel, &previous.cancel),
        replace: outcome_delta(&current.replace, &previous.replace),
    };
    *previous = *current;
    delta
}

async fn collect_connection_intervals(
    mut receiver: mpsc::Receiver<ConnectionInterval>,
    scenario: Arc<LoadScenario>,
    connection_count: u64,
    progress: Option<mpsc::Sender<IntervalReport>>,
) -> IntervalCollection {
    let duration_secs = scenario.duration_secs;
    let length = usize::try_from(duration_secs).unwrap_or(0);
    let mut aggregate = vec![IntervalCounters::default(); length];
    let mut actions = vec![ActionCounters::default(); length];
    let mut queue_delay = (0..length)
        .map(|_| Box::new(LatencyHistogram::new(60 * NANOS_PER_SECOND)))
        .collect::<Vec<_>>();
    let mut request_to_ack = (0..length)
        .map(|_| Box::new(LatencyHistogram::new(60 * NANOS_PER_SECOND)))
        .collect::<Vec<_>>();
    let mut action_queue_delay = (0..length)
        .map(|_| Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND)))
        .collect::<Vec<_>>();
    let mut action_request_to_ack = (0..length)
        .map(|_| Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND)))
        .collect::<Vec<_>>();
    let mut dimensions = vec![Vec::<ConnectionDimension>::new(); length];
    let mut reports = vec![None::<IntervalReport>; length];
    let mut contributors = vec![0u64; length];
    for (second, interval) in aggregate.iter_mut().enumerate() {
        interval.second = u64::try_from(second).unwrap_or(u64::MAX);
    }
    let mut lost = 0u64;
    while let Some(update) = receiver.recv().await {
        let Some(index) = usize::try_from(update.delta.second)
            .ok()
            .filter(|index| *index < aggregate.len())
        else {
            lost = lost.saturating_add(1);
            continue;
        };
        if queue_delay[index].merge(&update.queue_delay).is_err()
            || request_to_ack[index].merge(&update.request_to_ack).is_err()
            || action_queue_delay[index]
                .merge(&update.action_queue_delay)
                .is_err()
            || action_request_to_ack[index]
                .merge(&update.action_request_to_ack)
                .is_err()
        {
            lost = lost.saturating_add(1);
            continue;
        }
        merge_interval(&mut aggregate, update.delta);
        actions[index].new_order.merge(&update.actions.new_order);
        actions[index].cancel.merge(&update.actions.cancel);
        actions[index].replace.merge(&update.actions.replace);
        if merge_connection_dimension(
            &mut dimensions[index],
            ConnectionDimension {
                region_index: update.region_index,
                endpoint_index: update.endpoint_index,
                counters: outcome_delta_from_interval(&update.delta),
                queue_delay: *update.queue_delay,
                request_to_ack: *update.request_to_ack,
            },
        )
        .is_err()
        {
            lost = lost.saturating_add(1);
            continue;
        }
        if update.complete {
            contributors[index] = contributors[index].saturating_add(1);
        }
        if contributors[index] == connection_count {
            let interval_dimensions = std::mem::take(&mut dimensions[index])
                .into_iter()
                .map(|dimension| MetricDimension {
                    region: scenario.regions[dimension.region_index].name.clone(),
                    endpoint: scenario.regions[dimension.region_index].endpoints
                        [dimension.endpoint_index]
                        .name
                        .clone(),
                    counters: dimension.counters,
                    queue_delay: HistogramReport::from_histogram(&dimension.queue_delay),
                    request_to_ack: HistogramReport::from_histogram(&dimension.request_to_ack),
                })
                .collect();
            let queue = std::mem::replace(
                &mut queue_delay[index],
                Box::new(LatencyHistogram::new(60 * NANOS_PER_SECOND)),
            );
            let ack = std::mem::replace(
                &mut request_to_ack[index],
                Box::new(LatencyHistogram::new(60 * NANOS_PER_SECOND)),
            );
            let action_queue = std::mem::replace(
                &mut action_queue_delay[index],
                Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND)),
            );
            let action_ack = std::mem::replace(
                &mut action_request_to_ack[index],
                Box::new(ActionHistograms::new(60 * NANOS_PER_SECOND)),
            );
            let report = IntervalReport {
                counters: aggregate[index],
                actions: actions[index],
                queue_delay: HistogramReport::from_histogram(&queue),
                request_to_ack: HistogramReport::from_histogram(&ack),
                action_queue_delay: ActionLatencyReport::from_histograms(&action_queue),
                action_request_to_ack: ActionLatencyReport::from_histograms(&action_ack),
                dimensions: interval_dimensions,
            };
            if let Some(sender) = &progress {
                if sender.try_send(report.clone()).is_err() {
                    lost = lost.saturating_add(1);
                }
            }
            reports[index] = Some(report);
        } else if contributors[index] > connection_count {
            lost = lost.saturating_add(1);
        }
    }
    let missing_contributors = contributors.iter().fold(0u64, |total, count| {
        total.saturating_add(connection_count.saturating_sub(*count))
    });
    IntervalCollection {
        reports: reports.into_iter().flatten().collect(),
        lost: lost.saturating_add(missing_contributors),
    }
}

fn outcome_delta_from_interval(interval: &IntervalCounters) -> OutcomeCounters {
    OutcomeCounters {
        offered: interval.offered,
        generated: interval.generated,
        queued: interval.queued,
        socket_written: interval.socket_written,
        acknowledged: interval.acknowledged,
        accepted: interval.accepted,
        rejected: interval.rejected,
        timed_out: interval.timed_out,
        generator_failed: interval.generator_failed,
        transport_failed_before_write: interval.transport_failed_before_write,
        transport_failed_after_write: interval.transport_failed_after_write,
        protocol_failed: interval.protocol_failed,
        locally_dropped: interval.locally_dropped,
        overflow: interval.overflow,
    }
}

fn dimensions_total(dimensions: &[MetricDimension]) -> OutcomeCounters {
    let mut total = OutcomeCounters::default();
    for dimension in dimensions {
        total.merge(&dimension.counters);
    }
    total
}

const fn terminal_failures(counters: &OutcomeCounters) -> u64 {
    counters
        .timed_out
        .saturating_add(counters.generator_failed)
        .saturating_add(counters.transport_failed_before_write)
        .saturating_add(counters.transport_failed_after_write)
        .saturating_add(counters.protocol_failed)
        .saturating_add(counters.locally_dropped)
}

async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
) -> Result<RpcResponse, LiveError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let payload_len = u32::from_le_bytes([header[15], header[16], header[17], header[18]]) as usize;
    if payload_len > MAX_RPC_FRAME_PAYLOAD {
        return Err(LiveError::Protocol(
            "response payload exceeds cap".to_string(),
        ));
    }
    let length = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| LiveError::Protocol("response length overflow".to_string()))?;
    if buffer.capacity() < length {
        return Err(LiveError::Protocol(
            "response buffer capacity exceeded".to_string(),
        ));
    }
    buffer.resize(length, 0);
    buffer[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream.read_exact(&mut buffer[FRAME_HEADER_LEN..]).await?;
    decode_response(buffer).map_err(|error| LiveError::Protocol(error.to_string()))
}

fn tls_connector(endpoint: &EndpointConfig) -> Result<TlsConnector, LiveError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = std::fs::read(&endpoint.tls.ca_file).map_err(|error| LiveError::Tls {
        endpoint: endpoint.name.clone(),
        reason: format!("read CA file: {error}"),
    })?;
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut BufReader::new(ca.as_slice())) {
        roots
            .add(certificate.map_err(|error| LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: format!("parse CA file: {error}"),
            })?)
            .map_err(|error| LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: format!("add CA certificate: {error}"),
            })?;
    }
    let builder = RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots);
    let config = if endpoint.tls.client_cert_file.is_empty() {
        builder.with_no_client_auth()
    } else {
        let cert_bytes =
            std::fs::read(&endpoint.tls.client_cert_file).map_err(|error| LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: format!("read client certificate: {error}"),
            })?;
        let certificates = rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|error| LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: format!("parse client certificate: {error}"),
            })?;
        let key_bytes =
            std::fs::read(&endpoint.tls.client_key_file).map_err(|error| LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: format!("read client key: {error}"),
            })?;
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
                .map_err(|error| LiveError::Tls {
                    endpoint: endpoint.name.clone(),
                    reason: format!("parse client key: {error}"),
                })?
                .ok_or_else(|| LiveError::Tls {
                    endpoint: endpoint.name.clone(),
                    reason: "client key file contains no private key".to_string(),
                })?;
        builder
            .with_client_auth_cert(certificates, key)
            .map_err(|error| LiveError::Tls {
                endpoint: endpoint.name.clone(),
                reason: error.to_string(),
            })?
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::{
        serve_reference_sink, EndpointConfig, OperationMix, ReferenceSinkConfig, RegionConfig,
        SinkCounters, SinkFaultMode, TargetKind, TlsClientConfig,
    };
    use crypto::KeyPair;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::server::WebPkiClientVerifier;
    use rustls::ServerConfig;
    use tokio::net::TcpListener;
    use tokio::sync::watch;
    use tokio_rustls::TlsAcceptor;
    use types::{AccountId, Ratio, RATIO_SCALE};

    async fn scenario_and_sink(
        fault: SinkFaultMode,
    ) -> (
        LoadScenario,
        ProtocolAdapter,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let sink = tokio::spawn(async move {
            let _ = serve_reference_sink(
                listener,
                ReferenceSinkConfig {
                    fault,
                    ..ReferenceSinkConfig::default()
                },
                stop_rx,
            )
            .await;
        });
        let scenario = LoadScenario {
            schema_version: 2,
            mode: RunMode::Sink,
            market_ids: vec![7],
            operation_mix: Some(OperationMix {
                new: Ratio::from_raw(RATIO_SCALE),
                cancel: Ratio::ZERO,
                replace: Ratio::ZERO,
            }),
            orders_per_second: 100,
            duration_secs: 1,
            drain_timeout_secs: 2,
            in_flight_per_connection: 4,
            regions: vec![RegionConfig {
                name: "local".to_string(),
                users: 1,
                source_ips: vec!["127.0.0.1".to_string()],
                endpoints: vec![EndpointConfig {
                    name: "sink".to_string(),
                    address: address.to_string(),
                    connections_per_source_ip: 1,
                    target_kind: TargetKind::ReferenceSink,
                    ..EndpointConfig::default()
                }],
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        };
        let adapter =
            ProtocolAdapter::new(AccountId::new(1), KeyPair::from_seed(&[8; 32]), 0, None);
        (scenario, adapter, stop_tx, sink)
    }

    #[tokio::test]
    async fn local_live_sink_run_reconciles_real_rpc_frames() {
        let (scenario, adapter, stop, sink) = scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        let report = run_local_live(&scenario, adapter).await.unwrap();
        let _ = stop.send(true);
        sink.await.unwrap();
        assert_eq!(report.target_label, "reference-sink-test-only");
        assert_eq!(report.counters.offered, 100);
        // Throughput is threshold-gated by qualification runs; this correctness
        // test must remain stable when a shared runner accumulates open-loop debt.
        assert!(report.counters.socket_written > 0);
        assert_eq!(report.counters.accepted, report.counters.socket_written);
        assert_eq!(report.dimensions.len(), 1);
        assert_eq!(report.dimensions[0].region, "local");
        assert_eq!(report.dimensions[0].endpoint, "sink");
        assert_eq!(report.dimensions[0].counters, report.counters);
        assert_eq!(
            report.dimensions[0].queue_delay.summary.count,
            report.counters.socket_written
        );
        assert_eq!(
            report.dimensions[0].request_to_ack.summary.count,
            report.counters.socket_written
        );
        assert_eq!(
            report.action_queue_delay.new_order.summary.count,
            report.counters.socket_written
        );
        assert_eq!(
            report.action_request_to_ack.new_order.summary.count,
            report.counters.socket_written
        );
        assert_eq!(report.action_request_to_ack.cancel.summary.count, 0);
        assert!(report.passed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn production_rpc_server_round_trips_all_trading_actions() {
        let key = KeyPair::from_seed(&[31; 32]);
        let backend = Arc::new(rpc::StubBackend::new(rpc::RpcMode::Full));
        backend.register_account_key(AccountId::new(1), key.public());
        let backend: Arc<dyn rpc::RpcBackend> = backend;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let server = tokio::spawn(rpc::serve_with_shutdown(
            listener,
            backend,
            rpc::RpcMode::Full,
            rpc::ServerConfig::default(),
            stop_rx,
        ));

        let scenario = LoadScenario {
            schema_version: 2,
            mode: RunMode::Validator,
            market_ids: vec![7, 11],
            operation_mix: Some(OperationMix::default()),
            orders_per_second: 200,
            duration_secs: 1,
            drain_timeout_secs: 2,
            worker_count: 1,
            in_flight_per_connection: 1,
            accounts: vec![crate::campaign::AccountMaterial {
                account_id: 1,
                signing_key_file: "in-memory-test-key".to_string(),
                ..crate::campaign::AccountMaterial::default()
            }],
            regions: vec![RegionConfig {
                name: "in-process-rpc".to_string(),
                users: 1,
                source_ips: vec!["127.0.0.1".to_string()],
                endpoints: vec![EndpointConfig {
                    name: "production-rpc-server".to_string(),
                    address: address.to_string(),
                    weight: 1,
                    connections_per_source_ip: 1,
                    target_kind: TargetKind::Validator,
                    ..EndpointConfig::default()
                }],
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        };
        let report = run_local_live(
            &scenario,
            ProtocolAdapter::new(AccountId::new(1), key, 0, None),
        )
        .await
        .unwrap();
        let mut unauthorized_scenario = scenario.clone();
        unauthorized_scenario.orders_per_second = 20;
        unauthorized_scenario.warm_up_secs = 1;
        let unauthorized = run_local_live(
            &unauthorized_scenario,
            ProtocolAdapter::new(
                AccountId::new(1),
                KeyPair::from_seed(&[32; 32]),
                10_000,
                None,
            ),
        )
        .await
        .unwrap();
        let _ = stop_tx.send(true);
        server.await.unwrap().unwrap();

        assert_eq!(report.target_label, "validator");
        assert_eq!(report.counters.offered, 200);
        assert!(report.counters.socket_written > 0);
        assert_eq!(report.counters.accepted, report.counters.socket_written);
        assert!(report.actions.new_order.accepted > 0);
        assert!(report.actions.cancel.accepted > 0);
        assert!(report.actions.replace.accepted > 0);
        assert_eq!(report.rejection_reasons.total(), 0);
        assert!(report.passed());
        assert_eq!(
            unauthorized.counters.rejected,
            unauthorized.counters.socket_written
        );
        assert!(unauthorized.counters.rejected > 0);
        assert_eq!(
            unauthorized.rejection_reasons.authentication,
            unauthorized.counters.rejected
        );
        assert_eq!(
            unauthorized.rejection_reasons.total(),
            unauthorized.counters.rejected
        );
        assert!(unauthorized.warmup_failed > 0);
        assert!(!unauthorized.passed());
    }

    #[tokio::test]
    async fn endpoint_weight_is_not_accidentally_multiplied_by_connection_count() {
        let (mut scenario, _adapter, stop, sink) =
            scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        scenario.regions[0].endpoints[0].weight = 3;
        scenario.regions[0].endpoints[0].connections_per_source_ip = 2;
        let mut second = scenario.regions[0].endpoints[0].clone();
        second.name = "sink-two".to_string();
        second.weight = 1;
        second.connections_per_source_ip = 1;
        scenario.regions[0].endpoints.push(second);
        let topology = preflight_topology(&scenario).unwrap();
        let rates = connection_rates(&scenario, &topology.connections).unwrap();
        assert_eq!(rates, [38, 37, 25]);
        assert_eq!(rates.iter().sum::<u64>(), 100);
        let _ = stop.send(true);
        sink.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn local_end_to_end_uses_multiple_endpoints_markets_and_actions() {
        let mut endpoints = Vec::new();
        let mut stops = Vec::new();
        let mut sinks = Vec::new();
        for index in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (stop_tx, stop_rx) = watch::channel(false);
            sinks.push(tokio::spawn(serve_reference_sink(
                listener,
                ReferenceSinkConfig::default(),
                stop_rx,
            )));
            stops.push(stop_tx);
            endpoints.push(EndpointConfig {
                name: format!("sink-{index}"),
                address: address.to_string(),
                weight: u32::try_from(index + 1).unwrap_or(1),
                connections_per_source_ip: 1,
                target_kind: TargetKind::ReferenceSink,
                ..EndpointConfig::default()
            });
        }
        let scenario = LoadScenario {
            schema_version: 2,
            mode: RunMode::Sink,
            market_ids: vec![7, 11, 13, 17],
            operation_mix: Some(OperationMix::default()),
            orders_per_second: 400,
            duration_secs: 1,
            drain_timeout_secs: 2,
            worker_count: 2,
            in_flight_per_connection: 8,
            regions: vec![RegionConfig {
                name: "local-multi".to_string(),
                users: 1,
                // Multi-address origin is exercised by the Linux-root namespace
                // test; this portable test keeps one universally bound loopback.
                source_ips: vec!["127.0.0.1".to_string()],
                endpoints,
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        };
        let adapter =
            ProtocolAdapter::new(AccountId::new(1), KeyPair::from_seed(&[19; 32]), 0, None);
        let report = run_local_live(&scenario, adapter).await.unwrap();
        for stop in stops {
            let _ = stop.send(true);
        }
        let mut received = 0u64;
        for sink in sinks {
            received = received.saturating_add(sink.await.unwrap().unwrap().snapshot().received);
        }
        assert_eq!(report.counters.offered, 400);
        assert_eq!(received, report.counters.socket_written);
        assert!(report.counters.socket_written > 0);
        assert_eq!(report.dimensions.len(), 2);
        assert!(report
            .dimensions
            .iter()
            .all(|dimension| dimension.counters.socket_written > 0));
        assert!(report.actions.new_order.offered > 0);
        assert!(report.actions.cancel.offered > 0);
        assert!(report.actions.replace.offered > 0);
        assert_eq!(report.interval_reports.len(), 1);
        let interval = &report.interval_reports[0];
        assert_eq!(interval.actions.total().socket_written, received);
        assert_eq!(
            interval.action_queue_delay.new_order.summary.count
                + interval.action_queue_delay.cancel.summary.count
                + interval.action_queue_delay.replace.summary.count,
            received
        );
        assert_eq!(interval.dimensions.len(), 2);
        assert_eq!(
            interval
                .dimensions
                .iter()
                .map(|dimension| dimension.counters.socket_written)
                .sum::<u64>(),
            received
        );
        assert!(report.passed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unhealthy_endpoint_redistributes_future_work_and_preserves_dimensions() {
        let primary_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_address = primary_listener.local_addr().unwrap();
        let (primary_stop_tx, primary_stop_rx) = watch::channel(false);
        let primary = tokio::spawn(serve_reference_sink(
            primary_listener,
            ReferenceSinkConfig {
                fault: SinkFaultMode::Disconnect { after_requests: 5 },
                ..ReferenceSinkConfig::default()
            },
            primary_stop_rx,
        ));

        let fallback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_address = fallback_listener.local_addr().unwrap();
        let (fallback_stop_tx, fallback_stop_rx) = watch::channel(false);
        let fallback = tokio::spawn(serve_reference_sink(
            fallback_listener,
            ReferenceSinkConfig::default(),
            fallback_stop_rx,
        ));

        let scenario = LoadScenario {
            schema_version: 2,
            mode: RunMode::Sink,
            market_ids: vec![7],
            operation_mix: Some(OperationMix {
                new: Ratio::from_raw(RATIO_SCALE),
                cancel: Ratio::ZERO,
                replace: Ratio::ZERO,
            }),
            orders_per_second: 100,
            duration_secs: 1,
            drain_timeout_secs: 2,
            worker_count: 2,
            in_flight_per_connection: 8,
            reconnect_base_delay_ms: 1,
            reconnect_max_delay_ms: 5,
            regions: vec![RegionConfig {
                name: "failover-region".to_string(),
                users: 1,
                source_ips: vec!["127.0.0.1".to_string()],
                endpoints: vec![
                    EndpointConfig {
                        name: "primary".to_string(),
                        address: primary_address.to_string(),
                        weight: 1,
                        connections_per_source_ip: 1,
                        target_kind: TargetKind::ReferenceSink,
                        ..EndpointConfig::default()
                    },
                    EndpointConfig {
                        name: "fallback".to_string(),
                        address: fallback_address.to_string(),
                        weight: 1,
                        connections_per_source_ip: 1,
                        target_kind: TargetKind::ReferenceSink,
                        ..EndpointConfig::default()
                    },
                ],
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        };
        let adapter =
            ProtocolAdapter::new(AccountId::new(1), KeyPair::from_seed(&[21; 32]), 0, None);
        let report = run_local_live(&scenario, adapter).await.unwrap();

        let _ = primary_stop_tx.send(true);
        let _ = fallback_stop_tx.send(true);
        let primary_received = primary.await.unwrap().unwrap().snapshot().received;
        let fallback_received = fallback.await.unwrap().unwrap().snapshot().received;

        assert_eq!(report.counters.offered, 100);
        report.counters.validate_conservation().unwrap();
        assert_eq!(dimensions_total(&report.dimensions), report.counters);
        assert_eq!(report.dimensions.len(), 2);
        let primary_dimension = report
            .dimensions
            .iter()
            .find(|dimension| dimension.endpoint == "primary")
            .unwrap();
        let fallback_dimension = report
            .dimensions
            .iter()
            .find(|dimension| dimension.endpoint == "fallback")
            .unwrap();
        primary_dimension.counters.validate_conservation().unwrap();
        fallback_dimension.counters.validate_conservation().unwrap();
        assert!(primary_dimension.counters.transport_failed_after_write > 0);
        assert!(fallback_dimension.counters.socket_written > 50);
        assert_eq!(report.interval_reports.len(), 1);
        assert_eq!(report.interval_reports[0].dimensions.len(), 2);
        assert_eq!(
            report.interval_reports[0]
                .dimensions
                .iter()
                .map(|dimension| dimension.counters.offered)
                .sum::<u64>(),
            report.intervals[0].offered
        );
        assert_eq!(primary_received, 5);
        assert!(fallback_received >= fallback_dimension.counters.accepted);
        assert!(report.passed());
    }

    #[tokio::test]
    async fn threshold_gate_rejects_a_low_second_even_when_average_passes() {
        let (scenario, adapter, stop, sink) = scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        let mut report = run_local_live(&scenario, adapter).await.unwrap();
        let _ = stop.send(true);
        sink.await.unwrap();
        let mut gate = scenario;
        gate.duration_secs = 2;
        let average = report.counters.socket_written / gate.duration_secs;
        gate.thresholds.minimum_written_per_second = average;
        let low = average.saturating_sub(1);
        let high = average.saturating_add(1);
        report.intervals = vec![
            IntervalCounters {
                second: 0,
                offered: low,
                socket_written: low,
                acknowledged: low,
                ..IntervalCounters::default()
            },
            IntervalCounters {
                second: 1,
                offered: high,
                socket_written: high,
                acknowledged: high,
                ..IntervalCounters::default()
            },
        ];
        assert_eq!(report.counters.socket_written / gate.duration_secs, average);
        assert!(report.intervals[0].socket_written < average);
        assert!(!report.passes_thresholds(&gate));
    }

    #[tokio::test]
    async fn warmup_primes_real_rpc_state_but_is_excluded_from_steady_counters() {
        let (mut scenario, adapter, stop, sink) =
            scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        scenario.orders_per_second = 20;
        scenario.warm_up_secs = 1;
        let report = run_local_live(&scenario, adapter).await.unwrap();
        let _ = stop.send(true);
        sink.await.unwrap();
        assert_eq!(report.warmup_socket_written, 20);
        assert_eq!(report.warmup_acknowledged, 20);
        assert_eq!(report.warmup_failed, 0);
        assert_eq!(report.counters.socket_written, 20);
        assert_eq!(report.intervals[0].socket_written, 20);
    }

    #[tokio::test]
    async fn progress_snapshot_arrives_before_the_run_finishes() {
        let (mut scenario, adapter, stop, sink) =
            scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        scenario.orders_per_second = 20;
        scenario.duration_secs = 2;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (progress_tx, mut progress_rx) = mpsc::channel(2);
        let run = tokio::spawn(async move {
            run_local_live_with_progress(&scenario, adapter, shutdown_rx, progress_tx).await
        });
        let first = tokio::time::timeout(Duration::from_millis(1_500), progress_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.counters.second, 0);
        assert_eq!(first.counters.socket_written, 20);
        assert_eq!(first.queue_delay.summary.count, 20);
        assert_eq!(first.request_to_ack.summary.count, 20);
        assert_eq!(first.actions.total().socket_written, 20);
        assert_eq!(first.dimensions.len(), 1);
        assert_eq!(
            first.action_request_to_ack.new_order.summary.count
                + first.action_request_to_ack.cancel.summary.count
                + first.action_request_to_ack.replace.summary.count,
            20
        );
        assert!(!run.is_finished());
        let report = run.await.unwrap().unwrap();
        let _ = shutdown_tx.send(true);
        let _ = stop.send(true);
        sink.await.unwrap();
        assert_eq!(report.interval_metrics_lost, 0);
        assert_eq!(report.interval_reports.len(), 2);
    }

    #[tokio::test]
    async fn undrained_progress_channel_invalidates_the_run() {
        let (mut scenario, adapter, stop, sink) =
            scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        scenario.orders_per_second = 20;
        scenario.duration_secs = 2;
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (progress_tx, _progress_rx) = mpsc::channel(1);
        let report = run_local_live_with_progress(&scenario, adapter, shutdown_rx, progress_tx)
            .await
            .unwrap();
        let _ = stop.send(true);
        sink.await.unwrap();
        assert_eq!(report.interval_metrics_lost, 1);
        assert!(!report.passed());
    }

    #[tokio::test]
    async fn cooperative_shutdown_stops_offering_and_still_drains() {
        let (mut scenario, adapter, stop, sink) =
            scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        scenario.duration_secs = 30;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = shutdown_tx.send(true);
        });
        let report = run_local_live_with_shutdown(&scenario, adapter, shutdown_rx)
            .await
            .unwrap();
        let _ = stop.send(true);
        sink.await.unwrap();
        assert!(report.interrupted);
        assert!(report.counters.offered < 3_000);
        report.counters.validate_conservation().unwrap();
        assert!(!report.passed());
    }

    #[tokio::test]
    async fn rejected_and_disconnected_targets_remain_conserved_failures() {
        let (scenario, adapter, stop, sink) = scenario_and_sink(SinkFaultMode::Reject).await;
        let report = run_local_live(&scenario, adapter).await.unwrap();
        let _ = stop.send(true);
        sink.await.unwrap();
        assert_eq!(report.counters.rejected, report.counters.socket_written);
        assert_eq!(
            report.rejection_reasons.backpressure,
            report.counters.rejected
        );
        report.counters.validate_conservation().unwrap();
    }

    #[tokio::test]
    async fn batched_out_of_order_acknowledgements_are_correlated() {
        let (mut scenario, adapter, stop, sink) =
            scenario_and_sink(SinkFaultMode::BatchedAck { batch: 4 }).await;
        scenario.in_flight_per_connection = 8;
        let report = run_local_live(&scenario, adapter).await.unwrap();
        let _ = stop.send(true);
        sink.await.unwrap();
        assert_eq!(report.counters.offered, 100);
        assert!(report.counters.socket_written > 0);
        assert_eq!(report.counters.accepted, report.counters.socket_written);
        assert_eq!(report.request_to_ack.count, report.counters.socket_written);
        assert_eq!(report.counters.protocol_failed, 0);
        report.counters.validate_conservation().unwrap();
    }

    #[tokio::test]
    async fn transport_disconnect_reconnects_without_reusing_logical_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(SinkCounters::default());
        let server_counters = Arc::clone(&counters);
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            let (second, _) = listener.accept().await.unwrap();
            let _ = crate::sink::serve_sink_connection(
                second,
                ReferenceSinkConfig::default(),
                server_counters,
            )
            .await;
        });
        let (mut scenario, adapter, stop, unused_sink) =
            scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        let _ = stop.send(true);
        unused_sink.await.unwrap();
        scenario.regions[0].endpoints[0].address = address.to_string();
        scenario.reconnect_base_delay_ms = 1;
        scenario.reconnect_max_delay_ms = 5;
        let report = run_local_live(&scenario, adapter).await.unwrap();
        report.counters.validate_conservation().unwrap();
        assert_eq!(report.counters.offered, 100);
        assert!(
            report.counters.transport_failed_before_write
                + report.counters.transport_failed_after_write
                >= 1
        );
        assert!(report.counters.accepted >= 95);
        server.await.unwrap();
        assert_eq!(counters.snapshot().received, report.counters.accepted);
    }

    #[tokio::test]
    async fn tls13_mtls_sink_path_uses_configured_identities() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey {
            cert: server_cert,
            key_pair: server_key,
        } = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let CertifiedKey {
            cert: client_cert,
            key_pair: client_key,
        } = generate_simple_self_signed(vec!["loadgen-client".to_string()]).unwrap();

        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_cert.der().clone()).unwrap();
        let verifier = WebPkiClientVerifier::builder(client_roots.into())
            .build()
            .unwrap();
        let server_config =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    vec![server_cert.der().clone()],
                    PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
                )
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(SinkCounters::default());
        let server_counters = Arc::clone(&counters);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = crate::sink::serve_sink_connection(
                tls,
                ReferenceSinkConfig::default(),
                server_counters,
            )
            .await;
        });

        let directory = std::env::temp_dir().join(format!(
            "dexos-loadgen-mtls-{}-{}",
            std::process::id(),
            crate::util::fnv1a_64(address.to_string().as_bytes())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let ca_file = directory.join("ca.pem");
        let cert_file = directory.join("client.pem");
        let key_file = directory.join("client-key.pem");
        std::fs::write(&ca_file, server_cert.pem()).unwrap();
        std::fs::write(&cert_file, client_cert.pem()).unwrap();
        std::fs::write(&key_file, client_key.serialize_pem()).unwrap();

        let (mut scenario, adapter, stop, plain_sink) =
            scenario_and_sink(SinkFaultMode::ImmediateAck).await;
        let _ = stop.send(true);
        plain_sink.await.unwrap();
        scenario.orders_per_second = 25;
        scenario.regions[0].endpoints[0].address = address.to_string();
        scenario.regions[0].endpoints[0].tls = TlsClientConfig {
            enabled: true,
            server_name: "localhost".to_string(),
            ca_file: ca_file.display().to_string(),
            client_cert_file: cert_file.display().to_string(),
            client_key_file: key_file.display().to_string(),
        };
        let report = run_local_live(&scenario, adapter).await.unwrap();
        assert_eq!(report.counters.socket_written, 25);
        assert_eq!(report.counters.accepted, 25);
        assert!(report.passed());
        server.await.unwrap();
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.received, 25);
        let _ = std::fs::remove_dir_all(directory);
    }
}
