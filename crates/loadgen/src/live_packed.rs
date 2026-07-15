//! Pipelined live runner for authenticated 32-128 record order batches.
//!
//! Every connection consumes an explicit server-issued sequence lease. The runner
//! distinguishes durable admission, deterministic execution, and consensus finality;
//! validator reports are valid only when TLS 1.3 is used and every record receives a
//! correlated `Finalized` receipt carrying a checkpoint height.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use codec::{Frame, TrafficClass, FRAME_HEADER_LEN};
use network::{
    decode_order_batch_receipt_frame, OrderBatchReceipt, OrderBatchReceiptStage,
    MSG_TYPE_ORDER_BATCH, ORDER_BATCH_RECEIPT_LEN,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::command::{CommandKind, SessionState};
use crate::config::LoadScenario;
use crate::distributed::{AuthenticatedAssignment, ControlAuthenticator};
use crate::live_rpc::{connect_stream, LiveRpcError, LiveStream, LiveTransport};
use crate::packed_adapter::{PackedAdapterError, PackedSessionAdapter, PackedSessionConfig};
use crate::realtime::{MetricsError, NanoHistogram};
use crate::rng::Lcg;
use crate::util::{fnv1a_64, fold_u64};

const MIN_VALIDATOR_WARMUP_SECS: u64 = 60;

/// Highest lifecycle boundary required before a batch is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackedCompletionBoundary {
    /// Durable admission followed by deterministic execution; component evidence only.
    Executed,
    /// Inclusion in a consensus checkpoint; required for validator qualification.
    Finalized,
}

/// One server-issued, disjoint packed-session lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedConnectionLease {
    /// Target socket assigned to this connection.
    pub endpoint: SocketAddr,
    /// Optional source address used to bind the outgoing socket.
    pub source_ip: Option<IpAddr>,
    /// Authenticated identity and disjoint command/batch sequence ranges.
    pub session: PackedSessionConfig,
}

/// Runtime settings for an authenticated packed campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePackedConfig {
    /// Exactly one lease per persistent connection.
    pub leases: Vec<PackedConnectionLease>,
    /// Fixed records per authenticated batch, in 32..=128.
    pub batch_size: u8,
    /// Maximum correlated batches written before receipts are drained.
    pub max_in_flight_batches: usize,
    /// Deadline for each next lifecycle receipt.
    pub receipt_timeout: Duration,
    /// Warm-up traffic duration excluded from returned counters.
    pub warmup_secs: u64,
    /// Future local warm-up lead used to connect every worker first.
    pub start_lead: Duration,
    /// Explicit plaintext-development or TLS 1.3 transport posture.
    pub transport: LiveTransport,
    /// Lifecycle proof required for every measured batch.
    pub completion_boundary: PackedCompletionBoundary,
}

/// Cumulative, conservation-friendly packed lifecycle totals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedLifecycleCounters {
    pub offered_records: u64,
    pub socket_written_batches: u64,
    pub socket_written_records: u64,
    pub admitted_records: u64,
    pub executed_records: u64,
    pub failed_records: u64,
    pub finalized_records: u64,
}

/// Exact lifecycle and raw receipt histograms attributed to one scheduled
/// steady-state second. Receipt arrival may occur later; attribution follows
/// the batch's open-loop schedule ordinal so controller aggregation cannot
/// shift slow finality into a later interval or hide coordinated omission.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedSteadyInterval {
    pub ordinal: u64,
    pub counters: PackedLifecycleCounters,
    pub accepted_new_records: u64,
    pub accepted_cancel_records: u64,
    pub accepted_replace_records: u64,
    pub action_attribution_complete: bool,
    pub admission_receipt_ns: NanoHistogram,
    pub execution_receipt_ns: NanoHistogram,
    pub finality_receipt_ns: NanoHistogram,
    pub highest_checkpoint: Option<u64>,
}

impl PackedSteadyInterval {
    fn empty(ordinal: u64) -> Self {
        Self {
            ordinal,
            action_attribution_complete: true,
            ..Self::default()
        }
    }

    fn checked_merge(&mut self, other: &Self) -> Result<(), LivePackedError> {
        if self.ordinal != other.ordinal {
            return Err(LivePackedError::IntervalMismatch);
        }
        self.counters.checked_merge(other.counters)?;
        self.accepted_new_records = self
            .accepted_new_records
            .checked_add(other.accepted_new_records)
            .ok_or(LivePackedError::CounterOverflow)?;
        self.accepted_cancel_records = self
            .accepted_cancel_records
            .checked_add(other.accepted_cancel_records)
            .ok_or(LivePackedError::CounterOverflow)?;
        self.accepted_replace_records = self
            .accepted_replace_records
            .checked_add(other.accepted_replace_records)
            .ok_or(LivePackedError::CounterOverflow)?;
        self.action_attribution_complete &= other.action_attribution_complete;
        self.admission_receipt_ns
            .checked_merge(&other.admission_receipt_ns)?;
        self.execution_receipt_ns
            .checked_merge(&other.execution_receipt_ns)?;
        self.finality_receipt_ns
            .checked_merge(&other.finality_receipt_ns)?;
        self.highest_checkpoint = match (self.highest_checkpoint, other.highest_checkpoint) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
        Ok(())
    }
}

impl PackedLifecycleCounters {
    fn checked_merge(&mut self, other: Self) -> Result<(), LivePackedError> {
        macro_rules! add {
            ($field:ident) => {
                self.$field = self
                    .$field
                    .checked_add(other.$field)
                    .ok_or(LivePackedError::CounterOverflow)?;
            };
        }
        add!(offered_records);
        add!(socket_written_batches);
        add!(socket_written_records);
        add!(admitted_records);
        add!(executed_records);
        add!(failed_records);
        add!(finalized_records);
        Ok(())
    }

    fn validate(self, boundary: PackedCompletionBoundary) -> Result<(), LivePackedError> {
        if self.offered_records != self.socket_written_records
            || self.socket_written_records != self.admitted_records
            || self.admitted_records
                != self
                    .executed_records
                    .checked_add(self.failed_records)
                    .ok_or(LivePackedError::CounterOverflow)?
            || self.finalized_records > self.executed_records
            || (boundary == PackedCompletionBoundary::Finalized
                && self.finalized_records != self.executed_records)
        {
            return Err(LivePackedError::Conservation);
        }
        Ok(())
    }
}

/// Successful packed campaign report. Signing material and lease details are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivePackedReport {
    pub mode: String,
    pub target_profile: String,
    pub completion_boundary: PackedCompletionBoundary,
    pub batch_size: u8,
    pub planned_records: u64,
    pub warmup_planned_records: u64,
    pub elapsed_ns: u64,
    pub drain_elapsed_ns: u64,
    pub counters: PackedLifecycleCounters,
    pub admission_receipt_ns: NanoHistogram,
    pub execution_receipt_ns: NanoHistogram,
    pub finality_receipt_ns: NanoHistogram,
    pub highest_checkpoint: Option<u64>,
    pub steady_intervals: Vec<PackedSteadyInterval>,
}

/// Authenticated controller identity wrapped around one successful packed
/// agent report. This is the raw regional input consumed by the composed-run
/// builder; lease material and signing seeds remain omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedPackedAgentReport {
    pub schema_version: u32,
    pub assignment: AuthenticatedAssignment,
    pub report_sha256: [u8; 32],
    pub report_tag: [u8; 32],
    pub report: LivePackedReport,
}

impl DistributedPackedAgentReport {
    pub const SCHEMA_VERSION: u32 = 1;

    /// Bind the exact successful report bytes to its authenticated assignment.
    pub fn authenticated(
        assignment: AuthenticatedAssignment,
        report: LivePackedReport,
        authenticator: &ControlAuthenticator,
    ) -> Result<Self, LivePackedError> {
        let report_sha256 = report_sha256(&report)?;
        let report_tag = authenticator.report_tag(&assignment.assignment, &report_sha256);
        Ok(Self {
            schema_version: Self::SCHEMA_VERSION,
            assignment,
            report_sha256,
            report_tag,
            report,
        })
    }

    /// Verify the assignment envelope, exact report digest, and report HMAC.
    pub fn verify(&self, authenticator: &ControlAuthenticator) -> Result<(), LivePackedError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(LivePackedError::ReportAuthentication);
        }
        self.assignment
            .verify_for(&self.assignment.assignment.agent_id, authenticator)
            .map_err(|_| LivePackedError::ReportAuthentication)?;
        let digest = report_sha256(&self.report)?;
        if digest != self.report_sha256
            || !authenticator.verify_report(
                &self.assignment.assignment,
                &self.report_sha256,
                &self.report_tag,
            )
        {
            return Err(LivePackedError::ReportAuthentication);
        }
        Ok(())
    }
}

fn report_sha256(report: &LivePackedReport) -> Result<[u8; 32], LivePackedError> {
    let bytes = serde_json::to_vec(report).map_err(|_| LivePackedError::ReportEncoding)?;
    Ok(Sha256::digest(bytes).into())
}

impl LivePackedReport {
    /// Records proven through the selected lifecycle boundary per configured second.
    #[must_use]
    pub fn completed_records_per_second(&self) -> u64 {
        if self.elapsed_ns == 0 {
            return 0;
        }
        let completed = match self.completion_boundary {
            PackedCompletionBoundary::Executed => self.counters.executed_records,
            PackedCompletionBoundary::Finalized => self.counters.finalized_records,
        };
        u64::try_from(
            u128::from(completed).saturating_mul(1_000_000_000) / u128::from(self.elapsed_ns),
        )
        .unwrap_or(u64::MAX)
    }
}

/// Run an exact-rate authenticated packed campaign over persistent connections.
pub async fn run_live_packed(
    scenario: &LoadScenario,
    config: &LivePackedConfig,
    target_profile: &str,
) -> Result<LivePackedReport, LivePackedError> {
    scenario
        .validate()
        .map_err(|error| LivePackedError::Scenario(error.to_string()))?;
    validate_config(scenario, config, target_profile)?;

    let batch_size = u64::from(config.batch_size);
    let aggregate_batches_per_second = scenario.orders_per_second / batch_size;
    let connection_count =
        u64::try_from(config.leases.len()).map_err(|_| LivePackedError::InvalidConfig)?;
    let base_rate = aggregate_batches_per_second / connection_count;
    let remainder = aggregate_batches_per_second % connection_count;
    let warmup_start = Instant::now() + config.start_lead;
    let steady_start = warmup_start + Duration::from_secs(config.warmup_secs);
    let elapsed_ns = scenario.duration_secs.saturating_mul(1_000_000_000);
    let steady_end = steady_start + Duration::from_nanos(elapsed_ns);

    let mut tasks = JoinSet::new();
    for (index, lease) in config.leases.iter().copied().enumerate() {
        let connection = u32::try_from(index).map_err(|_| LivePackedError::InvalidConfig)?;
        let rate = base_rate + u64::from(u64::try_from(index).unwrap_or(u64::MAX) < remainder);
        let scenario = scenario.clone();
        let transport = config.transport.clone();
        let batch_size = config.batch_size;
        let max_in_flight = config.max_in_flight_batches;
        let receipt_timeout = config.receipt_timeout;
        let warmup_secs = config.warmup_secs;
        let duration_secs = scenario.duration_secs;
        let boundary = config.completion_boundary;
        tasks.spawn(async move {
            run_connection(
                connection,
                rate,
                warmup_start,
                steady_start,
                warmup_secs,
                duration_secs,
                &scenario,
                lease,
                batch_size,
                max_in_flight,
                receipt_timeout,
                boundary,
                &transport,
            )
            .await
        });
    }

    let mut aggregate = ConnectionReport::default();
    while let Some(result) = tasks.join_next().await {
        let report = result.map_err(|error| LivePackedError::WorkerJoin(error.to_string()))??;
        aggregate.checked_merge(report)?;
    }
    aggregate.counters.validate(config.completion_boundary)?;
    if aggregate.intervals.len()
        != usize::try_from(scenario.duration_secs).map_err(|_| LivePackedError::InvalidConfig)?
    {
        return Err(LivePackedError::IntervalMismatch);
    }
    for (ordinal, interval) in aggregate.intervals.iter().enumerate() {
        if interval.ordinal != u64::try_from(ordinal).map_err(|_| LivePackedError::InvalidConfig)?
            || interval.counters.offered_records != scenario.orders_per_second
        {
            return Err(LivePackedError::IntervalMismatch);
        }
        interval.counters.validate(config.completion_boundary)?;
    }
    let planned_records = scenario.planned_actions();
    if aggregate.counters.offered_records != planned_records {
        return Err(LivePackedError::PlannedMismatch {
            planned: planned_records,
            offered: aggregate.counters.offered_records,
        });
    }
    let drain_elapsed_ns = u64::try_from(
        Instant::now()
            .saturating_duration_since(steady_end)
            .as_nanos(),
    )
    .unwrap_or(u64::MAX);
    Ok(LivePackedReport {
        mode: "live-authenticated-packed".to_string(),
        target_profile: target_profile.to_string(),
        completion_boundary: config.completion_boundary,
        batch_size: config.batch_size,
        planned_records,
        warmup_planned_records: scenario
            .orders_per_second
            .checked_mul(config.warmup_secs)
            .ok_or(LivePackedError::CounterOverflow)?,
        elapsed_ns,
        drain_elapsed_ns,
        counters: aggregate.counters,
        admission_receipt_ns: aggregate.admission_receipt_ns,
        execution_receipt_ns: aggregate.execution_receipt_ns,
        finality_receipt_ns: aggregate.finality_receipt_ns,
        highest_checkpoint: aggregate.highest_checkpoint,
        steady_intervals: aggregate.intervals,
    })
}

fn validate_config(
    scenario: &LoadScenario,
    config: &LivePackedConfig,
    target_profile: &str,
) -> Result<(), LivePackedError> {
    if config.leases.is_empty()
        || !(32..=128).contains(&config.batch_size)
        || config.max_in_flight_batches == 0
        || config.receipt_timeout.is_zero()
        || !scenario
            .orders_per_second
            .is_multiple_of(u64::from(config.batch_size))
        || u64::try_from(config.leases.len()).unwrap_or(u64::MAX)
            > scenario.orders_per_second / u64::from(config.batch_size)
    {
        return Err(LivePackedError::InvalidConfig);
    }
    if target_profile != "component" && target_profile != "validator" {
        return Err(LivePackedError::InvalidTargetProfile);
    }
    if target_profile == "validator" {
        if matches!(config.transport, LiveTransport::DevPlaintext) {
            return Err(LivePackedError::ValidatorTlsRequired);
        }
        if config.completion_boundary != PackedCompletionBoundary::Finalized {
            return Err(LivePackedError::ValidatorFinalityRequired);
        }
        if config.warmup_secs < MIN_VALIDATOR_WARMUP_SECS {
            return Err(LivePackedError::ValidatorWarmupRequired);
        }
    }
    for lease in &config.leases {
        if lease.session.max_in_flight_batches < config.max_in_flight_batches {
            return Err(LivePackedError::LeaseCapacity);
        }
        if lease.session.batch_sequence_stride == 0
            || (lease.session.command_sequence_stride != 0
                && lease.session.command_sequence_stride < u64::from(config.batch_size))
        {
            return Err(LivePackedError::InvalidSequenceStride);
        }
    }
    validate_disjoint_leases(scenario, config)
}

fn validate_disjoint_leases(
    scenario: &LoadScenario,
    config: &LivePackedConfig,
) -> Result<(), LivePackedError> {
    let total_secs = config
        .warmup_secs
        .checked_add(scenario.duration_secs)
        .ok_or(LivePackedError::CounterOverflow)?;
    let total_batch_rate = scenario.orders_per_second / u64::from(config.batch_size);
    let count = u64::try_from(config.leases.len()).map_err(|_| LivePackedError::InvalidConfig)?;
    let base = total_batch_rate / count;
    let remainder = total_batch_rate % count;
    let mut ranges = Vec::with_capacity(config.leases.len());
    for (index, lease) in config.leases.iter().enumerate() {
        let ordinal = u64::try_from(index).map_err(|_| LivePackedError::InvalidConfig)?;
        let batches = (base + u64::from(ordinal < remainder))
            .checked_mul(total_secs)
            .ok_or(LivePackedError::CounterOverflow)?;
        let records = batches
            .checked_mul(u64::from(config.batch_size))
            .ok_or(LivePackedError::CounterOverflow)?;
        let command_end = lease
            .session
            .first_command_sequence
            .checked_add(records)
            .ok_or(LivePackedError::LeaseExhausted)?;
        let batch_end = lease
            .session
            .first_batch_sequence
            .checked_add(batches)
            .ok_or(LivePackedError::LeaseExhausted)?;
        ranges.push((
            lease.session.first_command_sequence..command_end,
            lease.session.first_batch_sequence..batch_end,
            lease.session.session_ref,
            lease.session.client_id,
        ));
    }
    for left in 0..ranges.len() {
        for right in (left + 1)..ranges.len() {
            if ranges[left].0.start == ranges[right].0.start {
                return Err(LivePackedError::OverlappingCommandLease);
            }
            if ranges[left].1.start == ranges[right].1.start {
                return Err(LivePackedError::OverlappingBatchLease);
            }
            if ranges[left].2 == ranges[right].2 || ranges[left].3 == ranges[right].3 {
                return Err(LivePackedError::DuplicateIdentity);
            }
        }
    }
    if ranges.len() > 1 {
        let batch_stride = config.leases[0].session.batch_sequence_stride;
        let command_stride = config.leases[0].session.command_sequence_stride;
        if command_stride
            != batch_stride
                .checked_mul(u64::from(config.batch_size))
                .ok_or(LivePackedError::CounterOverflow)?
            || config.leases.iter().any(|lease| {
                lease.session.batch_sequence_stride != batch_stride
                    || lease.session.command_sequence_stride != command_stride
            })
        {
            return Err(LivePackedError::InvalidSequenceStride);
        }
        let mut starts: Vec<_> = ranges
            .iter()
            .map(|range| (range.1.start, range.0.start))
            .collect();
        starts.sort_unstable();
        let (batch_base, command_base) = starts[0];
        for (batch, command) in starts {
            let batch_offset = batch
                .checked_sub(batch_base)
                .ok_or(LivePackedError::UnstripedSequenceLease)?;
            let expected_command = command_base
                .checked_add(
                    batch_offset
                        .checked_mul(u64::from(config.batch_size))
                        .ok_or(LivePackedError::CounterOverflow)?,
                )
                .ok_or(LivePackedError::CounterOverflow)?;
            if batch_offset >= batch_stride || command != expected_command {
                return Err(LivePackedError::UnstripedSequenceLease);
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct ConnectionReport {
    counters: PackedLifecycleCounters,
    admission_receipt_ns: NanoHistogram,
    execution_receipt_ns: NanoHistogram,
    finality_receipt_ns: NanoHistogram,
    highest_checkpoint: Option<u64>,
    intervals: Vec<PackedSteadyInterval>,
}

impl ConnectionReport {
    fn new(duration_secs: u64) -> Result<Self, LivePackedError> {
        usize::try_from(duration_secs).map_err(|_| LivePackedError::InvalidConfig)?;
        Ok(Self {
            intervals: (0..duration_secs)
                .map(PackedSteadyInterval::empty)
                .collect::<Vec<_>>(),
            ..Self::default()
        })
    }

    fn checked_merge(&mut self, other: Self) -> Result<(), LivePackedError> {
        self.counters.checked_merge(other.counters)?;
        self.admission_receipt_ns
            .checked_merge(&other.admission_receipt_ns)?;
        self.execution_receipt_ns
            .checked_merge(&other.execution_receipt_ns)?;
        self.finality_receipt_ns
            .checked_merge(&other.finality_receipt_ns)?;
        self.highest_checkpoint = match (self.highest_checkpoint, other.highest_checkpoint) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
        if self.intervals.is_empty() {
            self.intervals = other.intervals;
        } else if self.intervals.len() == other.intervals.len() {
            for (left, right) in self.intervals.iter_mut().zip(&other.intervals) {
                left.checked_merge(right)?;
            }
        } else {
            return Err(LivePackedError::IntervalMismatch);
        }
        Ok(())
    }

    fn interval_mut(&mut self, ordinal: u64) -> Result<&mut PackedSteadyInterval, LivePackedError> {
        let index = usize::try_from(ordinal).map_err(|_| LivePackedError::IntervalMismatch)?;
        self.intervals
            .get_mut(index)
            .ok_or(LivePackedError::IntervalMismatch)
    }
}

struct PendingBatch {
    batch_sequence: u64,
    first_sequence: u64,
    record_count: u8,
    scheduled_at: Instant,
    admitted: bool,
    executed: bool,
    interval_ordinal: u64,
    new_records: u8,
    cancel_records: u8,
    replace_records: u8,
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    connection: u32,
    batch_rate: u64,
    warmup_start: Instant,
    steady_start: Instant,
    warmup_secs: u64,
    duration_secs: u64,
    scenario: &LoadScenario,
    lease: PackedConnectionLease,
    batch_size: u8,
    max_in_flight: usize,
    receipt_timeout: Duration,
    boundary: PackedCompletionBoundary,
    transport: &LiveTransport,
) -> Result<ConnectionReport, LivePackedError> {
    let mut stream = connect_stream(lease.endpoint, lease.source_ip, transport).await?;
    tokio::time::sleep_until(warmup_start).await;
    let mut adapter = PackedSessionAdapter::new(lease.session)?;
    let mut generator = SessionState::new(connection);
    let mut rng = Lcg::new(fold_u64(
        scenario.seed,
        fold_u64(
            fnv1a_64(b"dexos.loadgen.live-packed.v1"),
            u64::from(connection),
        ),
    ));
    let mut transport_sequence = 0u64;
    let mut receipt_sequence = 0u64;
    execute_phase(
        &mut stream,
        batch_rate,
        warmup_start,
        warmup_secs,
        scenario,
        &mut generator,
        &mut rng,
        &mut adapter,
        batch_size,
        max_in_flight,
        receipt_timeout,
        boundary,
        &mut transport_sequence,
        &mut receipt_sequence,
        None,
    )
    .await?;
    let mut report = ConnectionReport::new(duration_secs)?;
    execute_phase(
        &mut stream,
        batch_rate,
        steady_start,
        duration_secs,
        scenario,
        &mut generator,
        &mut rng,
        &mut adapter,
        batch_size,
        max_in_flight,
        receipt_timeout,
        boundary,
        &mut transport_sequence,
        &mut receipt_sequence,
        Some(&mut report),
    )
    .await?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn execute_phase(
    stream: &mut LiveStream,
    batch_rate: u64,
    phase_start: Instant,
    duration_secs: u64,
    scenario: &LoadScenario,
    generator: &mut SessionState,
    rng: &mut Lcg,
    adapter: &mut PackedSessionAdapter,
    batch_size: u8,
    max_in_flight: usize,
    receipt_timeout: Duration,
    boundary: PackedCompletionBoundary,
    transport_sequence: &mut u64,
    receipt_sequence: &mut u64,
    mut report: Option<&mut ConnectionReport>,
) -> Result<(), LivePackedError> {
    let planned_batches = batch_rate
        .checked_mul(duration_secs)
        .ok_or(LivePackedError::CounterOverflow)?;
    let mut next_batch = 0u64;
    let mut commands = Vec::with_capacity(usize::from(batch_size));
    let mut pending = Vec::with_capacity(max_in_flight);
    while next_batch < planned_batches {
        pending.clear();
        while pending.len() < max_in_flight && next_batch < planned_batches {
            let interval_ordinal = next_batch / batch_rate;
            let due_ns = u64::try_from(
                u128::from(next_batch).saturating_mul(1_000_000_000) / u128::from(batch_rate),
            )
            .unwrap_or(u64::MAX);
            let due = phase_start + Duration::from_nanos(due_ns);
            tokio::time::sleep_until(due).await;
            commands.clear();
            let mut new_records = 0u8;
            let mut cancel_records = 0u8;
            let mut replace_records = 0u8;
            for _ in 0..batch_size {
                let command = generator.next_command(rng, scenario);
                match command.kind {
                    CommandKind::NewOrder => {
                        new_records = new_records
                            .checked_add(1)
                            .ok_or(LivePackedError::CounterOverflow)?;
                    }
                    CommandKind::Cancel => {
                        cancel_records = cancel_records
                            .checked_add(1)
                            .ok_or(LivePackedError::CounterOverflow)?;
                    }
                    CommandKind::Replace => {
                        replace_records = replace_records
                            .checked_add(1)
                            .ok_or(LivePackedError::CounterOverflow)?;
                    }
                }
                commands.push(command);
            }
            let prepared = adapter.prepare_batch(&commands)?;
            let bytes = Frame {
                class: TrafficClass::NewOrder,
                msg_type: MSG_TYPE_ORDER_BATCH,
                sequence: *transport_sequence,
                payload: prepared.bytes,
            }
            .encode()?;
            *transport_sequence = transport_sequence
                .checked_add(1)
                .ok_or(LivePackedError::SequenceExhausted)?;
            stream.write_all(&bytes).await?;
            if let Some(metrics) = report.as_deref_mut() {
                record_written(&mut metrics.counters, batch_size)?;
                record_written(
                    &mut metrics.interval_mut(interval_ordinal)?.counters,
                    batch_size,
                )?;
            }
            pending.push(PendingBatch {
                batch_sequence: prepared.batch_sequence,
                first_sequence: prepared.first_sequence,
                record_count: prepared.record_count,
                scheduled_at: due,
                admitted: false,
                executed: false,
                interval_ordinal,
                new_records,
                cancel_records,
                replace_records,
            });
            next_batch = next_batch
                .checked_add(1)
                .ok_or(LivePackedError::CounterOverflow)?;
        }
        stream.flush().await?;
        while !pending.is_empty() {
            let frame = tokio::time::timeout(receipt_timeout, read_receipt_frame(stream))
                .await
                .map_err(|_| LivePackedError::ReceiptTimeout)??;
            if frame.sequence != *receipt_sequence {
                return Err(LivePackedError::ReceiptSequence {
                    expected: *receipt_sequence,
                    actual: frame.sequence,
                });
            }
            *receipt_sequence = receipt_sequence
                .checked_add(1)
                .ok_or(LivePackedError::SequenceExhausted)?;
            let receipt = decode_order_batch_receipt_frame(&frame)?;
            let position = pending
                .iter()
                .position(|item| item.batch_sequence == receipt.batch_sequence)
                .ok_or(LivePackedError::UnknownReceipt(receipt.batch_sequence))?;
            apply_receipt(
                &mut pending[position],
                &receipt,
                adapter,
                report.as_deref_mut(),
            )?;
            let complete = match boundary {
                PackedCompletionBoundary::Executed => pending[position].executed,
                PackedCompletionBoundary::Finalized => {
                    receipt.stage == OrderBatchReceiptStage::Finalized
                }
            };
            if complete {
                pending.swap_remove(position);
            }
        }
    }
    Ok(())
}

fn record_written(
    counters: &mut PackedLifecycleCounters,
    batch_size: u8,
) -> Result<(), LivePackedError> {
    counters.offered_records = counters
        .offered_records
        .checked_add(u64::from(batch_size))
        .ok_or(LivePackedError::CounterOverflow)?;
    counters.socket_written_batches = counters
        .socket_written_batches
        .checked_add(1)
        .ok_or(LivePackedError::CounterOverflow)?;
    counters.socket_written_records = counters
        .socket_written_records
        .checked_add(u64::from(batch_size))
        .ok_or(LivePackedError::CounterOverflow)?;
    Ok(())
}

fn apply_receipt(
    pending: &mut PendingBatch,
    receipt: &OrderBatchReceipt,
    adapter: &mut PackedSessionAdapter,
    mut report: Option<&mut ConnectionReport>,
) -> Result<(), LivePackedError> {
    if receipt.first_sequence != pending.first_sequence
        || receipt.record_count != pending.record_count
    {
        return Err(LivePackedError::ReceiptMismatch);
    }
    if receipt.stage == OrderBatchReceiptStage::Rejected {
        return Err(LivePackedError::Rejected {
            batch_sequence: receipt.batch_sequence,
            code: receipt.rejection_code,
        });
    }
    let received_at = Instant::now();
    let latency = u64::try_from(
        received_at
            .saturating_duration_since(pending.scheduled_at)
            .as_nanos(),
    )
    .unwrap_or(u64::MAX);
    if !pending.admitted {
        adapter.acknowledge_receipt(receipt)?;
        pending.admitted = true;
        if let Some(metrics) = report.as_deref_mut() {
            record_admitted(
                &mut metrics.counters,
                &mut metrics.admission_receipt_ns,
                receipt,
                latency,
            )?;
            let interval = metrics.interval_mut(pending.interval_ordinal)?;
            record_admitted(
                &mut interval.counters,
                &mut interval.admission_receipt_ns,
                receipt,
                latency,
            )?;
        }
    } else if receipt.stage == OrderBatchReceiptStage::Admitted {
        return Err(LivePackedError::DuplicateStage);
    }
    if matches!(
        receipt.stage,
        OrderBatchReceiptStage::Executed | OrderBatchReceiptStage::Finalized
    ) && !pending.executed
    {
        pending.executed = true;
        if let Some(metrics) = report.as_deref_mut() {
            record_executed(
                &mut metrics.counters,
                &mut metrics.execution_receipt_ns,
                receipt,
                latency,
            )?;
            let interval = metrics.interval_mut(pending.interval_ordinal)?;
            record_executed(
                &mut interval.counters,
                &mut interval.execution_receipt_ns,
                receipt,
                latency,
            )?;
            if receipt.failed == 0 {
                interval.accepted_new_records = interval
                    .accepted_new_records
                    .checked_add(u64::from(pending.new_records))
                    .ok_or(LivePackedError::CounterOverflow)?;
                interval.accepted_cancel_records = interval
                    .accepted_cancel_records
                    .checked_add(u64::from(pending.cancel_records))
                    .ok_or(LivePackedError::CounterOverflow)?;
                interval.accepted_replace_records = interval
                    .accepted_replace_records
                    .checked_add(u64::from(pending.replace_records))
                    .ok_or(LivePackedError::CounterOverflow)?;
            } else {
                interval.action_attribution_complete = false;
            }
        }
    } else if receipt.stage == OrderBatchReceiptStage::Executed && pending.executed {
        return Err(LivePackedError::DuplicateStage);
    }
    if receipt.stage == OrderBatchReceiptStage::Finalized {
        if let Some(metrics) = report {
            record_finalized(
                &mut metrics.counters,
                &mut metrics.finality_receipt_ns,
                &mut metrics.highest_checkpoint,
                receipt,
                latency,
            )?;
            let interval = metrics.interval_mut(pending.interval_ordinal)?;
            record_finalized(
                &mut interval.counters,
                &mut interval.finality_receipt_ns,
                &mut interval.highest_checkpoint,
                receipt,
                latency,
            )?;
        }
    }
    Ok(())
}

fn record_admitted(
    counters: &mut PackedLifecycleCounters,
    histogram: &mut NanoHistogram,
    receipt: &OrderBatchReceipt,
    latency: u64,
) -> Result<(), LivePackedError> {
    counters.admitted_records = counters
        .admitted_records
        .checked_add(u64::from(receipt.admitted))
        .ok_or(LivePackedError::CounterOverflow)?;
    histogram.record_n(latency, u64::from(receipt.admitted));
    Ok(())
}

fn record_executed(
    counters: &mut PackedLifecycleCounters,
    histogram: &mut NanoHistogram,
    receipt: &OrderBatchReceipt,
    latency: u64,
) -> Result<(), LivePackedError> {
    counters.executed_records = counters
        .executed_records
        .checked_add(u64::from(receipt.executed))
        .ok_or(LivePackedError::CounterOverflow)?;
    counters.failed_records = counters
        .failed_records
        .checked_add(u64::from(receipt.failed))
        .ok_or(LivePackedError::CounterOverflow)?;
    histogram.record_n(
        latency,
        u64::from(receipt.executed) + u64::from(receipt.failed),
    );
    Ok(())
}

fn record_finalized(
    counters: &mut PackedLifecycleCounters,
    histogram: &mut NanoHistogram,
    highest_checkpoint: &mut Option<u64>,
    receipt: &OrderBatchReceipt,
    latency: u64,
) -> Result<(), LivePackedError> {
    counters.finalized_records = counters
        .finalized_records
        .checked_add(u64::from(receipt.finalized))
        .ok_or(LivePackedError::CounterOverflow)?;
    histogram.record_n(latency, u64::from(receipt.finalized));
    *highest_checkpoint = match (*highest_checkpoint, receipt.checkpoint_height) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    };
    Ok(())
}

async fn read_receipt_frame(stream: &mut LiveStream) -> Result<Frame, LivePackedError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let declared = usize::try_from(u32::from_le_bytes([
        header[15], header[16], header[17], header[18],
    ]))
    .map_err(|_| LivePackedError::ReceiptOversize)?;
    if declared != ORDER_BATCH_RECEIPT_LEN {
        return Err(LivePackedError::ReceiptOversize);
    }
    let mut bytes = vec![0; FRAME_HEADER_LEN + declared];
    bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream.read_exact(&mut bytes[FRAME_HEADER_LEN..]).await?;
    let (frame, consumed) = Frame::decode_with_max(&bytes, ORDER_BATCH_RECEIPT_LEN)?;
    if consumed != bytes.len() {
        return Err(LivePackedError::ReceiptOversize);
    }
    Ok(frame)
}

/// Packed campaign failure. Any variant invalidates a qualification report.
#[derive(Debug, thiserror::Error)]
pub enum LivePackedError {
    #[error("invalid live packed configuration")]
    InvalidConfig,
    #[error("packed steady interval attribution is incomplete or inconsistent")]
    IntervalMismatch,
    #[error("packed agent report authentication failed")]
    ReportAuthentication,
    #[error("packed agent report could not be canonically encoded")]
    ReportEncoding,
    #[error("target profile must be `component` or `validator`")]
    InvalidTargetProfile,
    #[error("validator packed campaigns require TLS 1.3")]
    ValidatorTlsRequired,
    #[error("validator packed campaigns require finalized checkpoint receipts")]
    ValidatorFinalityRequired,
    #[error("validator packed campaigns require at least 60 seconds of warm-up")]
    ValidatorWarmupRequired,
    #[error("configured pipeline exceeds a session lease capacity")]
    LeaseCapacity,
    #[error("packed command sequence leases overlap")]
    OverlappingCommandLease,
    #[error("packed batch sequence leases overlap")]
    OverlappingBatchLease,
    #[error("multi-connection packed leases are not globally striped")]
    UnstripedSequenceLease,
    #[error("packed sequence lease stride is invalid or inconsistent")]
    InvalidSequenceStride,
    #[error("packed session_ref or client_id is duplicated")]
    DuplicateIdentity,
    #[error("packed session lease sequence range is exhausted")]
    LeaseExhausted,
    #[error("invalid load scenario: {0}")]
    Scenario(String),
    #[error(transparent)]
    Transport(#[from] LiveRpcError),
    #[error("packed runner I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packed frame codec error: {0}")]
    Codec(#[from] codec::CodecError),
    #[error("packed receipt codec error: {0}")]
    Receipt(#[from] network::OrderBatchReceiptError),
    #[error(transparent)]
    Adapter(#[from] PackedAdapterError),
    #[error(transparent)]
    Metrics(#[from] MetricsError),
    #[error("packed lifecycle counter overflow")]
    CounterOverflow,
    #[error("packed lifecycle counters do not conserve")]
    Conservation,
    #[error("packed transport or receipt sequence exhausted")]
    SequenceExhausted,
    #[error("packed receipt deadline elapsed")]
    ReceiptTimeout,
    #[error("packed receipt sequence mismatch: expected {expected}, got {actual}")]
    ReceiptSequence { expected: u64, actual: u64 },
    #[error("unknown packed batch receipt {0}")]
    UnknownReceipt(u64),
    #[error("packed receipt does not match its leased sequence range")]
    ReceiptMismatch,
    #[error("duplicate packed lifecycle receipt stage")]
    DuplicateStage,
    #[error("packed batch {batch_sequence} rejected with code {code}")]
    Rejected { batch_sequence: u64, code: u16 },
    #[error("packed receipt frame has an invalid fixed length")]
    ReceiptOversize,
    #[error("packed worker failed: {0}")]
    WorkerJoin(String),
    #[error("planned/offered mismatch: planned={planned}, offered={offered}")]
    PlannedMismatch { planned: u64, offered: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyPair;
    use network::{
        encode_order_batch_receipt_frame, AuthenticatedOrderBatchCodec, OrderBatchCodec,
    };
    use tokio::net::TcpListener;
    use types::AccountId;

    fn session(first_command_sequence: u64) -> PackedSessionConfig {
        PackedSessionConfig {
            destination: [9; 32],
            session_ref: 7,
            account: AccountId::new(3),
            client_id: 44,
            nonce_base: 1_000,
            signing_seed: [5; 32],
            first_batch_sequence: 20,
            first_command_sequence,
            batch_sequence_stride: 1,
            command_sequence_stride: 0,
            max_in_flight_batches: 4,
            max_live_orders: 256,
        }
    }

    #[tokio::test]
    async fn component_runner_pipelines_and_reconciles_executed_receipts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut next_receipt_sequence = 0;
            for transport_sequence in 0..4 {
                let mut header = [0; FRAME_HEADER_LEN];
                stream.read_exact(&mut header).await.unwrap();
                let declared = u32::from_le_bytes(header[15..19].try_into().unwrap()) as usize;
                let mut bytes = vec![0; FRAME_HEADER_LEN + declared];
                bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
                stream
                    .read_exact(&mut bytes[FRAME_HEADER_LEN..])
                    .await
                    .unwrap();
                let (frame, consumed) = Frame::decode(&bytes).unwrap();
                assert_eq!(consumed, bytes.len());
                assert_eq!(frame.sequence, transport_sequence);
                let verified =
                    AuthenticatedOrderBatchCodec::verify(&frame.payload, &[9; 32]).unwrap();
                assert_eq!(verified.signer, KeyPair::from_seed(&[5; 32]).public());
                assert_eq!(verified.binding.session_ref, 7);
                assert_eq!(verified.binding.account, AccountId::new(3));
                let record_count =
                    OrderBatchCodec::inspect_record_count(verified.envelope).unwrap();
                for stage in [
                    OrderBatchReceiptStage::Admitted,
                    OrderBatchReceiptStage::Executed,
                ] {
                    let receipt = OrderBatchReceipt {
                        stage,
                        record_count,
                        admitted: record_count,
                        executed: if stage == OrderBatchReceiptStage::Executed {
                            record_count
                        } else {
                            0
                        },
                        finalized: 0,
                        failed: 0,
                        rejection_code: 0,
                        batch_sequence: verified.binding.batch_sequence,
                        first_sequence: verified.binding.first_sequence,
                        checkpoint_height: None,
                        observed_unix_ns: 0,
                    };
                    let bytes = encode_order_batch_receipt_frame(&receipt, next_receipt_sequence)
                        .unwrap()
                        .encode()
                        .unwrap();
                    next_receipt_sequence += 1;
                    stream.write_all(&bytes).await.unwrap();
                }
                stream.flush().await.unwrap();
            }
        });
        let scenario = LoadScenario {
            orders_per_second: 128,
            duration_secs: 1,
            ..LoadScenario::default()
        };
        let report = run_live_packed(
            &scenario,
            &LivePackedConfig {
                leases: vec![PackedConnectionLease {
                    endpoint,
                    source_ip: None,
                    session: session(1_000),
                }],
                batch_size: 32,
                max_in_flight_batches: 4,
                receipt_timeout: Duration::from_secs(2),
                warmup_secs: 0,
                start_lead: Duration::from_millis(10),
                transport: LiveTransport::DevPlaintext,
                completion_boundary: PackedCompletionBoundary::Executed,
            },
            "component",
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(report.counters.offered_records, 128);
        assert_eq!(report.counters.admitted_records, 128);
        assert_eq!(report.counters.executed_records, 128);
        assert_eq!(report.counters.finalized_records, 0);
        assert_eq!(report.execution_receipt_ns.count, 128);
        assert_eq!(report.steady_intervals.len(), 1);
        assert_eq!(report.steady_intervals[0].ordinal, 0);
        assert_eq!(report.steady_intervals[0].counters, report.counters);
        assert_eq!(report.steady_intervals[0].accepted_new_records, 128);
        assert_eq!(report.steady_intervals[0].accepted_cancel_records, 0);
        assert_eq!(report.steady_intervals[0].accepted_replace_records, 0);
        assert!(report.steady_intervals[0].action_attribution_complete);
    }

    #[test]
    fn validator_label_requires_tls_and_finality() {
        let scenario = LoadScenario {
            orders_per_second: 32,
            duration_secs: 1,
            ..LoadScenario::default()
        };
        let config = LivePackedConfig {
            leases: vec![PackedConnectionLease {
                endpoint: "127.0.0.1:1".parse().unwrap(),
                source_ip: None,
                session: session(1_000),
            }],
            batch_size: 32,
            max_in_flight_batches: 1,
            receipt_timeout: Duration::from_secs(1),
            warmup_secs: 0,
            start_lead: Duration::ZERO,
            transport: LiveTransport::DevPlaintext,
            completion_boundary: PackedCompletionBoundary::Executed,
        };
        assert!(matches!(
            validate_config(&scenario, &config, "validator"),
            Err(LivePackedError::ValidatorTlsRequired)
        ));

        let config = LivePackedConfig {
            transport: LiveTransport::Tls13 {
                server_name: "validator.example".to_string(),
                ca_certificates_pem: Vec::new(),
                client_identity: None,
            },
            completion_boundary: PackedCompletionBoundary::Finalized,
            ..config
        };
        assert!(matches!(
            validate_config(&scenario, &config, "validator"),
            Err(LivePackedError::ValidatorWarmupRequired)
        ));
    }

    #[test]
    fn multi_connection_leases_must_be_globally_striped() {
        let scenario = LoadScenario {
            orders_per_second: 64,
            duration_secs: 1,
            ..LoadScenario::default()
        };
        let mut first = session(1_000);
        first.first_batch_sequence = 20;
        first.batch_sequence_stride = 2;
        first.command_sequence_stride = 64;
        let mut second = session(1_032);
        second.session_ref = 8;
        second.client_id = 45;
        second.first_batch_sequence = 21;
        second.batch_sequence_stride = 2;
        second.command_sequence_stride = 64;
        let mut config = LivePackedConfig {
            leases: vec![
                PackedConnectionLease {
                    endpoint: "127.0.0.1:1".parse().unwrap(),
                    source_ip: None,
                    session: first,
                },
                PackedConnectionLease {
                    endpoint: "127.0.0.1:1".parse().unwrap(),
                    source_ip: None,
                    session: second,
                },
            ],
            batch_size: 32,
            max_in_flight_batches: 1,
            receipt_timeout: Duration::from_secs(1),
            warmup_secs: 0,
            start_lead: Duration::ZERO,
            transport: LiveTransport::DevPlaintext,
            completion_boundary: PackedCompletionBoundary::Executed,
        };
        assert!(validate_config(&scenario, &config, "component").is_ok());
        config.leases[1].session.first_command_sequence = 1_064;
        assert!(matches!(
            validate_config(&scenario, &config, "component"),
            Err(LivePackedError::UnstripedSequenceLease)
        ));
    }
}
