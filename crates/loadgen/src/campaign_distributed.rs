//! Deterministic distributed controller/agent partitioning and health state.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex};

use crate::config::{LoadScenario, RunMode, RunRole};
use crate::metrics::{
    ActionCounters, ActionHistograms, HistogramMergeError, HistogramSummary, LatencyHistogram,
    OutcomeCounters,
};
use crate::protocol::ProtocolAdapter;
use crate::runtime::{
    run_partitioned_live_with_progress, ActionLatencyReport, HistogramReport, IntervalCounters,
    IntervalReport, LiveError, LiveReport, MetricDimension, RejectionCounters,
};
use crate::topology::{partition_weighted, TopologyError};
use crate::util::{fnv1a_64, fold_u64};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAdvertisement {
    pub agent_id: String,
    pub capacity_per_second: u64,
    pub max_connections: u64,
    pub regions: Vec<String>,
    pub allowed_endpoints: Vec<String>,
    pub clock_offset_ns: i64,
    pub clock_uncertainty_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPartition {
    pub agent_id: String,
    pub offered_rate: u64,
    pub connection_offset: u64,
    pub connection_count: u64,
    pub client_id_start: u64,
    pub client_id_end_exclusive: u64,
    pub nonce_start: u64,
    pub idempotency_prefix: u64,
    pub rng_stream: u64,
    pub market_ids: Vec<u32>,
    pub account_ids: Vec<u64>,
    pub synchronized_start_unix_ms: u64,
    pub clock_offset_ns: i64,
    pub clock_uncertainty_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedPlan {
    pub run_id: u64,
    pub synchronized_start_unix_ms: u64,
    pub partitions: Vec<AgentPartition>,
}

#[derive(Debug, thiserror::Error)]
pub enum DistributedError {
    #[error("at least one agent is required")]
    NoAgents,
    #[error("duplicate agent id `{0}`")]
    DuplicateAgent(String),
    #[error("agent `{agent}` does not allow target `{endpoint}`")]
    TargetNotAllowed { agent: String, endpoint: String },
    #[error("agent `{agent}` capacity is insufficient: assigned {assigned}, maximum {maximum}")]
    Capacity {
        agent: String,
        assigned: u64,
        maximum: u64,
    },
    #[error("identity/connection namespace overflow")]
    NamespaceOverflow,
    #[error("validator plan has {accounts} account(s) for {agents} agent(s)")]
    InsufficientAccounts { accounts: usize, agents: usize },
    #[error("weighted partition failed: {0}")]
    Partition(#[from] TopologyError),
    #[error("histogram merge failed: {0}")]
    Histogram(#[from] HistogramMergeError),
    #[error("control-plane I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("control-plane serialization failed: {0}")]
    Serialization(String),
    #[error("control-plane authentication failed for `{0}`")]
    Authentication(String),
    #[error("unexpected control-plane message: {0}")]
    UnexpectedMessage(&'static str),
    #[error("control-plane frame exceeds the {0}-byte limit")]
    OversizedFrame(usize),
    #[error("agent `{0}` was not present in the controller allow-list")]
    UnexpectedAgent(String),
    #[error("agent `{agent}` missed its heartbeat/result deadline: {reason}")]
    AgentMissing { agent: String, reason: String },
    #[error("agent `{agent}` failed: {reason}")]
    AgentFailed { agent: String, reason: String },
    #[error("distributed start time is already in the past")]
    LateStart,
    #[error("control token file is invalid: {0}")]
    InvalidToken(String),
    #[error("agent live run failed: {0}")]
    Live(#[from] LiveError),
}

/// Partition rates, connections, identities, markets, accounts, and RNG streams
/// without a lost remainder or overlap.
pub fn build_distributed_plan(
    scenario: &LoadScenario,
    agents: &[AgentAdvertisement],
    synchronized_start_unix_ms: u64,
) -> Result<DistributedPlan, DistributedError> {
    if agents.is_empty() {
        return Err(DistributedError::NoAgents);
    }
    let mut ids = BTreeMap::new();
    let endpoints = scenario
        .regions
        .iter()
        .flat_map(|region| {
            region
                .endpoints
                .iter()
                .map(|endpoint| endpoint.address.clone())
        })
        .collect::<Vec<_>>();
    for agent in agents {
        if ids.insert(agent.agent_id.clone(), ()).is_some() {
            return Err(DistributedError::DuplicateAgent(agent.agent_id.clone()));
        }
        for endpoint in &endpoints {
            if !agent.allowed_endpoints.contains(endpoint) {
                return Err(DistributedError::TargetNotAllowed {
                    agent: agent.agent_id.clone(),
                    endpoint: endpoint.clone(),
                });
            }
        }
    }
    let capacities = agents
        .iter()
        .map(|agent| agent.capacity_per_second)
        .collect::<Vec<_>>();
    let rates = partition_weighted(scenario.orders_per_second, &capacities)?;
    let connections = partition_weighted(scenario.total_connections(), &capacities)?;
    let markets = scenario.effective_market_ids();
    let account_ids = scenario
        .accounts
        .iter()
        .map(|account| account.account_id)
        .collect::<Vec<_>>();
    if scenario.mode == RunMode::Validator && account_ids.len() < agents.len() {
        return Err(DistributedError::InsufficientAccounts {
            accounts: account_ids.len(),
            agents: agents.len(),
        });
    }
    let mut connection_offset = 0u64;
    let mut client_id = scenario.client_id_base;
    let mut partitions = Vec::with_capacity(agents.len());
    for (index, agent) in agents.iter().enumerate() {
        if connections[index] > agent.max_connections {
            return Err(DistributedError::Capacity {
                agent: agent.agent_id.clone(),
                assigned: connections[index],
                maximum: agent.max_connections,
            });
        }
        let client_count = connections[index].max(1);
        let client_end = client_id
            .checked_add(client_count)
            .ok_or(DistributedError::NamespaceOverflow)?;
        let mut rng_stream = fnv1a_64(b"dexos.loadgen.distributed.v1");
        rng_stream = fold_u64(rng_stream, scenario.seed);
        rng_stream = fold_u64(rng_stream, fnv1a_64(agent.agent_id.as_bytes()));
        rng_stream = fold_u64(rng_stream, u64::try_from(index).unwrap_or(u64::MAX));
        let assigned_markets = markets
            .iter()
            .enumerate()
            .filter_map(|(market_index, market)| {
                (market_index % agents.len() == index).then_some(*market)
            })
            .collect::<Vec<_>>();
        let assigned_accounts = account_ids
            .iter()
            .enumerate()
            .filter_map(|(account_index, account)| {
                (account_index % agents.len() == index).then_some(*account)
            })
            .collect::<Vec<_>>();
        partitions.push(AgentPartition {
            agent_id: agent.agent_id.clone(),
            offered_rate: rates[index],
            connection_offset,
            connection_count: connections[index],
            client_id_start: client_id,
            client_id_end_exclusive: client_end,
            nonce_start: scenario.nonce_base,
            idempotency_prefix: u64::try_from(index).unwrap_or(u64::MAX),
            rng_stream,
            market_ids: assigned_markets,
            account_ids: assigned_accounts,
            synchronized_start_unix_ms,
            clock_offset_ns: agent.clock_offset_ns,
            clock_uncertainty_ns: agent.clock_uncertainty_ns,
        });
        connection_offset = connection_offset
            .checked_add(connections[index])
            .ok_or(DistributedError::NamespaceOverflow)?;
        client_id = client_end;
    }
    let mut run_id = fnv1a_64(b"dexos.loadgen.run.v1");
    run_id = fold_u64(run_id, scenario.seed);
    run_id = fold_u64(run_id, synchronized_start_unix_ms);
    Ok(DistributedPlan {
        run_id,
        synchronized_start_unix_ms,
        partitions,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    Waiting,
    Ready,
    Scheduled,
    Running,
    Draining,
    Complete,
    Late,
    Missing,
    Disconnected,
    Saturated,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Heartbeat {
    state: AgentState,
    last_seen_ms: u64,
    replay_epoch: u64,
}

/// Controller-side explicit agent health. Missing/lost/saturated agents make success
/// impossible; reconnect epochs must increase so an old partition cannot replay.
#[derive(Debug, Clone)]
pub struct HeartbeatTracker {
    timeout_ms: u64,
    agents: BTreeMap<String, Heartbeat>,
}

impl HeartbeatTracker {
    #[must_use]
    pub fn new(agent_ids: impl IntoIterator<Item = String>, timeout_ms: u64) -> Self {
        let agents = agent_ids
            .into_iter()
            .map(|id| {
                (
                    id,
                    Heartbeat {
                        state: AgentState::Waiting,
                        last_seen_ms: 0,
                        replay_epoch: 0,
                    },
                )
            })
            .collect();
        Self { timeout_ms, agents }
    }

    pub fn update(
        &mut self,
        agent_id: &str,
        state: AgentState,
        now_ms: u64,
        replay_epoch: u64,
    ) -> bool {
        let Some(agent) = self.agents.get_mut(agent_id) else {
            return false;
        };
        if replay_epoch < agent.replay_epoch {
            return false;
        }
        agent.state = state;
        agent.last_seen_ms = now_ms;
        agent.replay_epoch = replay_epoch;
        true
    }

    pub fn expire(&mut self, now_ms: u64) {
        for heartbeat in self.agents.values_mut() {
            if now_ms.saturating_sub(heartbeat.last_seen_ms) > self.timeout_ms
                && heartbeat.state != AgentState::Complete
            {
                heartbeat.state = AgentState::Missing;
            }
        }
    }

    #[must_use]
    pub fn state(&self, agent_id: &str) -> Option<AgentState> {
        self.agents.get(agent_id).map(|heartbeat| heartbeat.state)
    }

    #[must_use]
    pub fn aggregate_success(&self) -> bool {
        !self.agents.is_empty()
            && self
                .agents
                .values()
                .all(|heartbeat| heartbeat.state == AgentState::Complete)
    }
}

/// Controller authentication proof over a fresh challenge. The secret itself is
/// never sent or included in reports.
#[must_use]
pub fn control_proof(token: &[u8], challenge: u64, agent_id: &str) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(32 + token.len() + agent_id.len());
    preimage.extend_from_slice(b"dexos.loadgen.control.v1");
    preimage.extend_from_slice(&challenge.to_le_bytes());
    preimage.extend_from_slice(agent_id.as_bytes());
    preimage.extend_from_slice(token);
    crypto::keccak256(&preimage)
}

#[must_use]
pub fn verify_control_proof(
    token: &[u8],
    challenge: u64,
    agent_id: &str,
    proof: &[u8; 32],
) -> bool {
    let expected = control_proof(token, challenge, agent_id);
    expected
        .iter()
        .zip(proof)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

pub struct AgentMetricDelta {
    pub counters: OutcomeCounters,
    pub queue_delay: LatencyHistogram,
    pub request_to_ack: LatencyHistogram,
}

pub fn merge_agent_metrics(
    deltas: impl IntoIterator<Item = AgentMetricDelta>,
) -> Result<AgentMetricDelta, DistributedError> {
    let mut merged = AgentMetricDelta {
        counters: OutcomeCounters::default(),
        queue_delay: LatencyHistogram::new(60_000_000_000),
        request_to_ack: LatencyHistogram::new(60_000_000_000),
    };
    for delta in deltas {
        merged.counters.merge(&delta.counters);
        merged.queue_delay.merge(&delta.queue_delay)?;
        merged.request_to_ack.merge(&delta.request_to_ack)?;
    }
    Ok(merged)
}

const CONTROL_PROTOCOL_VERSION: u16 = 1;
const MAX_CONTROL_FRAME: usize = 2 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
enum ControlMessage {
    Challenge {
        protocol_version: u16,
        challenge: u64,
    },
    Hello {
        advertisement: AgentAdvertisement,
        replay_epoch: u64,
        proof: [u8; 32],
    },
    Plan {
        run_id: u64,
        partition: AgentPartition,
    },
    State {
        run_id: u64,
        replay_epoch: u64,
        state: AgentState,
    },
    Interval {
        run_id: u64,
        replay_epoch: u64,
        report: Box<IntervalReport>,
    },
    Result {
        run_id: u64,
        report: Box<WireLiveReport>,
    },
    Error {
        run_id: u64,
        reason: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct WireLiveReport {
    mode: RunMode,
    connections: u64,
    counters: OutcomeCounters,
    rejection_reasons: RejectionCounters,
    actions: ActionCounters,
    action_queue_delay: ActionLatencyReport,
    action_request_to_ack: ActionLatencyReport,
    queue_delay: HistogramSummary,
    request_to_ack: HistogramSummary,
    scheduler_rate_debt: u64,
    elapsed_ns: u64,
    histogram_max_trackable_ns: u64,
    queue_delay_raw: Vec<u64>,
    request_to_ack_raw: Vec<u64>,
    intervals: Vec<IntervalCounters>,
    interval_metrics_lost: u64,
    warmup_socket_written: u64,
    warmup_acknowledged: u64,
    warmup_failed: u64,
    interrupted: bool,
    dimensions: Vec<MetricDimension>,
}

impl From<&LiveReport> for WireLiveReport {
    fn from(report: &LiveReport) -> Self {
        Self {
            mode: report.mode,
            connections: report.connections,
            counters: report.counters,
            rejection_reasons: report.rejection_reasons,
            actions: report.actions,
            action_queue_delay: report.action_queue_delay.clone(),
            action_request_to_ack: report.action_request_to_ack.clone(),
            queue_delay: report.queue_delay,
            request_to_ack: report.request_to_ack,
            scheduler_rate_debt: report.scheduler_rate_debt,
            elapsed_ns: report.elapsed_ns,
            histogram_max_trackable_ns: report.histogram_max_trackable_ns,
            queue_delay_raw: report.queue_delay_raw.clone(),
            request_to_ack_raw: report.request_to_ack_raw.clone(),
            intervals: report.intervals.clone(),
            interval_metrics_lost: report.interval_metrics_lost,
            warmup_socket_written: report.warmup_socket_written,
            warmup_acknowledged: report.warmup_acknowledged,
            warmup_failed: report.warmup_failed,
            interrupted: report.interrupted,
            dimensions: report.dimensions.clone(),
        }
    }
}

impl WireLiveReport {
    fn into_live(self) -> Result<LiveReport, DistributedError> {
        // Rehydration validates raw bucket lengths and declared sample counts before
        // the controller trusts any percentile or aggregate.
        let queue = LatencyHistogram::from_raw_parts(
            self.histogram_max_trackable_ns,
            &self.queue_delay_raw,
            self.queue_delay.count,
            self.queue_delay.max,
            self.queue_delay.saturated,
            self.queue_delay.overflow,
        )?;
        let ack = LatencyHistogram::from_raw_parts(
            self.histogram_max_trackable_ns,
            &self.request_to_ack_raw,
            self.request_to_ack.count,
            self.request_to_ack.max,
            self.request_to_ack.saturated,
            self.request_to_ack.overflow,
        )?;
        Ok(LiveReport {
            mode: self.mode,
            target_label: target_label(self.mode),
            connections: self.connections,
            counters: self.counters,
            rejection_reasons: self.rejection_reasons,
            actions: self.actions,
            action_queue_delay: self.action_queue_delay,
            action_request_to_ack: self.action_request_to_ack,
            queue_delay: queue.summary(),
            request_to_ack: ack.summary(),
            scheduler_rate_debt: self.scheduler_rate_debt,
            elapsed_ns: self.elapsed_ns,
            queue_delay_raw: self.queue_delay_raw,
            request_to_ack_raw: self.request_to_ack_raw,
            histogram_max_trackable_ns: self.histogram_max_trackable_ns,
            intervals: self.intervals,
            interval_reports: Vec::new(),
            interval_metrics_lost: self.interval_metrics_lost,
            warmup_socket_written: self.warmup_socket_written,
            warmup_acknowledged: self.warmup_acknowledged,
            warmup_failed: self.warmup_failed,
            interrupted: self.interrupted,
            dimensions: self.dimensions,
        })
    }
}

/// Controller result with every independently validated agent report and a raw-bucket
/// aggregate. A missing or failed agent returns an error instead of a partial success.
#[derive(Debug, Clone)]
pub struct DistributedRunReport {
    pub run_id: u64,
    pub synchronized_start_unix_ms: u64,
    pub agents: Vec<(String, LiveReport)>,
    pub aggregate: LiveReport,
}

impl DistributedRunReport {
    #[must_use]
    pub fn to_json(&self) -> String {
        let agents = self
            .agents
            .iter()
            .map(|(agent, report)| {
                format!(
                    "{{\"agent_id\":\"{}\",\"report\":{}}}",
                    crate::util::json_escape(agent),
                    report.to_json()
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"mode\":\"distributed\",\"run_id\":{},\"synchronized_start_unix_ms\":{},\"agents\":[{}],\"aggregate\":{}}}",
            self.run_id,
            self.synchronized_start_unix_ms,
            agents,
            self.aggregate.to_json()
        )
    }
}

/// Connect to a controller, authenticate, enforce the local endpoint allow-list, wait
/// for the synchronized start, execute the exact assigned partition, and stream
/// heartbeats plus raw final metrics.
pub async fn run_distributed_agent(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
) -> Result<LiveReport, DistributedError> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_distributed_agent_with_shutdown(scenario, adapter, shutdown_rx).await
}

/// Agent entry point that reports a signal-interrupted, fully drained run to the
/// controller instead of terminating without terminal accounting.
pub async fn run_distributed_agent_with_shutdown(
    scenario: &LoadScenario,
    adapter: ProtocolAdapter,
    shutdown: watch::Receiver<bool>,
) -> Result<LiveReport, DistributedError> {
    let token = read_control_token(&scenario.control.token_file)?;
    let mut stream = TcpStream::connect(&scenario.controller_address).await?;
    stream.set_nodelay(true)?;
    let challenge = match read_control_message(&mut stream).await? {
        ControlMessage::Challenge {
            protocol_version,
            challenge,
        } if protocol_version == CONTROL_PROTOCOL_VERSION => challenge,
        _ => return Err(DistributedError::UnexpectedMessage("challenge")),
    };
    let replay_epoch = unix_nanos();
    let advertisement = AgentAdvertisement {
        agent_id: scenario.agent_id.clone(),
        capacity_per_second: scenario.orders_per_second,
        max_connections: scenario.total_connections(),
        regions: scenario
            .regions
            .iter()
            .map(|region| region.name.clone())
            .collect(),
        allowed_endpoints: scenario.control.allowed_endpoints.clone(),
        clock_offset_ns: scenario
            .regions
            .first()
            .map_or(0, |region| region.clock_offset_us.saturating_mul(1_000)),
        clock_uncertainty_ns: scenario.clock_uncertainty_ns,
    };
    write_control_message(
        &mut stream,
        &ControlMessage::Hello {
            proof: control_proof(&token, challenge, &scenario.agent_id),
            advertisement,
            replay_epoch,
        },
    )
    .await?;
    let (run_id, partition) = match read_control_message(&mut stream).await? {
        ControlMessage::Plan { run_id, partition } if partition.agent_id == scenario.agent_id => {
            (run_id, partition)
        }
        ControlMessage::Error { reason, .. } => {
            return Err(DistributedError::AgentFailed {
                agent: scenario.agent_id.clone(),
                reason,
            });
        }
        _ => return Err(DistributedError::UnexpectedMessage("plan")),
    };

    let mut local = scenario.clone();
    local.role = RunRole::Local;
    local.controller_address.clear();
    local.orders_per_second = partition.offered_rate;
    local.client_id_base = partition.client_id_start;
    local.nonce_base = partition.nonce_start;
    if !partition.market_ids.is_empty() {
        local.market_ids.clone_from(&partition.market_ids);
        local.market_count = u32::try_from(local.market_ids.len()).unwrap_or(u32::MAX);
    }
    if !partition.account_ids.is_empty() {
        local
            .accounts
            .retain(|account| partition.account_ids.contains(&account.account_id));
    }
    local
        .validate()
        .map_err(|error| DistributedError::AgentFailed {
            agent: scenario.agent_id.clone(),
            reason: error.to_string(),
        })?;

    let (read_half, write_half) = stream.into_split();
    drop(read_half);
    let writer = Arc::new(Mutex::new(write_half));
    let (state_tx, state_rx) = watch::channel(AgentState::Scheduled);
    send_agent_state(&writer, run_id, replay_epoch, AgentState::Scheduled).await?;
    let heartbeat_writer = Arc::clone(&writer);
    let heartbeat_interval = Duration::from_millis(scenario.control.heartbeat_ms);
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let current_state = *state_rx.borrow();
                    if send_agent_state(
                        &heartbeat_writer,
                        run_id,
                        replay_epoch,
                        current_state,
                    ).await.is_err() {
                        break;
                    }
                }
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() { break; }
                }
            }
        }
    });
    let (progress_tx, mut progress_rx) = mpsc::channel::<IntervalReport>(4);
    let interval_writer = Arc::clone(&writer);
    let human_output = scenario.output.human;
    let interval_forwarder = tokio::spawn(async move {
        while let Some(report) = progress_rx.recv().await {
            let delta = report.counters;
            if human_output {
                eprintln!(
                    "loadgen agent second={} offered={} generated={} written={} acknowledged={} accepted={} rejected={} failures={}",
                    delta.second,
                    delta.offered,
                    delta.generated,
                    delta.socket_written,
                    delta.acknowledged,
                    delta.accepted,
                    delta.rejected,
                    delta.failures,
                );
            }
            let mut locked = interval_writer.lock().await;
            write_control_message(
                &mut *locked,
                &ControlMessage::Interval {
                    run_id,
                    replay_epoch,
                    report: Box::new(report),
                },
            )
            .await?;
        }
        Ok::<(), DistributedError>(())
    });

    let now = unix_millis();
    if partition.synchronized_start_unix_ms <= now {
        let _ = state_tx.send(AgentState::Late);
        let _ = stop_tx.send(true);
        let _ = heartbeat.await;
        return Err(DistributedError::LateStart);
    }
    tokio::time::sleep(Duration::from_millis(
        partition.synchronized_start_unix_ms - now,
    ))
    .await;
    let _ = state_tx.send(AgentState::Running);
    send_agent_state(&writer, run_id, replay_epoch, AgentState::Running).await?;

    let adapter = adapter.with_client_id_base(partition.client_id_start);
    let result = run_partitioned_live_with_progress(
        &local,
        adapter,
        partition.connection_count,
        shutdown,
        progress_tx,
    )
    .await;
    interval_forwarder
        .await
        .map_err(|error| DistributedError::AgentFailed {
            agent: scenario.agent_id.clone(),
            reason: error.to_string(),
        })??;
    let _ = state_tx.send(AgentState::Draining);
    let _ = stop_tx.send(true);
    let _ = heartbeat.await;
    match result {
        Ok(report) => {
            let mut locked = writer.lock().await;
            write_control_message(
                &mut *locked,
                &ControlMessage::Result {
                    run_id,
                    report: Box::new(WireLiveReport::from(&report)),
                },
            )
            .await?;
            Ok(report)
        }
        Err(error) => {
            let mut locked = writer.lock().await;
            let _ = write_control_message(
                &mut *locked,
                &ControlMessage::Error {
                    run_id,
                    reason: error.to_string(),
                },
            )
            .await;
            Err(error.into())
        }
    }
}

/// Listen for every configured agent, authenticate and validate advertisements,
/// distribute exact partitions, enforce heartbeat deadlines, and merge raw reports.
pub async fn run_distributed_controller(
    scenario: &LoadScenario,
) -> Result<DistributedRunReport, DistributedError> {
    if scenario.control.agents.is_empty() {
        return Err(DistributedError::NoAgents);
    }
    let token = read_control_token(&scenario.control.token_file)?;
    let listener = TcpListener::bind(&scenario.control.listen).await?;
    let timeout = Duration::from_millis(scenario.control.agent_timeout_ms);
    let mut connected = BTreeMap::<String, (AgentAdvertisement, u64, TcpStream)>::new();
    for sequence in 0..scenario.control.agents.len() {
        let accepted = tokio::time::timeout(timeout, listener.accept())
            .await
            .map_err(|_| DistributedError::AgentMissing {
                agent: "unconnected".to_string(),
                reason: "controller accept timeout".to_string(),
            })??;
        let (mut stream, peer) = accepted;
        stream.set_nodelay(true)?;
        let challenge = fold_u64(
            fold_u64(unix_nanos(), u64::try_from(sequence).unwrap_or(u64::MAX)),
            fnv1a_64(peer.to_string().as_bytes()),
        );
        write_control_message(
            &mut stream,
            &ControlMessage::Challenge {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                challenge,
            },
        )
        .await?;
        let hello = tokio::time::timeout(timeout, read_control_message(&mut stream))
            .await
            .map_err(|_| DistributedError::AgentMissing {
                agent: peer.to_string(),
                reason: "authentication timeout".to_string(),
            })??;
        let (advertisement, replay_epoch, proof) = match hello {
            ControlMessage::Hello {
                advertisement,
                replay_epoch,
                proof,
            } => (advertisement, replay_epoch, proof),
            _ => return Err(DistributedError::UnexpectedMessage("hello")),
        };
        if !expected_agent(&scenario.control.agents, &advertisement.agent_id) {
            return Err(DistributedError::UnexpectedAgent(advertisement.agent_id));
        }
        if !verify_control_proof(&token, challenge, &advertisement.agent_id, &proof) {
            return Err(DistributedError::Authentication(advertisement.agent_id));
        }
        let agent_id = advertisement.agent_id.clone();
        if connected
            .insert(agent_id.clone(), (advertisement, replay_epoch, stream))
            .is_some()
        {
            return Err(DistributedError::DuplicateAgent(agent_id));
        }
    }

    let advertisements = connected
        .values()
        .map(|(advertisement, _, _)| advertisement.clone())
        .collect::<Vec<_>>();
    let synchronized_start = unix_millis().saturating_add(scenario.control.start_delay_ms);
    let plan = build_distributed_plan(scenario, &advertisements, synchronized_start)?;
    let mut monitors = tokio::task::JoinSet::new();
    for partition in &plan.partitions {
        let (_, replay_epoch, mut stream) = connected
            .remove(&partition.agent_id)
            .ok_or_else(|| DistributedError::UnexpectedAgent(partition.agent_id.clone()))?;
        write_control_message(
            &mut stream,
            &ControlMessage::Plan {
                run_id: plan.run_id,
                partition: partition.clone(),
            },
        )
        .await?;
        let agent_id = partition.agent_id.clone();
        let run_id = plan.run_id;
        let human_output = scenario.output.human;
        monitors.spawn(async move {
            monitor_agent(
                stream,
                agent_id,
                run_id,
                replay_epoch,
                timeout,
                human_output,
            )
            .await
        });
    }

    let mut agents = Vec::with_capacity(plan.partitions.len());
    while let Some(result) = monitors.join_next().await {
        let pair = result.map_err(|error| DistributedError::AgentFailed {
            agent: "unknown".to_string(),
            reason: error.to_string(),
        })??;
        agents.push(pair);
    }
    agents.sort_by(|left, right| left.0.cmp(&right.0));
    let aggregate = merge_live_reports(scenario.mode, agents.iter().map(|(_, report)| report))?;
    Ok(DistributedRunReport {
        run_id: plan.run_id,
        synchronized_start_unix_ms: plan.synchronized_start_unix_ms,
        agents,
        aggregate,
    })
}

async fn monitor_agent(
    mut stream: TcpStream,
    agent: String,
    run_id: u64,
    replay_epoch: u64,
    timeout: Duration,
    human_output: bool,
) -> Result<(String, LiveReport), DistributedError> {
    let mut streamed_intervals = Vec::<Option<IntervalReport>>::new();
    loop {
        let message = tokio::time::timeout(timeout, read_control_message(&mut stream))
            .await
            .map_err(|_| DistributedError::AgentMissing {
                agent: agent.clone(),
                reason: "heartbeat timeout".to_string(),
            })??;
        match message {
            ControlMessage::State {
                run_id: message_run,
                replay_epoch: message_epoch,
                state,
            } if message_run == run_id && message_epoch == replay_epoch => {
                if matches!(
                    state,
                    AgentState::Late
                        | AgentState::Missing
                        | AgentState::Disconnected
                        | AgentState::Saturated
                        | AgentState::Failed
                ) {
                    return Err(DistributedError::AgentFailed {
                        agent,
                        reason: format!("terminal state {state:?}"),
                    });
                }
            }
            ControlMessage::Interval {
                run_id: message_run,
                replay_epoch: message_epoch,
                report,
            } if message_run == run_id && message_epoch == replay_epoch => {
                let report = *report;
                let delta = report.counters;
                report
                    .queue_delay
                    .rehydrate()
                    .map_err(|error| DistributedError::AgentFailed {
                        agent: agent.clone(),
                        reason: format!("invalid interval queue histogram: {error}"),
                    })?;
                report.request_to_ack.rehydrate().map_err(|error| {
                    DistributedError::AgentFailed {
                        agent: agent.clone(),
                        reason: format!("invalid interval ack histogram: {error}"),
                    }
                })?;
                if !report.valid() {
                    return Err(DistributedError::AgentFailed {
                        agent,
                        reason: "interval contains an invalid histogram".to_string(),
                    });
                }
                let index =
                    usize::try_from(delta.second).map_err(|_| DistributedError::AgentFailed {
                        agent: agent.clone(),
                        reason: "interval index exceeds platform limits".to_string(),
                    })?;
                if streamed_intervals.len() <= index {
                    streamed_intervals.resize(index + 1, None);
                }
                if streamed_intervals[index].replace(report).is_some() {
                    return Err(DistributedError::AgentFailed {
                        agent,
                        reason: format!("duplicate interval {index}"),
                    });
                }
                if human_output {
                    eprintln!(
                        "loadgen controller agent={} second={} offered={} generated={} written={} acknowledged={} accepted={} rejected={} failures={} queue_p99_ns={} ack_p99_ns={}",
                        agent,
                        delta.second,
                        delta.offered,
                        delta.generated,
                        delta.socket_written,
                        delta.acknowledged,
                        delta.accepted,
                        delta.rejected,
                        delta.failures,
                        streamed_intervals[index]
                            .as_ref()
                            .map_or(0, |interval| interval.queue_delay.summary.p99),
                        streamed_intervals[index]
                            .as_ref()
                            .map_or(0, |interval| interval.request_to_ack.summary.p99),
                    );
                }
            }
            ControlMessage::Result {
                run_id: message_run,
                report,
            } if message_run == run_id => {
                let mut report = (*report).into_live()?;
                report.counters.validate_conservation().map_err(|error| {
                    DistributedError::AgentFailed {
                        agent: agent.clone(),
                        reason: error.to_string(),
                    }
                })?;
                let streamed = streamed_intervals
                    .iter()
                    .flatten()
                    .cloned()
                    .collect::<Vec<_>>();
                if !report.interrupted && report.interval_metrics_lost == 0 {
                    let streamed = streamed_intervals
                        .iter()
                        .cloned()
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| DistributedError::AgentFailed {
                            agent: agent.clone(),
                            reason: "missing streamed interval".to_string(),
                        })?;
                    if streamed
                        .iter()
                        .map(|interval| interval.counters)
                        .collect::<Vec<_>>()
                        != report.intervals
                    {
                        return Err(DistributedError::AgentFailed {
                            agent,
                            reason: "streamed intervals differ from final report".to_string(),
                        });
                    }
                }
                if streamed.iter().any(|interval| !interval.valid()) {
                    return Err(DistributedError::AgentFailed {
                        agent,
                        reason: "streamed interval contains an invalid histogram".to_string(),
                    });
                }
                report.interval_reports = streamed;
                return Ok((agent, report));
            }
            ControlMessage::Error {
                run_id: message_run,
                reason,
            } if message_run == run_id => {
                return Err(DistributedError::AgentFailed { agent, reason });
            }
            _ => return Err(DistributedError::UnexpectedMessage("agent state/result")),
        }
    }
}

fn merge_live_reports<'a>(
    mode: RunMode,
    reports: impl IntoIterator<Item = &'a LiveReport>,
) -> Result<LiveReport, DistributedError> {
    let mut counters = OutcomeCounters::default();
    let mut rejection_reasons = RejectionCounters::default();
    let mut actions = ActionCounters::default();
    let mut action_queue_delay = Box::new(ActionHistograms::new(60_000_000_000));
    let mut action_request_to_ack = Box::new(ActionHistograms::new(60_000_000_000));
    let mut queue = LatencyHistogram::new(60_000_000_000);
    let mut ack = LatencyHistogram::new(60_000_000_000);
    let mut connections = 0u64;
    let mut rate_debt = 0u64;
    let mut elapsed_ns = 0u64;
    let mut intervals: Vec<IntervalCounters> = Vec::new();
    let mut interval_reports: Vec<Option<IntervalReport>> = Vec::new();
    let mut interval_metrics_lost = 0u64;
    let mut warmup_socket_written = 0u64;
    let mut warmup_acknowledged = 0u64;
    let mut warmup_failed = 0u64;
    let mut interrupted = false;
    let mut dimensions = Vec::new();
    let mut seen = false;
    for report in reports {
        seen = true;
        counters.merge(&report.counters);
        rejection_reasons.merge(&report.rejection_reasons);
        actions.new_order.merge(&report.actions.new_order);
        actions.cancel.merge(&report.actions.cancel);
        actions.replace.merge(&report.actions.replace);
        action_queue_delay.merge(&report.action_queue_delay.rehydrate()?)?;
        action_request_to_ack.merge(&report.action_request_to_ack.rehydrate()?)?;
        let local_queue = LatencyHistogram::from_raw_parts(
            report.histogram_max_trackable_ns,
            &report.queue_delay_raw,
            report.queue_delay.count,
            report.queue_delay.max,
            report.queue_delay.saturated,
            report.queue_delay.overflow,
        )?;
        let local_ack = LatencyHistogram::from_raw_parts(
            report.histogram_max_trackable_ns,
            &report.request_to_ack_raw,
            report.request_to_ack.count,
            report.request_to_ack.max,
            report.request_to_ack.saturated,
            report.request_to_ack.overflow,
        )?;
        queue.merge(&local_queue)?;
        ack.merge(&local_ack)?;
        connections = connections.saturating_add(report.connections);
        rate_debt = rate_debt.saturating_add(report.scheduler_rate_debt);
        elapsed_ns = elapsed_ns.max(report.elapsed_ns);
        if intervals.len() < report.intervals.len() {
            let old_len = intervals.len();
            intervals.resize(report.intervals.len(), IntervalCounters::default());
            for (index, interval) in intervals.iter_mut().enumerate().skip(old_len) {
                interval.second = u64::try_from(index).unwrap_or(u64::MAX);
            }
        }
        for delta in &report.intervals {
            let Some(interval) = usize::try_from(delta.second)
                .ok()
                .and_then(|index| intervals.get_mut(index))
            else {
                continue;
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
        for incoming in &report.interval_reports {
            let Some(index) = usize::try_from(incoming.counters.second).ok() else {
                interval_metrics_lost = interval_metrics_lost.saturating_add(1);
                continue;
            };
            if interval_reports.len() <= index {
                interval_reports.resize(index + 1, None);
            }
            if let Some(existing) = &mut interval_reports[index] {
                merge_interval_report(existing, incoming)?;
            } else {
                interval_reports[index] = Some(incoming.clone());
            }
        }
        interval_metrics_lost = interval_metrics_lost.saturating_add(report.interval_metrics_lost);
        warmup_socket_written = warmup_socket_written.saturating_add(report.warmup_socket_written);
        warmup_acknowledged = warmup_acknowledged.saturating_add(report.warmup_acknowledged);
        warmup_failed = warmup_failed.saturating_add(report.warmup_failed);
        interrupted |= report.interrupted;
        for dimension in &report.dimensions {
            merge_metric_dimension(&mut dimensions, dimension)?;
        }
    }
    if !seen {
        return Err(DistributedError::NoAgents);
    }
    counters
        .validate_conservation()
        .map_err(|error| DistributedError::AgentFailed {
            agent: "aggregate".to_string(),
            reason: error.to_string(),
        })?;
    Ok(LiveReport {
        mode,
        target_label: target_label(mode),
        connections,
        counters,
        rejection_reasons,
        actions,
        action_queue_delay: ActionLatencyReport::from_histograms(&action_queue_delay),
        action_request_to_ack: ActionLatencyReport::from_histograms(&action_request_to_ack),
        queue_delay: queue.summary(),
        request_to_ack: ack.summary(),
        scheduler_rate_debt: rate_debt,
        elapsed_ns,
        queue_delay_raw: queue.raw_buckets().to_vec(),
        request_to_ack_raw: ack.raw_buckets().to_vec(),
        histogram_max_trackable_ns: queue.max_trackable_ns(),
        intervals,
        interval_reports: interval_reports.into_iter().flatten().collect(),
        interval_metrics_lost,
        warmup_socket_written,
        warmup_acknowledged,
        warmup_failed,
        interrupted,
        dimensions,
    })
}

fn merge_interval_report(
    existing: &mut IntervalReport,
    incoming: &IntervalReport,
) -> Result<(), HistogramMergeError> {
    merge_interval_counters(&mut existing.counters, &incoming.counters);
    existing
        .actions
        .new_order
        .merge(&incoming.actions.new_order);
    existing.actions.cancel.merge(&incoming.actions.cancel);
    existing.actions.replace.merge(&incoming.actions.replace);

    let mut queue = existing.queue_delay.rehydrate()?;
    queue.merge(&incoming.queue_delay.rehydrate()?)?;
    existing.queue_delay = HistogramReport::from_histogram(&queue);
    let mut ack = existing.request_to_ack.rehydrate()?;
    ack.merge(&incoming.request_to_ack.rehydrate()?)?;
    existing.request_to_ack = HistogramReport::from_histogram(&ack);

    let mut action_queue = existing.action_queue_delay.rehydrate()?;
    action_queue.merge(&incoming.action_queue_delay.rehydrate()?)?;
    existing.action_queue_delay = ActionLatencyReport::from_histograms(&action_queue);
    let mut action_ack = existing.action_request_to_ack.rehydrate()?;
    action_ack.merge(&incoming.action_request_to_ack.rehydrate()?)?;
    existing.action_request_to_ack = ActionLatencyReport::from_histograms(&action_ack);

    for dimension in &incoming.dimensions {
        merge_metric_dimension(&mut existing.dimensions, dimension)?;
    }
    Ok(())
}

fn merge_interval_counters(existing: &mut IntervalCounters, incoming: &IntervalCounters) {
    existing.offered = existing.offered.saturating_add(incoming.offered);
    existing.generated = existing.generated.saturating_add(incoming.generated);
    existing.queued = existing.queued.saturating_add(incoming.queued);
    existing.socket_written = existing
        .socket_written
        .saturating_add(incoming.socket_written);
    existing.acknowledged = existing.acknowledged.saturating_add(incoming.acknowledged);
    existing.accepted = existing.accepted.saturating_add(incoming.accepted);
    existing.rejected = existing.rejected.saturating_add(incoming.rejected);
    existing.timed_out = existing.timed_out.saturating_add(incoming.timed_out);
    existing.generator_failed = existing
        .generator_failed
        .saturating_add(incoming.generator_failed);
    existing.transport_failed_before_write = existing
        .transport_failed_before_write
        .saturating_add(incoming.transport_failed_before_write);
    existing.transport_failed_after_write = existing
        .transport_failed_after_write
        .saturating_add(incoming.transport_failed_after_write);
    existing.protocol_failed = existing
        .protocol_failed
        .saturating_add(incoming.protocol_failed);
    existing.failures = existing.failures.saturating_add(incoming.failures);
    existing.locally_dropped = existing
        .locally_dropped
        .saturating_add(incoming.locally_dropped);
    existing.overflow = existing.overflow.saturating_add(incoming.overflow);
}

fn merge_metric_dimension(
    dimensions: &mut Vec<MetricDimension>,
    incoming: &MetricDimension,
) -> Result<(), HistogramMergeError> {
    if let Some(existing) = dimensions.iter_mut().find(|dimension| {
        dimension.region == incoming.region && dimension.endpoint == incoming.endpoint
    }) {
        existing.counters.merge(&incoming.counters);
        let mut queue = existing.queue_delay.rehydrate()?;
        queue.merge(&incoming.queue_delay.rehydrate()?)?;
        existing.queue_delay = HistogramReport::from_histogram(&queue);
        let mut ack = existing.request_to_ack.rehydrate()?;
        ack.merge(&incoming.request_to_ack.rehydrate()?)?;
        existing.request_to_ack = HistogramReport::from_histogram(&ack);
    } else {
        dimensions.push(incoming.clone());
    }
    Ok(())
}

const fn target_label(mode: RunMode) -> &'static str {
    match mode {
        RunMode::Sink => "reference-sink-test-only",
        RunMode::Validator => "validator",
        RunMode::Simulate => "simulation",
    }
}

async fn send_agent_state<W: AsyncWrite + Unpin>(
    writer: &Arc<Mutex<W>>,
    run_id: u64,
    replay_epoch: u64,
    state: AgentState,
) -> Result<(), DistributedError> {
    let mut locked = writer.lock().await;
    write_control_message(
        &mut *locked,
        &ControlMessage::State {
            run_id,
            replay_epoch,
            state,
        },
    )
    .await
}

async fn write_control_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ControlMessage,
) -> Result<(), DistributedError> {
    let bytes = postcard::to_stdvec(message)
        .map_err(|error| DistributedError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_CONTROL_FRAME {
        return Err(DistributedError::OversizedFrame(bytes.len()));
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| DistributedError::OversizedFrame(bytes.len()))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_control_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ControlMessage, DistributedError> {
    let length = reader.read_u32().await? as usize;
    if length > MAX_CONTROL_FRAME {
        return Err(DistributedError::OversizedFrame(length));
    }
    let mut bytes = vec![0u8; length];
    reader.read_exact(&mut bytes).await?;
    postcard::from_bytes(&bytes).map_err(|error| DistributedError::Serialization(error.to_string()))
}

fn read_control_token(path: &str) -> Result<Vec<u8>, DistributedError> {
    let bytes = std::fs::read(path).map_err(|error| {
        DistributedError::InvalidToken(format!("cannot read `{path}`: {error}"))
    })?;
    if bytes.len() > 4_096 {
        return Err(DistributedError::InvalidToken(
            "secret exceeds 4096 bytes".to_string(),
        ));
    }
    let token = bytes
        .into_iter()
        .skip_while(u8::is_ascii_whitespace)
        .collect::<Vec<_>>();
    let end = token
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    let token = token[..end].to_vec();
    if token.len() < 16 {
        return Err(DistributedError::InvalidToken(
            "secret must contain at least 16 non-whitespace bytes".to_string(),
        ));
    }
    Ok(token)
}

fn expected_agent(expected: &[String], agent_id: &str) -> bool {
    expected.iter().any(|entry| {
        entry == agent_id
            || entry
                .strip_prefix(agent_id)
                .is_some_and(|suffix| suffix.starts_with(':'))
    })
}

fn unix_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn unix_nanos() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    )
    .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::{
        serve_reference_sink, ControlPlaneConfig, EndpointConfig, OperationMix,
        ReferenceSinkConfig, RegionConfig, RunMode, TargetKind,
    };
    use crypto::KeyPair;
    use types::AccountId;

    fn scenario() -> LoadScenario {
        LoadScenario {
            schema_version: 2,
            mode: RunMode::Sink,
            market_ids: vec![1, 2, 3, 4, 5, 6],
            operation_mix: Some(OperationMix::default()),
            orders_per_second: 20_000_003,
            client_id_base: 1_000,
            regions: vec![RegionConfig {
                name: "r".to_string(),
                users: 1,
                source_ips: vec!["127.0.0.1".to_string()],
                endpoints: vec![EndpointConfig {
                    name: "sink".to_string(),
                    address: "127.0.0.1:9900".to_string(),
                    connections_per_source_ip: 10_001,
                    target_kind: TargetKind::ReferenceSink,
                    ..EndpointConfig::default()
                }],
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        }
    }

    fn agents() -> Vec<AgentAdvertisement> {
        (0..3)
            .map(|index| AgentAdvertisement {
                agent_id: format!("agent-{index}"),
                capacity_per_second: u64::try_from(index + 1).unwrap_or(1),
                max_connections: 10_001,
                regions: vec!["r".to_string()],
                allowed_endpoints: vec!["127.0.0.1:9900".to_string()],
                clock_offset_ns: i64::from(index) * 100,
                clock_uncertainty_ns: 50,
            })
            .collect()
    }

    #[test]
    fn three_agent_plan_is_exact_unique_and_synchronized() {
        let scenario = scenario();
        let plan = build_distributed_plan(&scenario, &agents(), 5_000).unwrap();
        assert_eq!(plan.partitions.len(), 3);
        assert_eq!(
            plan.partitions.iter().map(|p| p.offered_rate).sum::<u64>(),
            scenario.orders_per_second
        );
        assert_eq!(
            plan.partitions
                .iter()
                .map(|p| p.connection_count)
                .sum::<u64>(),
            scenario.total_connections()
        );
        for pair in plan.partitions.windows(2) {
            assert_eq!(pair[0].client_id_end_exclusive, pair[1].client_id_start);
            assert_ne!(pair[0].rng_stream, pair[1].rng_stream);
            assert_ne!(pair[0].idempotency_prefix, pair[1].idempotency_prefix);
        }
        assert!(plan
            .partitions
            .iter()
            .all(|partition| partition.synchronized_start_unix_ms == 5_000));
        let markets = plan
            .partitions
            .iter()
            .flat_map(|partition| partition.market_ids.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(markets.len(), 6);
    }

    #[test]
    fn agent_loss_and_replay_cannot_report_success() {
        let mut tracker =
            HeartbeatTracker::new(["a", "b", "c"].into_iter().map(str::to_string), 1_000);
        for id in ["a", "b", "c"] {
            assert!(tracker.update(id, AgentState::Running, 100, 1));
        }
        assert!(!tracker.update("a", AgentState::Running, 200, 0));
        tracker.update("a", AgentState::Complete, 500, 1);
        tracker.update("b", AgentState::Complete, 500, 1);
        tracker.expire(2_000);
        assert_eq!(tracker.state("c"), Some(AgentState::Missing));
        assert!(!tracker.aggregate_success());
        tracker.update("c", AgentState::Complete, 2_000, 2);
        assert!(tracker.aggregate_success());
    }

    #[test]
    fn authentication_proof_is_bound_to_challenge_and_agent() {
        let token = b"secret control token";
        let proof = control_proof(token, 7, "agent-a");
        assert!(verify_control_proof(token, 7, "agent-a", &proof));
        assert!(!verify_control_proof(token, 8, "agent-a", &proof));
        assert!(!verify_control_proof(token, 7, "agent-b", &proof));
    }

    #[test]
    fn raw_histograms_merge_instead_of_averaging_percentiles() {
        let mut left = LatencyHistogram::new(60_000_000_000);
        let mut right = LatencyHistogram::new(60_000_000_000);
        left.record(10);
        right.record(10_000);
        let merged = merge_agent_metrics([
            AgentMetricDelta {
                counters: OutcomeCounters::default(),
                queue_delay: left.clone(),
                request_to_ack: left,
            },
            AgentMetricDelta {
                counters: OutcomeCounters::default(),
                queue_delay: right.clone(),
                request_to_ack: right,
            },
        ])
        .unwrap();
        assert_eq!(merged.request_to_ack.summary().count, 2);
        assert!(merged.request_to_ack.summary().p99 >= 10_000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_real_agents_authenticate_start_together_and_merge_sink_results() {
        let sink_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_address = sink_listener.local_addr().unwrap().to_string();
        let (sink_stop_tx, sink_stop_rx) = watch::channel(false);
        let sink = tokio::spawn(serve_reference_sink(
            sink_listener,
            ReferenceSinkConfig::default(),
            sink_stop_rx,
        ));

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let controller_address = probe.local_addr().unwrap().to_string();
        drop(probe);
        let token_path = std::env::temp_dir().join(format!(
            "dexos-loadgen-control-{}-{}",
            std::process::id(),
            unix_nanos()
        ));
        std::fs::write(&token_path, b"test-only-control-secret-552").unwrap();

        let endpoint = EndpointConfig {
            name: "sink".to_string(),
            address: sink_address.clone(),
            connections_per_source_ip: 3,
            target_kind: TargetKind::ReferenceSink,
            ..EndpointConfig::default()
        };
        let region = RegionConfig {
            name: "local".to_string(),
            users: 3,
            source_ips: vec!["127.0.0.1".to_string()],
            endpoints: vec![endpoint],
            ..RegionConfig::default()
        };
        let control = ControlPlaneConfig {
            listen: controller_address.clone(),
            token_file: token_path.display().to_string(),
            heartbeat_ms: 25,
            agent_timeout_ms: 500,
            start_delay_ms: 200,
            agents: vec![
                "agent-a".to_string(),
                "agent-b".to_string(),
                "agent-c".to_string(),
            ],
            allowed_endpoints: vec![sink_address.clone()],
        };
        let controller_scenario = LoadScenario {
            schema_version: 2,
            mode: RunMode::Sink,
            role: RunRole::Controller,
            orders_per_second: 300,
            duration_secs: 1,
            drain_timeout_secs: 2,
            worker_count: 3,
            in_flight_per_connection: 8,
            market_ids: vec![1, 2],
            operation_mix: Some(OperationMix::default()),
            control: control.clone(),
            regions: vec![region.clone()],
            ..LoadScenario::default()
        };
        controller_scenario.validate().unwrap();
        let controller_copy = controller_scenario.clone();
        let controller =
            tokio::spawn(async move { run_distributed_controller(&controller_copy).await });
        tokio::time::sleep(Duration::from_millis(25)).await;

        let mut agent_scenarios = Vec::new();
        for agent_id in ["agent-a", "agent-b", "agent-c"] {
            let mut local_region = region.clone();
            local_region.endpoints[0].connections_per_source_ip = 1;
            agent_scenarios.push(LoadScenario {
                role: RunRole::Agent,
                agent_id: agent_id.to_string(),
                controller_address: controller_address.clone(),
                orders_per_second: 100,
                control: control.clone(),
                regions: vec![local_region],
                ..controller_scenario.clone()
            });
        }
        let mut agents = tokio::task::JoinSet::new();
        for (index, scenario) in agent_scenarios.into_iter().enumerate() {
            agents.spawn(async move {
                let adapter = ProtocolAdapter::new(
                    AccountId::new(0),
                    KeyPair::from_seed(&[u8::try_from(index + 1).unwrap_or(1); 32]),
                    0,
                    None,
                );
                run_distributed_agent(&scenario, adapter).await
            });
        }
        while let Some(result) = agents.join_next().await {
            let report = result.unwrap().unwrap();
            assert_eq!(report.counters.socket_written, 100);
            assert_eq!(report.interval_reports.len(), 1);
            assert_eq!(report.interval_reports[0].counters.socket_written, 100);
        }
        let report = controller.await.unwrap().unwrap();
        assert_eq!(report.agents.len(), 3);
        assert_eq!(report.aggregate.connections, 3);
        assert_eq!(report.aggregate.counters.socket_written, 300);
        assert_eq!(report.aggregate.request_to_ack.count, 300);
        assert_eq!(report.aggregate.interval_reports.len(), 1);
        assert_eq!(
            report.aggregate.interval_reports[0].counters.socket_written,
            300
        );
        assert_eq!(
            report.aggregate.interval_reports[0]
                .action_request_to_ack
                .new_order
                .summary
                .count
                + report.aggregate.interval_reports[0]
                    .action_request_to_ack
                    .cancel
                    .summary
                    .count
                + report.aggregate.interval_reports[0]
                    .action_request_to_ack
                    .replace
                    .summary
                    .count,
            300
        );
        assert!(report.aggregate.passed());

        let _ = sink_stop_tx.send(true);
        let snapshot = sink.await.unwrap().unwrap().snapshot();
        assert_eq!(snapshot.received, 300);
        let _ = std::fs::remove_file(token_path);
    }
}
