//! Non-blocking, multi-connection live runner over production signed RPC frames.
//!
//! This is the replacement path for the legacy capped/private measured protocol.
//! It partitions an uncapped open-loop plan over persistent Tokio connections,
//! pipelines a bounded number of correlated requests, and reports socket-written and
//! acknowledged outcomes separately. Explicit source-IP binding, TLS 1.3 certificate
//! validation, optional mTLS, and a named development-plaintext mode are built in.

use std::io::{BufReader, Cursor};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use codec::{FRAME_HEADER_LEN, MAX_RPC_FRAME_PAYLOAD};
use proto::{decode_response, encode_request, RpcMethod};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::{client::TlsStream, TlsConnector};
use types::AccountId;

use crate::command::{CommandKind, SessionState};
use crate::config::LoadScenario;
use crate::realtime::{
    ActionKind, IntervalMetrics, MetricsError, OperationCounters, WorkerMetrics,
};
use crate::rng::Lcg;
use crate::rpc_adapter::{AdapterOutcome, RpcAdapterError, RpcSessionAdapter, RpcSessionConfig};
use crate::util::{fnv1a_64, fold_u64};

/// Explicit live-RPC runtime settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRpcConfig {
    /// Explicit validator/reference-sink endpoints, round-robin by connection.
    pub endpoints: Vec<SocketAddr>,
    /// Optional explicit source IPs, round-robin by connection.
    pub source_ips: Vec<IpAddr>,
    /// Persistent connections owned by this local agent.
    pub connections: u32,
    /// Funded account authorized by `signing_seed`.
    pub account: AccountId,
    /// First disjoint client identifier.
    pub client_id_base: u64,
    /// High nonce namespace allocated by the distributed controller.
    pub nonce_namespace: u32,
    /// External production/session key seed. Test fixtures may use deterministic data.
    pub signing_seed: [u8; 32],
    /// Bounded request pipeline depth per connection.
    pub max_in_flight: usize,
    /// Bounded accepted live-order table per connection.
    pub max_live_orders: usize,
    /// Per-response timeout; a timeout fails the connection/run closed.
    pub response_timeout: Duration,
    /// Warm-up traffic duration, excluded from the returned steady metrics.
    pub warmup_secs: u64,
    /// Future local warm-up start lead time used to establish all connections first.
    pub start_lead: Duration,
    /// Explicit transport posture. Validator qualification requires TLS 1.3.
    pub transport: LiveTransport,
}

/// TLS client identity for optional mutual TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTlsIdentity {
    /// PEM certificate chain.
    pub certificate_chain_pem: Vec<u8>,
    /// PEM private key.
    pub private_key_pem: Vec<u8>,
}

/// Live target transport. Plaintext is deliberately named and restricted to dev/sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveTransport {
    /// Explicit local/reference-sink plaintext mode.
    DevPlaintext,
    /// TLS 1.3 with certificate validation and optional client authentication.
    Tls13 {
        /// DNS name verified against the server certificate.
        server_name: String,
        /// PEM trust roots.
        ca_certificates_pem: Vec<u8>,
        /// Optional mTLS certificate and key.
        client_identity: Option<ClientTlsIdentity>,
    },
}

impl LiveRpcConfig {
    fn validate(&self) -> Result<(), LiveRpcError> {
        if self.endpoints.is_empty()
            || self.connections == 0
            || self.max_in_flight == 0
            || self.max_live_orders == 0
            || self.response_timeout.is_zero()
        {
            return Err(LiveRpcError::InvalidConfig);
        }
        self.client_id_base
            .checked_add(u64::from(self.connections))
            .ok_or(LiveRpcError::IdentityOverflow)?;
        Ok(())
    }
}

/// Successful live production-protocol report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LiveRpcReport {
    /// Disambiguates this runner from the legacy private measured mode.
    pub mode: String,
    /// Target profile; reference-sink results are not validator capacity.
    pub target_profile: String,
    /// Configured uncapped actions over the duration.
    pub planned: u64,
    /// Warm-up actions scheduled before the measured interval.
    pub warmup_planned: u64,
    /// Exact configured synchronized steady interval.
    pub elapsed_ns: u64,
    /// Time spent after the steady boundary completing the final bounded pipeline.
    pub drain_elapsed_ns: u64,
    /// Aggregate lifecycle counters.
    pub counters: OperationCounters,
    /// Whole-steady-plus-drain raw metrics used for final conservation.
    pub metrics: IntervalMetrics,
    /// Mergeable raw one-second steady-state intervals.
    pub intervals: Vec<IntervalMetrics>,
    /// Events whose local timestamp fell after the steady-state boundary.
    pub drain_metrics: IntervalMetrics,
}

impl LiveRpcReport {
    /// Socket-written operations per second over actual elapsed wall time.
    #[must_use]
    pub fn socket_written_per_second(&self) -> u64 {
        if self.elapsed_ns == 0 {
            return 0;
        }
        u64::try_from(
            u128::from(self.counters.socket_written).saturating_mul(1_000_000_000)
                / u128::from(self.elapsed_ns),
        )
        .unwrap_or(u64::MAX)
    }
}

/// Run an uncapped, multi-connection production-RPC campaign.
pub async fn run_live_rpc(
    scenario: &LoadScenario,
    config: &LiveRpcConfig,
    target_profile: &str,
) -> Result<LiveRpcReport, LiveRpcError> {
    scenario
        .validate()
        .map_err(|error| LiveRpcError::Scenario(error.to_string()))?;
    config.validate()?;
    if target_profile != "reference-sink" && target_profile != "validator" {
        return Err(LiveRpcError::InvalidTargetProfile);
    }
    if target_profile == "validator" && matches!(config.transport, LiveTransport::DevPlaintext) {
        return Err(LiveRpcError::ValidatorTlsRequired);
    }
    let planned = scenario.planned_actions();
    let warmup_planned = scenario
        .orders_per_second
        .checked_mul(config.warmup_secs)
        .ok_or(LiveRpcError::IdentityOverflow)?;
    let start = Instant::now() + config.start_lead;
    let steady_start = start + Duration::from_secs(config.warmup_secs);
    let duration_ns = scenario.duration_secs.saturating_mul(1_000_000_000);
    let steady_end = steady_start + Duration::from_nanos(duration_ns);
    let connection_count = u64::from(config.connections);
    let base_rate = scenario.orders_per_second / connection_count;
    let remainder = scenario.orders_per_second % connection_count;
    let maximum_connection_rate = base_rate + u64::from(remainder != 0);
    let maximum_connection_actions = maximum_connection_rate
        .checked_mul(
            config
                .warmup_secs
                .checked_add(scenario.duration_secs)
                .ok_or(LiveRpcError::IdentityOverflow)?,
        )
        .ok_or(LiveRpcError::IdentityOverflow)?;
    if maximum_connection_actions > u64::from(u32::MAX) {
        return Err(LiveRpcError::NonceNamespaceExhausted);
    }
    let last_client = config
        .client_id_base
        .checked_add(u64::from(config.connections - 1))
        .ok_or(LiveRpcError::IdentityOverflow)?;
    if last_client >= (1u64 << REQUEST_SEQUENCE_BITS) {
        return Err(LiveRpcError::RequestNamespaceExhausted);
    }
    let interval_count =
        usize::try_from(scenario.duration_secs).map_err(|_| LiveRpcError::InvalidConfig)?;
    let mut tasks = JoinSet::new();
    for connection in 0..config.connections {
        let connection_u64 = u64::from(connection);
        let rate = base_rate + u64::from(connection_u64 < remainder);
        let endpoint_index = usize::try_from(connection).unwrap_or(0) % config.endpoints.len();
        let endpoint = config.endpoints[endpoint_index];
        let source_ip = if config.source_ips.is_empty() {
            None
        } else {
            Some(config.source_ips[endpoint_index % config.source_ips.len()])
        };
        let scenario = scenario.clone();
        let session_config = RpcSessionConfig {
            account: config.account,
            client_id: config.client_id_base + connection_u64,
            nonce_base: (u64::from(config.nonce_namespace) << 32),
            signing_seed: config.signing_seed,
            max_in_flight: config.max_in_flight,
            max_live_orders: config.max_live_orders,
        };
        let response_timeout = config.response_timeout;
        let max_in_flight = config.max_in_flight;
        let transport = config.transport.clone();
        tasks.spawn(async move {
            run_connection(
                endpoint,
                source_ip,
                connection,
                rate,
                start,
                steady_start,
                &scenario,
                session_config,
                max_in_flight,
                response_timeout,
                &transport,
            )
            .await
        });
    }

    let mut aggregate_intervals: Vec<Option<IntervalMetrics>> = std::iter::repeat_with(|| None)
        .take(interval_count)
        .collect();
    let mut drains = Vec::with_capacity(usize::try_from(config.connections).unwrap_or(0));
    while let Some(result) = tasks.join_next().await {
        let mut connection =
            result.map_err(|error| LiveRpcError::WorkerJoin(error.to_string()))??;
        if connection.intervals.len() != aggregate_intervals.len() {
            return Err(LiveRpcError::IntervalCountMismatch);
        }
        for (ordinal, interval) in connection.intervals.into_iter().enumerate() {
            if let Some(existing) = &mut aggregate_intervals[ordinal] {
                existing.checked_merge(&interval)?;
            } else {
                aggregate_intervals[ordinal] = Some(interval);
            }
        }
        drains.push(std::mem::take(&mut connection.drain));
    }
    let intervals = aggregate_intervals
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(LiveRpcError::IntervalCountMismatch)?;
    let drain_elapsed_ns = u64::try_from(
        Instant::now()
            .saturating_duration_since(steady_end)
            .as_nanos(),
    )
    .unwrap_or(u64::MAX);
    let drain_end_ns = duration_ns.saturating_add(drain_elapsed_ns.max(1));
    let mut drain_metrics: Option<IntervalMetrics> = None;
    for mut drain in drains {
        let interval = drain.take_interval(duration_ns, drain_end_ns)?;
        if let Some(existing) = &mut drain_metrics {
            existing.checked_merge(&interval)?;
        } else {
            drain_metrics = Some(interval);
        }
    }
    let drain_metrics = drain_metrics.ok_or(LiveRpcError::InvalidConfig)?;
    let mut metrics = intervals
        .first()
        .cloned()
        .ok_or(LiveRpcError::InvalidConfig)?;
    for interval in intervals.iter().skip(1) {
        metrics.checked_accumulate(interval)?;
    }
    metrics.checked_accumulate(&drain_metrics)?;
    let counters = metrics.validate_drained()?;
    if counters.offered != planned {
        return Err(LiveRpcError::PlannedMismatch {
            planned,
            offered: counters.offered,
        });
    }
    Ok(LiveRpcReport {
        mode: "live-production-rpc".to_string(),
        target_profile: target_profile.to_string(),
        planned,
        warmup_planned,
        elapsed_ns: duration_ns,
        drain_elapsed_ns,
        counters,
        metrics,
        intervals,
        drain_metrics,
    })
}

const REQUEST_SEQUENCE_BITS: u32 = 24;
const REQUEST_LOCAL_BITS: u32 = 64 - REQUEST_SEQUENCE_BITS;

struct ConnectionMetrics {
    intervals: Vec<IntervalMetrics>,
    drain: WorkerMetrics,
}

struct EventMetrics {
    start: Instant,
    end: Instant,
    seconds: Vec<WorkerMetrics>,
    drain: WorkerMetrics,
}

impl EventMetrics {
    fn new(start: Instant, duration_secs: u64) -> Result<Self, LiveRpcError> {
        let count = usize::try_from(duration_secs).map_err(|_| LiveRpcError::InvalidConfig)?;
        Ok(Self {
            start,
            end: start + Duration::from_secs(duration_secs),
            seconds: std::iter::repeat_with(WorkerMetrics::default)
                .take(count)
                .collect(),
            drain: WorkerMetrics::default(),
        })
    }

    fn scheduled(&mut self, ordinal: u64) -> Result<&mut WorkerMetrics, LiveRpcError> {
        self.seconds
            .get_mut(usize::try_from(ordinal).map_err(|_| LiveRpcError::IntervalCountMismatch)?)
            .ok_or(LiveRpcError::IntervalCountMismatch)
    }

    fn at(&mut self, instant: Instant) -> &mut WorkerMetrics {
        if instant >= self.end {
            return &mut self.drain;
        }
        let ordinal = instant.saturating_duration_since(self.start).as_secs();
        let index = usize::try_from(ordinal).unwrap_or(self.seconds.len());
        self.seconds.get_mut(index).unwrap_or(&mut self.drain)
    }

    fn finish(mut self) -> Result<ConnectionMetrics, LiveRpcError> {
        let mut intervals = Vec::with_capacity(self.seconds.len());
        for (ordinal, metrics) in self.seconds.iter_mut().enumerate() {
            let start_ns = u64::try_from(ordinal)
                .unwrap_or(u64::MAX)
                .saturating_mul(1_000_000_000);
            intervals
                .push(metrics.take_interval(start_ns, start_ns.saturating_add(1_000_000_000))?);
        }
        Ok(ConnectionMetrics {
            intervals,
            drain: self.drain,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    endpoint: SocketAddr,
    source_ip: Option<IpAddr>,
    connection: u32,
    rate: u64,
    warmup_start: Instant,
    steady_start: Instant,
    scenario: &LoadScenario,
    session_config: RpcSessionConfig,
    max_in_flight: usize,
    response_timeout: Duration,
    transport: &LiveTransport,
) -> Result<ConnectionMetrics, LiveRpcError> {
    let mut stream = connect_stream(endpoint, source_ip, transport).await?;
    tokio::time::sleep_until(warmup_start).await;
    let mut rng = Lcg::new(fold_u64(
        scenario.seed,
        fold_u64(
            fnv1a_64(b"dexos.loadgen.live-rpc.v1"),
            u64::from(connection),
        ),
    ));
    let mut generator = SessionState::new(connection);
    let mut adapter = RpcSessionAdapter::new(session_config)?;
    let mut request_sequence = 0u64;
    execute_phase(
        &mut stream,
        connection,
        rate,
        warmup_start,
        scenario,
        config_duration_secs(warmup_start, steady_start),
        &mut rng,
        &mut generator,
        &mut adapter,
        max_in_flight,
        response_timeout,
        &mut request_sequence,
        None,
    )
    .await?;
    let mut metrics = EventMetrics::new(steady_start, scenario.duration_secs)?;
    execute_phase(
        &mut stream,
        connection,
        rate,
        steady_start,
        scenario,
        scenario.duration_secs,
        &mut rng,
        &mut generator,
        &mut adapter,
        max_in_flight,
        response_timeout,
        &mut request_sequence,
        Some(&mut metrics),
    )
    .await?;
    metrics.finish()
}

fn config_duration_secs(start: Instant, end: Instant) -> u64 {
    end.saturating_duration_since(start).as_secs()
}

struct PendingWire {
    request_id: u64,
    kind: ActionKind,
    bytes: Vec<u8>,
    written_at: Instant,
}

#[allow(clippy::too_many_arguments)]
async fn execute_phase(
    stream: &mut LiveStream,
    connection: u32,
    rate: u64,
    phase_start: Instant,
    scenario: &LoadScenario,
    duration_secs: u64,
    rng: &mut Lcg,
    generator: &mut SessionState,
    adapter: &mut RpcSessionAdapter,
    max_in_flight: usize,
    response_timeout: Duration,
    request_sequence: &mut u64,
    mut metrics: Option<&mut EventMetrics>,
) -> Result<(), LiveRpcError> {
    let planned = rate.saturating_mul(duration_secs);
    let mut next_index = 0u64;
    let mut batch = Vec::with_capacity(max_in_flight);
    while next_index < planned {
        batch.clear();
        while batch.len() < max_in_flight && next_index < planned {
            let generated = generator.next_command(rng, scenario);
            let requested_kind = action_kind(generated.kind);
            let ordinal = next_index.checked_div(rate).unwrap_or(0);
            if let Some(recorder) = metrics.as_deref_mut() {
                let counters = &mut recorder
                    .scheduled(ordinal)?
                    .action_mut(requested_kind)
                    .counters;
                counters.offered = counters.offered.saturating_add(1);
            }

            let due_offset = if rate == 0 {
                u64::MAX
            } else {
                u64::try_from(
                    u128::from(next_index).saturating_mul(1_000_000_000) / u128::from(rate),
                )
                .unwrap_or(u64::MAX)
            };
            next_index = next_index.saturating_add(1);
            let due = phase_start + Duration::from_nanos(due_offset);
            if Instant::now() < due {
                tokio::time::sleep_until(due).await;
            }
            let lag = u64::try_from(Instant::now().saturating_duration_since(due).as_nanos())
                .unwrap_or(u64::MAX);
            if let Some(recorder) = metrics.as_deref_mut() {
                let current = recorder.at(Instant::now());
                current.max_scheduler_lag_ns = current.max_scheduler_lag_ns.max(lag);
            }
            let quantum = if rate == 0 {
                u64::MAX
            } else {
                1_000_000_000 / rate.max(1)
            };
            if lag > quantum.saturating_mul(2) {
                if let Some(recorder) = metrics.as_deref_mut() {
                    let counters = &mut recorder
                        .at(Instant::now())
                        .action_mut(requested_kind)
                        .counters;
                    counters.locally_dropped = counters.locally_dropped.saturating_add(1);
                }
                continue;
            }
            let generated_at = Instant::now();
            if let Some(recorder) = metrics.as_deref_mut() {
                let counters = &mut recorder
                    .at(generated_at)
                    .action_mut(requested_kind)
                    .counters;
                counters.generated = counters.generated.saturating_add(1);
            }
            let request_id = request_id(adapter, *request_sequence)?;
            *request_sequence = request_sequence.saturating_add(1);
            let request = match adapter.build_request(request_id, &generated) {
                Ok(request) => request,
                Err(_) => {
                    if let Some(recorder) = metrics.as_deref_mut() {
                        let counters = &mut recorder
                            .at(Instant::now())
                            .action_mut(requested_kind)
                            .counters;
                        counters.protocol_failed = counters.protocol_failed.saturating_add(1);
                    }
                    continue;
                }
            };
            let actual_kind = method_kind(&request.method);
            if actual_kind != requested_kind {
                if let Some(recorder) = metrics.as_deref_mut() {
                    let scheduled = recorder.scheduled(ordinal)?;
                    scheduled.action_mut(requested_kind).counters.offered = scheduled
                        .action_mut(requested_kind)
                        .counters
                        .offered
                        .saturating_sub(1);
                    scheduled.action_mut(actual_kind).counters.offered = scheduled
                        .action_mut(actual_kind)
                        .counters
                        .offered
                        .saturating_add(1);
                    let current = recorder.at(generated_at);
                    current.action_mut(requested_kind).counters.generated = current
                        .action_mut(requested_kind)
                        .counters
                        .generated
                        .saturating_sub(1);
                    current.action_mut(actual_kind).counters.generated = current
                        .action_mut(actual_kind)
                        .counters
                        .generated
                        .saturating_add(1);
                }
            }
            let bytes = match encode_request(&request) {
                Ok(bytes) => bytes,
                Err(_) => {
                    if let Some(recorder) = metrics.as_deref_mut() {
                        let actual =
                            &mut recorder.at(Instant::now()).action_mut(actual_kind).counters;
                        actual.protocol_failed = actual.protocol_failed.saturating_add(1);
                    }
                    continue;
                }
            };
            let queued_at = Instant::now();
            if let Some(recorder) = metrics.as_deref_mut() {
                let current = recorder.at(queued_at);
                let actual = &mut current.action_mut(actual_kind);
                actual.counters.queued = actual.counters.queued.saturating_add(1);
                actual.queue_delay_ns.record(
                    u64::try_from(queued_at.saturating_duration_since(due).as_nanos())
                        .unwrap_or(u64::MAX),
                );
                current.queue_high_water = current
                    .queue_high_water
                    .max(u64::try_from(batch.len() + 1).unwrap_or(u64::MAX));
            }
            batch.push(PendingWire {
                request_id,
                kind: actual_kind,
                bytes,
                written_at: queued_at,
            });
        }

        for item in &mut batch {
            if let Err(source) = stream.write_all(&item.bytes).await {
                return Err(LiveRpcError::Io(source));
            }
            item.written_at = Instant::now();
            if let Some(recorder) = metrics.as_deref_mut() {
                let counters = &mut recorder.at(item.written_at).action_mut(item.kind).counters;
                counters.socket_written = counters.socket_written.saturating_add(1);
            }
        }
        stream.flush().await?;

        while !batch.is_empty() {
            let timeout_request_id = batch[0].request_id;
            let bytes = tokio::time::timeout(
                response_timeout,
                read_response_frame(stream, MAX_RPC_FRAME_PAYLOAD),
            )
            .await
            .map_err(|_| LiveRpcError::ResponseTimeout {
                request_id: timeout_request_id,
            })??;
            let response = decode_response(&bytes).map_err(LiveRpcError::Protocol)?;
            let position = batch
                .iter()
                .position(|item| item.request_id == response.request_id)
                .ok_or(LiveRpcError::UnknownCorrelation(response.request_id))?;
            let item = batch.swap_remove(position);
            let acknowledged_at = Instant::now();
            if let Some(recorder) = metrics.as_deref_mut() {
                let actual = recorder.at(acknowledged_at).action_mut(item.kind);
                actual.request_ack_ns.record(
                    u64::try_from(
                        acknowledged_at
                            .saturating_duration_since(item.written_at)
                            .as_nanos(),
                    )
                    .unwrap_or(u64::MAX),
                );
                actual.counters.acknowledged = actual.counters.acknowledged.saturating_add(1);
            }
            match adapter.apply_response(response)? {
                AdapterOutcome::Accepted(_) => {
                    if let Some(recorder) = metrics.as_deref_mut() {
                        let counters =
                            &mut recorder.at(acknowledged_at).action_mut(item.kind).counters;
                        counters.accepted = counters.accepted.saturating_add(1);
                    }
                }
                AdapterOutcome::Rejected(_) => {
                    if let Some(recorder) = metrics.as_deref_mut() {
                        let counters =
                            &mut recorder.at(acknowledged_at).action_mut(item.kind).counters;
                        counters.rejected = counters.rejected.saturating_add(1);
                    }
                }
            }
        }
    }
    let _ = connection;
    Ok(())
}

fn request_id(adapter: &RpcSessionAdapter, sequence: u64) -> Result<u64, LiveRpcError> {
    if sequence >= (1u64 << REQUEST_LOCAL_BITS) {
        return Err(LiveRpcError::RequestNamespaceExhausted);
    }
    let client_id = adapter.client_id();
    if client_id >= (1u64 << REQUEST_SEQUENCE_BITS) {
        return Err(LiveRpcError::RequestNamespaceExhausted);
    }
    Ok((client_id << REQUEST_LOCAL_BITS) | sequence)
}

pub(crate) async fn read_response_frame(
    stream: &mut LiveStream,
    max_payload: usize,
) -> Result<Vec<u8>, LiveRpcError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let declared = u32::from_le_bytes([header[15], header[16], header[17], header[18]]);
    let payload_len = usize::try_from(declared).map_err(|_| LiveRpcError::Oversize)?;
    if payload_len > max_payload {
        return Err(LiveRpcError::Oversize);
    }
    let mut bytes = vec![0u8; FRAME_HEADER_LEN + payload_len];
    bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream.read_exact(&mut bytes[FRAME_HEADER_LEN..]).await?;
    Ok(bytes)
}

pub(crate) enum LiveStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for LiveStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LiveStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

pub(crate) async fn connect_stream(
    endpoint: SocketAddr,
    source_ip: Option<IpAddr>,
    transport: &LiveTransport,
) -> Result<LiveStream, LiveRpcError> {
    let socket = match endpoint {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(source_ip) = source_ip {
        if source_ip.is_ipv4() != endpoint.is_ipv4() {
            return Err(LiveRpcError::SourceAddressFamily);
        }
        socket.bind(SocketAddr::new(source_ip, 0))?;
    }
    let tcp = socket
        .connect(endpoint)
        .await
        .map_err(|source| LiveRpcError::Connect { endpoint, source })?;
    tcp.set_nodelay(true)?;
    match transport {
        LiveTransport::DevPlaintext => Ok(LiveStream::Plain(tcp)),
        LiveTransport::Tls13 {
            server_name,
            ca_certificates_pem,
            client_identity,
        } => {
            let connector = tls_connector(ca_certificates_pem, client_identity.as_ref())?;
            let name = ServerName::try_from(server_name.clone())
                .map_err(|error| LiveRpcError::TlsConfig(error.to_string()))?;
            let stream = connector
                .connect(name, tcp)
                .await
                .map_err(|error| LiveRpcError::TlsHandshake(error.to_string()))?;
            Ok(LiveStream::Tls(Box::new(stream)))
        }
    }
}

fn tls_connector(
    roots_pem: &[u8],
    client_identity: Option<&ClientTlsIdentity>,
) -> Result<TlsConnector, LiveRpcError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(roots_pem)))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|error| LiveRpcError::TlsConfig(error.to_string()))?;
    if certs.is_empty() {
        return Err(LiveRpcError::TlsConfig("no CA certificates".to_string()));
    }
    for cert in certs {
        roots
            .add(cert)
            .map_err(|error| LiveRpcError::TlsConfig(error.to_string()))?;
    }
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots);
    let mut config = match client_identity {
        None => builder.with_no_client_auth(),
        Some(identity) => {
            let certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(
                &identity.certificate_chain_pem,
            )))
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|error| LiveRpcError::TlsConfig(error.to_string()))?;
            let key = rustls_pemfile::private_key(&mut BufReader::new(Cursor::new(
                &identity.private_key_pem,
            )))
            .map_err(|error| LiveRpcError::TlsConfig(error.to_string()))?
            .ok_or_else(|| LiveRpcError::TlsConfig("no client private key".to_string()))?;
            builder
                .with_client_auth_cert(certs, PrivateKeyDer::clone_key(&key))
                .map_err(|error| LiveRpcError::TlsConfig(error.to_string()))?
        }
    };
    config.alpn_protocols = vec![b"dexos-rpc/1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

const fn action_kind(kind: CommandKind) -> ActionKind {
    match kind {
        CommandKind::NewOrder => ActionKind::New,
        CommandKind::Cancel => ActionKind::Cancel,
        CommandKind::Replace => ActionKind::Replace,
    }
}

fn method_kind(method: &RpcMethod) -> ActionKind {
    match method {
        RpcMethod::SubmitOrder(..) => ActionKind::New,
        RpcMethod::CancelOrder(..) => ActionKind::Cancel,
        RpcMethod::ReplaceOrder(..) => ActionKind::Replace,
        _ => ActionKind::New,
    }
}

/// Live production-RPC runtime error. Any error invalidates a qualification run.
#[derive(Debug, thiserror::Error)]
pub enum LiveRpcError {
    /// Empty endpoint/connection/capacity settings.
    #[error("invalid live RPC configuration")]
    InvalidConfig,
    /// Target label must explicitly be validator or reference-sink.
    #[error("invalid target profile")]
    InvalidTargetProfile,
    /// Validator campaigns may not use plaintext.
    #[error("validator target profile requires TLS 1.3")]
    ValidatorTlsRequired,
    /// Client identity range overflowed.
    #[error("client identity range overflow")]
    IdentityOverflow,
    /// Explicit source IP has the wrong address family.
    #[error("source IP and endpoint address families differ")]
    SourceAddressFamily,
    /// TLS roots/client identity could not be parsed.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
    /// TLS certificate validation or handshake failed.
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),
    /// Scenario validation failed.
    #[error("invalid load scenario: {0}")]
    Scenario(String),
    /// Target could not be connected.
    #[error("cannot connect to {endpoint}: {source}")]
    Connect {
        /// Explicit target endpoint.
        endpoint: SocketAddr,
        /// Socket error.
        source: std::io::Error,
    },
    /// Socket read/write failure.
    #[error("live RPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Production frame codec failure.
    #[error("live RPC protocol error: {0}")]
    Protocol(proto::RpcError),
    /// Stateful signing/correlation adapter failure.
    #[error(transparent)]
    Adapter(#[from] RpcAdapterError),
    /// Response deadline elapsed; the stream is no longer safe to reuse.
    #[error("response timeout for request {request_id}")]
    ResponseTimeout { request_id: u64 },
    /// Response did not match any request in the bounded pipeline.
    #[error("response id {0} does not match an in-flight request")]
    UnknownCorrelation(u64),
    /// The controller-assigned high nonce namespace would be crossed.
    #[error("per-connection nonce namespace would be exhausted")]
    NonceNamespaceExhausted,
    /// Client/request identity cannot fit the collision-free request-ID partition.
    #[error("request ID namespace would be exhausted")]
    RequestNamespaceExhausted,
    /// A worker returned an unexpected number of steady intervals.
    #[error("worker interval count mismatch")]
    IntervalCountMismatch,
    /// Declared response exceeds the configured cap.
    #[error("response frame exceeds configured payload cap")]
    Oversize,
    /// Worker task panicked or was cancelled.
    #[error("live RPC worker failed: {0}")]
    WorkerJoin(String),
    /// Raw interval metrics did not merge or conserve.
    #[error(transparent)]
    Metrics(#[from] MetricsError),
    /// Partitioned offered total differs from scenario plan.
    #[error("planned/offered mismatch: planned={planned}, offered={offered}")]
    PlannedMismatch { planned: u64, offered: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serve_reference_sink, ReferenceSinkConfig, ReferenceSinkCounters};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    #[tokio::test]
    async fn uncapped_production_rpc_runner_reconciles_reference_sink() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let counters = Arc::new(ReferenceSinkCounters::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        let sink_counters = counters.clone();
        let sink = tokio::spawn(async move {
            serve_reference_sink(
                listener,
                ReferenceSinkConfig::default(),
                sink_counters,
                stop_rx,
            )
            .await
            .unwrap();
        });
        let scenario = LoadScenario {
            orders_per_second: 20,
            duration_secs: 2,
            cancel_ratio: types::Ratio::from_raw(300_000),
            replace_ratio: types::Ratio::from_raw(200_000),
            ..LoadScenario::default()
        };
        let report = run_live_rpc(
            &scenario,
            &LiveRpcConfig {
                endpoints: vec![endpoint],
                source_ips: Vec::new(),
                connections: 2,
                account: AccountId::new(1),
                client_id_base: 1_000,
                nonce_namespace: 9,
                signing_seed: [4; 32],
                max_in_flight: 4,
                max_live_orders: 32,
                response_timeout: Duration::from_secs(2),
                warmup_secs: 1,
                start_lead: Duration::from_millis(10),
                transport: LiveTransport::DevPlaintext,
            },
            "reference-sink",
        )
        .await
        .unwrap();
        stop_tx.send(true).unwrap();
        sink.await.unwrap();
        assert_eq!(report.mode, "live-production-rpc");
        assert_eq!(report.target_profile, "reference-sink");
        assert_eq!(report.planned, 40);
        assert_eq!(report.warmup_planned, 20);
        assert_eq!(report.intervals.len(), 2);
        assert_eq!(report.counters.offered, 40);
        assert_eq!(report.counters.socket_written, 40);
        assert_eq!(report.counters.acknowledged, 40);
        assert_eq!(report.counters.accepted, 40);
        let sink = counters.snapshot();
        assert_eq!(sink.received, 60);
        assert_eq!(sink.accepted, 60);
    }

    #[tokio::test]
    async fn unreachable_endpoint_fails_instead_of_reporting_planned_work() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        drop(listener);
        let error = run_live_rpc(
            &LoadScenario {
                orders_per_second: 1,
                duration_secs: 1,
                ..LoadScenario::default()
            },
            &LiveRpcConfig {
                endpoints: vec![endpoint],
                source_ips: Vec::new(),
                connections: 1,
                account: AccountId::new(1),
                client_id_base: 1,
                nonce_namespace: 1,
                signing_seed: [1; 32],
                max_in_flight: 1,
                max_live_orders: 1,
                response_timeout: Duration::from_secs(1),
                warmup_secs: 0,
                start_lead: Duration::ZERO,
                transport: LiveTransport::Tls13 {
                    server_name: "localhost".to_string(),
                    ca_certificates_pem: Vec::new(),
                    client_identity: None,
                },
            },
            "validator",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, LiveRpcError::Connect { .. }));
    }

    #[tokio::test]
    async fn tls13_validates_server_certificate_and_negotiates_rpc_alpn() {
        let (cert_pem, key_pem) = rpc::generate_self_signed_localhost().unwrap();
        let acceptor = rpc::acceptor_from_pem(&cert_pem, &key_pem, None).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut byte = [0u8; 1];
            tls.read_exact(&mut byte).await.unwrap();
            tls.write_all(&byte).await.unwrap();
            tls.flush().await.unwrap();
        });
        let mut stream = connect_stream(
            endpoint,
            None,
            &LiveTransport::Tls13 {
                server_name: "localhost".to_string(),
                ca_certificates_pem: cert_pem,
                client_identity: None,
            },
        )
        .await
        .unwrap();
        stream.write_all(&[7]).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 1];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, [7]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls13_optional_client_identity_satisfies_mtls() {
        let (cert_pem, key_pem) = rpc::generate_self_signed_localhost().unwrap();
        let acceptor = rpc::acceptor_from_pem(&cert_pem, &key_pem, Some(&cert_pem)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            tls.write_all(&[11]).await.unwrap();
            tls.flush().await.unwrap();
        });
        let mut stream = connect_stream(
            endpoint,
            None,
            &LiveTransport::Tls13 {
                server_name: "localhost".to_string(),
                ca_certificates_pem: cert_pem.clone(),
                client_identity: Some(ClientTlsIdentity {
                    certificate_chain_pem: cert_pem,
                    private_key_pem: key_pem,
                }),
            },
        )
        .await
        .unwrap();
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [11]);
        server.await.unwrap();
    }
}
