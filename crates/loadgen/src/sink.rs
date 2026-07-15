//! Protocol-conformant, unmistakably test-only reference sink and fault harness.

use std::io::BufReader;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use codec::{FRAME_HEADER_LEN, MAX_RPC_FRAME_PAYLOAD};
use proto::{
    command_hash, decode_request, encode_response_into, CommandAck, FinalityStatus, RpcError,
    RpcMethod, RpcOk, RpcRequest, RpcResponse,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use types::OrderId;

use crate::metrics::{HistogramSummary, LatencyHistogram};

const SINK_HISTOGRAM_MAX_NS: u64 = 60_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkFaultMode {
    NoAck,
    ImmediateAck,
    BatchedAck { batch: u32 },
    DelayedAck { delay_ms: u64 },
    Reject,
    Drop,
    CorruptResponse,
    Throttle { delay_us: u64 },
    Disconnect { after_requests: u64 },
}

#[derive(Debug, Clone)]
pub struct ReferenceSinkConfig {
    pub fault: SinkFaultMode,
    pub validate_signatures: bool,
    pub max_frame_payload: usize,
    pub response_buffer_bytes: usize,
}

impl Default for ReferenceSinkConfig {
    fn default() -> Self {
        Self {
            fault: SinkFaultMode::ImmediateAck,
            validate_signatures: true,
            max_frame_payload: MAX_RPC_FRAME_PAYLOAD,
            response_buffer_bytes: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkSnapshot {
    pub mode: &'static str,
    pub received: u64,
    pub acknowledged: u64,
    pub rejected: u64,
    pub new_orders: u64,
    pub cancels: u64,
    pub replaces: u64,
    pub malformed: u64,
    pub transport_errors: u64,
    pub connections: u64,
    pub histogram_merge_errors: u64,
}

/// Raw sink-side processing latency, compatible with load-generator histogram
/// artifacts. The boundary is complete request frame read through completion of the
/// configured acknowledgement/fault action on the same monotonic clock.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SinkHistogramReport {
    pub summary: HistogramSummary,
    pub raw: Vec<u64>,
    pub max_trackable_ns: u64,
}

#[derive(Debug)]
pub struct SinkCounters {
    received: AtomicU64,
    acknowledged: AtomicU64,
    rejected: AtomicU64,
    new_orders: AtomicU64,
    cancels: AtomicU64,
    replaces: AtomicU64,
    malformed: AtomicU64,
    transport_errors: AtomicU64,
    connections: AtomicU64,
    histogram_merge_errors: AtomicU64,
    processing_latency: Mutex<LatencyHistogram>,
}

impl Default for SinkCounters {
    fn default() -> Self {
        Self {
            received: AtomicU64::new(0),
            acknowledged: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            new_orders: AtomicU64::new(0),
            cancels: AtomicU64::new(0),
            replaces: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            transport_errors: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            histogram_merge_errors: AtomicU64::new(0),
            processing_latency: Mutex::new(LatencyHistogram::new(SINK_HISTOGRAM_MAX_NS)),
        }
    }
}

impl SinkCounters {
    #[must_use]
    pub fn snapshot(&self) -> SinkSnapshot {
        SinkSnapshot {
            mode: "reference-sink-test-only",
            received: self.received.load(Ordering::Relaxed),
            acknowledged: self.acknowledged.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            new_orders: self.new_orders.load(Ordering::Relaxed),
            cancels: self.cancels.load(Ordering::Relaxed),
            replaces: self.replaces.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
            transport_errors: self.transport_errors.load(Ordering::Relaxed),
            connections: self.connections.load(Ordering::Relaxed),
            histogram_merge_errors: self.histogram_merge_errors.load(Ordering::Relaxed),
        }
    }

    /// Snapshot raw compatible processing-latency buckets off the receive hot path.
    #[must_use]
    pub fn processing_latency(&self) -> SinkHistogramReport {
        let histogram = self
            .processing_latency
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        SinkHistogramReport {
            summary: histogram.summary(),
            raw: histogram.raw_buckets().to_vec(),
            max_trackable_ns: histogram.max_trackable_ns(),
        }
    }
}

struct ConnectionHistogram {
    counters: Arc<SinkCounters>,
    processing_latency: LatencyHistogram,
}

impl ConnectionHistogram {
    fn new(counters: Arc<SinkCounters>) -> Self {
        Self {
            counters,
            processing_latency: LatencyHistogram::new(SINK_HISTOGRAM_MAX_NS),
        }
    }

    fn record(&mut self, latency_ns: u64) {
        self.processing_latency.record(latency_ns);
    }
}

impl Drop for ConnectionHistogram {
    fn drop(&mut self) {
        let mut aggregate = self
            .counters
            .processing_latency
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if aggregate.merge(&self.processing_latency).is_err() {
            self.counters
                .histogram_merge_errors
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("reference sink peer closed cleanly")]
    Closed,
    #[error("reference sink I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("reference sink received an oversized frame")]
    Oversized,
    #[error("reference sink protocol failure: {0}")]
    Protocol(#[from] RpcError),
    #[error("reference sink configuration is invalid: {0}")]
    Config(&'static str),
    #[error("reference sink TLS configuration failed: {0}")]
    Tls(String),
}

/// Serve a plaintext test sink until shutdown. Every artifact remains explicitly
/// labelled `reference-sink-test-only`.
pub async fn serve_reference_sink(
    listener: TcpListener,
    config: ReferenceSinkConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<Arc<SinkCounters>, SinkError> {
    validate_config(&config)?;
    let counters = Arc::new(SinkCounters::default());
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                stream.set_nodelay(true)?;
                counters.connections.fetch_add(1, Ordering::Relaxed);
                let local_counters = Arc::clone(&counters);
                let local_config = config.clone();
                connections.spawn(async move {
                    let result = serve_sink_connection(stream, local_config, Arc::clone(&local_counters)).await;
                    local_counters.connections.fetch_sub(1, Ordering::Relaxed);
                    if result.is_err() && !matches!(result, Err(SinkError::Closed)) {
                        local_counters.transport_errors.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(counters)
}

/// Serve the same bounded sink contract over TLS 1.3. Client-certificate
/// verification, when configured on `acceptor`, occurs before a connection can
/// contribute any receive counter.
pub async fn serve_reference_sink_tls(
    listener: TcpListener,
    config: ReferenceSinkConfig,
    acceptor: TlsAcceptor,
    mut shutdown: watch::Receiver<bool>,
) -> Result<Arc<SinkCounters>, SinkError> {
    validate_config(&config)?;
    let counters = Arc::new(SinkCounters::default());
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                stream.set_nodelay(true)?;
                counters.connections.fetch_add(1, Ordering::Relaxed);
                let local_counters = Arc::clone(&counters);
                let local_config = config.clone();
                let local_acceptor = acceptor.clone();
                connections.spawn(async move {
                    let result = match local_acceptor.accept(stream).await {
                        Ok(stream) => serve_sink_connection(
                            stream,
                            local_config,
                            Arc::clone(&local_counters),
                        )
                        .await,
                        Err(error) => Err(SinkError::Tls(error.to_string())),
                    };
                    local_counters.connections.fetch_sub(1, Ordering::Relaxed);
                    if result.is_err() && !matches!(result, Err(SinkError::Closed)) {
                        local_counters.transport_errors.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(counters)
}

/// Build a TLS 1.3-only sink acceptor from PEM files. Supplying `client_ca_file`
/// enables mandatory mTLS; omitting it keeps server-authenticated TLS.
pub fn reference_sink_tls_acceptor(
    certificate_file: &str,
    private_key_file: &str,
    client_ca_file: Option<&str>,
) -> Result<TlsAcceptor, SinkError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate_bytes = std::fs::read(certificate_file)
        .map_err(|error| SinkError::Tls(format!("read certificate: {error}")))?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate_bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| SinkError::Tls(format!("parse certificate: {error}")))?;
    if certificates.is_empty() {
        return Err(SinkError::Tls(
            "certificate file contains no certificates".to_string(),
        ));
    }
    let private_key_bytes = std::fs::read(private_key_file)
        .map_err(|error| SinkError::Tls(format!("read private key: {error}")))?;
    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(private_key_bytes.as_slice()))
            .map_err(|error| SinkError::Tls(format!("parse private key: {error}")))?
            .ok_or_else(|| SinkError::Tls("private-key file contains no key".to_string()))?;

    let builder = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let builder = if let Some(client_ca_file) = client_ca_file {
        let ca_bytes = std::fs::read(client_ca_file)
            .map_err(|error| SinkError::Tls(format!("read client CA: {error}")))?;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut BufReader::new(ca_bytes.as_slice())) {
            roots
                .add(
                    certificate
                        .map_err(|error| SinkError::Tls(format!("parse client CA: {error}")))?,
                )
                .map_err(|error| SinkError::Tls(format!("add client CA: {error}")))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|error| SinkError::Tls(format!("build client verifier: {error}")))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let config = builder
        .with_single_cert(certificates, private_key)
        .map_err(|error| SinkError::Tls(format!("install identity: {error}")))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub(crate) async fn serve_sink_connection<S>(
    mut stream: S,
    config: ReferenceSinkConfig,
    counters: Arc<SinkCounters>,
) -> Result<(), SinkError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_config(&config)?;
    let mut histogram = ConnectionHistogram::new(Arc::clone(&counters));
    let mut read_buffer = Vec::with_capacity(FRAME_HEADER_LEN + config.max_frame_payload);
    let mut response_payload = vec![0u8; config.response_buffer_bytes].into_boxed_slice();
    let mut response_frame = Vec::with_capacity(config.response_buffer_bytes + FRAME_HEADER_LEN);
    let mut batched = Vec::with_capacity(match config.fault {
        SinkFaultMode::BatchedAck { batch } => usize::try_from(batch).unwrap_or(1),
        _ => 1,
    });
    let mut connection_received = 0u64;
    loop {
        let bytes = read_frame(&mut stream, &mut read_buffer, config.max_frame_payload).await?;
        let processing_started = Instant::now();
        let request = match decode_request(bytes) {
            Ok(request) => request,
            Err(error) => {
                counters.malformed.fetch_add(1, Ordering::Relaxed);
                return Err(SinkError::Protocol(error));
            }
        };
        let acknowledgement =
            inspect_request(&request, config.validate_signatures).map_err(|error| {
                counters.malformed.fetch_add(1, Ordering::Relaxed);
                SinkError::Protocol(error)
            })?;
        counters.received.fetch_add(1, Ordering::Relaxed);
        count_method(&counters, &request.method);
        connection_received = connection_received.saturating_add(1);

        if matches!(config.fault, SinkFaultMode::Disconnect { after_requests } if connection_received >= after_requests)
        {
            histogram
                .record(u64::try_from(processing_started.elapsed().as_nanos()).unwrap_or(u64::MAX));
            return Ok(());
        }
        let result: Result<(), SinkError> = async {
            match config.fault {
                SinkFaultMode::NoAck | SinkFaultMode::Drop | SinkFaultMode::Disconnect { .. } => {}
                SinkFaultMode::CorruptResponse => {
                    stream.write_all(b"not-a-dexos-frame").await?;
                    stream.flush().await?;
                }
                SinkFaultMode::DelayedAck { delay_ms } => {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    write_response(
                        &mut stream,
                        RpcResponse::new(
                            request.request_id,
                            Ok(RpcOk::CommandAck(acknowledgement)),
                        ),
                        &mut response_payload,
                        &mut response_frame,
                    )
                    .await?;
                    counters.acknowledged.fetch_add(1, Ordering::Relaxed);
                }
                SinkFaultMode::Throttle { delay_us } => {
                    tokio::time::sleep(Duration::from_micros(delay_us)).await;
                    write_response(
                        &mut stream,
                        RpcResponse::new(
                            request.request_id,
                            Ok(RpcOk::CommandAck(acknowledgement)),
                        ),
                        &mut response_payload,
                        &mut response_frame,
                    )
                    .await?;
                    counters.acknowledged.fetch_add(1, Ordering::Relaxed);
                }
                SinkFaultMode::Reject => {
                    write_response(
                        &mut stream,
                        RpcResponse::new(request.request_id, Err(RpcError::Backpressure)),
                        &mut response_payload,
                        &mut response_frame,
                    )
                    .await?;
                    counters.rejected.fetch_add(1, Ordering::Relaxed);
                    counters.acknowledged.fetch_add(1, Ordering::Relaxed);
                }
                SinkFaultMode::ImmediateAck => {
                    write_response(
                        &mut stream,
                        RpcResponse::new(
                            request.request_id,
                            Ok(RpcOk::CommandAck(acknowledgement)),
                        ),
                        &mut response_payload,
                        &mut response_frame,
                    )
                    .await?;
                    counters.acknowledged.fetch_add(1, Ordering::Relaxed);
                }
                SinkFaultMode::BatchedAck { batch } => {
                    batched.push(RpcResponse::new(
                        request.request_id,
                        Ok(RpcOk::CommandAck(acknowledgement)),
                    ));
                    if batched.len() >= usize::try_from(batch).unwrap_or(1) {
                        for response in batched.drain(..).rev() {
                            write_response(
                                &mut stream,
                                response,
                                &mut response_payload,
                                &mut response_frame,
                            )
                            .await?;
                            counters.acknowledged.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            Ok(())
        }
        .await;
        histogram
            .record(u64::try_from(processing_started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        result?;
    }
}

fn validate_config(config: &ReferenceSinkConfig) -> Result<(), SinkError> {
    if config.max_frame_payload == 0 || config.max_frame_payload > MAX_RPC_FRAME_PAYLOAD {
        return Err(SinkError::Config("invalid max_frame_payload"));
    }
    if config.response_buffer_bytes < 256 {
        return Err(SinkError::Config(
            "response buffer must be at least 256 bytes",
        ));
    }
    if matches!(config.fault, SinkFaultMode::BatchedAck { batch: 0 }) {
        return Err(SinkError::Config("batch must be nonzero"));
    }
    if matches!(
        config.fault,
        SinkFaultMode::Disconnect { after_requests: 0 }
    ) {
        return Err(SinkError::Config("disconnect threshold must be nonzero"));
    }
    Ok(())
}

fn inspect_request(request: &RpcRequest, validate_signature: bool) -> Result<CommandAck, RpcError> {
    let (meta, command, market, order_id) = match &request.method {
        RpcMethod::SubmitOrder(meta, params) => (
            meta,
            params.to_command(),
            params.market,
            Some(OrderId::new(request.request_id)),
        ),
        RpcMethod::CancelOrder(meta, params) => (
            meta,
            params.to_command(),
            params.market,
            Some(params.order_id),
        ),
        RpcMethod::ReplaceOrder(meta, params) => (
            meta,
            params.to_command(),
            params.market,
            Some(params.order_id),
        ),
        _ => return Err(RpcError::UnknownMethod),
    };
    if validate_signature {
        meta.verify_signature(&command)?;
    }
    Ok(CommandAck {
        command_hash: command_hash(&command),
        finality: FinalityStatus::Accepted,
        order_id,
        market_id: Some(market),
    })
}

fn count_method(counters: &SinkCounters, method: &RpcMethod) {
    match method {
        RpcMethod::SubmitOrder(..) => &counters.new_orders,
        RpcMethod::CancelOrder(..) => &counters.cancels,
        RpcMethod::ReplaceOrder(..) => &counters.replaces,
        _ => &counters.malformed,
    }
    .fetch_add(1, Ordering::Relaxed);
}

async fn read_frame<'a, S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &'a mut Vec<u8>,
    max_payload: usize,
) -> Result<&'a [u8], SinkError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    if stream.read(&mut header[..1]).await? == 0 {
        return Err(SinkError::Closed);
    }
    stream.read_exact(&mut header[1..]).await?;
    let payload_len = u32::from_le_bytes([header[15], header[16], header[17], header[18]]) as usize;
    if payload_len > max_payload {
        return Err(SinkError::Oversized);
    }
    let frame_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(SinkError::Oversized)?;
    if buffer.capacity() < frame_len {
        return Err(SinkError::Oversized);
    }
    buffer.resize(frame_len, 0);
    buffer[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream.read_exact(&mut buffer[FRAME_HEADER_LEN..]).await?;
    Ok(buffer)
}

async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: RpcResponse,
    payload: &mut [u8],
    frame: &mut Vec<u8>,
) -> Result<(), SinkError> {
    encode_response_into(&response, payload, frame)?;
    stream.write_all(frame).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::{OperationMix, ProtocolAdapter};
    use crate::{Lcg, LoadScenario, SessionState};
    use crypto::KeyPair;
    use proto::decode_response;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;
    use types::{AccountId, Ratio, RATIO_SCALE};

    fn request(request_id: u64) -> Vec<u8> {
        let scenario = LoadScenario {
            market_ids: vec![7],
            operation_mix: Some(OperationMix {
                new: Ratio::from_raw(RATIO_SCALE),
                cancel: Ratio::ZERO,
                replace: Ratio::ZERO,
            }),
            ..LoadScenario::default()
        };
        let mut session = SessionState::with_partition(1, &scenario, "sink-test", 0, false);
        let command = session.next_command(&mut Lcg::new(0), &scenario);
        ProtocolAdapter::new(AccountId::new(1), KeyPair::from_seed(&[3; 32]), 0, None)
            .encode(request_id, command)
            .unwrap()
            .bytes
    }

    async fn run_one(mode: SinkFaultMode) -> (SinkSnapshot, SinkHistogramReport, Vec<u8>) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let counters = Arc::new(SinkCounters::default());
        let task_counters = Arc::clone(&counters);
        let task = tokio::spawn(async move {
            let _ = serve_sink_connection(
                server,
                ReferenceSinkConfig {
                    fault: mode,
                    ..ReferenceSinkConfig::default()
                },
                task_counters,
            )
            .await;
        });
        client.write_all(&request(11)).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response).await;
        let _ = task.await;
        (counters.snapshot(), counters.processing_latency(), response)
    }

    #[tokio::test]
    async fn immediate_reject_drop_corrupt_and_disconnect_are_deterministic() {
        let (healthy, histogram, response) = run_one(SinkFaultMode::ImmediateAck).await;
        assert_eq!(healthy.received, 1);
        assert_eq!(healthy.acknowledged, 1);
        assert_eq!(healthy.mode, "reference-sink-test-only");
        assert_eq!(histogram.summary.count, 1);
        assert_eq!(histogram.raw.iter().sum::<u64>(), 1);
        assert_eq!(histogram.summary.saturated, 0);
        assert_eq!(histogram.summary.overflow, 0);
        assert!(decode_response(&response).is_ok());
        let (reject, _, response) = run_one(SinkFaultMode::Reject).await;
        assert_eq!(reject.rejected, 1);
        assert!(decode_response(&response).unwrap().result.is_err());
        for mode in [SinkFaultMode::NoAck, SinkFaultMode::Drop] {
            let (snapshot, _, response) = run_one(mode).await;
            assert_eq!(snapshot.received, 1);
            assert!(response.is_empty());
        }
        let (_, _, corrupt) = run_one(SinkFaultMode::CorruptResponse).await;
        assert!(decode_response(&corrupt).is_err());
        let (disconnect, _, response) =
            run_one(SinkFaultMode::Disconnect { after_requests: 1 }).await;
        assert_eq!(disconnect.received, 1);
        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn delayed_throttled_and_batched_modes_acknowledge() {
        for mode in [
            SinkFaultMode::DelayedAck { delay_ms: 1 },
            SinkFaultMode::Throttle { delay_us: 1 },
            SinkFaultMode::BatchedAck { batch: 1 },
        ] {
            let (snapshot, _, response) = run_one(mode).await;
            assert_eq!(snapshot.acknowledged, 1, "{mode:?}");
            assert!(decode_response(&response).is_ok(), "{mode:?}");
        }
    }

    #[tokio::test]
    async fn malformed_and_oversized_input_is_bounded() {
        let (mut client, server) = tokio::io::duplex(1024);
        let counters = Arc::new(SinkCounters::default());
        let task = tokio::spawn(serve_sink_connection(
            server,
            ReferenceSinkConfig::default(),
            Arc::clone(&counters),
        ));
        let mut bad = [0u8; FRAME_HEADER_LEN];
        bad[15..19].copy_from_slice(&u32::MAX.to_le_bytes());
        client.write_all(&bad).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(matches!(task.await.unwrap(), Err(SinkError::Oversized)));
    }

    #[tokio::test]
    async fn tls13_mtls_listener_uses_pem_identity_and_client_roots() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey {
            cert: server_cert,
            key_pair: server_key,
        } = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let CertifiedKey {
            cert: client_cert,
            key_pair: client_key,
        } = generate_simple_self_signed(vec!["loadgen-client".to_string()]).unwrap();
        let directory =
            std::env::temp_dir().join(format!("dexos-reference-sink-tls-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let certificate_file = directory.join("server.pem");
        let private_key_file = directory.join("server-key.pem");
        let client_ca_file = directory.join("client-ca.pem");
        std::fs::write(&certificate_file, server_cert.pem()).unwrap();
        std::fs::write(&private_key_file, server_key.serialize_pem()).unwrap();
        std::fs::write(&client_ca_file, client_cert.pem()).unwrap();

        let acceptor = reference_sink_tls_acceptor(
            &certificate_file.to_string_lossy(),
            &private_key_file.to_string_lossy(),
            Some(&client_ca_file.to_string_lossy()),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let server = tokio::spawn(serve_reference_sink_tls(
            listener,
            ReferenceSinkConfig::default(),
            acceptor,
            stop_rx,
        ));

        let mut roots = RootCertStore::empty();
        roots.add(server_cert.der().clone()).unwrap();
        let client_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    vec![client_cert.der().clone()],
                    PrivatePkcs8KeyDer::from(client_key.serialize_der()).into(),
                )
                .unwrap();
        let tcp = TcpStream::connect(address).await.unwrap();
        let mut tls = TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("localhost".to_string()).unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(&request(77)).await.unwrap();
        let mut response = Vec::with_capacity(FRAME_HEADER_LEN + MAX_RPC_FRAME_PAYLOAD);
        let frame = read_frame(&mut tls, &mut response, MAX_RPC_FRAME_PAYLOAD)
            .await
            .unwrap();
        assert_eq!(decode_response(frame).unwrap().request_id, 77);
        drop(tls);
        let _ = stop_tx.send(true);
        let counters = server.await.unwrap().unwrap();
        assert_eq!(counters.snapshot().received, 1);
        assert_eq!(counters.snapshot().transport_errors, 0);
        let _ = std::fs::remove_dir_all(directory);
    }
}
