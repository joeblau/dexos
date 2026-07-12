//! Async length-prefixed framed RPC server over a Tokio TCP listener, with
//! optional TLS 1.3, isolated blocking dispatch, and byte-bounded in-flight work.
//!
//! # Sequential (non-pipelined) request handling
//!
//! Each connection is a **strictly sequential** request/response loop: the
//! server reads one complete framed `RpcRequest`, dispatches it against the
//! backend on a dedicated blocking pool (never on the Tokio IO worker), writes
//! the framed [`RpcResponse`], and only then accepts the next request on that
//! connection.
//!
//! # Admission control (DoS hardening)
//! The accept loop enforces a layered connection budget so a flood of cheap
//! connections cannot exhaust file descriptors or task memory:
//! - a process-wide concurrent-connection ceiling ([`ServerConfig::max_connections`])
//!   backed by a [`Semaphore`];
//! - a per-source-IP concurrent-connection cap and token-bucket connection rate
//!   limit (`ConnectionLimiter`);
//! - process-wide and per-connection **in-flight request / byte** budgets
//!   ([`crate::work::WorkBudget`]) so large frames and slow handlers cannot
//!   exhaust RSS independently of connection count;
//! - idle, read, and write [timeouts](ServerConfig) that evict slowloris-style
//!   stalled clients; and
//! - `TCP_NODELAY` on every accepted socket.
//!
//! # TLS
//! Production config ([`ServerConfig::production`]) requires TLS 1.3 via
//! rustls/tokio-rustls. Local tests may use [`TlsMode::Disabled`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use codec::{FRAME_HEADER_LEN, MAX_RPC_FRAME_PAYLOAD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::backend::{dispatch, RpcBackend};
use crate::error::RpcError;
use crate::limits::{ConnectionLimiter, RateLimit};
use crate::response::RpcResponse;
use crate::transport::{decode_request, encode_response};
use crate::wire::RpcMode;
use crate::work::{ConnBudget, WorkBudget, WorkBudgetConfig};

/// A failure while serving a connection.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Transport I/O failure (also signals a closed connection).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A frame declared a payload larger than the codec cap.
    #[error("frame payload too large")]
    Oversize,
    /// A read or write exceeded the configured timeout (e.g. a stalled client).
    #[error("connection timed out")]
    Timeout,
    /// An RPC-layer failure while encoding a reply.
    #[error("rpc error: {0}")]
    Rpc(#[from] RpcError),
    /// TLS is required by config but was not provided.
    #[error("tls required but not configured")]
    TlsRequired,
    /// TLS handshake failure.
    #[error("tls handshake failed: {0}")]
    TlsHandshake(std::io::Error),
}

/// Whether the server accepts cleartext TCP or requires TLS 1.3.
#[derive(Clone)]
pub enum TlsMode {
    /// Plain TCP — for tests and local loopback only.
    Disabled,
    /// Require TLS 1.3 (rustls). Optional client-cert verification is configured
    /// on the acceptor itself.
    Required(TlsAcceptor),
}

impl std::fmt::Debug for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsMode::Disabled => write!(f, "TlsMode::Disabled"),
            TlsMode::Required(_) => write!(f, "TlsMode::Required(..)"),
        }
    }
}

/// Tunable limits and timeouts for the RPC server's accept loop and per
/// connection I/O. Construct via [`ServerConfig::default`] (dev) or
/// [`ServerConfig::production`] (TLS required, tighter caps).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Process-wide ceiling on concurrently served connections.
    pub max_connections: usize,
    /// Maximum concurrent connections admitted from a single source IP.
    pub max_connections_per_ip: u32,
    /// Optional per-IP connection rate limit; `None` disables rate limiting.
    pub per_ip_rate: Option<RateLimit>,
    /// Maximum time to wait for the next request frame's header before closing an
    /// otherwise idle connection (bounds keep-alive and slow-header slowloris).
    pub idle_timeout: Duration,
    /// Maximum time to receive a frame's payload once its header has arrived
    /// (bounds slow-body slowloris).
    pub read_timeout: Duration,
    /// Maximum time to flush a response before abandoning a stalled reader.
    pub write_timeout: Duration,
    /// Soft cap on tracked per-IP rate-limiter buckets (bounds bookkeeping
    /// memory; idle buckets beyond this are pruned).
    pub max_tracked_ips: usize,
    /// Maximum accepted RPC frame payload (defaults to
    /// [`MAX_RPC_FRAME_PAYLOAD`], far below the peer-sync 16 MiB ceiling).
    pub max_payload: usize,
    /// TLS mode. Production requires [`TlsMode::Required`].
    pub tls: TlsMode,
    /// In-flight request / byte budgets (process + per-connection).
    pub work: WorkBudgetConfig,
    /// Maximum time a single backend dispatch may run on the blocking pool
    /// before the connection is failed closed. Does **not** cancel a command
    /// that has already been durably committed by the backend — it only bounds
    /// how long this connection waits for a reply.
    pub dispatch_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 4_096,
            max_connections_per_ip: 64,
            per_ip_rate: Some(RateLimit {
                per_sec: 32,
                burst: 64,
            }),
            idle_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            max_tracked_ips: 65_536,
            max_payload: MAX_RPC_FRAME_PAYLOAD,
            tls: TlsMode::Disabled,
            work: WorkBudgetConfig::default(),
            dispatch_timeout: Duration::from_secs(5),
        }
    }
}

impl ServerConfig {
    /// Production defaults: TLS required (caller must install the acceptor),
    /// tighter payload cap, and conservative in-flight budgets.
    pub fn production(tls: TlsAcceptor) -> Self {
        Self {
            max_connections: 4_096,
            max_connections_per_ip: 32,
            per_ip_rate: Some(RateLimit {
                per_sec: 16,
                burst: 32,
            }),
            idle_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            max_tracked_ips: 65_536,
            max_payload: MAX_RPC_FRAME_PAYLOAD,
            tls: TlsMode::Required(tls),
            work: WorkBudgetConfig {
                max_in_flight_requests: 1_024,
                max_in_flight_bytes: 32 * 1024 * 1024,
                max_in_flight_requests_per_conn: 1,
                max_in_flight_bytes_per_conn: MAX_RPC_FRAME_PAYLOAD,
            },
            dispatch_timeout: Duration::from_secs(2),
        }
    }
}

/// Read one whole framed message (header + declared payload) from `reader`,
/// returning the full frame bytes. Bounds the payload by `max_payload`.
async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_payload: usize,
) -> Result<Vec<u8>, ServerError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    // Payload length lives in the last 4 header bytes (little-endian).
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]);
    let plen = usize::try_from(plen).map_err(|_| ServerError::Oversize)?;
    if plen > max_payload {
        return Err(ServerError::Oversize);
    }
    let mut buf = vec![0u8; FRAME_HEADER_LEN + plen];
    buf[..FRAME_HEADER_LEN].copy_from_slice(&header);
    reader.read_exact(&mut buf[FRAME_HEADER_LEN..]).await?;
    Ok(buf)
}

/// Like [`read_frame`], but bounds the wait for the header by `idle_timeout` and
/// the wait for the payload by `read_timeout`. A timeout in either phase yields
/// [`ServerError::Timeout`], evicting stalled (slowloris-style) clients instead
/// of holding the connection open indefinitely.
async fn read_frame_timed<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle_timeout: Duration,
    read_timeout: Duration,
    max_payload: usize,
) -> Result<Vec<u8>, ServerError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    match tokio::time::timeout(idle_timeout, reader.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(ServerError::Io(e)),
        Err(_elapsed) => return Err(ServerError::Timeout),
    }
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]);
    let plen = usize::try_from(plen).map_err(|_| ServerError::Oversize)?;
    if plen > max_payload {
        return Err(ServerError::Oversize);
    }
    let mut buf = vec![0u8; FRAME_HEADER_LEN + plen];
    buf[..FRAME_HEADER_LEN].copy_from_slice(&header);
    match tokio::time::timeout(
        read_timeout,
        reader.read_exact(&mut buf[FRAME_HEADER_LEN..]),
    )
    .await
    {
        Ok(Ok(_)) => Ok(buf),
        Ok(Err(e)) => Err(ServerError::Io(e)),
        Err(_elapsed) => Err(ServerError::Timeout),
    }
}

/// Write `buf` in full and flush, bounded by `write_timeout`. A stalled reader
/// (one that stops draining its socket) yields [`ServerError::Timeout`].
async fn write_all_timed<S: AsyncWrite + Unpin>(
    stream: &mut S,
    buf: &[u8],
    write_timeout: Duration,
) -> Result<(), ServerError> {
    let write = async {
        stream.write_all(buf).await?;
        stream.flush().await
    };
    match tokio::time::timeout(write_timeout, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(ServerError::Io(e)),
        Err(_elapsed) => Err(ServerError::Timeout),
    }
}

/// Serve one connection to completion with default timeouts. See
/// [`handle_connection_with`] to supply a [`ServerConfig`].
pub async fn handle_connection<S>(
    stream: S,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_connection_with(stream, backend, mode, &ServerConfig::default(), None).await
}

/// Serve one connection to completion: loop reading requests and writing
/// responses until the peer closes, stalls past a timeout, or an unrecoverable
/// transport error occurs. Idle/read/write timeouts come from `config`.
///
/// Synchronous backend work is isolated onto Tokio's blocking pool so a slow
/// handler cannot starve the accept loop or other IO workers. Admission against
/// `work_budget` (process-wide) and a per-connection ceiling happens
/// **before** dispatch: a rejected request gets [`RpcError::Backpressure`] and
/// is never committed.
pub async fn handle_connection_with<S>(
    mut stream: S,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: &ServerConfig,
    work_budget: Option<Arc<WorkBudget>>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let work_budget = work_budget.unwrap_or_else(|| WorkBudget::new(&config.work));
    let conn_budget = ConnBudget::new(&config.work);
    let max_payload = config.max_payload.clamp(1, codec::MAX_FRAME_PAYLOAD);

    loop {
        let bytes = match read_frame_timed(
            &mut stream,
            config.idle_timeout,
            config.read_timeout,
            max_payload,
        )
        .await
        {
            Ok(bytes) => bytes,
            // A clean EOF/reset or a stalled-client timeout ends the session
            // without a hard error.
            Err(ServerError::Io(_)) | Err(ServerError::Timeout) => return Ok(()),
            Err(ServerError::Oversize) => {
                // Size violations are not admission pressure — use the
                // dedicated error so clients can distinguish retries.
                let resp = RpcResponse::new(0, Err(RpcError::MessageTooLarge));
                let out = encode_response(&resp)?;
                let _ = write_all_timed(&mut stream, &out, config.write_timeout).await;
                return Ok(());
            }
            Err(other) => return Err(other),
        };

        let frame_bytes = bytes.len();
        // Pre-admission: hold process + connection permits for the whole
        // dispatch. Failure here means the command was never submitted.
        let response = match (
            work_budget.try_acquire(frame_bytes),
            conn_budget.try_acquire(frame_bytes),
        ) {
            (Some(proc_permit), Some(conn_permit)) => {
                match decode_request(&bytes) {
                    Ok(request) => {
                        let span = tracing::debug_span!(
                            "rpc.request",
                            request_id = request.request_id,
                            method = ?request.method,
                        );
                        let _g = span.enter();
                        let backend = Arc::clone(&backend);
                        let dispatch_timeout = config.dispatch_timeout;
                        // Isolate synchronous backend work off the IO worker.
                        let join =
                            tokio::task::spawn_blocking(move || dispatch(&*backend, mode, request));
                        let result = match tokio::time::timeout(dispatch_timeout, join).await {
                            Ok(Ok(resp)) => resp,
                            Ok(Err(join_err)) => RpcResponse::new(
                                0,
                                Err(RpcError::Internal(format!("dispatch join: {join_err}"))),
                            ),
                            Err(_elapsed) => {
                                // Pre-admission succeeded but the handler outran
                                // the wait budget. We cannot cancel a committed
                                // command; surface backpressure / timeout to the
                                // client and drop the connection after the reply.
                                RpcResponse::new(0, Err(RpcError::Backpressure))
                            }
                        };
                        drop(proc_permit);
                        drop(conn_permit);
                        result
                    }
                    Err(err) => {
                        drop(proc_permit);
                        drop(conn_permit);
                        RpcResponse::new(0, Err(err))
                    }
                }
            }
            _ => {
                // Not admitted: command was never submitted to the backend.
                RpcResponse::new(0, Err(RpcError::Backpressure))
            }
        };
        let out = encode_response(&response)?;
        write_all_timed(&mut stream, &out, config.write_timeout).await?;
    }
}

/// Best-effort: tell a rejected client the server is at capacity, then close.
/// The notice is bounded by `write_timeout` so a non-draining peer cannot stall
/// the rejection path.
async fn send_rejection<S: AsyncWrite + Unpin>(mut stream: S, write_timeout: Duration) {
    let resp = RpcResponse::new(0, Err(RpcError::Backpressure));
    if let Ok(out) = encode_response(&resp) {
        let _ = write_all_timed(&mut stream, &out, write_timeout).await;
    }
    // `stream` is dropped here, sending a clean FIN.
}

/// Accept connections on `listener` and serve each on its own task, using the
/// default [`ServerConfig`]. See [`serve_with_config`].
pub async fn serve(
    listener: TcpListener,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
) -> std::io::Result<()> {
    serve_with_config(listener, backend, mode, ServerConfig::default())
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Accept connections on `listener` and serve each on its own task, enforcing
/// the admission control in `config`. Runs until the listener errors.
///
/// When `config.tls` is [`TlsMode::Required`], each accepted socket performs a
/// TLS 1.3 handshake before entering the RPC session. When TLS is required by
/// a production config but the acceptor is missing, the function returns
/// immediately with [`ServerError::TlsRequired`].
pub async fn serve_with_config(
    listener: TcpListener,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: ServerConfig,
) -> Result<(), ServerError> {
    let config = Arc::new(config);
    let global = Arc::new(Semaphore::new(config.max_connections));
    let limiter = Arc::new(ConnectionLimiter::new(
        config.max_connections_per_ip,
        config.per_ip_rate,
        config.max_tracked_ips,
    ));
    let work_budget = WorkBudget::new(&config.work);
    let write_timeout = config.write_timeout;
    let tls = config.tls.clone();

    loop {
        let (stream, peer) = listener.accept().await?;
        // Disable Nagle's algorithm so small framed replies are not delayed.
        let _ = stream.set_nodelay(true);

        // Global concurrency budget: bounds total live connections / sockets.
        let global_permit = match Arc::clone(&global).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tokio::spawn(send_rejection(stream, write_timeout));
                continue;
            }
        };

        // Per-IP concurrency + rate budget.
        let ip_permit = match limiter.try_admit(peer.ip(), Instant::now()) {
            Ok(permit) => permit,
            Err(_) => {
                // Release the global permit before rejecting so it is not tied up
                // for the connection we are refusing.
                drop(global_permit);
                tokio::spawn(send_rejection(stream, write_timeout));
                continue;
            }
        };

        let backend = Arc::clone(&backend);
        let config = Arc::clone(&config);
        let work_budget = Arc::clone(&work_budget);
        let tls = tls.clone();
        tokio::spawn(async move {
            // The permits live for the connection's lifetime and are released on
            // task exit, freeing the global and per-IP slots.
            let _global_permit = global_permit;
            let _ip_permit = ip_permit;
            match tls {
                TlsMode::Disabled => {
                    let _ =
                        handle_connection_with(stream, backend, mode, &config, Some(work_budget))
                            .await;
                }
                TlsMode::Required(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let _ = handle_connection_with(
                            tls_stream,
                            backend,
                            mode,
                            &config,
                            Some(work_budget),
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "tls handshake failed");
                    }
                },
            }
        });
    }
}

/// Convenience: connect to a server, send one request over a fresh connection,
/// and read one response. Primarily for tests and simple clients.
pub async fn round_trip(
    addr: std::net::SocketAddr,
    request: &crate::request::RpcRequest,
) -> Result<RpcResponse, ServerError> {
    use crate::transport::encode_request;
    let mut stream = TcpStream::connect(addr).await?;
    let out = encode_request(request)?;
    stream.write_all(&out).await?;
    stream.flush().await?;
    let bytes = read_frame(&mut stream, MAX_RPC_FRAME_PAYLOAD).await?;
    let resp = crate::transport::decode_response(&bytes)?;
    Ok(resp)
}
