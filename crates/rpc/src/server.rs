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
//!   exhaust RSS independently of connection count — charged from the frame
//!   header's **declared** size before the payload is read or allocated
//!   (#427), so an unadmitted flood cannot force `max_payload`-sized
//!   allocations either;
//! - idle, read, and write [timeouts](ServerConfig) that evict slowloris-style
//!   stalled clients;
//! - classified `accept()` error handling (#406): transient per-connection
//!   failures and FD/buffer exhaustion never terminate the accept loop —
//!   exhaustion backs off briefly so in-flight connections can free
//!   descriptors, and only unclassified errors are fatal; and
//! - `TCP_NODELAY` on every accepted socket.
//!
//! # Observability (#416)
//! Every shed path above is countable: [`serve_with_metrics`] threads optional
//! pre-registered [`RpcMetrics`] handles through the accept loop and each
//! connection, recording read/idle timeouts, oversize frames, dispatch
//! timeouts, work-budget backpressure, accept-time rejections, and the live
//! connection count. All other entry points default to `None` — no metric is
//! touched — so instrumentation is strictly opt-in and off the happy path.
//!
//! # TLS
//! Production config ([`ServerConfig::production`]) requires TLS 1.3 via
//! rustls/tokio-rustls. Local tests may use [`TlsMode::Disabled`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use codec::{FRAME_HEADER_LEN, MAX_RPC_FRAME_PAYLOAD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::backend::{dispatch, RpcBackend};
use crate::error::RpcError;
use crate::limits::{ConnectionLimiter, RateLimit};
use crate::metrics::RpcMetrics;
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
    /// (bounds slow-body slowloris). Also bounds the TLS handshake when TLS is
    /// required, so a stalled ClientHello cannot pin connection permits.
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
    /// Maximum time [`serve_with_shutdown`] waits, after the stop signal fires
    /// (or the listener errors), for in-flight connections to observe shutdown
    /// and finish their current request. Connections still live at the deadline
    /// are aborted so shutdown is always bounded.
    pub drain_timeout: Duration,
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
            drain_timeout: Duration::from_secs(5),
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
            drain_timeout: Duration::from_secs(5),
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

/// A frame header read off the wire, before its payload (#427).
///
/// Holding one of these means exactly [`FRAME_HEADER_LEN`] bytes have been
/// consumed and the declared payload length passed the `max_payload` cap —
/// nothing of the payload has been read, and **no payload-sized buffer has
/// been allocated**. The payload is only read (via [`read_payload_timed`])
/// after the work budgets admit the declared frame size.
struct FrameHeader {
    /// The raw header bytes, kept so the full frame can be reassembled for
    /// [`decode_request`] once the payload arrives.
    raw: [u8; FRAME_HEADER_LEN],
    /// The declared payload length (already validated against `max_payload`).
    plen: usize,
}

impl FrameHeader {
    /// The header-level protocol checks [`codec::Frame::decode`] performs —
    /// magic, frame version, traffic class — surfaced at header time so a
    /// non-protocol peer is rejected before any budget is charged or payload
    /// byte buffered. Returns exactly the [`RpcError`] the full decode used to
    /// report when these checks ran after the payload was read. `msg_type` and
    /// the payload body are still validated by [`decode_request`] once the
    /// frame is assembled.
    fn validate(&self) -> Result<(), RpcError> {
        let magic = u16::from_le_bytes([self.raw[0], self.raw[1]]);
        if magic != codec::FRAME_MAGIC {
            return Err(RpcError::from(codec::CodecError::BadMagic));
        }
        let version = u16::from_le_bytes([self.raw[2], self.raw[3]]);
        if version != codec::FRAME_VERSION {
            return Err(RpcError::from(codec::CodecError::UnsupportedVersion(
                version,
            )));
        }
        if codec::TrafficClass::from_u8(self.raw[4]).is_none() {
            return Err(RpcError::from(codec::CodecError::UnknownClass(self.raw[4])));
        }
        Ok(())
    }
}

/// Phase 1 of the framed read (#427): read exactly the [`FRAME_HEADER_LEN`]
/// header bytes, bounded by `idle_timeout` (this is the between-requests wait,
/// so the idle budget applies), parse the declared payload length, and enforce
/// the `max_payload` cap **first** — an oversize declaration is rejected from
/// the header alone, before any payload-sized allocation could exist. A stall
/// yields [`ServerError::Timeout`], evicting slowloris-style clients.
async fn read_header_timed<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle_timeout: Duration,
    max_payload: usize,
) -> Result<FrameHeader, ServerError> {
    let mut raw = [0u8; FRAME_HEADER_LEN];
    match tokio::time::timeout(idle_timeout, reader.read_exact(&mut raw)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(ServerError::Io(e)),
        Err(_elapsed) => return Err(ServerError::Timeout),
    }
    // Payload length lives in the last 4 header bytes (little-endian).
    let plen = u32::from_le_bytes([raw[15], raw[16], raw[17], raw[18]]);
    let plen = usize::try_from(plen).map_err(|_| ServerError::Oversize)?;
    if plen > max_payload {
        return Err(ServerError::Oversize);
    }
    Ok(FrameHeader { raw, plen })
}

/// Phase 2 of the framed read (#427): allocate the frame buffer — legal only
/// now, after the work budgets admitted `FRAME_HEADER_LEN + plen` — and read
/// the declared payload, bounded by `read_timeout` (the header has arrived, so
/// the body budget applies). Returns the reassembled full frame bytes for
/// [`decode_request`]. A stall yields [`ServerError::Timeout`].
async fn read_payload_timed<R: AsyncRead + Unpin>(
    reader: &mut R,
    header: &FrameHeader,
    read_timeout: Duration,
) -> Result<Vec<u8>, ServerError> {
    let mut buf = vec![0u8; FRAME_HEADER_LEN + header.plen];
    buf[..FRAME_HEADER_LEN].copy_from_slice(&header.raw);
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

/// Consume and discard `plen` declared payload bytes through a small fixed
/// buffer — never a `plen`-sized allocation — bounded as a whole by
/// `read_timeout`, exactly like an admitted payload read. Used when a frame is
/// refused at header time (work-budget backpressure, header-level protocol
/// violation) so the length-prefixed session stays framed for the client's
/// next request instead of desynchronizing.
async fn discard_payload_timed<R: AsyncRead + Unpin>(
    reader: &mut R,
    plen: usize,
    read_timeout: Duration,
) -> Result<(), ServerError> {
    /// Fixed drain chunk: bounds the rejection path's memory at a constant,
    /// independent of the frame's declared (up to `max_payload`) size.
    const DISCARD_CHUNK: usize = 4096;
    let drain = async {
        let mut chunk = [0u8; DISCARD_CHUNK];
        let mut remaining = plen;
        while remaining > 0 {
            let want = remaining.min(DISCARD_CHUNK);
            let n = reader.read(&mut chunk[..want]).await?;
            if n == 0 {
                // Mirror `read_exact`: EOF mid-payload is an IO error, which
                // the caller treats as a clean peer hang-up.
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            remaining -= n;
        }
        Ok(())
    };
    match tokio::time::timeout(read_timeout, drain).await {
        Ok(Ok(())) => Ok(()),
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
/// **before** dispatch — and, since #427, before the request payload is even
/// read: budgets are charged from the frame header's declared size, so a
/// rejected request never costs the server a payload-sized buffer. A rejected
/// request gets [`RpcError::Backpressure`] and is never committed.
pub async fn handle_connection_with<S>(
    stream: S,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: &ServerConfig,
    work_budget: Option<Arc<WorkBudget>>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The sender guard lives across the await below, so the stop flag can never
    // fire for callers of the non-shutdown-aware API.
    let (_stop_tx, stop_rx) = watch::channel(false);
    handle_connection_stoppable(stream, backend, mode, config, work_budget, None, stop_rx).await
}

/// Resolves once the stop flag reads `true`.
///
/// A dropped sender also resolves: with no sender left the flag could never
/// fire again, and an un-stoppable server is exactly the failure mode this
/// signal exists to prevent. `wait_for` inspects the current value before
/// awaiting changes, so a stop signalled before this call resolves immediately.
async fn stop_requested(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// [`handle_connection_with`], plus a shutdown signal: between requests the
/// loop also watches `stop`, and once the flag fires the connection is closed
/// (clean FIN) after its current request instead of reading another. A request
/// whose frame has not yet fully arrived is abandoned — nothing has been
/// dispatched, so no committed work is lost.
///
/// When `metrics` is present, the shed paths below record onto its
/// pre-registered counters (read/idle timeout, oversize frame, dispatch
/// timeout, work-budget backpressure); `None` keeps every path metric-free —
/// the happy path never consults metrics at all, and the shed paths pay only
/// an `Option` branch.
async fn handle_connection_stoppable<S>(
    mut stream: S,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: &ServerConfig,
    work_budget: Option<Arc<WorkBudget>>,
    metrics: Option<Arc<RpcMetrics>>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let work_budget = work_budget.unwrap_or_else(|| WorkBudget::new(&config.work));
    let conn_budget = ConnBudget::new(&config.work);
    let max_payload = config.max_payload.clamp(1, codec::MAX_FRAME_PAYLOAD);

    loop {
        // Phase 1 (#427): header only. The declared payload is neither read
        // nor allocated until the work budgets admit it below.
        let read = tokio::select! {
            biased;
            // Shutdown between requests: close instead of reading another. The
            // previous request (if any) has already been fully replied to.
            _ = stop_requested(&mut stop) => return Ok(()),
            read = read_header_timed(&mut stream, config.idle_timeout, max_payload) => read,
        };
        let header = match read {
            Ok(header) => header,
            // A clean EOF/reset ends the session without a hard error.
            Err(ServerError::Io(_)) => return Ok(()),
            // A stalled-client (slowloris) eviction also ends the session
            // cleanly, but is counted: a flood of stalls surfaces as a rising
            // `rpc_read_timeouts_total` instead of silently shed connections.
            Err(ServerError::Timeout) => {
                if let Some(m) = &metrics {
                    m.record_read_timeout();
                }
                return Ok(());
            }
            Err(ServerError::Oversize) => {
                if let Some(m) = &metrics {
                    m.record_oversize();
                }
                // Size violations are not admission pressure — use the
                // dedicated error so clients can distinguish retries. The
                // oversize declaration was refused on the header alone (#427):
                // no payload byte was read, no payload buffer allocated.
                let resp = RpcResponse::new(0, Err(RpcError::MessageTooLarge));
                let out = encode_response(&resp)?;
                let _ = write_all_timed(&mut stream, &out, config.write_timeout).await;
                return Ok(());
            }
            Err(other) => return Err(other),
        };

        // Header-level protocol violations (bad magic/version/class) are
        // refused before any budget is charged or payload byte buffered. The
        // reply is the identical codec error `decode_request` reported when
        // this check ran after the full read, and it is sent at the same
        // point — after the declared bytes have arrived (drained through a
        // fixed-size buffer) — so the session stays framed and keeps serving,
        // exactly as before the #427 split.
        if let Err(err) = header.validate() {
            match discard_payload_timed(&mut stream, header.plen, config.read_timeout).await {
                Ok(()) => {}
                Err(ServerError::Io(_)) => return Ok(()),
                Err(ServerError::Timeout) => {
                    if let Some(m) = &metrics {
                        m.record_read_timeout();
                    }
                    return Ok(());
                }
                Err(other) => return Err(other),
            }
            let resp = RpcResponse::new(0, Err(err));
            let out = encode_response(&resp)?;
            write_all_timed(&mut stream, &out, config.write_timeout).await?;
            continue;
        }

        // Pre-admission (#427): charge process + connection budgets from the
        // frame's *declared* size, before any payload-sized buffer exists.
        // The permits are held for the whole dispatch; failure here means the
        // payload was never read past its header, never allocated, and the
        // command was never submitted — an over-budget flood can no longer
        // force `max_payload`-sized allocations.
        let frame_bytes = FRAME_HEADER_LEN + header.plen;
        let (proc_permit, conn_permit) = match (
            work_budget.try_acquire(frame_bytes),
            conn_budget.try_acquire(frame_bytes),
        ) {
            (Some(proc_permit), Some(conn_permit)) => (proc_permit, conn_permit),
            partial => {
                // Not admitted. Release whichever half was granted before
                // draining, so a rejected frame cannot pin budget while its
                // payload is discarded.
                drop(partial);
                if let Some(m) = &metrics {
                    m.record_backpressure();
                }
                // Signal the rejection immediately — the payload is not
                // waited for, so a client mid-upload learns to back off as
                // soon as its header is on the wire.
                let resp = RpcResponse::new(0, Err(RpcError::Backpressure));
                let out = encode_response(&resp)?;
                write_all_timed(&mut stream, &out, config.write_timeout).await?;
                // Keep the session framed for the retry: drain the declared
                // payload through a fixed-size buffer (never a `plen`-sized
                // allocation), bounded by the payload read timeout.
                match discard_payload_timed(&mut stream, header.plen, config.read_timeout).await {
                    Ok(()) => continue,
                    Err(ServerError::Io(_)) => return Ok(()),
                    Err(ServerError::Timeout) => {
                        if let Some(m) = &metrics {
                            m.record_read_timeout();
                        }
                        return Ok(());
                    }
                    Err(other) => return Err(other),
                }
            }
        };

        // Phase 2 (#427): admitted — the frame buffer may now exist. Payload
        // assembly is bounded by `read_timeout` and still races shutdown
        // (#407): a request whose frame has not fully arrived when the stop
        // fires is abandoned — nothing has been dispatched, so no committed
        // work is lost, and the permits drop with the early return.
        let read = tokio::select! {
            biased;
            _ = stop_requested(&mut stop) => return Ok(()),
            read = read_payload_timed(&mut stream, &header, config.read_timeout) => read,
        };
        let bytes = match read {
            Ok(bytes) => bytes,
            Err(ServerError::Io(_)) => return Ok(()),
            Err(ServerError::Timeout) => {
                if let Some(m) = &metrics {
                    m.record_read_timeout();
                }
                return Ok(());
            }
            Err(other) => return Err(other),
        };

        let response = match decode_request(&bytes) {
            Ok(request) => {
                let span = tracing::debug_span!(
                    "rpc.request",
                    request_id = request.request_id,
                    method = ?request.method,
                );
                let _g = span.enter();
                let request_id = request.request_id;
                let backend = Arc::clone(&backend);
                let dispatch_timeout = config.dispatch_timeout;
                // Isolate synchronous backend work off the IO worker.
                let mut join =
                    tokio::task::spawn_blocking(move || dispatch(&*backend, mode, request));
                // Poll the JoinHandle by reference: on timeout the handle
                // must survive so the still-running blocking task (which
                // cannot be aborted) can be reaped below.
                let result = match tokio::time::timeout(dispatch_timeout, &mut join).await {
                    Ok(Ok(resp)) => resp,
                    // The dispatch task died (a panic — it is never
                    // aborted). The request was decoded, so like every
                    // post-decode error reply this one echoes the
                    // request's id: a pipelining client correlates
                    // in-flight requests by `request_id`, and an
                    // uncorrelated reply would break that (#421).
                    Ok(Err(join_err)) => RpcResponse::new(
                        request_id,
                        Err(RpcError::Internal(format!("dispatch join: {join_err}"))),
                    ),
                    Err(_elapsed) => {
                        // Pre-admission succeeded but the handler outran
                        // the wait budget. We cannot cancel a committed
                        // command, and a `spawn_blocking` task cannot be
                        // aborted: it keeps running on the blocking pool.
                        // Keep the process-wide work permit charged until
                        // that orphaned task really finishes so the budget
                        // reflects in-flight work; the per-connection
                        // permit dies with this connection, which is
                        // failed closed after the reply below.
                        if let Some(m) = &metrics {
                            m.record_dispatch_timeout();
                        }
                        tokio::spawn(async move {
                            let _proc_permit = proc_permit;
                            let _ = join.await;
                        });
                        let resp = RpcResponse::new(request_id, Err(RpcError::Backpressure));
                        let out = encode_response(&resp)?;
                        let _ = write_all_timed(&mut stream, &out, config.write_timeout).await;
                        return Ok(());
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
/// the admission control in `config`. Runs until the listener fails with a
/// **fatal** error: transient per-connection accept failures and resource
/// exhaustion are absorbed by the loop instead of terminating the server (see
/// `accept_action`).
///
/// When `config.tls` is [`TlsMode::Required`], each accepted socket performs a
/// TLS 1.3 handshake before entering the RPC session. The handshake is bounded
/// by [`ServerConfig::read_timeout`] — the connection permits are held from
/// accept time, so an unbounded handshake would let clients that never send a
/// ClientHello exhaust the admission budget. When TLS is required by
/// a production config but the acceptor is missing, the function returns
/// immediately with [`ServerError::TlsRequired`].
///
/// This is [`serve_with_shutdown`] with a stop signal that never fires; use
/// that variant when the caller needs to stop accepting and drain in-flight
/// connections.
pub async fn serve_with_config(
    listener: TcpListener,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: ServerConfig,
) -> Result<(), ServerError> {
    // The sender guard lives across the await below, so the stop flag can never
    // fire for callers of the non-shutdown-aware API.
    let (_stop_tx, stop_rx) = watch::channel(false);
    serve_with_shutdown(listener, backend, mode, config, stop_rx)
        .await
        .map(|_served| ())
}

/// How the accept loop should respond to a `listener.accept()` error (#406).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptAction {
    /// Per-connection failure (e.g. the peer aborted before we accepted): the
    /// dead socket was consumed and the listener is healthy — accept the next
    /// connection immediately.
    Continue,
    /// Resource exhaustion (out of file descriptors / buffers / memory): the
    /// listener is healthy but the process cannot admit a socket *right now*.
    /// Pause briefly so in-flight connections can close and free resources,
    /// then resume accepting.
    Backoff,
    /// Anything else is unclassified and treated as fatal: terminate the
    /// server (with the bounded drain) rather than spin on a broken listener.
    Fatal,
}

/// Classify a `listener.accept()` error (#406). Without this, *any* accept
/// error — including transient `ECONNABORTED` from a peer racing its own
/// close, or `EMFILE`/`ENFILE` during exactly the FD-exhaustion flood the
/// admission control above exists to survive — would permanently terminate
/// the whole RPC server while established connections kept running detached.
///
/// Rust 1.92 has no stable [`io::ErrorKind`](std::io::ErrorKind) for FD/buffer
/// exhaustion (`EMFILE`/`ENFILE`/`ENOBUFS` decode to `Uncategorized`), so the
/// exhaustion arm matches [`std::io::Error::raw_os_error`] against the errno
/// constants instead of the kind.
pub(crate) fn accept_action(err: &std::io::Error) -> AcceptAction {
    match err.kind() {
        // The pending connection died between the kernel queuing it and us
        // accepting it (or the syscall was interrupted). Nothing is wrong
        // with the listener; the very next accept can succeed.
        std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::Interrupted => AcceptAction::Continue,
        _ => match err.raw_os_error() {
            Some(code)
                if code == libc::EMFILE
                    || code == libc::ENFILE
                    || code == libc::ENOBUFS
                    || code == libc::ENOMEM =>
            {
                AcceptAction::Backoff
            }
            _ => AcceptAction::Fatal,
        },
    }
}

/// How long the accept loop pauses after a resource-exhaustion accept failure
/// before retrying, giving in-flight connections a chance to close and free
/// file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// [`serve_with_config`], plus a shutdown path (#407): accept connections until
/// the `stop` flag fires, then drain and return how many connections were
/// admitted and served over the server's lifetime.
///
/// # Shutdown protocol
/// Send `true` on the paired [`watch::Sender`] (dropping the sender is treated
/// the same — with no sender left the flag could never fire, and an
/// un-stoppable server is the failure mode this signal exists to prevent).
/// The server then:
/// 1. breaks out of the accept loop and **drops the listener immediately**, so
///    the accept socket is closed and no new connection is admitted;
/// 2. lets in-flight connections — which each hold a clone of `stop` — observe
///    the flag and close after their current request (clean FIN);
/// 3. bounds that drain by [`ServerConfig::drain_timeout`], **aborting** any
///    connection task still live at the deadline; and
/// 4. returns the count of connections served.
///
/// Connection tasks are tracked in a [`JoinSet`] (reaped opportunistically each
/// accept so bookkeeping stays bounded over long uptimes), so — unlike a plain
/// detached spawn — they can be enumerated, joined, and on the drain deadline
/// aborted. Dropping this future likewise aborts all tracked connection tasks
/// instead of leaking them.
///
/// # Accept-error resilience (#406)
/// An accept failure does **not** blindly terminate the server. Errors are
/// classified by `accept_action`: per-connection failures
/// (`ECONNABORTED`/`ECONNRESET`/`EINTR`) are logged and skipped; resource
/// exhaustion (`EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM`) pauses accepting for
/// `ACCEPT_BACKOFF` — still racing the stop signal — so in-flight
/// connections can close and free descriptors; only unclassified errors are
/// fatal. A **fatal** listener error takes the same bounded drain path before
/// returning the error, so already-admitted connections get a chance to finish
/// their current request even on an accept failure.
pub async fn serve_with_shutdown(
    listener: TcpListener,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: ServerConfig,
    stop: watch::Receiver<bool>,
) -> Result<u64, ServerError> {
    serve_with_metrics(listener, backend, mode, config, None, stop).await
}

/// [`serve_with_shutdown`], plus observability (#416): when `metrics` is
/// present, the flood-facing shed paths record onto its pre-registered,
/// lock-free handles so brown-outs are visible instead of silent:
///
/// - `rpc_accept_rejections_total` — a connection refused at accept time by
///   the global or per-IP admission budget;
/// - `rpc_connections_active` — incremented when a connection is admitted and
///   decremented when its task ends (any exit path, including a drain-deadline
///   abort, via a drop guard);
/// - per-connection shed counters (`rpc_read_timeouts_total`,
///   `rpc_oversize_total`, `rpc_dispatch_timeouts_total`,
///   `rpc_backpressure_total`) — recorded inside the connection loop.
///
/// Build the handles once at startup with
/// [`RpcMetrics::register`]. Passing `None`
/// is exactly [`serve_with_shutdown`]: no metric is touched anywhere.
pub async fn serve_with_metrics(
    listener: TcpListener,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: ServerConfig,
    metrics: Option<Arc<RpcMetrics>>,
    mut stop: watch::Receiver<bool>,
) -> Result<u64, ServerError> {
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
    // Every spawned task — served connections and bounded rejection notices —
    // is tracked here so shutdown can join or abort all of them.
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut served: u64 = 0;

    let outcome = loop {
        // Opportunistic reap: discard entries for tasks that already finished
        // so the JoinSet's bookkeeping stays bounded over long uptimes.
        while tasks.try_join_next().is_some() {}

        let accepted = tokio::select! {
            biased;
            _ = stop_requested(&mut stop) => break Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            // Classified accept-error handling (#406): only unclassified
            // errors terminate the server; transient and exhaustion errors
            // keep the accept loop alive.
            Err(err) => match accept_action(&err) {
                AcceptAction::Continue => {
                    tracing::debug!(error = %err, "transient accept error; continuing");
                    continue;
                }
                AcceptAction::Backoff => {
                    tracing::warn!(
                        error = %err,
                        "accept failed on resource exhaustion; backing off"
                    );
                    // Race the pause against shutdown so a stop signalled
                    // mid-backoff is still honored promptly.
                    tokio::select! {
                        biased;
                        _ = stop_requested(&mut stop) => break Ok(()),
                        () = tokio::time::sleep(ACCEPT_BACKOFF) => {}
                    }
                    continue;
                }
                AcceptAction::Fatal => break Err(ServerError::Io(err)),
            },
        };
        // Disable Nagle's algorithm so small framed replies are not delayed.
        let _ = stream.set_nodelay(true);

        // Global concurrency budget: bounds total live connections / sockets.
        let global_permit = match Arc::clone(&global).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                if let Some(m) = &metrics {
                    m.record_accept_rejection();
                }
                tasks.spawn(send_rejection(stream, write_timeout));
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
                if let Some(m) = &metrics {
                    m.record_accept_rejection();
                }
                tasks.spawn(send_rejection(stream, write_timeout));
                continue;
            }
        };

        served = served.saturating_add(1);
        let backend = Arc::clone(&backend);
        let config = Arc::clone(&config);
        let work_budget = Arc::clone(&work_budget);
        let tls = tls.clone();
        let conn_stop = stop.clone();
        let conn_metrics = metrics.clone();
        // Admitted: charge the active-connections gauge now, restore it when
        // the connection task ends (its drop guard runs on every exit path,
        // including a drain-deadline abort).
        let active = metrics.as_ref().map(|m| m.track_connection());
        tasks.spawn(async move {
            // Declared first so it drops last: the gauge must not read zero
            // while the admission permits below are still held.
            let _active = active;
            // The permits live for the connection's lifetime and are released on
            // task exit, freeing the global and per-IP slots.
            let _global_permit = global_permit;
            let _ip_permit = ip_permit;
            match tls {
                TlsMode::Disabled => {
                    let _ = handle_connection_stoppable(
                        stream,
                        backend,
                        mode,
                        &config,
                        Some(work_budget),
                        conn_metrics,
                        conn_stop,
                    )
                    .await;
                }
                TlsMode::Required(acceptor) => {
                    // Bound the handshake by `read_timeout`: the permits above are
                    // already held, so a client that completes the TCP handshake
                    // but never sends (or trickles) its ClientHello would otherwise
                    // pin a global and a per-IP slot forever — permit-exhaustion
                    // DoS. Dropping the timed-out accept future drops the stream
                    // (clean close) and the task exits, releasing both permits.
                    match tokio::time::timeout(config.read_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(tls_stream)) => {
                            let _ = handle_connection_stoppable(
                                tls_stream,
                                backend,
                                mode,
                                &config,
                                Some(work_budget),
                                conn_metrics,
                                conn_stop,
                            )
                            .await;
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(error = %e, "tls handshake failed");
                        }
                        Err(_elapsed) => {
                            tracing::debug!(peer = %peer, "tls handshake timed out");
                        }
                    }
                }
            }
        });
    };

    // Stop accepting immediately: dropping the listener closes the accept
    // socket, so no new connection can be admitted from here on.
    drop(listener);

    // Bounded drain: in-flight connections hold a `stop` clone and close after
    // their current request; anything still live at the deadline is aborted.
    let drained = tokio::time::timeout(config.drain_timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tasks.abort_all();
        // Reap the aborted tasks; each next join resolves promptly with a
        // cancelled `JoinError`, so this loop is bounded.
        while tasks.join_next().await.is_some() {}
    }

    outcome.map(|()| served)
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
