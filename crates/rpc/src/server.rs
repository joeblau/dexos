//! Async length-prefixed framed RPC server over a Tokio TCP listener.
//!
//! Each connection is a sequential request/response loop: read one framed
//! [`RpcRequest`], [`dispatch`] it against the backend (enforcing read-only /
//! light mode), and write the framed [`RpcResponse`]. Decode failures produce an
//! error response rather than tearing down the connection.
//!
//! # Admission control (DoS hardening)
//! The accept loop enforces a layered connection budget so a flood of cheap
//! connections cannot exhaust file descriptors or task memory:
//! - a process-wide concurrent-connection ceiling ([`ServerConfig::max_connections`])
//!   backed by a [`Semaphore`];
//! - a per-source-IP concurrent-connection cap and token-bucket connection rate
//!   limit ([`crate::limits::ConnectionLimiter`]);
//! - idle, read, and write [timeouts](ServerConfig) that evict slowloris-style
//!   stalled clients; and
//! - `TCP_NODELAY` on every accepted socket.
//!
//! Connections that exceed the budget are rejected cleanly: the server sends a
//! single [`RpcError::Backpressure`] response and closes, rather than resetting
//! abruptly or (worse) queueing work without bound.

use std::sync::Arc;
use std::time::{Duration, Instant};

use codec::{FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::backend::{dispatch, RpcBackend};
use crate::error::RpcError;
use crate::limits::{ConnectionLimiter, RateLimit};
use crate::response::RpcResponse;
use crate::transport::{decode_request, encode_response};
use crate::wire::RpcMode;

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
}

/// Tunable limits and timeouts for the RPC server's accept loop and per
/// connection I/O. Construct via [`ServerConfig::default`] and override fields.
///
/// The default connection budget is: at most `max_connections` concurrent
/// connections process-wide, `max_connections_per_ip` from any single source IP,
/// and no more than `per_ip_rate` new connections per second per IP. A
/// connection that produces no complete request within `idle_timeout`, stalls
/// mid-frame beyond `read_timeout`, or stops reading its response for
/// `write_timeout` is closed.
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
        }
    }
}

/// Read one whole framed message (header + declared payload) from `reader`,
/// returning the full frame bytes. Bounds the payload by [`MAX_FRAME_PAYLOAD`].
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, ServerError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    // Payload length lives in the last 4 header bytes (little-endian).
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]);
    let plen = usize::try_from(plen).map_err(|_| ServerError::Oversize)?;
    if plen > MAX_FRAME_PAYLOAD {
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
) -> Result<Vec<u8>, ServerError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    match tokio::time::timeout(idle_timeout, reader.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(ServerError::Io(e)),
        Err(_elapsed) => return Err(ServerError::Timeout),
    }
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]);
    let plen = usize::try_from(plen).map_err(|_| ServerError::Oversize)?;
    if plen > MAX_FRAME_PAYLOAD {
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
    handle_connection_with(stream, backend, mode, &ServerConfig::default()).await
}

/// Serve one connection to completion: loop reading requests and writing
/// responses until the peer closes, stalls past a timeout, or an unrecoverable
/// transport error occurs. Idle/read/write timeouts come from `config`.
pub async fn handle_connection_with<S>(
    mut stream: S,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: &ServerConfig,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let bytes =
            match read_frame_timed(&mut stream, config.idle_timeout, config.read_timeout).await {
                Ok(bytes) => bytes,
                // A clean EOF/reset or a stalled-client timeout ends the session
                // without a hard error.
                Err(ServerError::Io(_)) | Err(ServerError::Timeout) => return Ok(()),
                Err(ServerError::Oversize) => {
                    let resp = RpcResponse::new(0, Err(RpcError::Backpressure));
                    let out = encode_response(&resp)?;
                    let _ = write_all_timed(&mut stream, &out, config.write_timeout).await;
                    return Ok(());
                }
                Err(other) => return Err(other),
            };
        let response = match decode_request(&bytes) {
            Ok(request) => dispatch(&*backend, mode, request),
            Err(err) => RpcResponse::new(0, Err(err)),
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
    serve_with_config(listener, backend, mode, ServerConfig::default()).await
}

/// Accept connections on `listener` and serve each on its own task, enforcing
/// the admission control in `config`. Runs until the listener errors.
///
/// Connections are admitted against a global [`Semaphore`] (the process-wide
/// concurrency budget) and a per-IP [`ConnectionLimiter`]. A permit and per-IP
/// slot are held for the connection's whole lifetime, so the number of live
/// server tasks — and thus open sockets — can never exceed
/// `config.max_connections`. Excess connections receive a single
/// [`RpcError::Backpressure`] reply and are closed. A per-connection failure is
/// isolated and does not stop the accept loop.
pub async fn serve_with_config(
    listener: TcpListener,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
    config: ServerConfig,
) -> std::io::Result<()> {
    let config = Arc::new(config);
    let global = Arc::new(Semaphore::new(config.max_connections));
    let limiter = Arc::new(ConnectionLimiter::new(
        config.max_connections_per_ip,
        config.per_ip_rate,
        config.max_tracked_ips,
    ));
    let write_timeout = config.write_timeout;

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
        tokio::spawn(async move {
            // The permits live for the connection's lifetime and are released on
            // task exit, freeing the global and per-IP slots.
            let _global_permit = global_permit;
            let _ip_permit = ip_permit;
            let _ = handle_connection_with(stream, backend, mode, &config).await;
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
    let bytes = read_frame(&mut stream).await?;
    let resp = crate::transport::decode_response(&bytes)?;
    Ok(resp)
}
