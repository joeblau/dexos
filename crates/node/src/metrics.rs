//! Optional Prometheus scrape server for a live [`MetricsRegistry`].
//!
//! Bound only when `[observability].metrics_listen` is non-empty. Serves:
//! - `GET /metrics` — Prometheus text exposition 0.0.4
//! - `GET /livez` / `GET /healthz` — process liveness
//! - `GET /readyz` — readiness (false until bootstrap; false on critical exit)
//!
//! Implemented with raw Tokio TCP + a minimal HTTP/1.0 response so the node
//! does not pull an HTTP framework into the composition root.
//!
//! # Hardening
//!
//! The listener is exposed to arbitrary peers, so the accept loop is defensive:
//! persistent `accept` failures (e.g. fd exhaustion) back off instead of
//! hot-spinning a runtime worker, every connection runs under a single deadline
//! covering both the read and the write, and total in-flight connections are
//! capped by a semaphore — excess connections are shed, never queued.

use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use observability::{MetricsRegistry, PROMETHEUS_CONTENT_TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::error::NodeError;
use crate::readiness::Readiness;

/// Upper bound on concurrently served scrape connections.
///
/// Prometheus scrapes each target on one connection at a time, so even several
/// scrapers plus liveness/readiness probes need only a handful; 64 leaves an
/// order-of-magnitude headroom while keeping worst-case task and fd usage
/// bounded. When every permit is taken the new connection is dropped
/// (fail-closed shed) rather than queued, so a flood of slow clients cannot
/// spawn unbounded tasks.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Budget for one whole connection: reading the request *and* writing the
/// response. A peer that connects but never sends — or that never reads,
/// stalling our write against a full send buffer — is dropped when this
/// elapses instead of pinning a task (and its fd) forever.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);

/// Pause after a non-transient `accept` failure (e.g. `EMFILE`/`ENFILE`
/// during fd exhaustion). `accept` returns such errors immediately, so
/// retrying without yielding spins a worker at 100% CPU; the sleep both
/// yields and gives the process a chance to release descriptors.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Spawn a background scrape server when `listen` is a non-empty socket addr.
/// Returns `None` when metrics are disabled.
pub async fn spawn_if_configured(
    listen: &str,
    registry: Arc<MetricsRegistry>,
    readiness: Arc<Readiness>,
) -> Result<Option<JoinHandle<()>>, NodeError> {
    let listen = listen.trim();
    if listen.is_empty() {
        return Ok(None);
    }
    let addr: std::net::SocketAddr = listen.parse().map_err(|e| {
        NodeError::Config(crate::config::ConfigError::Validation(format!(
            "observability.metrics_listen is not a valid socket address ({listen}): {e}"
        )))
    })?;
    let listener = TcpListener::bind(addr).await.map_err(NodeError::Runtime)?;
    tracing::info!(
        target: "node",
        %addr,
        "prometheus scrape endpoint listening (/metrics, /livez, /readyz)"
    );
    Ok(Some(tokio::spawn(serve(listener, registry, readiness))))
}

/// Accept loop with bounded concurrency, a per-connection deadline, and
/// backoff on persistent accept errors. Runs until the task is aborted.
async fn serve(listener: TcpListener, registry: Arc<MetricsRegistry>, readiness: Arc<Readiness>) {
    // Hoisted out of the loop: registering a counter takes the registry
    // mutex, and the handle itself is a lock-free atomic on the error path.
    let accept_errors = registry.counter("metrics_accept_errors_total");
    let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            // Transient per-connection races (the peer vanished between the
            // kernel queueing the connection and us accepting it): retry now.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            // Persistent failures (EMFILE/ENFILE, ...): count, log, and back
            // off so the loop cannot hot-spin a runtime worker while the
            // process is out of descriptors.
            Err(e) => {
                accept_errors.inc();
                tracing::warn!(
                    target: "node",
                    error = %e,
                    "metrics listener accept failed; backing off"
                );
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        // Fail-closed shed: when every permit is in use, drop the connection
        // instead of waiting for one, so slow clients bound total tasks.
        let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let reg = Arc::clone(&registry);
        let ready = Arc::clone(&readiness);
        tokio::spawn(async move {
            // Permit is held for the whole task lifetime; dropped on exit.
            let _permit = permit;
            // The deadline covers the request read AND the response write:
            // a peer that never reads stalls `write_all` exactly like a peer
            // that never sends stalls `read`. On timeout the future — and
            // with it the socket — is dropped, closing the connection.
            let _ =
                tokio::time::timeout(CONNECTION_TIMEOUT, handle_connection(stream, &reg, &ready))
                    .await;
        });
    }
}

/// Serve exactly one HTTP/1.0 exchange on `stream`. Callers bound the whole
/// exchange with [`CONNECTION_TIMEOUT`].
async fn handle_connection(mut stream: TcpStream, reg: &MetricsRegistry, ready: &Readiness) {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let path = req.lines().next().unwrap_or("");
    let (status, content_type, body) = route_request(path, reg, ready);
    let resp = format!(
        "HTTP/1.0 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Route a single HTTP request line to a status/body triple.
fn route_request(
    path: &str,
    reg: &MetricsRegistry,
    readiness: &Readiness,
) -> (&'static str, &'static str, String) {
    if path.starts_with("GET /metrics") {
        ("200 OK", PROMETHEUS_CONTENT_TYPE, reg.export_text())
    } else if path.starts_with("GET /livez") || path.starts_with("GET /healthz") {
        if readiness.is_live() {
            ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string())
        } else {
            (
                "503 Service Unavailable",
                "text/plain; charset=utf-8",
                "not live\n".to_string(),
            )
        }
    } else if path.starts_with("GET /readyz") {
        if readiness.is_ready() {
            ("200 OK", "text/plain; charset=utf-8", "ready\n".to_string())
        } else {
            let reason = readiness.reason();
            (
                "503 Service Unavailable",
                "text/plain; charset=utf-8",
                format!("not ready: {reason}\n"),
            )
        }
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Bind the real accept loop on an ephemeral port and return its address.
    async fn spawn_server(
        reg: Arc<MetricsRegistry>,
        readiness: Arc<Readiness>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, reg, readiness));
        addr
    }

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out).into_owned();
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, text)
    }

    #[tokio::test]
    async fn metrics_livez_readyz_endpoints() {
        let reg = Arc::new(MetricsRegistry::new());
        reg.counter("demo_total").add(3);
        let readiness = Readiness::new();
        let addr = spawn_server(Arc::clone(&reg), Arc::clone(&readiness)).await;

        // Not ready until bootstrap.
        let (code, body) = http_get(addr, "/readyz").await;
        assert_eq!(code, 503, "{body}");
        assert!(body.contains("not ready"), "{body}");

        let (code, body) = http_get(addr, "/livez").await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("ok"));

        let (code, body) = http_get(addr, "/metrics").await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("demo_total 3"), "{body}");

        readiness.mark_ready();
        let (code, body) = http_get(addr, "/readyz").await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("ready"));

        readiness.mark_not_ready("handler crashed");
        let (code, body) = http_get(addr, "/readyz").await;
        assert_eq!(code, 503, "{body}");
        assert!(body.contains("handler crashed"), "{body}");
    }

    #[tokio::test]
    async fn stalled_client_is_dropped_and_server_stays_responsive() {
        let reg = Arc::new(MetricsRegistry::new());
        reg.counter("demo_total").inc();
        let readiness = Readiness::new();
        let addr = spawn_server(Arc::clone(&reg), Arc::clone(&readiness)).await;

        // Connect but never send a byte: the server must close the connection
        // once CONNECTION_TIMEOUT elapses instead of parking a task forever.
        let mut stalled = TcpStream::connect(addr).await.unwrap();
        let mut sink = Vec::new();
        let closed = tokio::time::timeout(
            CONNECTION_TIMEOUT + Duration::from_secs(3),
            stalled.read_to_end(&mut sink),
        )
        .await;
        let n = closed
            .expect("server did not drop a silent client within the deadline")
            .unwrap_or(0);
        assert_eq!(n, 0, "silent client should receive no response bytes");

        // The stalled client must not have wedged the accept loop.
        let (code, body) = http_get(addr, "/metrics").await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("demo_total 1"), "{body}");
    }

    #[tokio::test]
    async fn empty_listen_disables_server() {
        let reg = Arc::new(MetricsRegistry::new());
        let readiness = Readiness::new();
        assert!(spawn_if_configured("", reg, readiness)
            .await
            .unwrap()
            .is_none());
    }
}
