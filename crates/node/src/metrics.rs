//! Optional Prometheus scrape server for a live [`MetricsRegistry`].
//!
//! Bound only when `[observability].metrics_listen` is non-empty. Serves:
//! - `GET /metrics` — Prometheus text exposition 0.0.4
//! - `GET /livez` / `GET /healthz` — process liveness
//! - `GET /readyz` — readiness (false until bootstrap; false on critical exit)
//!
//! Implemented with raw Tokio TCP + a minimal HTTP/1.0 response so the node
//! does not pull an HTTP framework into the composition root.

use std::sync::Arc;

use observability::{MetricsRegistry, PROMETHEUS_CONTENT_TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::error::NodeError;
use crate::readiness::Readiness;

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
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let reg = Arc::clone(&registry);
            let ready = Arc::clone(&readiness);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let path = req.lines().next().unwrap_or("");
                let (status, content_type, body) = route_request(path, &reg, &ready);
                let resp = format!(
                    "HTTP/1.0 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(Some(handle))
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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let reg2 = Arc::clone(&reg);
        let ready2 = Arc::clone(&readiness);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let reg = Arc::clone(&reg2);
                let ready = Arc::clone(&ready2);
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                    let path = req.lines().next().unwrap_or("");
                    let (status, ct, body) = route_request(path, &reg, &ready);
                    let resp = format!(
                        "HTTP/1.0 {status}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

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
    async fn empty_listen_disables_server() {
        let reg = Arc::new(MetricsRegistry::new());
        let readiness = Readiness::new();
        assert!(spawn_if_configured("", reg, readiness)
            .await
            .unwrap()
            .is_none());
    }
}
