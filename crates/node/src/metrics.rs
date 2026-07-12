//! Optional Prometheus scrape server for a live [`MetricsRegistry`].
//!
//! Bound only when `[observability].metrics_listen` is non-empty. Serves:
//! - `GET /metrics` — Prometheus text exposition 0.0.4
//! - `GET /livez` — process liveness (`ok`)
//!
//! Implemented with raw Tokio TCP + a minimal HTTP/1.0 response so the node
//! does not pull an HTTP framework into the composition root.

use std::sync::Arc;

use observability::{MetricsRegistry, PROMETHEUS_CONTENT_TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::error::NodeError;

/// Spawn a background scrape server when `listen` is a non-empty socket addr.
/// Returns `None` when metrics are disabled.
pub async fn spawn_if_configured(
    listen: &str,
    registry: Arc<MetricsRegistry>,
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
    let listener = TcpListener::bind(addr)
        .await
        .map_err(NodeError::Runtime)?;
    tracing::info!(
        target: "node",
        %addr,
        "prometheus scrape endpoint listening (/metrics, /livez)"
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let reg = Arc::clone(&registry);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let path = req.lines().next().unwrap_or("");
                let (status, content_type, body) = if path.starts_with("GET /metrics") {
                    (
                        "200 OK",
                        PROMETHEUS_CONTENT_TYPE,
                        reg.export_text(),
                    )
                } else if path.starts_with("GET /livez") || path.starts_with("GET /healthz") {
                    ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string())
                } else {
                    (
                        "404 Not Found",
                        "text/plain; charset=utf-8",
                        "not found\n".to_string(),
                    )
                };
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_text() {
        let reg = Arc::new(MetricsRegistry::new());
        let c = reg.counter("demo_total");
        c.add(3);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let reg2 = Arc::clone(&reg);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            let body = reg2.export_text();
            let resp = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: {PROMETHEUS_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("demo_total 3"), "{text}");
        assert!(text.contains("# TYPE demo_total counter"));
    }

    #[tokio::test]
    async fn empty_listen_disables_server() {
        let reg = Arc::new(MetricsRegistry::new());
        assert!(spawn_if_configured("", reg).await.unwrap().is_none());
    }
}
