//! The native TLS 1.3 client transport.
//!
//! Lifted from the tested pattern in `crates/rpc/src/tests.rs`: a TLS-1.3-only
//! rustls client over a fresh TCP connection, reading exactly one length-prefixed
//! frame (parse the 19-byte header for the payload length) rather than reading to
//! EOF. That matches the node's one-request/one-response-per-connection model and
//! stays correct if the node ever keeps the socket open for pipelining.

use std::net::SocketAddr;
use std::sync::Arc;

use dexos_sdk_core::{Transport, TransportError, FRAME_HEADER_LEN};
use rustls::ClientConfig as RustlsClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A one-shot TLS 1.3 transport to a node's RPC listener. Cheap to clone the
/// target; a fresh TCP + TLS handshake is performed per `exchange`.
pub struct TlsTransport {
    addr: SocketAddr,
    server_name: String,
    connector: TlsConnector,
}

impl TlsTransport {
    /// Build a transport trusting the platform's native root certificates.
    ///
    /// `server_name` is the SNI / certificate name presented to the node (e.g.
    /// `"localhost"` against a self-signed dev cert).
    pub fn new(addr: SocketAddr, server_name: impl Into<String>) -> Self {
        // Idempotent: installing the process-default crypto provider more than
        // once is expected across many transports, so the result is ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        let cfg = RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            addr,
            server_name: server_name.into(),
            connector: TlsConnector::from(Arc::new(cfg)),
        }
    }

    /// The node endpoint this transport targets.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Transport for TlsTransport {
    async fn exchange(&self, framed: Vec<u8>) -> Result<Vec<u8>, TransportError> {
        let tcp = TcpStream::connect(self.addr)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| TransportError::Io("invalid server name".into()))?;
        let mut tls = self
            .connector
            .connect(name, tcp)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        tls.write_all(&framed)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        tls.flush()
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        read_one_frame(&mut tls).await
    }
}

/// Read exactly one framed message: the fixed 19-byte header, then the payload
/// whose length is the u32 LE at header bytes `[15..19]`.
async fn read_one_frame<S>(stream: &mut S) -> Result<Vec<u8>, TransportError>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]) as usize;
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + plen);
    out.extend_from_slice(&header);
    let mut body = vec![0u8; plen];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    out.extend_from_slice(&body);
    Ok(out)
}
