//! A plaintext TCP client transport for local development.
//!
//! Mirrors [`crate::tls::TlsTransport`] without the TLS layer: a fresh TCP
//! connection per `exchange`, writing the framed request and reading exactly one
//! length-prefixed frame back. Pairs with a node running its RPC listener in
//! `TlsMode::Disabled` (dev). Production deployments must use
//! [`crate::tls::TlsTransport`].

use std::net::SocketAddr;

use dexos_sdk_core::{Transport, TransportError, FRAME_HEADER_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A one-shot plaintext TCP transport to a node's RPC listener.
pub struct TcpTransport {
    addr: SocketAddr,
}

impl TcpTransport {
    /// Build a transport targeting a plaintext RPC listener.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// The node endpoint this transport targets.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Transport for TcpTransport {
    async fn exchange(&self, framed: Vec<u8>) -> Result<Vec<u8>, TransportError> {
        let mut tcp = TcpStream::connect(self.addr)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        tcp.write_all(&framed)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        tcp.flush()
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;

        // Read exactly one frame: fixed 19-byte header, then the declared payload.
        let mut header = [0u8; FRAME_HEADER_LEN];
        tcp.read_exact(&mut header)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]) as usize;
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + plen);
        out.extend_from_slice(&header);
        let mut body = vec![0u8; plen];
        tcp.read_exact(&mut body)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        out.extend_from_slice(&body);
        Ok(out)
    }
}
