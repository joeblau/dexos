//! Async length-prefixed framed RPC server over a Tokio TCP listener.
//!
//! Each connection is a sequential request/response loop: read one framed
//! [`RpcRequest`], [`dispatch`] it against the backend (enforcing read-only /
//! light mode), and write the framed [`RpcResponse`]. Decode failures produce an
//! error response rather than tearing down the connection.

use std::sync::Arc;

use codec::{FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::backend::{dispatch, RpcBackend};
use crate::error::RpcError;
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
    /// An RPC-layer failure while encoding a reply.
    #[error("rpc error: {0}")]
    Rpc(#[from] RpcError),
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

/// Serve one connection to completion: loop reading requests and writing
/// responses until the peer closes or an unrecoverable transport error occurs.
pub async fn handle_connection<S>(
    mut stream: S,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let bytes = match read_frame(&mut stream).await {
            Ok(bytes) => bytes,
            // A clean EOF or reset ends the session without error.
            Err(ServerError::Io(_)) => return Ok(()),
            Err(ServerError::Oversize) => {
                let resp = RpcResponse::new(0, Err(RpcError::Backpressure));
                let out = encode_response(&resp)?;
                stream.write_all(&out).await?;
                return Ok(());
            }
            Err(other) => return Err(other),
        };
        let response = match decode_request(&bytes) {
            Ok(request) => dispatch(&*backend, mode, request),
            Err(err) => RpcResponse::new(0, Err(err)),
        };
        let out = encode_response(&response)?;
        stream.write_all(&out).await?;
        stream.flush().await?;
    }
}

/// Accept connections on `listener` and serve each on its own task. Runs until
/// the listener errors. A per-connection failure is isolated and does not stop
/// the accept loop.
pub async fn serve(
    listener: TcpListener,
    backend: Arc<dyn RpcBackend>,
    mode: RpcMode,
) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let backend = Arc::clone(&backend);
        tokio::spawn(async move {
            let _ = handle_connection(stream, backend, mode).await;
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
