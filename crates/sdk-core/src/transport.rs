//! The one runtime-agnostic async byte-exchange seam plus the generic [`Client`]
//! that ties `encode_request -> exchange -> decode_response`.
//!
//! The correctness-critical request/response path is defined once here and never
//! re-implemented per language: a binding provides only a [`Transport`] that
//! moves opaque frame bytes, and inherits framing + decoding for free.

use proto::{decode_response, encode_request, RpcError, RpcRequest, RpcResponse};

/// A failure exchanging bytes with, or decoding a reply from, the node.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The underlying byte transport (socket, relay, …) failed.
    #[error("transport i/o failure: {0}")]
    Io(String),
    /// The bytes were exchanged but framing/decoding failed.
    #[error("protocol error: {0}")]
    Rpc(#[from] RpcError),
}

/// Runtime-agnostic byte exchange: implementors only move opaque frame bytes.
///
/// No `Send` bound and no tokio types in the signature, so the same trait
/// compiles for a native multi-threaded executor and a single-threaded wasm
/// executor alike. The returned future is spelled with RPITIT so no boxing is
/// forced on the hot path.
pub trait Transport {
    /// Send one framed request and return the single framed response.
    fn exchange(
        &self,
        framed_request: Vec<u8>,
    ) -> impl core::future::Future<Output = Result<Vec<u8>, TransportError>>;
}

/// The generic request/response client. Owns a [`Transport`] and layers the
/// shared framing + decoding over it.
pub struct Client<T: Transport> {
    transport: T,
}

impl<T: Transport> Client<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Frame `req`, exchange bytes, and decode the framed response.
    pub async fn call(&self, req: &RpcRequest) -> Result<RpcResponse, TransportError> {
        let framed = encode_request(req)?;
        let bytes = self.transport.exchange(framed).await?;
        Ok(decode_response(&bytes)?)
    }
}
