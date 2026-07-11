//! Typed RPC errors. Every fallible path returns one of these; no panics on
//! untrusted input.

use serde::{Deserialize, Serialize};

/// A failure returned by an RPC method or the dispatch/transport layer.
///
/// The variants are serializable so a server can return them to a client over
/// the compact binary wire, and are `#[non_exhaustive]`-free by design so the
/// wire encoding stays stable across the workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum RpcError {
    /// The requested entity (account, market, order, receipt, …) does not exist.
    #[error("not found")]
    NotFound,
    /// A control (write) method was invoked on a read-only or light node.
    #[error("node is read-only")]
    ReadOnly,
    /// The ingress queue is saturated; the caller must retry with backoff. No
    /// unbounded queue growth is permitted, so this is returned rather than
    /// blocking.
    #[error("backpressure: ingress saturated")]
    Backpressure,
    /// The request was structurally invalid or failed decoding.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The caller is not authorized for this action.
    #[error("unauthorized")]
    Unauthorized,
    /// The presented session key has expired.
    #[error("session expired")]
    SessionExpired,
    /// The command targets a market outside the session's authorized scope.
    #[error("out of session scope")]
    OutOfScope,
    /// The command exceeds the session's per-command notional cap.
    #[error("over notional limit")]
    OverNotional,
    /// The command exceeds the session's leverage cap.
    #[error("over leverage limit")]
    OverLeverage,
    /// A codec/serialization failure crossing the wire.
    #[error("codec error: {0}")]
    Codec(String),
    /// The method tag was not recognized by this server.
    #[error("unknown method")]
    UnknownMethod,
    /// An internal backend failure that is safe to surface to callers.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<codec::CodecError> for RpcError {
    fn from(e: codec::CodecError) -> Self {
        RpcError::Codec(e.to_string())
    }
}
