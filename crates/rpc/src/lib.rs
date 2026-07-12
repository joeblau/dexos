//! `rpc` — the public binary RPC surface and streaming subscription API for
//! DexOS.
//!
//! The crate is transport- and engine-decoupled: it defines the request/response
//! wire types (compact binary via [`codec`], never JSON in the core path), a
//! [`RpcBackend`] trait the node implements over its live engine, a pure
//! [`dispatch`] router that enforces read-only / light mode, an async framed TCP
//! (TLS 1.3) [`server`], and a sequenced streaming subscription layer with gap
//! detection and snapshot recovery.
//!
//! # Layout
//! - [`error`] — the typed [`RpcError`].
//! - [`wire`] — integer-only data types shared by requests, responses, streams.
//! - [`command`] — control parameters and the canonical [`Command`] lowering.
//! - [`session`] — session-scoped authorization and server-side bindings.
//! - [`request`] / [`response`] — the correlated envelopes.
//! - [`backend`] — the [`RpcBackend`] trait and [`dispatch`].
//! - [`transport`] — framing into [`codec::Frame`]s.
//! - [`server`] — the async TCP/TLS server with isolated blocking dispatch.
//! - [`metrics`] — pre-registered counters/gauge for the server's shed paths.
//! - [`limits`] — connection admission control (per-IP caps and rate limits).
//! - [`work`] — process/per-connection in-flight request and byte budgets.
//! - [`idempotency`] — bounded TTL/LRU exactly-once store.
//! - [`stream`] — sharded, byte-bounded streaming subscription registry.
//! - [`tls`] — TLS 1.3 acceptor helpers.
//! - [`stub`] — an in-memory backend for tests.
#![forbid(unsafe_code)]

pub mod backend;
pub mod idempotency;
pub mod limits;
pub mod metrics;
pub mod server;
pub mod session;
pub mod stream;
pub mod stub;
pub mod tls;
pub mod work;

// The transport-free wire/protocol modules (`command`, `error`, `request`,
// `response`, `transport`, `wire`) now live in the `proto` crate. Re-export them
// as modules so both intra-crate (`crate::command::…`) and downstream
// (`rpc::command::…`) paths keep resolving unchanged.
pub use proto::{command, error, request, response, transport, wire};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "rpc";

pub use backend::{dispatch, RpcBackend, MAX_BOOK_DEPTH};
pub use command::{
    command_hash, AuthorizeSessionParams, BasketParams, BindWalletParams, CancelAllParams,
    CancelOrderParams, Command, CommandAck, ControlMeta, CreateMarketParams, ReplaceOrderParams,
    RequestWithdrawalParams, RevokeSessionParams, SessionScope, StakeMarketParams,
    SubmitOrderParams,
};
pub use error::RpcError;
pub use idempotency::{IdempotencyConfig, IdempotencyStore};
pub use limits::RateLimit;
pub use metrics::RpcMetrics;
pub use request::{RpcMethod, RpcRequest};
pub use response::{RpcOk, RpcResponse, RpcResult};
pub use server::{
    handle_connection, handle_connection_with, serve, serve_with_config, serve_with_metrics,
    serve_with_shutdown, ServerConfig, ServerError, TlsMode,
};
pub use session::{
    authorize_private_topic, session_may_read, Session, SessionBinding, SessionLookup,
    SessionRegistry,
};
pub use stream::{
    EventKind, Gap, Progress, Recovery, Reliability, SequenceTracker, SharedEvent, StreamError,
    StreamEvent, StreamHub, StreamPayload, StreamStats, Subscription, Topic, DEFAULT_MAX_TOPICS,
    DEFAULT_TOPIC_BYTE_BUDGET,
};
pub use stub::StubBackend;
pub use tls::{acceptor_from_pem, generate_self_signed_localhost, TlsError};
pub use transport::{
    decode_request, decode_response, decode_stream_event, encode_request, encode_response,
    encode_stream_event,
};
pub use wire::{
    Account, AccountProof, Book, BookDelta, BridgeStatus, Checkpoint, DepositStatus,
    ExecutionReceipt, Fill, FinalityStatus, Funding, MarkPrice, MarketDetail, MarketLifecycleEvent,
    MarketStatus, MarketSummary, NetworkStatus, NodeInfo, OraclePrice, OracleStatus, Order,
    PageParams, PeerInfo, Position, RpcMode, Trade, VerificationStatus, WithdrawalStatus,
};
pub use work::{WorkBudget, WorkBudgetConfig};

#[cfg(test)]
mod tests;
