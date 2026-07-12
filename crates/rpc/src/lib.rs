//! `rpc` — the public binary RPC surface and streaming subscription API for
//! DexOS.
//!
//! The crate is transport- and engine-decoupled: it defines the request/response
//! wire types (compact binary via [`codec`], never JSON in the core path), a
//! [`RpcBackend`] trait the node implements over its live engine, a pure
//! [`dispatch`] router that enforces read-only / light mode, an async framed TCP
//! [`server`], and a sequenced streaming subscription layer with gap detection
//! and snapshot recovery.
//!
//! # Layout
//! - [`error`] — the typed [`RpcError`].
//! - [`wire`] — integer-only data types shared by requests, responses, streams.
//! - [`command`] — control parameters and the canonical [`Command`] lowering.
//! - [`session`] — session-scoped authorization.
//! - [`request`] / [`response`] — the correlated envelopes.
//! - [`backend`] — the [`RpcBackend`] trait and [`dispatch`].
//! - [`transport`] — framing into [`codec::Frame`]s.
//! - [`server`] — the async TCP server.
//! - [`limits`] — connection admission control (per-IP caps and rate limits).
//! - [`stream`] — the streaming subscription registry.
//! - [`stub`] — an in-memory backend for tests.
#![forbid(unsafe_code)]

pub mod backend;
pub mod command;
pub mod error;
pub mod limits;
pub mod request;
pub mod response;
pub mod server;
pub mod session;
pub mod stream;
pub mod stub;
pub mod transport;
pub mod wire;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "rpc";

pub use backend::{dispatch, RpcBackend};
pub use command::{
    AuthorizeSessionParams, BasketParams, BindWalletParams, CancelAllParams, CancelOrderParams,
    Command, CommandAck, ControlMeta, CreateMarketParams, ReplaceOrderParams,
    RequestWithdrawalParams, RevokeSessionParams, SessionScope, StakeMarketParams,
    SubmitOrderParams,
};
pub use error::RpcError;
pub use limits::RateLimit;
pub use request::{RpcMethod, RpcRequest};
pub use response::{RpcOk, RpcResponse, RpcResult};
pub use server::{
    handle_connection, handle_connection_with, serve, serve_with_config, ServerConfig, ServerError,
};
pub use session::Session;
pub use stream::{
    EventKind, Gap, Progress, Recovery, Reliability, SequenceTracker, StreamError, StreamEvent,
    StreamHub, StreamPayload, Subscription, Topic, DEFAULT_MAX_TOPICS,
};
pub use stub::StubBackend;
pub use transport::{
    decode_request, decode_response, decode_stream_event, encode_request, encode_response,
    encode_stream_event,
};
pub use wire::{
    Account, AccountProof, Book, BookDelta, BookLevel, BridgeStatus, Checkpoint, DepositStatus,
    ExecutionReceipt, Fill, FinalityStatus, Funding, MarkPrice, MarketDetail, MarketLifecycleEvent,
    MarketStatus, MarketSummary, NetworkStatus, NodeInfo, OraclePrice, OracleStatus, Order,
    PageParams, PeerInfo, Position, RpcMode, Trade, VerificationStatus, WithdrawalStatus,
};

#[cfg(test)]
mod tests;
