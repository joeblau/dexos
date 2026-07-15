//! `proto` — the transport-free wire/protocol types for the DexOS binary RPC.
//!
//! Split out of the `rpc` crate so any client — including wasm frontends — can
//! build, sign, encode, and decode requests/responses and stream events without
//! linking the async server stack (tokio, rustls, ring, rcgen, libc). It depends
//! only on `types`, `codec`, `crypto`, `serde`, and `thiserror`.
//!
//! # Layout
//! - [`error`] — the typed [`RpcError`].
//! - [`wire`] — integer-only data types shared by requests, responses, streams.
//! - [`command`] — control parameters and the canonical [`Command`] lowering.
//! - [`request`] / [`response`] — the correlated envelopes.
//! - [`transport`] — framing into [`codec::Frame`]s.
//! - [`stream`] — the sequenced streaming event **types** (the async fan-out hub
//!   that carries them lives in `rpc::stream`).
#![forbid(unsafe_code)]

pub mod command;
pub mod error;
mod packed;
pub mod request;
pub mod response;
pub mod stream;
pub mod transport;
pub mod wire;

pub use command::{
    command_hash, AuthorizeSessionParams, BasketParams, BindWalletParams, CancelAllParams,
    CancelOrderParams, Command, CommandAck, ControlMeta, CreateMarketParams, ReplaceOrderParams,
    RequestWithdrawalParams, RevokeSessionParams, SessionScope, StakeMarketParams,
    SubmitOrderParams,
};
pub use error::RpcError;
pub use packed::{command_from_packed_order, packed_order_from_method};
pub use request::{RpcMethod, RpcRequest};
pub use response::{RpcOk, RpcResponse, RpcResult};
pub use stream::{
    EventKind, Gap, Progress, Recovery, Reliability, SequenceTracker, SharedEvent, StreamError,
    StreamEvent, StreamPayload, StreamStats, Topic, DEFAULT_BROADCAST_CAPACITY, DEFAULT_MAX_TOPICS,
    DEFAULT_TOPIC_BYTE_BUDGET,
};
pub use transport::{
    decode_request, decode_response, decode_stream_event, encode_request, encode_request_into,
    encode_response, encode_response_into, encode_stream_event,
};
pub use wire::{
    Account, AccountProof, Book, BookDelta, BridgeStatus, Checkpoint, DepositStatus,
    ExecutionReceipt, Fill, FinalityStatus, Funding, MarkPrice, MarketDetail, MarketLifecycleEvent,
    MarketStatus, MarketSummary, NetworkStatus, NodeInfo, OraclePrice, OracleStatus, Order,
    PageParams, PeerInfo, Position, RpcMode, Trade, VerificationStatus, WithdrawalStatus,
};

#[cfg(test)]
mod float_guard {
    /// A grep-in-test guard mirroring the CI no-float gate for the wire modules:
    /// every value that crosses the wire must be fixed-point integer, never a
    /// float. Scans the module sources directly so a stray `f32`/`f64` fails here
    /// as well as at the CI gate.
    #[test]
    fn no_floating_point_in_wire_modules() {
        for src in [
            include_str!("wire.rs"),
            include_str!("command.rs"),
            include_str!("request.rs"),
            include_str!("response.rs"),
            include_str!("stream.rs"),
        ] {
            assert!(!src.contains("f32"), "f32 found in a wire module");
            assert!(!src.contains("f64"), "f64 found in a wire module");
        }
    }
}
