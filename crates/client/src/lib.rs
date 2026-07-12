//! `client` — a native, typed RPC client for the DexOS node.
//!
//! It pairs the transport-free [`proto`] wire types with [`rpc`]'s plaintext-TCP
//! [`round_trip`](rpc::server::round_trip) into a small [`Client`], generalizing
//! the request-building and ed25519 signing that `bin/dexos` performs inline so
//! the Dioxus **desktop** and **mobile** apps — and the **web** app's server
//! side — share one client. Read queries are unsigned; control (write) methods
//! are signed through a [`Signer`].
//!
//! This crate is **native only**: it links `rpc` (and thus tokio/rustls) and
//! must not be a dependency of a wasm target. A browser reaches the node through
//! the web app's server functions, which call this crate server-side.
//!
//! ```no_run
//! # async fn demo() -> Result<(), client::ClientError> {
//! let client = client::Client::new("127.0.0.1:8080".parse().unwrap());
//! let markets = client.get_markets(Default::default()).await?;
//! println!("{} markets", markets.len());
//! # Ok(()) }
//! ```
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use proto::{
    command_hash, Account, AccountProof, Book, Checkpoint, Command, CommandAck, ControlMeta,
    DepositStatus, ExecutionReceipt, MarketDetail, MarketStatus, MarketSummary, NetworkStatus,
    NodeInfo, OracleStatus, Order, PageParams, PeerInfo, Position, RpcMethod, RpcOk, RpcRequest,
    SubmitOrderParams, Trade, WithdrawalStatus,
};
use types::{AccountId, Hash, MarketId};

/// A failure talking to the node.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The connection, frame, or socket failed (before a method result existed).
    #[error("transport error: {0}")]
    Transport(#[from] rpc::ServerError),
    /// The node decoded the request but the method itself returned an error.
    #[error("rpc method error: {0}")]
    Rpc(proto::RpcError),
    /// The node returned a success payload of the wrong shape for the method
    /// (a protocol violation — the correct variant is named by `expected`).
    #[error("unexpected response payload (expected {expected})")]
    UnexpectedResponse {
        /// The [`RpcOk`] variant the method should have returned.
        expected: &'static str,
    },
    /// A control ack's `command_hash` did not match the command that was sent —
    /// the ack does not correspond to our request. Defense in depth.
    #[error("control ack command_hash did not match the submitted command")]
    AckMismatch,
}

/// A typed client bound to one node endpoint. Cheap to clone the target; a fresh
/// TCP connection is opened per call (matching the node's one-shot RPC model).
#[derive(Debug)]
pub struct Client {
    target: SocketAddr,
    next_request_id: AtomicU64,
}

impl Client {
    /// Create a client targeting the node's plaintext RPC listener.
    pub fn new(target: SocketAddr) -> Self {
        Client {
            target,
            next_request_id: AtomicU64::new(1),
        }
    }

    /// The node endpoint this client targets.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    fn next_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Send one method and return its raw success payload, mapping a method-level
    /// error to [`ClientError::Rpc`]. Prefer the typed helpers below.
    pub async fn call(&self, method: RpcMethod) -> Result<RpcOk, ClientError> {
        let request = RpcRequest::new(self.next_id(), method);
        let response = rpc::server::round_trip(self.target, &request).await?;
        response.result.map_err(ClientError::Rpc)
    }

    /// Submit a signed order and return the node's acknowledgement. The ack's
    /// `command_hash` is verified against the command we sent
    /// ([`ClientError::AckMismatch`] otherwise).
    pub async fn submit_order(
        &self,
        signer: &Signer,
        params: SubmitOrderParams,
    ) -> Result<CommandAck, ClientError> {
        let command = params.to_command();
        let meta = signer.sign(&command)?;
        let ack = match self.call(RpcMethod::SubmitOrder(meta, params)).await? {
            RpcOk::CommandAck(ack) => ack,
            _ => {
                return Err(ClientError::UnexpectedResponse {
                    expected: "CommandAck",
                })
            }
        };
        if ack.command_hash != command_hash(&command) {
            return Err(ClientError::AckMismatch);
        }
        Ok(ack)
    }
}

/// Generate the typed read-query helpers: each sends its `RpcMethod` and unwraps
/// the single expected [`RpcOk`] variant, returning [`ClientError::UnexpectedResponse`]
/// on any other payload.
macro_rules! read_queries {
    ($(
        $(#[$attr:meta])*
        fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty = $method:expr => $variant:ident;
    )*) => {
        impl Client {
            $(
                $(#[$attr])*
                pub async fn $name(&self, $($arg: $ty),*) -> Result<$ret, ClientError> {
                    match self.call($method).await? {
                        RpcOk::$variant(value) => Ok(value),
                        _ => Err(ClientError::UnexpectedResponse { expected: stringify!($variant) }),
                    }
                }
            )*
        }
    };
}

read_queries! {
    /// Node identity and status.
    fn get_node_info() -> NodeInfo = RpcMethod::GetNodeInfo => NodeInfo;
    /// Connected peers.
    fn get_peers() -> Vec<PeerInfo> = RpcMethod::GetPeers => Peers;
    /// A page of markets.
    fn get_markets(page: PageParams) -> Vec<MarketSummary> = RpcMethod::GetMarkets(page) => Markets;
    /// One market's metadata.
    fn get_market(market: MarketId) -> MarketDetail = RpcMethod::GetMarket(market) => Market;
    /// A market's order book to `depth` levels.
    fn get_market_book(market: MarketId, depth: u32) -> Book = RpcMethod::GetMarketBook(market, depth) => MarketBook;
    /// Recent trades for a market.
    fn get_market_trades(market: MarketId, page: PageParams) -> Vec<Trade> = RpcMethod::GetMarketTrades(market, page) => MarketTrades;
    /// Live status for a market.
    fn get_market_status(market: MarketId) -> MarketStatus = RpcMethod::GetMarketStatus(market) => MarketStatus;
    /// Oracle status for a market.
    fn get_oracle_status(market: MarketId) -> OracleStatus = RpcMethod::GetOracleStatus(market) => OracleStatus;
    /// A checkpoint by height.
    fn get_checkpoint(height: u64) -> Checkpoint = RpcMethod::GetCheckpoint(height) => Checkpoint;
    /// The latest checkpoint.
    fn get_latest_checkpoint() -> Checkpoint = RpcMethod::GetLatestCheckpoint => Checkpoint;
    /// An account's state.
    fn get_account(account: AccountId) -> Account = RpcMethod::GetAccount(account) => Account;
    /// A Merkle proof for an account against the latest checkpoint.
    fn get_account_proof(account: AccountId) -> AccountProof = RpcMethod::GetAccountProof(account) => AccountProof;
    /// A position by account and market.
    fn get_position(account: AccountId, market: MarketId) -> Position = RpcMethod::GetPosition(account, market) => Position;
    /// A page of an account's orders.
    fn get_orders(account: AccountId, page: PageParams) -> Vec<Order> = RpcMethod::GetOrders(account, page) => Orders;
    /// An execution receipt by command hash.
    fn get_execution_receipt(command: Hash) -> ExecutionReceipt = RpcMethod::GetExecutionReceipt(command) => ExecutionReceipt;
    /// A deposit's status by tx hash.
    fn get_deposit_status(tx: Hash) -> DepositStatus = RpcMethod::GetDepositStatus(tx) => DepositStatus;
    /// A withdrawal's status by request hash.
    fn get_withdrawal_status(request: Hash) -> WithdrawalStatus = RpcMethod::GetWithdrawalStatus(request) => WithdrawalStatus;
    /// Network / sync status.
    fn get_network_status() -> NetworkStatus = RpcMethod::GetNetworkStatus => NetworkStatus;
}

/// Signs control (write) commands. Holds the authorizing ed25519 keypair, the
/// stable `client_id`, and a monotonic nonce so each command is idempotent
/// exactly once (`(client_id, nonce)`).
#[derive(Debug)]
pub struct Signer {
    client_id: u64,
    keypair: crypto::KeyPair,
    session_pubkey: Option<[u8; 32]>,
    next_nonce: AtomicU64,
}

impl Signer {
    /// A signer authorizing with an account root key, starting at `start_nonce`.
    pub fn new(client_id: u64, keypair: crypto::KeyPair, start_nonce: u64) -> Self {
        Signer {
            client_id,
            keypair,
            session_pubkey: None,
            next_nonce: AtomicU64::new(start_nonce),
        }
    }

    /// A signer authorizing with a delegated session key. The keypair must be the
    /// session key itself (its public half is carried as `session_pubkey`).
    pub fn with_session(
        client_id: u64,
        session_keypair: crypto::KeyPair,
        start_nonce: u64,
    ) -> Self {
        let session_pubkey = Some(session_keypair.public());
        Signer {
            client_id,
            keypair: session_keypair,
            session_pubkey,
            next_nonce: AtomicU64::new(start_nonce),
        }
    }

    /// The stable client identifier.
    pub fn client_id(&self) -> u64 {
        self.client_id
    }

    /// Build a signed [`ControlMeta`] for `command`, consuming the next nonce.
    fn sign(&self, command: &Command) -> Result<ControlMeta, ClientError> {
        let nonce = self.next_nonce.fetch_add(1, Ordering::Relaxed);
        ControlMeta::signed(
            self.client_id,
            nonce,
            self.session_pubkey,
            &self.keypair,
            command,
        )
        .map_err(ClientError::Rpc)
    }
}
