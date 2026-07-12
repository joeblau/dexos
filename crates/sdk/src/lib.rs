#![forbid(unsafe_code)]
//! `dexos-sdk` — the native rust client SDK.
//!
//! A thin, typed layer over [`dexos_sdk_core`] (which owns all wire logic) plus
//! this crate's own tokio + tokio-rustls TLS 1.3 transport. It follows a
//! three-client shape:
//!
//! * [`InfoClient`] — unsigned read queries.
//! * [`ExchangeClient`] — the 11 signed control writes, each verifying the ack's
//!   `command_hash` against the command that was sent.
//! * [`SubscriptionClient`] — reserved; live streaming needs a `Subscribe` wire
//!   method and server push (a later phase), so it is `Unsupported` today.
//!
//! It links only `dexos-sdk-core` + tokio + rustls — never `rpc`, `network`, or
//! `observability` — so its published dependency graph stays clean.

use std::sync::atomic::{AtomicU64, Ordering};

use dexos_sdk_core::{builders, command_hash, Client, Signer, Transport, TransportError};
use dexos_sdk_core::{
    Account, AuthorizeSessionParams, BasketParams, BindWalletParams, CancelAllParams,
    CancelOrderParams, Command, CommandAck, ControlMeta, CreateMarketParams, MarketDetail,
    MarketSummary, NetworkStatus, NodeInfo, PageParams, PeerInfo, ReplaceOrderParams,
    RequestWithdrawalParams, RevokeSessionParams, RpcOk, RpcRequest, RpcResponse,
    StakeMarketParams, SubmitOrderParams,
};
use types::{AccountId, MarketId};

#[cfg(feature = "native-transport")]
pub mod tcp;
#[cfg(feature = "native-transport")]
pub mod tls;

#[cfg(feature = "native-transport")]
pub use tcp::TcpTransport;
#[cfg(feature = "native-transport")]
pub use tls::TlsTransport;

/// A failure from an SDK call.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    /// The transport failed, or its reply could not be framed/decoded.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// The node decoded the request but the method itself returned an error.
    #[error("rpc method error: {0}")]
    Rpc(dexos_sdk_core::RpcError),
    /// The node returned a success payload of the wrong shape for the method.
    #[error("unexpected response payload (expected {expected})")]
    UnexpectedResponse {
        /// The [`RpcOk`] variant the method should have returned.
        expected: &'static str,
    },
    /// A control ack's `command_hash` did not match the command that was sent.
    #[error("control ack command_hash did not match the submitted command")]
    AckMismatch,
}

fn ok(resp: RpcResponse) -> Result<RpcOk, SdkError> {
    resp.result.map_err(SdkError::Rpc)
}

/// Entry point: open a connection to a node.
pub struct Dexos;

impl Dexos {
    /// Connect to a node's TLS RPC listener, trusting the platform root store.
    #[cfg(feature = "native-transport")]
    pub fn connect(addr: std::net::SocketAddr, server_name: &str) -> InfoClient<TlsTransport> {
        InfoClient::new(TlsTransport::new(addr, server_name))
    }

    /// Connect to a node's plaintext RPC listener (local dev only).
    #[cfg(feature = "native-transport")]
    pub fn connect_plaintext(addr: std::net::SocketAddr) -> InfoClient<TcpTransport> {
        InfoClient::new(TcpTransport::new(addr))
    }
}

/// Unsigned read-query client. Convert to an [`ExchangeClient`] with
/// [`InfoClient::exchange`] to issue signed writes over the same transport.
pub struct InfoClient<T: Transport> {
    inner: Client<T>,
    next_id: AtomicU64,
}

impl<T: Transport> InfoClient<T> {
    /// Wrap any [`Transport`].
    pub fn new(transport: T) -> Self {
        Self {
            inner: Client::new(transport),
            next_id: AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Issue a raw request and return the full response envelope.
    pub async fn call(&self, req: &RpcRequest) -> Result<RpcResponse, SdkError> {
        Ok(self.inner.call(req).await?)
    }

    /// `get_node_info`.
    pub async fn get_node_info(&self) -> Result<NodeInfo, SdkError> {
        match ok(self
            .inner
            .call(&builders::get_node_info(self.next_id()))
            .await?)?
        {
            RpcOk::NodeInfo(v) => Ok(v),
            _ => Err(SdkError::UnexpectedResponse {
                expected: "NodeInfo",
            }),
        }
    }

    /// `get_peers`.
    pub async fn get_peers(&self) -> Result<Vec<PeerInfo>, SdkError> {
        match ok(self
            .inner
            .call(&builders::get_peers(self.next_id()))
            .await?)?
        {
            RpcOk::Peers(v) => Ok(v),
            _ => Err(SdkError::UnexpectedResponse { expected: "Peers" }),
        }
    }

    /// `get_markets`.
    pub async fn get_markets(&self, page: PageParams) -> Result<Vec<MarketSummary>, SdkError> {
        match ok(self
            .inner
            .call(&builders::get_markets(self.next_id(), page))
            .await?)?
        {
            RpcOk::Markets(v) => Ok(v),
            _ => Err(SdkError::UnexpectedResponse {
                expected: "Markets",
            }),
        }
    }

    /// `get_market`.
    pub async fn get_market(&self, market: MarketId) -> Result<MarketDetail, SdkError> {
        match ok(self
            .inner
            .call(&builders::get_market(self.next_id(), market))
            .await?)?
        {
            RpcOk::Market(v) => Ok(v),
            _ => Err(SdkError::UnexpectedResponse { expected: "Market" }),
        }
    }

    /// `get_account`.
    pub async fn get_account(&self, account: AccountId) -> Result<Account, SdkError> {
        match ok(self
            .inner
            .call(&builders::get_account(self.next_id(), account))
            .await?)?
        {
            RpcOk::Account(v) => Ok(v),
            _ => Err(SdkError::UnexpectedResponse {
                expected: "Account",
            }),
        }
    }

    /// `get_network_status`.
    pub async fn get_network_status(&self) -> Result<NetworkStatus, SdkError> {
        match ok(self
            .inner
            .call(&builders::get_network_status(self.next_id()))
            .await?)?
        {
            RpcOk::NetworkStatus(v) => Ok(v),
            _ => Err(SdkError::UnexpectedResponse {
                expected: "NetworkStatus",
            }),
        }
    }

    /// Upgrade to a signing [`ExchangeClient`] over the same transport.
    pub fn exchange(self, signer: Signer) -> ExchangeClient<T> {
        ExchangeClient {
            inner: self.inner,
            next_id: self.next_id,
            signer,
        }
    }
}

/// Signed control-write client. Every method builds the canonical [`Command`],
/// signs it, sends the request, and verifies the returned ack's `command_hash`
/// equals the command that was sent (fail-closed on any mismatch).
pub struct ExchangeClient<T: Transport> {
    inner: Client<T>,
    next_id: AtomicU64,
    signer: Signer,
}

impl<T: Transport> ExchangeClient<T> {
    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Sign `cmd`, send the request built from its envelope, and verify the ack.
    async fn control(
        &self,
        cmd: Command,
        build: impl FnOnce(u64, ControlMeta) -> RpcRequest,
    ) -> Result<CommandAck, SdkError> {
        let meta = self.signer.sign(&cmd).map_err(SdkError::Rpc)?;
        let req = build(self.next_id(), meta);
        match ok(self.inner.call(&req).await?)? {
            RpcOk::CommandAck(ack) => {
                if ack.command_hash != command_hash(&cmd) {
                    return Err(SdkError::AckMismatch);
                }
                Ok(ack)
            }
            _ => Err(SdkError::UnexpectedResponse {
                expected: "CommandAck",
            }),
        }
    }

    /// `submit_order`.
    pub async fn submit_order(&self, p: SubmitOrderParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::submit_order(id, meta, p))
            .await
    }

    /// `cancel_order`.
    pub async fn cancel_order(&self, p: CancelOrderParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::cancel_order(id, meta, p))
            .await
    }

    /// `cancel_all`.
    pub async fn cancel_all(&self, p: CancelAllParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::cancel_all(id, meta, p))
            .await
    }

    /// `replace_order`.
    pub async fn replace_order(&self, p: ReplaceOrderParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::replace_order(id, meta, p))
            .await
    }

    /// `submit_basket`.
    pub async fn submit_basket(&self, p: BasketParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::submit_basket(id, meta, p))
            .await
    }

    /// `authorize_session`.
    pub async fn authorize_session(
        &self,
        p: AuthorizeSessionParams,
    ) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::authorize_session(id, meta, p))
            .await
    }

    /// `revoke_session`.
    pub async fn revoke_session(&self, p: RevokeSessionParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::revoke_session(id, meta, p))
            .await
    }

    /// `bind_wallet`.
    pub async fn bind_wallet(&self, p: BindWalletParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::bind_wallet(id, meta, p))
            .await
    }

    /// `request_withdrawal`.
    pub async fn request_withdrawal(
        &self,
        p: RequestWithdrawalParams,
    ) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::request_withdrawal(id, meta, p))
            .await
    }

    /// `create_market`.
    pub async fn create_market(&self, p: CreateMarketParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::create_market(id, meta, p))
            .await
    }

    /// `stake_market`.
    pub async fn stake_market(&self, p: StakeMarketParams) -> Result<CommandAck, SdkError> {
        let cmd = p.to_command();
        self.control(cmd, |id, meta| builders::stake_market(id, meta, p))
            .await
    }
}

/// Live subscriptions are not yet supported: the wire protocol has no
/// `Subscribe` method and the node performs no server push. This type exists so
/// the three-client surface is named and stable; every call returns
/// [`SdkError::UnexpectedResponse`]-style unsupported until that phase lands.
pub struct SubscriptionClient;

impl SubscriptionClient {
    /// Always unsupported in this phase.
    pub fn unsupported() -> SdkError {
        SdkError::UnexpectedResponse {
            expected: "subscriptions unsupported until a Subscribe wire method lands",
        }
    }
}
