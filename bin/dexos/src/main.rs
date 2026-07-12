//! `dexos` — a command-line client for the DexOS binary RPC.
//!
//! `dexos` speaks the same wire protocol the node serves from `crates/rpc`: a
//! length-prefixed, postcard-encoded `codec::Frame` carrying an `RpcRequest`
//! over a TCP socket, one request/response per connection. Read-only queries are
//! sent unsigned; control (write) methods are signed with an ed25519 key so the
//! server can authenticate them (`ControlMeta` over the canonical command bytes).
//!
//! Argument parsing is total: bad input yields a nonzero exit via clap, never a
//! panic, matching the `marketd` convention.
//!
//! # Status
//! - The client uses the **plaintext** TCP path (`rpc::server::round_trip`). The
//!   production server is TLS 1.3-only; a TLS client connector is not yet
//!   provided by the `rpc` crate, so `dexos` targets a plaintext listener (a dev
//!   node, or a future `--tls` mode).
//! - The node does not yet bind the RPC listener from `marketd run`; `dexos` is
//!   usable against a process that calls `rpc::serve*` directly (tests, harnesses).
//! - Live subscriptions (order book / fills feeds) are not exposed on the wire
//!   yet, so `dexos` performs synchronous request/response only.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use rpc::{
    AuthorizeSessionParams, BindWalletParams, CancelAllParams, CancelOrderParams,
    Command as RpcCommand, ControlMeta, CreateMarketParams, PageParams, ReplaceOrderParams,
    RequestWithdrawalParams, RevokeSessionParams, RpcMethod, RpcRequest, RpcResponse, SessionScope,
    StakeMarketParams, SubmitOrderParams,
};
use types::{
    AccountId, Amount, Hash, MarketId, MarketType, OrderId, OrderType, Price, Quantity, Ratio,
    Side, SponsorId, TimeInForce,
};

#[derive(Parser, Debug)]
#[command(
    name = "dexos",
    version,
    about = "DexOS — command-line client for the node RPC",
    propagate_version = true
)]
struct Cli {
    /// RPC endpoint to connect to (`host:port`).
    #[arg(
        long,
        global = true,
        value_name = "ADDR",
        default_value = "127.0.0.1:8080"
    )]
    target: SocketAddr,
    /// Hex ed25519 seed file (from `marketd keygen --output`) that signs control
    /// methods with the account's root authorization key.
    #[arg(long, global = true, value_name = "PATH")]
    key: Option<PathBuf>,
    /// Hex ed25519 seed file for a delegated session key. When set, control
    /// methods are signed by this key and `session_pubkey` is populated.
    #[arg(long, global = true, value_name = "PATH")]
    session_key: Option<PathBuf>,
    /// Stable per-client identifier used with `nonce` for exactly-once control
    /// idempotency.
    #[arg(long, global = true, value_name = "ID", default_value_t = 1)]
    client_id: u64,
    /// Monotonic per-client nonce for the next control command. The server dedupes
    /// `(client_id, nonce)`, so a retransmit must reuse the same value and a new
    /// command must increase it.
    #[arg(long, global = true, value_name = "N", default_value_t = 0)]
    nonce: u64,
    /// Correlation id echoed back on the response envelope.
    #[arg(long, global = true, value_name = "ID", default_value_t = 1)]
    request_id: u64,
    #[command(subcommand)]
    command: Command,
}

/// A `dexos` subcommand — one per RPC method (queries first, then the signed
/// control methods).
#[derive(Subcommand, Debug)]
enum Command {
    // ---- read-only queries ----
    /// Node identity and status.
    GetNodeInfo,
    /// Connected peers.
    GetPeers,
    /// List markets (paginated).
    GetMarkets(Page),
    /// One market's metadata.
    GetMarket(MarketRef),
    /// One market's order book to `--depth` levels.
    GetMarketBook(BookArgs),
    /// Recent trades for a market (paginated).
    GetMarketTrades(MarketPage),
    /// Live status for a market.
    GetMarketStatus(MarketRef),
    /// Oracle status for a market.
    GetOracleStatus(MarketRef),
    /// A checkpoint by height.
    GetCheckpoint(CheckpointArgs),
    /// The latest checkpoint.
    GetLatestCheckpoint,
    /// An account's state.
    GetAccount(AccountRef),
    /// A Merkle proof for an account against the latest checkpoint.
    GetAccountProof(AccountRef),
    /// A position by account and market.
    GetPosition(PositionArgs),
    /// Orders for an account (paginated).
    GetOrders(AccountPage),
    /// An execution receipt by command hash.
    GetExecutionReceipt(HashArgs),
    /// A deposit's status by tx hash.
    GetDepositStatus(HashArgs),
    /// A withdrawal's status by request hash.
    GetWithdrawalStatus(HashArgs),
    /// Network / sync status.
    GetNetworkStatus,

    // ---- control (write) methods; require --key or --session-key ----
    /// Submit a new order.
    SubmitOrder(SubmitOrderArgs),
    /// Cancel an order.
    CancelOrder(CancelOrderArgs),
    /// Cancel all orders (optionally scoped to a market).
    CancelAll(CancelAllArgs),
    /// Replace an order's price and quantity.
    ReplaceOrder(ReplaceOrderArgs),
    /// Authorize a delegated session key with a scope.
    AuthorizeSession(AuthorizeSessionArgs),
    /// Revoke a session key.
    RevokeSession(RevokeSessionArgs),
    /// Bind an external wallet to an account.
    BindWallet(BindWalletArgs),
    /// Request a withdrawal to an external address.
    RequestWithdrawal(RequestWithdrawalArgs),
    /// Create a market.
    CreateMarket(CreateMarketArgs),
    /// Stake a market on behalf of a sponsor.
    StakeMarket(StakeMarketArgs),
}

/// A CLI order side (mirrors `types::Side`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum SideArg {
    Bid,
    Ask,
}

impl From<SideArg> for Side {
    fn from(s: SideArg) -> Self {
        match s {
            SideArg::Bid => Side::Bid,
            SideArg::Ask => Side::Ask,
        }
    }
}

/// A CLI order type (mirrors `types::OrderType`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OrderTypeArg {
    Limit,
    Market,
    PostOnly,
    ReduceOnly,
}

impl From<OrderTypeArg> for OrderType {
    fn from(o: OrderTypeArg) -> Self {
        match o {
            OrderTypeArg::Limit => OrderType::Limit,
            OrderTypeArg::Market => OrderType::Market,
            OrderTypeArg::PostOnly => OrderType::PostOnly,
            OrderTypeArg::ReduceOnly => OrderType::ReduceOnly,
        }
    }
}

/// A CLI time-in-force policy (mirrors `types::TimeInForce`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TifArg {
    Gtc,
    Ioc,
    Fok,
}

impl From<TifArg> for TimeInForce {
    fn from(t: TifArg) -> Self {
        match t {
            TifArg::Gtc => TimeInForce::Gtc,
            TifArg::Ioc => TimeInForce::Ioc,
            TifArg::Fok => TimeInForce::Fok,
        }
    }
}

/// A CLI market type (mirrors `types::MarketType`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum MarketTypeArg {
    Perpetual,
    BinaryPrediction,
    MultiOutcomePrediction,
    Decision,
    Sports,
    Scalar,
    CustomPayoutVector,
}

impl From<MarketTypeArg> for MarketType {
    fn from(m: MarketTypeArg) -> Self {
        match m {
            MarketTypeArg::Perpetual => MarketType::Perpetual,
            MarketTypeArg::BinaryPrediction => MarketType::BinaryPrediction,
            MarketTypeArg::MultiOutcomePrediction => MarketType::MultiOutcomePrediction,
            MarketTypeArg::Decision => MarketType::Decision,
            MarketTypeArg::Sports => MarketType::Sports,
            MarketTypeArg::Scalar => MarketType::Scalar,
            MarketTypeArg::CustomPayoutVector => MarketType::CustomPayoutVector,
        }
    }
}

/// Pagination bound shared by list queries.
#[derive(Args, Debug)]
struct Page {
    /// Offset into the result set.
    #[arg(long, default_value_t = 0)]
    offset: u32,
    /// Requested maximum items (the server clamps this).
    #[arg(long, default_value_t = 100)]
    limit: u32,
}

impl Page {
    fn to_params(&self) -> PageParams {
        PageParams {
            offset: self.offset,
            limit: self.limit,
        }
    }
}

#[derive(Args, Debug)]
struct MarketRef {
    /// Market id.
    #[arg(long, value_name = "ID")]
    market: u32,
}

#[derive(Args, Debug)]
struct AccountRef {
    /// Account id.
    #[arg(long, value_name = "ID")]
    account: u32,
}

#[derive(Args, Debug)]
struct BookArgs {
    /// Market id.
    #[arg(long, value_name = "ID")]
    market: u32,
    /// Number of price levels per side.
    #[arg(long, default_value_t = 10)]
    depth: u32,
}

#[derive(Args, Debug)]
struct MarketPage {
    /// Market id.
    #[arg(long, value_name = "ID")]
    market: u32,
    #[command(flatten)]
    page: Page,
}

#[derive(Args, Debug)]
struct CheckpointArgs {
    /// Checkpoint height.
    #[arg(long)]
    height: u64,
}

#[derive(Args, Debug)]
struct PositionArgs {
    /// Account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// Market id.
    #[arg(long, value_name = "ID")]
    market: u32,
}

#[derive(Args, Debug)]
struct AccountPage {
    /// Account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    #[command(flatten)]
    page: Page,
}

#[derive(Args, Debug)]
struct HashArgs {
    /// 32-byte hash as hex (64 chars, optional `0x` prefix).
    #[arg(long, value_name = "HEX32", value_parser = parse_hash)]
    hash: Hash,
}

#[derive(Args, Debug)]
struct SubmitOrderArgs {
    /// Owning account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// Target market id.
    #[arg(long, value_name = "ID")]
    market: u32,
    /// Order side.
    #[arg(long, value_enum)]
    side: SideArg,
    /// Execution style.
    #[arg(long, value_enum, default_value = "limit")]
    order_type: OrderTypeArg,
    /// Limit price in raw scaled units (1.0 = 1_000_000).
    #[arg(long)]
    price: i64,
    /// Quantity in raw scaled units (1.0 = 1_000_000).
    #[arg(long)]
    quantity: i64,
    /// Time-in-force policy.
    #[arg(long, value_enum, default_value = "gtc")]
    time_in_force: TifArg,
    /// Requested leverage in raw scaled units (1.0x = 1_000_000).
    #[arg(long, default_value_t = 1_000_000)]
    leverage: i64,
}

#[derive(Args, Debug)]
struct CancelOrderArgs {
    /// Owning account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// Market id.
    #[arg(long, value_name = "ID")]
    market: u32,
    /// Order id to cancel.
    #[arg(long, value_name = "ID")]
    order_id: u64,
}

#[derive(Args, Debug)]
struct CancelAllArgs {
    /// Owning account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// Restrict to one market; omit to cancel across all markets.
    #[arg(long, value_name = "ID")]
    market: Option<u32>,
}

#[derive(Args, Debug)]
struct ReplaceOrderArgs {
    /// Owning account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// Market id.
    #[arg(long, value_name = "ID")]
    market: u32,
    /// Order id to replace.
    #[arg(long, value_name = "ID")]
    order_id: u64,
    /// New price in raw scaled units (1.0 = 1_000_000).
    #[arg(long)]
    new_price: i64,
    /// New quantity in raw scaled units (1.0 = 1_000_000).
    #[arg(long)]
    new_quantity: i64,
}

#[derive(Args, Debug)]
struct AuthorizeSessionArgs {
    /// Authorizing account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// Session public key as hex (32 bytes / 64 hex chars).
    #[arg(long, value_name = "HEX32", value_parser = parse_hex32)]
    session_pubkey: [u8; 32],
    /// Authorized market id; repeatable. Ignored when `--all-markets` is set.
    #[arg(long = "market", value_name = "ID")]
    market: Vec<u32>,
    /// Grant every market (wildcard); overrides the `--market` allow-list.
    #[arg(long)]
    all_markets: bool,
    /// Max per-command notional in raw scaled units (1.0 = 1_000_000).
    #[arg(long, default_value_t = 0)]
    max_notional: i128,
    /// Max leverage in raw scaled units (1.0x = 1_000_000).
    #[arg(long, default_value_t = 1_000_000)]
    max_leverage: i64,
    /// Allow the session to request withdrawals.
    #[arg(long)]
    allow_withdrawal: bool,
    /// Allow delegable account-administration commands (e.g. bind-wallet).
    #[arg(long)]
    allow_session_admin: bool,
    /// Allow the session to create markets.
    #[arg(long)]
    allow_market_create: bool,
    /// Session expiry as unix milliseconds.
    #[arg(long)]
    expiry: u64,
}

#[derive(Args, Debug)]
struct RevokeSessionArgs {
    /// Authorizing account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// Session public key to revoke, as hex (32 bytes).
    #[arg(long, value_name = "HEX32", value_parser = parse_hex32)]
    session_pubkey: [u8; 32],
}

#[derive(Args, Debug)]
struct BindWalletArgs {
    /// Account id to bind.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// External wallet address as hex (20-byte EVM address).
    #[arg(long, value_name = "HEX20", value_parser = parse_hex20)]
    wallet: [u8; 20],
    /// Signature proving control of the wallet, as hex bytes.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_bytes)]
    proof: Vec<u8>,
}

#[derive(Args, Debug)]
struct RequestWithdrawalArgs {
    /// Withdrawing account id.
    #[arg(long, value_name = "ID")]
    account: u32,
    /// Amount in raw scaled units (1.0 = 1_000_000).
    #[arg(long)]
    amount: i128,
    /// Destination address as hex (20-byte EVM address).
    #[arg(long, value_name = "HEX20", value_parser = parse_hex20)]
    destination: [u8; 20],
}

#[derive(Args, Debug)]
struct CreateMarketArgs {
    /// Creating account id.
    #[arg(long, value_name = "ID")]
    creator: u32,
    /// Kind of market.
    #[arg(long, value_enum)]
    market_type: MarketTypeArg,
    /// Human-readable symbol, e.g. `BTC-PERP`.
    #[arg(long)]
    symbol: String,
    /// Number of outcomes (1 for perpetuals).
    #[arg(long, default_value_t = 1)]
    outcomes: u16,
}

#[derive(Args, Debug)]
struct StakeMarketArgs {
    /// Market id to stake.
    #[arg(long, value_name = "ID")]
    market: u32,
    /// Sponsor id providing the stake.
    #[arg(long, value_name = "ID")]
    sponsor: u32,
    /// Stake amount in raw scaled units (1.0 = 1_000_000).
    #[arg(long)]
    amount: i128,
}

/// Build the `RpcMethod` for the parsed subcommand. Control methods are signed
/// here, which is why this borrows `cli` for the key/nonce material.
fn build_method(cli: &Cli) -> anyhow::Result<RpcMethod> {
    Ok(match &cli.command {
        // ---- queries ----
        Command::GetNodeInfo => RpcMethod::GetNodeInfo,
        Command::GetPeers => RpcMethod::GetPeers,
        Command::GetMarkets(p) => RpcMethod::GetMarkets(p.to_params()),
        Command::GetMarket(a) => RpcMethod::GetMarket(MarketId::new(a.market)),
        Command::GetMarketBook(a) => RpcMethod::GetMarketBook(MarketId::new(a.market), a.depth),
        Command::GetMarketTrades(a) => {
            RpcMethod::GetMarketTrades(MarketId::new(a.market), a.page.to_params())
        }
        Command::GetMarketStatus(a) => RpcMethod::GetMarketStatus(MarketId::new(a.market)),
        Command::GetOracleStatus(a) => RpcMethod::GetOracleStatus(MarketId::new(a.market)),
        Command::GetCheckpoint(a) => RpcMethod::GetCheckpoint(a.height),
        Command::GetLatestCheckpoint => RpcMethod::GetLatestCheckpoint,
        Command::GetAccount(a) => RpcMethod::GetAccount(AccountId::new(a.account)),
        Command::GetAccountProof(a) => RpcMethod::GetAccountProof(AccountId::new(a.account)),
        Command::GetPosition(a) => {
            RpcMethod::GetPosition(AccountId::new(a.account), MarketId::new(a.market))
        }
        Command::GetOrders(a) => {
            RpcMethod::GetOrders(AccountId::new(a.account), a.page.to_params())
        }
        Command::GetExecutionReceipt(a) => RpcMethod::GetExecutionReceipt(a.hash),
        Command::GetDepositStatus(a) => RpcMethod::GetDepositStatus(a.hash),
        Command::GetWithdrawalStatus(a) => RpcMethod::GetWithdrawalStatus(a.hash),
        Command::GetNetworkStatus => RpcMethod::GetNetworkStatus,

        // ---- control methods ----
        Command::SubmitOrder(a) => {
            let params = SubmitOrderParams {
                account: AccountId::new(a.account),
                market: MarketId::new(a.market),
                side: a.side.into(),
                order_type: a.order_type.into(),
                price: Price::from_raw(a.price),
                quantity: Quantity::from_raw(a.quantity),
                time_in_force: a.time_in_force.into(),
                leverage: Ratio::from_raw(a.leverage),
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::SubmitOrder(meta, params)
        }
        Command::CancelOrder(a) => {
            let params = CancelOrderParams {
                account: AccountId::new(a.account),
                market: MarketId::new(a.market),
                order_id: OrderId::new(a.order_id),
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::CancelOrder(meta, params)
        }
        Command::CancelAll(a) => {
            let params = CancelAllParams {
                account: AccountId::new(a.account),
                market: a.market.map(MarketId::new),
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::CancelAll(meta, params)
        }
        Command::ReplaceOrder(a) => {
            let params = ReplaceOrderParams {
                account: AccountId::new(a.account),
                market: MarketId::new(a.market),
                order_id: OrderId::new(a.order_id),
                new_price: Price::from_raw(a.new_price),
                new_quantity: Quantity::from_raw(a.new_quantity),
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::ReplaceOrder(meta, params)
        }
        Command::AuthorizeSession(a) => {
            let scope = SessionScope {
                markets: a.market.iter().copied().map(MarketId::new).collect(),
                all_markets: a.all_markets,
                max_notional: Amount::from_raw(a.max_notional),
                max_leverage: Ratio::from_raw(a.max_leverage),
                allow_withdrawal: a.allow_withdrawal,
                allow_session_admin: a.allow_session_admin,
                allow_market_create: a.allow_market_create,
                expiry: a.expiry,
            };
            let params = AuthorizeSessionParams {
                account: AccountId::new(a.account),
                session_pubkey: a.session_pubkey,
                scope,
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::AuthorizeSession(meta, params)
        }
        Command::RevokeSession(a) => {
            let params = RevokeSessionParams {
                account: AccountId::new(a.account),
                session_pubkey: a.session_pubkey,
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::RevokeSession(meta, params)
        }
        Command::BindWallet(a) => {
            let params = BindWalletParams {
                account: AccountId::new(a.account),
                wallet: a.wallet,
                signature: a.proof.clone(),
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::BindWallet(meta, params)
        }
        Command::RequestWithdrawal(a) => {
            let params = RequestWithdrawalParams {
                account: AccountId::new(a.account),
                amount: Amount::from_raw(a.amount),
                destination: a.destination,
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::RequestWithdrawal(meta, params)
        }
        Command::CreateMarket(a) => {
            let params = CreateMarketParams {
                creator: AccountId::new(a.creator),
                market_type: a.market_type.into(),
                symbol: a.symbol.clone(),
                outcomes: a.outcomes,
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::CreateMarket(meta, params)
        }
        Command::StakeMarket(a) => {
            let params = StakeMarketParams {
                market: MarketId::new(a.market),
                sponsor: SponsorId::new(a.sponsor),
                amount: Amount::from_raw(a.amount),
            };
            let meta = control_meta(cli, &params.to_command())?;
            RpcMethod::StakeMarket(meta, params)
        }
    })
}

/// Sign the canonical bytes for `command` with the configured key, producing the
/// `ControlMeta` a write method carries.
fn control_meta(cli: &Cli, command: &RpcCommand) -> anyhow::Result<ControlMeta> {
    let (keypair, session_pubkey) = load_signer(cli)?;
    Ok(ControlMeta::signed(
        cli.client_id,
        cli.nonce,
        session_pubkey,
        &keypair,
        command,
    ))
}

/// Resolve the signing key: a delegated session key if `--session-key` is set,
/// otherwise the account root key from `--key`. Errors if neither is provided.
fn load_signer(cli: &Cli) -> anyhow::Result<(crypto::KeyPair, Option<[u8; 32]>)> {
    if let Some(path) = &cli.session_key {
        let keypair = load_keypair(path)?;
        let pubkey = keypair.public();
        Ok((keypair, Some(pubkey)))
    } else if let Some(path) = &cli.key {
        Ok((load_keypair(path)?, None))
    } else {
        anyhow::bail!(
            "this control command must be signed: pass a signing key with --key <SEED_FILE> \
             (or --session-key <SEED_FILE> for a delegated session key)"
        )
    }
}

/// Load an ed25519 keypair from a hex seed file (as written by `marketd keygen`).
fn load_keypair(path: &Path) -> anyhow::Result<crypto::KeyPair> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading key file {}: {e}", path.display()))?;
    let seed = parse_hex32(contents.trim())
        .map_err(|e| anyhow::anyhow!("parsing seed in {}: {e}", path.display()))?;
    Ok(crypto::KeyPair::from_seed(&seed))
}

/// Decode a hex string (optional `0x` prefix) to bytes.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(trimmed).map_err(|e| format!("invalid hex: {e}"))
}

/// Decode exactly 32 bytes from hex.
fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex_bytes(s)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("expected 32 bytes (64 hex chars), got {}", bytes.len()))
}

/// Decode exactly 20 bytes from hex.
fn parse_hex20(s: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex_bytes(s)?;
    <[u8; 20]>::try_from(bytes.as_slice())
        .map_err(|_| format!("expected 20 bytes (40 hex chars), got {}", bytes.len()))
}

/// Decode a 32-byte `Hash` from hex.
fn parse_hash(s: &str) -> Result<Hash, String> {
    Ok(Hash::from_bytes(parse_hex32(s)?))
}

/// Send one request over a fresh plaintext connection and print the response.
async fn send(cli: &Cli, method: RpcMethod) -> anyhow::Result<()> {
    let request = RpcRequest::new(cli.request_id, method);
    let response = rpc::server::round_trip(cli.target, &request)
        .await
        .map_err(|e| anyhow::anyhow!("rpc round-trip to {}: {e}", cli.target))?;
    render(response)
}

/// Print a successful payload, or surface a server error as a nonzero exit.
fn render(response: RpcResponse) -> anyhow::Result<()> {
    match response.result {
        Ok(ok) => {
            println!("{ok:#?}");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("server returned error: {e}")),
    }
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let method = build_method(&cli)?;
    send(&cli, method).await
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(dispatch(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_representative_commands() {
        let cases: Vec<&[&str]> = vec![
            &["dexos", "get-node-info"],
            &["dexos", "get-latest-checkpoint"],
            &[
                "dexos",
                "--target",
                "10.0.0.1:9000",
                "get-market",
                "--market",
                "1",
            ],
            &["dexos", "get-market-book", "--market", "2", "--depth", "10"],
            &["dexos", "get-orders", "--account", "3", "--limit", "50"],
            &[
                "dexos",
                "--key",
                "k.seed",
                "submit-order",
                "--account",
                "1",
                "--market",
                "1",
                "--side",
                "bid",
                "--price",
                "1000000",
                "--quantity",
                "500000",
            ],
            &[
                "dexos",
                "--key",
                "k.seed",
                "create-market",
                "--creator",
                "1",
                "--market-type",
                "perpetual",
                "--symbol",
                "BTC-PERP",
                "--outcomes",
                "1",
            ],
        ];
        for args in cases {
            assert!(Cli::try_parse_from(args).is_ok(), "should parse: {args:?}");
        }
    }

    #[test]
    fn rejects_bad_input_without_panic() {
        // Unknown market type.
        assert!(Cli::try_parse_from([
            "dexos",
            "create-market",
            "--creator",
            "1",
            "--market-type",
            "banana",
            "--symbol",
            "X",
            "--outcomes",
            "1",
        ])
        .is_err());
        // Non-numeric account.
        assert!(Cli::try_parse_from(["dexos", "get-account", "--account", "abc"]).is_err());
        // Malformed target address.
        assert!(
            Cli::try_parse_from(["dexos", "--target", "not-an-addr", "get-node-info"]).is_err()
        );
    }

    #[test]
    fn hex_parsing_round_trips_and_validates_length() {
        assert_eq!(parse_hex32(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(parse_hex32("ab").is_err()); // too short
        assert_eq!(parse_hex20(&"cd".repeat(20)).unwrap(), [0xcd; 20]);
        assert_eq!(parse_hash(&"00".repeat(32)).unwrap(), Hash::ZERO);
        assert_eq!(parse_hex_bytes("0xdead").unwrap(), vec![0xde, 0xad]);
        assert!(parse_hex_bytes("nothex").is_err());
    }

    #[test]
    fn control_command_requires_a_key() {
        let cli = Cli::try_parse_from(["dexos", "cancel-all", "--account", "1"]).unwrap();
        let err = build_method(&cli).expect_err("must require a signing key");
        assert!(format!("{err:#}").contains("signed"), "{err:#}");
    }

    #[test]
    fn query_command_needs_no_key() {
        let cli = Cli::try_parse_from(["dexos", "get-market", "--market", "1"]).unwrap();
        assert!(build_method(&cli).is_ok(), "queries are unsigned");
    }

    #[test]
    fn signed_control_envelope_verifies_against_its_command() {
        // Prove the CLI's signing path produces an envelope the server would accept,
        // without needing a live socket: sign the lowered command and verify it.
        let keypair = crypto::KeyPair::from_seed(&[7u8; 32]);
        let params = CancelAllParams {
            account: AccountId::new(1),
            market: None,
        };
        let command = params.to_command();
        let meta = ControlMeta::signed(1, 0, None, &keypair, &command);
        assert!(meta.verify_signature(&command).is_ok());
        // The signer is the root key (no session delegation).
        assert_eq!(meta.signer, keypair.public());
        assert_eq!(meta.session_pubkey, None);
    }
}
