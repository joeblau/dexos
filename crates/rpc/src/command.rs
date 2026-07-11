//! Control-method parameters, the canonical [`Command`] they translate into,
//! and the acknowledgement returned to callers.

use serde::{Deserialize, Serialize};
use types::{
    AccountId, Amount, Hash, MarketId, MarketType, OrderId, OrderType, Price, Quantity, Ratio,
    Side, SponsorId, TimeInForce,
};

use crate::wire::FinalityStatus;

/// Idempotency and authorization metadata attached to every control request.
///
/// A `(client_id, nonce)` pair identifies a command exactly once: a retransmit
/// with the same pair must execute at most once, while a new nonce is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ControlMeta {
    /// Stable per-client identifier.
    pub client_id: u64,
    /// Per-client monotonically increasing nonce.
    pub nonce: u64,
    /// Session key authorizing the command, if delegated.
    pub session_pubkey: Option<[u8; 32]>,
}

/// Parameters for `submit_order`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitOrderParams {
    /// Owning account.
    pub account: AccountId,
    /// Target market.
    pub market: MarketId,
    /// Order side.
    pub side: Side,
    /// Execution style.
    pub order_type: OrderType,
    /// Limit price.
    pub price: Price,
    /// Quantity.
    pub quantity: Quantity,
    /// Time-in-force.
    pub time_in_force: TimeInForce,
    /// Requested leverage for margin checks.
    pub leverage: Ratio,
}

/// Parameters for `cancel_order`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelOrderParams {
    /// Owning account.
    pub account: AccountId,
    /// Market of the order.
    pub market: MarketId,
    /// Order to cancel.
    pub order_id: OrderId,
}

/// Parameters for `cancel_all`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelAllParams {
    /// Owning account.
    pub account: AccountId,
    /// Restrict to one market, or `None` for all markets.
    pub market: Option<MarketId>,
}

/// Parameters for `replace_order`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaceOrderParams {
    /// Owning account.
    pub account: AccountId,
    /// Market of the order.
    pub market: MarketId,
    /// Order to replace.
    pub order_id: OrderId,
    /// New price.
    pub new_price: Price,
    /// New quantity.
    pub new_quantity: Quantity,
}

/// Parameters for `submit_basket`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasketParams {
    /// Owning account.
    pub account: AccountId,
    /// Constituent orders, applied atomically.
    pub orders: Vec<SubmitOrderParams>,
}

/// The scope a session key is authorized to act within.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionScope {
    /// Authorized markets. Empty means all markets.
    pub markets: Vec<MarketId>,
    /// Maximum per-command notional.
    pub max_notional: Amount,
    /// Maximum leverage.
    pub max_leverage: Ratio,
    /// Whether the session may request withdrawals.
    pub allow_withdrawal: bool,
    /// Session expiry (unix millis).
    pub expiry: u64,
}

/// Parameters for `authorize_session`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizeSessionParams {
    /// Authorizing account.
    pub account: AccountId,
    /// Session public key.
    pub session_pubkey: [u8; 32],
    /// Scope granted to the session.
    pub scope: SessionScope,
}

/// Parameters for `revoke_session`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeSessionParams {
    /// Authorizing account.
    pub account: AccountId,
    /// Session public key to revoke.
    pub session_pubkey: [u8; 32],
}

/// Parameters for `bind_wallet`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindWalletParams {
    /// Account to bind.
    pub account: AccountId,
    /// External wallet address (20-byte EVM address).
    pub wallet: [u8; 20],
    /// Signature proving control of the wallet.
    pub signature: Vec<u8>,
}

/// Parameters for `request_withdrawal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestWithdrawalParams {
    /// Withdrawing account.
    pub account: AccountId,
    /// Amount to withdraw.
    pub amount: Amount,
    /// Destination address (20-byte EVM address).
    pub destination: [u8; 20],
}

/// Parameters for `create_market`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMarketParams {
    /// Creating account.
    pub creator: AccountId,
    /// Kind of market.
    pub market_type: MarketType,
    /// Human-readable symbol.
    pub symbol: String,
    /// Number of outcomes (1 for perpetuals).
    pub outcomes: u16,
}

/// Parameters for `stake_market`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeMarketParams {
    /// Market to stake.
    pub market: MarketId,
    /// Sponsor providing the stake.
    pub sponsor: SponsorId,
    /// Stake amount.
    pub amount: Amount,
}

/// The canonical command a control request lowers to. This is the shape the
/// live engine consumes; the RPC layer stays decoupled from execution by
/// producing it rather than depending on the execution crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// Place a new order.
    PlaceOrder {
        /// Owning account.
        account: AccountId,
        /// Market.
        market: MarketId,
        /// Side.
        side: Side,
        /// Execution style.
        order_type: OrderType,
        /// Price.
        price: Price,
        /// Quantity.
        quantity: Quantity,
        /// Time-in-force.
        time_in_force: TimeInForce,
        /// Requested leverage.
        leverage: Ratio,
    },
    /// Cancel a single order.
    CancelOrder {
        /// Owning account.
        account: AccountId,
        /// Market.
        market: MarketId,
        /// Order id.
        order_id: OrderId,
    },
    /// Cancel all orders, optionally scoped to a market.
    CancelAll {
        /// Owning account.
        account: AccountId,
        /// Market or all.
        market: Option<MarketId>,
    },
    /// Replace an order's price/quantity.
    ReplaceOrder {
        /// Owning account.
        account: AccountId,
        /// Market.
        market: MarketId,
        /// Order id.
        order_id: OrderId,
        /// New price.
        price: Price,
        /// New quantity.
        quantity: Quantity,
    },
    /// Submit a basket of orders atomically.
    Basket {
        /// Owning account.
        account: AccountId,
        /// Constituent orders.
        orders: Vec<SubmitOrderParams>,
    },
    /// Authorize a session key.
    AuthorizeSession {
        /// Account.
        account: AccountId,
        /// Session key.
        session_pubkey: [u8; 32],
        /// Granted scope.
        scope: SessionScope,
    },
    /// Revoke a session key.
    RevokeSession {
        /// Account.
        account: AccountId,
        /// Session key.
        session_pubkey: [u8; 32],
    },
    /// Bind an external wallet.
    BindWallet {
        /// Account.
        account: AccountId,
        /// Wallet address.
        wallet: [u8; 20],
        /// Signature.
        signature: Vec<u8>,
    },
    /// Request a withdrawal.
    Withdraw {
        /// Account.
        account: AccountId,
        /// Amount.
        amount: Amount,
        /// Destination.
        destination: [u8; 20],
    },
    /// Create a market.
    CreateMarket {
        /// Creator.
        creator: AccountId,
        /// Market type.
        market_type: MarketType,
        /// Symbol.
        symbol: String,
        /// Outcomes.
        outcomes: u16,
    },
    /// Stake a market.
    StakeMarket {
        /// Market.
        market: MarketId,
        /// Sponsor.
        sponsor: SponsorId,
        /// Amount.
        amount: Amount,
    },
}

impl Command {
    /// The account whose funds/positions the command acts on, when the command
    /// is account-scoped. Returns `None` for commands that carry no owning
    /// account (e.g. [`Command::StakeMarket`], which is sponsor-scoped).
    pub fn account(&self) -> Option<AccountId> {
        match self {
            Command::PlaceOrder { account, .. }
            | Command::CancelOrder { account, .. }
            | Command::CancelAll { account, .. }
            | Command::ReplaceOrder { account, .. }
            | Command::Basket { account, .. }
            | Command::AuthorizeSession { account, .. }
            | Command::RevokeSession { account, .. }
            | Command::BindWallet { account, .. }
            | Command::Withdraw { account, .. } => Some(*account),
            Command::CreateMarket { creator, .. } => Some(*creator),
            Command::StakeMarket { .. } => None,
        }
    }
}

impl SubmitOrderParams {
    /// Lower to the canonical [`Command::PlaceOrder`].
    pub fn to_command(&self) -> Command {
        Command::PlaceOrder {
            account: self.account,
            market: self.market,
            side: self.side,
            order_type: self.order_type,
            price: self.price,
            quantity: self.quantity,
            time_in_force: self.time_in_force,
            leverage: self.leverage,
        }
    }
}

impl CancelOrderParams {
    /// Lower to [`Command::CancelOrder`].
    pub fn to_command(&self) -> Command {
        Command::CancelOrder {
            account: self.account,
            market: self.market,
            order_id: self.order_id,
        }
    }
}

impl CancelAllParams {
    /// Lower to [`Command::CancelAll`].
    pub fn to_command(&self) -> Command {
        Command::CancelAll {
            account: self.account,
            market: self.market,
        }
    }
}

impl ReplaceOrderParams {
    /// Lower to [`Command::ReplaceOrder`].
    pub fn to_command(&self) -> Command {
        Command::ReplaceOrder {
            account: self.account,
            market: self.market,
            order_id: self.order_id,
            price: self.new_price,
            quantity: self.new_quantity,
        }
    }
}

impl BasketParams {
    /// Lower to [`Command::Basket`].
    pub fn to_command(&self) -> Command {
        Command::Basket {
            account: self.account,
            orders: self.orders.clone(),
        }
    }
}

impl AuthorizeSessionParams {
    /// Lower to [`Command::AuthorizeSession`].
    pub fn to_command(&self) -> Command {
        Command::AuthorizeSession {
            account: self.account,
            session_pubkey: self.session_pubkey,
            scope: self.scope.clone(),
        }
    }
}

impl RevokeSessionParams {
    /// Lower to [`Command::RevokeSession`].
    pub fn to_command(&self) -> Command {
        Command::RevokeSession {
            account: self.account,
            session_pubkey: self.session_pubkey,
        }
    }
}

impl BindWalletParams {
    /// Lower to [`Command::BindWallet`].
    pub fn to_command(&self) -> Command {
        Command::BindWallet {
            account: self.account,
            wallet: self.wallet,
            signature: self.signature.clone(),
        }
    }
}

impl RequestWithdrawalParams {
    /// Lower to [`Command::Withdraw`].
    pub fn to_command(&self) -> Command {
        Command::Withdraw {
            account: self.account,
            amount: self.amount,
            destination: self.destination,
        }
    }
}

impl CreateMarketParams {
    /// Lower to [`Command::CreateMarket`].
    pub fn to_command(&self) -> Command {
        Command::CreateMarket {
            creator: self.creator,
            market_type: self.market_type,
            symbol: self.symbol.clone(),
            outcomes: self.outcomes,
        }
    }
}

impl StakeMarketParams {
    /// Lower to [`Command::StakeMarket`].
    pub fn to_command(&self) -> Command {
        Command::StakeMarket {
            market: self.market,
            sponsor: self.sponsor,
            amount: self.amount,
        }
    }
}

/// The acknowledgement returned by every control method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandAck {
    /// Canonical hash of the accepted command.
    pub command_hash: Hash,
    /// Finality status at the moment of acknowledgement (always [`FinalityStatus::Accepted`]
    /// for a freshly ingested command).
    pub finality: FinalityStatus,
    /// Resulting order id, if any.
    pub order_id: Option<OrderId>,
    /// Affected market, if any.
    pub market_id: Option<MarketId>,
}
