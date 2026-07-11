//! The deterministic command set, execution receipts, and the engine trait.

use serde::{Deserialize, Serialize};
use types::{
    AccountId, Hash, MarketId, MarketType, OrderId, OrderType, Price, Quantity, SequenceNumber,
    Side, TimeInForce,
};

use crate::error::ExecutionError;

/// Network timestamp in nanoseconds (assigned by the sequencer, part of the log).
pub type Timestamp = u64;

/// Create a new internal account, funded with `initial_collateral` credited from
/// an already-verified source (test / genesis). Real funds arrive via deposits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccount {
    /// Optional genesis collateral (micro-units, non-negative).
    pub initial_collateral: types::Amount,
}

/// Bind an external wallet to an account (EVM/SVM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindWallet {
    /// Account to bind to.
    pub account: AccountId,
    /// External chain id.
    pub chain_id: u32,
    /// Wallet address bytes.
    pub address: Vec<u8>,
}

/// Authorize a scoped trading session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizeSession {
    /// Master account.
    pub account: AccountId,
    /// Session public key (ed25519).
    pub session_key: [u8; 32],
    /// Markets this session may trade (empty == all).
    pub allowed_markets: Vec<MarketId>,
    /// Max per-order notional (micro-units).
    pub max_notional: types::Amount,
    /// Session expiry (timestamp).
    pub expires_at: Timestamp,
    /// Inclusive nonce range start.
    pub nonce_start: u64,
    /// Inclusive nonce range end.
    pub nonce_end: u64,
}

/// Revoke a session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeSession {
    /// Master account.
    pub account: AccountId,
    /// Session key to revoke.
    pub session_key: [u8; 32],
}

/// Credit a verified external deposit. Idempotent on the source coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCredit {
    /// Source chain id.
    pub source_chain: u32,
    /// Source transaction id bytes.
    pub source_tx: Vec<u8>,
    /// Source event index within the transaction.
    pub source_event_index: u32,
    /// Destination account.
    pub account: AccountId,
    /// Amount to credit (micro-units, non-negative).
    pub amount: types::Amount,
}

/// Request a withdrawal: reserves/debits funds before custody signs externally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestWithdrawal {
    /// Withdrawing account.
    pub account: AccountId,
    /// Amount (micro-units, non-negative).
    pub amount: types::Amount,
    /// Monotonic per-account nonce.
    pub nonce: u64,
    /// Destination chain id.
    pub destination_chain: u32,
    /// Destination address bytes.
    pub destination_address: Vec<u8>,
}

/// Finalize a previously requested withdrawal (custody signed & broadcast).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeWithdrawal {
    /// Deterministic withdrawal id.
    pub withdrawal_id: u64,
}

/// Register a market (Phase 1 minimal registry; full lifecycle/sponsorship in Phase 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMarket {
    /// Market id.
    pub market: MarketId,
    /// Market type.
    pub market_type: MarketType,
    /// Number of outcomes (>=2 for prediction/multi-outcome; 1 for perp).
    pub outcomes: u16,
    /// Initial mark price.
    pub mark_price: Price,
}

/// Set a market's mark price (minimal oracle input; native oracle lands in Phase 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetMarkPrice {
    /// Market id.
    pub market: MarketId,
    /// New mark price.
    pub price: Price,
}

/// Place an order into a market book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceOrder {
    /// Owning account.
    pub account: AccountId,
    /// Target market.
    pub market: MarketId,
    /// Client-assigned order id.
    pub order_id: OrderId,
    /// Side.
    pub side: Side,
    /// Order type.
    pub order_type: OrderType,
    /// Time in force.
    pub tif: TimeInForce,
    /// Limit price.
    pub price: Price,
    /// Quantity.
    pub quantity: Quantity,
    /// Idempotency key.
    pub client_id: u64,
    /// Reduce-only flag.
    pub reduce_only: bool,
}

/// Cancel a resting order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelOrder {
    /// Market.
    pub market: MarketId,
    /// Order id.
    pub order_id: OrderId,
}

/// Cancel all of an account's resting orders in a market.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelAll {
    /// Market.
    pub market: MarketId,
    /// Account.
    pub account: AccountId,
}

/// Atomically cancel-replace a resting order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaceOrder {
    /// Market.
    pub market: MarketId,
    /// Order id.
    pub order_id: OrderId,
    /// New price.
    pub price: Price,
    /// New quantity.
    pub quantity: Quantity,
}

/// Mint or redeem `count` complete sets in a market.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteSetOp {
    /// Account.
    pub account: AccountId,
    /// Market.
    pub market: MarketId,
    /// Number of complete sets (non-negative micro-units of stablecoin locked).
    pub count: types::Amount,
}

/// Upgrade the active protocol version. Monotonic: the target must exceed the
/// current version. Later commands can be gated on the active version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolUpgrade {
    /// The new protocol version to activate.
    pub target_version: u16,
}

/// The deterministic command set applied by the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Command {
    /// Create an account.
    CreateAccount(CreateAccount),
    /// Bind an external wallet.
    BindWallet(BindWallet),
    /// Authorize a session key.
    AuthorizeSession(AuthorizeSession),
    /// Revoke a session key.
    RevokeSession(RevokeSession),
    /// Credit a verified deposit.
    DepositCredit(DepositCredit),
    /// Request a withdrawal.
    RequestWithdrawal(RequestWithdrawal),
    /// Finalize a withdrawal.
    FinalizeWithdrawal(FinalizeWithdrawal),
    /// Register a market.
    CreateMarket(CreateMarket),
    /// Set a mark price.
    SetMarkPrice(SetMarkPrice),
    /// Place an order.
    PlaceOrder(PlaceOrder),
    /// Cancel an order.
    CancelOrder(CancelOrder),
    /// Cancel all orders in a market.
    CancelAll(CancelAll),
    /// Replace an order.
    ReplaceOrder(ReplaceOrder),
    /// Mint complete sets.
    MintCompleteSet(CompleteSetOp),
    /// Redeem complete sets.
    RedeemCompleteSet(CompleteSetOp),
    /// Upgrade the protocol version.
    ProtocolUpgrade(ProtocolUpgrade),
}

impl Command {
    /// Stable numeric tag for the append-only log's `command_type` field.
    pub fn command_type(&self) -> u16 {
        match self {
            Command::CreateAccount(_) => 1,
            Command::BindWallet(_) => 2,
            Command::AuthorizeSession(_) => 3,
            Command::RevokeSession(_) => 4,
            Command::DepositCredit(_) => 5,
            Command::RequestWithdrawal(_) => 6,
            Command::FinalizeWithdrawal(_) => 7,
            Command::CreateMarket(_) => 8,
            Command::SetMarkPrice(_) => 9,
            Command::PlaceOrder(_) => 10,
            Command::CancelOrder(_) => 11,
            Command::CancelAll(_) => 12,
            Command::ReplaceOrder(_) => 13,
            Command::MintCompleteSet(_) => 14,
            Command::RedeemCompleteSet(_) => 15,
            Command::ProtocolUpgrade(_) => 16,
        }
    }
}

/// What a command did, for the execution receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptKind {
    /// A new account was created with this id.
    AccountCreated(AccountId),
    /// Funds credited (deposit / genesis).
    Credited(AccountId, types::Amount),
    /// A withdrawal was requested with this deterministic id.
    WithdrawalRequested(u64),
    /// A withdrawal was finalized.
    WithdrawalFinalized(u64),
    /// Session authorized / revoked.
    SessionUpdated,
    /// A market was registered / updated.
    MarketUpdated(MarketId),
    /// An order produced `filled` quantity and rested (or not).
    OrderApplied {
        /// Filled quantity.
        filled: Quantity,
        /// Whether a remainder rested on the book.
        rested: bool,
    },
    /// An order/orders were cancelled (count).
    Cancelled(u32),
    /// Complete sets minted/redeemed.
    CompleteSet(types::Amount),
    /// A wallet was bound.
    WalletBound,
    /// The protocol was upgraded to this version.
    ProtocolUpgraded(u16),
}

/// The result of applying one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReceipt {
    /// The sequence this command was applied at.
    pub sequence: u64,
    /// What happened.
    pub kind: ReceiptKind,
    /// State root after applying the command.
    pub state_root: Hash,
}

/// A single-writer deterministic state machine.
pub trait DeterministicEngine {
    /// Apply one sequenced command, returning a receipt or a typed error.
    fn execute(
        &mut self,
        sequence: SequenceNumber,
        command: Command,
    ) -> Result<ExecutionReceipt, ExecutionError>;
    /// The current committed state root.
    fn state_root(&self) -> Hash;
}
