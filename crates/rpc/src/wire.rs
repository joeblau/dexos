//! Wire data types shared by requests, responses, and stream events.
//!
//! Every struct here is integer-only (fixed-point scalars from `types`); no
//! floating-point value ever crosses the RPC surface. All types are
//! `Serialize`/`Deserialize` for the compact binary codec and `Clone` so they
//! can be fanned out over broadcast channels.

use crypto::QuorumCertificate;
use serde::{Deserialize, Serialize};
use types::{
    AccountId, Amount, Hash, MarketId, MarketLifecycle, MarketType, OracleHealth, OrderId,
    OrderType, Price, Quantity, Ratio, SequenceNumber, Side, StateRoot, TimeInForce,
};

/// Operating mode of the RPC surface. Controls whether write methods are
/// accepted and whether streamed data is locally verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcMode {
    /// Full node: queries and writes accepted, data locally verified.
    Full,
    /// Full node in read-only mode: queries only.
    ReadOnly,
    /// Light node: queries only, data carries an explicit verification status.
    Light,
}

impl RpcMode {
    /// Whether control (write) methods are accepted in this mode.
    #[inline]
    pub const fn allows_writes(self) -> bool {
        matches!(self, RpcMode::Full)
    }

    /// Whether streamed/queried data must carry a verification status because it
    /// was not produced by a locally trusted full state.
    #[inline]
    pub const fn is_light(self) -> bool {
        matches!(self, RpcMode::Light)
    }
}

/// Whether a piece of data was verified against local trusted state, or (for a
/// light node) proven / left unverified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Produced by a trusted local full state.
    Verified,
    /// Relayed to a light client and not independently checked.
    Unverified,
    /// A cryptographic proof was supplied and validated.
    ProofValid,
    /// A cryptographic proof was supplied but failed validation.
    ProofInvalid,
}

/// Per-command finality lifecycle. Monotonic: a command only ever advances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    /// Ingested and admitted to the mempool.
    Accepted,
    /// Applied against the execution state (locally observed).
    Executed,
    /// Included in a checkpoint that has been witnessed by validators.
    Certified,
    /// Included in a checkpoint with quorum finality; irreversible.
    Finalized,
}

/// Pagination bound for list queries. The server clamps `limit` to its
/// configured page size so a caller can never force an unbounded response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageParams {
    /// Offset into the result set.
    pub offset: u32,
    /// Requested maximum number of items (clamped by the server).
    pub limit: u32,
}

impl Default for PageParams {
    fn default() -> Self {
        PageParams {
            offset: 0,
            limit: 100,
        }
    }
}

/// Identity and status of the serving node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node public identity key.
    pub node_id: [u8; 32],
    /// Chain / network identifier.
    pub chain_id: u64,
    /// RPC protocol version.
    pub protocol_version: u16,
    /// Operating mode.
    pub mode: RpcMode,
    /// Latest local block height.
    pub height: u64,
}

/// A connected peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer public identity key.
    pub peer_id: [u8; 32],
    /// Dialable address.
    pub address: String,
    /// Whether the peer is currently connected.
    pub connected: bool,
    /// Observed round-trip latency in milliseconds.
    pub latency_ms: u32,
}

/// A compact market summary for listings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketSummary {
    /// Market identifier.
    pub market_id: MarketId,
    /// Market kind.
    pub market_type: MarketType,
    /// Lifecycle state.
    pub lifecycle: MarketLifecycle,
}

/// Full market metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketDetail {
    /// Summary fields.
    pub summary: MarketSummary,
    /// Minimum price increment.
    pub tick_size: Price,
    /// Minimum quantity increment.
    pub lot_size: Quantity,
    /// Human-readable symbol.
    pub symbol: String,
    /// Number of possible outcomes (1 for perpetuals).
    pub outcomes: u16,
}

/// A single aggregated price level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookLevel {
    /// Price of the level.
    pub price: Price,
    /// Total resting quantity at the level.
    pub quantity: Quantity,
}

/// An order-book snapshot to `depth` levels per side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Book {
    /// Market the book belongs to.
    pub market_id: MarketId,
    /// Sequence number of the last update reflected in this snapshot.
    pub sequence: SequenceNumber,
    /// Bid levels, best first.
    pub bids: Vec<BookLevel>,
    /// Ask levels, best first.
    pub asks: Vec<BookLevel>,
}

/// An incremental book update. `quantity == ZERO` removes the level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookDelta {
    /// Market the delta applies to.
    pub market_id: MarketId,
    /// Side of the book.
    pub side: Side,
    /// Price of the affected level.
    pub price: Price,
    /// New total quantity at the level (`ZERO` = removed).
    pub quantity: Quantity,
}

/// A public trade print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trade {
    /// Market of the trade.
    pub market_id: MarketId,
    /// Aggressing order identifier.
    pub order_id: OrderId,
    /// Execution price.
    pub price: Price,
    /// Execution quantity.
    pub quantity: Quantity,
    /// Aggressor side.
    pub side: Side,
    /// Wall-clock timestamp (unix millis).
    pub timestamp: u64,
}

/// Live market statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketStatus {
    /// Market identifier.
    pub market_id: MarketId,
    /// Lifecycle state.
    pub lifecycle: MarketLifecycle,
    /// Current mark price.
    pub mark_price: Price,
    /// Current index / oracle price.
    pub index_price: Price,
    /// Current funding rate.
    pub funding_rate: Ratio,
    /// Open interest in contracts.
    pub open_interest: Quantity,
    /// Oracle health for this market.
    pub oracle_health: OracleHealth,
}

/// Oracle feed status for a market.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleStatus {
    /// Market identifier.
    pub market_id: MarketId,
    /// Health state.
    pub health: OracleHealth,
    /// Latest oracle price.
    pub price: Price,
    /// Number of contributing sources.
    pub sources: u32,
    /// Last update timestamp (unix millis).
    pub last_update: u64,
}

/// A checkpoint header, optionally carrying its quorum certificate so a light
/// client can verify quorum finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint height.
    pub height: u64,
    /// State root committed by this checkpoint.
    pub new_state_root: StateRoot,
    /// Previous checkpoint's state root.
    pub prev_state_root: StateRoot,
    /// Timestamp (unix millis).
    pub timestamp: u64,
    /// Quorum certificate for the checkpoint, present once finalized.
    pub quorum_certificate: Option<QuorumCertificate>,
}

impl Checkpoint {
    /// Whether this checkpoint carries quorum finality.
    #[inline]
    pub fn is_finalized(&self) -> bool {
        self.quorum_certificate.is_some()
    }
}

/// An account's on-chain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Account identifier.
    pub account_id: AccountId,
    /// Collateral balance.
    pub balance: Amount,
    /// Total account equity (balance + unrealized pnl).
    pub equity: Amount,
    /// Replay-protection nonce.
    pub nonce: u64,
}

/// A Merkle inclusion proof for an account leaf against a checkpoint state root.
///
/// Deliberately carries **no** server-asserted verification status: every
/// field here is supplied by the serving node, so any embedded status would be
/// an unverifiable trust claim, not evidence. Clients derive the status
/// locally by obtaining the state root from a quorum-certified [`Checkpoint`]
/// at `checkpoint_height` and calling [`AccountProof::verify_against`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProof {
    /// Account the proof is for.
    pub account_id: AccountId,
    /// Leaf hash committed for the account.
    pub leaf: Hash,
    /// Leaf index in the account tree.
    pub leaf_index: u64,
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<Hash>,
    /// Height of the checkpoint the proof is anchored to.
    pub checkpoint_height: u64,
    /// State root the server claims the proof is anchored to. Informational:
    /// clients verify against a quorum-certified root, never this field.
    pub state_root: StateRoot,
}

impl AccountProof {
    /// Verify this proof against a checkpoint's state root, returning the
    /// resulting [`VerificationStatus`]. This is the sole way to obtain a
    /// status for an account proof; pass a root taken from a quorum-certified
    /// [`Checkpoint`], not one supplied by the serving node. Never panics: an
    /// out-of-range leaf index simply yields `ProofInvalid`.
    pub fn verify_against(&self, state_root: StateRoot) -> VerificationStatus {
        let Ok(index) = usize::try_from(self.leaf_index) else {
            return VerificationStatus::ProofInvalid;
        };
        if crypto::verify_proof(state_root, index, self.leaf, &self.siblings) {
            VerificationStatus::ProofValid
        } else {
            VerificationStatus::ProofInvalid
        }
    }
}

/// An open position.
///
/// The side of the position is *not* a separate field: it is fully determined
/// by the sign of [`size`](Position::size). Carrying a redundant side enum
/// would let the two encodings disagree on the wire (e.g. a negative size
/// labelled as a long), so the contradictory state is made unrepresentable
/// instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    /// Owning account.
    pub account_id: AccountId,
    /// Market of the position.
    pub market_id: MarketId,
    /// Signed exposure: positive = long, negative = short. Mirrors the
    /// canonical internal model (`risk::PerpPosition::net_qty`), which is the
    /// single source of truth for position direction.
    pub size: Quantity,
    /// Volume-weighted entry price.
    pub entry_price: Price,
    /// Unrealized profit and loss.
    pub unrealized_pnl: Amount,
}

/// A resting or historical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// Order identifier.
    pub order_id: OrderId,
    /// Owning account.
    pub account_id: AccountId,
    /// Market of the order.
    pub market_id: MarketId,
    /// Order side.
    pub side: Side,
    /// Order execution style.
    pub order_type: OrderType,
    /// Limit price (ignored for market orders).
    pub price: Price,
    /// Original quantity.
    pub quantity: Quantity,
    /// Cumulative filled quantity.
    pub filled: Quantity,
    /// Time-in-force policy.
    pub time_in_force: TimeInForce,
}

/// A single fill within an execution receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fill {
    /// Fill price.
    pub price: Price,
    /// Fill quantity.
    pub quantity: Quantity,
}

/// The receipt for an executed command, carrying its finality lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Canonical hash of the command.
    pub command_hash: Hash,
    /// Resulting order id, if the command created one.
    pub order_id: Option<OrderId>,
    /// Fills produced.
    pub fills: Vec<Fill>,
    /// Current finality status.
    pub finality: FinalityStatus,
    /// Height of the checkpoint that includes the command, once known.
    pub checkpoint_height: Option<u64>,
    /// Verification status (relevant for light nodes).
    pub verification_status: VerificationStatus,
}

/// Bridge deposit progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeStatus {
    /// Observed but not yet confirmed.
    Pending,
    /// Confirmed and credited.
    Confirmed,
    /// Rejected / reverted.
    Failed,
}

/// Status of an inbound deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositStatus {
    /// Deposit transaction hash.
    pub tx_hash: Hash,
    /// Credited account.
    pub account_id: AccountId,
    /// Amount.
    pub amount: Amount,
    /// Progress.
    pub status: BridgeStatus,
    /// Source-chain confirmations observed.
    pub confirmations: u32,
}

/// Status of an outbound withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalStatus {
    /// Withdrawal request hash.
    pub request_hash: Hash,
    /// Requesting account.
    pub account_id: AccountId,
    /// Amount.
    pub amount: Amount,
    /// Progress.
    pub status: BridgeStatus,
    /// Finality of the enclosing checkpoint (a withdrawal is never reported
    /// `Confirmed` before its checkpoint reaches `Finalized`).
    pub finality: FinalityStatus,
}

/// Network / sync status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStatus {
    /// Number of connected peers.
    pub peer_count: u32,
    /// Latest local height.
    pub height: u64,
    /// Latest finalized height.
    pub finalized_height: u64,
    /// Whether the node is still catching up.
    pub syncing: bool,
}

/// Mark-price update for a market.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkPrice {
    /// Market identifier.
    pub market_id: MarketId,
    /// Mark price.
    pub price: Price,
}

/// Oracle-price update for a market.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePrice {
    /// Market identifier.
    pub market_id: MarketId,
    /// Oracle price.
    pub price: Price,
    /// Oracle health.
    pub health: OracleHealth,
}

/// Funding update for a market.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Funding {
    /// Market identifier.
    pub market_id: MarketId,
    /// Current funding rate.
    pub rate: Ratio,
    /// Timestamp (unix millis).
    pub timestamp: u64,
}

/// A market lifecycle transition event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketLifecycleEvent {
    /// Market identifier.
    pub market_id: MarketId,
    /// New lifecycle state.
    pub lifecycle: MarketLifecycle,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire form of [`AccountProof`] round-trips through the codec and
    /// carries no verification status: validity is established solely by the
    /// client calling [`AccountProof::verify_against`] with a trusted root.
    #[test]
    fn account_proof_round_trips_without_server_status() {
        let proof = AccountProof {
            account_id: AccountId::new(7),
            leaf: Hash::from_bytes([7u8; 32]),
            leaf_index: 3,
            siblings: vec![Hash::from_bytes([1u8; 32]), Hash::from_bytes([2u8; 32])],
            checkpoint_height: 42,
            state_root: Hash::from_bytes([9u8; 32]),
        };
        let bytes = codec::encode(&proof).unwrap();
        let back: AccountProof = codec::decode(&bytes).unwrap();
        assert_eq!(proof, back);
    }

    /// Issue #442: a [`Position`] carries direction solely as the sign of
    /// `size` — there is no separable `side` field left to disagree with the
    /// sign, so a payload like "negative size labelled long" is
    /// unrepresentable. Both a long (positive) and a short (negative)
    /// position round-trip through the codec, and the exhaustive
    /// destructuring below is the compile-time proof that no extra field
    /// (such as the removed `side`) exists on the struct.
    #[test]
    fn position_side_is_derived_from_signed_size() {
        let long = Position {
            account_id: AccountId::new(1),
            market_id: MarketId::new(2),
            size: Quantity::from_raw(5_000_000),
            entry_price: Price::ONE,
            unrealized_pnl: Amount::ZERO,
        };
        let bytes = codec::encode(&long).unwrap();
        let back: Position = codec::decode(&bytes).unwrap();
        assert_eq!(long, back);

        // Exhaustive pattern: compilation fails if a `side` field (or any
        // other field) is ever reintroduced.
        let Position {
            account_id: _,
            market_id: _,
            size,
            entry_price: _,
            unrealized_pnl: _,
        } = back;
        assert!(size.raw() > 0, "positive size reads as long exposure");

        let short = Position {
            size: Quantity::from_raw(-5_000_000),
            ..long
        };
        let bytes = codec::encode(&short).unwrap();
        let back: Position = codec::decode(&bytes).unwrap();
        assert_eq!(short, back);
        assert!(back.size.raw() < 0, "negative size reads as short exposure");
    }

    /// An out-of-range leaf index yields `ProofInvalid` instead of panicking.
    #[test]
    fn verify_against_rejects_out_of_range_leaf_index() {
        let proof = AccountProof {
            account_id: AccountId::new(1),
            leaf: Hash::from_bytes([1u8; 32]),
            leaf_index: u64::MAX,
            siblings: vec![],
            checkpoint_height: 0,
            state_root: Hash::ZERO,
        };
        assert_eq!(
            proof.verify_against(Hash::ZERO),
            VerificationStatus::ProofInvalid
        );
    }
}
