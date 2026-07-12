// Hand-authored wire types mirroring `crates/proto/src/wire.rs`.
//
// typeshare is deliberately NOT used (it cannot model the tuple-variant enums,
// and pulling its attribute into `types` trips scripts/check-core-deps.sh).
// Instead these interfaces exist purely for DX; their SHAPE is guarded at
// RUNTIME by `test/poc.test.ts`, which decodes Rust-produced golden bytes via
// the wasm core and deep-equals the result against conformance/vectors.json — a
// stronger, byte-level drift gate than a static type diff.
//
// Numeric discipline (enforced by eslint's no-restricted-syntax money rule):
//   * u16 / u32 identifiers (MarketId, AccountId, counts)  -> number
//   * i64 / u64 scaled or wide values (Price, Quantity, Ratio, OrderId,
//     SequenceNumber, timestamps)                          -> bigint
//   * i128 money (Amount)                                  -> string (decimal)
//   * fixed byte arrays ([u8; N])                          -> Uint8Array
// Money-named fields are NEVER `number`.

/** 32-byte hash / root / id, hex-agnostic (raw bytes). */
export type Bytes32 = Uint8Array;

export type MarketType = "spot" | "perp" | "prediction";
export type MarketLifecycle =
  | "pending"
  | "active"
  | "halted"
  | "settled"
  | "expired";
export type OracleHealth = "healthy" | "degraded" | "stale";
export type Side = "buy" | "sell";
export type OrderType = "limit" | "market";
export type TimeInForce = "gtc" | "ioc" | "fok" | "post_only";
export type FinalityStatus = "pending" | "included" | "final";
export type VerificationStatus = "unverified" | "verified" | "invalid";
export type BridgeStatus = "pending" | "confirmed" | "failed";

export interface PageParams {
  offset: number; // u32
  limit: number; // u32
}

export interface NodeInfo {
  node_id: Bytes32;
  chain_id: bigint; // u64
  protocol_version: number; // u16
  mode: string;
  height: bigint; // u64
}

export interface PeerInfo {
  peer_id: Bytes32;
  address: string;
  connected: boolean;
  latency_ms: number; // u32
}

export interface MarketSummary {
  market_id: number; // MarketId(u32)
  market_type: MarketType;
  lifecycle: MarketLifecycle;
}

export interface MarketDetail {
  summary: MarketSummary;
  tick_size: bigint; // Price(i64)
  lot_size: bigint; // Quantity(i64)
  symbol: string;
  outcomes: number; // u16
}

export interface BookLevel {
  price: bigint; // Price(i64)
  quantity: bigint; // Quantity(i64)
}

export interface Book {
  market_id: number; // MarketId(u32)
  sequence: bigint; // SequenceNumber(u64)
  bids: BookLevel[];
  asks: BookLevel[];
}

export interface Trade {
  market_id: number; // MarketId(u32)
  order_id: bigint; // OrderId(u64)
  price: bigint; // Price(i64)
  quantity: bigint; // Quantity(i64)
  side: Side;
  timestamp: bigint; // u64
}

export interface MarketStatus {
  market_id: number; // MarketId(u32)
  lifecycle: MarketLifecycle;
  mark_price: bigint; // Price(i64)
  index_price: bigint; // Price(i64)
  funding_rate: bigint; // Ratio(i64)
  open_interest: bigint; // Quantity(i64)
  oracle_health: OracleHealth;
}

export interface OracleStatus {
  market_id: number; // MarketId(u32)
  health: OracleHealth;
  price: bigint; // Price(i64)
  sources: number; // u32
  last_update: bigint; // u64
}

export interface Account {
  account_id: number; // AccountId(u32)
  balance: string; // Amount(i128) decimal
  equity: string; // Amount(i128) decimal
  nonce: bigint; // u64
}

export interface Position {
  account_id: number; // AccountId(u32)
  market_id: number; // MarketId(u32)
  size: bigint; // Quantity(i64), signed exposure
  entry_price: bigint; // Price(i64)
  unrealized_pnl: string; // Amount(i128) decimal
}

export interface Order {
  order_id: bigint; // OrderId(u64)
  account_id: number; // AccountId(u32)
  market_id: number; // MarketId(u32)
  side: Side;
  order_type: OrderType;
  price: bigint; // Price(i64)
  quantity: bigint; // Quantity(i64)
  filled: bigint; // Quantity(i64)
  time_in_force: TimeInForce;
}

export interface Fill {
  price: bigint; // Price(i64)
  quantity: bigint; // Quantity(i64)
}

export interface ExecutionReceipt {
  command_hash: Bytes32;
  order_id: bigint | null; // Option<OrderId(u64)>
  fills: Fill[];
  finality: FinalityStatus;
  checkpoint_height: bigint | null; // Option<u64>
  verification_status: VerificationStatus;
}

export interface DepositStatus {
  tx_hash: Bytes32;
  account_id: number; // AccountId(u32)
  amount: string; // Amount(i128) decimal
  status: BridgeStatus;
  confirmations: number; // u32
}

export interface WithdrawalStatus {
  request_hash: Bytes32;
  account_id: number; // AccountId(u32)
  amount: string; // Amount(i128) decimal
  status: BridgeStatus;
}
