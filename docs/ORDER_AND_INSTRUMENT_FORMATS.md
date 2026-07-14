# Order and Instrument Wire Formats

This document defines the target fixed-width trading format for the packed-order
and SIMD work in [#569](https://github.com/joeblau/dexos/issues/569),
[#570](https://github.com/joeblau/dexos/issues/570), and
[#571](https://github.com/joeblau/dexos/issues/571). It also defines how spot,
derivative, prediction, event, and decision-market products compose from static
instrument descriptors.

> **Status: design target, not the current production wire.** The current RPC
> path uses serde/postcard, repeats `ControlMeta` authentication material, and
> does not expose an outcome/instrument coordinate. The layouts below are the
> proposed canonical v1 format to implement and test. Stable tags become
> protocol commitments only when the implementation and golden fixtures land.

## One order format, many product types

An **order instruction** says what a trader wants to do: place, cancel, amend,
trigger, schedule, or activate a multi-leg strategy. An **instrument definition**
says what is being traded: spot, a future, an option, an outcome claim, and so
on. These are deliberately separate.

Every ordinary operation and pre-registered strategy activation is one 64-byte
`PackedOrderV1`; one-off multi-leg definitions use a bounded sequence of the
same 64-byte records. Product terms are looked up by `(market_id,
instrument_id)` in immutable, cache-local static descriptors. An order therefore
never repeats an option strike, future expiry, prediction resolution rule, swap
schedule, or decision utility table.

This design gives the hot path:

- one cache line and one constant stride per record;
- no per-record length branch after the v1 header is validated;
- no product-specific union or variable-length decode in the order loop;
- fixed offsets for SIMD validation and AoS-to-SoA transposition;
- a 64-byte contribution for every single-record operation before batch,
  compression, AEAD, IP, and Ethernet overhead, below the `<80 B` target in
  #567 and #569.

## Product taxonomy

The economic families and their compact representation are:

| Product | Economic meaning | Static hot descriptor | Bytes | Repository status |
|---|---|---:|---:|---|
| Spot | Exchange the actual asset for immediate ledger delivery | Core | 64 | New `MarketType` required |
| Forward | Custom/private agreement to buy or sell later | Core + Expiry | 128 | New `MarketType` required |
| Future | Standardized exchange-traded forward with expiration | Core + Expiry | 128 | New `MarketType` required |
| Perpetual | Future with no expiration and periodic funding | Core + Funding | 128 | Present |
| Option | Right, but not obligation, to buy or sell at a strike | Core + Option | 128 | New `MarketType` required |
| Swap | Agreement to exchange cash flows over time | Core + Swap | 128 | New `MarketType` required |
| Binary prediction | Fully collateralized event claims with two outcomes | Core + Event | 128 | Present as `BinaryPrediction` |
| Multi-outcome prediction | Complete set of mutually exclusive event claims | Core + Event | 128 | Present as `MultiOutcomePrediction` |
| Scalar/range | Long/short claims paying linearly over a bounded range | Core + Event + Scalar | 192 | Present as `Scalar` |
| Sports/event | Event claims with winner/dead-heat settlement | Core + Event | 128 | Present as `Sports` |
| Event future | Expiring future whose settlement is event-dependent | Core + Expiry + Event | 192 | Proposed composed profile |
| Event swap | Swap whose cash flows are event-dependent | Core + Swap + Event | 192 | Proposed composed profile |
| Decision market | Action-contingent grid of outcome claims | Core + Event + Decision + Guards | 256 | Present as `Decision` |
| Custom payout vector | Adapter/table-defined bounded settlement | Core + Custom Payout | 128 minimum | Present as `CustomPayoutVector` |

“Binary option,” “event future,” and “event swap” describe economic/wire
profiles here, not a claim that the products receive the same legal or
regulatory classification in every jurisdiction. A binary prediction claim is
normally fully collateralized and does not create the uncovered writer exposure
of a conventional option.

The current `types::MarketType` contains `Perpetual`, `BinaryPrediction`,
`MultiOutcomePrediction`, `Decision`, `Sports`, `Scalar`, and
`CustomPayoutVector`. Spot, forward, future, option, and swap variants require
new execution, risk, settlement, and lifecycle semantics before they can be
advertised as supported.

## Existing order instructions

The current execution styles map into one flags byte:

| Style | Meaning | Flags bits 2..1 |
|---|---|---:|
| Limit | Execute at the limit price or better; remainder may rest | `00` |
| Market | Execute immediately within the required protection collar | `01` |
| Post-only | Reject if the order would take liquidity | `10` |
| Reduce-only | May only reduce an existing position | `11` |

Time in force occupies flags bits 5..4:

| Time in force | Meaning | Flags bits 5..4 |
|---|---|---:|
| GTC | Good until cancelled | `00` |
| IOC | Execute now and cancel the remainder | `01` |
| FOK | Execute the full quantity now or reject | `10` |
| Reserved | Invalid in v1 | `11` |

The separate reduce-only bit preserves the engine's current representation,
which has both `OrderType::ReduceOnly` and `PlaceOrder::reduce_only`. A
`ReduceOnly` style MUST set that bit; future limit/market styles may also set it
when the engine explicitly supports that combination.

## Integer and byte conventions

- All multi-byte integers are little-endian.
- Signed integers use two's-complement representation.
- `Price`, `Quantity`, and `Ratio` retain the repository's 6-decimal scale of
  `1_000_000` units per `1.0`.
- Times in these new static descriptors are unsigned Unix nanoseconds. Gateways
  MUST normalize external time units before encoding.
- Decoders read from bytes with explicit endian conversion. They MUST NOT cast
  untrusted bytes to a Rust `repr(packed)` reference.
- Reserved fields and bits MUST be zero on encode and MUST cause rejection when
  nonzero on decode.

The widths align with current core types:

| Core type | Wire type | Bytes |
|---|---:|---:|
| `ShardId` | `u16` | 2 |
| `AccountId`, `MarketId` | `u32` | 4 |
| `OrderId`, `SequenceNumber` | `u64` | 8 |
| `Price`, `Quantity`, `Ratio` | `i64` | 8 |
| `Amount` | `i128` | 16 |

## `PackedOrderV1`: fixed 64-byte order command

The record is a 32-byte common routing/authentication/replay header followed by
four opcode-specific 64-bit operands. Typed decoders expose named views such as
`Place`, `Stop`, or `Iceberg`; generic `arg0..arg3` names exist only at the wire
layer.

| Offset | Size | Type | Field | Validation/meaning |
|---:|---:|---:|---|---|
| 0 | 1 | `u8` | `schema_version` | Exactly `1` |
| 1 | 1 | `u8` | `opcode` | Operation tag selecting the typed operand view |
| 2 | 1 | `u8` | `record_len` | Exactly `64` |
| 3 | 1 | `u8` | `flags` | Common order bits plus opcode-specific high bits |
| 4 | 2 | `u16` | `shard_id` | Must match the committed route for `market_id` |
| 6 | 2 | `u16` | `instrument_id` | Product sub-instrument/outcome coordinate |
| 8 | 4 | `u32` | `market_id` | Static descriptor lookup key |
| 12 | 4 | `u32` | `account_id` | Owning account |
| 16 | 4 | `u32` | `auth_context_slot` | Connection-epoch alias for root/session authorization |
| 20 | 4 | `u32` | `client_slot` | Connection-epoch alias for the stable client namespace |
| 24 | 8 | `u64` | `nonce` | Monotonic replay value for one logical command/group |
| 32 | 8 | `u64/i64` | `arg0` | Opcode-specific operand |
| 40 | 8 | `u64/i64` | `arg1` | Opcode-specific operand |
| 48 | 8 | `u64/i64` | `arg2` | Opcode-specific operand |
| 56 | 8 | `u64/i64` | `arg3` | Opcode-specific operand |
|  | **64** |  | **Total** | One cache line |

The placement/trigger flags byte is:

| Bits | Field | Values |
|---:|---|---|
| 0 | Side | `0` bid/buy, `1` ask/sell |
| 2..1 | Order style | `00` limit, `01` market, `10` post-only, `11` reduce-only |
| 3 | Reduce-only | `1` means exposure may only decrease |
| 5..4 | Time in force | `00` GTC, `01` IOC, `10` FOK, `11` invalid |
| 7..6 | Trigger/reference source | `00` mark/default, `01` index, `10` last trade, `11` committed external source |

For ordinary place, cancel, cancel-all, and replace records, bits 7..6 MUST be
zero. Triggered/pegged records interpret them as the reference source. An opcode
may further restrict otherwise valid combinations; unused bits always remain
canonical zero.

Opcode assignments are:

| Tag | Opcode | `arg0` | `arg1` | `arg2` | `arg3` |
|---:|---|---|---|---|---|
| `0x01` | Place/GTD | Order id | Price/collar | Quantity | Expiry Unix ns; `0` none |
| `0x02` | Cancel | Target order id | `0` | `0` | `0` |
| `0x03` | Cancel all in market | `0` | `0` | `0` | `0` |
| `0x04` | Replace | Target order id | New price | New quantity | `0` |
| `0x05` | Stop | Child order id | Trigger price | Execution price/collar | Quantity |
| `0x06` | Trailing stop | Child order id | Positive absolute offset | Execution price/collar | Quantity |
| `0x07` | Cancel conditional | Conditional/instance id | `0` | `0` | `0` |
| `0x08` | Amend conditional | Conditional/instance id | New trigger/offset | New execution price | New quantity |
| `0x09` | Iceberg | Order id | Price | Total quantity | Display quantity |
| `0x0a` | Pegged | Order id | Signed price offset | Quantity | Limit cap/floor; `0` none |
| `0x0b` | TWAP | Parent order id | Price/collar | Total quantity | Packed slice count + interval |
| `0x0c` | Activate strategy | Strategy id | Instance order id | Quantity override; `0` default | Price limit; `0` default |
| `0x0d` | Cancel strategy | Strategy instance id | `0` | `0` | `0` |
| `0x20` | Strategy definition header | Strategy id | Packed kind + leg count | Expiry Unix ns; `0` none | Definition revision |
| `0x21` | Strategy leg | Strategy-specific | Strategy-specific | Strategy-specific | Strategy-specific |

TWAP `arg3` packs `slice_count: u32` in bits 31..0 and `interval_ms: u32` in
bits 63..32. Both values must be nonzero and child order ids are derived from the
parent id with checked addition. A trailing stop takes its initial reference
from the committed source at sequencing time; an explicit historical reference
or additional activation condition uses a strategy definition instead.

For `Place`, `Stop`, `Trailing stop`, `Iceberg`, and `Pegged`, prices and
quantities retain their full signed `i64` fixed-point widths. Required prices,
quantities, offsets, display quantities, slice counts, and intervals must be
strictly positive. Iceberg display quantity may not exceed total quantity.

`opcode == 0`, unknown opcodes, noncanonical zero fields, invalid enum values,
and mismatched route or authorization context fail before allocation or state
lookup. Replace retains the resting order's side, style, reduce-only status, TIF,
and instrument; changing those values requires cancel plus place.

The current lowering rule may populate Place `arg0` from `nonce`, but the wire
retains an explicit order id so client-assigned and sequencer-assigned id
policies remain possible without changing offsets.

### Fixed-stride multi-record strategies

Arbitrary OCO, bracket, OTO, OTOCO, basket, and custom multi-leg definitions are
not forced into one record. They are encoded as one `Strategy definition header`
followed immediately by 1-64 `Strategy leg` records in the same authenticated
batch. Every record remains exactly 64 bytes.

The header's `arg1` packs `strategy_kind: u8` in bits 7..0 and `leg_count: u8`
in bits 15..8; bits 63..16 are zero. Stable strategy kinds are `1` OCO, `2`
bracket, `3` OTO, `4` OTOCO, `5` atomic basket, and `255` versioned custom.

All group records share `shard_id`, `account_id`, `auth_context_slot`,
`client_slot`, and `nonce`; legs may select different markets/instruments within
that shard. The group is parsed, authenticated, authorized, replay-classified,
and committed as one logical command. It may not cross a batch boundary. Missing,
extra, reordered, or independently replayed legs reject the entire group before
execution.

For an OCO-style leg, the four operands are trigger price, execution
price/collar, quantity, and sibling order id to cancel. For a plain basket leg,
they are child order id, price/collar, quantity, and zero. Bracket/OTO roles are
determined by strategy kind plus leg order; typed validation rejects ambiguous
or invalid combinations.

Definitions can be registered once outside the steady-state order stream.
Activation and cancellation then require only one 64-byte record carrying the
strategy or instance id. If a workload sends one-off definitions, every header
and leg counts toward its encoded contribution; fixed stride does not hide those
bytes.

Per-order leverage is intentionally absent. The current deterministic engine
does not consume the RPC leverage request; leverage limits live in the session
scope and static risk configuration.

## Instrument-coordinate mapping

`market_id` identifies a fungible contract/series. `instrument_id` identifies a
bounded sub-instrument within that market:

| Product profile | Canonical `instrument_id` |
|---|---|
| Spot, forward, future, perpetual, option, swap | `0`; use a distinct `market_id` for each fungible series |
| Binary/multi-outcome/sports prediction | `2 * outcome_index + claim_kind`, where YES = `0`, synthetic NO = `1` |
| Scalar | LONG = `0`, SHORT = `1`, matching `types::ScalarOutcome` |
| Event future/event swap | `0`; event outcomes affect settlement, not the traded series id |
| Decision | `action_index * outcome_count + outcome_index` |
| Custom payout | Definition-assigned index in `0..outcome_count` |

The repository caps prediction outcomes at 256 and decision actions at 64, so
the largest decision coordinate is below `64 * 256 = 16,384` and safely fits in
`u16`. The decision-market crate currently exposes a `u32 InstrumentId`; lowering
to this wire MUST reject any definition whose mapped coordinate exceeds
`u16::MAX` rather than truncate it.

The client MUST NOT supply a product kind. The validator derives it from the
committed static descriptor for `market_id`, preventing a record from changing
risk or settlement semantics by relabeling itself.

## `OrderBatchV1`: bounded LZ4 envelope

Steady-state batches contain 32-128 compatible 64-byte records. Records from
different traffic classes, deadlines, auth contexts, session epochs, shards, or
replay domains are not mixed.

| Offset | Size | Type | Field | Validation/meaning |
|---:|---:|---:|---|---|
| 0 | 4 | `[u8; 4]` | `magic` | ASCII `DXOB` |
| 4 | 1 | `u8` | `batch_version` | Exactly `1` |
| 5 | 1 | `u8` | `codec` | `0` raw, `1` LZ4 block |
| 6 | 2 | `u16` | `flags` | Partial/raw-fallback/auth/backend flags |
| 8 | 2 | `u16` | `record_count` | 32-128 at steady state |
| 10 | 2 | `u16` | `record_size` | Exactly `64` |
| 12 | 4 | `u32` | `uncompressed_len` | Exactly `record_count * 64` |
| 16 | 4 | `u32` | `payload_len` | Bounded bytes following the header |
| 20 | 8 | `u64` | `batch_sequence` | Strictly monotonic in the replay domain |
| 28 | 4 | `u32` | `header_crc32c` | Fast corruption check over bytes 0..28 |
|  | **32** |  | **Header total** | Followed by payload and auth tag |

Batch flags are `bit 0 = partial` (permits 1-31 records only for bounded
low-load/shutdown flush), `bit 1 = raw LZ4 fallback`, `bit 2 = application auth
tag present` (required in v1), and bits 4..3 = encoder backend (`00` scalar,
`01` AVX2, `10` AVX-512, `11` NEON). The backend tag is observational; every
backend produces interoperable bytes. Bits 15..5 are reserved and zero.

The compressed or raw payload is followed by a 16-byte application
authentication tag. LZ4 is used only when it produces fewer payload bytes;
otherwise `codec = 0` and the raw-fallback flag is set. Decompression is bounded
to `uncompressed_len` before any write.

The tag binds, at minimum:

```text
"dexos.order.batch.v1" || network_id || connection_epoch ||
header[0..28] || payload
```

It is keyed by the authenticated trading context established with the account
root or delegated session key. The payload bytes commit to record order and
boundaries, while `batch_sequence`, `nonce`, route, network, and connection epoch
prevent replay, detachment, reordering, and redirection. TLS/QUIC AEAD remains
required where configured; CRC32C is never treated as authentication.

If this envelope is carried inside the existing 19-byte `codec::Frame`, that
frame appears once per batch, never once per order. A 128-record raw payload is
8,192 bytes, within the current 32 KiB NewOrder semantic payload ceiling.

## Static `InstrumentCoreV1`: fixed 64-byte registry row

The hot descriptor is a deterministic projection of the authoritative market
definition, not a replacement for sponsor, resolver, metadata, or state-tree
commitments. It contains only fields required by routing, matching, risk, and
settlement dispatch.

| Offset | Size | Type | Field | Meaning |
|---:|---:|---:|---|---|
| 0 | 1 | `u8` | `schema_version` | Exactly `1` |
| 1 | 1 | `u8` | `product_kind` | Stable product tag below |
| 2 | 1 | `u8` | `core_len` | Exactly `64` |
| 3 | 1 | `u8` | `extension_count` | Number of following 64-byte blocks |
| 4 | 4 | `u32` | `flags` | Settlement/collateralization flags |
| 8 | 4 | `u32` | `market_id` | Must equal the registry key |
| 12 | 4 | `u32` | `base_asset_id` | Delivered/underlying base asset, or `0` |
| 16 | 4 | `u32` | `quote_asset_id` | Price denomination asset |
| 20 | 4 | `u32` | `collateral_asset_id` | Margin/complete-set collateral |
| 24 | 4 | `u32` | `settlement_asset_id` | Cash settlement/delivery asset |
| 28 | 4 | `u32` | `definition_revision` | Monotonic immutable-definition revision |
| 32 | 8 | `i64` | `contract_multiplier` | 6-dp quantity multiplier |
| 40 | 8 | `i64` | `tick_size` | Positive 6-dp price increment |
| 48 | 8 | `i64` | `lot_size` | Positive 6-dp quantity increment |
| 56 | 8 | `u64` | `maturity_time` | Unix ns; `0` for spot/perpetual/no maturity |
|  | **64** |  | **Total** | Followed immediately by extension blocks |

Core flags are `bit 0 = cash-settled`, `bit 1 = physically/ledger-settled`,
`bit 2 = margined`, `bit 3 = fully collateralized`, and `bit 4 = oracle
settled`. Conflicting settlement flags and all unknown bits are invalid.

Proposed stable `product_kind` tags are:

| Tag | Kind | Tag | Kind |
|---:|---|---:|---|
| `0x00` | Spot | `0x10` | Binary prediction |
| `0x01` | Forward | `0x11` | Multi-outcome prediction |
| `0x02` | Future | `0x12` | Scalar/range |
| `0x03` | Perpetual | `0x13` | Sports/event |
| `0x04` | Option | `0x14` | Event future |
| `0x05` | Swap | `0x15` | Event swap |
|  |  | `0x16` | Decision market |
|  |  | `0x17` | Custom payout vector |

## Fixed 64-byte extension blocks

Every extension begins with the same 8-byte header:

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 0 | 1 | `u8` | `extension_kind` |
| 1 | 1 | `u8` | `extension_version` = `1` |
| 2 | 2 | `u16` | `block_len` = `64` |
| 4 | 4 | `u32` | Extension-specific flags |

Unknown required extensions fail closed. Extension blocks MUST appear in
ascending `extension_kind` order, with no duplicates unless that extension's
specification explicitly permits chunks.

### `ExpiryTermsV1` (`extension_kind = 0x01`)

Used by forwards, futures, and event futures.

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 8 | `u64` | `start_time` |
| 16 | 8 | `u64` | `last_trade_time` |
| 24 | 8 | `u64` | `settlement_time` |
| 32 | 4 | `u32` | `delivery_asset_id` |
| 36 | 4 | `u32` | `settlement_oracle_id` |
| 40 | 4 | `u32` | `reference_index_id` |
| 44 | 4 | `u32` | `margin_schedule_id` |
| 48 | 4 | `u32` | `access_policy_id`; nonzero for private/bilateral forwards |
| 52 | 4 | `u32` | `delivery_location_id`; `0` for cash/ledger settlement |
| 56 | 8 | `i64` | `initial_margin_ratio` |
|  | **64** |  | **Block total including common header** |

### `FundingTermsV1` (`extension_kind = 0x02`)

Used by perpetuals.

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 8 | `u64` | `funding_interval_ns` |
| 16 | 8 | `i64` | `max_funding_rate` |
| 24 | 8 | `i64` | `funding_clamp` |
| 32 | 4 | `u32` | `index_oracle_id` |
| 36 | 4 | `u32` | `mark_oracle_id` |
| 40 | 4 | `u32` | `funding_model_id` |
| 44 | 4 | `u32` | `margin_schedule_id` |
| 48 | 8 | `i64` | `initial_margin_ratio` |
| 56 | 8 | `i64` | `maintenance_margin_ratio` |
|  | **64** |  | **Block total including common header** |

### `OptionTermsV1` (`extension_kind = 0x03`)

Used by vanilla and bounded barrier option series. Extension flags are bit 0
put/call (`0` call, `1` put), bits 2..1 exercise style (`00` European, `01`
American, `10` Bermudan), and bit 3 barrier-present.

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 4 | `u32` | `underlying_id` |
| 12 | 4 | `u32` | `settlement_oracle_id` |
| 16 | 8 | `i64` | `strike_price` |
| 24 | 8 | `u64` | `expiry_time` |
| 32 | 8 | `u64` | `exercise_start_time`; equals expiry for European |
| 40 | 8 | `u64` | `settlement_time` |
| 48 | 4 | `u32` | `premium_asset_id` |
| 52 | 4 | `u32` | `access_policy_id` |
| 56 | 8 | `i64` | `barrier_price`; zero unless barrier-present |
|  | **64** |  | **Block total including common header** |

### `SwapTermsV1` (`extension_kind = 0x04`)

Used by fixed/floating, basis, and event swaps. Extension flags declare whether
each leg is fixed, floating, or event-dependent.

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 4 | `u32` | `pay_leg_id` |
| 12 | 4 | `u32` | `receive_leg_id` |
| 16 | 8 | `u64` | `start_time` |
| 24 | 8 | `u64` | `end_time` |
| 32 | 8 | `u64` | `payment_interval_ns` |
| 40 | 8 | `i64` | `pay_fixed_rate_or_spread` |
| 48 | 8 | `i64` | `receive_fixed_rate_or_spread` |
| 56 | 4 | `u32` | `settlement_oracle_id` |
| 60 | 4 | `u32` | `access_policy_id` |
|  | **64** |  | **Block total including common header** |

### `EventTermsV1` (`extension_kind = 0x10`)

Used by prediction, sports, event-future, event-swap, scalar, and decision
profiles.

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 32 | `[u8; 32]` | `criteria_hash` |
| 40 | 8 | `u64` | `close_time` |
| 48 | 8 | `u64` | `resolution_time` |
| 56 | 2 | `u16` | `outcome_count` |
| 58 | 1 | `u8` | `payout_rule`: winner-take-all/dead-heat/custom |
| 59 | 1 | `u8` | `invalid_policy` |
| 60 | 4 | `u32` | `resolver_set_id` |
|  | **64** |  | **Block total including common header** |

Outcome labels, evidence, committee keys, and human-readable criteria stay in
bounded authoritative metadata committed by `criteria_hash` and the market
definition. They are not needed to match an order.

### `ScalarTermsV1` (`extension_kind = 0x11`)

Used with `EventTermsV1` for range markets. Bounds retain the current `Amount`
`i128` width.

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 16 | `i128` | `lower_bound` |
| 24 | 16 | `i128` | `upper_bound` |
| 40 | 4 | `u32` | `reference_index_id` |
| 44 | 4 | `u32` | `settlement_oracle_id` |
| 48 | 8 | `u64` | `settlement_time` |
| 56 | 8 | `i64` | `payout_scale`; exactly `1_000_000` in v1 |
|  | **64** |  | **Block total including common header** |

Settlement clamps the observed value to `[lower_bound, upper_bound]`; LONG is
`(value - lower) / (upper - lower)` and SHORT is the exact complement.

### `DecisionTermsV1` (`extension_kind = 0x12`)

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 2 | `u16` | `action_count`; 1-64 |
| 10 | 2 | `u16` | `outcome_count`; 1-256 |
| 12 | 1 | `u8` | `decision_rule`: maximize/minimize expected utility |
| 13 | 1 | `u8` | `unselected_action_policy`: refund/void |
| 14 | 2 | `u16` | Reserved, zero |
| 16 | 8 | `u64` | `selection_start` |
| 24 | 8 | `u64` | `selection_end` |
| 32 | 8 | `u64` | `evaluation_start` |
| 40 | 8 | `u64` | `evaluation_end` |
| 48 | 4 | `u32` | `utility_table_id` |
| 52 | 4 | `u32` | `authority_set_id` |
| 56 | 8 | `u64` | `network_id` |
|  | **64** |  | **Block total including common header** |

### `DecisionGuardsV1` (`extension_kind = 0x13`)

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 16 | `i128` | `min_liquidity` |
| 24 | 8 | `i64` | `max_concentration` |
| 32 | 8 | `i64` | `min_twap_coverage` |
| 40 | 16 | `i128` | `collateral_per_set` |
| 56 | 8 | `u64` | Reserved, zero |
|  | **64** |  | **Block total including common header** |

The utility table is immutable registry data keyed by `utility_table_id`; it is
not repeated in orders. A canonical persisted table may use fixed 64-byte
chunks containing a common 8-byte header, an 8-byte chunk index/count header,
and three `i128` utilities (48 bytes).

### `CustomPayoutTermsV1` (`extension_kind = 0x14`)

| Offset | Size | Type | Field |
|---:|---:|---:|---|
| 8 | 32 | `[u8; 32]` | `adapter_hash` |
| 40 | 4 | `u32` | `payout_table_id` |
| 44 | 2 | `u16` | `outcome_count` |
| 46 | 2 | `u16` | Reserved, zero |
| 48 | 16 | `i128` | `max_payout_per_complete_set` |
|  | **64** |  | **Block total including common header** |

An event-resolved custom payout adds `EventTermsV1`, increasing its hot
descriptor from 128 to 192 bytes. Payout tables use the same fixed chunk model
as decision utility tables and remain outside order records.

## SIMD processing model

The network payload is an array of 64-byte records (AoS). A batch decoder:

1. validates the 32-byte envelope and bounded decompression length;
2. authenticates before exposing commands to execution;
3. loads 32-128 records from caller-owned buffers;
4. vector-checks versions, lengths, nonzero slots, reserved bits, tags, routes,
   and opcode-specific argument masks (signs, tick/lot divisibility, ranges, and
   canonical zeros);
5. transposes required fields into cache-local SoA lanes for risk and matching;
6. uses a scalar tail and checked scalar implementation as the reference.

The bytes, accepted/rejected decisions, consumed lengths, and typed errors MUST
be identical across scalar, AVX2, AVX-512, and NEON paths. SIMD code must use
unaligned-safe loads or explicitly aligned batch buffers; the wire format itself
does not promise pointer alignment.

## Authentication, replay, and failure semantics

`auth_context_slot` and `client_slot` are connection-epoch aliases, not truncated
global identities and not weaker authentication. Establishment verifies the
current root/session signature and binds at least `{network, account,
signer/session key, scopes, expiry, connection epoch, full client identity}`.
Before sequencing, the ingress validator expands both slots into the current
engine `Authorization` and full canonical client identity; connection-local slot
numbers never enter the durable command log as global identities.

Slot zero is invalid. Allocation is unique within one connection epoch, slot
wrap is forbidden, and reconnect/rekey creates a new epoch and new mappings. The
batch authentication tag binds the epoch, so a captured slot value has no
meaning on another connection or after rekey.

Required rules:

- A batch contains exactly one authenticated context/replay domain even though
  every record carries its slot for independent validation.
- Every ordinary record nonce is consumed once. A strategy header and its legs
  share one nonce and are replay-classified as one payload-bound logical command.
- Duplicate `(connection_epoch, auth_context_slot, client_slot, nonce)` returns
  the original result or a deterministic duplicate response only when the full
  logical command digest matches.
- Revocation or expiry invalidates the context before new records are accepted.
- Authentication failure rejects the whole batch without partial execution.
- After authentication, record validation may produce per-record rejects, but
  accepted commands retain original order and sequence continuity.
- A strategy group is atomic only after its header and exact declared leg count
  have been assembled and validated; independent Place records never acquire
  atomicity merely by sharing a batch.

## 100 Gbit/s DoubleZero link-capacity table

A provisioned 100 Gbit/s path carries `100,000,000,000 / 8 = 12.5 GB/s` in
each direction. This section computes the link-only ceiling; it does not assume
an offered message rate or claim that execution can sustain the result.

Let:

- `B` = records per batch, 32-128;
- `rho` = compressed LZ4 payload bytes / raw payload bytes; lower is better;
- `H = 32 + 16 + 19 + 78 = 145` bytes per batch: batch header, application
  tag, current DexOS frame, and illustrative outer network overhead;
- `C = 12.5e9` bytes/s for one direction of the 100 Gbit/s path.

Then:

```text
wire_bytes_per_batch   = B * 64 * rho + H
wire_bytes_per_message = 64 * rho + H/B
max_messages_per_sec   = C / wire_bytes_per_message
```

| Batch | LZ4 ratio `rho` | Average wire bytes/batch | Wire bytes/message | 100 Gbit/s ceiling |
|---:|---:|---:|---:|---:|
| 32 | 1.00 raw fallback | 2,193.0 | 68.531250 | 182.399 Mmsg/s |
| 32 | 0.90 | 1,988.2 | 62.131250 | 201.187 Mmsg/s |
| 32 | 0.75 | 1,681.0 | 52.531250 | 237.954 Mmsg/s |
| 32 | 0.50 | 1,169.0 | 36.531250 | 342.173 Mmsg/s |
| 64 | 1.00 raw fallback | 4,241.0 | 66.265625 | 188.635 Mmsg/s |
| 64 | 0.90 | 3,831.4 | 59.865625 | 208.801 Mmsg/s |
| 64 | 0.75 | 3,217.0 | 50.265625 | 248.679 Mmsg/s |
| 64 | 0.50 | 2,193.0 | 34.265625 | 364.797 Mmsg/s |
| 128 | 1.00 raw fallback | 8,337.0 | 65.132812 | 191.916 Mmsg/s |
| 128 | 0.90 | 7,517.8 | 58.732813 | 212.828 Mmsg/s |
| 128 | 0.75 | 6,289.0 | 49.132812 | 254.412 Mmsg/s |
| 128 | 0.50 | 4,241.0 | 33.132812 | 377.270 Mmsg/s |

The ceiling is measured in 64-byte records per second. A single-record order or
strategy activation is one message; a one-off strategy definition with `L` legs
consumes `L + 1` records, so its logical-command ceiling is the table value
divided by `L + 1` before accounting for its different compression ratio.

The fractional batch sizes are corpus averages implied by `rho`; individual
LZ4 blocks always contain an integer number of bytes. `rho = 1` is the safe raw
fallback bound. The 0.90, 0.75, and 0.50 rows are sensitivity points, not assumed
compression results. The committed corpus must supply the measured ratio.

The 78-byte outer-overhead input is illustrative and must be replaced with the
observed DoubleZero packet capture, including the deployed TCP/QUIC, VLAN,
encryption, MTU, and segmentation behavior. The table is for one link direction.
Full duplex provides a separate 100 Gbit/s budget in the reverse direction; the
two directions are not added together when checking either bottleneck.

These are network ceilings only. End-to-end capacity remains:

```text
system_capacity = min(
    encode, decode, sequence, match, risk, state_update,
    journal, network, receipt, and finality capacities
)
```

## Implementation gaps and acceptance gates

Before this document can become a live protocol:

- add the missing product kinds only with their execution/risk/settlement
  semantics, not enum tags alone;
- add `instrument_id` to the RPC order schema; the current lowering sends every
  order to instrument `0`;
- implement `PackedOrderV1` caller-owned encode and borrowed validated decode,
  removing postcard from the measured order path;
- implement connection-epoch slot negotiation, fail-closed slot exhaustion,
  expansion to full canonical identities before sequencing, and exact batch-MAC
  key derivation before removing repeated signatures;
- connect stop, trailing-stop, iceberg, pegged, TWAP, conditional amend/cancel,
  and strategy opcodes through RPC, authorization, sequencing, execution,
  persistence, replay, and receipts; the current conditional engine is
  orderbook-local only;
- implement bounded strategy-group assembly and atomic execution before exposing
  OCO, bracket, OTO/OTOCO, or basket opcodes;
- add raw/LZ4 `OrderBatchV1` integration to real transports;
- commit golden bytes for every opcode, product descriptor, extension, boundary,
  malformed flag, truncation point, and maximum value;
- prove scalar/SIMD byte and error identity on x86_64 and aarch64;
- report mean/p95/p99/max bytes per order, compression ratio, cycles/order,
  allocations, and full outer-network overhead on the committed workload.
