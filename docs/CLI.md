# `dexos` — command-line RPC client

`dexos` is a workspace binary that drives the **full system over the node's RPC
socket**. It speaks the exact wire protocol served by `crates/rpc`: a
length-prefixed, [`postcard`](https://docs.rs/postcard)-encoded `codec::Frame`
carrying an `RpcRequest`, one request/response per TCP connection. Read-only
queries are sent unsigned; control (write) methods are signed with an ed25519 key
so the server can authenticate them.

> **Status.** `dexos` targets a **plaintext** RPC listener today. The production
> server is TLS 1.3-only, and `marketd run` does not yet bind the RPC endpoint
> (see [status](#status--limitations)). `dexos` is usable against a process that
> serves the RPC directly (dev harnesses, tests), and is the reference client for
> the wire protocol as the transport lands.

## Build

`dexos` is not installed on your `PATH` by default. Build it from the workspace,
then run it from `target/release/`:

```sh
cargo build --release --bin dexos     # produces target/release/dexos

./target/release/dexos --target 127.0.0.1:8080 get-node-info
```

Prefer a bare `dexos`? Install it onto your `PATH` (`~/.cargo/bin`):

```sh
cargo install --path bin/dexos
dexos get-node-info
```

## Transport

Each invocation opens one connection, sends one request, reads one response, and
exits — matching the server's strictly-sequential, one-in-flight-per-connection
model. On the wire every message is a `codec::Frame` (19-byte little-endian
header + postcard payload); requests are tagged `msg_type = 1`, responses
`msg_type = 2`. The RPC control plane caps a frame payload at 256 KiB. `dexos`
uses `rpc::server::round_trip`, the crate's plaintext client helper.

## Global options

These apply to every subcommand and may appear before or after it.

| Option | Default | Purpose |
|---|---|---|
| `--target <ADDR>` | `127.0.0.1:8080` | RPC endpoint (`host:port`) |
| `--key <PATH>` | — | Hex ed25519 seed file that signs control methods with the account root key |
| `--session-key <PATH>` | — | Hex ed25519 seed file for a delegated session key (signs instead of `--key`) |
| `--client-id <ID>` | `1` | Stable per-client id; part of the exactly-once idempotency key |
| `--nonce <N>` | — (required for control methods) | Monotonic per-client nonce for the next control command; ignored by queries |
| `--request-id <ID>` | `1` | Correlation id echoed back on the response |

## Queries (unsigned)

Read-only methods need no key. Results are pretty-printed.

| Subcommand | Arguments | Returns |
|---|---|---|
| `get-node-info` | — | node identity + status |
| `get-peers` | — | connected peers |
| `get-markets` | `--offset` `--limit` | market summaries |
| `get-market` | `--market` | one market's metadata |
| `get-market-book` | `--market` `--depth` | order book to N levels |
| `get-market-trades` | `--market` `--offset` `--limit` | recent trades |
| `get-market-status` | `--market` | live market status |
| `get-oracle-status` | `--market` | oracle health |
| `get-checkpoint` | `--height` | a checkpoint by height |
| `get-latest-checkpoint` | — | the latest checkpoint |
| `get-account` | `--account` | account state |
| `get-account-proof` | `--account` | Merkle proof vs the latest checkpoint |
| `get-position` | `--account` `--market` | a position |
| `get-orders` | `--account` `--offset` `--limit` | orders for an account |
| `get-execution-receipt` | `--hash` | receipt by command hash |
| `get-deposit-status` | `--hash` | deposit status by tx hash |
| `get-withdrawal-status` | `--hash` | withdrawal status by request hash |
| `get-network-status` | — | network / sync status |

## Control methods (signed)

Control methods require a signing key (`--key`, or `--session-key` for a
delegated key) and an explicit `--nonce` — there is deliberately no default, so
two commands can never silently collide on the same idempotency key. `dexos`
builds the canonical `Command`, signs the domain-tagged bytes
(`dexos.rpc.control.v1`) with ed25519, and attaches a `ControlMeta`
(`client_id`, `nonce`, optional `session_pubkey`, `signer`, `signature`). The
server verifies the signature before dispatch and dedupes `(client_id, nonce)`
for exactly-once semantics — reuse the same nonce to retransmit, increment it for
a new command. Reusing a consumed nonce for a *different* command is rejected
(`nonce already consumed by a different command`) rather than answered with the
earlier command's stale ack. Every control method returns a `CommandAck`;
`dexos` additionally verifies the ack's `command_hash` matches the command it
actually sent and exits nonzero on a mismatch.

| Subcommand | Arguments | Notes |
|---|---|---|
| `submit-order` | `--account` `--market` `--side` `--order-type` `--price` `--quantity` `--time-in-force` `--leverage` | `--side bid\|ask`; `--order-type limit\|market\|post-only\|reduce-only` |
| `cancel-order` | `--account` `--market` `--order-id` | |
| `cancel-all` | `--account` `[--market]` | omit `--market` to cancel across all markets |
| `replace-order` | `--account` `--market` `--order-id` `--new-price` `--new-quantity` | |
| `authorize-session` | `--account` `--session-pubkey` `[--market …]` `[--all-markets]` `--max-notional` `--max-leverage` `[--allow-withdrawal]` `[--allow-session-admin]` `[--allow-market-create]` `--expiry` | scope is deny-by-default; session authorize/revoke is root-key only |
| `revoke-session` | `--account` `--session-pubkey` | |
| `bind-wallet` | `--account` `--wallet` `--proof` | `--wallet` is a 20-byte hex address; `--proof` is hex bytes |
| `request-withdrawal` | `--account` `--amount` `--destination` | `--destination` is a 20-byte hex address |
| `create-market` | `--creator` `--market-type` `--symbol` `--outcomes` | needs the `allow-market-create` scope when signed by a session key |
| `stake-market` | `--market` `--sponsor` `--amount` | |

`--market-type` is one of `perpetual`, `binary-prediction`,
`multi-outcome-prediction`, `decision`, `sports`, `scalar`,
`custom-payout-vector`.

### Scaled units

Prices, quantities, leverage, and amounts are passed as **raw scaled integers**
where `1.0 = 1_000_000` (the fixed-point scale used across the deterministic
core). For example `--price 25000000` is `25.0`, and `--leverage 3000000` is
`3.0x`.

## Examples

```sh
# Read-only queries (no key needed).
dexos get-node-info
dexos get-market --market 1
dexos get-market-book --market 1 --depth 20
dexos get-orders --account 42 --limit 50

# Generate a signing key (marketd writes an owner-only hex seed file).
marketd keygen --output trader.seed

# Create a perpetual market (a signed control method).
dexos --key trader.seed --nonce 0 \
  create-market --creator 1 --market-type perpetual --symbol BTC-PERP --outcomes 1

# Submit a limit buy: 1.0 unit @ 25.0, 3x leverage. Bump --nonce each command.
dexos --key trader.seed --nonce 1 \
  submit-order --account 1 --market 1 --side bid --order-type limit \
    --price 25000000 --quantity 1000000 --leverage 3000000

# Cancel everything for an account.
dexos --key trader.seed --nonce 2 cancel-all --account 1
```

## Status & limitations

`dexos` is honest about what the transport can do today:

| Capability | Status |
|---|---|
| Binary framing + envelope + ed25519 control signing | **Real** — verified end-to-end against a live in-process server (`bin/dexos/tests/e2e.rs`) |
| All 18 queries + 10 control methods | **Real** — one subcommand per RPC method |
| TLS 1.3 client | **Planned** — the `rpc` crate ships only server-side acceptors; `dexos` uses the plaintext path until a client connector lands |
| Reachable via `marketd run` | **Planned** — the node does not yet bind the RPC listener; use a process that serves the RPC directly |
| Live subscriptions (book / fills feeds) | **Planned** — the streaming layer exists (`rpc::StreamHub`) but there is no `Subscribe` method on the wire; `dexos` is request/response only |
| `submit-basket` (atomic multi-order) | **Not exposed** — the `RpcMethod::SubmitBasket` variant carries a vector of orders and is not yet mapped to a subcommand |

See [architecture](ARCHITECTURE.md), [security status](SECURITY.md), and the
`rpc` crate rustdoc (`cargo doc --open -p rpc`) for the underlying protocol.
