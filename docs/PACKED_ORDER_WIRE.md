# Packed order wire format v1

Packed order records are the allocation-free hot-path representation for public
`SubmitOrder`, `CancelOrder`, and `ReplaceOrder` RPC methods. Other RPC and peer
messages retain the generic codec.

All multi-byte integers are little-endian. Each record begins with version, tag,
record length, and flags, followed by a 32-bit established-session reference, a
64-bit monotonic nonce, the original 64-bit control `client_id`, 32-bit account
and market identifiers, and tag-specific fields. Retaining `client_id` is
required because the execution engine uses it as the order idempotency key; a
connection-level default would make distinct submits in one batch collide. V1
sizes include all per-order tag, length, routing, idempotency,
session-reference, and replay material:

| Tag | Command | Bytes | Tag-specific fields |
| --- | --- | ---: | --- |
| 1 | submit | 56 | side/type/TIF flags, i64 price, quantity, leverage |
| 2 | cancel | 40 | u64 order id |
| 3 | replace | 56 | u64 order id, i64 price, quantity |

For the committed 70/20/10 new/cancel/replace workload, the mean record
contribution is 52.8 bytes; p95, p99, and max are each 56 bytes (min is 40).
Before compression, the implemented framing adds a 20-byte inner envelope, a
100-byte signed binding header, one 64-byte Ed25519 batch signature, and the
19-byte peer frame. This 203/N-byte overhead is 6.344 at N=32, 3.172 at N=64,
and 1.586 at N=128. Thus the corresponding authenticated pre-compression frame
means are 59.144, 55.972, and 54.386 bytes/order. Transport AEAD, IP, and
Ethernet overhead remain separate columns and are never silently removed from
frame- or L2-bytes/order figures; their exact values depend on the negotiated
transport and are measured in the composed campaign.
The machine-readable derivation, workload digest, exact distribution, frame
overhead at 32/64/128 records, and cross-architecture golden digest are pinned in
`crates/benchmarks/artifacts/20m/packed-wire-size-v1.json`.

The session reference is allocated only after authenticating the public RPC
`ControlMeta` signer. A batch may contain records from one session/replay domain.
The v1 `DXOB` batch authentication preimage covers its version, destination
identity, session reference, account, batch sequence, first canonical command
sequence, signer, inner-envelope length, and the exact compressed inner envelope.
The signed inner envelope in turn commits to record count, raw/LZ4 selection,
uncompressed length, compressed length, CRC, and exact ordered record bytes.
Consequently a record cannot be detached, reordered, replayed under another
session/batch sequence, or redirected to another shard without invalidating the
outer authenticator. Partial-batch validation is atomic: any malformed record,
session mismatch, count mismatch, or authentication failure rejects the complete
batch before admission. Replay state advances only after successful atomic shard
publication, so bounded-backpressure retry is safe but an admitted replay or
sequence gap is rejected.

## Lifecycle receipts

The reliable execution-receipt lane uses message type `0x0102` with a fixed
48-byte `DXBR` v1 payload. It correlates the outer batch sequence and first
command sequence with the exact record count and cumulative admitted,
successfully executed, failed, and finalized counts. The authenticated
TLS/peer connection supplies receipt authenticity; a receipt received on any
other traffic class or message type is rejected.

Receipt stages are fail-closed. An admitted receipt must cover all records and
contain no execution/finality counts. An executed receipt must conserve
`executed + failed == admitted == record_count`. A finalized receipt additionally
requires `finalized == executed` and a Minimmit checkpoint height. An atomic
rejection has zero lifecycle counts and a nonzero typed rejection code. The node
tracks admitted sequence ranges in a preallocated FIFO, rejects admission/effect
gaps, and emits execution evidence only after every effect in the exact range is
terminal. Merely relabeling admission or execution as finality is impossible:
only the Minimmit checkpoint path may promote a complete executed receipt.

The composed node component persists the exact authenticated `DXOB` bytes to a
`SyncPolicy::Always` journal before publishing any command to the shard SPSC ring.
Only then may it emit `Admitted`; it emits `Executed` only after the shard worker has
returned an effect for every sequence in the batch. Recovery re-verifies and replays
the journal into a fresh deterministic engine and must reproduce the same state root.
The node now has a bounded Minimmit wall-clock/P0-frame driver and a fail-closed
receipt bridge that binds `block.payload_root` to the checkpoint header and the
execution L-certificate's deterministic state root to `checkpoint.new_state_root`
before promotion. The checkpoint's `execution_root` separately commits the
per-command execution-result hashes. `serve_packed_with_finality`
retains executed-receipt routes and delivers the asynchronously promoted third
receipt through the connection's sole writer; direct finality not first bound to
a registered checkpoint is rejected. The Phase-0 `Node::run` role skeleton still
does not instantiate this stack from operator config, so this tested composition
is not yet a deployed validator-capacity claim.

`loadgen::run_live_packed` drives this lane over persistent framed TCP/TLS connections.
Each connection requires a server-issued lease containing its batch/command starts
and explicit `batch_sequence_stride` / `command_sequence_stride`. Multi-connection
leases are striped by fixed batch across one global sequence: every stripe is
registered at the validator, a future stripe waits without admission, and stale or
unstriped traffic fails closed. Colliding lanes, inconsistent strides, duplicate
session/client identities, receipt gaps, rejection, timeout, or lifecycle-counter
mismatch invalidate the run. A
`component` profile may select the `Executed` boundary. A `validator` profile is
accepted only with TLS 1.3 and the `Finalized` boundary, and therefore cannot turn the
current component server into validator-capacity evidence.

Decoders reject unsupported versions, unknown tags, non-canonical lengths,
reserved flags, truncation, invalid enum values, zero order ids, and invalid
positive price/quantity/leverage bounds before allocation. V1 negotiation succeeds
only when the peer range includes version 1; there is no silent downgrade. Golden
bytes and a SHA-256 digest pin cross-architecture compatibility.
A checked-in libFuzzer target also exercises arbitrary decoder inputs and asserts
that every accepted prefix re-encodes to the identical canonical bytes:

```sh
rustup run nightly cargo fuzz run packed_order_decode -- -max_total_time=60
```

A pinned Rust 1.92 x86_64 Mach-O run under Rosetta passed all 284 codec, network,
and node unit/integration tests with the same golden digest. Its exact command and
limitations are archived in
`crates/benchmarks/artifacts/20m/packed-x86_64-rosetta-determinism-v1.json`;
Rosetta selected the scalar backend, so this is determinism evidence rather than
x86 SIMD performance evidence.

## SIMD qualification

Packed records are represented as five (cancel) or seven (submit/replace)
canonical little-endian `u64` lanes. The batch codec retains the checked scalar
reference and has isolated AVX2, AVX-512F, and NEON unaligned lane load/store
kernels. Runtime detection occurs once. Forced unavailable backends fail at
selection rather than silently changing the requested backend.

The corrected-idempotency Apple aarch64 paired run found a repeatable
128-record benefit (encode p50 1125 ns scalar versus 583 ns NEON; decode 1417
ns versus 1209 ns),
with zero allocations in both paths. The 32/64-record candidates were tied or
slightly slower, so those sizes deliberately remain scalar. Full cross-host
cycles/order and variance evidence remains part of the final #577 campaign; the
figures here are component evidence, not a composed throughput claim.
