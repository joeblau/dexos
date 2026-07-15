# DexOS client SDKs

The Rust, TypeScript, and Python libraries connect to the production packed-order
lane. Each implementation covers the complete v1 client-side contract:

- fixed-width submit, cancel, and replace records;
- 32–128 record batch validation;
- raw v1 batch envelopes (plus automatic LZ4 selection in Rust);
- Ed25519 authentication bound to destination, session, account, and replay ranges;
- persistent TCP and certificate-verified TLS 1.3 (`dexos-rpc/1` ALPN);
- strict transport, batch, and command sequence tracking; and
- correlated admitted, executed, rejected, and finalized lifecycle receipts.

| Language | Package | Primary connection type |
| --- | --- | --- |
| Rust | [`client::packed`](../crates/client/src/packed.rs) | async `PackedClient` |
| TypeScript | [`@dexos/sdk`](typescript/) | async `PackedClient` |
| Python | [`dexos-sdk`](python/) | blocking `PackedClient` |

The libraries require a server-issued lease. A lease supplies the target
destination identity, established session reference, authorized account, and
the first/stride values for the replay domains. Signing seeds and private keys
are never derived from a lease and must be provided through a secrets boundary.

`sdk/vectors/packed-v1.json` is consumed by all three test suites. It fixes the
record bytes, raw envelope, authenticated batch, transport frame, Ed25519 public
key, and a lifecycle receipt. A wire change therefore has to move every language
in lockstep.

Plaintext is intentionally named as a development posture. Production callers
should select TLS 1.3, validate the node certificate with their deployment CA,
and supply a client certificate when the listener requires mTLS.
