# `@dexos/sdk`

Node.js TypeScript client for DexOS packed order batches. It supports canonical
submit/cancel/replace records, raw v1 envelopes, Ed25519 batch authentication,
persistent TCP or certificate-verified TLS 1.3 connections, strict replay
sequences, and admitted/executed/finalized receipts.

All 64-bit wire integers use `bigint`; fixed-point price, quantity, and leverage
values must already be scaled by the application. Plaintext is an explicit
development transport. Production callers should use `tls13` and a server-issued
`PackedLease`.

From this repository:

```sh
cd sdk/typescript
npm install
npm test
```

Applications construct a `PackedLease` from the server-issued session values,
then connect with a 32-byte session signing seed:

```ts
import { PackedClient } from "@dexos/sdk";

const client = await PackedClient.connect(lease, signingSeed, {
  kind: "tls13",
  serverName: "validator.example",
  ca: deploymentCaPem,
});
const result = await client.sendBatch(records, "finalized");
```

`sendBatch` is serialized per client. Open one client per disjoint lease for
concurrency. After an ambiguous socket, timeout, rejection, or protocol error,
the instance fails closed and must be replaced with a reconciled server lease.
Executed-only calls retain up to 65,536 batch keys for late finality receipts;
once that protocol limit is reached, another executed-only call is rejected
before it writes to the socket. A finalized call can still drain late finality.
