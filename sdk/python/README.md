# `dexos-sdk`

Python client for DexOS packed order batches. It supports canonical
submit/cancel/replace records, raw v1 envelopes, Ed25519 batch authentication,
persistent TCP or certificate-verified TLS 1.3 connections, strict replay
sequences, and admitted/executed/finalized receipts.

Wire integers are Python `int` values and are strictly range-checked. Fixed-point
price, quantity, and leverage values must already be scaled by the application.
Plaintext is an explicit development transport. Production callers should use
`Tls13` and a server-issued `PackedLease`.

From this repository:

```sh
python -m venv .venv
.venv/bin/pip install -e sdk/python
PYTHONPATH=sdk/python/src .venv/bin/python -m unittest discover -s sdk/python/tests
```

Applications construct a `PackedLease` from the server-issued session values,
then connect with a 32-byte session signing seed:

```python
from dexos_sdk import CompletionBoundary, PackedClient, Tls13

with PackedClient.connect(
    lease,
    signing_seed,
    Tls13(server_hostname="validator.example", ca_file="deployment-ca.pem"),
) as client:
    result = client.send_batch(records, CompletionBoundary.FINALIZED)
```

`send_batch` is serialized per client. Open one client per disjoint lease for
concurrency. After an ambiguous socket, timeout, rejection, or protocol error,
the instance fails closed and must be replaced with a reconciled server lease.
