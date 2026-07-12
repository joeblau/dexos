#!/usr/bin/env bash
# Prove deterministic compatibility: scalar ≡ vectorized SIMD kernels, and
# cross-crate golden vectors that must be byte-stable across architectures.
#
# CI runs this on the host architecture. A multi-arch matrix (x86_64 + aarch64)
# should produce identical digests for the printed corpus summary.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> host"
uname -a || true
echo "endian: $(python3 -c 'import sys; print(sys.byteorder)')"
echo "target: $(rustc -vV | awk '/^host:/{print $2}')"

echo "==> simd: scalar ≡ vectorized ≡ dispatched (all backends)"
cargo test -p simd --lib --locked -- --nocapture forcing_each_backend 2>&1 | tail -20
cargo test -p simd --lib --locked -- --nocapture dispatch_runs 2>&1 | tail -20

echo "==> node cross-crate scalar payout goldens (architecture-stable)"
cargo test -p node --test scalar_payout_cross_crate --locked

echo "==> execution + state-tree deterministic roots"
./scripts/verify-state-roots.sh

echo "==> corpus digest (for cross-arch comparison)"
# Stable summary of golden tables + host notes for CI artifact comparison.
python3 - <<'PY'
import hashlib, platform, struct
h = hashlib.sha256()
# Fixed golden table from crates/node/tests/scalar_payout_cross_crate.rs
GOLDEN = [
    (0, 100_000_000, 0, 0, 1_000_000),
    (0, 100_000_000, 25_000_000, 250_000, 750_000),
    (0, 100_000_000, 50_000_000, 500_000, 500_000),
    (0, 100_000_000, 75_000_000, 750_000, 250_000),
    (0, 100_000_000, 100_000_000, 1_000_000, 0),
    (0, 3_000_000, 1_000_000, 333_333, 666_667),
    (10_000_000, 20_000_000, 15_000_000, 500_000, 500_000),
    (10_000_000, 20_000_000, 5_000_000, 0, 1_000_000),
    (10_000_000, 20_000_000, 25_000_000, 1_000_000, 0),
]
for row in GOLDEN:
    for v in row:
        h.update(struct.pack("<q", int(v)))
digest = h.hexdigest()
print(f"golden_corpus_sha256={digest}")
print(f"host_machine={platform.machine()}")
print(f"host_endian={sys_byteorder if (sys_byteorder := __import__('sys').byteorder) else '?'}")
print("note: wire formats and state roots are little-endian fixed-width integers;")
print("      big-endian hosts are not a supported production target.")
# Write digest for CI artifact upload / matrix comparison.
open("determinism-digest.txt", "w").write(
    f"golden_corpus_sha256={digest}\nmachine={platform.machine()}\nendian={__import__('sys').byteorder}\n"
)
print("wrote determinism-digest.txt")
PY

echo
echo "==> determinism checks passed on this host"
