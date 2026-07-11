#!/usr/bin/env bash
# Single-market benchmark: runs the purpose-built harness and emits a
# machine-readable report plus a rendered summary. Targets the engine-only and
# order-book hot-path suites.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-results.json}"
echo "==> building marketd (release)"
cargo build --release --bin marketd
echo "==> running benchmark suite -> $OUT"
./target/release/marketd benchmark --suite all --output "$OUT"
echo
if [ -f "$OUT" ]; then
    echo "==> wrote $OUT ($(wc -c < "$OUT") bytes)"
fi
echo "==> reproduce any figure with: ./scripts/benchmark-single-market.sh"
