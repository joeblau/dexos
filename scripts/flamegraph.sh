#!/usr/bin/env bash
set -euo pipefail

command -v cargo-flamegraph >/dev/null || {
  echo "cargo-flamegraph is required: cargo install flamegraph --locked" >&2
  exit 1
}

output=${FLAMEGRAPH_OUTPUT:-flamegraph.svg}
cargo flamegraph --profile release-with-debug --output "$output" --bin marketd --features dev-tools -- benchmark --suite all --output /tmp/dexos-bench.json
echo "wrote $output"
