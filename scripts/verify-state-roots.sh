#!/usr/bin/env bash
# Verify deterministic state-root agreement: identical command streams must
# produce bit-identical state roots on every node, and surviving nodes must agree
# after faults. These properties are proven by the deterministic-replay tests in
# `execution` and the multi-node agreement tests in `simulation`.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> execution: deterministic replay yields identical state roots"
cargo test -p execution --quiet deterministic_replay

echo "==> state-tree: incremental root equals from-scratch recomputation"
cargo test -p state-tree --quiet incremental 2>/dev/null || cargo test -p state-tree --quiet

echo "==> simulation: surviving honest nodes agree on finalized state roots"
cargo test -p simulation --quiet

echo
echo "==> state-root agreement verified across deterministic replay + multi-node simulation."
