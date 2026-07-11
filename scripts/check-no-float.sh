#!/usr/bin/env bash
# Gate: no floating point in the deterministic execution core.
# "Fixed-point integer arithmetic only" / "No floating-point consensus logic".
set -euo pipefail
cd "$(dirname "$0")/.."

CORE=(types execution orderbook risk state-tree)
status=0
for crate in "${CORE[@]}"; do
    src="crates/$crate/src"
    [ -d "$src" ] || continue
    # Match f32/f64 as whole tokens, ignoring line and doc comments.
    if grep -RInE '\b(f32|f64)\b' "$src" | grep -vE '^\s*[0-9]+:\s*(//|///|//!)'; then
        echo "no-float gate FAILED: floating point in deterministic-core crate '$crate'" >&2
        status=1
    fi
done
if [ "$status" -eq 0 ]; then
    echo "no-float gate: OK (${CORE[*]})"
fi
exit "$status"
