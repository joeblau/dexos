#!/usr/bin/env bash
# Gate: no `unsafe` in the deterministic execution core without an explicit,
# documented allow annotation. Belt-and-suspenders alongside the workspace
# `unsafe_code = "deny"` lint.
set -euo pipefail
cd "$(dirname "$0")/.."

CORE=(types execution orderbook risk state-tree)
status=0
for crate in "${CORE[@]}"; do
    src="crates/$crate/src"
    [ -d "$src" ] || continue
    if grep -RInE '\bunsafe\b' "$src" | grep -vE 'allow\(unsafe_code\)|SAFETY:'; then
        echo "unsafe gate FAILED: unannotated unsafe in core crate '$crate'" >&2
        status=1
    fi
done
if [ "$status" -eq 0 ]; then
    echo "unsafe gate: OK (${CORE[*]})"
fi
exit "$status"
