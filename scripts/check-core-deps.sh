#!/usr/bin/env bash
# Gate: the deterministic execution core must not depend on async runtimes,
# networking, discovery, RPC, or storage crates (strict dependency direction).
set -euo pipefail
cd "$(dirname "$0")/.."

CORE=(types execution orderbook risk state-tree)
# Forbidden dependency crate names (whole-word match in the cargo tree).
FORBIDDEN='tokio|async-std|network|discovery|rpc|storage'
status=0
for crate in "${CORE[@]}"; do
    tree="$(cargo tree --quiet -e normal -p "$crate" 2>/dev/null || true)"
    # Drop the first line (the crate itself) before scanning its dependencies.
    hits="$(printf '%s\n' "$tree" | tail -n +2 | grep -Eiw "$FORBIDDEN" || true)"
    if [ -n "$hits" ]; then
        echo "dep-direction gate FAILED: core crate '$crate' reaches a forbidden dependency:" >&2
        printf '%s\n' "$hits" >&2
        status=1
    fi
done
if [ "$status" -eq 0 ]; then
    echo "dep-direction gate: OK (${CORE[*]} are runtime/network/storage free)"
fi
exit "$status"
