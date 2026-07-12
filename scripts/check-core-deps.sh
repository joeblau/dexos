#!/usr/bin/env bash
# Gate: the deterministic execution core must not depend on async runtimes,
# networking, discovery, RPC, or storage crates (strict dependency direction).
#
# Enforced fail-closed as an ALLOWLIST: every crate in the normal-dependency
# closure of each core crate must appear in scripts/core-deps-allowlist.txt.
# Any crate not on the list fails the gate — a new dependency must be
# justified and added there explicitly (or removed).
set -euo pipefail
cd "$(dirname "$0")/.."

CORE=(types execution orderbook risk state-tree)
ALLOWLIST=scripts/core-deps-allowlist.txt

if [ ! -f "$ALLOWLIST" ]; then
    echo "dep-direction gate FAILED: allowlist '$ALLOWLIST' is missing" >&2
    exit 1
fi

status=0
for crate in "${CORE[@]}"; do
    # Fail closed: a broken `cargo tree` (missing target, resolver error, …)
    # must not be swallowed. Previously `|| true` hid toolchain/config failures.
    if ! tree="$(cargo tree --quiet -e normal --target all -p "$crate" --prefix none 2>&1)"; then
        echo "dep-direction gate FAILED: cargo tree -p $crate errored:" >&2
        printf '%s\n' "$tree" >&2
        status=1
        continue
    fi
    # Crate names only: first token drops versions and '(*)' dedup markers.
    closure="$(printf '%s\n' "$tree" | awk 'NF {print $1}' | LC_ALL=C sort -u)"
    # Fail closed: anything in the closure but absent from the allowlist fails.
    violations="$(LC_ALL=C comm -23 <(printf '%s\n' "$closure") <(LC_ALL=C sort -u "$ALLOWLIST"))"
    if [ -n "$violations" ]; then
        echo "dep-direction gate FAILED: core crate '$crate' pulls in crate(s) not in $ALLOWLIST:" >&2
        printf '%s\n' "$violations" >&2
        echo "If the new dependency is intentional, justify it in your PR and add the crate name to $ALLOWLIST (one name per line, LC_ALL=C sorted); otherwise remove the dependency." >&2
        status=1
    fi
done
if [ "$status" -eq 0 ]; then
    echo "dep-direction gate: OK (${CORE[*]} depend only on crates in $ALLOWLIST)"
fi
exit "$status"
