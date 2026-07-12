#!/usr/bin/env bash
# Gate: no floating point in the deterministic execution core.
# "Fixed-point integer arithmetic only" / "No floating-point consensus logic".
set -euo pipefail
cd "$(dirname "$0")/.."

CORE=(types execution orderbook risk state-tree)
status=0
for crate in "${CORE[@]}"; do
    src="crates/$crate/src"
    # Fail closed: a missing/renamed core crate dir must not pass vacuously.
    [ -d "$src" ] || { echo "no-float gate FAILED: core crate dir '$src' missing — update CORE list in $0" >&2; status=1; continue; }
    # Match f32/f64 as whole tokens, ignoring comment-only lines. grep -RIn
    # emits `path:line:content`, so exempt on the content field; a leading
    # `//` also covers `///` and `//!`, and a Rust line starting with `//`
    # cannot contain code (trailing comments after code are still flagged).
    if grep -RInE '\b(f32|f64)\b' "$src" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//'; then
        echo "no-float gate FAILED: floating point in deterministic-core crate '$crate'" >&2
        status=1
    fi
done
if [ "$status" -eq 0 ]; then
    echo "no-float gate: OK (${CORE[*]})"
fi
exit "$status"
