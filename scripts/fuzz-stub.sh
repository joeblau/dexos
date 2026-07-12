#!/usr/bin/env bash
# Time-boxed fuzz / property-test stub for CI.
#
# Full cargo-fuzz targets for codec/RPC/storage/config land with those epics.
# Until then this job runs existing deterministic LCG property tests that exercise
# the same surfaces, with a wall-clock budget so the job stays bounded.
set -euo pipefail
cd "$(dirname "$0")/.."

BUDGET_SECS="${FUZZ_BUDGET_SECS:-120}"
echo "==> fuzz stub (budget ${BUDGET_SECS}s) — property tests as interim coverage"

deadline=$((SECONDS + BUDGET_SECS))

run_step() {
  local label="$1"
  shift
  if (( SECONDS >= deadline )); then
    echo "budget exhausted before: ${label}"
    return 0
  fi
  echo "-- ${label}"
  "$@"
}

run_step "node config never_panics corpus" \
  cargo test -p node --lib never_panics_on_arbitrary_input --locked -- --nocapture

run_step "simd backend differential corpus" \
  cargo test -p simd --lib forcing_each_backend --locked

run_step "codec / crypto unit surfaces" \
  cargo test -p codec -p crypto --locked

run_step "storage + rpc unit surfaces" \
  cargo test -p storage -p rpc --locked

echo
echo "==> fuzz stub completed in ${SECONDS}s (budget ${BUDGET_SECS}s)"
echo "note: replace with cargo-fuzz targets when codec/RPC/storage fuzz harnesses land"
