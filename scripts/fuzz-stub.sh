#!/usr/bin/env bash
# Fuzz / property-test stub for CI.
#
# These are placeholder steps (existing workspace test invocations) until real
# cargo-fuzz targets for codec/RPC/storage/config land with those epics. The
# deterministic LCG property tests below exercise the same surfaces.
#
# The former per-step soft time budget (SECONDS-based deadline) was removed:
# SECONDS includes cargo compile time, so on a cold cache the first step could
# consume the whole budget and every later step was silently skipped while the
# job still passed. All steps now run unconditionally; wall-clock is bounded by
# the GitHub Actions job-level timeout instead.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> fuzz stub — property tests as interim coverage (all steps run unconditionally)"

run_step() {
  local label="$1"
  shift
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
echo "==> fuzz stub completed"
echo "note: replace with cargo-fuzz targets when codec/RPC/storage fuzz harnesses land"
