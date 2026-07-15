#!/usr/bin/env bash
# Fuzz / property-test gate for CI.
#
# The packed-order decoder has a real libFuzzer target under `fuzz/`; CI builds
# that target so it cannot drift, while the remaining RPC/storage/config
# surfaces retain deterministic property corpora until their cargo-fuzz targets
# land with those epics.
#
# The former per-step soft time budget (SECONDS-based deadline) was removed:
# SECONDS includes cargo compile time, so on a cold cache the first step could
# consume the whole budget and every later step was silently skipped while the
# job still passed. All steps now run unconditionally; wall-clock is bounded by
# the GitHub Actions job-level timeout instead.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> fuzz/property gate (all steps run unconditionally)"

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

run_step "packed-order libFuzzer target builds" \
  cargo check --manifest-path fuzz/Cargo.toml --locked

run_step "storage + rpc unit surfaces" \
  cargo test -p storage -p rpc --locked

echo
echo "==> fuzz/property gate completed"
echo "note: RPC/storage/config still need dedicated cargo-fuzz targets"
