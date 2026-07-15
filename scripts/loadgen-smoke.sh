#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo build --locked -p market-loadgen

tmp="$(mktemp -d)"
sink_pid=""
cleanup() {
  if [[ -n "$sink_pid" ]] && kill -0 "$sink_pid" 2>/dev/null; then
    kill -INT "$sink_pid" 2>/dev/null || true
    wait "$sink_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

target/debug/market-loadgen-campaign reference-sink \
  --listen 127.0.0.1:9900 \
  >"$tmp/sink.json" 2>"$tmp/sink.log" &
sink_pid=$!

for _ in {1..50}; do
  if (exec 3<>/dev/tcp/127.0.0.1/9900) 2>/dev/null; then
    exec 3>&-
    break
  fi
  sleep 0.1
done

target/debug/market-loadgen-campaign \
  --scenario config/loadgen/local-sink-smoke.toml \
  >"$tmp/generator.json"

kill -INT "$sink_pid"
wait "$sink_pid"
sink_pid=""

python3 - "$tmp/generator.json" "$tmp/sink.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    generator = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    sink = json.load(handle)

assert generator["target"] == "reference-sink-test-only"
assert sink["mode"] == "reference-sink-test-only"
assert generator["socket_written"] > 0
assert generator["acknowledged"] > 0
assert generator["acknowledged"] == generator["accepted"] + generator["rejected"]
assert sink["received"] == generator["socket_written"]
assert sink["acknowledged"] == generator["acknowledged"]
PY
test "$(wc -l < artifacts/loadgen/local-sink-smoke/intervals.jsonl)" -eq 1
test -s artifacts/loadgen/local-sink-smoke/provenance.json

echo "loadgen smoke passed"
