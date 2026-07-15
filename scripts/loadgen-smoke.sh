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
  --scenario config/loadgen/local-sink.toml \
  >"$tmp/generator.json"

kill -INT "$sink_pid"
wait "$sink_pid"
sink_pid=""

grep -q '"target":"reference-sink-test-only"' "$tmp/generator.json"
grep -q '"mode":"reference-sink-test-only"' "$tmp/sink.json"
grep -q '"socket_written":1000' "$tmp/generator.json"
test "$(wc -l < artifacts/loadgen/local-sink/intervals.jsonl)" -eq 1
test -s artifacts/loadgen/local-sink/provenance.json

echo "loadgen smoke passed"
