#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo build --locked -p market-loadgen

tmp="$(mktemp -d)"
sink_pid=""
generator_pid=""
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$generator_pid" ]] && kill -0 "$generator_pid" 2>/dev/null; then
    kill -KILL "$generator_pid" 2>/dev/null || true
    wait "$generator_pid" 2>/dev/null || true
  fi
  if [[ -n "$sink_pid" ]] && kill -0 "$sink_pid" 2>/dev/null; then
    kill -TERM "$sink_pid" 2>/dev/null || true
    wait "$sink_pid" 2>/dev/null || true
  fi
  if ((status != 0)); then
    for log in "$tmp"/*.log; do
      [[ -f "$log" ]] && sed -n '1,200p' "$log" >&2
    done
  fi
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT

target/debug/market-loadgen-campaign reference-sink --listen 127.0.0.1:9900 \
  >"$tmp/sink.json" 2>"$tmp/sink.log" &
sink_pid=$!

for _ in {1..50}; do
  if (exec 3<>/dev/tcp/127.0.0.1/9900) 2>/dev/null; then
    exec 3>&-
    break
  fi
  sleep 0.1
done

run_signal() {
  signal=$1
  scenario="$tmp/scenario-$signal.toml"
  sed \
    -e 's/duration_secs = 1/duration_secs = 30/' \
    -e "s#directory = .*#directory = \"$tmp/artifacts-$signal\"#" \
    config/loadgen/local-sink.toml >"$scenario"

  target/debug/market-loadgen-campaign --scenario "$scenario" \
    >"$tmp/generator-$signal.json" 2>"$tmp/generator-$signal.log" &
  generator_pid=$!
  sleep 0.5
  kill -"$signal" "$generator_pid"
  if wait "$generator_pid"; then
    echo "error: $signal-interrupted loadgen unexpectedly exited successfully" >&2
    exit 1
  else
    status=$?
  fi
  generator_pid=""
  if [[ "$status" -ne 1 ]]; then
    echo "error: $signal-interrupted loadgen was not cooperatively drained (status=$status)" >&2
    exit 1
  fi
  grep -q '"interrupted":true' "$tmp/generator-$signal.json"
  grep -q '"target":"reference-sink-test-only"' "$tmp/generator-$signal.json"
  grep -q 'live run violated a configured threshold or conservation gate' \
    "$tmp/generator-$signal.log"
}

run_signal TERM
run_signal INT

kill -TERM "$sink_pid"
wait "$sink_pid"
sink_pid=""

grep -q '"mode":"reference-sink-test-only"' "$tmp/sink.json"
grep -q '"fault":"immediate-ack"' "$tmp/sink.json"
grep -q '"signature_validation":true' "$tmp/sink.json"
grep -q '"transport_errors":0' "$tmp/sink.json"
grep -q '"histogram_merge_errors":0' "$tmp/sink.json"
grep -q '"processing_latency"' "$tmp/sink.json"

echo "loadgen SIGINT/SIGTERM smoke passed"
