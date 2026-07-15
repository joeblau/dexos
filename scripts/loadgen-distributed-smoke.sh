#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
cargo build --locked -p market-loadgen

tmp="$(mktemp -d)"
pids=()
cleanup() {
  status=$?
  trap - EXIT
  if ((status != 0)); then
    for log in "$tmp"/*.log; do
      if [[ -f "$log" ]]; then
        printf 'distributed smoke failure: %s\n' "$log" >&2
        sed -n '1,200p' "$log" >&2
      fi
    done
  fi
  for pid in "${pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -INT "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT

printf '%s\n' 'ci-only-loadgen-control-secret-563' >"$tmp/token"
for name in distributed-controller-smoke distributed-agent-a-smoke distributed-agent-b-smoke distributed-agent-c-smoke; do
  sed "s#secrets/loadgen-smoke.token#$tmp/token#g" \
    "config/loadgen/$name.toml" >"$tmp/$name.toml"
done

target/debug/market-loadgen-campaign reference-sink --listen 127.0.0.1:9900 \
  >"$tmp/sink.json" 2>"$tmp/sink.log" &
sink_pid=$!
pids+=("$sink_pid")
for _ in {1..50}; do
  if (exec 3<>/dev/tcp/127.0.0.1/9900) 2>/dev/null; then
    exec 3>&-
    break
  fi
  sleep 0.1
done

target/debug/market-loadgen-campaign \
  --scenario "$tmp/distributed-controller-smoke.toml" \
  controller --target-kind sink >"$tmp/controller.json" 2>"$tmp/controller.log" &
controller_pid=$!
pids+=("$controller_pid")
sleep 0.2

target/debug/market-loadgen-campaign \
  --scenario "$tmp/distributed-agent-a-smoke.toml" \
  agent --controller 127.0.0.1:9910 --target-kind sink \
  >"$tmp/agent-a.json" 2>"$tmp/agent-a.log" &
agent_a_pid=$!
pids+=("$agent_a_pid")
target/debug/market-loadgen-campaign \
  --scenario "$tmp/distributed-agent-b-smoke.toml" \
  agent --controller 127.0.0.1:9910 --target-kind sink \
  >"$tmp/agent-b.json" 2>"$tmp/agent-b.log" &
agent_b_pid=$!
pids+=("$agent_b_pid")
target/debug/market-loadgen-campaign \
  --scenario "$tmp/distributed-agent-c-smoke.toml" \
  agent --controller 127.0.0.1:9910 --target-kind sink \
  >"$tmp/agent-c.json" 2>"$tmp/agent-c.log" &
agent_c_pid=$!
pids+=("$agent_c_pid")

wait "$agent_a_pid"
wait "$agent_b_pid"
wait "$agent_c_pid"
wait "$controller_pid"
kill -INT "$sink_pid"
wait "$sink_pid"

python3 - \
  "$tmp/controller.json" \
  "$tmp/agent-a.json" "$tmp/agent-b.json" "$tmp/agent-c.json" \
  "$tmp/sink.json" <<'PY'
import json
import sys

def read(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)

controller = read(sys.argv[1])
agents = [read(path) for path in sys.argv[2:5]]
sink = read(sys.argv[5])

assert controller["mode"] == "distributed"
assert len(controller["agents"]) == 3
assert all(agent["socket_written"] > 0 for agent in agents)
assert all(agent["acknowledged"] > 0 for agent in agents)
written = sum(agent["socket_written"] for agent in agents)
acknowledged = sum(agent["acknowledged"] for agent in agents)
assert controller["aggregate"]["socket_written"] == written
assert controller["aggregate"]["acknowledged"] == acknowledged
assert sink["received"] == written
assert sink["acknowledged"] == acknowledged
assert sink["transport_errors"] == 0
PY
test "$(wc -l < artifacts/loadgen/distributed-smoke/controller/intervals.jsonl)" -eq 2
test "$(wc -l < artifacts/loadgen/distributed-smoke/agent-agent-a/intervals.jsonl)" -eq 2
test "$(wc -l < artifacts/loadgen/distributed-smoke/agent-agent-b/intervals.jsonl)" -eq 2
test "$(wc -l < artifacts/loadgen/distributed-smoke/agent-agent-c/intervals.jsonl)" -eq 2

echo "distributed loadgen smoke passed"
