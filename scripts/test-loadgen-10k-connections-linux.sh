#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Linux ]] || [[ "${EUID:-$(id -u)}" -ne 0 ]] || ! command -v ip >/dev/null; then
  echo "SKIP: 10k source-sharding test requires Linux root and iproute2"
  exit 0
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
cargo build --locked -p market-loadgen
binary="$root/target/debug/market-loadgen-campaign"
tmp="$(mktemp -d)"
namespace="dexos-loadgen-$$"
pids=()
cleanup() {
  for pid in "${pids[@]-}"; do
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  ip netns del "$namespace" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

ip netns add "$namespace"
ip -n "$namespace" link set lo up
ip -n "$namespace" address add 127.0.0.2/8 dev lo
ip -n "$namespace" address add 127.0.0.3/8 dev lo
ip -n "$namespace" -6 address add fd00:552::2/128 dev lo
ip -n "$namespace" -6 address add fd00:552::3/128 dev lo

ip netns exec "$namespace" sh -c "ulimit -n 40000; exec '$binary' reference-sink --listen 127.0.0.1:9900 --skip-signature-validation" \
  >"$tmp/sink-v4.json" 2>"$tmp/sink-v4.log" &
pids+=("$!")
ip netns exec "$namespace" sh -c "ulimit -n 40000; exec '$binary' reference-sink --listen '[::1]:9901' --skip-signature-validation" \
  >"$tmp/sink-v6.json" 2>"$tmp/sink-v6.log" &
pids+=("$!")
sleep 0.5

cat >"$tmp/scenario.toml" <<'EOF'
schema_version = 2
mode = "Sink"
role = "Local"
seed = 559
orders_per_second = 10000
duration_secs = 1
drain_timeout_secs = 10
worker_count = 8
in_flight_per_connection = 2
market_ids = [1]

[operation_mix]
new = 1000000
cancel = 0
replace = 0

[output]
directory = "/tmp/dexos-loadgen-10k-artifacts"
interval_jsonl = true
human = false

[[regions]]
name = "ipv4"
users = 5000
source_ips = ["127.0.0.2", "127.0.0.3"]

[[regions.endpoints]]
name = "sink-v4"
address = "127.0.0.1:9900"
connections_per_source_ip = 2500
target_kind = "ReferenceSink"

[[regions]]
name = "ipv6"
users = 5000
source_ips = ["fd00:552::2", "fd00:552::3"]

[[regions.endpoints]]
name = "sink-v6"
address = "[::1]:9901"
connections_per_source_ip = 2500
target_kind = "ReferenceSink"
EOF

ip netns exec "$namespace" sh -c "ulimit -n 40000; exec '$binary' --scenario '$tmp/scenario.toml' local --target-kind sink" \
  >"$tmp/generator.json"
grep -q '"connections":10000' "$tmp/generator.json"
grep -q '"socket_written":10000' "$tmp/generator.json"

echo "10k IPv4/IPv6 source-sharded connection test passed"
