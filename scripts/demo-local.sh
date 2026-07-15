#!/usr/bin/env bash
# Local regional process-smoke demo: starts four independent composition
# skeletons on distinct metrics ports, shows their startup manifests, then
# shuts them down on SIGINT/SIGTERM. This does not exercise peer networking,
# execution, consensus, durable recovery, or failover.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building marketd (release)"
cargo build --release --locked --bin marketd

BIN=./target/release/marketd
RUN=$(mktemp -d)
trap 'echo "==> stopping nodes"; kill -TERM ${PIDS[@]:-} 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$RUN"' EXIT

# Example configs already use non-colliding ports (us/eu/tokyo/light).
# Copy them into the temp dir so per-node data dirs stay under $RUN.
for name in us eu tokyo light; do
  sed "s#data_dir = \"./data/#data_dir = \"$RUN/data/#g" "config/${name}.toml" > "$RUN/${name}.toml"
done
# Shared validators set next to the resolved configs.
cp config/validators.toml "$RUN/validators.toml"
# Point validator_set_path at the temp copy (paths resolve relative to config file dir).
for name in us eu tokyo light; do
  # already "validators.toml" relative to $RUN — good.
  :
done

PIDS=()
NAMES=(us eu tokyo light)
start() { # name config extra...
    echo "==> starting $1"
    RUST_LOG=info $BIN run --config "$RUN/$2.toml" "${@:3}" >"$RUN/$1.log" 2>&1 &
    PIDS+=($!)
}
start us    us
start eu    eu
start tokyo tokyo
start light light

sleep 2
for idx in "${!PIDS[@]}"; do
  if ! kill -0 "${PIDS[$idx]}" 2>/dev/null; then
    echo "error: ${NAMES[$idx]:-process-$idx} exited during startup" >&2
    sed -n '1,160p' "$RUN/${NAMES[$idx]:-process-$idx}.log" >&2 || true
    exit 1
  fi
done
echo
echo "==> startup manifests:"
grep -h "dexos node" "$RUN"/*.log || true
echo
echo "==> probe metrics (us-1 metrics_listen 127.0.0.1:9100) if bound:"
curl -sS "http://127.0.0.1:9100/livez" || true
echo
curl -sS "http://127.0.0.1:9100/readyz" || true
echo
echo "Four independent regional process-smoke runtimes are running."
echo "They are not a connected cluster and do not prove execution or consensus."
echo "Press Ctrl-C to stop them (SIGTERM drain under performance.drain_timeout_ms)."
wait
