#!/usr/bin/env bash
# Local three-region demo: starts three full nodes (US / EU / Japan) and one
# light node on distinct ports, shows their startup manifests, then shuts them
# down cleanly on SIGINT/SIGTERM. Preserves the production process model (separate
# marketd processes with region configs).
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
echo
echo "==> startup manifests:"
grep -h "dexos node" "$RUN"/*.log || true
echo
echo "==> probe metrics (us-1 metrics_listen 127.0.0.1:9100) if bound:"
curl -sS "http://127.0.0.1:9100/livez" || true
echo
curl -sS "http://127.0.0.1:9100/readyz" || true
echo
echo "Three full nodes (US/EU/Japan) + one light node are running."
echo "Press Ctrl-C to stop them (SIGTERM drain under performance.drain_timeout_ms)."
wait
