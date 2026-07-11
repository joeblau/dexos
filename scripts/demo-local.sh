#!/usr/bin/env bash
# Local three-region demo: starts three full nodes (US / EU / Japan) and one
# light node on distinct ports, shows their startup manifests, then shuts them
# down cleanly on SIGINT. Preserves the production process model (separate
# marketd processes with region configs).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building marketd (release)"
cargo build --release --bin marketd

BIN=./target/release/marketd
RUN=$(mktemp -d)
trap 'echo "==> stopping nodes"; kill -INT ${PIDS[@]:-} 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$RUN"' EXIT

# Derive per-node configs with distinct listen/rpc ports so they coexist on one host.
mkconf() { # name base_config listen_port rpc_port
    sed -E "s#listen = \"0.0.0.0:9000\"#listen = \"0.0.0.0:$3\"#; s#listen = \"0.0.0.0:8080\"#listen = \"0.0.0.0:$4\"#" \
        "config/$2.toml" > "$RUN/$1.toml"
}
mkconf us    us    9000 8080
mkconf eu    eu    9010 8081
mkconf tokyo tokyo 9020 8082
mkconf light light 9030 8083

PIDS=()
start() { # name config extra...
    echo "==> starting $1"
    RUST_LOG=info $BIN run --config "$RUN/$2.toml" "${@:3}" >"$RUN/$1.log" 2>&1 &
    PIDS+=($!)
}
start us    us
start eu    eu
start tokyo tokyo
start light light --light

sleep 2
echo
echo "==> startup manifests:"
grep -h "dexos node" "$RUN"/*.log || true
echo
echo "Three full nodes (US/EU/Japan) + one light node are running."
echo "Press Ctrl-C to stop them (they drain their bounded queues and exit cleanly)."
wait
