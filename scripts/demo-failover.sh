#!/usr/bin/env bash
# Process-isolation smoke demo: start three independent composition skeletons,
# kill one, and show the other processes remain alive. This is not a connected
# cluster, does not elect a live leader, and proves no consensus failover.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building marketd (release)"
cargo build --release --locked --bin marketd
BIN=./target/release/marketd
RUN=$(mktemp -d)
trap 'kill -INT ${PIDS[@]:-} 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$RUN"' EXIT

mkconf() { sed -E "s#0.0.0.0:9000#0.0.0.0:$3#; s#0.0.0.0:8080#0.0.0.0:$4#" "config/$2.toml" > "$RUN/$1.toml"; }
mkconf us us 9000 8080; mkconf eu eu 9010 8081; mkconf tokyo tokyo 9020 8082
cp config/validators.toml "$RUN/validators.toml"

PIDS=(); NAMES=(us eu tokyo)
i=0
for n in "${NAMES[@]}"; do
    RUST_LOG=info $BIN run --config "$RUN/$n.toml" >"$RUN/$n.log" 2>&1 &
    PIDS+=($!); i=$((i+1))
done
sleep 2
for idx in "${!PIDS[@]}"; do
    if ! kill -0 "${PIDS[$idx]}" 2>/dev/null; then
        echo "error: ${NAMES[$idx]} exited during startup" >&2
        sed -n '1,160p' "$RUN/${NAMES[$idx]}.log" >&2 || true
        exit 1
    fi
done
echo "==> independent smoke processes up: ${NAMES[*]} (pids ${PIDS[*]})"

FAILED_PID=${PIDS[0]}; FAILED_NAME=${NAMES[0]}
echo "==> killing one smoke process: $FAILED_NAME (pid $FAILED_PID)"
kill -KILL "$FAILED_PID"
sleep 2

echo "==> surviving nodes:"
alive=0
for idx in 1 2; do
    if kill -0 "${PIDS[$idx]}" 2>/dev/null; then echo "   ${NAMES[$idx]} still running (pid ${PIDS[$idx]})"; alive=$((alive+1)); fi
done
echo "==> $alive/2 independent processes survived the unrelated process kill."
echo "   This demonstrates process isolation only; marketd run does not compose live consensus."
echo "==> stopping the rest"
kill -INT "${PIDS[1]}" "${PIDS[2]}" 2>/dev/null || true
wait 2>/dev/null || true
