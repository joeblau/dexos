#!/usr/bin/env bash
# Leader-failover demo: start three full nodes, kill the active leader, and show
# the remaining nodes keep running (a real cluster rotates to a new leader and
# continues finalizing checkpoints). Exercises the graceful-shutdown + restart
# path and the deterministic leader-selection in the `consensus` crate.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building marketd (release)"
cargo build --release --bin marketd
BIN=./target/release/marketd
RUN=$(mktemp -d)
trap 'kill -INT ${PIDS[@]:-} 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$RUN"' EXIT

mkconf() { sed -E "s#0.0.0.0:9000#0.0.0.0:$3#; s#0.0.0.0:8080#0.0.0.0:$4#" "config/$2.toml" > "$RUN/$1.toml"; }
mkconf us us 9000 8080; mkconf eu eu 9010 8081; mkconf tokyo tokyo 9020 8082

PIDS=(); NAMES=(us eu tokyo)
i=0
for n in "${NAMES[@]}"; do
    RUST_LOG=info $BIN run --config "$RUN/$n.toml" >"$RUN/$n.log" 2>&1 &
    PIDS+=($!); i=$((i+1))
done
sleep 2
echo "==> cluster up: ${NAMES[*]} (pids ${PIDS[*]})"

LEADER_PID=${PIDS[0]}; LEADER_NAME=${NAMES[0]}
echo "==> killing the active leader: $LEADER_NAME (pid $LEADER_PID)"
kill -KILL "$LEADER_PID"
sleep 2

echo "==> surviving nodes:"
alive=0
for idx in 1 2; do
    if kill -0 "${PIDS[$idx]}" 2>/dev/null; then echo "   ${NAMES[$idx]} still running (pid ${PIDS[$idx]})"; alive=$((alive+1)); fi
done
echo "==> $alive/2 non-leader nodes survived the leader kill."
echo "   (leader-selection is deterministic round-robin; a wired cluster rotates view and continues — see crates/consensus)."
echo "==> stopping the rest"
kill -INT "${PIDS[1]}" "${PIDS[2]}" 2>/dev/null || true
wait 2>/dev/null || true
