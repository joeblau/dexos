#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 9 ]]; then
  echo "usage: $0 CONTROLLER_HOST GENERATOR_HOST... (eight or more generators)" >&2
  exit 2
fi

controller=$1
shift
generators=("$@")
sink_hosts=()
if [[ -n "${SINK_HOSTS:-}" ]]; then
  IFS=, read -r -a sink_hosts <<<"$SINK_HOSTS"
fi
scenario=${SCENARIO:-config/loadgen/reference-20m.toml}
artifact_root=${ARTIFACT_ROOT:-artifacts/loadgen/reference-20m-$(date -u +%Y%m%dT%H%M%SZ)}

mkdir -p "$artifact_root/hosts"
cp "$scenario" "$artifact_root/scenario.toml"
git rev-parse HEAD >"$artifact_root/commit.txt"
rustc -Vv >"$artifact_root/rustc.txt"

for host in "$controller" "${generators[@]}" "${sink_hosts[@]}"; do
  safe_host=${host//[^a-zA-Z0-9_.-]/_}
  ssh "$host" 'uname -a; lscpu; free -h; ip -details link; sysctl net.ipv4.ip_local_port_range; ulimit -n' \
    >"$artifact_root/hosts/$safe_host.txt"
done

echo "Reference campaign launch is intentionally explicit." >&2
echo "Start authenticated agents on: ${generators[*]}" >&2
if [[ "${#sink_hosts[@]}" -gt 0 ]]; then
  echo "Independently instrumented sink hosts: ${sink_hosts[*]}" >&2
else
  echo "Independently instrumented sink hosts: set SINK_HOSTS" >&2
fi
echo "Then run on $controller:" >&2
echo "  market-loadgen-campaign --scenario $scenario controller --target-kind sink" >&2
echo "Collect every agent, controller, and sink JSONL file under $artifact_root." >&2
echo "This script does not synthesize or claim a 20M result." >&2

if [[ "${EXECUTE:-0}" != 1 ]]; then
  echo "Set EXECUTE=1 only after staging release binaries, per-host scenarios, and independently instrumented sinks." >&2
  exit 0
fi

if [[ "${#sink_hosts[@]}" -lt 2 ]]; then
  echo "error: EXECUTE=1 requires SINK_HOSTS with at least two comma-separated sink hosts" >&2
  exit 2
fi

: "${REMOTE_BINARY:?set REMOTE_BINARY to the staged release market-loadgen-campaign path}"
: "${REMOTE_CONFIG_DIR:?set REMOTE_CONFIG_DIR to the staged scenario directory}"
: "${REMOTE_ARTIFACT_DIR:?set REMOTE_ARTIFACT_DIR to the remote artifact directory}"
: "${REMOTE_SINK_ARTIFACT_DIR:?set REMOTE_SINK_ARTIFACT_DIR to the remote sink artifact directory}"
: "${CONTROLLER_ADDRESS:?set CONTROLLER_ADDRESS to the agent-visible controller host:port}"

mkdir -p "$artifact_root/process" "$artifact_root/remote"
ssh "$controller" "$REMOTE_BINARY" \
  --scenario "$REMOTE_CONFIG_DIR/controller.toml" \
  controller --target-kind sink \
  >"$artifact_root/process/controller.json" \
  2>"$artifact_root/process/controller.log" &
controller_pid=$!
sleep 1

agent_pids=()
for host in "${generators[@]}"; do
  safe_host=${host//[^a-zA-Z0-9_.-]/_}
  ssh "$host" "$REMOTE_BINARY" \
    --scenario "$REMOTE_CONFIG_DIR/agent-$safe_host.toml" \
    agent --controller "$CONTROLLER_ADDRESS" --target-kind sink \
    >"$artifact_root/process/agent-$safe_host.json" \
    2>"$artifact_root/process/agent-$safe_host.log" &
  agent_pids+=("$!")
done

status=0
for pid in "${agent_pids[@]}"; do
  wait "$pid" || status=1
done
wait "$controller_pid" || status=1
if [[ "$status" -ne 0 ]]; then
  echo "error: at least one distributed process failed; artifacts retained" >&2
  exit 1
fi

for host in "$controller" "${generators[@]}"; do
  safe_host=${host//[^a-zA-Z0-9_.-]/_}
  mkdir -p "$artifact_root/remote/$safe_host"
  scp -r "$host:$REMOTE_ARTIFACT_DIR/." "$artifact_root/remote/$safe_host/"
done

for host in "${sink_hosts[@]}"; do
  safe_host=${host//[^a-zA-Z0-9_.-]/_}
  mkdir -p "$artifact_root/remote/sink-$safe_host"
  scp -r "$host:$REMOTE_SINK_ARTIFACT_DIR/." "$artifact_root/remote/sink-$safe_host/"
done

echo "Run scripts/verify-loadgen-qualification.sh after adding independent sink artifacts and setting SINK_FINALS." >&2
