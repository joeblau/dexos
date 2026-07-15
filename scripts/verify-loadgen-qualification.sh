#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 ARTIFACT_ROOT" >&2
  exit 2
fi
command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 2; }

root=$1
controller=${CONTROLLER_FINAL:-$root/controller/final.json}
intervals=${CONTROLLER_INTERVALS:-$root/controller/intervals.jsonl}
if [[ ! -s "$controller" || ! -s "$intervals" ]]; then
  echo "error: controller final.json and intervals.jsonl are required" >&2
  exit 1
fi

jq -e '
  .mode == "distributed" and
  (.agents | length) >= 8 and
  .aggregate.target == "reference-sink-test-only" and
  .aggregate.connections >= 10000 and
  .aggregate.interval_metrics_lost == 0 and
  .aggregate.scheduler_rate_debt == 0 and
  .aggregate.interrupted == false and
  .aggregate.request_to_ack.overflow == 0 and
  .aggregate.request_to_ack.saturated == 0
' "$controller" >/dev/null || {
  echo "error: controller final report fails distributed qualification invariants" >&2
  exit 1
}

interval_count=$(wc -l < "$intervals" | tr -d ' ')
if [[ "$interval_count" -ne 300 ]]; then
  echo "error: expected 300 steady intervals, found $interval_count" >&2
  exit 1
fi
jq -se '
  def hist_ok:
    .overflow == 0 and .saturated == 0 and
    .p50 <= .p95 and .p95 <= .p99 and .p99 <= .p999;
  length == 300 and all(.[ ];
    .socket_written >= 20000000 and
    .overflow == 0 and
    ((.failures * 1000000) <= (.offered * 100)) and
    (.queue_delay | hist_ok) and
    (.request_to_ack | hist_ok) and
    (.action_queue_delay.new | hist_ok) and
    (.action_queue_delay.cancel | hist_ok) and
    (.action_queue_delay.replace | hist_ok) and
    (.action_request_to_ack.new | hist_ok) and
    (.action_request_to_ack.cancel | hist_ok) and
    (.action_request_to_ack.replace | hist_ok) and
    (.actions.new.socket_written + .actions.cancel.socket_written + .actions.replace.socket_written) == .socket_written and
    (.action_queue_delay.new.count + .action_queue_delay.cancel.count + .action_queue_delay.replace.count) == .queue_delay.count and
    (.action_request_to_ack.new.count + .action_request_to_ack.cancel.count + .action_request_to_ack.replace.count) == .request_to_ack.count and
    (.dimensions | length) > 0 and
    ([.dimensions[].counters.socket_written] | add) == .socket_written and
    ([.dimensions[].queue_delay.count] | add) == .queue_delay.count and
    ([.dimensions[].request_to_ack.count] | add) == .request_to_ack.count and
    all(.dimensions[]; (.queue_delay | hist_ok) and (.request_to_ack | hist_ok))
  )
' "$intervals" >/dev/null || {
  echo "error: at least one steady interval violates the rate, failure, or dimensional metric gate" >&2
  exit 1
}

controller_dir=$(dirname "$controller")
agent_interval_count=0
if [[ -d "$controller_dir/agents" ]]; then
  while IFS= read -r agent_intervals; do
    [[ -n "$agent_intervals" ]] || continue
    agent_interval_count=$((agent_interval_count + 1))
    count=$(wc -l < "$agent_intervals" | tr -d ' ')
    if [[ "$count" -ne 300 ]]; then
      echo "error: expected 300 intervals in $agent_intervals, found $count" >&2
      exit 1
    fi
    jq -se '
      length == 300 and all(.[ ];
        (.actions.new.socket_written + .actions.cancel.socket_written + .actions.replace.socket_written) == .socket_written and
        (.dimensions | length) > 0 and
        ([.dimensions[].counters.socket_written] | add) == .socket_written
      )
    ' "$agent_intervals" >/dev/null || {
      echo "error: agent interval dimensions do not reconcile in $agent_intervals" >&2
      exit 1
    }
  done < <(find "$controller_dir/agents" -name intervals.jsonl -type f | sort)
fi
if [[ "$agent_interval_count" -lt 8 ]]; then
  echo "error: controller artifacts for eight agent interval streams are required" >&2
  exit 1
fi

written=$(jq -r '.aggregate.socket_written' "$controller")
acknowledged=$(jq -r '.aggregate.acknowledged' "$controller")
if [[ -n "${SINK_FINALS:-}" ]]; then
  IFS=: read -r -a sink_finals <<<"$SINK_FINALS"
  received=0
  sink_acknowledged=0
  for sink in "${sink_finals[@]}"; do
    [[ -s "$sink" ]] || { echo "error: missing sink artifact $sink" >&2; exit 1; }
    jq -e '
      .processing_latency as $hist |
      .mode == "reference-sink-test-only" and
      .transport == "tls13" and
      .fault == "immediate-ack" and
      .signature_validation == true and
      .malformed == 0 and
      .transport_errors == 0 and
      .histogram_merge_errors == 0 and
      (.new_orders + .cancels + .replaces) == .received and
      $hist.count == .received and
      $hist.saturated == 0 and
      $hist.overflow == 0 and
      ($hist.raw | length) == 2048 and
      ($hist.raw | add) == $hist.count
    ' "$sink" >/dev/null
    received=$((received + $(jq -r '.received' "$sink")))
    sink_acknowledged=$((sink_acknowledged + $(jq -r '.acknowledged' "$sink")))
  done
  if [[ "$written" -ne "$received" || "$acknowledged" -ne "$sink_acknowledged" ]]; then
    echo "error: generator/sink final counters do not reconcile" >&2
    exit 1
  fi
else
  echo "error: SINK_FINALS must list independently collected sink final JSON files" >&2
  exit 1
fi

provenance_count=$(find "$root" -name provenance.json -type f | wc -l | tr -d ' ')
if [[ "$provenance_count" -lt 9 ]]; then
  echo "error: controller and eight-agent provenance artifacts are required" >&2
  exit 1
fi
while IFS= read -r provenance; do
  jq -e '
    (.commit | length) > 0 and
    (.rustc | length) > 0 and
    (.host | length) > 0 and
    (.scenario_hash_fnv1a64 | length) == 16 and
    .release_build == true and
    .phase_seconds.warmup == 30 and
    .phase_seconds.steady == 300
  ' "$provenance" >/dev/null
done < <(find "$root" -name provenance.json -type f)

host_inventory_count=0
if [[ -d "$root/hosts" ]]; then
  host_inventory_count=$(find "$root/hosts" -name '*.txt' -type f | wc -l | tr -d ' ')
fi
if [[ "$host_inventory_count" -lt 11 ]]; then
  echo "error: controller, eight-generator, and two-sink host inventories are required" >&2
  exit 1
fi

echo "PASS: independently reconciled 20M+ reference-sink qualification artifacts"
