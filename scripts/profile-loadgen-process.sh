#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 PID OUTPUT_DIRECTORY [DURATION_SECONDS]" >&2
  exit 2
fi
if [[ "$(uname -s)" != Linux ]]; then
  echo "error: process profiling requires Linux /proc" >&2
  exit 2
fi

pid=$1
output=$2
duration=${3:-360}
[[ "$pid" =~ ^[0-9]+$ && "$duration" =~ ^[0-9]+$ ]] || {
  echo "error: PID and duration must be positive integers" >&2
  exit 2
}
kill -0 "$pid" 2>/dev/null || { echo "error: PID $pid is not running" >&2; exit 1; }
mkdir -p "$output"

uname -a >"$output/uname.txt"
lscpu >"$output/lscpu.txt"
cp /proc/meminfo "$output/meminfo-before.txt"
cp /proc/net/dev "$output/net-dev-before.txt"
if command -v ethtool >/dev/null; then
  for interface in /sys/class/net/*; do
    name=${interface##*/}
    ethtool -S "$name" >"$output/ethtool-$name-before.txt" 2>&1 || true
  done
fi

if command -v perf >/dev/null; then
  timeout "$duration" perf stat -d -x, -p "$pid" -o "$output/perf-stat.csv" &
  perf_pid=$!
else
  perf_pid=
fi

deadline=$((SECONDS + duration))
while ((SECONDS < deadline)) && kill -0 "$pid" 2>/dev/null; do
  timestamp=$(date -u +%s)
  status=$(awk '/^(VmRSS|VmHWM|Threads):/{printf "%s=%s%s ", $1, $2, $3}' "/proc/$pid/status")
  fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  printf '%s %sFDs=%s\n' "$timestamp" "$status" "$fds" >>"$output/process-samples.txt"
  sleep 1
done

if [[ -n "$perf_pid" ]]; then
  wait "$perf_pid" || true
fi
cp /proc/meminfo "$output/meminfo-after.txt"
cp /proc/net/dev "$output/net-dev-after.txt"
ss -s >"$output/socket-summary.txt" 2>&1 || true
nstat -az >"$output/network-counters.txt" 2>&1 || true
if command -v ethtool >/dev/null; then
  for interface in /sys/class/net/*; do
    name=${interface##*/}
    ethtool -S "$name" >"$output/ethtool-$name-after.txt" 2>&1 || true
  done
fi
