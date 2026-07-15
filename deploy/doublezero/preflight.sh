#!/usr/bin/env bash
set -euo pipefail

: "${DZ_INTERFACE:=doublezero0}"
: "${EXPECTED_MTU:=9000}"
: "${EXPECTED_SPEED_MBPS:=100000}"
: "${DZ_PEERS:?set DZ_PEERS to comma-separated provisioned peer IPs}"

for command in doublezero ip ethtool jq lscpu numactl chronyc sysctl; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

[[ "$(uname -s)" == "Linux" ]] || {
  echo "DoubleZero campaign requires Linux" >&2
  exit 1
}
[[ "$(uname -m)" == "x86_64" ]] || {
  echo "DoubleZero campaign profile requires x86_64" >&2
  exit 1
}

status="$(doublezero status 2>&1)"
grep -Eiq '(^|[^[:alpha:]])up([^[:alpha:]]|$)' <<<"$status" || {
  echo "DoubleZero session is not up" >&2
  exit 1
}

doublezero latency >/dev/null
ip link show dev "$DZ_INTERFACE" >/dev/null

actual_mtu="$(ip -j link show dev "$DZ_INTERFACE" | jq -er '.[0].mtu')"
[[ "$actual_mtu" == "$EXPECTED_MTU" ]] || {
  echo "$DZ_INTERFACE MTU $actual_mtu, expected $EXPECTED_MTU" >&2
  exit 1
}

actual_speed="$(ethtool "$DZ_INTERFACE" | awk '/Speed:/ {gsub(/Mb\/s/, "", $2); print $2}')"
[[ "$actual_speed" == "$EXPECTED_SPEED_MBPS" ]] || {
  echo "$DZ_INTERFACE speed ${actual_speed:-unknown}Mb/s, expected ${EXPECTED_SPEED_MBPS}Mb/s" >&2
  exit 1
}

IFS=',' read -r -a peers <<<"$DZ_PEERS"
for peer in "${peers[@]}"; do
  route_dev="$(ip -j route get "$peer" | jq -er '.[0].dev')"
  [[ "$route_dev" == "$DZ_INTERFACE" ]] || {
    echo "route to $peer uses $route_dev, not $DZ_INTERFACE" >&2
    exit 1
  }
done

[[ "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)" == "performance" ]] || {
  echo "CPU governor is not performance" >&2
  exit 1
}

[[ "$(sysctl -n net.core.rmem_max)" == "536870912" ]]
[[ "$(sysctl -n net.core.wmem_max)" == "536870912" ]]
[[ "$(sysctl -n net.core.netdev_max_backlog)" == "250000" ]]
[[ "$(sysctl -n net.core.somaxconn)" == "65535" ]]
[[ "$(sysctl -n net.ipv4.tcp_congestion_control)" == "bbr" ]]
[[ "$(ulimit -n)" -ge 1048576 ]]

chronyc tracking | grep -Eq '^Leap status[[:space:]]*:[[:space:]]*Normal$'

echo "DoubleZero host preflight passed for $DZ_INTERFACE"
