#!/usr/bin/env bash
# Verify the installed service. The default is intentionally a process smoke
# check; --production-gate fails for this repository state because the data
# plane and durability are not composed.
set -euo pipefail

SERVICE="marketd.service"
HEALTH_URL="http://127.0.0.1:9100"
PRODUCTION_GATE=0

usage() {
    cat <<'EOF'
usage: bare-metal-verify [options]

  --service NAME       systemd unit (default: marketd.service)
  --health-url URL     metrics base URL (default: http://127.0.0.1:9100)
  --production-gate    require exchange/data-plane readiness (expected to fail
                       for the current composition skeleton)
  -h, --help           show this help
EOF
}

die() { printf 'verify: error: %s\n' "$*" >&2; exit 1; }
info() { printf 'verify: %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service) [[ $# -ge 2 ]] || die "--service needs a name"; SERVICE="$2"; shift 2 ;;
        --health-url) [[ $# -ge 2 ]] || die "--health-url needs a URL"; HEALTH_URL="${2%/}"; shift 2 ;;
        --production-gate) PRODUCTION_GATE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[[ "$SERVICE" =~ ^[A-Za-z0-9_][A-Za-z0-9_.@:-]*$ ]] || die \
    "--service contains unsupported characters"
[[ "$HEALTH_URL" =~ ^https?://[^[:space:]]+$ ]] || die \
    "--health-url must be a non-empty http:// or https:// URL"
[[ "$(uname -s)" == "Linux" ]] || die "the packaged service supports Linux/systemd only"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
command -v curl >/dev/null 2>&1 || die "curl is required"

if [[ "$EUID" -eq 0 && -x /usr/libexec/dexos/bare-metal-preflight ]]; then
    /usr/libexec/dexos/bare-metal-preflight --skip-skeleton-ack
else
    info "static owner/access preflight skipped (run this verifier as root to include it)"
fi

if ! systemctl is-active --quiet -- "$SERVICE"; then
    systemctl --no-pager --full status -- "$SERVICE" >&2 || true
    journalctl --no-pager --unit="$SERVICE" -n 30 >&2 || true
    die "$SERVICE is not active"
fi

MAIN_PID="$(systemctl show --property MainPID --value -- "$SERVICE")"
[[ "$MAIN_PID" =~ ^[1-9][0-9]*$ ]] || die "$SERVICE has no live main PID"
[[ -d "/proc/$MAIN_PID" ]] || die "main PID $MAIN_PID does not exist"
info "$SERVICE active (pid=$MAIN_PID)"

curl --fail --silent --show-error --max-time 3 "$HEALTH_URL/livez" | grep -qx 'ok' || \
    die "liveness probe failed: $HEALTH_URL/livez"
READY_BODY="$(curl --fail --silent --show-error --max-time 3 "$HEALTH_URL/readyz")" || \
    die "bootstrap-readiness probe failed: $HEALTH_URL/readyz"
[[ "$READY_BODY" == "ready" ]] || die "unexpected readiness response: $READY_BODY"
METRICS="$(curl --fail --silent --show-error --max-time 3 "$HEALTH_URL/metrics")" || \
    die "metrics probe failed: $HEALTH_URL/metrics"
printf '%s\n' "$METRICS" | grep -Eq '^node_ready(\{[^}]*\})?[[:space:]]+1([.]0+)?$' || \
    die "metrics do not report node_ready=1"

info "SMOKE PASS: process, placeholder handlers, metrics, /livez, and bootstrap /readyz are responsive"
info "this result does not prove RPC, peer networking, execution, consensus finality, WAL durability, snapshots, or recovery"

if [[ "$PRODUCTION_GATE" -eq 1 ]]; then
    cat >&2 <<'EOF'
verify: PRODUCTION GATE FAIL (expected for this repository state):
  - Node::run_until starts placeholder role handlers.
  - configured peer and RPC listeners are not bound by marketd run.
  - storage.data_dir is not opened by the composition root.
  - no node identity seed is loaded by marketd run.
  - authoritative snapshot/recovery is not implemented.
  - /readyz therefore establishes bootstrap readiness only.
Do not custody assets or accept public trading traffic.
EOF
    exit 2
fi
