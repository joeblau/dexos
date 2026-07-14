#!/usr/bin/env bash
# Switch to an already-installed immutable release after an explicit
# compatibility acknowledgement. Restores the starting binary on smoke failure.
set -Eeuo pipefail

RELEASE=""
HEALTH_URL="http://127.0.0.1:9100"
COMPATIBILITY_CONFIRMED=0
CURRENT=/opt/dexos/current
RELEASE_ROOT=/opt/dexos/releases
SERVICE=marketd.service

usage() {
    cat <<'EOF'
usage: sudo bare-metal-rollback --release SHA256 --compatibility-confirmed [options]

  --release SHA256             installed release digest to activate
  --compatibility-confirmed    confirm config/WAL/snapshot compatibility review
  --health-url URL             metrics base URL (default: http://127.0.0.1:9100)
  -h, --help                   show this help

This switches binaries only. It cannot establish state compatibility or restore
an authoritative snapshot; those capabilities are not composed in marketd yet.
Settled inactive/failed units are accepted as explicit recovery operations;
the selected target is started and verified.
EOF
}

die() { printf 'rollback: error: %s\n' "$*" >&2; exit 1; }
info() { printf 'rollback: %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) [[ $# -ge 2 ]] || die "--release needs a digest"; RELEASE="$2"; shift 2 ;;
        --compatibility-confirmed) COMPATIBILITY_CONFIRMED=1; shift ;;
        --health-url) [[ $# -ge 2 ]] || die "--health-url needs a URL"; HEALTH_URL="${2%/}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "Linux/systemd is required"
[[ "$EUID" -eq 0 ]] || die "run as root (sudo)"
[[ "$COMPATIBILITY_CONFIRMED" -eq 1 ]] || die "--compatibility-confirmed is required"
[[ "$HEALTH_URL" =~ ^https?://[^[:space:]]+$ ]] || die \
    "--health-url must be a non-empty http:// or https:// URL"
RELEASE="$(printf '%s' "$RELEASE" | tr '[:upper:]' '[:lower:]')"
[[ "$RELEASE" =~ ^[0-9a-f]{64}$ ]] || die "--release must be a full SHA-256 digest"
[[ -L "$CURRENT" ]] || die "$CURRENT is not an installed release symlink"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
TARGET_DIR="$RELEASE_ROOT/$RELEASE"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}
atomic_switch() {
    local target="$1" temporary="${CURRENT}.new.$$"
    rm -f "$temporary"
    ln -s "$target" "$temporary"
    mv -Tf "$temporary" "$CURRENT"
}
mode_of() { stat -c '%a' "$1"; }
owner_of() { stat -c '%U' "$1"; }
group_of() { stat -c '%G' "$1"; }
require_metadata() {
    local path="$1" label="$2" expected_mode="$3"
    [[ "$(owner_of "$path")" == "root" ]] || die "$label must be owned by root: $path"
    [[ "$(group_of "$path")" == "root" ]] || die "$label group must be root: $path"
    [[ "$(mode_of "$path")" == "$expected_mode" ]] || die \
        "$label mode must be $expected_mode (found $(mode_of "$path")): $path"
}
validate_release() {
    local directory="$1" digest="$2" checksum_line checksum_lines
    [[ -d "$directory" && ! -L "$directory" ]] || die \
        "release is missing, not a directory, or is a symlink: $directory"
    require_metadata "$directory" "release directory" 755
    [[ -f "$directory/marketd" && ! -L "$directory/marketd" ]] || die \
        "release binary is missing, not regular, or is a symlink: $directory/marketd"
    [[ -f "$directory/SHA256" && ! -L "$directory/SHA256" ]] || die \
        "release checksum is missing, not regular, or is a symlink: $directory/SHA256"
    require_metadata "$directory/marketd" "release binary" 755
    require_metadata "$directory/SHA256" "release checksum" 644
    checksum_line="$(sed -n '1p' "$directory/SHA256")"
    checksum_lines="$(awk 'END { print NR }' "$directory/SHA256")"
    [[ "$checksum_lines" == "1" && "$checksum_line" == "$digest  marketd" ]] || die \
        "release checksum record is malformed: $directory/SHA256"
    [[ "$(sha256_file "$directory/marketd")" == "$digest" ]] || die \
        "release binary checksum mismatch: $directory/marketd"
}
service_state() {
    local load_state active_state
    load_state="$(systemctl show "$SERVICE" --property LoadState --value 2>/dev/null)" || die \
        "cannot inspect $SERVICE"
    [[ "$load_state" == "loaded" ]] || die "$SERVICE is not loaded (LoadState=$load_state)"
    active_state="$(systemctl show "$SERVICE" --property ActiveState --value 2>/dev/null)" || die \
        "cannot inspect $SERVICE state"
    case "$active_state" in
        active|inactive|failed) printf '%s\n' "$active_state" ;;
        *) die "$SERVICE is in transitional/unsupported state '$active_state'; wait for it to settle" ;;
    esac
}

require_metadata /opt/dexos "release installation root" 755
require_metadata "$RELEASE_ROOT" "release root" 755
require_metadata "$CURRENT" "current symlink" 777
validate_release "$TARGET_DIR" "$RELEASE"

OLD_TARGET="$(readlink "$CURRENT")"
[[ "$OLD_TARGET" =~ ^releases/[0-9a-f]{64}$ ]] || die \
    "unexpected current target (expected releases/<lowercase-sha256>): $OLD_TARGET"
INITIAL_SERVICE_STATE="$(service_state)"
if [[ "$OLD_TARGET" == "releases/$RELEASE" ]]; then
    if [[ "$INITIAL_SERVICE_STATE" == "active" ]]; then
        info "requested release is already active"
        exit 0
    fi
    info "requested release is selected but $SERVICE is $INITIAL_SERVICE_STATE; attempting recovery start"
    systemctl stop "$SERVICE"
    systemctl reset-failed "$SERVICE"
    systemctl start "$SERVICE"
    /usr/libexec/dexos/bare-metal-verify --health-url "$HEALTH_URL"
    info "binary recovery smoke PASS: releases/$RELEASE"
    exit 0
fi
if [[ "$INITIAL_SERVICE_STATE" != "active" ]]; then
    info "$SERVICE is $INITIAL_SERVICE_STATE; proceeding in explicit recovery mode"
fi

CUTOVER_STARTED=0
restore_on_error() {
    local rc=$?
    trap - ERR INT TERM
    if [[ "$CUTOVER_STARTED" -eq 1 ]]; then
        systemctl stop "$SERVICE" >/dev/null 2>&1 || true
        atomic_switch "$OLD_TARGET" || true
        systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
        systemctl start "$SERVICE" >/dev/null 2>&1 || true
        printf 'rollback: restored starting release %s after failure\n' "$OLD_TARGET" >&2
    fi
    exit "$rc"
}
trap restore_on_error ERR INT TERM

CUTOVER_SERVICE_STATE="$(service_state)"
if [[ "$CUTOVER_SERVICE_STATE" != "active" ]]; then
    info "$SERVICE is $CUTOVER_SERVICE_STATE at cutover; no running process can be drained"
fi
systemctl stop "$SERVICE"
CUTOVER_STARTED=1
atomic_switch "releases/$RELEASE"
systemctl reset-failed "$SERVICE"
systemctl start "$SERVICE"
/usr/libexec/dexos/bare-metal-verify --health-url "$HEALTH_URL"

trap - ERR INT TERM
info "binary rollback smoke PASS: $OLD_TARGET -> releases/$RELEASE"
info "bootstrap readiness does not prove state compatibility; keep the node fenced from traffic"
