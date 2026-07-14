#!/usr/bin/env bash
# Stage a checksummed immutable release, drain the active service, switch the
# current symlink, and automatically restore the old binary if smoke checks fail.
set -Eeuo pipefail

BINARY=""
EXPECTED_SHA256=""
HEALTH_URL="http://127.0.0.1:9100"
BACKUP_CONFIRMED=0
CURRENT=/opt/dexos/current
RELEASE_ROOT=/opt/dexos/releases
SERVICE=marketd.service

usage() {
    cat <<'EOF'
usage: sudo bare-metal-upgrade --binary PATH --sha256 HEX --backup-confirmed [options]

  --binary PATH          reviewed marketd release binary
  --sha256 HEX           trusted expected SHA-256
  --backup-confirmed     confirm config/state backup and compatibility review
  --health-url URL       metrics base URL (default: http://127.0.0.1:9100)
  -h, --help             show this help

The script does not create an authoritative state backup: marketd snapshots are
currently fail-closed. It preserves the prior binary release and automatically
switches back if the new process smoke check fails.
Settled inactive/failed units are accepted as explicit recovery operations;
the selected target is started and verified.
EOF
}

die() { printf 'upgrade: error: %s\n' "$*" >&2; exit 1; }
info() { printf 'upgrade: %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) [[ $# -ge 2 ]] || die "--binary needs a path"; BINARY="$2"; shift 2 ;;
        --sha256) [[ $# -ge 2 ]] || die "--sha256 needs a value"; EXPECTED_SHA256="$2"; shift 2 ;;
        --backup-confirmed) BACKUP_CONFIRMED=1; shift ;;
        --health-url) [[ $# -ge 2 ]] || die "--health-url needs a URL"; HEALTH_URL="${2%/}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "Linux/systemd is required"
[[ "$EUID" -eq 0 ]] || die "run as root (sudo)"
[[ "$BACKUP_CONFIRMED" -eq 1 ]] || die "--backup-confirmed is required"
[[ -f "$BINARY" ]] || die "binary is missing: $BINARY"
[[ "$HEALTH_URL" =~ ^https?://[^[:space:]]+$ ]] || die \
    "--health-url must be a non-empty http:// or https:// URL"
EXPECTED_SHA256="$(printf '%s' "$EXPECTED_SHA256" | tr '[:upper:]' '[:lower:]')"
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 hex characters"
[[ -L "$CURRENT" ]] || die "$CURRENT is not an installed release symlink"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"

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

ACTUAL_SHA256="$(sha256_file "$BINARY")"
[[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]] || die \
    "checksum mismatch: expected $EXPECTED_SHA256, got $ACTUAL_SHA256"
VERSION="$($BINARY --version 2>/dev/null)" || die "cannot execute new binary"
[[ "$VERSION" == marketd\ * ]] || die "unexpected binary identity: $VERSION"

OLD_TARGET="$(readlink "$CURRENT")"
[[ "$OLD_TARGET" =~ ^releases/[0-9a-f]{64}$ ]] || die \
    "unexpected current target (expected releases/<lowercase-sha256>): $OLD_TARGET"
[[ "$OLD_TARGET" != "releases/$EXPECTED_SHA256" ]] || die "requested release is already active"
require_metadata /opt/dexos "release installation root" 755
require_metadata "$RELEASE_ROOT" "release root" 755
require_metadata "$CURRENT" "current symlink" 777

INITIAL_SERVICE_STATE="$(service_state)"
if [[ "$INITIAL_SERVICE_STATE" != "active" ]]; then
    info "$SERVICE is $INITIAL_SERVICE_STATE; proceeding in explicit recovery mode"
fi
if ! /usr/libexec/dexos/bare-metal-preflight --skip-skeleton-ack; then
    if [[ "$INITIAL_SERVICE_STATE" == "active" ]]; then
        die "current installation failed preflight while $SERVICE is active"
    fi
    info "current release failed preflight; recovery will rely on the fully validated new release and systemd ExecStartPre"
fi

NEW_RELEASE="$RELEASE_ROOT/$EXPECTED_SHA256"
TEMP_RELEASE=""
cleanup_staging() {
    if [[ -n "$TEMP_RELEASE" && -d "$TEMP_RELEASE" ]]; then
        rm -rf -- "$TEMP_RELEASE"
    fi
}
trap cleanup_staging EXIT
if [[ -e "$NEW_RELEASE" || -L "$NEW_RELEASE" ]]; then
    validate_release "$NEW_RELEASE" "$EXPECTED_SHA256"
    info "reusing already staged immutable release $NEW_RELEASE"
else
    TEMP_RELEASE="$(mktemp -d "$RELEASE_ROOT/.release-$EXPECTED_SHA256.XXXXXX")"
    chmod 0755 "$TEMP_RELEASE"
    install -m 0755 "$BINARY" "$TEMP_RELEASE/marketd"
    [[ "$(sha256_file "$TEMP_RELEASE/marketd")" == "$EXPECTED_SHA256" ]] || die \
        "copy verification failed"
    printf '%s  marketd\n' "$EXPECTED_SHA256" > "$TEMP_RELEASE/SHA256"
    printf '%s\n' "$VERSION" > "$TEMP_RELEASE/VERSION"
    chmod 0644 "$TEMP_RELEASE/SHA256" "$TEMP_RELEASE/VERSION"
    chown root:root "$TEMP_RELEASE" "$TEMP_RELEASE/marketd" \
        "$TEMP_RELEASE/SHA256" "$TEMP_RELEASE/VERSION"
    validate_release "$TEMP_RELEASE" "$EXPECTED_SHA256"
    mv -T "$TEMP_RELEASE" "$NEW_RELEASE" || die \
        "cannot publish $NEW_RELEASE; inspect a concurrent or partial release"
    TEMP_RELEASE=""
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RECEIPT="/var/lib/dexos/admin/upgrades/$STAMP"
install -d -m 0700 "$RECEIPT"
cp -a /etc/dexos "$RECEIPT/config"
printf 'from=%s\nto=releases/%s\nnew_version=%s\nnew_sha256=%s\n' \
    "$OLD_TARGET" "$EXPECTED_SHA256" "$VERSION" "$EXPECTED_SHA256" > "$RECEIPT/cutover.env"
chmod 0600 "$RECEIPT/cutover.env"
info "saved root-only configuration copy and cutover receipt at $RECEIPT"

CUTOVER_STARTED=0
restore_on_error() {
    local rc=$?
    trap - ERR INT TERM
    if [[ "$CUTOVER_STARTED" -eq 1 ]]; then
        systemctl stop "$SERVICE" >/dev/null 2>&1 || true
        atomic_switch "$OLD_TARGET" || true
        systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
        systemctl start "$SERVICE" >/dev/null 2>&1 || true
        printf 'upgrade: restored prior release %s after failure\n' "$OLD_TARGET" >&2
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
atomic_switch "releases/$EXPECTED_SHA256"
systemctl reset-failed "$SERVICE"
systemctl start "$SERVICE"
/usr/libexec/dexos/bare-metal-verify --health-url "$HEALTH_URL"

trap - ERR INT TERM
info "upgrade smoke PASS: $OLD_TARGET -> releases/$EXPECTED_SHA256"
info "retain the old immutable release until independent state/replay compatibility is established"
