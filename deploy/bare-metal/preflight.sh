#!/usr/bin/env bash
# Static host/configuration validation used by systemd ExecStartPre.
#
# This deliberately does not call `marketd run`: there is no validate-config
# subcommand, and starting the runtime as a validator would be an unsafe way to
# lint a configuration once durable/consensus composition lands. The real
# parser still validates the complete schema at ExecStart and fails closed.
set -euo pipefail

BINARY="${DEXOS_BINARY:-/opt/dexos/current/marketd}"
CONFIG="${DEXOS_CONFIG:-/etc/dexos/marketd.toml}"
ENV_FILE="${DEXOS_ENV_FILE:-/etc/dexos/marketd.env}"
DATA_DIR="${DEXOS_DATA_DIR:-/var/lib/dexos/data}"
CURRENT=/opt/dexos/current
RELEASE_ROOT=/opt/dexos/releases
SKIP_ACK=0

usage() {
    cat <<'EOF'
usage: bare-metal-preflight [options]

  --binary PATH       marketd binary (default: /opt/dexos/current/marketd)
  --config PATH       node TOML (default: /etc/dexos/marketd.toml)
  --env-file PATH     systemd environment file (default: /etc/dexos/marketd.env)
  --data-dir PATH     writable state path (default: /var/lib/dexos/data)
  --skip-skeleton-ack static audit only; systemd must never use this option
  -h, --help          show this help
EOF
}

die() { printf 'bare-metal preflight: error: %s\n' "$*" >&2; exit 1; }
warn() { printf 'bare-metal preflight: warning: %s\n' "$*" >&2; }
ok() { printf 'bare-metal preflight: ok: %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) [[ $# -ge 2 ]] || die "--binary needs a path"; BINARY="$2"; shift 2 ;;
        --config) [[ $# -ge 2 ]] || die "--config needs a path"; CONFIG="$2"; shift 2 ;;
        --env-file) [[ $# -ge 2 ]] || die "--env-file needs a path"; ENV_FILE="$2"; shift 2 ;;
        --data-dir) [[ $# -ge 2 ]] || die "--data-dir needs a path"; DATA_DIR="$2"; shift 2 ;;
        --skip-skeleton-ack) SKIP_ACK=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "the packaged service supports Linux/systemd only"
[[ -x "$BINARY" ]] || die "binary is missing or not executable: $BINARY"
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || die \
    "configuration is missing, not regular, or is a symlink: $CONFIG"
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || die \
    "environment file is missing, not regular, or is a symlink: $ENV_FILE"
[[ -d "$DATA_DIR" && ! -L "$DATA_DIR" ]] || die \
    "state directory is missing, not a real directory, or is a symlink: $DATA_DIR"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

mode_of() { stat -c '%a' "$1"; }
owner_of() { stat -c '%U' "$1"; }
group_of() { stat -c '%G' "$1"; }

require_metadata() {
    local path="$1" label="$2" expected_owner="$3" expected_group="$4" expected_mode="$5"
    local actual_owner actual_group actual_mode
    actual_owner="$(owner_of "$path")"
    actual_group="$(group_of "$path")"
    actual_mode="$(mode_of "$path")"
    [[ "$actual_owner" == "$expected_owner" ]] || die \
        "$label owner must be $expected_owner (found $actual_owner): $path"
    [[ "$actual_group" == "$expected_group" ]] || die \
        "$label group must be $expected_group (found $actual_group): $path"
    [[ "$actual_mode" == "$expected_mode" ]] || die \
        "$label mode must be $expected_mode (found $actual_mode): $path"
}

reject_writable_by_group_or_other() {
    local path="$1" label="$2" mode
    mode="$(mode_of "$path")"
    (( (8#$mode & 022) == 0 )) || die "$label is group/world-writable ($mode): $path"
}

reject_world_readable() {
    local path="$1" label="$2" mode
    mode="$(mode_of "$path")"
    (( (8#$mode & 004) == 0 )) || die "$label is world-readable ($mode): $path"
}

require_dexos_readable() {
    local path="$1" label="$2"
    if [[ "$EUID" -eq 0 ]] && command -v runuser >/dev/null 2>&1; then
        runuser -u dexos -- test -r "$path" || die "dexos cannot read $label: $path"
    elif [[ "$(id -un)" == "dexos" ]]; then
        test -r "$path" || die "dexos cannot read $label: $path"
    elif [[ "$EUID" -eq 0 ]]; then
        warn "runuser unavailable; dexos readability check skipped for $label: $path"
    else
        die "run as root or as the dexos service account"
    fi
}

require_public_tls_file() {
    local path="$1" label="$2"
    [[ -f "$path" && ! -L "$path" ]] || die \
        "$label is missing, not regular, or is a symlink: $path"
    [[ "$(owner_of "$path")" == "root" ]] || die "$label must be owned by root: $path"
    reject_writable_by_group_or_other "$path" "$label"
    require_dexos_readable "$path" "$label"
}

# Extract a simple scalar from a TOML section. This is an operational policy
# check, not a replacement for NodeConfig::load: ExecStart performs authoritative
# parsing, unknown-field rejection, range validation, and committee validation.
toml_value() {
    local section="$1" key="$2"
    awk -v wanted_section="$section" -v wanted_key="$key" '
        /^[[:space:]]*\[[^[]/ {
            current = $0
            gsub(/^[[:space:]]*\[/, "", current)
            gsub(/\][[:space:]]*(#.*)?$/, "", current)
            gsub(/[[:space:]]/, "", current)
            next
        }
        current == wanted_section && $0 ~ "^[[:space:]]*" wanted_key "[[:space:]]*=" {
            value = $0
            sub("^[[:space:]]*" wanted_key "[[:space:]]*=[[:space:]]*", "", value)
            sub(/[[:space:]]*#.*$/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (value ~ /^\".*\"$/) {
                sub(/^\"/, "", value)
                sub(/\"$/, "", value)
            }
            print value
            exit
        }
    ' "$CONFIG"
}

resolve_config_path() {
    local value="$1"
    if [[ "$value" == /* ]]; then
        printf '%s\n' "$value"
    else
        printf '%s/%s\n' "$(dirname "$CONFIG")" "$value"
    fi
}

[[ -L "$CURRENT" ]] || die "$CURRENT must be a symlink"
CURRENT_TARGET="$(readlink "$CURRENT")" || die "cannot read $CURRENT"
if [[ ! "$CURRENT_TARGET" =~ ^releases/([0-9a-f]{64})$ ]]; then
    die "$CURRENT target must be exactly releases/<lowercase-sha256> (found '$CURRENT_TARGET')"
fi
CURRENT_DIGEST="${BASH_REMATCH[1]}"
require_metadata /opt/dexos "release installation root" root root 755
require_metadata "$RELEASE_ROOT" "release root" root root 755
require_metadata "$CURRENT" "current symlink" root root 777

RELEASE_DIR="/opt/dexos/$CURRENT_TARGET"
[[ -d "$RELEASE_DIR" && ! -L "$RELEASE_DIR" ]] || die \
    "selected release is missing, not a directory, or is a symlink: $RELEASE_DIR"
require_metadata "$RELEASE_DIR" "release directory" root root 755

EXPECTED_BINARY="$RELEASE_DIR/marketd"
[[ -f "$EXPECTED_BINARY" && ! -L "$EXPECTED_BINARY" ]] || die \
    "selected binary is missing, not regular, or is a symlink: $EXPECTED_BINARY"
RESOLVED_BINARY="$(readlink -f "$BINARY")" || die "cannot resolve binary path: $BINARY"
[[ "$RESOLVED_BINARY" == "$EXPECTED_BINARY" ]] || die \
    "binary does not resolve to the release selected by $CURRENT: $RESOLVED_BINARY"
require_metadata "$RESOLVED_BINARY" "binary" root root 755

HASH_FILE="$RELEASE_DIR/SHA256"
[[ -f "$HASH_FILE" && ! -L "$HASH_FILE" ]] || die \
    "release checksum record is missing, not regular, or is a symlink: $HASH_FILE"
require_metadata "$HASH_FILE" "release checksum record" root root 644
HASH_LINE="$(sed -n '1p' "$HASH_FILE")"
HASH_LINE_COUNT="$(awk 'END { print NR }' "$HASH_FILE")"
[[ "$HASH_LINE_COUNT" == "1" && "$HASH_LINE" == "$CURRENT_DIGEST  marketd" ]] || die \
    "release checksum record must contain exactly '<release-digest>  marketd': $HASH_FILE"
EXPECTED_HASH="$CURRENT_DIGEST"
ACTUAL_HASH="$(sha256_file "$RESOLVED_BINARY")"
[[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]] || die "installed binary checksum mismatch"
# Do not execute even `--version` until the immutable-release checksum has
# authenticated the file selected by the current symlink.
VERSION="$($RESOLVED_BINARY --version 2>/dev/null)" || die \
    "cannot execute $RESOLVED_BINARY --version"
[[ "$VERSION" == marketd\ * ]] || die "unexpected binary identity: $VERSION"
ok "$VERSION; sha256=$ACTUAL_HASH"

[[ "$(owner_of "$CONFIG")" == "root" ]] || die "configuration must be owned by root"
[[ "$(group_of "$CONFIG")" == "dexos" ]] || die "configuration group must be dexos"
reject_writable_by_group_or_other "$CONFIG" "configuration"
require_metadata "$ENV_FILE" "environment file" root dexos 640

CONFIG_DATA_DIR="$(toml_value storage data_dir)"
[[ -n "$CONFIG_DATA_DIR" ]] || die "[storage].data_dir must be explicit for the systemd sandbox"
[[ "$CONFIG_DATA_DIR" == "$DATA_DIR" ]] || die \
    "[storage].data_dir must be '$DATA_DIR' (configured '$CONFIG_DATA_DIR')"

[[ "$(owner_of "$DATA_DIR")" == "dexos" ]] || die "state directory must be owned by dexos"
[[ "$(group_of "$DATA_DIR")" == "dexos" ]] || die "state directory group must be dexos"
reject_writable_by_group_or_other "$DATA_DIR" "state directory"
require_dexos_readable "$CONFIG" "configuration"
require_dexos_readable "$ENV_FILE" "environment file"
require_dexos_readable "$RESOLVED_BINARY" "binary"
if [[ "$EUID" -eq 0 ]] && command -v runuser >/dev/null 2>&1; then
    runuser -u dexos -- test -w "$DATA_DIR" || die "dexos cannot write $DATA_DIR"
elif [[ "$(id -un)" == "dexos" ]]; then
    # systemd applies User=dexos to ExecStartPre as well as ExecStart.  Test
    # access directly in that context; runuser is a root-only tool on the
    # supported util-linux hosts and would make every service start fail.
    test -w "$DATA_DIR" || die "dexos cannot write $DATA_DIR"
elif [[ "$EUID" -eq 0 ]]; then
    warn "runuser unavailable; service-account access checks skipped"
else
    die "run as root or as the dexos service account"
fi

METRICS_LISTEN="$(toml_value observability metrics_listen)"
if [[ -n "$METRICS_LISTEN" ]]; then
    case "$METRICS_LISTEN" in
        127.0.0.1:*|'[::1]':*) ;;
        *)
            [[ "${DEXOS_ALLOW_PUBLIC_METRICS:-0}" == "1" ]] || die \
                "metrics listener '$METRICS_LISTEN' is not loopback; set DEXOS_ALLOW_PUBLIC_METRICS=1 only after an exposure review"
            warn "unauthenticated metrics/health listener is publicly reachable at $METRICS_LISTEN"
            ;;
    esac
fi

ROLES="$(toml_value node roles)"
if [[ "$ROLES" == *validator* || "$ROLES" == *sequencer* || "$ROLES" == *witness* || "$ROLES" == *custody* ]]; then
    VALIDATORS="$(toml_value consensus validator_set_path)"
    [[ -n "$VALIDATORS" ]] || die "consensus-bearing roles require [consensus].validator_set_path"
    VALIDATORS="$(resolve_config_path "$VALIDATORS")"
    [[ -f "$VALIDATORS" && ! -L "$VALIDATORS" ]] || die \
        "validator-set file is missing, not regular, or is a symlink: $VALIDATORS"
    [[ "$(owner_of "$VALIDATORS")" == "root" ]] || die "validator set must be owned by root"
    reject_writable_by_group_or_other "$VALIDATORS" "validator set"
    require_dexos_readable "$VALIDATORS" "validator set"
fi

TLS_CERT="$(toml_value rpc tls_cert_path)"
if [[ -n "$TLS_CERT" ]]; then
    TLS_CERT="$(resolve_config_path "$TLS_CERT")"
    require_public_tls_file "$TLS_CERT" "RPC TLS certificate"
fi

TLS_KEY="$(toml_value rpc tls_key_path)"
if [[ -n "$TLS_KEY" ]]; then
    TLS_KEY="$(resolve_config_path "$TLS_KEY")"
    [[ -f "$TLS_KEY" && ! -L "$TLS_KEY" ]] || die \
        "RPC TLS private key is missing, not regular, or is a symlink: $TLS_KEY"
    [[ "$(owner_of "$TLS_KEY")" == "root" ]] || die "RPC TLS private key must be owned by root"
    [[ "$(group_of "$TLS_KEY")" == "dexos" ]] || die "RPC TLS private-key group must be dexos"
    reject_writable_by_group_or_other "$TLS_KEY" "RPC TLS private key"
    reject_world_readable "$TLS_KEY" "RPC TLS private key"
    require_dexos_readable "$TLS_KEY" "RPC TLS private key"
fi

TLS_CLIENT_CA="$(toml_value rpc tls_client_ca_path)"
if [[ -n "$TLS_CLIENT_CA" ]]; then
    TLS_CLIENT_CA="$(resolve_config_path "$TLS_CLIENT_CA")"
    require_public_tls_file "$TLS_CLIENT_CA" "RPC TLS client CA"
fi

if [[ "$SKIP_ACK" -eq 0 && "${DEXOS_ACKNOWLEDGE_SKELETON:-0}" != "1" ]]; then
    die "current marketd is a composition skeleton; set DEXOS_ACKNOWLEDGE_SKELETON=1 only for pre-production smoke operation"
fi

warn "/readyz proves process bootstrap only; RPC, peer networking, durable execution, and authoritative recovery are not composed"
ok "static host/configuration policy checks passed; marketd will perform authoritative TOML/schema validation at ExecStart"
