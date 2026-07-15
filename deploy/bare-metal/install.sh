#!/usr/bin/env bash
# Install one verified marketd release and its hardened systemd service.
# Existing deployments with a different release must use upgrade.sh.
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DOC_SOURCE="$SCRIPT_DIR/../../docs/runbooks/BARE_METAL.md"
DESTDIR="${DESTDIR:-}"
BINARY=""
EXPECTED_SHA256=""
CONFIG_SOURCE="$SCRIPT_DIR/marketd.toml.example"
VALIDATORS_SOURCE=""
REPLACE_CONFIG=0
ACK_SKELETON=0
ENABLE=0
START=0
HEALTH_URL="http://127.0.0.1:9100"

usage() {
    cat <<'EOF'
usage: sudo ./deploy/bare-metal/install.sh --binary PATH --sha256 HEX [options]

Required:
  --binary PATH              reviewed marketd release binary
  --sha256 HEX               expected lowercase SHA-256 from a trusted channel

Options:
  --config PATH              install this config instead of the safe smoke template
  --validators PATH          install as /etc/dexos/validators.toml
  --replace-config           back up and replace existing config/env/validators
  --acknowledge-skeleton     write DEXOS_ACKNOWLEDGE_SKELETON=1
  --enable                   enable service at boot (does not start it)
  --start                    enable, start, and smoke-verify the service
  --health-url URL           smoke-verifier base URL used with --start
                             (default: http://127.0.0.1:9100)
  -h, --help                 show this help

For packaging tests, set DESTDIR to an absolute staging root. User creation,
ownership changes, systemd actions, and runtime preflight are then skipped.
EOF
}

die() { printf 'install: error: %s\n' "$*" >&2; exit 1; }
info() { printf 'install: %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) [[ $# -ge 2 ]] || die "--binary needs a path"; BINARY="$2"; shift 2 ;;
        --sha256) [[ $# -ge 2 ]] || die "--sha256 needs a value"; EXPECTED_SHA256="$2"; shift 2 ;;
        --config) [[ $# -ge 2 ]] || die "--config needs a path"; CONFIG_SOURCE="$2"; shift 2 ;;
        --validators) [[ $# -ge 2 ]] || die "--validators needs a path"; VALIDATORS_SOURCE="$2"; shift 2 ;;
        --replace-config) REPLACE_CONFIG=1; shift ;;
        --acknowledge-skeleton) ACK_SKELETON=1; shift ;;
        --enable) ENABLE=1; shift ;;
        --start) START=1; ENABLE=1; shift ;;
        --health-url) [[ $# -ge 2 ]] || die "--health-url needs a URL"; HEALTH_URL="${2%/}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[[ -n "$BINARY" ]] || die "--binary is required"
[[ -f "$BINARY" ]] || die "binary is not a regular file: $BINARY"
[[ -f "$CONFIG_SOURCE" ]] || die "configuration source is missing: $CONFIG_SOURCE"
[[ -z "$VALIDATORS_SOURCE" || -f "$VALIDATORS_SOURCE" ]] || die \
    "validator-set source is missing: $VALIDATORS_SOURCE"
[[ "$HEALTH_URL" =~ ^https?://[^[:space:]]+$ ]] || die \
    "--health-url must be a non-empty http:// or https:// URL"
EXPECTED_SHA256="$(printf '%s' "$EXPECTED_SHA256" | tr '[:upper:]' '[:lower:]')"
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be exactly 64 hex characters"
if [[ "$START" -eq 1 && "$ACK_SKELETON" -ne 1 ]]; then
    die "--start requires --acknowledge-skeleton for this pre-production composition"
fi
if [[ -n "$DESTDIR" && "$DESTDIR" != /* ]]; then
    die "DESTDIR must be absolute"
fi
if [[ -z "$DESTDIR" ]]; then
    [[ "$(uname -s)" == "Linux" ]] || die "the packaged service supports Linux/systemd only"
    [[ "$EUID" -eq 0 ]] || die "run as root (sudo)"
    command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

ACTUAL_SHA256="$(sha256_file "$BINARY")"
[[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]] || die \
    "binary checksum mismatch: expected $EXPECTED_SHA256, got $ACTUAL_SHA256"
VERSION="$($BINARY --version 2>/dev/null)" || die "cannot execute $BINARY --version on this host"
[[ "$VERSION" == marketd\ * ]] || die "unexpected binary identity: $VERSION"
info "verified $VERSION ($ACTUAL_SHA256)"

path() { printf '%s%s\n' "$DESTDIR" "$1"; }
SYSUSERS="$(path /usr/lib/sysusers.d/dexos-marketd.conf)"
TMPFILES="$(path /usr/lib/tmpfiles.d/dexos-marketd.conf)"
UNIT="$(path /etc/systemd/system/marketd.service)"
LIBEXEC="$(path /usr/libexec/dexos)"
DOC_DIR="$(path /usr/share/doc/dexos)"
ETC_DIR="$(path /etc/dexos)"
STATE_DIR="$(path /var/lib/dexos)"
RELEASE_ROOT="$(path /opt/dexos/releases)"
RELEASE_DIR="$RELEASE_ROOT/$EXPECTED_SHA256"
CURRENT="$(path /opt/dexos/current)"
INSTALL_ROOT="$(path /opt/dexos)"

# Refuse the install workflow before creating accounts or changing configuration
# when another immutable release is already selected.  Previously this guard ran
# after the managed-config writes, so an accidental install invocation could
# replace configuration and only then tell the operator to use upgrade.sh.
if [[ -L "$CURRENT" ]]; then
    EXISTING_TARGET="$(readlink "$CURRENT")"
    [[ "$EXISTING_TARGET" == "releases/$EXPECTED_SHA256" ]] || die \
        "another release is installed ($EXISTING_TARGET); use upgrade.sh"
elif [[ -e "$CURRENT" ]]; then
    die "$CURRENT exists and is not a symlink"
fi

mkdir -p "$(dirname "$SYSUSERS")" "$(dirname "$TMPFILES")" "$(dirname "$UNIT")" \
    "$LIBEXEC" "$DOC_DIR" "$ETC_DIR/tls" "$STATE_DIR/data" "$STATE_DIR/admin" \
    "$(dirname "$INSTALL_ROOT")"
for directory in "$INSTALL_ROOT" "$RELEASE_ROOT"; do
    if [[ -e "$directory" || -L "$directory" ]]; then
        [[ -d "$directory" && ! -L "$directory" ]] || die \
            "release path exists but is not a real directory: $directory"
    fi
    install -d -m 0755 "$directory"
done
install -m 0644 "$SCRIPT_DIR/systemd/dexos-marketd.sysusers.conf" "$SYSUSERS"
install -m 0644 "$SCRIPT_DIR/systemd/dexos-marketd.tmpfiles.conf" "$TMPFILES"

if [[ -z "$DESTDIR" ]]; then
    if command -v systemd-sysusers >/dev/null 2>&1; then
        systemd-sysusers "$SYSUSERS"
    else
        getent group dexos >/dev/null 2>&1 || groupadd --system dexos
        id dexos >/dev/null 2>&1 || useradd --system --gid dexos \
            --home-dir /var/lib/dexos --shell /usr/sbin/nologin \
            --comment "DexOS marketd service user" dexos
    fi
    chown root:dexos "$ETC_DIR" "$ETC_DIR/tls"
    chmod 0750 "$ETC_DIR" "$ETC_DIR/tls"
    chown dexos:dexos "$STATE_DIR" "$STATE_DIR/data"
    chmod 0750 "$STATE_DIR" "$STATE_DIR/data"
    chown root:root "$STATE_DIR/admin"
    chmod 0700 "$STATE_DIR/admin"
    chown root:root "$INSTALL_ROOT" "$RELEASE_ROOT"
    chmod 0755 "$INSTALL_ROOT" "$RELEASE_ROOT"
fi

install_managed_config() {
    local source="$1" destination="$2" mode="$3"
    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" ]] || die \
            "managed configuration destination is not a regular file: $destination"
    fi
    if [[ -e "$destination" && "$REPLACE_CONFIG" -ne 1 ]]; then
        chmod "$mode" "$destination"
        if [[ -z "$DESTDIR" ]]; then
            chown root:dexos "$destination"
        fi
        info "preserving existing $destination"
        return
    fi
    if [[ -e "$destination" ]]; then
        local stamp backup
        stamp="$(date -u +%Y%m%dT%H%M%SZ)"
        backup="$STATE_DIR/admin/$(basename "$destination").$stamp.bak"
        cp -p "$destination" "$backup"
        info "backed up $destination to $backup"
    fi
    install -m "$mode" "$source" "$destination"
    if [[ -z "$DESTDIR" ]]; then
        chown root:dexos "$destination"
    fi
}

install_managed_config "$CONFIG_SOURCE" "$ETC_DIR/marketd.toml" 0640
install_managed_config "$SCRIPT_DIR/marketd.env.example" "$ETC_DIR/marketd.env" 0640
if [[ -n "$VALIDATORS_SOURCE" ]]; then
    install_managed_config "$VALIDATORS_SOURCE" "$ETC_DIR/validators.toml" 0640
fi

if [[ "$ACK_SKELETON" -eq 1 ]]; then
    if grep -q '^DEXOS_ACKNOWLEDGE_SKELETON=' "$ETC_DIR/marketd.env"; then
        sed -i.bak 's/^DEXOS_ACKNOWLEDGE_SKELETON=.*/DEXOS_ACKNOWLEDGE_SKELETON=1/' "$ETC_DIR/marketd.env"
        rm -f "$ETC_DIR/marketd.env.bak"
    else
        printf '\nDEXOS_ACKNOWLEDGE_SKELETON=1\n' >> "$ETC_DIR/marketd.env"
    fi
fi
chmod 0640 "$ETC_DIR/marketd.env"
if [[ -z "$DESTDIR" ]]; then
    chown root:dexos "$ETC_DIR/marketd.env"
fi

if [[ -e "$RELEASE_DIR" || -L "$RELEASE_DIR" ]]; then
    [[ -d "$RELEASE_DIR" && ! -L "$RELEASE_DIR" ]] || die \
        "release path exists but is not a real directory: $RELEASE_DIR"
fi
install -d -m 0755 "$RELEASE_DIR"
for artifact in marketd SHA256 VERSION; do
    [[ ! -L "$RELEASE_DIR/$artifact" ]] || die \
        "refusing to replace symlinked release artifact: $RELEASE_DIR/$artifact"
done
TMP_BINARY="$RELEASE_DIR/.marketd.$$"
install -m 0755 "$BINARY" "$TMP_BINARY"
[[ "$(sha256_file "$TMP_BINARY")" == "$EXPECTED_SHA256" ]] || die "checksum changed while copying"
mv -f "$TMP_BINARY" "$RELEASE_DIR/marketd"
printf '%s  marketd\n' "$EXPECTED_SHA256" > "$RELEASE_DIR/SHA256"
printf '%s\n' "$VERSION" > "$RELEASE_DIR/VERSION"
chmod 0755 "$RELEASE_DIR" "$RELEASE_DIR/marketd"
chmod 0644 "$RELEASE_DIR/SHA256" "$RELEASE_DIR/VERSION"
if [[ -z "$DESTDIR" ]]; then
    chown root:root "$RELEASE_DIR" "$RELEASE_DIR/marketd" \
        "$RELEASE_DIR/SHA256" "$RELEASE_DIR/VERSION"
fi

if [[ ! -L "$CURRENT" ]]; then
    TMP_LINK="${CURRENT}.new.$$"
    ln -s "releases/$EXPECTED_SHA256" "$TMP_LINK"
    mv -f "$TMP_LINK" "$CURRENT"
fi
if [[ -z "$DESTDIR" ]]; then
    chown -h root:root "$CURRENT"
fi

install -m 0755 "$SCRIPT_DIR/preflight.sh" "$LIBEXEC/bare-metal-preflight"
install -m 0755 "$SCRIPT_DIR/verify.sh" "$LIBEXEC/bare-metal-verify"
install -m 0755 "$SCRIPT_DIR/upgrade.sh" "$LIBEXEC/bare-metal-upgrade"
install -m 0755 "$SCRIPT_DIR/rollback.sh" "$LIBEXEC/bare-metal-rollback"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$LIBEXEC/bare-metal-uninstall"
install -m 0644 "$SCRIPT_DIR/systemd/marketd.service" "$UNIT"
install -m 0644 "$DOC_SOURCE" "$DOC_DIR/BARE_METAL.md"

if [[ -n "$DESTDIR" ]]; then
    info "staged installation beneath $DESTDIR"
    exit 0
fi

DEXOS_ACKNOWLEDGE_SKELETON="$ACK_SKELETON" \
    "$LIBEXEC/bare-metal-preflight" --skip-skeleton-ack
systemctl daemon-reload
if [[ "$ENABLE" -eq 1 ]]; then
    systemctl enable marketd.service
fi
if [[ "$START" -eq 1 ]]; then
    systemctl start marketd.service
    "$LIBEXEC/bare-metal-verify" --health-url "$HEALTH_URL"
else
    info "installed but not started; review /etc/dexos/marketd.toml and BARE_METAL.md"
    info "start explicitly with: systemctl start marketd.service"
fi
