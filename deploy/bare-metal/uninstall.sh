#!/usr/bin/env bash
# Remove the service and binaries. Configuration and state are preserved unless
# the operator supplies an explicit data-loss confirmation token.
set -euo pipefail

PURGE=0
CONFIRM_TOKEN=""

usage() {
    cat <<'EOF'
usage: sudo bare-metal-uninstall [options]

  --purge-data CONFIRM_REMOVE_DEXOS_DATA
      also remove /etc/dexos, /var/lib/dexos, and the dexos service account
  -h, --help

Without --purge-data, config/state and the service account are preserved. The
service, immutable binaries, unit, helpers, and packaging metadata are removed.
EOF
}

die() { printf 'uninstall: error: %s\n' "$*" >&2; exit 1; }
info() { printf 'uninstall: %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge-data)
            [[ $# -ge 2 ]] || die "--purge-data needs the confirmation token"
            PURGE=1; CONFIRM_TOKEN="$2"; shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "Linux/systemd is required"
[[ "$EUID" -eq 0 ]] || die "run as root (sudo)"
if [[ "$PURGE" -eq 1 && "$CONFIRM_TOKEN" != "CONFIRM_REMOVE_DEXOS_DATA" ]]; then
    die "wrong purge token; no data was removed"
fi
if [[ "$PURGE" -eq 1 ]]; then
    command -v findmnt >/dev/null 2>&1 || die \
        "findmnt is required to prove purge trees contain no mounts; nothing was removed"
    if ! MOUNT_TARGETS="$(findmnt --raw --noheadings --output TARGET)"; then
        die "findmnt could not enumerate mount targets; nothing was removed"
    fi
    for purge_path in /etc/dexos /var/lib/dexos; do
        if [[ -L "$purge_path" ]]; then
            die "refusing to purge symlinked $purge_path; nothing was removed"
        fi
        while IFS= read -r mounted_path; do
            case "$mounted_path" in
                "$purge_path"|"$purge_path"/*)
                    die "refusing to purge mount $mounted_path inside $purge_path; unmount it after preserving data; nothing was removed"
                    ;;
            esac
        done <<< "$MOUNT_TARGETS"
    done
fi

systemctl disable --now marketd.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/marketd.service
rm -rf /usr/libexec/dexos
rm -f /usr/lib/sysusers.d/dexos-marketd.conf
rm -f /usr/lib/tmpfiles.d/dexos-marketd.conf
rm -rf /usr/share/doc/dexos
rm -rf /opt/dexos
systemctl daemon-reload
systemctl reset-failed marketd.service >/dev/null 2>&1 || true

if [[ "$PURGE" -eq 1 ]]; then
    rm -rf /etc/dexos /var/lib/dexos
    if id dexos >/dev/null 2>&1; then
        userdel dexos
    fi
    getent group dexos >/dev/null 2>&1 && groupdel dexos || true
    info "purged config, state, and service account"
else
    info "preserved /etc/dexos, /var/lib/dexos, and the dexos account"
fi

info "marketd service and installed binaries removed"
