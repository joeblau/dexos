#!/usr/bin/env bash
# Prove that a nested bind mount refuses purge before any mutation. The test
# runs only inside a disposable privileged container; it never targets the host.
set -euo pipefail

TEST_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(dirname "$TEST_DIR")"
IMAGE="${DEXOS_TEST_UBUNTU_IMAGE:-ubuntu:24.04}"

command -v docker >/dev/null 2>&1 || {
    printf 'nested-mount purge test: docker is required\n' >&2
    exit 1
}

docker run --rm --privileged -i \
    --mount "type=bind,src=$BUNDLE_DIR,dst=/bundle,readonly" \
    "$IMAGE" bash -s <<'CONTAINER'
set -euo pipefail

fail() { printf 'nested-mount purge test: FAIL: %s\n' "$*" >&2; exit 1; }
TARGET=/var/lib/dexos/data/nested

cleanup() {
    if mountpoint -q "$TARGET"; then
        umount "$TARGET"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p /tmp/mockbin /tmp/mounted-data "$TARGET" \
    /etc/dexos /etc/systemd/system /usr/libexec/dexos /opt/dexos
printf 'mounted sentinel\n' > /tmp/mounted-data/sentinel
printf 'config sentinel\n' > /etc/dexos/sentinel
printf 'state sentinel\n' > /var/lib/dexos/sentinel
printf 'unit sentinel\n' > /etc/systemd/system/marketd.service
printf 'helper sentinel\n' > /usr/libexec/dexos/sentinel
printf 'release sentinel\n' > /opt/dexos/sentinel

cat > /tmp/mockbin/systemctl <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> /tmp/systemctl.calls
MOCK
chmod 0755 /tmp/mockbin/systemctl
export PATH="/tmp/mockbin:$PATH"

mount --bind /tmp/mounted-data "$TARGET"
if /bundle/uninstall.sh --purge-data CONFIRM_REMOVE_DEXOS_DATA \
    > /tmp/nested-mount.out 2>&1; then
    fail "purge accepted a nested bind mount"
fi
grep -q "refusing to purge mount $TARGET" /tmp/nested-mount.out ||
    fail "purge did not identify the nested mount target"
[[ ! -e /tmp/systemctl.calls ]] ||
    fail "systemctl ran before all purge-tree checks completed"
for sentinel in \
    /tmp/mounted-data/sentinel \
    /etc/dexos/sentinel \
    /var/lib/dexos/sentinel \
    /etc/systemd/system/marketd.service \
    /usr/libexec/dexos/sentinel \
    /opt/dexos/sentinel; do
    [[ -e "$sentinel" ]] || fail "refused purge removed $sentinel"
done

umount "$TARGET"
mkdir -p /tmp/failing-findmnt
cat > /tmp/failing-findmnt/findmnt <<'MOCK'
#!/usr/bin/env bash
exit 73
MOCK
chmod 0755 /tmp/failing-findmnt/findmnt
PATH="/tmp/failing-findmnt:$PATH" \
    /bundle/uninstall.sh --purge-data CONFIRM_REMOVE_DEXOS_DATA \
    > /tmp/findmnt-failure.out 2>&1 &&
    fail "purge continued after findmnt failed"
grep -q 'findmnt could not enumerate mount targets; nothing was removed' \
    /tmp/findmnt-failure.out || fail "findmnt failure was not fail-closed"
[[ ! -e /tmp/systemctl.calls ]] ||
    fail "systemctl ran after an incomplete mount inventory"
for sentinel in \
    /etc/dexos/sentinel \
    /var/lib/dexos/sentinel \
    /etc/systemd/system/marketd.service \
    /usr/libexec/dexos/sentinel \
    /opt/dexos/sentinel; do
    [[ -e "$sentinel" ]] || fail "findmnt failure removed $sentinel"
done

printf 'nested-mount purge test: PASS\n'
CONTAINER
