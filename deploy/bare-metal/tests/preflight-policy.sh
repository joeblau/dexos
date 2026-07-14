#!/usr/bin/env bash
# Exercise host preflight path, ownership, mode, and service-account access
# policy in a disposable Ubuntu container. The test never changes the host.
set -euo pipefail

TEST_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(dirname "$TEST_DIR")"
IMAGE="${DEXOS_TEST_UBUNTU_IMAGE:-ubuntu:24.04}"

command -v docker >/dev/null 2>&1 || {
    printf 'bare-metal preflight policy test: docker is required\n' >&2
    exit 1
}

docker run --rm -i \
    --mount "type=bind,src=$BUNDLE_DIR,dst=/bundle,readonly" \
    "$IMAGE" bash -s <<'CONTAINER'
set -euo pipefail

fail() {
    printf 'bare-metal preflight policy test: FAIL: %s\n' "$*" >&2
    exit 1
}

pass() {
    printf 'bare-metal preflight policy test: PASS: %s\n' "$*"
}

run_preflight() {
    DEXOS_ACKNOWLEDGE_SKELETON=1 /bundle/preflight.sh
}

assert_no_runtime_invocation() {
    local label="$1"
    [[ ! -e /tmp/marketd.runtime ]] ||
        fail "$label invoked the runtime after a failed policy check"
    if [[ -s /tmp/marketd.calls ]] &&
        grep -Fvx -- '--version' /tmp/marketd.calls >/dev/null; then
        fail "$label invoked marketd with an argument other than --version"
    fi
    [[ "$(wc -l < /tmp/marketd.calls)" -le 1 ]] ||
        fail "$label invoked the binary more than once"
}

expect_failure() {
    local label="$1" expected="$2"
    : > /tmp/marketd.calls
    rm -f /tmp/marketd.runtime /tmp/preflight.out
    if run_preflight > /tmp/preflight.out 2>&1; then
        fail "$label unexpectedly succeeded"
    fi
    grep -Fq -- "$expected" /tmp/preflight.out || {
        sed -n '1,200p' /tmp/preflight.out >&2
        fail "$label did not report '$expected'"
    }
    assert_no_runtime_invocation "$label"
}

expect_symlink_failure() {
    local path="$1" label="$2" expected="$3" real_path
    real_path="${path}.real"
    mv "$path" "$real_path"
    ln -s "$(basename "$real_path")" "$path"
    expect_failure "$label" "$expected"
    rm "$path"
    mv "$real_path" "$path"
}

groupadd --system dexos
useradd --system --gid dexos --home-dir /var/lib/dexos \
    --shell /usr/sbin/nologin dexos

install -d -o root -g root -m 0755 /opt/dexos /opt/dexos/releases
install -d -o root -g dexos -m 0750 /etc/dexos
install -d -o dexos -g dexos -m 0750 /var/lib/dexos /var/lib/dexos/data

cat > /tmp/marketd.fixture <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> /tmp/marketd.calls
if [[ "$#" -eq 1 && "$1" == "--version" ]]; then
    printf 'marketd preflight-policy-test\n'
    exit 0
fi
: > /tmp/marketd.runtime
exit 70
EOF
chmod 0755 /tmp/marketd.fixture

DIGEST="$(sha256sum /tmp/marketd.fixture | awk '{ print $1 }')"
RELEASE="/opt/dexos/releases/$DIGEST"
install -d -o root -g root -m 0755 "$RELEASE"
install -o root -g root -m 0755 /tmp/marketd.fixture "$RELEASE/marketd"
printf '%s  marketd\n' "$DIGEST" > "$RELEASE/SHA256"
chown root:root "$RELEASE/SHA256"
chmod 0644 "$RELEASE/SHA256"
ln -s "releases/$DIGEST" /opt/dexos/current
chown -h root:root /opt/dexos/current

cat > /etc/dexos/marketd.toml <<'EOF'
[node]
roles = ["validator"]

[consensus]
validator_set_path = "/etc/dexos/validators.toml"

[storage]
data_dir = "/var/lib/dexos/data"

[rpc]
tls_cert_path = "/etc/dexos/server.crt"
tls_key_path = "/etc/dexos/server.key"
tls_client_ca_path = "/etc/dexos/client-ca.crt"

[observability]
metrics_listen = "127.0.0.1:9100"
EOF
printf 'DEXOS_ACKNOWLEDGE_SKELETON=1\n' > /etc/dexos/marketd.env
printf '[[validators]]\nid = 1\nweight = 1\npublic_key = "%064d"\n' 0 \
    > /etc/dexos/validators.toml
printf 'test certificate\n' > /etc/dexos/server.crt
printf 'test private key\n' > /etc/dexos/server.key
printf 'test client CA\n' > /etc/dexos/client-ca.crt

chown root:dexos /etc/dexos/marketd.toml /etc/dexos/marketd.env \
    /etc/dexos/validators.toml /etc/dexos/server.key
chmod 0640 /etc/dexos/marketd.toml /etc/dexos/marketd.env \
    /etc/dexos/validators.toml /etc/dexos/server.key
chown root:root /etc/dexos/server.crt /etc/dexos/client-ca.crt
chmod 0644 /etc/dexos/server.crt /etc/dexos/client-ca.crt

: > /tmp/marketd.calls
rm -f /tmp/marketd.runtime
run_preflight > /tmp/preflight.out 2>&1 || {
    sed -n '1,200p' /tmp/preflight.out >&2
    fail "valid baseline was rejected"
}
[[ "$(cat /tmp/marketd.calls)" == '--version' ]] ||
    fail "valid baseline made an unexpected binary call"
[[ ! -e /tmp/marketd.runtime ]] || fail "valid baseline invoked the runtime"
pass "valid TLS-enabled validator baseline"

expect_symlink_failure /var/lib/dexos/data "symlinked state directory" \
    "state directory is missing, not a real directory, or is a symlink"
expect_symlink_failure /etc/dexos/validators.toml "symlinked validator set" \
    "validator-set file is missing, not regular, or is a symlink"
expect_symlink_failure /etc/dexos/server.crt "symlinked RPC TLS certificate" \
    "RPC TLS certificate is missing, not regular, or is a symlink"
expect_symlink_failure /etc/dexos/server.key "symlinked RPC TLS private key" \
    "RPC TLS private key is missing, not regular, or is a symlink"
expect_symlink_failure /etc/dexos/client-ca.crt "symlinked RPC TLS client CA" \
    "RPC TLS client CA is missing, not regular, or is a symlink"
pass "state, validator, certificate, private-key, and client-CA symlinks fail closed"

chown dexos:dexos /etc/dexos/server.crt
expect_failure "non-root-owned RPC TLS certificate" \
    "RPC TLS certificate must be owned by root"
chown root:root /etc/dexos/server.crt
chmod 0664 /etc/dexos/server.crt
expect_failure "writable RPC TLS certificate" \
    "RPC TLS certificate is group/world-writable"
chmod 0600 /etc/dexos/server.crt
expect_failure "service-unreadable RPC TLS certificate" \
    "dexos cannot read RPC TLS certificate"
chmod 0644 /etc/dexos/server.crt

chown dexos:dexos /etc/dexos/client-ca.crt
expect_failure "non-root-owned RPC TLS client CA" \
    "RPC TLS client CA must be owned by root"
chown root:root /etc/dexos/client-ca.crt
chmod 0664 /etc/dexos/client-ca.crt
expect_failure "writable RPC TLS client CA" \
    "RPC TLS client CA is group/world-writable"
chmod 0600 /etc/dexos/client-ca.crt
expect_failure "service-unreadable RPC TLS client CA" \
    "dexos cannot read RPC TLS client CA"
chmod 0644 /etc/dexos/client-ca.crt

chown dexos:dexos /etc/dexos/server.key
expect_failure "non-root-owned RPC TLS private key" \
    "RPC TLS private key must be owned by root"
chown root:root /etc/dexos/server.key
expect_failure "wrong-group RPC TLS private key" \
    "RPC TLS private-key group must be dexos"
chown root:dexos /etc/dexos/server.key
chmod 0660 /etc/dexos/server.key
expect_failure "writable RPC TLS private key" \
    "RPC TLS private key is group/world-writable"
chmod 0644 /etc/dexos/server.key
expect_failure "world-readable RPC TLS private key" \
    "RPC TLS private key is world-readable"
chmod 0600 /etc/dexos/server.key
expect_failure "service-unreadable RPC TLS private key" \
    "dexos cannot read RPC TLS private key"
chmod 0640 /etc/dexos/server.key
pass "TLS ownership, write, secrecy, and service-readability gates fail closed"

: > /tmp/marketd.calls
rm -f /tmp/marketd.runtime
run_preflight > /tmp/preflight.out 2>&1 || {
    sed -n '1,200p' /tmp/preflight.out >&2
    fail "restored valid fixture was rejected"
}
[[ "$(cat /tmp/marketd.calls)" == '--version' ]] ||
    fail "restored fixture made an unexpected binary call"
[[ ! -e /tmp/marketd.runtime ]] || fail "restored fixture invoked the runtime"
pass "fixture restoration preserves the valid baseline"

printf 'bare-metal preflight policy test: all checks passed\n'
CONTAINER
