#!/usr/bin/env bash
# Exercise packaging-time invariants without requiring root or systemd.
set -euo pipefail

TEST_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(dirname "$TEST_DIR")"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dexos-bare-metal-test.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT INT TERM

fail() { printf 'bare-metal staging test: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'bare-metal staging test: PASS: %s\n' "$*"; }

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

mode_of() {
    if stat -c '%a' "$1" >/dev/null 2>&1; then
        stat -c '%a' "$1"
    else
        stat -f '%Lp' "$1"
    fi
}

assert_eq() {
    local expected="$1" actual="$2" label="$3"
    [[ "$actual" == "$expected" ]] || fail "$label: expected '$expected', found '$actual'"
}

assert_fails() {
    local label="$1"
    shift
    if "$@" >"$TMP_ROOT/failure.out" 2>&1; then
        fail "$label unexpectedly succeeded"
    fi
}

make_binary() {
    local destination="$1" version="$2"
    # The generated fixture must retain its own positional-parameter expansion.
    # shellcheck disable=SC2016
    printf '#!/usr/bin/env bash\nif [[ "${1:-}" == "--version" ]]; then printf "marketd %s\\n"; else exit 64; fi\n' \
        "$version" > "$destination"
    chmod 0755 "$destination"
}

for script in "$BUNDLE_DIR"/*.sh "$TEST_DIR"/*.sh; do
    bash -n "$script"
done
pass "all bare-metal shell scripts parse"

grep -qx 'ConditionFileIsExecutable=/opt/dexos/current/marketd' \
    "$BUNDLE_DIR/systemd/marketd.service" || \
    fail "systemd unit does not use the supported executable-file condition"
grep -qx 'EnvironmentFile=/etc/dexos/marketd.env' \
    "$BUNDLE_DIR/systemd/marketd.service" || \
    fail "systemd unit does not require the audited environment file"
pass "systemd unit uses fail-closed executable and environment directives"

BINARY_A="$TMP_ROOT/marketd-a"
BINARY_B="$TMP_ROOT/marketd-b"
make_binary "$BINARY_A" 1.0.0-test
make_binary "$BINARY_B" 2.0.0-test
DIGEST_A="$(sha256_file "$BINARY_A")"
DIGEST_B="$(sha256_file "$BINARY_B")"
STAGE="$TMP_ROOT/stage"

DESTDIR="$STAGE" "$BUNDLE_DIR/install.sh" \
    --binary "$BINARY_A" \
    --sha256 "$DIGEST_A" \
    --acknowledge-skeleton \
    --start \
    --health-url http://127.0.0.1:19100 >/dev/null

RELEASE="$STAGE/opt/dexos/releases/$DIGEST_A"
assert_eq "releases/$DIGEST_A" "$(readlink "$STAGE/opt/dexos/current")" \
    "relative current target"
assert_eq 755 "$(mode_of "$STAGE/opt/dexos")" "installation-root mode"
assert_eq 755 "$(mode_of "$STAGE/opt/dexos/releases")" "release-root mode"
assert_eq 755 "$(mode_of "$RELEASE")" "release-directory mode"
assert_eq 755 "$(mode_of "$RELEASE/marketd")" "binary mode"
assert_eq 644 "$(mode_of "$RELEASE/SHA256")" "checksum mode"
assert_eq 640 "$(mode_of "$STAGE/etc/dexos/marketd.env")" "environment mode"
assert_eq "$DIGEST_A  marketd" "$(sed -n '1p' "$RELEASE/SHA256")" \
    "checksum record"
grep -qx 'DEXOS_ACKNOWLEDGE_SKELETON=1' "$STAGE/etc/dexos/marketd.env" || \
    fail "staged --start acknowledgement was not recorded"
pass "staged install emits strict release and environment metadata"

printf 'PRESERVED_MARKER=1\n' > "$STAGE/etc/dexos/marketd.env"
chmod 0666 "$STAGE/etc/dexos/marketd.env"
DESTDIR="$STAGE" "$BUNDLE_DIR/install.sh" \
    --binary "$BINARY_A" --sha256 "$DIGEST_A" >/dev/null
grep -qx 'PRESERVED_MARKER=1' "$STAGE/etc/dexos/marketd.env" || \
    fail "existing environment content was not preserved"
assert_eq 640 "$(mode_of "$STAGE/etc/dexos/marketd.env")" \
    "preserved environment normalized mode"
pass "preserved environment files are normalized to 0640"

assert_fails "invalid install health URL" env DESTDIR="$TMP_ROOT/bad-url-stage" \
    "$BUNDLE_DIR/install.sh" --binary "$BINARY_A" --sha256 "$DIGEST_A" \
    --acknowledge-skeleton --start --health-url file:///tmp/not-http
grep -q -- '--health-url must be' "$TMP_ROOT/failure.out" || \
    fail "invalid health URL did not report its policy failure"
# This is intentionally a literal source assertion for the non-runnable
# systemd branch of a DESTDIR staging test.
# shellcheck disable=SC2016
grep -Fq '"$LIBEXEC/bare-metal-verify" --health-url "$HEALTH_URL"' \
    "$BUNDLE_DIR/install.sh" || fail "install does not hand its health URL to the verifier"
grep -Fq '"--health-url must be a non-empty http:// or https:// URL"' \
    "$BUNDLE_DIR/verify.sh" || fail "standalone verifier does not validate its health URL"
assert_fails "invalid verifier health URL" \
    "$BUNDLE_DIR/verify.sh" --health-url file:///tmp/not-http
grep -q -- '--health-url must be' "$TMP_ROOT/failure.out" || \
    fail "standalone verifier did not reject an unsafe URL"
assert_fails "option-shaped verifier service" \
    "$BUNDLE_DIR/verify.sh" --service -quiet
grep -q -- '--service contains unsupported characters' "$TMP_ROOT/failure.out" || \
    fail "standalone verifier accepted an option-shaped service name"
pass "install and verifier validate health/service input before host actions"

printf 'CONFIG_MUST_SURVIVE=1\n' > "$STAGE/etc/dexos/marketd.env"
assert_fails "different digest reinstall" env DESTDIR="$STAGE" \
    "$BUNDLE_DIR/install.sh" --binary "$BINARY_B" --sha256 "$DIGEST_B" \
    --replace-config
grep -qx 'CONFIG_MUST_SURVIVE=1' "$STAGE/etc/dexos/marketd.env" || \
    fail "different-digest refusal modified configuration"
pass "different-digest install refusal precedes configuration changes"

rm -f "$STAGE/opt/dexos/current"
ln -s "releases/${DIGEST_A}extra" "$STAGE/opt/dexos/current"
assert_fails "malformed current target" env DESTDIR="$STAGE" \
    "$BUNDLE_DIR/install.sh" --binary "$BINARY_A" --sha256 "$DIGEST_A"
grep -q 'another release is installed' "$TMP_ROOT/failure.out" || \
    fail "malformed current target was not rejected"
pass "installer refuses a non-exact current target"

guard_line="$(grep -n 'for purge_path in /etc/dexos /var/lib/dexos' \
    "$BUNDLE_DIR/uninstall.sh" | cut -d: -f1)"
disable_line="$(grep -n '^systemctl disable --now' "$BUNDLE_DIR/uninstall.sh" | cut -d: -f1)"
[[ "$guard_line" -lt "$disable_line" ]] || \
    fail "purge safety guard does not precede service/file removal"
pass "purge mount-tree/symlink guards run before uninstall mutation"

printf 'bare-metal staging test: all checks passed\n'
