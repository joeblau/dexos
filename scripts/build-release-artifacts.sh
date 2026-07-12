#!/usr/bin/env bash
# Build reproducible production artifacts for marketd with checksums, SBOM, and
# rollback metadata. Intended for CI tag builds and operator release smoke tests.
#
# Outputs under ${OUT_DIR:-dist/}:
#   marketd-<target>                 binary
#   SHA256SUMS                       checksums
#   sbom.cdx.json                    CycloneDX-like SBOM from cargo metadata
#   build-metadata.json              commit, rustc, features, target, timestamp
#   ROLLBACK.md                      digest-based rollback procedure
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${TARGET:-$(rustc -vV | awk '/^host:/{print $2}')}"
OUT_DIR="${OUT_DIR:-dist}"
FEATURES="${FEATURES:-}"
BIN_NAME="marketd"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
SHORT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
RUSTC_V="$(rustc -vV | tr '\n' '|' | sed 's/|$//')"
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "${OUT_DIR}"

echo "==> building ${BIN_NAME} (release, locked, target=${TARGET})"
# Production artifacts use minimal features (no dev-tools).
if [[ -n "${FEATURES}" ]]; then
  cargo build --release --locked --bin "${BIN_NAME}" --no-default-features --features "${FEATURES}"
else
  cargo build --release --locked --bin "${BIN_NAME}" --no-default-features
fi

SRC_BIN="target/release/${BIN_NAME}"
if [[ ! -f "${SRC_BIN}" ]]; then
  SRC_BIN="target/${TARGET}/release/${BIN_NAME}"
fi
DEST_BIN="${OUT_DIR}/${BIN_NAME}-${TARGET}"
cp "${SRC_BIN}" "${DEST_BIN}"
chmod +x "${DEST_BIN}"

echo "==> SHA-256 checksums"
(
  cd "${OUT_DIR}"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$(basename "${DEST_BIN}")" > SHA256SUMS
  else
    sha256sum "$(basename "${DEST_BIN}")" > SHA256SUMS
  fi
  cat SHA256SUMS
)

echo "==> SBOM (CycloneDX-like from cargo metadata)"
python3 - <<'PY' > "${OUT_DIR}/sbom.cdx.json"
import json, subprocess, datetime
meta = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--format-version", "1", "--locked"]
))
components = []
for pkg in meta.get("packages", []):
    components.append({
        "type": "library",
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": "pkg:cargo/{}@{}".format(pkg["name"], pkg["version"]),
        "bom-ref": "{}@{}".format(pkg["name"], pkg["version"]),
    })
marketd_ver = next(
    (p["version"] for p in meta["packages"] if p["name"] == "marketd"),
    "0.0.0",
)
bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "component": {
            "type": "application",
            "name": "marketd",
            "version": marketd_ver,
        },
    },
    "components": components,
}
print(json.dumps(bom, indent=2, sort_keys=True))
PY

echo "==> build metadata"
DIGEST="$(awk '{print $1}' "${OUT_DIR}/SHA256SUMS" | head -1)"
python3 - <<PY > "${OUT_DIR}/build-metadata.json"
import json
print(json.dumps({
    "binary": "$(basename "${DEST_BIN}")",
    "target": "${TARGET}",
    "commit": "${COMMIT}",
    "commit_short": "${SHORT_COMMIT}",
    "rustc": """${RUSTC_V}""".replace("|", "\n"),
    "features": "${FEATURES:-none}",
    "profile": "release",
    "panic_strategy": "abort",
    "sha256": "${DIGEST}",
    "built_at_utc": "${TIMESTAMP_UTC}",
    "reproducibility_notes": [
        "Built with cargo build --release --locked --no-default-features",
        "Accepted nondeterminism: toolchain-embedded paths; macOS ad-hoc code-sign IDs",
        "Two clean builds on the same host/target with identical Cargo.lock should match SHA-256 on Linux"
    ],
}, indent=2, sort_keys=True))
PY

echo "==> rollback procedure"
cat > "${OUT_DIR}/ROLLBACK.md" <<EOF
# Rollback by immutable digest

Artifact: \`$(basename "${DEST_BIN}")\`
SHA-256: \`${DIGEST}\`
Commit: \`${COMMIT}\`
Built: \`${TIMESTAMP_UTC}\`

## Restore previous binary

1. Identify the last known-good digest from your release notes / artifact store.
2. Fetch that exact binary (do not rebuild ad-hoc).
3. Verify: \`shasum -a 256 -c SHA256SUMS\` (or \`sha256sum -c\`).
4. Stop the running node with SIGTERM; wait for drain (see \`performance.drain_timeout_ms\`).
5. Replace the binary path used by systemd/k8s with the verified artifact.
6. Start the node; confirm \`/livez\` then \`/readyz\`, and that the state root
   matches the pre-upgrade checkpoint when applicable.
7. If readiness fails or roots diverge, fence the node and restore the matching
   snapshot + command log from the backup taken before the upgrade.

Never roll forward by "rebuilding main" — always pin by digest + commit SHA.
EOF

echo
echo "==> release artifacts written to ${OUT_DIR}/"
ls -la "${OUT_DIR}"
