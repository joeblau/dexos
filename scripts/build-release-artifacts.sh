#!/usr/bin/env bash
# Build production-shaped marketd artifacts with checksums, a target-scoped
# SBOM, and rollback metadata. Intended for CI tag builds and operator smoke
# tests performed from a reviewed, clean commit.
#
# A dirty or unversioned source tree is rejected by default. Local tests may
# set DEXOS_TEST_ONLY_ALLOW_UNCLEAN_RELEASE=1; artifacts built that way are
# explicitly marked test-only and retain the unclean source state in both the
# build metadata and SBOM.
#
# Outputs under ${OUT_DIR:-dist/} (all names are target-suffixed so that
# multiple architectures can attach to one GitHub Release without colliding):
#   marketd-<target>                 binary
#   SHA256SUMS-<target>              checksums
#   sbom-<target>.cdx.json           CycloneDX SBOM for marketd's build closure
#   build-metadata-<target>.json     source, toolchain, features, target, digest
#   ROLLBACK-<target>.md             digest-based rollback procedure
set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
cd "${REPO_ROOT}"

for required_command in awk cargo python3 rustc; do
  command -v "${required_command}" >/dev/null 2>&1 || {
    echo "error: required command not found: ${required_command}" >&2
    exit 1
  }
done
if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  CHECKSUM_TOOL="shasum"
else
  echo "error: neither sha256sum (Linux) nor shasum (macOS) is available" >&2
  exit 1
fi

TARGET="${TARGET:-$(rustc -vV | awk '/^host:/{print $2}')}"
OUT_DIR="${OUT_DIR:-dist}"
FEATURES="${FEATURES:-}"
UNCLEAN_OVERRIDE="${DEXOS_TEST_ONLY_ALLOW_UNCLEAN_RELEASE:-0}"
BIN_NAME="marketd"
MARKETD_MANIFEST="${REPO_ROOT}/bin/marketd/Cargo.toml"

if [[ -z "${TARGET}" || ${#TARGET} -gt 128 || ! "${TARGET}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  echo "error: TARGET must be a conventional target triple (letters, digits, '.', '_' and '-' only)" >&2
  exit 1
fi
if [[ -z "${OUT_DIR}" || "${OUT_DIR}" == *$'\n'* || "${OUT_DIR}" == *$'\r'* ]]; then
  echo "error: OUT_DIR must be a non-empty, single-line path" >&2
  exit 1
fi
case "${UNCLEAN_OVERRIDE}" in
  0 | 1) ;;
  *)
    echo "error: DEXOS_TEST_ONLY_ALLOW_UNCLEAN_RELEASE must be 0 or 1" >&2
    exit 1
    ;;
esac

# Accept only top-level Cargo feature names. This prevents FEATURES from
# reaching into dependency-private feature namespaces. Operator-only features
# are never valid in a production-shaped artifact.
FEATURES_CANONICAL=""
if [[ -n "${FEATURES//[[:space:]]/}" ]]; then
  if [[ "${FEATURES}" == *$'\n'* || "${FEATURES}" == *$'\r'* || "${FEATURES}" == *$'\t'* ]]; then
    echo "error: FEATURES must be a comma- or space-separated single-line list" >&2
    exit 1
  fi
  read -r -a FEATURE_LIST <<< "${FEATURES//,/ }"
  for feature in "${FEATURE_LIST[@]}"; do
    if [[ ! "${feature}" =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]*$ ]]; then
      echo "error: invalid top-level Cargo feature name: ${feature}" >&2
      exit 1
    fi
    case "${feature}" in
      dev-tools | mock-chains)
        echo "error: feature '${feature}' is forbidden in production artifacts" >&2
        exit 1
        ;;
    esac
  done
  FEATURES_CANONICAL="$(IFS=,; echo "${FEATURE_LIST[*]}")"
fi

COMMIT="unversioned"
SHORT_COMMIT="unversioned"
SOURCE_TREE_STATE="unversioned"
if command -v git >/dev/null 2>&1 && git rev-parse --verify HEAD >/dev/null 2>&1; then
  COMMIT="$(git rev-parse --verify HEAD)"
  SHORT_COMMIT="$(git rev-parse --short HEAD)"
  GIT_STATUS="$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
  if [[ -z "${GIT_STATUS}" ]]; then
    SOURCE_TREE_STATE="clean"
  else
    SOURCE_TREE_STATE="dirty"
  fi
fi

if [[ "${SOURCE_TREE_STATE}" != "clean" && "${UNCLEAN_OVERRIDE}" != "1" ]]; then
  echo "error: refusing to build release artifacts from a ${SOURCE_TREE_STATE} source tree" >&2
  echo "       commit or clean all tracked and untracked changes first" >&2
  echo "       local tests only: DEXOS_TEST_ONLY_ALLOW_UNCLEAN_RELEASE=1" >&2
  exit 1
fi
if [[ "${UNCLEAN_OVERRIDE}" == "1" ]]; then
  echo "warning: TEST-ONLY override enabled; source tree state is ${SOURCE_TREE_STATE}" >&2
fi

RUSTC_V="$(rustc -vV)"
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "${OUT_DIR}"
OUT_DIR_ABS="$(cd "${OUT_DIR}" && pwd -P)"
ARTIFACT_STAGE="$(mktemp -d "${OUT_DIR_ABS}/.release-artifacts.XXXXXX")"
cleanup() {
  rm -rf "${ARTIFACT_STAGE}"
}
trap cleanup EXIT HUP INT TERM

METADATA_JSON="${ARTIFACT_STAGE}/cargo-metadata.json"
METADATA_ARGS=(
  metadata
  --format-version 1
  --locked
  --manifest-path "${MARKETD_MANIFEST}"
  --no-default-features
  --filter-platform "${TARGET}"
)
BUILD_ARGS=(
  build
  --release
  --locked
  --manifest-path "${MARKETD_MANIFEST}"
  --target "${TARGET}"
  --bin "${BIN_NAME}"
  --no-default-features
)
if [[ -n "${FEATURES_CANONICAL}" ]]; then
  METADATA_ARGS+=(--features "${FEATURES_CANONICAL}")
  BUILD_ARGS+=(--features "${FEATURES_CANONICAL}")
fi

# Use the same manifest, feature selection, and target for metadata and the
# build. The resolved graph still contains workspace nodes, so the SBOM writer
# below explicitly walks only normal/build edges reachable from marketd.
cargo "${METADATA_ARGS[@]}" > "${METADATA_JSON}"
TARGET_DIR="$(python3 - "${METADATA_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["target_directory"])
PY
)"
[[ -n "${TARGET_DIR}" && "${TARGET_DIR}" != *$'\n'* && "${TARGET_DIR}" != *$'\r'* ]] || {
  echo "error: cargo metadata did not report a target directory" >&2
  exit 1
}

echo "==> building ${BIN_NAME} (release, locked, target=${TARGET})"
cargo "${BUILD_ARGS[@]}"

SRC_BIN="${TARGET_DIR}/${TARGET}/release/${BIN_NAME}"
[[ -f "${SRC_BIN}" ]] || {
  echo "error: cargo did not produce expected target artifact: ${SRC_BIN}" >&2
  exit 1
}
DEST_BASENAME="${BIN_NAME}-${TARGET}"
DEST_BIN="${ARTIFACT_STAGE}/${DEST_BASENAME}"
cp "${SRC_BIN}" "${DEST_BIN}"
chmod 0755 "${DEST_BIN}"

echo "==> SHA-256 checksums"
CHECKSUM_BASENAME="SHA256SUMS-${TARGET}"
(
  cd "${ARTIFACT_STAGE}"
  if [[ "${CHECKSUM_TOOL}" == "sha256sum" ]]; then
    sha256sum "${DEST_BASENAME}" > "${CHECKSUM_BASENAME}"
  else
    shasum -a 256 "${DEST_BASENAME}" > "${CHECKSUM_BASENAME}"
  fi
  cat "${CHECKSUM_BASENAME}"
)

echo "==> SBOM (CycloneDX from marketd's target-specific normal/build closure)"
SBOM_BASENAME="sbom-${TARGET}.cdx.json"
SBOM_TARGET="${TARGET}" \
SBOM_FEATURES="${FEATURES_CANONICAL:-none}" \
SBOM_TIMESTAMP="${TIMESTAMP_UTC}" \
SBOM_COMMIT="${COMMIT}" \
SBOM_SOURCE_TREE_STATE="${SOURCE_TREE_STATE}" \
SBOM_UNCLEAN_OVERRIDE="${UNCLEAN_OVERRIDE}" \
python3 - "${METADATA_JSON}" > "${ARTIFACT_STAGE}/${SBOM_BASENAME}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
import urllib.parse

with open(sys.argv[1], encoding="utf-8") as source:
    meta = json.load(source)

manifest = pathlib.Path(meta["workspace_root"]) / "bin" / "marketd" / "Cargo.toml"
roots = [
    package
    for package in meta["packages"]
    if package["name"] == "marketd"
    and pathlib.Path(package["manifest_path"]).resolve() == manifest.resolve()
]
if len(roots) != 1:
    raise SystemExit(f"expected one marketd package, found {len(roots)}")
root = roots[0]
root_id = root["id"]

resolve = meta.get("resolve")
if not resolve:
    raise SystemExit("cargo metadata did not include a resolved dependency graph")
packages = {package["id"]: package for package in meta["packages"]}
nodes = {node["id"]: node for node in resolve["nodes"]}

def build_dependencies(node):
    """Yield normal/build dependencies, excluding all dev-only edges."""
    for dependency in node.get("deps", []):
        kinds = dependency.get("dep_kinds", [])
        if not kinds or any(kind.get("kind") != "dev" for kind in kinds):
            yield dependency["pkg"]

reachable = set()
pending = [root_id]
while pending:
    package_id = pending.pop()
    if package_id in reachable:
        continue
    if package_id not in packages or package_id not in nodes:
        raise SystemExit(f"resolved dependency is missing metadata: {package_id}")
    reachable.add(package_id)
    pending.extend(build_dependencies(nodes[package_id]))

workspace_members = set(meta["workspace_members"])

def source_identity(package):
    source = package.get("source")
    if source:
        return source
    return "workspace" if package["id"] in workspace_members else "path"

def bom_ref(package):
    identity = source_identity(package)
    source_hash = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    name = urllib.parse.quote(package["name"], safe="")
    version = urllib.parse.quote(package["version"], safe="")
    return f"urn:dexos:cargo:{name}:{version}:{source_hash}"

def purl(package):
    name = urllib.parse.quote(package["name"], safe="")
    version = urllib.parse.quote(package["version"], safe="")
    return f"pkg:cargo/{name}@{version}"

refs = {package_id: bom_ref(packages[package_id]) for package_id in reachable}
if len(refs.values()) != len(set(refs.values())):
    raise SystemExit("dependency closure produced duplicate CycloneDX bom-ref values")

components = []
for package_id in sorted(reachable - {root_id}, key=lambda item: (
    packages[item]["name"], packages[item]["version"], source_identity(packages[item])
)):
    package = packages[package_id]
    component = {
        "type": "library",
        "name": package["name"],
        "version": package["version"],
        "purl": purl(package),
        "bom-ref": refs[package_id],
        "properties": [
            {"name": "cargo:source", "value": source_identity(package)},
        ],
    }
    if package.get("license"):
        component["licenses"] = [{"expression": package["license"]}]
    components.append(component)

dependencies = []
for package_id in sorted(reachable, key=lambda item: refs[item]):
    depends_on = sorted({
        refs[dependency_id]
        for dependency_id in build_dependencies(nodes[package_id])
        if dependency_id in reachable
    })
    dependencies.append({"ref": refs[package_id], "dependsOn": depends_on})

root_component = {
    "type": "application",
    "name": root["name"],
    "version": root["version"],
    "purl": purl(root),
    "bom-ref": refs[root_id],
}
if root.get("license"):
    root_component["licenses"] = [{"expression": root["license"]}]

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": os.environ["SBOM_TIMESTAMP"],
        "component": root_component,
        "properties": [
            {"name": "dexos:cargo_dependency_kinds", "value": "normal,build"},
            {"name": "dexos:commit", "value": os.environ["SBOM_COMMIT"]},
            {"name": "dexos:features", "value": os.environ["SBOM_FEATURES"]},
            {"name": "dexos:source_tree_state", "value": os.environ["SBOM_SOURCE_TREE_STATE"]},
            {"name": "dexos:target", "value": os.environ["SBOM_TARGET"]},
            {"name": "dexos:test_only_unclean_override", "value": os.environ["SBOM_UNCLEAN_OVERRIDE"]},
        ],
    },
    "components": components,
    "dependencies": dependencies,
}
print(json.dumps(bom, indent=2, sort_keys=True))
PY

echo "==> build metadata"
DIGEST="$(awk 'NR == 1 {print $1}' "${ARTIFACT_STAGE}/${CHECKSUM_BASENAME}")"
METADATA_BASENAME="build-metadata-${TARGET}.json"
BUILD_BINARY="${DEST_BASENAME}" \
BUILD_TARGET="${TARGET}" \
BUILD_COMMIT="${COMMIT}" \
BUILD_SHORT_COMMIT="${SHORT_COMMIT}" \
BUILD_RUSTC="${RUSTC_V}" \
BUILD_FEATURES="${FEATURES_CANONICAL:-none}" \
BUILD_DIGEST="${DIGEST}" \
BUILD_TIMESTAMP="${TIMESTAMP_UTC}" \
BUILD_SOURCE_TREE_STATE="${SOURCE_TREE_STATE}" \
BUILD_UNCLEAN_OVERRIDE="${UNCLEAN_OVERRIDE}" \
python3 - > "${ARTIFACT_STAGE}/${METADATA_BASENAME}" <<'PY'
import json
import os

state = os.environ["BUILD_SOURCE_TREE_STATE"]
override = os.environ["BUILD_UNCLEAN_OVERRIDE"] == "1"
features = os.environ["BUILD_FEATURES"]
invocation = [
    "cargo", "build", "--release", "--locked",
    "--manifest-path", "bin/marketd/Cargo.toml",
    "--target", os.environ["BUILD_TARGET"],
    "--bin", "marketd", "--no-default-features",
]
if features != "none":
    invocation.extend(["--features", features])

print(json.dumps({
    "artifact_class": "release" if state == "clean" and not override else "test-only",
    "binary": os.environ["BUILD_BINARY"],
    "target": os.environ["BUILD_TARGET"],
    "commit": os.environ["BUILD_COMMIT"],
    "commit_short": os.environ["BUILD_SHORT_COMMIT"],
    "source_tree_state": state,
    "source_tree_clean": state == "clean",
    "test_only_unclean_override": override,
    "rustc": os.environ["BUILD_RUSTC"],
    "features": features,
    "profile": "release",
    "panic_strategy": "abort",
    "sha256": os.environ["BUILD_DIGEST"],
    "built_at_utc": os.environ["BUILD_TIMESTAMP"],
    "cargo_invocation": invocation,
    "reproducibility_notes": [
        "Built with Cargo.lock and an explicit target using marketd --no-default-features",
        "Accepted binary nondeterminism: toolchain-embedded paths; macOS ad-hoc code-sign IDs",
        "Two clean builds on the same host/target with identical Cargo.lock should match SHA-256 on Linux",
    ],
}, indent=2, sort_keys=True))
PY

echo "==> rollback procedure"
ROLLBACK_BASENAME="ROLLBACK-${TARGET}.md"
cat > "${ARTIFACT_STAGE}/${ROLLBACK_BASENAME}" <<EOF
# Rollback by immutable digest

Artifact: \`${DEST_BASENAME}\`
SHA-256: \`${DIGEST}\`
Commit: \`${COMMIT}\`
Source tree state: \`${SOURCE_TREE_STATE}\`
Built: \`${TIMESTAMP_UTC}\`

## Restore previous binary

1. Identify the last known-good digest from your release notes / artifact store.
2. Fetch that exact binary (do not rebuild ad-hoc).
3. Verify with \`sha256sum -c ${CHECKSUM_BASENAME}\` on Linux or
   \`shasum -a 256 -c ${CHECKSUM_BASENAME}\` on macOS.
4. Stop the running node with SIGTERM; wait for drain (see
   \`performance.drain_timeout_ms\`).
5. Replace the binary path used by systemd/k8s with the verified artifact.
6. Start the node and run \`bare-metal-verify\`. Today that proves only process
   smoke readiness; it does not prove durable state or consensus recovery.
7. Keep the node fenced. This repository does not yet provide an authoritative
   snapshot/restore or composed state-root recovery check; stop the service and
   preserve evidence if configuration or compatibility is uncertain.

Never roll forward by "rebuilding main" -- always pin by digest + commit SHA.
EOF
if [[ "${SOURCE_TREE_STATE}" != "clean" || "${UNCLEAN_OVERRIDE}" == "1" ]]; then
  cat >> "${ARTIFACT_STAGE}/${ROLLBACK_BASENAME}" <<'EOF'

> **TEST-ONLY ARTIFACT:** the source tree was not a clean reviewed commit.
> Do not publish, sign, install, or use this artifact as a rollback target.
EOF
fi

rm -f "${METADATA_JSON}"
for artifact in \
  "${DEST_BASENAME}" \
  "${CHECKSUM_BASENAME}" \
  "${SBOM_BASENAME}" \
  "${METADATA_BASENAME}" \
  "${ROLLBACK_BASENAME}"; do
  mv -f "${ARTIFACT_STAGE}/${artifact}" "${OUT_DIR_ABS}/${artifact}"
done
rmdir "${ARTIFACT_STAGE}"

echo
echo "==> release artifacts written to ${OUT_DIR_ABS}/"
ls -la "${OUT_DIR_ABS}"
