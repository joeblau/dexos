#!/usr/bin/env bash
# Compare architecture digests produced by check-determinism.sh.
# Fails closed if any shared (arch-independent) key diverges.
#
# Usage:
#   ./scripts/compare-determinism-digests.sh digests/x86_64/determinism-digest.txt \
#                                           digests/aarch64/determinism-digest.txt
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <digest-a> <digest-b> [more...]" >&2
  exit 2
fi

# Keys that MUST match across architectures (not host-specific).
# `execution_replay_root` is the execution-core state root recomputed by each
# arch's build over the pinned golden replay script (crates/execution
# tests::execution_replay_root_golden) — the key the gate actually exists for.
REQUIRED_KEYS=(execution_replay_root snapshot_sha256 state_root wire_corpus_sha256)

extract_keys() {
  local f="$1"
  grep -E '^(execution_replay_root|snapshot_sha256|state_root|wire_corpus_sha256)=' "$f" \
    | sort
}

# Fail closed if a digest is missing any required key: a silently-dropped key
# would otherwise "match" across architectures by both being absent.
require_keys() {
  local f="$1" key
  for key in "${REQUIRED_KEYS[@]}"; do
    if ! grep -q "^${key}=" "$f"; then
      echo "digest $f is missing required key: ${key}" >&2
      exit 1
    fi
  done
}

ref="$1"
shift
if [[ ! -f "$ref" ]]; then
  echo "missing digest file: $ref" >&2
  exit 1
fi
require_keys "$ref"
ref_keys="$(extract_keys "$ref")"
if [[ -z "$ref_keys" ]]; then
  echo "no comparable keys in $ref" >&2
  exit 1
fi
echo "reference ($ref):"
echo "$ref_keys"

for other in "$@"; do
  if [[ ! -f "$other" ]]; then
    echo "missing digest file: $other" >&2
    exit 1
  fi
  require_keys "$other"
  other_keys="$(extract_keys "$other")"
  echo "candidate ($other):"
  echo "$other_keys"
  if [[ "$ref_keys" != "$other_keys" ]]; then
    echo "ERROR: architecture digests diverged between $ref and $other" >&2
    diff -u <(printf '%s\n' "$ref_keys") <(printf '%s\n' "$other_keys") >&2 || true
    exit 1
  fi
done

echo "OK: all architecture digests agree on protocol-stable keys"
exit 0
