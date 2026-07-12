#!/usr/bin/env bash
# Prove deterministic compatibility: scalar ≡ vectorized SIMD kernels, and
# cross-crate golden vectors that must be byte-stable across architectures.
#
# CI runs this on every supported host architecture (x86_64 + aarch64). The
# produced `determinism-digest.txt` is compared across matrix legs; protocol-
# stable keys must match or the compare job fails closed.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_DIGEST="${DETERMINISM_DIGEST_PATH:-determinism-digest.txt}"

echo "==> host"
uname -a || true
echo "endian: $(python3 -c 'import sys; print(sys.byteorder)')"
echo "target: $(rustc -vV | awk '/^host:/{print $2}')"

echo "==> simd: scalar ≡ vectorized ≡ dispatched (all backends)"
cargo test -p simd --lib --locked -- --nocapture forcing_each_backend 2>&1 | tail -20
cargo test -p simd --lib --locked -- --nocapture dispatch_runs 2>&1 | tail -20

echo "==> node cross-crate scalar payout goldens (architecture-stable)"
cargo test -p node --test scalar_payout_cross_crate --locked

echo "==> execution + state-tree deterministic roots"
./scripts/verify-state-roots.sh

echo "==> storage cross-arch snapshot fixture (export digests)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/dexos-det.XXXXXX")"
SNAP_OUT="${WORKDIR}/cross-arch.snap"
TEST_LOG="${WORKDIR}/cross-arch-out.txt"
export CROSS_ARCH_SNAPSHOT_OUT="${SNAP_OUT}"
set +e
cargo test -p storage --test cross_arch_snapshot --locked \
  cross_arch_snapshot_round_trip -- --nocapture >"${TEST_LOG}" 2>&1
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  echo "storage cross_arch_snapshot test failed:" >&2
  cat "${TEST_LOG}" >&2
  exit "$rc"
fi
tail -30 "${TEST_LOG}" || true

echo "==> execution golden replay root (export for cross-arch comparison)"
# A REAL execution-core state root, recomputed by this host's build of the
# engine over the pinned golden replay script. Unlike a table hashed inside
# this script, a cross-arch divergence in matching/risk/funding/liquidation
# arithmetic shows up here and fails the multi-arch compare gate.
EXEC_LOG="${WORKDIR}/execution-replay-out.txt"
set +e
cargo test -p execution --lib --locked \
  execution_replay_root_golden -- --nocapture >"${EXEC_LOG}" 2>&1
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  echo "execution execution_replay_root_golden test failed:" >&2
  cat "${EXEC_LOG}" >&2
  exit "$rc"
fi
tail -10 "${EXEC_LOG}" || true

echo "==> determinism digest (for cross-arch comparison)"
export CROSS_ARCH_TEST_LOG="${TEST_LOG}"
export EXECUTION_REPLAY_TEST_LOG="${EXEC_LOG}"
export DETERMINISM_DIGEST_PATH="${OUT_DIGEST}"
python3 - <<'PY'
import platform, os, re, pathlib
lines = [
    f"host_machine={platform.machine()}",
    f"host_endian={__import__('sys').byteorder}",
]
# Execution-core replay root: scraped from the golden known-answer replay
# test (crates/execution tests::execution_replay_root_golden), which prints
# `execution_replay_root=<hex>` and asserts it equals the in-source pinned
# constant EXECUTION_REPLAY_ROOT_GOLDEN.
exec_log = pathlib.Path(os.environ.get("EXECUTION_REPLAY_TEST_LOG", ""))
if exec_log.is_file():
    m = re.search(r"execution_replay_root=([0-9a-fA-F]+)", exec_log.read_text())
    if m:
        lines.append(f"execution_replay_root={m.group(1).lower()}")
# Merge storage fixture digests (architecture-stable keys).
snap_file = os.environ.get("CROSS_ARCH_SNAPSHOT_OUT", "")
found = False
if snap_file:
    p = pathlib.Path(snap_file)
    for c in (p.with_suffix(".digest"), pathlib.Path(str(p) + ".digest")):
        if c.is_file():
            for line in c.read_text().splitlines():
                if line.startswith(("snapshot_sha256=", "state_root=", "wire_corpus_sha256=")):
                    lines.append(line)
            found = True
            break
if not found:
    log = pathlib.Path(os.environ.get("CROSS_ARCH_TEST_LOG", ""))
    if log.is_file():
        text = log.read_text()
        for key in ("snapshot_sha256", "state_root", "wire_corpus_sha256"):
            m = re.search(rf"{key}=([0-9a-fA-F]+)", text)
            if m:
                lines.append(f"{key}={m.group(1).lower()}")

out = os.environ.get("DETERMINISM_DIGEST_PATH", "determinism-digest.txt")
pathlib.Path(out).write_text("\n".join(lines) + "\n")
print("\n".join(lines))
print(f"wrote {out}")
print("note: wire formats and state roots are little-endian fixed-width integers;")
print("      big-endian hosts are not a supported production target.")
# Require protocol-stable keys so multi-arch compare has something to gate on.
required = {"execution_replay_root", "snapshot_sha256", "state_root", "wire_corpus_sha256"}
have = {ln.split("=", 1)[0] for ln in lines if "=" in ln}
missing = required - have
if missing:
    raise SystemExit(f"determinism digest missing required keys: {sorted(missing)}")
PY

echo
echo "==> determinism checks passed on this host (digest: ${OUT_DIGEST})"
