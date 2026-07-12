#!/usr/bin/env bash
# Run the PR-blocking CI gates locally, in the order ci.yml runs them.
#
# Default (fast) path: rustfmt, clippy, workspace tests, docs (warnings are
# errors), the deterministic-core guard scripts, and the state-root agreement
# suite.
#
# `--full` additionally runs the determinism suite (check-determinism.sh).
# That script invokes verify-state-roots.sh internally, so the standalone
# state-root step is skipped on the full path to avoid running it twice.
#
# Mirrors .github/workflows/ci.yml — keep the two in sync when adding a gate.
set -euo pipefail
cd "$(dirname "$0")/.."

# ci.yml sets RUSTFLAGS at the workflow level; without this, local builds and
# tests can pass on warnings that CI rejects.
export RUSTFLAGS="-D warnings"

FULL=0
for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
        -h|--help)
            echo "usage: $0 [--full]"
            echo "  default  fmt, clippy, test, doc, core guards, state-root agreement"
            echo "  --full   also run the determinism suite (which itself includes"
            echo "           the state-root agreement check)"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg (usage: $0 [--full])" >&2
            exit 2
            ;;
    esac
done

echo "==> rustfmt (ci job: lint)"
cargo fmt --all --check

echo "==> clippy (ci job: lint)"
cargo clippy --workspace --all-targets --locked -- -D warnings

echo "==> workspace tests (ci job: test)"
cargo test --workspace --locked

echo "==> docs, fail on warnings (ci job: docs)"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

echo "==> no floating point in deterministic core (ci job: gates)"
./scripts/check-no-float.sh

echo "==> deterministic-core dependency direction (ci job: gates)"
./scripts/check-core-deps.sh

echo "==> no unannotated unsafe in core (ci job: gates)"
./scripts/check-unsafe.sh

if [ "$FULL" -eq 1 ]; then
    # check-determinism.sh runs verify-state-roots.sh internally; running the
    # standalone step here would execute the state-root suite twice.
    echo "==> determinism suite, includes state-root agreement (ci jobs: determinism + state-roots)"
    ./scripts/check-determinism.sh
else
    echo "==> state-root agreement (ci job: state-roots)"
    ./scripts/verify-state-roots.sh
fi

echo
if [ "$FULL" -eq 1 ]; then
    echo "==> preflight (--full) passed"
else
    echo "==> preflight passed (run with --full before release/CI-affecting changes)"
fi
