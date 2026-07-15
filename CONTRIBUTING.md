# Contributing

Use stable Rust 1.92 or the version in `rust-toolchain.toml`. Keep deterministic
core crates free of I/O, async runtimes, floating point, and nondeterminism.
Never weaken a safety gate to make a change pass.

Before opening a pull request, run the preflight script. It executes the
PR-blocking gates from `.github/workflows/ci.yml` in CI order, with
`RUSTFLAGS="-D warnings"` exported to match CI:

```sh
./scripts/preflight.sh
```

This covers rustfmt, clippy, the workspace test suite, the docs build
(`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`), the
deterministic-core guard scripts (`check-no-float.sh`, `check-core-deps.sh`,
`check-unsafe.sh`), and the state-root agreement suite
(`verify-state-roots.sh`). The docs, determinism, and state-root gates were
previously missing from this checklist even though CI enforces them; they are
now covered.

Before a release, or any change that can affect determinism, replay, wire
formats, or CI itself, run the full path — it additionally runs the
determinism suite (`check-determinism.sh`, which itself includes the
state-root agreement check, so preflight skips the standalone step):

```sh
./scripts/preflight.sh --full
```

CI also enforces gates that need CI-specific tooling or multiple
architectures and are not part of preflight: coverage (`cargo llvm-cov`), the
multi-arch determinism digest compare, cross-arch snapshot transfer, the
fuzz/property job (including the checked-in packed-order libFuzzer target build), release builds
(`cargo build --release --locked --bin marketd --no-default-features` and
`--all-features`) plus release-artifact scaffolding, workflow pinning
(`./scripts/check-workflows.sh`), and
`cargo deny check advisories bans licenses sources`. Run the relevant ones
directly when your change touches those areas.

PRs must describe safety and compatibility impact, tests, migration/rollback
requirements, and benchmark methodology for performance claims. Update
`CHANGELOG.md` for user-visible behavior. Security reports follow
`docs/SECURITY.md`; do not publish vulnerabilities in issues.
