# Contributing

Use stable Rust 1.92 or the version in `rust-toolchain.toml`. Keep deterministic
core crates free of I/O, async runtimes, floating point, and nondeterminism.
Never weaken a safety gate to make a change pass.

Before opening a pull request, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked --bin marketd --no-default-features
cargo build --release --locked --bin marketd --all-features
./scripts/check-no-float.sh
./scripts/check-core-deps.sh
./scripts/check-unsafe.sh
./scripts/check-workflows.sh
cargo deny check advisories bans licenses sources
```

PRs must describe safety and compatibility impact, tests, migration/rollback
requirements, and benchmark methodology for performance claims. Update
`CHANGELOG.md` for user-visible behavior. Security reports follow
`docs/SECURITY.md`; do not publish vulnerabilities in issues.
