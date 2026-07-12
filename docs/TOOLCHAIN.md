# Toolchain policy

DexOS pins a **single** Rust toolchain for development, CI, and releases. There
is no multi-MSRV matrix and no claim of support for older compilers.

## Pin == `rust-version`

| Source | Value |
|--------|--------|
| [`rust-toolchain.toml`](../rust-toolchain.toml) | `channel = "1.92.0"` |
| Workspace [`Cargo.toml`](../Cargo.toml) `rust-version` | `"1.92"` |

These are intentionally the same channel. `rust-toolchain.toml` is the
authoritative install pin (what `rustup` / CI actually builds with);
`package.rust-version` is the Cargo metadata echo of that pin so crates.io /
dependents see the same floor.

**Policy:**

- Bump both together when upgrading.
- Do **not** maintain a CI matrix over older MSRV compilers. The project does
  not promise that `cargo +1.NN check` works for `NN < 92`.
- Clippy and rustfmt versions ride with the same toolchain channel
  (`components = ["rustfmt", "clippy"]` in `rust-toolchain.toml`).

## CI

Every PR runs on `ubuntu-latest` with the pinned toolchain (`--locked` builds
and tests). An optional **macOS portability** job
(`portability-macos` in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml))
runs only on:

- `workflow_dispatch` (manual), and
- the weekly `schedule` cron,

not on every pull request. It catches OS-level differences (file locking,
`/dev/urandom`, thread affinity assumptions) without doubling PR wall-clock.

## Local development

```sh
rustup show            # should report 1.92.0 from rust-toolchain.toml
cargo test --workspace --locked
```

If your host has a newer default toolchain, `rustup` still respects the
workspace `rust-toolchain.toml` when invoked from this repository.
