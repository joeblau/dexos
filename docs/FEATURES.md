# Build feature matrix

`marketd` has no default features. The supported production build is:

```sh
cargo build --release --locked --bin marketd --no-default-features
```

| Feature | Default | Purpose | Production policy |
|---|---:|---|---|
| `dev-tools` | no | benchmark command and load-generator linkage | forbidden |
| `mock-chains` | no | in-memory EVM/SVM adapters | forbidden |
| `metrics-http` | no | reserved HTTP metrics surface | enable only when implemented/reviewed |
| `simd` | no | reserved accelerated kernels | enable only after target validation |

For local development, `cargo build --bin marketd --all-features` verifies the
complete feature graph. The standalone `market-loadgen` binary remains a
separate workspace artifact and is never linked into default `marketd`.
