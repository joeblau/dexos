# Performance profiling

Install `cargo-flamegraph` and platform prerequisites, then run:

```sh
./scripts/flamegraph.sh
```

The script uses `release-with-debug`: production optimization, thin LTO, one
codegen unit, and debug symbols. Set `FLAMEGRAPH_OUTPUT=path.svg` to select the
output. Linux hardware counters can be collected with:

```sh
perf stat -d target/release-with-debug/marketd benchmark --suite all --output /tmp/report.json
```

## Example report

Record commit, compiler, CPU model/governor, command, sample duration, and input
configuration. Attach the SVG rather than committing generated profiles.

```text
commit: <sha>  rustc: 1.92.0  cpu: <model>; governor: performance
command: ./scripts/flamegraph.sh
finding: <symbol> accounted for <percent>% of on-CPU samples
action: <change or no-action rationale>
```

Flamegraphs are diagnostic evidence, not benchmark results. Use the benchmark
JSON and repeated isolated runs for latency/throughput claims.
