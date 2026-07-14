//! Interleaved scalar/SIMD qualification for the production match-plan summary.

use std::hint::black_box;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use benchmarks::{measure_allocations, percentile_permille};
use orderbook::{BookConfig, MatchingBackend, NewOrder, OrderBook};
use serde::Serialize;
use types::{AccountId, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

const SCHEMA_VERSION: u32 = 1;
const FIXTURE_FILLS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    iterations: usize,
    warmup: usize,
    bootstrap_resamples: usize,
    output: PathBuf,
}

#[derive(Debug, Serialize)]
struct SampleSummary {
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    total_ns: u64,
    ops_per_sec: u64,
}

#[derive(Debug, Serialize)]
struct AllocationEvidence {
    measured: bool,
    scalar_allocations: u64,
    scalar_bytes: u64,
    simd_allocations: u64,
    simd_bytes: u64,
}

#[derive(Debug, Serialize)]
struct PairSample {
    scalar_ns: u64,
    simd_ns: u64,
    scalar_minus_simd_ns: i64,
}

#[derive(Debug, Serialize)]
struct PairedEvidence {
    mean_scalar_minus_simd_ns: i64,
    median_scalar_minus_simd_ns: i64,
    bootstrap_confidence_permille: u32,
    bootstrap_mean_delta_low_ns: i64,
    bootstrap_mean_delta_high_ns: i64,
    simd_wins: u64,
    ties: u64,
    scalar_wins: u64,
    speedup_basis_points: i64,
    statistically_significant_simd_win: bool,
}

#[derive(Debug, Serialize)]
struct Artifact {
    schema_version: u32,
    artifact_type: &'static str,
    exact_binary_command: String,
    host_os: &'static str,
    host_arch: &'static str,
    backend: &'static str,
    fixture: &'static str,
    iterations: usize,
    warmup: usize,
    bootstrap_resamples: usize,
    scalar: SampleSummary,
    simd: SampleSummary,
    allocations: AllocationEvidence,
    paired: PairedEvidence,
    raw_pairs: Vec<PairSample>,
}

fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut iterations = 20_000usize;
    let mut warmup = 2_000usize;
    let mut bootstrap_resamples = 5_000usize;
    let mut output = None;
    let mut args = args.into_iter();
    let _program = args.next();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {flag}"))?;
        match flag.as_str() {
            "--iterations" => {
                iterations = value
                    .parse()
                    .map_err(|_| format!("invalid --iterations '{value}'"))?;
            }
            "--warmup" => {
                warmup = value
                    .parse()
                    .map_err(|_| format!("invalid --warmup '{value}'"))?;
            }
            "--bootstrap-resamples" => {
                bootstrap_resamples = value
                    .parse()
                    .map_err(|_| format!("invalid --bootstrap-resamples '{value}'"))?;
            }
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument '{flag}'")),
        }
    }
    if iterations == 0 || bootstrap_resamples == 0 {
        return Err("--iterations and --bootstrap-resamples must be positive".into());
    }
    Ok(Args {
        iterations,
        warmup,
        bootstrap_resamples,
        output: output.ok_or_else(|| "--output is required".to_string())?,
    })
}

fn fixture(backend: MatchingBackend) -> (OrderBook, NewOrder) {
    let mut book = OrderBook::new(BookConfig {
        matching_backend: backend,
        ..BookConfig::default()
    });
    for lane in 0..FIXTURE_FILLS {
        let lane_u64 = u64::try_from(lane).unwrap_or(0);
        let lane_i64 = i64::try_from(lane).unwrap_or(0);
        book.submit(NewOrder {
            order_id: OrderId::new(lane_u64 + 1),
            account: AccountId::new(u32::try_from(lane + 1).unwrap_or(0)),
            side: Side::Ask,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price::from_raw(1_000_001 + lane_i64),
            quantity: Quantity::from_raw(500_001 + lane_i64),
            client_id: lane_u64 + 1,
            reduce_only: false,
        })
        .expect("fixed benchmark maker is valid");
    }
    let taker = NewOrder {
        order_id: OrderId::new(10_000),
        account: AccountId::new(10_000),
        side: Side::Bid,
        order_type: OrderType::Market,
        tif: TimeInForce::Ioc,
        price: Price::from_raw(1_000_128),
        quantity: Quantity::from_raw(64_008_128),
        client_id: 10_000,
        reduce_only: false,
    };
    (book, taker)
}

fn timed_call(book: &OrderBook, taker: &NewOrder) -> u64 {
    let start = Instant::now();
    black_box(
        book.plan_match_summary(taker)
            .expect("qualification fixture must plan"),
    );
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn summarize(samples: &[u64]) -> SampleSummary {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let total_ns = samples.iter().copied().fold(0u64, u64::saturating_add);
    let count = u64::try_from(samples.len()).unwrap_or(u64::MAX);
    SampleSummary {
        p50_ns: percentile_permille(&sorted, 500),
        p95_ns: percentile_permille(&sorted, 950),
        p99_ns: percentile_permille(&sorted, 990),
        total_ns,
        ops_per_sec: if total_ns == 0 {
            0
        } else {
            u64::try_from(u128::from(count) * 1_000_000_000u128 / u128::from(total_ns))
                .unwrap_or(u64::MAX)
        },
    }
}

fn signed_percentile(sorted: &[i64], permille: u32) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len() as u128;
    let rank = (u128::from(permille) * n).div_ceil(1000).clamp(1, n);
    sorted[usize::try_from(rank - 1).unwrap_or(sorted.len() - 1)]
}

fn bootstrap_mean_ci(deltas: &[i64], resamples: usize) -> (i64, i64) {
    let mut state = 0x5720_b007_57a7_15c5u64;
    let mut means = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let mut sum = 0i128;
        for _ in 0..deltas.len() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let index = usize::try_from(state).unwrap_or(0) % deltas.len();
            sum += i128::from(deltas[index]);
        }
        let mean = sum / i128::try_from(deltas.len()).unwrap_or(1);
        means.push(i64::try_from(mean).unwrap_or(if mean < 0 { i64::MIN } else { i64::MAX }));
    }
    means.sort_unstable();
    (
        signed_percentile(&means, 25),
        signed_percentile(&means, 975),
    )
}

fn run(args: &Args, command: String) -> Result<Artifact, String> {
    let backend = simd::detect();
    if !backend.is_vectorized() {
        return Err("no vector backend is available on this host".into());
    }
    let (scalar_book, scalar_taker) = fixture(MatchingBackend::Scalar);
    let (simd_book, simd_taker) = fixture(backend);
    let scalar_answer = scalar_book
        .plan_match_summary(&scalar_taker)
        .map_err(|error| error.to_string())?;
    let simd_answer = simd_book
        .plan_match_summary(&simd_taker)
        .map_err(|error| error.to_string())?;
    if scalar_answer != simd_answer {
        return Err("scalar and SIMD fixtures produced different answers".into());
    }

    for iteration in 0..args.warmup {
        if iteration.is_multiple_of(2) {
            let _ = black_box(scalar_book.plan_match_summary(&scalar_taker));
            let _ = black_box(simd_book.plan_match_summary(&simd_taker));
        } else {
            let _ = black_box(simd_book.plan_match_summary(&simd_taker));
            let _ = black_box(scalar_book.plan_match_summary(&scalar_taker));
        }
    }

    let mut raw_pairs = Vec::with_capacity(args.iterations);
    let mut scalar_samples = Vec::with_capacity(args.iterations);
    let mut simd_samples = Vec::with_capacity(args.iterations);
    let mut deltas = Vec::with_capacity(args.iterations);
    for iteration in 0..args.iterations {
        let (scalar_ns, simd_ns) = if iteration.is_multiple_of(2) {
            (
                timed_call(&scalar_book, &scalar_taker),
                timed_call(&simd_book, &simd_taker),
            )
        } else {
            let simd_ns = timed_call(&simd_book, &simd_taker);
            let scalar_ns = timed_call(&scalar_book, &scalar_taker);
            (scalar_ns, simd_ns)
        };
        let delta = i128::from(scalar_ns) - i128::from(simd_ns);
        let delta = i64::try_from(delta).unwrap_or(if delta < 0 { i64::MIN } else { i64::MAX });
        scalar_samples.push(scalar_ns);
        simd_samples.push(simd_ns);
        deltas.push(delta);
        raw_pairs.push(PairSample {
            scalar_ns,
            simd_ns,
            scalar_minus_simd_ns: delta,
        });
    }

    let (scalar_allocations, scalar_bytes) = measure_allocations(|| {
        let _ = black_box(scalar_book.plan_match_summary(&scalar_taker));
    });
    let (simd_allocations, simd_bytes) = measure_allocations(|| {
        let _ = black_box(simd_book.plan_match_summary(&simd_taker));
    });
    let scalar = summarize(&scalar_samples);
    let simd = summarize(&simd_samples);
    let mut sorted_deltas = deltas.clone();
    sorted_deltas.sort_unstable();
    let mean_delta_i128 = deltas.iter().map(|value| i128::from(*value)).sum::<i128>()
        / i128::try_from(deltas.len()).unwrap_or(1);
    let mean_delta = i64::try_from(mean_delta_i128).unwrap_or(if mean_delta_i128 < 0 {
        i64::MIN
    } else {
        i64::MAX
    });
    let (ci_low, ci_high) = bootstrap_mean_ci(&deltas, args.bootstrap_resamples);
    let simd_wins =
        u64::try_from(deltas.iter().filter(|delta| **delta > 0).count()).unwrap_or(u64::MAX);
    let ties =
        u64::try_from(deltas.iter().filter(|delta| **delta == 0).count()).unwrap_or(u64::MAX);
    let scalar_wins =
        u64::try_from(deltas.iter().filter(|delta| **delta < 0).count()).unwrap_or(u64::MAX);
    let speedup_basis_points = if scalar.total_ns == 0 {
        0
    } else {
        let delta = i128::from(scalar.total_ns) - i128::from(simd.total_ns);
        i64::try_from(delta * 10_000 / i128::from(scalar.total_ns)).unwrap_or(if delta < 0 {
            i64::MIN
        } else {
            i64::MAX
        })
    };

    Ok(Artifact {
        schema_version: SCHEMA_VERSION,
        artifact_type: "paired-component-microbenchmark",
        exact_binary_command: command,
        host_os: std::env::consts::OS,
        host_arch: std::env::consts::ARCH,
        backend: backend.name(),
        fixture: "128 best-first maker fills; six-decimal price/quantity; exact rounding; no mutation/socket/journal",
        iterations: args.iterations,
        warmup: args.warmup,
        bootstrap_resamples: args.bootstrap_resamples,
        scalar,
        simd,
        allocations: AllocationEvidence {
            measured: cfg!(feature = "count-alloc"),
            scalar_allocations,
            scalar_bytes,
            simd_allocations,
            simd_bytes,
        },
        paired: PairedEvidence {
            mean_scalar_minus_simd_ns: mean_delta,
            median_scalar_minus_simd_ns: signed_percentile(&sorted_deltas, 500),
            bootstrap_confidence_permille: 950,
            bootstrap_mean_delta_low_ns: ci_low,
            bootstrap_mean_delta_high_ns: ci_high,
            simd_wins,
            ties,
            scalar_wins,
            speedup_basis_points,
            statistically_significant_simd_win: ci_low > 0,
        },
        raw_pairs,
    })
}

fn main() -> ExitCode {
    let command = std::env::args().collect::<Vec<_>>().join(" ");
    let args = match parse_args(std::env::args()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!(
                "error: {error}\nusage: matching-paired --iterations <n> --warmup <n> \\\n+                 --bootstrap-resamples <n> --output <artifact.json>"
            );
            return ExitCode::FAILURE;
        }
    };
    let artifact = match run(&args, command) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let json = match serde_json::to_vec_pretty(&artifact) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("error: serialize artifact: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = std::fs::write(&args.output, json) {
        eprintln!("error: write {}: {error}", args.output.display());
        return ExitCode::FAILURE;
    }
    println!(
        "matching paired benchmark: backend={} significant={} speedup={} bps; wrote {}",
        artifact.backend,
        artifact.paired.statistically_significant_simd_win,
        artifact.paired.speedup_basis_points,
        args.output.display(),
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_output_and_positive_counts() {
        assert!(parse_args(["matching-paired".into()]).is_err());
        assert!(parse_args([
            "matching-paired".into(),
            "--iterations".into(),
            "0".into(),
            "--output".into(),
            "out.json".into(),
        ])
        .is_err());
    }

    #[test]
    fn bootstrap_interval_is_positive_for_uniform_wins() {
        let (low, high) = bootstrap_mean_ci(&[7; 32], 128);
        assert_eq!((low, high), (7, 7));
    }
}
