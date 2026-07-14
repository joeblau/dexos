//! Interleaved scalar/SIMD qualification for the production Minimmit QC
//! signer-bitmap weight reduction.

use std::hint::black_box;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use benchmarks::{measure_allocations, percentile_permille};
use serde::Serialize;

const SCHEMA_VERSION: u32 = 1;
const REDUCTIONS_PER_SAMPLE: usize = 256;
const WEIGHTS: [u32; simd::QUORUM_WEIGHT_LANES] = [
    1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597,
];

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
    reductions_per_second: u64,
}

#[derive(Debug, Serialize)]
struct PairSample {
    scalar_ns: u64,
    simd_ns: u64,
    scalar_minus_simd_ns: i64,
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
    reductions_per_sample: usize,
    iterations: usize,
    warmup: usize,
    bootstrap_resamples: usize,
    scalar: SampleSummary,
    simd: SampleSummary,
    scalar_allocations: u64,
    scalar_bytes_allocated: u64,
    simd_allocations: u64,
    simd_bytes_allocated: u64,
    mean_scalar_minus_simd_ns: i64,
    median_scalar_minus_simd_ns: i64,
    bootstrap_mean_delta_low_ns: i64,
    bootstrap_mean_delta_high_ns: i64,
    speedup_basis_points: i64,
    statistically_significant_simd_win: bool,
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

fn bitmaps() -> [u16; REDUCTIONS_PER_SAMPLE] {
    let mut state = 0x0057_3051_ad0f_f5e7_u64;
    core::array::from_fn(|index| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // A production n=16 L certificate has at least 13 unit signers. Rotate
        // three absent lanes to exercise varying dense bitmap shapes.
        let a = index % 16;
        let b = usize::try_from(state >> 16).unwrap_or(0) % 16;
        let c = usize::try_from(state >> 32).unwrap_or(0) % 16;
        !(1u16 << a) & !(1u16 << b) & !(1u16 << c)
    })
}

fn reduce_scalar(bitmaps: &[u16; REDUCTIONS_PER_SAMPLE]) -> u64 {
    bitmaps.iter().fold(0u64, |checksum, bitmap| {
        checksum.wrapping_add(
            simd::selected_weight_scalar(black_box(*bitmap), black_box(&WEIGHTS), 16).unwrap_or(0),
        )
    })
}

fn reduce_simd(backend: simd::Backend, bitmaps: &[u16; REDUCTIONS_PER_SAMPLE]) -> u64 {
    bitmaps.iter().fold(0u64, |checksum, bitmap| {
        checksum.wrapping_add(
            simd::selected_weight(backend, black_box(*bitmap), black_box(&WEIGHTS), 16)
                .unwrap_or(0),
        )
    })
}

fn timed_scalar(bitmaps: &[u16; REDUCTIONS_PER_SAMPLE]) -> u64 {
    let start = Instant::now();
    black_box(reduce_scalar(bitmaps));
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn timed_simd(backend: simd::Backend, bitmaps: &[u16; REDUCTIONS_PER_SAMPLE]) -> u64 {
    let start = Instant::now();
    black_box(reduce_simd(backend, bitmaps));
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn summarize(samples: &[u64]) -> SampleSummary {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let total_ns = samples.iter().copied().fold(0u64, u64::saturating_add);
    let reductions =
        u128::try_from(samples.len().saturating_mul(REDUCTIONS_PER_SAMPLE)).unwrap_or(u128::MAX);
    SampleSummary {
        p50_ns: percentile_permille(&sorted, 500),
        p95_ns: percentile_permille(&sorted, 950),
        p99_ns: percentile_permille(&sorted, 990),
        total_ns,
        reductions_per_second: if total_ns == 0 {
            0
        } else {
            u64::try_from(reductions * 1_000_000_000 / u128::from(total_ns)).unwrap_or(u64::MAX)
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
    let mut state = 0x5730_b007_57a7_15c5u64;
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
    let bitmaps = bitmaps();
    if reduce_scalar(&bitmaps) != reduce_simd(backend, &bitmaps) {
        return Err("scalar and SIMD weight reductions diverged".into());
    }

    for iteration in 0..args.warmup {
        if iteration.is_multiple_of(2) {
            black_box(reduce_scalar(&bitmaps));
            black_box(reduce_simd(backend, &bitmaps));
        } else {
            black_box(reduce_simd(backend, &bitmaps));
            black_box(reduce_scalar(&bitmaps));
        }
    }

    let mut scalar_samples = Vec::with_capacity(args.iterations);
    let mut simd_samples = Vec::with_capacity(args.iterations);
    let mut deltas = Vec::with_capacity(args.iterations);
    let mut raw_pairs = Vec::with_capacity(args.iterations);
    for iteration in 0..args.iterations {
        let (scalar_ns, simd_ns) = if iteration.is_multiple_of(2) {
            (timed_scalar(&bitmaps), timed_simd(backend, &bitmaps))
        } else {
            let simd_ns = timed_simd(backend, &bitmaps);
            let scalar_ns = timed_scalar(&bitmaps);
            (scalar_ns, simd_ns)
        };
        let delta128 = i128::from(scalar_ns) - i128::from(simd_ns);
        let delta =
            i64::try_from(delta128).unwrap_or(if delta128 < 0 { i64::MIN } else { i64::MAX });
        scalar_samples.push(scalar_ns);
        simd_samples.push(simd_ns);
        deltas.push(delta);
        raw_pairs.push(PairSample {
            scalar_ns,
            simd_ns,
            scalar_minus_simd_ns: delta,
        });
    }

    let (scalar_allocations, scalar_bytes_allocated) = measure_allocations(|| {
        black_box(reduce_scalar(&bitmaps));
    });
    let (simd_allocations, simd_bytes_allocated) = measure_allocations(|| {
        black_box(reduce_simd(backend, &bitmaps));
    });
    let scalar = summarize(&scalar_samples);
    let simd = summarize(&simd_samples);
    let mut sorted_deltas = deltas.clone();
    sorted_deltas.sort_unstable();
    let mean128 = deltas.iter().map(|value| i128::from(*value)).sum::<i128>()
        / i128::try_from(deltas.len()).unwrap_or(1);
    let mean = i64::try_from(mean128).unwrap_or(if mean128 < 0 { i64::MIN } else { i64::MAX });
    let (low, high) = bootstrap_mean_ci(&deltas, args.bootstrap_resamples);
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
        fixture: "256 dense n=16 weighted Minimmit L-certificate bitmaps per sample; pure production QC weight reduction",
        reductions_per_sample: REDUCTIONS_PER_SAMPLE,
        iterations: args.iterations,
        warmup: args.warmup,
        bootstrap_resamples: args.bootstrap_resamples,
        scalar,
        simd,
        scalar_allocations,
        scalar_bytes_allocated,
        simd_allocations,
        simd_bytes_allocated,
        mean_scalar_minus_simd_ns: mean,
        median_scalar_minus_simd_ns: signed_percentile(&sorted_deltas, 500),
        bootstrap_mean_delta_low_ns: low,
        bootstrap_mean_delta_high_ns: high,
        speedup_basis_points,
        statistically_significant_simd_win: low > 0,
        raw_pairs,
    })
}

fn main() -> ExitCode {
    let command = std::env::args().collect::<Vec<_>>().join(" ");
    let args = match parse_args(std::env::args()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("error: {error}");
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
        "Minimmit weight paired benchmark: backend={} significant={} speedup={} bps; wrote {}",
        artifact.backend,
        artifact.statistically_significant_simd_win,
        artifact.speedup_basis_points,
        args.output.display(),
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_output_and_positive_counts() {
        assert!(parse_args(["minimmit-weight-paired".into()]).is_err());
        assert!(parse_args([
            "minimmit-weight-paired".into(),
            "--iterations".into(),
            "0".into(),
            "--output".into(),
            "out.json".into(),
        ])
        .is_err());
    }

    #[test]
    fn bitmap_fixture_and_bootstrap_are_deterministic() {
        let fixture = bitmaps();
        assert_eq!(
            reduce_scalar(&fixture),
            reduce_simd(simd::detect(), &fixture)
        );
        assert_eq!(bootstrap_mean_ci(&[11; 32], 128), (11, 11));
    }
}
