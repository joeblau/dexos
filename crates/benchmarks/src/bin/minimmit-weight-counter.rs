//! Long-running single-path driver for external hardware-counter collection.
//!
//! Timing and paired significance belong to `minimmit-weight-paired`; this
//! binary keeps one implementation active long enough for `perf`/Instruments
//! to attribute cycles, instructions, branches, and cache behavior without
//! mixing scalar and SIMD samples in one process.

use std::hint::black_box;
use std::process::ExitCode;

const WEIGHTS: [u32; simd::QUORUM_WEIGHT_LANES] = [
    1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Scalar,
    Simd,
}

fn parse_args<I>(args: I) -> Result<(Mode, u64), String>
where
    I: IntoIterator<Item = String>,
{
    let mut mode = None;
    let mut iterations = None;
    let mut args = args.into_iter();
    let _program = args.next();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {flag}"))?;
        match flag.as_str() {
            "--mode" => {
                mode = Some(match value.as_str() {
                    "scalar" => Mode::Scalar,
                    "simd" => Mode::Simd,
                    _ => return Err(format!("invalid --mode '{value}'")),
                });
            }
            "--iterations" => {
                iterations = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --iterations '{value}'"))?,
                );
            }
            _ => return Err(format!("unknown argument '{flag}'")),
        }
    }
    let mode = mode.ok_or_else(|| "--mode is required".to_string())?;
    let iterations = iterations.ok_or_else(|| "--iterations is required".to_string())?;
    if iterations == 0 {
        return Err("--iterations must be positive".into());
    }
    Ok((mode, iterations))
}

fn run(mode: Mode, iterations: u64) -> Result<(u64, &'static str), String> {
    let backend = simd::detect();
    if mode == Mode::Simd && !backend.is_vectorized() {
        return Err("no vector backend is available on this host".into());
    }
    let mut checksum = 0u64;
    for iteration in 0..iterations {
        let lane = u32::try_from(iteration & 15).unwrap_or(0);
        let bitmap = !(1u16 << lane);
        let weight = match mode {
            Mode::Scalar => simd::selected_weight_scalar(bitmap, black_box(&WEIGHTS), 16),
            Mode::Simd => simd::selected_weight(backend, bitmap, black_box(&WEIGHTS), 16),
        }
        .ok_or_else(|| "valid counter fixture was rejected".to_string())?;
        checksum = checksum.wrapping_add(black_box(weight));
    }
    Ok((checksum, backend.name()))
}

fn main() -> ExitCode {
    let (mode, iterations) = match parse_args(std::env::args()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    match run(mode, iterations) {
        Ok((checksum, backend)) => {
            println!("mode={mode:?} backend={backend} iterations={iterations} checksum={checksum}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_and_paths_are_checked_and_identical() {
        assert!(parse_args(["counter".into()]).is_err());
        let scalar = run(Mode::Scalar, 1024).unwrap();
        if simd::detect().is_vectorized() {
            let vector = run(Mode::Simd, 1024).unwrap();
            assert_eq!(scalar.0, vector.0);
        } else {
            assert!(run(Mode::Simd, 1024).is_err());
        }
    }
}
