//! Validate three composed validator artifacts against the committed 20M contract.

use std::path::PathBuf;
use std::process::ExitCode;

use benchmarks::{evaluate_campaign, load_manifest, ComposedRun};

#[derive(Debug, PartialEq, Eq)]
struct Args {
    manifest: PathBuf,
    runs: Vec<PathBuf>,
    output: PathBuf,
}

fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut manifest = None;
    let mut runs = Vec::new();
    let mut output = None;
    let mut args = args.into_iter();
    let _program = args.next();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {flag}"))?;
        match flag.as_str() {
            "--manifest" => manifest = Some(PathBuf::from(value)),
            "--run" => runs.push(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument '{flag}'")),
        }
    }
    Ok(Args {
        manifest: manifest.ok_or_else(|| "--manifest is required".to_string())?,
        runs,
        output: output.ok_or_else(|| "--output is required".to_string())?,
    })
}

fn run(args: &Args) -> Result<bool, String> {
    let (manifest, manifest_hash) = load_manifest(&args.manifest)?;
    let mut runs = Vec::with_capacity(args.runs.len());
    for path in &args.runs {
        let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let run: ComposedRun =
            serde_json::from_slice(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
        runs.push(run);
    }
    let evaluation = evaluate_campaign(&manifest, &manifest_hash, &runs);
    let json = serde_json::to_vec_pretty(&evaluation)
        .map_err(|e| format!("serialize campaign evaluation: {e}"))?;
    std::fs::write(&args.output, json)
        .map_err(|e| format!("write {}: {e}", args.output.display()))?;
    println!(
        "composed 20M gate: {} ({} run artifact(s)); wrote {}",
        if evaluation.passed { "PASS" } else { "FAIL" },
        evaluation.runs.len(),
        args.output.display()
    );
    for violation in &evaluation.violations {
        eprintln!("gate: {violation}");
    }
    for result in &evaluation.runs {
        if !result.passed {
            for violation in &result.violations {
                eprintln!("{}: {violation}", result.run_id);
            }
        }
    }
    Ok(evaluation.passed)
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args()) {
        Ok(args) => args,
        Err(e) => {
            eprintln!(
                "error: {e}\nusage: composed-gate --manifest <workload.toml> \\\n                 --run <run-1.json> --run <run-2.json> --run <run-3.json> \\\n                 --output <evaluation.json>"
            );
            return ExitCode::FAILURE;
        }
    };
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_manifest_and_output_and_preserves_run_order() {
        let args = parse_args(
            [
                "composed-gate",
                "--manifest",
                "workload.toml",
                "--run",
                "one.json",
                "--run",
                "two.json",
                "--output",
                "gate.json",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        assert_eq!(args.manifest, PathBuf::from("workload.toml"));
        assert_eq!(
            args.runs,
            vec![PathBuf::from("one.json"), PathBuf::from("two.json")]
        );
        assert_eq!(args.output, PathBuf::from("gate.json"));
    }

    #[test]
    fn parser_rejects_unknown_or_incomplete_flags() {
        assert!(parse_args(["gate", "--wat", "x"].into_iter().map(str::to_string)).is_err());
        assert!(parse_args(["gate", "--manifest"].into_iter().map(str::to_string)).is_err());
    }
}
