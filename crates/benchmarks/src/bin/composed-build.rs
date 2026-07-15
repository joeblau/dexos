//! Build one structurally reconciled composed-run artifact from regional reports.

use std::path::PathBuf;
use std::process::ExitCode;

use benchmarks::composed_builder::sha256_hex;
use benchmarks::{
    build_composed_run, evaluate_run, load_manifest, render_raw_campaign, ComposedRunEvidence,
};
use loadgen::{ControlAuthenticator, DistributedPackedAgentReport};

#[derive(Debug, PartialEq, Eq)]
struct Args {
    manifest: PathBuf,
    agents: Vec<PathBuf>,
    control_key_file: PathBuf,
    evidence: PathBuf,
    raw_output: PathBuf,
    output: PathBuf,
}

fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut manifest = None;
    let mut agents = Vec::new();
    let mut control_key_file = None;
    let mut evidence = None;
    let mut raw_output = None;
    let mut output = None;
    let mut args = args.into_iter();
    let _program = args.next();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {flag}"))?;
        match flag.as_str() {
            "--manifest" => manifest = Some(PathBuf::from(value)),
            "--agent" => agents.push(PathBuf::from(value)),
            "--control-key-file" => control_key_file = Some(PathBuf::from(value)),
            "--evidence" => evidence = Some(PathBuf::from(value)),
            "--raw-output" => raw_output = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument '{flag}'")),
        }
    }
    if agents.is_empty() {
        return Err("at least one --agent is required".into());
    }
    Ok(Args {
        manifest: manifest.ok_or_else(|| "--manifest is required".to_string())?,
        agents,
        control_key_file: control_key_file
            .ok_or_else(|| "--control-key-file is required".to_string())?,
        evidence: evidence.ok_or_else(|| "--evidence is required".to_string())?,
        raw_output: raw_output.ok_or_else(|| "--raw-output is required".to_string())?,
        output: output.ok_or_else(|| "--output is required".to_string())?,
    })
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T, String> {
    let raw = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&raw).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn run(args: &Args) -> Result<bool, String> {
    let (manifest, manifest_sha256) = load_manifest(&args.manifest)?;
    let agents: Vec<DistributedPackedAgentReport> = args
        .agents
        .iter()
        .map(read_json)
        .collect::<Result<_, _>>()?;
    let evidence: ComposedRunEvidence = read_json(&args.evidence)?;
    let control_key = std::fs::read(&args.control_key_file)
        .map_err(|error| format!("read {}: {error}", args.control_key_file.display()))?;
    let authenticator =
        ControlAuthenticator::new(&control_key).map_err(|error| format!("control key: {error}"))?;
    let raw = render_raw_campaign(&agents, &evidence)?;
    let raw_sha256 = sha256_hex(&raw);
    let composed = build_composed_run(
        &manifest,
        &manifest_sha256,
        &agents,
        &authenticator,
        evidence,
        args.raw_output.display().to_string(),
        raw_sha256,
    )?;
    let output = serde_json::to_vec_pretty(&composed)
        .map_err(|error| format!("serialize composed run: {error}"))?;
    std::fs::write(&args.raw_output, raw)
        .map_err(|error| format!("write {}: {error}", args.raw_output.display()))?;
    std::fs::write(&args.output, output)
        .map_err(|error| format!("write {}: {error}", args.output.display()))?;

    let evaluation = evaluate_run(&manifest, &manifest_sha256, &composed);
    println!(
        "composed run {}: {} at {}/s; wrote {} and {}",
        evaluation.run_id,
        if evaluation.passed { "PASS" } else { "FAIL" },
        evaluation.effective_orders_per_second,
        args.raw_output.display(),
        args.output.display()
    );
    for violation in &evaluation.violations {
        eprintln!("{}: {violation}", evaluation.run_id);
    }
    Ok(evaluation.passed)
}

fn usage() -> &'static str {
    concat!(
        "composed-build --manifest <workload.toml> \\\n",
        "  --agent <london.json> --agent <new-york.json> --agent <tokyo.json> \\\n",
        "  --control-key-file <control.key> --evidence <operator-evidence.json> \\\n",
        "  --raw-output <raw.json> --output <run.json>"
    )
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("error: {error}\nusage: {}", usage());
            return ExitCode::FAILURE;
        }
    };
    match run(&args) {
        // A structurally valid artifact is useful even when it honestly misses
        // the throughput target. composed-gate owns the campaign exit status.
        Ok(_) => ExitCode::SUCCESS,
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
    fn parser_preserves_regional_report_order() {
        let args = parse_args(
            [
                "composed-build",
                "--manifest",
                "workload.toml",
                "--agent",
                "london.json",
                "--agent",
                "new-york.json",
                "--agent",
                "tokyo.json",
                "--control-key-file",
                "control.key",
                "--evidence",
                "evidence.json",
                "--raw-output",
                "raw.json",
                "--output",
                "run.json",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .expect("args");
        assert_eq!(
            args.agents,
            ["london.json", "new-york.json", "tokyo.json"]
                .into_iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn parser_rejects_missing_agents_and_unknown_flags() {
        assert!(parse_args(
            [
                "build",
                "--manifest",
                "m",
                "--control-key-file",
                "k",
                "--evidence",
                "e",
                "--raw-output",
                "r",
                "--output",
                "o",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .is_err());
        assert!(parse_args(["build", "--wat", "x"].into_iter().map(str::to_string)).is_err());
    }
}
