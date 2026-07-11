//! `marketd` — the DexOS network node binary.
//!
//! Exposes the eight operator modes from the spec. Argument parsing is total: bad
//! input yields a nonzero exit via clap, never a panic. `run` builds a
//! [`node::NodeConfig`] (file values overridden by CLI flags) and hands off to the
//! `node` composition root, which owns the async runtime.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use node::{ConfigOverrides, NodeConfig, Role};

#[derive(Parser, Debug)]
#[command(
    name = "marketd",
    version,
    about = "DexOS — decentralized market operating system node",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a full network node (add --light for a read-only light node).
    Run(RunArgs),
    /// Run reproducible benchmarks and emit a machine-readable report.
    Benchmark(BenchmarkArgs),
    /// Deterministically replay a command log against a snapshot.
    Replay(ReplayArgs),
    /// Inspect a single sequence in the command log.
    Inspect(InspectArgs),
    /// Generate a node identity keypair.
    Keygen(KeygenArgs),
    /// Produce a verified state snapshot.
    Snapshot(SnapshotArgs),
    /// Verify a snapshot's state root and checkpoint ancestry.
    Verify(VerifyArgs),
}

/// A role selectable on the command line (mirrors [`node::Role`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum RoleArg {
    Validator,
    Sequencer,
    Witness,
    Gateway,
    Oracle,
    Custody,
    Observer,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::Validator => Role::Validator,
            RoleArg::Sequencer => Role::Sequencer,
            RoleArg::Witness => Role::Witness,
            RoleArg::Gateway => Role::Gateway,
            RoleArg::Oracle => Role::Oracle,
            RoleArg::Custody => Role::Custody,
            RoleArg::Observer => Role::Observer,
        }
    }
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Path to a TOML configuration file.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Run as a read-only light node (no consensus, execution, or order entry).
    #[arg(long)]
    light: bool,
    /// Role to assume; repeatable. Overrides roles from the config file.
    #[arg(long = "role", value_name = "ROLE")]
    roles: Vec<RoleArg>,
}

#[derive(Args, Debug)]
struct BenchmarkArgs {
    /// Benchmark suite to run (e.g. `all`, `orderbook`).
    #[arg(long, default_value = "all")]
    suite: String,
    /// Machine-readable results output path.
    #[arg(long, default_value = "results.json")]
    output: PathBuf,
    /// Optional configuration for the benchmarked node.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ReplayArgs {
    /// Snapshot to start replay from.
    #[arg(long, value_name = "PATH")]
    snapshot: PathBuf,
    /// Command log to replay.
    #[arg(long, value_name = "PATH")]
    log: PathBuf,
}

#[derive(Args, Debug)]
struct InspectArgs {
    /// Sequence number to inspect (unsigned, never truncated).
    #[arg(long)]
    sequence: u64,
}

#[derive(Args, Debug)]
struct KeygenArgs {
    /// Where to write the generated keypair (stdout if omitted).
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct SnapshotArgs {
    /// Configuration selecting the data directory to snapshot.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Where to write the snapshot.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Snapshot to verify.
    #[arg(long, value_name = "PATH")]
    snapshot: PathBuf,
}

/// Resolve the effective configuration for a `run` invocation: file values first,
/// then CLI overrides, then validation.
fn resolve_config(args: &RunArgs) -> anyhow::Result<NodeConfig> {
    let base = match &args.config {
        Some(path) => NodeConfig::load(path)?,
        None => NodeConfig::default(),
    };
    let overrides = ConfigOverrides {
        light: args.light,
        roles: args.roles.iter().map(|r| Role::from(*r)).collect(),
    };
    Ok(base.with_overrides(&overrides)?)
}

fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Run(args) => {
            let config = resolve_config(&args)?;
            let report = node::Node::run_blocking(config)?;
            println!(
                "node stopped cleanly: {} subsystem(s), {} command(s) drained",
                report.handlers, report.processed
            );
            Ok(())
        }
        Command::Benchmark(a) => {
            let report = benchmarks::run_all();
            let json = benchmarks::render_json(&report);
            std::fs::write(&a.output, &json)
                .map_err(|e| anyhow::anyhow!("writing {}: {e}", a.output.display()))?;
            println!("{}", benchmarks::render_markdown(&report));
            println!(
                "suite='{}' — wrote machine-readable results to {}",
                a.suite,
                a.output.display()
            );
            Ok(())
        }
        Command::Replay(a) => {
            println!(
                "replay: snapshot='{}' log='{}' [Phase 0 stub — deterministic replay lands in the storage epic]",
                a.snapshot.display(),
                a.log.display()
            );
            Ok(())
        }
        Command::Inspect(a) => {
            println!(
                "inspect: sequence={} [Phase 0 stub — command-log inspection lands in the storage epic]",
                a.sequence
            );
            Ok(())
        }
        Command::Keygen(a) => {
            let mut seed = [0u8; 32];
            read_entropy(&mut seed);
            let keypair = crypto::KeyPair::from_seed(&seed);
            let public_hex = to_hex(&keypair.public());
            match &a.output {
                Some(path) => {
                    std::fs::write(path, to_hex(&seed))
                        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
                    println!("public_key: {public_hex}");
                    println!("wrote private seed to {}", path.display());
                }
                None => println!("public_key: {public_hex}"),
            }
            Ok(())
        }
        Command::Snapshot(a) => {
            println!(
                "snapshot: output={} [Phase 0 stub — snapshots land in the storage epic]",
                a.output
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<default>".to_string())
            );
            Ok(())
        }
        Command::Verify(a) => {
            println!(
                "verify: snapshot='{}' [Phase 0 stub — state-root verification lands in the state-tree epic]",
                a.snapshot.display()
            );
            Ok(())
        }
    }
}

/// Lowercase hex encoding (no external dep).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Fill `buf` with entropy from the OS CSPRNG, falling back to a time-seeded
/// mixer only if `/dev/urandom` is unavailable.
fn read_entropy(buf: &mut [u8; 32]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(buf).is_ok() {
            return;
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut state = u64::try_from(nanos % u128::from(u64::MAX))
        .unwrap_or(1)
        .max(1);
    for chunk in buf.chunks_mut(8) {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_all_eight_modes() {
        let cases: &[&[&str]] = &[
            &["marketd", "run"],
            &["marketd", "run", "--light"],
            &[
                "marketd",
                "benchmark",
                "--suite",
                "all",
                "--output",
                "results.json",
            ],
            &[
                "marketd",
                "replay",
                "--snapshot",
                "s.snap",
                "--log",
                "c.log",
            ],
            &["marketd", "verify", "--snapshot", "s.snap"],
            &["marketd", "inspect", "--sequence", "42"],
            &["marketd", "keygen"],
            &["marketd", "snapshot"],
        ];
        for args in cases {
            assert!(Cli::try_parse_from(*args).is_ok(), "should parse: {args:?}");
        }
    }

    #[test]
    fn repeated_role_flags_accumulate() {
        let cli = Cli::try_parse_from([
            "marketd",
            "run",
            "--role",
            "validator",
            "--role",
            "sequencer",
        ])
        .unwrap();
        let Command::Run(args) = cli.command else {
            panic!("expected run");
        };
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.node.roles, vec![Role::Validator, Role::Sequencer]);
    }

    #[test]
    fn light_flag_sets_light_mode() {
        let cli = Cli::try_parse_from(["marketd", "run", "--light", "--role", "gateway"]).unwrap();
        let Command::Run(args) = cli.command else {
            panic!("expected run");
        };
        let cfg = resolve_config(&args).unwrap();
        assert!(cfg.node.light);
    }

    #[test]
    fn malformed_arguments_are_rejected_without_panic() {
        // Non-numeric sequence.
        assert!(Cli::try_parse_from(["marketd", "inspect", "--sequence", "abc"]).is_err());
        // Unknown role.
        assert!(Cli::try_parse_from(["marketd", "run", "--role", "banana"]).is_err());
        // Missing required path.
        assert!(Cli::try_parse_from(["marketd", "replay", "--snapshot", "s"]).is_err());
        // Negative sequence (u64).
        assert!(Cli::try_parse_from(["marketd", "inspect", "--sequence", "-1"]).is_err());
    }

    #[test]
    fn light_plus_validator_is_rejected_at_config_resolution() {
        let cli =
            Cli::try_parse_from(["marketd", "run", "--light", "--role", "validator"]).unwrap();
        let Command::Run(args) = cli.command else {
            panic!("expected run");
        };
        assert!(resolve_config(&args).is_err());
    }
}
