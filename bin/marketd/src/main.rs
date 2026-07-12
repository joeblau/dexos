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
    /// Run reproducible benchmarks and emit a machine-readable report (dev-tools only).
    #[cfg(feature = "dev-tools")]
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
#[cfg(feature = "dev-tools")]
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
    /// Durable WAL directory (`seg-*.log` files).
    #[arg(long, value_name = "PATH")]
    log: PathBuf,
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
/// then CLI overrides, then validation. Duplicate `--role` flags fail closed.
fn resolve_config(args: &RunArgs) -> anyhow::Result<NodeConfig> {
    let base = match &args.config {
        Some(path) => NodeConfig::load(path)?,
        None => NodeConfig::default(),
    };
    let roles: Vec<Role> = args.roles.iter().map(|r| Role::from(*r)).collect();
    // Surface duplicate CLI roles with the same message the TOML path uses.
    let mut seen = Vec::new();
    for role in &roles {
        if seen.contains(role) {
            anyhow::bail!(
                "duplicate node role '{}'; each role may appear at most once",
                role.as_str()
            );
        }
        seen.push(*role);
    }
    let overrides = ConfigOverrides {
        light: args.light,
        roles,
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
        #[cfg(feature = "dev-tools")]
        Command::Benchmark(a) => run_benchmark(&a, benchmarks::Config::default()),
        Command::Replay(a) => run_replay(&a),
        Command::Inspect(a) => run_inspect(&a),
        Command::Keygen(a) => {
            let mut seed = [0u8; 32];
            fill_entropy(&mut seed)?;
            let keypair = crypto::KeyPair::from_seed(&seed);
            let public_hex = to_hex(&keypair.public());
            let seed_hex = to_hex(&seed);
            match &a.output {
                Some(path) => {
                    write_secret_file(path, &seed_hex)
                        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
                    println!("public_key: {public_hex}");
                    println!("wrote private seed to {} (owner-only)", path.display());
                }
                None => {
                    // The seed is never silently discarded: with no --output we
                    // print it to stdout and warn on stderr that it is secret.
                    println!("public_key: {public_hex}");
                    println!("private_seed: {seed_hex}");
                    eprintln!(
                        "warning: private seed printed to stdout — keep it secret. \
                         Re-run with --output <PATH> to write it to an owner-only file instead."
                    );
                }
            }
            Ok(())
        }
        Command::Snapshot(_a) => {
            // Fail closed: engine serialize/restore is not wired into marketd yet.
            // Operators must not believe a stub snapshot is crash-recovery safe.
            anyhow::bail!(
                "snapshot: fail-closed — engine state serialization is not implemented; \
                 refuse to emit a non-authoritative snapshot (see storage::Snapshot for the on-disk format)"
            );
        }
        Command::Verify(a) => run_verify(&a),
    }
}

/// Load a snapshot + durable WAL, verify integrity, and count applied records.
fn run_replay(args: &ReplayArgs) -> anyhow::Result<()> {
    let snap = storage::Snapshot::load(&args.snapshot)
        .map_err(|e| anyhow::anyhow!("loading snapshot {}: {e}", args.snapshot.display()))?;
    if !snap.verify(snap.state_root()) {
        anyhow::bail!(
            "snapshot {} failed self-verify (content digest / version)",
            args.snapshot.display()
        );
    }

    let log = storage::DurableLog::open(
        storage::DurableConfig::new(&args.log).with_sync(storage::SyncPolicy::Never),
    )
    .map_err(|e| anyhow::anyhow!("opening durable log {}: {e}", args.log.display()))?;
    log.verify()
        .map_err(|e| anyhow::anyhow!("log integrity verify failed: {e}"))?;

    let mut applied = 0u64;
    let last = log
        .replay(Some(snap.last_sequence()), |_| {
            applied = applied.saturating_add(1);
        })
        .map_err(|e| anyhow::anyhow!("replay failed: {e}"))?;

    println!(
        "replay: snapshot_seq={} state_root={} applied={} last_seq={} log_records={}",
        snap.last_sequence(),
        to_hex(snap.state_root().as_bytes()),
        applied,
        last,
        log.len()
    );
    Ok(())
}

/// Decode and self-verify a snapshot file (content digest + CRC).
fn run_verify(args: &VerifyArgs) -> anyhow::Result<()> {
    let snap = storage::Snapshot::load(&args.snapshot)
        .map_err(|e| anyhow::anyhow!("loading snapshot {}: {e}", args.snapshot.display()))?;
    if !snap.verify(snap.state_root()) {
        anyhow::bail!("snapshot self-verify failed");
    }
    println!(
        "verify: ok snapshot_seq={} state_root={} state_bytes={}",
        snap.last_sequence(),
        to_hex(snap.state_root().as_bytes()),
        snap.state().len()
    );
    Ok(())
}

/// Inspect a single sequence from a durable WAL directory.
fn run_inspect(args: &InspectArgs) -> anyhow::Result<()> {
    let log = storage::DurableLog::open(
        storage::DurableConfig::new(&args.log).with_sync(storage::SyncPolicy::Never),
    )
    .map_err(|e| anyhow::anyhow!("opening durable log {}: {e}", args.log.display()))?;
    let rec = log
        .find(args.sequence)
        .map_err(|e| anyhow::anyhow!("inspect sequence {}: {e}", args.sequence))?;
    println!(
        "inspect: sequence={} timestamp={} command_type={} payload_len={}",
        rec.sequence,
        rec.timestamp,
        rec.command_type,
        rec.payload.len()
    );
    Ok(())
}

/// The reserved suite selector that runs every registered suite and enforces the
/// spec-target gate.
#[cfg(feature = "dev-tools")]
const SUITE_ALL: &str = "all";

/// Run the benchmark subcommand: honour `--suite` and `--config`, and exit nonzero
/// when the suite selector is invalid or the spec-target gate fails.
///
/// Suite selection genuinely changes what runs: `all` runs every suite (and gates on
/// the spec targets), a specific name runs exactly that suite, and an unknown name is
/// rejected rather than silently falling back to a full pass.
#[cfg(feature = "dev-tools")]
fn run_benchmark(args: &BenchmarkArgs, config: benchmarks::Config) -> anyhow::Result<()> {
    // `--config` is no longer ignored: an invalid benchmarked-node config aborts the
    // run (nonzero) instead of being silently discarded.
    if let Some(path) = &args.config {
        let _validated = NodeConfig::load(path)
            .map_err(|e| anyhow::anyhow!("invalid --config {}: {e}", path.display()))?;
        println!("benchmarked-node config: {} (validated)", path.display());
    }

    let gated = args.suite == SUITE_ALL;
    let report = if gated {
        benchmarks::run_all_with(config)
    } else {
        benchmarks::run_suite(&args.suite, config).ok_or_else(|| {
            let known: Vec<&str> = std::iter::once(SUITE_ALL)
                .chain(benchmarks::registry().iter().map(|s| s.name))
                .collect();
            anyhow::anyhow!(
                "unknown benchmark suite '{}'; known suites: {}",
                args.suite,
                known.join(", ")
            )
        })?
    };

    let json = benchmarks::render_json(&report);
    std::fs::write(&args.output, &json)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", args.output.display()))?;
    println!("{}", benchmarks::render_markdown(&report));
    println!(
        "suite='{}' — ran {} suite(s), wrote machine-readable results to {}",
        args.suite,
        report.stats.len(),
        args.output.display()
    );

    // Only the full run carries every gated suite; a single-suite run is a targeted
    // micro-measurement and is not held to the whole-system gate (whose other suites
    // would be reported missing).
    if gated && !report.all_targets_passed {
        anyhow::bail!("spec-target gate FAILED — see the report above");
    }
    Ok(())
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

/// Fill `buf` with cryptographically secure random bytes from the OS CSPRNG.
///
/// Uses `getrandom`, which reads the platform secure RNG (`getrandom(2)` /
/// `getentropy` on Linux, `SecRandomCopyBytes`/`arc4random` on macOS, etc.), so
/// it is portable and does not assume a `/dev/urandom` device node. If the OS
/// CSPRNG is unavailable we fail hard — there is no time-seeded LCG fallback,
/// which would produce a predictable and therefore forgeable private key.
fn fill_entropy(buf: &mut [u8]) -> anyhow::Result<()> {
    getrandom::getrandom(buf)
        .map_err(|e| anyhow::anyhow!("OS CSPRNG unavailable; refusing to generate a weak key: {e}"))
}

/// Write `contents` to `path`, restricting the file to owner read/write (`0600`)
/// on Unix so a private seed is never left group- or world-readable. On non-Unix
/// platforms the file is created with the default permissions.
fn write_secret_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    // Narrow permissions explicitly as well, so an already-existing file that was
    // created with wider bits is tightened rather than left as-is.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(contents.as_bytes())?;
    f.flush()?;
    Ok(())
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
    fn parses_all_enabled_modes() {
        let cases: Vec<&[&str]> = vec![
            &["marketd", "run"],
            &["marketd", "run", "--light"],
            &[
                "marketd",
                "replay",
                "--snapshot",
                "s.snap",
                "--log",
                "c.log",
            ],
            &["marketd", "verify", "--snapshot", "s.snap"],
            &["marketd", "inspect", "--sequence", "42", "--log", "/tmp/wal"],
            &["marketd", "keygen"],
            &["marketd", "snapshot"],
        ];
        for args in cases {
            assert!(Cli::try_parse_from(args).is_ok(), "should parse: {args:?}");
        }
    }

    #[test]
    fn inspect_requires_log_path() {
        assert!(Cli::try_parse_from(["marketd", "inspect", "--sequence", "1"]).is_err());
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn benchmark_mode_parses_with_dev_tools() {
        assert!(Cli::try_parse_from([
            "marketd",
            "benchmark",
            "--suite",
            "all",
            "--output",
            "results.json",
        ])
        .is_ok());
    }

    #[test]
    fn duplicate_role_flags_are_rejected() {
        let cli = Cli::try_parse_from([
            "marketd",
            "run",
            "--role",
            "gateway",
            "--role",
            "gateway",
        ])
        .unwrap();
        let Command::Run(args) = cli.command else {
            panic!("expected run");
        };
        let err = resolve_config(&args).expect_err("duplicate roles must fail");
        assert!(
            format!("{err:#}").contains("duplicate"),
            "error should name the problem: {err:#}"
        );
    }

    #[test]
    fn snapshot_command_fails_closed() {
        // Snapshot remains fail-closed until engine serialize lands (#296).
        let cli = Cli::try_parse_from(["marketd", "snapshot"]).unwrap();
        let err = dispatch(cli).expect_err("snapshot must fail closed");
        assert!(format!("{err:#}").contains("fail-closed"), "{err:#}");
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

    #[test]
    fn fill_entropy_yields_distinct_nonzero_seeds() {
        // On any supported platform the OS CSPRNG is available, so `fill_entropy`
        // succeeds and produces fresh, non-degenerate bytes each call. This
        // proves the LCG/time fallback is gone: two draws differ overwhelmingly.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_entropy(&mut a).expect("OS CSPRNG must be available");
        fill_entropy(&mut b).expect("OS CSPRNG must be available");
        assert_ne!(a, [0u8; 32], "seed was all zero");
        assert_ne!(a, b, "two CSPRNG seeds collided");
    }

    #[test]
    fn keygen_public_key_is_deterministic_from_seed() {
        // The public key is a pure function of the seed, so a written seed can
        // always be reloaded to recover the identity — the seed is never lost.
        let seed = [7u8; 32];
        let a = to_hex(&crypto::KeyPair::from_seed(&seed).public());
        let b = to_hex(&crypto::KeyPair::from_seed(&seed).public());
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "32-byte public key hex-encodes to 64 chars");
    }

    #[test]
    fn write_secret_file_round_trips_contents() {
        let path = unique_temp_path("roundtrip");
        write_secret_file(&path, "deadbeef").expect("write should succeed");
        let read_back = std::fs::read_to_string(&path).expect("read should succeed");
        assert_eq!(read_back, "deadbeef");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_temp_path("mode");
        // Pre-create a world-readable file to prove we tighten, not just create.
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_secret_file(&path, "secret-seed").expect("write should succeed");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "seed file must be owner read/write only"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A small benchmark config so suite-selection tests run fast.
    #[cfg(feature = "dev-tools")]
    fn tiny_bench() -> benchmarks::Config {
        benchmarks::Config {
            iterations: 16,
            warmup: 2,
        }
    }

    #[cfg(feature = "dev-tools")]
    fn bench_args(suite: &str, output: PathBuf, config: Option<PathBuf>) -> BenchmarkArgs {
        BenchmarkArgs {
            suite: suite.to_string(),
            output,
            config,
        }
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn unknown_benchmark_suite_is_rejected() {
        let out = unique_temp_path("bench-unknown");
        let err = run_benchmark(
            &bench_args("does-not-exist", out.clone(), None),
            tiny_bench(),
        )
        .expect_err("unknown suite must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown benchmark suite"), "{msg}");
        // A rejected selection must not fabricate a results file.
        assert!(
            !out.exists(),
            "no output should be written for a bad selection"
        );
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn single_suite_selection_runs_exactly_that_suite() {
        let out = unique_temp_path("bench-single");
        run_benchmark(&bench_args("risk-check", out.clone(), None), tiny_bench())
            .expect("valid single suite runs");
        let json = std::fs::read_to_string(&out).expect("results written");
        let report = benchmarks::Report::from_json(&json).expect("valid results json");
        assert_eq!(report.stats.len(), 1, "only the selected suite ran");
        assert_eq!(report.stats[0].name, "risk-check");
        let _ = std::fs::remove_file(&out);
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn all_selection_runs_the_full_suite_set() {
        let out = unique_temp_path("bench-all");
        // The whole-system gate may pass or fail on arbitrary CI hardware, so we do
        // not assert on the Result — only that `all` actually ran every suite.
        let _ = run_benchmark(&bench_args("all", out.clone(), None), tiny_bench());
        let json = std::fs::read_to_string(&out).expect("results written");
        let report = benchmarks::Report::from_json(&json).expect("valid results json");
        assert_eq!(
            report.stats.len(),
            benchmarks::registry().len(),
            "all suites ran"
        );
        let _ = std::fs::remove_file(&out);
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn invalid_config_aborts_the_benchmark() {
        let out = unique_temp_path("bench-cfg");
        let cfg = unique_temp_path("bench-badcfg");
        std::fs::write(&cfg, "this is = not [valid toml").unwrap();
        let err = run_benchmark(
            &bench_args("risk-check", out.clone(), Some(cfg.clone())),
            tiny_bench(),
        )
        .expect_err("invalid config must abort");
        assert!(format!("{err:#}").contains("invalid --config"));
        let _ = std::fs::remove_file(&cfg);
        let _ = std::fs::remove_file(&out);
    }

    /// A unique, per-invocation temp path so parallel tests never collide.
    #[cfg(test)]
    fn unique_temp_path(tag: &str) -> std::path::PathBuf {
        let mut salt = [0u8; 8];
        fill_entropy(&mut salt).expect("OS CSPRNG must be available");
        std::env::temp_dir().join(format!(
            "marketd-keygen-{tag}-{}-{}.seed",
            std::process::id(),
            to_hex(&salt)
        ))
    }
}
