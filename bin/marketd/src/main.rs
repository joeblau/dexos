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
    /// Verify a snapshot's integrity (frame CRC, version, content digest,
    /// state-length bounds), and its state root when --expect-root is given.
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
    /// Trusted checkpoint state root (exactly 64 lowercase hex chars) to verify
    /// the snapshot against. Without it the embedded root is NOT verified.
    #[arg(long, value_name = "HEX", value_parser = parse_expect_root)]
    expect_root: Option<types::Hash>,
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
    /// Trusted checkpoint state root (exactly 64 lowercase hex chars) to verify
    /// the snapshot against. Without it the embedded root is NOT verified.
    #[arg(long, value_name = "HEX", value_parser = parse_expect_root)]
    expect_root: Option<types::Hash>,
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

/// Open a durable WAL strictly read-only for the inspection subcommands.
///
/// `DurableLog::open` is a *writer* open: it takes the exclusive `wal.lock`
/// and truncates torn tails during recovery, so it must never be used by
/// `replay`/`inspect` — they could mutate the WAL or race a live node
/// (issue #402). `open_read_only` takes a shared lock and recovers purely in
/// memory. A `Locked` result (a live writer holds the exclusive lock) is
/// mapped to an operator-actionable message.
fn open_wal_read_only(path: &std::path::Path) -> anyhow::Result<storage::DurableLog> {
    storage::DurableLog::open_read_only(
        storage::DurableConfig::new(path).with_sync(storage::SyncPolicy::Never),
    )
    .map_err(|e| match e {
        storage::DurableError::Locked { .. } => anyhow::anyhow!(
            "durable log {} is locked by a live writer ({e}); \
             stop the node or run against a copy of the WAL directory",
            path.display()
        ),
        e => anyhow::anyhow!("opening durable log {}: {e}", path.display()),
    })
}

/// Load a snapshot + durable WAL, verify what can actually be verified, and
/// count applied records.
///
/// `Snapshot::load` already fail-closes on frame CRC, version, content digest,
/// and state-length bounds, so those are not re-checked here. The embedded
/// state root is only *verified* when the operator supplies a trusted
/// checkpoint root via `--expect-root`; otherwise it is reported as unverified.
/// The durable log is opened **read-only** (shared lock, in-memory recovery,
/// no on-disk mutation), checked for record CRCs, sequence continuity, and
/// sealed chain tips, and `DurableLog::replay` enforces contiguous sequences
/// from `snapshot_seq + 1`.
fn run_replay(args: &ReplayArgs) -> anyhow::Result<()> {
    let snap = storage::Snapshot::load(&args.snapshot)
        .map_err(|e| anyhow::anyhow!("loading snapshot {}: {e}", args.snapshot.display()))?;
    let root_status = describe_state_root(&snap, args.expect_root)?;

    let log = open_wal_read_only(&args.log)?;
    log.verify()
        .map_err(|e| anyhow::anyhow!("log integrity verify failed: {e}"))?;

    let mut applied = 0u64;
    let last = log
        .replay(Some(snap.last_sequence()), |_| {
            applied = applied.saturating_add(1);
        })
        .map_err(|e| anyhow::anyhow!("replay failed: {e}"))?;

    println!(
        "replay: snapshot_seq={} applied={} last_seq={} log_records={}",
        snap.last_sequence(),
        applied,
        last,
        log.len()
    );
    println!("state_root={root_status}");
    println!(
        "log: verified record CRCs, sequence continuity, and sealed chain tips; \
         replay enforced contiguous sequences from {}",
        snap.last_sequence().saturating_add(1)
    );
    Ok(())
}

/// Decode a snapshot and report exactly which checks ran.
///
/// `Snapshot::load` fail-closes on frame CRC, version, content digest, and
/// state-length bounds — those are the only checks a bare `verify` performs.
/// The embedded state root is only *verified* when `--expect-root` supplies a
/// trusted checkpoint root to compare against; on its own the embedded root is
/// just data from the file and proves nothing.
fn run_verify(args: &VerifyArgs) -> anyhow::Result<()> {
    let snap = storage::Snapshot::load(&args.snapshot)
        .map_err(|e| anyhow::anyhow!("loading snapshot {}: {e}", args.snapshot.display()))?;
    let root_status = describe_state_root(&snap, args.expect_root)?;
    println!(
        "verify: ok snapshot_seq={} state_bytes={} \
         checked=[frame CRC, version, content digest, state-length bounds]",
        snap.last_sequence(),
        snap.state().len()
    );
    println!("state_root={root_status}");
    Ok(())
}

/// Enforce `--expect-root` when present and describe the state root honestly.
///
/// The embedded root cannot self-verify — comparing it to itself is a
/// tautology (issue #423). Only an operator-supplied checkpoint root makes
/// [`storage::Snapshot::verify`] meaningful; without one, the returned
/// description says explicitly that no root verification happened.
///
/// # Errors
/// Fails when `expected` is present and does not match the embedded root.
fn describe_state_root(
    snap: &storage::Snapshot,
    expected: Option<types::Hash>,
) -> anyhow::Result<String> {
    let embedded = to_hex(snap.state_root().as_bytes());
    match expected {
        Some(root) => {
            if !snap.verify(root) {
                anyhow::bail!(
                    "state root mismatch: snapshot embeds {embedded} but --expect-root is {}",
                    to_hex(root.as_bytes())
                );
            }
            Ok(format!("{embedded} (verified against --expect-root)"))
        }
        None => Ok(format!(
            "{embedded} (embedded; NOT verified — pass --expect-root <checkpoint root> to verify)"
        )),
    }
}

/// Inspect a single sequence from a durable WAL directory.
///
/// The WAL is opened **read-only**: inspection never truncates a torn tail or
/// takes the writer lock, so it is safe next to (but not concurrent with the
/// exclusive lock of) a live node.
fn run_inspect(args: &InspectArgs) -> anyhow::Result<()> {
    let log = open_wal_read_only(&args.log)?;
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

/// Strictly decode an operator-supplied expected state root: exactly 64
/// lowercase hex characters (no `0x` prefix, no uppercase) into a 32-byte
/// [`types::Hash`].
///
/// Used as a clap value parser, so malformed input becomes a typed argument
/// error and a nonzero exit — never a panic.
///
/// # Errors
/// Returns a descriptive error on wrong length or non-lowercase-hex input.
fn parse_expect_root(s: &str) -> anyhow::Result<types::Hash> {
    if s.len() != 64 {
        anyhow::bail!(
            "expected exactly 64 lowercase hex characters (32 bytes), got {}",
            s.len()
        );
    }
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *byte = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(types::Hash::from_bytes(bytes))
}

/// Decode one lowercase hex digit; uppercase and non-hex bytes are rejected.
fn hex_nibble(b: u8) -> anyhow::Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => anyhow::bail!(
            "invalid hex character {:?}; only lowercase [0-9a-f] is accepted",
            char::from(b)
        ),
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
            &[
                "marketd",
                "inspect",
                "--sequence",
                "42",
                "--log",
                "/tmp/wal",
            ],
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
        let cli = Cli::try_parse_from(["marketd", "run", "--role", "gateway", "--role", "gateway"])
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
        let cli =
            Cli::try_parse_from(["marketd", "run", "--role", "gateway", "--role", "observer"])
                .unwrap();
        let Command::Run(args) = cli.command else {
            panic!("expected run");
        };
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.node.roles, vec![Role::Gateway, Role::Observer]);
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
    fn expect_root_parses_valid_64_lowercase_hex_on_replay_and_verify() {
        let hex = "ab".repeat(32);
        let want = types::Hash::from_bytes([0xab; 32]);

        let cli = Cli::try_parse_from([
            "marketd",
            "replay",
            "--snapshot",
            "s.snap",
            "--log",
            "c.log",
            "--expect-root",
            hex.as_str(),
        ])
        .expect("valid --expect-root must parse on replay");
        let Command::Replay(args) = cli.command else {
            panic!("expected replay");
        };
        assert_eq!(args.expect_root, Some(want));

        let cli = Cli::try_parse_from([
            "marketd",
            "verify",
            "--snapshot",
            "s.snap",
            "--expect-root",
            hex.as_str(),
        ])
        .expect("valid --expect-root must parse on verify");
        let Command::Verify(args) = cli.command else {
            panic!("expected verify");
        };
        assert_eq!(args.expect_root, Some(want));
    }

    #[test]
    fn expect_root_rejects_malformed_input_without_panic() {
        let bad = [
            "ab".repeat(31),                  // too short (62 chars)
            "ab".repeat(33),                  // too long (66 chars)
            format!("{}g", "a".repeat(63)),   // non-hex character, right length
            "AB".repeat(32),                  // uppercase is rejected
            format!("0x{}", "ab".repeat(31)), // 0x prefix ('x' is not hex)
            String::new(),                    // empty
        ];
        for value in &bad {
            assert!(
                Cli::try_parse_from([
                    "marketd",
                    "verify",
                    "--snapshot",
                    "s.snap",
                    "--expect-root",
                    value.as_str(),
                ])
                .is_err(),
                "verify must reject --expect-root {value:?}"
            );
            assert!(
                Cli::try_parse_from([
                    "marketd",
                    "replay",
                    "--snapshot",
                    "s.snap",
                    "--log",
                    "c.log",
                    "--expect-root",
                    value.as_str(),
                ])
                .is_err(),
                "replay must reject --expect-root {value:?}"
            );
        }
    }

    #[test]
    fn replay_and_verify_parse_without_expect_root() {
        let cli = Cli::try_parse_from(["marketd", "verify", "--snapshot", "s.snap"]).unwrap();
        let Command::Verify(args) = cli.command else {
            panic!("expected verify");
        };
        assert!(args.expect_root.is_none());

        let cli = Cli::try_parse_from([
            "marketd",
            "replay",
            "--snapshot",
            "s.snap",
            "--log",
            "c.log",
        ])
        .unwrap();
        let Command::Replay(args) = cli.command else {
            panic!("expected replay");
        };
        assert!(args.expect_root.is_none());
    }

    #[test]
    fn parse_expect_root_round_trips_to_hex_and_rejects_uppercase() {
        let hex = to_hex(&[0x5a; 32]);
        assert_eq!(
            parse_expect_root(&hex).expect("to_hex output must parse back"),
            types::Hash::from_bytes([0x5a; 32])
        );
        let err = parse_expect_root(&hex.to_uppercase()).expect_err("uppercase must be rejected");
        assert!(format!("{err:#}").contains("lowercase"), "{err:#}");
    }

    #[test]
    fn verify_enforces_expect_root_against_a_real_snapshot() {
        let path = unique_temp_path("verify-root");
        let root = types::Hash::from_bytes([7u8; 32]);
        storage::Snapshot::new(root, 42, b"engine-state".to_vec())
            .install_atomic(&path)
            .expect("fixture snapshot installs");

        // The correct checkpoint root passes.
        run_verify(&VerifyArgs {
            snapshot: path.clone(),
            expect_root: Some(root),
        })
        .expect("matching --expect-root must pass");

        // A wrong checkpoint root bails with a typed error naming the mismatch.
        let err = run_verify(&VerifyArgs {
            snapshot: path.clone(),
            expect_root: Some(types::Hash::from_bytes([8u8; 32])),
        })
        .expect_err("wrong --expect-root must fail");
        assert!(
            format!("{err:#}").contains("state root mismatch"),
            "{err:#}"
        );

        // Without --expect-root only the load-time checks run; no root claim.
        run_verify(&VerifyArgs {
            snapshot: path.clone(),
            expect_root: None,
        })
        .expect("verify without --expect-root still succeeds");

        let _ = std::fs::remove_file(&path);
    }

    /// Path to the single `seg-*.log` file inside a WAL directory.
    fn only_segment_path(dir: &std::path::Path) -> std::path::PathBuf {
        let mut segs: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("seg-") && n.ends_with(".log"))
            })
            .collect();
        segs.sort();
        assert_eq!(segs.len(), 1, "expected exactly one segment in {dir:?}");
        segs.remove(0)
    }

    #[test]
    fn inspect_fails_cleanly_when_wal_is_locked_by_a_live_writer() {
        // Issue #402: inspect used to take the writer open path and could run
        // concurrently with a live node. Now it takes a shared lock and fails
        // closed (typed error, no panic) while the writer holds wal.lock.
        let dir = unique_temp_path("inspect-locked");
        let mut writer = storage::DurableLog::open(storage::DurableConfig::new(&dir))
            .expect("writer opens fresh WAL");
        writer.append(1, 0, 1, b"live").expect("writer appends");

        let err = run_inspect(&InspectArgs {
            sequence: 1,
            log: dir.clone(),
        })
        .expect_err("inspect must be excluded while a writer holds wal.lock");
        assert!(
            format!("{err:#}").contains("locked by a live writer"),
            "error should name the lock conflict: {err:#}"
        );

        // Dropping the writer releases the lock; inspect then works read-only.
        drop(writer);
        run_inspect(&InspectArgs {
            sequence: 1,
            log: dir.clone(),
        })
        .expect("inspect succeeds once the writer is gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inspect_missing_wal_dir_is_an_error_not_an_empty_log() {
        // A typo'd --log path must be an error; the old writer-open would
        // create_dir_all and "inspect" a freshly created empty WAL.
        let dir = unique_temp_path("inspect-missing");
        let _ = std::fs::remove_dir_all(&dir);
        let err = run_inspect(&InspectArgs {
            sequence: 1,
            log: dir.clone(),
        })
        .expect_err("missing WAL dir must be rejected");
        assert!(
            format!("{err:#}").contains("does not exist"),
            "error should say the directory is missing: {err:#}"
        );
        assert!(!dir.exists(), "inspect must not create the WAL directory");
    }

    #[test]
    fn replay_is_read_only_and_leaves_torn_wal_bytes_unchanged() {
        // Issue #402: replay used DurableLog::open, whose recovery truncates a
        // torn tail on disk — an ostensibly read-only subcommand mutated the
        // WAL. Now recovery runs purely in memory.
        let wal_dir = unique_temp_path("replay-ro-wal");
        {
            let mut log = storage::DurableLog::open(storage::DurableConfig::new(&wal_dir))
                .expect("writer opens fresh WAL");
            for seq in 1..=3u64 {
                log.append(seq, seq, 1, b"cmd").expect("append");
            }
        }
        // Tear the active segment's tail, as a crashed writer would.
        let seg = only_segment_path(&wal_dir);
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
            // Only a 1–3-byte partial next-length field is unambiguously torn.
            // Four bytes would be a complete, unauthenticated length and must
            // fail closed rather than risk deleting corrupted acknowledged data.
            f.write_all(&[0xDE, 0xAD, 0xBE]).unwrap();
            f.sync_data().unwrap();
        }
        let before = std::fs::read(&seg).unwrap();

        // Snapshot at sequence 1 so replay applies 2..=3.
        let snap_path = unique_temp_path("replay-ro-snap");
        storage::Snapshot::new(types::Hash::from_bytes([9u8; 32]), 1, b"state".to_vec())
            .install_atomic(&snap_path)
            .expect("fixture snapshot installs");

        run_replay(&ReplayArgs {
            snapshot: snap_path.clone(),
            log: wal_dir.clone(),
            expect_root: None,
        })
        .expect("replay over a torn WAL succeeds read-only");

        // The torn tail is still on disk, byte for byte: replay mutated nothing.
        let after = std::fs::read(&seg).unwrap();
        assert_eq!(after, before, "replay must not rewrite WAL bytes");

        let _ = std::fs::remove_file(&snap_path);
        let _ = std::fs::remove_dir_all(&wal_dir);
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
