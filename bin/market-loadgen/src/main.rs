//! `market-loadgen` — deterministic simulation or measured socket load driver.
//!
//! Parses a load plan — either from CLI flags or a full TOML scenario file — and hands
//! off to the deterministic `loadgen` engine. Argument parsing is total; bad input
//! exits nonzero without panicking. Results are emitted as machine-readable JSON at run
//! end.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use loadgen::{
    partition_plan, ratio_from_unit_f64, run_live_packed, run_live_rpc, run_scenario,
    serve_reference_sink, Adversarial, AgentDescriptor, AssignmentReplayGuard,
    AuthenticatedAssignment, ClientTlsIdentity, ControlAuthenticator, ControllerPlan,
    DistributedPackedAgentReport, Impairment, LivePackedConfig, LiveRpcConfig, LiveTransport,
    LoadScenario, OracleWorkload, PackedCompletionBoundary, PackedConnectionLease,
    PackedSessionConfig, ReferenceSinkConfig, ReferenceSinkCounters, RegionConfig,
};
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(
    name = "market-loadgen",
    version,
    about = "DexOS load driver (simulation by default; --measured uses the target socket)"
)]
struct Cli {
    /// Target node address. Used only with `--measured`; retained as provenance
    /// in simulation reports.
    #[arg(long, value_name = "ADDR")]
    target: Option<String>,
    /// Number of simulated users / persistent sessions (across all regions).
    #[arg(long, default_value_t = 1000)]
    users: u64,
    /// Number of distinct markets to spread load across.
    #[arg(long = "market-count", default_value_t = 1)]
    market_count: u32,
    /// Aggregate order submission rate.
    #[arg(long = "orders-per-second", default_value_t = 1000)]
    orders_per_second: u64,
    /// Fraction of orders that are cancels, in [0.0, 1.0].
    #[arg(long = "cancel-ratio", default_value_t = 0.0)]
    cancel_ratio: f64,
    /// Run duration, e.g. `60s`, `500ms`, `5m`.
    #[arg(long, value_parser = parse_duration, default_value = "60s")]
    duration: Duration,
    /// Warm-up seconds before counters are collected in measured mode.
    #[arg(long = "warmup-seconds", default_value_t = 60)]
    warmup_seconds: u64,
    /// Number of regions to spread users across (first is same-region).
    #[arg(long, default_value_t = 1)]
    regions: u32,
    /// Network impairment: fraction of packets lost, in [0.0, 1.0].
    #[arg(long, default_value_t = 0.0)]
    impairment: f64,
    /// Enable adversarial frame injection.
    #[arg(long)]
    adversarial: bool,
    /// Oracle price updates emitted per second.
    #[arg(long = "oracle-update-frequency", default_value_t = 0)]
    oracle_update_frequency: u64,
    /// Deterministic seed for reproducible runs.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Load a full TOML scenario file (overrides the flags above).
    #[arg(long, value_name = "PATH")]
    scenario: Option<PathBuf>,
    /// Drive the target with signed production RPC over persistent non-blocking
    /// sockets. Without this flag the run is a labelled deterministic simulation.
    #[arg(long)]
    measured: bool,
    /// Raw 32-byte ed25519 seed for measured production RPC. Never stored in reports.
    #[arg(long = "signing-key-file", value_name = "PATH")]
    signing_key_file: Option<PathBuf>,
    /// Funded account authorized by the measured signing key.
    #[arg(long = "account-id", default_value_t = 0)]
    account_id: u32,
    /// First disjoint measured client ID.
    #[arg(long = "client-id-base", default_value_t = 1)]
    client_id_base: u64,
    /// Controller-assigned upper 32-bit nonce namespace.
    #[arg(long = "nonce-namespace", default_value_t = 1)]
    nonce_namespace: u32,
    /// Persistent production-RPC connections for local measured mode.
    #[arg(long = "connections", default_value_t = 1)]
    connections: u32,
    /// Bounded correlated request depth per connection.
    #[arg(long = "max-in-flight", default_value_t = 8)]
    max_in_flight: usize,
    /// JSON array of server-issued packed session leases. When present, measured
    /// mode uses authenticated 32-128 record batches instead of per-order RPC.
    #[arg(long = "packed-leases", value_name = "PATH", requires = "measured")]
    packed_leases: Option<PathBuf>,
    /// Records per authenticated packed batch.
    #[arg(long = "packed-batch-size", default_value_t = 128)]
    packed_batch_size: u8,
    /// Required packed receipt boundary: `executed` (component only) or `finalized`.
    #[arg(long = "packed-completion", default_value = "finalized")]
    packed_completion: String,
    /// Explicitly label the target as `validator` or `reference-sink`.
    #[arg(long = "target-profile", default_value = "validator")]
    target_profile: String,
    /// Explicit source IPs, round-robin across measured connections.
    #[arg(long = "source-ip")]
    source_ips: Vec<std::net::IpAddr>,
    /// Explicitly allow plaintext only for local/reference-sink development.
    #[arg(long = "dev-plaintext")]
    dev_plaintext: bool,
    /// TLS server DNS name used for certificate verification.
    #[arg(long = "tls-server-name")]
    tls_server_name: Option<String>,
    /// PEM CA roots for TLS 1.3 server validation.
    #[arg(long = "ca-cert", value_name = "PATH")]
    ca_cert: Option<PathBuf>,
    /// PEM client certificate chain for optional mTLS.
    #[arg(long = "client-cert", value_name = "PATH", requires = "client_key")]
    client_cert: Option<PathBuf>,
    /// PEM client private key for optional mTLS.
    #[arg(long = "client-key", value_name = "PATH", requires = "client_cert")]
    client_key: Option<PathBuf>,
    /// Distributed planning or agent-preflight mode. Without a subcommand, run
    /// the local simulator/measured engine as before.
    #[command(subcommand)]
    distributed: Option<DistributedCommand>,
}

#[derive(Debug, Subcommand)]
enum DistributedCommand {
    /// Partition a run and emit authenticated, per-agent assignment envelopes.
    Controller(ControllerArgs),
    /// Authenticate and consume one assignment before starting an agent engine.
    Agent(Box<AgentArgs>),
    /// Run the production-protocol reference sink (never validator capacity).
    ReferenceSink(ReferenceSinkArgs),
}

#[derive(Debug, Args)]
struct ControllerArgs {
    /// Controller run plan JSON.
    #[arg(long, value_name = "PATH")]
    plan: PathBuf,
    /// JSON array of validated agent capacity/topology descriptors.
    #[arg(long, value_name = "PATH")]
    agents: PathBuf,
    /// File containing at least 32 bytes of out-of-band control-plane key material.
    #[arg(long = "control-key-file", value_name = "PATH")]
    control_key_file: PathBuf,
    /// Output JSON array of authenticated assignments.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Override current Unix nanoseconds for deterministic tests/planning.
    #[arg(long = "now-unix-ns")]
    now_unix_ns: Option<u64>,
}

#[derive(Debug, Args)]
struct AgentArgs {
    /// Authenticated assignment-envelope JSON emitted by controller mode.
    #[arg(long, value_name = "PATH")]
    assignment: PathBuf,
    /// Expected stable agent identity.
    #[arg(long = "agent-id")]
    agent_id: String,
    /// File containing the shared out-of-band control-plane key.
    #[arg(long = "control-key-file", value_name = "PATH")]
    control_key_file: PathBuf,
    /// Full TOML workload scenario; assignment rate/duration/targets override it.
    #[arg(long, value_name = "PATH")]
    scenario: PathBuf,
    /// Raw 32-byte ed25519 signing seed for target RPC.
    #[arg(long = "signing-key-file", value_name = "PATH")]
    signing_key_file: PathBuf,
    /// Funded account authorized by the target signing key.
    #[arg(long = "account-id")]
    account_id: u32,
    /// Explicit target label: `validator` or `reference-sink`.
    #[arg(long = "target-profile", default_value = "validator")]
    target_profile: String,
    /// Explicit source IPs, round-robin across assigned connections.
    #[arg(long = "source-ip")]
    source_ips: Vec<std::net::IpAddr>,
    /// Optional server-issued packed leases for the optimized validator route.
    #[arg(long = "packed-leases", value_name = "PATH")]
    packed_leases: Option<PathBuf>,
    /// Fixed records per authenticated packed batch.
    #[arg(long = "packed-batch-size", default_value_t = 128)]
    packed_batch_size: u8,
    /// Required packed lifecycle boundary: `executed` or `finalized`.
    #[arg(long = "packed-completion", default_value = "finalized")]
    packed_completion: String,
    /// Allow plaintext only for local/reference-sink development.
    #[arg(long = "dev-plaintext")]
    dev_plaintext: bool,
    /// TLS server DNS name.
    #[arg(long = "tls-server-name")]
    tls_server_name: Option<String>,
    /// PEM CA roots.
    #[arg(long = "ca-cert", value_name = "PATH")]
    ca_cert: Option<PathBuf>,
    /// PEM client certificate chain for optional mTLS.
    #[arg(long = "client-cert", value_name = "PATH", requires = "client_key")]
    client_cert: Option<PathBuf>,
    /// PEM client private key for optional mTLS.
    #[arg(long = "client-key", value_name = "PATH", requires = "client_cert")]
    client_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ReferenceSinkArgs {
    /// Explicit reference-sink listen address.
    #[arg(long, default_value = "127.0.0.1:9100")]
    listen: std::net::SocketAddr,
    /// Maximum persistent connections accepted by this sink process.
    #[arg(long = "max-connections", default_value_t = 16_384)]
    max_connections: usize,
}

/// Non-secret portion of a server-issued packed connection/session lease.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackedLeaseInput {
    endpoint: std::net::SocketAddr,
    #[serde(default)]
    source_ip: Option<std::net::IpAddr>,
    destination: [u8; 32],
    session_ref: u32,
    account_id: u32,
    client_id: u64,
    nonce_base: u64,
    first_batch_sequence: u64,
    first_command_sequence: u64,
    #[serde(default = "default_batch_sequence_stride")]
    batch_sequence_stride: u64,
    #[serde(default)]
    command_sequence_stride: u64,
    #[serde(default = "default_packed_live_orders")]
    max_live_orders: usize,
}

const fn default_packed_live_orders() -> usize {
    1_024
}

const fn default_batch_sequence_stride() -> u64 {
    1
}

/// Parse a duration with an `ms`, `s`, or `m` suffix into a [`Duration`].
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (value, unit_ms) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1u64)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1000)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60_000)
    } else {
        return Err(format!("duration '{s}' must end with ms, s, or m"));
    };
    let n: u64 = value
        .parse()
        .map_err(|_| format!("duration '{s}' has a non-numeric magnitude"))?;
    let millis = n
        .checked_mul(unit_ms)
        .ok_or_else(|| format!("duration '{s}' overflows"))?;
    Ok(Duration::from_millis(millis))
}

/// Build a [`LoadScenario`] from CLI flags.
fn scenario_from_cli(cli: &Cli) -> LoadScenario {
    let region_count = cli.regions.max(1);
    let total = cli.users.max(1);
    let per_region = total / u64::from(region_count);
    let mut regions = Vec::with_capacity(usize::try_from(region_count).unwrap_or(1));
    for i in 0..region_count {
        let cross = i > 0;
        // Give the last region any rounding remainder.
        let users = if i + 1 == region_count {
            total - per_region * u64::from(region_count - 1)
        } else {
            per_region
        };
        regions.push(RegionConfig {
            name: format!("region-{i}"),
            users: u32::try_from(users.min(u64::from(u32::MAX))).unwrap_or(u32::MAX),
            cross_region: cross,
            base_latency_us: if cross { 4_000 } else { 200 },
            jitter_us: if cross { 300 } else { 50 },
            clock_offset_us: 0,
        });
    }

    LoadScenario {
        seed: cli.seed,
        target: cli
            .target
            .clone()
            .unwrap_or_else(|| "127.0.0.1:9000".to_string()),
        regions,
        market_count: cli.market_count.max(1),
        orders_per_second: cli.orders_per_second,
        cancel_ratio: ratio_from_unit_f64(cli.cancel_ratio),
        duration_secs: cli.duration.as_secs(),
        impairment: Impairment {
            loss_ratio: ratio_from_unit_f64(cli.impairment),
            ..Impairment::default()
        },
        adversarial: Adversarial {
            enabled: cli.adversarial,
            ..Adversarial::default()
        },
        oracle: OracleWorkload {
            updates_per_second: cli.oracle_update_frequency,
        },
        ..LoadScenario::default()
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(distributed) = &cli.distributed {
        return match distributed {
            DistributedCommand::Controller(args) => run_controller(args),
            DistributedCommand::Agent(args) => run_agent(args).await,
            DistributedCommand::ReferenceSink(args) => run_reference_sink(args).await,
        };
    }

    if cli.scenario.is_none() && cli.target.is_none() {
        eprintln!("error: --target is required for local execution without --scenario");
        return ExitCode::FAILURE;
    }

    let scenario = match &cli.scenario {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => match LoadScenario::from_toml(&text) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            },
            Err(err) => {
                eprintln!("error: cannot read scenario {}: {err}", path.display());
                return ExitCode::FAILURE;
            }
        },
        None => scenario_from_cli(&cli),
    };

    if cli.measured {
        let Some(key_path) = &cli.signing_key_file else {
            return report_error("--signing-key-file is required with --measured");
        };
        let signing_seed = match read_signing_seed(key_path) {
            Ok(seed) => seed,
            Err(error) => return report_error(error),
        };
        let endpoint = match scenario.target.parse() {
            Ok(endpoint) => endpoint,
            Err(error) => return report_error(format!("invalid target socket address: {error}")),
        };
        let transport = match live_transport(&cli) {
            Ok(transport) => transport,
            Err(error) => return report_error(error),
        };
        if let Some(lease_path) = &cli.packed_leases {
            let leases = match read_packed_leases(lease_path, signing_seed, cli.max_in_flight) {
                Ok(value) => value,
                Err(error) => return report_error(error),
            };
            let completion_boundary = match parse_packed_completion(&cli.packed_completion) {
                Ok(value) => value,
                Err(error) => return report_error(error),
            };
            let config = LivePackedConfig {
                leases,
                batch_size: cli.packed_batch_size,
                max_in_flight_batches: cli.max_in_flight,
                receipt_timeout: Duration::from_secs(10),
                warmup_secs: cli.warmup_seconds,
                start_lead: Duration::from_secs(1),
                transport,
                completion_boundary,
            };
            return match run_live_packed(&scenario, &config, &cli.target_profile).await {
                Ok(report) => match serde_json::to_string(&report) {
                    Ok(json) => {
                        println!("{json}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => report_error(format!("cannot encode packed report: {error}")),
                },
                Err(error) => report_error(error.to_string()),
            };
        }
        let config = LiveRpcConfig {
            endpoints: vec![endpoint],
            source_ips: cli.source_ips.clone(),
            connections: cli.connections,
            account: types::AccountId::new(cli.account_id),
            client_id_base: cli.client_id_base,
            nonce_namespace: cli.nonce_namespace,
            signing_seed,
            max_in_flight: cli.max_in_flight,
            max_live_orders: 1_024,
            response_timeout: Duration::from_secs(10),
            warmup_secs: cli.warmup_seconds,
            start_lead: Duration::from_secs(1),
            transport,
        };
        return match run_live_rpc(&scenario, &config, &cli.target_profile).await {
            Ok(report) => match serde_json::to_string(&report) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(error) => report_error(format!("cannot encode live report: {error}")),
            },
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        };
    }

    // Simulation: no socket is opened. The report models the pipeline from fixed
    // per-stage costs; it is explicitly NOT a measurement of `--target`. We say so on
    // stderr so an operator cannot mistake a simulation for a live measurement.
    eprintln!(
        "note: simulation mode — results model the pipeline and are NOT a live \
         measurement of '{}'. Re-run with --measured to drive the real target.",
        scenario.target
    );
    match run_scenario(&scenario) {
        Ok(report) => {
            println!("{}", report.to_json());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn read_signing_seed(path: &std::path::Path) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read signing key {}: {error}", path.display()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "signing key {} must contain exactly 32 raw bytes, got {}",
            path.display(),
            bytes.len()
        )
    })
}

fn read_packed_leases(
    path: &std::path::Path,
    signing_seed: [u8; 32],
    max_in_flight_batches: usize,
) -> Result<Vec<PackedConnectionLease>, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read packed leases {}: {error}", path.display()))?;
    let inputs: Vec<PackedLeaseInput> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse packed leases {}: {error}", path.display()))?;
    if inputs.is_empty() {
        return Err("packed lease file must contain at least one lease".to_string());
    }
    Ok(inputs
        .into_iter()
        .map(|input| PackedConnectionLease {
            endpoint: input.endpoint,
            source_ip: input.source_ip,
            session: PackedSessionConfig {
                destination: input.destination,
                session_ref: input.session_ref,
                account: types::AccountId::new(input.account_id),
                client_id: input.client_id,
                nonce_base: input.nonce_base,
                signing_seed,
                first_batch_sequence: input.first_batch_sequence,
                first_command_sequence: input.first_command_sequence,
                batch_sequence_stride: input.batch_sequence_stride,
                command_sequence_stride: input.command_sequence_stride,
                max_in_flight_batches,
                max_live_orders: input.max_live_orders,
            },
        })
        .collect())
}

fn parse_packed_completion(value: &str) -> Result<PackedCompletionBoundary, String> {
    match value {
        "executed" => Ok(PackedCompletionBoundary::Executed),
        "finalized" => Ok(PackedCompletionBoundary::Finalized),
        _ => Err("--packed-completion must be `executed` or `finalized`".to_string()),
    }
}

fn live_transport(cli: &Cli) -> Result<LiveTransport, String> {
    if cli.dev_plaintext {
        return Ok(LiveTransport::DevPlaintext);
    }
    let server_name = cli
        .tls_server_name
        .clone()
        .ok_or_else(|| "--tls-server-name is required unless --dev-plaintext is set".to_string())?;
    let ca_path = cli
        .ca_cert
        .as_ref()
        .ok_or_else(|| "--ca-cert is required unless --dev-plaintext is set".to_string())?;
    let ca_certificates_pem = std::fs::read(ca_path)
        .map_err(|error| format!("cannot read CA certificate {}: {error}", ca_path.display()))?;
    let client_identity = match (&cli.client_cert, &cli.client_key) {
        (Some(cert), Some(key)) => Some(ClientTlsIdentity {
            certificate_chain_pem: std::fs::read(cert).map_err(|error| {
                format!("cannot read client certificate {}: {error}", cert.display())
            })?,
            private_key_pem: std::fs::read(key)
                .map_err(|error| format!("cannot read client key {}: {error}", key.display()))?,
        }),
        (None, None) => None,
        _ => return Err("--client-cert and --client-key must be provided together".to_string()),
    };
    Ok(LiveTransport::Tls13 {
        server_name,
        ca_certificates_pem,
        client_identity,
    })
}

fn run_controller(args: &ControllerArgs) -> ExitCode {
    let plan: ControllerPlan = match read_json(&args.plan) {
        Ok(value) => value,
        Err(error) => return report_error(error),
    };
    let agents: Vec<AgentDescriptor> = match read_json(&args.agents) {
        Ok(value) => value,
        Err(error) => return report_error(error),
    };
    let key = match std::fs::read(&args.control_key_file) {
        Ok(value) => value,
        Err(error) => return report_error(format!("cannot read control key: {error}")),
    };
    let authenticator = match ControlAuthenticator::new(&key) {
        Ok(value) => value,
        Err(error) => return report_error(error.to_string()),
    };
    let now_unix_ns = match args.now_unix_ns {
        Some(value) => value,
        None => match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(value) => u64::try_from(value.as_nanos()).unwrap_or(u64::MAX),
            Err(error) => return report_error(format!("system clock before Unix epoch: {error}")),
        },
    };
    let assignments = match partition_plan(&plan, &agents, now_unix_ns) {
        Ok(value) => value,
        Err(error) => return report_error(error.to_string()),
    };
    let mut envelopes = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        let mut challenge = [0u8; 32];
        if let Err(error) = getrandom::getrandom(&mut challenge) {
            return report_error(format!("cannot generate control challenge: {error}"));
        }
        envelopes.push(AuthenticatedAssignment::new(
            assignment,
            challenge,
            &authenticator,
        ));
    }
    let bytes = match serde_json::to_vec_pretty(&envelopes) {
        Ok(value) => value,
        Err(error) => return report_error(format!("cannot encode assignments: {error}")),
    };
    if let Err(error) = std::fs::write(&args.output, bytes) {
        return report_error(format!("cannot write {}: {error}", args.output.display()));
    }
    println!(
        "controller: wrote {} authenticated assignments to {}",
        envelopes.len(),
        args.output.display()
    );
    ExitCode::SUCCESS
}

async fn run_agent(args: &AgentArgs) -> ExitCode {
    let envelope = match read_agent_assignment(&args.assignment, &args.agent_id) {
        Ok(value) => value,
        Err(error) => return report_error(error),
    };
    let key = match std::fs::read(&args.control_key_file) {
        Ok(value) => value,
        Err(error) => return report_error(format!("cannot read control key: {error}")),
    };
    let authenticator = match ControlAuthenticator::new(&key) {
        Ok(value) => value,
        Err(error) => return report_error(error.to_string()),
    };
    if let Err(error) = envelope.verify_for(&args.agent_id, &authenticator) {
        return report_error(error.to_string());
    }
    let mut replay = AssignmentReplayGuard::default();
    if let Err(error) = replay.consume(&envelope.assignment) {
        return report_error(error.to_string());
    }
    let signing_seed = match read_signing_seed(&args.signing_key_file) {
        Ok(value) => value,
        Err(error) => return report_error(error),
    };
    let scenario_text = match std::fs::read_to_string(&args.scenario) {
        Ok(value) => value,
        Err(error) => {
            return report_error(format!("cannot read {}: {error}", args.scenario.display()))
        }
    };
    let mut scenario = match LoadScenario::from_toml(&scenario_text) {
        Ok(value) => value,
        Err(error) => return report_error(error),
    };
    let endpoints = match envelope
        .assignment
        .targets
        .iter()
        .map(|target| target.parse())
        .collect::<Result<Vec<std::net::SocketAddr>, _>>()
    {
        Ok(value) => value,
        Err(error) => return report_error(format!("invalid assigned target: {error}")),
    };
    let transport = match agent_transport(args) {
        Ok(value) => value,
        Err(error) => return report_error(error),
    };
    let now_unix_ns = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(value) => u64::try_from(value.as_nanos()).unwrap_or(u64::MAX),
        Err(error) => return report_error(format!("system clock before Unix epoch: {error}")),
    };
    if envelope.assignment.start_unix_ns <= now_unix_ns {
        return report_error("assignment warm-up start is not in the future");
    }
    scenario.orders_per_second = envelope.assignment.rate;
    scenario.duration_secs = envelope.assignment.phases.steady_secs;
    scenario.target = envelope.assignment.targets[0].clone();
    scenario.regions = vec![RegionConfig {
        name: envelope.assignment.region.clone(),
        users: envelope.assignment.connections,
        cross_region: false,
        base_latency_us: 0,
        jitter_us: 0,
        clock_offset_us: 0,
    }];
    eprintln!(
        "agent {}: authenticated run {}; waiting for synchronized warm-up; target traffic is direct",
        envelope.assignment.agent_id, envelope.assignment.run_id
    );
    if let Some(path) = &args.packed_leases {
        let leases = match read_packed_leases(path, signing_seed, 8) {
            Ok(value) => value,
            Err(error) => return report_error(error),
        };
        if leases.len() != usize::try_from(envelope.assignment.connections).unwrap_or(usize::MAX) {
            return report_error(format!(
                "packed lease count {} does not match assigned connections {}",
                leases.len(),
                envelope.assignment.connections
            ));
        }
        if leases
            .iter()
            .any(|lease| !endpoints.contains(&lease.endpoint))
        {
            return report_error("packed lease endpoint is outside the authenticated assignment");
        }
        let completion_boundary = match parse_packed_completion(&args.packed_completion) {
            Ok(value) => value,
            Err(error) => return report_error(error),
        };
        let report = match run_live_packed(
            &scenario,
            &LivePackedConfig {
                leases,
                batch_size: args.packed_batch_size,
                max_in_flight_batches: 8,
                receipt_timeout: Duration::from_secs(10),
                warmup_secs: envelope.assignment.phases.warmup_secs,
                start_lead: Duration::from_nanos(envelope.assignment.start_unix_ns - now_unix_ns),
                transport,
                completion_boundary,
            },
            &args.target_profile,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return report_error(error.to_string()),
        };
        let report = match DistributedPackedAgentReport::authenticated(
            envelope.clone(),
            report,
            &authenticator,
        ) {
            Ok(value) => value,
            Err(error) => return report_error(error.to_string()),
        };
        return match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => report_error(format!("cannot encode packed agent report: {error}")),
        };
    }

    let report = match run_live_rpc(
        &scenario,
        &LiveRpcConfig {
            endpoints,
            source_ips: args.source_ips.clone(),
            connections: envelope.assignment.connections,
            account: types::AccountId::new(args.account_id),
            client_id_base: envelope.assignment.client_id_start,
            nonce_namespace: envelope.assignment.nonce_namespace,
            signing_seed,
            max_in_flight: 8,
            max_live_orders: 1_024,
            response_timeout: Duration::from_secs(10),
            warmup_secs: envelope.assignment.phases.warmup_secs,
            start_lead: Duration::from_nanos(envelope.assignment.start_unix_ns - now_unix_ns),
            transport,
        },
        &args.target_profile,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return report_error(error),
    };
    match serde_json::to_string(&report) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => report_error(format!("cannot encode agent report: {error}")),
    }
}

fn read_agent_assignment(
    path: &std::path::Path,
    agent_id: &str,
) -> Result<AuthenticatedAssignment, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if let Ok(envelope) = serde_json::from_slice::<AuthenticatedAssignment>(&bytes) {
        return Ok(envelope);
    }
    let envelopes: Vec<AuthenticatedAssignment> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    envelopes
        .into_iter()
        .find(|envelope| envelope.assignment.agent_id == agent_id)
        .ok_or_else(|| format!("assignment file contains no entry for agent `{agent_id}`"))
}

fn agent_transport(args: &AgentArgs) -> Result<LiveTransport, String> {
    if args.dev_plaintext {
        return Ok(LiveTransport::DevPlaintext);
    }
    let server_name = args
        .tls_server_name
        .clone()
        .ok_or_else(|| "--tls-server-name is required unless --dev-plaintext is set".to_string())?;
    let ca_path = args
        .ca_cert
        .as_ref()
        .ok_or_else(|| "--ca-cert is required unless --dev-plaintext is set".to_string())?;
    let ca_certificates_pem = std::fs::read(ca_path)
        .map_err(|error| format!("cannot read CA certificate {}: {error}", ca_path.display()))?;
    let client_identity = match (&args.client_cert, &args.client_key) {
        (Some(cert), Some(key)) => Some(ClientTlsIdentity {
            certificate_chain_pem: std::fs::read(cert).map_err(|error| {
                format!("cannot read client certificate {}: {error}", cert.display())
            })?,
            private_key_pem: std::fs::read(key)
                .map_err(|error| format!("cannot read client key {}: {error}", key.display()))?,
        }),
        (None, None) => None,
        _ => return Err("--client-cert and --client-key must be provided together".to_string()),
    };
    Ok(LiveTransport::Tls13 {
        server_name,
        ca_certificates_pem,
        client_identity,
    })
}

async fn run_reference_sink(args: &ReferenceSinkArgs) -> ExitCode {
    let listener = match tokio::net::TcpListener::bind(args.listen).await {
        Ok(listener) => listener,
        Err(error) => return report_error(format!("cannot bind {}: {error}", args.listen)),
    };
    let counters = Arc::new(ReferenceSinkCounters::default());
    let server_counters = counters.clone();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let config = ReferenceSinkConfig {
        max_connections: args.max_connections,
        ..ReferenceSinkConfig::default()
    };
    eprintln!(
        "reference-sink: listening on {}; this measures generator capacity, not validator throughput",
        args.listen
    );
    let server = tokio::spawn(async move {
        serve_reference_sink(listener, config, server_counters, stop_rx).await
    });
    if let Err(error) = tokio::signal::ctrl_c().await {
        return report_error(format!("cannot install ctrl-c handler: {error}"));
    }
    let _ = stop_tx.send(true);
    match server.await {
        Ok(Ok(())) => match serde_json::to_string(&counters.snapshot()) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => report_error(format!("cannot encode sink report: {error}")),
        },
        Ok(Err(error)) => report_error(error),
        Err(error) => report_error(format!("reference sink task failed: {error}")),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

fn report_error(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("error: {error}");
    ExitCode::FAILURE
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
    fn parses_full_invocation() {
        let cli = Cli::try_parse_from([
            "market-loadgen",
            "--target",
            "offline.example:9000",
            "--users",
            "100000",
            "--orders-per-second",
            "1000000",
            "--cancel-ratio",
            "0.7",
            "--duration",
            "60s",
        ])
        .unwrap();
        assert_eq!(cli.users, 100_000);
        assert_eq!(cli.duration, Duration::from_secs(60));
    }

    #[test]
    fn parses_all_spec_knobs() {
        let cli = Cli::try_parse_from([
            "market-loadgen",
            "--target",
            "offline.example:9000",
            "--users",
            "500",
            "--orders-per-second",
            "2000",
            "--cancel-ratio",
            "0.3",
            "--duration",
            "30s",
            "--regions",
            "3",
            "--impairment",
            "0.05",
            "--adversarial",
            "--oracle-update-frequency",
            "10",
            "--seed",
            "99",
        ])
        .unwrap();
        assert_eq!(cli.regions, 3);
        assert!((cli.impairment - 0.05).abs() < 1e-9);
        assert!(cli.adversarial);
        assert_eq!(cli.oracle_update_frequency, 10);
        assert_eq!(cli.seed, 99);

        let scenario = scenario_from_cli(&cli);
        assert_eq!(scenario.regions.len(), 3);
        assert_eq!(scenario.total_users(), 500);
        assert_eq!(scenario.cancel_ratio.raw(), 300_000);
        assert_eq!(scenario.impairment.loss_ratio.raw(), 50_000);
        assert!(scenario.adversarial.enabled);
        assert_eq!(scenario.oracle.updates_per_second, 10);
        assert!(scenario.validate().is_ok());
    }

    #[test]
    fn help_lists_all_spec_knobs() {
        let mut cmd = Cli::command();
        let help = cmd.render_long_help().to_string();
        for knob in [
            "--target",
            "--users",
            "--market-count",
            "--orders-per-second",
            "--cancel-ratio",
            "--duration",
            "--regions",
            "--impairment",
            "--adversarial",
        ] {
            assert!(help.contains(knob), "help missing {knob}");
        }
    }

    #[test]
    fn duration_units_parse() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("xs").is_err());
    }

    #[test]
    fn legacy_market_symbol_is_rejected_instead_of_ignored() {
        assert!(Cli::try_parse_from([
            "market-loadgen",
            "--target",
            "offline.example:9000",
            "--market",
            "BTC-PERP",
        ])
        .is_err());
    }

    #[test]
    fn cli_scenario_runs() {
        let cli = Cli::try_parse_from([
            "market-loadgen",
            "--target",
            "offline.example:9000",
            "--users",
            "10",
            "--orders-per-second",
            "100",
            "--duration",
            "2s",
        ])
        .unwrap();
        let report = run_scenario(&scenario_from_cli(&cli)).unwrap();
        assert_eq!(report.planned_orders, 200);
        assert!(report.to_json().starts_with('{'));
    }

    #[test]
    fn measured_flag_parses_and_defaults_off() {
        let sim = Cli::try_parse_from(["market-loadgen", "--target", "127.0.0.1:9000"]).unwrap();
        assert!(!sim.measured, "measured is opt-in");
        let meas =
            Cli::try_parse_from(["market-loadgen", "--target", "127.0.0.1:9000", "--measured"])
                .unwrap();
        assert!(meas.measured);
    }

    #[tokio::test]
    async fn measured_run_against_unreachable_target_fails() {
        use loadgen::LiveRpcError;
        use std::net::TcpListener;

        // Bind then drop so the port is guaranteed closed and refuses connections.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let cli = Cli::try_parse_from([
            "market-loadgen",
            "--target",
            &addr.to_string(),
            "--users",
            "4",
            "--orders-per-second",
            "8",
            "--duration",
            "1s",
            "--measured",
        ])
        .unwrap();
        let err = run_live_rpc(
            &scenario_from_cli(&cli),
            &LiveRpcConfig {
                endpoints: vec![addr],
                source_ips: Vec::new(),
                connections: 1,
                account: types::AccountId::new(1),
                client_id_base: 1,
                nonce_namespace: 1,
                signing_seed: [1; 32],
                max_in_flight: 1,
                max_live_orders: 1,
                response_timeout: Duration::from_secs(1),
                warmup_secs: 0,
                start_lead: Duration::ZERO,
                transport: LiveTransport::Tls13 {
                    server_name: "localhost".to_string(),
                    ca_certificates_pem: Vec::new(),
                    client_identity: None,
                },
            },
            "validator",
        )
        .await
        .expect_err("unreachable must fail");
        assert!(matches!(err, LiveRpcError::Connect { .. }), "{err:?}");
    }

    #[test]
    fn checked_in_doublezero_examples_partition_exactly() {
        let mut plan: ControllerPlan = serde_json::from_str(include_str!(
            "../../../deploy/doublezero/loadgen-controller-plan.template.json"
        ))
        .unwrap();
        plan.start_unix_ns = loadgen::MIN_START_LEAD_NS + 1;
        let agents: Vec<AgentDescriptor> = serde_json::from_str(include_str!(
            "../../../deploy/doublezero/loadgen-agents.json"
        ))
        .unwrap();
        let assignments = partition_plan(&plan, &agents, 0).unwrap();
        assert_eq!(assignments.len(), 3);
        assert_eq!(
            assignments.iter().map(|item| item.rate).sum::<u64>(),
            24_000_000
        );
        assert_eq!(
            assignments.iter().map(|item| item.connections).sum::<u32>(),
            12_000
        );
        assert!(assignments.iter().all(|item| item.targets.len() == 2));
    }
}
