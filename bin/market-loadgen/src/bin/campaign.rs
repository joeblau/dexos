//! `market-loadgen-campaign` — extended distributed qualification driver.
//!
//! Parses a load plan — either from CLI flags or a full TOML scenario file — and hands
//! off to the deterministic `loadgen` engine. Argument parsing is total; bad input
//! exits nonzero without panicking. Results are emitted as machine-readable JSON at run
//! end.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use loadgen::campaign::{
    ratio_from_unit_f64, reference_sink_tls_acceptor, run_distributed_agent_with_shutdown,
    run_distributed_controller, run_local_live_with_progress, run_measured, run_scenario,
    serve_reference_sink, serve_reference_sink_tls, AccountMaterial, ActionLatencyReport,
    Adversarial, DistributedRunReport, EndpointConfig, HistogramReport, Impairment, IntervalReport,
    LiveReport, LoadScenario, OperationMix, OracleWorkload, ProtocolAdapter, ReferenceSinkConfig,
    RegionConfig, RunMode, RunRole, SinkFaultMode, SinkHistogramReport, TargetKind,
    TlsClientConfig,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LiveTarget {
    Validator,
    Sink,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Deterministic planning/test mode; opens no target sockets.
    Simulate,
    /// Execute the data-plane agent engine in this process.
    Local {
        /// Whether the target is a validator/gateway or the test-only reference sink.
        #[arg(long, value_enum, default_value_t = LiveTarget::Validator)]
        target_kind: LiveTarget,
    },
    /// Wait for an authenticated plan from a distributed controller.
    Agent {
        /// Authenticated controller host:port.
        #[arg(long)]
        controller: String,
        /// Whether this agent targets validators or reference sinks.
        #[arg(long, value_enum, default_value_t = LiveTarget::Validator)]
        target_kind: LiveTarget,
    },
    /// Partition and coordinate a distributed run.
    Controller {
        /// Whether agents target validators or reference sinks.
        #[arg(long, value_enum, default_value_t = LiveTarget::Validator)]
        target_kind: LiveTarget,
    },
    /// Run the test-only protocol-conformant capacity sink/fault harness.
    ReferenceSink {
        /// Address on which the test sink listens.
        #[arg(long, default_value = "127.0.0.1:9900")]
        listen: String,
        /// Deterministic sink response behavior.
        #[arg(long, value_enum, default_value_t = SinkFaultArg::ImmediateAck)]
        fault: SinkFaultArg,
        /// Optional automatic shutdown for smoke tests.
        #[arg(long, value_parser = parse_duration)]
        shutdown_after: Option<Duration>,
        /// Skip signature verification to measure framing-only sink capacity.
        #[arg(long)]
        skip_signature_validation: bool,
        /// PEM certificate chain enabling a TLS 1.3 listener.
        #[arg(long, requires = "tls_key_file")]
        tls_cert_file: Option<PathBuf>,
        /// PEM private key for the TLS sink identity.
        #[arg(long, requires = "tls_cert_file")]
        tls_key_file: Option<PathBuf>,
        /// PEM trust roots for mandatory client-certificate authentication.
        #[arg(long, requires = "tls_cert_file")]
        client_ca_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SinkFaultArg {
    NoAck,
    ImmediateAck,
    BatchedAck,
    DelayedAck,
    Reject,
    Drop,
    CorruptResponse,
    Throttle,
    Disconnect,
}

impl SinkFaultArg {
    const fn into_mode(self) -> SinkFaultMode {
        match self {
            SinkFaultArg::NoAck => SinkFaultMode::NoAck,
            SinkFaultArg::ImmediateAck => SinkFaultMode::ImmediateAck,
            SinkFaultArg::BatchedAck => SinkFaultMode::BatchedAck { batch: 32 },
            SinkFaultArg::DelayedAck => SinkFaultMode::DelayedAck { delay_ms: 10 },
            SinkFaultArg::Reject => SinkFaultMode::Reject,
            SinkFaultArg::Drop => SinkFaultMode::Drop,
            SinkFaultArg::CorruptResponse => SinkFaultMode::CorruptResponse,
            SinkFaultArg::Throttle => SinkFaultMode::Throttle { delay_us: 100 },
            SinkFaultArg::Disconnect => SinkFaultMode::Disconnect {
                after_requests: 100,
            },
        }
    }

    const fn label(self) -> &'static str {
        match self {
            SinkFaultArg::NoAck => "no-ack",
            SinkFaultArg::ImmediateAck => "immediate-ack",
            SinkFaultArg::BatchedAck => "batched-ack",
            SinkFaultArg::DelayedAck => "delayed-ack",
            SinkFaultArg::Reject => "reject",
            SinkFaultArg::Drop => "drop",
            SinkFaultArg::CorruptResponse => "corrupt-response",
            SinkFaultArg::Throttle => "throttle",
            SinkFaultArg::Disconnect => "disconnect",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "market-loadgen-campaign",
    version,
    about = "DexOS load driver (simulation by default; --measured uses the target socket)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Target node address. Used only with `--measured`; retained as provenance
    /// in simulation reports.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:9000")]
    target: String,
    /// Number of simulated users / persistent sessions (across all regions).
    #[arg(long, default_value_t = 1000)]
    users: u64,
    /// Number of distinct markets to spread load across.
    #[arg(long = "market-count", default_value_t = 1)]
    market_count: u32,
    /// Explicit market ID. Repeat for every market in a live plan.
    #[arg(long = "market-id")]
    market_ids: Vec<u32>,
    /// Aggregate order submission rate.
    #[arg(long = "orders-per-second", default_value_t = 1000)]
    orders_per_second: u64,
    /// Fraction of orders that are cancels, in [0.0, 1.0].
    #[arg(long = "cancel-ratio", default_value_t = 0.0)]
    cancel_ratio: f64,
    /// Explicit fraction of actions that replace live orders.
    #[arg(long = "replace-ratio", default_value_t = 0.0)]
    replace_ratio: f64,
    /// Explicit fraction of actions that submit new orders. Supplying this enables
    /// the production three-way ratio contract; all three values must total 1.0.
    #[arg(long = "new-ratio")]
    new_ratio: Option<f64>,
    /// Run duration, e.g. `60s`, `500ms`, `5m`.
    #[arg(long, value_parser = parse_duration, default_value = "60s")]
    duration: Duration,
    /// Warm-up before steady-state measurement.
    #[arg(long, value_parser = parse_duration, default_value = "0s")]
    warm_up: Duration,
    /// Bounded shutdown drain timeout.
    #[arg(long, value_parser = parse_duration, default_value = "10s")]
    drain_timeout: Duration,
    /// Cool-down/final snapshot phase.
    #[arg(long, value_parser = parse_duration, default_value = "0s")]
    cool_down: Duration,
    /// Number of regions to spread users across (first is same-region).
    #[arg(long, default_value_t = 1)]
    regions: u32,
    /// Explicit source IPv4/IPv6 address. Repeat to form the local source pool.
    #[arg(long = "source-ip")]
    source_ips: Vec<String>,
    /// Persistent connections opened per endpoint/source-IP pair.
    #[arg(long, default_value_t = 1)]
    connections_per_source_ip: u32,
    /// Fixed data-plane worker count.
    #[arg(long, default_value_t = 1)]
    workers: u16,
    /// Fixed bounded request queue capacity.
    #[arg(long, default_value_t = 1024)]
    queue_capacity: usize,
    /// Maximum correlated in-flight requests per connection.
    #[arg(long, default_value_t = 1)]
    in_flight_per_connection: u32,
    /// Bounded reconnect attempts after a transport failure.
    #[arg(long, default_value_t = 5)]
    reconnect_attempts: u16,
    /// Initial reconnect backoff in milliseconds.
    #[arg(long, default_value_t = 10)]
    reconnect_base_delay_ms: u64,
    /// Maximum reconnect backoff in milliseconds.
    #[arg(long, default_value_t = 1000)]
    reconnect_max_delay_ms: u64,
    /// Base of the disjoint client-ID namespace.
    #[arg(long, default_value_t = 0)]
    client_id_base: u64,
    /// Initial nonce in each client namespace.
    #[arg(long, default_value_t = 0)]
    nonce_base: u64,
    /// Stable agent identifier used by reports and RNG partitioning.
    #[arg(long, default_value = "local")]
    agent_id: String,
    /// Require TLS 1.3 for the CLI target.
    #[arg(long)]
    tls: bool,
    /// Expected certificate DNS identity.
    #[arg(long, default_value = "")]
    tls_server_name: String,
    /// PEM trust-root file.
    #[arg(long, default_value = "")]
    tls_ca_file: String,
    /// PEM client certificate for mTLS.
    #[arg(long, default_value = "")]
    mtls_cert_file: String,
    /// PKCS#8 client private key for mTLS (redacted in resolved output).
    #[arg(long, default_value = "")]
    mtls_key_file: String,
    /// Funded account ID for a validator run.
    #[arg(long)]
    account_id: Option<u64>,
    /// Account/session signing-key file (redacted in resolved output).
    #[arg(long, default_value = "")]
    signing_key_file: String,
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
    #[arg(long, value_name = "PATH", global = true)]
    scenario: Option<PathBuf>,
    /// Validate and print the fully resolved plan without opening sockets. Secret
    /// material references are redacted.
    #[arg(long, global = true)]
    dry_run: bool,
    /// Drive the real target over a live socket and measure it. An unreachable
    /// target exits nonzero, and submitted commands are reconciled against server
    /// receipts. Without this flag the run is a labelled deterministic *simulation*.
    #[arg(long)]
    measured: bool,
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
    let (mode, role, controller_address) = command_mode(cli.command.as_ref());
    let target_kind = match mode {
        RunMode::Sink => TargetKind::ReferenceSink,
        RunMode::Validator | RunMode::Simulate => TargetKind::Validator,
    };
    for i in 0..region_count {
        let cross = i > 0;
        // Give the last region any rounding remainder.
        let users = if i + 1 == region_count {
            total - per_region * u64::from(region_count - 1)
        } else {
            per_region
        };
        let source_ips = cli
            .source_ips
            .iter()
            .enumerate()
            .filter(|(index, _)| u32::try_from(*index).unwrap_or(u32::MAX) % region_count == i)
            .map(|(_, source)| source.clone())
            .collect::<Vec<_>>();
        let endpoints = if mode == RunMode::Simulate {
            Vec::new()
        } else {
            vec![EndpointConfig {
                name: format!("region-{i}-target"),
                address: cli.target.clone(),
                weight: 1,
                connections_per_source_ip: cli.connections_per_source_ip,
                target_kind,
                tls: TlsClientConfig {
                    enabled: cli.tls,
                    server_name: cli.tls_server_name.clone(),
                    ca_file: cli.tls_ca_file.clone(),
                    client_cert_file: cli.mtls_cert_file.clone(),
                    client_key_file: cli.mtls_key_file.clone(),
                },
            }]
        };
        regions.push(RegionConfig {
            name: format!("region-{i}"),
            users: u32::try_from(users.min(u64::from(u32::MAX))).unwrap_or(u32::MAX),
            cross_region: cross,
            base_latency_us: if cross { 4_000 } else { 200 },
            jitter_us: if cross { 300 } else { 50 },
            clock_offset_us: 0,
            source_ips,
            endpoints,
        });
    }

    let operation_mix = cli.new_ratio.map(|new| OperationMix {
        new: ratio_from_unit_f64(new),
        cancel: ratio_from_unit_f64(cli.cancel_ratio),
        replace: ratio_from_unit_f64(cli.replace_ratio),
    });
    let accounts = cli.account_id.map_or_else(Vec::new, |account_id| {
        vec![AccountMaterial {
            account_id,
            signing_key_file: cli.signing_key_file.clone(),
            session_public_key_file: String::new(),
            token_file: String::new(),
        }]
    });

    LoadScenario {
        schema_version: if mode == RunMode::Simulate { 1 } else { 2 },
        mode,
        role,
        seed: cli.seed,
        target: cli.target.clone(),
        regions,
        market_count: cli.market_count.max(1),
        market_ids: cli.market_ids.clone(),
        orders_per_second: cli.orders_per_second,
        cancel_ratio: ratio_from_unit_f64(cli.cancel_ratio),
        replace_ratio: ratio_from_unit_f64(cli.replace_ratio),
        operation_mix,
        duration_secs: cli.duration.as_secs(),
        warm_up_secs: cli.warm_up.as_secs(),
        drain_timeout_secs: cli.drain_timeout.as_secs(),
        cool_down_secs: cli.cool_down.as_secs(),
        worker_count: cli.workers,
        connection_queue_capacity: cli.queue_capacity,
        in_flight_per_connection: cli.in_flight_per_connection,
        reconnect_max_attempts: cli.reconnect_attempts,
        reconnect_base_delay_ms: cli.reconnect_base_delay_ms,
        reconnect_max_delay_ms: cli.reconnect_max_delay_ms,
        client_id_base: cli.client_id_base,
        nonce_base: cli.nonce_base,
        agent_id: cli.agent_id.clone(),
        controller_address,
        accounts,
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

fn command_mode(command: Option<&Command>) -> (RunMode, RunRole, String) {
    match command {
        None | Some(Command::Simulate) => (RunMode::Simulate, RunRole::Local, String::new()),
        Some(Command::Local { target_kind }) => {
            (live_mode(*target_kind), RunRole::Local, String::new())
        }
        Some(Command::Agent {
            controller,
            target_kind,
        }) => (live_mode(*target_kind), RunRole::Agent, controller.clone()),
        Some(Command::Controller { target_kind }) => {
            (live_mode(*target_kind), RunRole::Controller, String::new())
        }
        Some(Command::ReferenceSink { .. }) => (RunMode::Simulate, RunRole::Local, String::new()),
    }
}

const fn live_mode(target: LiveTarget) -> RunMode {
    match target {
        LiveTarget::Validator => RunMode::Validator,
        LiveTarget::Sink => RunMode::Sink,
    }
}

fn apply_command_override(command: Option<&Command>, scenario: &mut LoadScenario) {
    let Some(command) = command else { return };
    let (mode, role, controller) = command_mode(Some(command));
    scenario.mode = mode;
    scenario.role = role;
    if role == RunRole::Agent {
        scenario.controller_address = controller;
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start Tokio runtime: {error}"))
}

fn runtime_for_scenario(scenario: &LoadScenario) -> Result<tokio::runtime::Runtime, String> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(usize::from(scenario.worker_count))
        .enable_all();
    if !scenario.cpu_affinity.is_empty() {
        let available = core_affinity::get_core_ids()
            .ok_or_else(|| "cannot enumerate CPU cores for requested affinity".to_string())?;
        for requested in &scenario.cpu_affinity {
            if !available
                .iter()
                .any(|core| core.id == usize::from(*requested))
            {
                return Err(format!(
                    "requested CPU affinity core {requested} is unavailable"
                ));
            }
        }
        let cpus = scenario
            .cpu_affinity
            .iter()
            .map(|cpu| core_affinity::CoreId {
                id: usize::from(*cpu),
            })
            .collect::<Vec<_>>();
        let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        builder.on_thread_start(move || {
            let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % cpus.len();
            let _ = core_affinity::set_for_current(cpus[index]);
        });
    }
    builder
        .build()
        .map_err(|error| format!("cannot start configured Tokio runtime: {error}"))
}

fn load_protocol_adapter(scenario: &LoadScenario) -> Result<ProtocolAdapter, String> {
    if scenario.mode == RunMode::Sink && scenario.accounts.is_empty() {
        let word = scenario.seed.to_le_bytes();
        let mut seed = [0u8; 32];
        for chunk in seed.chunks_exact_mut(8) {
            chunk.copy_from_slice(&word);
        }
        return Ok(ProtocolAdapter::new(
            types::AccountId::new(0),
            crypto::KeyPair::from_seed(&seed),
            scenario.client_id_base,
            None,
        ));
    }
    let account = scenario
        .accounts
        .first()
        .ok_or_else(|| "validator mode requires an account".to_string())?;
    let account_id = u32::try_from(account.account_id)
        .map_err(|_| format!("account_id {} exceeds u32", account.account_id))?;
    let bytes = std::fs::read(&account.signing_key_file)
        .map_err(|error| format!("cannot read signing key: {error}"))?;
    let seed = if bytes.len() == 32 {
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "invalid key length".to_string())?
    } else {
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| {
                "signing key must be 32 raw bytes or 64 hexadecimal characters".to_string()
            })?
            .trim();
        let decoded =
            hex::decode(text).map_err(|error| format!("invalid hex signing key: {error}"))?;
        <[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| "hex signing key must decode to exactly 32 bytes".to_string())?
    };
    Ok(ProtocolAdapter::new(
        types::AccountId::new(account_id),
        crypto::KeyPair::from_seed(&seed),
        scenario.client_id_base,
        None,
    ))
}

fn run_reference_sink_command(
    listen: &str,
    fault: SinkFaultArg,
    shutdown_after: Option<Duration>,
    validate_signatures: bool,
    tls_cert_file: Option<&std::path::Path>,
    tls_key_file: Option<&std::path::Path>,
    client_ca_file: Option<&std::path::Path>,
) -> ExitCode {
    let tls_acceptor = match (tls_cert_file, tls_key_file) {
        (Some(certificate), Some(private_key)) => match reference_sink_tls_acceptor(
            &certificate.to_string_lossy(),
            &private_key.to_string_lossy(),
            client_ca_file
                .map(std::path::Path::to_string_lossy)
                .as_deref(),
        ) {
            Ok(acceptor) => Some(acceptor),
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::FAILURE;
            }
        },
        (None, None) => None,
        _ => {
            eprintln!("error: --tls-cert-file and --tls-key-file must be supplied together");
            return ExitCode::FAILURE;
        }
    };
    let transport = if tls_acceptor.is_some() {
        "tls13"
    } else {
        "dev-plaintext"
    };
    let runtime = match runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        let bound = listener.local_addr()?;
        eprintln!(
            "note: reference-sink-test-only listening on {bound}; results are NOT validator capacity"
        );
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let sink_config = ReferenceSinkConfig {
                fault: fault.into_mode(),
                validate_signatures,
                ..ReferenceSinkConfig::default()
            };
        let server = tokio::spawn(async move {
            if let Some(acceptor) = tls_acceptor {
                serve_reference_sink_tls(listener, sink_config, acceptor, stop_rx).await
            } else {
                serve_reference_sink(listener, sink_config, stop_rx).await
            }
        });
        match shutdown_after {
            Some(duration) => tokio::time::sleep(duration).await,
            None => {
                shutdown_signal().await?;
            }
        }
        let _ = stop_tx.send(true);
        let counters = server
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok::<_, std::io::Error>((counters.snapshot(), counters.processing_latency()))
    }) {
        Ok((snapshot, processing_latency)) => {
            println!(
                "{{\"mode\":\"{}\",\"transport\":\"{}\",\"fault\":\"{}\",\"signature_validation\":{},\
                 \"received\":{},\"acknowledged\":{},\"rejected\":{},\
                 \"new_orders\":{},\"cancels\":{},\"replaces\":{},\"malformed\":{},\
                 \"transport_errors\":{},\"connections\":{},\"histogram_merge_errors\":{},\
                 \"processing_latency\":{}}}",
                snapshot.mode,
                transport,
                fault.label(),
                validate_signatures,
                snapshot.received,
                snapshot.acknowledged,
                snapshot.rejected,
                snapshot.new_orders,
                snapshot.cancels,
                snapshot.replaces,
                snapshot.malformed,
                snapshot.transport_errors,
                snapshot.connections,
                snapshot.histogram_merge_errors,
                sink_histogram_report_json(&processing_latency),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: reference sink failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn sink_histogram_report_json(report: &SinkHistogramReport) -> String {
    let raw = report
        .raw
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"max_trackable_ns\":{},\"count\":{},\"p50\":{},\"p95\":{},\"p99\":{},\"p999\":{},\"max\":{},\"saturated\":{},\"overflow\":{},\"raw\":[{}]}}",
        report.max_trackable_ns,
        report.summary.count,
        report.summary.p50,
        report.summary.p95,
        report.summary.p99,
        report.summary.p999,
        report.summary.max,
        report.summary.saturated,
        report.summary.overflow,
        raw,
    )
}

fn write_live_artifacts(
    scenario: &LoadScenario,
    report: &LiveReport,
    final_json: &str,
) -> Result<(), String> {
    let mut directory = scenario.output.directory.clone();
    match scenario.role {
        RunRole::Local => {}
        RunRole::Agent => directory.push_str(&format!("/agent-{}", safe_name(&scenario.agent_id))),
        RunRole::Controller => directory.push_str("/controller"),
    }
    let directory = std::path::Path::new(&directory);
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("cannot create artifact directory: {error}"))?;
    let resolved = scenario
        .to_redacted_toml()
        .map_err(|error| format!("cannot redact resolved scenario: {error}"))?;
    let scenario_hash = loadgen::util::fnv1a_64(resolved.as_bytes());
    std::fs::write(directory.join("resolved-plan.toml"), &resolved)
        .map_err(|error| format!("cannot write resolved plan: {error}"))?;
    std::fs::write(directory.join("final.json"), format!("{final_json}\n"))
        .map_err(|error| format!("cannot write final report: {error}"))?;
    if scenario.output.interval_jsonl {
        let mut jsonl = String::new();
        for interval in &report.interval_reports {
            jsonl.push_str(&interval.to_json());
            jsonl.push('\n');
        }
        std::fs::write(directory.join("intervals.jsonl"), jsonl)
            .map_err(|error| format!("cannot write interval report: {error}"))?;
    }
    let queue_buckets = report
        .queue_delay_raw
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let ack_buckets = report
        .request_to_ack_raw
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let action_queue = action_histograms_json(&report.action_queue_delay);
    let action_ack = action_histograms_json(&report.action_request_to_ack);
    let dimensions = report
        .dimensions
        .iter()
        .map(|dimension| {
            format!(
                "{{\"region\":\"{}\",\"endpoint\":\"{}\",\"queue_delay\":{},\"request_to_ack\":{}}}",
                json_escape(&dimension.region),
                json_escape(&dimension.endpoint),
                histogram_report_json(&dimension.queue_delay),
                histogram_report_json(&dimension.request_to_ack),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(
        directory.join("histograms.json"),
        format!(
            "{{\"max_trackable_ns\":{},\"queue_delay\":[{}],\"request_to_ack\":[{}],\"action_queue_delay\":{},\"action_request_to_ack\":{},\"dimensions\":[{}]}}\n",
            report.histogram_max_trackable_ns,
            queue_buckets,
            ack_buckets,
            action_queue,
            action_ack,
            dimensions,
        ),
    )
    .map_err(|error| format!("cannot write raw histograms: {error}"))?;
    let commit = command_output("git", &["rev-parse", "HEAD"]);
    let rustc = command_output("rustc", &["--version", "--verbose"]);
    let uname = command_output("uname", &["-a"]);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let topology = scenario
        .regions
        .iter()
        .map(|region| {
            let sources = region
                .source_ips
                .iter()
                .map(|source| format!("\"{}\"", json_escape(source)))
                .collect::<Vec<_>>()
                .join(",");
            let endpoints = region
                .endpoints
                .iter()
                .map(|endpoint| {
                    format!(
                        "{{\"name\":\"{}\",\"address\":\"{}\",\"weight\":{},\"connections_per_source_ip\":{}}}",
                        json_escape(&endpoint.name),
                        json_escape(&endpoint.address),
                        endpoint.weight,
                        endpoint.connections_per_source_ip,
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"region\":\"{}\",\"source_ips\":[{}],\"endpoints\":[{}]}}",
                json_escape(&region.name),
                sources,
                endpoints,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let cpu_affinity = scenario
        .cpu_affinity
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let provenance = format!(
        "{{\"unix_seconds\":{},\"scenario_hash_fnv1a64\":\"{:016x}\",\"seed\":{},\"commit\":\"{}\",\"version\":\"{}\",\"rustc\":\"{}\",\"host\":\"{}\",\"role\":\"{:?}\",\"agent_id\":\"{}\",\"clock_method\":\"{:?}\",\"clock_uncertainty_ns\":{},\"phase_seconds\":{{\"warmup\":{},\"steady\":{},\"drain\":{},\"cooldown\":{}}},\"release_build\":{},\"target_arch\":\"{}\",\"target_os\":\"{}\",\"cpu_affinity\":[{}],\"connections\":{},\"topology\":[{}]}}\n",
        timestamp,
        scenario_hash,
        scenario.seed,
        json_escape(&commit),
        env!("CARGO_PKG_VERSION"),
        json_escape(&rustc),
        json_escape(&uname),
        scenario.role,
        json_escape(&scenario.agent_id),
        scenario.clock_method,
        scenario.clock_uncertainty_ns,
        scenario.warm_up_secs,
        scenario.duration_secs,
        scenario.drain_timeout_secs,
        scenario.cool_down_secs,
        !cfg!(debug_assertions),
        std::env::consts::ARCH,
        std::env::consts::OS,
        cpu_affinity,
        scenario.total_connections(),
        topology,
    );
    std::fs::write(directory.join("provenance.json"), provenance)
        .map_err(|error| format!("cannot write provenance: {error}"))?;
    Ok(())
}

fn write_distributed_agent_intervals(
    scenario: &LoadScenario,
    report: &DistributedRunReport,
) -> Result<(), String> {
    if !scenario.output.interval_jsonl {
        return Ok(());
    }
    let root = std::path::Path::new(&scenario.output.directory)
        .join("controller")
        .join("agents");
    for (agent, agent_report) in &report.agents {
        let directory = root.join(safe_name(agent));
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("cannot create agent interval directory: {error}"))?;
        let mut jsonl = String::new();
        for interval in &agent_report.interval_reports {
            jsonl.push_str(&interval.to_json());
            jsonl.push('\n');
        }
        std::fs::write(directory.join("intervals.jsonl"), jsonl)
            .map_err(|error| format!("cannot write agent interval report: {error}"))?;
    }
    Ok(())
}

fn histogram_report_json(report: &HistogramReport) -> String {
    let raw = report
        .raw
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"max_trackable_ns\":{},\"count\":{},\"p50\":{},\"p95\":{},\"p99\":{},\"p999\":{},\"max\":{},\"saturated\":{},\"overflow\":{},\"raw\":[{}]}}",
        report.max_trackable_ns,
        report.summary.count,
        report.summary.p50,
        report.summary.p95,
        report.summary.p99,
        report.summary.p999,
        report.summary.max,
        report.summary.saturated,
        report.summary.overflow,
        raw,
    )
}

fn action_histograms_json(report: &ActionLatencyReport) -> String {
    format!(
        "{{\"new\":{},\"cancel\":{},\"replace\":{}}}",
        histogram_report_json(&report.new_order),
        histogram_report_json(&report.cancel),
        histogram_report_json(&report.replace),
    )
}

fn command_output(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn safe_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn emit_human_report(scenario: &LoadScenario, report: &LiveReport) {
    if !scenario.output.human {
        return;
    }
    eprintln!(
        "loadgen final offered={} written={} acknowledged={} p99_ns={} interrupted={}",
        report.counters.offered,
        report.counters.socket_written,
        report.counters.acknowledged,
        report.request_to_ack.p99,
        report.interrupted,
    );
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(Command::ReferenceSink {
        listen,
        fault,
        shutdown_after,
        skip_signature_validation,
        tls_cert_file,
        tls_key_file,
        client_ca_file,
    }) = &cli.command
    {
        return run_reference_sink_command(
            listen,
            *fault,
            *shutdown_after,
            !skip_signature_validation,
            tls_cert_file.as_deref(),
            tls_key_file.as_deref(),
            client_ca_file.as_deref(),
        );
    }

    let mut scenario = match &cli.scenario {
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

    apply_command_override(cli.command.as_ref(), &mut scenario);

    if let Err(err) = scenario.validate() {
        eprintln!("error: {err}");
        return ExitCode::FAILURE;
    }

    if cli.dry_run {
        return match scenario.to_redacted_toml() {
            Ok(plan) => {
                println!("{plan}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: cannot render resolved plan: {err}");
                ExitCode::FAILURE
            }
        };
    }

    if cli.measured {
        // Live measurement: a real socket to the real target. Unreachable targets and
        // count mismatches fail loudly here instead of yielding a rosy report.
        return match run_measured(&scenario) {
            Ok(report) => {
                println!("{}", report.to_json());
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        };
    }

    if scenario.mode != RunMode::Simulate {
        let runtime = match runtime_for_scenario(&scenario) {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::FAILURE;
            }
        };
        return match scenario.role {
            RunRole::Local | RunRole::Agent => {
                let adapter = match load_protocol_adapter(&scenario) {
                    Ok(adapter) => adapter,
                    Err(error) => {
                        eprintln!("error: {error}");
                        return ExitCode::FAILURE;
                    }
                };
                let result = runtime.block_on(async {
                    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                    tokio::spawn(async move {
                        if shutdown_signal().await.is_ok() {
                            let _ = shutdown_tx.send(true);
                        }
                    });
                    if scenario.role == RunRole::Agent {
                        run_distributed_agent_with_shutdown(&scenario, adapter, shutdown_rx).await
                    } else {
                        let (progress_tx, mut progress_rx) =
                            tokio::sync::mpsc::channel::<IntervalReport>(4);
                        let human = scenario.output.human;
                        let reporter = tokio::spawn(async move {
                            while let Some(interval) = progress_rx.recv().await {
                                if human {
                                    let counters = interval.counters;
                                    eprintln!(
                                        "loadgen second={} offered={} generated={} written={} acknowledged={} accepted={} rejected={} timed_out={} failures={} dropped={} queue_p99_ns={} ack_p99_ns={}",
                                        counters.second,
                                        counters.offered,
                                        counters.generated,
                                        counters.socket_written,
                                        counters.acknowledged,
                                        counters.accepted,
                                        counters.rejected,
                                        counters.timed_out,
                                        counters.failures,
                                        counters.locally_dropped,
                                        interval.queue_delay.summary.p99,
                                        interval.request_to_ack.summary.p99,
                                    );
                                }
                            }
                        });
                        let result = run_local_live_with_progress(
                            &scenario,
                            adapter,
                            shutdown_rx,
                            progress_tx,
                        )
                        .await
                        .map_err(Into::into);
                        let _ = reporter.await;
                        result
                    }
                });
                match result {
                    Ok(report) => {
                        let json = report.to_json();
                        if let Err(error) = write_live_artifacts(&scenario, &report, &json) {
                            eprintln!("error: {error}");
                            return ExitCode::FAILURE;
                        }
                        emit_human_report(&scenario, &report);
                        println!("{json}");
                        if report.passes_thresholds(&scenario) {
                            ExitCode::SUCCESS
                        } else {
                            eprintln!(
                                "error: live run violated a configured threshold or conservation gate"
                            );
                            ExitCode::FAILURE
                        }
                    }
                    Err(error) => {
                        eprintln!("error: live run failed: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            RunRole::Controller => match runtime.block_on(run_distributed_controller(&scenario)) {
                Ok(report) => {
                    let json = report.to_json();
                    if let Err(error) = write_live_artifacts(&scenario, &report.aggregate, &json) {
                        eprintln!("error: {error}");
                        return ExitCode::FAILURE;
                    }
                    if let Err(error) = write_distributed_agent_intervals(&scenario, &report) {
                        eprintln!("error: {error}");
                        return ExitCode::FAILURE;
                    }
                    emit_human_report(&scenario, &report.aggregate);
                    println!("{json}");
                    if report.aggregate.passes_thresholds(&scenario) {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "error: distributed run violated a configured threshold or conservation gate"
                        );
                        ExitCode::FAILURE
                    }
                }
                Err(error) => {
                    eprintln!("error: distributed run failed: {error}");
                    ExitCode::FAILURE
                }
            },
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
            "--market-id",
            "--orders-per-second",
            "--cancel-ratio",
            "--replace-ratio",
            "--new-ratio",
            "--duration",
            "--warm-up",
            "--drain-timeout",
            "--source-ip",
            "--connections-per-source-ip",
            "--workers",
            "--queue-capacity",
            "--in-flight-per-connection",
            "--reconnect-attempts",
            "--tls",
            "--account-id",
            "--signing-key-file",
            "--scenario",
            "--dry-run",
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

    #[test]
    fn measured_run_against_unreachable_target_fails() {
        use loadgen::LoadError;
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
        let err = run_measured(&scenario_from_cli(&cli)).expect_err("unreachable must fail");
        assert!(matches!(err, LoadError::Unreachable { .. }), "{err:?}");
    }

    #[test]
    fn parses_complete_live_sink_surface_and_subcommands() {
        let cli = Cli::try_parse_from([
            "market-loadgen",
            "--target",
            "127.0.0.1:9900",
            "--market-id",
            "7",
            "--market-id",
            "8",
            "--new-ratio",
            "0.7",
            "--cancel-ratio",
            "0.2",
            "--replace-ratio",
            "0.1",
            "--orders-per-second",
            "2000",
            "--duration",
            "2s",
            "--drain-timeout",
            "3s",
            "--source-ip",
            "127.0.0.1",
            "--connections-per-source-ip",
            "4",
            "--workers",
            "2",
            "--in-flight-per-connection",
            "8",
            "--reconnect-attempts",
            "7",
            "--reconnect-base-delay-ms",
            "2",
            "--reconnect-max-delay-ms",
            "20",
            "local",
            "--target-kind",
            "sink",
        ])
        .unwrap();
        let scenario = scenario_from_cli(&cli);
        assert_eq!(scenario.mode, RunMode::Sink);
        assert_eq!(scenario.role, RunRole::Local);
        assert_eq!(scenario.market_ids, [7, 8]);
        assert_eq!(scenario.total_connections(), 4);
        assert_eq!(scenario.reconnect_max_attempts, 7);
        assert!(scenario.validate().is_ok());

        let agent = Cli::try_parse_from([
            "market-loadgen",
            "--scenario",
            "agent.toml",
            "agent",
            "--controller",
            "controller.example:9910",
            "--target-kind",
            "validator",
        ])
        .unwrap();
        assert!(matches!(agent.command, Some(Command::Agent { .. })));
        let sink = Cli::try_parse_from([
            "market-loadgen",
            "reference-sink",
            "--fault",
            "batched-ack",
            "--shutdown-after",
            "1s",
            "--tls-cert-file",
            "sink.pem",
            "--tls-key-file",
            "sink-key.pem",
            "--client-ca-file",
            "client-ca.pem",
        ])
        .unwrap();
        assert!(matches!(sink.command, Some(Command::ReferenceSink { .. })));
        assert!(Cli::try_parse_from([
            "market-loadgen",
            "reference-sink",
            "--tls-cert-file",
            "sink.pem",
        ])
        .is_err());
    }
}
