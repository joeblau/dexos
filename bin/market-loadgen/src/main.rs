//! `market-loadgen` — the DexOS distributed load generator binary.
//!
//! Parses a load plan — either from CLI flags or a full TOML scenario file — and hands
//! off to the deterministic `loadgen` engine. Argument parsing is total; bad input
//! exits nonzero without panicking. Results are emitted as machine-readable JSON at run
//! end.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use loadgen::{
    ratio_from_unit_f64, run_measured, run_scenario, Adversarial, Impairment, LoadScenario,
    OracleWorkload, RegionConfig,
};

#[derive(Parser, Debug)]
#[command(
    name = "market-loadgen",
    version,
    about = "DexOS distributed load generator"
)]
struct Cli {
    /// Target node address.
    #[arg(long, value_name = "ADDR")]
    target: String,
    /// Number of simulated users / persistent sessions (across all regions).
    #[arg(long, default_value_t = 1000)]
    users: u64,
    /// Market symbol / count to trade against.
    #[arg(long, default_value = "BTC-PERP")]
    market: String,
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
        target: cli.target.clone(),
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

fn main() -> ExitCode {
    let cli = Cli::parse();

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
            "127.0.0.1:9000",
            "--users",
            "100000",
            "--market",
            "BTC-PERP",
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
            "host:1",
            "--users",
            "500",
            "--market",
            "ETH-PERP",
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
            "--users",
            "--market",
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
    fn missing_target_is_rejected() {
        assert!(Cli::try_parse_from(["market-loadgen"]).is_err());
    }

    #[test]
    fn cli_scenario_runs() {
        let cli = Cli::try_parse_from([
            "market-loadgen",
            "--target",
            "host:1",
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
}
