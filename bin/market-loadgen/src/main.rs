//! `market-loadgen` — the DexOS distributed load generator binary.
//!
//! Parses a load plan and hands off to the `loadgen` engine, which owns its own
//! runtime. Argument parsing is total; bad input exits nonzero without panicking.

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use loadgen::{run_blocking, LoadConfig};

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
    /// Number of simulated users / persistent sessions.
    #[arg(long, default_value_t = 1000)]
    users: u64,
    /// Market symbol to trade.
    #[arg(long, default_value = "BTC-PERP")]
    market: String,
    /// Aggregate order submission rate.
    #[arg(long = "orders-per-second", default_value_t = 1000)]
    orders_per_second: u64,
    /// Fraction of orders that are cancels, in [0.0, 1.0].
    #[arg(long = "cancel-ratio", default_value_t = 0.0)]
    cancel_ratio: f64,
    /// Run duration, e.g. `60s`, `500ms`, `5m`.
    #[arg(long, value_parser = parse_duration, default_value = "60s")]
    duration: Duration,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = LoadConfig {
        target: cli.target,
        users: cli.users,
        market: cli.market,
        orders_per_second: cli.orders_per_second,
        cancel_ratio: cli.cancel_ratio,
        duration: cli.duration,
    };
    match run_blocking(config) {
        Ok(report) => {
            println!(
                "load plan accepted: {} orders planned [Phase 0 stub — session drivers land in the loadgen epic]",
                report.planned_orders
            );
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
}
