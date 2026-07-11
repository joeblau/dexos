//! `loadgen` — distributed load generator engine for DexOS.
//!
//! Drives persistent sessions against a target node with a configurable order mix,
//! cancel ratio, burst pattern, and injected loss/latency, capturing full-path
//! timestamps. Phase 0 ships the configuration surface and a runnable stub; later
//! phases implement the session drivers and measurement pipeline.
//!
//! Not part of the deterministic core, so floating-point knobs (e.g. cancel ratio)
//! are permitted here.

use std::time::Duration;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "loadgen";

/// A parsed, validated load-generation plan.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadConfig {
    /// Target node address.
    pub target: String,
    /// Number of simulated users / persistent sessions.
    pub users: u64,
    /// Market symbol to trade.
    pub market: String,
    /// Aggregate order submission rate.
    pub orders_per_second: u64,
    /// Fraction of orders that are cancels, in `[0.0, 1.0]`.
    pub cancel_ratio: f64,
    /// Total run duration.
    pub duration: Duration,
}

/// Summary of a load run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadReport {
    /// Total orders the plan would submit over its duration.
    pub planned_orders: u64,
}

/// Errors from configuring or running the load generator.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// A configuration value was invalid.
    #[error("invalid load config: {0}")]
    Invalid(String),
    /// The async runtime could not be built.
    #[error("failed to build async runtime: {0}")]
    Runtime(#[source] std::io::Error),
}

impl LoadConfig {
    /// Validate the plan without running it.
    pub fn validate(&self) -> Result<(), LoadError> {
        if !(0.0..=1.0).contains(&self.cancel_ratio) {
            return Err(LoadError::Invalid(format!(
                "cancel_ratio {} must be within [0.0, 1.0]",
                self.cancel_ratio
            )));
        }
        if self.users == 0 {
            return Err(LoadError::Invalid("users must be greater than zero".into()));
        }
        if self.target.is_empty() {
            return Err(LoadError::Invalid("target must not be empty".into()));
        }
        Ok(())
    }

    /// Orders the plan would submit over its duration.
    pub fn planned_orders(&self) -> u64 {
        self.orders_per_second
            .saturating_mul(self.duration.as_secs())
    }
}

/// Build a runtime and run the plan to completion (synchronous entry point).
pub fn run_blocking(config: LoadConfig) -> Result<LoadReport, LoadError> {
    config.validate()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(LoadError::Runtime)?;
    runtime.block_on(async move {
        // Phase 0 stub: report the plan the driver will execute in later phases.
        Ok(LoadReport {
            planned_orders: config.planned_orders(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LoadConfig {
        LoadConfig {
            target: "127.0.0.1:9000".into(),
            users: 100,
            market: "BTC-PERP".into(),
            orders_per_second: 1000,
            cancel_ratio: 0.7,
            duration: Duration::from_secs(60),
        }
    }

    #[test]
    fn planned_orders_is_rate_times_duration() {
        assert_eq!(cfg().planned_orders(), 60_000);
    }

    #[test]
    fn rejects_out_of_range_cancel_ratio() {
        let mut c = cfg();
        c.cancel_ratio = 1.5;
        assert!(c.validate().is_err());
    }

    #[test]
    fn run_blocking_reports_plan() {
        let report = run_blocking(cfg()).unwrap();
        assert_eq!(report.planned_orders, 60_000);
    }
}
