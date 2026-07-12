//! `loadgen` — deterministic distributed load-generator engine for DexOS.
//!
//! The crate drives a configurable population of virtual users across multiple regions
//! against a target node, with a tunable order mix, cancel/replace ratio, burst
//! pattern, network impairment (loss, duplication, reordering, latency), adversarial
//! frame injection, oracle-update and market-data workloads, and clock-synchronised
//! full-path timestamping.
//!
//! The core planning and measurement logic is **synchronous and deterministic**: every
//! stochastic decision comes from a seeded [`Lcg`], so two runs with the same
//! [`LoadScenario`] produce a bit-identical command sequence and equivalent aggregate
//! latency percentiles. This makes runs reproducible in tests and CI without pulling in
//! `rand`, `criterion`, or an async runtime.
//!
//! # Layout
//! - [`config`] — the [`LoadConfig`]/[`LoadScenario`] surface and TOML parsing.
//! - [`command`] — virtual-user sessions and generated commands.
//! - [`timing`] — the ten-stage full-path timestamp pipeline.
//! - [`metrics`] — fixed-capacity sampling and integer percentile aggregation.
//! - [`impairment`] — network-impairment and adversarial-frame injection.
//! - [`workload`] — oracle-update and market-data subscriber drivers.
//! - [`engine`] — the deterministic **simulation** runner and [`LoadReport`].
//! - [`measured`] — the real, socket-backed **measured mode** ([`run_measured`]),
//!   which connects to the target, times real round trips, and reconciles counts
//!   against server receipts. Unlike the simulation, an unreachable target fails.
//!
//! `loadgen` is not part of the deterministic execution core, so the CLI-facing
//! [`LoadConfig::cancel_ratio`] is an `f64`; it is converted once to a fixed-point
//! [`types::Ratio`] at the configuration boundary and the engine is integer-only
//! thereafter.

pub mod command;
pub mod config;
pub mod engine;
pub mod impairment;
pub mod measured;
pub mod metrics;
pub mod rng;
pub mod timing;
pub mod util;
pub mod workload;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "loadgen";

pub use command::{CommandKind, GeneratedCommand, SessionState};
pub use config::{
    ratio_from_unit_f64, Adversarial, BurstKind, BurstPattern, ClockMethod, ConfigError,
    Impairment, LoadConfig, LoadScenario, MarketDataWorkload, OracleWorkload, OrderMix,
    RegionConfig,
};
pub use engine::{run_blocking, run_scenario, LoadError, LoadReport, RegionReport, SyncBarrier};
pub use impairment::{AdversarialGenerator, DedupSet, Impairer, PacketDisposition};
pub use measured::{
    decode_submit, receipt_frame, run_measured, submit_frame, MeasuredReport, MSG_RECEIPT,
    MSG_RECONCILE, MSG_RECONCILE_ACK, MSG_SUBMIT,
};
pub use metrics::{percentile_permille, Percentiles, SampleSet};
pub use rng::Lcg;
pub use timing::{ClockStamp, FullPathTimestamps, Stage, TimingError, STAGE_COUNT};
pub use workload::{
    oracle_outranks_orders, oracle_update_count, oracle_update_time_ns, SubscriberState,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "loadgen");
    }

    #[test]
    fn end_to_end_smoke() {
        let scenario = LoadScenario {
            seed: 7,
            orders_per_second: 200,
            duration_secs: 3,
            ..LoadScenario::default()
        };
        let report = run_scenario(&scenario).unwrap();
        assert_eq!(report.planned_orders, 600);
        assert!(report.end_to_end.count > 0);
        assert!(!report.to_json().is_empty());
    }

    /// Deterministic LCG-driven property test: for a corpus of random scenarios, two
    /// runs with the same scenario are always bit-identical, and reports never panic.
    #[test]
    fn property_reproducible_over_random_corpus() {
        let mut r = Lcg::new(0x5EED_1234);
        for _ in 0..64 {
            let scenario = LoadScenario {
                seed: r.next_u64(),
                orders_per_second: r.below(1000),
                duration_secs: 1 + r.below(5),
                market_count: 1 + u32::try_from(r.below(8)).unwrap_or(0),
                cancel_ratio: types::Ratio::from_raw(i64::try_from(r.below(500_000)).unwrap_or(0)),
                sample_capacity: 1 + usize::try_from(r.below(2000)).unwrap_or(0),
                ..LoadScenario::default()
            };
            if scenario.validate().is_err() {
                continue;
            }
            let a = run_scenario(&scenario).unwrap();
            let b = run_scenario(&scenario).unwrap();
            assert_eq!(a.command_sequence_hash, b.command_sequence_hash);
            assert_eq!(a.to_json(), b.to_json());
        }
    }
}
