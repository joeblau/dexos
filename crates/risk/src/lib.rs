//! `risk` — fixed-point risk & margin engine.
//!
//! Part of the DexOS decentralized market operating system and its
//! deterministic execution core: no async runtime, no networking, no floating
//! point, fixed-point integers only. Every fallible operation returns a typed
//! [`RiskError`]; nothing panics on adversarial input.
//!
//! The engine covers both **scalar perpetual** exposure (signed quantity at a
//! mark price, average-entry PnL accounting) and **payout-vector**
//! (multi-outcome) exposure (worst-case scenario collateral over a
//! [`types::PayoutVector`]).
//!
//! # Cached Structure-of-Arrays state
//!
//! [`RiskEngine`] keeps each cached risk scalar in its own contiguous column so
//! the liquidation scan streams dense arrays. Mutations update exactly one
//! account incrementally; [`RiskEngine::recompute_all`] is the batch reference
//! the incremental path is proven equal to.
//!
//! # Margin & liquidation waterfall
//!
//! Isolated or cross (risk-group-netted) margin, per-market and portfolio
//! notional caps, an allocation-free [`RiskEngine::check_order`] pre-trade gate,
//! a maintenance-margin liquidation scan and FIFO queue, an
//! [`InsuranceFund`], and socialized loss as the explicit final fallback drawn
//! only after the fund is exhausted.
#![forbid(unsafe_code)]

mod config;
mod engine;
mod error;
mod liquidation;
mod math;
mod position;
mod scenario;

pub use config::{MarginMode, OrderPriority, RiskConfig};
pub use engine::RiskEngine;
pub use error::RiskError;
pub use liquidation::{InsuranceFund, LiquidationOutcome, LiquidationQueue};
pub use position::PerpPosition;
pub use scenario::{
    best_case_scenario_pnl, required_collateral, scenario_values, worst_case_scenario_pnl,
    PayoutPosition,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "risk";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "risk");
    }

    /// Guard test: the deterministic risk modules contain no floating-point
    /// types. The needles are constructed at runtime so this test file does not
    /// trip its own scan.
    #[test]
    fn no_floating_point_in_source() {
        let f = 'f';
        let needle32 = format!("{f}32");
        let needle64 = format!("{f}64");
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut checked = 0usize;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            assert!(
                !src.contains(&needle32),
                "found {needle32} in {}",
                path.display()
            );
            assert!(
                !src.contains(&needle64),
                "found {needle64} in {}",
                path.display()
            );
            checked += 1;
        }
        assert!(checked >= 6, "expected to scan every risk module");
    }
}
