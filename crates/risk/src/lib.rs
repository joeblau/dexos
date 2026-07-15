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
//! # Rounding and dust policy
//!
//! | Operation | Direction | Rationale |
//! |---|---|---|
//! | Initial/maintenance margin and non-negative fees | toward +infinity | obligations never under-collect |
//! | Notional risk/fee bases | toward +infinity | sub-micro-unit exposure is retained |
//! | Realized/unrealized PnL, funding and scenario payoffs | toward zero | symmetric signed accounting |
//! | Settlement transfers | exact fixed-point units | no implicit dust redistribution |
//!
//! Any positive fractional obligation therefore becomes one micro-unit. Dust is
//! retained by the collecting account; signed economic values never inherit
//! this directed rounding rule.
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

pub use config::{
    MarginMode, OrderPriority, RiskConfig, DEFAULT_MAX_ACCOUNTS, DEFAULT_MAX_MARKETS,
    MAX_ACCOUNT_CAPACITY, MAX_MARKET_CAPACITY,
};
pub use engine::RiskEngine;
pub use error::RiskError;
pub use liquidation::{AdlFill, InsuranceFund, LiquidationOutcome, LiquidationQueue};
pub use position::PerpPosition;
pub use scenario::{
    best_case_scenario_pnl, required_collateral, scenario_values, worst_case_scenario_pnl,
    PayoutPosition,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "risk";

/// Canonical stored-risk transition-root schema.
pub const RISK_TRANSITION_ROOT_SCHEMA_VERSION: u16 = 1;

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
