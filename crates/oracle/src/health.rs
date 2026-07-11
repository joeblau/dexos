//! Deterministic oracle health state machine.
//!
//! Health is a pure function of three observable signals — freshness (age of the
//! newest observation), source count (distinct venues), and dispersion (relative
//! MAD) — evaluated against a [`HealthConfig`]. Downstream market behavior
//! branches on the returned [`OracleHealth`]; see [`market_action`].

use types::OracleHealth;

/// Thresholds that drive the health state machine. All ages are nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    /// Newest observation older than this ⇒ at least `Stale`.
    pub stale_age_ns: u64,
    /// Newest observation older than this (or no observations) ⇒ `Halted`.
    pub halt_age_ns: u64,
    /// Distinct sources below this ⇒ at least `Degraded`.
    pub min_sources_normal: u32,
    /// Distinct sources below this ⇒ `Halted`.
    pub min_sources_halt: u32,
    /// Dispersion (bps) above this ⇒ at least `Degraded`.
    pub max_dispersion_bps_normal: i64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            stale_age_ns: 5_000_000_000, // 5s
            halt_age_ns: 30_000_000_000, // 30s
            min_sources_normal: 3,
            min_sources_halt: 1,
            max_dispersion_bps_normal: 100, // 1%
        }
    }
}

/// Observable inputs to the health evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthInputs {
    /// Age of the newest surviving observation, in nanoseconds.
    pub newest_age_ns: u64,
    /// Distinct sources (union `source_mask` popcount).
    pub sources: u32,
    /// Count of surviving observations.
    pub observations: usize,
    /// Relative dispersion in basis points.
    pub dispersion_bps: i64,
}

/// Evaluate health deterministically. The checks are ordered most-severe first
/// so the result is unambiguous.
pub fn evaluate(inputs: HealthInputs, cfg: &HealthConfig) -> OracleHealth {
    if inputs.observations == 0
        || inputs.sources < cfg.min_sources_halt
        || inputs.newest_age_ns > cfg.halt_age_ns
    {
        return OracleHealth::Halted;
    }
    if inputs.newest_age_ns > cfg.stale_age_ns {
        return OracleHealth::Stale;
    }
    if inputs.sources < cfg.min_sources_normal
        || inputs.dispersion_bps > cfg.max_dispersion_bps_normal
    {
        return OracleHealth::Degraded;
    }
    OracleHealth::Normal
}

/// The market-behavior decision implied by an oracle health state. This is the
/// deterministic branch downstream markets take; it keeps the price oracle
/// separate from resolution logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketAction {
    /// Trade normally; the oracle price is authoritative.
    TradeNormally,
    /// Trade with widened risk controls (reduce-only encouraged upstream).
    TradeCautiously,
    /// Freeze new risk; the price is stale but the market is not halted.
    FreezeNewRisk,
    /// Halt the market; the oracle cannot be trusted.
    Halt,
}

/// Map a health state to its canonical market action.
pub const fn market_action(health: OracleHealth) -> MarketAction {
    match health {
        OracleHealth::Normal => MarketAction::TradeNormally,
        OracleHealth::Degraded => MarketAction::TradeCautiously,
        OracleHealth::Stale => MarketAction::FreezeNewRisk,
        OracleHealth::Halted => MarketAction::Halt,
    }
}

/// Stable 1-byte tag for an [`OracleHealth`], used in canonical signing bytes.
pub(crate) const fn health_tag(health: OracleHealth) -> u8 {
    match health {
        OracleHealth::Normal => 0,
        OracleHealth::Degraded => 1,
        OracleHealth::Stale => 2,
        OracleHealth::Halted => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HealthConfig {
        HealthConfig::default()
    }

    fn inputs(age: u64, sources: u32, obs: usize, disp: i64) -> HealthInputs {
        HealthInputs {
            newest_age_ns: age,
            sources,
            observations: obs,
            dispersion_bps: disp,
        }
    }

    #[test]
    fn normal_when_fresh_diverse_tight() {
        assert_eq!(
            evaluate(inputs(1_000_000_000, 3, 5, 10), &cfg()),
            OracleHealth::Normal
        );
    }

    #[test]
    fn degraded_on_low_sources_or_wide_dispersion() {
        assert_eq!(
            evaluate(inputs(1_000_000_000, 2, 5, 10), &cfg()),
            OracleHealth::Degraded
        );
        assert_eq!(
            evaluate(inputs(1_000_000_000, 5, 5, 500), &cfg()),
            OracleHealth::Degraded
        );
    }

    #[test]
    fn stale_when_beyond_stale_age_but_within_halt() {
        assert_eq!(
            evaluate(inputs(6_000_000_000, 5, 5, 10), &cfg()),
            OracleHealth::Stale
        );
    }

    #[test]
    fn halted_on_no_obs_or_no_sources_or_ancient() {
        assert_eq!(evaluate(inputs(0, 3, 0, 0), &cfg()), OracleHealth::Halted);
        assert_eq!(
            evaluate(inputs(1_000_000_000, 0, 5, 10), &cfg()),
            OracleHealth::Halted
        );
        assert_eq!(
            evaluate(inputs(31_000_000_000, 5, 5, 10), &cfg()),
            OracleHealth::Halted
        );
    }

    #[test]
    fn action_mapping_is_total() {
        assert_eq!(
            market_action(OracleHealth::Normal),
            MarketAction::TradeNormally
        );
        assert_eq!(
            market_action(OracleHealth::Degraded),
            MarketAction::TradeCautiously
        );
        assert_eq!(
            market_action(OracleHealth::Stale),
            MarketAction::FreezeNewRisk
        );
        assert_eq!(market_action(OracleHealth::Halted), MarketAction::Halt);
    }
}
