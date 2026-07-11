//! Risk parameters and per-account margin mode.

use serde::{Deserialize, Serialize};
use types::Ratio;

use crate::error::RiskError;

/// Static risk parameters applied uniformly by the engine.
///
/// All three fields are [`Ratio`]s (scale `1_000_000` == 1.0):
/// * `initial_margin` — fraction of notional required to *open* exposure.
/// * `maintenance_margin` — fraction of notional below which equity triggers
///   liquidation. Must be `<= initial_margin`.
/// * `max_leverage` — cap on `notional / equity`; a value of `10_000_000`
///   means 10x.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskConfig {
    /// Initial-margin fraction of notional (open requirement).
    pub initial_margin: Ratio,
    /// Maintenance-margin fraction of notional (liquidation floor).
    pub maintenance_margin: Ratio,
    /// Maximum `notional / equity` leverage.
    pub max_leverage: Ratio,
}

impl RiskConfig {
    /// Construct and validate a config.
    ///
    /// Rejects non-positive margins/leverage and a maintenance margin above the
    /// initial margin (which would be economically incoherent).
    pub fn new(
        initial_margin: Ratio,
        maintenance_margin: Ratio,
        max_leverage: Ratio,
    ) -> Result<Self, RiskError> {
        if initial_margin.raw() <= 0
            || maintenance_margin.raw() <= 0
            || max_leverage.raw() <= 0
            || maintenance_margin.raw() > initial_margin.raw()
        {
            return Err(RiskError::NegativeAmount);
        }
        Ok(Self {
            initial_margin,
            maintenance_margin,
            max_leverage,
        })
    }
}

/// How an account's positions share collateral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MarginMode {
    /// Each position is margined on its own gross notional. Exposure is the sum
    /// of absolute per-position notionals.
    #[default]
    Isolated,
    /// Positions net within their risk group before margining. Exposure is the
    /// sum over risk groups of the absolute *net* notional, so a hedged book
    /// requires no more margin than the isolated equivalent, and strictly less
    /// when positions offset.
    Cross,
}

/// Execution priority hint for an order given the account's risk state.
///
/// The matching engine should service [`OrderPriority::RiskReducing`] orders
/// ahead of [`OrderPriority::Normal`] ones so distressed accounts can delever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderPriority {
    /// Order reduces exposure or the account is at/under maintenance margin.
    RiskReducing,
    /// Ordinary exposure-increasing order from a healthy account.
    Normal,
}
