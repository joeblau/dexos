//! Risk parameters and per-account margin mode.

use serde::{Deserialize, Serialize};
use types::Ratio;

use crate::error::RiskError;

/// Hard ceiling on the account slab capacity an operator may configure.
///
/// It bounds the worst-case dense-column allocation the risk engine can ever be
/// asked to make: the account Structure-of-Arrays grows to at most one slot per
/// admitted identifier, so no configuration — however hostile — can request a
/// multi-billion-element allocation from an out-of-range `u32` id.
pub const MAX_ACCOUNT_CAPACITY: usize = 1 << 24; // 16_777_216

/// Hard ceiling on the market slab capacity an operator may configure.
///
/// Mirrors [`MAX_ACCOUNT_CAPACITY`] for the market-indexed columns
/// (`marks`, `risk_group`, `market_limit`).
pub const MAX_MARKET_CAPACITY: usize = 1 << 20; // 1_048_576

/// Default account slab capacity applied when a config does not specify one.
pub const DEFAULT_MAX_ACCOUNTS: usize = 1 << 20; // 1_048_576

/// Default market slab capacity applied when a config does not specify one.
pub const DEFAULT_MAX_MARKETS: usize = 1 << 16; // 65_536

/// Static risk parameters applied uniformly by the engine.
///
/// The three [`Ratio`] fields (scale `1_000_000` == 1.0) are:
/// * `initial_margin` — fraction of notional required to *open* exposure.
/// * `maintenance_margin` — fraction of notional below which equity triggers
///   liquidation. Must be `<= initial_margin`.
/// * `max_leverage` — cap on `notional / equity`; a value of `10_000_000`
///   means 10x.
///
/// The two capacity fields declare the maximum number of dense account/market
/// slots the engine may allocate. An identifier whose slab index reaches its
/// capacity is rejected before any column is grown, so a sparse external id can
/// never trigger an unbounded allocation. Capacities are validated against the
/// hard resource budget ([`MAX_ACCOUNT_CAPACITY`] / [`MAX_MARKET_CAPACITY`]) at
/// engine construction and by [`RiskConfig::with_capacities`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskConfig {
    /// Initial-margin fraction of notional (open requirement).
    pub initial_margin: Ratio,
    /// Maintenance-margin fraction of notional (liquidation floor).
    pub maintenance_margin: Ratio,
    /// Maximum `notional / equity` leverage.
    pub max_leverage: Ratio,
    /// Maximum number of dense account slots the engine may allocate. An
    /// account id at or beyond this bound is rejected before allocation.
    pub max_accounts: usize,
    /// Maximum number of dense market slots the engine may allocate. A market
    /// id at or beyond this bound is rejected before allocation.
    pub max_markets: usize,
}

impl RiskConfig {
    /// Construct and validate a config with the default dense-slot capacities
    /// ([`DEFAULT_MAX_ACCOUNTS`] / [`DEFAULT_MAX_MARKETS`]).
    ///
    /// Rejects non-positive margins/leverage and a maintenance margin above the
    /// initial margin (which would be economically incoherent). Use
    /// [`RiskConfig::with_capacities`] to override the capacities.
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
            max_accounts: DEFAULT_MAX_ACCOUNTS,
            max_markets: DEFAULT_MAX_MARKETS,
        })
    }

    /// Override the dense-slot capacities, validating each against the engine's
    /// hard resource budget.
    ///
    /// A capacity of zero (which would admit no ids) or one above the ceiling
    /// ([`MAX_ACCOUNT_CAPACITY`] / [`MAX_MARKET_CAPACITY`], which would permit an
    /// unbounded allocation) is rejected with [`RiskError::CapacityConfig`]. This
    /// is the startup gate: a config that passes here can never demand more than
    /// the budgeted amount of dense memory.
    pub fn with_capacities(
        mut self,
        max_accounts: usize,
        max_markets: usize,
    ) -> Result<Self, RiskError> {
        if max_accounts == 0 || max_accounts > MAX_ACCOUNT_CAPACITY {
            return Err(RiskError::CapacityConfig {
                requested: max_accounts,
                budget: MAX_ACCOUNT_CAPACITY,
            });
        }
        if max_markets == 0 || max_markets > MAX_MARKET_CAPACITY {
            return Err(RiskError::CapacityConfig {
                requested: max_markets,
                budget: MAX_MARKET_CAPACITY,
            });
        }
        self.max_accounts = max_accounts;
        self.max_markets = max_markets;
        Ok(self)
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
