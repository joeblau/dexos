//! Session-scoped authorization checks applied to lowered [`Command`]s before
//! they reach the engine.

use serde::{Deserialize, Serialize};
use types::Price;

use crate::command::{Command, SessionScope};
use crate::error::RpcError;

/// An authorized session: a delegated key with a bounded [`SessionScope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Session public key.
    pub session_pubkey: [u8; 32],
    /// Authorized scope.
    pub scope: SessionScope,
}

impl Session {
    /// Authorize a command against this session at wall-clock time `now`
    /// (unix millis). Returns a typed [`RpcError`] for every rejection class:
    /// expired session, out-of-scope market, over-notional, over-leverage, and
    /// unauthorized withdrawal.
    pub fn authorize(&self, command: &Command, now: u64) -> Result<(), RpcError> {
        if now > self.scope.expiry {
            return Err(RpcError::SessionExpired);
        }
        match command {
            Command::PlaceOrder {
                market,
                price,
                quantity,
                leverage,
                ..
            } => {
                self.check_market(*market)?;
                self.check_leverage(*leverage)?;
                let notional = price
                    .notional(*quantity)
                    .map_err(|_| RpcError::OverNotional)?;
                if notional > self.scope.max_notional {
                    return Err(RpcError::OverNotional);
                }
                Ok(())
            }
            Command::ReplaceOrder {
                market,
                price,
                quantity,
                ..
            } => {
                self.check_market(*market)?;
                let notional = price
                    .notional(*quantity)
                    .map_err(|_| RpcError::OverNotional)?;
                if notional > self.scope.max_notional {
                    return Err(RpcError::OverNotional);
                }
                Ok(())
            }
            Command::CancelOrder { market, .. } => self.check_market(*market),
            Command::CancelAll { market, .. } => match market {
                Some(m) => self.check_market(*m),
                None => Ok(()),
            },
            Command::StakeMarket { market, .. } => self.check_market(*market),
            Command::Basket { orders, .. } => {
                for order in orders {
                    self.authorize(&order.to_command(), now)?;
                }
                Ok(())
            }
            Command::Withdraw { amount, .. } => {
                if !self.scope.allow_withdrawal {
                    return Err(RpcError::Unauthorized);
                }
                if *amount > self.scope.max_notional {
                    return Err(RpcError::OverNotional);
                }
                Ok(())
            }
            // Account-management commands carry no market/notional scope.
            Command::AuthorizeSession { .. }
            | Command::RevokeSession { .. }
            | Command::BindWallet { .. }
            | Command::CreateMarket { .. } => Ok(()),
        }
    }

    fn check_market(&self, market: types::MarketId) -> Result<(), RpcError> {
        if self.scope.markets.is_empty() || self.scope.markets.contains(&market) {
            Ok(())
        } else {
            Err(RpcError::OutOfScope)
        }
    }

    fn check_leverage(&self, leverage: types::Ratio) -> Result<(), RpcError> {
        if leverage > self.scope.max_leverage {
            Err(RpcError::OverLeverage)
        } else {
            Ok(())
        }
    }
}

/// Whether a session key may subscribe to `account`-scoped private streams.
/// A session is bound to exactly one account at authorization time; the caller
/// supplies that binding.
pub fn session_may_read(
    bound_account: types::AccountId,
    requested_account: types::AccountId,
    session_expiry: u64,
    now: u64,
) -> Result<(), RpcError> {
    if now > session_expiry {
        return Err(RpcError::SessionExpired);
    }
    if bound_account != requested_account {
        return Err(RpcError::Unauthorized);
    }
    Ok(())
}

/// Convenience: notional of a price/quantity pair, saturating to `Amount::MAX`
/// on overflow so callers can compare without a fallible path.
#[inline]
pub fn notional_or_max(price: Price, quantity: types::Quantity) -> types::Amount {
    price.notional(quantity).unwrap_or(types::Amount::MAX)
}
