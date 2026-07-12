//! Session-scoped authorization checks applied to lowered [`Command`]s before
//! they reach the engine, plus a lookup trait for authenticated stream binding.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use types::{AccountId, Price};

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

/// Server-side binding of a session key to exactly one account. Installed by
/// `authorize_session` and consulted by private stream subscription so clients
/// cannot spoof the account binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// Account the session is bound to.
    pub account: AccountId,
    /// Session key and scope.
    pub session: Session,
}

/// Lookup installed sessions by verified public key. Implemented by the live
/// backend (and the test stub); the stream layer never trusts client-supplied
/// account/expiry fields.
pub trait SessionLookup: Send + Sync {
    /// Resolve a session public key to its binding, or `None` if unknown/revoked.
    fn lookup_session(&self, session_pubkey: &[u8; 32]) -> Option<SessionBinding>;
}

/// In-memory session registry shared by the stub backend and the stream hub.
/// Cheap to clone via [`Arc`].
#[derive(Debug, Default, Clone)]
pub struct SessionRegistry {
    inner: Arc<Mutex<HashMap<[u8; 32], SessionBinding>>>,
}

impl SessionRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install (or overwrite) a session binding.
    pub fn insert(&self, account: AccountId, session: Session) {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        g.insert(session.session_pubkey, SessionBinding { account, session });
    }

    /// Revoke a session key. Returns whether one was present.
    pub fn revoke(&self, session_pubkey: &[u8; 32]) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        g.remove(session_pubkey).is_some()
    }

    /// Number of installed sessions (tests / metrics).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SessionLookup for SessionRegistry {
    fn lookup_session(&self, session_pubkey: &[u8; 32]) -> Option<SessionBinding> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(session_pubkey)
            .cloned()
    }
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
            // Session-key management is the account root key's exclusive
            // privilege: a delegated session may never mint a new (possibly
            // broader) session or revoke one, which would otherwise allow a
            // limited key to escalate its own privileges. This is not gated by
            // any scope flag — it is unconditionally denied for sessions.
            Command::AuthorizeSession { .. } | Command::RevokeSession { .. } => {
                Err(RpcError::Unauthorized)
            }
            // Account-administration and market-creation ops are default-deny
            // and require an explicit capability flag on the scope.
            Command::BindWallet { .. } => {
                if self.scope.allow_session_admin {
                    Ok(())
                } else {
                    Err(RpcError::Unauthorized)
                }
            }
            Command::CreateMarket { .. } => {
                if self.scope.allow_market_create {
                    Ok(())
                } else {
                    Err(RpcError::Unauthorized)
                }
            }
        }
    }

    fn check_market(&self, market: types::MarketId) -> Result<(), RpcError> {
        // An empty allow-list denies every market: the wildcard must be granted
        // explicitly via `all_markets`, so an unconfigured scope never trades.
        if self.scope.all_markets || self.scope.markets.contains(&market) {
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
///
/// Prefer [`authorize_private_topic`], which resolves the binding from a
/// server-side registry rather than trusting caller-supplied account/expiry.
pub fn session_may_read(
    bound_account: AccountId,
    requested_account: AccountId,
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

/// Authorize a private stream subscription by looking up `session_pubkey` in
/// `sessions` (server-installed) and checking the topic's owner against the
/// verified binding. Client-supplied account/expiry claims are never consulted.
pub fn authorize_private_topic(
    sessions: &dyn SessionLookup,
    session_pubkey: &[u8; 32],
    topic_account: AccountId,
    now: u64,
) -> Result<SessionBinding, RpcError> {
    let binding = sessions
        .lookup_session(session_pubkey)
        .ok_or(RpcError::Unauthorized)?;
    session_may_read(
        binding.account,
        topic_account,
        binding.session.scope.expiry,
        now,
    )?;
    Ok(binding)
}

/// Convenience: notional of a price/quantity pair, saturating to `Amount::MAX`
/// on overflow so callers can compare without a fallible path.
#[inline]
pub fn notional_or_max(price: Price, quantity: types::Quantity) -> types::Amount {
    price.notional(quantity).unwrap_or(types::Amount::MAX)
}
