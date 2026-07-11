//! Scoped trading session keys with monotonic-nonce replay protection.

use std::collections::{HashMap, HashSet};

use types::{AccountId, Amount, MarketId};

use crate::error::ExecutionError;

/// A single authorized session key and its scope.
#[derive(Debug, Clone)]
struct Session {
    allowed_markets: Vec<MarketId>,
    max_notional: Amount,
    expires_at: u64,
    nonce_start: u64,
    nonce_end: u64,
    consumed: HashSet<u64>,
}

impl Session {
    fn authorizes_market(&self, market: MarketId) -> bool {
        self.allowed_markets.is_empty() || self.allowed_markets.contains(&market)
    }
}

/// The set of session keys per account.
#[derive(Debug, Clone, Default)]
pub struct SessionRegistry {
    // (account index, session_key) -> Session
    sessions: HashMap<(u32, [u8; 32]), Session>,
}

impl SessionRegistry {
    /// A new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorize (or overwrite) a session key.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &mut self,
        account: AccountId,
        session_key: [u8; 32],
        allowed_markets: Vec<MarketId>,
        max_notional: Amount,
        expires_at: u64,
        nonce_start: u64,
        nonce_end: u64,
    ) -> Result<(), ExecutionError> {
        if max_notional.is_negative() || nonce_end < nonce_start {
            return Err(ExecutionError::BadNonce);
        }
        self.sessions.insert(
            (account.get(), session_key),
            Session {
                allowed_markets,
                max_notional,
                expires_at,
                nonce_start,
                nonce_end,
                consumed: HashSet::new(),
            },
        );
        Ok(())
    }

    /// Revoke a session key. Returns whether one existed.
    pub fn revoke(&mut self, account: AccountId, session_key: [u8; 32]) -> bool {
        self.sessions
            .remove(&(account.get(), session_key))
            .is_some()
    }

    /// Whether a session key exists for the account.
    pub fn contains(&self, account: AccountId, session_key: [u8; 32]) -> bool {
        self.sessions.contains_key(&(account.get(), session_key))
    }

    /// Validate a session action and consume its nonce exactly once. Rejects
    /// expired sessions, unauthorized markets, over-notional orders, and any
    /// out-of-range or replayed nonce — without mutating on rejection.
    pub fn consume(
        &mut self,
        account: AccountId,
        session_key: [u8; 32],
        nonce: u64,
        market: MarketId,
        notional: Amount,
        now: u64,
    ) -> Result<(), ExecutionError> {
        let session = self
            .sessions
            .get_mut(&(account.get(), session_key))
            .ok_or(ExecutionError::UnknownSession)?;
        if now > session.expires_at {
            return Err(ExecutionError::SessionExpired);
        }
        if !session.authorizes_market(market) {
            return Err(ExecutionError::MarketNotAuthorized);
        }
        if notional > session.max_notional {
            return Err(ExecutionError::NotionalExceeded);
        }
        if nonce < session.nonce_start || nonce > session.nonce_end {
            return Err(ExecutionError::BadNonce);
        }
        if !session.consumed.insert(nonce) {
            return Err(ExecutionError::BadNonce);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(i: u32) -> AccountId {
        AccountId::new(i)
    }

    #[test]
    fn authorize_consume_revoke_flow() {
        let mut r = SessionRegistry::new();
        let key = [1u8; 32];
        r.authorize(
            acct(0),
            key,
            vec![],
            Amount::from_raw(1_000_000),
            100,
            0,
            10,
        )
        .unwrap();
        // First use of nonce 5 succeeds.
        assert!(r
            .consume(
                acct(0),
                key,
                5,
                MarketId::new(0),
                Amount::from_raw(500_000),
                50
            )
            .is_ok());
        // Replay of nonce 5 is rejected.
        assert_eq!(
            r.consume(acct(0), key, 5, MarketId::new(0), Amount::from_raw(1), 50),
            Err(ExecutionError::BadNonce)
        );
        // Over-notional rejected.
        assert_eq!(
            r.consume(
                acct(0),
                key,
                6,
                MarketId::new(0),
                Amount::from_raw(2_000_000),
                50
            ),
            Err(ExecutionError::NotionalExceeded)
        );
        // Expired rejected.
        assert_eq!(
            r.consume(acct(0), key, 7, MarketId::new(0), Amount::from_raw(1), 200),
            Err(ExecutionError::SessionExpired)
        );
        // Out-of-range nonce rejected.
        assert_eq!(
            r.consume(acct(0), key, 99, MarketId::new(0), Amount::from_raw(1), 50),
            Err(ExecutionError::BadNonce)
        );
        assert!(r.revoke(acct(0), key));
        assert_eq!(
            r.consume(acct(0), key, 8, MarketId::new(0), Amount::from_raw(1), 50),
            Err(ExecutionError::UnknownSession)
        );
    }

    #[test]
    fn market_scoping() {
        let mut r = SessionRegistry::new();
        let key = [2u8; 32];
        r.authorize(
            acct(0),
            key,
            vec![MarketId::new(1)],
            Amount::from_raw(10),
            100,
            0,
            100,
        )
        .unwrap();
        assert!(r
            .consume(acct(0), key, 0, MarketId::new(1), Amount::ZERO, 1)
            .is_ok());
        assert_eq!(
            r.consume(acct(0), key, 1, MarketId::new(2), Amount::ZERO, 1),
            Err(ExecutionError::MarketNotAuthorized)
        );
    }
}
