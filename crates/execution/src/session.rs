//! Scoped trading session keys with monotonic-nonce replay protection.

use std::collections::{HashMap, HashSet};

use types::{AccountId, Amount, Hash, MarketId};

use crate::error::ExecutionError;

/// Canonical execution-session transition-root schema.
pub const SESSION_TRANSITION_ROOT_SCHEMA_VERSION: u16 = 1;

/// Fixed-width canonical writer kept local to the session component so its
/// schema can evolve independently from account/market leaf codecs.
#[derive(Default)]
struct TransitionWriter {
    bytes: Vec<u8>,
}

impl TransitionWriter {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn len(&mut self, value: usize) {
        self.u64(u64::try_from(value).expect("usize must fit u64 on supported targets"));
    }
}

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

    /// Canonical commitment to all execution-layer session authorization and
    /// nonce-replay state that can change a future [`Self::consume`] result.
    ///
    /// Hash-map/set layout and insertion order are excluded. Sessions are
    /// sorted by `(account, session_key)`, explicit market scopes are encoded as
    /// semantic sets, and consumed nonces are sorted. The method fail-stops if
    /// private state violates invariants enforced by [`Self::authorize`] and
    /// [`Self::consume`].
    #[must_use]
    pub fn transition_root_v1(&self) -> Hash {
        let mut writer = TransitionWriter::default();
        writer.u16(SESSION_TRANSITION_ROOT_SCHEMA_VERSION);

        let mut sessions: Vec<((u32, [u8; 32]), &Session)> = self
            .sessions
            .iter()
            .map(|(key, session)| (*key, session))
            .collect();
        sessions.sort_unstable_by_key(|(key, _)| *key);
        writer.len(sessions.len());

        for ((account, session_key), session) in sessions {
            assert!(
                !session.max_notional.is_negative(),
                "session maximum notional must be nonnegative"
            );
            assert!(
                session.nonce_start <= session.nonce_end,
                "session nonce range must be ordered"
            );

            writer.u32(account);
            writer.bytes.extend_from_slice(&session_key);

            if session.allowed_markets.is_empty() {
                writer.u8(0); // wildcard: all markets
                writer.len(0);
            } else {
                writer.u8(1); // explicit semantic allow-list
                let mut markets: Vec<u32> = session
                    .allowed_markets
                    .iter()
                    .map(|market| market.get())
                    .collect();
                markets.sort_unstable();
                markets.dedup();
                writer.len(markets.len());
                for market in markets {
                    writer.u32(market);
                }
            }

            writer.i128(session.max_notional.raw());
            writer.u64(session.expires_at);
            writer.u64(session.nonce_start);
            writer.u64(session.nonce_end);

            let mut consumed: Vec<u64> = session.consumed.iter().copied().collect();
            consumed.sort_unstable();
            writer.len(consumed.len());
            for nonce in consumed {
                assert!(
                    (session.nonce_start..=session.nonce_end).contains(&nonce),
                    "consumed nonce must lie inside the authorized range"
                );
                writer.u64(nonce);
            }
        }

        crypto::hash_domain(crypto::DOMAIN_EXECUTION_SESSION_STATE, &writer.bytes)
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

    #[allow(clippy::too_many_arguments)]
    fn registry_with_session(
        account: u32,
        key_byte: u8,
        markets: &[u32],
        max_notional: i128,
        expires_at: u64,
        nonce_start: u64,
        nonce_end: u64,
        consumed: &[u64],
    ) -> SessionRegistry {
        let mut registry = SessionRegistry::new();
        let key = [key_byte; 32];
        registry
            .authorize(
                acct(account),
                key,
                markets.iter().copied().map(MarketId::new).collect(),
                Amount::from_raw(max_notional),
                expires_at,
                nonce_start,
                nonce_end,
            )
            .unwrap();
        let market = markets.first().copied().map_or(0, |value| value);
        for nonce in consumed {
            registry
                .consume(
                    acct(account),
                    key,
                    *nonce,
                    MarketId::new(market),
                    Amount::ZERO,
                    0,
                )
                .unwrap();
        }
        registry
    }

    #[test]
    fn transition_root_v1_golden_vectors() {
        assert_eq!(
            SessionRegistry::new().transition_root_v1(),
            Hash::from_bytes([
                150, 107, 144, 227, 55, 115, 114, 166, 75, 95, 115, 10, 11, 134, 122, 129, 72, 201,
                2, 68, 84, 182, 133, 193, 21, 236, 138, 209, 142, 115, 250, 20,
            ])
        );

        let mut rich = SessionRegistry::new();
        rich.authorize(
            acct(2),
            [2; 32],
            vec![],
            Amount::from_raw(i128::from(i64::MAX) + 42),
            1_000,
            7,
            9,
        )
        .unwrap();
        rich.authorize(
            acct(1),
            [1; 32],
            vec![MarketId::new(9), MarketId::new(3), MarketId::new(9)],
            Amount::from_raw(1_000),
            500,
            1,
            5,
        )
        .unwrap();
        rich.consume(acct(2), [2; 32], 9, MarketId::new(999), Amount::ZERO, 1)
            .unwrap();
        rich.consume(acct(1), [1; 32], 5, MarketId::new(3), Amount::ZERO, 1)
            .unwrap();
        rich.consume(acct(1), [1; 32], 1, MarketId::new(3), Amount::ZERO, 1)
            .unwrap();
        assert_eq!(
            rich.transition_root_v1(),
            Hash::from_bytes([
                22, 225, 5, 92, 21, 149, 18, 43, 167, 171, 181, 93, 81, 255, 114, 253, 171, 115,
                71, 83, 198, 222, 150, 124, 148, 73, 70, 85, 155, 254, 211, 44,
            ])
        );
    }

    #[test]
    fn transition_root_v1_is_semantic_set_and_insertion_order_independent() {
        let mut a = registry_with_session(2, 2, &[], 200, 100, 7, 9, &[9, 7]);
        a.authorize(
            acct(1),
            [1; 32],
            vec![MarketId::new(9), MarketId::new(3), MarketId::new(9)],
            Amount::from_raw(100),
            100,
            1,
            5,
        )
        .unwrap();
        a.consume(acct(1), [1; 32], 5, MarketId::new(3), Amount::ZERO, 0)
            .unwrap();
        a.consume(acct(1), [1; 32], 1, MarketId::new(9), Amount::ZERO, 0)
            .unwrap();

        let mut b = registry_with_session(1, 1, &[3, 9], 100, 100, 1, 5, &[1, 5]);
        b.authorize(acct(2), [2; 32], vec![], Amount::from_raw(200), 100, 7, 9)
            .unwrap();
        b.consume(acct(2), [2; 32], 7, MarketId::new(123), Amount::ZERO, 0)
            .unwrap();
        b.consume(acct(2), [2; 32], 9, MarketId::new(456), Amount::ZERO, 0)
            .unwrap();

        assert_eq!(a.transition_root_v1(), b.transition_root_v1());
    }

    #[test]
    fn transition_root_v1_orders_session_keys_within_one_account() {
        let mut reverse = SessionRegistry::new();
        let mut canonical = SessionRegistry::new();
        for (registry, keys) in [
            (&mut reverse, [[2; 32], [1; 32]]),
            (&mut canonical, [[1; 32], [2; 32]]),
        ] {
            for key in keys {
                registry
                    .authorize(
                        acct(1),
                        key,
                        vec![MarketId::new(u32::from(key[0]))],
                        Amount::from_raw(i128::from(key[0])),
                        100,
                        1,
                        5,
                    )
                    .unwrap();
            }
        }
        assert_eq!(reverse.transition_root_v1(), canonical.transition_root_v1());
    }

    #[test]
    fn transition_root_v1_binds_every_behavior_field_and_exact_nonce_set() {
        let base = registry_with_session(1, 1, &[3], 100, 100, 1, 5, &[3]).transition_root_v1();
        for changed in [
            registry_with_session(2, 1, &[3], 100, 100, 1, 5, &[3]),
            registry_with_session(1, 2, &[3], 100, 100, 1, 5, &[3]),
            registry_with_session(1, 1, &[], 100, 100, 1, 5, &[3]),
            registry_with_session(1, 1, &[4], 100, 100, 1, 5, &[3]),
            registry_with_session(1, 1, &[3], 101, 100, 1, 5, &[3]),
            registry_with_session(1, 1, &[3], 100, 101, 1, 5, &[3]),
            registry_with_session(1, 1, &[3], 100, 100, 2, 5, &[3]),
            registry_with_session(1, 1, &[3], 100, 100, 1, 4, &[3]),
            registry_with_session(1, 1, &[3], 100, 100, 1, 5, &[2]),
        ] {
            assert_ne!(changed.transition_root_v1(), base);
        }

        let consumed_13 = registry_with_session(1, 1, &[3], 100, 100, 1, 5, &[1, 3]);
        let consumed_23 = registry_with_session(1, 1, &[3], 100, 100, 1, 5, &[2, 3]);
        assert_ne!(
            consumed_13.transition_root_v1(),
            consumed_23.transition_root_v1()
        );
    }

    #[test]
    fn consume_changes_root_only_on_success() {
        let registry = registry_with_session(1, 1, &[3], 10, 100, 1, 5, &[]);
        let initial = registry.transition_root_v1();

        let mut success = registry.clone();
        success
            .consume(
                acct(1),
                [1; 32],
                1,
                MarketId::new(3),
                Amount::from_raw(10),
                100,
            )
            .unwrap();
        assert_ne!(success.transition_root_v1(), initial);

        let rejection_cases = [
            (
                [1; 32],
                1,
                MarketId::new(3),
                Amount::ZERO,
                101,
                ExecutionError::SessionExpired,
            ),
            (
                [1; 32],
                1,
                MarketId::new(4),
                Amount::ZERO,
                0,
                ExecutionError::MarketNotAuthorized,
            ),
            (
                [1; 32],
                1,
                MarketId::new(3),
                Amount::from_raw(11),
                0,
                ExecutionError::NotionalExceeded,
            ),
            (
                [1; 32],
                6,
                MarketId::new(3),
                Amount::ZERO,
                0,
                ExecutionError::BadNonce,
            ),
            (
                [9; 32],
                1,
                MarketId::new(3),
                Amount::ZERO,
                0,
                ExecutionError::UnknownSession,
            ),
        ];
        for (key, nonce, market, notional, now, expected) in rejection_cases {
            let mut rejected = registry.clone();
            assert_eq!(
                rejected.consume(acct(1), key, nonce, market, notional, now),
                Err(expected)
            );
            assert_eq!(rejected.transition_root_v1(), initial);
        }

        let before_replay = success.transition_root_v1();
        assert_eq!(
            success.consume(acct(1), [1; 32], 1, MarketId::new(3), Amount::ZERO, 0),
            Err(ExecutionError::BadNonce)
        );
        assert_eq!(success.transition_root_v1(), before_replay);
    }

    #[test]
    fn overwrite_and_revoke_have_canonical_root_semantics() {
        let mut overwritten = registry_with_session(1, 1, &[3], 10, 100, 1, 5, &[1]);
        overwritten
            .authorize(
                acct(1),
                [1; 32],
                vec![MarketId::new(7)],
                Amount::from_raw(20),
                200,
                10,
                20,
            )
            .unwrap();
        let fresh = registry_with_session(1, 1, &[7], 20, 200, 10, 20, &[]);
        assert_eq!(overwritten.transition_root_v1(), fresh.transition_root_v1());

        let empty = SessionRegistry::new().transition_root_v1();
        assert!(overwritten.revoke(acct(1), [1; 32]));
        assert_eq!(overwritten.transition_root_v1(), empty);
        let before_unknown = overwritten.transition_root_v1();
        assert!(!overwritten.revoke(acct(1), [9; 32]));
        assert_eq!(overwritten.transition_root_v1(), before_unknown);
    }

    #[test]
    fn rejected_authorize_leaves_root_unchanged() {
        let mut registry = registry_with_session(1, 1, &[3], 10, 100, 1, 5, &[1]);
        let root = registry.transition_root_v1();
        assert_eq!(
            registry.authorize(
                acct(1),
                [1; 32],
                vec![MarketId::new(9)],
                Amount::from_raw(-1),
                200,
                10,
                20,
            ),
            Err(ExecutionError::BadNonce)
        );
        assert_eq!(registry.transition_root_v1(), root);
        assert_eq!(
            registry.authorize(
                acct(1),
                [1; 32],
                vec![MarketId::new(9)],
                Amount::from_raw(20),
                200,
                20,
                10,
            ),
            Err(ExecutionError::BadNonce)
        );
        assert_eq!(registry.transition_root_v1(), root);
    }

    #[test]
    #[should_panic(expected = "session maximum notional must be nonnegative")]
    fn transition_root_v1_rejects_corrupt_negative_notional() {
        let mut registry = registry_with_session(1, 1, &[3], 10, 100, 1, 5, &[]);
        registry
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .max_notional = Amount::from_raw(-1);
        let _ = registry.transition_root_v1();
    }

    #[test]
    #[should_panic(expected = "session nonce range must be ordered")]
    fn transition_root_v1_rejects_corrupt_reversed_nonce_range() {
        let mut registry = registry_with_session(1, 1, &[3], 10, 100, 1, 5, &[]);
        registry
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .nonce_start = 6;
        let _ = registry.transition_root_v1();
    }

    #[test]
    #[should_panic(expected = "consumed nonce must lie inside the authorized range")]
    fn transition_root_v1_rejects_corrupt_consumed_nonce() {
        let mut registry = registry_with_session(1, 1, &[3], 10, 100, 1, 5, &[]);
        registry
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .consumed
            .insert(6);
        let _ = registry.transition_root_v1();
    }
}
