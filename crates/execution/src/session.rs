//! Scoped trading session keys with monotonic-nonce replay protection.

use std::collections::{HashMap, HashSet};

use types::{AccountId, Amount, Hash, MarketId};

use crate::error::ExecutionError;

mod state;
mod state_codec;

pub use state::{SessionStateError, SessionStateLimits};

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
        self.validate_transition_invariants()
            .unwrap_or_else(|error| panic!("invalid session transition state: {error}"));
        self.transition_root_v1_checked()
            .unwrap_or_else(|error| panic!("failed to encode canonical session state: {error}"))
    }

    /// Validate every stored relation required to interpret session state.
    ///
    /// Market scopes are deliberately not compared with the engine's current
    /// market registry: a session may be authorized before a market exists, or
    /// retain a scope after that market's lifecycle changes. Account ownership
    /// is checked separately by the enclosing engine validator.
    pub fn validate_transition_invariants(&self) -> Result<(), ExecutionError> {
        for session in self.sessions.values() {
            if session.max_notional.is_negative() {
                return Err(ExecutionError::StateInvariant(
                    "session maximum notional must be nonnegative",
                ));
            }
            if session.nonce_start > session.nonce_end {
                return Err(ExecutionError::StateInvariant(
                    "session nonce range must be ordered",
                ));
            }
            for nonce in &session.consumed {
                if !(session.nonce_start..=session.nonce_end).contains(nonce) {
                    return Err(ExecutionError::StateInvariant(
                        "consumed nonce must lie inside the authorized range",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate session principals against the authoritative dense account
    /// registry without imposing any relation on market scopes.
    pub(crate) fn validate_engine_context(
        &self,
        account_count: usize,
    ) -> Result<(), ExecutionError> {
        self.validate_transition_invariants()?;
        if self.sessions.keys().any(|(account, _)| {
            usize::try_from(*account).map_or(true, |index| index >= account_count)
        }) {
            return Err(ExecutionError::StateInvariant(
                "session principal does not reference an existing ledger account",
            ));
        }
        Ok(())
    }

    fn write_state_v1_unchecked(
        &self,
        writer: &mut TransitionWriter,
    ) -> Result<(), SessionStateError> {
        writer.u16(SESSION_TRANSITION_ROOT_SCHEMA_VERSION);

        let mut sessions = Vec::new();
        sessions
            .try_reserve_exact(self.sessions.len())
            .map_err(|_| SessionStateError::AllocationFailed {
                resource: "session ordering",
            })?;
        sessions.extend(self.sessions.iter().map(|(key, session)| (*key, session)));
        sessions.sort_unstable_by_key(|(key, _)| *key);
        writer.len(sessions.len());

        for ((account, session_key), session) in sessions {
            writer.u32(account);
            writer.bytes.extend_from_slice(&session_key);

            if session.allowed_markets.is_empty() {
                writer.u8(0); // wildcard: all markets
                writer.len(0);
            } else {
                writer.u8(1); // explicit semantic allow-list
                let mut markets = Vec::new();
                markets
                    .try_reserve_exact(session.allowed_markets.len())
                    .map_err(|_| SessionStateError::AllocationFailed {
                        resource: "session market ordering",
                    })?;
                markets.extend(session.allowed_markets.iter().map(|market| market.get()));
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

            let mut consumed = Vec::new();
            consumed
                .try_reserve_exact(session.consumed.len())
                .map_err(|_| SessionStateError::AllocationFailed {
                    resource: "consumed nonce ordering",
                })?;
            consumed.extend(session.consumed.iter().copied());
            consumed.sort_unstable();
            writer.len(consumed.len());
            for nonce in consumed {
                writer.u64(nonce);
            }
        }
        Ok(())
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

    fn rich_registry() -> SessionRegistry {
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
        rich
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

        let rich = rich_registry();
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
    fn transition_validator_is_typed_read_only_and_checks_engine_principals() {
        let registry = registry_with_session(1, 1, &[3], 10, 100, 1, 5, &[1]);
        let root = registry.transition_root_v1();
        assert_eq!(registry.validate_transition_invariants(), Ok(()));
        assert_eq!(registry.validate_engine_context(2), Ok(()));
        assert_eq!(registry.transition_root_v1(), root);
        assert_eq!(
            registry.validate_engine_context(1),
            Err(ExecutionError::StateInvariant(
                "session principal does not reference an existing ledger account"
            ))
        );

        let mut negative = registry.clone();
        negative
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .max_notional = Amount::from_raw(-1);
        assert_eq!(
            negative.validate_transition_invariants(),
            Err(ExecutionError::StateInvariant(
                "session maximum notional must be nonnegative"
            ))
        );

        let mut reversed = registry.clone();
        reversed
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .nonce_start = 6;
        assert_eq!(
            reversed.validate_transition_invariants(),
            Err(ExecutionError::StateInvariant(
                "session nonce range must be ordered"
            ))
        );

        let mut consumed = registry;
        consumed
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .consumed
            .insert(6);
        assert_eq!(
            consumed.validate_transition_invariants(),
            Err(ExecutionError::StateInvariant(
                "consumed nonce must lie inside the authorized range"
            ))
        );
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

    fn codec_bytes(registry: &SessionRegistry) -> Vec<u8> {
        registry.encode_state_v1_bounded(usize::MAX).unwrap()
    }

    fn overwrite_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn overwrite_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn overwrite_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn overwrite_i128(bytes: &mut [u8], offset: usize, value: i128) {
        bytes[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn state_codec_v1_exact_preimages_roots_and_semantic_recovery() {
        let empty = SessionRegistry::new();
        let empty_bytes = codec_bytes(&empty);
        assert_eq!(empty_bytes.len(), 10);
        assert_eq!(hex::encode(&empty_bytes), "01000000000000000000");
        assert_eq!(
            crypto::hash_domain(crypto::DOMAIN_EXECUTION_SESSION_STATE, &empty_bytes),
            empty.transition_root_v1()
        );
        let restored =
            SessionRegistry::decode_state_v1_bounded(&empty_bytes, &SessionStateLimits::default())
                .unwrap();
        assert_eq!(codec_bytes(&restored), empty_bytes);

        let rich = rich_registry();
        let rich_bytes = codec_bytes(&rich);
        assert_eq!(rich_bytes.len(), 228);
        assert_eq!(
            hex::encode(&rich_bytes),
            concat!(
                "010002000000000000000100000001010101010101010101010101010101010101010101",
                "010101010101010101010102000000000000000300000009000000e8030000000000000000",
                "000000000000f4010000000000000100000000000000050000000000000002000000000000",
                "0001000000000000000500000000000000020000000202020202020202020202020202020202",
                "0202020202020202020202020202020000000000000000002900000000000080000000000000",
                "0000e80300000000000007000000000000000900000000000000010000000000000009000000",
                "00000000"
            )
        );
        assert_eq!(
            crypto::hash_domain(crypto::DOMAIN_EXECUTION_SESSION_STATE, &rich_bytes),
            rich.transition_root_v1()
        );

        let restored =
            SessionRegistry::decode_state_v1_bounded(&rich_bytes, &SessionStateLimits::default())
                .unwrap();
        assert_eq!(codec_bytes(&restored), rich_bytes);
        assert_eq!(restored.transition_root_v1(), rich.transition_root_v1());
        assert_eq!(
            restored
                .sessions
                .get(&(1, [1; 32]))
                .unwrap()
                .allowed_markets,
            vec![MarketId::new(3), MarketId::new(9)]
        );

        assert_eq!(
            rich.encode_state_v1_bounded(rich_bytes.len() - 1),
            Err(SessionStateError::EncodedBytesLimit {
                actual: rich_bytes.len(),
                max: rich_bytes.len() - 1,
            })
        );
        assert_eq!(
            rich.encode_state_v1_bounded(rich_bytes.len()).unwrap(),
            rich_bytes
        );
    }

    #[test]
    fn state_codec_v1_enforces_each_independent_and_cumulative_limit() {
        let bytes = codec_bytes(&rich_registry());
        let exact = SessionStateLimits {
            max_encoded_bytes: bytes.len(),
            max_sessions: 2,
            max_markets_per_session: 2,
            max_total_markets: 2,
            max_consumed_nonces_per_session: 2,
            max_total_consumed_nonces: 3,
        };
        assert!(SessionRegistry::decode_state_v1_bounded(&bytes, &exact).is_ok());

        assert_eq!(
            SessionRegistry::decode_state_v1_bounded(
                &bytes,
                &SessionStateLimits {
                    max_encoded_bytes: bytes.len() - 1,
                    ..exact
                },
            )
            .unwrap_err(),
            SessionStateError::EncodedBytesLimit {
                actual: bytes.len(),
                max: bytes.len() - 1,
            }
        );

        let cases = [
            (
                "sessions",
                SessionStateLimits {
                    max_sessions: 1,
                    ..exact
                },
            ),
            (
                "markets per session",
                SessionStateLimits {
                    max_markets_per_session: 1,
                    ..exact
                },
            ),
            (
                "total session markets",
                SessionStateLimits {
                    max_total_markets: 1,
                    ..exact
                },
            ),
            (
                "consumed nonces per session",
                SessionStateLimits {
                    max_consumed_nonces_per_session: 1,
                    ..exact
                },
            ),
            (
                "total consumed nonces",
                SessionStateLimits {
                    max_total_consumed_nonces: 2,
                    ..exact
                },
            ),
        ];
        for (expected_resource, limits) in cases {
            assert!(matches!(
                SessionRegistry::decode_state_v1_bounded(&bytes, &limits),
                Err(SessionStateError::ResourceLimit { resource, .. })
                    if resource == expected_resource
            ));
        }
    }

    #[test]
    fn state_codec_v1_rejects_every_truncation_suffix_and_noncanonical_field() {
        let bytes = codec_bytes(&rich_registry());
        let limits = SessionStateLimits::default();
        for end in 0..bytes.len() {
            assert!(
                SessionRegistry::decode_state_v1_bounded(&bytes[..end], &limits).is_err(),
                "truncation at byte {end} was accepted"
            );
        }

        let mut suffixed = bytes.clone();
        suffixed.push(0);
        assert_eq!(
            SessionRegistry::decode_state_v1_bounded(&suffixed, &limits).unwrap_err(),
            SessionStateError::TrailingBytes { remaining: 1 }
        );

        let mut malformed = Vec::new();

        let mut changed = bytes.clone();
        overwrite_u16(&mut changed, 0, 2);
        malformed.push(changed);

        let mut changed = bytes.clone();
        changed[46] = 2;
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u64(&mut changed, 47, 0);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u64(&mut changed, 164, 1);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u32(&mut changed, 127, 0);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u32(&mut changed, 127, 1);
        changed[131..163].copy_from_slice(&[1; 32]);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u32(&mut changed, 127, 1);
        changed[131..163].copy_from_slice(&[0; 32]);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u32(&mut changed, 55, 10);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u32(&mut changed, 59, 3);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_i128(&mut changed, 63, -1);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u64(&mut changed, 87, 6);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u64(&mut changed, 87, 1);
        overwrite_u64(&mut changed, 95, 1);
        overwrite_u64(&mut changed, 103, 2);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u64(&mut changed, 111, 0);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u64(&mut changed, 119, 6);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u64(&mut changed, 119, 1);
        malformed.push(changed);

        let mut changed = bytes.clone();
        overwrite_u64(&mut changed, 111, 4);
        overwrite_u64(&mut changed, 119, 2);
        malformed.push(changed);

        for (index, changed) in malformed.iter().enumerate() {
            assert!(
                SessionRegistry::decode_state_v1_bounded(changed, &limits).is_err(),
                "malformed case {index} was accepted"
            );
        }

        let mut negative = rich_registry();
        negative
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .max_notional = Amount::from_raw(-1);
        assert!(matches!(
            negative.encode_state_v1_bounded(usize::MAX),
            Err(SessionStateError::InvalidValue { .. })
        ));

        let mut reversed = rich_registry();
        reversed
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .nonce_start = 6;
        assert!(matches!(
            reversed.encode_state_v1_bounded(usize::MAX),
            Err(SessionStateError::InvalidValue { .. })
        ));

        let mut out_of_range = rich_registry();
        out_of_range
            .sessions
            .get_mut(&(1, [1; 32]))
            .unwrap()
            .consumed
            .insert(6);
        assert!(matches!(
            out_of_range.encode_state_v1_bounded(usize::MAX),
            Err(SessionStateError::InvalidValue { .. })
        ));
    }

    #[test]
    fn state_codec_v1_count_bombs_and_mutations_never_panic() {
        let limits = SessionStateLimits::default();
        let mut empty = codec_bytes(&SessionRegistry::new());
        overwrite_u64(&mut empty, 2, u64::MAX);
        assert!(matches!(
            SessionRegistry::decode_state_v1_bounded(&empty, &limits),
            Err(SessionStateError::ResourceLimit {
                resource: "sessions",
                ..
            })
        ));

        let bytes = codec_bytes(&rich_registry());
        for (offset, count_offset) in [
            ("markets per session", 47),
            ("consumed nonces per session", 103),
        ] {
            let mut bomb = bytes.clone();
            overwrite_u64(&mut bomb, count_offset, u64::MAX);
            assert!(matches!(
                SessionRegistry::decode_state_v1_bounded(&bomb, &limits),
                Err(SessionStateError::ResourceLimit { resource, .. }) if resource == offset
            ));
        }

        let unbounded = SessionStateLimits {
            max_encoded_bytes: usize::MAX,
            max_sessions: usize::MAX,
            max_markets_per_session: usize::MAX,
            max_total_markets: usize::MAX,
            max_consumed_nonces_per_session: usize::MAX,
            max_total_consumed_nonces: usize::MAX,
        };
        overwrite_u64(&mut empty, 2, u64::try_from(usize::MAX).unwrap());
        assert!(matches!(
            SessionRegistry::decode_state_v1_bounded(&empty, &unbounded),
            Err(SessionStateError::ArithmeticOverflow { .. })
        ));

        let mut market_bomb = bytes.clone();
        overwrite_u64(&mut market_bomb, 47, u64::MAX);
        assert!(SessionRegistry::decode_state_v1_bounded(&market_bomb, &unbounded).is_err());

        let mut consumed_bomb = bytes.clone();
        overwrite_u64(&mut consumed_bomb, 87, 0);
        overwrite_u64(&mut consumed_bomb, 95, u64::MAX);
        overwrite_u64(&mut consumed_bomb, 103, u64::MAX);
        assert!(SessionRegistry::decode_state_v1_bounded(&consumed_bomb, &unbounded).is_err());

        // Each nested count fits the bytes remaining at its own field, but not
        // after reserving the second session's 93-byte minimum framing.
        let mut market_tail_bomb = bytes.clone();
        overwrite_u64(&mut market_tail_bomb, 47, 20);
        assert!(matches!(
            SessionRegistry::decode_state_v1_bounded(&market_tail_bomb, &unbounded),
            Err(SessionStateError::Truncated { .. })
        ));

        let mut nonce_tail_bomb = bytes.clone();
        overwrite_u64(&mut nonce_tail_bomb, 103, 4);
        assert!(matches!(
            SessionRegistry::decode_state_v1_bounded(&nonce_tail_bomb, &unbounded),
            Err(SessionStateError::Truncated { .. })
        ));

        for offset in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[offset] ^= 0xa5;
            assert!(std::panic::catch_unwind(|| {
                let _ = SessionRegistry::decode_state_v1_bounded(&changed, &limits);
            })
            .is_ok());
        }

        let mut state = 0x43d2_91ab_77e5_102cu64;
        for _ in 0..5_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let len = usize::try_from(state % 256).unwrap();
            let mut arbitrary = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                arbitrary.push(state.to_le_bytes()[3]);
            }
            assert!(std::panic::catch_unwind(|| {
                let _ = SessionRegistry::decode_state_v1_bounded(&arbitrary, &limits);
            })
            .is_ok());
        }
    }

    #[test]
    fn state_codec_v1_accepts_boundary_state_and_numeric_account_order() {
        let mut registry = SessionRegistry::new();
        registry
            .authorize(acct(256), [0; 32], vec![], Amount::ZERO, 0, 0, 0)
            .unwrap();
        registry
            .authorize(
                acct(255),
                [u8::MAX; 32],
                vec![
                    MarketId::new(u32::MAX),
                    MarketId::new(0),
                    MarketId::new(u32::MAX),
                ],
                Amount::from_raw(i128::MAX),
                u64::MAX,
                0,
                u64::MAX,
            )
            .unwrap();
        registry
            .consume(
                acct(255),
                [u8::MAX; 32],
                0,
                MarketId::new(0),
                Amount::from_raw(i128::MAX),
                u64::MAX,
            )
            .unwrap();
        registry
            .consume(
                acct(255),
                [u8::MAX; 32],
                u64::MAX,
                MarketId::new(u32::MAX),
                Amount::from_raw(-1),
                u64::MAX,
            )
            .unwrap();

        let bytes = codec_bytes(&registry);
        let restored =
            SessionRegistry::decode_state_v1_bounded(&bytes, &SessionStateLimits::default())
                .unwrap();
        assert_eq!(codec_bytes(&restored), bytes);
        assert_eq!(restored.transition_root_v1(), registry.transition_root_v1());
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_pair(
        left: &mut SessionRegistry,
        right: &mut SessionRegistry,
        account: AccountId,
        key: [u8; 32],
        nonce: u64,
        market: MarketId,
        notional: Amount,
        now: u64,
        expected: Result<(), ExecutionError>,
    ) {
        let left_before = codec_bytes(left);
        let right_before = codec_bytes(right);
        let left_result = left.consume(account, key, nonce, market, notional, now);
        let right_result = right.consume(account, key, nonce, market, notional, now);
        assert_eq!(left_result, expected);
        assert_eq!(right_result, expected);
        if expected.is_err() {
            assert_eq!(codec_bytes(left), left_before);
            assert_eq!(codec_bytes(right), right_before);
        }
        assert_eq!(codec_bytes(left), codec_bytes(right));
        assert_eq!(left.transition_root_v1(), right.transition_root_v1());
    }

    #[test]
    fn state_codec_v1_restored_registry_has_identical_continuation_behavior() {
        let mut original = rich_registry();
        let bytes = codec_bytes(&original);
        let mut restored =
            SessionRegistry::decode_state_v1_bounded(&bytes, &SessionStateLimits::default())
                .unwrap();

        consume_pair(
            &mut original,
            &mut restored,
            acct(99),
            [9; 32],
            99,
            MarketId::new(99),
            Amount::from_raw(i128::MAX),
            u64::MAX,
            Err(ExecutionError::UnknownSession),
        );
        consume_pair(
            &mut original,
            &mut restored,
            acct(1),
            [1; 32],
            6,
            MarketId::new(4),
            Amount::from_raw(1_001),
            501,
            Err(ExecutionError::SessionExpired),
        );
        consume_pair(
            &mut original,
            &mut restored,
            acct(1),
            [1; 32],
            6,
            MarketId::new(4),
            Amount::from_raw(1_001),
            0,
            Err(ExecutionError::MarketNotAuthorized),
        );
        consume_pair(
            &mut original,
            &mut restored,
            acct(1),
            [1; 32],
            6,
            MarketId::new(3),
            Amount::from_raw(1_001),
            0,
            Err(ExecutionError::NotionalExceeded),
        );
        consume_pair(
            &mut original,
            &mut restored,
            acct(1),
            [1; 32],
            6,
            MarketId::new(3),
            Amount::from_raw(1_000),
            0,
            Err(ExecutionError::BadNonce),
        );
        consume_pair(
            &mut original,
            &mut restored,
            acct(1),
            [1; 32],
            1,
            MarketId::new(3),
            Amount::ZERO,
            0,
            Err(ExecutionError::BadNonce),
        );
        consume_pair(
            &mut original,
            &mut restored,
            acct(1),
            [1; 32],
            2,
            MarketId::new(9),
            Amount::from_raw(1_000),
            500,
            Ok(()),
        );
        consume_pair(
            &mut original,
            &mut restored,
            acct(1),
            [1; 32],
            3,
            MarketId::new(3),
            Amount::from_raw(-1),
            0,
            Ok(()),
        );
        consume_pair(
            &mut original,
            &mut restored,
            acct(2),
            [2; 32],
            7,
            MarketId::new(u32::MAX),
            Amount::ZERO,
            1_000,
            Ok(()),
        );

        for registry in [&mut original, &mut restored] {
            registry
                .authorize(
                    acct(1),
                    [1; 32],
                    vec![MarketId::new(8), MarketId::new(8)],
                    Amount::ZERO,
                    0,
                    u64::MAX,
                    u64::MAX,
                )
                .unwrap();
        }
        assert_eq!(codec_bytes(&original), codec_bytes(&restored));
        consume_pair(
            &mut original,
            &mut restored,
            acct(1),
            [1; 32],
            u64::MAX,
            MarketId::new(8),
            Amount::ZERO,
            0,
            Ok(()),
        );
        assert!(original.revoke(acct(1), [1; 32]));
        assert!(restored.revoke(acct(1), [1; 32]));
        assert!(!original.revoke(acct(1), [9; 32]));
        assert!(!restored.revoke(acct(1), [9; 32]));
        assert_eq!(codec_bytes(&original), codec_bytes(&restored));
    }
}
