//! Deterministic oracle engine: applies threshold-signed [`OracleCertificate`]s
//! into canonical per-market state and commits an `oracle_root`.
//!
//! The engine is pure and replay-deterministic: applying the same certificate
//! stream (in any order that respects per-market sequence monotonicity) yields a
//! bit-identical `oracle_root`. A malformed or sub-threshold certificate is
//! rejected without mutating canonical state and without panicking. The price
//! oracle here is deliberately independent of market *resolution*.

use std::collections::BTreeMap;

use crypto::{merkle_root, ValidatorSet};
use types::{Amount, Hash, MarketId, OracleHealth, Price};

use crate::certificate::{AggregatePrice, OracleCertificate};
use crate::error::OracleError;
use crate::health::{market_action, MarketAction};

/// Canonical committed oracle state for one market.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarketOracleState {
    /// Last committed aggregate.
    pub last: AggregatePrice,
}

impl MarketOracleState {
    /// Committed price.
    pub fn price(&self) -> Price {
        self.last.price
    }
    /// Committed confidence.
    pub fn confidence(&self) -> Amount {
        self.last.confidence
    }
    /// Committed health.
    pub fn health(&self) -> OracleHealth {
        self.last.health
    }
    /// Committed sequence.
    pub fn sequence(&self) -> u64 {
        self.last.sequence
    }
    /// The market behavior implied by this state's health.
    pub fn market_action(&self) -> MarketAction {
        market_action(self.last.health)
    }
    /// The leaf commitment for this market (the aggregate digest).
    pub fn leaf(&self) -> Hash {
        self.last.digest()
    }
}

/// A deterministic oracle price engine over a fixed validator set.
#[derive(Debug, Clone)]
pub struct OracleEngine {
    validator_set: ValidatorSet,
    markets: BTreeMap<u32, MarketOracleState>,
}

impl OracleEngine {
    /// Create an engine that accepts certificates from `validator_set`.
    pub fn new(validator_set: ValidatorSet) -> Self {
        Self {
            validator_set,
            markets: BTreeMap::new(),
        }
    }

    /// Apply an oracle update (a verified certificate) to canonical state.
    ///
    /// Rejects — without any mutation — a certificate that fails verification
    /// (bad digest, sub-threshold, or wrong signer) or that does not strictly
    /// advance the per-market sequence.
    pub fn apply(&mut self, cert: &OracleCertificate) -> Result<(), OracleError> {
        cert.verify(&self.validator_set)?;
        let market = cert.aggregate.market_id.get();
        if let Some(existing) = self.markets.get(&market) {
            if cert.aggregate.sequence <= existing.last.sequence {
                return Err(OracleError::StaleSequence {
                    have: existing.last.sequence,
                    got: cert.aggregate.sequence,
                });
            }
        }
        self.markets.insert(
            market,
            MarketOracleState {
                last: cert.aggregate,
            },
        );
        Ok(())
    }

    /// Current committed state for `market`, if any.
    pub fn market(&self, market: MarketId) -> Option<&MarketOracleState> {
        self.markets.get(&market.get())
    }

    /// Current health for `market`; `Halted` if the market is unknown.
    pub fn health(&self, market: MarketId) -> OracleHealth {
        self.market(market)
            .map(MarketOracleState::health)
            .unwrap_or(OracleHealth::Halted)
    }

    /// Number of markets with committed state.
    pub fn len(&self) -> usize {
        self.markets.len()
    }

    /// Whether the engine has no committed markets.
    pub fn is_empty(&self) -> bool {
        self.markets.is_empty()
    }

    /// Commit the oracle root: a Merkle root over per-market leaves in ascending
    /// market-id order. Deterministic and non-trivial; changes whenever any
    /// market's committed aggregate changes.
    pub fn oracle_root(&self) -> Hash {
        // BTreeMap iterates in ascending key order, giving canonical leaf order.
        let leaves: Vec<Hash> = self.markets.values().map(MarketOracleState::leaf).collect();
        merkle_root(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ThresholdSigners;

    fn signers(n: usize, k: u64) -> ThresholdSigners {
        let seeds: Vec<[u8; 32]> = (0..n).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        ThresholdSigners::from_seeds(&seeds, k)
    }

    fn agg(market: u32, seq: u64, price: i64, health: OracleHealth) -> AggregatePrice {
        AggregatePrice {
            market_id: MarketId::new(market),
            price: Price::from_raw(price),
            confidence: Amount::from_raw(1_000_000),
            health,
            observed_at_ns: 1_000,
            sequence: seq,
            producer_set_version: 1,
            inputs_digest: Hash::from_bytes([9u8; 32]),
        }
    }

    fn cert(
        ts: &ThresholdSigners,
        market: u32,
        seq: u64,
        price: i64,
        health: OracleHealth,
    ) -> OracleCertificate {
        OracleCertificate::form(agg(market, seq, price, health), ts, vec![0, 1, 2])
    }

    #[test]
    fn apply_updates_state_and_root_changes() {
        let ts = signers(4, 3);
        let mut engine = OracleEngine::new(ts.validator_set());
        let empty_root = engine.oracle_root();
        assert!(empty_root.is_zero());

        engine
            .apply(&cert(&ts, 1, 1, 100, OracleHealth::Normal))
            .unwrap();
        let r1 = engine.oracle_root();
        assert!(!r1.is_zero());
        assert_eq!(engine.health(MarketId::new(1)), OracleHealth::Normal);

        // Different oracle state -> different root.
        engine
            .apply(&cert(&ts, 1, 2, 200, OracleHealth::Degraded))
            .unwrap();
        let r2 = engine.oracle_root();
        assert_ne!(r1, r2);
        assert_eq!(engine.health(MarketId::new(1)), OracleHealth::Degraded);
    }

    #[test]
    fn stale_sequence_rejected_without_mutation() {
        let ts = signers(4, 3);
        let mut engine = OracleEngine::new(ts.validator_set());
        engine
            .apply(&cert(&ts, 1, 5, 100, OracleHealth::Normal))
            .unwrap();
        let root_before = engine.oracle_root();
        assert_eq!(
            engine.apply(&cert(&ts, 1, 5, 999, OracleHealth::Halted)),
            Err(OracleError::StaleSequence { have: 5, got: 5 })
        );
        assert_eq!(engine.oracle_root(), root_before);
        assert_eq!(
            engine.market(MarketId::new(1)).unwrap().price(),
            Price::from_raw(100)
        );
    }

    #[test]
    fn subthreshold_certificate_rejected_without_mutation() {
        let ts = signers(4, 3);
        let mut engine = OracleEngine::new(ts.validator_set());
        let bad = OracleCertificate::form(agg(1, 1, 100, OracleHealth::Normal), &ts, vec![0, 1]);
        let root_before = engine.oracle_root();
        assert!(engine.apply(&bad).is_err());
        assert_eq!(engine.oracle_root(), root_before);
        assert!(engine.market(MarketId::new(1)).is_none());
    }

    #[test]
    fn replay_is_order_independent_bit_identical_root() {
        let ts = signers(4, 3);
        let updates = [
            cert(&ts, 1, 1, 100, OracleHealth::Normal),
            cert(&ts, 2, 1, 500, OracleHealth::Degraded),
            cert(&ts, 3, 1, 700, OracleHealth::Normal),
        ];
        let mut a = OracleEngine::new(ts.validator_set());
        for u in &updates {
            a.apply(u).unwrap();
        }
        let mut b = OracleEngine::new(ts.validator_set());
        for u in updates.iter().rev() {
            b.apply(u).unwrap();
        }
        assert_eq!(a.oracle_root(), b.oracle_root());
    }

    #[test]
    fn unknown_market_is_halted() {
        let ts = signers(4, 3);
        let engine = OracleEngine::new(ts.validator_set());
        assert_eq!(engine.health(MarketId::new(42)), OracleHealth::Halted);
    }
}
