//! Deterministic oracle engine: applies threshold-signed [`OracleCertificate`]s
//! into canonical per-market state and commits an `oracle_root`.
//!
//! The engine is pure and replay-deterministic: applying the same certificate
//! stream (in any order that respects per-market sequence monotonicity) yields a
//! bit-identical `oracle_root`. A malformed or sub-threshold certificate is
//! rejected without mutating canonical state and without panicking. The price
//! oracle here is deliberately independent of market *resolution*.
//!
//! # Root complexity
//!
//! Per-market leaves are held in ascending market-id order. Updating an
//! **existing** market is O(log M) via the incremental Merkle tree; inserting a
//! new market rebuilds the tree in O(M) bottom-up. Root reads are O(1).

use std::collections::BTreeMap;

use crypto::{MerkleTree, ValidatorSet};
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
    /// Dense leaf order matching ascending market-id iteration.
    leaf_order: Vec<u32>,
    /// Incremental Merkle over `leaf_order` digests. Rebuilt on insert.
    tree: MerkleTree,
    /// Cached root (O(1) reads).
    cached_root: Hash,
}

impl OracleEngine {
    /// Create an engine that accepts certificates from `validator_set`.
    pub fn new(validator_set: ValidatorSet) -> Self {
        // Empty root is the canonical zero hash (matches `merkle_root(&[])`).
        Self {
            validator_set,
            markets: BTreeMap::new(),
            leaf_order: Vec::new(),
            tree: MerkleTree::new(1),
            cached_root: Hash::ZERO,
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
        let state = MarketOracleState {
            last: cert.aggregate,
        };
        let leaf = state.leaf();
        let is_new = !self.markets.contains_key(&market);
        self.markets.insert(market, state);
        if is_new {
            // Insert into sorted leaf_order and rebuild bottom-up O(M).
            let pos = self.leaf_order.binary_search(&market).unwrap_or_else(|i| i);
            self.leaf_order.insert(pos, market);
            self.rebuild_tree();
        } else {
            // Existing market: O(log M) path update.
            let idx = self
                .leaf_order
                .binary_search(&market)
                .expect("leaf_order tracks markets");
            self.tree.set(idx, leaf).expect("index in range");
            self.cached_root = self.tree.root();
        }
        Ok(())
    }

    fn rebuild_tree(&mut self) {
        let leaves: Vec<Hash> = self
            .leaf_order
            .iter()
            .map(|m| self.markets[m].leaf())
            .collect();
        if leaves.is_empty() {
            self.tree = MerkleTree::new(1);
            self.cached_root = Hash::ZERO;
            return;
        }
        self.tree = MerkleTree::from_leaves(&leaves);
        self.cached_root = self.tree.root();
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
    /// market-id order. O(1) cached read; changes whenever any market's
    /// committed aggregate changes.
    pub fn oracle_root(&self) -> Hash {
        self.cached_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{merkle_root, ThresholdSigners};

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

    #[test]
    fn incremental_root_matches_from_scratch() {
        let ts = signers(4, 3);
        let mut eng = OracleEngine::new(ts.validator_set());
        for m in [3u32, 1, 7, 2] {
            eng.apply(&cert(&ts, m, 1, 100 + i64::from(m), OracleHealth::Normal))
                .unwrap();
            let leaves: Vec<Hash> = eng
                .leaf_order
                .iter()
                .map(|id| eng.markets[id].leaf())
                .collect();
            assert_eq!(eng.oracle_root(), merkle_root(&leaves));
        }
        eng.apply(&cert(&ts, 1, 2, 999, OracleHealth::Normal))
            .unwrap();
        let leaves: Vec<Hash> = eng
            .leaf_order
            .iter()
            .map(|id| eng.markets[id].leaf())
            .collect();
        assert_eq!(eng.oracle_root(), merkle_root(&leaves));
    }
}
