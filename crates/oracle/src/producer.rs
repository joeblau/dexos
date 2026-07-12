//! Authorized oracle producer registry.
//!
//! An oracle only trusts price reports from a *committed, versioned* set of
//! authorized producers. Each producer is one ed25519 signer bound to a fixed
//! *source* (venue) identity, a policy ceiling on the confidence weight it may
//! claim, and the set of markets it is allowed to price.
//!
//! The registry is local-derived truth. A [`crate::PriceObservation`] no longer
//! carries a self-declared venue bitmap: an observation's source identity and
//! weight ceiling are looked up here, keyed by the (signature-authenticated)
//! signer. An unknown signer contributes nothing, a known signer contributes
//! exactly one source bit regardless of what it claims, and its weight is capped
//! by policy — so no actor can manufacture venue diversity or dominate the
//! weighting by minting keys or inflating confidence.
//!
//! [`ProducerRegistry::commitment`] binds the version and every entry into a
//! single hash that the oracle certificate commits, so verifiers agree on which
//! authorized set produced a price.

use std::collections::BTreeMap;

use crypto::{hash_domain, DOMAIN_ORACLE};
use types::{Amount, Hash, MarketId};

use crate::error::OracleError;

/// Maximum number of distinct source (venue) identities. Diversity is a popcount
/// over a `u64` bitmap of derived source bits, so a source id must lie in
/// `0..MAX_SOURCES`.
pub const MAX_SOURCES: u8 = 64;

/// The set of markets a producer is authorized to price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketScope {
    /// Authorized for every market.
    All,
    /// Authorized only for this explicit set (kept ascending and de-duplicated).
    Only(Vec<MarketId>),
}

impl MarketScope {
    /// Whether `market` is within scope.
    fn contains(&self, market: MarketId) -> bool {
        match self {
            MarketScope::All => true,
            MarketScope::Only(markets) => markets.binary_search(&market).is_ok(),
        }
    }
}

/// One authorized producer: a signer bound to a source identity, a weight
/// ceiling, and a market scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Producer {
    signer: [u8; 32],
    source_id: u8,
    max_confidence: Amount,
    scope: MarketScope,
}

impl Producer {
    /// The producer's ed25519 signer key.
    #[inline]
    pub fn signer(&self) -> [u8; 32] {
        self.signer
    }

    /// The locally-derived source (venue) identity, in `0..MAX_SOURCES`.
    #[inline]
    pub fn source_id(&self) -> u8 {
        self.source_id
    }

    /// The single source-diversity bit this producer contributes.
    #[inline]
    pub fn source_bit(&self) -> u64 {
        1u64 << self.source_id
    }

    /// The policy ceiling on the confidence weight this producer may claim.
    #[inline]
    pub fn max_confidence(&self) -> Amount {
        self.max_confidence
    }

    /// Whether this producer is authorized to price `market`.
    #[inline]
    pub fn authorized_for(&self, market: MarketId) -> bool {
        self.scope.contains(market)
    }
}

/// A committed, versioned set of authorized oracle producers.
///
/// Keyed by signer so lookup during aggregation is `O(log n)` and iteration is in
/// canonical ascending signer order (used by [`ProducerRegistry::commitment`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProducerRegistry {
    version: u64,
    by_signer: BTreeMap<[u8; 32], Producer>,
}

impl ProducerRegistry {
    /// A new, empty registry at producer-set `version`.
    pub fn new(version: u64) -> Self {
        Self {
            version,
            by_signer: BTreeMap::new(),
        }
    }

    /// The producer-set version, committed into the oracle certificate.
    #[inline]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Number of authorized producers.
    #[inline]
    pub fn len(&self) -> usize {
        self.by_signer.len()
    }

    /// Whether the registry authorizes no producers.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_signer.is_empty()
    }

    /// Authorize `signer` for `source_id` with a confidence ceiling of
    /// `max_confidence`, restricted to `scope`.
    ///
    /// Rejects a source id at or beyond [`MAX_SOURCES`], a negative confidence
    /// ceiling, or a signer that is already authorized (no silent overwrite).
    pub fn authorize(
        &mut self,
        signer: [u8; 32],
        source_id: u8,
        max_confidence: Amount,
        scope: MarketScope,
    ) -> Result<(), OracleError> {
        if source_id >= MAX_SOURCES {
            return Err(OracleError::InvalidProducer);
        }
        if max_confidence.is_negative() {
            return Err(OracleError::InvalidProducer);
        }
        if self.by_signer.contains_key(&signer) {
            return Err(OracleError::InvalidProducer);
        }
        let scope = match scope {
            MarketScope::All => MarketScope::All,
            MarketScope::Only(mut markets) => {
                markets.sort_unstable();
                markets.dedup();
                MarketScope::Only(markets)
            }
        };
        self.by_signer.insert(
            signer,
            Producer {
                signer,
                source_id,
                max_confidence,
                scope,
            },
        );
        Ok(())
    }

    /// The producer authorized under `signer`, if any.
    #[inline]
    pub fn get(&self, signer: &[u8; 32]) -> Option<&Producer> {
        self.by_signer.get(signer)
    }

    /// A domain-separated commitment binding the version and every producer
    /// (signer, source id, confidence ceiling, market scope) in canonical
    /// ascending signer order. Deterministic and endianness-independent.
    pub fn commitment(&self) -> Hash {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&(self.by_signer.len() as u64).to_le_bytes());
        for (signer, p) in &self.by_signer {
            buf.extend_from_slice(signer);
            buf.push(p.source_id);
            buf.extend_from_slice(&p.max_confidence.raw().to_le_bytes());
            match &p.scope {
                MarketScope::All => buf.push(0),
                MarketScope::Only(markets) => {
                    buf.push(1);
                    buf.extend_from_slice(&(markets.len() as u64).to_le_bytes());
                    for m in markets {
                        buf.extend_from_slice(&m.get().to_le_bytes());
                    }
                }
            }
        }
        hash_domain(DOMAIN_ORACLE, &buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyPair;

    fn pk(seed: u8) -> [u8; 32] {
        KeyPair::from_seed(&[seed; 32]).public()
    }

    #[test]
    fn authorize_then_lookup_derives_source_and_bit() {
        let mut reg = ProducerRegistry::new(7);
        reg.authorize(pk(1), 5, Amount::from_raw(1_000), MarketScope::All)
            .unwrap();
        let p = reg.get(&pk(1)).unwrap();
        assert_eq!(p.source_id(), 5);
        assert_eq!(p.source_bit(), 1u64 << 5);
        assert_eq!(p.max_confidence(), Amount::from_raw(1_000));
        assert!(p.authorized_for(MarketId::new(42)));
        assert_eq!(reg.version(), 7);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn unknown_signer_absent() {
        let reg = ProducerRegistry::new(1);
        assert!(reg.get(&pk(9)).is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn authorize_rejects_out_of_range_source() {
        let mut reg = ProducerRegistry::new(1);
        assert_eq!(
            reg.authorize(pk(1), MAX_SOURCES, Amount::from_raw(1), MarketScope::All),
            Err(OracleError::InvalidProducer)
        );
    }

    #[test]
    fn authorize_rejects_negative_cap() {
        let mut reg = ProducerRegistry::new(1);
        assert_eq!(
            reg.authorize(pk(1), 0, Amount::from_raw(-1), MarketScope::All),
            Err(OracleError::InvalidProducer)
        );
    }

    #[test]
    fn authorize_rejects_duplicate_signer() {
        let mut reg = ProducerRegistry::new(1);
        reg.authorize(pk(1), 0, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        assert_eq!(
            reg.authorize(pk(1), 1, Amount::from_raw(2), MarketScope::All),
            Err(OracleError::InvalidProducer)
        );
    }

    #[test]
    fn market_scope_only_restricts_authorization() {
        let mut reg = ProducerRegistry::new(1);
        reg.authorize(
            pk(1),
            0,
            Amount::from_raw(1),
            MarketScope::Only(vec![MarketId::new(3), MarketId::new(1)]),
        )
        .unwrap();
        let p = reg.get(&pk(1)).unwrap();
        assert!(p.authorized_for(MarketId::new(1)));
        assert!(p.authorized_for(MarketId::new(3)));
        assert!(!p.authorized_for(MarketId::new(2)));
    }

    #[test]
    fn commitment_changes_with_version_and_membership() {
        let mut a = ProducerRegistry::new(1);
        a.authorize(pk(1), 0, Amount::from_raw(1), MarketScope::All)
            .unwrap();

        // Same membership, different version -> different commitment.
        let mut b = ProducerRegistry::new(2);
        b.authorize(pk(1), 0, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        assert_ne!(a.commitment(), b.commitment());

        // Same version, extra member -> different commitment.
        let mut c = ProducerRegistry::new(1);
        c.authorize(pk(1), 0, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        c.authorize(pk(2), 1, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        assert_ne!(a.commitment(), c.commitment());

        // Identical registries -> identical commitment.
        let mut d = ProducerRegistry::new(1);
        d.authorize(pk(1), 0, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        assert_eq!(a.commitment(), d.commitment());
    }

    #[test]
    fn commitment_is_insertion_order_independent() {
        let mut a = ProducerRegistry::new(9);
        a.authorize(pk(1), 0, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        a.authorize(pk(2), 1, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        let mut b = ProducerRegistry::new(9);
        b.authorize(pk(2), 1, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        b.authorize(pk(1), 0, Amount::from_raw(1), MarketScope::All)
            .unwrap();
        assert_eq!(a.commitment(), b.commitment());
    }
}
