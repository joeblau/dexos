//! Threshold-signed oracle certificates across oracle nodes.
//!
//! Each oracle node aggregates locally (see [`crate::aggregate`]) and reports a
//! [`NodeAggregate`]. [`median_across_nodes`] combines those into a canonical
//! [`AggregatePrice`], whose domain-separated [`AggregatePrice::digest`] is then
//! threshold-signed by the oracle validator set to form an [`OracleCertificate`].
//! Verification recomputes the digest (rejecting tampered fields) and checks the
//! quorum reaches threshold weight (rejecting sub-threshold and wrong-signer
//! certificates).

use crypto::{hash_domain, QuorumCertificate, ThresholdSigners, ValidatorSet, DOMAIN_ORACLE};
use serde::{Deserialize, Serialize};
use types::{Amount, Hash, MarketId, OracleHealth, Price};

use crate::error::OracleError;
use crate::health::health_tag;
use crate::math::{weighted_median, Sample};

/// One oracle node's aggregated view of a market, prior to threshold signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAggregate {
    /// Node's weighted-median price.
    pub price: Price,
    /// Node's confidence/liquidity weight.
    pub confidence: Amount,
    /// Node's freshest observation timestamp (ns).
    pub observed_at_ns: u64,
}

/// The canonical aggregate price agreed across oracle nodes. This is the payload
/// the oracle validator set threshold-signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatePrice {
    /// Market priced.
    pub market_id: MarketId,
    /// Cross-node median price.
    pub price: Price,
    /// Cross-node confidence.
    pub confidence: Amount,
    /// Oracle health at aggregation time.
    pub health: OracleHealth,
    /// Conservative (minimum) freshness across nodes, in ns.
    pub observed_at_ns: u64,
    /// Monotonic oracle-update sequence for this market.
    pub sequence: u64,
}

impl AggregatePrice {
    /// Domain-separated 32-byte digest bound by the threshold signature. Fixed
    /// little-endian layout; deterministic across machines.
    pub fn digest(&self) -> Hash {
        let mut buf = Vec::with_capacity(4 + 8 + 16 + 1 + 8 + 8);
        buf.extend_from_slice(&self.market_id.get().to_le_bytes());
        buf.extend_from_slice(&self.price.raw().to_le_bytes());
        buf.extend_from_slice(&self.confidence.raw().to_le_bytes());
        buf.push(health_tag(self.health));
        buf.extend_from_slice(&self.observed_at_ns.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        hash_domain(DOMAIN_ORACLE, &buf)
    }
}

/// Combine per-node aggregates into a canonical [`AggregatePrice`] by taking the
/// confidence-weighted median across nodes. Order-independent. The `health` and
/// `sequence` are supplied by the caller (engine policy). Returns `None` if no
/// nodes are provided.
pub fn median_across_nodes(
    market_id: MarketId,
    nodes: &[NodeAggregate],
    health: OracleHealth,
    sequence: u64,
) -> Option<AggregatePrice> {
    if nodes.is_empty() {
        return None;
    }
    let samples: Vec<Sample> = nodes
        .iter()
        .map(|n| Sample {
            price: n.price.raw(),
            weight: n.confidence.raw(),
        })
        .collect();
    let price_raw = weighted_median(&samples)?;
    let confidence = nodes
        .iter()
        .fold(Amount::ZERO, |acc, n| acc.saturating_add(n.confidence));
    let observed_at_ns = nodes.iter().map(|n| n.observed_at_ns).min().unwrap_or(0);
    Some(AggregatePrice {
        market_id,
        price: Price::from_raw(price_raw),
        confidence,
        health,
        observed_at_ns,
        sequence,
    })
}

/// A threshold-signed oracle price certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleCertificate {
    /// The signed aggregate price payload.
    pub aggregate: AggregatePrice,
    /// Quorum certificate over `aggregate.digest()`.
    pub quorum: QuorumCertificate,
}

impl OracleCertificate {
    /// Form a certificate by threshold-signing `aggregate` with `signers` at the
    /// given signer indices. The quorum message is bound to the aggregate digest.
    pub fn form(
        aggregate: AggregatePrice,
        signers: &ThresholdSigners,
        indices: Vec<usize>,
    ) -> OracleCertificate {
        let quorum = signers.sign(aggregate.digest(), indices);
        OracleCertificate { aggregate, quorum }
    }

    /// Verify the certificate against `set`: the quorum message must equal the
    /// recomputed aggregate digest (rejecting tampered payloads) and the quorum
    /// must reach threshold weight with valid member signatures (rejecting
    /// sub-threshold and wrong-signer certificates). Never panics.
    pub fn verify(&self, set: &ValidatorSet) -> Result<(), OracleError> {
        if self.quorum.message != self.aggregate.digest() {
            return Err(OracleError::DigestMismatch);
        }
        set.verify(&self.quorum)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::QuorumError;

    fn signers(n: usize, k: u64) -> ThresholdSigners {
        let seeds: Vec<[u8; 32]> = (0..n).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        ThresholdSigners::from_seeds(&seeds, k)
    }

    fn agg(seq: u64, price: i64) -> AggregatePrice {
        AggregatePrice {
            market_id: MarketId::new(3),
            price: Price::from_raw(price),
            confidence: Amount::from_raw(1_000_000),
            health: OracleHealth::Normal,
            observed_at_ns: 1_000,
            sequence: seq,
        }
    }

    #[test]
    fn median_across_nodes_hand_computed() {
        let nodes = [
            NodeAggregate {
                price: Price::from_raw(100),
                confidence: Amount::from_raw(1),
                observed_at_ns: 50,
            },
            NodeAggregate {
                price: Price::from_raw(200),
                confidence: Amount::from_raw(1),
                observed_at_ns: 40,
            },
            NodeAggregate {
                price: Price::from_raw(300),
                confidence: Amount::from_raw(1),
                observed_at_ns: 60,
            },
        ];
        let a = median_across_nodes(MarketId::new(3), &nodes, OracleHealth::Normal, 1).unwrap();
        assert_eq!(a.price, Price::from_raw(200));
        assert_eq!(a.observed_at_ns, 40); // conservative min
    }

    #[test]
    fn certificate_forms_and_verifies_at_quorum() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let cert = OracleCertificate::form(agg(1, 100), &ts, vec![0, 1, 2]);
        assert!(cert.verify(&set).is_ok());
    }

    #[test]
    fn certificate_below_threshold_rejected() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let cert = OracleCertificate::form(agg(1, 100), &ts, vec![0, 1]);
        assert!(matches!(
            cert.verify(&set),
            Err(OracleError::Quorum(QuorumError::BelowThreshold { .. }))
        ));
    }

    #[test]
    fn tampered_payload_rejected() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let mut cert = OracleCertificate::form(agg(1, 100), &ts, vec![0, 1, 2]);
        // Mutate the payload after signing: digest no longer matches quorum msg.
        cert.aggregate.price = Price::from_raw(999);
        assert_eq!(cert.verify(&set), Err(OracleError::DigestMismatch));
    }

    #[test]
    fn wrong_signer_rejected() {
        let ts = signers(4, 3);
        // A disjoint key set (seeds offset by 100) signs the same digest.
        let foreign_seeds: Vec<[u8; 32]> = (0..4)
            .map(|i| [u8::try_from(i).unwrap() + 100; 32])
            .collect();
        let foreign = ThresholdSigners::from_seeds(&foreign_seeds, 3);
        let set = ts.validator_set();
        let cert = OracleCertificate::form(agg(1, 100), &foreign, vec![0, 1, 2]);
        // Digest matches (same payload) but member signatures are from foreign keys.
        assert_eq!(cert.quorum.message, cert.aggregate.digest());
        assert!(matches!(
            cert.verify(&set),
            Err(OracleError::Quorum(QuorumError::InvalidSignature))
        ));
    }

    #[test]
    fn identical_node_sets_yield_bit_identical_certificate() {
        let ts = signers(5, 3);
        let nodes = [
            NodeAggregate {
                price: Price::from_raw(100),
                confidence: Amount::from_raw(2),
                observed_at_ns: 10,
            },
            NodeAggregate {
                price: Price::from_raw(110),
                confidence: Amount::from_raw(1),
                observed_at_ns: 20,
            },
            NodeAggregate {
                price: Price::from_raw(90),
                confidence: Amount::from_raw(3),
                observed_at_ns: 30,
            },
        ];
        let mut reordered = nodes;
        reordered.reverse();
        let a = median_across_nodes(MarketId::new(3), &nodes, OracleHealth::Normal, 7).unwrap();
        let b = median_across_nodes(MarketId::new(3), &reordered, OracleHealth::Normal, 7).unwrap();
        assert_eq!(a, b);
        let ca = OracleCertificate::form(a, &ts, vec![0, 1, 2]);
        let cb = OracleCertificate::form(b, &ts, vec![2, 1, 0]);
        assert_eq!(ca, cb);
    }
}
