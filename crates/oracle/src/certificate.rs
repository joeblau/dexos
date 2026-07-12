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
    /// Version of the authorized producer set this node aggregated over.
    pub producer_set_version: u64,
    /// This node's commitment to exactly the authorized reports it aggregated.
    pub inputs_digest: Hash,
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
    /// Version of the authorized producer set that produced this price. Committed
    /// so verifiers agree on which authorized set is responsible.
    pub producer_set_version: u64,
    /// Order-independent commitment over the per-node aggregation inputs.
    pub inputs_digest: Hash,
}

impl AggregatePrice {
    /// Domain-separated 32-byte digest bound by the threshold signature. Fixed
    /// little-endian layout; deterministic across machines.
    pub fn digest(&self) -> Hash {
        let mut buf = Vec::with_capacity(4 + 8 + 16 + 1 + 8 + 8 + 8 + 32);
        buf.extend_from_slice(&self.market_id.get().to_le_bytes());
        buf.extend_from_slice(&self.price.raw().to_le_bytes());
        buf.extend_from_slice(&self.confidence.raw().to_le_bytes());
        buf.push(health_tag(self.health));
        buf.extend_from_slice(&self.observed_at_ns.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.producer_set_version.to_le_bytes());
        buf.extend_from_slice(self.inputs_digest.as_bytes());
        hash_domain(DOMAIN_ORACLE, &buf)
    }
}

/// Combine per-node aggregates into a canonical [`AggregatePrice`] by taking the
/// confidence-weighted median across nodes. Order-independent. The `health` and
/// `sequence` are supplied by the caller (engine policy). The producer-set
/// version and an order-independent commitment over the per-node inputs are
/// derived from `nodes` and committed into the result.
///
/// Returns `None` if no nodes are provided, or if the nodes do not all reference
/// the same producer-set version (an inconsistent set cannot be certified).
pub fn median_across_nodes(
    market_id: MarketId,
    nodes: &[NodeAggregate],
    health: OracleHealth,
    sequence: u64,
) -> Option<AggregatePrice> {
    let (first, rest) = nodes.split_first()?;
    let producer_set_version = first.producer_set_version;
    if rest
        .iter()
        .any(|n| n.producer_set_version != producer_set_version)
    {
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
    let inputs_digest = combine_node_inputs(producer_set_version, nodes);
    Some(AggregatePrice {
        market_id,
        price: Price::from_raw(price_raw),
        confidence,
        health,
        observed_at_ns,
        sequence,
        producer_set_version,
        inputs_digest,
    })
}

/// Order-independent commitment folding the per-node input digests (sorted) and
/// the producer-set version into a single domain-separated hash.
fn combine_node_inputs(version: u64, nodes: &[NodeAggregate]) -> Hash {
    let mut digests: Vec<[u8; 32]> = nodes.iter().map(|n| *n.inputs_digest.as_bytes()).collect();
    digests.sort_unstable();
    let mut buf = Vec::with_capacity(8 + 8 + digests.len() * 32);
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&(digests.len() as u64).to_le_bytes());
    for d in &digests {
        buf.extend_from_slice(d);
    }
    hash_domain(DOMAIN_ORACLE, &buf)
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
            producer_set_version: 1,
            inputs_digest: Hash::from_bytes([7u8; 32]),
        }
    }

    fn node(price: i64, conf: i128, ts: u64, version: u64, digest: u8) -> NodeAggregate {
        NodeAggregate {
            price: Price::from_raw(price),
            confidence: Amount::from_raw(conf),
            observed_at_ns: ts,
            producer_set_version: version,
            inputs_digest: Hash::from_bytes([digest; 32]),
        }
    }

    #[test]
    fn median_across_nodes_hand_computed() {
        let nodes = [
            node(100, 1, 50, 1, 10),
            node(200, 1, 40, 1, 20),
            node(300, 1, 60, 1, 30),
        ];
        let a = median_across_nodes(MarketId::new(3), &nodes, OracleHealth::Normal, 1).unwrap();
        assert_eq!(a.price, Price::from_raw(200));
        assert_eq!(a.observed_at_ns, 40); // conservative min
        assert_eq!(a.producer_set_version, 1);
    }

    #[test]
    fn median_across_nodes_rejects_producer_set_disagreement() {
        // Two nodes reference different producer-set versions -> cannot certify.
        let nodes = [node(100, 1, 50, 1, 10), node(200, 1, 40, 2, 20)];
        assert!(median_across_nodes(MarketId::new(3), &nodes, OracleHealth::Normal, 1).is_none());
    }

    #[test]
    fn tampered_producer_set_version_rejected() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let mut cert = OracleCertificate::form(agg(1, 100), &ts, vec![0, 1, 2]);
        // The producer-set version is part of the signed digest.
        cert.aggregate.producer_set_version = 999;
        assert_eq!(cert.verify(&set), Err(OracleError::DigestMismatch));
    }

    #[test]
    fn tampered_inputs_digest_rejected() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let mut cert = OracleCertificate::form(agg(1, 100), &ts, vec![0, 1, 2]);
        cert.aggregate.inputs_digest = Hash::from_bytes([0xAB; 32]);
        assert_eq!(cert.verify(&set), Err(OracleError::DigestMismatch));
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
            node(100, 2, 10, 1, 11),
            node(110, 1, 20, 1, 22),
            node(90, 3, 30, 1, 33),
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
