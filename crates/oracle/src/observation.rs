//! Signed per-venue price observations.
//!
//! A [`PriceObservation`] is a single oracle signer's report of a market price
//! at a point in time. It carries an ed25519 signature over its domain-separated
//! canonical bytes; [`PriceObservation::verify`] rejects tampered fields and
//! foreign signers. The signature covers every field *except* the signature
//! itself (the signer key is authenticated implicitly by verification).
//!
//! An observation deliberately carries **no self-declared venue/source claim**.
//! Source identity is not the reporter's to assert: it is derived locally from
//! the authorized [`crate::ProducerRegistry`], keyed by the authenticated
//! `signer`. This is what prevents one actor from fabricating venue diversity.

use crypto::{hash_domain, verify_ed25519, KeyPair, DOMAIN_ORACLE};
use serde::{Deserialize, Serialize};
use types::{Amount, Hash, MarketId, Price};

use crate::codec::sig64;
use crate::error::OracleError;

/// A single signed price observation from one oracle signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceObservation {
    /// Market this observation prices.
    pub market_id: MarketId,
    /// Observed price (fixed-point, 6 dp).
    pub price: Price,
    /// Confidence / liquidity weight behind the price (micro-units). Bounded by
    /// the signer's registered ceiling during aggregation; the raw claim here is
    /// never trusted unbounded.
    pub confidence: Amount,
    /// Observation timestamp in nanoseconds since the epoch.
    pub observed_at_ns: u64,
    /// Per-signer monotonic sequence number.
    pub sequence: u64,
    /// ed25519 public key of the signer.
    pub signer: [u8; 32],
    /// ed25519 signature over the canonical signing bytes.
    #[serde(with = "sig64")]
    pub signature: [u8; 64],
}

impl PriceObservation {
    /// Build an unsigned observation (zeroed signer/signature). Call
    /// [`PriceObservation::sign`] to authenticate it.
    pub fn unsigned(
        market_id: MarketId,
        price: Price,
        confidence: Amount,
        observed_at_ns: u64,
        sequence: u64,
    ) -> Self {
        Self {
            market_id,
            price,
            confidence,
            observed_at_ns,
            sequence,
            signer: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    /// Domain-separated 32-byte digest that the signature covers. Deterministic
    /// and endianness-independent (all integers little-endian, fixed layout).
    pub fn signing_digest(&self) -> Hash {
        let mut buf = Vec::with_capacity(4 + 8 + 16 + 8 + 8);
        buf.extend_from_slice(&self.market_id.get().to_le_bytes());
        buf.extend_from_slice(&self.price.raw().to_le_bytes());
        buf.extend_from_slice(&self.confidence.raw().to_le_bytes());
        buf.extend_from_slice(&self.observed_at_ns.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        hash_domain(DOMAIN_ORACLE, &buf)
    }

    /// Sign this observation with `keypair`, setting `signer` and `signature`.
    pub fn sign(&mut self, keypair: &KeyPair) {
        self.signer = keypair.public();
        let digest = self.signing_digest();
        self.signature = keypair.sign(digest.as_bytes());
    }

    /// Verify the signature against the named `signer`. Returns
    /// [`OracleError::InvalidSignature`] for tampered fields or a foreign signer,
    /// and [`OracleError::MalformedSigner`] for an invalid key. Never panics.
    ///
    /// Verifying only proves possession of the named key; it does **not** prove
    /// the signer is authorized. Authorization is enforced separately against the
    /// [`crate::ProducerRegistry`] during aggregation.
    pub fn verify(&self) -> Result<(), OracleError> {
        let digest = self.signing_digest();
        verify_ed25519(&self.signer, digest.as_bytes(), &self.signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(kp: &KeyPair, seq: u64) -> PriceObservation {
        let mut o = PriceObservation::unsigned(
            MarketId::new(7),
            Price::from_raw(1_500_000),
            Amount::from_raw(1_000_000),
            1_000,
            seq,
        );
        o.sign(kp);
        o
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let kp = KeyPair::from_seed(&[1u8; 32]);
        let o = obs(&kp, 1);
        assert_eq!(o.signer, kp.public());
        assert!(o.verify().is_ok());
    }

    #[test]
    fn tampered_price_fails_verify() {
        let kp = KeyPair::from_seed(&[2u8; 32]);
        let mut o = obs(&kp, 1);
        o.price = Price::from_raw(o.price.raw() + 1);
        assert_eq!(o.verify(), Err(OracleError::InvalidSignature));
    }

    #[test]
    fn tampered_confidence_fails_verify() {
        let kp = KeyPair::from_seed(&[5u8; 32]);
        let mut o = obs(&kp, 1);
        o.confidence = Amount::from_raw(o.confidence.raw() + 1);
        assert_eq!(o.verify(), Err(OracleError::InvalidSignature));
    }

    #[test]
    fn foreign_signer_rejected() {
        let kp = KeyPair::from_seed(&[3u8; 32]);
        let foreign = KeyPair::from_seed(&[9u8; 32]);
        let mut o = obs(&kp, 1);
        // Swap in a foreign signer key: signature no longer matches.
        o.signer = foreign.public();
        assert_eq!(o.verify(), Err(OracleError::InvalidSignature));
    }

    #[test]
    fn malformed_signer_key_rejected() {
        let kp = KeyPair::from_seed(&[4u8; 32]);
        let mut o = obs(&kp, 1);
        o.signer = [0xffu8; 32]; // not a valid compressed Edwards point
        assert!(matches!(
            o.verify(),
            Err(OracleError::MalformedSigner) | Err(OracleError::InvalidSignature)
        ));
    }
}
