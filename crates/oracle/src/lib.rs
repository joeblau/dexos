//! `oracle` — native threshold-signed price oracle subsystem for DexOS.
//!
//! The oracle turns many signed per-venue [`PriceObservation`]s into a single
//! trustworthy price through a deterministic, integer-only pipeline:
//!
//! 1. **Observation** — each signer signs a [`PriceObservation`] (ed25519 over
//!    domain-separated canonical bytes); tampered fields and foreign signers are
//!    rejected by [`PriceObservation::verify`]. An observation carries no
//!    self-declared venue claim — source identity is the registry's, not the
//!    reporter's.
//! 2. **Local aggregation** ([`aggregate_local`]) — trusting only the authorized
//!    [`ProducerRegistry`], it drops unknown/out-of-scope signers, forged
//!    signatures, far-future and stale timestamps; keeps only the newest report
//!    per signer; derives source identity and caps confidence locally; performs
//!    robust `k·MAD` outlier rejection; recomputes the distinct-source and
//!    minimum-observation gates from the survivors; and takes a
//!    confidence/liquidity-weighted median, producing a [`LocalAggregate`] with a
//!    confidence interval. Output is order-invariant and replay-stable.
//! 3. **Cross-node aggregation** ([`median_across_nodes`]) — combine per-node
//!    [`NodeAggregate`]s into a canonical [`AggregatePrice`], threshold-signed
//!    into an [`OracleCertificate`] by the oracle validator set.
//! 4. **Health** ([`health::evaluate`]) — a deterministic `NORMAL/DEGRADED/
//!    STALE/HALTED` state machine over freshness, source count, and dispersion,
//!    exposed so downstream markets can branch on it ([`health::market_action`]).
//! 5. **Engine** ([`OracleEngine`]) — applies verified certificates into
//!    canonical per-market state and commits a Merkle `oracle_root`, rejecting
//!    malformed / sub-threshold / stale-sequence updates without mutating state.
//!
//! The price oracle is intentionally separate from market *resolution*. An
//! optional [`ExternalReference`] adapter can contribute fallback samples that
//! flow through the very same pipeline (never a protocol dependency). No floating
//! point, no `unsafe`, no I/O; every fallible operation returns [`OracleError`].

pub mod adapter;
pub mod aggregate;
pub mod certificate;
pub mod codec;
pub mod engine;
pub mod error;
pub mod health;
pub mod kernels;
mod math;
pub mod observation;
pub mod producer;

pub use adapter::{merge_reference, ExternalReference};
pub use aggregate::{aggregate_local, AggregationConfig, LocalAggregate};
pub use certificate::{median_across_nodes, AggregatePrice, NodeAggregate, OracleCertificate};
pub use codec::{decode, encode};
pub use engine::{MarketOracleState, OracleEngine};
pub use error::OracleError;
pub use health::{
    evaluate as evaluate_health, market_action, HealthConfig, HealthInputs, MarketAction,
};
pub use observation::PriceObservation;
pub use producer::{MarketScope, Producer, ProducerRegistry, MAX_SOURCES};

// Re-export the shared health enum for convenience.
pub use types::OracleHealth;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "oracle";

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ThresholdSigners;
    use types::{Amount, MarketId, OracleHealth, Price};

    // Deterministic LCG so "property" tests are reproducible bit-for-bit.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn next_i64(&mut self) -> i64 {
            i64::from_le_bytes(self.next_u64().to_le_bytes())
        }
        fn next_i128(&mut self) -> i128 {
            (i128::from(self.next_i64()) << 64) | i128::from(self.next_u64())
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "oracle");
    }

    #[test]
    fn observation_codec_roundtrip_boundaries() {
        let o = PriceObservation {
            market_id: MarketId::new(u32::MAX),
            price: Price::from_raw(i64::MIN),
            confidence: Amount::from_raw(i128::MAX),
            observed_at_ns: u64::MAX,
            sequence: u64::MAX,
            signer: [0xABu8; 32],
            signature: [0xCDu8; 64],
        };
        let bytes = encode(&o).unwrap();
        let back: PriceObservation = decode(&bytes).unwrap();
        assert_eq!(o, back);

        let o2 = PriceObservation {
            market_id: MarketId::new(0),
            price: Price::from_raw(i64::MAX),
            confidence: Amount::from_raw(i128::MIN),
            observed_at_ns: 0,
            sequence: 0,
            signer: [0u8; 32],
            signature: [0u8; 64],
        };
        assert_eq!(
            o2,
            decode::<PriceObservation>(&encode(&o2).unwrap()).unwrap()
        );
    }

    #[test]
    fn health_enum_codec_roundtrip() {
        for h in [
            OracleHealth::Normal,
            OracleHealth::Degraded,
            OracleHealth::Stale,
            OracleHealth::Halted,
        ] {
            assert_eq!(h, decode::<OracleHealth>(&encode(&h).unwrap()).unwrap());
        }
    }

    #[test]
    fn certificate_codec_roundtrip() {
        let seeds: Vec<[u8; 32]> = (0..4).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        let ts = ThresholdSigners::from_seeds(&seeds, 3);
        let agg = AggregatePrice {
            market_id: MarketId::new(9),
            price: Price::from_raw(i64::MAX),
            confidence: Amount::from_raw(1_000_000),
            health: OracleHealth::Degraded,
            observed_at_ns: u64::MAX,
            sequence: 42,
            producer_set_version: 3,
            inputs_digest: types::Hash::from_bytes([0x5Au8; 32]),
        };
        let cert = OracleCertificate::form(agg, &ts, vec![0, 1, 2]);
        let bytes = encode(&cert).unwrap();
        let back: OracleCertificate = decode(&bytes).unwrap();
        assert_eq!(cert, back);
        // Round-tripped certificate still verifies.
        assert!(back.verify(&ts.validator_set()).is_ok());
    }

    #[test]
    fn property_decode_encode_is_identity() {
        let mut r = Lcg(0x0BAD_F00D);
        for _ in 0..3_000 {
            let o = PriceObservation {
                market_id: MarketId::new(u32::try_from(r.next_u64() & 0xFFFF_FFFF).unwrap()),
                price: Price::from_raw(r.next_i64()),
                confidence: Amount::from_raw(r.next_i128()),
                observed_at_ns: r.next_u64(),
                sequence: r.next_u64(),
                signer: r.next_u64().to_le_bytes().repeat(4)[..32]
                    .try_into()
                    .unwrap(),
                signature: r.next_u64().to_le_bytes().repeat(8)[..64]
                    .try_into()
                    .unwrap(),
            };
            let round: PriceObservation = decode(&encode(&o).unwrap()).unwrap();
            assert_eq!(o, round);
        }
    }

    #[test]
    fn decode_arbitrary_bytes_never_panics() {
        let mut r = Lcg(0xFEED_BEEF);
        for _ in 0..20_000 {
            let len = usize::try_from(r.next_u64() % 200).unwrap();
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(u8::try_from(r.next_u64() & 0xFF).unwrap());
            }
            // All decoders must return Result, never panic, on arbitrary input.
            let _ = decode::<PriceObservation>(&bytes);
            let _ = decode::<OracleCertificate>(&bytes);
            let _ = decode::<AggregatePrice>(&bytes);
            let _ = decode::<OracleHealth>(&bytes);
        }
    }

    #[test]
    fn end_to_end_pipeline() {
        use crypto::KeyPair;

        // Five signed venue observations for one market, from five authorized
        // producers each bound to a distinct source.
        let mut obs = Vec::new();
        let mut registry = ProducerRegistry::new(1);
        for (i, price) in [100i64, 101, 99, 100, 500].iter().enumerate() {
            let kp = KeyPair::from_seed(&[u8::try_from(i).unwrap() + 1; 32]);
            registry
                .authorize(
                    kp.public(),
                    u8::try_from(i).unwrap(),
                    Amount::from_raw(1_000_000),
                    MarketScope::All,
                )
                .unwrap();
            let mut o = PriceObservation::unsigned(
                MarketId::new(1),
                Price::from_raw(price * 1_000_000),
                Amount::from_raw(1),
                1_000,
                1,
            );
            o.sign(&kp);
            obs.push(o);
        }
        let cfg = AggregationConfig {
            max_age_ns: 10_000,
            min_observations: 3,
            min_sources: 3,
            ..AggregationConfig::default()
        };
        let local = aggregate_local(MarketId::new(1), &obs, 1_500, &cfg, &registry).unwrap();
        // Gross outlier (500) dropped; median of the tight cluster.
        assert_eq!(local.price, Price::from_raw(100_000_000));

        let health = local.health(&HealthConfig::default());
        let node = NodeAggregate {
            price: local.price,
            confidence: local.confidence,
            observed_at_ns: 1_000,
            producer_set_version: local.producer_set_version,
            inputs_digest: local.inputs_digest,
        };
        let agg = median_across_nodes(MarketId::new(1), &[node], health, 1).unwrap();

        let seeds: Vec<[u8; 32]> = (0..4).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        let ts = ThresholdSigners::from_seeds(&seeds, 3);
        let cert = OracleCertificate::form(agg, &ts, vec![0, 1, 2]);

        let mut engine = OracleEngine::new(ts.validator_set());
        assert!(engine.apply(&cert).is_ok());
        assert_eq!(
            engine.market(MarketId::new(1)).unwrap().price(),
            local.price
        );
        assert!(!engine.oracle_root().is_zero());
    }
}
