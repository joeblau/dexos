//! Deterministic, integer-only local venue aggregation over *authorized* reports.
//!
//! Given a set of signed [`PriceObservation`]s for one market and the authorized
//! [`ProducerRegistry`], [`aggregate_local`] applies, in order:
//!
//! 1. **Authorization + authentication** — drop reports from unknown signers,
//!    signers not scoped to this market, tampered/forged signatures, timestamps
//!    beyond the future-skew tolerance, and stale timestamps. Source identity and
//!    the confidence ceiling are derived *locally* from the registry, never from
//!    the report.
//! 2. **One vote per signer** — keep only the newest monotonic report per signer;
//!    replays and sequence rollbacks are dropped.
//! 3. **Robust outlier rejection** — drop samples beyond `center ± k·MAD`.
//! 4. **Recomputed gates** — the distinct-source *and* minimum-observation gates
//!    are recomputed from the final survivors, so an outlier's source can never
//!    prop up diversity.
//! 5. **Weighted median** — a confidence/liquidity-weighted median with a
//!    confidence interval and the signals that drive [`crate::health`].
//!
//! The output is invariant to input ordering and bit-identical across runs on
//! identical inputs. It also commits an `inputs_digest` binding exactly the
//! surviving authorized reports and the producer-set version.

use std::collections::BTreeMap;

use crypto::{hash_domain, DOMAIN_ORACLE};
use types::{Amount, Hash, MarketId, OracleHealth, Price, Ratio, RATIO_SCALE};

use crate::error::OracleError;
use crate::health::{evaluate, HealthConfig, HealthInputs};
use crate::math::{
    dispersion_bps, median_absolute_deviation, scale_by_ratio, weighted_median, Sample,
};
use crate::observation::PriceObservation;
use crate::producer::ProducerRegistry;

/// Hard bound on untrusted reports admitted to one aggregation tick. The check
/// precedes registry lookup, signature verification, and statistical work.
pub const MAX_AGGREGATION_OBSERVATIONS: usize = 1_024;

/// Tunable parameters for local aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregationConfig {
    /// Observations older than this (relative to `now_ns`) are dropped.
    pub max_age_ns: u64,
    /// Observations timestamped further than this ahead of `now_ns` are rejected
    /// (a small tolerance for clock skew; anything beyond is treated as forged).
    pub max_future_skew_ns: u64,
    /// Minimum observations that must survive filtering and outlier rejection.
    pub min_observations: usize,
    /// Minimum distinct sources (union of derived source bits) required.
    pub min_sources: u32,
    /// Outlier band multiplier `k`: drop samples beyond `center ± k·MAD`.
    pub mad_k: Ratio,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            max_age_ns: 5_000_000_000,         // 5s
            max_future_skew_ns: 1_000_000_000, // 1s clock-skew tolerance
            min_observations: 3,
            min_sources: 3,
            mad_k: Ratio::from_raw(3 * RATIO_SCALE), // 3.0 · MAD
        }
    }
}

/// The result of local aggregation for one market.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAggregate {
    /// Market aggregated.
    pub market_id: MarketId,
    /// Confidence/liquidity-weighted median price.
    pub price: Price,
    /// Summed (policy-capped) confidence/liquidity of the surviving observations.
    pub confidence: Amount,
    /// Lower confidence bound (`price − k·MAD`, saturating).
    pub lower: Price,
    /// Upper confidence bound (`price + k·MAD`, saturating).
    pub upper: Price,
    /// Union of derived source bits of surviving observations.
    pub source_mask: u64,
    /// Distinct sources surviving (union popcount).
    pub sources: u32,
    /// Count of observations surviving outlier rejection.
    pub observations: usize,
    /// Age of the newest surviving observation, in nanoseconds.
    pub newest_age_ns: u64,
    /// Relative dispersion (MAD/price) in basis points.
    pub dispersion_bps: i64,
    /// Version of the authorized producer set used to produce this aggregate.
    pub producer_set_version: u64,
    /// Commitment binding exactly the surviving authorized reports (and version).
    pub inputs_digest: Hash,
}

impl LocalAggregate {
    /// The health inputs implied by this aggregate.
    pub fn health_inputs(&self) -> HealthInputs {
        HealthInputs {
            newest_age_ns: self.newest_age_ns,
            sources: self.sources,
            observations: self.observations,
            dispersion_bps: self.dispersion_bps,
        }
    }

    /// Evaluate this aggregate's health against `cfg`.
    pub fn health(&self, cfg: &HealthConfig) -> OracleHealth {
        evaluate(self.health_inputs(), cfg)
    }
}

/// A single authorized, authenticated, non-stale report after normalization. The
/// source bit and weight are derived from the registry, not from the report.
#[derive(Debug, Clone, Copy)]
struct Authorized {
    signer: [u8; 32],
    source_bit: u64,
    price: i64,
    /// Confidence clamped to `[0, producer.max_confidence]`.
    weight: i128,
    sequence: u64,
    age: u64,
}

impl Authorized {
    /// Whether `self` should replace `other` as the retained report for a signer.
    /// A strictly higher sequence wins; ties break deterministically so replays
    /// (identical reports) collapse and rollbacks (lower sequence) are dropped.
    fn supersedes(&self, other: &Authorized) -> bool {
        (self.sequence, self.price, self.weight) > (other.sequence, other.price, other.weight)
    }
}

/// Aggregate `observations` for `market_id` at wall-clock `now_ns`, trusting only
/// reports from the authorized `producers` set.
///
/// Reports from unknown signers, signers out of market scope, forged signatures,
/// far-future or stale timestamps, and all but the newest report per signer are
/// discarded before any statistic is computed.
pub fn aggregate_local(
    market_id: MarketId,
    observations: &[PriceObservation],
    now_ns: u64,
    cfg: &AggregationConfig,
    producers: &ProducerRegistry,
) -> Result<LocalAggregate, OracleError> {
    if observations.len() > MAX_AGGREGATION_OBSERVATIONS {
        return Err(OracleError::TooManyObservations {
            have: observations.len(),
            max: MAX_AGGREGATION_OBSERVATIONS,
        });
    }
    // 1. Authorize, authenticate, and normalize; 2. keep the newest per signer.
    //    Keyed by signer, so iteration order is canonical and input-order
    //    independent.
    let horizon = now_ns.saturating_add(cfg.max_future_skew_ns);
    let mut newest_by_signer: BTreeMap<[u8; 32], Authorized> = BTreeMap::new();
    for o in observations {
        if o.market_id != market_id {
            continue;
        }
        let Some(producer) = producers.get(&o.signer) else {
            continue; // unknown / unauthorized key
        };
        if !producer.authorized_for(market_id) {
            continue; // authorized signer, but not for this market
        }
        if o.verify().is_err() {
            continue; // forged or tampered
        }
        if o.observed_at_ns > horizon {
            continue; // far-future timestamp (never allowed to read as "fresh")
        }
        let age = now_ns.saturating_sub(o.observed_at_ns);
        if age > cfg.max_age_ns {
            continue; // stale
        }
        // Source identity and the weight ceiling are the registry's, not the
        // report's: bound the claimed confidence to `[0, cap]`.
        let weight = o.confidence.raw().clamp(0, producer.max_confidence().raw());
        let record = Authorized {
            signer: o.signer,
            source_bit: producer.source_bit(),
            price: o.price.raw(),
            weight,
            sequence: o.sequence,
            age,
        };
        match newest_by_signer.get(&o.signer) {
            Some(existing) if !record.supersedes(existing) => {} // replay / rollback
            _ => {
                newest_by_signer.insert(o.signer, record);
            }
        }
    }

    if newest_by_signer.is_empty() {
        return Err(OracleError::NoObservations);
    }

    // Canonical (ascending signer) order.
    let records: Vec<Authorized> = newest_by_signer.into_values().collect();

    // 3. Robust center + MAD outlier band.
    let samples: Vec<Sample> = records
        .iter()
        .map(|r| Sample {
            price: r.price,
            weight: r.weight,
        })
        .collect();
    let center = weighted_median(&samples).ok_or(OracleError::NoObservations)?;
    let prices: Vec<i64> = records.iter().map(|r| r.price).collect();
    let mad = median_absolute_deviation(&prices, center);
    let band = scale_by_ratio(mad, cfg.mad_k);

    // Drop outliers (skip when MAD == 0, i.e. no dispersion to reject against).
    let survivors: Vec<Authorized> = records
        .into_iter()
        .filter(|r| mad == 0 || (i128::from(r.price) - i128::from(center)).abs() <= band)
        .collect();

    // 4. Recompute BOTH gates from the final survivors: an outlier's source can
    //    never prop up diversity, and neither gate is satisfied by dropped rows.
    let source_mask = survivors.iter().fold(0u64, |m, r| m | r.source_bit);
    let sources = source_mask.count_ones();
    if sources < cfg.min_sources {
        return Err(OracleError::TooFewSources {
            have: sources,
            need: cfg.min_sources,
        });
    }
    if survivors.len() < cfg.min_observations {
        return Err(OracleError::TooFewObservations {
            have: survivors.len(),
            need: cfg.min_observations,
        });
    }

    // 5. Final weighted median over survivors + aggregate signals.
    let final_samples: Vec<Sample> = survivors
        .iter()
        .map(|r| Sample {
            price: r.price,
            weight: r.weight,
        })
        .collect();
    let price_raw = weighted_median(&final_samples).ok_or(OracleError::NoObservations)?;

    let confidence = survivors.iter().fold(Amount::ZERO, |acc, r| {
        acc.saturating_add(Amount::from_raw(r.weight))
    });
    let newest_age_ns = survivors.iter().map(|r| r.age).min().unwrap_or(0);

    let band_i64 = i64::try_from(band).unwrap_or(i64::MAX);
    let lower = Price::from_raw(price_raw).saturating_sub(Price::from_raw(band_i64));
    let upper = Price::from_raw(price_raw).saturating_add(Price::from_raw(band_i64));
    let disp = dispersion_bps(mad, price_raw);
    let inputs_digest = commit_inputs(market_id, producers.version(), &survivors);

    Ok(LocalAggregate {
        market_id,
        price: Price::from_raw(price_raw),
        confidence,
        lower,
        upper,
        source_mask,
        sources,
        observations: survivors.len(),
        newest_age_ns,
        dispersion_bps: disp,
        producer_set_version: producers.version(),
        inputs_digest,
    })
}

/// Domain-separated commitment over exactly the surviving authorized reports (in
/// canonical signer order) plus the market and producer-set version.
fn commit_inputs(market_id: MarketId, version: u64, survivors: &[Authorized]) -> Hash {
    let mut buf = Vec::with_capacity(4 + 8 + 8 + survivors.len() * (32 + 8 + 8 + 16 + 8));
    buf.extend_from_slice(&market_id.get().to_le_bytes());
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&(survivors.len() as u64).to_le_bytes());
    for r in survivors {
        buf.extend_from_slice(&r.signer);
        buf.extend_from_slice(&r.source_bit.to_le_bytes());
        buf.extend_from_slice(&r.price.to_le_bytes());
        buf.extend_from_slice(&r.weight.to_le_bytes());
        buf.extend_from_slice(&r.sequence.to_le_bytes());
    }
    hash_domain(DOMAIN_ORACLE, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::producer::MarketScope;
    use crypto::KeyPair;

    fn kp(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32])
    }

    fn signed(
        market: u32,
        price: i64,
        conf: i128,
        ts: u64,
        seq: u64,
        seed: u8,
    ) -> PriceObservation {
        let mut o = PriceObservation::unsigned(
            MarketId::new(market),
            Price::from_raw(price),
            Amount::from_raw(conf),
            ts,
            seq,
        );
        o.sign(&kp(seed));
        o
    }

    const BIG_CAP: i128 = 1_000_000_000_000;

    /// Authorize each `seed` to a distinct source id (its slice index), all
    /// markets, generous confidence ceiling.
    fn registry(seeds: &[u8]) -> ProducerRegistry {
        let mut reg = ProducerRegistry::new(1);
        for (i, &s) in seeds.iter().enumerate() {
            reg.authorize(
                kp(s).public(),
                u8::try_from(i).unwrap(),
                Amount::from_raw(BIG_CAP),
                MarketScope::All,
            )
            .unwrap();
        }
        reg
    }

    /// Authorize explicit (seed, source_id) pairs (lets sources be shared).
    fn registry_pairs(pairs: &[(u8, u8)]) -> ProducerRegistry {
        let mut reg = ProducerRegistry::new(1);
        for &(seed, src) in pairs {
            reg.authorize(
                kp(seed).public(),
                src,
                Amount::from_raw(BIG_CAP),
                MarketScope::All,
            )
            .unwrap();
        }
        reg
    }

    fn cfg() -> AggregationConfig {
        AggregationConfig {
            max_age_ns: 1_000,
            max_future_skew_ns: 1_000,
            min_observations: 3,
            min_sources: 3,
            mad_k: Ratio::from_raw(3 * RATIO_SCALE),
        }
    }

    #[test]
    fn oversized_batch_is_rejected_before_authentication() {
        let obs = vec![signed(1, 100_000_000, 1, 1_000, 1, 1); MAX_AGGREGATION_OBSERVATIONS + 1];
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 1_000, &cfg(), &registry(&[1])),
            Err(OracleError::TooManyObservations {
                have: MAX_AGGREGATION_OBSERVATIONS + 1,
                max: MAX_AGGREGATION_OBSERVATIONS,
            })
        );
    }

    #[test]
    fn weighted_median_and_outlier_rejection_hand_computed() {
        // Four tight quotes around 100 plus one gross outlier at 1000.
        let obs = [
            signed(1, 100_000_000, 1, 1000, 1, 1),
            signed(1, 101_000_000, 1, 1000, 1, 2),
            signed(1, 99_000_000, 1, 1000, 1, 3),
            signed(1, 100_000_000, 1, 1000, 1, 4),
            signed(1, 1_000_000_000, 1, 1000, 1, 5),
        ];
        let reg = registry(&[1, 2, 3, 4, 5]);
        let agg = aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg).unwrap();
        // Outlier dropped -> median of {99,100,100,101} lower-median = 100.
        assert_eq!(agg.price, Price::from_raw(100_000_000));
        assert_eq!(agg.observations, 4);
        assert_eq!(agg.sources, 4); // outlier's source excluded
        assert_eq!(agg.producer_set_version, 1);
    }

    #[test]
    fn staleness_filtering_drops_old() {
        let obs = [
            signed(1, 100_000_000, 1, 10_000, 1, 1), // fresh (now 10_500)
            signed(1, 100_000_000, 1, 10_000, 1, 2),
            signed(1, 100_000_000, 1, 10_000, 1, 3),
            signed(1, 500_000_000, 1, 1, 1, 4), // ancient -> dropped
        ];
        let reg = registry(&[1, 2, 3, 4]);
        let agg = aggregate_local(MarketId::new(1), &obs, 10_500, &cfg(), &reg).unwrap();
        assert_eq!(agg.observations, 3);
        assert_eq!(agg.price, Price::from_raw(100_000_000));
    }

    #[test]
    fn min_sources_gate() {
        // Three signers but only two distinct sources (seeds 1 and 2 share src 0).
        let obs = [
            signed(1, 100_000_000, 1, 1000, 1, 1),
            signed(1, 100_000_000, 1, 1000, 1, 2),
            signed(1, 100_000_000, 1, 1000, 1, 3),
        ];
        let reg = registry_pairs(&[(1, 0), (2, 0), (3, 1)]);
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg),
            Err(OracleError::TooFewSources { have: 2, need: 3 })
        );
    }

    #[test]
    fn min_observations_gate() {
        // Two fresh survivors from distinct sources satisfy a 2-source gate but
        // not the 3-observation gate; the third is stale and dropped.
        let obs = [
            signed(1, 100_000_000, 1, 2500, 1, 1), // fresh
            signed(1, 100_000_000, 1, 2500, 1, 2), // fresh
            signed(1, 100_000_000, 1, 1000, 1, 3), // stale (age 2000 > 1000)
        ];
        let reg = registry(&[1, 2, 3]);
        let cfg = AggregationConfig {
            min_sources: 2,
            ..cfg()
        };
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 3000, &cfg, &reg),
            Err(OracleError::TooFewObservations { have: 2, need: 3 })
        );
    }

    #[test]
    fn permutation_invariant_and_adapter_idempotent() {
        let obs = [
            signed(1, 100_000_000, 3, 1000, 1, 1),
            signed(1, 102_000_000, 1, 1000, 1, 2),
            signed(1, 98_000_000, 4, 1000, 1, 3),
            signed(1, 101_000_000, 2, 1000, 1, 4),
        ];
        let reg = registry(&[1, 2, 3, 4]);
        let base = aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg).unwrap();

        let mut permuted = obs;
        permuted.reverse();
        let perm = aggregate_local(MarketId::new(1), &permuted, 1000, &cfg(), &reg).unwrap();
        assert_eq!(base, perm);

        // Adapter supplies a duplicate of an existing sample -> collapses -> identical.
        let mut with_adapter = obs.to_vec();
        with_adapter.push(obs[0]);
        let adapted = aggregate_local(MarketId::new(1), &with_adapter, 1000, &cfg(), &reg).unwrap();
        assert_eq!(base, adapted);
    }

    #[test]
    fn deterministic_replay_is_bit_identical() {
        let obs = [
            signed(1, 100_000_000, 3, 1000, 1, 1),
            signed(1, 102_000_000, 1, 1000, 1, 2),
            signed(1, 98_000_000, 4, 1000, 1, 3),
        ];
        let reg = registry(&[1, 2, 3]);
        let a = aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg).unwrap();
        let b = aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_yields_no_observations() {
        let reg = registry(&[1, 2, 3]);
        assert_eq!(
            aggregate_local(MarketId::new(1), &[], 1000, &cfg(), &reg),
            Err(OracleError::NoObservations)
        );
    }

    // --- #328 acceptance criteria -------------------------------------------

    /// Unknown keys and (structurally) unauthorized source claims cannot contribute.
    #[test]
    fn unknown_signer_cannot_contribute() {
        let good = [
            signed(1, 100_000_000, 1, 1000, 1, 1),
            signed(1, 100_000_000, 1, 1000, 1, 2),
            signed(1, 100_000_000, 1, 1000, 1, 3),
        ];
        let reg = registry(&[1, 2, 3]);
        let base = aggregate_local(MarketId::new(1), &good, 1000, &cfg(), &reg).unwrap();

        // A wild report from an unregistered key (huge weight, absurd price).
        let intruder = signed(1, 9_000_000_000, BIG_CAP, 1000, 99, 200);
        let mut mixed = good.to_vec();
        mixed.push(intruder);
        let with_intruder = aggregate_local(MarketId::new(1), &mixed, 1000, &cfg(), &reg).unwrap();
        // The intruder is invisible: identical aggregate, no extra source.
        assert_eq!(base, with_intruder);

        // A batch of only unknown keys aggregates to nothing.
        let only_intruders = [
            signed(1, 9_000_000_000, BIG_CAP, 1000, 1, 200),
            signed(1, 9_000_000_000, BIG_CAP, 1000, 1, 201),
            signed(1, 9_000_000_000, BIG_CAP, 1000, 1, 202),
        ];
        assert_eq!(
            aggregate_local(MarketId::new(1), &only_intruders, 1000, &cfg(), &reg),
            Err(OracleError::NoObservations)
        );
    }

    /// A signer scoped to another market cannot price this one.
    #[test]
    fn out_of_market_scope_cannot_contribute() {
        let mut reg = ProducerRegistry::new(1);
        reg.authorize(
            kp(1).public(),
            0,
            Amount::from_raw(BIG_CAP),
            MarketScope::Only(vec![MarketId::new(2)]), // NOT market 1
        )
        .unwrap();
        reg.authorize(
            kp(2).public(),
            1,
            Amount::from_raw(BIG_CAP),
            MarketScope::All,
        )
        .unwrap();
        reg.authorize(
            kp(3).public(),
            2,
            Amount::from_raw(BIG_CAP),
            MarketScope::All,
        )
        .unwrap();
        let obs = [
            signed(1, 100_000_000, 1, 1000, 1, 1), // scoped to market 2 -> dropped
            signed(1, 100_000_000, 1, 1000, 1, 2),
            signed(1, 100_000_000, 1, 1000, 1, 3),
        ];
        // Only two sources survive -> below the 3-source gate.
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg),
            Err(OracleError::TooFewSources { have: 2, need: 3 })
        );
    }

    /// Multiple reports from one signer count once per interval (newest wins).
    #[test]
    fn multiple_reports_from_one_signer_count_once() {
        let obs = [
            signed(1, 100_000_000, 1, 1000, 1, 1), // signer 1, seq 1
            signed(1, 500_000_000, 1, 1000, 2, 1), // signer 1, seq 2 (newer)
            signed(1, 500_000_000, 1, 1000, 1, 2),
            signed(1, 500_000_000, 1, 1000, 1, 3),
        ];
        let reg = registry(&[1, 2, 3]);
        let agg = aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg).unwrap();
        // Signer 1 votes once with its newest (seq 2) report -> 3 obs, 3 sources.
        assert_eq!(agg.observations, 3);
        assert_eq!(agg.sources, 3);
        // Its retained price (500) is what shows; confidence sums 3 votes.
        assert_eq!(agg.price, Price::from_raw(500_000_000));
        assert_eq!(agg.confidence, Amount::from_raw(3));
    }

    /// Replay collapses; a sequence rollback is ignored (newest sequence wins).
    #[test]
    fn replay_and_sequence_rollback_reject() {
        let seq5 = signed(1, 100_000_000, 1, 1000, 5, 1); // signer 1, seq 5
        let rollback = signed(1, 900_000_000, 1, 1000, 3, 1); // signer 1, seq 3 (older)
        let obs = [
            seq5,
            seq5,     // exact replay -> counted once
            rollback, // rollback -> dropped, seq5 retained
            signed(1, 100_000_000, 1, 1000, 1, 2),
            signed(1, 100_000_000, 1, 1000, 1, 3),
        ];
        let reg = registry(&[1, 2, 3]);
        let agg = aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg).unwrap();
        assert_eq!(agg.observations, 3);
        // The rollback's price (900) never enters; seq5's 100 does.
        assert_eq!(agg.price, Price::from_raw(100_000_000));
    }

    /// A far-future timestamp is rejected rather than read as maximally fresh.
    #[test]
    fn far_future_timestamp_rejected() {
        let good = [
            signed(1, 100_000_000, 1, 1000, 1, 1),
            signed(1, 100_000_000, 1, 1000, 1, 2),
            signed(1, 100_000_000, 1, 1000, 1, 3),
        ];
        let reg = registry(&[1, 2, 3, 4]);
        let base = aggregate_local(MarketId::new(1), &good, 1000, &cfg(), &reg).unwrap();

        // An authorized report far in the future with a dominating weight/price.
        // Under naive saturating age it would look freshest and dominate.
        let future = signed(1, 9_000_000_000, BIG_CAP, 10_000_000, 1, 4);
        let mut mixed = good.to_vec();
        mixed.push(future);
        let with_future = aggregate_local(MarketId::new(1), &mixed, 1000, &cfg(), &reg).unwrap();
        assert_eq!(base, with_future); // future report is invisible
    }

    /// A timestamp within the skew tolerance is accepted and clamped to age 0.
    #[test]
    fn near_future_within_tolerance_accepted() {
        // now = 1000, skew tolerance = 1000 -> observed_at 1500 is allowed.
        let obs = [
            signed(1, 100_000_000, 1, 1500, 1, 1),
            signed(1, 100_000_000, 1, 1500, 1, 2),
            signed(1, 100_000_000, 1, 1500, 1, 3),
        ];
        let reg = registry(&[1, 2, 3]);
        let agg = aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg).unwrap();
        assert_eq!(agg.observations, 3);
        assert_eq!(agg.newest_age_ns, 0); // clamped, not negative/huge
    }

    /// Survivors must independently satisfy the distinct-source threshold: an
    /// outlier carrying the only third source cannot prop up diversity.
    #[test]
    fn survivor_source_gate_recomputed_after_outlier_removal() {
        // Tight cluster on sources 0,1; a gross outlier is the only source 2.
        let obs = [
            signed(1, 100_000_000, 1, 1000, 1, 1),     // source 0
            signed(1, 102_000_000, 1, 1000, 1, 2),     // source 1
            signed(1, 100_000_000_000, 1, 1000, 1, 3), // source 2, gross outlier
        ];
        let reg = registry(&[1, 2, 3]);
        let cfg = AggregationConfig {
            min_observations: 2,
            min_sources: 3,
            ..cfg()
        };
        // Outlier dropped -> only sources {0,1} survive -> 2 < 3.
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 1000, &cfg, &reg),
            Err(OracleError::TooFewSources { have: 2, need: 3 })
        );
    }

    /// Survivors must independently satisfy the observation threshold too.
    #[test]
    fn survivor_observation_gate_recomputed_after_outlier_removal() {
        let obs = [
            signed(1, 100_000_000, 1, 1000, 1, 1),
            signed(1, 102_000_000, 1, 1000, 1, 2),
            signed(1, 100_000_000_000, 1, 1000, 1, 3), // gross outlier dropped
        ];
        let reg = registry(&[1, 2, 3]);
        let cfg = AggregationConfig {
            min_observations: 3,
            min_sources: 2,
            ..cfg()
        };
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 1000, &cfg, &reg),
            Err(OracleError::TooFewObservations { have: 2, need: 3 })
        );
    }

    /// Sybil: a swarm of freshly-minted keys cannot manufacture source diversity.
    #[test]
    fn sybil_swarm_cannot_forge_diversity() {
        // Only two real authorized sources exist.
        let reg = registry(&[1, 2]);
        let mut obs = vec![
            signed(1, 100_000_000, 1, 1000, 1, 1),
            signed(1, 100_000_000, 1, 1000, 1, 2),
        ];
        // Ten Sybil keys claim to be a third+ source with dominating weight.
        for seed in 100u8..110 {
            obs.push(signed(1, 777_000_000, BIG_CAP, 1000, 1, seed));
        }
        let cfg = AggregationConfig {
            min_sources: 3,
            min_observations: 2,
            ..cfg()
        };
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 1000, &cfg, &reg),
            Err(OracleError::TooFewSources { have: 2, need: 3 })
        );
    }

    /// Confidence inflation: a policy cap prevents one signer from dominating the
    /// weighted median by claiming enormous confidence.
    #[test]
    fn confidence_inflation_is_capped() {
        // Cap every producer at 1_000_000 micro-units.
        let mut reg = ProducerRegistry::new(1);
        for (i, &s) in [1u8, 2, 3].iter().enumerate() {
            reg.authorize(
                kp(s).public(),
                u8::try_from(i).unwrap(),
                Amount::from_raw(1_000_000),
                MarketScope::All,
            )
            .unwrap();
        }
        let obs = [
            signed(1, 100_000_000, 1_000_000, 1000, 1, 1),
            signed(1, 100_000_000, 1_000_000, 1000, 1, 2),
            // Attacker claims an astronomically large confidence to dominate.
            signed(1, 500_000_000, i128::MAX, 1000, 1, 3),
        ];
        let agg = aggregate_local(MarketId::new(1), &obs, 1000, &cfg(), &reg).unwrap();
        // Capped weight -> equal weights -> lower median of {100,100,500} = 100.
        assert_eq!(agg.price, Price::from_raw(100_000_000));
        // Summed confidence is bounded by 3 * cap, not driven to i128::MAX.
        assert_eq!(agg.confidence, Amount::from_raw(3_000_000));
    }

    /// The inputs digest binds exactly the surviving reports: dropping the outlier
    /// yields the same digest as never having supplied it.
    #[test]
    fn inputs_digest_binds_only_survivors() {
        let clean = [
            signed(1, 100_000_000, 1, 1000, 1, 1),
            signed(1, 101_000_000, 1, 1000, 1, 2),
            signed(1, 99_000_000, 1, 1000, 1, 3),
        ];
        let reg = registry(&[1, 2, 3, 4]);
        let a = aggregate_local(MarketId::new(1), &clean, 1000, &cfg(), &reg).unwrap();

        // Same three survivors + a dropped stale report -> identical inputs digest.
        let mut with_stale = clean.to_vec();
        with_stale.push(signed(1, 500_000_000, 1, 1, 1, 4)); // ancient -> dropped
        let b = aggregate_local(MarketId::new(1), &with_stale, 1000, &cfg(), &reg).unwrap();
        assert_eq!(a.inputs_digest, b.inputs_digest);
        assert!(!a.inputs_digest.is_zero());

        // A different producer-set version changes the commitment.
        let reg2 = {
            let mut r = ProducerRegistry::new(2);
            for (i, &s) in [1u8, 2, 3, 4].iter().enumerate() {
                r.authorize(
                    kp(s).public(),
                    u8::try_from(i).unwrap(),
                    Amount::from_raw(BIG_CAP),
                    MarketScope::All,
                )
                .unwrap();
            }
            r
        };
        let c = aggregate_local(MarketId::new(1), &clean, 1000, &cfg(), &reg2).unwrap();
        assert_ne!(a.inputs_digest, c.inputs_digest);
        assert_eq!(c.producer_set_version, 2);
    }
}
