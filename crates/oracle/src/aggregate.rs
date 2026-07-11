//! Deterministic, integer-only local venue aggregation.
//!
//! Given a set of signed [`PriceObservation`]s for one market, [`aggregate_local`]
//! applies, in order: identical-report de-duplication, optional signature
//! verification, staleness filtering, a minimum-distinct-source (venue) gate, a
//! minimum-observation gate, robust outlier rejection (drop beyond
//! `center ± k·MAD`), and a confidence/liquidity-weighted median. The result is
//! a [`LocalAggregate`] with a confidence interval and the signals needed to
//! drive the [`crate::health`] state machine.
//!
//! The output is invariant to input ordering (de-dup + sort) and bit-identical
//! across runs on identical inputs.

use crate::error::OracleError;
use crate::health::{evaluate, HealthConfig, HealthInputs};
use crate::math::{
    dispersion_bps, median_absolute_deviation, scale_by_ratio, weighted_median, Sample,
};
use crate::observation::PriceObservation;
use types::{Amount, MarketId, OracleHealth, Price, Ratio, RATIO_SCALE};

/// Tunable parameters for local aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregationConfig {
    /// Observations older than this (relative to `now_ns`) are dropped.
    pub max_age_ns: u64,
    /// Minimum observations that must survive filtering.
    pub min_observations: usize,
    /// Minimum distinct sources (union `source_mask` popcount) required.
    pub min_sources: u32,
    /// Outlier band multiplier `k`: drop samples beyond `center ± k·MAD`.
    pub mad_k: Ratio,
    /// Whether each observation's signature must verify to be counted.
    pub require_signature: bool,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            max_age_ns: 5_000_000_000, // 5s
            min_observations: 3,
            min_sources: 3,
            mad_k: Ratio::from_raw(3 * RATIO_SCALE), // 3.0 · MAD
            require_signature: true,
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
    /// Summed confidence/liquidity of the surviving observations.
    pub confidence: Amount,
    /// Lower confidence bound (`price − k·MAD`, saturating).
    pub lower: Price,
    /// Upper confidence bound (`price + k·MAD`, saturating).
    pub upper: Price,
    /// Union `source_mask` of surviving observations.
    pub source_mask: u64,
    /// Distinct sources surviving (union popcount).
    pub sources: u32,
    /// Count of observations surviving outlier rejection.
    pub observations: usize,
    /// Age of the newest surviving observation, in nanoseconds.
    pub newest_age_ns: u64,
    /// Relative dispersion (MAD/price) in basis points.
    pub dispersion_bps: i64,
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

/// Aggregate `observations` for `market_id` at wall-clock `now_ns`.
///
/// De-duplicates identical reports first, so supplying the same sample twice
/// (e.g. from an external adapter) never changes the result.
pub fn aggregate_local(
    market_id: MarketId,
    observations: &[PriceObservation],
    now_ns: u64,
    cfg: &AggregationConfig,
) -> Result<LocalAggregate, OracleError> {
    // 1. De-duplicate identical reports (order-independent, adapter-idempotent).
    let mut unique: Vec<PriceObservation> = Vec::with_capacity(observations.len());
    for o in observations {
        if !unique.contains(o) {
            unique.push(*o);
        }
    }

    // 2. Filter: matching market, valid signature (optional), and non-stale.
    let mut kept: Vec<(PriceObservation, u64)> = Vec::with_capacity(unique.len());
    for o in unique {
        if o.market_id != market_id {
            continue;
        }
        if cfg.require_signature && o.verify().is_err() {
            continue;
        }
        let age = now_ns.saturating_sub(o.observed_at_ns);
        if age <= cfg.max_age_ns {
            kept.push((o, age));
        }
    }

    if kept.is_empty() {
        return Err(OracleError::NoObservations);
    }

    // 3. Source-diversity gate (over all fresh, valid observations).
    let union_mask = kept.iter().fold(0u64, |m, (o, _)| m | o.source_mask);
    let sources = union_mask.count_ones();
    if sources < cfg.min_sources {
        return Err(OracleError::TooFewSources {
            have: sources,
            need: cfg.min_sources,
        });
    }

    // 4. Robust center + MAD outlier band.
    let samples: Vec<Sample> = kept
        .iter()
        .map(|(o, _)| Sample {
            price: o.price.raw(),
            weight: o.confidence.raw(),
        })
        .collect();
    let center = weighted_median(&samples).ok_or(OracleError::NoObservations)?;
    let prices: Vec<i64> = samples.iter().map(|s| s.price).collect();
    let mad = median_absolute_deviation(&prices, center);
    let band = scale_by_ratio(mad, cfg.mad_k);

    // 5. Drop outliers (skip when MAD == 0, i.e. no dispersion to reject against).
    let survivors: Vec<(PriceObservation, u64)> = kept
        .into_iter()
        .filter(|(o, _)| mad == 0 || (i128::from(o.price.raw()) - i128::from(center)).abs() <= band)
        .collect();

    if survivors.len() < cfg.min_observations {
        return Err(OracleError::TooFewObservations {
            have: survivors.len(),
            need: cfg.min_observations,
        });
    }

    // 6. Final weighted median over survivors + aggregate signals.
    let final_samples: Vec<Sample> = survivors
        .iter()
        .map(|(o, _)| Sample {
            price: o.price.raw(),
            weight: o.confidence.raw(),
        })
        .collect();
    let price_raw = weighted_median(&final_samples).ok_or(OracleError::NoObservations)?;

    let confidence = survivors
        .iter()
        .fold(Amount::ZERO, |acc, (o, _)| acc.saturating_add(o.confidence));
    let final_mask = survivors.iter().fold(0u64, |m, (o, _)| m | o.source_mask);
    let final_sources = final_mask.count_ones();
    let newest_age_ns = survivors.iter().map(|(_, age)| *age).min().unwrap_or(0);

    let band_i64 = i64::try_from(band).unwrap_or(i64::MAX);
    let lower = Price::from_raw(price_raw).saturating_sub(Price::from_raw(band_i64));
    let upper = Price::from_raw(price_raw).saturating_add(Price::from_raw(band_i64));
    let disp = dispersion_bps(mad, price_raw);

    Ok(LocalAggregate {
        market_id,
        price: Price::from_raw(price_raw),
        confidence,
        lower,
        upper,
        source_mask: final_mask,
        sources: final_sources,
        observations: survivors.len(),
        newest_age_ns,
        dispersion_bps: disp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyPair;

    fn signed(
        market: u32,
        price: i64,
        conf: i128,
        mask: u64,
        ts: u64,
        seq: u64,
        seed: u8,
    ) -> PriceObservation {
        let kp = KeyPair::from_seed(&[seed; 32]);
        let mut o = PriceObservation::unsigned(
            MarketId::new(market),
            Price::from_raw(price),
            Amount::from_raw(conf),
            mask,
            ts,
            seq,
        );
        o.sign(&kp);
        o
    }

    fn cfg() -> AggregationConfig {
        AggregationConfig {
            max_age_ns: 1_000,
            min_observations: 3,
            min_sources: 3,
            mad_k: Ratio::from_raw(3 * RATIO_SCALE),
            require_signature: true,
        }
    }

    #[test]
    fn weighted_median_and_outlier_rejection_hand_computed() {
        // Four tight quotes around 100 plus one gross outlier at 1000.
        let obs = [
            signed(1, 100_000_000, 1, 0b0001, 1000, 1, 1),
            signed(1, 101_000_000, 1, 0b0010, 1000, 1, 2),
            signed(1, 99_000_000, 1, 0b0100, 1000, 1, 3),
            signed(1, 100_000_000, 1, 0b1000, 1000, 1, 4),
            signed(1, 1_000_000_000, 1, 0b10000, 1000, 1, 5),
        ];
        let agg = aggregate_local(MarketId::new(1), &obs, 1000, &cfg()).unwrap();
        // Outlier dropped -> median of {99,100,100,101} lower-median = 100.
        assert_eq!(agg.price, Price::from_raw(100_000_000));
        assert_eq!(agg.observations, 4);
        assert_eq!(agg.sources, 4); // outlier's bit excluded
    }

    #[test]
    fn staleness_filtering_drops_old() {
        let obs = [
            signed(1, 100_000_000, 1, 0b0001, 10_000, 1, 1), // fresh (now 10_500)
            signed(1, 100_000_000, 1, 0b0010, 10_000, 1, 2),
            signed(1, 100_000_000, 1, 0b0100, 10_000, 1, 3),
            signed(1, 500_000_000, 1, 0b1000, 1, 1, 4), // ancient -> dropped
        ];
        let agg = aggregate_local(MarketId::new(1), &obs, 10_500, &cfg()).unwrap();
        assert_eq!(agg.observations, 3);
        assert_eq!(agg.price, Price::from_raw(100_000_000));
    }

    #[test]
    fn min_sources_gate() {
        // Three observations but only two distinct source bits.
        let obs = [
            signed(1, 100_000_000, 1, 0b0001, 1000, 1, 1),
            signed(1, 100_000_000, 1, 0b0001, 1000, 1, 2),
            signed(1, 100_000_000, 1, 0b0010, 1000, 1, 3),
        ];
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 1000, &cfg()),
            Err(OracleError::TooFewSources { have: 2, need: 3 })
        );
    }

    #[test]
    fn min_observations_gate() {
        // Two fresh multi-bit observations satisfy the 3-source gate (union = 0b111)
        // but not the 3-observation gate; the third is stale and dropped.
        let obs = [
            signed(1, 100_000_000, 1, 0b0011, 2500, 1, 1), // fresh, 2 source bits
            signed(1, 100_000_000, 1, 0b0100, 2500, 1, 2), // fresh, 1 source bit
            signed(1, 100_000_000, 1, 0b1000, 1000, 1, 3), // stale (age 2000 > 1000)
        ];
        assert_eq!(
            aggregate_local(MarketId::new(1), &obs, 3000, &cfg()),
            Err(OracleError::TooFewObservations { have: 2, need: 3 })
        );
    }

    #[test]
    fn permutation_invariant_and_adapter_idempotent() {
        let obs = [
            signed(1, 100_000_000, 3, 0b0001, 1000, 1, 1),
            signed(1, 102_000_000, 1, 0b0010, 1000, 1, 2),
            signed(1, 98_000_000, 4, 0b0100, 1000, 1, 3),
            signed(1, 101_000_000, 2, 0b1000, 1000, 1, 4),
        ];
        let base = aggregate_local(MarketId::new(1), &obs, 1000, &cfg()).unwrap();

        let mut permuted = obs;
        permuted.reverse();
        let perm = aggregate_local(MarketId::new(1), &permuted, 1000, &cfg()).unwrap();
        assert_eq!(base, perm);

        // Adapter supplies a duplicate of an existing sample -> de-dup -> identical.
        let mut with_adapter = obs.to_vec();
        with_adapter.push(obs[0]);
        let adapted = aggregate_local(MarketId::new(1), &with_adapter, 1000, &cfg()).unwrap();
        assert_eq!(base, adapted);
    }

    #[test]
    fn deterministic_replay_is_bit_identical() {
        let obs = [
            signed(1, 100_000_000, 3, 0b0001, 1000, 1, 1),
            signed(1, 102_000_000, 1, 0b0010, 1000, 1, 2),
            signed(1, 98_000_000, 4, 0b0100, 1000, 1, 3),
        ];
        let a = aggregate_local(MarketId::new(1), &obs, 1000, &cfg()).unwrap();
        let b = aggregate_local(MarketId::new(1), &obs, 1000, &cfg()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_yields_no_observations() {
        assert_eq!(
            aggregate_local(MarketId::new(1), &[], 1000, &cfg()),
            Err(OracleError::NoObservations)
        );
    }
}
