//! Optional external reference adapter.
//!
//! An [`ExternalReference`] is a *fallback* hook — e.g. a Pyth-like secondary
//! price feed — that can contribute an extra [`PriceObservation`] when the native
//! venue set is thin. It is deliberately not a protocol dependency: the adapter
//! yields ordinary observations that flow through the same de-dup, staleness,
//! diversity, and outlier pipeline as native ones, so a supplied sample that
//! duplicates a native one never changes the aggregate.

use types::MarketId;

use crate::observation::PriceObservation;

/// A secondary/fallback price source. Implementations must be pure and must not
/// perform I/O on the deterministic path (callers gather references out of band
/// and feed them in).
pub trait ExternalReference {
    /// Return a reference observation for `market` at `now_ns`, if available.
    fn reference(&self, market: MarketId, now_ns: u64) -> Option<PriceObservation>;
}

/// Merge native observations with an optional external reference into a single
/// slice for aggregation. The reference is appended (de-dup happens downstream),
/// so passing the same reference as a native sample is a no-op.
pub fn merge_reference<R: ExternalReference>(
    native: &[PriceObservation],
    reference: Option<&R>,
    market: MarketId,
    now_ns: u64,
) -> Vec<PriceObservation> {
    let mut out: Vec<PriceObservation> = native.to_vec();
    if let Some(r) = reference {
        if let Some(o) = r.reference(market, now_ns) {
            out.push(o);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::{aggregate_local, AggregationConfig};
    use crypto::KeyPair;
    use types::{Amount, Price, Ratio, RATIO_SCALE};

    struct FixedRef(PriceObservation);
    impl ExternalReference for FixedRef {
        fn reference(&self, _market: MarketId, _now_ns: u64) -> Option<PriceObservation> {
            Some(self.0)
        }
    }

    fn signed(price: i64, mask: u64, seed: u8) -> PriceObservation {
        let kp = KeyPair::from_seed(&[seed; 32]);
        let mut o = PriceObservation::unsigned(
            MarketId::new(1),
            Price::from_raw(price),
            Amount::from_raw(1),
            mask,
            1000,
            1,
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
    fn duplicate_reference_does_not_change_aggregate() {
        let native = [
            signed(100_000_000, 0b001, 1),
            signed(101_000_000, 0b010, 2),
            signed(99_000_000, 0b100, 3),
        ];
        let base = aggregate_local(MarketId::new(1), &native, 1000, &cfg()).unwrap();

        // Adapter re-supplies an existing native sample -> identical result.
        let adapter = FixedRef(native[0]);
        let merged = merge_reference(&native, Some(&adapter), MarketId::new(1), 1000);
        let with_ref = aggregate_local(MarketId::new(1), &merged, 1000, &cfg()).unwrap();
        assert_eq!(base, with_ref);
    }

    #[test]
    fn no_adapter_is_identity() {
        let native = [signed(100_000_000, 0b001, 1)];
        let merged = merge_reference::<FixedRef>(&native, None, MarketId::new(1), 1000);
        assert_eq!(merged, native.to_vec());
    }
}
