//! Cross-crate golden vectors and a rational-reference property test proving the
//! `markets` and `prediction-markets` scalar payout vectors agree by *named*
//! outcome (`types::ScalarOutcome`), not by an ad-hoc positional convention.
//!
//! Both crates express scalar fractions at the same 6-dp scale (`Amount` and
//! `Ratio` both scale `1_000_000 == 1.0`), so the LONG and SHORT raw values must
//! match exactly for identical `(lower, upper, value)` inputs.

use types::{Amount, ScalarOutcome};

const UNIT: i128 = 1_000_000; // 1.0 at the shared 6-dp scale

fn amt(raw: i128) -> Amount {
    Amount::from_raw(raw)
}

/// Golden table: `(lower, upper, value, expected_long_raw, expected_short_raw)`,
/// all at the 6-dp scale. Covers lower/mid/upper, a non-divisible range whose
/// floor remainder lands on SHORT, and clamped out-of-range values.
const GOLDEN: &[(i128, i128, i128, i64, i64)] = &[
    // range [0.0, 100.0]
    (0, 100_000_000, 0, 0, 1_000_000), // lower bound -> full short
    (0, 100_000_000, 25_000_000, 250_000, 750_000), // quarter
    (0, 100_000_000, 50_000_000, 500_000, 500_000), // midpoint
    (0, 100_000_000, 75_000_000, 750_000, 250_000), // three-quarter
    (0, 100_000_000, 100_000_000, 1_000_000, 0), // upper bound -> full long
    // non-divisible range [0.0, 3.0]: floor division, SHORT absorbs the remainder
    (0, 3_000_000, 1_000_000, 333_333, 666_667),
    // shifted range [10.0, 20.0], including clamped values
    (10_000_000, 20_000_000, 15_000_000, 500_000, 500_000),
    (10_000_000, 20_000_000, 5_000_000, 0, 1_000_000), // below lower clamps
    (10_000_000, 20_000_000, 25_000_000, 1_000_000, 0), // above upper clamps
];

#[test]
fn scalar_payout_agrees_across_crates_by_named_outcome() {
    for &(lo, hi, v, exp_long, exp_short) in GOLDEN {
        // markets crate: PayoutVector indexed by ScalarOutcome.
        let mkt = markets::scalar_payout(amt(lo), amt(hi), amt(v)).unwrap();
        let mkt_long = mkt.values()[ScalarOutcome::Long.index()].raw();
        let mkt_short = mkt.values()[ScalarOutcome::Short.index()].raw();

        // prediction-markets crate: [long, short] in the same canonical order.
        let range = prediction_markets::ScalarRange::new(amt(lo), amt(hi)).unwrap();
        let [pm_long, pm_short] = range.fractions(amt(v)).unwrap();

        // Each crate matches the golden value.
        assert_eq!(
            mkt_long,
            i128::from(exp_long),
            "markets long for {lo},{hi},{v}"
        );
        assert_eq!(
            mkt_short,
            i128::from(exp_short),
            "markets short for {lo},{hi},{v}"
        );
        assert_eq!(pm_long.raw(), exp_long, "prediction long for {lo},{hi},{v}");
        assert_eq!(
            pm_short.raw(),
            exp_short,
            "prediction short for {lo},{hi},{v}"
        );

        // Cross-crate: identical by named outcome.
        assert_eq!(mkt_long, i128::from(pm_long.raw()));
        assert_eq!(mkt_short, i128::from(pm_short.raw()));

        // Both conserve to exactly one unit.
        assert_eq!(mkt_long + mkt_short, UNIT);
        assert_eq!(i128::from(pm_long.raw()) + i128::from(pm_short.raw()), UNIT);
    }
}

// Deterministic LCG so this "property" test is reproducible bit-for-bit.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

#[test]
fn scalar_payout_cross_crate_matches_rational_reference() {
    let mut r = Lcg(0x0D15_EA5E_C0FF_EE11);
    for _ in 0..10_000 {
        // Wide ranges (including negative lower bounds) with an exact rational
        // reference; bounded so the reference product stays inside i128.
        let lo = i128::from(r.next_u64() % 1_000_000_000) - 500_000_000;
        let span = i128::from(r.next_u64() % 100_000_000) + 1; // >= 1 => lo < hi
        let hi = lo + span;
        let v = lo - 10_000_000 + i128::from(r.next_u64() % 120_000_000);

        let mkt = markets::scalar_payout(amt(lo), amt(hi), amt(v)).unwrap();
        let mkt_long = mkt.values()[ScalarOutcome::Long.index()].raw();
        let mkt_short = mkt.values()[ScalarOutcome::Short.index()].raw();

        let range = prediction_markets::ScalarRange::new(amt(lo), amt(hi)).unwrap();
        let [pm_long, pm_short] = range.fractions(amt(v)).unwrap();

        // Exact i128 rational reference: long == floor((clamp(v) - lo) * UNIT / span).
        let clamped = v.clamp(lo, hi);
        let expected_long = (clamped - lo) * UNIT / span;

        assert_eq!(mkt_long, expected_long);
        assert_eq!(i128::from(pm_long.raw()), expected_long);

        // Cross-crate agreement by named outcome and exact conservation.
        assert_eq!(mkt_long, i128::from(pm_long.raw()));
        assert_eq!(mkt_short, i128::from(pm_short.raw()));
        assert_eq!(mkt_long + mkt_short, UNIT);
    }
}
