//! Time-weighted decision price accumulator.
//!
//! A decision market MUST NOT choose an action from the final tick alone. This
//! module integrates price over a [`TimeWindow`]: each observed price is assumed
//! to hold until the next observation (a right-continuous step function), and the
//! time-weighted average is `Σ price_i · Δt_i / Σ Δt_i` over the window.
//!
//! [`TwapAccumulator`] performs streaming updates with **zero heap allocation**
//! (it holds only scalar fields), so it is suitable for a hot accumulator loop.
//! The free function [`time_weighted_average`] is a convenience that sorts a
//! batch of ticks first, making the result independent of input ordering.
//!
//! All math is fixed-point integer: prices are [`Price`] (scale `1e6`), durations
//! are `u64`, and the internal weighted sum is `i128`.

use serde::{Deserialize, Serialize};
use types::Price;

use crate::error::DecisionMarketError;

/// A half-open time window `[start, end)` with strictly positive duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Inclusive start timestamp.
    pub start: u64,
    /// Exclusive end timestamp.
    pub end: u64,
}

impl TimeWindow {
    /// Construct, rejecting a zero-length (single-instant) window.
    pub fn new(start: u64, end: u64) -> Result<Self, DecisionMarketError> {
        if end <= start {
            return Err(DecisionMarketError::EmptyWindow);
        }
        Ok(Self { start, end })
    }

    /// Window duration (`end - start`), always `>= 1` for a constructed window.
    #[inline]
    pub const fn duration(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether `ts` falls within `[start, end)`.
    #[inline]
    pub const fn contains(self, ts: u64) -> bool {
        ts >= self.start && ts < self.end
    }
}

/// A single `(timestamp, price)` observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceTick {
    /// Observation timestamp.
    pub ts: u64,
    /// Observed price (interpreted as holding until the next tick).
    pub price: Price,
}

impl PriceTick {
    /// Construct a tick.
    #[inline]
    pub const fn new(ts: u64, price: Price) -> Self {
        Self { ts, price }
    }
}

/// Streaming, allocation-free time-weighted average accumulator.
#[derive(Debug, Clone, Copy)]
pub struct TwapAccumulator {
    window: TimeWindow,
    last_ts: Option<u64>,
    last_price: Price,
    // Σ price.raw() · Δt over priced intervals clamped to the window.
    weighted: i128,
    // Σ Δt of priced intervals within the window.
    covered: u64,
}

impl TwapAccumulator {
    /// Create an accumulator over `window`.
    #[inline]
    pub const fn new(window: TimeWindow) -> Self {
        Self {
            window,
            last_ts: None,
            last_price: Price::ZERO,
            weighted: 0,
            covered: 0,
        }
    }

    /// The window being integrated over.
    #[inline]
    pub const fn window(&self) -> TimeWindow {
        self.window
    }

    /// Duration (within the window) spanned by *observed* inter-tick intervals,
    /// i.e. the gaps between consecutive observations clamped to the window. This
    /// deliberately excludes [`Self::finalize`]'s extrapolation of the final tick
    /// to the window end, so a single observation reports zero coverage — the
    /// signal a lone tick carries no time-weighting and must not decide a market.
    #[inline]
    pub const fn observed_coverage(&self) -> u64 {
        self.covered
    }

    /// Whether the observed inter-tick coverage reaches `min_coverage` (a fraction
    /// of the window duration in `Ratio` micro-units): `covered / duration >=
    /// min_coverage`. A single observation (zero inter-tick coverage) never meets
    /// a positive minimum.
    #[inline]
    pub fn coverage_meets(&self, min_coverage: types::Ratio) -> Result<bool, DecisionMarketError> {
        // covered/duration >= min  <=>  covered * RATIO_SCALE >= duration * min.
        let lhs = i128::from(self.covered)
            .checked_mul(i128::from(types::RATIO_SCALE))
            .ok_or(DecisionMarketError::Truncation)?;
        let rhs = i128::from(self.window.duration())
            .checked_mul(i128::from(min_coverage.raw()))
            .ok_or(DecisionMarketError::Truncation)?;
        Ok(lhs >= rhs)
    }

    /// Fold the interval `[from, to)` carrying `price` into the accumulator,
    /// clamped to the window. Pure scalar arithmetic; never allocates.
    #[inline]
    fn fold_interval(
        &mut self,
        from: u64,
        to: u64,
        price: Price,
    ) -> Result<(), DecisionMarketError> {
        let lo = from.max(self.window.start);
        let hi = to.min(self.window.end);
        if hi <= lo {
            return Ok(());
        }
        let dt = hi - lo;
        let contribution = i128::from(price.raw())
            .checked_mul(i128::from(dt))
            .ok_or(DecisionMarketError::Truncation)?;
        self.weighted = self
            .weighted
            .checked_add(contribution)
            .ok_or(DecisionMarketError::Truncation)?;
        self.covered = self
            .covered
            .checked_add(dt)
            .ok_or(DecisionMarketError::Truncation)?;
        Ok(())
    }

    /// Observe a price at `ts`. The *previous* price is credited over the gap
    /// `[last_ts, ts)`. Ticks must arrive in non-decreasing timestamp order;
    /// an out-of-order tick returns [`DecisionMarketError::OutOfOrderTick`].
    ///
    /// This is the steady-state hot path and performs no heap allocation.
    pub fn observe(&mut self, ts: u64, price: Price) -> Result<(), DecisionMarketError> {
        if let Some(prev) = self.last_ts {
            if ts < prev {
                return Err(DecisionMarketError::OutOfOrderTick);
            }
            self.fold_interval(prev, ts, self.last_price)?;
        }
        self.last_ts = Some(ts);
        self.last_price = price;
        Ok(())
    }

    /// Finalize the TWAP, extending the last observed price to the window end.
    ///
    /// Returns [`DecisionMarketError::NoObservations`] if no priced interval fell
    /// inside the window (e.g. no observations, or all observations after `end`).
    pub fn finalize(&self) -> Result<Price, DecisionMarketError> {
        let mut acc = *self;
        if let Some(last) = acc.last_ts {
            acc.fold_interval(last, acc.window.end, acc.last_price)?;
        }
        if acc.covered == 0 {
            return Err(DecisionMarketError::NoObservations);
        }
        let avg = acc.weighted / i128::from(acc.covered);
        let raw = i64::try_from(avg).map_err(|_| DecisionMarketError::Truncation)?;
        Ok(Price::from_raw(raw))
    }
}

/// Compute the time-weighted average price of `ticks` over `window`.
///
/// The ticks are stably sorted by timestamp first, so the result is independent
/// of the input ordering / batching (determinism). This convenience allocates a
/// sorted copy; the steady-state [`TwapAccumulator::observe`] path does not.
pub fn time_weighted_average(
    window: TimeWindow,
    ticks: &[PriceTick],
) -> Result<Price, DecisionMarketError> {
    let mut sorted = ticks.to_vec();
    // Canonicalize by (timestamp, price) so ties break deterministically and the
    // result is independent of input ordering even with duplicate timestamps.
    sorted.sort_by(|a, b| {
        a.ts.cmp(&b.ts)
            .then_with(|| a.price.raw().cmp(&b.price.raw()))
    });
    let mut acc = TwapAccumulator::new(window);
    for tick in &sorted {
        acc.observe(tick.ts, tick.price)?;
    }
    acc.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: i64) -> Price {
        Price::from_raw(v)
    }

    #[test]
    fn constant_price_yields_that_price() {
        let w = TimeWindow::new(0, 10).unwrap();
        let ticks = [PriceTick::new(0, p(2_000_000))];
        assert_eq!(time_weighted_average(w, &ticks).unwrap(), p(2_000_000));
    }

    #[test]
    fn ramp_matches_hand_computed_integral() {
        // price 1.0 over [0,5), price 3.0 over [5,10): (1*5 + 3*5)/10 = 2.0
        let w = TimeWindow::new(0, 10).unwrap();
        let ticks = [
            PriceTick::new(0, p(1_000_000)),
            PriceTick::new(5, p(3_000_000)),
        ];
        assert_eq!(time_weighted_average(w, &ticks).unwrap(), p(2_000_000));
    }

    #[test]
    fn final_tick_spike_does_not_dominate() {
        // price 1.0 over [0,9), spike to 100.0 at t=9 for [9,10):
        // TWAP = (1*9 + 100*1)/10 = 10.9, NOT the last price of 100.0.
        let w = TimeWindow::new(0, 10).unwrap();
        let ticks = [
            PriceTick::new(0, p(1_000_000)),
            PriceTick::new(9, p(100_000_000)),
        ];
        let twap = time_weighted_average(w, &ticks).unwrap();
        assert_eq!(twap, p(10_900_000));
        // A last-price rule would have chosen 100.0 — prove they differ.
        assert_ne!(twap, p(100_000_000));
    }

    #[test]
    fn reordering_and_rebatching_is_identical() {
        let w = TimeWindow::new(0, 100).unwrap();
        let forward = [
            PriceTick::new(0, p(1_000_000)),
            PriceTick::new(10, p(2_000_000)),
            PriceTick::new(40, p(5_000_000)),
            PriceTick::new(70, p(3_000_000)),
        ];
        let mut reversed = forward;
        reversed.reverse();
        assert_eq!(
            time_weighted_average(w, &forward).unwrap(),
            time_weighted_average(w, &reversed).unwrap()
        );
    }

    #[test]
    fn zero_length_window_is_rejected() {
        assert_eq!(TimeWindow::new(5, 5), Err(DecisionMarketError::EmptyWindow));
        assert_eq!(TimeWindow::new(6, 5), Err(DecisionMarketError::EmptyWindow));
    }

    #[test]
    fn no_observations_covering_window_errors() {
        let w = TimeWindow::new(0, 10).unwrap();
        assert_eq!(
            time_weighted_average(w, &[]),
            Err(DecisionMarketError::NoObservations)
        );
        // All observations after the window end -> nothing covered.
        let after = [PriceTick::new(20, p(1_000_000))];
        assert_eq!(
            time_weighted_average(w, &after),
            Err(DecisionMarketError::NoObservations)
        );
    }

    #[test]
    fn single_tick_reports_zero_observed_coverage() {
        use types::Ratio;
        let w = TimeWindow::new(0, 100).unwrap();
        let mut acc = TwapAccumulator::new(w);
        // A lone tick at the window start: finalize extrapolates it across the
        // whole window (so a value exists), but observed coverage is zero.
        acc.observe(0, p(700_000)).unwrap();
        assert_eq!(acc.finalize().unwrap(), p(700_000));
        assert_eq!(acc.observed_coverage(), 0);
        // Any positive minimum coverage is therefore unmet.
        assert!(!acc.coverage_meets(Ratio::from_raw(1)).unwrap());
        assert!(!acc.coverage_meets(Ratio::ONE).unwrap());
        // A zero minimum is trivially met (guarded against elsewhere).
        assert!(acc.coverage_meets(Ratio::ZERO).unwrap());
    }

    #[test]
    fn observed_coverage_counts_inter_tick_span_only() {
        use types::Ratio;
        let w = TimeWindow::new(0, 100).unwrap();
        let mut acc = TwapAccumulator::new(w);
        acc.observe(10, p(1_000_000)).unwrap();
        acc.observe(60, p(1_000_000)).unwrap();
        // Inter-tick span [10, 60) == 50; the [60, 100) tail is extrapolation.
        assert_eq!(acc.observed_coverage(), 50);
        // 50/100 == 0.5 exactly.
        assert!(acc.coverage_meets(Ratio::from_raw(500_000)).unwrap());
        assert!(!acc.coverage_meets(Ratio::from_raw(500_001)).unwrap());
    }

    #[test]
    fn out_of_order_streaming_tick_rejected() {
        let w = TimeWindow::new(0, 100).unwrap();
        let mut acc = TwapAccumulator::new(w);
        acc.observe(10, p(1_000_000)).unwrap();
        assert_eq!(
            acc.observe(5, p(2_000_000)),
            Err(DecisionMarketError::OutOfOrderTick)
        );
    }

    // Deterministic LCG property test: reordering a random tick set never
    // changes the TWAP, and the accumulator never panics.
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
    fn property_reorder_invariance_and_no_panic() {
        let mut r = Lcg(0xC0FFEE);
        for _ in 0..2_000 {
            let w = TimeWindow::new(0, 1_000).unwrap();
            let n = usize::try_from(r.next_u64() % 8).unwrap() + 1;
            let mut ticks = Vec::with_capacity(n);
            for _ in 0..n {
                let ts = r.next_u64() % 1_200; // may fall outside window
                let raw = i64::from_le_bytes((r.next_u64()).to_le_bytes()) % 10_000_000;
                ticks.push(PriceTick::new(ts, Price::from_raw(raw)));
            }
            let a = time_weighted_average(w, &ticks);
            let mut shuffled = ticks.clone();
            shuffled.reverse();
            let b = time_weighted_average(w, &shuffled);
            assert_eq!(a, b);
        }
    }
}
