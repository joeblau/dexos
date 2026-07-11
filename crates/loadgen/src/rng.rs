//! Deterministic, dependency-free pseudo-random number generator.
//!
//! A 64-bit linear congruential generator (the PCG/Knuth multiplier) drives every
//! stochastic decision in the load generator — order mix, cancel/replace selection,
//! latency jitter, packet loss, duplication, and reordering. Because the sequence is
//! a pure function of the seed, two runs with the same seed produce a bit-identical
//! command stream, which the reproduction tests assert on.
//!
//! This is **not** a cryptographic RNG and must never be used for key material; it
//! exists purely so simulations are reproducible without pulling in `rand`.

use types::{Ratio, RATIO_SCALE};

/// Multiplier and increment from Knuth's MMIX / PCG family (full period `2^64`).
const LCG_MULT: u64 = 6_364_136_223_846_793_005;
const LCG_INCR: u64 = 1_442_695_040_888_963_407;

/// A seeded 64-bit linear congruential generator.
#[derive(Debug, Clone)]
pub struct Lcg {
    state: u64,
}

impl Lcg {
    /// Create a generator from a seed. Any seed is valid; `0` is fine.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advance the state and return the next raw 64-bit word.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(LCG_MULT).wrapping_add(LCG_INCR);
        // Output the high bits, which have the best statistical quality in an LCG.
        self.state ^ (self.state >> 29)
    }

    /// Return the next 32-bit word (high half of [`Lcg::next_u64`]).
    pub fn next_u32(&mut self) -> u32 {
        // Widening-free narrowing: take the high 32 bits explicitly.
        let v = self.next_u64() >> 32;
        u32::try_from(v & 0xFFFF_FFFF).unwrap_or(0)
    }

    /// Uniform integer in `[0, bound)`. Returns `0` when `bound == 0`.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }

    /// Draw a Bernoulli trial that succeeds with probability `ratio` (fixed-point,
    /// where [`RATIO_SCALE`] == 1.0). Ratios `<= 0` never succeed and ratios `>= 1`
    /// always succeed, so the result is well defined for any input.
    pub fn chance(&mut self, ratio: Ratio) -> bool {
        let raw = ratio.raw();
        if raw <= 0 {
            return false;
        }
        if raw >= RATIO_SCALE {
            return true;
        }
        // Scale a draw into [0, RATIO_SCALE) and compare against the threshold.
        let scale = u64::try_from(RATIO_SCALE).unwrap_or(1_000_000);
        let threshold = u64::try_from(raw).unwrap_or(0);
        self.below(scale) < threshold
    }

    /// Uniform jitter in `[0, span]` nanoseconds (inclusive), for latency modelling.
    pub fn jitter(&mut self, span: u64) -> u64 {
        if span == 0 {
            return 0;
        }
        self.below(span.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = Lcg::new(0xDEAD_BEEF);
        let mut b = Lcg::new(0xDEAD_BEEF);
        for _ in 0..10_000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seed_diverges() {
        let mut a = Lcg::new(1);
        let mut b = Lcg::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn below_is_bounded() {
        let mut r = Lcg::new(7);
        for _ in 0..10_000 {
            assert!(r.below(100) < 100);
        }
        assert_eq!(r.below(0), 0);
        assert_eq!(r.below(1), 0);
    }

    #[test]
    fn chance_saturates_at_bounds() {
        let mut r = Lcg::new(9);
        assert!(!r.chance(Ratio::from_raw(0)));
        assert!(!r.chance(Ratio::from_raw(-5)));
        assert!(r.chance(Ratio::from_raw(RATIO_SCALE)));
        assert!(r.chance(Ratio::from_raw(RATIO_SCALE + 100)));
    }

    #[test]
    fn chance_frequency_within_tolerance() {
        let mut r = Lcg::new(42);
        let ratio = Ratio::from_raw(RATIO_SCALE / 4); // 0.25
        let n = 200_000u64;
        let mut hits = 0u64;
        for _ in 0..n {
            if r.chance(ratio) {
                hits += 1;
            }
        }
        // Expect ~50_000; allow 5% relative tolerance.
        let expected = n / 4;
        let diff = hits.abs_diff(expected);
        assert!(diff < expected / 20, "hits={hits} expected~{expected}");
    }
}
