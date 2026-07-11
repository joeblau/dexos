//! Deterministic, seedable pseudo-random number generator for the simulator.
//!
//! This is a 64-bit linear-congruential generator whose raw state is passed
//! through a SplitMix64-style finalizer to decorrelate consecutive outputs.
//! It uses **no floating point** and no external crates, so every draw is
//! bit-reproducible across platforms given the same seed. All fault decisions
//! (delay, drop, duplicate, reorder, Byzantine choices) are driven from a
//! [`SimRng`], which is the sole source of nondeterminism in a run.

/// A deterministic LCG + SplitMix64 finalizer PRNG.
///
/// Cloning yields an independent stream that continues from the cloned state,
/// which is used to snapshot-and-replay sub-streams deterministically.
#[derive(Debug, Clone)]
pub struct SimRng {
    state: u64,
}

/// LCG multiplier (from Knuth / PCG lineage).
const LCG_MUL: u64 = 6_364_136_223_846_793_005;
/// LCG increment (odd, from PCG lineage).
const LCG_INC: u64 = 1_442_695_040_888_963_407;

impl SimRng {
    /// Create a generator from a 64-bit seed. Every seed produces a distinct,
    /// fully deterministic stream (seed `0` is a valid, non-degenerate seed
    /// because the increment keeps the LCG from sticking at zero).
    #[must_use]
    pub fn new(seed: u64) -> Self {
        // Mix the seed once so nearby seeds produce well-separated streams.
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// Advance the LCG and return a finalized 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(LCG_MUL).wrapping_add(LCG_INC);
        // SplitMix64 finalizer over the raw LCG state.
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Draw a 32-bit value from the high bits of the stream.
    pub fn next_u32(&mut self) -> u32 {
        // The high 32 bits are always `< 2^32`, so this conversion never fails.
        u32::try_from(self.next_u64() >> 32).unwrap_or(0)
    }

    /// Draw a value uniformly in `[0, bound)`. Returns `0` when `bound == 0`.
    ///
    /// Uses rejection sampling to avoid modulo bias so the distribution is
    /// exact (still fully deterministic).
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        // Largest multiple of `bound` that fits in u64; reject above it.
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let x = self.next_u64();
            if x < zone {
                return x % bound;
            }
        }
    }

    /// Draw a value uniformly in the inclusive range `[lo, hi]`.
    ///
    /// If `hi < lo` the arguments are swapped, so the call never panics.
    pub fn range_inclusive(&mut self, lo: u64, hi: u64) -> u64 {
        let (lo, hi) = if hi < lo { (hi, lo) } else { (lo, hi) };
        let span = hi - lo;
        if span == u64::MAX {
            return self.next_u64();
        }
        lo + self.below(span + 1)
    }

    /// Return `true` with probability `permille / 1000` (integer-only, no float).
    ///
    /// `permille >= 1000` is always `true`; `permille == 0` is always `false`.
    pub fn chance_permille(&mut self, permille: u32) -> bool {
        if permille == 0 {
            return false;
        }
        if permille >= 1000 {
            return true;
        }
        self.below(1000) < u64::from(permille)
    }

    /// Derive a fresh, independent sub-generator seeded from this stream plus a
    /// caller-chosen `salt`. Deterministic and side-effect free apart from
    /// consuming one draw from the parent.
    pub fn fork(&mut self, salt: u64) -> SimRng {
        let base = self.next_u64();
        SimRng {
            state: base ^ salt.wrapping_mul(0x2545_F491_4F6C_DD1D),
        }
    }

    /// Fill a byte buffer deterministically from the stream.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let word = self.next_u64().to_le_bytes();
            let take = core::cmp::min(8, out.len() - i);
            out[i..i + take].copy_from_slice(&word[..take]);
            i += take;
        }
    }

    /// Deterministic Fisher-Yates shuffle of a slice.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        let n = items.len();
        if n < 2 {
            return;
        }
        let mut i = n - 1;
        while i > 0 {
            let j =
                usize::try_from(self.below(u64::try_from(i + 1).unwrap_or(u64::MAX))).unwrap_or(0);
            items.swap(i, j);
            i -= 1;
        }
    }
}
