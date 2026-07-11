//! A tiny deterministic linear congruential generator.
//!
//! Purpose-built and dependency-free (no `rand`), so a workload seeded with a
//! given value replays the exact same operation sequence on every run — the
//! property the "deterministic replay" acceptance criteria rely on.

/// A seedable LCG (Numerical Recipes constants) producing a reproducible
/// pseudo-random stream. Not cryptographically secure; determinism is the point.
#[derive(Debug, Clone)]
pub struct Lcg(u64);

impl Lcg {
    /// Create a generator from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        // Mix the seed so small/adjacent seeds diverge immediately.
        Lcg(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    /// Advance and return the next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    /// A `u32` drawn from the stream.
    pub fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() >> 32).unwrap_or(0)
    }

    /// An inclusive integer in `[lo, hi]`. `lo` is returned if `hi <= lo`.
    pub fn range_i64(&mut self, lo: i64, hi: i64) -> i64 {
        if hi <= lo {
            return lo;
        }
        let span = u64::try_from(hi - lo).unwrap_or(u64::MAX).saturating_add(1);
        lo + i64::try_from(self.next_u64() % span).unwrap_or(0)
    }

    /// A `usize` in `[0, bound)`. Returns 0 when `bound == 0`.
    pub fn upto(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64()).unwrap_or(0) % bound
    }

    /// `len` pseudo-random bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        v.truncate(len);
        v
    }

    /// A 32-byte digest-shaped array from the stream.
    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for chunk in b.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Lcg::new(42);
        let mut b = Lcg::new(42);
        for _ in 0..1000 {
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
    fn range_is_bounded_and_total() {
        let mut r = Lcg::new(7);
        for _ in 0..10_000 {
            let v = r.range_i64(-5, 5);
            assert!((-5..=5).contains(&v));
        }
        // Degenerate bounds never panic.
        assert_eq!(r.range_i64(3, 3), 3);
        assert_eq!(r.range_i64(9, 1), 9);
        assert_eq!(r.upto(0), 0);
    }
}
