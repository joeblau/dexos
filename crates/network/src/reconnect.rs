//! Exponential reconnect backoff with full jitter.
//!
//! After a partition or remote close, callers must not stampede the peer with
//! reconnect attempts. [`ReconnectBackoff`] grows the wait exponentially up to a
//! configured ceiling and applies full-jitter so concurrent reconnectors desync
//! without sharing a clock. All arithmetic is integer (no floating point).

use std::time::Duration;

/// Default initial backoff (250 ms).
pub const DEFAULT_INITIAL_MS: u64 = 250;
/// Default maximum backoff (30 s).
pub const DEFAULT_MAX_MS: u64 = 30_000;
/// Default exponential growth numerator (base * 2 each step).
pub const DEFAULT_MULTIPLIER_NUM: u32 = 2;
/// Default exponential growth denominator.
pub const DEFAULT_MULTIPLIER_DEN: u32 = 1;

/// Policy for reconnection spacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    /// Delay before the first retry.
    pub initial: Duration,
    /// Hard ceiling on the delay.
    pub max: Duration,
    /// Multiplier numerator applied each attempt (`delay * num / den`).
    pub multiplier_num: u32,
    /// Multiplier denominator.
    pub multiplier_den: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(DEFAULT_INITIAL_MS),
            max: Duration::from_millis(DEFAULT_MAX_MS),
            multiplier_num: DEFAULT_MULTIPLIER_NUM,
            multiplier_den: DEFAULT_MULTIPLIER_DEN,
        }
    }
}

/// Mutable reconnect state for one peer (or one dial target).
#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    policy: ReconnectPolicy,
    /// Current base delay before jitter (clamped to `policy.max`).
    current: Duration,
    /// Successful consecutive failures (resets on [`ReconnectBackoff::reset`]).
    attempt: u32,
}

impl ReconnectBackoff {
    /// Create state with the given policy, starting at the initial delay.
    pub fn new(policy: ReconnectPolicy) -> Self {
        Self {
            current: policy.initial,
            policy,
            attempt: 0,
        }
    }

    /// Number of failed attempts since the last reset.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Current base delay (pre-jitter).
    pub fn current_base(&self) -> Duration {
        self.current
    }

    /// Reset after a successful reconnect.
    pub fn reset(&mut self) {
        self.current = self.policy.initial;
        self.attempt = 0;
    }

    /// Compute the next sleep duration with **full jitter**.
    ///
    /// `rng_u64` supplies an unbiased-enough 64-bit random value (tests inject a
    /// deterministic LCG; production uses the OS CSPRNG). The returned delay is
    /// uniform in `[0, base]` where `base` is the current exponential base,
    /// then the base is grown for the next attempt.
    pub fn next_delay<R: FnMut() -> u64>(&mut self, mut rng_u64: R) -> Duration {
        let base = self.current;
        let base_ns = u128::from(base.as_nanos().min(u128::from(u64::MAX)));
        let delay = if base_ns == 0 {
            Duration::ZERO
        } else {
            // Full jitter: uniform in [0, base].
            let r = u128::from(rng_u64());
            let pick = r % (base_ns + 1);
            Duration::from_nanos(u64::try_from(pick).unwrap_or(u64::MAX))
        };

        // Grow the base for the next attempt: base * num / den, capped at max.
        self.attempt = self.attempt.saturating_add(1);
        let den = self.policy.multiplier_den.max(1);
        let grown_ms = self
            .current
            .as_millis()
            .saturating_mul(u128::from(self.policy.multiplier_num))
            / u128::from(den);
        let grown = Duration::from_millis(u64::try_from(grown_ms).unwrap_or(u64::MAX));
        self.current = if grown > self.policy.max {
            self.policy.max
        } else if grown < self.policy.initial {
            self.policy.initial
        } else {
            grown
        };
        delay
    }

    /// Draw the next delay using the OS CSPRNG for the jitter bits.
    pub fn next_delay_os_rng(&mut self) -> Duration {
        self.next_delay(|| {
            let mut b = [0u8; 8];
            // Fall back to a fixed pattern only if the OS RNG is unavailable —
            // still non-zero so concurrent clients desync somewhat.
            if getrandom::getrandom(&mut b).is_err() {
                return 0xA5A5_5A5A_C3C3_3C3C;
            }
            u64::from_le_bytes(b)
        })
    }
}

impl Default for ReconnectBackoff {
    fn default() -> Self {
        Self::new(ReconnectPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_growth_caps_at_max() {
        let policy = ReconnectPolicy {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(800),
            multiplier_num: 2,
            multiplier_den: 1,
        };
        let mut b = ReconnectBackoff::new(policy);
        // Force zero jitter so we observe base growth via current_base.
        let mut rng = || 0u64;
        let _ = b.next_delay(&mut rng);
        assert_eq!(b.current_base(), Duration::from_millis(200));
        let _ = b.next_delay(&mut rng);
        assert_eq!(b.current_base(), Duration::from_millis(400));
        let _ = b.next_delay(&mut rng);
        assert_eq!(b.current_base(), Duration::from_millis(800));
        let _ = b.next_delay(&mut rng);
        assert_eq!(b.current_base(), Duration::from_millis(800)); // capped
    }

    #[test]
    fn full_jitter_stays_within_base() {
        let policy = ReconnectPolicy {
            initial: Duration::from_millis(1000),
            max: Duration::from_millis(1000),
            multiplier_num: 1,
            multiplier_den: 1,
        };
        let mut b = ReconnectBackoff::new(policy);
        // Deterministic LCG over many draws: every delay must be in [0, base].
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut rng = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        for _ in 0..512 {
            let d = b.next_delay(&mut rng);
            assert!(d <= Duration::from_millis(1000));
        }
    }

    #[test]
    fn reset_clears_attempt_and_base() {
        let mut b = ReconnectBackoff::default();
        let mut rng = || 0u64;
        let _ = b.next_delay(&mut rng);
        let _ = b.next_delay(&mut rng);
        assert!(b.attempt() >= 2);
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.current_base(), ReconnectPolicy::default().initial);
    }

    #[test]
    fn concurrent_clients_desync_under_same_base() {
        // Two clients with independent RNG streams must not always pick the same
        // delay — full jitter prevents a reconnect stampede.
        let policy = ReconnectPolicy::default();
        let mut a = ReconnectBackoff::new(policy);
        let mut b = ReconnectBackoff::new(policy);
        let mut sa = 1u64;
        let mut sb = 2u64;
        let mut same = 0u32;
        for _ in 0..64 {
            let da = a.next_delay(|| {
                sa = sa.wrapping_mul(6364136223846793005).wrapping_add(1);
                sa
            });
            let db = b.next_delay(|| {
                sb = sb.wrapping_mul(6364136223846793005).wrapping_add(1);
                sb
            });
            if da == db {
                same += 1;
            }
        }
        assert!(
            same < 16,
            "too many identical delays ({same}/64); jitter not desynchronising"
        );
    }
}
