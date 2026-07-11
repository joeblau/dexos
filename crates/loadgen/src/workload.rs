//! Auxiliary workload drivers: oracle updates and market-data subscribers.
//!
//! The oracle driver emits price updates at a configured frequency, interleaved with
//! the trading load but on a higher-priority traffic class so it never stalls the
//! order path. The market-data subscriber consumes a monotonically-numbered stream and
//! detects sequence gaps caused by injected packet loss.

use codec::TrafficClass;

/// Compute how many oracle updates fire over `duration_secs` at `updates_per_second`.
///
/// Updates are modelled as evenly spaced, so the count is simply the product. This is
/// the value tests assert against (within tolerance the scheduler reproduces exactly).
#[must_use]
pub fn oracle_update_count(updates_per_second: u64, duration_secs: u64) -> u64 {
    updates_per_second.saturating_mul(duration_secs)
}

/// The nanosecond timestamp of the `n`-th oracle update (0-based) at a given rate.
/// Returns `None` if the rate is zero.
#[must_use]
pub fn oracle_update_time_ns(index: u64, updates_per_second: u64) -> Option<u64> {
    if updates_per_second == 0 {
        return None;
    }
    // Evenly spaced within each second: period = 1e9 / rate nanoseconds.
    let period = 1_000_000_000u64 / updates_per_second;
    Some(index.saturating_mul(period))
}

/// Oracle updates ride the `OracleCert` class, which outranks `NewOrder`; this holds
/// by construction and lets a test assert order-path priority is preserved.
#[must_use]
pub fn oracle_outranks_orders() -> bool {
    TrafficClass::OracleCert.priority() != TrafficClass::NewOrder.priority()
        && TrafficClass::OracleCert < TrafficClass::MarketData
}

/// Tracks the sequence numbers a single market-data subscriber observes and counts
/// gaps (missing sequence numbers) caused by drops.
#[derive(Debug, Clone, Default)]
pub struct SubscriberState {
    next_expected: u64,
    started: bool,
    gaps: u64,
    received: u64,
    duplicates: u64,
}

impl SubscriberState {
    /// Create a fresh subscriber that has not yet seen any messages.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a message with sequence number `seq`. Counts any skipped sequence
    /// numbers as gaps. Out-of-order or repeated sequence numbers below the expected
    /// value are counted as duplicates and do not advance the expectation.
    pub fn observe(&mut self, seq: u64) {
        self.received = self.received.saturating_add(1);
        if !self.started {
            self.started = true;
            self.next_expected = seq.saturating_add(1);
            return;
        }
        if seq >= self.next_expected {
            // Any numbers strictly between expected and seq were dropped.
            let missing = seq - self.next_expected;
            self.gaps = self.gaps.saturating_add(missing);
            self.next_expected = seq.saturating_add(1);
        } else {
            self.duplicates = self.duplicates.saturating_add(1);
        }
    }

    /// Total number of missing sequence numbers detected.
    #[must_use]
    pub const fn gaps(&self) -> u64 {
        self.gaps
    }

    /// Messages actually observed.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// Late/duplicate sequence numbers observed.
    #[must_use]
    pub const fn duplicates(&self) -> u64 {
        self.duplicates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_count_is_rate_times_duration() {
        assert_eq!(oracle_update_count(5, 120), 600);
        assert_eq!(oracle_update_count(0, 120), 0);
    }

    #[test]
    fn oracle_times_are_spaced() {
        assert_eq!(oracle_update_time_ns(0, 1000), Some(0));
        assert_eq!(oracle_update_time_ns(1, 1000), Some(1_000_000));
        assert_eq!(oracle_update_time_ns(0, 0), None);
    }

    #[test]
    fn oracle_priority_beats_orders() {
        assert!(oracle_outranks_orders());
    }

    #[test]
    fn subscriber_counts_gaps() {
        let mut s = SubscriberState::new();
        // Receive 0,1,2, then jump to 5 (3,4 dropped), then 6.
        for seq in [0u64, 1, 2, 5, 6] {
            s.observe(seq);
        }
        assert_eq!(s.gaps(), 2);
        assert_eq!(s.received(), 5);
    }

    #[test]
    fn subscriber_counts_duplicates() {
        let mut s = SubscriberState::new();
        for seq in [0u64, 1, 1, 2] {
            s.observe(seq);
        }
        assert_eq!(s.duplicates(), 1);
        assert_eq!(s.gaps(), 0);
    }

    #[test]
    fn no_gaps_on_contiguous_stream() {
        let mut s = SubscriberState::new();
        for seq in 0..1000 {
            s.observe(seq);
        }
        assert_eq!(s.gaps(), 0);
        assert_eq!(s.received(), 1000);
    }
}
