//! Integer open-loop scheduling with bounded catch-up and explicit run phases.

use crate::config::{BurstKind, BurstPattern, LoadScenario};

pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPhase {
    WarmUp,
    Steady,
    Drain,
    CoolDown,
    Complete,
}

/// Absolute monotonic boundaries for the four phase contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseTimeline {
    pub started_ns: u64,
    pub steady_ns: u64,
    pub drain_ns: u64,
    pub cool_down_ns: u64,
    pub complete_ns: u64,
}

impl PhaseTimeline {
    #[must_use]
    pub fn from_scenario(started_ns: u64, scenario: &LoadScenario) -> Self {
        let steady_ns =
            started_ns.saturating_add(scenario.warm_up_secs.saturating_mul(NANOS_PER_SECOND));
        let drain_ns =
            steady_ns.saturating_add(scenario.duration_secs.saturating_mul(NANOS_PER_SECOND));
        let cool_down_ns =
            drain_ns.saturating_add(scenario.drain_timeout_secs.saturating_mul(NANOS_PER_SECOND));
        let complete_ns =
            cool_down_ns.saturating_add(scenario.cool_down_secs.saturating_mul(NANOS_PER_SECOND));
        Self {
            started_ns,
            steady_ns,
            drain_ns,
            cool_down_ns,
            complete_ns,
        }
    }

    #[must_use]
    pub const fn phase_at(self, now_ns: u64) -> RunPhase {
        if now_ns < self.steady_ns {
            RunPhase::WarmUp
        } else if now_ns < self.drain_ns {
            RunPhase::Steady
        } else if now_ns < self.cool_down_ns {
            RunPhase::Drain
        } else if now_ns < self.complete_ns {
            RunPhase::CoolDown
        } else {
            RunPhase::Complete
        }
    }
}

/// Result of one scheduler poll. `emit` is bounded by the configured catch-up
/// quantum; additional overdue deadlines are terminal local drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScheduleBatch {
    pub offered: u64,
    pub emit: u64,
    pub locally_dropped: u64,
    pub scheduler_lag_ns: u64,
    pub cumulative_rate_debt: u64,
    /// Ideal deadline of the first emitted operation, relative to scheduler start.
    pub first_due_ns: u64,
    /// Nominal spacing used to recover per-operation deadlines within this batch.
    pub spacing_ns: u64,
}

/// Open-loop schedule. Polling is O(1), allocation-free, and never converts a long
/// pause into an unbounded catch-up burst.
#[derive(Debug, Clone)]
pub struct OpenLoopScheduler {
    start_ns: u64,
    base_rate: u64,
    duration_secs: u64,
    pattern: BurstPattern,
    accounted: u64,
    rate_debt: u64,
}

impl OpenLoopScheduler {
    #[must_use]
    pub fn new(start_ns: u64, base_rate: u64, duration_secs: u64, pattern: BurstPattern) -> Self {
        Self {
            start_ns,
            base_rate,
            duration_secs,
            pattern,
            accounted: 0,
            rate_debt: 0,
        }
    }

    /// Account for all deadlines through `now_ns`, emitting at most `max_catch_up`.
    #[must_use]
    pub fn poll(&mut self, now_ns: u64, max_catch_up: u64) -> ScheduleBatch {
        let elapsed_ns = now_ns.saturating_sub(self.start_ns);
        let scheduled = self.scheduled_through(elapsed_ns);
        let previously_accounted = self.accounted;
        let offered = scheduled.saturating_sub(previously_accounted);
        self.accounted = scheduled;
        let emit = offered.min(max_catch_up);
        let locally_dropped = offered.saturating_sub(emit);
        self.rate_debt = self.rate_debt.saturating_add(locally_dropped);
        let scheduler_lag_ns = if offered == 0 || self.base_rate == 0 {
            0
        } else {
            // Conservative lag of the oldest due deadline, capped by elapsed time.
            elapsed_ns.min(
                offered
                    .saturating_mul(NANOS_PER_SECOND)
                    .div_ceil(self.base_rate.max(1)),
            )
        };
        let spacing_ns = NANOS_PER_SECOND
            .checked_div(self.base_rate)
            .unwrap_or(0)
            .max(1);
        let first_due_ns = if self.pattern.kind == BurstKind::Steady && self.base_rate != 0 {
            previously_accounted
                .saturating_mul(NANOS_PER_SECOND)
                .checked_div(self.base_rate)
                .unwrap_or(u64::MAX)
        } else {
            elapsed_ns.saturating_sub(scheduler_lag_ns)
        };
        ScheduleBatch {
            offered,
            emit,
            locally_dropped,
            scheduler_lag_ns,
            cumulative_rate_debt: self.rate_debt,
            first_due_ns,
            spacing_ns,
        }
    }

    #[must_use]
    pub const fn cumulative_rate_debt(&self) -> u64 {
        self.rate_debt
    }

    fn scheduled_through(&self, elapsed_ns: u64) -> u64 {
        let total_ns = self.duration_secs.saturating_mul(NANOS_PER_SECOND);
        let elapsed_ns = elapsed_ns.min(total_ns);
        let whole_seconds = elapsed_ns / NANOS_PER_SECOND;
        let partial_ns = elapsed_ns % NANOS_PER_SECOND;
        let whole = match self.pattern.kind {
            BurstKind::Steady => self.base_rate.saturating_mul(whole_seconds),
            BurstKind::Ramp => ramp_whole(self.base_rate, self.duration_secs, whole_seconds),
            BurstKind::Bursty => bursty_whole(self.base_rate, self.pattern, whole_seconds),
        };
        let partial_rate = if whole_seconds >= self.duration_secs {
            0
        } else {
            self.pattern
                .rate_at(whole_seconds, self.base_rate, self.duration_secs)
        };
        let partial = partial_rate.saturating_mul(partial_ns) / NANOS_PER_SECOND;
        let starts_active_interval = elapsed_ns < total_ns && partial_rate != 0;
        whole
            .saturating_add(partial)
            .saturating_add(u64::from(starts_active_interval))
    }
}

fn ramp_whole(base_rate: u64, duration: u64, seconds: u64) -> u64 {
    if duration <= 1 {
        return base_rate.saturating_mul(seconds.min(duration));
    }
    // Sum floor(base_rate * second / (duration-1)). Iteration would be exact but
    // non-O(1); the rational sum differs by less than one action per completed
    // second and the final-second remainder is explicitly retained by the scheduler.
    let n = seconds.min(duration);
    let triangular = u128::from(n).saturating_mul(u128::from(n.saturating_sub(1))) / 2;
    let total = u128::from(base_rate).saturating_mul(triangular) / u128::from(duration - 1);
    u64::try_from(total).unwrap_or(u64::MAX)
}

fn bursty_whole(base_rate: u64, pattern: BurstPattern, seconds: u64) -> u64 {
    let burst = pattern.burst_secs;
    let idle = pattern.idle_secs;
    let period = burst.saturating_add(idle).max(1);
    let cycles = seconds / period;
    let remainder = seconds % period;
    let active = cycles
        .saturating_mul(burst)
        .saturating_add(remainder.min(burst));
    active
        .saturating_mul(base_rate)
        .saturating_mul(u64::from(pattern.peak_multiplier.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_use_half_open_boundaries() {
        let scenario = LoadScenario {
            warm_up_secs: 2,
            duration_secs: 3,
            drain_timeout_secs: 4,
            cool_down_secs: 5,
            ..LoadScenario::default()
        };
        let timeline = PhaseTimeline::from_scenario(10, &scenario);
        assert_eq!(timeline.phase_at(10), RunPhase::WarmUp);
        assert_eq!(timeline.phase_at(timeline.steady_ns), RunPhase::Steady);
        assert_eq!(timeline.phase_at(timeline.drain_ns), RunPhase::Drain);
        assert_eq!(timeline.phase_at(timeline.cool_down_ns), RunPhase::CoolDown);
        assert_eq!(timeline.phase_at(timeline.complete_ns), RunPhase::Complete);
    }

    #[test]
    fn steady_schedule_is_exact_and_catch_up_is_bounded() {
        let mut scheduler = OpenLoopScheduler::new(0, 1_000, 10, BurstPattern::default());
        let first = scheduler.poll(NANOS_PER_SECOND / 2, 1_000);
        assert_eq!(first.offered, 501);
        assert_eq!(first.emit, 501);
        assert_eq!(first.first_due_ns, 0);
        assert_eq!(first.spacing_ns, 1_000_000);
        assert_eq!(
            first
                .first_due_ns
                .saturating_add((first.emit - 1).saturating_mul(first.spacing_ns)),
            NANOS_PER_SECOND / 2
        );
        let delayed = scheduler.poll(5 * NANOS_PER_SECOND, 100);
        assert_eq!(delayed.offered, 4_500);
        assert_eq!(delayed.emit, 100);
        assert_eq!(delayed.locally_dropped, 4_400);
        assert_eq!(scheduler.cumulative_rate_debt(), 4_400);
        let no_more = scheduler.poll(5 * NANOS_PER_SECOND, 100);
        assert_eq!(no_more.offered, 0);
        assert_eq!(no_more.emit, 0);
        assert_eq!(no_more.cumulative_rate_debt, 4_400);
    }

    #[test]
    fn ramp_and_burst_schedules_do_not_exceed_shape() {
        let ramp = BurstPattern {
            kind: BurstKind::Ramp,
            ..BurstPattern::default()
        };
        let mut scheduler = OpenLoopScheduler::new(0, 100, 5, ramp);
        let result = scheduler.poll(5 * NANOS_PER_SECOND, u64::MAX);
        assert_eq!(result.offered, 250); // 0 + 25 + 50 + 75 + 100

        let burst = BurstPattern {
            kind: BurstKind::Bursty,
            peak_multiplier: 3,
            burst_secs: 2,
            idle_secs: 3,
        };
        let mut scheduler = OpenLoopScheduler::new(0, 100, 10, burst);
        let result = scheduler.poll(10 * NANOS_PER_SECOND, u64::MAX);
        assert_eq!(result.offered, 1_200); // four active seconds * 300
    }
}
