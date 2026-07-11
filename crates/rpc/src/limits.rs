//! Connection admission control for the RPC server: a per-IP concurrent
//! connection cap and an integer token-bucket connection rate limiter.
//!
//! The logic here is deliberately runtime-free and deterministic — every method
//! takes an explicit `now: Instant`, so the admission decisions can be unit
//! tested without wall-clock timing. The async [`crate::server`] wires this into
//! the accept loop, pairing it with a global [`tokio::sync::Semaphore`] for the
//! process-wide concurrent-connection budget.
//!
//! All arithmetic is integer-only (token counts are tracked in milli-units); no
//! floating point crosses this module.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

/// Whole tokens are tracked internally as milli-tokens so the refill rate can be
/// applied with integer arithmetic; one admission costs [`TOKENS_PER_CONN`].
const TOKENS_PER_CONN: u64 = 1_000;

/// Token-bucket parameters for the per-IP connection rate limiter (integer, no
/// floating point).
///
/// A source IP may open up to `burst` connections instantaneously; thereafter it
/// is refilled at `per_sec` connections per second up to the `burst` ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Sustained connection admissions refilled per second.
    pub per_sec: u64,
    /// Maximum burst (bucket capacity) of admissions.
    pub burst: u64,
}

impl RateLimit {
    /// Bucket capacity in milli-tokens.
    #[inline]
    fn capacity_milli(self) -> u64 {
        self.burst.saturating_mul(TOKENS_PER_CONN)
    }
}

/// Why a connection was refused by [`ConnectionLimiter::try_admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reject {
    /// The source IP already holds the maximum number of concurrent connections.
    PerIpConnections,
    /// The source IP exceeded its connection rate budget.
    RateLimited,
}

/// One source IP's token bucket for the connection rate limiter.
struct Bucket {
    /// Available tokens in milli-units (`TOKENS_PER_CONN` == one admission).
    tokens_milli: u64,
    /// Instant the bucket was last refilled.
    last: Instant,
}

/// Mutable shared state, guarded by a single mutex. Both maps are keyed by the
/// peer IP so the whole admission decision is one lock acquisition.
struct Inner {
    /// Live connection count per source IP.
    active: HashMap<IpAddr, u32>,
    /// Rate-limit token bucket per source IP.
    buckets: HashMap<IpAddr, Bucket>,
}

/// Per-IP admission control: a concurrent-connection cap plus an optional
/// token-bucket connection rate limiter. Cheap to clone via [`Arc`].
pub(crate) struct ConnectionLimiter {
    /// Maximum concurrent connections permitted from a single source IP.
    max_per_ip: u32,
    /// Optional per-IP connection rate limit; `None` disables rate limiting.
    rate: Option<RateLimit>,
    /// Soft cap on the number of tracked IP buckets before idle ones are pruned.
    max_tracked_ips: usize,
    inner: Mutex<Inner>,
}

/// An RAII admission ticket. Holding it counts one live connection for its
/// source IP; dropping it releases that slot. Connections are admitted for the
/// full duration the ticket is held (i.e. the connection's lifetime).
pub(crate) struct IpPermit {
    limiter: Arc<ConnectionLimiter>,
    ip: IpAddr,
}

impl Drop for IpPermit {
    fn drop(&mut self) {
        let mut inner = self
            .limiter
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = inner.active.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inner.active.remove(&self.ip);
            }
        }
    }
}

impl ConnectionLimiter {
    /// Build a limiter with `max_per_ip` concurrent connections per source IP and
    /// an optional per-IP connection `rate` limit. `max_tracked_ips` bounds the
    /// rate-limiter bookkeeping memory by pruning fully-refilled (idle) buckets.
    pub(crate) fn new(max_per_ip: u32, rate: Option<RateLimit>, max_tracked_ips: usize) -> Self {
        Self {
            max_per_ip,
            rate,
            max_tracked_ips: max_tracked_ips.max(1),
            inner: Mutex::new(Inner {
                active: HashMap::new(),
                buckets: HashMap::new(),
            }),
        }
    }

    /// Attempt to admit a new connection from `ip` at `now`.
    ///
    /// Returns an [`IpPermit`] to hold for the connection's lifetime, or a
    /// [`Reject`] reason. The concurrency cap is checked first (a cheap read that
    /// does not spend a rate token), then the rate budget; a rate token is only
    /// consumed when the connection is actually admitted.
    pub(crate) fn try_admit(
        self: &Arc<Self>,
        ip: IpAddr,
        now: Instant,
    ) -> Result<IpPermit, Reject> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);

        // Concurrency cap: refuse before touching the rate budget so a client
        // parked at its cap does not also burn its reconnect allowance.
        let active = inner.active.get(&ip).copied().unwrap_or(0);
        if active >= self.max_per_ip {
            return Err(Reject::PerIpConnections);
        }

        // Rate budget (token bucket). Consumes one token on success.
        if let Some(rate) = self.rate {
            if !inner.admit_token(ip, now, rate, self.max_tracked_ips) {
                return Err(Reject::RateLimited);
            }
        }

        *inner.active.entry(ip).or_insert(0) += 1;
        Ok(IpPermit {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// Total live connections across all source IPs.
    #[cfg(test)]
    pub(crate) fn active_connections(&self) -> u64 {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.active.values().map(|n| u64::from(*n)).sum()
    }

    /// Number of source IPs with rate-limiter state currently tracked.
    #[cfg(test)]
    pub(crate) fn tracked_ips(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.buckets.len()
    }
}

impl Inner {
    /// Refill `ip`'s bucket to `now` and consume one admission token if
    /// available. Returns whether a token was consumed (i.e. admission allowed).
    fn admit_token(
        &mut self,
        ip: IpAddr,
        now: Instant,
        rate: RateLimit,
        max_tracked: usize,
    ) -> bool {
        let cap = rate.capacity_milli();

        // Bound bookkeeping memory: when the table is large, drop buckets that
        // have fully refilled (idle IPs no longer being rate-limited). Buckets
        // still holding rate state (below capacity) are retained so churning
        // reconnects cannot dodge the limit.
        if self.buckets.len() >= max_tracked && !self.buckets.contains_key(&ip) {
            self.buckets.retain(|_, b| {
                // Keep buckets that are still below capacity (actively rate
                // limited); drop those that have refilled to full (idle).
                let refilled = b
                    .tokens_milli
                    .saturating_add(refill_milli(now, b.last, rate));
                refilled < cap
            });
        }

        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            tokens_milli: cap,
            last: now,
        });
        let refill = refill_milli(now, bucket.last, rate);
        bucket.tokens_milli = bucket.tokens_milli.saturating_add(refill).min(cap);
        bucket.last = now;

        if bucket.tokens_milli >= TOKENS_PER_CONN {
            bucket.tokens_milli -= TOKENS_PER_CONN;
            true
        } else {
            false
        }
    }
}

/// Milli-tokens accrued between `last` and `now` at `rate.per_sec` tokens/sec.
///
/// `per_sec` tokens/sec == `per_sec` milli-tokens per millisecond, so the refill
/// in milli-tokens is simply `elapsed_ms * per_sec` — integer arithmetic with no
/// rounding loss at millisecond granularity.
fn refill_milli(now: Instant, last: Instant, rate: RateLimit) -> u64 {
    let elapsed_ms =
        u64::try_from(now.saturating_duration_since(last).as_millis()).unwrap_or(u64::MAX);
    elapsed_ms.saturating_mul(rate.per_sec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
    }

    fn limiter(max_per_ip: u32, rate: Option<RateLimit>) -> Arc<ConnectionLimiter> {
        Arc::new(ConnectionLimiter::new(max_per_ip, rate, 1_024))
    }

    #[test]
    fn per_ip_concurrency_cap_is_enforced_and_released() {
        let l = limiter(2, None);
        let t = Instant::now();
        let p1 = l.try_admit(ip(1), t).expect("first admit");
        let p2 = l.try_admit(ip(1), t).expect("second admit");
        assert_eq!(l.active_connections(), 2);
        // Third concurrent connection from the same IP is refused.
        assert!(matches!(
            l.try_admit(ip(1), t),
            Err(Reject::PerIpConnections)
        ));
        // Releasing a permit frees a slot.
        drop(p1);
        assert_eq!(l.active_connections(), 1);
        let _p3 = l.try_admit(ip(1), t).expect("admit after release");
        assert_eq!(l.active_connections(), 2);
        drop(p2);
    }

    #[test]
    fn distinct_ips_have_independent_budgets() {
        let l = limiter(1, None);
        let t = Instant::now();
        let _a = l.try_admit(ip(1), t).expect("ip1 admit");
        // ip(1) is now full ...
        assert!(matches!(
            l.try_admit(ip(1), t),
            Err(Reject::PerIpConnections)
        ));
        // ... but a different IP is unaffected.
        let _b = l.try_admit(ip(2), t).expect("ip2 admit");
        assert_eq!(l.active_connections(), 2);
    }

    #[test]
    fn rate_limit_allows_burst_then_refills_over_time() {
        // Capacity 3, refilled 2/sec. Concurrency is not the constraint here.
        let rate = RateLimit {
            per_sec: 2,
            burst: 3,
        };
        let l = limiter(1_000, Some(rate));
        let t0 = Instant::now();
        // Burst of 3 admits succeed back-to-back at t0.
        for _ in 0..3 {
            l.try_admit(ip(1), t0).expect("burst admit");
        }
        // The 4th at the same instant is rate limited (bucket empty).
        assert!(matches!(l.try_admit(ip(1), t0), Err(Reject::RateLimited)));
        // 250ms later only 0.5 tokens accrued (2/sec) -> still limited.
        assert!(matches!(
            l.try_admit(ip(1), t0 + Duration::from_millis(250)),
            Err(Reject::RateLimited)
        ));
        // 500ms after t0, one whole token has accrued -> exactly one admit.
        l.try_admit(ip(1), t0 + Duration::from_millis(500))
            .expect("refilled admit");
        assert!(matches!(
            l.try_admit(ip(1), t0 + Duration::from_millis(500)),
            Err(Reject::RateLimited)
        ));
    }

    #[test]
    fn rate_limit_never_exceeds_burst_ceiling() {
        let rate = RateLimit {
            per_sec: 5,
            burst: 4,
        };
        let l = limiter(1_000, Some(rate));
        let t0 = Instant::now();
        // Idle for a long time -> refill saturates at the burst ceiling, not more.
        let much_later = t0 + Duration::from_secs(3_600);
        let mut admitted = 0;
        for _ in 0..100 {
            if l.try_admit(ip(1), much_later).is_ok() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 4, "burst ceiling must cap accumulated tokens");
    }

    #[test]
    fn zero_burst_rate_refuses_all() {
        let rate = RateLimit {
            per_sec: 0,
            burst: 0,
        };
        let l = limiter(1_000, Some(rate));
        assert!(matches!(
            l.try_admit(ip(1), Instant::now()),
            Err(Reject::RateLimited)
        ));
    }

    #[test]
    fn concurrency_check_precedes_rate_spend() {
        // With a single concurrency slot, a client parked at its cap must be
        // refused on concurrency grounds without spending rate tokens.
        let rate = RateLimit {
            per_sec: 0,
            burst: 4,
        };
        let l = limiter(1, Some(rate));
        let t = Instant::now();
        let _held = l.try_admit(ip(1), t).expect("first admit spends one token");
        // Repeated attempts while parked are all PerIpConnections (not RateLimited),
        // proving no rate token is consumed on the concurrency-refused path.
        for _ in 0..10 {
            assert!(matches!(
                l.try_admit(ip(1), t),
                Err(Reject::PerIpConnections)
            ));
        }
    }

    #[test]
    fn idle_buckets_are_pruned_to_bound_memory() {
        let rate = RateLimit {
            per_sec: 1_000,
            burst: 1,
        };
        // Tiny tracking cap forces pruning of fully-refilled buckets.
        let l = Arc::new(ConnectionLimiter::new(1_000, Some(rate), 4));
        let t0 = Instant::now();
        // Touch many distinct IPs; each connect-and-release refills fully after a
        // second of idleness, so stale buckets get reclaimed on later admits.
        for i in 0..200u8 {
            let now = t0 + Duration::from_secs(u64::from(i) + 10);
            let _ = l.try_admit(ip(i), now);
        }
        assert!(
            l.tracked_ips() <= 16,
            "bucket table must stay bounded, got {}",
            l.tracked_ips()
        );
    }
}
