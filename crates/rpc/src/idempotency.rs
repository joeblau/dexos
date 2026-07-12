//! Bounded, TTL-aware idempotency store for control-command dedupe.
//!
//! A naive `HashMap<(client_id, nonce), Ack>` grows without bound under a flood
//! of unique keys. This store enforces two independent ceilings:
//!
//! * a hard entry-count cap with LRU eviction of the least-recently-used key;
//! * a per-entry TTL so idle keys age out even when the map is under capacity.
//!
//! Lookups refresh LRU order (a successful replay is "use"); inserts of new
//! keys push to the front of the recency list. Expired entries are skipped on
//! lookup and reclaimed opportunistically on insert / lookup pressure.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Configuration for a [`IdempotencyStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdempotencyConfig {
    /// Maximum number of live entries retained.
    pub max_entries: usize,
    /// Wall-clock lifetime of an entry after its last successful touch.
    pub ttl: Duration,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            max_entries: 65_536,
            ttl: Duration::from_secs(300),
        }
    }
}

#[derive(Debug)]
struct Entry<V> {
    value: V,
    expires_at: Instant,
}

/// A capacity- and TTL-bounded map used for control-command exactly-once
/// semantics. Keys are typically `(client_id, nonce)`.
#[derive(Debug)]
pub struct IdempotencyStore<K, V> {
    max_entries: usize,
    ttl: Duration,
    map: HashMap<K, Entry<V>>,
    /// Front = most recently used; back = least recently used (eviction victim).
    order: VecDeque<K>,
}

impl<K, V> IdempotencyStore<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Build a store from `config`. `max_entries` is clamped to at least 1.
    pub fn new(config: IdempotencyConfig) -> Self {
        Self {
            max_entries: config.max_entries.max(1),
            ttl: config.ttl,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Number of currently retained entries (including any that may be expired
    /// but not yet reclaimed).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Lookup `key` at `now`. Returns a clone of the stored value if present
    /// and unexpired; expired entries are removed. A hit refreshes LRU order
    /// and extends the TTL from `now`.
    pub fn get(&mut self, key: &K, now: Instant) -> Option<V> {
        self.reclaim_expired(now, /*budget=*/ 8);
        let entry = self.map.get_mut(key)?;
        if now >= entry.expires_at {
            self.map.remove(key);
            self.order.retain(|k| k != key);
            return None;
        }
        entry.expires_at = now.checked_add(self.ttl).unwrap_or(now);
        let value = entry.value.clone();
        self.touch(key);
        Some(value)
    }

    /// Insert or replace `key` → `value` at `now`. Evicts the LRU entry when
    /// at capacity and the key is novel. Returns the previous value if any.
    pub fn insert(&mut self, key: K, value: V, now: Instant) -> Option<V> {
        self.reclaim_expired(now, /*budget=*/ 16);
        let expires_at = now.checked_add(self.ttl).unwrap_or(now);
        if let Some(existing) = self.map.get_mut(&key) {
            let prev = std::mem::replace(&mut existing.value, value);
            existing.expires_at = expires_at;
            self.touch(&key);
            return Some(prev);
        }
        while self.map.len() >= self.max_entries {
            let Some(victim) = self.order.pop_back() else {
                break;
            };
            self.map.remove(&victim);
        }
        self.map.insert(key.clone(), Entry { value, expires_at });
        self.order.push_front(key);
        None
    }

    /// Snapshot of currently retained keys (for tests).
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    fn touch(&mut self, key: &K) {
        // Linear scan is fine: capacity is bounded and this is the control
        // path, not the market-data hot path. A doubly-linked list would be
        // overkill relative to the rest of the stub backend.
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            let k = self.order.remove(pos).expect("position just found");
            self.order.push_front(k);
        }
    }

    /// Drop up to `budget` expired entries from the LRU end.
    fn reclaim_expired(&mut self, now: Instant, budget: usize) {
        let mut reclaimed = 0;
        while reclaimed < budget {
            let Some(back) = self.order.back().cloned() else {
                break;
            };
            let expired = self
                .map
                .get(&back)
                .map(|e| now >= e.expires_at)
                .unwrap_or(true);
            if !expired {
                // Order is recency, not expiry; stop scanning when the oldest
                // non-evicted entry is still live. Opportunistic full sweep is
                // done only when over capacity (handled by insert).
                break;
            }
            self.order.pop_back();
            self.map.remove(&back);
            reclaimed += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max: usize, ttl_ms: u64) -> IdempotencyConfig {
        IdempotencyConfig {
            max_entries: max,
            ttl: Duration::from_millis(ttl_ms),
        }
    }

    #[test]
    fn capacity_bound_evicts_lru() {
        let mut s = IdempotencyStore::new(cfg(3, 60_000));
        let t = Instant::now();
        s.insert(1u64, "a", t);
        s.insert(2, "b", t);
        s.insert(3, "c", t);
        // Touch 1 so it is MRU; 2 becomes the LRU after next insert.
        assert_eq!(s.get(&1, t).as_deref(), Some("a"));
        s.insert(4, "d", t);
        assert_eq!(s.len(), 3);
        // 2 was least recently used and should be gone.
        assert!(s.get(&2, t).is_none());
        assert_eq!(s.get(&1, t).as_deref(), Some("a"));
        assert_eq!(s.get(&3, t).as_deref(), Some("c"));
        assert_eq!(s.get(&4, t).as_deref(), Some("d"));
    }

    #[test]
    fn ttl_expires_entries() {
        let mut s = IdempotencyStore::new(cfg(8, 100));
        let t0 = Instant::now();
        s.insert(1u64, 42u32, t0);
        assert_eq!(s.get(&1, t0), Some(42));
        let later = t0 + Duration::from_millis(200);
        assert!(s.get(&1, later).is_none());
    }

    #[test]
    fn flood_stays_bounded() {
        let mut s = IdempotencyStore::new(cfg(64, 60_000));
        let t = Instant::now();
        for i in 0..10_000u64 {
            s.insert(i, i, t);
        }
        assert!(s.len() <= 64, "store grew to {}", s.len());
    }
}
