//! Bounded, deterministic idempotency cache for `(account, client_id)` keys.
//!
//! The cache remembers the result of each recently-seen client submission so a
//! duplicate submission executes **exactly once** and replays the identical
//! result. Memory is bounded to `capacity` entries; when full, the oldest entry
//! is evicted (strict FIFO). Because eviction depends only on insertion order,
//! two identical command streams evict identically and therefore stay
//! bit-identical across replays.

use std::collections::{HashMap, HashSet, VecDeque};

use types::AccountId;

use crate::order::MatchResult;

/// Composite idempotency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    account: u32,
    client_id: u64,
}

/// A fixed-capacity FIFO cache of recent submission results.
pub(crate) struct DedupCache {
    capacity: usize,
    map: HashMap<Key, MatchResult>,
    order: VecDeque<Key>,
}

impl Clone for DedupCache {
    fn clone(&self) -> Self {
        // Container `clone` sizes the copies for the current entries only,
        // dropping the eager reservation made by
        // [`DedupCache::with_capacity`]. Restore it so inserts into a cloned
        // cache (via a cloned book) stay allocation-free up to `capacity`.
        // Reserved capacity is not logical state; behavior is bit-identical.
        let mut map = self.map.clone();
        map.reserve(self.capacity.saturating_sub(map.len()));
        let mut order = self.order.clone();
        order.reserve(self.capacity.saturating_sub(order.len()));
        DedupCache {
            capacity: self.capacity,
            map,
            order,
        }
    }
}

impl DedupCache {
    /// Create a cache holding at most `capacity` recent keys. A zero capacity
    /// disables deduplication entirely.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        DedupCache {
            capacity,
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    fn key(account: AccountId, client_id: u64) -> Key {
        Key {
            account: account.get(),
            client_id,
        }
    }

    /// Look up a previously-cached result for this key, if still in the window.
    pub(crate) fn get(&self, account: AccountId, client_id: u64) -> Option<&MatchResult> {
        if self.capacity == 0 {
            return None;
        }
        self.map.get(&Self::key(account, client_id))
    }

    /// Record `result` for this key, evicting the oldest entry if at capacity.
    /// Re-recording an existing key refreshes its stored result without changing
    /// its position (it is already the most recent by construction).
    pub(crate) fn insert(&mut self, account: AccountId, client_id: u64, result: MatchResult) {
        if self.capacity == 0 {
            return;
        }
        let key = Self::key(account, client_id);
        if let Some(slot) = self.map.get_mut(&key) {
            // Already recorded (it is already the most recent); refresh its result.
            *slot = result;
            return;
        }
        while self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
        self.order.push_back(key);
        self.map.insert(key, result);
    }

    /// Number of records retained in the authoritative FIFO window.
    pub(crate) fn record_count(&self) -> usize {
        assert_eq!(
            self.order.len(),
            self.map.len(),
            "dedup FIFO and result map must contain the same keys"
        );
        self.order.len()
    }

    /// Fail-stop validation for the result map, FIFO, and actual eviction
    /// capacity read by future lookups/inserts.
    pub(crate) fn validate_representation(&self, expected_capacity: usize) {
        assert_eq!(
            self.capacity, expected_capacity,
            "dedup capacity must match the logical book configuration"
        );
        assert_eq!(
            self.order.len(),
            self.map.len(),
            "dedup FIFO and result map must contain the same keys"
        );
        assert!(
            self.map.len() <= self.capacity,
            "dedup records must not exceed capacity"
        );
        let mut seen = HashSet::with_capacity(self.order.len());
        for key in &self.order {
            assert!(
                seen.insert(*key),
                "dedup FIFO must not contain duplicate keys"
            );
            assert!(
                self.map.contains_key(key),
                "dedup FIFO key must have a cached result"
            );
        }
    }

    /// Visit records in eviction order (oldest first). The queue and map are
    /// updated atomically by [`Self::insert`], so a queued key always has a
    /// corresponding result.
    pub(crate) fn for_each_in_eviction_order<F: FnMut(u32, u64, &MatchResult)>(&self, mut f: F) {
        let mut seen = HashSet::with_capacity(self.order.len());
        for key in &self.order {
            assert!(
                seen.insert(*key),
                "dedup FIFO must not contain duplicate keys"
            );
            let result = self
                .map
                .get(key)
                .expect("dedup FIFO key must have a cached result");
            f(key.account, key.client_id, result);
        }
    }

    /// Number of live cached keys.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order::OrderOutcome;
    use types::Quantity;

    fn result(tag: i64) -> MatchResult {
        MatchResult {
            fills: Vec::new(),
            outcome: OrderOutcome::Resting {
                remaining: Quantity::from_raw(tag),
            },
        }
    }

    #[test]
    fn hit_and_miss() {
        let mut c = DedupCache::with_capacity(4);
        let a = AccountId::new(1);
        assert!(c.get(a, 7).is_none());
        c.insert(a, 7, result(10));
        assert_eq!(c.get(a, 7), Some(&result(10)));
        // Different account, same client id: independent.
        assert!(c.get(AccountId::new(2), 7).is_none());
    }

    #[test]
    fn fifo_eviction_is_bounded_and_deterministic() {
        let mut c = DedupCache::with_capacity(2);
        let a = AccountId::new(1);
        c.insert(a, 1, result(1));
        c.insert(a, 2, result(2));
        c.insert(a, 3, result(3)); // evicts key 1
        assert!(c.get(a, 1).is_none());
        assert!(c.get(a, 2).is_some());
        assert!(c.get(a, 3).is_some());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn clone_preserves_reserved_capacity() {
        let mut c = DedupCache::with_capacity(32);
        let a = AccountId::new(1);
        c.insert(a, 7, result(10));
        let cloned = c.clone();
        assert_eq!(cloned.get(a, 7), Some(&result(10)));
        // The eager reservations must survive the clone, not shrink to len.
        assert!(cloned.map.capacity() >= 32);
        assert!(cloned.order.capacity() >= 32);
    }

    #[test]
    fn zero_capacity_disables_dedup() {
        let mut c = DedupCache::with_capacity(0);
        let a = AccountId::new(1);
        c.insert(a, 1, result(1));
        assert!(c.get(a, 1).is_none());
    }

    #[test]
    #[should_panic(expected = "dedup FIFO must not contain duplicate keys")]
    fn canonical_iteration_rejects_duplicate_fifo_keys() {
        let mut c = DedupCache::with_capacity(2);
        let a = AccountId::new(1);
        c.insert(a, 1, result(1));
        c.insert(a, 2, result(2));
        c.order[1] = c.order[0];

        assert_eq!(c.record_count(), 2);
        c.for_each_in_eviction_order(|_, _, _| {});
    }

    #[test]
    fn representation_validator_binds_actual_capacity() {
        let mut cache = DedupCache::with_capacity(2);
        cache.insert(AccountId::new(1), 1, result(1));
        cache.validate_representation(2);

        let mismatch = std::panic::catch_unwind(|| cache.validate_representation(3));
        assert!(mismatch.is_err());
    }

    #[test]
    #[should_panic(expected = "dedup records must not exceed capacity")]
    fn representation_validator_rejects_records_over_capacity() {
        let mut cache = DedupCache::with_capacity(1);
        cache.insert(AccountId::new(1), 1, result(1));
        cache.capacity = 0;
        cache.validate_representation(0);
    }
}
