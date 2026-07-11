//! Bounded, deterministic idempotency cache for `(account, client_id)` keys.
//!
//! The cache remembers the result of each recently-seen client submission so a
//! duplicate submission executes **exactly once** and replays the identical
//! result. Memory is bounded to `capacity` entries; when full, the oldest entry
//! is evicted (strict FIFO). Because eviction depends only on insertion order,
//! two identical command streams evict identically and therefore stay
//! bit-identical across replays.

use std::collections::HashMap;
use std::collections::VecDeque;

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
    fn zero_capacity_disables_dedup() {
        let mut c = DedupCache::with_capacity(0);
        let a = AccountId::new(1);
        c.insert(a, 1, result(1));
        assert!(c.get(a, 1).is_none());
    }
}
