//! A bounded, insertion-ordered cache used for discovery, recent checkpoints,
//! and recent proof responses.
//!
//! Capacity is a hard bound: inserting a new key into a full cache evicts the
//! oldest key (FIFO) and increments an eviction counter, so a burst of inserts
//! can never grow memory past the configured limit. Re-inserting an existing key
//! updates its value in place without changing its age. Entries can be
//! selectively invalidated with [`BoundedCache::retain`] — used to drop stale
//! cached responses when the verified tip advances.

use std::collections::{BTreeMap, VecDeque};

/// A fixed-capacity, insertion-ordered map.
#[derive(Debug, Clone)]
pub struct BoundedCache<K: Ord + Clone, V> {
    map: BTreeMap<K, V>,
    order: VecDeque<K>,
    capacity: usize,
    evicted: u64,
}

impl<K: Ord + Clone, V> BoundedCache<K, V> {
    /// A cache holding at most `capacity` entries (at least one).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            evicted: 0,
        }
    }

    /// Maximum number of entries retained.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Current number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Total entries evicted due to capacity pressure.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Whether `key` is present.
    #[must_use]
    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Get a reference to the value for `key`.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Insert `key => value`, returning any evicted `(key, value)` if the
    /// capacity bound forced an eviction. Updating an existing key never evicts.
    pub fn insert(&mut self, key: K, value: V) -> Option<(K, V)> {
        if let std::collections::btree_map::Entry::Occupied(mut e) = self.map.entry(key.clone()) {
            e.insert(value);
            return None;
        }
        let mut evicted_entry = None;
        while self.map.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(v) = self.map.remove(&oldest) {
                self.evicted = self.evicted.saturating_add(1);
                evicted_entry = Some((oldest, v));
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
        evicted_entry
    }

    /// Remove `key`, returning its value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let removed = self.map.remove(key);
        if removed.is_some() {
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
        }
        removed
    }

    /// Retain only entries for which `pred(&key, &value)` is true. Used to
    /// invalidate stale entries when the verified tip advances.
    pub fn retain<F: FnMut(&K, &V) -> bool>(&mut self, mut pred: F) {
        let mut drop_keys: Vec<K> = Vec::new();
        for (k, v) in &self.map {
            if !pred(k, v) {
                drop_keys.push(k.clone());
            }
        }
        for k in drop_keys {
            self.map.remove(&k);
            if let Some(pos) = self.order.iter().position(|ok| ok == &k) {
                self.order.remove(pos);
            }
        }
    }

    /// Clear all entries (retains the capacity bound and eviction counter).
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    /// Iterate values in key order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.map.values()
    }

    /// Iterate `(key, value)` pairs in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }
}
