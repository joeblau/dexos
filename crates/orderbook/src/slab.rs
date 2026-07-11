//! Fixed-capacity slab (arena) allocator with a free list.
//!
//! The slab holds up to `capacity` values in a contiguous `Vec`. Slots are
//! handed out from a LIFO free list and returned to it on removal, so a warm
//! slab performs **no heap allocation on the normal insert/remove path** — the
//! backing `Vec` is sized once up front and never grows.
//!
//! Slot reuse is deterministic: an identical sequence of `insert`/`remove`
//! calls always yields the identical sequence of slot indices, because the free
//! list is a strict stack keyed only by the order of operations. This property
//! is relied on for reproducible order-book replay.

use crate::error::SlabError;

/// Sentinel meaning "no slot" in an intrusive index chain.
pub(crate) const NIL: u32 = u32::MAX;

/// A single arena slot: either an occupied value or a link in the free stack.
enum Entry<T> {
    /// Holds a live value.
    Occupied(T),
    /// Free; stores the index of the next free slot (or [`NIL`]).
    Free(u32),
}

/// A fixed-capacity arena with O(1) insert and remove and deterministic reuse.
pub struct Slab<T> {
    entries: Vec<Entry<T>>,
    free_head: u32,
    len: usize,
    capacity: usize,
}

impl<T> Slab<T> {
    /// Create a slab that can hold exactly `capacity` values. The backing
    /// storage is reserved eagerly so steady-state operations never allocate.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Slab {
            entries: Vec::with_capacity(capacity),
            free_head: NIL,
            len: 0,
            capacity,
        }
    }

    /// The maximum number of live values.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of currently live values.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when no values are live.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when every slot is occupied.
    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == self.capacity
    }

    /// Insert `value`, returning its slot index.
    ///
    /// Prefers a recycled slot from the free list (LIFO); otherwise grows the
    /// live region up to `capacity`. Returns [`SlabError::CapacityExhausted`]
    /// when the slab is full — it never panics or reallocates past capacity.
    pub fn insert(&mut self, value: T) -> Result<u32, SlabError> {
        if self.free_head != NIL {
            let idx = self.free_head;
            let slot = usize::try_from(idx).map_err(|_| SlabError::InvalidSlot)?;
            let next = match &self.entries[slot] {
                Entry::Free(next) => *next,
                Entry::Occupied(_) => return Err(SlabError::InvalidSlot),
            };
            self.entries[slot] = Entry::Occupied(value);
            self.free_head = next;
            self.len += 1;
            return Ok(idx);
        }
        if self.entries.len() >= self.capacity {
            return Err(SlabError::CapacityExhausted);
        }
        let idx = u32::try_from(self.entries.len()).map_err(|_| SlabError::CapacityExhausted)?;
        self.entries.push(Entry::Occupied(value));
        self.len += 1;
        Ok(idx)
    }

    /// Remove and return the value at `index`, returning its slot to the free
    /// list. Errors (never panics) on an out-of-range or already-free slot.
    pub fn remove(&mut self, index: u32) -> Result<T, SlabError> {
        let slot = usize::try_from(index).map_err(|_| SlabError::InvalidSlot)?;
        if slot >= self.entries.len() {
            return Err(SlabError::InvalidSlot);
        }
        match &self.entries[slot] {
            Entry::Free(_) => return Err(SlabError::NotOccupied),
            Entry::Occupied(_) => {}
        }
        let taken = std::mem::replace(&mut self.entries[slot], Entry::Free(self.free_head));
        self.free_head = index;
        self.len -= 1;
        match taken {
            Entry::Occupied(v) => Ok(v),
            // Unreachable: guarded above, but no panic on the error path.
            Entry::Free(_) => Err(SlabError::NotOccupied),
        }
    }

    /// Shared reference to the value at `index`, if occupied.
    #[inline]
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&T> {
        let slot = usize::try_from(index).ok()?;
        match self.entries.get(slot)? {
            Entry::Occupied(v) => Some(v),
            Entry::Free(_) => None,
        }
    }

    /// Mutable reference to the value at `index`, if occupied.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self, index: u32) -> Option<&mut T> {
        let slot = usize::try_from(index).ok()?;
        match self.entries.get_mut(slot)? {
            Entry::Occupied(v) => Some(v),
            Entry::Free(_) => None,
        }
    }

    /// True when `index` currently holds a live value.
    #[inline]
    #[must_use]
    pub fn contains(&self, index: u32) -> bool {
        self.get(index).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small deterministic LCG for reproducible randomized tests.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next_u64() % u64::try_from(n).unwrap()).unwrap()
        }
    }

    #[test]
    fn insert_get_remove_roundtrip() {
        let mut s: Slab<u32> = Slab::with_capacity(4);
        let a = s.insert(10).unwrap();
        let b = s.insert(20).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(*s.get(a).unwrap(), 10);
        assert_eq!(*s.get(b).unwrap(), 20);
        assert_eq!(s.remove(a).unwrap(), 10);
        assert!(s.get(a).is_none());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn capacity_exhaustion_is_typed_and_non_panicking() {
        let mut s: Slab<u8> = Slab::with_capacity(2);
        assert!(s.insert(1).is_ok());
        assert!(s.insert(2).is_ok());
        assert_eq!(s.insert(3), Err(SlabError::CapacityExhausted));
        assert!(s.is_full());
    }

    #[test]
    fn double_free_and_bad_index_error() {
        let mut s: Slab<u8> = Slab::with_capacity(2);
        let a = s.insert(1).unwrap();
        assert_eq!(s.remove(a).unwrap(), 1);
        assert_eq!(s.remove(a), Err(SlabError::NotOccupied));
        assert_eq!(s.remove(999), Err(SlabError::InvalidSlot));
    }

    #[test]
    fn reuse_is_lifo_and_deterministic() {
        // Free list is a stack: the most recently freed slot is reused first.
        let mut s: Slab<u32> = Slab::with_capacity(3);
        let a = s.insert(1).unwrap();
        let b = s.insert(2).unwrap();
        let c = s.insert(3).unwrap();
        assert_eq!((a, b, c), (0, 1, 2));
        s.remove(b).unwrap();
        s.remove(a).unwrap();
        // a was freed last -> reused first.
        assert_eq!(s.insert(4).unwrap(), a);
        assert_eq!(s.insert(5).unwrap(), b);
    }

    #[test]
    fn identical_command_sequences_yield_identical_indices() {
        fn run() -> Vec<i64> {
            let mut r = Lcg(0xABCD_1234);
            let mut s: Slab<u32> = Slab::with_capacity(64);
            let mut live: Vec<u32> = Vec::new();
            let mut trace = Vec::new();
            for step in 0..5_000u32 {
                if !live.is_empty() && r.below(2) == 0 {
                    let pick = r.below(live.len());
                    let idx = live.swap_remove(pick);
                    s.remove(idx).unwrap();
                    trace.push(-1);
                } else {
                    match s.insert(step) {
                        Ok(idx) => {
                            live.push(idx);
                            trace.push(i64::from(idx));
                        }
                        Err(_) => trace.push(-2),
                    }
                }
            }
            trace
        }
        assert_eq!(run(), run());
    }

    #[test]
    fn free_list_correctness_under_randomized_alloc_free() {
        let mut r = Lcg(0x5EED);
        let mut s: Slab<u64> = Slab::with_capacity(32);
        let mut model: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
        let mut live: Vec<u32> = Vec::new();
        for step in 0..20_000u64 {
            if !live.is_empty() && (r.below(2) == 0 || s.is_full()) {
                let pick = r.below(live.len());
                let idx = live.swap_remove(pick);
                let expected = model.remove(&idx).unwrap();
                assert_eq!(s.remove(idx).unwrap(), expected);
            } else if let Ok(idx) = s.insert(step) {
                // A returned slot must never alias a live slot.
                assert!(!model.contains_key(&idx));
                model.insert(idx, step);
                live.push(idx);
            }
            assert_eq!(s.len(), model.len());
            for (&idx, &val) in &model {
                assert_eq!(*s.get(idx).unwrap(), val);
            }
            assert!(s.len() <= s.capacity());
        }
    }
}
