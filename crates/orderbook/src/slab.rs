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
use crate::BookStateError;

/// Sentinel meaning "no slot" in an intrusive index chain.
pub(crate) const NIL: u32 = u32::MAX;

/// A single arena slot: either an occupied value or a link in the free stack.
#[derive(Clone)]
enum Entry<T> {
    /// Holds a live value.
    Occupied(T),
    /// Free; stores the index of the next free slot (or [`NIL`]).
    Free(u32),
}

/// A fixed-capacity arena with O(1) insert and remove and deterministic reuse.
///
/// [`Clone`] produces a bit-identical arena (same slots, same free list), which
/// the order book relies on to snapshot and roll back speculative work. The
/// clone re-reserves the full `capacity` eagerly, so cloned slabs keep the
/// no-allocation guarantee on the warm insert path.
pub struct Slab<T> {
    entries: Vec<Entry<T>>,
    free_head: u32,
    len: usize,
    capacity: usize,
}

impl<T: Clone> Clone for Slab<T> {
    fn clone(&self) -> Self {
        // `#[derive(Clone)]` would clone `entries` with capacity == len,
        // silently dropping the eager reservation made by
        // [`Slab::with_capacity`]; subsequent inserts into the clone would then
        // reallocate, voiding the "no heap allocation on the warm insert path"
        // contract for snapshot / transaction copies of the book. Rebuild the
        // backing `Vec` at full capacity instead. This is deterministic: slot
        // indices depend only on `entries.len()` and the copied free list, and
        // `Vec` capacity is not part of logical state.
        let mut entries = Vec::with_capacity(self.capacity);
        entries.extend(self.entries.iter().cloned());
        Slab {
            entries,
            free_head: self.free_head,
            len: self.len,
            capacity: self.capacity,
        }
    }
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

    /// Validate every allocator field read by a future insert or remove.
    ///
    /// Free-list order is intentionally non-logical, but it must be a
    /// duplicate-free permutation of every free entry. The walk is bounded by
    /// the number of stored free entries, so a corrupt cycle cannot hang
    /// recovery validation.
    pub(crate) fn validate_representation(
        &self,
        expected_capacity: usize,
    ) -> Result<(), BookStateError> {
        if self.capacity != expected_capacity {
            return Err(BookStateError::InvalidValue {
                field: "slab capacity must match the logical book configuration",
            });
        }
        if self.entries.len() > self.capacity {
            return Err(BookStateError::InvalidValue {
                field: "slab entries must not exceed capacity",
            });
        }
        let occupied = self
            .entries
            .iter()
            .filter(|entry| matches!(entry, Entry::Occupied(_)))
            .count();
        if occupied != self.len {
            return Err(BookStateError::InvalidValue {
                field: "slab live count must equal its occupied entries",
            });
        }

        let stored_free = self
            .entries
            .iter()
            .filter(|entry| matches!(entry, Entry::Free(_)))
            .count();
        let mut current = self.free_head;
        let mut free_count = 0usize;
        while current != NIL {
            let index = usize::try_from(current).map_err(|_| BookStateError::NativeWidth {
                field: "slab free-list slot",
                value: u64::from(current),
            })?;
            let entry = self
                .entries
                .get(index)
                .ok_or(BookStateError::InvalidValue {
                    field: "slab free list must reference an existing entry",
                })?;
            current = match entry {
                Entry::Free(next) => {
                    if free_count >= stored_free {
                        return Err(BookStateError::InvalidValue {
                            field: "slab free list must not contain a cycle",
                        });
                    }
                    free_count += 1;
                    *next
                }
                Entry::Occupied(_) => {
                    return Err(BookStateError::InvalidValue {
                        field: "slab free list must reference only free entries",
                    })
                }
            };
        }
        if free_count != stored_free {
            return Err(BookStateError::InvalidValue {
                field: "slab free list must cover every free entry exactly once",
            });
        }
        Ok(())
    }

    /// Visit every occupied slot exactly once in physical slot order.
    ///
    /// This is a bounded representation walk for recovery validation; logical
    /// encoding deliberately remains independent of physical slab order.
    pub(crate) fn try_for_each_occupied<F>(&self, mut f: F) -> Result<(), BookStateError>
    where
        F: FnMut(u32, &T) -> Result<(), BookStateError>,
    {
        for (index, entry) in self.entries.iter().enumerate() {
            if let Entry::Occupied(value) = entry {
                let slot = u32::try_from(index).map_err(|_| BookStateError::NativeWidth {
                    field: "occupied slab slot",
                    value: u64::try_from(index).unwrap_or(u64::MAX),
                })?;
                f(slot, value)?;
            }
        }
        Ok(())
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

    /// Test-only fingerprint proving two logically equivalent slabs may retain
    /// different dense/free-list layouts across canonical restore.
    #[cfg(test)]
    pub(crate) fn representation_for_test(&self) -> (usize, u32) {
        (self.entries.len(), self.free_head)
    }

    #[cfg(test)]
    pub(crate) fn make_free_list_cycle_for_test(&mut self) {
        let slot = usize::try_from(self.free_head).unwrap();
        self.entries[slot] = Entry::Free(self.free_head);
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
    fn clone_preserves_reserved_capacity() {
        let mut s: Slab<u64> = Slab::with_capacity(64);
        for i in 0..8u64 {
            s.insert(i).unwrap();
        }
        let c = s.clone();
        assert_eq!(c.capacity(), 64);
        assert_eq!(c.len(), s.len());
        // The backing Vec must keep the eager reservation, not shrink to len.
        assert!(c.entries.capacity() >= 64);
        // A clone of a completely empty slab keeps its reservation too.
        let empty: Slab<u64> = Slab::with_capacity(16);
        assert!(empty.clone().entries.capacity() >= 16);
    }

    #[test]
    fn representation_validator_accepts_reuse_and_rejects_bad_capacity() {
        let mut slab = Slab::with_capacity(4);
        let first = slab.insert(1).unwrap();
        slab.insert(2).unwrap();
        slab.remove(first).unwrap();
        slab.validate_representation(4).unwrap();

        assert!(matches!(
            slab.validate_representation(5),
            Err(BookStateError::InvalidValue { .. })
        ));
    }

    #[test]
    fn representation_validator_rejects_free_list_into_live_entry() {
        let mut slab = Slab::with_capacity(2);
        let live = slab.insert(1).unwrap();
        slab.free_head = live;
        assert!(matches!(
            slab.validate_representation(2),
            Err(BookStateError::InvalidValue {
                field: "slab free list must reference only free entries"
            })
        ));
    }

    #[test]
    fn representation_validator_rejects_free_list_cycle() {
        let mut slab = Slab::with_capacity(2);
        let first = slab.insert(1).unwrap();
        let second = slab.insert(2).unwrap();
        slab.remove(first).unwrap();
        slab.remove(second).unwrap();
        slab.entries[usize::try_from(second).unwrap()] = Entry::Free(second);
        slab.free_head = second;
        assert!(matches!(
            slab.validate_representation(2),
            Err(BookStateError::InvalidValue {
                field: "slab free list must not contain a cycle"
            })
        ));
    }

    #[test]
    fn representation_validator_rejects_unlinked_free_entry() {
        let mut slab = Slab::with_capacity(2);
        let first = slab.insert(1).unwrap();
        slab.remove(first).unwrap();
        slab.free_head = NIL;
        assert!(matches!(
            slab.validate_representation(2),
            Err(BookStateError::InvalidValue {
                field: "slab free list must cover every free entry exactly once"
            })
        ));
    }

    #[test]
    fn warm_inserts_into_clone_never_reallocate() {
        let mut s: Slab<u64> = Slab::with_capacity(32);
        for i in 0..4u64 {
            s.insert(i).unwrap();
        }
        s.remove(1).unwrap();
        let mut c = s.clone();
        let base = c.entries.as_ptr();
        // Free-list state survives the clone: the freed slot is reused first.
        assert_eq!(c.insert(99).unwrap(), 1);
        // Filling the clone to capacity must stay within the pre-reserved
        // allocation: the backing buffer never moves (no realloc).
        while !c.is_full() {
            c.insert(100).unwrap();
        }
        assert_eq!(c.len(), c.capacity());
        assert_eq!(c.entries.as_ptr(), base);
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
