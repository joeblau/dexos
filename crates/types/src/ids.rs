//! Compact, strongly-typed integer identifiers and monotonic sequence numbers.
//!
//! IDs are distinct newtypes so an `AccountId` can never be passed where a
//! `MarketId` is expected. Conversions to `usize` (for indexed-array / slab
//! addressing) are checked and never truncate or panic.

use serde::{Deserialize, Serialize};

/// An identifier conversion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// A raw value could not be represented as `usize` on this platform.
    #[error("identifier value does not fit usize")]
    OutOfRange,
}

/// Sequence-number failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SequenceError {
    /// The sequence space is exhausted (would wrap past the maximum).
    #[error("sequence number exhausted")]
    Exhausted,
}

macro_rules! define_id {
    ($name:ident, $repr:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[repr(transparent)]
        #[serde(transparent)]
        pub struct $name($repr);

        impl $name {
            /// Construct from a raw compact integer.
            #[inline]
            pub const fn new(raw: $repr) -> Self {
                Self(raw)
            }

            /// The raw compact integer.
            #[inline]
            pub const fn get(self) -> $repr {
                self.0
            }

            /// Convert to a slab/array index, erroring rather than truncating.
            #[inline]
            pub fn index(self) -> Result<usize, IdError> {
                usize::try_from(self.0).map_err(|_| IdError::OutOfRange)
            }

            /// Build from a slab/array index, erroring rather than truncating.
            #[inline]
            pub fn from_index(index: usize) -> Result<Self, IdError> {
                <$repr>::try_from(index)
                    .map(Self)
                    .map_err(|_| IdError::OutOfRange)
            }
        }
    };
}

define_id!(AccountId, u32, "A compact account identifier.");
define_id!(MarketId, u32, "A compact market identifier.");
define_id!(OrderId, u64, "A compact order identifier.");
define_id!(ShardId, u16, "A compact market-shard identifier.");
define_id!(SponsorId, u32, "A compact sponsor identifier.");

/// A monotonic, non-wrapping global/shard sequence number.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SequenceNumber(u64);

impl SequenceNumber {
    /// The first sequence number.
    pub const ZERO: Self = Self(0);

    /// Construct from a raw value.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next sequence number, erroring at the maximum instead of wrapping.
    #[inline]
    pub fn next(self) -> Result<Self, SequenceError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(SequenceError::Exhausted)
    }

    /// True if `self` immediately follows `prev` (no gaps).
    #[inline]
    pub fn follows(self, prev: SequenceNumber) -> bool {
        self.0 == prev.0.wrapping_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_index_on_boundaries() {
        assert_eq!(AccountId::new(0).index(), Ok(0));
        assert_eq!(
            AccountId::new(u32::MAX).index(),
            Ok(usize::try_from(u32::MAX).unwrap())
        );
        assert_eq!(AccountId::from_index(7).map(|a| a.get()), Ok(7));
        // Out of range for u16 shard.
        assert_eq!(ShardId::from_index(70_000), Err(IdError::OutOfRange));
    }

    #[test]
    fn sequence_is_strictly_monotonic_and_errors_at_max() {
        let mut s = SequenceNumber::ZERO;
        for _ in 0..10_000 {
            let n = s.next().unwrap();
            assert!(n.get() > s.get());
            assert!(n.follows(s));
            s = n;
        }
        assert_eq!(
            SequenceNumber::new(u64::MAX).next(),
            Err(SequenceError::Exhausted)
        );
    }

    #[test]
    fn conversions_never_panic() {
        for i in [0usize, 1, 255, 65_535, 65_536, usize::MAX] {
            let _ = ShardId::from_index(i);
            let _ = OrderId::from_index(i);
        }
    }
}
