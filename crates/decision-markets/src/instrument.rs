//! Compact action / outcome identifiers and the bijective instrument mapping.
//!
//! Every tradeable instrument in a decision market is an `(action, outcome)`
//! pair. The mapping to a flat [`InstrumentId`] is bijective and stable for a
//! fixed outcome count, computed with checked integer arithmetic only.

use serde::{Deserialize, Serialize};

use crate::error::DecisionMarketError;

/// A compact action identifier (index into the definition's action list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionId(u16);

/// A compact outcome identifier (index into the definition's outcome list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OutcomeId(u16);

/// A flat instrument identifier for an `(action, outcome)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InstrumentId(u32);

macro_rules! define_index {
    ($name:ident, $repr:ty, $doc:literal) => {
        impl $name {
            #[doc = $doc]
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
            pub fn index(self) -> Result<usize, DecisionMarketError> {
                usize::try_from(self.0).map_err(|_| DecisionMarketError::Truncation)
            }

            /// Build from a slab/array index, erroring rather than truncating.
            #[inline]
            pub fn from_index(index: usize) -> Result<Self, DecisionMarketError> {
                <$repr>::try_from(index)
                    .map(Self)
                    .map_err(|_| DecisionMarketError::Truncation)
            }
        }
    };
}

define_index!(ActionId, u16, "Construct from a raw action index.");
define_index!(OutcomeId, u16, "Construct from a raw outcome index.");

impl InstrumentId {
    /// The raw flat instrument id.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Map an `(action, outcome)` pair to a flat [`InstrumentId`].
///
/// The mapping is `action * num_outcomes + outcome`, computed with checked u32
/// arithmetic. It is bijective over `outcome in 0..num_outcomes`.
pub fn instrument_id(
    action: ActionId,
    outcome: OutcomeId,
    num_outcomes: u16,
) -> Result<InstrumentId, DecisionMarketError> {
    if num_outcomes == 0 || outcome.get() >= num_outcomes {
        return Err(DecisionMarketError::UnknownOutcome);
    }
    let flat = u32::from(action.get())
        .checked_mul(u32::from(num_outcomes))
        .and_then(|base| base.checked_add(u32::from(outcome.get())))
        .ok_or(DecisionMarketError::Truncation)?;
    Ok(InstrumentId(flat))
}

/// Invert [`instrument_id`]: recover the `(action, outcome)` pair.
pub fn instrument_coords(
    id: InstrumentId,
    num_outcomes: u16,
) -> Result<(ActionId, OutcomeId), DecisionMarketError> {
    if num_outcomes == 0 {
        return Err(DecisionMarketError::UnknownOutcome);
    }
    let divisor = u32::from(num_outcomes);
    let action_raw = id.0 / divisor;
    let outcome_raw = id.0 % divisor;
    let action = u16::try_from(action_raw).map_err(|_| DecisionMarketError::Truncation)?;
    let outcome = u16::try_from(outcome_raw).map_err(|_| DecisionMarketError::Truncation)?;
    Ok((ActionId(action), OutcomeId(outcome)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_is_bijective_over_grid() {
        let num_outcomes = 7u16;
        let mut seen = std::collections::BTreeSet::new();
        for a in 0..11u16 {
            for o in 0..num_outcomes {
                let id = instrument_id(ActionId::new(a), OutcomeId::new(o), num_outcomes).unwrap();
                // Distinct.
                assert!(seen.insert(id.get()));
                // Invertible.
                let (ba, bo) = instrument_coords(id, num_outcomes).unwrap();
                assert_eq!((ba.get(), bo.get()), (a, o));
            }
        }
    }

    #[test]
    fn out_of_range_outcome_rejected() {
        assert_eq!(
            instrument_id(ActionId::new(0), OutcomeId::new(3), 3),
            Err(DecisionMarketError::UnknownOutcome)
        );
        assert_eq!(
            instrument_id(ActionId::new(0), OutcomeId::new(0), 0),
            Err(DecisionMarketError::UnknownOutcome)
        );
    }

    #[test]
    fn coords_never_panic_on_arbitrary_ids() {
        for raw in [0u32, 1, u32::MAX, 12345, 65_536] {
            for n in [1u16, 2, 256, u16::MAX] {
                let _ = instrument_coords(InstrumentId(raw), n);
            }
            let _ = instrument_coords(InstrumentId(raw), 0);
        }
    }
}
