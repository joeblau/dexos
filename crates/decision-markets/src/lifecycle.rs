//! Validated decision-market lifecycle.
//!
//! A decision market walks a fixed state machine:
//!
//! ```text
//! Draft ─▶ Trading ─▶ DecisionLocked ─▶ ActionSelected ─▶ Evaluating ─▶ Resolved ─▶ Settled
//!                          │
//!                          └▶ Invalid ─▶ Settled   (guards failed / market voided)
//! ```
//!
//! Every transition is checked; illegal transitions return
//! [`DecisionMarketError::IllegalTransition`] rather than panicking. There is no
//! floating point in this module.

use serde::{Deserialize, Serialize};

use crate::error::DecisionMarketError;

/// A phase in the decision-market lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionPhase {
    /// Created but not yet open for trading.
    Draft,
    /// Open for trading; complete sets may be minted/redeemed/traded.
    Trading,
    /// Trading frozen; time-weighted decision prices are being finalized.
    DecisionLocked,
    /// The winning action has been selected (auto or externally confirmed).
    ActionSelected,
    /// The realized outcome for the selected action is being determined.
    Evaluating,
    /// The realized outcome is known; payouts can be computed.
    Resolved,
    /// Collateral has been distributed; the market is terminal.
    Settled,
    /// A guard failed (thin liquidity / concentration); market is voided.
    Invalid,
}

impl DecisionPhase {
    /// A stable single-byte discriminant used for deterministic state hashing.
    #[inline]
    pub const fn discriminant(self) -> u8 {
        match self {
            DecisionPhase::Draft => 0,
            DecisionPhase::Trading => 1,
            DecisionPhase::DecisionLocked => 2,
            DecisionPhase::ActionSelected => 3,
            DecisionPhase::Evaluating => 4,
            DecisionPhase::Resolved => 5,
            DecisionPhase::Settled => 6,
            DecisionPhase::Invalid => 7,
        }
    }

    /// Whether `self -> to` is a legal transition.
    #[inline]
    pub const fn can_transition(self, to: DecisionPhase) -> bool {
        matches!(
            (self, to),
            (DecisionPhase::Draft, DecisionPhase::Trading)
                | (DecisionPhase::Trading, DecisionPhase::DecisionLocked)
                | (DecisionPhase::Trading, DecisionPhase::Invalid)
                | (DecisionPhase::DecisionLocked, DecisionPhase::ActionSelected)
                | (DecisionPhase::DecisionLocked, DecisionPhase::Invalid)
                | (DecisionPhase::ActionSelected, DecisionPhase::Evaluating)
                | (DecisionPhase::Evaluating, DecisionPhase::Resolved)
                | (DecisionPhase::Resolved, DecisionPhase::Settled)
                | (DecisionPhase::Invalid, DecisionPhase::Settled)
        )
    }

    /// Attempt a transition, returning the new phase or an error.
    #[inline]
    pub fn transition(self, to: DecisionPhase) -> Result<DecisionPhase, DecisionMarketError> {
        if self.can_transition(to) {
            Ok(to)
        } else {
            Err(DecisionMarketError::IllegalTransition { from: self, to })
        }
    }

    /// Whether this phase is terminal (no outgoing transitions except into it).
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, DecisionPhase::Settled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [DecisionPhase; 8] = [
        DecisionPhase::Draft,
        DecisionPhase::Trading,
        DecisionPhase::DecisionLocked,
        DecisionPhase::ActionSelected,
        DecisionPhase::Evaluating,
        DecisionPhase::Resolved,
        DecisionPhase::Settled,
        DecisionPhase::Invalid,
    ];

    const LEGAL: [(DecisionPhase, DecisionPhase); 9] = [
        (DecisionPhase::Draft, DecisionPhase::Trading),
        (DecisionPhase::Trading, DecisionPhase::DecisionLocked),
        (DecisionPhase::Trading, DecisionPhase::Invalid),
        (DecisionPhase::DecisionLocked, DecisionPhase::ActionSelected),
        (DecisionPhase::DecisionLocked, DecisionPhase::Invalid),
        (DecisionPhase::ActionSelected, DecisionPhase::Evaluating),
        (DecisionPhase::Evaluating, DecisionPhase::Resolved),
        (DecisionPhase::Resolved, DecisionPhase::Settled),
        (DecisionPhase::Invalid, DecisionPhase::Settled),
    ];

    #[test]
    fn every_legal_transition_is_accepted() {
        for (from, to) in LEGAL {
            assert_eq!(from.transition(to), Ok(to));
            assert!(from.can_transition(to));
        }
    }

    #[test]
    fn every_illegal_transition_is_rejected_without_panic() {
        for from in ALL {
            for to in ALL {
                let legal = LEGAL.contains(&(from, to));
                assert_eq!(from.can_transition(to), legal);
                match from.transition(to) {
                    Ok(p) => assert!(legal && p == to),
                    Err(DecisionMarketError::IllegalTransition { from: f, to: t }) => {
                        assert!(!legal);
                        assert_eq!((f, t), (from, to));
                    }
                    Err(other) => panic!("unexpected error: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn discriminants_are_distinct() {
        for (i, a) in ALL.iter().enumerate() {
            for b in &ALL[i + 1..] {
                assert_ne!(a.discriminant(), b.discriminant());
            }
        }
    }
}
