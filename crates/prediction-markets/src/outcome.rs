//! Outcome-set model: mutually-exclusive, exhaustive outcomes and the claim IDs
//! (YES / synthetic NO) that trade against a locked complete set.

use serde::{Deserialize, Serialize};
use types::MAX_OUTCOMES;

/// Stable label for one outcome of a market. Values are opaque; ordering within
/// an [`OutcomeSet`] is by insertion position, not by this label.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct OutcomeId(pub u16);

impl OutcomeId {
    /// Construct from a raw label.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        OutcomeId(raw)
    }

    /// The raw label.
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// The two economic sides of a claim over a single outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    /// Pays the outcome's payout fraction if that outcome (partly) wins.
    Yes,
    /// Synthetic complement: pays `1 - fraction(outcome)`; equivalent to holding a
    /// YES claim of every *other* outcome (the complete set minus this outcome).
    No,
}

/// A tradeable claim: a YES or synthetic-NO position over one outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClaimId {
    /// The outcome this claim references.
    pub outcome: OutcomeId,
    /// Whether this is the YES claim or the synthetic NO claim.
    pub kind: ClaimKind,
}

impl ClaimId {
    /// A YES claim over `outcome`.
    #[inline]
    pub const fn yes(outcome: OutcomeId) -> Self {
        ClaimId {
            outcome,
            kind: ClaimKind::Yes,
        }
    }

    /// A synthetic NO claim over `outcome`.
    #[inline]
    pub const fn no(outcome: OutcomeId) -> Self {
        ClaimId {
            outcome,
            kind: ClaimKind::No,
        }
    }
}

/// Outcome-set construction / lookup failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OutcomeError {
    /// Zero outcomes supplied.
    #[error("outcome set must have at least one outcome")]
    Empty,
    /// More than [`MAX_OUTCOMES`] outcomes supplied.
    #[error("outcome set exceeds the maximum of {MAX_OUTCOMES} outcomes")]
    TooMany,
    /// The same [`OutcomeId`] appeared twice.
    #[error("duplicate outcome id in set")]
    Duplicate,
    /// A binary market was given anything other than exactly two outcomes.
    #[error("binary market requires exactly two outcomes")]
    NotBinary,
    /// A referenced outcome is not a member of the set.
    #[error("unknown outcome id")]
    UnknownOutcome,
}

/// A set of mutually-exclusive, collectively-exhaustive outcomes.
///
/// Membership is unique; a complete set is one claim of every outcome. The set
/// order is the canonical settlement index order (position `0..len`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeSet {
    outcomes: Vec<OutcomeId>,
}

impl OutcomeSet {
    /// Build an outcome set, rejecting empty, over-large, and duplicate inputs.
    pub fn new(outcomes: Vec<OutcomeId>) -> Result<Self, OutcomeError> {
        if outcomes.is_empty() {
            return Err(OutcomeError::Empty);
        }
        if outcomes.len() > MAX_OUTCOMES {
            return Err(OutcomeError::TooMany);
        }
        for (i, a) in outcomes.iter().enumerate() {
            if outcomes[i + 1..].contains(a) {
                return Err(OutcomeError::Duplicate);
            }
        }
        Ok(Self { outcomes })
    }

    /// Build the canonical binary set `[OutcomeId(0), OutcomeId(1)]`.
    pub fn binary() -> Self {
        Self {
            outcomes: vec![OutcomeId(0), OutcomeId(1)],
        }
    }

    /// Build a set of `n` sequential outcomes `0..n`. Rejects `0` and `> MAX`.
    pub fn sequential(n: usize) -> Result<Self, OutcomeError> {
        if n == 0 {
            return Err(OutcomeError::Empty);
        }
        if n > MAX_OUTCOMES {
            return Err(OutcomeError::TooMany);
        }
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            // `n <= MAX_OUTCOMES` (256) so the index always fits in a u16.
            let label = u16::try_from(i).map_err(|_| OutcomeError::TooMany)?;
            v.push(OutcomeId(label));
        }
        Ok(Self { outcomes: v })
    }

    /// Validate the set against a binary market, requiring exactly two outcomes.
    pub fn require_binary(&self) -> Result<(), OutcomeError> {
        if self.outcomes.len() == 2 {
            Ok(())
        } else {
            Err(OutcomeError::NotBinary)
        }
    }

    /// The number of outcomes (== complete-set size).
    #[inline]
    pub fn len(&self) -> usize {
        self.outcomes.len()
    }

    /// Whether the set is empty (never true for a constructed set).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    /// The outcomes in canonical settlement order.
    #[inline]
    pub fn outcomes(&self) -> &[OutcomeId] {
        &self.outcomes
    }

    /// Whether `id` is a member.
    pub fn contains(&self, id: OutcomeId) -> bool {
        self.outcomes.contains(&id)
    }

    /// The settlement position (index) of `id`, or an error if absent.
    pub fn index_of(&self, id: OutcomeId) -> Result<usize, OutcomeError> {
        self.outcomes
            .iter()
            .position(|o| *o == id)
            .ok_or(OutcomeError::UnknownOutcome)
    }

    /// The complement of a synthetic NO claim over `outcome`: the deterministic
    /// list of YES claims for every *other* outcome. A NO claim is economically
    /// equivalent to holding exactly this basket.
    pub fn no_claim_complement(&self, outcome: OutcomeId) -> Result<Vec<ClaimId>, OutcomeError> {
        // Ensure the outcome is a member (deterministic error, not silent empty).
        self.index_of(outcome)?;
        Ok(self
            .outcomes
            .iter()
            .filter(|o| **o != outcome)
            .map(|o| ClaimId::yes(*o))
            .collect())
    }
}
