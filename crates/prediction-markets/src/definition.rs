//! Immutable market definitions and resolution rules.
//!
//! A [`PredictionMarketDefinition`] binds a market's type, outcome set, and the
//! resolution rules — including an evidence-hash commitment, a challenge window,
//! and an optional threshold committee — that are fixed at creation time.

use serde::{Deserialize, Serialize};
use types::{Hash, MarketId, MarketType};

use crate::committee::Committee;
use crate::outcome::{OutcomeError, OutcomeSet};

/// Domain tag for hashing prediction-market resolution evidence.
pub const DOMAIN_RESOLUTION: &[u8] = b"dexos:prediction:resolution:v1";

/// Compute a domain-separated commitment over resolution evidence bytes.
///
/// Deterministic and total for arbitrary input. Used to bind a resolution to the
/// evidence that justified it without storing the evidence on-chain.
pub fn evidence_hash(evidence: &[u8]) -> Hash {
    crypto::hash_domain(DOMAIN_RESOLUTION, evidence)
}

/// A challenge window: resolution may be disputed until `duration` units after
/// `opened_at`. Times are opaque monotonic units (block heights or ticks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeWindow {
    /// The time the window opened.
    pub opened_at: u64,
    /// The window length in the same units as `opened_at`.
    pub duration: u64,
}

impl ChallengeWindow {
    /// A window opening at `opened_at` lasting `duration` units.
    #[inline]
    pub const fn new(opened_at: u64, duration: u64) -> Self {
        ChallengeWindow {
            opened_at,
            duration,
        }
    }

    /// The first time at which the window is considered elapsed (saturating).
    #[inline]
    pub const fn closes_at(&self) -> u64 {
        self.opened_at.saturating_add(self.duration)
    }

    /// Whether the window is still open (challenges accepted) at `now`.
    #[inline]
    pub const fn is_open(&self, now: u64) -> bool {
        now < self.closes_at()
    }

    /// Whether the window has elapsed (resolution may finalize) at `now`.
    #[inline]
    pub const fn is_elapsed(&self, now: u64) -> bool {
        now >= self.closes_at()
    }
}

/// Immutable rules governing how a market resolves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionRules {
    /// Commitment to the resolution criteria / source (see [`evidence_hash`]).
    pub criteria_hash: Hash,
    /// The dispute window applied once a resolution is proposed.
    pub challenge_window: ChallengeWindow,
    /// An optional k-of-n resolver committee; `None` for oracle/authority markets.
    pub committee: Option<Committee>,
}

impl ResolutionRules {
    /// Construct resolution rules.
    pub fn new(
        criteria_hash: Hash,
        challenge_window: ChallengeWindow,
        committee: Option<Committee>,
    ) -> Self {
        ResolutionRules {
            criteria_hash,
            challenge_window,
            committee,
        }
    }
}

/// An immutable prediction-market definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredictionMarketDefinition {
    /// The market's identifier.
    pub market_id: MarketId,
    /// The market kind (must be a prediction-style type).
    pub market_type: MarketType,
    /// The mutually-exclusive, exhaustive outcome set.
    pub outcomes: OutcomeSet,
    /// Immutable resolution rules.
    pub rules: ResolutionRules,
}

impl PredictionMarketDefinition {
    /// Construct and validate a definition. Enforces the binary two-outcome rule
    /// for [`MarketType::BinaryPrediction`].
    pub fn new(
        market_id: MarketId,
        market_type: MarketType,
        outcomes: OutcomeSet,
        rules: ResolutionRules,
    ) -> Result<Self, OutcomeError> {
        if matches!(market_type, MarketType::BinaryPrediction) {
            outcomes.require_binary()?;
        }
        Ok(PredictionMarketDefinition {
            market_id,
            market_type,
            outcomes,
            rules,
        })
    }

    /// The number of outcomes (complete-set size).
    #[inline]
    pub fn outcome_count(&self) -> usize {
        self.outcomes.len()
    }
}
