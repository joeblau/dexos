//! Threshold (k-of-n) resolution committees.
//!
//! A committee is a fixed set of resolvers and a threshold `k`. Each resolver
//! may cast at most one vote for a winning [`OutcomeId`] with an evidence hash.
//! When at least `k` registered resolvers agree on the same outcome, the
//! committee decision is [`CommitteeDecision::Accepted`]. Tallying is total and
//! deterministic; it never panics.

use serde::{Deserialize, Serialize};
use types::Hash;

use crate::outcome::OutcomeId;

/// Identity of a resolution committee member.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct ResolverId(pub u32);

/// Committee construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommitteeError {
    /// No resolvers were supplied.
    #[error("committee must have at least one resolver")]
    Empty,
    /// The threshold was zero or larger than the resolver count.
    #[error("threshold must be in 1..=resolver_count")]
    BadThreshold,
    /// The same resolver id appeared twice.
    #[error("duplicate resolver id")]
    DuplicateResolver,
}

/// A single resolver's vote for the winning outcome, with an evidence hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverVote {
    /// The resolver casting the vote.
    pub resolver: ResolverId,
    /// The outcome the resolver believes won.
    pub outcome: OutcomeId,
    /// A commitment to the resolver's supporting evidence.
    pub evidence_hash: Hash,
}

/// The outcome of tallying committee votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitteeDecision {
    /// The threshold was reached for `outcome` with `votes` agreeing resolvers.
    Accepted {
        /// The winning outcome.
        outcome: OutcomeId,
        /// The number of agreeing registered resolvers.
        votes: u32,
    },
    /// No outcome reached the threshold; `leader_votes` is the best tally so far.
    Insufficient {
        /// The highest agreement count observed (0 if no valid votes).
        leader_votes: u32,
    },
}

/// A k-of-n resolution committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committee {
    resolvers: Vec<ResolverId>,
    threshold: u32,
}

impl Committee {
    /// Construct a committee, validating non-empty, unique resolvers and a
    /// threshold in `1..=n`.
    pub fn new(resolvers: Vec<ResolverId>, threshold: u32) -> Result<Self, CommitteeError> {
        if resolvers.is_empty() {
            return Err(CommitteeError::Empty);
        }
        for (i, r) in resolvers.iter().enumerate() {
            if resolvers[i + 1..].contains(r) {
                return Err(CommitteeError::DuplicateResolver);
            }
        }
        let n = u32::try_from(resolvers.len()).map_err(|_| CommitteeError::BadThreshold)?;
        if threshold == 0 || threshold > n {
            return Err(CommitteeError::BadThreshold);
        }
        Ok(Self {
            resolvers,
            threshold,
        })
    }

    /// The registered resolvers.
    #[inline]
    pub fn resolvers(&self) -> &[ResolverId] {
        &self.resolvers
    }

    /// The agreement threshold `k`.
    #[inline]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The resolver count `n`.
    #[inline]
    pub fn size(&self) -> usize {
        self.resolvers.len()
    }

    /// Whether `resolver` is a registered member.
    pub fn is_member(&self, resolver: ResolverId) -> bool {
        self.resolvers.contains(&resolver)
    }

    /// Tally `votes` and decide. Votes from non-members are ignored; a resolver
    /// that votes more than once is counted at most once (its first vote, in
    /// input order). Total and deterministic.
    pub fn tally(&self, votes: &[ResolverVote]) -> CommitteeDecision {
        // Bounded by the committee size; each resolver contributes at most once.
        let mut counted: Vec<ResolverId> = Vec::with_capacity(self.resolvers.len());
        // (outcome, count) tallies; small N so a linear scan is fine.
        let mut tallies: Vec<(OutcomeId, u32)> = Vec::new();
        for v in votes {
            if !self.is_member(v.resolver) {
                continue;
            }
            if counted.contains(&v.resolver) {
                continue;
            }
            counted.push(v.resolver);
            if let Some(entry) = tallies.iter_mut().find(|(o, _)| *o == v.outcome) {
                entry.1 = entry.1.saturating_add(1);
            } else {
                tallies.push((v.outcome, 1));
            }
        }
        // Deterministic leader: highest count, tie-break by lowest OutcomeId.
        let mut leader: Option<(OutcomeId, u32)> = None;
        for (outcome, count) in &tallies {
            match leader {
                None => leader = Some((*outcome, *count)),
                Some((lo, lc)) => {
                    if *count > lc || (*count == lc && outcome.get() < lo.get()) {
                        leader = Some((*outcome, *count));
                    }
                }
            }
        }
        match leader {
            Some((outcome, votes)) if votes >= self.threshold => {
                CommitteeDecision::Accepted { outcome, votes }
            }
            Some((_, leader_votes)) => CommitteeDecision::Insufficient { leader_votes },
            None => CommitteeDecision::Insufficient { leader_votes: 0 },
        }
    }
}
