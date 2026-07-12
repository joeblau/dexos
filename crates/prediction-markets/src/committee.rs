//! Authenticated threshold (k-of-n) resolution committees.
//!
//! A committee is a fixed, epoch-tagged set of resolvers — each identified by an
//! ed25519 public key — together with a threshold `k`. A resolver authorizes a
//! resolution by signing a *domain-separated vote digest* that binds the
//! deployment, committee epoch, market/definition/rule commitment, resolution
//! round, expiry, claimed outcome, payout digest, and evidence hash. Because the
//! signed message is the digest of all of these fields, a vote can only ever
//! count toward the exact round and claim it was signed for.
//!
//! [`Committee::tally`] verifies each vote's signature against the member key it
//! names, rejects votes that do not bind the expected round (wrong deployment,
//! wrong market, wrong epoch, replayed or stale round number, mismatched
//! expiry), rejects rounds past their expiry, counts each distinct verified key
//! at most once, detects and exports equivocation (a member signing two
//! conflicting claims in one round), and accepts a claim only when at least `k`
//! distinct non-equivocating keys agree on the *same* outcome, payout digest,
//! and evidence hash. Tallying is total and deterministic; it never panics.
//!
//! Committee reconfiguration is bound to a finalized epoch transition via
//! [`Committee::reconfigure`]: the successor committee's epoch is strictly
//! greater than the predecessor's, and a committee only authorizes rounds bound
//! to its own epoch — so a threshold or membership change can never authorize an
//! in-flight round from a prior epoch.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crypto::{hash_domain, verify_ed25519, KeyPair};
use types::Hash;

use crate::outcome::OutcomeId;

/// Domain tag for a resolver vote digest.
pub const DOMAIN_RESOLVER_VOTE: &[u8] = b"dexos:prediction:resolver-vote:v1";

/// Domain tag for a canonical resolution-committee commitment.
pub const DOMAIN_RESOLVER_COMMITTEE: &[u8] = b"dexos:prediction:resolver-committee:v1";

/// Maximum number of resolvers in a committee.
///
/// Bounds allocation and the worst-case tally scan, and keeps the threshold (a
/// `u32`) representable as a member count.
pub const MAX_RESOLVERS: usize = 256;

/// Index of a resolver within its committee's membership (a 0-based slot).
///
/// This is a *position*, not an opaque label: `ResolverId(i)` names the member
/// whose public key is `Committee::resolvers()[i]`. Votes and equivocation
/// evidence reference members by this index; a vote only counts if its signature
/// verifies against the public key at that slot.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct ResolverId(pub u32);

/// Committee construction / reconfiguration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommitteeError {
    /// No resolvers were supplied.
    #[error("committee must have at least one resolver")]
    Empty,
    /// More than [`MAX_RESOLVERS`] resolvers were supplied.
    #[error("committee exceeds the maximum of {MAX_RESOLVERS} resolvers")]
    TooManyResolvers,
    /// The threshold was zero or larger than the resolver count.
    #[error("threshold must be in 1..=resolver_count")]
    BadThreshold,
    /// The same resolver public key appeared twice; one signer could otherwise
    /// be counted more than once toward the threshold.
    #[error("duplicate resolver public key")]
    DuplicateResolver,
    /// A reconfiguration did not strictly advance the committee epoch, so it
    /// could authorize an in-flight round of the current epoch.
    #[error("reconfiguration epoch must strictly exceed the current epoch")]
    StaleEpoch,
    /// A vote's signature did not verify against the named member key.
    #[error("invalid resolver signature")]
    InvalidSignature,
}

/// The round-level parameters every honest vote in a resolution round binds.
///
/// All fields are part of the signed vote digest, so a vote can never be
/// replayed into a different deployment, market, epoch, round, or expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionRound {
    /// Deployment / chain identifier this resolution belongs to.
    pub deployment: Hash,
    /// Epoch of the committee authorized to resolve this round.
    pub epoch: u64,
    /// Commitment to the market id, definition, and resolution rules.
    pub market_binding: Hash,
    /// Monotonic resolution-round number for this market.
    pub round: u64,
    /// Opaque time (block height / tick) at which this round can no longer be
    /// resolved. A vote whose round has reached `expiry` is not counted.
    pub expiry: u64,
}

/// The claim a resolver ratifies: the winning outcome together with commitments
/// to the full payout distribution and the supporting evidence.
///
/// Two votes count toward the same quorum only if their entire claim agrees, so
/// votes over different payout digests or evidence hashes can never combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResolutionClaim {
    /// The outcome the resolver believes won.
    pub outcome: OutcomeId,
    /// Commitment to the full payout vector / resolution.
    pub payout_digest: Hash,
    /// Commitment to the resolver's supporting evidence.
    pub evidence_hash: Hash,
}

/// A single resolver's authenticated vote for a resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverVote {
    /// The round this vote binds.
    pub round: ResolutionRound,
    /// The claim this vote ratifies.
    pub claim: ResolutionClaim,
    /// The committee slot of the resolver casting the vote.
    pub resolver: ResolverId,
    /// ed25519 signature over [`ResolverVote::digest`].
    #[serde(with = "sig64")]
    pub signature: [u8; 64],
}

impl ResolverVote {
    /// The canonical, domain-separated digest a resolver signs.
    ///
    /// Binds every round and claim field (but neither the resolver slot nor the
    /// signature), so distinct members ratifying the *same* round and claim sign
    /// the *same* digest — which is what lets the tally count distinct keys — and
    /// any change to a bound field yields a different digest.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut buf = Vec::with_capacity(32 + 8 + 32 + 8 + 8 + 2 + 32 + 32);
        buf.extend_from_slice(self.round.deployment.as_bytes());
        buf.extend_from_slice(&self.round.epoch.to_le_bytes());
        buf.extend_from_slice(self.round.market_binding.as_bytes());
        buf.extend_from_slice(&self.round.round.to_le_bytes());
        buf.extend_from_slice(&self.round.expiry.to_le_bytes());
        buf.extend_from_slice(&self.claim.outcome.get().to_le_bytes());
        buf.extend_from_slice(self.claim.payout_digest.as_bytes());
        buf.extend_from_slice(self.claim.evidence_hash.as_bytes());
        hash_domain(DOMAIN_RESOLVER_VOTE, &buf)
    }

    /// Verify this vote's signature against `public_key`.
    ///
    /// # Errors
    /// [`CommitteeError::InvalidSignature`] if the signature does not verify.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), CommitteeError> {
        verify_ed25519(public_key, self.digest().as_bytes(), &self.signature)
            .map_err(|_| CommitteeError::InvalidSignature)
    }

    /// Build a signed vote for `round`/`claim` from `resolver` using `signing_key`.
    ///
    /// The digest is independent of the signature field, so signing the
    /// zero-signature vote and then storing the signature yields a vote that
    /// verifies against `signing_key`'s public key.
    #[must_use]
    pub fn signed(
        round: ResolutionRound,
        claim: ResolutionClaim,
        resolver: ResolverId,
        signing_key: &KeyPair,
    ) -> Self {
        let mut vote = Self {
            round,
            claim,
            resolver,
            signature: [0u8; 64],
        };
        let digest = vote.digest();
        vote.signature = signing_key.sign(digest.as_bytes());
        vote
    }
}

/// Verifiable evidence that a resolver signed two conflicting claims in one round.
///
/// Both votes carry the same resolver and round but different claims, and each is
/// independently signature-checkable against the member key, so the evidence is
/// self-contained and exportable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equivocation {
    /// The offending resolver's committee slot.
    pub resolver: ResolverId,
    /// The first claim the resolver validly signed for the round.
    pub first: ResolverVote,
    /// The second, conflicting claim the resolver validly signed.
    pub second: ResolverVote,
}

/// The outcome of tallying committee votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitteeDecision {
    /// The threshold was reached for `claim` with `votes` agreeing distinct keys.
    Accepted {
        /// The ratified claim (outcome, payout digest, evidence hash).
        claim: ResolutionClaim,
        /// The number of agreeing distinct verified keys.
        votes: u32,
    },
    /// No claim reached the threshold; `leader_votes` is the best tally so far.
    Insufficient {
        /// The highest agreement count observed (0 if no valid votes).
        leader_votes: u32,
    },
}

/// A committee decision plus any equivocation evidence gathered while tallying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyOutcome {
    /// Whether the threshold was reached, and for what.
    pub decision: CommitteeDecision,
    /// Exportable evidence of any resolver that double-signed the round.
    pub equivocations: Vec<Equivocation>,
}

/// Per-member state accumulated during a single tally pass.
struct MemberState {
    /// Index into the input slice of the first valid vote this member cast.
    first_index: usize,
    /// The claim of that first vote.
    first_claim: ResolutionClaim,
    /// Whether this member has been observed signing a conflicting claim.
    equivocated: bool,
}

/// A k-of-n resolution committee for one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committee {
    epoch: u64,
    resolvers: Vec<[u8; 32]>,
    threshold: u32,
}

impl Committee {
    /// Construct a committee for `epoch`, validating non-empty, bounded, unique
    /// resolver keys and a threshold in `1..=n`.
    ///
    /// # Errors
    /// [`CommitteeError::Empty`], [`CommitteeError::TooManyResolvers`],
    /// [`CommitteeError::DuplicateResolver`], or [`CommitteeError::BadThreshold`].
    pub fn new(
        epoch: u64,
        resolvers: Vec<[u8; 32]>,
        threshold: u32,
    ) -> Result<Self, CommitteeError> {
        if resolvers.is_empty() {
            return Err(CommitteeError::Empty);
        }
        if resolvers.len() > MAX_RESOLVERS {
            return Err(CommitteeError::TooManyResolvers);
        }
        for (i, k) in resolvers.iter().enumerate() {
            if resolvers[i + 1..].contains(k) {
                return Err(CommitteeError::DuplicateResolver);
            }
        }
        let n = u32::try_from(resolvers.len()).map_err(|_| CommitteeError::BadThreshold)?;
        if threshold == 0 || threshold > n {
            return Err(CommitteeError::BadThreshold);
        }
        Ok(Self {
            epoch,
            resolvers,
            threshold,
        })
    }

    /// Produce the successor committee for a finalized epoch transition.
    ///
    /// `new_epoch` must strictly exceed the current epoch, so votes bound to any
    /// prior (possibly in-flight) round can never authorize a decision under the
    /// new membership or threshold. The new membership is validated exactly as in
    /// [`Committee::new`].
    ///
    /// # Errors
    /// [`CommitteeError::StaleEpoch`] if `new_epoch <= self.epoch()`, or any error
    /// from [`Committee::new`].
    pub fn reconfigure(
        &self,
        new_epoch: u64,
        resolvers: Vec<[u8; 32]>,
        threshold: u32,
    ) -> Result<Self, CommitteeError> {
        if new_epoch <= self.epoch {
            return Err(CommitteeError::StaleEpoch);
        }
        Self::new(new_epoch, resolvers, threshold)
    }

    /// The committee epoch.
    #[inline]
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The registered resolver public keys, in slot order.
    #[inline]
    #[must_use]
    pub fn resolvers(&self) -> &[[u8; 32]] {
        &self.resolvers
    }

    /// The agreement threshold `k`.
    #[inline]
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The resolver count `n`.
    #[inline]
    #[must_use]
    pub fn size(&self) -> usize {
        self.resolvers.len()
    }

    /// The public key at slot `resolver`, or `None` if the slot is out of range.
    #[must_use]
    pub fn public_key(&self, resolver: ResolverId) -> Option<[u8; 32]> {
        let i = usize::try_from(resolver.0).ok()?;
        self.resolvers.get(i).copied()
    }

    /// The slot of `public_key` if it is a registered member.
    #[must_use]
    pub fn index_of(&self, public_key: &[u8; 32]) -> Option<ResolverId> {
        self.resolvers
            .iter()
            .position(|k| k == public_key)
            .and_then(|i| u32::try_from(i).ok())
            .map(ResolverId)
    }

    /// Whether `public_key` is a registered member.
    #[must_use]
    pub fn is_member(&self, public_key: &[u8; 32]) -> bool {
        self.resolvers.contains(public_key)
    }

    /// A canonical, domain-separated commitment to this committee's epoch,
    /// membership, and threshold.
    ///
    /// Members are hashed in sorted key order, so two committees with the same
    /// epoch, members, and threshold in any construction order commit to the same
    /// hash, while any change to the epoch, a key, the membership, or the
    /// threshold changes it. Callers fold this into a market's `market_binding`
    /// so a resolution is bound to the exact committee configuration.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut ordered: Vec<&[u8; 32]> = self.resolvers.iter().collect();
        ordered.sort_unstable();
        let count = u32::try_from(ordered.len()).unwrap_or(u32::MAX);
        let mut buf = Vec::with_capacity(8 + 4 + 4 + ordered.len() * 32);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.threshold.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());
        for k in ordered {
            buf.extend_from_slice(k);
        }
        hash_domain(DOMAIN_RESOLVER_COMMITTEE, &buf)
    }

    /// Tally `votes` for the expected `round` at time `now` and decide.
    ///
    /// A vote is counted only if it (1) binds exactly `round` (rejecting wrong
    /// deployment, wrong market, wrong epoch, replayed or stale round number, and
    /// mismatched expiry), (2) names a real member slot, and (3) carries a
    /// signature that verifies against that member's key. A member's first valid
    /// vote counts once toward its claim; a later identical vote is a harmless
    /// duplicate; a later *conflicting* claim marks the member as an equivocator,
    /// exports [`Equivocation`] evidence, and removes the member from the tally
    /// entirely (so an equivocator can push no claim over the line).
    ///
    /// The committee only authorizes rounds bound to its own epoch, and a round
    /// at or past its expiry can no longer be resolved. Total and deterministic:
    /// identical inputs always produce bit-identical output, and it never panics.
    #[must_use]
    pub fn tally(&self, round: &ResolutionRound, now: u64, votes: &[ResolverVote]) -> TallyOutcome {
        let mut equivocations: Vec<Equivocation> = Vec::new();

        // A committee only authorizes rounds bound to its own epoch. After a
        // finalized reconfiguration, votes bound to a prior epoch's round can
        // never be counted here.
        if round.epoch != self.epoch {
            return TallyOutcome {
                decision: CommitteeDecision::Insufficient { leader_votes: 0 },
                equivocations,
            };
        }
        // A round that has reached its expiry can no longer be resolved.
        if now >= round.expiry {
            return TallyOutcome {
                decision: CommitteeDecision::Insufficient { leader_votes: 0 },
                equivocations,
            };
        }

        // Per-member state, keyed by slot index (ascending for determinism).
        let mut members: BTreeMap<u32, MemberState> = BTreeMap::new();
        for (i, v) in votes.iter().enumerate() {
            // Exact round binding: rejects wrong deployment/market/epoch, a
            // replayed or stale round number, and a mismatched expiry.
            if v.round != *round {
                continue;
            }
            // Membership: the slot must name a real member.
            let Some(public_key) = self.public_key(v.resolver) else {
                continue;
            };
            // Authentication: the signature must verify against the member key.
            if verify_ed25519(&public_key, v.digest().as_bytes(), &v.signature).is_err() {
                continue;
            }
            match members.get_mut(&v.resolver.0) {
                None => {
                    members.insert(
                        v.resolver.0,
                        MemberState {
                            first_index: i,
                            first_claim: v.claim,
                            equivocated: false,
                        },
                    );
                }
                Some(state) => {
                    if state.first_claim != v.claim && !state.equivocated {
                        state.equivocated = true;
                        equivocations.push(Equivocation {
                            resolver: v.resolver,
                            first: votes[state.first_index].clone(),
                            second: v.clone(),
                        });
                    }
                    // A same-claim repeat is a duplicate; a conflicting one is
                    // equivocation. Neither is ever counted a second time.
                }
            }
        }

        // Count distinct, non-equivocating keys per claim. Equivocators are
        // excluded entirely so they can contribute to no claim.
        let mut tally: BTreeMap<ResolutionClaim, u32> = BTreeMap::new();
        for state in members.values() {
            if state.equivocated {
                continue;
            }
            let counter = tally.entry(state.first_claim).or_insert(0);
            *counter = counter.saturating_add(1);
        }

        // Deterministic leader: highest count, ties broken by the smallest claim
        // (the BTreeMap iterates claims in ascending order, and only a strictly
        // greater count replaces the incumbent).
        let mut leader: Option<(ResolutionClaim, u32)> = None;
        for (claim, count) in &tally {
            match leader {
                Some((_, best)) if *count <= best => {}
                _ => leader = Some((*claim, *count)),
            }
        }

        let decision = match leader {
            Some((claim, count)) if count >= self.threshold => CommitteeDecision::Accepted {
                claim,
                votes: count,
            },
            Some((_, leader_votes)) => CommitteeDecision::Insufficient { leader_votes },
            None => CommitteeDecision::Insufficient { leader_votes: 0 },
        };
        TallyOutcome {
            decision,
            equivocations,
        }
    }
}

/// serde adapter for `[u8; 64]` signatures (serde's built-in array impls stop at
/// 32 bytes). Mirrors `crypto::quorum` and `consensus::sig64`: encode as a byte
/// sequence, decode back into a fixed array.
mod sig64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        v.as_slice().serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        <[u8; 64]>::try_from(v.as_slice())
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyPair;

    fn key(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32])
    }

    /// A committee of `n` deterministic members with threshold `k`, plus their
    /// signing keys in slot order.
    fn committee(n: u8, k: u32) -> (Committee, Vec<KeyPair>) {
        let keys: Vec<KeyPair> = (0..n).map(key).collect();
        let members: Vec<[u8; 32]> = keys.iter().map(KeyPair::public).collect();
        (Committee::new(0, members, k).unwrap(), keys)
    }

    fn round(epoch: u64, round: u64, expiry: u64) -> ResolutionRound {
        ResolutionRound {
            deployment: Hash::from_bytes([0xDE; 32]),
            epoch,
            market_binding: Hash::from_bytes([0xAB; 32]),
            round,
            expiry,
        }
    }

    fn claim(outcome: u16, ev: u8) -> ResolutionClaim {
        ResolutionClaim {
            outcome: OutcomeId(outcome),
            payout_digest: Hash::from_bytes([ev.wrapping_add(1); 32]),
            evidence_hash: Hash::from_bytes([ev; 32]),
        }
    }

    #[test]
    fn construction_rejects_empty_duplicate_bounds_and_bad_threshold() {
        assert_eq!(Committee::new(0, vec![], 1), Err(CommitteeError::Empty));
        assert_eq!(
            Committee::new(0, vec![[1u8; 32], [1u8; 32]], 1),
            Err(CommitteeError::DuplicateResolver)
        );
        assert_eq!(
            Committee::new(0, vec![[1u8; 32]], 2),
            Err(CommitteeError::BadThreshold)
        );
        assert_eq!(
            Committee::new(0, vec![[1u8; 32]], 0),
            Err(CommitteeError::BadThreshold)
        );
        let too_many: Vec<[u8; 32]> = (0..=MAX_RESOLVERS)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..8].copy_from_slice(&u64::try_from(i).unwrap().to_le_bytes());
                k
            })
            .collect();
        assert_eq!(
            Committee::new(0, too_many, 1),
            Err(CommitteeError::TooManyResolvers)
        );
    }

    #[test]
    fn accepts_at_threshold_and_rejects_below() {
        let (c, keys) = committee(3, 2);
        let r = round(0, 1, 100);
        let cl = claim(1, 0xAA);
        // Two of three agree -> accepted.
        let votes = vec![
            ResolverVote::signed(r, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(r, cl, ResolverId(1), &keys[1]),
            ResolverVote::signed(r, claim(0, 0xBB), ResolverId(2), &keys[2]),
        ];
        let out = c.tally(&r, 0, &votes);
        assert_eq!(
            out.decision,
            CommitteeDecision::Accepted {
                claim: cl,
                votes: 2
            }
        );
        assert!(out.equivocations.is_empty());

        // Only one agrees -> insufficient.
        let votes = vec![
            ResolverVote::signed(r, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(r, claim(0, 0xBB), ResolverId(1), &keys[1]),
        ];
        assert_eq!(
            c.tally(&r, 0, &votes).decision,
            CommitteeDecision::Insufficient { leader_votes: 1 }
        );
    }

    #[test]
    fn unsigned_and_forged_votes_reject() {
        let (c, keys) = committee(3, 2);
        let r = round(0, 1, 100);
        let cl = claim(1, 0xAA);

        // Unsigned (zero signature) does not verify.
        let unsigned = ResolverVote {
            round: r,
            claim: cl,
            resolver: ResolverId(0),
            signature: [0u8; 64],
        };
        // Forged: a valid signature by key 0 but attributed to slot 1 (key 1).
        let mut forged = ResolverVote::signed(r, cl, ResolverId(0), &keys[0]);
        forged.resolver = ResolverId(1);
        // A genuine second vote so the honest count would be 1 either way.
        let honest = ResolverVote::signed(r, cl, ResolverId(2), &keys[2]);

        let out = c.tally(&r, 0, &[unsigned, forged, honest]);
        assert_eq!(
            out.decision,
            CommitteeDecision::Insufficient { leader_votes: 1 }
        );
    }

    #[test]
    fn wrong_market_and_wrong_deployment_reject() {
        let (c, keys) = committee(3, 2);
        let r = round(0, 1, 100);
        let cl = claim(1, 0xAA);
        // Both votes are signed over a *different* market binding.
        let mut other_market = r;
        other_market.market_binding = Hash::from_bytes([0x99; 32]);
        let mut other_deploy = r;
        other_deploy.deployment = Hash::from_bytes([0x11; 32]);
        let votes = vec![
            ResolverVote::signed(other_market, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(other_deploy, cl, ResolverId(1), &keys[1]),
        ];
        // Expected round `r` matches neither -> nothing counts.
        assert_eq!(
            c.tally(&r, 0, &votes).decision,
            CommitteeDecision::Insufficient { leader_votes: 0 }
        );
    }

    #[test]
    fn replayed_and_stale_round_reject() {
        let (c, keys) = committee(3, 2);
        let cl = claim(1, 0xAA);
        // Votes signed for round 1 replayed while resolving round 2.
        let r1 = round(0, 1, 100);
        let r2 = round(0, 2, 100);
        let replayed = vec![
            ResolverVote::signed(r1, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(r1, cl, ResolverId(1), &keys[1]),
        ];
        assert_eq!(
            c.tally(&r2, 0, &replayed).decision,
            CommitteeDecision::Insufficient { leader_votes: 0 }
        );

        // A round tallied at or past its expiry cannot resolve, even at quorum.
        let quorum = vec![
            ResolverVote::signed(r1, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(r1, cl, ResolverId(1), &keys[1]),
        ];
        assert_eq!(
            c.tally(&r1, 100, &quorum).decision,
            CommitteeDecision::Insufficient { leader_votes: 0 }
        );
        // One tick before expiry still resolves.
        assert_eq!(
            c.tally(&r1, 99, &quorum).decision,
            CommitteeDecision::Accepted {
                claim: cl,
                votes: 2
            }
        );
    }

    #[test]
    fn different_evidence_or_payout_cannot_form_one_quorum() {
        let (c, keys) = committee(4, 3);
        let r = round(0, 1, 100);
        let win = OutcomeId(1);
        // Four resolvers, same winning outcome, but split across two distinct
        // evidence/payout digests: 2 vs 2. Neither reaches the 3-key threshold.
        let ev_a = ResolutionClaim {
            outcome: win,
            payout_digest: Hash::from_bytes([1u8; 32]),
            evidence_hash: Hash::from_bytes([2u8; 32]),
        };
        let ev_b = ResolutionClaim {
            outcome: win,
            payout_digest: Hash::from_bytes([3u8; 32]),
            evidence_hash: Hash::from_bytes([4u8; 32]),
        };
        let votes = vec![
            ResolverVote::signed(r, ev_a, ResolverId(0), &keys[0]),
            ResolverVote::signed(r, ev_a, ResolverId(1), &keys[1]),
            ResolverVote::signed(r, ev_b, ResolverId(2), &keys[2]),
            ResolverVote::signed(r, ev_b, ResolverId(3), &keys[3]),
        ];
        assert_eq!(
            c.tally(&r, 0, &votes).decision,
            CommitteeDecision::Insufficient { leader_votes: 2 }
        );
    }

    #[test]
    fn duplicate_signers_count_once() {
        let (c, keys) = committee(3, 2);
        let r = round(0, 1, 100);
        let cl = claim(1, 0xAA);
        // Resolver 0 votes three times (identical); resolver 2 votes once.
        let votes = vec![
            ResolverVote::signed(r, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(r, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(r, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(r, cl, ResolverId(2), &keys[2]),
        ];
        // Two distinct keys -> exactly at threshold, no equivocation.
        let out = c.tally(&r, 0, &votes);
        assert_eq!(
            out.decision,
            CommitteeDecision::Accepted {
                claim: cl,
                votes: 2
            }
        );
        assert!(out.equivocations.is_empty());
    }

    #[test]
    fn equivocation_is_detected_excluded_and_exportable() {
        let (c, keys) = committee(3, 2);
        let r = round(0, 1, 100);
        let cl_a = claim(1, 0xAA);
        let cl_b = claim(0, 0xBB);
        // Resolver 0 double-signs two conflicting claims; resolver 1 votes A once.
        let votes = vec![
            ResolverVote::signed(r, cl_a, ResolverId(0), &keys[0]),
            ResolverVote::signed(r, cl_b, ResolverId(0), &keys[0]),
            ResolverVote::signed(r, cl_a, ResolverId(1), &keys[1]),
        ];
        let out = c.tally(&r, 0, &votes);
        // The equivocator is excluded entirely, so claim A has only 1 key: below
        // the threshold of 2.
        assert_eq!(
            out.decision,
            CommitteeDecision::Insufficient { leader_votes: 1 }
        );
        assert_eq!(out.equivocations.len(), 1);
        let ev = &out.equivocations[0];
        assert_eq!(ev.resolver, ResolverId(0));
        assert_eq!(ev.first.claim, cl_a);
        assert_eq!(ev.second.claim, cl_b);
        // The evidence is independently verifiable against the member key.
        let pk = c.public_key(ResolverId(0)).unwrap();
        assert!(ev.first.verify(&pk).is_ok());
        assert!(ev.second.verify(&pk).is_ok());
        // ...and exportable (byte-identical round trip).
        let bytes = postcard::to_allocvec(&out).unwrap();
        let back: TallyOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(out, back);
        assert_eq!(bytes, postcard::to_allocvec(&back).unwrap());
    }

    #[test]
    fn reconfiguration_requires_strictly_greater_epoch() {
        let (c, keys) = committee(3, 2);
        let members: Vec<[u8; 32]> = keys.iter().map(KeyPair::public).collect();
        assert_eq!(
            c.reconfigure(0, members.clone(), 2),
            Err(CommitteeError::StaleEpoch)
        );
        assert!(c.reconfigure(1, members, 3).is_ok());
    }

    #[test]
    fn membership_or_threshold_change_cannot_authorize_old_round() {
        // Old committee, epoch 0, 3 members, threshold 2.
        let (old, keys) = committee(3, 2);
        let old_round = round(0, 7, 100);
        let cl = claim(1, 0xAA);
        // A genuine 2-of-3 quorum for the in-flight epoch-0 round.
        let old_votes = vec![
            ResolverVote::signed(old_round, cl, ResolverId(0), &keys[0]),
            ResolverVote::signed(old_round, cl, ResolverId(1), &keys[1]),
        ];
        // The old committee still resolves its own in-flight round.
        assert_eq!(
            old.tally(&old_round, 0, &old_votes).decision,
            CommitteeDecision::Accepted {
                claim: cl,
                votes: 2
            }
        );

        // Reconfigure to epoch 1, raising the threshold to 3 (same members).
        let members: Vec<[u8; 32]> = keys.iter().map(KeyPair::public).collect();
        let new = old.reconfigure(1, members, 3).unwrap();

        // The new committee cannot ratify the old (epoch-0) round: its epoch
        // differs, so nothing counts.
        assert_eq!(
            new.tally(&old_round, 0, &old_votes).decision,
            CommitteeDecision::Insufficient { leader_votes: 0 }
        );
        // Nor can the old votes be re-presented as an epoch-1 round: they bind
        // epoch 0, so they do not match the expected round.
        let forged_round = round(1, 7, 100);
        assert_eq!(
            new.tally(&forged_round, 0, &old_votes).decision,
            CommitteeDecision::Insufficient { leader_votes: 0 }
        );
    }

    #[test]
    fn commitment_binds_epoch_membership_and_threshold_and_is_order_invariant() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let cc = [3u8; 32];
        let base = Committee::new(0, vec![a, b, cc], 2).unwrap();
        let shuffled = Committee::new(0, vec![cc, a, b], 2).unwrap();
        // Same epoch, members, threshold in any order -> identical commitment.
        assert_eq!(base.commitment(), shuffled.commitment());
        // Epoch, threshold, and membership each change the commitment.
        assert_ne!(
            base.commitment(),
            Committee::new(1, vec![a, b, cc], 2).unwrap().commitment()
        );
        assert_ne!(
            base.commitment(),
            Committee::new(0, vec![a, b, cc], 3).unwrap().commitment()
        );
        assert_ne!(
            base.commitment(),
            Committee::new(0, vec![a, b, [9u8; 32]], 2)
                .unwrap()
                .commitment()
        );
    }

    #[test]
    fn tally_never_panics_on_arbitrary_bytes() {
        let (c, _keys) = committee(3, 2);
        let r = round(0, 1, 100);
        let mut state = 0x1234_5678u64;
        for _ in 0..20_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut sig = [0u8; 64];
            sig[0] = state.to_le_bytes()[0];
            sig[1] = state.to_le_bytes()[1];
            let v = ResolverVote {
                round: r,
                claim: claim(u16::try_from(state % 4).unwrap(), state.to_le_bytes()[2]),
                resolver: ResolverId(u32::try_from(state % 8).unwrap()),
                signature: sig,
            };
            // Total: returns a decision for any input, never panics.
            let _ = c.tally(&r, state % 200, &[v]);
        }
    }
}
