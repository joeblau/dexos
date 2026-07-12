//! HotStuff-style votes, committees, and Byzantine quorum-certificate formation.
//!
//! A [`Vote`] is a validator's signature over a domain-separated *vote digest*
//! that binds `(epoch, view, height, phase, block_hash)`. Because the signed
//! message is the digest itself, a formed [`QuorumCertificate`] verifies
//! directly against a [`crypto::ValidatorSet`].
//!
//! A [`VoteCollector`] deduplicates signers, rejects foreign / malformed votes,
//! detects equivocation (two different blocks voted by the same validator in the
//! same round+phase), and forms a QC once `>= threshold` weight is present.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crypto::{hash_domain, verify_ed25519, QuorumCertificate, Validator, ValidatorSet};
use types::Hash;

/// Domain tag for vote digests.
pub const DOMAIN_VOTE: &[u8] = b"dexos:consensus:vote:v1";

/// Domain tag for timeout (view-change) digests.
pub const DOMAIN_TIMEOUT: &[u8] = b"dexos:consensus:timeout:v1";

/// Maximum committee size — bounded by the 64-bit signer bitmap of a
/// [`QuorumCertificate`] (bit `i` names validator index `i`).
///
/// This is the operational ceiling for HotStuff committees and must stay in
/// lockstep with [`crypto::MAX_VALIDATORS`]: a larger set cannot be encoded in
/// the QC bitmap and is rejected at committee construction.
pub const MAX_VALIDATORS: usize = 64;

/// A pipelined HotStuff voting phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VotePhase {
    /// Prepare phase.
    Prepare,
    /// Pre-commit phase.
    PreCommit,
    /// Commit phase.
    Commit,
}

impl VotePhase {
    /// Stable one-byte tag used inside the vote digest (avoids `as` casts).
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            VotePhase::Prepare => 0,
            VotePhase::PreCommit => 1,
            VotePhase::Commit => 2,
        }
    }
}

/// The canonical, domain-separated digest a validator signs for a vote.
#[must_use]
pub fn vote_digest(epoch: u64, view: u64, height: u64, phase: VotePhase, block_hash: Hash) -> Hash {
    let mut buf = Vec::with_capacity(8 * 3 + 1 + 32);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.push(phase.tag());
    buf.extend_from_slice(block_hash.as_bytes());
    hash_domain(DOMAIN_VOTE, &buf)
}

/// A single validator vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// Epoch of the validator set that produced this vote.
    pub epoch: u64,
    /// Leader view.
    pub view: u64,
    /// Pipeline height being voted on.
    pub height: u64,
    /// Voting phase.
    pub phase: VotePhase,
    /// The block / batch commitment being voted for.
    pub block_hash: Hash,
    /// Index of the signing validator within its committee.
    pub validator_index: u32,
    /// ed25519 signature over [`Vote::digest`].
    #[serde(with = "crate::sig64")]
    pub signature: [u8; 64],
}

impl Vote {
    /// The digest this vote signs.
    #[must_use]
    pub fn digest(&self) -> Hash {
        vote_digest(
            self.epoch,
            self.view,
            self.height,
            self.phase,
            self.block_hash,
        )
    }

    /// The round+phase identity used for equivocation detection.
    #[must_use]
    pub fn round_key(&self) -> (u32, u64, u64, u64, u8) {
        (
            self.validator_index,
            self.epoch,
            self.view,
            self.height,
            self.phase.tag(),
        )
    }

    /// Verify this vote's signature against `public_key`.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), VoteError> {
        verify_ed25519(public_key, self.digest().as_bytes(), &self.signature)
            .map_err(|_| VoteError::InvalidSignature)
    }
}

/// Verifiable evidence that a validator double-signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equivocation {
    /// The offending validator index.
    pub validator_index: u32,
    /// Epoch of the round.
    pub epoch: u64,
    /// View of the round.
    pub view: u64,
    /// Height of the round.
    pub height: u64,
    /// Phase of the round.
    pub phase: VotePhase,
    /// First block the validator voted for.
    pub first_block: Hash,
    /// Second, conflicting block the validator voted for.
    pub second_block: Hash,
}

/// A vote-handling failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VoteError {
    /// The signer index is outside the committee (or beyond bitmap capacity).
    #[error("foreign or out-of-range signer index {0}")]
    ForeignSigner(u32),
    /// The signature failed to verify.
    #[error("invalid vote signature")]
    InvalidSignature,
    /// The committee is empty.
    #[error("empty committee")]
    EmptyCommittee,
    /// The committee exceeds the 64-signer bitmap capacity.
    #[error("committee exceeds 64 validators")]
    TooManyValidators,
    /// A timeout certificate's aggregate does not sign the expected
    /// `(epoch, view)` digest.
    #[error("timeout certificate digest mismatch")]
    TimeoutDigestMismatch,
    /// A timeout certificate carries below-threshold weight.
    #[error("timeout certificate below threshold")]
    TimeoutBelowThreshold,
}

/// The result of admitting a vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteOutcome {
    /// A new, valid, distinct vote was recorded.
    Accepted,
    /// The identical vote was already present (idempotent).
    Duplicate,
    /// The validator equivocated; the vote was rejected and evidence recorded.
    Equivocated(Equivocation),
}

/// The canonical, domain-separated digest a validator signs to time out a view.
///
/// Binds `(epoch, view)` only, so every honest replica timing out the *same*
/// view produces the *same* digest — allowing their signatures to aggregate
/// into one [`QuorumCertificate`] (a timeout certificate). The high-QC each
/// replica carries into the next view is tracked by the engine, not signed
/// here, so the certificate stays single-message and verifiable by a
/// [`ValidatorSet`].
#[must_use]
pub fn timeout_digest(epoch: u64, view: u64) -> Hash {
    let mut buf = Vec::with_capacity(8 + 8);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    hash_domain(DOMAIN_TIMEOUT, &buf)
}

/// A validator's signed timeout for a leader view — the view-change primitive.
///
/// A quorum of these forms a [`TimeoutCertificate`], which is the *only* thing
/// that lets a Byzantine-fault-tolerant engine leave a view. This prevents a
/// single replica (or a Byzantine leader) from advancing the view unilaterally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutVote {
    /// Epoch of the validator set that produced this timeout.
    pub epoch: u64,
    /// The view the validator is abandoning.
    pub view: u64,
    /// Index of the signing validator within its committee.
    pub validator_index: u32,
    /// ed25519 signature over [`TimeoutVote::digest`].
    #[serde(with = "crate::sig64")]
    pub signature: [u8; 64],
}

impl TimeoutVote {
    /// The digest this timeout signs.
    #[must_use]
    pub fn digest(&self) -> Hash {
        timeout_digest(self.epoch, self.view)
    }

    /// Verify this timeout's signature against `public_key`.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), VoteError> {
        verify_ed25519(public_key, self.digest().as_bytes(), &self.signature)
            .map_err(|_| VoteError::InvalidSignature)
    }
}

/// Verifiable view-change evidence: a quorum of validators timed out `view`.
///
/// The embedded [`QuorumCertificate`] signs exactly `timeout_digest(epoch,
/// view)`, so it verifies directly against a [`ValidatorSet`]. Advancing to
/// `view + 1` requires exhibiting one of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutCertificate {
    /// Epoch of the certifying validator set.
    pub epoch: u64,
    /// The view that a quorum abandoned.
    pub view: u64,
    /// Aggregate signatures over [`timeout_digest`].
    pub quorum: QuorumCertificate,
}

impl TimeoutCertificate {
    /// Verify the certificate: the aggregate must sign `timeout_digest(epoch,
    /// view)` and meet the set's threshold.
    pub fn verify(&self, set: &ValidatorSet) -> Result<(), VoteError> {
        if self.quorum.message != timeout_digest(self.epoch, self.view) {
            return Err(VoteError::TimeoutDigestMismatch);
        }
        set.verify(&self.quorum)
            .map_err(|_| VoteError::TimeoutBelowThreshold)
    }
}

/// A committee: the validators of one epoch, with a BFT `2f+1` threshold and
/// direct access to public keys (which [`ValidatorSet`] hides).
#[derive(Debug, Clone)]
pub struct Committee {
    epoch: u64,
    validators: Vec<Validator>,
    set: ValidatorSet,
}

impl Committee {
    /// Build a BFT committee for `epoch`. Rejects empty or oversized sets.
    pub fn new_bft(epoch: u64, validators: Vec<Validator>) -> Result<Self, VoteError> {
        if validators.is_empty() {
            return Err(VoteError::EmptyCommittee);
        }
        if validators.len() > MAX_VALIDATORS {
            return Err(VoteError::TooManyValidators);
        }
        let set = ValidatorSet::new_bft(validators.clone());
        Ok(Self {
            epoch,
            validators,
            set,
        })
    }

    /// The committee epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Whether the committee is empty (never true post-construction).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// The BFT weight threshold (`floor(2*total/3)+1`).
    #[must_use]
    pub fn threshold(&self) -> u64 {
        self.set.threshold()
    }

    /// Total voting weight.
    #[must_use]
    pub fn total_weight(&self) -> u64 {
        self.set.total_weight()
    }

    /// The underlying [`ValidatorSet`] for QC verification.
    #[must_use]
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.set
    }

    /// Public key of validator `index`, if present.
    #[must_use]
    pub fn public_key(&self, index: u32) -> Option<[u8; 32]> {
        let i = usize::try_from(index).ok()?;
        self.validators.get(i).map(|v| v.public_key)
    }

    /// Voting weight of validator `index`, if present.
    #[must_use]
    pub fn weight(&self, index: u32) -> Option<u64> {
        let i = usize::try_from(index).ok()?;
        self.validators.get(i).map(|v| v.weight)
    }

    /// Deterministic round-robin leader for `view`: `(epoch + view) mod n`.
    ///
    /// Every honest replica computes the same leader for a given
    /// `(epoch, view, committee)`.
    #[must_use]
    pub fn leader(&self, view: u64) -> u32 {
        let n = u64::try_from(self.validators.len()).unwrap_or(1).max(1);
        let idx = self.epoch.wrapping_add(view) % n;
        u32::try_from(idx).unwrap_or(0)
    }
}

/// Accumulates votes across rounds/heights and forms quorum certificates.
///
/// Votes are keyed by their digest so QC formation for one height/phase never
/// interferes with another (supporting pipelining). Equivocation is tracked per
/// `(validator, epoch, view, height, phase)`.
#[derive(Debug, Clone, Default)]
pub struct VoteCollector {
    // digest -> (validator_index -> signature), BTreeMap keeps ascending order.
    votes: BTreeMap<Hash, BTreeMap<u32, [u8; 64]>>,
    // round key -> first block seen (for equivocation detection).
    seen: BTreeMap<(u32, u64, u64, u64, u8), Hash>,
    equivocations: Vec<Equivocation>,
}

impl VoteCollector {
    /// A fresh, empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a vote. Verifies membership + signature, deduplicates, and detects
    /// equivocation. Malformed / foreign votes return an error; a validator
    /// double-signing returns [`VoteOutcome::Equivocated`] and is not counted.
    pub fn add_vote(
        &mut self,
        committee: &Committee,
        vote: &Vote,
    ) -> Result<VoteOutcome, VoteError> {
        let idx = usize::try_from(vote.validator_index)
            .map_err(|_| VoteError::ForeignSigner(vote.validator_index))?;
        if idx >= committee.len() || idx >= MAX_VALIDATORS {
            return Err(VoteError::ForeignSigner(vote.validator_index));
        }
        let public_key = committee
            .public_key(vote.validator_index)
            .ok_or(VoteError::ForeignSigner(vote.validator_index))?;
        vote.verify(&public_key)?;

        // Equivocation: same round+phase, different block.
        let key = vote.round_key();
        if let Some(prev_block) = self.seen.get(&key) {
            if *prev_block != vote.block_hash {
                let evidence = Equivocation {
                    validator_index: vote.validator_index,
                    epoch: vote.epoch,
                    view: vote.view,
                    height: vote.height,
                    phase: vote.phase,
                    first_block: *prev_block,
                    second_block: vote.block_hash,
                };
                self.equivocations.push(evidence.clone());
                return Ok(VoteOutcome::Equivocated(evidence));
            }
        } else {
            self.seen.insert(key, vote.block_hash);
        }

        let digest = vote.digest();
        let per_digest = self.votes.entry(digest).or_default();
        if per_digest.contains_key(&vote.validator_index) {
            return Ok(VoteOutcome::Duplicate);
        }
        per_digest.insert(vote.validator_index, vote.signature);
        Ok(VoteOutcome::Accepted)
    }

    /// Total signed weight currently collected for `digest`.
    #[must_use]
    pub fn weight_for(&self, committee: &Committee, digest: Hash) -> u64 {
        self.votes
            .get(&digest)
            .map(|m| {
                m.keys()
                    .filter_map(|&i| committee.weight(i))
                    .fold(0u64, u64::saturating_add)
            })
            .unwrap_or(0)
    }

    /// Attempt to form a quorum certificate for `digest`.
    ///
    /// Returns `Some(qc)` iff `>= threshold` distinct valid weight is present
    /// and the assembled certificate verifies against the committee's set.
    #[must_use]
    pub fn try_form_qc(&self, committee: &Committee, digest: Hash) -> Option<QuorumCertificate> {
        let per_digest = self.votes.get(&digest)?;
        let mut bitmap: u64 = 0;
        let mut signatures: Vec<[u8; 64]> = Vec::with_capacity(per_digest.len());
        let mut weight: u64 = 0;
        for (&index, signature) in per_digest {
            // index < MAX_VALIDATORS (64) is guaranteed at insertion time.
            bitmap |= 1u64 << index;
            signatures.push(*signature);
            weight = weight.saturating_add(committee.weight(index)?);
        }
        if weight < committee.threshold() {
            return None;
        }
        let qc = QuorumCertificate {
            message: digest,
            signer_bitmap: bitmap,
            signatures,
        };
        committee.validator_set().verify(&qc).ok().map(|()| qc)
    }

    /// All equivocation evidence collected so far.
    #[must_use]
    pub fn equivocations(&self) -> &[Equivocation] {
        &self.equivocations
    }

    /// Whether any equivocation has been observed.
    #[must_use]
    pub fn has_equivocation(&self) -> bool {
        !self.equivocations.is_empty()
    }
}

/// Accumulates [`TimeoutVote`]s per view and forms [`TimeoutCertificate`]s.
///
/// Timeouts are keyed by `(epoch, view)`; a validator can only meaningfully time
/// out a view once, so a repeat is idempotent (there is no equivocation to
/// detect — the message binds nothing but the view being abandoned).
#[derive(Debug, Clone, Default)]
pub struct TimeoutCollector {
    // (epoch, view) -> (validator_index -> signature)
    timeouts: BTreeMap<(u64, u64), BTreeMap<u32, [u8; 64]>>,
}

impl TimeoutCollector {
    /// A fresh, empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a timeout. Verifies committee membership and the signature, then
    /// deduplicates by validator index. Foreign / malformed timeouts error.
    pub fn add_timeout(
        &mut self,
        committee: &Committee,
        timeout: &TimeoutVote,
    ) -> Result<VoteOutcome, VoteError> {
        let idx = usize::try_from(timeout.validator_index)
            .map_err(|_| VoteError::ForeignSigner(timeout.validator_index))?;
        if idx >= committee.len() || idx >= MAX_VALIDATORS {
            return Err(VoteError::ForeignSigner(timeout.validator_index));
        }
        let public_key = committee
            .public_key(timeout.validator_index)
            .ok_or(VoteError::ForeignSigner(timeout.validator_index))?;
        timeout.verify(&public_key)?;

        let per_view = self
            .timeouts
            .entry((timeout.epoch, timeout.view))
            .or_default();
        if per_view.contains_key(&timeout.validator_index) {
            return Ok(VoteOutcome::Duplicate);
        }
        per_view.insert(timeout.validator_index, timeout.signature);
        Ok(VoteOutcome::Accepted)
    }

    /// Total signed timeout weight currently collected for `(epoch, view)`.
    #[must_use]
    pub fn weight_for(&self, committee: &Committee, epoch: u64, view: u64) -> u64 {
        self.timeouts
            .get(&(epoch, view))
            .map(|m| {
                m.keys()
                    .filter_map(|&i| committee.weight(i))
                    .fold(0u64, u64::saturating_add)
            })
            .unwrap_or(0)
    }

    /// Attempt to form a [`TimeoutCertificate`] for `(epoch, view)`.
    ///
    /// Returns `Some(tc)` iff `>= threshold` distinct valid weight timed out the
    /// view and the assembled certificate verifies against the committee's set.
    #[must_use]
    pub fn try_form_certificate(
        &self,
        committee: &Committee,
        epoch: u64,
        view: u64,
    ) -> Option<TimeoutCertificate> {
        let per_view = self.timeouts.get(&(epoch, view))?;
        let mut bitmap: u64 = 0;
        let mut signatures: Vec<[u8; 64]> = Vec::with_capacity(per_view.len());
        let mut weight: u64 = 0;
        for (&index, signature) in per_view {
            // index < MAX_VALIDATORS (64) is guaranteed at insertion time.
            bitmap |= 1u64 << index;
            signatures.push(*signature);
            weight = weight.saturating_add(committee.weight(index)?);
        }
        if weight < committee.threshold() {
            return None;
        }
        let quorum = QuorumCertificate {
            message: timeout_digest(epoch, view),
            signer_bitmap: bitmap,
            signatures,
        };
        committee.validator_set().verify(&quorum).ok()?;
        Some(TimeoutCertificate {
            epoch,
            view,
            quorum,
        })
    }
}
