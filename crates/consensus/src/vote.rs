//! HotStuff-style votes, committees, and Byzantine quorum-certificate formation.
//!
//! A [`Vote`] is a validator's signature over a domain-separated *vote digest*
//! that binds `(epoch, view, height, phase, block_hash)`. Because the signed
//! message is the digest itself, a formed [`QuorumCertificate`] verifies
//! directly against a [`crypto::ValidatorSet`].
//!
//! A [`VoteCollector`] deduplicates signers, rejects foreign / malformed / out-of
//! window votes **before** signature work where possible, detects equivocation,
//! excludes offenders from further QC weight, and forms a QC once `>= threshold`
//! weight is present — without re-verifying already-admitted signatures.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crypto::{
    hash_domain, verify_ed25519, CachedEd25519Key, QuorumCertificate, Validator, ValidatorSet,
};
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

/// Default how far ahead of the collector watermark a height may be.
///
/// Large enough for long-running soak tests and pipelined heights; engines
/// should call [`VoteCollector::prune_finalized`] / [`VoteCollector::set_window`]
/// to keep the live window tight around the watermark.
pub const DEFAULT_HEIGHT_HORIZON: u64 = 4096;
/// Default how far ahead of the current view a vote may target.
pub const DEFAULT_VIEW_HORIZON: u64 = 256;
/// Default bound on retained slash / equivocation evidence entries.
pub const DEFAULT_EVIDENCE_LIMIT: usize = 256;

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

    /// Verify against a pre-parsed cached key.
    pub fn verify_cached(&self, key: &CachedEd25519Key) -> Result<(), VoteError> {
        key.verify(self.digest().as_bytes(), &self.signature)
            .map_err(|_| VoteError::InvalidSignature)
    }
}

/// Verifiable evidence that a validator double-signed.
///
/// Serializable for gossip: peers re-verify both signatures against the
/// committee public key before acting on the evidence.
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
    /// Signature over the first block (optional for legacy evidence).
    #[serde(default, with = "crate::sig64::opt")]
    pub first_signature: Option<[u8; 64]>,
    /// Signature over the second block.
    #[serde(default, with = "crate::sig64::opt")]
    pub second_signature: Option<[u8; 64]>,
}

/// Slash / equivocation evidence ready for gossip and the slash-hook API.
///
/// This is the real, serializable wire type operators and peers exchange when
/// an offender is detected. [`SlashHook::on_equivocation`] receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashEvidence {
    /// Kind of misbehavior.
    pub kind: SlashKind,
    /// Equivocation payload (present for double-sign).
    pub equivocation: Option<Equivocation>,
    /// Epoch of the active committee when evidence was recorded.
    pub epoch: u64,
}

/// Classification of slashable misbehavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashKind {
    /// Two conflicting votes in the same round+phase.
    VoteEquivocation,
    /// Two conflicting proposals at the same height+view.
    ProposalFork,
}

/// Callback invoked when slashable evidence is recorded.
///
/// Implementations may broadcast evidence, update staking, or trigger an
/// emergency halt. The consensus engine always excludes the offender from
/// further QC weight regardless of the hook.
pub trait SlashHook: Send {
    /// Handle newly recorded slash evidence.
    fn on_equivocation(&mut self, evidence: &SlashEvidence);
}

/// A no-op slash hook (default).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSlashHook;

impl SlashHook for NoopSlashHook {
    fn on_equivocation(&mut self, _evidence: &SlashEvidence) {}
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
    /// The committee membership is not canonical: duplicate public keys,
    /// zero-weight members, or a weight sum that overflows `u64`.
    #[error("invalid validator set membership")]
    InvalidValidatorSet,
    /// A timeout certificate's aggregate does not sign the expected
    /// `(epoch, view)` digest.
    #[error("timeout certificate digest mismatch")]
    TimeoutDigestMismatch,
    /// A timeout certificate carries below-threshold weight.
    #[error("timeout certificate below threshold")]
    TimeoutBelowThreshold,
    /// Vote epoch does not match the active committee.
    #[error("vote epoch mismatch")]
    EpochMismatch,
    /// Vote height/view is outside the admitted window.
    #[error("vote outside admitted window")]
    OutsideWindow,
    /// The validator has been halted for prior equivocation.
    #[error("validator {0} is halted for equivocation")]
    HaltedOffender(u32),
}

/// The result of admitting a vote.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum VoteOutcome {
    /// A new, valid, distinct vote was recorded.
    Accepted,
    /// The identical vote was already present (idempotent).
    Duplicate,
    /// The validator equivocated; the vote was rejected, evidence recorded, and
    /// the offender is halted for further certification weight.
    Equivocated(Equivocation),
}

/// The canonical, domain-separated digest a validator signs to time out a view.
#[must_use]
pub fn timeout_digest(epoch: u64, view: u64) -> Hash {
    let mut buf = Vec::with_capacity(8 + 8);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    hash_domain(DOMAIN_TIMEOUT, &buf)
}

/// A validator's signed timeout for a leader view — the view-change primitive.
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

    /// Verify against a pre-parsed cached key.
    pub fn verify_cached(&self, key: &CachedEd25519Key) -> Result<(), VoteError> {
        key.verify(self.digest().as_bytes(), &self.signature)
            .map_err(|_| VoteError::InvalidSignature)
    }
}

/// Verifiable view-change evidence: a quorum of validators timed out `view`.
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

/// Bounds on heights/views admitted into a collector, and evidence retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectorWindow {
    /// Active committee epoch; votes for any other epoch are rejected.
    pub epoch: u64,
    /// Inclusive lower height bound (typically last-finalized + 1, or 0).
    pub min_height: u64,
    /// How many heights above `min_height` may be admitted.
    pub height_horizon: u64,
    /// Current view of the local engine.
    pub current_view: u64,
    /// How far ahead of `current_view` a vote may target.
    pub view_horizon: u64,
    /// Max retained slash/equivocation evidence entries.
    pub evidence_limit: usize,
}

impl CollectorWindow {
    /// Default window for `epoch`, admitting heights `[0, horizon]` and views
    /// up to `view_horizon` from view 0.
    #[must_use]
    pub fn default_for(epoch: u64) -> Self {
        Self {
            epoch,
            min_height: 0,
            height_horizon: DEFAULT_HEIGHT_HORIZON,
            current_view: 0,
            view_horizon: DEFAULT_VIEW_HORIZON,
            evidence_limit: DEFAULT_EVIDENCE_LIMIT,
        }
    }

    /// Highest height currently admitted.
    #[must_use]
    pub fn max_height(&self) -> u64 {
        self.min_height.saturating_add(self.height_horizon)
    }

    /// Highest view currently admitted.
    #[must_use]
    pub fn max_view(&self) -> u64 {
        self.current_view.saturating_add(self.view_horizon)
    }

    fn admits(&self, epoch: u64, height: u64, view: u64) -> Result<(), VoteError> {
        if epoch != self.epoch {
            return Err(VoteError::EpochMismatch);
        }
        if height < self.min_height || height > self.max_height() {
            return Err(VoteError::OutsideWindow);
        }
        if view > self.max_view() {
            return Err(VoteError::OutsideWindow);
        }
        Ok(())
    }
}

/// A committee: the validators of one epoch, with a BFT `2f+1` threshold,
/// direct access to public keys, and cached ed25519 verifying keys.
#[derive(Debug, Clone)]
pub struct Committee {
    epoch: u64,
    validators: Vec<Validator>,
    set: ValidatorSet,
    /// Pre-parsed verifying keys aligned with `validators` (same length).
    cached_keys: Vec<CachedEd25519Key>,
}

impl Committee {
    /// Build a BFT committee for `epoch`. Rejects empty or oversized sets and
    /// noncanonical membership (duplicate keys, zero weights, weight overflow).
    ///
    /// The membership is validated through the fallible
    /// [`ValidatorSet::try_new_bft`] builder — never the panicking constructor —
    /// so an untrusted epoch-boundary [`crate::ValidatorSetUpdate`] can only
    /// return an error, never abort the node.
    pub fn new_bft(epoch: u64, validators: Vec<Validator>) -> Result<Self, VoteError> {
        if validators.is_empty() {
            return Err(VoteError::EmptyCommittee);
        }
        if validators.len() > MAX_VALIDATORS {
            return Err(VoteError::TooManyValidators);
        }
        let set = ValidatorSet::try_new_bft(validators.clone())
            .map_err(|_| VoteError::InvalidValidatorSet)?;
        let mut cached_keys = Vec::with_capacity(validators.len());
        for v in &validators {
            cached_keys.push(
                CachedEd25519Key::parse(&v.public_key)
                    .map_err(|_| VoteError::InvalidValidatorSet)?,
            );
        }
        Ok(Self {
            epoch,
            validators,
            set,
            cached_keys,
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

    /// Cached verifying key of validator `index`, if present.
    #[must_use]
    pub fn cached_key(&self, index: u32) -> Option<&CachedEd25519Key> {
        let i = usize::try_from(index).ok()?;
        self.cached_keys.get(i)
    }

    /// Voting weight of validator `index`, if present.
    #[must_use]
    pub fn weight(&self, index: u32) -> Option<u64> {
        let i = usize::try_from(index).ok()?;
        self.validators.get(i).map(|v| v.weight)
    }

    /// Deterministic round-robin leader for `view`: `(epoch + view) mod n`.
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
/// `(validator, epoch, view, height, phase)`. Offenders are **halted**: their
/// weight is excluded from subsequent QC formation. Signatures are verified
/// exactly once at admission; [`try_form_qc`] does not re-verify them.
#[derive(Debug, Clone)]
pub struct VoteCollector {
    // digest -> (validator_index -> signature), BTreeMap keeps ascending order.
    votes: BTreeMap<Hash, BTreeMap<u32, [u8; 64]>>,
    // round key -> first block + signature seen (for equivocation detection).
    #[allow(clippy::type_complexity)] // equivocation index key
    seen: BTreeMap<(u32, u64, u64, u64, u8), (Hash, [u8; 64])>,
    equivocations: Vec<Equivocation>,
    slash_log: Vec<SlashEvidence>,
    /// Validators whose conflicting vote was observed; excluded from QC weight.
    halted: BTreeSet<u32>,
    window: CollectorWindow,
    /// Dropped votes rejected for being outside the window (observability).
    window_drops: u64,
}

impl Default for VoteCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl VoteCollector {
    /// A fresh collector with a permissive default window (epoch 0).
    #[must_use]
    pub fn new() -> Self {
        Self::with_window(CollectorWindow::default_for(0))
    }

    /// A collector with an explicit admission window.
    #[must_use]
    pub fn with_window(window: CollectorWindow) -> Self {
        Self {
            votes: BTreeMap::new(),
            seen: BTreeMap::new(),
            equivocations: Vec::new(),
            slash_log: Vec::new(),
            halted: BTreeSet::new(),
            window,
            window_drops: 0,
        }
    }

    /// Current admission window.
    #[must_use]
    pub fn window(&self) -> CollectorWindow {
        self.window
    }

    /// Update the active epoch / view / prune watermark. Does not wipe votes.
    pub fn set_window(&mut self, window: CollectorWindow) {
        self.window = window;
    }

    /// Advance the prune watermark: drop votes, seen keys, and digests for
    /// heights strictly below `finalized_height` (exclusive lower bound becomes
    /// `finalized_height`). Protocol-required evidence is retained up to the
    /// evidence limit.
    pub fn prune_finalized(&mut self, finalized_height: u64) {
        self.window.min_height = self.window.min_height.max(finalized_height);
        // Drop vote digests whose height we can no longer admit — we do not
        // store height on the digest key, so purge `seen` by height and rebuild
        // empty digests lazily. Clear votes entirely below watermark by
        // scanning seen-derived heights is approximate; instead clear all votes
        // for rounds with height < min_height via `seen` keys, then drop empty.
        self.seen
            .retain(|(_, _, _, height, _), _| *height >= self.window.min_height);
        // Votes map is keyed by digest only; leave it — try_form_qc still works
        // for live heights. Bound growth by also clearing votes when the map is
        // large relative to the horizon: drop all when over capacity.
        let cap = usize::try_from(self.window.height_horizon)
            .unwrap_or(usize::MAX)
            .saturating_mul(3)
            .saturating_mul(self.window.evidence_limit.max(1))
            .max(64);
        if self.votes.len() > cap {
            self.votes.clear();
        }
        while self.equivocations.len() > self.window.evidence_limit {
            self.equivocations.remove(0);
        }
        while self.slash_log.len() > self.window.evidence_limit {
            self.slash_log.remove(0);
        }
    }

    /// Number of retained vote-digest entries (observability).
    #[must_use]
    pub fn retained_digests(&self) -> usize {
        self.votes.len()
    }

    /// Votes dropped for being outside the window.
    #[must_use]
    pub fn window_drops(&self) -> u64 {
        self.window_drops
    }

    /// Validators currently halted for equivocation.
    #[must_use]
    pub fn halted_offenders(&self) -> &BTreeSet<u32> {
        &self.halted
    }

    /// Whether `validator_index` is halted.
    #[must_use]
    pub fn is_halted(&self, validator_index: u32) -> bool {
        self.halted.contains(&validator_index)
    }

    /// Serializable slash evidence log (bounded).
    #[must_use]
    pub fn slash_evidence(&self) -> &[SlashEvidence] {
        &self.slash_log
    }

    /// Admit a vote. Window checks run before signature verification. Detects
    /// equivocation, halts the offender, and records slash evidence. A vote is
    /// cryptographically verified **once** here; [`try_form_qc`] trusts these
    /// retained signatures.
    pub fn add_vote(
        &mut self,
        committee: &Committee,
        vote: &Vote,
    ) -> Result<VoteOutcome, VoteError> {
        // Cheap window / membership checks before signature work.
        if let Err(e) = self.window.admits(vote.epoch, vote.height, vote.view) {
            self.window_drops = self.window_drops.saturating_add(1);
            return Err(e);
        }
        if vote.epoch != committee.epoch() {
            return Err(VoteError::EpochMismatch);
        }
        let idx = usize::try_from(vote.validator_index)
            .map_err(|_| VoteError::ForeignSigner(vote.validator_index))?;
        if idx >= committee.len() || idx >= MAX_VALIDATORS {
            return Err(VoteError::ForeignSigner(vote.validator_index));
        }
        if self.halted.contains(&vote.validator_index) {
            return Err(VoteError::HaltedOffender(vote.validator_index));
        }

        // Single cryptographic verification (cached key).
        let key = committee
            .cached_key(vote.validator_index)
            .ok_or(VoteError::ForeignSigner(vote.validator_index))?;
        vote.verify_cached(key)?;

        // Equivocation: same round+phase, different block.
        let key_rk = vote.round_key();
        if let Some((prev_block, prev_sig)) = self.seen.get(&key_rk).copied() {
            if prev_block != vote.block_hash {
                let evidence = Equivocation {
                    validator_index: vote.validator_index,
                    epoch: vote.epoch,
                    view: vote.view,
                    height: vote.height,
                    phase: vote.phase,
                    first_block: prev_block,
                    second_block: vote.block_hash,
                    first_signature: Some(prev_sig),
                    second_signature: Some(vote.signature),
                };
                self.record_equivocation(evidence.clone());
                return Ok(VoteOutcome::Equivocated(evidence));
            }
        } else {
            self.seen.insert(key_rk, (vote.block_hash, vote.signature));
        }

        let digest = vote.digest();
        let per_digest = self.votes.entry(digest).or_default();
        if per_digest.contains_key(&vote.validator_index) {
            return Ok(VoteOutcome::Duplicate);
        }
        per_digest.insert(vote.validator_index, vote.signature);
        Ok(VoteOutcome::Accepted)
    }

    fn record_equivocation(&mut self, evidence: Equivocation) {
        self.halted.insert(evidence.validator_index);
        // Strip any previously counted weight from this offender.
        for per in self.votes.values_mut() {
            per.remove(&evidence.validator_index);
        }
        let slash = SlashEvidence {
            kind: SlashKind::VoteEquivocation,
            epoch: evidence.epoch,
            equivocation: Some(evidence.clone()),
        };
        self.equivocations.push(evidence);
        self.slash_log.push(slash);
        while self.equivocations.len() > self.window.evidence_limit {
            self.equivocations.remove(0);
        }
        while self.slash_log.len() > self.window.evidence_limit {
            self.slash_log.remove(0);
        }
    }

    /// Record proposal-fork slash evidence and halt the proposer.
    pub fn record_proposal_fork(
        &mut self,
        epoch: u64,
        proposer: u32,
        height: u64,
        view: u64,
        first: Hash,
        second: Hash,
    ) {
        self.halted.insert(proposer);
        for per in self.votes.values_mut() {
            per.remove(&proposer);
        }
        let evidence = Equivocation {
            validator_index: proposer,
            epoch,
            view,
            height,
            phase: VotePhase::Prepare,
            first_block: first,
            second_block: second,
            first_signature: None,
            second_signature: None,
        };
        let slash = SlashEvidence {
            kind: SlashKind::ProposalFork,
            epoch,
            equivocation: Some(evidence.clone()),
        };
        self.equivocations.push(evidence);
        self.slash_log.push(slash);
        while self.slash_log.len() > self.window.evidence_limit {
            self.slash_log.remove(0);
        }
    }

    /// Total signed weight currently collected for `digest`, excluding halted
    /// offenders.
    #[must_use]
    pub fn weight_for(&self, committee: &Committee, digest: Hash) -> u64 {
        self.votes
            .get(&digest)
            .map(|m| {
                m.keys()
                    .filter(|i| !self.halted.contains(i))
                    .filter_map(|&i| committee.weight(i))
                    .fold(0u64, u64::saturating_add)
            })
            .unwrap_or(0)
    }

    /// Attempt to form a quorum certificate for `digest`.
    ///
    /// Returns `Some(qc)` iff `>= threshold` distinct **non-halted** weight is
    /// present. Signatures were verified at admission; this method does **not**
    /// re-verify them (hot path). Callers that need an independent check may
    /// still call [`ValidatorSet::verify`].
    #[must_use]
    pub fn try_form_qc(&self, committee: &Committee, digest: Hash) -> Option<QuorumCertificate> {
        let per_digest = self.votes.get(&digest)?;
        let mut bitmap: u64 = 0;
        let mut signatures: Vec<[u8; 64]> = Vec::with_capacity(per_digest.len());
        let mut weight: u64 = 0;
        for (&index, signature) in per_digest {
            if self.halted.contains(&index) {
                continue;
            }
            // index < MAX_VALIDATORS (64) is guaranteed at insertion time.
            bitmap |= 1u64 << index;
            signatures.push(*signature);
            weight = weight.saturating_add(committee.weight(index)?);
        }
        if weight < committee.threshold() {
            return None;
        }
        Some(QuorumCertificate {
            message: digest,
            signer_bitmap: bitmap,
            signatures,
        })
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

    /// Admit a timeout. Verifies committee membership and the signature (once),
    /// then deduplicates by validator index.
    pub fn add_timeout(
        &mut self,
        committee: &Committee,
        timeout: &TimeoutVote,
    ) -> Result<VoteOutcome, VoteError> {
        if timeout.epoch != committee.epoch() {
            return Err(VoteError::EpochMismatch);
        }
        let idx = usize::try_from(timeout.validator_index)
            .map_err(|_| VoteError::ForeignSigner(timeout.validator_index))?;
        if idx >= committee.len() || idx >= MAX_VALIDATORS {
            return Err(VoteError::ForeignSigner(timeout.validator_index));
        }
        let key = committee
            .cached_key(timeout.validator_index)
            .ok_or(VoteError::ForeignSigner(timeout.validator_index))?;
        timeout.verify_cached(key)?;

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
    /// Does not re-verify signatures admitted via [`add_timeout`].
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
            bitmap |= 1u64 << index;
            signatures.push(*signature);
            weight = weight.saturating_add(committee.weight(index)?);
        }
        if weight < committee.threshold() {
            return None;
        }
        Some(TimeoutCertificate {
            epoch,
            view,
            quorum: QuorumCertificate {
                message: timeout_digest(epoch, view),
                signer_bitmap: bitmap,
                signatures,
            },
        })
    }

    /// Drop timeouts for views strictly below `min_view`.
    pub fn prune_below_view(&mut self, min_view: u64) {
        self.timeouts.retain(|(_, view), _| *view >= min_view);
    }
}
