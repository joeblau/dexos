//! Leader-based, pipelined BFT lifecycle driver.
//!
//! [`BftEngine`] is a pure, synchronous state machine (no async, no I/O). It
//! ingests [`Proposal`]s and [`Vote`]s, forms quorum certificates through a
//! [`VoteCollector`], and advances a per-height pipeline through
//! `Accepted -> Executed -> Certified -> Finalized`. Multiple heights may be
//! in flight simultaneously, so certification of one height never stalls
//! execution of another.
//!
//! # Consensus modes
//!
//! The engine runs in one of two [`ConsensusMode`]s:
//!
//! - [`ConsensusMode::CrashTolerant`] — single-phase `Commit` certification, as
//!   used by the demo's three regional replicas. It provides crash tolerance
//!   and liveness but does **not**, on its own, provide Byzantine safety; it is
//!   the "demo" mode and requires no more than three nodes.
//! - [`ConsensusMode::ByzantineFaultTolerant`] — the full HotStuff/PBFT pipeline:
//!   chained `Prepare -> PreCommit -> Commit` quorum certificates, a high-QC /
//!   locking rule, parent/ancestry validation, [`TimeoutCertificate`]-gated view
//!   changes, refusal to certify a forked round, and finalization that is
//!   refused until an execution commitment is certified. Tolerating one
//!   Byzantine fault requires a `3f+1` set (**>= 4 validators**).
//!
//! It also performs deterministic round-robin leader selection, view rotation,
//! explicit epoch / validator-set transitions, and fork detection (two
//! conflicting proposals at the same height+view).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crypto::{hash_domain, verify_ed25519, QuorumCertificate, Validator};
use types::Hash;

use crate::sequencer::CommandStatus;
use crate::vote::{
    vote_digest, CollectorWindow, Committee, Equivocation, SlashEvidence, TimeoutCertificate,
    TimeoutCollector, TimeoutVote, Vote, VoteError, VoteOutcome, VotePhase,
};

/// Domain tag for proposal digests.
pub const DOMAIN_PROPOSAL: &[u8] = b"dexos:consensus:proposal:v1";

/// Domain tag for the execution-commitment digest an execution certificate signs.
pub const DOMAIN_EXEC_COMMIT: &[u8] = b"dexos:consensus:exec-commit:v1";

/// How strictly the engine enforces Byzantine-fault-tolerance rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMode {
    /// Single-phase `Commit` certification for a small crash-fault-tolerant
    /// deployment (the demo runs three regional replicas this way). Provides
    /// crash tolerance and liveness, but not Byzantine safety on its own.
    CrashTolerant,
    /// The full HotStuff pipeline — chained QCs, high-QC locking,
    /// parent/ancestry validation, timeout-certificate view changes, and
    /// execution-certified finalization. Requires a `3f+1` set (>= 4
    /// validators) to tolerate one Byzantine fault.
    ByzantineFaultTolerant,
}

/// A leader's proposal for a pipeline height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Epoch of the proposing committee.
    pub epoch: u64,
    /// Leader view the proposal was made in.
    pub view: u64,
    /// Pipeline height.
    pub height: u64,
    /// Commitment to the batch of sequenced commands.
    pub block_hash: Hash,
    /// The parent block this proposal extends (ancestry / fork linkage).
    pub parent_hash: Hash,
    /// First sequence covered by the batch.
    pub first_sequence: u64,
    /// Last sequence covered by the batch.
    pub last_sequence: u64,
    /// Index of the proposing validator.
    pub proposer_index: u32,
    /// ed25519 signature over [`Proposal::digest`].
    #[serde(with = "crate::sig64")]
    pub signature: [u8; 64],
}

/// The canonical, domain-separated proposal digest a leader signs.
#[must_use]
pub fn proposal_digest(
    epoch: u64,
    view: u64,
    height: u64,
    block_hash: Hash,
    parent_hash: Hash,
    first_sequence: u64,
    last_sequence: u64,
) -> Hash {
    let mut buf = Vec::with_capacity(8 * 3 + 32 + 32 + 8 + 8);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(block_hash.as_bytes());
    buf.extend_from_slice(parent_hash.as_bytes());
    buf.extend_from_slice(&first_sequence.to_le_bytes());
    buf.extend_from_slice(&last_sequence.to_le_bytes());
    hash_domain(DOMAIN_PROPOSAL, &buf)
}

impl Proposal {
    /// The digest this proposal signs.
    #[must_use]
    pub fn digest(&self) -> Hash {
        proposal_digest(
            self.epoch,
            self.view,
            self.height,
            self.block_hash,
            self.parent_hash,
            self.first_sequence,
            self.last_sequence,
        )
    }

    /// Verify the proposer's signature against `public_key`.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), BftError> {
        verify_ed25519(public_key, self.digest().as_bytes(), &self.signature)
            .map_err(|_| BftError::InvalidProposal)
    }
}

/// The canonical digest an execution certificate signs, binding a finalized
/// block to the deterministic execution root it produced.
#[must_use]
pub fn execution_commitment_digest(
    epoch: u64,
    view: u64,
    height: u64,
    block_hash: Hash,
    execution_root: Hash,
) -> Hash {
    let mut buf = Vec::with_capacity(8 * 3 + 32 + 32);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(block_hash.as_bytes());
    buf.extend_from_slice(execution_root.as_bytes());
    hash_domain(DOMAIN_EXEC_COMMIT, &buf)
}

/// Verifiable evidence of a fork: two distinct blocks proposed at the same
/// height and view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fork {
    /// The conflicted height.
    pub height: u64,
    /// The conflicted view.
    pub view: u64,
    /// First block observed.
    pub first_block: Hash,
    /// Second, conflicting block observed.
    pub second_block: Hash,
}

/// An explicit validator-set change that activates at a deterministic epoch
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetUpdate {
    /// The epoch at which the new set becomes active.
    pub activation_epoch: u64,
    /// The new validator set (with weights).
    pub validators: Vec<Validator>,
}

/// A BFT lifecycle failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BftError {
    /// The proposer is not the deterministic leader for the proposal's view.
    #[error("proposer {got} is not the leader {expected} for view")]
    NotLeader {
        /// The proposer that signed.
        got: u32,
        /// The expected leader index.
        expected: u32,
    },
    /// The proposal's epoch does not match the active committee.
    #[error("proposal epoch mismatch")]
    EpochMismatch,
    /// The proposer's signature failed to verify.
    #[error("invalid proposal signature")]
    InvalidProposal,
    /// The proposal is for a view other than the engine's current view (BFT).
    #[error("proposal view {got} does not match current view {expected}")]
    WrongView {
        /// The view the engine is in.
        expected: u64,
        /// The view the proposal claimed.
        got: u64,
    },
    /// The proposal's `parent_hash` conflicts with the known block at the
    /// preceding height (BFT ancestry rule).
    #[error("proposal at height {height} breaks ancestry")]
    AncestryMismatch {
        /// Height whose parent linkage was rejected.
        height: u64,
    },
    /// A conflicting block was proposed at a height the engine is locked on
    /// (high-QC / locking rule).
    #[error("height {height} is locked on a different block")]
    Locked {
        /// Locked height.
        height: u64,
    },
    /// A phase QC was requested before its predecessor phase was certified
    /// (Prepare -> PreCommit -> Commit chaining).
    #[error("phase {phase:?} at height {height} is not chained to its predecessor")]
    PhaseNotChained {
        /// Height whose certification was rejected.
        height: u64,
        /// The phase that was requested out of order.
        phase: VotePhase,
    },
    /// Certification was refused because the round is forked (its leader
    /// equivocated at this view).
    #[error("height {height} view {view} is forked; certification halted")]
    ForkedRound {
        /// The forked height.
        height: u64,
        /// The forked view.
        view: u64,
    },
    /// Two different blocks reached a Commit certificate at the same height — a
    /// safety violation that would only occur with a Byzantine quorum.
    #[error("safety violation: conflicting certified blocks at height {height}")]
    SafetyViolation {
        /// The height with conflicting certified blocks.
        height: u64,
    },
    /// Finalization was refused because no execution certificate is present.
    #[error("height {0} has no certified execution commitment")]
    MissingExecutionCertificate(u64),
    /// An execution certificate did not verify (wrong digest or below quorum).
    #[error("invalid execution certificate for height {0}")]
    InvalidExecutionCertificate(u64),
    /// A view change was attempted for the wrong (non-current) view.
    #[error("view change targets view {got}, engine is at {expected}")]
    WrongViewChange {
        /// The engine's current view.
        expected: u64,
        /// The view the certificate abandons.
        got: u64,
    },
    /// No proposal exists at the referenced height.
    #[error("unknown height {0}")]
    UnknownHeight(u64),
    /// The referenced height is not certified yet.
    #[error("height {0} is not certified")]
    NotCertified(u64),
    /// A lifecycle transition did not strictly advance.
    #[error("invalid lifecycle transition at height {height}: {from:?} -> {to:?}")]
    InvalidTransition {
        /// Height whose transition was rejected.
        height: u64,
        /// Current status.
        from: CommandStatus,
        /// Requested status.
        to: CommandStatus,
    },
    /// No pending validator-set update to activate.
    #[error("no pending validator-set update")]
    NoPendingUpdate,
    /// The pending update does not activate at the requested epoch.
    #[error("update activates at {activation}, not {requested}")]
    WrongActivationEpoch {
        /// Epoch the update activates at.
        activation: u64,
        /// Epoch that was requested.
        requested: u64,
    },
    /// A vote-layer error.
    #[error(transparent)]
    Vote(#[from] VoteError),
}

/// The outcome of receiving a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// A new proposal was admitted to the pipeline.
    Accepted,
    /// The identical proposal was already present (idempotent).
    Duplicate,
    /// A conflicting proposal was detected; evidence recorded, not admitted.
    Forked(Fork),
}

/// A reference to a formed quorum certificate, used for high-QC / lock tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QcRef {
    view: u64,
    height: u64,
    block: Hash,
}

/// Per-height pipeline state.
#[derive(Debug, Clone)]
struct HeightState {
    proposal: Proposal,
    status: CommandStatus,
    prepare_qc: Option<QuorumCertificate>,
    precommit_qc: Option<QuorumCertificate>,
    commit_qc: Option<QuorumCertificate>,
    certified_block: Option<Hash>,
    execution_root: Option<Hash>,
    execution_certified: bool,
}

impl HeightState {
    fn new(proposal: Proposal) -> Self {
        Self {
            proposal,
            status: CommandStatus::Accepted,
            prepare_qc: None,
            precommit_qc: None,
            commit_qc: None,
            certified_block: None,
            execution_root: None,
            execution_certified: false,
        }
    }

    fn highest_qc(&self) -> Option<&QuorumCertificate> {
        self.commit_qc
            .as_ref()
            .or(self.precommit_qc.as_ref())
            .or(self.prepare_qc.as_ref())
    }
}

/// The pipelined BFT engine for one node.
#[derive(Debug, Clone)]
pub struct BftEngine {
    committee: Committee,
    mode: ConsensusMode,
    view: u64,
    pipeline: BTreeMap<u64, HeightState>,
    // Accepted / finalized canonical block per height (ancestry linkage).
    chain: BTreeMap<u64, Hash>,
    collector: crate::vote::VoteCollector,
    timeouts: TimeoutCollector,
    high_qc: Option<QcRef>,
    // Per-height lock installed by a PreCommit QC (BFT).
    locked: BTreeMap<u64, QcRef>,
    last_view_change: Option<TimeoutCertificate>,
    forks: Vec<Fork>,
    quorum_forks: Vec<Fork>,
    pending_update: Option<ValidatorSetUpdate>,
}

impl BftEngine {
    /// Create a crash-tolerant (demo) engine for `committee`, starting at view 0.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        Self::with_mode(committee, ConsensusMode::CrashTolerant)
    }

    /// Create a fully Byzantine-fault-tolerant engine (chained QCs, locking,
    /// timeout certificates, execution-certified finalize). Use a `3f+1` set.
    #[must_use]
    pub fn new_byzantine(committee: Committee) -> Self {
        Self::with_mode(committee, ConsensusMode::ByzantineFaultTolerant)
    }

    /// Create an engine in an explicit [`ConsensusMode`].
    #[must_use]
    pub fn with_mode(committee: Committee, mode: ConsensusMode) -> Self {
        Self {
            committee,
            mode,
            view: 0,
            pipeline: BTreeMap::new(),
            chain: BTreeMap::new(),
            collector: crate::vote::VoteCollector::new(),
            timeouts: TimeoutCollector::new(),
            high_qc: None,
            locked: BTreeMap::new(),
            last_view_change: None,
            forks: Vec::new(),
            quorum_forks: Vec::new(),
            pending_update: None,
        }
    }

    /// The engine's consensus mode.
    #[must_use]
    pub fn mode(&self) -> ConsensusMode {
        self.mode
    }

    /// Whether the engine enforces the full Byzantine-fault-tolerant ruleset.
    #[must_use]
    pub fn is_bft(&self) -> bool {
        self.mode == ConsensusMode::ByzantineFaultTolerant
    }

    /// The active committee's epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.committee.epoch()
    }

    /// The current leader view.
    #[must_use]
    pub fn view(&self) -> u64 {
        self.view
    }

    /// The deterministic leader index for the current view.
    #[must_use]
    pub fn leader(&self) -> u32 {
        self.committee.leader(self.view)
    }

    /// The active committee.
    #[must_use]
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// The view of the highest quorum certificate observed (the high-QC rule
    /// input), if any.
    #[must_use]
    pub fn high_qc_view(&self) -> Option<u64> {
        self.high_qc.as_ref().map(|q| q.view)
    }

    /// The block the engine is locked on at `height`, if a PreCommit QC has
    /// formed there.
    #[must_use]
    pub fn locked_block(&self, height: u64) -> Option<Hash> {
        self.locked.get(&height).map(|q| q.block)
    }

    /// The most recent view-change certificate the engine acted on, if any.
    #[must_use]
    pub fn last_view_change(&self) -> Option<&TimeoutCertificate> {
        self.last_view_change.as_ref()
    }

    /// Crash-tolerant view rotation (demo failover).
    ///
    /// In [`ConsensusMode::ByzantineFaultTolerant`] this does **not** advance the
    /// view — a [`TimeoutCertificate`] is required (see [`BftEngine::advance_view`])
    /// so no replica can leave a view without a quorum of view-change evidence.
    /// It returns the (possibly unchanged) current view.
    pub fn on_timeout(&mut self) -> u64 {
        if self.mode == ConsensusMode::CrashTolerant {
            self.view = self.view.wrapping_add(1);
        }
        self.view
    }

    /// Admit a view-change timeout into the shared collector.
    pub fn add_timeout(&mut self, timeout: &TimeoutVote) -> Result<VoteOutcome, BftError> {
        Ok(self.timeouts.add_timeout(&self.committee, timeout)?)
    }

    /// Attempt to form a timeout certificate for `view` from collected timeouts.
    #[must_use]
    pub fn try_form_timeout_certificate(&self, view: u64) -> Option<TimeoutCertificate> {
        self.timeouts
            .try_form_certificate(&self.committee, self.epoch(), view)
    }

    /// Advance to the next view, justified by a timeout certificate for the
    /// current view. The certificate must be for this epoch and current view and
    /// must verify against the active set; on success the view increments and the
    /// certificate is retained as the justification for the next leader's proposal.
    pub fn advance_view(&mut self, tc: &TimeoutCertificate) -> Result<u64, BftError> {
        if tc.epoch != self.epoch() {
            return Err(BftError::EpochMismatch);
        }
        if tc.view != self.view {
            return Err(BftError::WrongViewChange {
                expected: self.view,
                got: tc.view,
            });
        }
        tc.verify(self.committee.validator_set())?;
        self.view = self.view.wrapping_add(1);
        self.last_view_change = Some(tc.clone());
        Ok(self.view)
    }

    /// Receive a proposal. Validates the proposer is the deterministic leader
    /// and the signature is valid, then admits it — unless a different block was
    /// already proposed at the same height+view, which is flagged as a fork.
    ///
    /// In [`ConsensusMode::ByzantineFaultTolerant`] it additionally enforces that
    /// the proposal is for the engine's current view, that its `parent_hash`
    /// links to the known block at the preceding height, and that it does not
    /// conflict with a locked block.
    pub fn receive_proposal(&mut self, proposal: Proposal) -> Result<ProposalOutcome, BftError> {
        if proposal.epoch != self.committee.epoch() {
            return Err(BftError::EpochMismatch);
        }
        let expected_leader = self.committee.leader(proposal.view);
        if proposal.proposer_index != expected_leader {
            return Err(BftError::NotLeader {
                got: proposal.proposer_index,
                expected: expected_leader,
            });
        }
        let public_key = self
            .committee
            .public_key(proposal.proposer_index)
            .ok_or(BftError::InvalidProposal)?;
        proposal.verify(&public_key)?;

        if self.is_bft() {
            if proposal.view != self.view {
                return Err(BftError::WrongView {
                    expected: self.view,
                    got: proposal.view,
                });
            }
            self.check_ancestry(&proposal)?;
            if let Some(lock) = self.locked.get(&proposal.height) {
                if lock.block != proposal.block_hash {
                    return Err(BftError::Locked {
                        height: proposal.height,
                    });
                }
            }
        }

        if let Some(existing) = self.pipeline.get(&proposal.height) {
            if existing.proposal.view == proposal.view {
                if existing.proposal.block_hash == proposal.block_hash {
                    return Ok(ProposalOutcome::Duplicate);
                }
                let fork = Fork {
                    height: proposal.height,
                    view: proposal.view,
                    first_block: existing.proposal.block_hash,
                    second_block: proposal.block_hash,
                };
                self.forks.push(fork.clone());
                // Halt the offender: exclude from QC weight and emit slash evidence.
                self.collector.record_proposal_fork(
                    proposal.epoch,
                    proposal.proposer_index,
                    proposal.height,
                    proposal.view,
                    fork.first_block,
                    fork.second_block,
                );
                return Ok(ProposalOutcome::Forked(fork));
            }
        }

        self.chain.insert(proposal.height, proposal.block_hash);
        self.pipeline
            .insert(proposal.height, HeightState::new(proposal));
        Ok(ProposalOutcome::Accepted)
    }

    /// BFT ancestry rule: if the block at the preceding height is known, the
    /// proposal's `parent_hash` must equal it. When the parent height is not yet
    /// observed, the linkage cannot be refuted, so the proposal is admitted
    /// (pipelined) and validated later.
    fn check_ancestry(&self, proposal: &Proposal) -> Result<(), BftError> {
        let Some(parent_height) = proposal.height.checked_sub(1) else {
            return Ok(());
        };
        if parent_height == 0 && !self.chain.contains_key(&0) {
            // Genesis parent: no committed block below; nothing to link against.
            return Ok(());
        }
        if let Some(parent_block) = self.chain.get(&parent_height) {
            if *parent_block != proposal.parent_hash {
                return Err(BftError::AncestryMismatch {
                    height: proposal.height,
                });
            }
        }
        Ok(())
    }

    /// Mark a height as executed. Pipelined: a height may be executed while
    /// earlier heights remain un-finalized.
    pub fn execute(&mut self, height: u64) -> Result<(), BftError> {
        self.transition(height, CommandStatus::Executed)
    }

    /// Attach a certified execution commitment to a height: an execution root
    /// plus a [`QuorumCertificate`] over
    /// [`execution_commitment_digest`]. Required (in BFT mode) before a height
    /// may finalize, so a block can never be finalized without a quorum having
    /// attested to the deterministic state it produced.
    pub fn certify_execution(
        &mut self,
        height: u64,
        execution_root: Hash,
        certificate: &QuorumCertificate,
    ) -> Result<(), BftError> {
        let (epoch, view, block_hash) = {
            let state = self
                .pipeline
                .get(&height)
                .ok_or(BftError::UnknownHeight(height))?;
            (
                state.proposal.epoch,
                state.proposal.view,
                state.proposal.block_hash,
            )
        };
        let digest = execution_commitment_digest(epoch, view, height, block_hash, execution_root);
        if certificate.message != digest {
            return Err(BftError::InvalidExecutionCertificate(height));
        }
        self.committee
            .validator_set()
            .verify(certificate)
            .map_err(|_| BftError::InvalidExecutionCertificate(height))?;
        let state = self
            .pipeline
            .get_mut(&height)
            .ok_or(BftError::UnknownHeight(height))?;
        state.execution_root = Some(execution_root);
        state.execution_certified = true;
        Ok(())
    }

    /// The certified execution root for a height, if one has been attached.
    #[must_use]
    pub fn execution_root(&self, height: u64) -> Option<Hash> {
        self.pipeline.get(&height).and_then(|s| s.execution_root)
    }

    /// Admit a vote into the shared collector, detecting equivocation.
    pub fn add_vote(&mut self, vote: &Vote) -> Result<VoteOutcome, BftError> {
        Ok(self.collector.add_vote(&self.committee, vote)?)
    }

    /// Attempt to certify `height` for `phase`: forms a QC over the proposal's
    /// block and, on success, records it. In BFT mode the phases must chain
    /// (`Prepare -> PreCommit -> Commit`), a forked round refuses certification,
    /// a PreCommit QC installs a lock, and a Commit QC that conflicts with an
    /// already-certified block at the same height is a [`BftError::SafetyViolation`].
    /// Advancing to [`CommandStatus::Certified`] happens on the `Commit` QC.
    pub fn try_certify(
        &mut self,
        height: u64,
        phase: VotePhase,
    ) -> Result<Option<QuorumCertificate>, BftError> {
        let (epoch, view, block_hash) = {
            let state = self
                .pipeline
                .get(&height)
                .ok_or(BftError::UnknownHeight(height))?;
            (
                state.proposal.epoch,
                state.proposal.view,
                state.proposal.block_hash,
            )
        };

        if self.is_bft() {
            if self.round_forked(height, view) {
                return Err(BftError::ForkedRound { height, view });
            }
            self.require_chain(height, phase)?;
        }

        let digest = vote_digest(epoch, view, height, phase, block_hash);
        let Some(qc) = self.collector.try_form_qc(&self.committee, digest) else {
            return Ok(None);
        };

        if self.is_bft() {
            self.update_high_qc(view, height, block_hash);
            if phase == VotePhase::PreCommit {
                self.locked.insert(
                    height,
                    QcRef {
                        view,
                        height,
                        block: block_hash,
                    },
                );
            }
            if phase == VotePhase::Commit {
                if let Some(existing) = self
                    .pipeline
                    .get(&height)
                    .and_then(|s| s.certified_block)
                    .filter(|b| *b != block_hash)
                {
                    self.quorum_forks.push(Fork {
                        height,
                        view,
                        first_block: existing,
                        second_block: block_hash,
                    });
                    return Err(BftError::SafetyViolation { height });
                }
            }
        }

        let state = self
            .pipeline
            .get_mut(&height)
            .ok_or(BftError::UnknownHeight(height))?;
        match phase {
            VotePhase::Prepare => state.prepare_qc = Some(qc.clone()),
            VotePhase::PreCommit => state.precommit_qc = Some(qc.clone()),
            VotePhase::Commit => {
                state.commit_qc = Some(qc.clone());
                state.certified_block = Some(block_hash);
                if state.status.rank() < CommandStatus::Certified.rank() {
                    state.status = CommandStatus::Certified;
                }
            }
        }
        Ok(Some(qc))
    }

    fn round_forked(&self, height: u64, view: u64) -> bool {
        self.forks
            .iter()
            .any(|f| f.height == height && f.view == view)
    }

    fn require_chain(&self, height: u64, phase: VotePhase) -> Result<(), BftError> {
        let state = self
            .pipeline
            .get(&height)
            .ok_or(BftError::UnknownHeight(height))?;
        let chained = match phase {
            VotePhase::Prepare => true,
            VotePhase::PreCommit => state.prepare_qc.is_some(),
            VotePhase::Commit => state.precommit_qc.is_some(),
        };
        if chained {
            Ok(())
        } else {
            Err(BftError::PhaseNotChained { height, phase })
        }
    }

    fn update_high_qc(&mut self, view: u64, height: u64, block: Hash) {
        let better = self.high_qc.as_ref().is_none_or(|q| view > q.view);
        if better {
            self.high_qc = Some(QcRef {
                view,
                height,
                block,
            });
        }
    }

    /// Finalize a certified height, returning its finalized block hash. A height
    /// must hold a `Commit` quorum certificate. In BFT mode it must also have
    /// been executed and hold a certified execution commitment — a block can
    /// never be finalized without proof of the state it produced.
    pub fn finalize(&mut self, height: u64) -> Result<Hash, BftError> {
        let state = self
            .pipeline
            .get(&height)
            .ok_or(BftError::UnknownHeight(height))?;
        if state.commit_qc.is_none() {
            return Err(BftError::NotCertified(height));
        }
        if self.is_bft() && !state.execution_certified {
            return Err(BftError::MissingExecutionCertificate(height));
        }
        let block = state.proposal.block_hash;
        self.transition(height, CommandStatus::Finalized)?;
        self.chain.insert(height, block);
        Ok(block)
    }

    fn transition(&mut self, height: u64, to: CommandStatus) -> Result<(), BftError> {
        let state = self
            .pipeline
            .get_mut(&height)
            .ok_or(BftError::UnknownHeight(height))?;
        if to.rank() <= state.status.rank() {
            return Err(BftError::InvalidTransition {
                height,
                from: state.status,
                to,
            });
        }
        state.status = to;
        Ok(())
    }

    /// Current lifecycle status of a height.
    #[must_use]
    pub fn status(&self, height: u64) -> Option<CommandStatus> {
        self.pipeline.get(&height).map(|s| s.status)
    }

    /// The quorum certificate for a height, if certified (the highest phase QC
    /// formed).
    #[must_use]
    pub fn quorum_certificate(&self, height: u64) -> Option<&QuorumCertificate> {
        self.pipeline.get(&height).and_then(HeightState::highest_qc)
    }

    /// The proposal admitted at a height, if any.
    #[must_use]
    pub fn proposal(&self, height: u64) -> Option<&Proposal> {
        self.pipeline.get(&height).map(|s| &s.proposal)
    }

    /// Number of heights currently in the pipeline.
    #[must_use]
    pub fn pipeline_len(&self) -> usize {
        self.pipeline.len()
    }

    /// All detected forks (two conflicting proposals at the same height+view).
    #[must_use]
    pub fn forks(&self) -> &[Fork] {
        &self.forks
    }

    /// All detected quorum forks (conflicting *certified* blocks at a height —
    /// a Byzantine-quorum safety alarm; empty under an honest majority).
    #[must_use]
    pub fn quorum_forks(&self) -> &[Fork] {
        &self.quorum_forks
    }

    /// All detected vote equivocations.
    #[must_use]
    pub fn equivocations(&self) -> &[Equivocation] {
        self.collector.equivocations()
    }

    /// Serializable slash / equivocation evidence ready for gossip.
    #[must_use]
    pub fn slash_evidence(&self) -> &[SlashEvidence] {
        self.collector.slash_evidence()
    }

    /// Whether a validator is halted for prior equivocation / fork.
    #[must_use]
    pub fn is_offender_halted(&self, validator_index: u32) -> bool {
        self.collector.is_halted(validator_index)
    }

    /// Prune finalized heights below `finalized_height` from the pipeline while
    /// retaining locks, high-QC, and bounded slash evidence. Updates the vote
    /// collector admission window so stale/future messages are rejected cheaply.
    pub fn prune_finalized(&mut self, finalized_height: u64) {
        self.pipeline
            .retain(|&h, s| h >= finalized_height || s.status != CommandStatus::Finalized);
        // Drop chain entries well below the watermark (keep one parent for ancestry).
        let keep_from = finalized_height.saturating_sub(1);
        self.chain.retain(|&h, _| h >= keep_from);
        self.locked.retain(|&h, _| h >= keep_from);
        let mut window = CollectorWindow::default_for(self.epoch());
        window.min_height = finalized_height;
        window.current_view = self.view;
        self.collector.set_window(window);
        self.collector.prune_finalized(finalized_height);
        self.timeouts.prune_below_view(self.view.saturating_sub(2));
    }

    /// Number of heights currently retained in the pipeline (observability).
    #[must_use]
    pub fn retained_pipeline(&self) -> usize {
        self.pipeline.len()
    }

    /// Schedule an explicit validator-set update to activate at its
    /// `activation_epoch` boundary.
    pub fn schedule_update(&mut self, update: ValidatorSetUpdate) {
        self.pending_update = Some(update);
    }

    /// Whether an update is pending.
    #[must_use]
    pub fn has_pending_update(&self) -> bool {
        self.pending_update.is_some()
    }

    /// Activate a scheduled update, transitioning into `new_epoch`.
    ///
    /// Requires a pending update whose `activation_epoch == new_epoch`. Installs
    /// the new committee, resets the view to 0, and clears the vote / timeout
    /// collectors and view-change justification so pre-boundary evidence cannot
    /// be counted against the new set. In-flight pipeline heights, locks, and
    /// fork/equivocation evidence are retained.
    pub fn activate_epoch(&mut self, new_epoch: u64) -> Result<(), BftError> {
        let update = self
            .pending_update
            .take()
            .ok_or(BftError::NoPendingUpdate)?;
        if update.activation_epoch != new_epoch {
            let activation = update.activation_epoch;
            self.pending_update = Some(update);
            return Err(BftError::WrongActivationEpoch {
                activation,
                requested: new_epoch,
            });
        }
        self.committee = Committee::new_bft(new_epoch, update.validators)?;
        self.view = 0;
        let mut window = CollectorWindow::default_for(new_epoch);
        window.current_view = 0;
        self.collector = crate::vote::VoteCollector::with_window(window);
        self.timeouts = TimeoutCollector::new();
        self.last_view_change = None;
        Ok(())
    }
}
