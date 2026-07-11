//! Leader-based, pipelined BFT lifecycle driver.
//!
//! [`BftEngine`] is a pure, synchronous state machine (no async, no I/O). It
//! ingests [`Proposal`]s and [`Vote`]s, forms quorum certificates through a
//! [`VoteCollector`], and advances a per-height pipeline through
//! `Accepted -> Executed -> Certified -> Finalized`. Multiple heights may be
//! in flight simultaneously, so certification of one height never stalls
//! execution of another.
//!
//! It also performs deterministic round-robin leader selection, view rotation
//! on timeout, explicit epoch / validator-set transitions, and fork detection
//! (two conflicting proposals at the same height+view).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crypto::{hash_domain, verify_ed25519, QuorumCertificate, Validator};
use types::Hash;

use crate::sequencer::CommandStatus;
use crate::vote::{Committee, Equivocation, Vote, VoteError, VoteOutcome, VotePhase};

/// Domain tag for proposal digests.
pub const DOMAIN_PROPOSAL: &[u8] = b"dexos:consensus:proposal:v1";

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

/// Per-height pipeline state.
#[derive(Debug, Clone)]
struct HeightState {
    proposal: Proposal,
    status: CommandStatus,
    qc: Option<QuorumCertificate>,
}

/// The pipelined BFT engine for one node.
#[derive(Debug, Clone)]
pub struct BftEngine {
    committee: Committee,
    view: u64,
    pipeline: BTreeMap<u64, HeightState>,
    collector: crate::vote::VoteCollector,
    forks: Vec<Fork>,
    pending_update: Option<ValidatorSetUpdate>,
}

impl BftEngine {
    /// Create an engine for `committee`, starting at view 0.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            view: 0,
            pipeline: BTreeMap::new(),
            collector: crate::vote::VoteCollector::new(),
            forks: Vec::new(),
            pending_update: None,
        }
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

    /// Rotate to the next view on a timeout, returning the new view. This
    /// deterministically advances the leader (sub-second failover in wall-clock
    /// terms; here it is a pure state transition).
    pub fn on_timeout(&mut self) -> u64 {
        self.view = self.view.wrapping_add(1);
        self.view
    }

    /// Receive a proposal. Validates the proposer is the deterministic leader
    /// and the signature is valid, then admits it — unless a different block was
    /// already proposed at the same height+view, which is flagged as a fork.
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
                return Ok(ProposalOutcome::Forked(fork));
            }
        }

        self.pipeline.insert(
            proposal.height,
            HeightState {
                proposal,
                status: CommandStatus::Accepted,
                qc: None,
            },
        );
        Ok(ProposalOutcome::Accepted)
    }

    /// Mark a height as executed. Pipelined: a height may be executed while
    /// earlier heights remain un-finalized.
    pub fn execute(&mut self, height: u64) -> Result<(), BftError> {
        self.transition(height, CommandStatus::Executed)
    }

    /// Admit a vote into the shared collector, detecting equivocation.
    pub fn add_vote(&mut self, vote: &Vote) -> Result<VoteOutcome, BftError> {
        Ok(self.collector.add_vote(&self.committee, vote)?)
    }

    /// Attempt to certify `height` for `phase`: forms a QC over the proposal's
    /// block and, on success, records it and advances the height to
    /// [`CommandStatus::Certified`]. Returns the QC if newly (or already) formed.
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
        let digest = crate::vote::vote_digest(epoch, view, height, phase, block_hash);
        let Some(qc) = self.collector.try_form_qc(&self.committee, digest) else {
            return Ok(None);
        };
        let state = self
            .pipeline
            .get_mut(&height)
            .ok_or(BftError::UnknownHeight(height))?;
        state.qc = Some(qc.clone());
        if state.status.rank() < CommandStatus::Certified.rank() {
            state.status = CommandStatus::Certified;
        }
        Ok(Some(qc))
    }

    /// Finalize a certified height, returning its finalized block hash. A height
    /// must hold a quorum certificate before it can finalize.
    pub fn finalize(&mut self, height: u64) -> Result<Hash, BftError> {
        let state = self
            .pipeline
            .get(&height)
            .ok_or(BftError::UnknownHeight(height))?;
        if state.qc.is_none() {
            return Err(BftError::NotCertified(height));
        }
        let block = state.proposal.block_hash;
        self.transition(height, CommandStatus::Finalized)?;
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

    /// The quorum certificate for a height, if certified.
    #[must_use]
    pub fn quorum_certificate(&self, height: u64) -> Option<&QuorumCertificate> {
        self.pipeline.get(&height).and_then(|s| s.qc.as_ref())
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

    /// All detected forks.
    #[must_use]
    pub fn forks(&self) -> &[Fork] {
        &self.forks
    }

    /// All detected vote equivocations.
    #[must_use]
    pub fn equivocations(&self) -> &[Equivocation] {
        self.collector.equivocations()
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
    /// the new committee, resets the view to 0, and clears the vote collector so
    /// pre-boundary votes cannot be counted against the new set. In-flight
    /// pipeline heights and fork/equivocation evidence are retained.
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
        self.collector = crate::vote::VoteCollector::new();
        Ok(())
    }
}
