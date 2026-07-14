//! The Minimmit replica: a clock-free reactor `step(Input) -> Vec<Effect>`
//! (`docs/CONSENSUS_MINIMMIT.md` §5, §7, #521).
//!
//! The node/network layer injects inputs into a single pure transition function
//! and
//! discrete [`Input`]s and executes the returned [`Effect`]s. The core never
//! reads a clock, never sleeps, never does I/O, and **never invokes
//! callbacks** — given the same ordered `Input` sequence it produces the same
//! `Effect` sequence and the same finalized chain on every node/arch.
//!
//! # The two I/O seams (resolved here, §7.1–§7.2)
//!
//! - **Propose-build seam:** leaders do not build blocks in-core. Entering a
//!   view this replica leads emits [`Effect::NeedProposal`]; the node builds
//!   the [`BlockHeader`] deterministically, signs
//!   `notarize_sig` + `propose_sig`, and re-injects the result as
//!   `Input::Message(Propose)` — so the leader's own propose flows through
//!   the same admission/tally path as everyone else's and its implicit
//!   notarize lands in the same tally (R1).
//! - **Verify-injection seam:** block validity is checked OUTSIDE the core.
//!   On a `Propose` passing the stateless guards the core buffers the pending
//!   proposal; the node runs `verify(block, parent_hash)` and injects the
//!   verdict as data via [`Input::ProposalVerified`]. R2 completes on that
//!   input — `step()` never calls a stored verify closure.
//!
//! # Genesis bootstrap (resolved here, §6.5)
//!
//! The genesis block (height 0, well-known `genesis_hash`) is injected at
//! construction and is finalized by definition: `chain[0] = genesis_hash`,
//! `finalized_tip = (⊥, genesis_hash)` — no proof object exists for it.
//! [`MinimmitReplica::new`] behaves like `enter_view(0)`: it returns the
//! bootstrap effects `ArmTimer { view: 0 }` (plus `NeedProposal` with the
//! `{ genesis_hash, ⊥ }` parent when this replica leads view 0) alongside the
//! replica, so no wall-clock or build decision ever happens in-core.
//!
//! # Phase 2 rule surface
//!
//! This module owns the state shape, the enums, the constructor, the `step`
//! reactor (#521), the locking predicates + view lifecycle
//! (#522): [`MinimmitReplica::select_parent`] /
//! [`MinimmitReplica::valid_parent`] (§6.3–§6.4, the safety core) and the
//! internal `enter_view` / `prune`
//! transitions (§6.2, §6.6) the rules drive — and the two-tally vote
//! machinery (#523): the **strictly separate** notarize / nullify [`Tally`]
//! maps with `(validator_index, epoch, view)`-scoped equivocation detection
//! (so R6's legitimate notarize + nullify in one view is never mis-flagged
//! as double-signing), the per-validator DoS vote quota re-derived for the
//! block-less nullify dimension, and **threshold-parameterized** certificate
//! formation ([`MinimmitReplica::try_form_notarization`] /
//! [`MinimmitReplica::try_form_nullification`] — never a single hardcoded
//! threshold, §12 risk 3), rules R1–R7 (#524–#526), the safety oracles (#527),
//! the mandatory execution-certificate ladder (#528), and atomic epoch
//! rotation (#529).

use std::collections::{BTreeMap, BTreeSet};

use crypto::KeyPair;
use types::Hash;

use crate::bft::ValidatorSetUpdate;
use crate::vote::{
    Equivocation, SlashEvidence, SlashKind, VoteError, DEFAULT_VIEW_HORIZON, DEFAULT_VOTE_QUOTA,
};

use super::block::BlockHeader;
use super::committee::{Certificate, MinimmitCommittee, ThresholdKind};
use super::digest::{notarize_digest, nullify_digest};
use super::wire::{
    ConsensusMessage, ExecAttest, Notarization, Notarize, Nullification, Nullify, ParentRef, Proof,
    Propose, BOTTOM_VIEW,
};

/// An event injected into the replica by the node/network driver
/// (`docs/CONSENSUS_MINIMMIT.md` §7).
///
/// Every nondeterministic concern — message delivery, the 2Δ timer, the
/// re-dissemination cadence, block validity — enters the core as one of these
/// discrete variants. Replaying the same ordered `Input` sequence replays the
/// exact same [`Effect`] sequence.
// A delivered wire message dwarfs the fixed-size timer/verdict variants; the
// spec locks the `Message(ConsensusMessage)` shape (§7), so the disparity is
// inherent to the protocol input shape.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// A consensus message delivered by the network (or the node re-injecting
    /// the leader's own built-and-signed `Propose`, §7.2).
    Message(ConsensusMessage),
    /// The node's 2Δ OS timer for `view` expired (armed by
    /// [`Effect::ArmTimer`]). Stale fires for superseded views are guard
    /// no-ops (R3, #524).
    TimerFired {
        /// The view the expired timer was armed for.
        view: u64,
    },
    /// The periodic driver pulse for re-dissemination (R7, #525). Cadence is
    /// a node concern: it changes *when* proofs go out, never finalized state.
    Tick,
    /// The node-side `verify(block, parent_hash)` verdict for a buffered
    /// proposal, entering as **data** (§7.1). R2 completes on this input
    /// (#524); `valid: false` drops the pending proposal.
    ProposalVerified {
        /// The view of the buffered proposal the verdict is for.
        view: u64,
        /// Hash of the verified (or rejected) block.
        block_hash: Hash,
        /// Whether the block passed the node's validity check.
        valid: bool,
    },
}

/// An action the node must execute on the replica's behalf
/// (`docs/CONSENSUS_MINIMMIT.md` §7).
///
/// The core only ever *returns* these — it performs none of them. The split
/// between [`Effect::ConsensusFinal`] (ordering-agreement: L-notarization
/// reached) and [`Effect::Finalized`] (state-agreement: the exec L-cert also
/// landed) is deliberate and mandatory (§10): a consumer can distinguish
/// consensus-final from execution-final, and the ladder between them is
/// monotone per height.
#[derive(Debug, Clone, PartialEq, Eq)]
// Certificates keep quorum signatures inline so forming and relaying consensus
// effects never allocates. Boxing the broadcast variant would defeat that
// hot-path guarantee.
#[allow(clippy::large_enum_variant)]
pub enum Effect {
    /// Send a consensus message to every peer.
    Broadcast(ConsensusMessage),
    /// Arm the 2Δ OS timer for `view` (`delta_ms` config knob, §13.4); on
    /// expiry the node injects [`Input::TimerFired`] for the same view.
    ArmTimer {
        /// The view the timer guards.
        view: u64,
    },
    /// Cancel the timer for `view` (a certificate formed or was ingested; a
    /// late fire would be a harmless guard no-op, but cancelling keeps
    /// traffic clean).
    CancelTimer {
        /// The view whose timer is obsolete.
        view: u64,
    },
    /// This replica leads the entered view: the node must build a
    /// [`BlockHeader`] extending `parent`, sign it, and
    /// re-inject it as `Input::Message(Propose)` (§7.2, R1).
    NeedProposal {
        /// The notarized parent (or genesis `⊥`) the proposal must extend.
        parent: ParentRef,
    },
    /// L-notarization reached for `block` at `height`: ordering is final
    /// (§10). The height is now *exec-pending*; [`Effect::Finalized`] follows
    /// only after the exec L-cert lands (#528).
    ConsensusFinal {
        /// The consensus-final block.
        block: Hash,
        /// Its chain height.
        height: u64,
    },
    /// The exec L-cert landed for a consensus-final `block`: the height is
    /// fully final (§10). Never emitted without a prior
    /// [`Effect::ConsensusFinal`] for the same height.
    Finalized {
        /// The finalized block.
        block: Hash,
        /// Its chain height.
        height: u64,
    },
    /// Slashable misbehavior was detected (equivocation / proposal fork);
    /// the node gossips the evidence.
    Slash(SlashEvidence),
}

/// Monotone per-height finality state (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
// The execution certificate intentionally remains inline for the same
// allocation-free finality handoff guaranteed by `Effect` above.
#[allow(clippy::large_enum_variant)]
pub enum FinalityStage {
    /// An L-notarization fixed ordering, but the execution L-certificate has
    /// not yet arrived.
    ConsensusFinal { view: u64, block: Hash },
    /// Both the ordering and execution L-certificates exist.
    Finalized {
        view: u64,
        block: Hash,
        execution_root: Hash,
        execution_cert: Certificate,
    },
}

/// A deterministic epoch-rotation rejection. The pending update is retained
/// after every error so the node may retry once the activation gate clears.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EpochError {
    #[error("no validator-set update is scheduled")]
    NoPendingUpdate,
    #[error("scheduled update activates at epoch {activation}, not {requested}")]
    WrongActivationEpoch { activation: u64, requested: u64 },
    #[error("pre-boundary consensus-final heights are still awaiting execution certificates")]
    ExecutionCertificatesPending,
    #[error("new validator set is invalid: {0}")]
    InvalidCommittee(VoteError),
    #[error("this replica is not a member of the new validator set")]
    ReplicaRemoved,
}

/// The result of admitting one vote into a [`Tally`] (#523).
///
/// An equivocation verdict carries the raw first-vote materials instead of a
/// pre-built [`crate::vote::Equivocation`]: Minimmit votes have no
/// height/phase dimensions, so the rules that observe the verdict (#524–#526)
/// assemble the [`SlashEvidence`] they emit from the conflicting vote they
/// hold plus these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TallyOutcome {
    /// A new, valid, distinct vote was recorded.
    Accepted,
    /// The identical vote was already present (idempotent).
    Duplicate,
    /// The validator already voted for a **different** candidate in this
    /// tally's `(epoch, view)` scope. Nothing was recorded; replica-level
    /// admission halts the offender and purges their votes everywhere.
    Equivocated {
        /// The candidate (block hash, or nullify digest) first voted for.
        first: Hash,
        /// The signature over the first vote's digest — with the conflicting
        /// vote's signature, the two-sided proof of double-signing.
        first_signature: [u8; 64],
    },
}

/// A per-round vote tally: one instance per `(kind, view)` — or per height
/// for the exec dimension (#528) — holding candidate-keyed signer maps with
/// per-validator dedup and in-tally equivocation detection (#523).
///
/// The *candidate* is whatever distinguishes conflicting votes inside one
/// tally: a notarize tally keys by `block_hash` (several blocks can compete
/// in a view), a nullify tally keys by the single nullify digest (a nullify
/// names no block, so there is nothing to conflict with). Because the
/// notarize and nullify tallies are **strictly separate instances**, R6's
/// legitimate notarize + nullify in one view can never be flagged as
/// double-signing — the equivocation index only ever sees same-kind votes
/// (`docs/CONSENSUS_MINIMMIT.md` §8, §12).
///
/// Equivocation is keyed by `validator_index` alone because a tally instance
/// is already scoped to one `(epoch, view)`: this is the
/// `(validator_index, epoch, view)` round key (§5); height and phase dimensions
/// are absent.
///
/// Signatures are **not** verified here: replica admission
/// ([`MinimmitReplica::admit_notarize`] / [`MinimmitReplica::admit_nullify`])
/// verifies each exactly once before recording, and
/// [`MinimmitCommittee::verify`] re-checks any assembled certificate
/// end-to-end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    /// candidate -> (validator_index -> signature); `BTreeMap` for
    /// deterministic iteration and ascending signer packing.
    votes: BTreeMap<Hash, BTreeMap<u16, [u8; 64]>>,
    /// validator -> first `(candidate, signature)` admitted — the
    /// equivocation index for this tally's `(epoch, view)` scope.
    seen: BTreeMap<u16, (Hash, [u8; 64])>,
}

impl Tally {
    /// Record one pre-verified vote for `candidate`.
    ///
    /// `within_quota` is the caller's per-validator DoS verdict: when
    /// `false`, a vote that would retain a **new** entry is rejected
    /// fail-closed — verdicts that retain nothing new (duplicates,
    /// equivocation) are unaffected, and nothing already admitted is ever
    /// wiped.
    ///
    /// Returns [`TallyOutcome::Equivocated`] — recording **nothing** — when
    /// the validator already voted for a different candidate in this tally.
    /// The caller owns the follow-up: replica admission halts the offender
    /// and purges their votes across every tally.
    ///
    /// # Errors
    ///
    /// [`VoteError::QuotaExceeded`] when the vote is new and `within_quota`
    /// is `false`.
    pub fn admit(
        &mut self,
        validator_index: u16,
        candidate: Hash,
        signature: [u8; 64],
        within_quota: bool,
    ) -> Result<TallyOutcome, VoteError> {
        if let Some(&(first, first_signature)) = self.seen.get(&validator_index) {
            if first != candidate {
                return Ok(TallyOutcome::Equivocated {
                    first,
                    first_signature,
                });
            }
            if self
                .votes
                .get(&candidate)
                .is_some_and(|per| per.contains_key(&validator_index))
            {
                return Ok(TallyOutcome::Duplicate);
            }
        }
        if !within_quota {
            return Err(VoteError::QuotaExceeded(u32::from(validator_index)));
        }
        self.seen.insert(validator_index, (candidate, signature));
        self.votes
            .entry(candidate)
            .or_default()
            .insert(validator_index, signature);
        Ok(TallyOutcome::Accepted)
    }

    /// Attempt to form a [`Certificate`] for `candidate` at one of the two
    /// Minimmit bars — **threshold-parameterized** cert formation (#523).
    ///
    /// `message` is what the certificate signs (`cert.message`): the
    /// notarize / nullify digest the tallied votes signed. The same tally
    /// answers both bars over the same retained votes — [`ThresholdKind`]
    /// selects [`MinimmitCommittee::advance_threshold`] (`M`) or
    /// [`MinimmitCommittee::finalize_threshold`] (`L`); nothing here ever
    /// consults a single hardcoded threshold, which is exactly the
    /// silent-collapse regression this parameterization exists to prevent
    /// (`docs/CONSENSUS_MINIMMIT.md` §12 risk 3).
    ///
    /// Returns `Some(certificate)` iff the summed signer weight meets the
    /// selected bar. Signatures were verified once at admission and are not
    /// re-verified here (hot path); [`MinimmitCommittee::verify`] re-checks
    /// an assembled certificate end-to-end.
    #[must_use]
    pub fn try_form(
        &self,
        committee: &MinimmitCommittee,
        candidate: Hash,
        message: Hash,
        kind: ThresholdKind,
    ) -> Option<Certificate> {
        let per = self.votes.get(&candidate)?;
        let threshold = match kind {
            ThresholdKind::Advance => committee.advance_threshold(),
            ThresholdKind::Finalize => committee.finalize_threshold(),
        };
        let mut weight: u64 = 0;
        let mut signers: Vec<(u16, [u8; 64])> = Vec::with_capacity(per.len());
        for (&index, &signature) in per {
            // Admission bounds indices to the committee; fail closed if not.
            weight = weight.saturating_add(committee.weight(index)?);
            signers.push((index, signature));
        }
        if weight < threshold {
            return None;
        }
        committee.assemble(message, &signers).ok()
    }

    /// Signed weight currently tallied for `candidate`.
    #[must_use]
    pub fn weight_for(&self, committee: &MinimmitCommittee, candidate: Hash) -> u64 {
        self.votes
            .get(&candidate)
            .map(|per| {
                per.keys()
                    .filter_map(|&i| committee.weight(i))
                    .fold(0u64, u64::saturating_add)
            })
            .unwrap_or(0)
    }

    /// candidate -> (validator_index -> signature): the raw signer maps,
    /// read-only (R6's contradiction counting iterates these, #526).
    #[must_use]
    pub fn votes(&self) -> &BTreeMap<Hash, BTreeMap<u16, [u8; 64]>> {
        &self.votes
    }

    /// Remove every retained vote of `validator_index` from this tally.
    ///
    /// The equivocation index keeps its entry: the tally remembers what the
    /// validator first signed, so a purged offender can never silently
    /// re-enter this tally un-flagged (replica admission additionally halts
    /// offenders outright).
    pub fn purge(&mut self, validator_index: u16) {
        for per in self.votes.values_mut() {
            per.remove(&validator_index);
        }
    }

    /// Whether this tally has recorded nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty() && self.seen.is_empty()
    }
}

/// The two strictly separate consensus-vote dimensions (#523); selects which
/// tally map an admitted vote lands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TallyKind {
    /// A [`Notarize`] vote: candidate = block hash.
    Notarize,
    /// A [`Nullify`] vote: candidate = the view's nullify digest.
    Nullify,
}

/// The pure, synchronous Minimmit replica state machine
/// (`docs/CONSENSUS_MINIMMIT.md` §5, #521).
///
/// No clock, no I/O, no async, no floats, no callbacks; all maps are
/// `BTreeMap` for deterministic iteration. Drive it exclusively through
/// [`Self::step`] — the old external view-change surface (`on_timeout` /
/// `advance_view`) does **not** carry over, and any caller driving views
/// externally would double-advance (§7.3).
#[derive(Debug, Clone)]
pub struct MinimmitReplica {
    /// Current epoch (validator-set generation).
    epoch: u64,
    /// The dual-threshold committee for `epoch` (§5.1).
    committee: MinimmitCommittee,
    /// This replica's index in the committee's canonical membership order.
    self_index: u16,
    /// Local consensus signing key. `None` is supported for read-only replay;
    /// a voting replica is constructed with [`Self::new_with_signer`].
    signer: Option<KeyPair>,
    /// The well-known genesis hash (height 0, finalized by definition).
    genesis_hash: Hash,
    /// Current view; starts at 0.
    view: u64,
    /// Block this replica notarized THIS view (`None` = ⊥).
    notarized: Option<Hash>,
    /// Whether this replica nullified THIS view.
    nullified: bool,
    /// Statelessly admitted proposals awaiting node-side block verification.
    pending_proposals: BTreeMap<u64, Propose>,
    /// First authenticated proposal observed per view, retained to produce
    /// proposal-fork evidence even after its verification verdict arrives.
    seen_proposals: BTreeMap<u64, Propose>,
    /// Authenticated block metadata indexed by hash, retained for ancestry
    /// traversal when an L-notarization finalizes a tip and its ancestors.
    blocks: BTreeMap<Hash, (u64, BlockHeader)>,
    /// view -> the single chosen proof (notarization or nullification).
    proofs: BTreeMap<u64, Proof>,
    /// view -> per-block notarize tally (candidates keyed by block hash).
    notarize_votes: BTreeMap<u64, Tally>,
    /// view -> nullify tally, STRICTLY separate from notarize — the split is
    /// what keeps R6 non-slashable (§12, #523).
    nullify_votes: BTreeMap<u64, Tally>,
    /// height -> exec-attestation tally toward the exec L-cert (fed by #528).
    exec_votes: BTreeMap<u64, Tally>,
    /// First execution attestation candidate retained per height/digest.
    exec_candidates: BTreeMap<(u64, Hash), ExecAttest>,
    /// Fully assembled execution L-certificates, parked until the matching
    /// block becomes consensus-final when attestations arrive first.
    exec_certificates: BTreeMap<u64, (Hash, Certificate)>,
    /// Per-height monotone consensus-final -> fully-finalized ladder.
    finality: BTreeMap<u64, FinalityStage>,
    /// Proof views already emitted by R7 on a periodic tick.
    redisseminated: BTreeSet<u64>,
    /// Validator-set update waiting for explicit boundary activation.
    pending_update: Option<ValidatorSetUpdate>,
    /// The highest prune horizon applied: votes for views below it are
    /// outside the admission window; the watermark is view-scoped (#523).
    view_floor: u64,
    /// validator -> retained vote entries across the notarize + nullify
    /// tallies, for the per-validator DoS quota (#523).
    per_validator: BTreeMap<u16, usize>,
    /// Validators halted for in-tally equivocation: their retained votes are
    /// purged and their future votes rejected fail-closed (#523).
    halted: BTreeSet<u16>,
    /// Max retained vote entries per validator
    /// ([`DEFAULT_VOTE_QUOTA`]-shaped, fail-closed; excess votes are
    /// rejected, nothing already admitted is wiped).
    vote_quota: usize,
    /// Highest L-finalized block as `(view, hash)`; genesis is
    /// `(⊥ = BOTTOM_VIEW, genesis_hash)` — no proof object exists for it.
    finalized_tip: (u64, Hash),
    /// height -> finalized block hash; seeded with `chain[0] = genesis_hash`.
    chain: BTreeMap<u64, Hash>,
}

impl MinimmitReplica {
    /// Construct a fresh replica at `view 0` of `epoch`, returning it
    /// together with the bootstrap effects (§6.5).
    ///
    /// Construction behaves like `enter_view(0)`: the returned effects carry
    /// `ArmTimer { view: 0 }` and — when `committee.leader(0) == self_index` —
    /// `NeedProposal` with the start-of-chain parent `{ genesis_hash, ⊥ }`
    /// (before any `Propose` exists, `select_parent(0)` can only name
    /// genesis). The genesis block is finalized by definition:
    /// `chain[0] = genesis_hash` and `finalized_tip = (⊥, genesis_hash)`.
    ///
    /// `epoch` is the replica's current epoch and normally equals
    /// `committee.epoch()`; it is bound into every digest so votes cannot
    /// cross an epoch boundary (§4.1). Epoch rotation is #529.
    ///
    /// # Errors
    ///
    /// [`VoteError::ForeignSigner`] when `self_index` is outside the
    /// committee — a replica must be a member to vote.
    pub fn new(
        committee: MinimmitCommittee,
        self_index: u16,
        genesis_hash: Hash,
        epoch: u64,
    ) -> Result<(Self, Vec<Effect>), VoteError> {
        if usize::from(self_index) >= committee.len() {
            return Err(VoteError::ForeignSigner(u32::from(self_index)));
        }
        let mut chain = BTreeMap::new();
        chain.insert(0u64, genesis_hash);
        let replica = Self {
            epoch,
            committee,
            self_index,
            signer: None,
            genesis_hash,
            view: 0,
            notarized: None,
            nullified: false,
            pending_proposals: BTreeMap::new(),
            seen_proposals: BTreeMap::new(),
            blocks: BTreeMap::new(),
            proofs: BTreeMap::new(),
            notarize_votes: BTreeMap::new(),
            nullify_votes: BTreeMap::new(),
            exec_votes: BTreeMap::new(),
            exec_candidates: BTreeMap::new(),
            exec_certificates: BTreeMap::new(),
            finality: BTreeMap::new(),
            redisseminated: BTreeSet::new(),
            pending_update: None,
            view_floor: 0,
            per_validator: BTreeMap::new(),
            halted: BTreeSet::new(),
            vote_quota: DEFAULT_VOTE_QUOTA,
            finalized_tip: (BOTTOM_VIEW, genesis_hash),
            chain,
        };
        // The §6.5 bootstrap IS the §6.2 view-entry path at view 0: with no
        // proofs yet, `select_parent(0)` can only name `{ genesis_hash, ⊥ }`.
        let effects = replica.view_entry_effects(0);
        Ok((replica, effects))
    }

    /// Construct a voting replica with its local ed25519 consensus key.
    ///
    /// The key must match `committee[self_index]`. Keeping signing inside the
    /// pure reactor is deterministic and avoids introducing a callback into
    /// `step`; the node still owns block building and block verification.
    pub fn new_with_signer(
        committee: MinimmitCommittee,
        self_index: u16,
        genesis_hash: Hash,
        epoch: u64,
        signer: KeyPair,
    ) -> Result<(Self, Vec<Effect>), VoteError> {
        let expected = committee
            .public_key(self_index)
            .ok_or(VoteError::ForeignSigner(u32::from(self_index)))?;
        if expected != signer.public() {
            return Err(VoteError::InvalidSignature);
        }
        let (mut replica, effects) = Self::new(committee, self_index, genesis_hash, epoch)?;
        replica.signer = Some(signer);
        Ok((replica, effects))
    }

    /// The single reactor entry point: apply one [`Input`], return the
    /// [`Effect`]s the node must execute (§7).
    ///
    /// Pure and deterministic: the same ordered `Input` sequence yields the
    /// same `Effect` sequence and the same finalized chain, because 2Δ,
    /// delivery order, and tick cadence are inputs — never core decisions.
    /// No arm invokes a callback; verify verdicts arrive as
    /// [`Input::ProposalVerified`] data (§7.1).
    ///
    /// All Phase 2 rule arms are implemented here: R1–R7, execution-certified
    /// finality, and explicit epoch rotation.
    pub fn step(&mut self, input: Input) -> Vec<Effect> {
        match input {
            Input::Message(message) => self.on_message(message),
            Input::TimerFired { view } => self.on_timer_fired(view),
            Input::Tick => self.on_tick(),
            Input::ProposalVerified {
                view,
                block_hash,
                valid,
            } => self.on_proposal_verified(view, block_hash, valid),
        }
    }

    /// Dispatch a delivered (or self-re-injected, §7.2) consensus message.
    fn on_message(&mut self, message: ConsensusMessage) -> Vec<Effect> {
        match message {
            // R1 self-admission + R2 stateless guards and buffering (#524).
            ConsensusMessage::Propose(propose) => self.on_propose(propose),
            // R4 form path: tally, M-cert assembly, L finalization (#523, #525).
            ConsensusMessage::Notarize(notarize) => self.on_notarize(notarize),
            // R5 form path + R6 contradiction observation (#523, #525, #526).
            ConsensusMessage::Nullify(nullify) => self.on_nullify(nullify),
            // R4 ingest path: verified inbound notarization (#525).
            ConsensusMessage::Notarization(notarization) => {
                self.on_notarization(notarization, false)
            }
            // R5 ingest path: verified inbound nullification (#525).
            ConsensusMessage::Nullification(nullification) => {
                self.on_nullification(nullification, false)
            }
            // Exec-attestation tally toward the exec L-cert (#528).
            ConsensusMessage::ExecAttest(attest) => self.on_exec_attest(attest),
        }
    }

    /// The node's 2Δ timer for `view` expired — R3 nullify-by-timeout (#524).
    /// Stale fires for superseded views are guard no-ops.
    fn on_timer_fired(&mut self, view: u64) -> Vec<Effect> {
        if view != self.view || self.notarized.is_some() || self.nullified {
            return Vec::new();
        }
        let Some(signer) = self.signer.as_ref() else {
            return Vec::new();
        };
        let mut vote = Nullify {
            epoch: self.epoch,
            view,
            validator_index: self.self_index,
            signature: [0; 64],
        };
        vote.signature = signer.sign(vote.digest().as_bytes());
        self.nullified = true;
        let mut effects = vec![Effect::Broadcast(ConsensusMessage::Nullify(vote.clone()))];
        effects.extend(self.on_nullify(vote));
        effects
    }

    /// Periodic driver pulse — R7 proof re-dissemination (#525).
    fn on_tick(&mut self) -> Vec<Effect> {
        let floor = self.view.saturating_sub(DEFAULT_VIEW_HORIZON);
        let views: Vec<u64> = self
            .proofs
            .range(floor..=self.view)
            .map(|(&view, _)| view)
            .filter(|view| !self.redisseminated.contains(view))
            .collect();
        let mut effects = Vec::with_capacity(views.len());
        for view in views {
            let Some(proof) = self.proofs.get(&view).cloned() else {
                continue;
            };
            self.redisseminated.insert(view);
            let message = match proof {
                Proof::Notarization(value) => ConsensusMessage::Notarization(value),
                Proof::Nullification(value) => ConsensusMessage::Nullification(value),
            };
            effects.push(Effect::Broadcast(message));
        }
        effects
    }

    /// Node-side block-validity verdict for a buffered proposal — completes
    /// R2 (§7.1, #524).
    fn on_proposal_verified(&mut self, view: u64, block_hash: Hash, valid: bool) -> Vec<Effect> {
        let Some(propose) = self.pending_proposals.remove(&view) else {
            return Vec::new();
        };
        if propose.block_hash != block_hash || !valid {
            return Vec::new();
        }
        self.blocks.insert(block_hash, (view, propose.block));
        if view != self.view {
            let l_proof = self.proofs.get(&view).and_then(|proof| match proof {
                Proof::Notarization(value) if value.block_hash == block_hash => {
                    Some(value.cert.clone())
                }
                _ => None,
            });
            if let Some(cert) = l_proof {
                if self
                    .committee
                    .verify(&cert, ThresholdKind::Finalize)
                    .is_ok()
                {
                    return self.consensus_finalize(view, block_hash);
                }
            }
            return Vec::new();
        }
        // Re-check the mutable guards: the timer may have fired while the
        // node verified the block.
        if self.notarized.is_some() || self.nullified || !self.valid_parent(view, &propose.parent) {
            return Vec::new();
        }

        let signature = if propose.proposer_index == self.self_index {
            propose.notarize_sig
        } else {
            let Some(signer) = self.signer.as_ref() else {
                return Vec::new();
            };
            signer.sign(propose.notarize_digest().as_bytes())
        };
        let vote = Notarize {
            epoch: self.epoch,
            view,
            block_hash,
            validator_index: self.self_index,
            signature,
        };
        self.notarized = Some(block_hash);
        let mut effects = if propose.proposer_index == self.self_index {
            vec![Effect::Broadcast(ConsensusMessage::Propose(
                propose.clone(),
            ))]
        } else {
            vec![Effect::Broadcast(ConsensusMessage::Notarize(vote.clone()))]
        };
        effects.extend(self.on_notarize(Notarize {
            epoch: propose.epoch,
            view: propose.view,
            block_hash,
            validator_index: propose.proposer_index,
            signature: propose.notarize_sig,
        }));
        if propose.proposer_index != self.self_index {
            effects.extend(self.on_notarize(vote));
        }
        effects
    }

    /// R1/R2 stateless proposal admission and verify-injection buffering.
    fn on_propose(&mut self, propose: Propose) -> Vec<Effect> {
        if propose.epoch != self.epoch
            || propose.view == BOTTOM_VIEW
            || propose.view > self.view
            || propose.proposer_index != self.committee.leader(propose.view)
            || propose.block.hash() != propose.block_hash
            || propose.block.parent_hash != propose.parent.parent_hash
        {
            return Vec::new();
        }
        let Some(key) = self.committee.cached_key(propose.proposer_index) else {
            return Vec::new();
        };
        if key
            .verify(propose.notarize_digest().as_bytes(), &propose.notarize_sig)
            .is_err()
            || key
                .verify(propose.auth_digest().as_bytes(), &propose.propose_sig)
                .is_err()
        {
            return Vec::new();
        }

        if let Some(first) = self.seen_proposals.get(&propose.view) {
            if first.block_hash == propose.block_hash {
                return Vec::new();
            }
            let evidence = Equivocation {
                validator_index: u32::from(propose.proposer_index),
                epoch: propose.epoch,
                view: propose.view,
                height: propose.block.height,
                first_block: first.block_hash,
                second_block: propose.block_hash,
                first_signature: Some(first.propose_sig),
                second_signature: Some(propose.propose_sig),
            };
            self.halt(propose.proposer_index);
            return vec![Effect::Slash(SlashEvidence {
                kind: SlashKind::ProposalFork,
                equivocation: Some(evidence),
                epoch: propose.epoch,
            })];
        }
        if propose.view < self.view {
            let matches_proof = self.proofs.get(&propose.view).is_some_and(
                |proof| matches!(proof, Proof::Notarization(value) if value.block_hash == propose.block_hash),
            );
            if matches_proof {
                self.seen_proposals.insert(propose.view, propose.clone());
                self.pending_proposals.insert(propose.view, propose);
            }
            return Vec::new();
        }
        if self.notarized.is_some()
            || self.nullified
            || !self.valid_parent(propose.view, &propose.parent)
        {
            return Vec::new();
        }
        self.seen_proposals.insert(propose.view, propose.clone());
        self.pending_proposals.insert(propose.view, propose);
        Vec::new()
    }

    /// R4 vote admission, M-certificate formation, and L finalization.
    fn on_notarize(&mut self, notarize: Notarize) -> Vec<Effect> {
        let outcome = match self.admit_notarize(&notarize) {
            Ok(outcome) => outcome,
            Err(_) => return Vec::new(),
        };
        let mut effects = Vec::new();
        if let TallyOutcome::Equivocated {
            first,
            first_signature,
        } = outcome
        {
            effects.push(self.vote_equivocation(&notarize, first, first_signature));
            return effects;
        }

        if let Some(cert) =
            self.try_form_notarization(notarize.view, notarize.block_hash, ThresholdKind::Advance)
        {
            let formed = Notarization {
                epoch: notarize.epoch,
                view: notarize.view,
                block_hash: notarize.block_hash,
                cert,
            };
            effects.extend(self.on_notarization(formed, true));
        }

        // R6 observes accepted, distinct contradicting notarize/nullify
        // senders even after the M proof for this view advanced other peers.
        effects.extend(self.maybe_nullify_by_contradiction(notarize.view));
        effects
    }

    /// R5 vote admission and M-nullification formation.
    fn on_nullify(&mut self, nullify: Nullify) -> Vec<Effect> {
        if self.admit_nullify(&nullify).is_err() {
            return Vec::new();
        }
        let mut effects = Vec::new();
        if let Some(cert) = self.try_form_nullification(nullify.view, ThresholdKind::Advance) {
            let formed = Nullification {
                epoch: nullify.epoch,
                view: nullify.view,
                cert,
            };
            effects.extend(self.on_nullification(formed, true));
        }
        effects.extend(self.maybe_nullify_by_contradiction(nullify.view));
        effects
    }

    /// Symmetric R4 form/ingest path. `formed_here` controls the one immediate
    /// certificate broadcast; later ticks provide bounded re-dissemination.
    fn on_notarization(&mut self, notarization: Notarization, formed_here: bool) -> Vec<Effect> {
        if notarization.epoch != self.epoch || notarization.verify(&self.committee).is_err() {
            return Vec::new();
        }
        let view = notarization.view;
        let block = notarization.block_hash;
        if self.proofs.get(&view).is_some_and(
            |proof| !matches!(proof, Proof::Notarization(value) if value.block_hash == block),
        ) {
            return Vec::new();
        }

        let mut effects = Vec::new();
        let incoming_is_l = self
            .committee
            .verify(&notarization.cert, ThresholdKind::Finalize)
            .is_ok();
        let existing_is_l = self.proofs.get(&view).is_some_and(|proof| match proof {
            Proof::Notarization(value) => self
                .committee
                .verify(&value.cert, ThresholdKind::Finalize)
                .is_ok(),
            Proof::Nullification(_) => false,
        });
        let is_new = !self.proofs.contains_key(&view);
        let is_upgrade = incoming_is_l && !existing_is_l;
        if is_new || is_upgrade {
            self.proofs
                .insert(view, Proof::Notarization(notarization.clone()));
            self.redisseminated.remove(&view);
            if is_new {
                effects.push(Effect::CancelTimer { view });
            }
            if formed_here {
                self.redisseminated.insert(view);
                effects.push(Effect::Broadcast(ConsensusMessage::Notarization(
                    notarization.clone(),
                )));
            }
            if is_new {
                effects.extend(self.enter_view(view.saturating_add(1)));
            }
        }

        if incoming_is_l {
            effects.extend(self.consensus_finalize(view, block));
        }
        effects
    }

    /// Symmetric R5 form/ingest path.
    fn on_nullification(&mut self, nullification: Nullification, formed_here: bool) -> Vec<Effect> {
        if nullification.epoch != self.epoch || nullification.verify(&self.committee).is_err() {
            return Vec::new();
        }
        let view = nullification.view;
        if self.proofs.contains_key(&view) {
            return Vec::new();
        }
        self.proofs
            .insert(view, Proof::Nullification(nullification.clone()));
        let mut effects = vec![Effect::CancelTimer { view }];
        if formed_here {
            self.redisseminated.insert(view);
            effects.push(Effect::Broadcast(ConsensusMessage::Nullification(
                nullification,
            )));
        }
        effects.extend(self.enter_view(view.saturating_add(1)));
        effects
    }

    fn vote_equivocation(&self, vote: &Notarize, first: Hash, first_signature: [u8; 64]) -> Effect {
        let height = self
            .blocks
            .get(&vote.block_hash)
            .map_or(0, |(_, block)| block.height);
        Effect::Slash(SlashEvidence {
            kind: SlashKind::NotarizeEquivocation,
            equivocation: Some(Equivocation {
                validator_index: u32::from(vote.validator_index),
                epoch: vote.epoch,
                view: vote.view,
                height,
                first_block: first,
                second_block: vote.block_hash,
                first_signature: Some(first_signature),
                second_signature: Some(vote.signature),
            }),
            epoch: vote.epoch,
        })
    }

    /// R6's non-slashable second vote: after this replica notarized `c`, a
    /// distinct M-weight union of nullifiers and notarizers for `c' != c`
    /// proves `c` cannot reach L.
    fn maybe_nullify_by_contradiction(&mut self, view: u64) -> Vec<Effect> {
        if view != self.view || self.nullified {
            return Vec::new();
        }
        let Some(ours) = self.notarized else {
            return Vec::new();
        };
        let mut contradictors = BTreeSet::new();
        if let Some(tally) = self.nullify_votes.get(&view) {
            for per in tally.votes().values() {
                contradictors.extend(per.keys().copied());
            }
        }
        if let Some(tally) = self.notarize_votes.get(&view) {
            for (&candidate, per) in tally.votes() {
                if candidate != ours {
                    contradictors.extend(per.keys().copied());
                }
            }
        }
        let weight = contradictors
            .into_iter()
            .filter_map(|index| self.committee.weight(index))
            .fold(0u64, u64::saturating_add);
        if weight < self.committee.advance_threshold() {
            return Vec::new();
        }
        let Some(signer) = self.signer.as_ref() else {
            return Vec::new();
        };
        let mut vote = Nullify {
            epoch: self.epoch,
            view,
            validator_index: self.self_index,
            signature: [0; 64],
        };
        vote.signature = signer.sign(vote.digest().as_bytes());
        self.nullified = true;
        let mut effects = vec![Effect::Broadcast(ConsensusMessage::Nullify(vote.clone()))];
        // The local R6 vote participates in R5 exactly once, but the split
        // tally deliberately prevents it from becoming slash evidence.
        if self.admit_nullify(&vote).is_ok() {
            if let Some(cert) = self.try_form_nullification(view, ThresholdKind::Advance) {
                effects.extend(self.on_nullification(
                    Nullification {
                        epoch: self.epoch,
                        view,
                        cert,
                    },
                    true,
                ));
            }
        }
        effects
    }

    /// Turn an L-notarized tip into ordered, per-height consensus-final
    /// events, walking authenticated parent headers back to the existing
    /// chain. If metadata is still missing, finalization waits for proposal
    /// re-delivery rather than inventing a height.
    fn consensus_finalize(&mut self, view: u64, tip: Hash) -> Vec<Effect> {
        if self.finalized_tip.0 != BOTTOM_VIEW && view <= self.finalized_tip.0 {
            return Vec::new();
        }
        let mut cursor = tip;
        let mut path = Vec::new();
        loop {
            if self.chain.values().any(|known| *known == cursor) {
                break;
            }
            let Some(&(block_view, block)) = self.blocks.get(&cursor) else {
                return Vec::new();
            };
            path.push((block.height, block_view, cursor));
            cursor = block.parent_hash;
        }
        path.reverse();
        let mut effects = Vec::new();
        for (height, block_view, block) in path {
            if self.chain.get(&height).is_some_and(|known| *known != block) {
                return Vec::new();
            }
            if self.finality.contains_key(&height) {
                continue;
            }
            self.chain.insert(height, block);
            self.finality.insert(
                height,
                FinalityStage::ConsensusFinal {
                    view: block_view,
                    block,
                },
            );
            effects.push(Effect::ConsensusFinal { block, height });
            effects.extend(self.try_complete_finality(height));
        }
        self.finalized_tip = (view, tip);
        self.prune(view.saturating_sub(DEFAULT_VIEW_HORIZON));
        effects
    }

    /// Collect execution attestations at L and complete the mandatory
    /// execution-finality gate if ordering is already consensus-final.
    fn on_exec_attest(&mut self, attest: ExecAttest) -> Vec<Effect> {
        if attest.epoch != self.epoch || attest.verify(&self.committee).is_err() {
            return Vec::new();
        }
        let Some(&(view, block)) = self.blocks.get(&attest.block_hash) else {
            return Vec::new();
        };
        if view != attest.view || block.height != attest.height {
            return Vec::new();
        }
        let digest = attest.digest();
        let tally = self.exec_votes.entry(attest.height).or_default();
        let outcome = match tally.admit(attest.validator_index, digest, attest.signature, true) {
            Ok(outcome) => outcome,
            Err(_) => return Vec::new(),
        };
        if matches!(outcome, TallyOutcome::Equivocated { .. }) {
            self.halt(attest.validator_index);
            return Vec::new();
        }
        self.exec_candidates
            .entry((attest.height, digest))
            .or_insert(attest.clone());
        let Some(cert) = self.exec_votes.get(&attest.height).and_then(|tally| {
            tally.try_form(&self.committee, digest, digest, ThresholdKind::Finalize)
        }) else {
            return Vec::new();
        };
        if self
            .committee
            .verify(&cert, ThresholdKind::Finalize)
            .is_err()
        {
            return Vec::new();
        }
        self.exec_certificates
            .entry(attest.height)
            .or_insert((attest.execution_root, cert));
        self.try_complete_finality(attest.height)
    }

    fn try_complete_finality(&mut self, height: u64) -> Vec<Effect> {
        let Some((execution_root, execution_cert)) = self.exec_certificates.get(&height).cloned()
        else {
            return Vec::new();
        };
        let Some(FinalityStage::ConsensusFinal { view, block }) =
            self.finality.get(&height).cloned()
        else {
            return Vec::new();
        };
        self.finality.insert(
            height,
            FinalityStage::Finalized {
                view,
                block,
                execution_root,
                execution_cert,
            },
        );
        self.exec_votes.remove(&height);
        self.exec_candidates.retain(|(h, _), _| *h != height);
        vec![Effect::Finalized { block, height }]
    }

    // ─── Two-tally vote machinery (§5, §8 R4/R5 feed, #523) ───

    /// Admit a [`Notarize`] vote into its view's notarize tally — the R4
    /// tally feed the rule wiring drives (#524/#525).
    ///
    /// Checks run cheapest-first, the signature verified exactly **once**:
    /// epoch match, view window (`[view_floor, view + DEFAULT_VIEW_HORIZON]`
    /// — past views stay admissible down to the prune watermark because
    /// L-finalization keeps tallying after the view advanced at `M`),
    /// halted-offender, committee membership, signature over
    /// [`Notarize::digest`], then the tally bookkeeping: equivocation
    /// detection, dedup, and the per-validator quota.
    ///
    /// A conflicting notarize — same view, **different block** — returns
    /// [`TallyOutcome::Equivocated`] and halts the offender: every vote they
    /// retained (both dimensions) is purged and their future votes are
    /// rejected. A notarize plus a *nullify* in one view is **not**
    /// equivocation: the two dimensions are strictly separate tallies, which
    /// is what keeps R6 non-slashable (§8, §12).
    ///
    /// # Errors
    ///
    /// [`VoteError::EpochMismatch`], [`VoteError::OutsideWindow`],
    /// [`VoteError::HaltedOffender`], [`VoteError::ForeignSigner`],
    /// [`VoteError::InvalidSignature`], or [`VoteError::QuotaExceeded`] —
    /// all fail-closed, never retaining anything.
    pub fn admit_notarize(&mut self, notarize: &Notarize) -> Result<TallyOutcome, VoteError> {
        self.admit_vote(
            TallyKind::Notarize,
            notarize.epoch,
            notarize.view,
            notarize.validator_index,
            notarize.block_hash,
            notarize.signature,
        )
    }

    /// Admit a [`Nullify`] vote into its view's nullify tally — the R5
    /// tally feed the rule wiring drives (#524/#525).
    ///
    /// The nullify dimension is **block-less**: the candidate is the view's
    /// single nullify digest, so in-tally equivocation is impossible by
    /// construction and a duplicate is idempotent. The DoS exposure is the
    /// *view* dimension instead — one signed `Nullify` per admissible view
    /// with no block to bind — so the same admission window and
    /// per-validator quota bounds a flooder via [`DEFAULT_VOTE_QUOTA`] (§5, #523).
    ///
    /// Shares every check and failure mode of [`Self::admit_notarize`].
    ///
    /// # Errors
    ///
    /// As for [`Self::admit_notarize`].
    pub fn admit_nullify(&mut self, nullify: &Nullify) -> Result<TallyOutcome, VoteError> {
        self.admit_vote(
            TallyKind::Nullify,
            nullify.epoch,
            nullify.view,
            nullify.validator_index,
            nullify.digest(),
            nullify.signature,
        )
    }

    /// Threshold-parameterized notarization formation over `view`'s tally
    /// (#523): `Some(certificate)` iff the notarize weight for `block_hash`
    /// meets the bar `kind` selects.
    ///
    /// The **same tally** must form the M-cert
    /// ([`ThresholdKind::Advance`] ⇒ store the proof, advance the view, R4)
    /// and separately answer the L bar ([`ThresholdKind::Finalize`] ⇒
    /// finalize the block and its ancestors) — never a single hardcoded
    /// threshold, which would silently collapse the two-threshold protocol
    /// (§12 risk 3). The certificate's `message` is the notarize digest, so
    /// it slots directly into a
    /// [`Notarization`] wire message.
    #[must_use]
    pub fn try_form_notarization(
        &self,
        view: u64,
        block_hash: Hash,
        kind: ThresholdKind,
    ) -> Option<Certificate> {
        let digest = notarize_digest(self.epoch, view, block_hash);
        self.notarize_votes
            .get(&view)?
            .try_form(&self.committee, block_hash, digest, kind)
    }

    /// Threshold-parameterized nullification formation over `view`'s tally
    /// (#523): `Some(certificate)` iff the nullify weight meets the bar
    /// `kind` selects.
    ///
    /// R5 only ever forms at [`ThresholdKind::Advance`] (`M`) —
    /// finalization is exclusively an L-notarization concern — but the bar
    /// stays caller-selected: formation is threshold-parameterized across
    /// **both** dimensions, with no hardcoded bar anywhere (§12 risk 3).
    /// The certificate's `message` is the nullify digest, so it slots
    /// directly into a [`Nullification`] wire message.
    #[must_use]
    pub fn try_form_nullification(&self, view: u64, kind: ThresholdKind) -> Option<Certificate> {
        let digest = nullify_digest(self.epoch, view);
        self.nullify_votes
            .get(&view)?
            .try_form(&self.committee, digest, digest, kind)
    }

    /// The shared admission path behind [`Self::admit_notarize`] /
    /// [`Self::admit_nullify`] (#523): cheap checks, one signature
    /// verification, then tally bookkeeping with quota + halt follow-up.
    fn admit_vote(
        &mut self,
        kind: TallyKind,
        epoch: u64,
        view: u64,
        validator_index: u16,
        candidate: Hash,
        signature: [u8; 64],
    ) -> Result<TallyOutcome, VoteError> {
        if epoch != self.epoch {
            return Err(VoteError::EpochMismatch);
        }
        if view < self.view_floor || view > self.view.saturating_add(DEFAULT_VIEW_HORIZON) {
            return Err(VoteError::OutsideWindow);
        }
        if self.halted.contains(&validator_index) {
            return Err(VoteError::HaltedOffender(u32::from(validator_index)));
        }
        // Single cryptographic verification (cached key); the digest binds
        // (epoch, view[, block_hash]) so a vote can never be replayed into
        // another round.
        let digest = match kind {
            TallyKind::Notarize => notarize_digest(epoch, view, candidate),
            TallyKind::Nullify => nullify_digest(epoch, view),
        };
        let key = self
            .committee
            .cached_key(validator_index)
            .ok_or(VoteError::ForeignSigner(u32::from(validator_index)))?;
        key.verify(digest.as_bytes(), &signature)
            .map_err(|_| VoteError::InvalidSignature)?;

        let within_quota = self
            .per_validator
            .get(&validator_index)
            .copied()
            .unwrap_or(0)
            < self.vote_quota;
        let map = match kind {
            TallyKind::Notarize => &mut self.notarize_votes,
            TallyKind::Nullify => &mut self.nullify_votes,
        };
        let tally = map.entry(view).or_default();
        let result = tally.admit(validator_index, candidate, signature, within_quota);
        if result.is_err() && tally.is_empty() {
            // Never retain an empty tally created for a rejected vote: a
            // quota-exhausted flooder must not grow the view maps either.
            map.remove(&view);
        }
        let outcome = result?;
        match outcome {
            TallyOutcome::Accepted => {
                let count = self.per_validator.entry(validator_index).or_insert(0);
                *count = count.saturating_add(1);
            }
            TallyOutcome::Equivocated { .. } => self.halt(validator_index),
            TallyOutcome::Duplicate => {}
        }
        Ok(outcome)
    }

    /// Halt `validator_index` for in-tally equivocation: purge every vote
    /// they retained across **all** tallies (their weight never again counts
    /// toward a certificate) and reject their future votes fail-closed
    /// ([`VoteError::HaltedOffender`], #523).
    fn halt(&mut self, validator_index: u16) {
        self.halted.insert(validator_index);
        for tally in self.notarize_votes.values_mut() {
            tally.purge(validator_index);
        }
        for tally in self.nullify_votes.values_mut() {
            tally.purge(validator_index);
        }
        for tally in self.exec_votes.values_mut() {
            tally.purge(validator_index);
        }
        self.per_validator.remove(&validator_index);
    }

    // ─── Locking predicates & view lifecycle (§6.2–§6.4, §6.6, #522) ───

    /// Choose the parent a proposal for `view` must extend: walking back from
    /// `view − 1`, the first view whose proof is a `Notarization`, skipping
    /// views whose proof is a `Nullification`
    /// (`docs/CONSENSUS_MINIMMIT.md` §6.3).
    ///
    /// - Every view below `view` nullified (vacuously true at `view = 0`) ⇒
    ///   the start-of-chain parent `{ genesis_hash, ⊥ }`.
    /// - Any view in the walk with **no proof at all** ⇒ `None`: this replica
    ///   cannot propose yet and must wait for re-dissemination (R7, #525) to
    ///   fill the gap.
    ///
    /// `proofs` entries are trusted here — R4/R5 verify every certificate
    /// before insertion (#525), which is why R4 must populate `proofs` from
    /// BOTH self-formed and inbound `Notarization` certs.
    #[must_use]
    pub fn select_parent(&self, view: u64) -> Option<ParentRef> {
        // Walk the stored proofs downward from `view − 1`; `next_expected`
        // tracks the view the walk must see next, so any skipped-over key is
        // a proof gap. Scanning `proofs` (never `0..view` itself) keeps this
        // O(|proofs below view|) even for astronomically large views.
        let mut next_expected = view;
        for (&walked, proof) in self.proofs.range(..view).rev() {
            if walked + 1 != next_expected {
                // A view between `walked` and the walk position is
                // unresolved: neither notarized nor nullified.
                return None;
            }
            match proof {
                Proof::Notarization(notarization) => {
                    return Some(ParentRef {
                        parent_hash: notarization.block_hash,
                        parent_view: walked,
                    });
                }
                Proof::Nullification(_) => next_expected = walked,
            }
        }
        if next_expected == 0 {
            // The walk crossed every view down to 0 on nullifications alone
            // (or `view == 0`): the chain starts at genesis.
            Some(ParentRef::genesis(self.genesis_hash))
        } else {
            None
        }
    }

    /// Whether `parent` is an admissible parent linkage for a proposal in
    /// `view` — Minimmit's locking rule (`docs/CONSENSUS_MINIMMIT.md` §6.4).
    ///
    /// True iff **both** hold:
    ///
    /// 1. `proofs[parent.parent_view]` is a `Notarization` naming
    ///    `parent.parent_hash` — or the parent is `⊥` with
    ///    `parent.parent_hash == genesis_hash` (§4.2), and
    /// 2. every skipped view `j ∈ (parent.parent_view, view)` (exclusive both
    ///    ends) holds a `Nullification` in `proofs`; `⊥` orders below every
    ///    real view, so a `⊥` parent requires every `j ∈ [0, view)`
    ///    nullified.
    ///
    /// A missing proof, a notarized skipped view, or a non-`⊥` parent view at
    /// or above `view` all reject: a proposal may only skip views that
    /// provably went nowhere. Views at or below `parent.parent_view` are not
    /// consulted — the parent notarization's own linkage was checked when it
    /// formed (R2, #524).
    #[must_use]
    pub fn valid_parent(&self, view: u64, parent: &ParentRef) -> bool {
        // Requirement 1, which also fixes the skip interval's lower bound.
        let skipped_from = match parent.real_view() {
            None => {
                if parent.parent_hash != self.genesis_hash {
                    return false;
                }
                0
            }
            Some(parent_view) => {
                // A block extends a strictly earlier view (`⊥` was handled
                // above; `BOTTOM_VIEW` never reaches this arm).
                if parent_view >= view {
                    return false;
                }
                match self.proofs.get(&parent_view) {
                    Some(Proof::Notarization(notarization))
                        if notarization.block_hash == parent.parent_hash => {}
                    _ => return false,
                }
                parent_view + 1
            }
        };
        // Requirement 2: `[skipped_from, view)` must be contiguous
        // nullifications. One ordered scan over the stored keys detects both
        // failure modes — a gap (key jump) and a notarized skipped view.
        let mut expected = skipped_from;
        for (&skipped, proof) in self.proofs.range(skipped_from..view) {
            if skipped != expected || !matches!(proof, Proof::Nullification(_)) {
                return false;
            }
            expected = skipped + 1;
        }
        expected == view
    }

    /// Advance into view `next`: reset the per-view vote flags and arm the 2Δ
    /// timer (`docs/CONSENSUS_MINIMMIT.md` §6.2).
    ///
    /// Idempotent no-op for `next <= view` — a duplicate certificate for an
    /// already-left view never double-arms the timer. On a real advance the
    /// per-view flags reset (`notarized = None`, `nullified = false`) and the
    /// entry effects fire ([`Effect::ArmTimer`], plus
    /// [`Effect::NeedProposal`] on the leader path, §7.2). `CancelTimer` for
    /// the view being left is the **caller's** concern (R4/R5 emit it
    /// alongside the certificate, #525); a stale fire is an R3 guard no-op
    /// either way.
    fn enter_view(&mut self, next: u64) -> Vec<Effect> {
        if next <= self.view {
            return Vec::new();
        }
        self.view = next;
        self.notarized = None;
        self.nullified = false;
        self.view_entry_effects(next)
    }

    /// The effects entering `view` produces: `ArmTimer { view }`, plus
    /// `NeedProposal { parent }` when this replica leads `view` **and**
    /// [`Self::select_parent`] can already name the parent (§6.2, §7.2 — a
    /// leader with missing proofs stays silent and waits for R7 to fill the
    /// gap). Shared by [`Self::new`] (the §6.5 view-0 bootstrap) and
    /// [`Self::enter_view`].
    fn view_entry_effects(&self, view: u64) -> Vec<Effect> {
        let mut effects = vec![Effect::ArmTimer { view }];
        if self.committee.leader(view) == self.self_index {
            if let Some(parent) = self.select_parent(view) {
                effects.push(Effect::NeedProposal { parent });
            }
        }
        effects
    }

    /// Evict all view-keyed state strictly below `horizon`: `proofs`,
    /// `notarize_votes`, and `nullify_votes` drop every entry with
    /// `view < horizon`; entries at or above the horizon are never touched
    /// (`docs/CONSENSUS_MINIMMIT.md` §6.6).
    ///
    /// Called after finalization (R4, #525) with a
    /// [`DEFAULT_VIEW_HORIZON`]-style bound, so the maps stay
    /// bounded without dropping the proofs `select_parent` / `valid_parent`
    /// and R7 re-dissemination still need. The prune horizon becomes the
    /// admission watermark (`view_floor`): votes below it are rejected as
    /// [`VoteError::OutsideWindow`], and every evicted vote entry is
    /// released from its validator's DoS quota (#523). Deliberately exempt:
    /// `exec_votes` is keyed by **height**, not view, and prunes when its
    /// height finalizes (§10, #528); `chain` is the finalized chain itself
    /// and only ever grows.
    fn prune(&mut self, horizon: u64) {
        self.view_floor = self.view_floor.max(horizon);
        // `split_off(&horizon)` keeps exactly the keys `>= horizon` — one
        // O(log n) cut per map, deterministic by construction.
        self.proofs = self.proofs.split_off(&horizon);
        for map in [&mut self.notarize_votes, &mut self.nullify_votes] {
            let kept = map.split_off(&horizon);
            let evicted = std::mem::replace(map, kept);
            // Release the evicted entries from the per-validator quota so a
            // pruned view frees capacity in the admission quota.
            for tally in evicted.values() {
                for per in tally.votes().values() {
                    for index in per.keys() {
                        let emptied = match self.per_validator.get_mut(index) {
                            Some(count) => {
                                *count = count.saturating_sub(1);
                                *count == 0
                            }
                            None => false,
                        };
                        if emptied {
                            self.per_validator.remove(index);
                        }
                    }
                }
            }
        }
    }

    /// Schedule a validator-set update for an explicit epoch boundary.
    pub fn schedule_update(&mut self, update: ValidatorSetUpdate) {
        self.pending_update = Some(update);
    }

    /// Whether a validator-set update is waiting for activation.
    #[must_use]
    pub fn has_pending_update(&self) -> bool {
        self.pending_update.is_some()
    }

    /// Activate the scheduled unit-weight validator set at `new_epoch`.
    ///
    /// Activation is drain-before-swap: every consensus-final height must
    /// already have its old-committee execution L-certificate. The committee
    /// and local index are validated before any state changes, so failure is
    /// atomic and leaves the pending update installed.
    pub fn activate_epoch(&mut self, new_epoch: u64) -> Result<Vec<Effect>, EpochError> {
        let update = self
            .pending_update
            .as_ref()
            .ok_or(EpochError::NoPendingUpdate)?;
        if update.activation_epoch != new_epoch {
            return Err(EpochError::WrongActivationEpoch {
                activation: update.activation_epoch,
                requested: new_epoch,
            });
        }
        if self
            .finality
            .values()
            .any(|stage| matches!(stage, FinalityStage::ConsensusFinal { .. }))
        {
            return Err(EpochError::ExecutionCertificatesPending);
        }
        let committee = MinimmitCommittee::new_unit(new_epoch, update.validators.clone())
            .map_err(EpochError::InvalidCommittee)?;
        let new_index = if let Some(signer) = self.signer.as_ref() {
            committee
                .validators()
                .iter()
                .position(|validator| validator.public_key == signer.public())
                .and_then(|index| u16::try_from(index).ok())
                .ok_or(EpochError::ReplicaRemoved)?
        } else if usize::from(self.self_index) < committee.len() {
            self.self_index
        } else {
            return Err(EpochError::ReplicaRemoved);
        };

        self.pending_update = None;
        self.epoch = new_epoch;
        self.committee = committee;
        self.self_index = new_index;
        self.view = 0;
        self.notarized = None;
        self.nullified = false;
        self.pending_proposals.clear();
        self.seen_proposals.clear();
        self.proofs.clear();
        self.notarize_votes.clear();
        self.nullify_votes.clear();
        self.exec_votes.clear();
        self.exec_candidates.clear();
        self.exec_certificates.clear();
        self.redisseminated.clear();
        self.per_validator.clear();
        self.halted.clear();
        self.view_floor = 0;
        Ok(self.view_entry_effects(0))
    }

    /// The replica's current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The dual-threshold committee this replica votes in.
    #[must_use]
    pub fn committee(&self) -> &MinimmitCommittee {
        &self.committee
    }

    /// This replica's index in the committee's canonical membership order.
    #[must_use]
    pub fn self_index(&self) -> u16 {
        self.self_index
    }

    /// The well-known genesis hash injected at construction.
    #[must_use]
    pub fn genesis_hash(&self) -> Hash {
        self.genesis_hash
    }

    /// The current view (starts at 0).
    #[must_use]
    pub fn view(&self) -> u64 {
        self.view
    }

    /// The block this replica notarized in the current view, if any.
    #[must_use]
    pub fn notarized(&self) -> Option<Hash> {
        self.notarized
    }

    /// Whether this replica nullified the current view.
    #[must_use]
    pub fn nullified(&self) -> bool {
        self.nullified
    }

    /// view -> the single chosen proof (notarization or nullification).
    #[must_use]
    pub fn proofs(&self) -> &BTreeMap<u64, Proof> {
        &self.proofs
    }

    /// view -> per-block notarize tally (candidates keyed by block hash).
    #[must_use]
    pub fn notarize_votes(&self) -> &BTreeMap<u64, Tally> {
        &self.notarize_votes
    }

    /// view -> nullify tally, strictly separate from notarize — the split
    /// that keeps R6 non-slashable (§12, #523).
    #[must_use]
    pub fn nullify_votes(&self) -> &BTreeMap<u64, Tally> {
        &self.nullify_votes
    }

    /// height -> exec-attestation tally toward the exec L-cert (fed by
    /// #528).
    #[must_use]
    pub fn exec_votes(&self) -> &BTreeMap<u64, Tally> {
        &self.exec_votes
    }

    /// Per-height monotone ordering/execution finality state.
    #[must_use]
    pub fn finality(&self) -> &BTreeMap<u64, FinalityStage> {
        &self.finality
    }

    /// Total retained vote entries across the notarize + nullify tallies
    /// (observability; bounded per validator by the vote quota, #523).
    #[must_use]
    pub fn retained_votes(&self) -> usize {
        self.per_validator.values().sum()
    }

    /// Validators halted for in-tally equivocation: their retained votes
    /// were purged and their future votes are rejected
    /// ([`VoteError::HaltedOffender`], #523).
    #[must_use]
    pub fn halted_offenders(&self) -> &BTreeSet<u16> {
        &self.halted
    }

    /// Highest L-finalized `(view, block)`; genesis reports the
    /// [`BOTTOM_VIEW`] `⊥` sentinel because it was never proposed in a view.
    #[must_use]
    pub fn finalized_tip(&self) -> (u64, Hash) {
        self.finalized_tip
    }

    /// height -> finalized block hash; `chain[0]` is always the genesis hash.
    #[must_use]
    pub fn chain(&self) -> &BTreeMap<u64, Hash> {
        &self.chain
    }
}

#[cfg(test)]
mod tests {
    use super::super::block::BlockHeader;
    use super::super::committee::Certificate;
    use super::super::digest::{notarize_digest, nullify_digest};
    use super::super::wire::{ExecAttest, Notarization, Notarize, Nullification, Nullify, Propose};
    use super::*;
    use crypto::{KeyPair, Validator};

    const EPOCH: u64 = 0;

    fn genesis() -> Hash {
        Hash::from_bytes([0x6E; 32])
    }

    /// A unit-weight 6-member committee (f = 1 ⇒ M = 3, L = 5) at `epoch`.
    fn committee(epoch: u64) -> MinimmitCommittee {
        let members: Vec<Validator> = (0..6)
            .map(|i| Validator {
                public_key: KeyPair::from_seed(&[u8::try_from(i).unwrap() + 1; 32]).public(),
                weight: 1,
            })
            .collect();
        MinimmitCommittee::new_unit(epoch, members).unwrap()
    }

    fn replica(self_index: u16) -> (MinimmitReplica, Vec<Effect>) {
        MinimmitReplica::new(committee(EPOCH), self_index, genesis(), EPOCH).unwrap()
    }

    fn block_header() -> BlockHeader {
        BlockHeader {
            height: 1,
            parent_hash: genesis(),
            payload_root: Hash::from_bytes([0xEF; 32]),
        }
    }

    fn dummy_cert(message: Hash) -> Certificate {
        Certificate {
            message,
            signer_bitmap: 0b0000_0000_0000_0111,
            signatures: [[0x55; 64], [0x66; 64], [0x77; 64]].into_iter().collect(),
        }
    }

    /// One `Input` per variant (and per message variant), for exhaustive
    /// dispatch/determinism assertions.
    fn all_inputs() -> Vec<Input> {
        let block = block_header();
        let block_hash = block.hash();
        vec![
            Input::Message(ConsensusMessage::Propose(Propose {
                epoch: EPOCH,
                view: 0,
                block,
                block_hash,
                parent: ParentRef::genesis(genesis()),
                proposer_index: 0,
                notarize_sig: [0x11; 64],
                propose_sig: [0x22; 64],
            })),
            Input::Message(ConsensusMessage::Notarize(Notarize {
                epoch: EPOCH,
                view: 0,
                block_hash,
                validator_index: 1,
                signature: [0x33; 64],
            })),
            Input::Message(ConsensusMessage::Nullify(Nullify {
                epoch: EPOCH,
                view: 0,
                validator_index: 2,
                signature: [0x44; 64],
            })),
            Input::Message(ConsensusMessage::Notarization(Notarization {
                epoch: EPOCH,
                view: 0,
                block_hash,
                cert: dummy_cert(notarize_digest(EPOCH, 0, block_hash)),
            })),
            Input::Message(ConsensusMessage::Nullification(Nullification {
                epoch: EPOCH,
                view: 0,
                cert: dummy_cert(nullify_digest(EPOCH, 0)),
            })),
            Input::Message(ConsensusMessage::ExecAttest(ExecAttest {
                epoch: EPOCH,
                view: 0,
                height: 1,
                block_hash,
                execution_root: Hash::from_bytes([0x88; 32]),
                validator_index: 3,
                signature: [0x99; 64],
            })),
            Input::TimerFired { view: 0 },
            Input::Tick,
            Input::ProposalVerified {
                view: 0,
                block_hash,
                valid: true,
            },
            Input::ProposalVerified {
                view: 0,
                block_hash,
                valid: false,
            },
        ]
    }

    #[test]
    fn fresh_replica_seeds_view_0_and_genesis() {
        let (replica, _) = replica(2);
        assert_eq!(replica.view(), 0);
        assert_eq!(replica.epoch(), EPOCH);
        assert_eq!(replica.self_index(), 2);
        assert_eq!(replica.genesis_hash(), genesis());
        assert_eq!(replica.notarized(), None);
        assert!(!replica.nullified());
        // Genesis is finalized by definition: chain[0] = genesis_hash and the
        // tip carries the ⊥ sentinel (genesis was never proposed in a view).
        assert_eq!(replica.chain().len(), 1);
        assert_eq!(replica.chain().get(&0), Some(&genesis()));
        assert_eq!(replica.finalized_tip(), (BOTTOM_VIEW, genesis()));
        // No votes, no proofs before the first message.
        assert!(replica.proofs().is_empty());
        assert!(replica.notarize_votes().is_empty());
        assert!(replica.nullify_votes().is_empty());
        assert!(replica.exec_votes().is_empty());
        // The committee rides along.
        assert_eq!(replica.committee().len(), 6);
        assert_eq!(replica.committee().advance_threshold(), 3);
        assert_eq!(replica.committee().finalize_threshold(), 5);
    }

    #[test]
    fn construction_bootstraps_like_enter_view_0() {
        // Epoch 0 over n = 6: leader(0) = (0 + 0) % 6 = 0.
        // The leader of view 0 gets ArmTimer + NeedProposal with the genesis
        // parent — the propose-build seam (§7.2): the node builds/signs and
        // re-injects, the core never builds in-core.
        let (_, effects) = replica(0);
        assert_eq!(
            effects,
            vec![
                Effect::ArmTimer { view: 0 },
                Effect::NeedProposal {
                    parent: ParentRef::genesis(genesis()),
                },
            ]
        );

        // A non-leader gets only the timer arm.
        let (_, effects) = replica(4);
        assert_eq!(effects, vec![Effect::ArmTimer { view: 0 }]);

        // Leader selection is epoch-mixed (§6.1): epoch 7 ⇒ leader(0) = 1.
        let (_, effects) = MinimmitReplica::new(committee(7), 1, genesis(), 7).unwrap();
        assert_eq!(effects.len(), 2, "epoch-mixed leader must self-nominate");
        let (_, effects) = MinimmitReplica::new(committee(7), 0, genesis(), 7).unwrap();
        assert_eq!(effects, vec![Effect::ArmTimer { view: 0 }]);
    }

    #[test]
    fn constructor_rejects_out_of_committee_self_index() {
        // n = 6: valid indices are 0..=5; membership is required to vote.
        for index in [6u16, 7, u16::MAX] {
            assert_eq!(
                MinimmitReplica::new(committee(EPOCH), index, genesis(), EPOCH).unwrap_err(),
                VoteError::ForeignSigner(u32::from(index))
            );
        }
    }

    #[test]
    fn invalid_inputs_cover_every_dispatch_variant_and_fail_closed() {
        // Exercise every dispatch arm with invalid signatures, absent buffered
        // state, or a signer-less local timeout. None may emit an effect or
        // mutate the replica. Valid rule behavior is covered by the focused
        // R1-R7 tests below.
        let (mut replica, _) = replica(3);
        let before = format!("{replica:?}");
        for input in all_inputs() {
            assert_eq!(replica.step(input.clone()), Vec::new(), "{input:?}");
        }
        assert_eq!(
            format!("{replica:?}"),
            before,
            "rejected inputs must not mutate replica state"
        );
    }

    #[test]
    fn step_replay_is_deterministic() {
        // Two identically-constructed replicas fed the same ordered Input
        // sequence produce identical Effect sequences and identical state —
        // the §7 determinism guarantee across every dispatch variant.
        let (mut a, boot_a) = replica(0);
        let (mut b, boot_b) = replica(0);
        assert_eq!(boot_a, boot_b, "bootstrap effects must replay identically");

        let mut effects_a = Vec::new();
        let mut effects_b = Vec::new();
        // Interleave every variant twice, in a fixed order.
        for _ in 0..2 {
            for input in all_inputs() {
                effects_a.extend(a.step(input.clone()));
                effects_b.extend(b.step(input));
            }
        }
        assert_eq!(effects_a, effects_b);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));

        // A fresh replica's step(Tick) is deterministic on its own.
        let (mut fresh, _) = replica(5);
        let first = fresh.step(Input::Tick);
        let (mut again, _) = replica(5);
        assert_eq!(again.step(Input::Tick), first);
    }

    // ─── #522: select_parent / valid_parent / enter_view / prune ───

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    /// A `Notarization` proof fixture for `proofs[view]`. The locking
    /// predicates read `proofs` as already-verified state (R4/R5 verify every
    /// certificate before insertion, #525), so a dummy cert suffices.
    fn notarized_view(view: u64, block_hash: Hash) -> Proof {
        Proof::Notarization(Notarization {
            epoch: EPOCH,
            view,
            block_hash,
            cert: dummy_cert(notarize_digest(EPOCH, view, block_hash)),
        })
    }

    /// A `Nullification` proof fixture for `proofs[view]` (see
    /// [`notarized_view`] on why a dummy cert suffices).
    fn nullified_view(view: u64) -> Proof {
        Proof::Nullification(Nullification {
            epoch: EPOCH,
            view,
            cert: dummy_cert(nullify_digest(EPOCH, view)),
        })
    }

    #[test]
    fn select_parent_names_genesis_bottom_at_start_of_chain() {
        let (replica, _) = replica(2);
        // View 0 has no predecessor: the walk is empty and the parent is the
        // start-of-chain `{ genesis_hash, ⊥ }`.
        let parent = replica.select_parent(0).unwrap();
        assert_eq!(parent, ParentRef::genesis(genesis()));
        assert!(parent.is_bottom());
        assert_eq!(parent.parent_view, BOTTOM_VIEW);
        assert_eq!(parent.real_view(), None);

        // Any later view with NO proof for its predecessors cannot name a
        // parent yet — view 0 is unresolved, not skippable.
        assert_eq!(replica.select_parent(1), None);
        assert_eq!(replica.select_parent(7), None);
    }

    #[test]
    fn select_parent_returns_the_latest_notarized_view() {
        let (mut replica, _) = replica(2);
        replica.proofs.insert(0, notarized_view(0, hash(0xA0)));
        assert_eq!(
            replica.select_parent(1),
            Some(ParentRef {
                parent_hash: hash(0xA0),
                parent_view: 0,
            })
        );

        // A later notarization wins: the walk stops at the FIRST notarized
        // view going backward.
        replica.proofs.insert(1, notarized_view(1, hash(0xA1)));
        assert_eq!(
            replica.select_parent(2),
            Some(ParentRef {
                parent_hash: hash(0xA1),
                parent_view: 1,
            })
        );
        // ... and views at/above the queried view are never consulted.
        assert_eq!(
            replica.select_parent(1),
            Some(ParentRef {
                parent_hash: hash(0xA0),
                parent_view: 0,
            })
        );
    }

    #[test]
    fn select_parent_skips_nullified_only_views() {
        let (mut replica, _) = replica(2);
        replica.proofs.insert(0, notarized_view(0, hash(0xA0)));
        replica.proofs.insert(1, nullified_view(1));
        replica.proofs.insert(2, nullified_view(2));
        // Views 2 and 1 are nullified-only: the walk lands on view 0.
        assert_eq!(
            replica.select_parent(3),
            Some(ParentRef {
                parent_hash: hash(0xA0),
                parent_view: 0,
            })
        );
    }

    #[test]
    fn select_parent_returns_genesis_when_every_view_is_nullified() {
        let (mut replica, _) = replica(2);
        for view in 0..3 {
            replica.proofs.insert(view, nullified_view(view));
        }
        // The walk exhausts every view down to 0 on nullifications alone:
        // the parent degrades to the genesis `⊥` sentinel.
        assert_eq!(
            replica.select_parent(3),
            Some(ParentRef::genesis(genesis()))
        );
    }

    #[test]
    fn select_parent_gap_without_any_proof_returns_none() {
        let (mut replica, _) = replica(2);
        // Views 2 and 1 nullified but view 0 unresolved: cannot reach
        // genesis, cannot name a parent — wait for R7 re-dissemination.
        replica.proofs.insert(1, nullified_view(1));
        replica.proofs.insert(2, nullified_view(2));
        assert_eq!(replica.select_parent(3), None);

        // A notarization BELOW an unresolved view is unreachable too: view 1
        // has no proof, so the walk from 3 cannot cross it to reach view 0.
        replica.proofs.remove(&1);
        replica.proofs.insert(0, notarized_view(0, hash(0xA0)));
        assert_eq!(replica.select_parent(3), None);
    }

    #[test]
    fn valid_parent_accepts_adjacent_and_fully_nullified_skips() {
        let (mut replica, _) = replica(2);
        // Genesis parent, no skipped views: the first-ever proposal.
        assert!(replica.valid_parent(0, &ParentRef::genesis(genesis())));

        // Genesis parent skipping views 0..2 — both nullified.
        replica.proofs.insert(0, nullified_view(0));
        replica.proofs.insert(1, nullified_view(1));
        assert!(replica.valid_parent(2, &ParentRef::genesis(genesis())));

        // Real parent, adjacent view (no skips).
        let parent = ParentRef {
            parent_hash: hash(0xB3),
            parent_view: 3,
        };
        replica.proofs.insert(3, notarized_view(3, hash(0xB3)));
        assert!(replica.valid_parent(4, &parent));

        // Real parent skipping views 4 and 5 — both nullified.
        replica.proofs.insert(4, nullified_view(4));
        replica.proofs.insert(5, nullified_view(5));
        assert!(replica.valid_parent(6, &parent));

        // Views at/below the parent are NOT consulted: view 2 is unresolved
        // here, yet the linkage 3 -> 6 stands on its own (the parent
        // notarization's ancestry was checked when it formed).
        assert_eq!(replica.proofs.get(&2), None);
        assert!(replica.valid_parent(6, &parent));
    }

    #[test]
    fn valid_parent_rejects_skipped_views_that_did_not_nullify() {
        let (mut replica, _) = replica(2);
        let parent = ParentRef {
            parent_hash: hash(0xB3),
            parent_view: 3,
        };
        replica.proofs.insert(3, notarized_view(3, hash(0xB3)));

        // Skipped view 4 has no proof at all.
        assert!(!replica.valid_parent(5, &parent));
        assert!(!replica.valid_parent(6, &parent));

        // A nullification at 5 does not cover the hole at 4.
        replica.proofs.insert(5, nullified_view(5));
        assert!(!replica.valid_parent(6, &parent));

        // A NOTARIZED skipped view is just as inadmissible as a missing one:
        // the chain may only skip views that provably went nowhere.
        replica.proofs.insert(4, notarized_view(4, hash(0xB4)));
        assert!(!replica.valid_parent(6, &parent));

        // Genesis-parent flavor: view 0 unresolved rejects the `⊥` skip.
        replica.proofs.remove(&4);
        assert!(!replica.valid_parent(2, &ParentRef::genesis(genesis())));
    }

    #[test]
    fn valid_parent_requires_a_matching_notarization_at_the_parent_view() {
        let (mut replica, _) = replica(2);
        let parent = ParentRef {
            parent_hash: hash(0xB3),
            parent_view: 3,
        };
        // No proof at the parent view.
        assert!(!replica.valid_parent(4, &parent));

        // A nullification at the parent view is not a notarization.
        replica.proofs.insert(3, nullified_view(3));
        assert!(!replica.valid_parent(4, &parent));

        // A notarization for a DIFFERENT block does not match.
        replica.proofs.insert(3, notarized_view(3, hash(0xEE)));
        assert!(!replica.valid_parent(4, &parent));

        // The matching notarization flips it to admissible.
        replica.proofs.insert(3, notarized_view(3, hash(0xB3)));
        assert!(replica.valid_parent(4, &parent));

        // A `⊥` parent must carry the genesis hash — `⊥` with any other
        // hash is inadmissible even with a fully nullified prefix.
        assert!(!replica.valid_parent(0, &ParentRef::genesis(hash(0xEE))));
    }

    #[test]
    fn valid_parent_bottom_orders_below_and_real_views_precede_strictly() {
        let (mut replica, _) = replica(2);
        // `⊥` (encoded u64::MAX) orders BELOW every real view (§4.2): a
        // genesis parent is admissible at view 0 even though the raw
        // encoding compares above it...
        assert!(replica.valid_parent(0, &ParentRef::genesis(genesis())));

        // ...but a REAL parent view must strictly precede the proposal view:
        // equal or later parent views reject, they never wrap the interval.
        replica.proofs.insert(3, notarized_view(3, hash(0xB3)));
        let parent = ParentRef {
            parent_hash: hash(0xB3),
            parent_view: 3,
        };
        assert!(!replica.valid_parent(3, &parent));
        assert!(!replica.valid_parent(2, &parent));
        assert!(replica.valid_parent(4, &parent));
    }

    #[test]
    fn enter_view_advances_resets_per_view_state_and_arms() {
        // Index 4 leads no early view (epoch 0: leader(v) = v % 6).
        let (mut replica, _) = replica(4);
        replica.notarized = Some(hash(0xAB));
        replica.nullified = true;

        assert_eq!(replica.enter_view(1), vec![Effect::ArmTimer { view: 1 }]);
        assert_eq!(replica.view(), 1);
        // The per-view flags reset on entry.
        assert_eq!(replica.notarized(), None);
        assert!(!replica.nullified());

        // Advances can skip views (nullification paths): 1 -> 3 directly.
        assert_eq!(replica.enter_view(3), vec![Effect::ArmTimer { view: 3 }]);
        assert_eq!(replica.view(), 3);
    }

    #[test]
    fn enter_view_is_idempotent_and_never_double_arms() {
        let (mut replica, _) = replica(4);
        assert_eq!(replica.enter_view(2), vec![Effect::ArmTimer { view: 2 }]);

        // Same view again: no second ArmTimer, no state change.
        replica.notarized = Some(hash(0xAB));
        assert_eq!(replica.enter_view(2), Vec::new());
        assert_eq!(replica.view(), 2);
        // Idempotence includes NOT resetting the per-view flags.
        assert_eq!(replica.notarized(), Some(hash(0xAB)));

        // Stale entries for superseded views are no-ops too.
        assert_eq!(replica.enter_view(1), Vec::new());
        assert_eq!(replica.enter_view(0), Vec::new());
        assert_eq!(replica.view(), 2);
    }

    #[test]
    fn enter_view_nominates_the_leader_only_when_a_parent_is_known() {
        // Epoch 0: leader(1) = 1. With view 0 notarized, the leader entering
        // view 1 is told to build on it.
        let (mut leader, _) = replica(1);
        leader.proofs.insert(0, notarized_view(0, hash(0xA0)));
        assert_eq!(
            leader.enter_view(1),
            vec![
                Effect::ArmTimer { view: 1 },
                Effect::NeedProposal {
                    parent: ParentRef {
                        parent_hash: hash(0xA0),
                        parent_view: 0,
                    },
                },
            ]
        );

        // The same leader with NO proofs cannot name a parent: it arms the
        // timer and stays silent, waiting for R7 to fill the gap.
        let (mut stalled, _) = replica(1);
        assert_eq!(stalled.enter_view(1), vec![Effect::ArmTimer { view: 1 }]);

        // A non-leader never self-nominates, proofs or not.
        let (mut follower, _) = replica(5);
        follower.proofs.insert(0, notarized_view(0, hash(0xA0)));
        assert_eq!(follower.enter_view(1), vec![Effect::ArmTimer { view: 1 }]);

        // Leader entering across a nullified skip builds on the notarized
        // view below it (leader(2) = 2).
        let (mut skipper, _) = replica(2);
        skipper.proofs.insert(0, notarized_view(0, hash(0xA0)));
        skipper.proofs.insert(1, nullified_view(1));
        assert_eq!(
            skipper.enter_view(2),
            vec![
                Effect::ArmTimer { view: 2 },
                Effect::NeedProposal {
                    parent: ParentRef {
                        parent_hash: hash(0xA0),
                        parent_view: 0,
                    },
                },
            ]
        );
    }

    #[test]
    fn prune_bounds_the_view_maps_and_keeps_everything_at_or_above() {
        let (mut replica, _) = replica(4);
        for view in 0..6u64 {
            let proof = if view % 2 == 0 {
                notarized_view(view, hash(u8::try_from(view).unwrap()))
            } else {
                nullified_view(view)
            };
            replica.proofs.insert(view, proof);
            replica.notarize_votes.insert(view, Tally::default());
            replica.nullify_votes.insert(view, Tally::default());
        }
        // exec_votes is HEIGHT-keyed: it must survive view pruning (§6.6 —
        // exec tallies prune when their height finalizes, #528).
        replica.exec_votes.insert(0, Tally::default());
        replica.exec_votes.insert(1, Tally::default());

        replica.prune(3);
        let kept: Vec<u64> = replica.proofs().keys().copied().collect();
        assert_eq!(kept, vec![3, 4, 5], "below-horizon proofs evicted");
        let kept: Vec<u64> = replica.notarize_votes().keys().copied().collect();
        assert_eq!(kept, vec![3, 4, 5]);
        let kept: Vec<u64> = replica.nullify_votes().keys().copied().collect();
        assert_eq!(kept, vec![3, 4, 5]);
        // The surviving entries are untouched, not rebuilt.
        assert_eq!(replica.proofs().get(&4), Some(&notarized_view(4, hash(4))));
        // Height-keyed / finalized state is exempt.
        assert_eq!(replica.exec_votes().len(), 2);
        assert_eq!(replica.chain().get(&0), Some(&genesis()));
        assert_eq!(replica.finalized_tip(), (BOTTOM_VIEW, genesis()));

        // A horizon at/below every key is a no-op.
        replica.prune(0);
        assert_eq!(replica.proofs().len(), 3);
        replica.prune(3);
        assert_eq!(replica.proofs().len(), 3);

        // A horizon above every key empties the view maps entirely.
        replica.prune(100);
        assert!(replica.proofs().is_empty());
        assert!(replica.notarize_votes().is_empty());
        assert!(replica.nullify_votes().is_empty());
        assert_eq!(replica.exec_votes().len(), 2, "exec_votes still exempt");
    }

    #[test]
    fn locking_predicates_agree_with_each_other() {
        // Whatever select_parent proposes, valid_parent must admit — the
        // R1 -> R2 handshake in miniature, across all three parent shapes.
        let (mut replica, _) = replica(2);

        // Genesis at start of chain.
        let parent = replica.select_parent(0).unwrap();
        assert!(replica.valid_parent(0, &parent));

        // Genesis behind a fully nullified prefix.
        replica.proofs.insert(0, nullified_view(0));
        replica.proofs.insert(1, nullified_view(1));
        let parent = replica.select_parent(2).unwrap();
        assert!(parent.is_bottom());
        assert!(replica.valid_parent(2, &parent));

        // A real notarized parent behind a nullified skip.
        replica.proofs.insert(2, notarized_view(2, hash(0xC2)));
        replica.proofs.insert(3, nullified_view(3));
        let parent = replica.select_parent(4).unwrap();
        assert_eq!(parent.real_view(), Some(2));
        assert!(replica.valid_parent(4, &parent));
    }

    // ─── #523: split tallies, threshold-parameterized formation, quota ───

    /// The deterministic keypairs behind [`committee`], index-aligned.
    fn keys6() -> Vec<KeyPair> {
        (0..6)
            .map(|i| KeyPair::from_seed(&[u8::try_from(i).unwrap() + 1; 32]))
            .collect()
    }

    /// A [`Notarize`] with a REAL signature from validator `index`.
    fn signed_notarize(view: u64, block_hash: Hash, index: u16) -> Notarize {
        let mut vote = Notarize {
            epoch: EPOCH,
            view,
            block_hash,
            validator_index: index,
            signature: [0; 64],
        };
        vote.signature = keys6()[usize::from(index)].sign(vote.digest().as_bytes());
        vote
    }

    /// A [`Nullify`] with a REAL signature from validator `index`.
    fn signed_nullify(view: u64, index: u16) -> Nullify {
        let mut vote = Nullify {
            epoch: EPOCH,
            view,
            validator_index: index,
            signature: [0; 64],
        };
        vote.signature = keys6()[usize::from(index)].sign(vote.digest().as_bytes());
        vote
    }

    #[test]
    fn notarize_plus_nullify_in_one_view_is_not_equivocation() {
        // The R6 shape: one notarize AND one nullify from the same validator
        // in the same view — legitimate (nullify-by-contradiction) and MUST
        // NOT be flagged as double-signing. This is exactly what the strict
        // tally split exists for (§8, §12).
        let (mut replica, _) = replica(4);
        assert_eq!(
            replica.admit_notarize(&signed_notarize(0, hash(0xC1), 3)),
            Ok(TallyOutcome::Accepted)
        );
        assert_eq!(
            replica.admit_nullify(&signed_nullify(0, 3)),
            Ok(TallyOutcome::Accepted)
        );
        // Not flagged, not halted, both votes retained in their own tallies.
        assert!(replica.halted_offenders().is_empty());
        assert_eq!(replica.retained_votes(), 2);
        assert_eq!(
            replica
                .notarize_votes()
                .get(&0)
                .unwrap()
                .weight_for(replica.committee(), hash(0xC1)),
            1
        );
        assert_eq!(
            replica
                .nullify_votes()
                .get(&0)
                .unwrap()
                .weight_for(replica.committee(), nullify_digest(EPOCH, 0)),
            1
        );
        // Re-sends of either vote are idempotent duplicates, never verdicts.
        assert_eq!(
            replica.admit_notarize(&signed_notarize(0, hash(0xC1), 3)),
            Ok(TallyOutcome::Duplicate)
        );
        assert_eq!(
            replica.admit_nullify(&signed_nullify(0, 3)),
            Ok(TallyOutcome::Duplicate)
        );
        assert_eq!(replica.retained_votes(), 2, "duplicates never re-count");
    }

    #[test]
    fn conflicting_notarize_in_one_view_is_equivocation_and_halts() {
        let (mut replica, _) = replica(4);
        // The retagged (validator_index, epoch, view) key: the same validator
        // notarizing DIFFERENT blocks in DIFFERENT views is fine...
        assert_eq!(
            replica.admit_notarize(&signed_notarize(0, hash(0xA0), 5)),
            Ok(TallyOutcome::Accepted)
        );
        assert_eq!(
            replica.admit_notarize(&signed_notarize(1, hash(0xA1), 5)),
            Ok(TallyOutcome::Accepted)
        );

        // ...but a conflicting notarize in ONE view is double-signing.
        // Validator 2 first spreads votes across both dimensions and views.
        assert_eq!(
            replica.admit_nullify(&signed_nullify(1, 2)),
            Ok(TallyOutcome::Accepted)
        );
        let first = signed_notarize(0, hash(0xA0), 2);
        assert_eq!(replica.admit_notarize(&first), Ok(TallyOutcome::Accepted));
        assert_eq!(
            replica.admit_notarize(&signed_notarize(0, hash(0xBB), 2)),
            Ok(TallyOutcome::Equivocated {
                first: hash(0xA0),
                first_signature: first.signature,
            }),
            "the verdict carries the two-sided proof materials"
        );

        // The offender is halted and EVERY retained vote purged — across
        // views and across BOTH dimensions — so their weight never again
        // counts toward any certificate.
        assert!(replica.halted_offenders().contains(&2));
        let committee = committee(EPOCH);
        assert_eq!(
            replica
                .notarize_votes()
                .get(&0)
                .unwrap()
                .weight_for(&committee, hash(0xA0)),
            1,
            "only validator 5's vote survives at (view 0, 0xA0)"
        );
        assert_eq!(
            replica
                .notarize_votes()
                .get(&0)
                .unwrap()
                .weight_for(&committee, hash(0xBB)),
            0,
            "the conflicting vote itself was never recorded"
        );
        assert_eq!(
            replica
                .nullify_votes()
                .get(&1)
                .unwrap()
                .weight_for(&committee, nullify_digest(EPOCH, 1)),
            0,
            "the offender's nullify in another view is purged too"
        );
        assert_eq!(replica.retained_votes(), 2, "validator 5's votes only");

        // Future votes from the offender are rejected fail-closed.
        assert_eq!(
            replica.admit_nullify(&signed_nullify(2, 2)),
            Err(VoteError::HaltedOffender(2))
        );
        assert_eq!(
            replica.admit_notarize(&signed_notarize(2, hash(0xA2), 2)),
            Err(VoteError::HaltedOffender(2))
        );
    }

    #[test]
    fn try_form_is_threshold_parameterized_never_collapsed() {
        // THE safety-critical test of #523 (§12 risk 3): the SAME tally must
        // form the M-cert and independently answer the L bar. It fails if
        // cert formation collapses to a single hardcoded threshold in either
        // direction: hardcoded-to-L would form nothing at M ≤ weight < L;
        // hardcoded-to-M would form a "finalize" cert below L.
        let (mut replica, _) = replica(4);
        let block = hash(0xC0);

        // Below M = 3: neither bar forms.
        for index in [0u16, 1] {
            assert_eq!(
                replica.admit_notarize(&signed_notarize(0, block, index)),
                Ok(TallyOutcome::Accepted)
            );
        }
        assert!(replica
            .try_form_notarization(0, block, ThresholdKind::Advance)
            .is_none());
        assert!(replica
            .try_form_notarization(0, block, ThresholdKind::Finalize)
            .is_none());

        // Exactly M = 3, and again between M and L at 4: the M-cert forms
        // while the L bar over the SAME tally independently reports unmet.
        for index in [2u16, 3] {
            assert_eq!(
                replica.admit_notarize(&signed_notarize(0, block, index)),
                Ok(TallyOutcome::Accepted)
            );
            let m_cert = replica
                .try_form_notarization(0, block, ThresholdKind::Advance)
                .expect("advance bar met");
            assert_eq!(m_cert.message, notarize_digest(EPOCH, 0, block));
            assert_eq!(
                replica.committee().verify(&m_cert, ThresholdKind::Advance),
                Ok(())
            );
            assert!(
                replica
                    .try_form_notarization(0, block, ThresholdKind::Finalize)
                    .is_none(),
                "M ≤ weight < L must NOT clear the finalize bar"
            );
        }
        // The formed M-cert slots into a verifying wire Notarization (#519).
        let notarization = Notarization {
            epoch: EPOCH,
            view: 0,
            block_hash: block,
            cert: replica
                .try_form_notarization(0, block, ThresholdKind::Advance)
                .unwrap(),
        };
        assert_eq!(notarization.verify(replica.committee()), Ok(()));

        // At L = 5 the finalize bar forms over the same tally, and the
        // resulting certificate clears BOTH verification bars.
        assert_eq!(
            replica.admit_notarize(&signed_notarize(0, block, 4)),
            Ok(TallyOutcome::Accepted)
        );
        let l_cert = replica
            .try_form_notarization(0, block, ThresholdKind::Finalize)
            .expect("finalize bar met at L");
        assert_eq!(
            replica.committee().verify(&l_cert, ThresholdKind::Finalize),
            Ok(())
        );
        assert_eq!(
            replica.committee().verify(&l_cert, ThresholdKind::Advance),
            Ok(())
        );

        // The nullify dimension is parameterized by the same seam: M = 3
        // nullifies form the M-cert; the L bar (never R5's business, but the
        // parameter must not lie) reports unmet. Validators 1 and 3 are also
        // notarizers of view 0 — the R6 shape yet again, unflagged.
        for index in [1u16, 3, 5] {
            assert_eq!(
                replica.admit_nullify(&signed_nullify(0, index)),
                Ok(TallyOutcome::Accepted)
            );
        }
        let n_cert = replica
            .try_form_nullification(0, ThresholdKind::Advance)
            .expect("advance bar met");
        assert_eq!(n_cert.message, nullify_digest(EPOCH, 0));
        assert!(replica
            .try_form_nullification(0, ThresholdKind::Finalize)
            .is_none());
        let nullification = Nullification {
            epoch: EPOCH,
            view: 0,
            cert: n_cert,
        };
        assert_eq!(nullification.verify(replica.committee()), Ok(()));
        assert!(replica.halted_offenders().is_empty());

        // Unknown views / candidates never form anything.
        assert!(replica
            .try_form_notarization(7, block, ThresholdKind::Advance)
            .is_none());
        assert!(replica
            .try_form_notarization(0, hash(0xDD), ThresholdKind::Advance)
            .is_none());
        assert!(replica
            .try_form_nullification(7, ThresholdKind::Advance)
            .is_none());
    }

    #[test]
    fn nullify_flood_is_bounded_by_quota_and_window() {
        // The block-less nullify dimension: nothing binds a nullify to a
        // block, so a flooder's only lever is the VIEW dimension — bounded by
        // the admission window and the per-validator quota (fail-closed,
        // nothing already admitted is wiped).
        let (mut replica, _) = replica(4);
        replica.vote_quota = 3;
        for view in 0..3u64 {
            assert_eq!(
                replica.admit_nullify(&signed_nullify(view, 0)),
                Ok(TallyOutcome::Accepted)
            );
        }
        for view in 3..10u64 {
            assert_eq!(
                replica.admit_nullify(&signed_nullify(view, 0)),
                Err(VoteError::QuotaExceeded(0))
            );
        }
        assert_eq!(replica.retained_votes(), 3);
        assert_eq!(
            replica.nullify_votes().len(),
            3,
            "rejected votes must not grow the view maps either"
        );
        // Duplicates are idempotent and never consume quota.
        assert_eq!(
            replica.admit_nullify(&signed_nullify(1, 0)),
            Ok(TallyOutcome::Duplicate)
        );
        assert_eq!(replica.retained_votes(), 3);
        // Honest validators are unaffected by the flooder's quota.
        assert_eq!(
            replica.admit_nullify(&signed_nullify(0, 1)),
            Ok(TallyOutcome::Accepted)
        );
        assert_eq!(replica.retained_votes(), 4);

        // Pruning releases evicted entries from the quota: views 0 and 1
        // evict (the flooder's two entries + validator 1's one), view 2
        // survives — and the flooder can vote again within the window.
        replica.prune(2);
        assert_eq!(replica.retained_votes(), 1);
        assert_eq!(
            replica.admit_nullify(&signed_nullify(5, 0)),
            Ok(TallyOutcome::Accepted)
        );
        // ...but views below the pruned watermark are outside the window.
        assert_eq!(
            replica.admit_nullify(&signed_nullify(1, 1)),
            Err(VoteError::OutsideWindow)
        );

        // The forward bound: beyond view + DEFAULT_VIEW_HORIZON rejects; the
        // horizon boundary itself is admissible.
        let (mut fresh, _) = MinimmitReplica::new(committee(EPOCH), 4, genesis(), EPOCH).unwrap();
        assert_eq!(
            fresh.admit_nullify(&signed_nullify(DEFAULT_VIEW_HORIZON + 1, 0)),
            Err(VoteError::OutsideWindow)
        );
        assert_eq!(
            fresh.admit_nullify(&signed_nullify(DEFAULT_VIEW_HORIZON, 0)),
            Ok(TallyOutcome::Accepted)
        );
    }

    #[test]
    fn admission_rejects_cheap_failures_before_signature_work() {
        let (mut replica, _) = replica(4);
        // Epoch and window rejections fire BEFORE signature verification: a
        // garbage signature still reports the cheap error, never
        // InvalidSignature.
        let garbage = Notarize {
            epoch: EPOCH + 1,
            view: 0,
            block_hash: hash(0xC1),
            validator_index: 1,
            signature: [0x99; 64],
        };
        assert_eq!(
            replica.admit_notarize(&garbage),
            Err(VoteError::EpochMismatch)
        );
        let far_future = Nullify {
            epoch: EPOCH,
            view: DEFAULT_VIEW_HORIZON + 1,
            validator_index: 1,
            signature: [0x99; 64],
        };
        assert_eq!(
            replica.admit_nullify(&far_future),
            Err(VoteError::OutsideWindow)
        );
        // Foreign indices fail closed (n = 6: valid indices are 0..=5).
        let foreign = Notarize {
            epoch: EPOCH,
            view: 0,
            block_hash: hash(0xC1),
            validator_index: 6,
            signature: [0x99; 64],
        };
        assert_eq!(
            replica.admit_notarize(&foreign),
            Err(VoteError::ForeignSigner(6))
        );
        // A member's bad signature is InvalidSignature; and a valid
        // signature over a DIFFERENT candidate does not admit (the digest
        // binds the block).
        let mut corrupted = signed_notarize(0, hash(0xC1), 1);
        corrupted.signature[0] ^= 0x01;
        assert_eq!(
            replica.admit_notarize(&corrupted),
            Err(VoteError::InvalidSignature)
        );
        let mut wrong_block = signed_notarize(0, hash(0xC1), 1);
        wrong_block.block_hash = hash(0xC2);
        assert_eq!(
            replica.admit_notarize(&wrong_block),
            Err(VoteError::InvalidSignature)
        );
        // Nothing was retained by any of the rejections.
        assert_eq!(replica.retained_votes(), 0);
        assert!(replica.notarize_votes().is_empty());
        assert!(replica.nullify_votes().is_empty());
        assert!(replica.halted_offenders().is_empty());
    }

    // ─── #524: R1 propose, R2 injected verification, R3 timeout ───

    fn voting_replica(index: u16) -> MinimmitReplica {
        MinimmitReplica::new_with_signer(
            committee(EPOCH),
            index,
            genesis(),
            EPOCH,
            keys6()[usize::from(index)].clone(),
        )
        .unwrap()
        .0
    }

    fn signed_propose(block: BlockHeader) -> Propose {
        let mut propose = Propose {
            epoch: EPOCH,
            view: 0,
            block,
            block_hash: block.hash(),
            parent: ParentRef::genesis(genesis()),
            proposer_index: 0,
            notarize_sig: [0; 64],
            propose_sig: [0; 64],
        };
        propose.notarize_sig = keys6()[0].sign(propose.notarize_digest().as_bytes());
        propose.propose_sig = keys6()[0].sign(propose.auth_digest().as_bytes());
        propose
    }

    #[test]
    fn r1_leader_propose_is_verified_broadcast_and_self_tallied() {
        let mut replica = voting_replica(0);
        let propose = signed_propose(block_header());
        let hash = propose.block_hash;
        assert!(replica
            .step(Input::Message(ConsensusMessage::Propose(propose.clone())))
            .is_empty());
        assert_eq!(replica.notarized(), None, "verdict is an explicit input");

        assert_eq!(
            replica.step(Input::ProposalVerified {
                view: 0,
                block_hash: hash,
                valid: true,
            }),
            vec![Effect::Broadcast(ConsensusMessage::Propose(propose))]
        );
        assert_eq!(replica.notarized(), Some(hash));
        assert_eq!(
            replica.notarize_votes()[&0].weight_for(replica.committee(), hash),
            1
        );
    }

    #[test]
    fn r2_follower_waits_for_valid_verdict_and_broadcasts_signed_notarize() {
        let mut replica = voting_replica(1);
        let propose = signed_propose(block_header());
        let hash = propose.block_hash;
        replica.step(Input::Message(ConsensusMessage::Propose(propose)));
        let effects = replica.step(Input::ProposalVerified {
            view: 0,
            block_hash: hash,
            valid: true,
        });
        let [Effect::Broadcast(ConsensusMessage::Notarize(vote))] = effects.as_slice() else {
            panic!("expected one notarize broadcast: {effects:?}");
        };
        assert_eq!(vote.validator_index, 1);
        assert_eq!(vote.block_hash, hash);
        assert_eq!(replica.admit_notarize(vote), Ok(TallyOutcome::Duplicate));
        assert_eq!(replica.notarized(), Some(hash));

        let mut rejected = voting_replica(1);
        rejected.step(Input::Message(ConsensusMessage::Propose(signed_propose(
            block_header(),
        ))));
        assert!(rejected
            .step(Input::ProposalVerified {
                view: 0,
                block_hash: hash,
                valid: false,
            })
            .is_empty());
        assert_eq!(rejected.notarized(), None);
    }

    #[test]
    fn r2_rejects_bad_guards_and_slashes_authenticated_proposal_fork() {
        let mut replica = voting_replica(1);
        let first = signed_propose(block_header());

        let mut bad_signature = first.clone();
        bad_signature.propose_sig[0] ^= 1;
        assert!(replica
            .step(Input::Message(ConsensusMessage::Propose(bad_signature)))
            .is_empty());

        replica.step(Input::Message(ConsensusMessage::Propose(first.clone())));
        let mut conflicting_block = block_header();
        conflicting_block.payload_root = hash(0x42);
        let conflict = signed_propose(conflicting_block);
        let effects = replica.step(Input::Message(ConsensusMessage::Propose(conflict)));
        assert!(matches!(
            effects.as_slice(),
            [Effect::Slash(SlashEvidence {
                kind: SlashKind::ProposalFork,
                ..
            })]
        ));
        assert!(replica.halted_offenders().contains(&0));
    }

    #[test]
    fn r3_current_timer_nullifies_once_and_stale_timer_is_noop() {
        let mut replica = voting_replica(2);
        assert!(replica.step(Input::TimerFired { view: 9 }).is_empty());
        let effects = replica.step(Input::TimerFired { view: 0 });
        let [Effect::Broadcast(ConsensusMessage::Nullify(vote))] = effects.as_slice() else {
            panic!("expected one nullify broadcast: {effects:?}");
        };
        assert_eq!(vote.validator_index, 2);
        assert_eq!(replica.admit_nullify(vote), Ok(TallyOutcome::Duplicate));
        assert!(replica.nullified());
        assert!(replica.step(Input::TimerFired { view: 0 }).is_empty());
    }

    fn signed_exec(
        view: u64,
        height: u64,
        block_hash: Hash,
        execution_root: Hash,
        index: u16,
    ) -> ExecAttest {
        let mut attest = ExecAttest {
            epoch: EPOCH,
            view,
            height,
            block_hash,
            execution_root,
            validator_index: index,
            signature: [0; 64],
        };
        attest.signature = keys6()[usize::from(index)].sign(attest.digest().as_bytes());
        attest
    }

    #[test]
    fn r4_forms_m_advances_at_m_and_consensus_finalizes_only_at_l() {
        let mut replica = voting_replica(5);
        let proposal = signed_propose(block_header());
        let block = proposal.block_hash;
        replica.step(Input::Message(ConsensusMessage::Propose(proposal)));
        replica.step(Input::ProposalVerified {
            view: 0,
            block_hash: block,
            valid: true,
        });
        // Leader + self are already tallied. The third vote reaches M.
        let effects = replica.step(Input::Message(ConsensusMessage::Notarize(signed_notarize(
            0, block, 1,
        ))));
        assert!(matches!(
            replica.proofs().get(&0),
            Some(Proof::Notarization(_))
        ));
        assert_eq!(replica.view(), 1);
        assert!(effects
            .iter()
            .any(|effect| matches!(effect, Effect::Broadcast(ConsensusMessage::Notarization(_)))));
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, Effect::ConsensusFinal { .. })));

        replica.step(Input::Message(ConsensusMessage::Notarize(signed_notarize(
            0, block, 2,
        ))));
        let effects = replica.step(Input::Message(ConsensusMessage::Notarize(signed_notarize(
            0, block, 3,
        ))));
        assert!(effects.contains(&Effect::ConsensusFinal { block, height: 1 }));
        assert_eq!(replica.chain().get(&1), Some(&block));
        assert!(matches!(
            replica.finality().get(&1),
            Some(FinalityStage::ConsensusFinal { .. })
        ));
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, Effect::Finalized { .. })));
    }

    #[test]
    fn execution_l_certificate_is_mandatory_and_finalized_fires_once() {
        let mut replica = voting_replica(5);
        let proposal = signed_propose(block_header());
        let block = proposal.block_hash;
        replica.step(Input::Message(ConsensusMessage::Propose(proposal)));
        replica.step(Input::ProposalVerified {
            view: 0,
            block_hash: block,
            valid: true,
        });
        for index in [1u16, 2, 3] {
            replica.step(Input::Message(ConsensusMessage::Notarize(signed_notarize(
                0, block, index,
            ))));
        }
        let root = hash(0xE1);
        for index in [0u16, 1, 2, 3] {
            let effects = replica.step(Input::Message(ConsensusMessage::ExecAttest(signed_exec(
                0, 1, block, root, index,
            ))));
            assert!(!effects
                .iter()
                .any(|effect| matches!(effect, Effect::Finalized { .. })));
        }
        let effects = replica.step(Input::Message(ConsensusMessage::ExecAttest(signed_exec(
            0, 1, block, root, 4,
        ))));
        assert_eq!(effects, vec![Effect::Finalized { block, height: 1 }]);
        assert!(matches!(
            replica.finality().get(&1),
            Some(FinalityStage::Finalized {
                execution_root,
                ..
            }) if *execution_root == root
        ));
        assert!(replica
            .step(Input::Message(ConsensusMessage::ExecAttest(signed_exec(
                0, 1, block, root, 5,
            ))))
            .is_empty());
    }

    #[test]
    fn r5_ingests_nullification_and_r7_redisseminates_once() {
        let keys = keys6();
        let digest = nullify_digest(EPOCH, 0);
        let signers: Vec<_> = [0u16, 1, 2]
            .into_iter()
            .map(|index| (index, keys[usize::from(index)].sign(digest.as_bytes())))
            .collect();
        let proof = Nullification {
            epoch: EPOCH,
            view: 0,
            cert: committee(EPOCH).assemble(digest, &signers).unwrap(),
        };
        let mut replica = voting_replica(5);
        let effects = replica.step(Input::Message(ConsensusMessage::Nullification(
            proof.clone(),
        )));
        assert_eq!(replica.view(), 1);
        assert!(effects.contains(&Effect::CancelTimer { view: 0 }));
        assert_eq!(
            replica.step(Input::Tick),
            vec![Effect::Broadcast(ConsensusMessage::Nullification(proof))]
        );
        assert!(replica.step(Input::Tick).is_empty());
    }

    #[test]
    fn late_matching_proposal_completes_deferred_l_finalization_without_voting() {
        let proposal = signed_propose(block_header());
        let block = proposal.block_hash;
        let digest = proposal.notarize_digest();
        let signers: Vec<_> = (0u16..5)
            .map(|index| (index, keys6()[usize::from(index)].sign(digest.as_bytes())))
            .collect();
        let notarization = Notarization {
            epoch: EPOCH,
            view: 0,
            block_hash: block,
            cert: committee(EPOCH).assemble(digest, &signers).unwrap(),
        };
        let mut lagging = voting_replica(5);
        let effects = lagging.step(Input::Message(ConsensusMessage::Notarization(notarization)));
        assert_eq!(lagging.view(), 1);
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, Effect::ConsensusFinal { .. })));

        assert!(lagging
            .step(Input::Message(ConsensusMessage::Propose(proposal)))
            .is_empty());
        assert_eq!(
            lagging.step(Input::ProposalVerified {
                view: 0,
                block_hash: block,
                valid: true,
            }),
            vec![Effect::ConsensusFinal { block, height: 1 }]
        );
        assert_eq!(
            lagging.notarized(),
            None,
            "stale proposals never cast votes"
        );
    }

    #[test]
    fn r6_notarize_then_nullify_is_non_slashable() {
        let mut replica = voting_replica(4);
        let proposal = signed_propose(block_header());
        let ours = proposal.block_hash;
        replica.step(Input::Message(ConsensusMessage::Propose(proposal)));
        replica.step(Input::ProposalVerified {
            view: 0,
            block_hash: ours,
            valid: true,
        });
        replica.step(Input::Message(ConsensusMessage::Nullify(signed_nullify(
            0, 1,
        ))));
        replica.step(Input::Message(ConsensusMessage::Nullify(signed_nullify(
            0, 2,
        ))));
        let effects = replica.step(Input::Message(ConsensusMessage::Notarize(signed_notarize(
            0,
            hash(0xCC),
            3,
        ))));
        assert!(effects.iter().any(|effect| matches!(
            effect,
            Effect::Broadcast(ConsensusMessage::Nullify(Nullify {
                validator_index: 4,
                ..
            }))
        )));
        assert!(replica.halted_offenders().is_empty());
        assert!(matches!(
            replica.proofs().get(&0),
            Some(Proof::Nullification(_))
        ));
    }

    #[test]
    fn epoch_rotation_is_atomic_and_rejects_old_epoch_votes() {
        let mut replica = voting_replica(2);
        replica.schedule_update(ValidatorSetUpdate {
            activation_epoch: 1,
            validators: committee(1).validators().to_vec(),
        });
        assert!(matches!(
            replica.activate_epoch(2),
            Err(EpochError::WrongActivationEpoch { .. })
        ));
        let effects = replica.activate_epoch(1).unwrap();
        assert_eq!(replica.epoch(), 1);
        assert_eq!(replica.view(), 0);
        assert_eq!(effects, vec![Effect::ArmTimer { view: 0 }]);
        assert_eq!(
            replica.admit_nullify(&signed_nullify(0, 0)),
            Err(VoteError::EpochMismatch)
        );
    }
}
