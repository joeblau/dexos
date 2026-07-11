//! A logical consensus node driven entirely through the simulated network.
//!
//! Each node wraps a real [`consensus::BftEngine`] and behaves like a HotStuff
//! replica: the view leader proposes a batch, replicas execute and cast a
//! `Commit` vote, and every node independently collects votes, forms a quorum
//! certificate, finalizes, and folds the finalized block into a running state
//! root. The fold is a pure function of the finalized block sequence, so any
//! two nodes that finalize the same blocks end at a bit-identical state root.
//!
//! Byzantine behaviors are injected by [`Behavior`]: a voter can equivocate
//! (double-sign conflicting blocks in the same round), a leader can equivocate
//! (propose two conflicting blocks), and a node can emit invalid signatures.
//! None of these can move an honest node to an incorrect finalized block,
//! because certification requires threshold weight over a single vote digest.

use std::collections::BTreeMap;

use consensus::{
    build_checkpoint_header, proposal_digest, vote_digest, BftEngine, CheckpointHeader, Committee,
    Proposal, ProposalOutcome, Vote, VotePhase,
};
use crypto::{hash_domain, hash_leaf, hash_node, KeyPair};
use types::{Hash, ShardId};

/// Logical node identifier (also the validator's committee index).
pub type NodeId = u32;

/// Domain tag for canonical (honest) block commitments.
const DOMAIN_BLOCK: &[u8] = b"dexos:sim:block:v1";
/// Domain tag for adversarial (Byzantine) block commitments.
const DOMAIN_EVIL: &[u8] = b"dexos:sim:evil-block:v1";

/// The canonical block every honest leader commits to at `height`.
#[must_use]
pub fn canonical_block(height: u64) -> Hash {
    hash_domain(DOMAIN_BLOCK, &height.to_le_bytes())
}

/// A distinct, conflicting block a Byzantine actor commits to at `height`.
#[must_use]
pub fn byzantine_block(height: u64) -> Hash {
    hash_domain(DOMAIN_EVIL, &height.to_le_bytes())
}

/// A node's behavioral profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    /// Follows the protocol faithfully.
    Honest,
    /// Double-signs: casts two conflicting votes in the same round.
    EquivocatingVoter,
    /// As leader, proposes two conflicting blocks at the same height and view.
    EquivocatingLeader,
    /// Emits votes whose signatures do not verify.
    InvalidSigner,
}

/// Where an outgoing message should go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Send to every node (including the sender, reliably to self).
    Broadcast,
    /// Send to a single node.
    To(NodeId),
}

/// A message payload carried over the simulated network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A leader proposal.
    Proposal(Proposal),
    /// A validator vote.
    Vote(Vote),
}

/// A message a node wishes to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// Destination of the message.
    pub target: Target,
    /// The message payload.
    pub payload: Payload,
}

impl Outgoing {
    fn broadcast(payload: Payload) -> Self {
        Self {
            target: Target::Broadcast,
            payload,
        }
    }
}

/// A message delivered to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Sending node.
    pub from: NodeId,
    /// Receiving node.
    pub to: NodeId,
    /// The payload.
    pub payload: Payload,
}

/// A durable (write-ahead) finalized-log record that survives a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogRecord {
    height: u64,
    block: Hash,
    timestamp: u64,
}

/// A single simulated consensus node.
#[derive(Debug, Clone)]
pub struct Node {
    id: NodeId,
    index: u32,
    keypair: KeyPair,
    engine: BftEngine,
    behavior: Behavior,
    crashed: bool,

    // Volatile state (cleared on crash, rebuilt from `durable_log` on restart).
    finalized: BTreeMap<u64, Hash>,
    applied_upto: u64,
    state_root: Hash,
    checkpoints: Vec<CheckpointHeader>,
    last_proposal: BTreeMap<u64, Proposal>,
    cast_votes: Vec<Vote>,

    // Durable state: the finalized log, replayed on restart.
    durable_log: Vec<LogRecord>,
}

impl Node {
    /// Create a node bound to `committee` at validator `index`, with the given
    /// deterministic key seed and behavior.
    #[must_use]
    pub fn new(index: u32, seed: &[u8; 32], committee: Committee, behavior: Behavior) -> Self {
        let keypair = KeyPair::from_seed(seed);
        Self {
            id: index,
            index,
            keypair,
            engine: BftEngine::new(committee),
            behavior,
            crashed: false,
            finalized: BTreeMap::new(),
            applied_upto: 0,
            state_root: Hash::ZERO,
            checkpoints: Vec::new(),
            last_proposal: BTreeMap::new(),
            cast_votes: Vec::new(),
            durable_log: Vec::new(),
        }
    }

    /// This node's id.
    #[must_use]
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Whether the node is currently crashed (silent).
    #[must_use]
    pub fn is_crashed(&self) -> bool {
        self.crashed
    }

    /// The running finalized state root.
    #[must_use]
    pub fn state_root(&self) -> Hash {
        self.state_root
    }

    /// Number of finalized heights.
    #[must_use]
    pub fn finalized_count(&self) -> u64 {
        u64::try_from(self.finalized.len()).unwrap_or(u64::MAX)
    }

    /// Whether `height` has been finalized locally.
    #[must_use]
    pub fn has_finalized(&self, height: u64) -> bool {
        self.finalized.contains_key(&height)
    }

    /// The finalized checkpoint headers, in height order.
    #[must_use]
    pub fn checkpoints(&self) -> &[CheckpointHeader] {
        &self.checkpoints
    }

    /// The deterministic leader index this node's committee assigns to `view`.
    #[must_use]
    pub fn leader_for_view(&self, view: u64) -> NodeId {
        self.engine.committee().leader(view)
    }

    /// Number of forks detected by this node's engine.
    #[must_use]
    pub fn forks_detected(&self) -> usize {
        self.engine.forks().len()
    }

    /// Number of vote equivocations detected by this node's engine.
    #[must_use]
    pub fn equivocations_detected(&self) -> usize {
        self.engine.equivocations().len()
    }

    fn epoch(&self) -> u64 {
        self.engine.epoch()
    }

    fn parent_of(height: u64) -> Hash {
        if height <= 1 {
            Hash::ZERO
        } else {
            canonical_block(height - 1)
        }
    }

    fn build_proposal(&self, view: u64, height: u64, block: Hash) -> Proposal {
        let epoch = self.epoch();
        let parent = Self::parent_of(height);
        let digest = proposal_digest(epoch, view, height, block, parent, height, height);
        Proposal {
            epoch,
            view,
            height,
            block_hash: block,
            parent_hash: parent,
            first_sequence: height,
            last_sequence: height,
            proposer_index: self.index,
            signature: self.keypair.sign(digest.as_bytes()),
        }
    }

    fn build_vote(&self, view: u64, height: u64, block: Hash) -> Vote {
        let epoch = self.epoch();
        let digest = vote_digest(epoch, view, height, VotePhase::Commit, block);
        Vote {
            epoch,
            view,
            height,
            phase: VotePhase::Commit,
            block_hash: block,
            validator_index: self.index,
            signature: self.keypair.sign(digest.as_bytes()),
        }
    }

    fn build_bad_vote(&self, view: u64, height: u64, block: Hash) -> Vote {
        // Sign with a key that is NOT this validator's key, so verification
        // against the committee public key fails deterministically.
        let wrong = KeyPair::from_seed(&[0xAB; 32]);
        let epoch = self.epoch();
        let digest = vote_digest(epoch, view, height, VotePhase::Commit, block);
        Vote {
            epoch,
            view,
            height,
            phase: VotePhase::Commit,
            block_hash: block,
            validator_index: self.index,
            signature: wrong.sign(digest.as_bytes()),
        }
    }

    /// Instructed by the scheduler: if this node is the leader for `view`,
    /// propose `height`. Returns the message(s) to broadcast.
    pub fn propose(&mut self, height: u64, view: u64) -> Vec<Outgoing> {
        if self.crashed || self.finalized.contains_key(&height) {
            return Vec::new();
        }
        if self.engine.committee().leader(view) != self.index {
            return Vec::new();
        }
        match self.behavior {
            Behavior::EquivocatingLeader => {
                let a = self.build_proposal(view, height, canonical_block(height));
                let b = self.build_proposal(view, height, byzantine_block(height));
                vec![
                    Outgoing::broadcast(Payload::Proposal(a)),
                    Outgoing::broadcast(Payload::Proposal(b)),
                ]
            }
            _ => {
                let p = self.build_proposal(view, height, canonical_block(height));
                self.last_proposal.insert(height, p.clone());
                vec![Outgoing::broadcast(Payload::Proposal(p))]
            }
        }
    }

    /// Handle a delivered message, returning any outgoing messages.
    pub fn handle(&mut self, env: &Envelope, now: u64) -> Vec<Outgoing> {
        if self.crashed {
            return Vec::new();
        }
        match &env.payload {
            Payload::Proposal(p) => self.on_proposal(p.clone()),
            Payload::Vote(v) => self.on_vote(v, now),
        }
    }

    fn on_proposal(&mut self, proposal: Proposal) -> Vec<Outgoing> {
        let height = proposal.height;
        if self.finalized.contains_key(&height) {
            return Vec::new();
        }
        let view = proposal.view;
        let block = proposal.block_hash;
        match self.engine.receive_proposal(proposal.clone()) {
            Ok(ProposalOutcome::Accepted) => {
                // Pipelined execute; ignore a benign double-execute.
                let _ = self.engine.execute(height);
                self.last_proposal.insert(height, proposal);
                self.cast_and_broadcast_vote(view, height, block)
            }
            // Duplicate / fork / rejection: never panic, emit nothing new.
            _ => Vec::new(),
        }
    }

    fn cast_and_broadcast_vote(&mut self, view: u64, height: u64, block: Hash) -> Vec<Outgoing> {
        match self.behavior {
            Behavior::InvalidSigner => {
                let v = self.build_bad_vote(view, height, block);
                self.cast_votes.push(v.clone());
                vec![Outgoing::broadcast(Payload::Vote(v))]
            }
            Behavior::EquivocatingVoter => {
                let good = self.build_vote(view, height, block);
                let evil = self.build_vote(view, height, byzantine_block(height));
                self.cast_votes.push(good.clone());
                self.cast_votes.push(evil.clone());
                vec![
                    Outgoing::broadcast(Payload::Vote(good)),
                    Outgoing::broadcast(Payload::Vote(evil)),
                ]
            }
            _ => {
                let v = self.build_vote(view, height, block);
                self.cast_votes.push(v.clone());
                vec![Outgoing::broadcast(Payload::Vote(v))]
            }
        }
    }

    fn on_vote(&mut self, vote: &Vote, now: u64) -> Vec<Outgoing> {
        // Invalid / foreign votes are rejected by the engine; we ignore them.
        if self.engine.add_vote(vote).is_err() {
            return Vec::new();
        }
        let height = vote.height;
        if let Ok(Some(_qc)) = self.engine.try_certify(height, VotePhase::Commit) {
            if !self.finalized.contains_key(&height) {
                if let Ok(block) = self.engine.finalize(height) {
                    self.record_finalized(height, block, now);
                }
            }
        }
        Vec::new()
    }

    fn record_finalized(&mut self, height: u64, block: Hash, timestamp: u64) {
        self.durable_log.push(LogRecord {
            height,
            block,
            timestamp,
        });
        self.finalized.insert(height, block);
        self.advance_apply();
    }

    /// Fold every newly-contiguous finalized height into the state root and
    /// emit its checkpoint header. Idempotent and order-independent: it always
    /// applies heights in strict ascending, gap-free order.
    fn advance_apply(&mut self) {
        loop {
            let next = self.applied_upto + 1;
            let Some(&block) = self.finalized.get(&next) else {
                break;
            };
            let timestamp = self
                .durable_log
                .iter()
                .find(|r| r.height == next)
                .map(|r| r.timestamp)
                .unwrap_or(0);
            let prev = self.state_root;
            let new = hash_node(prev, block);
            let exec = hash_leaf(block.as_bytes());
            if let Ok(header) = build_checkpoint_header(
                self.epoch(),
                ShardId::new(0),
                next,
                next,
                prev,
                new,
                &[block],
                &[exec],
                Hash::ZERO,
                timestamp,
            ) {
                self.checkpoints.push(header);
            }
            self.state_root = new;
            self.applied_upto = next;
        }
    }

    /// Periodic gossip: rebroadcast the accepted proposal and cast votes for
    /// `height` so that dropped/partitioned peers can still make progress once
    /// connectivity returns. Bounded to a single height's cached artifacts.
    pub fn retransmit(&mut self, height: u64) -> Vec<Outgoing> {
        if self.crashed {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(p) = self.last_proposal.get(&height) {
            out.push(Outgoing::broadcast(Payload::Proposal(p.clone())));
        }
        for v in &self.cast_votes {
            if v.height == height {
                out.push(Outgoing::broadcast(Payload::Vote(v.clone())));
            }
        }
        out
    }

    /// Crash the node: it goes silent and loses all volatile state, but its
    /// durable finalized log survives.
    pub fn crash(&mut self) {
        self.crashed = true;
        let committee = self.engine.committee().clone();
        self.engine = BftEngine::new(committee);
        self.finalized.clear();
        self.applied_upto = 0;
        self.state_root = Hash::ZERO;
        self.checkpoints.clear();
        self.last_proposal.clear();
        self.cast_votes.clear();
    }

    /// Restart the node: replay the durable finalized log to rebuild the state
    /// root and checkpoints bit-identically, then resume participation.
    pub fn restart(&mut self) {
        self.crashed = false;
        self.rebuild_from_log();
    }

    fn rebuild_from_log(&mut self) {
        // Rebuild the volatile derived state from the durable log.
        self.finalized.clear();
        self.applied_upto = 0;
        self.state_root = Hash::ZERO;
        self.checkpoints.clear();
        self.durable_log.sort_by_key(|r| r.height);
        let log = self.durable_log.clone();
        for record in log {
            self.finalized.insert(record.height, record.block);
        }
        self.advance_apply();
    }

    /// A copy of the durable finalized log as `(height, block, timestamp)`
    /// tuples, used to seed a recovering peer via state sync.
    #[must_use]
    pub fn durable_snapshot(&self) -> Vec<(u64, Hash, u64)> {
        self.durable_log
            .iter()
            .map(|r| (r.height, r.block, r.timestamp))
            .collect()
    }

    /// Restart the node, first syncing any finalized heights it missed while
    /// crashed from a peer `snapshot`. The result is a state root bit-identical
    /// to peers that finalized the same block sequence.
    pub fn restart_and_sync(&mut self, snapshot: &[(u64, Hash, u64)]) {
        self.crashed = false;
        for &(height, block, timestamp) in snapshot {
            if !self.durable_log.iter().any(|r| r.height == height) {
                self.durable_log.push(LogRecord {
                    height,
                    block,
                    timestamp,
                });
            }
        }
        self.rebuild_from_log();
    }
}
