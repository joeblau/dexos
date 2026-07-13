//! Minimmit reactor adapter for the deterministic simulator.

use std::collections::BTreeMap;

use consensus::minimmit::{
    BlockHeader, ConsensusMessage, Effect, ExecAttest, Input, MinimmitCommittee, MinimmitReplica,
    Notarize, ParentRef, Propose,
};
use consensus::{build_checkpoint_header, CheckpointHeader};
use crypto::{hash_domain, hash_leaf, hash_node, KeyPair};
use types::{Hash, ShardId};

pub type NodeId = u32;

const DOMAIN_BLOCK: &[u8] = b"dexos:sim:minimmit:block:v1";
const DOMAIN_EVIL: &[u8] = b"dexos:sim:minimmit:evil-block:v1";

#[must_use]
pub fn canonical_block(height: u64) -> Hash {
    hash_domain(DOMAIN_BLOCK, &height.to_le_bytes())
}

#[must_use]
pub fn byzantine_block(height: u64) -> Hash {
    hash_domain(DOMAIN_EVIL, &height.to_le_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    Honest,
    EquivocatingVoter,
    EquivocatingLeader,
    InvalidSigner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Broadcast,
    To(NodeId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Consensus(ConsensusMessage),
}

impl Payload {
    #[must_use]
    pub fn digest(&self) -> Hash {
        match self {
            Self::Consensus(message) => match message {
                ConsensusMessage::Propose(value) => value.auth_digest(),
                ConsensusMessage::Notarize(value) => value.digest(),
                ConsensusMessage::Nullify(value) => value.digest(),
                ConsensusMessage::Notarization(value) => value.digest(),
                ConsensusMessage::Nullification(value) => value.digest(),
                ConsensusMessage::ExecAttest(value) => value.digest(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub target: Target,
    pub payload: Payload,
}

impl Outgoing {
    fn broadcast(message: ConsensusMessage) -> Self {
        Self {
            target: Target::Broadcast,
            payload: Payload::Consensus(message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub from: NodeId,
    pub to: NodeId,
    pub payload: Payload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NodeAction {
    Send(Box<Outgoing>),
    ArmTimer { view: u64 },
    CancelTimer { view: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogRecord {
    height: u64,
    block: Hash,
    timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct Node {
    id: NodeId,
    index: u16,
    keypair: KeyPair,
    committee: MinimmitCommittee,
    replica: MinimmitReplica,
    behavior: Behavior,
    max_height: u64,
    crashed: bool,
    finalized: BTreeMap<u64, Hash>,
    finalized_at: BTreeMap<u64, u64>,
    applied_upto: u64,
    block_heights: BTreeMap<Hash, u64>,
    state_root: Hash,
    checkpoints: Vec<CheckpointHeader>,
    durable_log: Vec<LogRecord>,
    gossip: Vec<ConsensusMessage>,
    proposal_gossip: BTreeMap<u64, Propose>,
    exec_gossip: BTreeMap<u64, ExecAttest>,
    slash_count: usize,
}

impl Node {
    pub(crate) fn new(
        index: u16,
        seed: &[u8; 32],
        committee: MinimmitCommittee,
        behavior: Behavior,
        genesis: Hash,
        max_height: u64,
    ) -> Result<(Self, Vec<NodeAction>), consensus::VoteError> {
        let keypair = KeyPair::from_seed(seed);
        let (replica, effects) = if behavior == Behavior::InvalidSigner {
            MinimmitReplica::new(committee.clone(), index, genesis, committee.epoch())?
        } else {
            MinimmitReplica::new_with_signer(
                committee.clone(),
                index,
                genesis,
                committee.epoch(),
                keypair.clone(),
            )?
        };
        let mut block_heights = BTreeMap::new();
        block_heights.insert(genesis, 0);
        let mut node = Self {
            id: u32::from(index),
            index,
            keypair,
            committee,
            replica,
            behavior,
            max_height,
            crashed: false,
            finalized: BTreeMap::new(),
            finalized_at: BTreeMap::new(),
            applied_upto: 0,
            block_heights,
            state_root: Hash::ZERO,
            checkpoints: Vec::new(),
            durable_log: Vec::new(),
            gossip: Vec::new(),
            proposal_gossip: BTreeMap::new(),
            exec_gossip: BTreeMap::new(),
            slash_count: 0,
        };
        let actions = node.consume_effects(effects, 0);
        Ok((node, actions))
    }

    #[must_use]
    pub fn id(&self) -> NodeId {
        self.id
    }

    #[must_use]
    pub fn is_crashed(&self) -> bool {
        self.crashed
    }

    #[must_use]
    pub fn state_root(&self) -> Hash {
        self.state_root
    }

    #[must_use]
    pub fn finalized_count(&self) -> u64 {
        u64::try_from(self.finalized.len()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn has_finalized(&self, height: u64) -> bool {
        self.finalized.contains_key(&height)
    }

    #[must_use]
    pub fn checkpoints(&self) -> &[CheckpointHeader] {
        &self.checkpoints
    }

    #[must_use]
    pub fn leader_for_view(&self, view: u64) -> NodeId {
        u32::from(self.committee.leader(view))
    }

    #[must_use]
    pub fn forks_detected(&self) -> usize {
        self.slash_count
    }

    #[must_use]
    pub fn equivocations_detected(&self) -> usize {
        self.slash_count
    }

    pub(crate) fn handle(&mut self, env: &Envelope, now: u64) -> Vec<NodeAction> {
        if self.crashed {
            return Vec::new();
        }
        let Payload::Consensus(message) = &env.payload;
        if let ConsensusMessage::Propose(proposal) = message {
            self.block_heights
                .insert(proposal.block_hash, proposal.block.height);
            self.proposal_gossip
                .entry(proposal.view)
                .or_insert_with(|| proposal.clone());
        }
        let mut actions = self.drive(Input::Message(message.clone()), now);
        if let ConsensusMessage::Propose(proposal) = message {
            actions.extend(self.drive(
                Input::ProposalVerified {
                    view: proposal.view,
                    block_hash: proposal.block_hash,
                    valid: proposal.block.parent_hash == proposal.parent.parent_hash,
                },
                now,
            ));
            actions.extend(self.adversarial_vote(proposal));
        }
        actions
    }

    pub(crate) fn timer_fired(&mut self, view: u64, now: u64) -> Vec<NodeAction> {
        if self.crashed {
            Vec::new()
        } else {
            self.drive(Input::TimerFired { view }, now)
        }
    }

    pub(crate) fn tick(&mut self, now: u64) -> Vec<NodeAction> {
        if self.crashed {
            Vec::new()
        } else {
            let mut actions: Vec<NodeAction> =
                self.proposal_gossip
                    .values()
                    .cloned()
                    .map(|proposal| {
                        NodeAction::Send(Box::new(Outgoing::broadcast(ConsensusMessage::Propose(
                            proposal,
                        ))))
                    })
                    .chain(self.exec_gossip.values().cloned().map(|attest| {
                        NodeAction::Send(Box::new(Outgoing::broadcast(
                            ConsensusMessage::ExecAttest(attest),
                        )))
                    }))
                    .chain(
                        self.gossip.iter().cloned().map(|message| {
                            NodeAction::Send(Box::new(Outgoing::broadcast(message)))
                        }),
                    )
                    .collect();
            actions.extend(self.drive(Input::Tick, now));
            actions
        }
    }

    fn drive(&mut self, input: Input, now: u64) -> Vec<NodeAction> {
        let effects = self.replica.step(input);
        self.consume_effects(effects, now)
    }

    fn consume_effects(&mut self, effects: Vec<Effect>, now: u64) -> Vec<NodeAction> {
        let mut actions = Vec::new();
        let mut pending = effects;
        while let Some(effect) = pending.pop() {
            match effect {
                Effect::Broadcast(message) => {
                    if let ConsensusMessage::ExecAttest(attest) = &message {
                        self.exec_gossip
                            .entry(attest.height)
                            .or_insert_with(|| attest.clone());
                    } else if !matches!(message, ConsensusMessage::Propose(_))
                        && !self.gossip.contains(&message)
                    {
                        if self.gossip.len() == 8 {
                            self.gossip.remove(0);
                        }
                        self.gossip.push(message.clone());
                    }
                    actions.push(NodeAction::Send(Box::new(Outgoing::broadcast(message))));
                }
                Effect::ArmTimer { view } => actions.push(NodeAction::ArmTimer { view }),
                Effect::CancelTimer { view } => actions.push(NodeAction::CancelTimer { view }),
                Effect::NeedProposal { parent } => {
                    let messages = self.build_proposals(parent);
                    for message in messages {
                        let proposal = match &message {
                            ConsensusMessage::Propose(value) => value.clone(),
                            _ => continue,
                        };
                        self.block_heights
                            .insert(proposal.block_hash, proposal.block.height);
                        self.proposal_gossip
                            .entry(proposal.view)
                            .or_insert_with(|| proposal.clone());
                        pending.extend(self.replica.step(Input::Message(message)));
                        pending.extend(self.replica.step(Input::ProposalVerified {
                            view: proposal.view,
                            block_hash: proposal.block_hash,
                            valid: true,
                        }));
                    }
                }
                Effect::ConsensusFinal { block, height } => {
                    let execution_root = hash_leaf(block.as_bytes());
                    let Some((view, _)) = self
                        .replica
                        .proofs()
                        .iter()
                        .find(|(_, proof)| matches!(proof, consensus::minimmit::Proof::Notarization(value) if value.block_hash == block))
                    else {
                        continue;
                    };
                    let mut attest = ExecAttest {
                        epoch: self.committee.epoch(),
                        view: *view,
                        height,
                        block_hash: block,
                        execution_root,
                        validator_index: self.index,
                        signature: [0; 64],
                    };
                    attest.signature = self.keypair.sign(attest.digest().as_bytes());
                    actions.push(NodeAction::Send(Box::new(Outgoing::broadcast(
                        ConsensusMessage::ExecAttest(attest),
                    ))));
                }
                Effect::Finalized { block, height } => self.record_finalized(height, block, now),
                Effect::Slash(_) => self.slash_count = self.slash_count.saturating_add(1),
            }
        }
        actions
    }

    fn build_proposals(&self, parent: ParentRef) -> Vec<ConsensusMessage> {
        let view = self.replica.view();
        let height = self
            .block_heights
            .get(&parent.parent_hash)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        if height > self.max_height {
            return Vec::new();
        }
        let honest = self.sign_proposal(view, height, parent, canonical_block(height));
        if self.behavior == Behavior::EquivocatingLeader {
            vec![
                ConsensusMessage::Propose(honest),
                ConsensusMessage::Propose(self.sign_proposal(
                    view,
                    height,
                    parent,
                    byzantine_block(height),
                )),
            ]
        } else {
            vec![ConsensusMessage::Propose(honest)]
        }
    }

    fn sign_proposal(&self, view: u64, height: u64, parent: ParentRef, payload: Hash) -> Propose {
        let block = BlockHeader {
            height,
            parent_hash: parent.parent_hash,
            payload_root: payload,
        };
        let mut proposal = Propose {
            epoch: self.committee.epoch(),
            view,
            block,
            block_hash: block.hash(),
            parent,
            proposer_index: self.index,
            notarize_sig: [0; 64],
            propose_sig: [0; 64],
        };
        proposal.notarize_sig = self.keypair.sign(proposal.notarize_digest().as_bytes());
        proposal.propose_sig = self.keypair.sign(proposal.auth_digest().as_bytes());
        proposal
    }

    fn adversarial_vote(&self, proposal: &Propose) -> Vec<NodeAction> {
        if self.index == proposal.proposer_index {
            return Vec::new();
        }
        let block_hash = match self.behavior {
            Behavior::EquivocatingVoter => byzantine_block(proposal.block.height),
            Behavior::InvalidSigner => proposal.block_hash,
            Behavior::Honest | Behavior::EquivocatingLeader => return Vec::new(),
        };
        let mut vote = Notarize {
            epoch: proposal.epoch,
            view: proposal.view,
            block_hash,
            validator_index: self.index,
            signature: [0; 64],
        };
        vote.signature = if self.behavior == Behavior::InvalidSigner {
            KeyPair::from_seed(&[0xAB; 32]).sign(vote.digest().as_bytes())
        } else {
            self.keypair.sign(vote.digest().as_bytes())
        };
        vec![NodeAction::Send(Box::new(Outgoing::broadcast(
            ConsensusMessage::Notarize(vote),
        )))]
    }

    fn record_finalized(&mut self, height: u64, block: Hash, timestamp: u64) {
        if self.finalized.insert(height, block).is_some() {
            return;
        }
        self.finalized_at.insert(height, timestamp);
        self.durable_log.push(LogRecord {
            height,
            block,
            timestamp,
        });
        self.advance_apply();
    }

    fn advance_apply(&mut self) {
        loop {
            let height = self.applied_upto.saturating_add(1);
            let Some(&block) = self.finalized.get(&height) else {
                break;
            };
            let timestamp = self.finalized_at.get(&height).copied().unwrap_or(0);
            let previous = self.state_root;
            self.state_root = hash_node(previous, block);
            let execution_root = hash_leaf(block.as_bytes());
            if let Ok(header) = build_checkpoint_header(
                self.committee.epoch(),
                ShardId::new(0),
                height,
                height,
                previous,
                self.state_root,
                &[block],
                &[execution_root],
                Hash::ZERO,
                timestamp,
            ) {
                self.checkpoints.push(header);
            }
            self.applied_upto = height;
        }
    }

    pub(crate) fn crash(&mut self) {
        self.crashed = true;
    }

    pub(crate) fn restart_and_sync(&mut self, snapshot: &[(u64, Hash, u64)]) {
        self.crashed = false;
        for &(height, block, timestamp) in snapshot {
            if !self.finalized.contains_key(&height) {
                self.record_finalized(height, block, timestamp);
            }
        }
    }

    #[must_use]
    pub fn durable_snapshot(&self) -> Vec<(u64, Hash, u64)> {
        self.durable_log
            .iter()
            .map(|record| (record.height, record.block, record.timestamp))
            .collect()
    }
}
