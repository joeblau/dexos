//! Wall-clock and I/O translation layer for the pure Minimmit reactor.
//!
//! Timers, network framing, block building/verification, execution and commits
//! stop here. The consensus crate receives only deterministic [`MinimmitInput`]
//! values and returns declarative effects.

use std::collections::BTreeMap;
use std::time::Duration;

use codec::{Frame, TrafficClass};
use consensus::{
    ConsensusMessage, ExecAttest, MinimmitEffect, MinimmitInput, MinimmitReplica, ParentRef, Proof,
    Propose,
};
use crypto::KeyPair;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use types::Hash;

use crate::ConsensusSection;

/// Work the node's network/builder/executor/checkpoint subsystems must perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverEvent {
    /// Send this P0 frame to all peers.
    Broadcast(Frame),
    /// Build and sign a proposal extending `parent`, then call `proposal_built`.
    BuildProposal(ParentRef),
    /// Verify an inbound proposal, then call `proposal_verified`.
    VerifyProposal(Box<Propose>),
    /// Execute the consensus-final block, then call `execution_completed`.
    Execute { block: Hash, height: u64 },
    /// Persist the execution-final block and fold it into checkpoint headers.
    Commit { block: Hash, height: u64 },
}

/// Typed failures at the node/consensus boundary.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The frame was not sent on the P0 consensus lane.
    #[error("consensus payload arrived on non-consensus traffic lane")]
    WrongTrafficClass,
    /// The Minimmit wire payload was malformed or used an unknown tag.
    #[error(transparent)]
    Wire(#[from] consensus::WireError),
    /// `2 * delta_ms` overflowed.
    #[error("consensus.delta_ms is too large for a 2-delta timer")]
    DeltaOverflow,
    /// Execution completed for a block with no retained notarization proof.
    #[error("consensus-final block has no retained notarization proof")]
    MissingNotarization,
    /// The P0 transport sequence cannot advance without wrapping.
    #[error("consensus transport sequence exhausted")]
    SequenceExhausted,
}

/// Node-owned driver for a single Minimmit replica.
pub struct ConsensusDriver {
    replica: MinimmitReplica,
    self_index: u16,
    signer: KeyPair,
    timer_duration: Duration,
    next_sequence: u64,
    timers: BTreeMap<u64, JoinHandle<()>>,
    timer_tx: mpsc::Sender<u64>,
    timer_rx: mpsc::Receiver<u64>,
}

impl ConsensusDriver {
    /// Construct from the validated node consensus section, making `delta_ms`
    /// a load-bearing runtime setting.
    pub fn from_config(
        replica: MinimmitReplica,
        self_index: u16,
        signer: KeyPair,
        config: &ConsensusSection,
    ) -> Result<Self, DriverError> {
        Self::new(replica, self_index, signer, config.delta_ms)
    }

    /// Construct a driver. Initial reactor effects must be passed to [`Self::drive`].
    pub fn new(
        replica: MinimmitReplica,
        self_index: u16,
        signer: KeyPair,
        delta_ms: u64,
    ) -> Result<Self, DriverError> {
        let timer_ms = delta_ms.checked_mul(2).ok_or(DriverError::DeltaOverflow)?;
        let (timer_tx, timer_rx) = mpsc::channel(64);
        Ok(Self {
            replica,
            self_index,
            signer,
            timer_duration: Duration::from_millis(timer_ms),
            next_sequence: 0,
            timers: BTreeMap::new(),
            timer_tx,
            timer_rx,
        })
    }

    /// The exact node-side view timeout (`2 * delta_ms`).
    #[must_use]
    pub fn timer_duration(&self) -> Duration {
        self.timer_duration
    }

    /// Translate reactor effects, arming/cancelling real Tokio timers as needed.
    pub fn drive(&mut self, effects: Vec<MinimmitEffect>) -> Result<Vec<DriverEvent>, DriverError> {
        let mut events = Vec::new();
        for effect in effects {
            match effect {
                MinimmitEffect::Broadcast(message) => {
                    let (msg_type, payload) = message.encode()?;
                    let sequence = self.next_sequence;
                    self.next_sequence = self
                        .next_sequence
                        .checked_add(1)
                        .ok_or(DriverError::SequenceExhausted)?;
                    events.push(DriverEvent::Broadcast(Frame {
                        class: TrafficClass::Consensus,
                        msg_type,
                        sequence,
                        payload,
                    }));
                }
                MinimmitEffect::ArmTimer { view } => {
                    if let Some(old) = self.timers.remove(&view) {
                        old.abort();
                    }
                    let tx = self.timer_tx.clone();
                    let duration = self.timer_duration;
                    self.timers.insert(
                        view,
                        tokio::spawn(async move {
                            tokio::time::sleep(duration).await;
                            let _ = tx.send(view).await;
                        }),
                    );
                }
                MinimmitEffect::CancelTimer { view } => {
                    if let Some(timer) = self.timers.remove(&view) {
                        timer.abort();
                    }
                }
                MinimmitEffect::NeedProposal { parent } => {
                    events.push(DriverEvent::BuildProposal(parent));
                }
                MinimmitEffect::ConsensusFinal { block, height } => {
                    events.push(DriverEvent::Execute { block, height });
                }
                MinimmitEffect::Finalized { block, height } => {
                    events.push(DriverEvent::Commit { block, height });
                }
                MinimmitEffect::Slash(_) => {}
            }
        }
        Ok(events)
    }

    /// Wait for the next OS timer and inject its view into the pure reactor.
    pub async fn next_timer(&mut self) -> Result<Vec<DriverEvent>, DriverError> {
        let Some(view) = self.timer_rx.recv().await else {
            return Ok(Vec::new());
        };
        self.timers.remove(&view);
        self.inject(MinimmitInput::TimerFired { view })
    }

    /// Periodic node pulse for R7 proof re-dissemination.
    pub fn tick(&mut self) -> Result<Vec<DriverEvent>, DriverError> {
        self.inject(MinimmitInput::Tick)
    }

    /// Decode an inbound P0 frame, inject it, and request proposal verification.
    pub fn on_frame(&mut self, frame: &Frame) -> Result<Vec<DriverEvent>, DriverError> {
        if frame.class != TrafficClass::Consensus {
            return Err(DriverError::WrongTrafficClass);
        }
        let message = ConsensusMessage::decode(frame.msg_type, &frame.payload)?;
        let proposal = match &message {
            ConsensusMessage::Propose(value) => Some(value.clone()),
            _ => None,
        };
        let mut events = self.inject(MinimmitInput::Message(message))?;
        if let Some(proposal) = proposal {
            events.push(DriverEvent::VerifyProposal(Box::new(proposal)));
        }
        Ok(events)
    }

    /// Re-inject a locally built proposal through the same message path.
    pub fn proposal_built(&mut self, proposal: Propose) -> Result<Vec<DriverEvent>, DriverError> {
        self.inject(MinimmitInput::Message(ConsensusMessage::Propose(proposal)))
    }

    /// Deliver the node-side block verification verdict.
    pub fn proposal_verified(
        &mut self,
        proposal: &Propose,
        valid: bool,
    ) -> Result<Vec<DriverEvent>, DriverError> {
        self.inject(MinimmitInput::ProposalVerified {
            view: proposal.view,
            block_hash: proposal.block_hash,
            valid,
        })
    }

    /// Sign and inject the local execution attestation after deterministic execution.
    pub fn execution_completed(
        &mut self,
        block: Hash,
        height: u64,
        execution_root: Hash,
    ) -> Result<Vec<DriverEvent>, DriverError> {
        let view = self
            .replica
            .proofs()
            .iter()
            .find_map(|(view, proof)| match proof {
                Proof::Notarization(value) if value.block_hash == block => Some(*view),
                _ => None,
            })
            .ok_or(DriverError::MissingNotarization)?;
        let mut attest = ExecAttest {
            epoch: self.replica.epoch(),
            view,
            height,
            block_hash: block,
            execution_root,
            validator_index: self.self_index,
            signature: [0; 64],
        };
        attest.signature = self.signer.sign(attest.digest().as_bytes());
        self.inject(MinimmitInput::Message(ConsensusMessage::ExecAttest(attest)))
    }

    fn inject(&mut self, input: MinimmitInput) -> Result<Vec<DriverEvent>, DriverError> {
        let effects = self.replica.step(input);
        self.drive(effects)
    }
}

impl Drop for ConsensusDriver {
    fn drop(&mut self) {
        for (_, timer) in std::mem::take(&mut self.timers) {
            timer.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{notarize_digest, MinimmitCommittee, Notarize};
    use crypto::Validator;

    fn driver() -> (ConsensusDriver, Vec<MinimmitEffect>, Vec<KeyPair>) {
        let keys: Vec<_> = (0u8..6).map(|i| KeyPair::from_seed(&[i; 32])).collect();
        let validators = keys
            .iter()
            .map(|key| Validator {
                public_key: key.public(),
                weight: 1,
            })
            .collect();
        let committee = MinimmitCommittee::new_unit(0, validators).unwrap();
        let (replica, effects) = MinimmitReplica::new_with_signer(
            committee,
            1,
            Hash::ZERO,
            0,
            KeyPair::from_seed(&[1; 32]),
        )
        .unwrap();
        (
            ConsensusDriver::new(replica, 1, KeyPair::from_seed(&[1; 32]), 1).unwrap(),
            effects,
            keys,
        )
    }

    #[tokio::test]
    async fn arms_two_delta_timer_and_routes_consensus_frames() {
        let (mut driver, initial, keys) = driver();
        assert_eq!(driver.timer_duration(), Duration::from_millis(2));
        let _ = driver.drive(initial).unwrap();
        let timer_events = tokio::time::timeout(Duration::from_millis(100), driver.next_timer())
            .await
            .expect("2-delta timer must fire")
            .unwrap();
        assert!(timer_events.iter().any(|event| matches!(
            event,
            DriverEvent::Broadcast(Frame {
                class: TrafficClass::Consensus,
                ..
            })
        )));

        let block = Hash::from_bytes([7; 32]);
        let digest = notarize_digest(0, 1, block);
        let message = ConsensusMessage::Notarize(Notarize {
            epoch: 0,
            view: 1,
            block_hash: block,
            validator_index: 0,
            signature: keys[0].sign(digest.as_bytes()),
        });
        let (msg_type, payload) = message.encode().unwrap();
        let frame = Frame {
            class: TrafficClass::Consensus,
            msg_type,
            sequence: 9,
            payload,
        };
        driver.on_frame(&frame).unwrap();
        let mut wrong_lane = frame;
        wrong_lane.class = TrafficClass::MarketData;
        assert!(matches!(
            driver.on_frame(&wrong_lane),
            Err(DriverError::WrongTrafficClass)
        ));
        driver.tick().unwrap();

        let block = Hash::from_bytes([8; 32]);
        let translated = driver
            .drive(vec![
                MinimmitEffect::ConsensusFinal { block, height: 1 },
                MinimmitEffect::Finalized { block, height: 1 },
            ])
            .unwrap();
        assert_eq!(
            translated,
            vec![
                DriverEvent::Execute { block, height: 1 },
                DriverEvent::Commit { block, height: 1 },
            ]
        );
    }

    #[tokio::test]
    async fn broadcast_sequence_exhaustion_fails_closed() {
        let (mut driver, _, keys) = driver();
        driver.next_sequence = u64::MAX;
        let block = Hash::from_bytes([9; 32]);
        let digest = notarize_digest(0, 0, block);
        let message = ConsensusMessage::Notarize(Notarize {
            epoch: 0,
            view: 0,
            block_hash: block,
            validator_index: 0,
            signature: keys[0].sign(digest.as_bytes()),
        });

        assert!(matches!(
            driver.drive(vec![MinimmitEffect::Broadcast(message)]),
            Err(DriverError::SequenceExhausted)
        ));
        assert_eq!(driver.next_sequence, u64::MAX);
    }
}
