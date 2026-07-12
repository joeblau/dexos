//! The per-shard checkpoint-chain sync state machine.
//!
//! A [`ShardSync`] ingests a stream of quorum-signed [`Checkpoint`]s for one
//! shard and maintains the *highest verified checkpoint* (height + state root).
//! Each ingested checkpoint is (1) matched to the shard, (2) verified against
//! the epoch's registered [`ValidatorSet`] via [`verify_checkpoint`], and
//! (3) linked into the verified chain by ancestry (`previous_state_root` must
//! equal the tip's `new_state_root`) and sequence continuity (`first_sequence`
//! must be exactly the tip's `last_sequence + 1`).
//!
//! # Validator-set trust
//!
//! Epoch 0 is a **weak-subjectivity bootstrap**: the host installs a trusted
//! genesis / checkpoint committee once (see [`ShardSync::bootstrap_validator_set`]).
//! Every later epoch must be installed via a quorum certificate from the
//! *prior* epoch over [`validator_set_transition_digest`] — free host
//! replacement of a non-bootstrap set is rejected.
//!
//! Out-of-order / gapped delivery buffers the future checkpoint and reports the
//! missing range so the driver can request a backfill; duplicate delivery is
//! idempotent; a checkpoint that conflicts with an already-accepted range is
//! rejected as equivocation. Compact commitments of accepted ranges are retained
//! for a bounded history window so conflicting historical QCs still surface
//! evidence after prune.

use std::collections::BTreeMap;

use consensus::{verify_checkpoint, Checkpoint};
use crypto::{
    hash_domain, ValidatorSet, DOMAIN_VALIDATOR_SET_TRANSITION, QuorumCertificate,
};
use types::{Hash, ShardId, StateRoot};

use crate::error::LightClientError;

/// Default bound on the equivocation/stale-detection history window.
pub const DEFAULT_HISTORY_LIMIT: usize = 1024;
/// Default bound on the out-of-order backfill buffer.
pub const DEFAULT_BUFFER_LIMIT: usize = 256;

/// Domain-separated digest the prior epoch signs to authorize a successor set.
///
/// Binds `(old_epoch, new_epoch, new_set.commitment())`.
#[must_use]
pub fn validator_set_transition_digest(
    old_epoch: u64,
    new_epoch: u64,
    new_set: &ValidatorSet,
) -> Hash {
    let mut buf = Vec::with_capacity(8 + 8 + 32);
    buf.extend_from_slice(&old_epoch.to_le_bytes());
    buf.extend_from_slice(&new_epoch.to_le_bytes());
    buf.extend_from_slice(new_set.commitment().as_bytes());
    hash_domain(DOMAIN_VALIDATOR_SET_TRANSITION, &buf)
}

/// A quorum-proven validator-set transition from `old_epoch` to `new_epoch`.
///
/// `certificate` must be a QC from the **old** epoch's set over
/// [`validator_set_transition_digest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSetTransition {
    /// Epoch of the committee that signed the transition (must already be known).
    pub old_epoch: u64,
    /// Epoch being installed (`old_epoch + 1` or any strictly greater unused epoch).
    pub new_epoch: u64,
    /// The successor validator set.
    pub new_set: ValidatorSet,
    /// Quorum certificate from `old_epoch` over the transition digest.
    pub certificate: QuorumCertificate,
}

/// Compact commitment retained for an accepted range (equivocation surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedRange {
    /// First sequence of the range.
    pub first: u64,
    /// Last sequence of the range.
    pub last: u64,
    /// Committed state root after the range.
    pub root: StateRoot,
    /// Epoch that certified the range.
    pub epoch: u64,
}

/// The highest verified checkpoint on a shard: its height and committed root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTip {
    /// The last sequence covered by the verified checkpoint (its "height").
    pub height: u64,
    /// The first sequence covered by the verified checkpoint.
    pub first_sequence: u64,
    /// The state root committed after applying the checkpoint's range.
    pub state_root: StateRoot,
    /// The epoch the verified checkpoint was produced in.
    pub epoch: u64,
}

/// The result of ingesting one checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// The checkpoint verified and advanced the verified tip.
    Advanced {
        /// New verified height.
        height: u64,
        /// New verified state root.
        state_root: StateRoot,
    },
    /// The checkpoint verified but is ahead of the tip; it was buffered pending
    /// a backfill of the intervening range `[need_from, got_from)`.
    Buffered {
        /// The next sequence the sync still needs (tip height + 1).
        need_from: u64,
        /// The first sequence of the buffered future checkpoint.
        got_from: u64,
    },
    /// The checkpoint duplicates an already-accepted range; ignored.
    Duplicate,
}

/// A single shard's verified checkpoint chain.
#[derive(Debug, Clone)]
pub struct ShardSync {
    shard_id: ShardId,
    trusted_root: StateRoot,
    validator_sets: BTreeMap<u64, ValidatorSet>,
    /// Highest epoch that has been installed (bootstrap or transition).
    latest_epoch: Option<u64>,
    tip: Option<VerifiedTip>,
    /// `first_sequence -> AcceptedRange` for equivocation detection. Bounded.
    accepted: BTreeMap<u64, AcceptedRange>,
    history_limit: usize,
    /// Future, QC-verified checkpoints held for backfill, keyed by
    /// `first_sequence`. Bounded; overflow drops with a counter.
    buffer: BTreeMap<u64, Checkpoint>,
    buffer_limit: usize,
    buffered_dropped: u64,
}

impl ShardSync {
    /// A new sync for `shard_id` anchored at `trusted_root` (the genesis /
    /// weak-subjectivity root the first checkpoint must chain onto).
    ///
    /// # Weak-subjectivity bootstrap
    ///
    /// Callers must install the epoch-0 (or checkpoint) committee via
    /// [`Self::bootstrap_validator_set`] from a trusted source (social
    /// consensus, hardened config, or a weak-subjectivity checkpoint). Later
    /// epochs require [`Self::apply_validator_set_transition`].
    #[must_use]
    pub fn new(shard_id: ShardId, trusted_root: StateRoot) -> Self {
        Self::with_limits(
            shard_id,
            trusted_root,
            DEFAULT_HISTORY_LIMIT,
            DEFAULT_BUFFER_LIMIT,
        )
    }

    /// A new sync with explicit history and backfill-buffer bounds.
    #[must_use]
    pub fn with_limits(
        shard_id: ShardId,
        trusted_root: StateRoot,
        history_limit: usize,
        buffer_limit: usize,
    ) -> Self {
        Self {
            shard_id,
            trusted_root,
            validator_sets: BTreeMap::new(),
            latest_epoch: None,
            tip: None,
            accepted: BTreeMap::new(),
            history_limit: history_limit.max(1),
            buffer: BTreeMap::new(),
            buffer_limit: buffer_limit.max(1),
            buffered_dropped: 0,
        }
    }

    /// Weak-subjectivity bootstrap: install the **first** trusted validator set.
    ///
    /// Allowed only when no set is known yet. Subsequent epochs must use
    /// [`Self::apply_validator_set_transition`]. Unsolicited replacement of an
    /// already-installed set is rejected.
    pub fn bootstrap_validator_set(
        &mut self,
        epoch: u64,
        set: ValidatorSet,
    ) -> Result<(), LightClientError> {
        if !self.validator_sets.is_empty() {
            return Err(LightClientError::UnsolicitedValidatorSet {
                epoch,
            });
        }
        self.validator_sets.insert(epoch, set);
        self.latest_epoch = Some(epoch);
        Ok(())
    }

    /// Register a validator set — **bootstrap only** (no set installed yet).
    ///
    /// Prefer [`Self::bootstrap_validator_set`] for clarity. This alias exists
    /// for call sites that historically treated host install as free; it now
    /// fails closed once a set is present.
    pub fn register_validator_set(&mut self, epoch: u64, set: ValidatorSet) {
        // Fallible path is preferred; this method keeps the old signature for
        // call-site migration but silently ignores unsolicited replacements so
        // existing host code that re-registers the same bootstrap epoch remains
        // harmless. Prefer `bootstrap_validator_set` / `apply_validator_set_transition`.
        let _ = self.try_register_validator_set(epoch, set);
    }

    /// Fallible registration: bootstrap if empty; reject unsolicited replacement.
    pub fn try_register_validator_set(
        &mut self,
        epoch: u64,
        set: ValidatorSet,
    ) -> Result<(), LightClientError> {
        if self.validator_sets.is_empty() {
            return self.bootstrap_validator_set(epoch, set);
        }
        // Idempotent re-bootstrap of the exact same epoch+commitment is OK.
        if let Some(existing) = self.validator_sets.get(&epoch) {
            if existing.commitment() == set.commitment() {
                return Ok(());
            }
        }
        Err(LightClientError::UnsolicitedValidatorSet { epoch })
    }

    /// Install a successor validator set proven by a QC from the prior epoch.
    pub fn apply_validator_set_transition(
        &mut self,
        transition: ValidatorSetTransition,
    ) -> Result<(), LightClientError> {
        if transition.new_epoch <= transition.old_epoch {
            return Err(LightClientError::InvalidValidatorSetTransition {
                old_epoch: transition.old_epoch,
                new_epoch: transition.new_epoch,
            });
        }
        if self.validator_sets.contains_key(&transition.new_epoch) {
            // Idempotent if identical.
            if let Some(existing) = self.validator_sets.get(&transition.new_epoch) {
                if existing.commitment() == transition.new_set.commitment() {
                    return Ok(());
                }
            }
            return Err(LightClientError::UnsolicitedValidatorSet {
                epoch: transition.new_epoch,
            });
        }
        let old_set = self
            .validator_sets
            .get(&transition.old_epoch)
            .ok_or(LightClientError::UnknownValidatorSet {
                epoch: transition.old_epoch,
            })?;
        let digest = validator_set_transition_digest(
            transition.old_epoch,
            transition.new_epoch,
            &transition.new_set,
        );
        if transition.certificate.message != digest {
            return Err(LightClientError::InvalidValidatorSetTransition {
                old_epoch: transition.old_epoch,
                new_epoch: transition.new_epoch,
            });
        }
        old_set
            .verify(&transition.certificate)
            .map_err(|_| LightClientError::InvalidValidatorSetTransition {
                old_epoch: transition.old_epoch,
                new_epoch: transition.new_epoch,
            })?;
        self.validator_sets
            .insert(transition.new_epoch, transition.new_set);
        self.latest_epoch = Some(
            self.latest_epoch
                .unwrap_or(0)
                .max(transition.new_epoch),
        );
        Ok(())
    }

    /// The shard this sync follows.
    #[must_use]
    pub fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// The trusted anchor root.
    #[must_use]
    pub fn trusted_root(&self) -> StateRoot {
        self.trusted_root
    }

    /// Latest installed validator-set epoch, if any.
    #[must_use]
    pub fn latest_epoch(&self) -> Option<u64> {
        self.latest_epoch
    }

    /// The highest verified checkpoint, if any has been accepted.
    #[must_use]
    pub fn verified_tip(&self) -> Option<VerifiedTip> {
        self.tip
    }

    /// The current verified height (last accepted sequence), if any.
    #[must_use]
    pub fn verified_height(&self) -> Option<u64> {
        self.tip.map(|t| t.height)
    }

    /// The current verified state root, if any.
    #[must_use]
    pub fn verified_root(&self) -> Option<StateRoot> {
        self.tip.map(|t| t.state_root)
    }

    /// The next sequence this sync expects (tip height + 1), or `None` before
    /// the first checkpoint is accepted.
    #[must_use]
    pub fn next_expected_sequence(&self) -> Option<u64> {
        self.tip.map(|t| t.height.wrapping_add(1))
    }

    /// Number of accepted ranges retained in the history window.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }

    /// Number of future checkpoints currently buffered for backfill.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Count of buffered checkpoints dropped due to buffer bounds (backpressure).
    #[must_use]
    pub fn buffered_dropped(&self) -> u64 {
        self.buffered_dropped
    }

    /// Ingest a checkpoint, advancing / buffering / rejecting it per the chain
    /// rules. Never panics; all failure modes are typed.
    pub fn ingest(&mut self, checkpoint: Checkpoint) -> Result<IngestOutcome, LightClientError> {
        if checkpoint.shard_id != self.shard_id {
            return Err(LightClientError::shard_mismatch(
                self.shard_id,
                checkpoint.shard_id,
            ));
        }
        let set = self.validator_sets.get(&checkpoint.epoch).ok_or(
            LightClientError::UnknownValidatorSet {
                epoch: checkpoint.epoch,
            },
        )?;
        // Verify the quorum certificate and header hash (catches tampering,
        // insufficient QC, wrong-epoch committee).
        verify_checkpoint(&checkpoint, set)?;

        match self.tip {
            None => {
                // Genesis: must chain onto the trusted root.
                if checkpoint.previous_state_root != self.trusted_root {
                    return Err(LightClientError::UntrustedRoot);
                }
                let out = self.accept(&checkpoint);
                self.drain_buffer();
                Ok(out)
            }
            Some(tip) => self.ingest_with_tip(checkpoint, tip),
        }
    }

    fn ingest_with_tip(
        &mut self,
        checkpoint: Checkpoint,
        tip: VerifiedTip,
    ) -> Result<IngestOutcome, LightClientError> {
        let expected = tip.height.wrapping_add(1);
        if checkpoint.first_sequence == expected {
            // Next in line: enforce ancestry linkage.
            if checkpoint.previous_state_root != tip.state_root {
                return Err(LightClientError::BrokenAncestry);
            }
            let out = self.accept(&checkpoint);
            self.drain_buffer();
            Ok(out)
        } else if checkpoint.first_sequence > expected {
            // Gap: buffer for backfill and report the missing range.
            self.buffer_future(checkpoint.clone());
            Ok(IngestOutcome::Buffered {
                need_from: expected,
                got_from: checkpoint.first_sequence,
            })
        } else {
            // Covers already-verified territory: duplicate or equivocation.
            self.classify_old(&checkpoint)
        }
    }

    /// Classify a checkpoint whose range starts at or before the verified tip.
    fn classify_old(&self, checkpoint: &Checkpoint) -> Result<IngestOutcome, LightClientError> {
        if let Some(range) = self.accepted.get(&checkpoint.first_sequence) {
            if range.last == checkpoint.last_sequence && range.root == checkpoint.new_state_root {
                Ok(IngestOutcome::Duplicate)
            } else {
                Err(LightClientError::Equivocation {
                    first: checkpoint.first_sequence,
                    last: checkpoint.last_sequence,
                })
            }
        } else {
            // Range boundary not on record (pruned). Conflicting historical QC
            // cannot be proven from local state; surface as stale-history miss
            // so callers can fetch evidence from peers rather than silently
            // accepting a fork.
            Err(LightClientError::PrunedHistoryConflict {
                first: checkpoint.first_sequence,
                last: checkpoint.last_sequence,
            })
        }
    }

    /// Record an accepted checkpoint and advance the tip.
    fn accept(&mut self, checkpoint: &Checkpoint) -> IngestOutcome {
        self.tip = Some(VerifiedTip {
            height: checkpoint.last_sequence,
            first_sequence: checkpoint.first_sequence,
            state_root: checkpoint.new_state_root,
            epoch: checkpoint.epoch,
        });
        self.accepted.insert(
            checkpoint.first_sequence,
            AcceptedRange {
                first: checkpoint.first_sequence,
                last: checkpoint.last_sequence,
                root: checkpoint.new_state_root,
                epoch: checkpoint.epoch,
            },
        );
        // Bound the history window: drop the oldest ranges.
        while self.accepted.len() > self.history_limit {
            if let Some((&k, _)) = self.accepted.iter().next() {
                self.accepted.remove(&k);
            } else {
                break;
            }
        }
        IngestOutcome::Advanced {
            height: checkpoint.last_sequence,
            state_root: checkpoint.new_state_root,
        }
    }

    /// Buffer a QC-verified future checkpoint, dropping (with a counter) when the
    /// bounded buffer is full so memory cannot grow under a burst.
    fn buffer_future(&mut self, checkpoint: Checkpoint) {
        if self.buffer.contains_key(&checkpoint.first_sequence) {
            return;
        }
        if self.buffer.len() >= self.buffer_limit {
            self.buffered_dropped = self.buffered_dropped.saturating_add(1);
            return;
        }
        self.buffer.insert(checkpoint.first_sequence, checkpoint);
    }

    /// Drain contiguous buffered checkpoints once the gap they were waiting on is
    /// filled (snapshot recovery after a gap).
    fn drain_buffer(&mut self) {
        loop {
            let Some(tip) = self.tip else { return };
            let expected = tip.height.wrapping_add(1);
            let Some(next) = self.buffer.remove(&expected) else {
                return;
            };
            if next.previous_state_root != tip.state_root {
                // Buffered fork / broken link: discard and stop draining.
                self.buffered_dropped = self.buffered_dropped.saturating_add(1);
                return;
            }
            self.accept(&next);
        }
    }

    /// Iterate accepted `(last_sequence, new_state_root)` pairs, newest first,
    /// for stale-root classification by proof re-verification.
    pub(crate) fn accepted_roots(&self) -> impl Iterator<Item = (u64, StateRoot)> + '_ {
        self.accepted
            .values()
            .rev()
            .map(|r| (r.last, r.root))
    }
}
