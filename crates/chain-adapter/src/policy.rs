//! Per-chain finality policy and the deposit observation state machine.

use crate::deposit::{DepositEvent, FinalityProof, SourceKey, VerifiedDeposit};
use crate::error::AdapterError;
use crate::withdrawal::WithdrawalStatus;
use std::collections::BTreeSet;

/// Default bound on distinct credited deposits a single tracker retains.
pub const DEFAULT_TRACKER_CAPACITY: usize = 1 << 20;

/// A per-chain finality rule: a transaction is final once it has at least
/// `min_confirmations` confirmations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityPolicy {
    min_confirmations: u32,
}

impl FinalityPolicy {
    /// Construct a policy requiring `min_confirmations` confirmations.
    #[must_use]
    pub const fn new(min_confirmations: u32) -> Self {
        Self { min_confirmations }
    }

    /// The required confirmation depth.
    #[must_use]
    pub const fn min_confirmations(self) -> u32 {
        self.min_confirmations
    }

    /// Whether `confirmations` satisfies this policy.
    #[must_use]
    pub const fn is_final(self, confirmations: u32) -> bool {
        confirmations >= self.min_confirmations
    }

    /// Map a raw confirmation count onto the observation state machine.
    ///
    /// `0` confirmations is [`WithdrawalStatus::Pending`], any positive count
    /// below the threshold is [`WithdrawalStatus::Confirming`], and reaching the
    /// threshold is [`WithdrawalStatus::Finalized`].
    #[must_use]
    pub const fn confirmation_status(self, confirmations: u32) -> WithdrawalStatus {
        if self.is_final(confirmations) {
            WithdrawalStatus::Finalized
        } else if confirmations == 0 {
            WithdrawalStatus::Pending
        } else {
            WithdrawalStatus::Confirming { confirmations }
        }
    }
}

/// The deposit observation state machine: enforces per-chain finality and
/// exactly-once crediting via a `(chain, tx, event)` uniqueness index.
///
/// The credited-key set is bounded by `capacity`; ingress past that bound is
/// rejected with [`AdapterError::CapacityExceeded`] rather than growing without
/// limit.
#[derive(Debug, Clone)]
pub struct DepositTracker {
    policy: FinalityPolicy,
    credited: BTreeSet<SourceKey>,
    capacity: usize,
}

impl DepositTracker {
    /// Build a tracker with the default capacity.
    #[must_use]
    pub fn new(policy: FinalityPolicy) -> Self {
        Self::with_capacity(policy, DEFAULT_TRACKER_CAPACITY)
    }

    /// Build a tracker with an explicit credited-key capacity.
    #[must_use]
    pub fn with_capacity(policy: FinalityPolicy, capacity: usize) -> Self {
        Self {
            policy,
            credited: BTreeSet::new(),
            capacity,
        }
    }

    /// The finality policy in force.
    #[must_use]
    pub const fn policy(&self) -> FinalityPolicy {
        self.policy
    }

    /// Number of deposits credited so far.
    #[must_use]
    pub fn credited_count(&self) -> usize {
        self.credited.len()
    }

    /// Whether the given key was already credited.
    #[must_use]
    pub fn is_credited(&self, key: &SourceKey) -> bool {
        self.credited.contains(key)
    }

    /// Observe a deposit event at a given finality proof.
    ///
    /// Returns `Ok(None)` while the deposit is still below the finality
    /// threshold (the certificate is withheld). Once final, the deposit is
    /// credited exactly once and returned; a second final observation of the
    /// same `(chain, tx, event)` is rejected.
    ///
    /// # Errors
    /// - [`AdapterError::DuplicateObservation`] on replay of a credited key.
    /// - [`AdapterError::CapacityExceeded`] if the credited set is full.
    pub fn observe(
        &mut self,
        event: &DepositEvent,
        proof: FinalityProof,
    ) -> Result<Option<VerifiedDeposit>, AdapterError> {
        if !self.policy.is_final(proof.confirmations) {
            return Ok(None);
        }
        let key = event.source_key();
        if self.credited.contains(&key) {
            return Err(AdapterError::DuplicateObservation);
        }
        if self.credited.len() >= self.capacity {
            return Err(AdapterError::CapacityExceeded);
        }
        self.credited.insert(key);
        Ok(Some(VerifiedDeposit::new(event.clone(), proof)))
    }

    /// Credit an already-verified deposit, enforcing uniqueness and capacity.
    ///
    /// # Errors
    /// - [`AdapterError::NotFinal`] if the deposit's proof is below policy.
    /// - [`AdapterError::DuplicateObservation`] on replay of a credited key.
    /// - [`AdapterError::CapacityExceeded`] if the credited set is full.
    pub fn accept(&mut self, deposit: &VerifiedDeposit) -> Result<(), AdapterError> {
        if !self.policy.is_final(deposit.finality_proof.confirmations) {
            return Err(AdapterError::NotFinal {
                have: deposit.finality_proof.confirmations,
                need: self.policy.min_confirmations(),
            });
        }
        let key = deposit.source_key();
        if self.credited.contains(&key) {
            return Err(AdapterError::DuplicateObservation);
        }
        if self.credited.len() >= self.capacity {
            return Err(AdapterError::CapacityExceeded);
        }
        self.credited.insert(key);
        Ok(())
    }
}
