//! Atomic per-account nonce reservation and the withdrawal lifecycle state
//! machine, with a durable, idempotent broadcast transaction identity.
//!
//! [`WithdrawalLedger`] is the single source of truth for which
//! `(account, nonce)` pairs are claimed. A pair is held by at most one
//! withdrawal id at a time, so *concurrent same-nonce requests produce exactly
//! one reservation*. Broadcasting records a durable [`TxId`] keyed by the
//! withdrawal id, so a *crash/retry returns the same identity and never
//! double-sends*.
//!
//! Lifecycle: `Reserved → Broadcast(tx) → Finalized`. A `Reserved` withdrawal
//! that was never broadcast may be `release`d, freeing its nonce for retry;
//! once broadcast it must be finalized, since releasing a sent transaction would
//! risk a double-send.

use crate::error::AdapterError;
use crate::ids::TxId;
use crate::withdrawal::{WithdrawalId, WithdrawalRequest};
use std::collections::BTreeMap;
use types::AccountId;

/// Where a reserved withdrawal sits in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationState {
    /// The nonce is claimed but nothing has been broadcast yet.
    Reserved,
    /// Broadcast with a durable, idempotent transaction identity.
    Broadcast(TxId),
    /// Settled on-chain; the nonce is permanently consumed.
    Finalized,
}

/// The outcome of a successful nonce reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalReservation {
    /// The reserved withdrawal id.
    pub withdrawal_id: WithdrawalId,
    /// The debited account.
    pub account: AccountId,
    /// The reserved per-account nonce.
    pub nonce: u64,
    /// `true` if this call created the reservation; `false` if it returned an
    /// existing reservation for the same request (an idempotent retry).
    pub fresh: bool,
}

#[derive(Debug, Clone)]
struct Entry {
    withdrawal_id: WithdrawalId,
    state: ReservationState,
}

/// Reserves per-account withdrawal nonces atomically and idempotently and tracks
/// each reservation through broadcast to finalize/release.
#[derive(Debug, Default)]
pub struct WithdrawalLedger {
    /// `(account, nonce) → entry`. A pair present here is claimed.
    by_nonce: BTreeMap<(u32, u64), Entry>,
    /// `withdrawal id → (account, nonce)`, for idempotent id-based lookup.
    index: BTreeMap<WithdrawalId, (u32, u64)>,
}

impl WithdrawalLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live (non-released) reservations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_nonce.len()
    }

    /// Whether the ledger holds no reservations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_nonce.is_empty()
    }

    /// Atomically reserve `(account, nonce)` for `req`.
    ///
    /// Idempotent: if the same withdrawal id already holds the reservation, the
    /// existing reservation is returned with `fresh == false`. A *different*
    /// withdrawal id colliding on the same `(account, nonce)` is rejected — so
    /// racing distinct requests for one nonce yield exactly one reservation.
    ///
    /// # Errors
    /// [`AdapterError::ReplayedNonce`] if the nonce is already held by a
    /// different withdrawal (including a consumed/finalized one).
    pub fn reserve(
        &mut self,
        req: &WithdrawalRequest,
    ) -> Result<WithdrawalReservation, AdapterError> {
        let id = req.id();
        let key = (req.account_id.get(), req.nonce);
        if let Some(entry) = self.by_nonce.get(&key) {
            if entry.withdrawal_id == id {
                return Ok(WithdrawalReservation {
                    withdrawal_id: id,
                    account: req.account_id,
                    nonce: req.nonce,
                    fresh: false,
                });
            }
            return Err(AdapterError::ReplayedNonce);
        }
        self.by_nonce.insert(
            key,
            Entry {
                withdrawal_id: id,
                state: ReservationState::Reserved,
            },
        );
        self.index.insert(id, key);
        Ok(WithdrawalReservation {
            withdrawal_id: id,
            account: req.account_id,
            nonce: req.nonce,
            fresh: true,
        })
    }

    /// The current lifecycle state of a reserved withdrawal, if any.
    #[must_use]
    pub fn state(&self, id: WithdrawalId) -> Option<&ReservationState> {
        let key = self.index.get(&id)?;
        self.by_nonce.get(key).map(|e| &e.state)
    }

    /// The durable broadcast transaction identity for a withdrawal, if it has
    /// been broadcast. A crash/retry consults this to recover the same identity.
    #[must_use]
    pub fn broadcast_tx(&self, id: WithdrawalId) -> Option<TxId> {
        match self.state(id)? {
            ReservationState::Broadcast(tx) => Some(tx.clone()),
            _ => None,
        }
    }

    /// Record the broadcast transaction identity for a reserved withdrawal.
    ///
    /// Idempotent and safe under crash/retry: if the withdrawal was already
    /// broadcast with the same `tx`, that recorded [`TxId`] is returned unchanged
    /// (no double-send). Presenting a *different* `tx` for an already-broadcast
    /// withdrawal is rejected, preventing a second transaction identity.
    ///
    /// # Errors
    /// - [`AdapterError::UnknownTx`] if the withdrawal was never reserved.
    /// - [`AdapterError::IllegalTransition`] if it is already finalized, or a
    ///   conflicting `tx` is presented for an already-broadcast withdrawal.
    pub fn record_broadcast(&mut self, id: WithdrawalId, tx: TxId) -> Result<TxId, AdapterError> {
        let key = *self.index.get(&id).ok_or(AdapterError::UnknownTx)?;
        let entry = self.by_nonce.get_mut(&key).ok_or(AdapterError::UnknownTx)?;
        match &entry.state {
            ReservationState::Reserved => {
                entry.state = ReservationState::Broadcast(tx.clone());
                Ok(tx)
            }
            ReservationState::Broadcast(existing) => {
                if *existing == tx {
                    Ok(existing.clone())
                } else {
                    Err(AdapterError::IllegalTransition)
                }
            }
            ReservationState::Finalized => Err(AdapterError::IllegalTransition),
        }
    }

    /// Finalize a broadcast withdrawal, permanently consuming its nonce.
    /// Idempotent: finalizing an already-finalized withdrawal is a no-op.
    ///
    /// # Errors
    /// - [`AdapterError::UnknownTx`] if the withdrawal was never reserved.
    /// - [`AdapterError::IllegalTransition`] if it has not been broadcast.
    pub fn finalize(&mut self, id: WithdrawalId) -> Result<(), AdapterError> {
        let key = *self.index.get(&id).ok_or(AdapterError::UnknownTx)?;
        let entry = self.by_nonce.get_mut(&key).ok_or(AdapterError::UnknownTx)?;
        match &entry.state {
            ReservationState::Broadcast(_) => {
                entry.state = ReservationState::Finalized;
                Ok(())
            }
            ReservationState::Finalized => Ok(()),
            ReservationState::Reserved => Err(AdapterError::IllegalTransition),
        }
    }

    /// Release a not-yet-broadcast reservation, freeing its nonce for retry.
    ///
    /// Only a `Reserved` withdrawal may be released; once broadcast it must be
    /// finalized (releasing a sent transaction would risk a double-send).
    ///
    /// # Errors
    /// - [`AdapterError::UnknownTx`] if the withdrawal was never reserved.
    /// - [`AdapterError::IllegalTransition`] if it was already broadcast or
    ///   finalized.
    pub fn release(&mut self, id: WithdrawalId) -> Result<(), AdapterError> {
        let key = *self.index.get(&id).ok_or(AdapterError::UnknownTx)?;
        let entry = self.by_nonce.get(&key).ok_or(AdapterError::UnknownTx)?;
        if !matches!(entry.state, ReservationState::Reserved) {
            return Err(AdapterError::IllegalTransition);
        }
        self.by_nonce.remove(&key);
        self.index.remove(&id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AssetId, ChainId};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use types::Amount;

    fn request(account: u32, nonce: u64, amount: i128) -> WithdrawalRequest {
        WithdrawalRequest {
            account_id: AccountId::new(account),
            destination_chain: ChainId::new(1),
            destination_address: vec![0xAB; 20],
            asset: AssetId::new(7),
            amount: Amount::from_raw(amount),
            nonce,
            expires_at: 1_000,
            user_signature: vec![],
        }
    }

    #[test]
    fn reserve_is_idempotent_on_same_request() {
        let mut ledger = WithdrawalLedger::new();
        let req = request(5, 1, 100);
        let first = ledger.reserve(&req).unwrap();
        assert!(first.fresh);
        let again = ledger.reserve(&req).unwrap();
        assert!(!again.fresh);
        assert_eq!(first.withdrawal_id, again.withdrawal_id);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn distinct_request_same_nonce_rejected() {
        let mut ledger = WithdrawalLedger::new();
        assert!(ledger.reserve(&request(5, 1, 100)).unwrap().fresh);
        // Same (account, nonce) but a different amount => different id => reject.
        assert_eq!(
            ledger.reserve(&request(5, 1, 200)),
            Err(AdapterError::ReplayedNonce)
        );
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn broadcast_is_idempotent_and_no_double_send() {
        let mut ledger = WithdrawalLedger::new();
        let req = request(5, 1, 100);
        let id = ledger.reserve(&req).unwrap().withdrawal_id;
        let tx = TxId::new(vec![0xEE; 32]);

        // First broadcast records the identity.
        assert_eq!(ledger.record_broadcast(id, tx.clone()).unwrap(), tx);
        // Crash/retry with the same tx returns the same identity, no double-send.
        assert_eq!(ledger.record_broadcast(id, tx.clone()).unwrap(), tx);
        assert_eq!(ledger.broadcast_tx(id), Some(tx.clone()));

        // A conflicting second identity for the same withdrawal is refused.
        assert_eq!(
            ledger.record_broadcast(id, TxId::new(vec![0x11; 32])),
            Err(AdapterError::IllegalTransition)
        );
    }

    #[test]
    fn broadcast_requires_prior_reservation() {
        let mut ledger = WithdrawalLedger::new();
        let id = request(5, 1, 100).id();
        assert_eq!(
            ledger.record_broadcast(id, TxId::new(vec![1])),
            Err(AdapterError::UnknownTx)
        );
    }

    #[test]
    fn finalize_and_release_state_machine() {
        let mut ledger = WithdrawalLedger::new();
        let req = request(5, 1, 100);
        let id = ledger.reserve(&req).unwrap().withdrawal_id;

        // Cannot finalize before broadcast.
        assert_eq!(ledger.finalize(id), Err(AdapterError::IllegalTransition));

        // Release a still-reserved withdrawal: frees the nonce for retry.
        assert_eq!(ledger.release(id), Ok(()));
        assert!(ledger.is_empty());
        assert!(ledger.reserve(&request(5, 1, 200)).unwrap().fresh);

        // Broadcast then finalize; finalize is idempotent, release is refused.
        let mut l2 = WithdrawalLedger::new();
        let id2 = l2.reserve(&req).unwrap().withdrawal_id;
        let tx = TxId::new(vec![0xEE; 32]);
        l2.record_broadcast(id2, tx).unwrap();
        assert_eq!(l2.release(id2), Err(AdapterError::IllegalTransition));
        assert_eq!(l2.finalize(id2), Ok(()));
        assert_eq!(l2.finalize(id2), Ok(())); // idempotent
                                              // A finalized nonce stays consumed.
        assert_eq!(
            l2.reserve(&request(5, 1, 999)),
            Err(AdapterError::ReplayedNonce)
        );
    }

    #[test]
    fn unknown_id_operations_report_unknown() {
        let mut ledger = WithdrawalLedger::new();
        let id = request(5, 1, 100).id();
        assert_eq!(ledger.finalize(id), Err(AdapterError::UnknownTx));
        assert_eq!(ledger.release(id), Err(AdapterError::UnknownTx));
        assert_eq!(ledger.broadcast_tx(id), None);
        assert_eq!(ledger.state(id), None);
    }

    #[test]
    fn concurrent_identical_requests_yield_one_reservation_and_one_broadcast() {
        // Many threads race to reserve and broadcast the *same* request. The
        // Mutex serializes each check-and-insert, so exactly one thread creates
        // the reservation and exactly one transaction identity is recorded.
        let ledger = Arc::new(Mutex::new(WithdrawalLedger::new()));
        let req = request(5, 1, 100);
        let id = req.id();
        let tx = TxId::new(vec![0xEE; 32]);

        let fresh_count = Arc::new(Mutex::new(0usize));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let ledger = Arc::clone(&ledger);
            let fresh_count = Arc::clone(&fresh_count);
            let req = req.clone();
            let tx = tx.clone();
            handles.push(thread::spawn(move || {
                let reservation = {
                    let mut l = ledger.lock().unwrap();
                    l.reserve(&req).unwrap()
                };
                if reservation.fresh {
                    *fresh_count.lock().unwrap() += 1;
                }
                let got = {
                    let mut l = ledger.lock().unwrap();
                    l.record_broadcast(id, tx.clone()).unwrap()
                };
                // Every thread observes the one durable identity.
                assert_eq!(got, tx);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*fresh_count.lock().unwrap(), 1, "exactly one reservation");
        let l = ledger.lock().unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l.broadcast_tx(id), Some(tx));
    }

    #[test]
    fn concurrent_distinct_requests_same_nonce_yield_one_winner() {
        // Threads race to claim the same (account, nonce) with distinct requests.
        // Exactly one wins; the rest see ReplayedNonce.
        let ledger = Arc::new(Mutex::new(WithdrawalLedger::new()));
        let winners = Arc::new(Mutex::new(0usize));
        let mut handles = Vec::new();
        for i in 0..16i128 {
            let ledger = Arc::clone(&ledger);
            let winners = Arc::clone(&winners);
            handles.push(thread::spawn(move || {
                let req = request(5, 1, 100 + i);
                let mut l = ledger.lock().unwrap();
                if l.reserve(&req).is_ok() {
                    *winners.lock().unwrap() += 1;
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*winners.lock().unwrap(), 1, "exactly one winner");
        assert_eq!(ledger.lock().unwrap().len(), 1);
    }
}
