//! The `ChainAdapter` trait: the custody edge's view of one external chain.

use crate::deposit::VerifiedDeposit;
use crate::error::AdapterError;
use crate::ids::{ChainId, TxId};
use crate::reservation::WithdrawalReservation;
use crate::withdrawal::{UnsignedTx, WithdrawalId, WithdrawalRequest, WithdrawalStatus};

/// An adapter over a single external chain.
///
/// Implementations observe deposits into custody and build/observe withdrawals
/// out of custody. The observation methods (`&self`) are read-only over the
/// adapter's view of the chain: they never mutate ledger state (that belongs to
/// execution/custody). The withdrawal-lifecycle methods (`&mut self`) mutate
/// only the adapter's own nonce-reservation ledger — not the replicated ledger —
/// and provide the atomic reserve → build → broadcast → finalize/release
/// semantics that keep a nonce single-use and a broadcast transaction identity
/// durable and idempotent. No method panics on adversarial input; they return
/// [`AdapterError`] instead.
///
/// The trait is object-safe: `dyn ChainAdapter` is usable by downstream code.
pub trait ChainAdapter {
    /// The chain this adapter serves.
    fn chain_id(&self) -> ChainId;

    /// Return every deposit that has reached this chain's finality policy.
    ///
    /// # Errors
    /// Implementation-defined observation failures.
    fn observe_deposits(&self) -> Result<Vec<VerifiedDeposit>, AdapterError>;

    /// Verify a single deposit transaction reached finality.
    ///
    /// # Errors
    /// - [`AdapterError::UnknownTx`] if the tx is not known.
    /// - [`AdapterError::NotFinal`] if it has not reached finality.
    fn verify_deposit(&self, tx: &TxId) -> Result<VerifiedDeposit, AdapterError>;

    /// Build a deterministic unsigned withdrawal transaction.
    ///
    /// Verifies the request's authorization first — the debited account's bound
    /// wallet signature over [`WithdrawalRequest::signing_hash`] under this
    /// chain's scheme, the destination chain, and the exact destination-address
    /// format. Pure and side-effect free: it does **not** reserve the nonce; call
    /// [`Self::reserve_withdrawal`] for that.
    ///
    /// # Errors
    /// - [`AdapterError::UnsupportedAsset`], [`AdapterError::Expired`].
    /// - [`AdapterError::Unauthorized`], [`AdapterError::WrongChain`],
    ///   [`AdapterError::InvalidSignature`], or [`AdapterError::InvalidRequest`]
    ///   if authorization fails.
    fn build_withdrawal(&self, w: &WithdrawalRequest) -> Result<UnsignedTx, AdapterError>;

    /// Atomically reserve the request's per-account nonce after verifying its
    /// authorization.
    ///
    /// Idempotent on the withdrawal id: a retry of the same request returns the
    /// existing reservation (`fresh == false`), while a *different* request that
    /// collides on the same `(account, nonce)` is rejected. Together these ensure
    /// concurrent same-nonce requests yield exactly one reservation.
    ///
    /// # Errors
    /// The authorization errors of [`Self::build_withdrawal`], or
    /// [`AdapterError::ReplayedNonce`] if the nonce is already claimed.
    fn reserve_withdrawal(
        &mut self,
        w: &WithdrawalRequest,
    ) -> Result<WithdrawalReservation, AdapterError>;

    /// Observe the lifecycle status of a broadcast withdrawal transaction.
    ///
    /// # Errors
    /// [`AdapterError::UnknownTx`] if the tx is not known.
    fn observe_withdrawal(&self, tx: &TxId) -> Result<WithdrawalStatus, AdapterError>;

    /// Finalize a settled withdrawal, permanently consuming its reserved nonce.
    ///
    /// # Errors
    /// - [`AdapterError::UnknownTx`] if the withdrawal was never reserved.
    /// - [`AdapterError::IllegalTransition`] if it has not been broadcast.
    fn finalize_withdrawal(&mut self, id: WithdrawalId) -> Result<(), AdapterError>;

    /// Release a not-yet-broadcast reservation, freeing its nonce for retry.
    ///
    /// # Errors
    /// - [`AdapterError::UnknownTx`] if the withdrawal was never reserved.
    /// - [`AdapterError::IllegalTransition`] if it was already broadcast.
    fn release_withdrawal(&mut self, id: WithdrawalId) -> Result<(), AdapterError>;
}
