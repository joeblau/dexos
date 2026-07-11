//! The `ChainAdapter` trait: the custody edge's view of one external chain.

use crate::deposit::VerifiedDeposit;
use crate::error::AdapterError;
use crate::ids::{ChainId, TxId};
use crate::withdrawal::{UnsignedTx, WithdrawalRequest, WithdrawalStatus};

/// An adapter over a single external chain.
///
/// Implementations observe deposits into custody and build/observe withdrawals
/// out of custody. All methods are read-only over the adapter's view of the
/// chain: they never mutate ledger state (that belongs to execution/custody) and
/// never panic on adversarial input, returning [`AdapterError`] instead.
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
    /// # Errors
    /// - [`AdapterError::UnsupportedAsset`], [`AdapterError::Expired`],
    ///   [`AdapterError::ReplayedNonce`], or [`AdapterError::InvalidRequest`].
    fn build_withdrawal(&self, w: &WithdrawalRequest) -> Result<UnsignedTx, AdapterError>;

    /// Observe the lifecycle status of a broadcast withdrawal transaction.
    ///
    /// # Errors
    /// [`AdapterError::UnknownTx`] if the tx is not known.
    fn observe_withdrawal(&self, tx: &TxId) -> Result<WithdrawalStatus, AdapterError>;
}
