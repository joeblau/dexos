//! Withdrawal requests, deterministic ids, unsigned txs, status machine, and
//! settlement certificates.

use crate::codec::{Codec, CodecError, Reader, Writer};
use crate::deposit::FinalityProof;
use crate::error::AdapterError;
use crate::ids::{AssetId, ChainId, TxId};
use crate::policy::FinalityPolicy;
use crypto::{hash_domain, QuorumCertificate, ThresholdSigners, ValidatorSet};
use serde::{Deserialize, Serialize};
use types::{AccountId, Amount, Hash};

/// Domain separator for deterministic withdrawal ids.
pub const DOMAIN_WITHDRAWAL_ID: &[u8] = b"dexos.custody.withdrawal.id";
/// Domain separator for withdrawal settlement certificate hashing.
pub const DOMAIN_WITHDRAWAL_CERT: &[u8] = b"dexos.custody.withdrawal.cert";
/// Maximum destination-address length accepted by the codec.
pub const MAX_ADDRESS_LEN: usize = 64;
/// Maximum user-signature length accepted by the codec.
pub const MAX_USER_SIG_LEN: usize = 96;

/// Lifecycle of an observed withdrawal on its destination chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Broadcast but not yet included / zero confirmations.
    Pending,
    /// Included with `confirmations` below the finality threshold.
    Confirming {
        /// Confirmations observed so far.
        confirmations: u32,
    },
    /// Reached the finality threshold; settlement is complete.
    Finalized,
    /// Settlement failed; any reservation should be re-credited upstream.
    Failed,
}

impl WithdrawalStatus {
    /// Whether this is a terminal state (no further transitions but self).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, WithdrawalStatus::Finalized | WithdrawalStatus::Failed)
    }

    /// Whether `next` is a legal successor of `self` in the lifecycle graph.
    #[must_use]
    pub const fn can_transition_to(self, next: WithdrawalStatus) -> bool {
        match self {
            WithdrawalStatus::Pending => true,
            WithdrawalStatus::Confirming { .. } => !matches!(next, WithdrawalStatus::Pending),
            WithdrawalStatus::Finalized => matches!(next, WithdrawalStatus::Finalized),
            WithdrawalStatus::Failed => matches!(next, WithdrawalStatus::Failed),
        }
    }

    /// Advance to `next`, rejecting illegal edges.
    ///
    /// # Errors
    /// [`AdapterError::IllegalTransition`] if `next` is not a legal successor.
    pub fn advance(self, next: WithdrawalStatus) -> Result<WithdrawalStatus, AdapterError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(AdapterError::IllegalTransition)
        }
    }
}

impl Codec for WithdrawalStatus {
    fn write(&self, w: &mut Writer) {
        match self {
            WithdrawalStatus::Pending => w.u8(0),
            WithdrawalStatus::Confirming { confirmations } => {
                w.u8(1);
                w.u32(*confirmations);
            }
            WithdrawalStatus::Finalized => w.u8(2),
            WithdrawalStatus::Failed => w.u8(3),
        }
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.u8()? {
            0 => Ok(WithdrawalStatus::Pending),
            1 => Ok(WithdrawalStatus::Confirming {
                confirmations: r.u32()?,
            }),
            2 => Ok(WithdrawalStatus::Finalized),
            3 => Ok(WithdrawalStatus::Failed),
            other => Err(CodecError::InvalidTag(other)),
        }
    }
}

/// A user-authorized request to withdraw funds to an external chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// DexOS account to debit.
    pub account_id: AccountId,
    /// Destination chain.
    pub destination_chain: ChainId,
    /// Destination address bytes (chain-specific encoding).
    pub destination_address: Vec<u8>,
    /// Asset to withdraw.
    pub asset: AssetId,
    /// Amount to withdraw.
    pub amount: Amount,
    /// Per-account replay-protection nonce.
    pub nonce: u64,
    /// Expiry height/timestamp; the request is invalid once time passes this.
    pub expires_at: u64,
    /// User signature over [`Self::signing_hash`].
    pub user_signature: Vec<u8>,
}

impl WithdrawalRequest {
    /// The canonical hash the user signs (excludes `user_signature`).
    #[must_use]
    pub fn signing_hash(&self) -> Hash {
        let mut w = Writer::new();
        self.account_id.write(&mut w);
        self.destination_chain.write(&mut w);
        w.bytes(&self.destination_address);
        self.asset.write(&mut w);
        self.amount.write(&mut w);
        w.u64(self.nonce);
        w.u64(self.expires_at);
        hash_domain(DOMAIN_WITHDRAWAL_ID, &w.into_bytes())
    }

    /// The deterministic, collision-free id for this request.
    #[must_use]
    pub fn id(&self) -> WithdrawalId {
        WithdrawalId(self.signing_hash())
    }
}

impl Codec for WithdrawalRequest {
    fn write(&self, w: &mut Writer) {
        self.account_id.write(w);
        self.destination_chain.write(w);
        w.bytes(&self.destination_address);
        self.asset.write(w);
        self.amount.write(w);
        w.u64(self.nonce);
        w.u64(self.expires_at);
        w.bytes(&self.user_signature);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let account_id = AccountId::read(r)?;
        let destination_chain = ChainId::read(r)?;
        let destination_address = r.bytes()?;
        if destination_address.len() > MAX_ADDRESS_LEN {
            return Err(CodecError::LengthOutOfRange);
        }
        let asset = AssetId::read(r)?;
        let amount = Amount::read(r)?;
        let nonce = r.u64()?;
        let expires_at = r.u64()?;
        let user_signature = r.bytes()?;
        if user_signature.len() > MAX_USER_SIG_LEN {
            return Err(CodecError::LengthOutOfRange);
        }
        Ok(Self {
            account_id,
            destination_chain,
            destination_address,
            asset,
            amount,
            nonce,
            expires_at,
            user_signature,
        })
    }
}

/// A deterministic withdrawal identifier (hash of the request body).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WithdrawalId(Hash);

impl WithdrawalId {
    /// Compute the id for a request.
    #[must_use]
    pub fn of(request: &WithdrawalRequest) -> Self {
        request.id()
    }

    /// The underlying hash.
    #[must_use]
    pub const fn into_hash(self) -> Hash {
        self.0
    }
}

impl Codec for WithdrawalId {
    fn write(&self, w: &mut Writer) {
        self.0.write(w);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(Hash::read(r)?))
    }
}

/// An unsigned withdrawal transaction ready for the custody signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedTx {
    /// Destination chain.
    pub destination_chain: ChainId,
    /// Deterministic id of the originating request.
    pub withdrawal_id: WithdrawalId,
    /// Destination address bytes.
    pub to: Vec<u8>,
    /// Asset to send.
    pub asset: AssetId,
    /// Amount to send.
    pub amount: Amount,
    /// Nonce for the destination-chain transaction.
    pub nonce: u64,
    /// Chain-specific serialized transaction body (deterministic).
    pub payload: Vec<u8>,
}

impl Codec for UnsignedTx {
    fn write(&self, w: &mut Writer) {
        self.destination_chain.write(w);
        self.withdrawal_id.write(w);
        w.bytes(&self.to);
        self.asset.write(w);
        self.amount.write(w);
        w.u64(self.nonce);
        w.bytes(&self.payload);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            destination_chain: ChainId::read(r)?,
            withdrawal_id: WithdrawalId::read(r)?,
            to: r.bytes()?,
            asset: AssetId::read(r)?,
            amount: Amount::read(r)?,
            nonce: r.u64()?,
            payload: r.bytes()?,
        })
    }
}

/// A quorum-signed certificate that a withdrawal settled on its chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalCertificate {
    /// Id of the settled withdrawal.
    pub withdrawal_id: WithdrawalId,
    /// Destination chain.
    pub destination_chain: ChainId,
    /// Transaction that settled the withdrawal.
    pub destination_tx: TxId,
    /// Asset settled.
    pub asset: AssetId,
    /// Amount settled.
    pub amount: Amount,
    /// Proof the settlement tx reached finality.
    pub finality_proof: FinalityProof,
    /// Bitmap of observers that attested.
    pub observer_bitmap: u64,
    /// Aggregated observer signatures over [`Self::message_hash`].
    pub quorum_signature: QuorumCertificate,
}

impl WithdrawalCertificate {
    /// The message hash the observer quorum signed.
    #[must_use]
    pub fn message_hash(&self) -> Hash {
        withdrawal_cert_body_hash(
            self.withdrawal_id,
            self.destination_chain,
            &self.destination_tx,
            self.asset,
            self.amount,
            &self.finality_proof,
        )
    }

    /// Verify finality and the observer quorum.
    ///
    /// # Errors
    /// - [`AdapterError::NotFinal`] if the finality policy is unmet.
    /// - [`AdapterError::QuorumNotMet`] / [`AdapterError::InvalidSignature`] on a
    ///   quorum inconsistency.
    pub fn verify(
        &self,
        validators: &ValidatorSet,
        policy: &FinalityPolicy,
    ) -> Result<(), AdapterError> {
        if !policy.is_final(self.finality_proof.confirmations) {
            return Err(AdapterError::NotFinal {
                have: self.finality_proof.confirmations,
                need: policy.min_confirmations(),
            });
        }
        if self.observer_bitmap != self.quorum_signature.signer_bitmap {
            return Err(AdapterError::QuorumNotMet);
        }
        if self.quorum_signature.message != self.message_hash() {
            return Err(AdapterError::QuorumNotMet);
        }
        validators
            .verify(&self.quorum_signature)
            .map_err(|e| match e {
                crypto::QuorumError::InvalidSignature => AdapterError::InvalidSignature,
                _ => AdapterError::QuorumNotMet,
            })
    }
}

impl Codec for WithdrawalCertificate {
    fn write(&self, w: &mut Writer) {
        self.withdrawal_id.write(w);
        self.destination_chain.write(w);
        self.destination_tx.write(w);
        self.asset.write(w);
        self.amount.write(w);
        self.finality_proof.write(w);
        w.u64(self.observer_bitmap);
        self.quorum_signature.write(w);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            withdrawal_id: WithdrawalId::read(r)?,
            destination_chain: ChainId::read(r)?,
            destination_tx: TxId::read(r)?,
            asset: AssetId::read(r)?,
            amount: Amount::read(r)?,
            finality_proof: FinalityProof::read(r)?,
            observer_bitmap: r.u64()?,
            quorum_signature: QuorumCertificate::read(r)?,
        })
    }
}

#[must_use]
fn withdrawal_cert_body_hash(
    withdrawal_id: WithdrawalId,
    destination_chain: ChainId,
    destination_tx: &TxId,
    asset: AssetId,
    amount: Amount,
    finality_proof: &FinalityProof,
) -> Hash {
    let mut w = Writer::new();
    withdrawal_id.write(&mut w);
    destination_chain.write(&mut w);
    destination_tx.write(&mut w);
    asset.write(&mut w);
    amount.write(&mut w);
    finality_proof.write(&mut w);
    hash_domain(DOMAIN_WITHDRAWAL_CERT, &w.into_bytes())
}

/// Assemble a quorum-signed [`WithdrawalCertificate`].
#[must_use]
#[allow(clippy::too_many_arguments)] // one argument per certified field; a wrapper struct would only relocate them
pub fn certify_withdrawal(
    withdrawal_id: WithdrawalId,
    destination_chain: ChainId,
    destination_tx: TxId,
    asset: AssetId,
    amount: Amount,
    finality_proof: FinalityProof,
    signers: &ThresholdSigners,
    observer_indices: Vec<usize>,
) -> WithdrawalCertificate {
    let message = withdrawal_cert_body_hash(
        withdrawal_id,
        destination_chain,
        &destination_tx,
        asset,
        amount,
        &finality_proof,
    );
    let qc = signers.sign(message, observer_indices);
    WithdrawalCertificate {
        withdrawal_id,
        destination_chain,
        destination_tx,
        asset,
        amount,
        finality_proof,
        observer_bitmap: qc.signer_bitmap,
        quorum_signature: qc,
    }
}
