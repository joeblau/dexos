//! Deposit observation, finality proofs, and quorum deposit certificates.

use crate::codec::{Codec, CodecError, Reader, Writer};
use crate::error::AdapterError;
use crate::ids::{AssetId, ChainId, TxId};
use crate::policy::FinalityPolicy;
use crypto::{hash_domain, QuorumCertificate, ThresholdSigners, ValidatorSet};
use serde::{Deserialize, Serialize};
use types::{AccountId, Amount, Hash};

/// Domain separator for deposit-certificate message hashing.
pub const DOMAIN_DEPOSIT: &[u8] = b"dexos.custody.deposit";

/// Uniqueness key for replay protection: one credit per `(chain, tx, event)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceKey {
    /// Source chain.
    pub chain: ChainId,
    /// Source transaction id bytes.
    pub tx: Vec<u8>,
    /// Log/event index within the transaction.
    pub event_index: u32,
}

/// A raw deposit event as seen on an external chain, before finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositEvent {
    /// Chain the deposit occurred on.
    pub source_chain: ChainId,
    /// Transaction that carried the deposit.
    pub source_tx: TxId,
    /// Event/log index within the transaction.
    pub source_event_index: u32,
    /// Asset deposited.
    pub asset: AssetId,
    /// Amount deposited.
    pub amount: Amount,
    /// DexOS account to be credited.
    pub destination_account: AccountId,
}

impl DepositEvent {
    /// The replay-protection key for this event.
    #[must_use]
    pub fn source_key(&self) -> SourceKey {
        SourceKey {
            chain: self.source_chain,
            tx: self.source_tx.as_bytes().to_vec(),
            event_index: self.source_event_index,
        }
    }
}

impl Codec for DepositEvent {
    fn write(&self, w: &mut Writer) {
        self.source_chain.write(w);
        self.source_tx.write(w);
        w.u32(self.source_event_index);
        self.asset.write(w);
        self.amount.write(w);
        self.destination_account.write(w);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            source_chain: ChainId::read(r)?,
            source_tx: TxId::read(r)?,
            source_event_index: r.u32()?,
            asset: AssetId::read(r)?,
            amount: Amount::read(r)?,
            destination_account: AccountId::read(r)?,
        })
    }
}

/// Proof that a transaction reached a given depth on its chain.
///
/// A trustworthy proof is only ever produced by
/// [`verify_finality`](crate::verify_finality), which derives `confirmations`
/// from a verified, hash-linked header chain and recomputes `block_hash` — it is
/// never a bare, observer-asserted count. Consumers that credit funds must
/// obtain proofs through verification, not by constructing this struct directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Block/slot height that included the transaction.
    pub block_number: u64,
    /// Block/slot hash.
    pub block_hash: Hash,
    /// Confirmation depth derived from a verified header chain (the number of
    /// contiguous headers from the including block through the head, inclusive).
    pub confirmations: u32,
}

impl Codec for FinalityProof {
    fn write(&self, w: &mut Writer) {
        w.u64(self.block_number);
        self.block_hash.write(w);
        w.u32(self.confirmations);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            block_number: r.u64()?,
            block_hash: Hash::read(r)?,
            confirmations: r.u32()?,
        })
    }
}

/// A deposit event that has met its chain's finality policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedDeposit {
    /// Chain the deposit occurred on.
    pub source_chain: ChainId,
    /// Transaction that carried the deposit.
    pub source_tx: TxId,
    /// Event/log index within the transaction.
    pub source_event_index: u32,
    /// Asset deposited.
    pub asset: AssetId,
    /// Amount deposited.
    pub amount: Amount,
    /// DexOS account to be credited.
    pub destination_account: AccountId,
    /// Proof the deposit reached finality.
    pub finality_proof: FinalityProof,
}

impl VerifiedDeposit {
    /// Build from a raw event plus its finality proof.
    #[must_use]
    pub fn new(event: DepositEvent, finality_proof: FinalityProof) -> Self {
        Self {
            source_chain: event.source_chain,
            source_tx: event.source_tx,
            source_event_index: event.source_event_index,
            asset: event.asset,
            amount: event.amount,
            destination_account: event.destination_account,
            finality_proof,
        }
    }

    /// The replay-protection key for this deposit.
    #[must_use]
    pub fn source_key(&self) -> SourceKey {
        SourceKey {
            chain: self.source_chain,
            tx: self.source_tx.as_bytes().to_vec(),
            event_index: self.source_event_index,
        }
    }

    /// The canonical message hash a quorum signs to certify this deposit.
    #[must_use]
    pub fn message_hash(&self) -> Hash {
        deposit_body_hash(
            self.source_chain,
            &self.source_tx,
            self.source_event_index,
            self.asset,
            self.amount,
            self.destination_account,
            &self.finality_proof,
        )
    }
}

impl Codec for VerifiedDeposit {
    fn write(&self, w: &mut Writer) {
        self.source_chain.write(w);
        self.source_tx.write(w);
        w.u32(self.source_event_index);
        self.asset.write(w);
        self.amount.write(w);
        self.destination_account.write(w);
        self.finality_proof.write(w);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            source_chain: ChainId::read(r)?,
            source_tx: TxId::read(r)?,
            source_event_index: r.u32()?,
            asset: AssetId::read(r)?,
            amount: Amount::read(r)?,
            destination_account: AccountId::read(r)?,
            finality_proof: FinalityProof::read(r)?,
        })
    }
}

/// Canonical body hash committed to by both [`VerifiedDeposit`] and
/// [`DepositCertificate`], so certification and verification agree bit-for-bit.
#[must_use]
fn deposit_body_hash(
    source_chain: ChainId,
    source_tx: &TxId,
    source_event_index: u32,
    asset: AssetId,
    amount: Amount,
    destination_account: AccountId,
    finality_proof: &FinalityProof,
) -> Hash {
    let mut w = Writer::new();
    source_chain.write(&mut w);
    source_tx.write(&mut w);
    w.u32(source_event_index);
    asset.write(&mut w);
    amount.write(&mut w);
    destination_account.write(&mut w);
    finality_proof.write(&mut w);
    hash_domain(DOMAIN_DEPOSIT, &w.into_bytes())
}

/// A quorum-signed certificate crediting a finalized deposit exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCertificate {
    /// Chain the deposit occurred on.
    pub source_chain: ChainId,
    /// Transaction that carried the deposit.
    pub source_tx: TxId,
    /// Event/log index within the transaction.
    pub source_event_index: u32,
    /// Asset deposited.
    pub asset: AssetId,
    /// Amount deposited.
    pub amount: Amount,
    /// DexOS account to be credited.
    pub destination_account: AccountId,
    /// Proof the deposit reached finality.
    pub finality_proof: FinalityProof,
    /// Bitmap of observers that attested to the deposit.
    pub observer_bitmap: u64,
    /// Aggregated observer signatures over [`Self::message_hash`].
    pub quorum_signature: QuorumCertificate,
}

impl DepositCertificate {
    /// The replay-protection key for this certificate.
    #[must_use]
    pub fn source_key(&self) -> SourceKey {
        SourceKey {
            chain: self.source_chain,
            tx: self.source_tx.as_bytes().to_vec(),
            event_index: self.source_event_index,
        }
    }

    /// The message hash the observer quorum signed.
    #[must_use]
    pub fn message_hash(&self) -> Hash {
        deposit_body_hash(
            self.source_chain,
            &self.source_tx,
            self.source_event_index,
            self.asset,
            self.amount,
            self.destination_account,
            &self.finality_proof,
        )
    }

    /// Extract the underlying verified deposit.
    #[must_use]
    pub fn verified_deposit(&self) -> VerifiedDeposit {
        VerifiedDeposit {
            source_chain: self.source_chain,
            source_tx: self.source_tx.clone(),
            source_event_index: self.source_event_index,
            asset: self.asset,
            amount: self.amount,
            destination_account: self.destination_account,
            finality_proof: self.finality_proof,
        }
    }

    /// Verify finality and the observer quorum against `validators` and `policy`.
    ///
    /// # Errors
    /// - [`AdapterError::NotFinal`] if the finality policy is unmet.
    /// - [`AdapterError::QuorumNotMet`] if the bitmap, message, or signed weight
    ///   is inconsistent, or [`AdapterError::InvalidSignature`] on a bad member
    ///   signature.
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

impl Codec for DepositCertificate {
    fn write(&self, w: &mut Writer) {
        self.source_chain.write(w);
        self.source_tx.write(w);
        w.u32(self.source_event_index);
        self.asset.write(w);
        self.amount.write(w);
        self.destination_account.write(w);
        self.finality_proof.write(w);
        w.u64(self.observer_bitmap);
        self.quorum_signature.write(w);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            source_chain: ChainId::read(r)?,
            source_tx: TxId::read(r)?,
            source_event_index: r.u32()?,
            asset: AssetId::read(r)?,
            amount: Amount::read(r)?,
            destination_account: AccountId::read(r)?,
            finality_proof: FinalityProof::read(r)?,
            observer_bitmap: r.u64()?,
            quorum_signature: QuorumCertificate::read(r)?,
        })
    }
}

/// Assemble a quorum-signed [`DepositCertificate`] from a verified deposit.
///
/// The `signers` sign [`VerifiedDeposit::message_hash`]; the resulting bitmap is
/// copied into `observer_bitmap`. Certification does not enforce quorum weight —
/// [`DepositCertificate::verify`] does, on the receiving side.
#[must_use]
pub fn certify_deposit(
    deposit: &VerifiedDeposit,
    signers: &ThresholdSigners,
    observer_indices: Vec<usize>,
) -> DepositCertificate {
    let message = deposit.message_hash();
    let qc = signers.sign(message, observer_indices);
    DepositCertificate {
        source_chain: deposit.source_chain,
        source_tx: deposit.source_tx.clone(),
        source_event_index: deposit.source_event_index,
        asset: deposit.asset,
        amount: deposit.amount,
        destination_account: deposit.destination_account,
        finality_proof: deposit.finality_proof,
        observer_bitmap: qc.signer_bitmap,
        quorum_signature: qc,
    }
}
