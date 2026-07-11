//! Withdrawal requests, deterministic withdrawal ids, finalized withdrawal
//! certificates, and the custody signer's independent verification step.
//!
//! Consensus produces a [`WithdrawalCertificate`] authorizing a finalized
//! withdrawal. The custody signer does **not** trust it: [`verify_certificate`]
//! independently re-derives the withdrawal id, checks finalization, the ledger
//! reservation, the validity window, and the quorum signature over the
//! finalizing checkpoint before any signing happens.

use crypto::{keccak256, QuorumCertificate, ValidatorSet};
use types::{AccountId, Amount, Hash, SequenceNumber};

use crate::chain::{ChainId, WalletAddress};
use crate::error::CustodyError;
use crate::wire::{Reader, Writer};

/// Domain tag mixed into every withdrawal-id preimage.
pub const WITHDRAWAL_DOMAIN: &[u8] = b"DEXOS/WITHDRAWAL/v1";

/// A deterministic 32-byte withdrawal identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WithdrawalId([u8; 32]);

impl WithdrawalId {
    /// Wrap raw bytes.
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// View the id as a [`Hash`] for threshold signing.
    pub fn to_hash(self) -> Hash {
        Hash::from_bytes(self.0)
    }
}

/// A request to move funds off the exchange to an external address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalRequest {
    /// The account being debited.
    pub account: AccountId,
    /// The destination chain.
    pub chain: ChainId,
    /// The destination address.
    pub to: WalletAddress,
    /// The amount to withdraw (must be non-negative).
    pub amount: Amount,
    /// A per-account withdrawal nonce.
    pub nonce: u64,
}

impl WithdrawalRequest {
    /// Canonical byte encoding (also the withdrawal-id preimage tail).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.account.get());
        w.u64(self.chain.get());
        self.to.encode_into(&mut w);
        w.i128(self.amount.raw());
        w.u64(self.nonce);
        w.into_vec()
    }

    /// Decode a request from bytes. Total: arbitrary input yields `Err`.
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        let mut r = Reader::new(bytes);
        let account = AccountId::new(r.u32()?);
        let chain = ChainId(r.u64()?);
        let to = WalletAddress::decode_from(&mut r)?;
        let amount = Amount::from_raw(r.i128()?);
        let nonce = r.u64()?;
        r.finish()?;
        Ok(Self {
            account,
            chain,
            to,
            amount,
            nonce,
        })
    }

    /// Derive the deterministic withdrawal id: `keccak256(DOMAIN || encode())`.
    ///
    /// Bit-identical across runs and distinct whenever any field differs.
    pub fn id(&self) -> WithdrawalId {
        let mut preimage = Vec::with_capacity(WITHDRAWAL_DOMAIN.len() + 64);
        preimage.extend_from_slice(WITHDRAWAL_DOMAIN);
        preimage.extend_from_slice(&self.encode());
        WithdrawalId(keccak256(&preimage))
    }
}

/// A consensus-authorized, finalized withdrawal certificate.
///
/// The custody signer verifies this independently before signing; see
/// [`verify_certificate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalCertificate {
    /// The underlying request.
    pub request: WithdrawalRequest,
    /// The withdrawal id claimed by the certificate (checked against `request`).
    pub withdrawal_id: WithdrawalId,
    /// The finalizing checkpoint (state root) the quorum signed over.
    pub checkpoint: Hash,
    /// The consensus quorum certificate over `checkpoint`.
    pub quorum: QuorumCertificate,
    /// Whether consensus marked the withdrawal finalized.
    pub finalized: bool,
    /// On-chain confirmations backing the reservation.
    pub confirmations: u32,
    /// Whether the ledger reservation for the funds is satisfied.
    pub ledger_reserved: bool,
    /// Last sequence at which the certificate may be signed (inclusive).
    pub expiry: SequenceNumber,
}

impl WithdrawalCertificate {
    /// Encode the certificate for transport / fuzzing.
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        let mut w = Writer::new();
        w.var_bytes(&self.request.encode())?;
        w.raw(self.withdrawal_id.as_bytes());
        w.raw(self.checkpoint.as_bytes());
        // quorum
        w.raw(self.quorum.message.as_bytes());
        w.u64(self.quorum.signer_bitmap);
        let n = u32::try_from(self.quorum.signatures.len()).map_err(|_| CustodyError::Decode)?;
        w.u32(n);
        for sig in &self.quorum.signatures {
            w.raw(sig);
        }
        w.u8(u8::from(self.finalized));
        w.u32(self.confirmations);
        w.u8(u8::from(self.ledger_reserved));
        w.u64(self.expiry.get());
        Ok(w.into_vec())
    }

    /// Decode a certificate from bytes. Total: arbitrary input yields `Err`.
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        let mut r = Reader::new(bytes);
        let request = WithdrawalRequest::decode(&r.var_bytes()?)?;
        let withdrawal_id = WithdrawalId::from_bytes(r.array::<32>()?);
        let checkpoint = Hash::from_bytes(r.array::<32>()?);
        let message = Hash::from_bytes(r.array::<32>()?);
        let signer_bitmap = r.u64()?;
        let count = usize::try_from(r.u32()?).map_err(|_| CustodyError::Decode)?;
        // Guard against a length field that would demand a huge allocation:
        // each signature is 64 bytes, so the buffer must have room for them.
        if count > r.remaining() / 64 {
            return Err(CustodyError::Decode);
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(r.array::<64>()?);
        }
        let finalized = r.u8()? != 0;
        let confirmations = r.u32()?;
        let ledger_reserved = r.u8()? != 0;
        let expiry = SequenceNumber::new(r.u64()?);
        r.finish()?;
        Ok(Self {
            request,
            withdrawal_id,
            checkpoint,
            quorum: QuorumCertificate {
                message,
                signer_bitmap,
                signatures,
            },
            finalized,
            confirmations,
            ledger_reserved,
            expiry,
        })
    }
}

/// Independently verify a finalized withdrawal certificate before signing.
///
/// Rejects, with the specific [`CustodyError`], any of: a withdrawal-id that
/// does not match the request, a non-finalized certificate, a missing ledger
/// reservation, an expired certificate, a quorum whose message is not the
/// checkpoint, and a quorum that fails to verify under `consensus`.
///
/// On `Ok`, the certificate is backed by a verifying quorum over its finalizing
/// checkpoint — the property the custody signer relies on.
pub fn verify_certificate(
    cert: &WithdrawalCertificate,
    consensus: &ValidatorSet,
    now: SequenceNumber,
) -> Result<(), CustodyError> {
    if cert.withdrawal_id != cert.request.id() {
        return Err(CustodyError::MismatchedWithdrawalId);
    }
    if !cert.finalized {
        return Err(CustodyError::NotFinalized);
    }
    if !cert.ledger_reserved {
        return Err(CustodyError::MissingLedgerReserve);
    }
    if now > cert.expiry {
        return Err(CustodyError::Expired);
    }
    if cert.quorum.message != cert.checkpoint {
        return Err(CustodyError::BadQuorumSignature);
    }
    consensus
        .verify(&cert.quorum)
        .map_err(|_| CustodyError::BadQuorumSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ThresholdSigners;

    fn request() -> WithdrawalRequest {
        WithdrawalRequest {
            account: AccountId::new(1),
            chain: ChainId(1),
            to: WalletAddress::Evm([0xAB; 20]),
            amount: Amount::from_raw(100_000_000),
            nonce: 7,
        }
    }

    fn signers() -> ThresholdSigners {
        let seeds: Vec<[u8; 32]> = (0..4u8).map(|i| [i + 1; 32]).collect();
        ThresholdSigners::from_seeds(&seeds, 3)
    }

    fn good_cert(consensus_signers: &ThresholdSigners) -> WithdrawalCertificate {
        let req = request();
        let checkpoint = Hash::from_bytes([9u8; 32]);
        let quorum = consensus_signers.sign(checkpoint, vec![0, 1, 2]);
        WithdrawalCertificate {
            withdrawal_id: req.id(),
            request: req,
            checkpoint,
            quorum,
            finalized: true,
            confirmations: 12,
            ledger_reserved: true,
            expiry: SequenceNumber::new(1000),
        }
    }

    #[test]
    fn withdrawal_id_is_deterministic_and_distinct() {
        let r = request();
        assert_eq!(r.id(), r.id());
        let mut r2 = request();
        r2.nonce = 8;
        assert_ne!(r.id(), r2.id());
        let mut r3 = request();
        r3.amount = Amount::from_raw(100_000_001);
        assert_ne!(r.id(), r3.id());
        // Bit-identical bytes across "runs".
        assert_eq!(r.id(), request().id());
    }

    #[test]
    fn valid_certificate_accepted() {
        let s = signers();
        let cert = good_cert(&s);
        assert!(verify_certificate(&cert, &s.validator_set(), SequenceNumber::new(1)).is_ok());
    }

    #[test]
    fn each_failure_mode_rejected() {
        let s = signers();
        let set = s.validator_set();
        let now = SequenceNumber::new(1);

        // bad quorum signature (tampered checkpoint but stale quorum)
        let mut c = good_cert(&s);
        c.checkpoint = Hash::from_bytes([1u8; 32]);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::BadQuorumSignature)
        );

        // non-finalized
        let mut c = good_cert(&s);
        c.finalized = false;
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::NotFinalized)
        );

        // mismatched withdrawal id
        let mut c = good_cert(&s);
        c.withdrawal_id = WithdrawalId::from_bytes([0u8; 32]);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::MismatchedWithdrawalId)
        );

        // missing ledger reserve
        let mut c = good_cert(&s);
        c.ledger_reserved = false;
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::MissingLedgerReserve)
        );

        // expired
        let c = good_cert(&s);
        assert_eq!(
            verify_certificate(&c, &set, SequenceNumber::new(2000)),
            Err(CustodyError::Expired)
        );

        // insufficient quorum (only 2-of-4 signed the checkpoint)
        let mut c = good_cert(&s);
        let cp = c.checkpoint;
        c.quorum = s.sign(cp, vec![0, 1]);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::BadQuorumSignature)
        );
    }

    #[test]
    fn certificate_and_request_decode_never_panic() {
        let mut state = 0xabcd_ef01u64;
        for _ in 0..30_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = usize::try_from(state % 160).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    state.to_le_bytes()[0]
                })
                .collect();
            let _ = WithdrawalRequest::decode(&bytes);
            let _ = WithdrawalCertificate::decode(&bytes);
        }
    }

    #[test]
    fn certificate_round_trips() {
        let s = signers();
        let cert = good_cert(&s);
        let bytes = cert.encode().unwrap();
        assert_eq!(WithdrawalCertificate::decode(&bytes).unwrap(), cert);
    }
}
