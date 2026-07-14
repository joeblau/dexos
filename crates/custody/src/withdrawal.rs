//! Withdrawal requests, deterministic withdrawal ids, finalized withdrawal
//! certificates, and the custody signer's independent verification step.
//!
//! Consensus produces a [`WithdrawalCertificate`] authorizing a finalized
//! withdrawal. The custody signer does **not** trust it: [`verify_certificate`]
//! independently re-derives the withdrawal id, re-derives the domain-separated
//! *withdrawal authorization digest* over the full request (account, chain,
//! destination, amount, nonce), the confirmations and the ledger reservation,
//! proves that digest is committed under the finalizing checkpoint via a Merkle
//! inclusion proof, and only then checks the consensus quorum over that
//! checkpoint before any signing happens.
//!
//! The quorum is bound to the withdrawal because the finalizing checkpoint it
//! signs commits — through the inclusion proof — to the authorization digest.
//! A quorum over an unrelated checkpoint cannot authorize a withdrawal: no
//! inclusion proof exists that binds the request's digest to that root.

use crypto::{
    hash_domain, verify_proof, QuorumCertificate, QuorumSignatures, ValidatorSet,
    DOMAIN_WITHDRAWAL_AUTH, DOMAIN_WITHDRAWAL_ID, MAX_VALIDATORS,
};
use types::{AccountId, Amount, Hash, SequenceNumber};

use crate::chain::{ChainId, WalletAddress};
use crate::error::CustodyError;
use crate::wire::{Reader, Writer};

/// Domain tag mixed into every withdrawal-id preimage.
///
/// Canonical value is [`DOMAIN_WITHDRAWAL_ID`] from the crypto domain registry
/// — shared with `chain-adapter`. Prefer the `crypto::DOMAIN_*` constants at
/// new call sites.
pub const WITHDRAWAL_DOMAIN: &[u8] = DOMAIN_WITHDRAWAL_ID;

/// Domain tag for the consensus-signed withdrawal authorization digest.
///
/// This is the domain-separated commitment that the finalizing checkpoint must
/// include for a withdrawal to be authorized. It binds the full request, the
/// confirmations backing the reservation, and the reservation itself.
/// Canonical value is [`DOMAIN_WITHDRAWAL_AUTH`].
pub const WITHDRAWAL_AUTH_DOMAIN: &[u8] = DOMAIN_WITHDRAWAL_AUTH;

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

    /// View the id as a `Hash` for threshold signing.
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

    /// Derive the deterministic withdrawal id via length-prefixed
    /// [`hash_domain`] over [`DOMAIN_WITHDRAWAL_ID`] and the request body.
    ///
    /// Bit-identical across runs and distinct whenever any field differs. Same
    /// domain tag as `chain_adapter` withdrawal ids so the two crates cannot
    /// disagree on the namespace.
    pub fn id(&self) -> WithdrawalId {
        let digest = hash_domain(DOMAIN_WITHDRAWAL_ID, &self.encode());
        WithdrawalId(*digest.as_bytes())
    }
}

/// Proof that a withdrawal's funds are reserved on the replicated ledger and
/// that the reservation is committed under the finalizing checkpoint.
///
/// The custody signer never trusts a boolean "reserved" flag: the reserved
/// amount and the ledger sequence/height at which it was reserved are folded
/// into the [authorization digest](withdrawal_authorization_digest), and
/// `branch` is the Merkle inclusion proof of that digest under the checkpoint
/// the consensus quorum signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationProof {
    /// The amount reserved on the ledger for this withdrawal (must cover it).
    pub reserved_amount: Amount,
    /// The ledger sequence/height at which the reservation was recorded.
    pub reservation_seq: SequenceNumber,
    /// Index of the authorization-digest leaf within the checkpoint's tree.
    pub leaf_index: u64,
    /// Merkle inclusion proof (sibling hashes, leaf → root) under `checkpoint`.
    pub branch: Vec<Hash>,
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
    /// The finalizing checkpoint (state root) the quorum signed over. It commits
    /// to the authorization digest through [`ReservationProof::branch`].
    pub checkpoint: Hash,
    /// The consensus quorum certificate over `checkpoint`.
    pub quorum: QuorumCertificate,
    /// On-chain confirmations backing the reservation (bound into the digest).
    pub confirmations: u32,
    /// The ledger reservation and its inclusion proof under `checkpoint`.
    pub reservation: ReservationProof,
    /// Last sequence at which the certificate may be signed (inclusive).
    pub expiry: SequenceNumber,
}

/// The domain-separated withdrawal authorization digest.
///
/// This is the payload the finalizing checkpoint commits to. It binds every
/// security-relevant field of the authorization — the full request (account,
/// chain, destination, amount, nonce, via [`WithdrawalRequest::encode`]), the
/// derived withdrawal id, the confirmations backing the reservation, and the
/// reserved amount and its ledger sequence/height — so that no field can be
/// altered without invalidating the checkpoint inclusion proof.
pub fn withdrawal_authorization_digest(
    request: &WithdrawalRequest,
    withdrawal_id: WithdrawalId,
    confirmations: u32,
    reserved_amount: Amount,
    reservation_seq: SequenceNumber,
) -> Hash {
    let mut w = Writer::new();
    w.raw(&request.encode());
    w.raw(withdrawal_id.as_bytes());
    w.u32(confirmations);
    w.i128(reserved_amount.raw());
    w.u64(reservation_seq.get());
    hash_domain(DOMAIN_WITHDRAWAL_AUTH, &w.into_vec())
}

impl WithdrawalCertificate {
    /// The authorization digest this certificate must prove is committed under
    /// its finalizing checkpoint. See [`withdrawal_authorization_digest`].
    pub fn authorization_digest(&self) -> Hash {
        withdrawal_authorization_digest(
            &self.request,
            self.withdrawal_id,
            self.confirmations,
            self.reservation.reserved_amount,
            self.reservation.reservation_seq,
        )
    }

    /// Encode the certificate for transport / fuzzing.
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        let mut w = Writer::new();
        w.var_bytes(&self.request.encode())?;
        w.raw(self.withdrawal_id.as_bytes());
        w.raw(self.checkpoint.as_bytes());
        // quorum (the u16 bitmap keeps its legacy 8-byte wire slot)
        w.raw(self.quorum.message.as_bytes());
        w.u64(u64::from(self.quorum.signer_bitmap));
        let n = u32::try_from(self.quorum.signatures.len()).map_err(|_| CustodyError::Decode)?;
        w.u32(n);
        for sig in &self.quorum.signatures {
            w.raw(sig);
        }
        w.u32(self.confirmations);
        // reservation proof
        w.i128(self.reservation.reserved_amount.raw());
        w.u64(self.reservation.reservation_seq.get());
        w.u64(self.reservation.leaf_index);
        let b = u32::try_from(self.reservation.branch.len()).map_err(|_| CustodyError::Decode)?;
        w.u32(b);
        for node in &self.reservation.branch {
            w.raw(node.as_bytes());
        }
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
        // Reject bitmaps naming signers beyond the 16-signer cap.
        let signer_bitmap = u16::try_from(r.u64()?).map_err(|_| CustodyError::Decode)?;
        let count = usize::try_from(r.u32()?).map_err(|_| CustodyError::Decode)?;
        // Guard against a length field that would demand a huge allocation:
        // each signature is 64 bytes, so the buffer must have room for them.
        if count > MAX_VALIDATORS || count > r.remaining() / 64 {
            return Err(CustodyError::Decode);
        }
        let mut signatures = QuorumSignatures::new();
        for _ in 0..count {
            signatures
                .try_push(r.array::<64>()?)
                .map_err(|_| CustodyError::Decode)?;
        }
        let confirmations = r.u32()?;
        let reserved_amount = Amount::from_raw(r.i128()?);
        let reservation_seq = SequenceNumber::new(r.u64()?);
        let leaf_index = r.u64()?;
        let branch_len = usize::try_from(r.u32()?).map_err(|_| CustodyError::Decode)?;
        // Each Merkle node is 32 bytes; bound the allocation by the input left.
        if branch_len > r.remaining() / 32 {
            return Err(CustodyError::Decode);
        }
        let mut branch = Vec::with_capacity(branch_len);
        for _ in 0..branch_len {
            branch.push(Hash::from_bytes(r.array::<32>()?));
        }
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
            confirmations,
            reservation: ReservationProof {
                reserved_amount,
                reservation_seq,
                leaf_index,
                branch,
            },
            expiry,
        })
    }
}

/// Independently verify a finalized withdrawal certificate before signing.
///
/// Rejects, with the specific [`CustodyError`], any of: a withdrawal-id that
/// does not match the request, a reservation that does not cover the amount, an
/// expired certificate, an authorization digest that is not committed under the
/// finalizing checkpoint (bad/forged inclusion proof, or a quorum over an
/// unrelated checkpoint), a quorum whose message is not the checkpoint, and a
/// quorum that fails to verify under `consensus`.
///
/// On `Ok`, the request's authorization digest — which binds the account,
/// chain, destination, amount, nonce, confirmations and reservation — is proven
/// to be committed under a checkpoint that a consensus quorum signed. That is
/// the property the custody signer relies on: the quorum can never be repurposed
/// to authorize a different withdrawal than the one it committed to.
pub fn verify_certificate(
    cert: &WithdrawalCertificate,
    consensus: &ValidatorSet,
    now: SequenceNumber,
) -> Result<(), CustodyError> {
    if cert.withdrawal_id != cert.request.id() {
        return Err(CustodyError::MismatchedWithdrawalId);
    }
    if cert.reservation.reserved_amount < cert.request.amount {
        return Err(CustodyError::MissingLedgerReserve);
    }
    if now > cert.expiry {
        return Err(CustodyError::Expired);
    }
    // The authorization digest must be committed under the finalizing checkpoint.
    // This replaces the old client-supplied `finalized` / `ledger_reserved`
    // booleans with a cryptographic inclusion proof, and binds the full request
    // to the checkpoint: a quorum over an unrelated checkpoint has no proof that
    // reconstructs this root, so it cannot authorize the withdrawal.
    let digest = cert.authorization_digest();
    let leaf_index = usize::try_from(cert.reservation.leaf_index)
        .map_err(|_| CustodyError::UnprovenAuthorization)?;
    if !verify_proof(
        cert.checkpoint,
        leaf_index,
        digest,
        &cert.reservation.branch,
    ) {
        return Err(CustodyError::UnprovenAuthorization);
    }
    // The finalizing checkpoint must be the exact message the quorum signed, and
    // that quorum must reach the consensus threshold.
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
    use crypto::{MerkleTree, ThresholdSigners};

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

    /// Build a checkpoint tree that commits to `digest` at `leaf_index`, padded
    /// with some unrelated sibling leaves, and return `(checkpoint, branch)`.
    fn commit(digest: Hash, leaf_index: usize) -> (Hash, Vec<Hash>) {
        let mut tree = MerkleTree::new(8);
        // Fill the tree with distinct unrelated leaves so the proof is non-trivial.
        for i in 0..8usize {
            tree.set(i, Hash::from_bytes([u8::try_from(i).unwrap() + 0x40; 32]))
                .unwrap();
        }
        tree.set(leaf_index, digest).unwrap();
        (tree.root(), tree.proof(leaf_index).unwrap())
    }

    fn good_cert(consensus_signers: &ThresholdSigners) -> WithdrawalCertificate {
        let req = request();
        let confirmations = 12;
        let reserved_amount = Amount::from_raw(100_000_000);
        let reservation_seq = SequenceNumber::new(42);
        let leaf_index = 3usize;
        let digest = withdrawal_authorization_digest(
            &req,
            req.id(),
            confirmations,
            reserved_amount,
            reservation_seq,
        );
        let (checkpoint, branch) = commit(digest, leaf_index);
        let quorum = consensus_signers.sign(checkpoint, vec![0, 1, 2]);
        WithdrawalCertificate {
            withdrawal_id: req.id(),
            request: req,
            checkpoint,
            quorum,
            confirmations,
            reservation: ReservationProof {
                reserved_amount,
                reservation_seq,
                leaf_index: leaf_index as u64,
                branch,
            },
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

        // Tampered checkpoint (stale quorum over the real root) fails the QC
        // message check even though the inclusion proof no longer matches.
        let mut c = good_cert(&s);
        c.checkpoint = Hash::from_bytes([1u8; 32]);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::UnprovenAuthorization)
        );

        // Mismatched withdrawal id.
        let mut c = good_cert(&s);
        c.withdrawal_id = WithdrawalId::from_bytes([0u8; 32]);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::MismatchedWithdrawalId)
        );

        // Reservation does not cover the amount.
        let mut c = good_cert(&s);
        c.reservation.reserved_amount = Amount::from_raw(1);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::MissingLedgerReserve)
        );

        // Expired.
        let c = good_cert(&s);
        assert_eq!(
            verify_certificate(&c, &set, SequenceNumber::new(2000)),
            Err(CustodyError::Expired)
        );

        // Insufficient quorum (only 2-of-4 signed the checkpoint).
        let mut c = good_cert(&s);
        let cp = c.checkpoint;
        c.quorum = s.sign(cp, vec![0, 1]);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::BadQuorumSignature)
        );
    }

    #[test]
    fn quorum_over_unrelated_checkpoint_cannot_authorize() {
        // A valid quorum over a *different*, unrelated checkpoint must not be
        // pairable with this request: no inclusion proof binds the request's
        // authorization digest to the unrelated root.
        let s = signers();
        let set = s.validator_set();
        let good = good_cert(&s);

        // Build an unrelated but internally-valid checkpoint + quorum. It commits
        // to entirely different leaves and knows nothing of our withdrawal.
        let mut other = MerkleTree::new(8);
        for i in 0..8usize {
            other
                .set(i, Hash::from_bytes([u8::try_from(i).unwrap() + 0xF0; 32]))
                .unwrap();
        }
        let unrelated_checkpoint = other.root();
        let unrelated_quorum = s.sign(unrelated_checkpoint, vec![0, 1, 2]);
        assert!(set.verify(&unrelated_quorum).is_ok());

        // Attacker keeps the request but swaps in the unrelated quorum/checkpoint,
        // reusing whatever branch they had. Verification must reject.
        let mut forged = good.clone();
        forged.checkpoint = unrelated_checkpoint;
        forged.quorum = unrelated_quorum;
        assert_eq!(
            verify_certificate(&forged, &set, SequenceNumber::new(1)),
            Err(CustodyError::UnprovenAuthorization)
        );

        // Even supplying a genuine proof for a *different* leaf of the unrelated
        // tree cannot rescue it: that leaf is not our authorization digest.
        let mut forged2 = good;
        forged2.checkpoint = unrelated_checkpoint;
        forged2.quorum = s.sign(unrelated_checkpoint, vec![0, 1, 2]);
        forged2.reservation.leaf_index = 5;
        forged2.reservation.branch = other.proof(5).unwrap();
        assert_eq!(
            verify_certificate(&forged2, &set, SequenceNumber::new(1)),
            Err(CustodyError::UnprovenAuthorization)
        );
    }

    #[test]
    fn flipping_any_request_field_fails_verification() {
        // Property test: a certificate whose committed checkpoint was built for
        // the original request must fail once *any* request field is flipped,
        // even if the attacker also fixes up the withdrawal id to keep the
        // id-match check happy. The signed checkpoint no longer commits to the
        // mutated request's digest.
        let s = signers();
        let set = s.validator_set();
        let now = SequenceNumber::new(1);
        let base = good_cert(&s);

        let mutators: [fn(&mut WithdrawalRequest); 6] = [
            |r| r.account = AccountId::new(99),
            |r| r.chain = ChainId(2),
            |r| r.to = WalletAddress::Evm([0xCD; 20]),
            |r| r.to = WalletAddress::Svm([0x11; 32]),
            |r| r.amount = Amount::from_raw(200_000_000),
            |r| r.nonce = 8,
        ];

        for mutate in mutators {
            let mut c = base.clone();
            mutate(&mut c.request);
            // Re-sync the id so the id-match guard passes; also raise the reserve
            // so the coverage guard passes. Only the checkpoint binding can catch
            // the tampering now.
            c.withdrawal_id = c.request.id();
            c.reservation.reserved_amount = Amount::from_raw(200_000_000);
            assert_eq!(
                verify_certificate(&c, &set, now),
                Err(CustodyError::UnprovenAuthorization),
                "flipping a request field was not rejected"
            );
        }
    }

    #[test]
    fn flipping_confirmations_or_reservation_fails_verification() {
        // The confirmations and reservation seq are folded into the signed
        // digest; changing either breaks the checkpoint inclusion proof.
        let s = signers();
        let set = s.validator_set();
        let now = SequenceNumber::new(1);

        let mut c = good_cert(&s);
        c.confirmations += 1;
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::UnprovenAuthorization)
        );

        let mut c = good_cert(&s);
        c.reservation.reservation_seq = SequenceNumber::new(43);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::UnprovenAuthorization)
        );

        // A larger-than-committed reservation also breaks the digest even though
        // it still covers the amount.
        let mut c = good_cert(&s);
        c.reservation.reserved_amount = Amount::from_raw(999_999_999);
        assert_eq!(
            verify_certificate(&c, &set, now),
            Err(CustodyError::UnprovenAuthorization)
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
