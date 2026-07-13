//! Minimmit wire types: [`ParentRef`], the five consensus messages plus the
//! execution attestation, and the [`Proof`] union
//! (`docs/CONSENSUS_MINIMMIT.md` §4.2–§4.4, #517, #520).
//!
//! All types serialize through `serde` + `codec` (postcard) with 64-byte
//! ed25519 signatures via the private `crate::sig64` adapter — the exact wire
//! conventions of the consensus crate.
//!
//! # `u16` signer indices (deliberate wire break)
//!
//! `validator_index` / `proposer_index` are **`u16`** on every Minimmit
//! message, safe under the
//! [`crate::vote::MAX_VALIDATORS`] = 16 cap and aligned with the 16-bit
//! [`Certificate`] signer bitmap. An index at or beyond the committee size is
//! rejectable through the [`MinimmitCommittee`]
//! accessors ([`public_key`](super::MinimmitCommittee::public_key) /
//! [`cached_key`](super::MinimmitCommittee::cached_key) /
//! [`weight`](super::MinimmitCommittee::weight) return `None`;
//! [`assemble`](super::MinimmitCommittee::assemble) errors).
//!
//! # Scope boundaries
//!
//! This module defines the data types with their digest accessors (#517), the
//! [`msg_type`] tag registry with the [`ConsensusMessage`] encode/decode
//! entry point (#518), the certificate `verify` methods
//! ([`Notarization::verify`] / [`Nullification::verify`], #519), and the
//! retained execution attestation [`ExecAttest`] at tag `0x0006` (#520) —
//! the wire half of the mandatory exec-cert flow. The reactor collection
//! path that assembles exec L-certs from these attestations is Phase 2
//! (#528); the sim self-feed is Phase 3.

use crypto::QuorumError;
use serde::{Deserialize, Serialize};
use types::Hash;

use crate::bft::execution_commitment_digest;
use crate::vote::VoteError;

use super::block::BlockHeader;
use super::committee::{Certificate, MinimmitCommittee, ThresholdKind};
use super::digest::{notarize_digest, nullify_digest, propose_auth};

/// The `⊥` ("bottom") sentinel for [`ParentRef::parent_view`], encoded as
/// `u64::MAX` (`docs/CONSENSUS_MINIMMIT.md` §4.2).
///
/// A genesis parent carries `parent_view = ⊥` because genesis was never
/// proposed in any view. The sentinel is **rejected wherever a real view is
/// required** ([`ParentRef::real_view`] returns `None`), and it conceptually
/// orders *below* every real view for the `valid_parent` interval logic
/// (§6.4): skipping over `⊥` means every view in `[0, v)` must carry a
/// nullification.
pub const BOTTOM_VIEW: u64 = u64::MAX;

/// A proposal's claimed parent: the notarized block it extends
/// (`docs/CONSENSUS_MINIMMIT.md` §4.2).
///
/// `parent_view` is either the view whose notarization named `parent_hash`,
/// or the [`BOTTOM_VIEW`] `⊥` sentinel when the parent is genesis. `⊥` is
/// never a real view: use [`Self::real_view`] wherever one is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentRef {
    /// Hash of the parent block header (or the genesis hash at `⊥`).
    pub parent_hash: Hash,
    /// View in which the parent was notarized, or [`BOTTOM_VIEW`] (`⊥`) for
    /// the genesis parent.
    pub parent_view: u64,
}

impl ParentRef {
    /// The start-of-chain parent: `{ genesis_hash, ⊥ }`.
    #[must_use]
    pub fn genesis(genesis_hash: Hash) -> Self {
        Self {
            parent_hash: genesis_hash,
            parent_view: BOTTOM_VIEW,
        }
    }

    /// Whether `parent_view` is the `⊥` sentinel (genesis parent).
    #[must_use]
    pub fn is_bottom(&self) -> bool {
        self.parent_view == BOTTOM_VIEW
    }

    /// The parent view as a *real* view: `None` for the `⊥` sentinel.
    ///
    /// This is the rejection point mandated by
    /// `docs/CONSENSUS_MINIMMIT.md` §4.2 — every consumer that needs an
    /// actual view (e.g. `proofs[parent_view]` lookups) must go through
    /// this accessor rather than reading `parent_view` raw.
    #[must_use]
    pub fn real_view(&self) -> Option<u64> {
        if self.is_bottom() {
            None
        } else {
            Some(self.parent_view)
        }
    }
}

/// The leader's proposal for a view — and, simultaneously, its notarize vote
/// (`docs/CONSENSUS_MINIMMIT.md` §4.3, `msg_type 0x0001` per #518).
///
/// **The propose IS the leader's implicit notarize:** `notarize_sig` signs
/// [`notarize_digest`] — the identical preimage a follower's [`Notarize`]
/// signs — so the leader's vote counts in the same tally. `propose_sig` signs
/// [`propose_auth`] and authenticates the parent binding (equivocation / fork
/// evidence uses it). A follower verifies **both**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Propose {
    /// Epoch of the proposing committee.
    pub epoch: u64,
    /// View this block is proposed in.
    pub view: u64,
    /// The proposed block header ([`BlockHeader::hash`] binds `height`).
    pub block: BlockHeader,
    /// [`BlockHeader::hash`] of `block`, carried explicitly so votes can be
    /// tallied against it without rehashing; receivers must recompute and
    /// compare.
    pub block_hash: Hash,
    /// The notarized parent this block extends (`⊥` sentinel for genesis).
    pub parent: ParentRef,
    /// Committee index of the proposing leader (`u16` wire standard).
    pub proposer_index: u16,
    /// ed25519 signature over [`Propose::notarize_digest`] — the leader's
    /// implicit notarize vote.
    #[serde(with = "crate::sig64")]
    pub notarize_sig: [u8; 64],
    /// ed25519 signature over [`Propose::auth_digest`] — authenticates the
    /// block-to-parent binding.
    #[serde(with = "crate::sig64")]
    pub propose_sig: [u8; 64],
}

impl Propose {
    /// The digest `notarize_sig` signs: exactly the digest a follower's
    /// [`Notarize`] for the same `(epoch, view, block_hash)` signs.
    #[must_use]
    pub fn notarize_digest(&self) -> Hash {
        notarize_digest(self.epoch, self.view, self.block_hash)
    }

    /// The digest `propose_sig` signs: binds `block_hash` to the claimed
    /// parent (`⊥` hashes like any other `parent_view` value here).
    #[must_use]
    pub fn auth_digest(&self) -> Hash {
        propose_auth(
            self.epoch,
            self.view,
            self.block_hash,
            self.parent.parent_hash,
            self.parent.parent_view,
        )
    }
}

/// A validator's notarize vote for a block in a view
/// (`docs/CONSENSUS_MINIMMIT.md` §4.3, `msg_type 0x0002` per #518).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notarize {
    /// Epoch of the voting committee.
    pub epoch: u64,
    /// View being voted in.
    pub view: u64,
    /// The block being notarized.
    pub block_hash: Hash,
    /// Committee index of the signing validator (`u16` wire standard).
    pub validator_index: u16,
    /// ed25519 signature over [`Notarize::digest`].
    #[serde(with = "crate::sig64")]
    pub signature: [u8; 64],
}

impl Notarize {
    /// The digest this vote signs — and the `message` a [`Notarization`]
    /// certificate aggregates.
    #[must_use]
    pub fn digest(&self) -> Hash {
        notarize_digest(self.epoch, self.view, self.block_hash)
    }
}

/// A validator's nullify vote: abandon the view without naming a block
/// (`docs/CONSENSUS_MINIMMIT.md` §4.3, `msg_type 0x0003` per #518).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nullify {
    /// Epoch of the voting committee.
    pub epoch: u64,
    /// View being abandoned.
    pub view: u64,
    /// Committee index of the signing validator (`u16` wire standard).
    pub validator_index: u16,
    /// ed25519 signature over [`Nullify::digest`].
    #[serde(with = "crate::sig64")]
    pub signature: [u8; 64],
}

impl Nullify {
    /// The digest this vote signs — and the `message` a [`Nullification`]
    /// certificate aggregates.
    #[must_use]
    pub fn digest(&self) -> Hash {
        nullify_digest(self.epoch, self.view)
    }
}

/// An M-certificate over notarize votes for one block in one view
/// (`docs/CONSENSUS_MINIMMIT.md` §4.3, `msg_type 0x0004` per #518).
///
/// `cert.message` must equal [`Notarization::digest`] — the recomputed
/// notarize digest for `(epoch, view, block_hash)`. [`Self::verify`] enforces
/// digest equality plus threshold verification against the
/// [`MinimmitCommittee`] advance set (#519); at **M** weight the certificate
/// advances the view, at **L** weight it finalizes the block and its
/// ancestors (§4.5: same [`Certificate`] type, two thresholds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notarization {
    /// Epoch of the certifying committee.
    pub epoch: u64,
    /// View the votes were cast in.
    pub view: u64,
    /// The notarized block.
    pub block_hash: Hash,
    /// The aggregated certificate; `cert.message` is the notarize digest.
    pub cert: Certificate,
}

impl Notarization {
    /// The digest `cert.message` must equal: the notarize digest every
    /// aggregated vote signed.
    #[must_use]
    pub fn digest(&self) -> Hash {
        notarize_digest(self.epoch, self.view, self.block_hash)
    }

    /// Verify this notarization at the advance bar `M` — the bar every
    /// received notarization must clear (#519).
    ///
    /// Asserts `cert.message == `[`Self::digest`] **before** any signature
    /// work, then routes the certificate through
    /// [`MinimmitCommittee::verify`] at [`ThresholdKind::Advance`], which
    /// re-checks every signature plus the signed-weight threshold. Models
    /// the committee's certificate verifier.
    ///
    /// L-threshold verification (finalization) is the Phase 2 finalize path:
    /// it re-verifies the *same* certificate via [`MinimmitCommittee::verify`]
    /// at [`ThresholdKind::Finalize`] — never here.
    ///
    /// # Errors
    ///
    /// [`CertError::DigestMismatch`] when `cert.message` is not the
    /// recomputed notarize digest (even if the aggregate is otherwise valid
    /// over the foreign message), otherwise [`CertError::Quorum`] carrying
    /// the underlying [`QuorumError`] (below-threshold weight, invalid
    /// signature, unknown signer, malformed certificate).
    pub fn verify(&self, committee: &MinimmitCommittee) -> Result<(), CertError> {
        if self.cert.message != self.digest() {
            return Err(CertError::DigestMismatch);
        }
        committee.verify(&self.cert, ThresholdKind::Advance)?;
        Ok(())
    }
}

/// An M-certificate over nullify votes for one view
/// (`docs/CONSENSUS_MINIMMIT.md` §4.3, `msg_type 0x0005` per #518).
///
/// `cert.message` must equal [`Nullification::digest`] — the recomputed
/// nullify digest for `(epoch, view)`; [`Self::verify`] enforces it (#519).
/// A nullification names no block: it certifies that the view is abandoned
/// and the chain skips it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nullification {
    /// Epoch of the certifying committee.
    pub epoch: u64,
    /// View being nullified.
    pub view: u64,
    /// The aggregated certificate; `cert.message` is the nullify digest.
    pub cert: Certificate,
}

impl Nullification {
    /// The digest `cert.message` must equal: the nullify digest every
    /// aggregated vote signed.
    #[must_use]
    pub fn digest(&self) -> Hash {
        nullify_digest(self.epoch, self.view)
    }

    /// Verify this nullification at the advance bar `M` (#519).
    ///
    /// Asserts `cert.message == `[`Self::digest`] **before** any signature
    /// work, then routes the certificate through
    /// [`MinimmitCommittee::verify`] at [`ThresholdKind::Advance`]. Models
    /// the committee's certificate verifier. `M` is the *only* bar a
    /// nullification is ever checked against — finalization is exclusively an
    /// L-notarization concern.
    ///
    /// # Errors
    ///
    /// [`CertError::DigestMismatch`] when `cert.message` is not the
    /// recomputed nullify digest (even if the aggregate is otherwise valid
    /// over the foreign message), otherwise [`CertError::Quorum`] carrying
    /// the underlying [`QuorumError`].
    pub fn verify(&self, committee: &MinimmitCommittee) -> Result<(), CertError> {
        if self.cert.message != self.digest() {
            return Err(CertError::DigestMismatch);
        }
        committee.verify(&self.cert, ThresholdKind::Advance)?;
        Ok(())
    }
}

/// A validator's execution attestation: its vote that executing a block
/// produced a specific state root (`docs/CONSENSUS_MINIMMIT.md` §4.3 / §10,
/// `msg_type 0x0006`, #520).
///
/// This is the retained per-validator execution vote feeding the
/// **mandatory** exec L-cert: execution runs OUTSIDE the pure core (in
/// `execution`); the node executes the block, produces `execution_root`,
/// signs the retained [`execution_commitment_digest`] (`crate::bft`, domain
/// `DOMAIN_EXEC_COMMIT` — **no new domain**), and broadcasts this
/// attestation. The reactor collects them into an L-threshold
/// [`Certificate`] over the same digest (#528); without that exec L-cert a
/// height never reaches `Finalized` — `ConsensusFinal` fires at
/// L-notarization, `Finalized` only after the exec L-cert lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecAttest {
    /// Epoch of the attesting committee.
    pub epoch: u64,
    /// View the block was notarized in.
    pub view: u64,
    /// Height of the executed block.
    pub height: u64,
    /// Hash of the executed block.
    pub block_hash: Hash,
    /// The deterministic state root execution produced.
    pub execution_root: Hash,
    /// Committee index of the attesting validator (`u16` wire standard).
    pub validator_index: u16,
    /// ed25519 signature over [`ExecAttest::digest`].
    #[serde(with = "crate::sig64")]
    pub signature: [u8; 64],
}

impl ExecAttest {
    /// The digest this attestation signs — the retained
    /// [`execution_commitment_digest`] over
    /// `(epoch, view, height, block_hash, execution_root)`, and the
    /// `message` the exec L-cert aggregates (#528).
    #[must_use]
    pub fn digest(&self) -> Hash {
        execution_commitment_digest(
            self.epoch,
            self.view,
            self.height,
            self.block_hash,
            self.execution_root,
        )
    }

    /// Verify this attestation's signature against the signer's cached
    /// committee key before tally admission.
    ///
    /// The L-cert over a set of attestations is assembled and verified
    /// separately against the committee's `finalize_set` (#528 / Phase 4) —
    /// never here.
    ///
    /// # Errors
    ///
    /// [`VoteError::ForeignSigner`] when `validator_index` is outside the
    /// committee, [`VoteError::InvalidSignature`] when the signature does
    /// not verify over [`Self::digest`] under that validator's key.
    pub fn verify(&self, committee: &MinimmitCommittee) -> Result<(), VoteError> {
        let key = committee
            .cached_key(self.validator_index)
            .ok_or(VoteError::ForeignSigner(u32::from(self.validator_index)))?;
        key.verify(self.digest().as_bytes(), &self.signature)
            .map_err(|_| VoteError::InvalidSignature)
    }
}

/// A Minimmit certificate verification failure ([`Notarization::verify`] /
/// [`Nullification::verify`], #519).
///
/// Digest mismatch and a below-threshold certificate remain distinct errors: a
/// wrong-message certificate is a **digest** error, distinguishable from
/// every cryptographic / threshold failure — which this type preserves
/// verbatim as the wrapped [`QuorumError`] instead of collapsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    /// `cert.message` does not equal the recomputed notarize / nullify
    /// digest for the certificate's own `(epoch, view[, block_hash])` fields.
    /// Checked before any signature verification, so a valid aggregate over
    /// a *foreign* message still reports this — never a signature error.
    #[error("certificate message does not match the expected vote digest")]
    DigestMismatch,
    /// The digest matched but the certificate failed verification against
    /// the threshold set: below-threshold weight, an invalid signature, an
    /// unknown signer, or a malformed certificate.
    #[error("certificate quorum verification failed: {0}")]
    Quorum(#[from] QuorumError),
}

/// The certificate union a view resolves to: notarized (a block advanced) or
/// nullified (the view was abandoned) — `docs/CONSENSUS_MINIMMIT.md` §4.4.
///
/// Used for `proofs[view]` storage, re-dissemination (R7), and the
/// `select_parent` / `valid_parent` predicates (Phase 2). It is **not** a
/// standalone wire message — the two variants already are (`0x0004` /
/// `0x0005`) — but it is codec-serializable for storage and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proof {
    /// The view produced a notarized block.
    Notarization(Notarization),
    /// The view was nullified.
    Nullification(Nullification),
}

impl Proof {
    /// Epoch of the certifying committee.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        match self {
            Proof::Notarization(n) => n.epoch,
            Proof::Nullification(n) => n.epoch,
        }
    }

    /// The view this proof resolves.
    #[must_use]
    pub fn view(&self) -> u64 {
        match self {
            Proof::Notarization(n) => n.view,
            Proof::Nullification(n) => n.view,
        }
    }
}

/// The `msg_type: u16` tag registry — defined here and **nowhere else**
/// (`docs/CONSENSUS_MINIMMIT.md` §4.3, #518).
///
/// Postcard is non-self-describing, so the decoder must branch on an explicit
/// tag. On the wire the tag rides `codec::Frame::msg_type` and the encoded
/// message rides `codec::Frame::payload`, both on
/// `codec::TrafficClass::Consensus` (P0 lane).
///
/// **`network` / `codec` require no change** (confirmed against
/// `docs/CONSENSUS_MINIMMIT.md` §13.6): the network already routes consensus
/// bytes purely by `TrafficClass::Consensus` and treats payloads as opaque;
/// the tag lives inside the frame the consensus layer owns. The priority
/// scheduler, per-class QUIC streams, and `ConsensusPermits` class auth are
/// untouched.
pub mod msg_type {
    /// [`Propose`](super::Propose) — the leader's proposal + implicit
    /// notarize vote.
    pub const PROPOSE: u16 = 0x0001;
    /// [`Notarize`](super::Notarize) — a validator's notarize vote.
    pub const NOTARIZE: u16 = 0x0002;
    /// [`Nullify`](super::Nullify) — a validator's nullify vote.
    pub const NULLIFY: u16 = 0x0003;
    /// [`Notarization`](super::Notarization) — a certificate over notarize
    /// votes.
    pub const NOTARIZATION: u16 = 0x0004;
    /// [`Nullification`](super::Nullification) — a certificate over nullify
    /// votes.
    pub const NULLIFICATION: u16 = 0x0005;
    /// [`ExecAttest`](super::ExecAttest) — a validator's execution
    /// attestation toward the mandatory exec L-cert (#520).
    pub const EXEC_ATTEST: u16 = 0x0006;
}

/// Errors from the [`ConsensusMessage`] encode/decode entry point.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The `msg_type` tag is not in the [`msg_type`] registry.
    #[error("unknown consensus msg_type tag {0:#06x}")]
    UnknownMsgType(u16),
    /// The payload failed to encode, or failed to decode as the type its tag
    /// names (truncated or malformed bytes).
    #[error("consensus wire codec failure: {0}")]
    Codec(#[from] codec::CodecError),
}

/// The single in-crate encode/decode entry point over the six Minimmit wire
/// messages (`docs/CONSENSUS_MINIMMIT.md` §4.3, #518, #520).
///
/// The node hands `(msg_type, payload)` pairs to/from the network layer; this
/// enum is how it maps them to typed messages without every caller
/// re-implementing the tag dispatch.
///
/// Deliberately **not** `Serialize`/`Deserialize`: the wire form is the
/// `(u16 tag, postcard payload)` pair carried by `codec::Frame`, and deriving
/// serde here would introduce a second, conflicting encoding (postcard's
/// variant index shadowing the [`msg_type`] registry). [`Self::encode`] /
/// [`Self::decode`] are the only entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusMessage {
    /// `msg_type` [`msg_type::PROPOSE`].
    Propose(Propose),
    /// `msg_type` [`msg_type::NOTARIZE`].
    Notarize(Notarize),
    /// `msg_type` [`msg_type::NULLIFY`].
    Nullify(Nullify),
    /// `msg_type` [`msg_type::NOTARIZATION`].
    Notarization(Notarization),
    /// `msg_type` [`msg_type::NULLIFICATION`].
    Nullification(Nullification),
    /// `msg_type` [`msg_type::EXEC_ATTEST`].
    ExecAttest(ExecAttest),
}

impl ConsensusMessage {
    /// The [`msg_type`] registry tag for this variant.
    #[must_use]
    pub fn msg_type(&self) -> u16 {
        match self {
            ConsensusMessage::Propose(_) => msg_type::PROPOSE,
            ConsensusMessage::Notarize(_) => msg_type::NOTARIZE,
            ConsensusMessage::Nullify(_) => msg_type::NULLIFY,
            ConsensusMessage::Notarization(_) => msg_type::NOTARIZATION,
            ConsensusMessage::Nullification(_) => msg_type::NULLIFICATION,
            ConsensusMessage::ExecAttest(_) => msg_type::EXEC_ATTEST,
        }
    }

    /// Encode to the `(msg_type, payload)` pair that rides
    /// `codec::Frame { msg_type, payload }` on `TrafficClass::Consensus`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Codec`] if postcard serialization fails.
    pub fn encode(&self) -> Result<(u16, Vec<u8>), WireError> {
        let payload = match self {
            ConsensusMessage::Propose(m) => codec::encode(m),
            ConsensusMessage::Notarize(m) => codec::encode(m),
            ConsensusMessage::Nullify(m) => codec::encode(m),
            ConsensusMessage::Notarization(m) => codec::encode(m),
            ConsensusMessage::Nullification(m) => codec::encode(m),
            ConsensusMessage::ExecAttest(m) => codec::encode(m),
        }?;
        Ok((self.msg_type(), payload))
    }

    /// Decode a payload by branching on its [`msg_type`] tag — the one tag
    /// dispatch in the crate.
    ///
    /// Total on adversarial input: an unknown tag or a truncated/malformed
    /// payload returns `Err`, never panics.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnknownMsgType`] for a tag outside the registry
    /// and [`WireError::Codec`] when the payload does not decode as the type
    /// the tag names.
    pub fn decode(tag: u16, bytes: &[u8]) -> Result<Self, WireError> {
        match tag {
            msg_type::PROPOSE => Ok(ConsensusMessage::Propose(codec::decode(bytes)?)),
            msg_type::NOTARIZE => Ok(ConsensusMessage::Notarize(codec::decode(bytes)?)),
            msg_type::NULLIFY => Ok(ConsensusMessage::Nullify(codec::decode(bytes)?)),
            msg_type::NOTARIZATION => Ok(ConsensusMessage::Notarization(codec::decode(bytes)?)),
            msg_type::NULLIFICATION => Ok(ConsensusMessage::Nullification(codec::decode(bytes)?)),
            msg_type::EXEC_ATTEST => Ok(ConsensusMessage::ExecAttest(codec::decode(bytes)?)),
            unknown => Err(WireError::UnknownMsgType(unknown)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vote::VoteError;
    use crypto::{KeyPair, Validator};

    const EPOCH: u64 = 7;
    const VIEW: u64 = 42;

    fn block_header() -> BlockHeader {
        BlockHeader {
            height: 9,
            parent_hash: Hash::from_bytes([0xCD; 32]),
            payload_root: Hash::from_bytes([0xEF; 32]),
        }
    }

    fn parent() -> ParentRef {
        ParentRef {
            parent_hash: Hash::from_bytes([0xCD; 32]),
            parent_view: VIEW - 1,
        }
    }

    fn propose() -> Propose {
        let block = block_header();
        Propose {
            epoch: EPOCH,
            view: VIEW,
            block,
            block_hash: block.hash(),
            parent: parent(),
            proposer_index: 3,
            notarize_sig: [0x11; 64],
            propose_sig: [0x22; 64],
        }
    }

    fn notarize() -> Notarize {
        Notarize {
            epoch: EPOCH,
            view: VIEW,
            block_hash: block_header().hash(),
            validator_index: 5,
            signature: [0x33; 64],
        }
    }

    fn nullify() -> Nullify {
        Nullify {
            epoch: EPOCH,
            view: VIEW,
            validator_index: 5,
            signature: [0x44; 64],
        }
    }

    fn exec_attest() -> ExecAttest {
        ExecAttest {
            epoch: EPOCH,
            view: VIEW,
            height: block_header().height,
            block_hash: block_header().hash(),
            execution_root: Hash::from_bytes([0x88; 32]),
            validator_index: 5,
            signature: [0x99; 64],
        }
    }

    /// [`exec_attest`] with a REAL signature from validator `index`.
    fn signed_exec_attest(keys: &[KeyPair], index: u16) -> ExecAttest {
        let mut attest = exec_attest();
        attest.validator_index = index;
        attest.signature = keys[usize::from(index)].sign(attest.digest().as_bytes());
        attest
    }

    fn cert(message: Hash) -> Certificate {
        Certificate {
            message,
            signer_bitmap: 0b0000_0000_0010_1001,
            signatures: vec![[0x55; 64], [0x66; 64], [0x77; 64]],
        }
    }

    /// A unit-weight 6-member committee (f = 1 ⇒ M = 3, L = 5) with its
    /// deterministic keypairs.
    fn m3_committee() -> (MinimmitCommittee, Vec<KeyPair>) {
        let keys: Vec<KeyPair> = (0..6)
            .map(|i| KeyPair::from_seed(&[u8::try_from(i).unwrap() + 1; 32]))
            .collect();
        let members: Vec<Validator> = keys
            .iter()
            .map(|kp| Validator {
                public_key: kp.public(),
                weight: 1,
            })
            .collect();
        (MinimmitCommittee::new_unit(EPOCH, members).unwrap(), keys)
    }

    /// Assemble a certificate over `message` with REAL signatures from the
    /// validators at `indices`.
    fn signed_cert(
        committee: &MinimmitCommittee,
        keys: &[KeyPair],
        message: Hash,
        indices: &[u16],
    ) -> Certificate {
        let signers: Vec<(u16, [u8; 64])> = indices
            .iter()
            .map(|&i| (i, keys[usize::from(i)].sign(message.as_bytes())))
            .collect();
        committee.assemble(message, &signers).unwrap()
    }

    fn notarization() -> Notarization {
        let block_hash = block_header().hash();
        Notarization {
            epoch: EPOCH,
            view: VIEW,
            block_hash,
            cert: cert(notarize_digest(EPOCH, VIEW, block_hash)),
        }
    }

    fn nullification() -> Nullification {
        Nullification {
            epoch: EPOCH,
            view: VIEW,
            cert: cert(nullify_digest(EPOCH, VIEW)),
        }
    }

    /// Encode → decode → identity, and canonical re-encode, for one type.
    fn round_trip<T>(value: &T)
    where
        T: PartialEq + core::fmt::Debug + Serialize + for<'de> Deserialize<'de>,
    {
        let bytes = codec::encode(value).unwrap();
        let decoded: T = codec::decode(&bytes).unwrap();
        assert_eq!(*value, decoded);
        // Encoding is canonical: re-encoding the decoded value is identical.
        assert_eq!(bytes, codec::encode(&decoded).unwrap());
    }

    #[test]
    fn all_wire_types_round_trip_through_codec() {
        round_trip(&parent());
        round_trip(&ParentRef::genesis(Hash::from_bytes([0xAB; 32])));
        round_trip(&propose());
        round_trip(&notarize());
        round_trip(&nullify());
        round_trip(&notarization());
        round_trip(&nullification());
        round_trip(&exec_attest());
        round_trip(&Proof::Notarization(notarization()));
        round_trip(&Proof::Nullification(nullification()));
    }

    #[test]
    fn bottom_sentinel_is_documented_and_rejected_as_a_real_view() {
        // ⊥ is pinned to u64::MAX — a wire-format constant.
        assert_eq!(BOTTOM_VIEW, u64::MAX);

        let genesis = ParentRef::genesis(Hash::from_bytes([0xAB; 32]));
        assert_eq!(genesis.parent_view, BOTTOM_VIEW);
        assert!(genesis.is_bottom());
        // The rejection point: ⊥ never converts into a real view.
        assert_eq!(genesis.real_view(), None);

        // A real parent view passes through untouched.
        let real = parent();
        assert!(!real.is_bottom());
        assert_eq!(real.real_view(), Some(VIEW - 1));
        // The greatest real view is still real — only the sentinel is ⊥.
        let max_real = ParentRef {
            parent_hash: Hash::from_bytes([0xAB; 32]),
            parent_view: u64::MAX - 1,
        };
        assert_eq!(max_real.real_view(), Some(u64::MAX - 1));
    }

    #[test]
    fn propose_carries_the_leaders_implicit_notarize() {
        // The propose's notarize digest is byte-identical to the digest a
        // follower's Notarize for the same (epoch, view, block_hash) signs —
        // this is what lets the leader's vote count in the same tally.
        let p = propose();
        let n = notarize();
        assert_eq!(p.block_hash, n.block_hash, "fixtures must align");
        assert_eq!(p.notarize_digest(), n.digest());
        assert_eq!(
            p.notarize_digest(),
            notarize_digest(EPOCH, VIEW, p.block_hash)
        );
        // The auth digest binds the parent (and is a distinct preimage).
        assert_eq!(
            p.auth_digest(),
            propose_auth(
                EPOCH,
                VIEW,
                p.block_hash,
                p.parent.parent_hash,
                p.parent.parent_view
            )
        );
        assert_ne!(p.notarize_digest(), p.auth_digest());
    }

    #[test]
    fn message_digests_match_the_phase_1_digest_functions() {
        assert_eq!(
            notarize().digest(),
            notarize_digest(EPOCH, VIEW, block_header().hash())
        );
        assert_eq!(nullify().digest(), nullify_digest(EPOCH, VIEW));
        // A certificate's message IS the vote digest it aggregates.
        let notarization = notarization();
        assert_eq!(notarization.cert.message, notarization.digest());
        assert_eq!(notarization.digest(), notarize().digest());
        let nullification = nullification();
        assert_eq!(nullification.cert.message, nullification.digest());
        assert_eq!(nullification.digest(), nullify().digest());
    }

    #[test]
    fn proof_exposes_epoch_and_view_of_either_variant() {
        let n = Proof::Notarization(notarization());
        assert_eq!(n.epoch(), EPOCH);
        assert_eq!(n.view(), VIEW);
        let x = Proof::Nullification(nullification());
        assert_eq!(x.epoch(), EPOCH);
        assert_eq!(x.view(), VIEW);
    }

    #[test]
    fn out_of_committee_u16_index_is_rejectable() {
        // n = 6, f = 1: valid indices are 0..=5. A message carrying index 6
        // resolves to no key/weight, and certificate assembly rejects it.
        let (committee, keys) = m3_committee();

        let mut foreign = notarize();
        foreign.validator_index = 6;
        assert!(committee.public_key(foreign.validator_index).is_none());
        assert!(committee.cached_key(foreign.validator_index).is_none());
        assert!(committee.weight(foreign.validator_index).is_none());
        assert_eq!(
            committee.assemble(
                foreign.digest(),
                &[(foreign.validator_index, foreign.signature)]
            ),
            Err(VoteError::ForeignSigner(6))
        );
        // An in-range index resolves (and u16::MAX is farthest out of range).
        let in_range = notarize();
        assert!(committee.public_key(in_range.validator_index).is_some());
        assert!(committee.public_key(u16::MAX).is_none());

        // End-to-end: real signatures over the wire digest assemble into a
        // certificate that verifies at the advance bar.
        let msg = in_range.digest();
        let cert = signed_cert(&committee, &keys, msg, &[0, 2, 4]);
        assert_eq!(committee.verify(&cert, ThresholdKind::Advance), Ok(()));
    }

    #[test]
    fn notarization_verifies_at_m_and_rejects_below_m() {
        let (committee, keys) = m3_committee();
        let block_hash = block_header().hash();
        let digest = notarize_digest(EPOCH, VIEW, block_hash);

        // Exactly M = 3 signers clear the advance bar.
        let notarization = Notarization {
            epoch: EPOCH,
            view: VIEW,
            block_hash,
            cert: signed_cert(&committee, &keys, digest, &[0, 2, 4]),
        };
        assert_eq!(notarization.verify(&committee), Ok(()));

        // An L-quorum (5 of 6) is a fortiori an M-quorum.
        let l_quorum = Notarization {
            cert: signed_cert(&committee, &keys, digest, &[0, 1, 2, 3, 4]),
            ..notarization.clone()
        };
        assert_eq!(l_quorum.verify(&committee), Ok(()));

        // M − 1 = 2 signers: below-threshold, reported as the quorum error —
        // never as a digest mismatch.
        let below_m = Notarization {
            cert: signed_cert(&committee, &keys, digest, &[1, 5]),
            ..notarization
        };
        assert_eq!(
            below_m.verify(&committee),
            Err(CertError::Quorum(QuorumError::BelowThreshold {
                signed: 2,
                threshold: 3,
            }))
        );
    }

    #[test]
    fn nullification_verifies_at_m_and_rejects_below_m() {
        let (committee, keys) = m3_committee();
        let digest = nullify_digest(EPOCH, VIEW);

        let nullification = Nullification {
            epoch: EPOCH,
            view: VIEW,
            cert: signed_cert(&committee, &keys, digest, &[1, 3, 5]),
        };
        assert_eq!(nullification.verify(&committee), Ok(()));

        let below_m = Nullification {
            cert: signed_cert(&committee, &keys, digest, &[0, 3]),
            ..nullification
        };
        assert_eq!(
            below_m.verify(&committee),
            Err(CertError::Quorum(QuorumError::BelowThreshold {
                signed: 2,
                threshold: 3,
            }))
        );
    }

    #[test]
    fn wrong_cert_message_is_a_digest_mismatch_not_a_signature_error() {
        let (committee, keys) = m3_committee();
        let block_hash = block_header().hash();

        // Adversarial cross-play: a FULLY VALID M-aggregate over the nullify
        // digest presented as a notarization. Every signature verifies over
        // cert.message, so only the digest-equality gate can reject it — and
        // it must fire as DigestMismatch, not as a signature/threshold error.
        let cross = Notarization {
            epoch: EPOCH,
            view: VIEW,
            block_hash,
            cert: signed_cert(&committee, &keys, nullify_digest(EPOCH, VIEW), &[0, 1, 2]),
        };
        assert_eq!(cross.verify(&committee), Err(CertError::DigestMismatch));

        // ... and the mirror image: a valid notarize aggregate inside a
        // nullification.
        let cross = Nullification {
            epoch: EPOCH,
            view: VIEW,
            cert: signed_cert(
                &committee,
                &keys,
                notarize_digest(EPOCH, VIEW, block_hash),
                &[0, 1, 2],
            ),
        };
        assert_eq!(cross.verify(&committee), Err(CertError::DigestMismatch));
    }

    #[test]
    fn field_tampering_rederives_the_digest_and_rejects() {
        let (committee, keys) = m3_committee();
        let block_hash = block_header().hash();

        // Any header-field tamper changes the recomputed expected digest, so
        // the untouched (still internally valid) cert no longer matches it.
        let good = Notarization {
            epoch: EPOCH,
            view: VIEW,
            block_hash,
            cert: signed_cert(
                &committee,
                &keys,
                notarize_digest(EPOCH, VIEW, block_hash),
                &[0, 1, 2],
            ),
        };
        assert_eq!(good.verify(&committee), Ok(()));
        for tampered in [
            Notarization {
                epoch: EPOCH + 1,
                ..good.clone()
            },
            Notarization {
                view: VIEW + 1,
                ..good.clone()
            },
            Notarization {
                block_hash: Hash::from_bytes([0x99; 32]),
                ..good
            },
        ] {
            assert_eq!(tampered.verify(&committee), Err(CertError::DigestMismatch));
        }

        let good = Nullification {
            epoch: EPOCH,
            view: VIEW,
            cert: signed_cert(&committee, &keys, nullify_digest(EPOCH, VIEW), &[0, 1, 2]),
        };
        assert_eq!(good.verify(&committee), Ok(()));
        for tampered in [
            Nullification {
                epoch: EPOCH + 1,
                ..good.clone()
            },
            Nullification {
                view: VIEW + 1,
                ..good
            },
        ] {
            assert_eq!(tampered.verify(&committee), Err(CertError::DigestMismatch));
        }
    }

    #[test]
    fn matching_digest_with_bad_signature_is_a_quorum_error() {
        // The complement of the DigestMismatch tests: once the message
        // matches, failures are cryptographic and surface as the wrapped
        // QuorumError — the two rejection classes never blur.
        let (committee, keys) = m3_committee();
        let block_hash = block_header().hash();
        let digest = notarize_digest(EPOCH, VIEW, block_hash);
        let mut cert = signed_cert(&committee, &keys, digest, &[0, 1, 2]);
        cert.signatures[1] = [0x99; 64];
        let forged = Notarization {
            epoch: EPOCH,
            view: VIEW,
            block_hash,
            cert,
        };
        assert_eq!(
            forged.verify(&committee),
            Err(CertError::Quorum(QuorumError::InvalidSignature))
        );
    }

    #[test]
    fn exec_attest_digest_reuses_execution_commitment_digest() {
        // The attestation signs the RETAINED digest from `crate::bft` — no
        // new domain — so the exec L-cert assembled over these attestations
        // is byte-compatible with the existing `certify_execution` layer.
        let attest = exec_attest();
        assert_eq!(
            attest.digest(),
            execution_commitment_digest(
                EPOCH,
                VIEW,
                attest.height,
                attest.block_hash,
                attest.execution_root,
            )
        );
        // Distinct preimage from every consensus digest (different domain).
        assert_ne!(
            attest.digest(),
            notarize_digest(EPOCH, VIEW, attest.block_hash)
        );
        assert_ne!(attest.digest(), nullify_digest(EPOCH, VIEW));
    }

    #[test]
    fn exec_attest_verify_accepts_a_correctly_signed_attestation() {
        let (committee, keys) = m3_committee();
        for index in [0u16, 2, 5] {
            let attest = signed_exec_attest(&keys, index);
            assert_eq!(attest.verify(&committee), Ok(()));
        }

        // End-to-end with the exec L-cert the attestations feed (#528):
        // L = 5 real attestation signatures over the SAME digest assemble
        // into a certificate that clears the finalize bar.
        let digest = exec_attest().digest();
        let cert = signed_cert(&committee, &keys, digest, &[0, 1, 2, 3, 4]);
        assert_eq!(committee.verify(&cert, ThresholdKind::Finalize), Ok(()));
    }

    #[test]
    fn exec_attest_verify_rejects_bad_signature_and_out_of_range_index() {
        let (committee, keys) = m3_committee();
        let good = signed_exec_attest(&keys, 2);

        // A corrupted signature fails as InvalidSignature.
        let mut corrupted = good.clone();
        corrupted.signature[0] ^= 0x01;
        assert_eq!(
            corrupted.verify(&committee),
            Err(VoteError::InvalidSignature)
        );

        // A valid signature from a DIFFERENT validator presented under this
        // index also fails: the signature binds the claimed signer.
        let mut wrong_signer = good.clone();
        wrong_signer.signature = keys[3].sign(good.digest().as_bytes());
        assert_eq!(
            wrong_signer.verify(&committee),
            Err(VoteError::InvalidSignature)
        );

        // Any field tamper changes the recomputed digest, so the (still
        // valid) signature no longer verifies over it.
        for tampered in [
            ExecAttest {
                epoch: EPOCH + 1,
                ..good.clone()
            },
            ExecAttest {
                view: VIEW + 1,
                ..good.clone()
            },
            ExecAttest {
                height: good.height + 1,
                ..good.clone()
            },
            ExecAttest {
                block_hash: Hash::from_bytes([0xA0; 32]),
                ..good.clone()
            },
            ExecAttest {
                execution_root: Hash::from_bytes([0xA1; 32]),
                ..good.clone()
            },
        ] {
            assert_eq!(
                tampered.verify(&committee),
                Err(VoteError::InvalidSignature)
            );
        }

        // Out-of-range indices fail closed as ForeignSigner (n = 6: valid
        // indices are 0..=5; u16::MAX is farthest out of range).
        for index in [6u16, 7, u16::MAX] {
            let mut foreign = good.clone();
            foreign.validator_index = index;
            assert_eq!(
                foreign.verify(&committee),
                Err(VoteError::ForeignSigner(u32::from(index)))
            );
        }
    }

    /// One `ConsensusMessage` per variant, for exhaustive tag/round-trip
    /// assertions. Keep in sync with the `msg_type` registry.
    fn all_messages() -> [ConsensusMessage; 6] {
        [
            ConsensusMessage::Propose(propose()),
            ConsensusMessage::Notarize(notarize()),
            ConsensusMessage::Nullify(nullify()),
            ConsensusMessage::Notarization(notarization()),
            ConsensusMessage::Nullification(nullification()),
            ConsensusMessage::ExecAttest(exec_attest()),
        ]
    }

    #[test]
    fn msg_type_tags_are_pinned_wire_constants() {
        // The registry values are wire-format constants — changing any of
        // them is a protocol break.
        assert_eq!(msg_type::PROPOSE, 0x0001);
        assert_eq!(msg_type::NOTARIZE, 0x0002);
        assert_eq!(msg_type::NULLIFY, 0x0003);
        assert_eq!(msg_type::NOTARIZATION, 0x0004);
        assert_eq!(msg_type::NULLIFICATION, 0x0005);
        assert_eq!(msg_type::EXEC_ATTEST, 0x0006);

        // Every variant reports its registry tag; all six tags are distinct.
        let mut seen = Vec::new();
        for msg in all_messages() {
            let tag = msg.msg_type();
            assert!(!seen.contains(&tag), "duplicate msg_type tag {tag:#06x}");
            seen.push(tag);
        }
        assert_eq!(seen, vec![0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006]);
    }

    #[test]
    fn consensus_message_round_trips_every_variant() {
        // tag -> struct -> bytes -> struct, for every variant.
        for msg in all_messages() {
            let (tag, bytes) = msg.encode().unwrap();
            assert_eq!(tag, msg.msg_type());
            let decoded = ConsensusMessage::decode(tag, &bytes).unwrap();
            assert_eq!(msg, decoded, "decode must reconstruct the exact variant");
            // The payload matches the standalone type's encoding (the enum
            // adds no framing of its own), and re-encoding is canonical.
            assert_eq!(decoded.encode().unwrap(), (tag, bytes));
        }
        let (_, propose_payload) = ConsensusMessage::Propose(propose()).encode().unwrap();
        assert_eq!(propose_payload, codec::encode(&propose()).unwrap());
    }

    #[test]
    fn unknown_msg_type_tag_is_rejected() {
        let valid_payload = codec::encode(&notarize()).unwrap();
        // 0x0000 (never assigned) and arbitrary out-of-registry tags all
        // fail closed — even over a well-formed payload. 0x0007 is the first
        // unassigned tag after ExecAttest claimed 0x0006 (#520).
        for tag in [0x0000, 0x0007, 0x00FF, u16::MAX] {
            assert_eq!(
                ConsensusMessage::decode(tag, &valid_payload),
                Err(WireError::UnknownMsgType(tag))
            );
            assert_eq!(
                ConsensusMessage::decode(tag, &[]),
                Err(WireError::UnknownMsgType(tag))
            );
        }
    }

    #[test]
    fn truncated_payload_is_an_error_never_a_panic() {
        // Every strict prefix of every valid encoding fails to decode with a
        // typed error — the dispatch is total on adversarial input.
        for msg in all_messages() {
            let (tag, bytes) = msg.encode().unwrap();
            for len in 0..bytes.len() {
                assert_eq!(
                    ConsensusMessage::decode(tag, &bytes[..len]),
                    Err(WireError::Codec(codec::CodecError::Deserialize)),
                    "truncated {tag:#06x} payload at {len}/{} must err",
                    bytes.len()
                );
            }
        }
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        // Deterministic in-test LCG (no external rng) — the same fuzz pattern
        // as `crate::tests::never_panics_on_arbitrary_bytes`, which also
        // covers these types; this local copy keeps the module self-checking.
        let mut state = 0xDEAD_BEEF_CAFE_0517_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        for _ in 0..2000 {
            let len = usize::try_from(next() % 256).unwrap();
            let mut bytes = Vec::with_capacity(len);
            while bytes.len() < len {
                bytes.extend_from_slice(&next().to_le_bytes());
            }
            bytes.truncate(len);
            // Every untrusted decode path is total: Result, never a panic.
            let _ = codec::decode::<ParentRef>(&bytes);
            let _ = codec::decode::<Propose>(&bytes);
            let _ = codec::decode::<Notarize>(&bytes);
            let _ = codec::decode::<Nullify>(&bytes);
            let _ = codec::decode::<Notarization>(&bytes);
            let _ = codec::decode::<Nullification>(&bytes);
            let _ = codec::decode::<ExecAttest>(&bytes);
            let _ = codec::decode::<Proof>(&bytes);
            // The tag-dispatch entry point (#518) shares the totality
            // guarantee across every registry tag (including 0x0006, #520)
            // and arbitrary tags.
            for tag in 0x0000..=0x0008u16 {
                let _ = ConsensusMessage::decode(tag, &bytes);
            }
            let arbitrary_tag = u16::try_from(next() & 0xFFFF).unwrap();
            let _ = ConsensusMessage::decode(arbitrary_tag, &bytes);
        }
    }
}
