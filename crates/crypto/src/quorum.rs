//! Validator sets, quorum certificates, and a deterministic threshold-signer
//! simulator (ed25519). Production HSM signers implement the same interface.

use std::collections::BTreeSet;

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};

use crate::hash::{hash_domain, DOMAIN_VALIDATOR_SET};
use crate::signature::{verify_ed25519, KeyPair};
use types::Hash;

/// Maximum number of validators in a [`ValidatorSet`].
///
/// Bound by the 16-bit `signer_bitmap` of a [`QuorumCertificate`]: bit `i`
/// names validator index `i`, so more than 16 members cannot be represented.
/// The product needs at most 16 validators; under Minimmit `n >= 5f + 1`
/// sizing this cap gives `f = 3` (`M = 7`, `L = 13`). Consensus committees
/// share this operational ceiling (see `consensus::MAX_VALIDATORS`).
pub const MAX_VALIDATORS: usize = 16;

/// Version tag of the canonical validator-set encoding used by
/// [`ValidatorSet::commitment`]. Bumping it changes every commitment, so it is
/// bound into the hashed preimage and must move whenever the encoding changes.
pub const VALIDATOR_SET_VERSION: u16 = 1;

/// A quorum / threshold verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QuorumError {
    /// A set bit refers to a validator index outside the set.
    #[error("unknown signer index")]
    UnknownSigner,
    /// The number of signatures does not match the number of set bits.
    #[error("signature count does not match signer bitmap")]
    MalformedCertificate,
    /// A member signature failed to verify.
    #[error("invalid member signature")]
    InvalidSignature,
    /// Signed weight did not reach the threshold.
    #[error("signed weight {signed} below threshold {threshold}")]
    BelowThreshold {
        /// Weight that actually signed.
        signed: u64,
        /// Required threshold.
        threshold: u64,
    },
    /// Summing validator weights overflowed `u64` (weights must use checked
    /// arithmetic; saturating sums would silently under-count the threshold).
    #[error("validator weight sum overflowed")]
    WeightOverflow,
    /// The validator set is empty or exceeds [`MAX_VALIDATORS`].
    #[error("invalid validator set")]
    InvalidSet,
    /// Two members share a public key; one signer could otherwise be counted
    /// more than once toward the threshold.
    #[error("duplicate validator public key")]
    DuplicateValidator,
    /// A member has zero voting weight, which cannot contribute to any quorum
    /// and inflates the apparent membership count.
    #[error("validator has zero weight")]
    ZeroWeight,
    /// The threshold is zero or exceeds the total weight, so it can never (or
    /// only trivially) be met.
    #[error("threshold {threshold} outside 1..={total}")]
    ThresholdOutOfRange {
        /// The rejected threshold.
        threshold: u64,
        /// Total voting weight it was checked against.
        total: u64,
    },
    /// The committee violates the Minimmit fault-model sizing: total weight
    /// `W` must satisfy `W >= 5B + 1` for Byzantine weight bound `B`, with a
    /// strict `M < L` separation between the advance and finalize thresholds.
    /// See [`require_minimmit_sizing`].
    #[error(
        "committee total weight {total_weight} is insufficient for byzantine weight \
         {byzantine_weight}: minimmit requires total >= 5*byzantine + 1 with M < L"
    )]
    InsufficientSizing {
        /// Total committee voting weight `W`.
        total_weight: u64,
        /// Byzantine weight bound `B` the committee was sized against.
        byzantine_weight: u64,
    },
}

/// A weighted validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// ed25519 public key.
    pub public_key: [u8; 32],
    /// Voting weight.
    pub weight: u64,
}

/// A validated validator set with a fixed weight threshold.
///
/// Every constructor is fallible and enforces the same canonical invariants:
/// nonempty membership no larger than [`MAX_VALIDATORS`], unique public keys,
/// strictly positive weights, an overflow-checked total, and a threshold in
/// `1..=total`. These invariants hold for the lifetime of the value, so quorum
/// verification never has to re-check them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    total_weight: u64,
    threshold: u64,
}

impl ValidatorSet {
    /// Build a BFT set with a `2f+1`-style threshold: `floor(2*total/3)+1`.
    ///
    /// # Panics
    ///
    /// Panics if the set is invalid (empty, `> MAX_VALIDATORS`, or weight
    /// overflow). Prefer [`Self::try_new_bft`] on untrusted input.
    pub fn new_bft(validators: Vec<Validator>) -> Self {
        Self::try_new_bft(validators).expect("invalid BFT validator set")
    }

    /// Fallible canonical BFT constructor.
    ///
    /// Rejects empty sets, sets larger than [`MAX_VALIDATORS`], duplicate public
    /// keys, zero-weight members, and weight sums that overflow `u64`. The
    /// threshold is the strictly-greater-than-two-thirds quorum
    /// `floor(2*total/3) + 1`, computed without the `2*total` product so debug
    /// and release builds behave identically (no overflow panic, no wraparound).
    pub fn try_new_bft(validators: Vec<Validator>) -> Result<Self, QuorumError> {
        let total = validate_membership(&validators)?;
        let threshold = bft_threshold(total);
        Ok(Self {
            validators,
            total_weight: total,
            threshold,
        })
    }

    /// Build a set with an explicit weight threshold (e.g. crash-tolerant `f+1`).
    ///
    /// # Panics
    ///
    /// Panics if the set is invalid. Prefer [`Self::try_with_threshold`].
    pub fn with_threshold(validators: Vec<Validator>, threshold: u64) -> Self {
        Self::try_with_threshold(validators, threshold).expect("invalid validator set")
    }

    /// Fallible canonical explicit-threshold constructor.
    ///
    /// Rejects empty sets, sets larger than [`MAX_VALIDATORS`], duplicate public
    /// keys, zero-weight members, weight overflow, and any threshold outside
    /// `1..=total`.
    pub fn try_with_threshold(
        validators: Vec<Validator>,
        threshold: u64,
    ) -> Result<Self, QuorumError> {
        let total = validate_membership(&validators)?;
        if threshold == 0 || threshold > total {
            return Err(QuorumError::ThresholdOutOfRange { threshold, total });
        }
        Ok(Self {
            validators,
            total_weight: total,
            threshold,
        })
    }

    /// Total voting weight.
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Required threshold weight.
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// The validators in this set, in their canonical membership order (bit `i`
    /// of a [`QuorumCertificate`] signer bitmap names `validators()[i]`).
    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Verify a quorum certificate over its message. Rejects unknown signers,
    /// malformed certificates, bad signatures, and below-threshold weight.
    pub fn verify(&self, qc: &QuorumCertificate) -> Result<(), QuorumError> {
        let set_bits = qc.signer_bitmap.count_ones() as usize;
        if set_bits != qc.signatures.len() {
            return Err(QuorumError::MalformedCertificate);
        }
        let mut signed_weight: u64 = 0;
        let mut sig_index = 0usize;
        for bit in 0..u16::BITS {
            if qc.signer_bitmap & (1u16 << bit) == 0 {
                continue;
            }
            let validator = self
                .validators
                .get(bit as usize)
                .ok_or(QuorumError::UnknownSigner)?;
            let signature = &qc.signatures[sig_index];
            sig_index += 1;
            verify_ed25519(&validator.public_key, qc.message.as_bytes(), signature)
                .map_err(|_| QuorumError::InvalidSignature)?;
            signed_weight = signed_weight
                .checked_add(validator.weight)
                .ok_or(QuorumError::WeightOverflow)?;
        }
        if signed_weight < self.threshold {
            return Err(QuorumError::BelowThreshold {
                signed: signed_weight,
                threshold: self.threshold,
            });
        }
        Ok(())
    }

    /// A canonical, versioned commitment to this set's membership and threshold.
    ///
    /// The preimage is domain-separated ([`DOMAIN_VALIDATOR_SET`]), carries
    /// [`VALIDATOR_SET_VERSION`], and lists members sorted by public key. Because
    /// members are canonically ordered and duplicates are rejected at
    /// construction, two sets built from the same members in any input order
    /// commit to the same hash, while any change to a key, weight, threshold, or
    /// membership changes it.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut ordered: Vec<&Validator> = self.validators.iter().collect();
        ordered.sort_unstable_by_key(|a| a.public_key);

        let mut buf = Vec::with_capacity(2 + 8 + 8 + 4 + ordered.len() * (32 + 8));
        buf.extend_from_slice(&VALIDATOR_SET_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.threshold.to_le_bytes());
        buf.extend_from_slice(&self.total_weight.to_le_bytes());
        // Length-prefix the membership so it can never be confused with a
        // different set whose trailing bytes happen to align.
        let count = u32::try_from(ordered.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&count.to_le_bytes());
        for v in ordered {
            buf.extend_from_slice(&v.public_key);
            buf.extend_from_slice(&v.weight.to_le_bytes());
        }
        hash_domain(DOMAIN_VALIDATOR_SET, &buf)
    }
}

/// The strictly-greater-than-two-thirds BFT quorum `floor(2*total/3) + 1`.
///
/// Computed without forming the `2 * total` product (which overflows `u64` for
/// `total > u64::MAX / 2`): with `total = 3*q + r` and `r in {0,1,2}`,
/// `floor(2*total/3) = 2*q + floor(2*r/3)`. Every intermediate fits in `u64`
/// (`2*q <= 2*(u64::MAX/3) < u64::MAX`), so the result is identical in debug and
/// release and never panics. For any `total >= 1` the result lies in `1..=total`
/// and satisfies `3 * threshold > 2 * total`.
const fn bft_threshold(total: u64) -> u64 {
    let q = total / 3;
    let r = total % 3;
    // `2*q` and the `<= 1` correction cannot overflow; see the doc comment.
    2 * q + (2 * r) / 3 + 1
}

/// The Minimmit dual thresholds `(M, L)` for a committee of total voting
/// weight `W = total_weight` tolerating at most `B = byzantine_weight` of
/// Byzantine weight:
///
/// - `M = 2B + 1` — the **advance** threshold: assembling an M-certificate
///   (notarization or nullification) advances the view.
/// - `L = W − B` — the **finalize** threshold: an L-notarization finalizes
///   the block and its ancestors.
///
/// Purely additive alongside the HotStuff-style `floor(2W/3)+1` quorum math;
/// existing callers of that helper are untouched.
///
/// All arithmetic is checked, so debug and release builds behave identically
/// (no overflow panic, no wraparound).
///
/// # Errors
///
/// - [`QuorumError::ThresholdOutOfRange`] if `B >= W`: the finalize threshold
///   `L = W − B` would fall outside the `1..=W` range accepted by
///   [`ValidatorSet::try_with_threshold`].
/// - [`QuorumError::WeightOverflow`] if `2B + 1` overflows `u64`.
///
/// # Range invariant (documented; hard sizing rejection is separate)
///
/// Whenever the Minimmit sizing requirement `W >= 5B + 1` holds, both
/// thresholds land inside [`ValidatorSet::try_with_threshold`]'s accepted
/// `1..=W` range: `1 <= M = 2B+1 <= W` (since `W >= 5B+1 >= 2B+1`) and
/// `1 <= L = W−B <= W` (since `B < W`). More generally `M <= L` holds exactly
/// when `W >= 3B + 1`. This helper does **not** reject undersized committees
/// (`W < 5B + 1`); that is the sizing guard's job.
pub fn minimmit_thresholds(
    total_weight: u64,
    byzantine_weight: u64,
) -> Result<(u64, u64), QuorumError> {
    // `B >= W` would push `L = W - B` outside `try_with_threshold`'s `1..=W`.
    if byzantine_weight >= total_weight {
        return Err(QuorumError::ThresholdOutOfRange {
            threshold: total_weight.saturating_sub(byzantine_weight),
            total: total_weight,
        });
    }
    let advance = byzantine_weight
        .checked_mul(2)
        .and_then(|doubled| doubled.checked_add(1))
        .ok_or(QuorumError::WeightOverflow)?;
    // Cannot underflow: `byzantine_weight < total_weight` was checked above.
    let finalize = total_weight - byzantine_weight;
    Ok((advance, finalize))
}

/// Reject committees that violate the Minimmit fault-model sizing.
///
/// Fail-closed gate for committee construction and config loading: a
/// committee of total voting weight `W = total_weight` sized against a
/// Byzantine weight bound `B = byzantine_weight` is accepted only when
///
/// - **`W >= 5B + 1`** (checked arithmetic; an overflowing `5B + 1` can never
///   be met by any `u64` weight, so it is rejected as insufficient), and
/// - **`M < L`** — strict separation between the advance threshold
///   `M = 2B + 1` and the finalize threshold `L = W - B` from
///   [`minimmit_thresholds`]. `M >= L` (i.e. `W <= 3B + 1`) collapses the
///   two-threshold design into a single-threshold protocol; the strict check
///   also rejects the degenerate `W = 1, B = 0` committee where `M == L == 1`.
///
/// Without this gate, [`ValidatorSet::try_with_threshold`] (which only bounds
/// a threshold to `1..=total`) silently accepts fault-model-violating
/// committees — e.g. an undersized `validators.toml` degrading to `f = 0`.
///
/// This guard owns the **lower** bound only. The upper bound on membership
/// (the [`MAX_VALIDATORS`] cap; e.g. `n = 17` unit-weight members rejected at
/// a 16-validator cap) is enforced by membership validation at set
/// construction, not here — this function sees weights, not member counts.
///
/// For unit-weight committees, derive `B` with
/// [`minimmit_unit_byzantine_bound`].
///
/// # Errors
///
/// [`QuorumError::InsufficientSizing`] naming the offending
/// `(total_weight, byzantine_weight)` pair when either condition fails.
pub fn require_minimmit_sizing(
    total_weight: u64,
    byzantine_weight: u64,
) -> Result<(), QuorumError> {
    let insufficient = QuorumError::InsufficientSizing {
        total_weight,
        byzantine_weight,
    };
    // W >= 5B + 1, checked: if 5B + 1 overflows u64 it exceeds any possible
    // W, so the committee is definitionally undersized (fail closed).
    match byzantine_weight
        .checked_mul(5)
        .and_then(|five_b| five_b.checked_add(1))
    {
        Some(min_weight) if total_weight >= min_weight => {}
        _ => return Err(insufficient),
    }
    // Strict M < L separation. `W >= 5B + 1` already guarantees `B < W` and a
    // non-overflowing `2B + 1`, so `minimmit_thresholds` cannot fail here;
    // propagate defensively rather than unwrap.
    let (advance, finalize) = minimmit_thresholds(total_weight, byzantine_weight)?;
    if advance >= finalize {
        return Err(insufficient);
    }
    Ok(())
}

/// The largest Byzantine bound a **unit-weight** committee of `n` members can
/// tolerate under Minimmit sizing: `f = floor((n - 1) / 5)`, the greatest `f`
/// with `n >= 5f + 1`.
///
/// Convenience for the common unit-weight path (`W = n`, `B = f`); weighted
/// committees must pass their explicit Byzantine weight bound to
/// [`require_minimmit_sizing`] instead. `n = 0` saturates to `f = 0` (and no
/// `n = 0` committee passes the sizing guard regardless). Note the derived
/// bound is the committee's *capacity*: an operator-intended `f` larger than
/// this value fails [`require_minimmit_sizing`].
#[must_use]
pub const fn minimmit_unit_byzantine_bound(n: u64) -> u64 {
    n.saturating_sub(1) / 5
}

/// Validate canonical membership and return the overflow-checked total weight.
///
/// Enforces nonempty membership no larger than [`MAX_VALIDATORS`], unique public
/// keys, strictly positive weights, and a `u64`-checked weight sum.
fn validate_membership(validators: &[Validator]) -> Result<u64, QuorumError> {
    if validators.is_empty() || validators.len() > MAX_VALIDATORS {
        return Err(QuorumError::InvalidSet);
    }
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut total: u64 = 0;
    for v in validators {
        if v.weight == 0 {
            return Err(QuorumError::ZeroWeight);
        }
        if !seen.insert(v.public_key) {
            return Err(QuorumError::DuplicateValidator);
        }
        total = total
            .checked_add(v.weight)
            .ok_or(QuorumError::WeightOverflow)?;
    }
    Ok(total)
}

/// Wire layout version for the compact QC packing
/// (`message[32] || bitmap_le[2] || signatures[64 * popcount]`).
///
/// v2 shrank the signer bitmap from 8 little-endian bytes (`u64`) to 2
/// (`u16`) alongside the [`MAX_VALIDATORS`] 64 -> 16 cap. The break is
/// one-way: v1 packings are rejected by [`QuorumCertificate::decode_packed`]
/// (the header no longer lines up), with no migration path — a hard fork.
pub const QC_WIRE_VERSION: u16 = 2;

/// Fixed header size of a packed QC: 32-byte message + 2-byte little-endian bitmap.
pub const QC_PACKED_HEADER_LEN: usize = 32 + 2;

/// Fixed-capacity canonical signatures for a committee of at most 16 members.
///
/// Inline storage removes the owned-QC heap allocation while retaining slice
/// indexing, iteration, and deterministic ascending signer order.
pub type QuorumSignatures = ArrayVec<[u8; 64], MAX_VALIDATORS>;

/// A quorum certificate: signatures over `message` from the validators named in
/// `signer_bitmap` (bit `i` == validator `i`), in ascending index order.
///
/// # Canonical wire packing
///
/// [`Self::encode_packed`] / [`Self::decode_packed`] use a single allocation
/// (encode) and no per-signature heap allocation (decode):
///
/// ```text
/// message[32] || signer_bitmap_le[2] || sig_0[64] || … || sig_{k-1}[64]
/// ```
///
/// where `k = popcount(signer_bitmap)` and signatures are in ascending set-bit
/// order. Count is always derived from the bitmap; a mismatched signature count
/// is rejected before any large allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// The message that was signed (typically a checkpoint or block hash).
    pub message: Hash,
    /// Bitmap of participating validator indices (bit `i` names validator
    /// index `i`; 16 bits cap membership at [`MAX_VALIDATORS`]).
    pub signer_bitmap: u16,
    /// Member signatures, aligned to the set bits in ascending order.
    #[serde(with = "sig_vec")]
    pub signatures: QuorumSignatures,
}

impl QuorumCertificate {
    /// Number of set bits (expected signature count).
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_bitmap.count_ones() as usize
    }

    /// Encode into the canonical packed form. Allocates once.
    #[must_use]
    pub fn encode_packed(&self) -> Vec<u8> {
        let k = self.signatures.len();
        let mut out = Vec::with_capacity(QC_PACKED_HEADER_LEN + k * 64);
        out.extend_from_slice(self.message.as_bytes());
        out.extend_from_slice(&self.signer_bitmap.to_le_bytes());
        for sig in &self.signatures {
            out.extend_from_slice(sig);
        }
        out
    }

    /// Decode a packed QC. Rejects length mismatches **before** allocating a
    /// signature vector larger than the input can justify.
    pub fn decode_packed(bytes: &[u8]) -> Result<Self, QuorumError> {
        if bytes.len() < QC_PACKED_HEADER_LEN {
            return Err(QuorumError::MalformedCertificate);
        }
        let mut msg = [0u8; 32];
        msg.copy_from_slice(&bytes[..32]);
        let mut bm = [0u8; 2];
        bm.copy_from_slice(&bytes[32..34]);
        let signer_bitmap = u16::from_le_bytes(bm);
        let k = signer_bitmap.count_ones() as usize;
        let expected = QC_PACKED_HEADER_LEN.saturating_add(k.saturating_mul(64));
        // Fail closed on malicious lengths before allocation.
        if bytes.len() != expected || k > MAX_VALIDATORS {
            return Err(QuorumError::MalformedCertificate);
        }
        let mut signatures = QuorumSignatures::new();
        let mut off = QC_PACKED_HEADER_LEN;
        for _ in 0..k {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes[off..off + 64]);
            signatures
                .try_push(sig)
                .map_err(|_| QuorumError::MalformedCertificate)?;
            off += 64;
        }
        Ok(Self {
            message: Hash::from_bytes(msg),
            signer_bitmap,
            signatures,
        })
    }
}

/// Serde adapter for inline 64-byte signatures (serde has no built-in impl past 32 bytes).
///
/// Encode writes each signature as a fixed 64-byte byte string without building
/// an intermediate `Vec<&[u8]>`. Decode validates each element is exactly 64
/// bytes and rejects oversized sequences before filling the output.
mod sig_vec {
    use super::QuorumSignatures;
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::fmt;

    pub(super) fn serialize<S: Serializer>(v: &QuorumSignatures, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for sig in v {
            // Serialize as a byte slice so postcard / bincode pack densely.
            seq.serialize_element(sig.as_slice())?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<QuorumSignatures, D::Error> {
        struct SigVisitor;
        impl<'de> Visitor<'de> for SigVisitor {
            type Value = QuorumSignatures;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a sequence of 64-byte signatures")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = QuorumSignatures::new();
                while let Some(v) = seq.next_element::<SigBytes>()? {
                    out.try_push(v.0)
                        .map_err(|_| serde::de::Error::custom("too many signatures"))?;
                }
                Ok(out)
            }
        }
        // Local newtype so we can accept a 64-byte byte buffer.
        struct SigBytes([u8; 64]);
        impl<'de> Deserialize<'de> for SigBytes {
            fn deserialize<D2: Deserializer<'de>>(d: D2) -> Result<Self, D2::Error> {
                struct BytesVisitor;
                impl<'de> Visitor<'de> for BytesVisitor {
                    type Value = SigBytes;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("exactly 64 signature bytes")
                    }

                    fn visit_seq<A: SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> Result<Self::Value, A::Error> {
                        let mut bytes = [0u8; 64];
                        for byte in &mut bytes {
                            *byte = seq.next_element()?.ok_or_else(|| {
                                serde::de::Error::custom("signature must be 64 bytes")
                            })?;
                        }
                        if seq.next_element::<u8>()?.is_some() {
                            return Err(serde::de::Error::custom("signature must be 64 bytes"));
                        }
                        Ok(SigBytes(bytes))
                    }
                }
                d.deserialize_seq(BytesVisitor)
            }
        }
        d.deserialize_seq(SigVisitor)
    }
}

/// A deterministic k-of-n threshold signer simulator (software; the production
/// signer interface is separate). Each signer is an ed25519 keypair.
#[derive(Debug, Clone)]
pub struct ThresholdSigners {
    signers: Vec<KeyPair>,
    threshold: u64,
}

impl ThresholdSigners {
    /// Build `n` deterministic signers from seeds, with threshold `k`.
    pub fn from_seeds(seeds: &[[u8; 32]], k: u64) -> Self {
        Self {
            signers: seeds.iter().map(KeyPair::from_seed).collect(),
            threshold: k,
        }
    }

    /// The validator set (unit weight each) with the instance threshold `k`.
    pub fn validator_set(&self) -> ValidatorSet {
        self.validator_set_with_threshold(self.threshold)
    }

    /// The same membership (unit weight each) at an explicit threshold `k`,
    /// independent of the instance threshold.
    ///
    /// This is the dual-threshold seam for Minimmit tests: one signer set
    /// yields both the advance set (`M = 2B + 1`) and the finalize set
    /// (`L = W − B`) from [`minimmit_thresholds`], so a single certificate
    /// can be checked at both bars. Both sets share the same canonical
    /// membership order (signer bitmaps line up), so a certificate assembled
    /// from any `L`-weight subset also verifies at `M`.
    ///
    /// # Panics
    ///
    /// Panics if `k` lies outside `1..=n` for the `n` unit-weight signers
    /// (the [`ValidatorSet::with_threshold`] contract).
    #[must_use]
    pub fn validator_set_with_threshold(&self, k: u64) -> ValidatorSet {
        let validators = self
            .signers
            .iter()
            .map(|kp| Validator {
                public_key: kp.public(),
                weight: 1,
            })
            .collect();
        ValidatorSet::with_threshold(validators, k)
    }

    /// Produce a certificate over `message` from the given signer indices
    /// (deduplicated and applied in ascending order).
    pub fn sign(&self, message: Hash, mut indices: Vec<usize>) -> QuorumCertificate {
        indices.sort_unstable();
        indices.dedup();
        let mut bitmap = 0u16;
        let mut signatures = QuorumSignatures::new();
        for &i in &indices {
            if i >= self.signers.len() || i >= MAX_VALIDATORS {
                continue;
            }
            bitmap |= 1u16 << i;
            let _ = signatures.try_push(self.signers[i].sign(message.as_bytes()));
        }
        QuorumCertificate {
            message,
            signer_bitmap: bitmap,
            signatures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signers(n: usize, k: u64) -> ThresholdSigners {
        let seeds: Vec<[u8; 32]> = (0..n).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        ThresholdSigners::from_seeds(&seeds, k)
    }

    #[test]
    fn quorum_verifies_iff_threshold_met() {
        let ts = signers(4, 3); // 3-of-4
        let set = ts.validator_set();
        let msg = Hash::from_bytes([42u8; 32]);

        // 3 signers -> verifies.
        let qc = ts.sign(msg, vec![0, 1, 2]);
        assert!(set.verify(&qc).is_ok());

        // 2 signers -> below threshold.
        let qc2 = ts.sign(msg, vec![0, 1]);
        assert!(matches!(
            set.verify(&qc2),
            Err(QuorumError::BelowThreshold { .. })
        ));
    }

    #[test]
    fn rejects_malformed_and_unknown_and_tampered() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let msg = Hash::from_bytes([1u8; 32]);

        // Signature count mismatch.
        let mut qc = ts.sign(msg, vec![0, 1, 2]);
        qc.signatures.pop();
        assert_eq!(set.verify(&qc), Err(QuorumError::MalformedCertificate));

        // Unknown signer bit (index 10 in a 4-validator set).
        let mut qc = ts.sign(msg, vec![0, 1, 2]);
        qc.signer_bitmap |= 1 << 10;
        qc.signatures.push([0u8; 64]);
        assert_eq!(set.verify(&qc), Err(QuorumError::UnknownSigner));

        // Tampered message vs signatures.
        let mut qc = ts.sign(msg, vec![0, 1, 2]);
        qc.message = Hash::from_bytes([2u8; 32]);
        assert_eq!(set.verify(&qc), Err(QuorumError::InvalidSignature));
    }

    #[test]
    fn any_k_of_n_subset_reconstructs() {
        let ts = signers(5, 3);
        let set = ts.validator_set();
        let msg = Hash::from_bytes([7u8; 32]);
        for subset in [vec![0, 1, 2], vec![2, 3, 4], vec![0, 2, 4], vec![1, 3, 4]] {
            assert!(set.verify(&ts.sign(msg, subset)).is_ok());
        }
        // Fewer than k fails.
        assert!(set.verify(&ts.sign(msg, vec![0, 4])).is_err());
    }

    #[test]
    fn try_new_bft_rejects_empty_oversized_and_weight_overflow() {
        assert_eq!(
            ValidatorSet::try_new_bft(vec![]),
            Err(QuorumError::InvalidSet)
        );
        let too_many: Vec<Validator> = (0..=MAX_VALIDATORS)
            .map(|i| Validator {
                public_key: [u8::try_from(i.min(255)).unwrap_or(0); 32],
                weight: 1,
            })
            .collect();
        assert_eq!(
            ValidatorSet::try_new_bft(too_many),
            Err(QuorumError::InvalidSet)
        );
        let overflow = vec![
            Validator {
                public_key: [1u8; 32],
                weight: u64::MAX,
            },
            Validator {
                public_key: [2u8; 32],
                weight: 1,
            },
        ];
        assert_eq!(
            ValidatorSet::try_new_bft(overflow),
            Err(QuorumError::WeightOverflow)
        );
    }

    #[test]
    fn try_with_threshold_rejects_zero_and_over_total() {
        let v = vec![
            Validator {
                public_key: [1u8; 32],
                weight: 2,
            },
            Validator {
                public_key: [2u8; 32],
                weight: 3,
            },
        ];
        // total == 5.
        assert_eq!(
            ValidatorSet::try_with_threshold(v.clone(), 0),
            Err(QuorumError::ThresholdOutOfRange {
                threshold: 0,
                total: 5
            })
        );
        assert_eq!(
            ValidatorSet::try_with_threshold(v.clone(), 6),
            Err(QuorumError::ThresholdOutOfRange {
                threshold: 6,
                total: 5
            })
        );
        // Boundaries 1 and total both accepted.
        assert!(ValidatorSet::try_with_threshold(v.clone(), 1).is_ok());
        assert!(ValidatorSet::try_with_threshold(v, 5).is_ok());
    }

    #[test]
    fn rejects_duplicate_keys_and_zero_weights() {
        let dup = vec![
            Validator {
                public_key: [7u8; 32],
                weight: 1,
            },
            Validator {
                public_key: [7u8; 32],
                weight: 1,
            },
        ];
        assert_eq!(
            ValidatorSet::try_new_bft(dup.clone()),
            Err(QuorumError::DuplicateValidator)
        );
        assert_eq!(
            ValidatorSet::try_with_threshold(dup, 1),
            Err(QuorumError::DuplicateValidator)
        );

        let zero = vec![
            Validator {
                public_key: [1u8; 32],
                weight: 1,
            },
            Validator {
                public_key: [2u8; 32],
                weight: 0,
            },
        ];
        assert_eq!(
            ValidatorSet::try_new_bft(zero.clone()),
            Err(QuorumError::ZeroWeight)
        );
        assert_eq!(
            ValidatorSet::try_with_threshold(zero, 1),
            Err(QuorumError::ZeroWeight)
        );
    }

    /// `floor(2*total/3) + 1` reference over `u128`, immune to `u64` overflow.
    fn bft_threshold_reference(total: u64) -> u64 {
        let t = u128::from(total);
        u64::try_from((2 * t) / 3 + 1).expect("BFT threshold always fits in u64")
    }

    #[test]
    fn bft_threshold_matches_reference_and_is_overflow_safe() {
        // A deterministic splitmix64 walk plus exact overflow boundaries. Every
        // sample must reproduce the u128 reference and never panic.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut totals: Vec<u64> = vec![
            1,
            2,
            3,
            4,
            5,
            6,
            u64::MAX,
            u64::MAX - 1,
            u64::MAX - 2,
            u64::MAX / 2,
            u64::MAX / 2 + 1,
            u64::MAX / 3,
            u64::MAX / 3 + 1,
            (u64::MAX / 3) * 3,
        ];
        for _ in 0..20_000 {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            totals.push((z ^ (z >> 31)).max(1));
        }
        for total in totals {
            assert_eq!(
                bft_threshold(total),
                bft_threshold_reference(total),
                "threshold mismatch for total {total}"
            );
        }
    }

    #[test]
    fn bft_threshold_strictly_exceeds_two_thirds() {
        // Property: for every valid total, 3*threshold > 2*total (strict), and
        // threshold stays within 1..=total. Checked over u128 so the comparison
        // itself cannot overflow.
        let mut state: u64 = 0x0123_4567_89AB_CDEF;
        let mut totals: Vec<u64> = vec![1, 2, 3, 4, 5, u64::MAX, u64::MAX - 1, u64::MAX / 3];
        for _ in 0..50_000 {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            totals.push((z ^ (z >> 31)).max(1));
        }
        for total in totals {
            let threshold = bft_threshold(total);
            assert!(threshold >= 1, "threshold underflow for total {total}");
            assert!(threshold <= total, "threshold exceeds total {total}");
            assert!(
                3 * u128::from(threshold) > 2 * u128::from(total),
                "threshold not strictly above two-thirds for total {total}"
            );
            // One short of the threshold must be at or below two-thirds.
            assert!(
                3 * u128::from(threshold - 1) <= 2 * u128::from(total),
                "threshold not minimal for total {total}"
            );
        }
    }

    /// Deterministic splitmix64 step, same generator as the `bft_threshold`
    /// walks above.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[test]
    fn minimmit_thresholds_returns_advance_and_finalize() {
        // Unit-weight committee at the tight n = 5f+1 sizing.
        assert_eq!(minimmit_thresholds(6, 1), Ok((3, 5)));
        // The 16-validator envelope: f = 3 => M = 7, L = 13.
        assert_eq!(minimmit_thresholds(16, 3), Ok((7, 13)));
        // Degenerate f = 0 committee: M = 1, L = W.
        assert_eq!(minimmit_thresholds(1, 0), Ok((1, 1)));
        assert_eq!(minimmit_thresholds(9, 0), Ok((1, 9)));
        // Weighted: W = 101, B = 20 => M = 41, L = 81.
        assert_eq!(minimmit_thresholds(101, 20), Ok((41, 81)));
    }

    #[test]
    fn minimmit_thresholds_rejects_byzantine_at_or_above_total_and_overflow() {
        // B == W: L would be 0, outside 1..=W.
        assert_eq!(
            minimmit_thresholds(5, 5),
            Err(QuorumError::ThresholdOutOfRange {
                threshold: 0,
                total: 5
            })
        );
        // B > W.
        assert_eq!(
            minimmit_thresholds(5, 9),
            Err(QuorumError::ThresholdOutOfRange {
                threshold: 0,
                total: 5
            })
        );
        // W == 0 rejects every B (never panics).
        assert_eq!(
            minimmit_thresholds(0, 0),
            Err(QuorumError::ThresholdOutOfRange {
                threshold: 0,
                total: 0
            })
        );
        // 2B + 1 overflows u64 (B > u64::MAX / 2) while B < W.
        assert_eq!(
            minimmit_thresholds(u64::MAX, u64::MAX / 2 + 1),
            Err(QuorumError::WeightOverflow)
        );
        // Largest non-overflowing B: 2B + 1 == u64::MAX exactly.
        assert_eq!(
            minimmit_thresholds(u64::MAX, u64::MAX / 2),
            Ok((u64::MAX, u64::MAX - u64::MAX / 2))
        );
    }

    #[test]
    fn minimmit_thresholds_land_in_try_with_threshold_range_when_sized() {
        // For W >= 5B + 1, both M and L must be accepted by
        // try_with_threshold(members, _) — i.e. they lie in 1..=W.
        let mut state: u64 = 0x5EED_5EED_5EED_5EED;
        let mut cases: Vec<(u64, u64)> = vec![
            (6, 1),                                             // tight unit committee
            (16, 3),                                            // 16-validator envelope
            (1, 0),                                             // degenerate f = 0
            (u64::MAX, (u64::MAX - 1) / 5),                     // near the u64 boundary
            (5 * ((u64::MAX - 1) / 5) + 1, (u64::MAX - 1) / 5), // exact 5B+1
        ];
        for _ in 0..2_000 {
            let b = splitmix64(&mut state) % 1_000_000;
            let extra = splitmix64(&mut state) % 1_000_000;
            let w = 5 * b + 1 + extra;
            cases.push((w, b));
        }
        for (w, b) in cases {
            // `W >= 5B + 1` over integers, written strictly for clippy.
            assert!(
                u128::from(w) > 5 * u128::from(b),
                "test-case generator violated W >= 5B+1 for ({w}, {b})"
            );
            let (m, l) = minimmit_thresholds(w, b)
                .unwrap_or_else(|e| panic!("thresholds failed for ({w}, {b}): {e}"));
            // A single member carrying the full weight W keeps membership
            // valid for any W >= 1.
            let members = vec![Validator {
                public_key: [1u8; 32],
                weight: w,
            }];
            assert!(
                ValidatorSet::try_with_threshold(members.clone(), m).is_ok(),
                "advance threshold M={m} rejected for (W={w}, B={b})"
            );
            assert!(
                ValidatorSet::try_with_threshold(members, l).is_ok(),
                "finalize threshold L={l} rejected for (W={w}, B={b})"
            );
            // The two-threshold separation at the heart of Minimmit.
            assert!(m <= l, "M={m} > L={l} despite W >= 5B+1 (W={w}, B={b})");
        }
    }

    #[test]
    fn minimmit_advance_at_most_finalize_iff_three_b_plus_one() {
        // Property: M <= L holds exactly when W >= 3B + 1, checked over a
        // deterministic splitmix64 walk (comparisons in u128 so the oracle
        // itself cannot overflow).
        let mut state: u64 = 0xDEC0_5DEC_05DE_C05D;
        let mut cases: Vec<(u64, u64)> = vec![
            (4, 1),                   // W == 3B + 1 exactly: M == L
            (3, 1),                   // W == 3B: M > L
            (7, 2),                   // W == 3B + 1: M == L == 5
            (6, 2),                   // just below: M = 5 > L = 4
            (2, 1),                   // minimal M > L case
            (u64::MAX, u64::MAX / 2), // huge non-overflowing B
        ];
        for _ in 0..20_000 {
            let w = splitmix64(&mut state).max(2);
            let b = splitmix64(&mut state) % w; // B < W always
            cases.push((w, b));
        }
        for (w, b) in cases {
            match minimmit_thresholds(w, b) {
                Ok((m, l)) => {
                    assert_eq!(u128::from(m), 2 * u128::from(b) + 1);
                    assert_eq!(l, w - b);
                    // `W >= 3B + 1` over integers, written strictly for clippy.
                    assert_eq!(
                        m <= l,
                        u128::from(w) > 3 * u128::from(b),
                        "M <= L must hold iff W >= 3B+1 (W={w}, B={b}, M={m}, L={l})"
                    );
                }
                Err(QuorumError::WeightOverflow) => {
                    // Only legitimate when 2B + 1 really exceeds u64.
                    assert!(
                        2 * u128::from(b) + 1 > u128::from(u64::MAX),
                        "spurious overflow for (W={w}, B={b})"
                    );
                }
                Err(e) => panic!("unexpected error for (W={w}, B={b}): {e}"),
            }
        }
    }

    #[test]
    fn require_minimmit_sizing_rejects_undersized_and_accepts_5f_plus_1() {
        // f = 1 needs n >= 6: n = 3, 4, 5 rejected, n = 6 accepted.
        for n in [3u64, 4, 5] {
            assert_eq!(
                require_minimmit_sizing(n, 1),
                Err(QuorumError::InsufficientSizing {
                    total_weight: n,
                    byzantine_weight: 1
                }),
                "n={n} at f=1 must be rejected"
            );
        }
        assert_eq!(require_minimmit_sizing(6, 1), Ok(()));

        // The 16-validator envelope: f = 3 at n = 16 accepted (5*3+1 = 16);
        // f = 4 at n = 16 rejected (needs n >= 21). The n = 17 upper bound is
        // the MAX_VALIDATORS cap's job, not this guard's.
        assert_eq!(require_minimmit_sizing(16, 3), Ok(()));
        assert_eq!(
            require_minimmit_sizing(16, 4),
            Err(QuorumError::InsufficientSizing {
                total_weight: 16,
                byzantine_weight: 4
            })
        );
        assert_eq!(require_minimmit_sizing(21, 4), Ok(()));

        // Weighted: W = 101, B = 20 (5*20+1 = 101) accepted; B = 21 rejected.
        assert_eq!(require_minimmit_sizing(101, 20), Ok(()));
        assert_eq!(
            require_minimmit_sizing(101, 21),
            Err(QuorumError::InsufficientSizing {
                total_weight: 101,
                byzantine_weight: 21
            })
        );
    }

    #[test]
    fn require_minimmit_sizing_rejects_threshold_collapse_and_degenerates() {
        // M >= L (W <= 3B + 1) collapses the two-threshold design. All such
        // committees also violate W >= 5B+1 for B >= 1 and must be rejected
        // with the sizing error, never a stray threshold error.
        for (w, b) in [(3u64, 1u64), (4, 1), (7, 2), (2, 1), (1, 1), (5, 9)] {
            assert_eq!(
                require_minimmit_sizing(w, b),
                Err(QuorumError::InsufficientSizing {
                    total_weight: w,
                    byzantine_weight: b
                }),
                "(W={w}, B={b}) must be rejected"
            );
        }
        // Degenerate W = 1, B = 0: passes 5B+1 but M == L == 1 — strict
        // separation rejects it.
        assert_eq!(
            require_minimmit_sizing(1, 0),
            Err(QuorumError::InsufficientSizing {
                total_weight: 1,
                byzantine_weight: 0
            })
        );
        // W = 0 has no committee at all.
        assert_eq!(
            require_minimmit_sizing(0, 0),
            Err(QuorumError::InsufficientSizing {
                total_weight: 0,
                byzantine_weight: 0
            })
        );
        // 5B + 1 overflows u64: no u64 weight can satisfy it (fail closed,
        // never panics).
        assert_eq!(
            require_minimmit_sizing(u64::MAX, u64::MAX / 5 + 1),
            Err(QuorumError::InsufficientSizing {
                total_weight: u64::MAX,
                byzantine_weight: u64::MAX / 5 + 1
            })
        );
        // Largest non-overflowing B at W = u64::MAX still sizes correctly:
        // 5 * floor((u64::MAX - 1) / 5) + 1 <= u64::MAX.
        assert_eq!(
            require_minimmit_sizing(u64::MAX, (u64::MAX - 1) / 5),
            Ok(())
        );
    }

    #[test]
    fn require_minimmit_sizing_matches_u128_oracle() {
        // Property: accepted iff W >= 5B + 1 AND M < L, over a deterministic
        // splitmix64 walk with the comparison done in u128 (overflow-immune).
        let mut state: u64 = 0x51D0_51D0_51D0_51D0;
        let mut cases: Vec<(u64, u64)> = vec![
            (6, 1),
            (5, 1),
            (16, 3),
            (16, 4),
            (1, 0),
            (2, 0),
            (0, 0),
            (u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX / 5),
            (u64::MAX, u64::MAX / 5 + 1),
        ];
        for _ in 0..20_000 {
            let w = splitmix64(&mut state);
            // Mix small and huge B so both rejection paths are exercised.
            let b = match splitmix64(&mut state) % 3 {
                0 => splitmix64(&mut state) % 8,
                1 => splitmix64(&mut state) % (w / 4).max(1),
                _ => splitmix64(&mut state),
            };
            cases.push((w, b));
        }
        for (w, b) in cases {
            let w128 = u128::from(w);
            let b128 = u128::from(b);
            // `W >= 5B + 1` over integers, written strictly for clippy.
            let sized = w128 > 5 * b128;
            let separated = 2 * b128 + 1 < w128 - b128.min(w128);
            let expect_ok = sized && separated;
            let got = require_minimmit_sizing(w, b);
            assert_eq!(
                got.is_ok(),
                expect_ok,
                "oracle mismatch for (W={w}, B={b}): got {got:?}"
            );
            if let Err(e) = got {
                assert_eq!(
                    e,
                    QuorumError::InsufficientSizing {
                        total_weight: w,
                        byzantine_weight: b
                    }
                );
            } else {
                // Accepted committees always yield usable, separated
                // thresholds.
                let (m, l) = minimmit_thresholds(w, b).expect("accepted committee must threshold");
                assert!(m < l, "accepted (W={w}, B={b}) must have M={m} < L={l}");
            }
        }
    }

    #[test]
    fn unit_byzantine_bound_derives_floor_n_minus_1_over_5() {
        assert_eq!(minimmit_unit_byzantine_bound(0), 0);
        assert_eq!(minimmit_unit_byzantine_bound(1), 0);
        assert_eq!(minimmit_unit_byzantine_bound(5), 0);
        assert_eq!(minimmit_unit_byzantine_bound(6), 1);
        assert_eq!(minimmit_unit_byzantine_bound(10), 1);
        assert_eq!(minimmit_unit_byzantine_bound(11), 2);
        assert_eq!(minimmit_unit_byzantine_bound(16), 3);
        assert_eq!(minimmit_unit_byzantine_bound(20), 3);
        assert_eq!(minimmit_unit_byzantine_bound(21), 4);
        assert_eq!(minimmit_unit_byzantine_bound(64), 12);
        assert_eq!(minimmit_unit_byzantine_bound(u64::MAX), (u64::MAX - 1) / 5);

        // The derived bound always satisfies the guard for n >= 2 (n = 1 is
        // the degenerate M == L committee, n = 0 is empty), and intending one
        // more Byzantine member than the capacity always fails.
        for n in 2u64..=64 {
            let f = minimmit_unit_byzantine_bound(n);
            assert_eq!(
                require_minimmit_sizing(n, f),
                Ok(()),
                "derived f={f} must satisfy sizing at n={n}"
            );
            assert_eq!(
                require_minimmit_sizing(n, f + 1),
                Err(QuorumError::InsufficientSizing {
                    total_weight: n,
                    byzantine_weight: f + 1
                }),
                "f={} must exceed capacity at n={n}",
                f + 1
            );
        }
        assert!(require_minimmit_sizing(1, minimmit_unit_byzantine_bound(1)).is_err());
        assert!(require_minimmit_sizing(0, minimmit_unit_byzantine_bound(0)).is_err());
    }

    #[test]
    fn one_threshold_signer_set_yields_working_m_and_l_sets() {
        // n = 6, f = 1 (the tight 5f+1 committee): M = 3, L = 5. ONE signer
        // instance produces both Minimmit sets; only the threshold differs.
        let ts = signers(6, 3);
        let (m, l) = minimmit_thresholds(6, 1).unwrap();
        assert_eq!((m, l), (3, 5));
        let advance_set = ts.validator_set_with_threshold(m);
        let finalize_set = ts.validator_set_with_threshold(l);
        assert_eq!(advance_set.threshold(), m);
        assert_eq!(finalize_set.threshold(), l);
        // Same membership in the same canonical order (bitmap bits line up)...
        assert_eq!(advance_set.validators(), finalize_set.validators());
        // ...but distinct commitments, because the threshold is bound in.
        assert_ne!(advance_set.commitment(), finalize_set.commitment());

        let msg = Hash::from_bytes([0x51u8; 32]);

        // A subset that meets L verifies at L AND at M (an L-quorum is an
        // M-quorum).
        let l_cert = ts.sign(msg, vec![0, 1, 2, 3, 4]);
        assert!(finalize_set.verify(&l_cert).is_ok());
        assert!(advance_set.verify(&l_cert).is_ok());

        // A subset that meets only M verifies at M but not at L.
        let m_cert = ts.sign(msg, vec![1, 3, 5]);
        assert!(advance_set.verify(&m_cert).is_ok());
        assert!(matches!(
            finalize_set.verify(&m_cert),
            Err(QuorumError::BelowThreshold {
                signed: 3,
                threshold: 5
            })
        ));

        // Below M fails both.
        let sub_m = ts.sign(msg, vec![2, 4]);
        assert!(advance_set.verify(&sub_m).is_err());
        assert!(finalize_set.verify(&sub_m).is_err());

        // The single-threshold accessor is the same set at the instance
        // threshold.
        assert_eq!(ts.validator_set(), advance_set);
    }

    #[test]
    fn minimal_m_and_l_quorums_overlap_in_f_plus_1_signers() {
        // Concrete worst case at unit weight: the M-quorum takes the FIRST M
        // signers and the L-quorum the LAST L — the minimum possible overlap
        // |M ∩ L| = M + L − n. Minimmit sizing makes that exactly f + 1:
        // strictly more than the Byzantine bound f, so at least one HONEST
        // signer sits in both quorums. Real certificates from one signer
        // instance per size (sizes stay within the 16-validator envelope; the
        // arithmetic sweep below covers the full u64 range).
        for n in [6usize, 11, 16] {
            let n_w = u64::try_from(n).unwrap();
            let f = minimmit_unit_byzantine_bound(n_w);
            require_minimmit_sizing(n_w, f).unwrap();
            let (m, l) = minimmit_thresholds(n_w, f).unwrap();
            let ts = signers(n, m);
            let advance_set = ts.validator_set_with_threshold(m);
            let finalize_set = ts.validator_set_with_threshold(l);
            let msg = Hash::from_bytes([0x0Bu8; 32]);

            let m_us = usize::try_from(m).unwrap();
            let l_us = usize::try_from(l).unwrap();
            let m_cert = ts.sign(msg, (0..m_us).collect());
            let l_cert = ts.sign(msg, (n - l_us..n).collect());

            assert!(advance_set.verify(&m_cert).is_ok(), "M-cert at M, n={n}");
            assert!(finalize_set.verify(&l_cert).is_ok(), "L-cert at L, n={n}");
            // A subset that meets L also verifies at M.
            assert!(advance_set.verify(&l_cert).is_ok(), "L-cert at M, n={n}");
            // The M-cert must NOT reach the finalize bar (M < L).
            assert!(finalize_set.verify(&m_cert).is_err(), "M-cert at L, n={n}");

            // Worst-case overlap between the two signer bitmaps is exactly
            // f + 1 — one more than the Byzantine bound.
            let overlap = u64::from((m_cert.signer_bitmap & l_cert.signer_bitmap).count_ones());
            assert_eq!(overlap, f + 1, "worst-case |M∩L| at n={n}");
            assert!(overlap > f, ">=1 honest signer in M∩L at n={n}");
        }
    }

    #[test]
    fn honest_intersection_holds_over_random_sized_committees() {
        // Property: for ANY committee with W >= 5B + 1 the Minimmit
        // thresholds satisfy M + L = W + B + 1, so by inclusion–exclusion any
        // M-quorum and any L-quorum overlap in at least M + L − W = B + 1
        // weight — strictly more than the Byzantine bound B, hence >= 1
        // honest signer in every M ∩ L overlap (unit weight:
        // L + M − n = f + 1 >= 1).
        let mut state: u64 = 0x0514_C0DE_0514_C0DE;
        // Largest B whose 5B + 1 floor still fits in u64.
        let max_b = (u64::MAX - 1) / 5;
        let mut cases: Vec<(u64, u64)> = vec![
            (6, 1),                 // tight unit committee n = 5f+1
            (16, 3),                // the 16-validator envelope
            (1, 0),                 // degenerate f = 0 singleton
            (101, 20),              // weighted, exact 5B+1
            (u64::MAX, max_b),      // near the u64 boundary
            (5 * max_b + 1, max_b), // exact 5B+1 at the boundary
        ];
        for _ in 0..20_000 {
            // Alternate small and huge Byzantine bounds so both regimes are
            // exercised; W is uniform in [5B+1, u64::MAX].
            let b = if splitmix64(&mut state).is_multiple_of(2) {
                splitmix64(&mut state) % 1_000_000
            } else {
                splitmix64(&mut state) % (max_b + 1)
            };
            let floor = 5 * b + 1; // no overflow: b <= (u64::MAX - 1) / 5
            let extra = splitmix64(&mut state) % (u64::MAX - floor + 1);
            cases.push((floor + extra, b));
        }
        for (w, b) in cases {
            // Walk invariant `W >= 5B + 1`, checked in u128 so the check
            // itself cannot overflow (written strictly for clippy).
            assert!(
                u128::from(w) > 5 * u128::from(b),
                "walk violated W >= 5B+1 for (W={w}, B={b})"
            );
            let (m, l) = minimmit_thresholds(w, b)
                .unwrap_or_else(|e| panic!("thresholds failed for (W={w}, B={b}): {e}"));
            // Inclusion–exclusion floor on any M-quorum ∩ L-quorum weight.
            let overlap = (u128::from(m) + u128::from(l))
                .checked_sub(u128::from(w))
                .expect("M + L must exceed W under 5B+1 sizing");
            assert_eq!(
                overlap,
                u128::from(b) + 1,
                "L + M − W must equal B + 1 for (W={w}, B={b}, M={m}, L={l})"
            );
            assert!(
                overlap > u128::from(b),
                "every M∩L overlap must contain >= 1 honest signer \
                 (W={w}, B={b}, M={m}, L={l})"
            );
        }
    }

    #[test]
    fn insufficient_sizing_message_names_the_offending_pair() {
        let err = require_minimmit_sizing(5, 1).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("total weight 5") && msg.contains("byzantine weight 1"),
            "message must name the offending (total, byzantine): {msg}"
        );
    }

    #[test]
    fn try_new_bft_threshold_within_bounds_for_weighted_sets() {
        // A weighted set whose total nears the overflow boundary still yields a
        // valid, in-range threshold (release and debug behave identically).
        let set = ValidatorSet::try_new_bft(vec![
            Validator {
                public_key: [1u8; 32],
                weight: u64::MAX - 10,
            },
            Validator {
                public_key: [2u8; 32],
                weight: 10,
            },
        ])
        .expect("near-max weighted BFT set is valid");
        assert_eq!(set.total_weight(), u64::MAX);
        assert_eq!(set.threshold(), bft_threshold_reference(u64::MAX));
        assert!(set.threshold() >= 1 && set.threshold() <= set.total_weight());
    }

    #[test]
    fn commitment_is_invariant_to_input_ordering() {
        let a = Validator {
            public_key: [3u8; 32],
            weight: 5,
        };
        let b = Validator {
            public_key: [1u8; 32],
            weight: 7,
        };
        let c = Validator {
            public_key: [2u8; 32],
            weight: 9,
        };
        let forward =
            ValidatorSet::try_with_threshold(vec![a.clone(), b.clone(), c.clone()], 12).unwrap();
        let shuffled = ValidatorSet::try_with_threshold(vec![c, a, b], 12).unwrap();
        // Same members, weights, and threshold in a different input order ->
        // identical canonical commitment.
        assert_eq!(forward.commitment(), shuffled.commitment());
    }

    #[test]
    fn packed_qc_roundtrip_and_rejects_bad_lengths() {
        let ts = signers(4, 3);
        let msg = Hash::from_bytes([42u8; 32]);
        let qc = ts.sign(msg, vec![0, 1, 2]);
        let bytes = qc.encode_packed();
        // message(32) + bitmap(2) + 3*64
        assert_eq!(bytes.len(), 32 + 2 + 3 * 64);
        let decoded = QuorumCertificate::decode_packed(&bytes).unwrap();
        assert_eq!(decoded, qc);
        assert_eq!(decoded.signer_count(), 3);

        // Truncated.
        assert_eq!(
            QuorumCertificate::decode_packed(&bytes[..10]),
            Err(QuorumError::MalformedCertificate)
        );
        // Extra trailing byte.
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            QuorumCertificate::decode_packed(&long),
            Err(QuorumError::MalformedCertificate)
        );
        // Bitmap claims more signatures than provided.
        let mut forged = bytes;
        // Set bit 3 (4th signer) without adding a signature.
        let bm = u16::from_le_bytes(forged[32..34].try_into().unwrap()) | (1 << 3);
        forged[32..34].copy_from_slice(&bm.to_le_bytes());
        assert_eq!(
            QuorumCertificate::decode_packed(&forged),
            Err(QuorumError::MalformedCertificate)
        );
    }

    #[test]
    fn packed_qc_rejects_legacy_v1_u64_bitmap_layout() {
        // A v1 (QC_WIRE_VERSION = 1) packing carried an 8-byte little-endian
        // u64 bitmap: message[32] || bitmap_le[8] || sigs. Rebuilding that
        // layout byte-for-byte must NOT decode under the v2 (2-byte) header —
        // the break is one-way (hard fork), never a silent misparse.
        let ts = signers(4, 3);
        let msg = Hash::from_bytes([42u8; 32]);
        let qc = ts.sign(msg, vec![0, 1, 2]);
        let mut legacy = Vec::new();
        legacy.extend_from_slice(qc.message.as_bytes());
        legacy.extend_from_slice(&u64::from(qc.signer_bitmap).to_le_bytes());
        for sig in &qc.signatures {
            legacy.extend_from_slice(sig);
        }
        assert_eq!(legacy.len(), 32 + 8 + 3 * 64);
        assert_eq!(
            QuorumCertificate::decode_packed(&legacy),
            Err(QuorumError::MalformedCertificate)
        );
    }

    #[test]
    fn commitment_binds_membership_weight_and_threshold() {
        let base = ValidatorSet::try_with_threshold(
            vec![
                Validator {
                    public_key: [1u8; 32],
                    weight: 3,
                },
                Validator {
                    public_key: [2u8; 32],
                    weight: 4,
                },
            ],
            5,
        )
        .unwrap();
        let base_commit = base.commitment();

        // Different threshold.
        let other_threshold = ValidatorSet::try_with_threshold(
            vec![
                Validator {
                    public_key: [1u8; 32],
                    weight: 3,
                },
                Validator {
                    public_key: [2u8; 32],
                    weight: 4,
                },
            ],
            6,
        )
        .unwrap();
        assert_ne!(base_commit, other_threshold.commitment());

        // Different weight.
        let other_weight = ValidatorSet::try_with_threshold(
            vec![
                Validator {
                    public_key: [1u8; 32],
                    weight: 3,
                },
                Validator {
                    public_key: [2u8; 32],
                    weight: 5,
                },
            ],
            5,
        )
        .unwrap();
        assert_ne!(base_commit, other_weight.commitment());

        // Different membership (a key changes).
        let other_member = ValidatorSet::try_with_threshold(
            vec![
                Validator {
                    public_key: [1u8; 32],
                    weight: 3,
                },
                Validator {
                    public_key: [9u8; 32],
                    weight: 4,
                },
            ],
            5,
        )
        .unwrap();
        assert_ne!(base_commit, other_member.commitment());
    }
}
