//! Sponsorship: multi-sponsor stake accounting, revenue-share distribution,
//! transferable ownership, and slashing restricted to *objectively measurable*
//! failures.
//!
//! # Value conservation
//! Stake in equals stake out: [`SponsorSet::add_sponsor`] credits exactly the
//! posted stake, [`SponsorSet::remove_sponsor`] returns exactly that sponsor's
//! remaining stake, and [`SponsorSet::slash`] moves exactly the slashed amount
//! to the caller (destined for the insurance backstop). No path creates or
//! destroys value.
//!
//! # Objective faults only
//! [`SlashableFault`] enumerates the *only* conditions that may reduce stake.
//! Subjective performance (slow quotes, thin books that still meet obligation,
//! unpopular markets) can never trigger a slash — there is no variant for it.
//!
//! # Verified slash evidence
//! [`SlashEvidence`] is the only portable proof that may authorize a stake
//! reduction. Every variant has a deterministic validator: signatures are
//! checked, domain bindings (protocol version, deployment, market, sponsor,
//! fault, epoch, message digests) are enforced, and nonconflicting / random
//! hashes cannot slash. Replay protection is keyed by
//! [`SlashEvidence::evidence_id`], never by a caller-supplied bare hash.

use crypto::{hash_domain, verify_ed25519, KeyPair};
use serde::{Deserialize, Serialize};
use types::{Amount, Hash, MarketId, Ratio, SponsorId};

use crate::config::MAX_BPS;
use crate::error::SponsorError;

/// Hash domain for domain-bound sponsor attestations.
pub const SPONSOR_MESSAGE_DOMAIN: &[u8] = b"DEXOS/SPONSOR/MSG/v1";

/// Hash domain for slash-evidence identity (replay / audit).
pub const SPONSOR_SLASH_DOMAIN: &[u8] = b"DEXOS/SPONSOR/SLASH/v1";

/// Protocol version folded into every sponsor message and evidence id.
pub const SPONSOR_SLASH_PROTOCOL_VERSION: u32 = 1;

/// Message-kind tags carried by [`SignedSponsorMessage`].
pub mod sponsor_msg_kind {
    /// Published market config attestation.
    pub const CONFIG: u8 = 1;
    /// Oracle-feed commitment or contradiction.
    pub const ORACLE: u8 = 2;
    /// Accepted quoting obligation for a window.
    pub const QUOTE_OBLIGATION: u8 = 3;
    /// Observed quote activity for a window.
    pub const QUOTE_ACTIVITY: u8 = 4;
    /// Resolution outcome claim.
    pub const RESOLUTION: u8 = 5;
    /// Liveness heartbeat.
    pub const HEARTBEAT: u8 = 6;
    /// Explicit absence / offline declaration.
    pub const ABSENCE: u8 = 7;
    /// Generic double-sign payload.
    pub const GENERIC: u8 = 8;
}

/// serde adapter for `[u8; 64]` (serde has no built-in impl past 32 bytes).
mod sig64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        v.as_slice().serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        <[u8; 64]>::try_from(v.as_slice())
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))
    }
}

/// One sponsor's stake, revenue entitlement, and governance weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorShare {
    /// The sponsor's identity.
    pub sponsor_id: SponsorId,
    /// Posted collateral stake (non-negative by invariant).
    pub stake: Amount,
    /// Share of the sponsor fee pool, in basis points.
    pub revenue_share_bps: u16,
    /// Governance voting weight.
    pub governance_weight: u64,
}

impl SponsorShare {
    /// Construct a sponsor share.
    #[must_use]
    pub fn new(
        sponsor_id: SponsorId,
        stake: Amount,
        revenue_share_bps: u16,
        governance_weight: u64,
    ) -> Self {
        Self {
            sponsor_id,
            stake,
            revenue_share_bps,
            governance_weight,
        }
    }
}

/// A set of sponsors backing one market, with a single current owner.
///
/// Invariants (checked by every mutator):
/// * `sum(revenue_share_bps) <= 10_000`.
/// * every `stake >= 0`.
/// * `sponsor_id`s are unique.
/// * the set is never empty.
/// * `owner` is always a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorSet {
    shares: Vec<SponsorShare>,
    owner: SponsorId,
}

impl SponsorSet {
    /// Create a set from a single founding sponsor, who becomes the owner.
    ///
    /// # Errors
    /// [`SponsorError::RevenueShareExceeded`] if the founder's bps exceed 10_000,
    /// or [`SponsorError::Arith`] if the stake is negative.
    pub fn new(founder: SponsorShare) -> Result<Self, SponsorError> {
        if founder.revenue_share_bps > MAX_BPS {
            return Err(SponsorError::RevenueShareExceeded);
        }
        if founder.stake.is_negative() {
            return Err(SponsorError::Arith(types::ArithError::OutOfRange));
        }
        Ok(Self {
            owner: founder.sponsor_id,
            shares: vec![founder],
        })
    }

    /// The current owner id.
    #[must_use]
    pub fn owner(&self) -> SponsorId {
        self.owner
    }

    /// Number of sponsors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Whether the set has no sponsors (never true once constructed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// All sponsor shares, in insertion order.
    #[must_use]
    pub fn shares(&self) -> &[SponsorShare] {
        &self.shares
    }

    /// Look up one sponsor's share.
    #[must_use]
    pub fn share(&self, sponsor_id: SponsorId) -> Option<&SponsorShare> {
        self.shares.iter().find(|s| s.sponsor_id == sponsor_id)
    }

    /// Aggregate stake across all sponsors (saturating; stays non-negative).
    #[must_use]
    pub fn total_stake(&self) -> Amount {
        self.shares
            .iter()
            .fold(Amount::ZERO, |acc, s| acc.saturating_add(s.stake))
    }

    /// Aggregate revenue-share basis points. Widened to `u32` so the `<=10_000`
    /// invariant is checked without truncation.
    #[must_use]
    pub fn total_revenue_bps(&self) -> u32 {
        self.shares
            .iter()
            .map(|s| u32::from(s.revenue_share_bps))
            .sum()
    }

    /// Aggregate governance weight (saturating).
    #[must_use]
    pub fn total_governance_weight(&self) -> u64 {
        self.shares
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.governance_weight))
    }

    /// Admit an additional sponsor.
    ///
    /// # Errors
    /// * [`SponsorError::DuplicateSponsor`] if the id is already present.
    /// * [`SponsorError::RevenueShareExceeded`] if the new aggregate bps > 10_000.
    /// * [`SponsorError::Arith`] if the stake is negative.
    pub fn add_sponsor(&mut self, share: SponsorShare) -> Result<(), SponsorError> {
        if share.stake.is_negative() {
            return Err(SponsorError::Arith(types::ArithError::OutOfRange));
        }
        if self.share(share.sponsor_id).is_some() {
            return Err(SponsorError::DuplicateSponsor);
        }
        let projected = self.total_revenue_bps() + u32::from(share.revenue_share_bps);
        if projected > u32::from(MAX_BPS) {
            return Err(SponsorError::RevenueShareExceeded);
        }
        self.shares.push(share);
        Ok(())
    }

    /// Add stake to an existing sponsor. Returns the sponsor's new stake.
    ///
    /// # Errors
    /// [`SponsorError::UnknownSponsor`] or [`SponsorError::Arith`] on overflow /
    /// negative amount.
    pub fn add_stake(
        &mut self,
        sponsor_id: SponsorId,
        amount: Amount,
    ) -> Result<Amount, SponsorError> {
        if amount.is_negative() {
            return Err(SponsorError::Arith(types::ArithError::OutOfRange));
        }
        let share = self
            .shares
            .iter_mut()
            .find(|s| s.sponsor_id == sponsor_id)
            .ok_or(SponsorError::UnknownSponsor)?;
        share.stake = share.stake.checked_add(amount)?;
        Ok(share.stake)
    }

    /// Remove a sponsor, returning the stake to refund to the ledger.
    ///
    /// `min_required` is the market's stake requirement, and `enforce` is true
    /// when the market is past `Draft` (so the requirement must still hold after
    /// removal). Removal is rejected if it would empty the set or remove the
    /// owner.
    ///
    /// # Errors
    /// [`SponsorError::UnknownSponsor`], [`SponsorError::WouldEmptySet`],
    /// [`SponsorError::NotOwner`] (attempt to remove the owner), or
    /// [`SponsorError::StakeRequirementBreach`].
    pub fn remove_sponsor(
        &mut self,
        sponsor_id: SponsorId,
        min_required: Amount,
        enforce: bool,
    ) -> Result<Amount, SponsorError> {
        if self.shares.len() == 1 {
            return Err(SponsorError::WouldEmptySet);
        }
        if sponsor_id == self.owner {
            // Ownership must be transferred before the owner can exit.
            return Err(SponsorError::NotOwner);
        }
        let idx = self
            .shares
            .iter()
            .position(|s| s.sponsor_id == sponsor_id)
            .ok_or(SponsorError::UnknownSponsor)?;
        let refunded = self.shares[idx].stake;
        if enforce {
            let remaining = self.total_stake().saturating_sub(refunded);
            if remaining.raw() < min_required.raw() {
                return Err(SponsorError::StakeRequirementBreach);
            }
        }
        self.shares.remove(idx);
        Ok(refunded)
    }

    /// Transfer ownership to another existing sponsor.
    ///
    /// # Errors
    /// [`SponsorError::NotOwner`] if `current` is not the owner, or
    /// [`SponsorError::UnknownSponsor`] if `next` is not a member.
    pub fn transfer_ownership(
        &mut self,
        current: SponsorId,
        next: SponsorId,
    ) -> Result<(), SponsorError> {
        if current != self.owner {
            return Err(SponsorError::NotOwner);
        }
        if self.share(next).is_none() {
            return Err(SponsorError::UnknownSponsor);
        }
        self.owner = next;
        Ok(())
    }

    /// Distribute an accrued sponsor fee `pool` across sponsors by bps.
    ///
    /// Returns `(payouts, remainder)` where `payouts[i]` corresponds to
    /// `shares()[i]`. Each payout is `pool * bps / 10_000` rounded toward zero;
    /// the deterministic `remainder` (rounding dust plus any unallocated bps)
    /// is `pool - sum(payouts)` and is conventionally credited to the owner.
    ///
    /// Conservation: `sum(payouts) + remainder == pool` exactly.
    ///
    /// # Errors
    /// [`SponsorError::Arith`] on overflow.
    pub fn distribute_revenue(
        &self,
        pool: Amount,
    ) -> Result<(Vec<(SponsorId, Amount)>, Amount), SponsorError> {
        let mut payouts = Vec::with_capacity(self.shares.len());
        let mut allocated = Amount::ZERO;
        for share in &self.shares {
            let ratio = Ratio::from_bps(i64::from(share.revenue_share_bps))?;
            let cut = pool.mul_ratio(ratio)?;
            allocated = allocated.checked_add(cut)?;
            payouts.push((share.sponsor_id, cut));
        }
        let remainder = pool.checked_sub(allocated)?;
        Ok((payouts, remainder))
    }
}

/// The closed set of *objectively measurable* sponsor failures. There is no
/// variant for subjective performance; slashing is impossible without one of
/// these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashableFault {
    /// The published market config was invalid / self-contradictory.
    InvalidConfig,
    /// The sponsor's oracle commitment was broken (feed absent vs commitment).
    BrokenOracleCommitment,
    /// A committed quoting obligation was measurably missed.
    QuotingObligationMiss,
    /// A resolution the sponsor certified was proven fraudulent.
    FraudulentResolution,
    /// The sponsor double-signed conflicting messages.
    DoubleSign,
    /// The sponsor abandoned the market (measurable prolonged absence).
    Abandonment,
}

impl SlashableFault {
    /// The slash penalty, in basis points of the sponsor's stake, for this
    /// fault. These are fixed, published constants (no discretion).
    #[must_use]
    pub const fn penalty_bps(self) -> u16 {
        match self {
            SlashableFault::InvalidConfig => 2_000,
            SlashableFault::BrokenOracleCommitment => 3_000,
            SlashableFault::QuotingObligationMiss => 1_000,
            SlashableFault::FraudulentResolution => 10_000,
            SlashableFault::DoubleSign => 10_000,
            SlashableFault::Abandonment => 5_000,
        }
    }

    /// Stable single-byte tag folded into evidence identities.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            SlashableFault::InvalidConfig => 1,
            SlashableFault::BrokenOracleCommitment => 2,
            SlashableFault::QuotingObligationMiss => 3,
            SlashableFault::FraudulentResolution => 4,
            SlashableFault::DoubleSign => 5,
            SlashableFault::Abandonment => 6,
        }
    }
}

/// A domain-bound sponsor attestation signed with ed25519.
///
/// The signed digest binds protocol version, deployment, market, sponsor,
/// epoch, message kind, and payload hash so a signature over one context can
/// never authorize another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSponsorMessage {
    /// Protocol generation of the slash framework.
    pub protocol_version: u32,
    /// Deployment / network id.
    pub deployment: u64,
    /// Market the attestation is about.
    pub market_id: MarketId,
    /// Sponsor identity bound into the signed digest.
    pub sponsor_id: SponsorId,
    /// Epoch / round of the attestation.
    pub epoch: u64,
    /// Message kind (see [`sponsor_msg_kind`]).
    pub kind: u8,
    /// Canonical hash of the kind-specific payload.
    pub payload_hash: Hash,
    /// Ed25519 public key of the signer.
    pub public_key: [u8; 32],
    /// Ed25519 signature over [`SignedSponsorMessage::message_digest`].
    #[serde(with = "sig64")]
    pub signature: [u8; 64],
}

impl SignedSponsorMessage {
    /// Domain-separated digest a sponsor signs.
    #[must_use]
    pub fn message_digest(
        protocol_version: u32,
        deployment: u64,
        market_id: MarketId,
        sponsor_id: SponsorId,
        epoch: u64,
        kind: u8,
        payload_hash: Hash,
    ) -> Hash {
        let mut buf = Vec::with_capacity(4 + 8 + 4 + 4 + 8 + 1 + 32);
        buf.extend_from_slice(&protocol_version.to_le_bytes());
        buf.extend_from_slice(&deployment.to_le_bytes());
        buf.extend_from_slice(&market_id.get().to_le_bytes());
        buf.extend_from_slice(&sponsor_id.get().to_le_bytes());
        buf.extend_from_slice(&epoch.to_le_bytes());
        buf.push(kind);
        buf.extend_from_slice(payload_hash.as_bytes());
        hash_domain(SPONSOR_MESSAGE_DOMAIN, &buf)
    }

    /// Digest of this message's bound fields.
    #[must_use]
    pub fn digest(&self) -> Hash {
        Self::message_digest(
            self.protocol_version,
            self.deployment,
            self.market_id,
            self.sponsor_id,
            self.epoch,
            self.kind,
            self.payload_hash,
        )
    }

    /// Build and sign a domain-bound attestation with `key`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        key: &KeyPair,
        deployment: u64,
        market_id: MarketId,
        sponsor_id: SponsorId,
        epoch: u64,
        kind: u8,
        payload_hash: Hash,
    ) -> Self {
        let protocol_version = SPONSOR_SLASH_PROTOCOL_VERSION;
        let digest = Self::message_digest(
            protocol_version,
            deployment,
            market_id,
            sponsor_id,
            epoch,
            kind,
            payload_hash,
        );
        let signature = key.sign(digest.as_bytes());
        Self {
            protocol_version,
            deployment,
            market_id,
            sponsor_id,
            epoch,
            kind,
            payload_hash,
            public_key: key.public(),
            signature,
        }
    }

    /// Verify the ed25519 signature over the domain-bound digest.
    ///
    /// # Errors
    /// [`SponsorError::EvidenceProtocolMismatch`] or
    /// [`SponsorError::EvidenceSignatureInvalid`].
    pub fn verify_signature(&self) -> Result<(), SponsorError> {
        if self.protocol_version != SPONSOR_SLASH_PROTOCOL_VERSION {
            return Err(SponsorError::EvidenceProtocolMismatch);
        }
        let digest = self.digest();
        verify_ed25519(&self.public_key, digest.as_bytes(), &self.signature)
            .map_err(|_| SponsorError::EvidenceSignatureInvalid)
    }

    /// Whether this message domain-binds the claimed market/sponsor/deployment/epoch.
    #[must_use]
    pub fn binds(
        &self,
        market_id: MarketId,
        sponsor_id: SponsorId,
        deployment: u64,
        epoch: u64,
    ) -> bool {
        self.protocol_version == SPONSOR_SLASH_PROTOCOL_VERSION
            && self.market_id == market_id
            && self.sponsor_id == sponsor_id
            && self.deployment == deployment
            && self.epoch == epoch
    }
}

/// Two signed messages conflict when they share the same domain binding and
/// kind under the same public key but attest different payloads.
#[must_use]
pub fn messages_conflict(a: &SignedSponsorMessage, b: &SignedSponsorMessage) -> bool {
    a.protocol_version == b.protocol_version
        && a.deployment == b.deployment
        && a.market_id == b.market_id
        && a.sponsor_id == b.sponsor_id
        && a.epoch == b.epoch
        && a.kind == b.kind
        && a.public_key == b.public_key
        && a.payload_hash != b.payload_hash
}

/// Commitment over structured config parameters used by invalid-config evidence.
#[must_use]
pub fn config_payload_hash(revenue_bps: u32, sponsor_count: u32) -> Hash {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&revenue_bps.to_le_bytes());
    buf[4..].copy_from_slice(&sponsor_count.to_le_bytes());
    hash_domain(SPONSOR_MESSAGE_DOMAIN, &buf)
}

/// Commitment over an oracle feed identifier.
#[must_use]
pub fn oracle_payload_hash(feed_id: u64) -> Hash {
    hash_domain(SPONSOR_MESSAGE_DOMAIN, &feed_id.to_le_bytes())
}

/// Commitment over a quoting window and count.
#[must_use]
pub fn quote_window_payload_hash(window_start: u64, window_end: u64, quotes: u32) -> Hash {
    let mut buf = [0u8; 20];
    buf[..8].copy_from_slice(&window_start.to_le_bytes());
    buf[8..16].copy_from_slice(&window_end.to_le_bytes());
    buf[16..].copy_from_slice(&quotes.to_le_bytes());
    hash_domain(SPONSOR_MESSAGE_DOMAIN, &buf)
}

/// Commitment over a resolution payout digest (opaque 32 bytes).
#[must_use]
pub fn resolution_payload_hash(payout_commitment: Hash) -> Hash {
    hash_domain(SPONSOR_MESSAGE_DOMAIN, payout_commitment.as_bytes())
}

/// Commitment over a heartbeat / absence epoch marker.
#[must_use]
pub fn epoch_payload_hash(epoch: u64) -> Hash {
    hash_domain(SPONSOR_MESSAGE_DOMAIN, &epoch.to_le_bytes())
}

/// Typed, portable evidence for every [`SlashableFault`].
///
/// Callers (and consensus gossip) exchange this structure; the registry verifies
/// it before any stake or escrow mutation and keys replay protection on
/// [`SlashEvidence::evidence_id`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashEvidence {
    /// Sponsor signed a self-contradictory / structurally invalid config.
    InvalidConfig {
        /// Deployment id.
        deployment: u64,
        /// Epoch of the attestation.
        epoch: u64,
        /// Signed config attestation.
        attestation: SignedSponsorMessage,
        /// Aggregate revenue-share bps claimed in the config.
        revenue_bps: u32,
        /// Sponsor count claimed in the config.
        sponsor_count: u32,
    },
    /// Sponsor committed to one oracle feed and later attested another.
    BrokenOracleCommitment {
        /// Deployment id.
        deployment: u64,
        /// Epoch of the commitment pair.
        epoch: u64,
        /// Original feed commitment.
        commitment: SignedSponsorMessage,
        /// Contradicting feed attestation.
        contradiction: SignedSponsorMessage,
    },
    /// Sponsor accepted a quoting obligation and reported insufficient activity.
    QuotingObligationMiss {
        /// Deployment id.
        deployment: u64,
        /// Epoch of the obligation window.
        epoch: u64,
        /// Window start (inclusive).
        window_start: u64,
        /// Window end (exclusive).
        window_end: u64,
        /// Minimum quotes required.
        min_quotes: u32,
        /// Actual quotes reported.
        actual_quotes: u32,
        /// Signed obligation acceptance.
        obligation: SignedSponsorMessage,
        /// Signed activity report for the same window.
        activity: SignedSponsorMessage,
    },
    /// Sponsor certified a resolution that conflicts with another claim or with
    /// the market's finalized payout.
    FraudulentResolution {
        /// Deployment id.
        deployment: u64,
        /// Epoch of the fraudulent claim.
        epoch: u64,
        /// Sponsor's resolution claim.
        claim: SignedSponsorMessage,
        /// Optional second conflicting claim (sponsor double-certified).
        conflicting_claim: Option<SignedSponsorMessage>,
        /// Authoritative finalized payout commitment, when proving against state.
        finalized_payout_hash: Option<Hash>,
    },
    /// Classic double-sign: two conflicting messages under one key.
    DoubleSign {
        /// Deployment id.
        deployment: u64,
        /// Epoch of the equivocation.
        epoch: u64,
        /// First signed message.
        first: SignedSponsorMessage,
        /// Second, conflicting signed message.
        second: SignedSponsorMessage,
    },
    /// Sponsor signed a heartbeat and a later absence past the max gap.
    Abandonment {
        /// Deployment id.
        deployment: u64,
        /// Slash epoch (current).
        epoch: u64,
        /// Maximum permitted absence in epochs.
        max_absence_epochs: u64,
        /// Last signed heartbeat.
        last_heartbeat: SignedSponsorMessage,
        /// Signed absence / offline declaration at `epoch`.
        absence: SignedSponsorMessage,
    },
}

/// Optional registry inputs needed by some evidence kinds (fraud vs finalized).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlashVerifyContext {
    /// Finalized payout commitment from market state, if any.
    pub finalized_payout_hash: Option<Hash>,
}

impl SlashEvidence {
    /// The fault kind this evidence proves.
    #[must_use]
    pub const fn fault(&self) -> SlashableFault {
        match self {
            SlashEvidence::InvalidConfig { .. } => SlashableFault::InvalidConfig,
            SlashEvidence::BrokenOracleCommitment { .. } => SlashableFault::BrokenOracleCommitment,
            SlashEvidence::QuotingObligationMiss { .. } => SlashableFault::QuotingObligationMiss,
            SlashEvidence::FraudulentResolution { .. } => SlashableFault::FraudulentResolution,
            SlashEvidence::DoubleSign { .. } => SlashableFault::DoubleSign,
            SlashEvidence::Abandonment { .. } => SlashableFault::Abandonment,
        }
    }

    /// Deployment bound into this evidence.
    #[must_use]
    pub const fn deployment(&self) -> u64 {
        match self {
            SlashEvidence::InvalidConfig { deployment, .. }
            | SlashEvidence::BrokenOracleCommitment { deployment, .. }
            | SlashEvidence::QuotingObligationMiss { deployment, .. }
            | SlashEvidence::FraudulentResolution { deployment, .. }
            | SlashEvidence::DoubleSign { deployment, .. }
            | SlashEvidence::Abandonment { deployment, .. } => *deployment,
        }
    }

    /// Epoch / round bound into this evidence.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        match self {
            SlashEvidence::InvalidConfig { epoch, .. }
            | SlashEvidence::BrokenOracleCommitment { epoch, .. }
            | SlashEvidence::QuotingObligationMiss { epoch, .. }
            | SlashEvidence::FraudulentResolution { epoch, .. }
            | SlashEvidence::DoubleSign { epoch, .. }
            | SlashEvidence::Abandonment { epoch, .. } => *epoch,
        }
    }

    /// Domain-bound identity used for replay protection and audit.
    ///
    /// Binds protocol version, deployment, market, sponsor, fault, epoch, and
    /// the ordered message digests so the same proof cannot replay across any
    /// of those dimensions.
    #[must_use]
    pub fn evidence_id(&self, market_id: MarketId, sponsor_id: SponsorId) -> Hash {
        let fault = self.fault();
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&SPONSOR_SLASH_PROTOCOL_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.deployment().to_le_bytes());
        buf.extend_from_slice(&market_id.get().to_le_bytes());
        buf.extend_from_slice(&sponsor_id.get().to_le_bytes());
        buf.push(fault.tag());
        buf.extend_from_slice(&self.epoch().to_le_bytes());
        for digest in self.message_digests() {
            buf.extend_from_slice(digest.as_bytes());
        }
        hash_domain(SPONSOR_SLASH_DOMAIN, &buf)
    }

    /// Ordered digests of the signed messages in this evidence.
    fn message_digests(&self) -> Vec<Hash> {
        match self {
            SlashEvidence::InvalidConfig { attestation, .. } => vec![attestation.digest()],
            SlashEvidence::BrokenOracleCommitment {
                commitment,
                contradiction,
                ..
            } => vec![commitment.digest(), contradiction.digest()],
            SlashEvidence::QuotingObligationMiss {
                obligation,
                activity,
                ..
            } => vec![obligation.digest(), activity.digest()],
            SlashEvidence::FraudulentResolution {
                claim,
                conflicting_claim,
                finalized_payout_hash,
                ..
            } => {
                let mut v = vec![claim.digest()];
                if let Some(c) = conflicting_claim {
                    v.push(c.digest());
                }
                if let Some(h) = finalized_payout_hash {
                    v.push(*h);
                }
                v
            }
            SlashEvidence::DoubleSign { first, second, .. } => {
                vec![first.digest(), second.digest()]
            }
            SlashEvidence::Abandonment {
                last_heartbeat,
                absence,
                ..
            } => vec![last_heartbeat.digest(), absence.digest()],
        }
    }

    /// Verify this evidence objectively for `market_id` / `sponsor_id`.
    ///
    /// On success the evidence is a valid proof of [`Self::fault`]; on failure
    /// no state may be mutated. `ctx` supplies market-finalized payout data for
    /// fraud-against-state checks.
    ///
    /// # Errors
    /// One of the `SponsorError::Evidence*` variants or
    /// [`SponsorError::InvalidEvidence`].
    pub fn verify(
        &self,
        market_id: MarketId,
        sponsor_id: SponsorId,
        ctx: SlashVerifyContext,
    ) -> Result<(), SponsorError> {
        match self {
            SlashEvidence::InvalidConfig {
                deployment,
                epoch,
                attestation,
                revenue_bps,
                sponsor_count,
            } => {
                check_msg(
                    attestation,
                    market_id,
                    sponsor_id,
                    *deployment,
                    *epoch,
                    sponsor_msg_kind::CONFIG,
                )?;
                let expected = config_payload_hash(*revenue_bps, *sponsor_count);
                if attestation.payload_hash != expected {
                    return Err(SponsorError::InvalidEvidence);
                }
                // Objective structural violation: bps overflow or empty set.
                if *revenue_bps <= u32::from(MAX_BPS) && *sponsor_count > 0 {
                    return Err(SponsorError::EvidenceNonconflicting);
                }
                Ok(())
            }
            SlashEvidence::BrokenOracleCommitment {
                deployment,
                epoch,
                commitment,
                contradiction,
            } => {
                check_msg(
                    commitment,
                    market_id,
                    sponsor_id,
                    *deployment,
                    *epoch,
                    sponsor_msg_kind::ORACLE,
                )?;
                check_msg(
                    contradiction,
                    market_id,
                    sponsor_id,
                    *deployment,
                    *epoch,
                    sponsor_msg_kind::ORACLE,
                )?;
                if commitment.public_key != contradiction.public_key {
                    return Err(SponsorError::EvidenceSignatureInvalid);
                }
                if !messages_conflict(commitment, contradiction) {
                    return Err(SponsorError::EvidenceNonconflicting);
                }
                Ok(())
            }
            SlashEvidence::QuotingObligationMiss {
                deployment,
                epoch,
                window_start,
                window_end,
                min_quotes,
                actual_quotes,
                obligation,
                activity,
            } => {
                if window_end <= window_start || actual_quotes >= min_quotes {
                    return Err(SponsorError::EvidenceNonconflicting);
                }
                check_msg(
                    obligation,
                    market_id,
                    sponsor_id,
                    *deployment,
                    *epoch,
                    sponsor_msg_kind::QUOTE_OBLIGATION,
                )?;
                check_msg(
                    activity,
                    market_id,
                    sponsor_id,
                    *deployment,
                    *epoch,
                    sponsor_msg_kind::QUOTE_ACTIVITY,
                )?;
                if obligation.public_key != activity.public_key {
                    return Err(SponsorError::EvidenceSignatureInvalid);
                }
                let obl_hash =
                    quote_window_payload_hash(*window_start, *window_end, *min_quotes);
                let act_hash =
                    quote_window_payload_hash(*window_start, *window_end, *actual_quotes);
                if obligation.payload_hash != obl_hash || activity.payload_hash != act_hash {
                    return Err(SponsorError::InvalidEvidence);
                }
                Ok(())
            }
            SlashEvidence::FraudulentResolution {
                deployment,
                epoch,
                claim,
                conflicting_claim,
                finalized_payout_hash,
            } => {
                check_msg(
                    claim,
                    market_id,
                    sponsor_id,
                    *deployment,
                    *epoch,
                    sponsor_msg_kind::RESOLUTION,
                )?;
                match (conflicting_claim, finalized_payout_hash) {
                    (Some(other), _) => {
                        check_msg(
                            other,
                            market_id,
                            sponsor_id,
                            *deployment,
                            *epoch,
                            sponsor_msg_kind::RESOLUTION,
                        )?;
                        if claim.public_key != other.public_key {
                            return Err(SponsorError::EvidenceSignatureInvalid);
                        }
                        if !messages_conflict(claim, other) {
                            return Err(SponsorError::EvidenceNonconflicting);
                        }
                        Ok(())
                    }
                    (None, Some(finalized)) => {
                        if claim.payload_hash == resolution_payload_hash(*finalized) {
                            return Err(SponsorError::EvidenceNonconflicting);
                        }
                        // Registry must confirm the finalized hash matches state.
                        match ctx.finalized_payout_hash {
                            Some(state) if state == *finalized => Ok(()),
                            Some(_) => Err(SponsorError::EvidenceFinalizedMismatch),
                            None => Err(SponsorError::EvidenceFinalizedMismatch),
                        }
                    }
                    (None, None) => Err(SponsorError::EvidenceNonconflicting),
                }
            }
            SlashEvidence::DoubleSign {
                deployment,
                epoch,
                first,
                second,
            } => {
                // Kind may be any, but both must match each other and bind the
                // claimed domain; signatures and key equality are required.
                if first.protocol_version != SPONSOR_SLASH_PROTOCOL_VERSION
                    || second.protocol_version != SPONSOR_SLASH_PROTOCOL_VERSION
                {
                    return Err(SponsorError::EvidenceProtocolMismatch);
                }
                if !first.binds(market_id, sponsor_id, *deployment, *epoch)
                    || !second.binds(market_id, sponsor_id, *deployment, *epoch)
                {
                    return Err(SponsorError::EvidenceDomainMismatch);
                }
                first.verify_signature()?;
                second.verify_signature()?;
                if first.public_key != second.public_key {
                    return Err(SponsorError::EvidenceSignatureInvalid);
                }
                if first.kind != second.kind {
                    return Err(SponsorError::EvidenceNonconflicting);
                }
                if !messages_conflict(first, second) {
                    return Err(SponsorError::EvidenceNonconflicting);
                }
                Ok(())
            }
            SlashEvidence::Abandonment {
                deployment,
                epoch,
                max_absence_epochs,
                last_heartbeat,
                absence,
            } => {
                if *max_absence_epochs == 0 {
                    return Err(SponsorError::InvalidEvidence);
                }
                // Heartbeat is at its own epoch (encoded in the message); absence
                // is at the slash epoch. Domain-bind market/sponsor/deployment.
                if last_heartbeat.protocol_version != SPONSOR_SLASH_PROTOCOL_VERSION
                    || absence.protocol_version != SPONSOR_SLASH_PROTOCOL_VERSION
                {
                    return Err(SponsorError::EvidenceProtocolMismatch);
                }
                if last_heartbeat.market_id != market_id
                    || last_heartbeat.sponsor_id != sponsor_id
                    || last_heartbeat.deployment != *deployment
                    || last_heartbeat.kind != sponsor_msg_kind::HEARTBEAT
                {
                    return Err(SponsorError::EvidenceDomainMismatch);
                }
                if !absence.binds(market_id, sponsor_id, *deployment, *epoch)
                    || absence.kind != sponsor_msg_kind::ABSENCE
                {
                    return Err(SponsorError::EvidenceDomainMismatch);
                }
                last_heartbeat.verify_signature()?;
                absence.verify_signature()?;
                if last_heartbeat.public_key != absence.public_key {
                    return Err(SponsorError::EvidenceSignatureInvalid);
                }
                let hb_epoch = last_heartbeat.epoch;
                if absence.epoch != *epoch
                    || absence.payload_hash != epoch_payload_hash(*epoch)
                    || last_heartbeat.payload_hash != epoch_payload_hash(hb_epoch)
                {
                    return Err(SponsorError::InvalidEvidence);
                }
                // Objective prolonged absence: slash epoch exceeds last heartbeat
                // by more than the permitted gap.
                if epoch.saturating_sub(hb_epoch) <= *max_absence_epochs {
                    return Err(SponsorError::EvidenceNonconflicting);
                }
                Ok(())
            }
        }
    }
}

fn check_msg(
    msg: &SignedSponsorMessage,
    market_id: MarketId,
    sponsor_id: SponsorId,
    deployment: u64,
    epoch: u64,
    kind: u8,
) -> Result<(), SponsorError> {
    if !msg.binds(market_id, sponsor_id, deployment, epoch) {
        return Err(SponsorError::EvidenceDomainMismatch);
    }
    if msg.kind != kind {
        return Err(SponsorError::InvalidEvidence);
    }
    msg.verify_signature()
}

/// Portable audit summary of a verified, applied slash (for gossip / appeal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedSlash {
    /// Domain-bound evidence identity.
    pub evidence_id: Hash,
    /// Market that was slashed.
    pub market_id: MarketId,
    /// Sponsor that was slashed.
    pub sponsor_id: SponsorId,
    /// Fault proven by the evidence.
    pub fault: SlashableFault,
    /// Deployment bound into the evidence.
    pub deployment: u64,
    /// Epoch bound into the evidence.
    pub epoch: u64,
    /// Amount moved from sponsor stake to insurance.
    pub amount: Amount,
}

impl SponsorSet {
    /// Slash a sponsor for an objective `fault`, reducing its stake by the
    /// fault's penalty bps and returning the slashed amount (to be credited to
    /// the insurance backstop by the caller).
    ///
    /// Only [`SlashableFault`] variants can reach here; there is no way to slash
    /// for subjective reasons. Value is conserved: the sponsor's stake drops by
    /// exactly the returned amount. Callers must verify [`SlashEvidence`] before
    /// invoking this.
    ///
    /// # Errors
    /// [`SponsorError::UnknownSponsor`] or [`SponsorError::Arith`].
    pub fn slash(
        &mut self,
        sponsor_id: SponsorId,
        fault: SlashableFault,
    ) -> Result<Amount, SponsorError> {
        let share = self
            .shares
            .iter_mut()
            .find(|s| s.sponsor_id == sponsor_id)
            .ok_or(SponsorError::UnknownSponsor)?;
        let ratio = Ratio::from_bps(i64::from(fault.penalty_bps()))?;
        let mut slashed = share.stake.mul_ratio(ratio)?;
        // Never slash more than the sponsor holds.
        if slashed.raw() > share.stake.raw() {
            slashed = share.stake;
        }
        share.stake = share.stake.checked_sub(slashed)?;
        Ok(slashed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u32) -> SponsorId {
        SponsorId::new(n)
    }

    fn founder() -> SponsorShare {
        SponsorShare::new(sid(1), Amount::from_raw(1_000_000), 6_000, 100)
    }

    #[test]
    fn multi_sponsor_stake_and_governance_totals() {
        let mut set = SponsorSet::new(founder()).unwrap();
        set.add_sponsor(SponsorShare::new(
            sid(2),
            Amount::from_raw(500_000),
            3_000,
            50,
        ))
        .unwrap();
        assert_eq!(set.total_stake(), Amount::from_raw(1_500_000));
        assert_eq!(set.total_revenue_bps(), 9_000);
        assert_eq!(set.total_governance_weight(), 150);
    }

    #[test]
    fn revenue_share_bps_bound_enforced() {
        let mut set = SponsorSet::new(founder()).unwrap();
        // founder is 6000; +5000 would be 11000 > 10000.
        let err = set
            .add_sponsor(SponsorShare::new(sid(2), Amount::ZERO, 5_000, 0))
            .unwrap_err();
        assert_eq!(err, SponsorError::RevenueShareExceeded);
        // +4000 is exactly 10000, allowed.
        assert!(set
            .add_sponsor(SponsorShare::new(sid(2), Amount::ZERO, 4_000, 0))
            .is_ok());
    }

    #[test]
    fn revenue_distribution_sums_exactly() {
        let mut set = SponsorSet::new(founder()).unwrap();
        set.add_sponsor(SponsorShare::new(sid(2), Amount::ZERO, 4_000, 0))
            .unwrap();
        let pool = Amount::from_raw(1_000_000); // 1.0
        let (payouts, remainder) = set.distribute_revenue(pool).unwrap();
        // 60% and 40% of 1.0.
        assert_eq!(payouts[0].1, Amount::from_raw(600_000));
        assert_eq!(payouts[1].1, Amount::from_raw(400_000));
        assert_eq!(remainder, Amount::ZERO);
        let sum = payouts
            .iter()
            .fold(Amount::ZERO, |a, p| a.checked_add(p.1).unwrap());
        assert_eq!(sum.checked_add(remainder).unwrap(), pool);
    }

    #[test]
    fn remainder_captures_rounding_and_unallocated_bps() {
        // Only 50% allocated; remainder holds the other half plus any dust.
        let set = SponsorSet::new(SponsorShare::new(sid(1), Amount::ZERO, 5_000, 0)).unwrap();
        let pool = Amount::from_raw(1_000_001); // odd micro-unit
        let (payouts, remainder) = set.distribute_revenue(pool).unwrap();
        let sum = payouts
            .iter()
            .fold(Amount::ZERO, |a, p| a.checked_add(p.1).unwrap());
        assert_eq!(sum.checked_add(remainder).unwrap(), pool);
        // 50% of 1_000_001 rounds toward zero to 500_000.
        assert_eq!(payouts[0].1, Amount::from_raw(500_000));
        assert_eq!(remainder, Amount::from_raw(500_001));
    }

    #[test]
    fn ownership_transfer_and_removal_rules() {
        let mut set = SponsorSet::new(founder()).unwrap();
        set.add_sponsor(SponsorShare::new(
            sid(2),
            Amount::from_raw(500_000),
            1_000,
            10,
        ))
        .unwrap();
        // Cannot remove the owner directly.
        assert_eq!(
            set.remove_sponsor(sid(1), Amount::ZERO, false).unwrap_err(),
            SponsorError::NotOwner
        );
        // Transfer then remove old owner.
        set.transfer_ownership(sid(1), sid(2)).unwrap();
        let refunded = set.remove_sponsor(sid(1), Amount::ZERO, false).unwrap();
        assert_eq!(refunded, Amount::from_raw(1_000_000));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn removal_respects_stake_requirement_when_active() {
        let mut set = SponsorSet::new(founder()).unwrap();
        set.add_sponsor(SponsorShare::new(
            sid(2),
            Amount::from_raw(500_000),
            1_000,
            10,
        ))
        .unwrap();
        set.transfer_ownership(sid(1), sid(2)).unwrap();
        // Requirement 1.2; removing sid(1) (1.0) leaves 0.5 < 1.2 -> breach.
        let req = Amount::from_raw(1_200_000);
        assert_eq!(
            set.remove_sponsor(sid(1), req, true).unwrap_err(),
            SponsorError::StakeRequirementBreach
        );
    }

    #[test]
    fn slash_only_reduces_by_penalty_and_conserves() {
        let mut set = SponsorSet::new(founder()).unwrap();
        let before = set.share(sid(1)).unwrap().stake;
        // InvalidConfig = 2000 bps = 20% of 1.0 = 0.2.
        let slashed = set.slash(sid(1), SlashableFault::InvalidConfig).unwrap();
        assert_eq!(slashed, Amount::from_raw(200_000));
        let after = set.share(sid(1)).unwrap().stake;
        assert_eq!(before.checked_sub(after).unwrap(), slashed);
        // Fraud / double-sign are total (100%).
        let mut set2 = SponsorSet::new(founder()).unwrap();
        let all = set2
            .slash(sid(1), SlashableFault::FraudulentResolution)
            .unwrap();
        assert_eq!(all, before);
        assert_eq!(set2.share(sid(1)).unwrap().stake, Amount::ZERO);
    }

    fn kp(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32])
    }

    fn mkt(n: u32) -> MarketId {
        MarketId::new(n)
    }

    fn double_sign_fixture(
        key: &KeyPair,
        market: MarketId,
        sponsor: SponsorId,
        deployment: u64,
        epoch: u64,
        payload_a: Hash,
        payload_b: Hash,
    ) -> SlashEvidence {
        let first = SignedSponsorMessage::sign(
            key,
            deployment,
            market,
            sponsor,
            epoch,
            sponsor_msg_kind::GENERIC,
            payload_a,
        );
        let second = SignedSponsorMessage::sign(
            key,
            deployment,
            market,
            sponsor,
            epoch,
            sponsor_msg_kind::GENERIC,
            payload_b,
        );
        SlashEvidence::DoubleSign {
            deployment,
            epoch,
            first,
            second,
        }
    }

    #[test]
    fn double_sign_valid_fixture_verifies_once_identity_stable() {
        let key = kp(7);
        let market = mkt(1);
        let sponsor = sid(1);
        let ev = double_sign_fixture(
            &key,
            market,
            sponsor,
            9,
            3,
            Hash::from_bytes([1u8; 32]),
            Hash::from_bytes([2u8; 32]),
        );
        assert_eq!(ev.fault(), SlashableFault::DoubleSign);
        assert_eq!(ev.fault().penalty_bps(), 10_000);
        ev.verify(market, sponsor, SlashVerifyContext::default())
            .unwrap();
        let id = ev.evidence_id(market, sponsor);
        assert!(!id.is_zero());
        // Same evidence → same id (replay key).
        assert_eq!(id, ev.evidence_id(market, sponsor));
    }

    #[test]
    fn nonconflicting_and_random_messages_cannot_slash() {
        let key = kp(7);
        let market = mkt(1);
        let sponsor = sid(1);
        // Same payload twice: no conflict.
        let same = double_sign_fixture(
            &key,
            market,
            sponsor,
            1,
            1,
            Hash::from_bytes([9u8; 32]),
            Hash::from_bytes([9u8; 32]),
        );
        assert_eq!(
            same.verify(market, sponsor, SlashVerifyContext::default())
                .unwrap_err(),
            SponsorError::EvidenceNonconflicting
        );
        // Domain mismatch: evidence for another market.
        let foreign = double_sign_fixture(
            &key,
            mkt(2),
            sponsor,
            1,
            1,
            Hash::from_bytes([1u8; 32]),
            Hash::from_bytes([2u8; 32]),
        );
        assert_eq!(
            foreign
                .verify(market, sponsor, SlashVerifyContext::default())
                .unwrap_err(),
            SponsorError::EvidenceDomainMismatch
        );
        // Malformed signature.
        let mut bad = double_sign_fixture(
            &key,
            market,
            sponsor,
            1,
            1,
            Hash::from_bytes([1u8; 32]),
            Hash::from_bytes([2u8; 32]),
        );
        if let SlashEvidence::DoubleSign { first, .. } = &mut bad {
            first.signature[0] ^= 0xff;
        }
        assert_eq!(
            bad.verify(market, sponsor, SlashVerifyContext::default())
                .unwrap_err(),
            SponsorError::EvidenceSignatureInvalid
        );
        // Valid config numbers are not slashable.
        let ok_cfg = SignedSponsorMessage::sign(
            &key,
            1,
            market,
            sponsor,
            1,
            sponsor_msg_kind::CONFIG,
            config_payload_hash(5_000, 2),
        );
        let not_invalid = SlashEvidence::InvalidConfig {
            deployment: 1,
            epoch: 1,
            attestation: ok_cfg,
            revenue_bps: 5_000,
            sponsor_count: 2,
        };
        assert_eq!(
            not_invalid
                .verify(market, sponsor, SlashVerifyContext::default())
                .unwrap_err(),
            SponsorError::EvidenceNonconflicting
        );
    }

    #[test]
    fn evidence_id_differs_across_market_sponsor_deployment_epoch() {
        let key = kp(3);
        let base = double_sign_fixture(
            &key,
            mkt(1),
            sid(1),
            1,
            1,
            Hash::from_bytes([1u8; 32]),
            Hash::from_bytes([2u8; 32]),
        );
        let id = base.evidence_id(mkt(1), sid(1));
        assert_ne!(id, base.evidence_id(mkt(2), sid(1)));
        assert_ne!(id, base.evidence_id(mkt(1), sid(2)));
        let other_dep = double_sign_fixture(
            &key,
            mkt(1),
            sid(1),
            2,
            1,
            Hash::from_bytes([1u8; 32]),
            Hash::from_bytes([2u8; 32]),
        );
        assert_ne!(id, other_dep.evidence_id(mkt(1), sid(1)));
        let other_epoch = double_sign_fixture(
            &key,
            mkt(1),
            sid(1),
            1,
            2,
            Hash::from_bytes([1u8; 32]),
            Hash::from_bytes([2u8; 32]),
        );
        assert_ne!(id, other_epoch.evidence_id(mkt(1), sid(1)));
    }

    #[test]
    fn fraud_conflicting_claims_and_finalized_mismatch() {
        let key = kp(11);
        let market = mkt(1);
        let sponsor = sid(1);
        let claim = SignedSponsorMessage::sign(
            &key,
            1,
            market,
            sponsor,
            4,
            sponsor_msg_kind::RESOLUTION,
            resolution_payload_hash(Hash::from_bytes([1u8; 32])),
        );
        let other = SignedSponsorMessage::sign(
            &key,
            1,
            market,
            sponsor,
            4,
            sponsor_msg_kind::RESOLUTION,
            resolution_payload_hash(Hash::from_bytes([2u8; 32])),
        );
        let fraud = SlashEvidence::FraudulentResolution {
            deployment: 1,
            epoch: 4,
            claim: claim.clone(),
            conflicting_claim: Some(other),
            finalized_payout_hash: None,
        };
        fraud
            .verify(market, sponsor, SlashVerifyContext::default())
            .unwrap();

        let against_state = SlashEvidence::FraudulentResolution {
            deployment: 1,
            epoch: 4,
            claim,
            conflicting_claim: None,
            finalized_payout_hash: Some(Hash::from_bytes([9u8; 32])),
        };
        // Missing / mismatched finalized state rejects.
        assert_eq!(
            against_state
                .verify(market, sponsor, SlashVerifyContext::default())
                .unwrap_err(),
            SponsorError::EvidenceFinalizedMismatch
        );
        against_state
            .verify(
                market,
                sponsor,
                SlashVerifyContext {
                    finalized_payout_hash: Some(Hash::from_bytes([9u8; 32])),
                },
            )
            .unwrap();
    }

    // Deterministic LCG property test: revenue distribution always conserves.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn property_distribution_conserves_over_random_sets() {
        let mut r = Lcg(0x5EED_1234);
        for _ in 0..20_000 {
            let n = usize::try_from(r.next_u64() % 6).unwrap() + 1;
            let mut remaining_bps = 10_000u32;
            let founder_bps = u16::try_from(r.next_u64() % u64::from(remaining_bps + 1)).unwrap();
            remaining_bps -= u32::from(founder_bps);
            let mut set = SponsorSet::new(SponsorShare::new(
                sid(0),
                Amount::from_raw(i128::from(r.next_u64() % 1_000_000)),
                founder_bps,
                r.next_u64() % 1000,
            ))
            .unwrap();
            for i in 1..n {
                if remaining_bps == 0 {
                    break;
                }
                let bps = u16::try_from(r.next_u64() % u64::from(remaining_bps + 1)).unwrap();
                remaining_bps -= u32::from(bps);
                // add_sponsor may still succeed; ignore duplicate-free ids.
                let _ = set.add_sponsor(SponsorShare::new(
                    sid(u32::try_from(i).unwrap()),
                    Amount::from_raw(i128::from(r.next_u64() % 1_000_000)),
                    bps,
                    r.next_u64() % 1000,
                ));
            }
            assert!(set.total_revenue_bps() <= u32::from(MAX_BPS));
            let pool = Amount::from_raw(i128::from(r.next_u64() % 1_000_000_000));
            let (payouts, remainder) = set.distribute_revenue(pool).unwrap();
            let sum = payouts
                .iter()
                .fold(Amount::ZERO, |a, p| a.checked_add(p.1).unwrap());
            assert_eq!(sum.checked_add(remainder).unwrap(), pool);
            assert!(!remainder.is_negative());
        }
    }

    #[test]
    fn property_conflicting_and_nonconflicting_pairs_and_penalty_bounds() {
        let mut r = Lcg(0xC0FF_EE00);
        let key = kp(42);
        let market = mkt(1);
        let sponsor = sid(1);
        for i in 0..5_000u64 {
            let deployment = r.next_u64() % 16;
            let epoch = r.next_u64() % 1_000;
            let mut pa = [0u8; 32];
            let mut pb = [0u8; 32];
            for b in &mut pa {
                *b = u8::try_from(r.next_u64() % 256).unwrap();
            }
            for b in &mut pb {
                *b = u8::try_from(r.next_u64() % 256).unwrap();
            }
            // Force a conflict on even iterations.
            if i % 2 == 0 && pa == pb {
                pb[0] ^= 1;
            }
            // Force equality on odd iterations.
            if i % 2 == 1 {
                pb = pa;
            }
            let a = Hash::from_bytes(pa);
            let b = Hash::from_bytes(pb);
            let first = SignedSponsorMessage::sign(
                &key,
                deployment,
                market,
                sponsor,
                epoch,
                sponsor_msg_kind::GENERIC,
                a,
            );
            let second = SignedSponsorMessage::sign(
                &key,
                deployment,
                market,
                sponsor,
                epoch,
                sponsor_msg_kind::GENERIC,
                b,
            );
            let conflict = messages_conflict(&first, &second);
            if i % 2 == 0 {
                assert!(conflict);
                let ev = SlashEvidence::DoubleSign {
                    deployment,
                    epoch,
                    first,
                    second,
                };
                ev.verify(market, sponsor, SlashVerifyContext::default())
                    .unwrap();
            } else {
                assert!(!conflict);
                let ev = SlashEvidence::DoubleSign {
                    deployment,
                    epoch,
                    first,
                    second,
                };
                assert_eq!(
                    ev.verify(market, sponsor, SlashVerifyContext::default())
                        .unwrap_err(),
                    SponsorError::EvidenceNonconflicting
                );
            }
        }
        // Fault-specific penalty bounds: every published penalty is in (0, 10000].
        for fault in [
            SlashableFault::InvalidConfig,
            SlashableFault::BrokenOracleCommitment,
            SlashableFault::QuotingObligationMiss,
            SlashableFault::FraudulentResolution,
            SlashableFault::DoubleSign,
            SlashableFault::Abandonment,
        ] {
            let bps = fault.penalty_bps();
            assert!(bps > 0 && bps <= 10_000);
        }
    }
}
