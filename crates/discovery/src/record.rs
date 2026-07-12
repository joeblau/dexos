//! Signed peer records: identity, roles, regions, advertised markets.
//!
//! A [`PeerRecord`] is the self-describing, self-signed gossip primitive of the
//! discovery layer. It is signed by the node's ed25519 identity key over the
//! canonical codec encoding of every field *except* the signature, so any
//! recipient can verify authenticity without a trusted channel.
//!
//! All decode/verify paths are total: adversarial, truncated, or oversized bytes
//! return a typed [`RecordError`], never a panic.

use codec::{decode, encode};
use crypto::{verify_ed25519, KeyPair};
pub use network::PeerId as NodeId;
use serde::{Deserialize, Serialize};
use types::MarketId;

/// Maximum dial addresses a single record may advertise (bounds allocation).
pub const MAX_ADDRESSES: usize = 16;
/// Maximum UTF-8 byte length of a single address string (bounds allocation).
pub const MAX_ADDRESS_BYTES: usize = 256;
/// Maximum total UTF-8 bytes across all address strings in one record.
pub const MAX_ADDRESSES_TOTAL_BYTES: usize = 2048;
/// Maximum regions a single record may claim.
pub const MAX_REGIONS: usize = 8;
/// Maximum protocol identifiers a single record may list.
pub const MAX_PROTOCOLS: usize = 64;
/// Maximum markets a single record may advertise. Adversarial lists beyond this
/// are rejected by [`PeerRecord::verify`] without allocating further.
pub const MAX_MARKET_IDS: usize = 1024;
/// Maximum static seeds retained for bootstrap fallback.
pub const MAX_STATIC_SEEDS: usize = 64;

/// A network role a peer may fulfil. Encoded as a single bit in a [`RoleSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Participates in BFT consensus.
    Validator,
    /// Orders transactions into blocks.
    Sequencer,
    /// Attests to state without voting.
    Witness,
    /// Bridges external clients into the network.
    Gateway,
    /// Feeds signed price/resolution data.
    Oracle,
    /// Holds collateral / custody keys.
    Custody,
    /// Read-only follower.
    Observer,
}

impl Role {
    /// The single-bit mask for this role.
    #[must_use]
    pub const fn bit(self) -> u16 {
        match self {
            Role::Validator => 0x01,
            Role::Sequencer => 0x02,
            Role::Witness => 0x04,
            Role::Gateway => 0x08,
            Role::Oracle => 0x10,
            Role::Custody => 0x20,
            Role::Observer => 0x40,
        }
    }

    /// Every role, for iteration in tests and selection.
    pub const ALL: [Role; 7] = [
        Role::Validator,
        Role::Sequencer,
        Role::Witness,
        Role::Gateway,
        Role::Oracle,
        Role::Custody,
        Role::Observer,
    ];
}

/// A compact bitset over [`Role`] (no external `bitflags` dependency).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct RoleSet(u16);

impl RoleSet {
    /// Mask of all defined role bits; bits outside this are reserved.
    const VALID_BITS: u16 = (1 << 7) - 1;

    /// An empty role set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Construct from a raw bit pattern, discarding reserved bits.
    #[must_use]
    pub const fn from_bits_truncate(bits: u16) -> Self {
        Self(bits & Self::VALID_BITS)
    }

    /// The raw bit pattern.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Return a copy with `role` added.
    #[must_use]
    pub const fn with(self, role: Role) -> Self {
        Self(self.0 | role.bit())
    }

    /// Add `role` in place.
    pub fn insert(&mut self, role: Role) {
        self.0 |= role.bit();
    }

    /// Remove `role` in place.
    pub fn remove(&mut self, role: Role) {
        self.0 &= !role.bit();
    }

    /// Whether `role` is present.
    #[must_use]
    pub const fn contains(self, role: Role) -> bool {
        (self.0 & role.bit()) != 0
    }

    /// Whether the set has no roles.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether `self` shares any role with `other`.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

impl FromIterator<Role> for RoleSet {
    fn from_iter<I: IntoIterator<Item = Role>>(iter: I) -> Self {
        let mut set = RoleSet::empty();
        for role in iter {
            set.insert(role);
        }
        set
    }
}

/// A coarse geographic region used for latency-diverse peer selection.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum Region {
    /// North America, east.
    UsEast,
    /// North America, west.
    UsWest,
    /// Europe, central.
    EuCentral,
    /// Asia-Pacific, northeast.
    ApNortheast,
    /// Any region not otherwise enumerated.
    #[default]
    Other,
}

/// A signed, self-describing peer advertisement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Canonical network peer identity; must match `public_key` to verify.
    pub node_id: NodeId,
    /// ed25519 public key that signed this record.
    pub public_key: [u8; 32],
    /// Dial addresses (host:port or multiaddr strings).
    pub addresses: Vec<String>,
    /// Roles the peer *claims* to serve.
    ///
    /// Self-attested role bits are **hints only** unless a committee/registry
    /// independently authorizes them. Consumers must not grant privileged
    /// admission (e.g. consensus) based solely on this field.
    pub roles: RoleSet,
    /// Regions the peer is reachable from.
    pub regions: Vec<Region>,
    /// Wire protocol version identifiers the peer supports.
    pub supported_protocols: Vec<u16>,
    /// Markets the peer advertises participation in.
    pub market_ids: Vec<MarketId>,
    /// Latest checkpoint height the peer claims.
    pub checkpoint_height: u64,
    /// Absolute expiry (unix seconds); records at or past this are rejected.
    pub expires_at: u64,
    /// ed25519 signature over the canonical no-signature encoding.
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

/// serde adapter for `[u8; 64]` (serde has no built-in impl past 32 bytes).
mod sig_bytes {
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

/// A record validation or construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The record's `expires_at` is at or before the reference time.
    #[error("record expired")]
    Expired,
    /// `node_id` is not the advertised public key identity.
    #[error("node id does not match public key")]
    NodeIdMismatch,
    /// The signature did not verify against the public key.
    #[error("invalid signature")]
    BadSignature,
    /// A variable-length field exceeded its configured bound.
    #[error("field exceeds bound")]
    OversizedField,
    /// The canonical encoding could not be produced or parsed.
    #[error("codec failure")]
    Codec,
}

impl PeerRecord {
    /// Build an unsigned record. `node_id`, `public_key`, and `signature` are
    /// filled in by [`PeerRecord::sign`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        addresses: Vec<String>,
        roles: RoleSet,
        regions: Vec<Region>,
        supported_protocols: Vec<u16>,
        market_ids: Vec<MarketId>,
        checkpoint_height: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            node_id: NodeId::default(),
            public_key: [0u8; 32],
            addresses,
            roles,
            regions,
            supported_protocols,
            market_ids,
            checkpoint_height,
            expires_at,
            signature: [0u8; 64],
        }
    }

    /// Whether any variable-length field is within its allocation bound.
    fn bounds_ok(&self) -> bool {
        if self.addresses.len() > MAX_ADDRESSES
            || self.regions.len() > MAX_REGIONS
            || self.supported_protocols.len() > MAX_PROTOCOLS
            || self.market_ids.len() > MAX_MARKET_IDS
        {
            return false;
        }
        let mut total = 0usize;
        for addr in &self.addresses {
            if addr.len() > MAX_ADDRESS_BYTES {
                return false;
            }
            total = total.saturating_add(addr.len());
            if total > MAX_ADDRESSES_TOTAL_BYTES {
                return false;
            }
        }
        true
    }

    /// Self-attested roles as **hints only**. Prefer
    /// [`PeerRecord::roles_if_authorized`] when a registry is available.
    #[must_use]
    pub fn claimed_roles(&self) -> RoleSet {
        self.roles
    }

    /// Roles authorized by an external registry (committee / membership).
    ///
    /// Returns the intersection of self-attested roles with `authorized`. When
    /// `authorized` is empty the peer has no registry-backed privileges and the
    /// result is empty — self-attested privileged roles alone never grant access.
    #[must_use]
    pub fn roles_if_authorized(&self, authorized: RoleSet) -> RoleSet {
        RoleSet::from_bits_truncate(self.roles.bits() & authorized.bits())
    }

    /// The canonical bytes that are signed: every field except `signature`.
    ///
    /// Encoded via [`codec`] so the layout is deterministic and matches the
    /// verifier bit-for-bit.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, RecordError> {
        let view = SigningView {
            node_id: &self.node_id,
            public_key: &self.public_key,
            addresses: &self.addresses,
            roles: self.roles,
            regions: &self.regions,
            supported_protocols: &self.supported_protocols,
            market_ids: &self.market_ids,
            checkpoint_height: self.checkpoint_height,
            expires_at: self.expires_at,
        };
        encode(&view).map_err(|_| RecordError::Codec)
    }

    /// Sign this record with `keypair`, deriving `node_id` and `public_key` from
    /// the key. Consumes and returns the signed record.
    pub fn sign(mut self, keypair: &KeyPair) -> Result<Self, RecordError> {
        if !self.bounds_ok() {
            return Err(RecordError::OversizedField);
        }
        self.public_key = keypair.public();
        self.node_id = NodeId::from_public_key(&self.public_key);
        let bytes = self.signing_bytes()?;
        self.signature = keypair.sign(&bytes);
        Ok(self)
    }

    /// Verify the record against reference time `now` (unix seconds).
    ///
    /// Checks, in order: field bounds, `node_id == public_key`,
    /// non-expiry, and the ed25519 signature. Returns the first failure.
    pub fn verify(&self, now: u64) -> Result<(), RecordError> {
        if !self.bounds_ok() {
            return Err(RecordError::OversizedField);
        }
        if self.node_id != NodeId::from_public_key(&self.public_key) {
            return Err(RecordError::NodeIdMismatch);
        }
        if self.expires_at <= now {
            return Err(RecordError::Expired);
        }
        let bytes = self.signing_bytes()?;
        verify_ed25519(&self.public_key, &bytes, &self.signature)
            .map_err(|_| RecordError::BadSignature)
    }

    /// Decode a record from wire bytes. Never panics on arbitrary input.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, RecordError> {
        decode::<PeerRecord>(bytes).map_err(|_| RecordError::Codec)
    }

    /// Encode this record to canonical wire bytes (including signature).
    pub fn to_wire(&self) -> Result<Vec<u8>, RecordError> {
        encode(self).map_err(|_| RecordError::Codec)
    }
}

/// Borrowed projection of a record without its signature, for canonical signing.
#[derive(Serialize)]
struct SigningView<'a> {
    node_id: &'a NodeId,
    public_key: &'a [u8; 32],
    addresses: &'a Vec<String>,
    roles: RoleSet,
    regions: &'a Vec<Region>,
    supported_protocols: &'a Vec<u16>,
    market_ids: &'a Vec<MarketId>,
    checkpoint_height: u64,
    expires_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32])
    }

    fn sample_unsigned() -> PeerRecord {
        PeerRecord::new_unsigned(
            vec!["10.0.0.1:9000".to_string()],
            RoleSet::empty().with(Role::Validator).with(Role::Gateway),
            vec![Region::UsEast],
            vec![1, 2],
            vec![MarketId::new(7)],
            42,
            1_000,
        )
    }

    #[test]
    fn sign_verify_round_trip() {
        let kp = keypair(1);
        let rec = sample_unsigned().sign(&kp).unwrap();
        assert_eq!(rec.public_key, kp.public());
        assert_eq!(rec.node_id, NodeId::from_public_key(&kp.public()));
        rec.verify(999).unwrap();
    }

    #[test]
    fn rejects_expired() {
        let kp = keypair(2);
        let rec = sample_unsigned().sign(&kp).unwrap();
        assert_eq!(rec.verify(1_000), Err(RecordError::Expired));
        assert_eq!(rec.verify(2_000), Err(RecordError::Expired));
    }

    #[test]
    fn rejects_tampered_field() {
        let kp = keypair(3);
        let mut rec = sample_unsigned().sign(&kp).unwrap();
        rec.checkpoint_height = 43;
        assert_eq!(rec.verify(999), Err(RecordError::BadSignature));

        let mut rec2 = sample_unsigned().sign(&kp).unwrap();
        rec2.market_ids.push(MarketId::new(99));
        assert_eq!(rec2.verify(999), Err(RecordError::BadSignature));
    }

    #[test]
    fn rejects_node_id_mismatch() {
        let kp = keypair(4);
        let mut rec = sample_unsigned().sign(&kp).unwrap();
        // Point node_id at a different key's identity.
        rec.node_id = NodeId::from_public_key(&keypair(5).public());
        assert_eq!(rec.verify(999), Err(RecordError::NodeIdMismatch));
    }

    #[test]
    fn rejects_public_key_swap() {
        let kp = keypair(6);
        let rec = sample_unsigned().sign(&kp).unwrap();
        let mut swapped = rec.clone();
        swapped.public_key = keypair(7).public();
        // node_id no longer matches the substituted key.
        assert_eq!(swapped.verify(999), Err(RecordError::NodeIdMismatch));

        // Even if the attacker also fixes node_id, the signature fails.
        let mut swapped2 = rec;
        swapped2.public_key = keypair(7).public();
        swapped2.node_id = NodeId::from_public_key(&swapped2.public_key);
        assert_eq!(swapped2.verify(999), Err(RecordError::BadSignature));
    }

    #[test]
    fn rejects_oversized_market_ids() {
        let kp = keypair(8);
        let mut rec = sample_unsigned().sign(&kp).unwrap();
        let over = u32::try_from(MAX_MARKET_IDS).unwrap() + 1;
        rec.market_ids = (0..over).map(MarketId::new).collect();
        assert_eq!(rec.verify(999), Err(RecordError::OversizedField));
    }

    #[test]
    fn rejects_oversized_address_string() {
        let kp = keypair(12);
        let too_long = "x".repeat(MAX_ADDRESS_BYTES + 1);
        let rec = PeerRecord::new_unsigned(
            vec![too_long],
            RoleSet::empty(),
            vec![Region::Other],
            vec![1],
            vec![],
            0,
            1_000,
        );
        assert!(matches!(rec.sign(&kp), Err(RecordError::OversizedField)));
    }

    #[test]
    fn rejects_oversized_total_address_bytes() {
        let kp = keypair(13);
        // Each address under the per-string cap, but total over the aggregate.
        let n = (MAX_ADDRESSES_TOTAL_BYTES / MAX_ADDRESS_BYTES) + 2;
        let addresses: Vec<String> = (0..n.min(MAX_ADDRESSES))
            .map(|_| "a".repeat(MAX_ADDRESS_BYTES))
            .collect();
        let total: usize = addresses.iter().map(String::len).sum();
        assert!(total > MAX_ADDRESSES_TOTAL_BYTES);
        let rec = PeerRecord::new_unsigned(
            addresses,
            RoleSet::empty(),
            vec![Region::Other],
            vec![1],
            vec![],
            0,
            1_000,
        );
        assert!(matches!(rec.sign(&kp), Err(RecordError::OversizedField)));
    }

    #[test]
    fn roles_are_hints_unless_registry_backed() {
        let kp = keypair(14);
        let rec = PeerRecord::new_unsigned(
            vec!["10.0.0.1:1".into()],
            RoleSet::empty().with(Role::Validator).with(Role::Oracle),
            vec![Region::UsEast],
            vec![1],
            vec![],
            0,
            1_000,
        )
        .sign(&kp)
        .unwrap();
        // Self-attested claim includes Validator.
        assert!(rec.claimed_roles().contains(Role::Validator));
        // Without registry authorization, privileged roles are empty.
        let none = rec.roles_if_authorized(RoleSet::empty());
        assert!(none.is_empty());
        // Registry authorizes only Oracle: Validator claim is stripped.
        let auth = RoleSet::empty().with(Role::Oracle);
        let effective = rec.roles_if_authorized(auth);
        assert!(effective.contains(Role::Oracle));
        assert!(!effective.contains(Role::Validator));
    }

    #[test]
    fn roleset_semantics() {
        let rs = RoleSet::empty().with(Role::Oracle).with(Role::Witness);
        assert!(rs.contains(Role::Oracle));
        assert!(rs.contains(Role::Witness));
        assert!(!rs.contains(Role::Validator));
        assert!(rs.intersects(RoleSet::empty().with(Role::Oracle)));
        assert!(!rs.intersects(RoleSet::empty().with(Role::Custody)));
        let collected: RoleSet = [Role::Validator, Role::Custody].into_iter().collect();
        assert_eq!(
            collected.bits(),
            Role::Validator.bit() | Role::Custody.bit()
        );
    }

    #[test]
    fn wire_round_trip_is_byte_identical() {
        let kp = keypair(9);
        let rec = sample_unsigned().sign(&kp).unwrap();
        let a = rec.to_wire().unwrap();
        let decoded = PeerRecord::from_wire(&a).unwrap();
        assert_eq!(decoded, rec);
        let b = decoded.to_wire().unwrap();
        assert_eq!(a, b);
    }

    // Deterministic LCG "property" test: no rand/proptest.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn next_usize(&mut self, bound: usize) -> usize {
            if bound == 0 {
                return 0;
            }
            usize::try_from(self.next_u64() % (bound as u64)).unwrap()
        }
    }

    #[test]
    fn property_encode_decode_encode_identical() {
        let mut lcg = Lcg(0x1234_5678_9abc_def0);
        for _ in 0..256 {
            let kp = KeyPair::from_seed(&[u8::try_from(lcg.next_u64() % 251).unwrap() + 1; 32]);
            let n_addr = lcg.next_usize(MAX_ADDRESSES + 1);
            let addresses: Vec<String> = (0..n_addr)
                .map(|i| format!("host-{}:{}", i, lcg.next_u64() % 65535))
                .collect();
            let mut roles = RoleSet::empty();
            for r in Role::ALL {
                if lcg.next_u64() & 1 == 1 {
                    roles.insert(r);
                }
            }
            let regions = vec![
                [
                    Region::UsEast,
                    Region::UsWest,
                    Region::EuCentral,
                    Region::ApNortheast,
                    Region::Other,
                ][lcg.next_usize(5)],
            ];
            let n_mkt = lcg.next_usize(8);
            let market_ids: Vec<MarketId> = (0..n_mkt)
                .map(|_| MarketId::new(u32::try_from(lcg.next_u64() & 0xffff).unwrap()))
                .collect();
            let rec = PeerRecord::new_unsigned(
                addresses,
                roles,
                regions,
                vec![u16::try_from(lcg.next_u64() & 0xffff).unwrap()],
                market_ids,
                lcg.next_u64(),
                lcg.next_u64() | 1,
            )
            .sign(&kp)
            .unwrap();

            let a = rec.to_wire().unwrap();
            let decoded = PeerRecord::from_wire(&a).unwrap();
            assert_eq!(decoded, rec);
            let b = decoded.to_wire().unwrap();
            assert_eq!(a, b, "re-encode must be byte-identical");
            // A signed record always verifies before its expiry.
            decoded.verify(0).unwrap();
        }
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut lcg = Lcg(0xdead_beef_0bad_f00d);
        for len in 0..300usize {
            let bytes: Vec<u8> = (0..len)
                .map(|_| u8::try_from(lcg.next_u64() & 0xff).unwrap())
                .collect();
            // Must return, never panic.
            let _ = PeerRecord::from_wire(&bytes);
            if let Ok(rec) = PeerRecord::from_wire(&bytes) {
                let _ = rec.verify(lcg.next_u64());
            }
        }
        // Structured-but-hostile: valid record with the signature zeroed.
        let kp = keypair(11);
        let mut rec = sample_unsigned().sign(&kp).unwrap();
        rec.signature = [0u8; 64];
        assert_eq!(rec.verify(0), Err(RecordError::BadSignature));
    }
}
