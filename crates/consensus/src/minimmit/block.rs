//! The minimal Minimmit block header: the one structure whose hash a
//! `Notarize` vote commits to (`docs/CONSENSUS_MINIMMIT.md` §4, #516).
//!
//! # Why the header must commit `height`
//!
//! Minimmit's [`notarize_digest`](super::digest::notarize_digest) preimage is
//! `epoch_le ‖ view_le ‖ block_hash[32]` — it deliberately drops the `height` /
//! phase fields from the signed preimage. That is
//! only safe because [`BlockHeader::hash`] binds `height` itself: a notarize
//! digest over `block_hash` therefore cannot be replayed for the same payload
//! at a different height.
//!
//! # Placement: `consensus`, not `types`
//!
//! [RISKY — resolved here] The header lives in the `consensus` crate. Nothing
//! outside consensus needs the type: light clients verify `Checkpoint`s (which
//! bind `execution_root`), and the node passes headers straight back into the
//! replica. Should a later phase need it shared, re-exporting from here is a
//! non-breaking move.
//!
//! # The build / verify seam
//!
//! `consensus` is a pure synchronous state machine, so it never constructs or
//! validates block *contents*:
//!
//! - **`build(parent_hash) → BlockHeader`** is a node-side callback: the
//!   node's execution / state-tree layer deterministically assembles the
//!   header (choosing `height`, `parent_hash`, `payload_root`) when the
//!   replica asks for a proposal (`docs/CONSENSUS_MINIMMIT.md` §7.2).
//! - **`verify(block, parent_hash) → bool`** likewise runs node-side, outside
//!   `step()`; its verdict re-enters the replica as data (a
//!   `ProposalVerified`-style input, §7.1).
//!
//! The consensus core only ever sees the header plus its [`BlockHeader::hash`]
//! (`BlockHeader::hash`) — both travel on the wire inside `Propose` (#517);
//! every other message references the 32-byte hash alone.

use crypto::hash_domain;
use serde::{Deserialize, Serialize};
use types::Hash;

/// Domain tag for the Minimmit block-header hash ([`BlockHeader::hash`]).
pub const DOMAIN_BLOCK: &[u8] = b"dexos:consensus:minimmit:block:v1";

/// The minimal block header Minimmit consensus orders.
///
/// Built by the node (`build`), validated by the node (`verify`), and treated
/// by the replica as opaque data plus a hash — see the module docs for the
/// seam. All fields are bound by [`BlockHeader::hash`], so the notarize digest
/// over that hash transitively commits every one of them, `height` included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Chain height this block occupies (parent height + 1).
    pub height: u64,
    /// Hash of the parent block header this block extends.
    pub parent_hash: Hash,
    /// Commitment to the block's payload (the batch of sequenced commands).
    pub payload_root: Hash,
}

impl BlockHeader {
    /// The canonical, domain-separated block-header hash — the `block_hash`
    /// every wire message and digest refers to.
    ///
    /// Preimage: `height_le ‖ parent_hash[32] ‖ payload_root[32]` under
    /// [`DOMAIN_BLOCK`]. Deterministic and architecture-independent
    /// (little-endian, fixed field order), following the exact builder pattern
    /// of [`crate::checkpoint::CheckpointHeader::hash`].
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut buf = [0u8; 8 + 32 * 2];
        buf[0..8].copy_from_slice(&self.height.to_le_bytes());
        buf[8..40].copy_from_slice(self.parent_hash.as_bytes());
        buf[40..72].copy_from_slice(self.payload_root.as_bytes());
        hash_domain(DOMAIN_BLOCK, &buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_hash() -> Hash {
        Hash::from_bytes([0xAB; 32])
    }

    fn payload_root() -> Hash {
        Hash::from_bytes([0xCD; 32])
    }

    fn header() -> BlockHeader {
        BlockHeader {
            height: 9,
            parent_hash: parent_hash(),
            payload_root: payload_root(),
        }
    }

    #[test]
    fn domain_string_is_pinned() {
        // Exact wire-format value — changing any byte is a consensus-breaking
        // change. Pairwise distinctness against every other consensus domain
        // is asserted centrally in `super::digest::tests`.
        assert_eq!(DOMAIN_BLOCK, b"dexos:consensus:minimmit:block:v1");
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(header().hash(), header().hash());
    }

    #[test]
    fn preimage_layout_is_locked() {
        // Rebuild the preimage by hand (field order + little-endian) and
        // assert `hash()` hashes exactly it: locks the byte layout against
        // accidental reordering or endianness drift.
        let h = header();
        let mut buf = Vec::new();
        buf.extend_from_slice(&h.height.to_le_bytes());
        buf.extend_from_slice(h.parent_hash.as_bytes());
        buf.extend_from_slice(h.payload_root.as_bytes());
        assert_eq!(h.hash(), hash_domain(DOMAIN_BLOCK, &buf));
    }

    #[test]
    fn height_change_changes_hash() {
        // The load-bearing regression test: `notarize_digest` dropped the
        // explicit `height` field, so the header hash MUST bind it — same
        // payload and parent, different height => different hash.
        let base = header();
        let mut bumped = base;
        bumped.height += 1;
        assert_ne!(base.hash(), bumped.hash());
    }

    #[test]
    fn every_field_perturbs_the_hash() {
        let base = header().hash();
        assert_ne!(
            base,
            BlockHeader {
                height: 10,
                parent_hash: parent_hash(),
                payload_root: payload_root(),
            }
            .hash()
        );
        assert_ne!(
            base,
            BlockHeader {
                height: 9,
                parent_hash: payload_root(),
                payload_root: payload_root(),
            }
            .hash()
        );
        assert_ne!(
            base,
            BlockHeader {
                height: 9,
                parent_hash: parent_hash(),
                payload_root: parent_hash(),
            }
            .hash()
        );
        // Fields are position-bound: swapping the two hashes changes the hash.
        assert_ne!(
            base,
            BlockHeader {
                height: 9,
                parent_hash: payload_root(),
                payload_root: parent_hash(),
            }
            .hash()
        );
    }

    #[test]
    fn round_trips_through_codec() {
        let original = header();
        let bytes = codec::encode(&original).unwrap();
        let decoded: BlockHeader = codec::decode(&bytes).unwrap();
        assert_eq!(original, decoded);
        // Encoding is canonical: re-encoding the decoded value is identical.
        assert_eq!(bytes, codec::encode(&decoded).unwrap());
        // And the hash survives the round trip.
        assert_eq!(original.hash(), decoded.hash());
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        // Deterministic in-test LCG (no external rng) — the same fuzz pattern
        // as `crate::tests::never_panics_on_arbitrary_bytes`.
        let mut state = 0xDEAD_BEEF_CAFE_0516_u64;
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
            // The untrusted decode path is total: Result, never a panic.
            let _ = codec::decode::<BlockHeader>(&bytes);
        }
    }
}
