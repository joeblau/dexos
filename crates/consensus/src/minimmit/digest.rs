//! Minimmit domain constants and the three signed digests
//! (`docs/CONSENSUS_MINIMMIT.md` §4.1).
//!
//! Every Minimmit vote signs a domain-separated digest built from
//! little-endian integer encodings through [`crypto::hash_domain`], so the
//! bytes are bit-identical across nodes and architectures — the exact builder
//! pattern used by every authenticated consensus message. There is **no**
//! separate certificate domain: a certificate's
//! [`Certificate::message`](super::Certificate) *is* the notarize / nullify
//! digest it aggregates. The retained [`crate::bft::DOMAIN_EXEC_COMMIT`]
//! execution-attestation digest remains separately domain-separated.

use crypto::hash_domain;
use types::Hash;

/// Domain tag for the leader's propose authentication digest
/// ([`propose_auth`]): binds the proposed block to its claimed parent.
pub const DOMAIN_PROPOSE: &[u8] = b"dexos:consensus:minimmit:propose:v1";

/// Domain tag for notarize vote digests ([`notarize_digest`]).
pub const DOMAIN_NOTARIZE: &[u8] = b"dexos:consensus:minimmit:notarize:v1";

/// Domain tag for nullify vote digests ([`nullify_digest`]).
pub const DOMAIN_NULLIFY: &[u8] = b"dexos:consensus:minimmit:nullify:v1";

/// The digest a `Notarize` vote signs — and the `message` a notarization
/// certificate aggregates.
///
/// Preimage: `epoch_le ‖ view_le ‖ block_hash[32]`. `block_hash` commits to
/// the block header **including its `height`**, so the digest safely drops the
/// height/phase fields: the block graph carries height. `epoch` is bound so no
/// vote or certificate can cross an epoch /
/// validator-set boundary.
#[must_use]
pub fn notarize_digest(epoch: u64, view: u64, block_hash: Hash) -> Hash {
    let mut buf = [0u8; 8 * 2 + 32];
    buf[0..8].copy_from_slice(&epoch.to_le_bytes());
    buf[8..16].copy_from_slice(&view.to_le_bytes());
    buf[16..48].copy_from_slice(block_hash.as_bytes());
    hash_domain(DOMAIN_NOTARIZE, &buf)
}

/// The digest a `Nullify` vote signs — and the `message` a nullification
/// certificate aggregates.
///
/// Preimage: `epoch_le ‖ view_le`. A nullify names no block: it votes to
/// abandon the view.
#[must_use]
pub fn nullify_digest(epoch: u64, view: u64) -> Hash {
    let mut buf = [0u8; 8 * 2];
    buf[0..8].copy_from_slice(&epoch.to_le_bytes());
    buf[8..16].copy_from_slice(&view.to_le_bytes());
    hash_domain(DOMAIN_NULLIFY, &buf)
}

/// The leader's propose authentication digest: binds `block_hash` to the
/// claimed parent so equivocation / fork evidence is self-authenticating.
///
/// Preimage: `epoch_le ‖ view_le ‖ block_hash[32] ‖ parent_hash[32] ‖
/// parent_view_le`. The leader signs this **in addition to** the
/// [`notarize_digest`] (its propose doubles as its notarize vote); followers
/// verify both. `parent_view` may be the genesis sentinel `⊥ = u64::MAX`
/// (`docs/CONSENSUS_MINIMMIT.md` §4.2) — it hashes like any other value here;
/// rejecting it as a *real* view is the wire layer's job.
#[must_use]
pub fn propose_auth(
    epoch: u64,
    view: u64,
    block_hash: Hash,
    parent_hash: Hash,
    parent_view: u64,
) -> Hash {
    let mut buf = [0u8; 8 * 3 + 32 * 2];
    buf[0..8].copy_from_slice(&epoch.to_le_bytes());
    buf[8..16].copy_from_slice(&view.to_le_bytes());
    buf[16..48].copy_from_slice(block_hash.as_bytes());
    buf[48..80].copy_from_slice(parent_hash.as_bytes());
    buf[80..88].copy_from_slice(&parent_view.to_le_bytes());
    hash_domain(DOMAIN_PROPOSE, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bft::DOMAIN_EXEC_COMMIT;

    const EPOCH: u64 = 7;
    const VIEW: u64 = 42;

    fn block_hash() -> Hash {
        Hash::from_bytes([0xAB; 32])
    }

    fn parent_hash() -> Hash {
        Hash::from_bytes([0xCD; 32])
    }

    #[test]
    fn domain_strings_are_pinned_and_pairwise_distinct() {
        // Exact wire-format values from docs/CONSENSUS_MINIMMIT.md §4.1 —
        // changing any byte is a consensus-breaking change.
        assert_eq!(DOMAIN_PROPOSE, b"dexos:consensus:minimmit:propose:v1");
        assert_eq!(DOMAIN_NOTARIZE, b"dexos:consensus:minimmit:notarize:v1");
        assert_eq!(DOMAIN_NULLIFY, b"dexos:consensus:minimmit:nullify:v1");
        // Pairwise distinct among themselves and from retained domains.
        let domains: [&[u8]; 5] = [
            DOMAIN_PROPOSE,
            DOMAIN_NOTARIZE,
            DOMAIN_NULLIFY,
            super::super::block::DOMAIN_BLOCK,
            DOMAIN_EXEC_COMMIT,
        ];
        for (i, a) in domains.iter().enumerate() {
            for b in &domains[i + 1..] {
                assert_ne!(a, b, "consensus domains must be pairwise distinct");
            }
        }
    }

    #[test]
    fn digests_are_deterministic() {
        assert_eq!(
            notarize_digest(EPOCH, VIEW, block_hash()),
            notarize_digest(EPOCH, VIEW, block_hash()),
        );
        assert_eq!(nullify_digest(EPOCH, VIEW), nullify_digest(EPOCH, VIEW));
        assert_eq!(
            propose_auth(EPOCH, VIEW, block_hash(), parent_hash(), 41),
            propose_auth(EPOCH, VIEW, block_hash(), parent_hash(), 41),
        );
    }

    #[test]
    fn preimage_layout_is_locked() {
        // Rebuild each preimage by hand (field order + little-endian) and
        // assert the functions hash exactly it: locks the byte layout against
        // accidental reordering or endianness drift.
        let mut notarize = Vec::new();
        notarize.extend_from_slice(&EPOCH.to_le_bytes());
        notarize.extend_from_slice(&VIEW.to_le_bytes());
        notarize.extend_from_slice(block_hash().as_bytes());
        assert_eq!(
            notarize_digest(EPOCH, VIEW, block_hash()),
            hash_domain(DOMAIN_NOTARIZE, &notarize),
        );

        let mut nullify = Vec::new();
        nullify.extend_from_slice(&EPOCH.to_le_bytes());
        nullify.extend_from_slice(&VIEW.to_le_bytes());
        assert_eq!(
            nullify_digest(EPOCH, VIEW),
            hash_domain(DOMAIN_NULLIFY, &nullify),
        );

        let mut propose = Vec::new();
        propose.extend_from_slice(&EPOCH.to_le_bytes());
        propose.extend_from_slice(&VIEW.to_le_bytes());
        propose.extend_from_slice(block_hash().as_bytes());
        propose.extend_from_slice(parent_hash().as_bytes());
        propose.extend_from_slice(&41u64.to_le_bytes());
        assert_eq!(
            propose_auth(EPOCH, VIEW, block_hash(), parent_hash(), 41),
            hash_domain(DOMAIN_PROPOSE, &propose),
        );
    }

    #[test]
    fn digests_are_domain_separated_for_aligned_inputs() {
        let notarize = notarize_digest(EPOCH, VIEW, block_hash());
        let nullify = nullify_digest(EPOCH, VIEW);
        let propose = propose_auth(EPOCH, VIEW, block_hash(), parent_hash(), 41);
        assert_ne!(notarize, nullify);
        assert_ne!(notarize, propose);
        assert_ne!(nullify, propose);
    }

    #[test]
    fn every_field_perturbs_its_digest() {
        let notarize = notarize_digest(EPOCH, VIEW, block_hash());
        assert_ne!(notarize, notarize_digest(EPOCH + 1, VIEW, block_hash()));
        assert_ne!(notarize, notarize_digest(EPOCH, VIEW + 1, block_hash()));
        assert_ne!(notarize, notarize_digest(EPOCH, VIEW, parent_hash()));

        let nullify = nullify_digest(EPOCH, VIEW);
        assert_ne!(nullify, nullify_digest(EPOCH + 1, VIEW));
        assert_ne!(nullify, nullify_digest(EPOCH, VIEW + 1));
        // Epoch and view are not interchangeable (LE positions differ).
        assert_ne!(nullify_digest(EPOCH, VIEW), nullify_digest(VIEW, EPOCH));

        let propose = propose_auth(EPOCH, VIEW, block_hash(), parent_hash(), 41);
        assert_ne!(
            propose,
            propose_auth(EPOCH + 1, VIEW, block_hash(), parent_hash(), 41)
        );
        assert_ne!(
            propose,
            propose_auth(EPOCH, VIEW + 1, block_hash(), parent_hash(), 41)
        );
        assert_ne!(
            propose,
            propose_auth(EPOCH, VIEW, parent_hash(), parent_hash(), 41)
        );
        assert_ne!(
            propose,
            propose_auth(EPOCH, VIEW, block_hash(), block_hash(), 41)
        );
        assert_ne!(
            propose,
            propose_auth(EPOCH, VIEW, block_hash(), parent_hash(), 40)
        );
        // The genesis ⊥ sentinel (u64::MAX) hashes distinctly from real views.
        assert_ne!(
            propose,
            propose_auth(EPOCH, VIEW, block_hash(), parent_hash(), u64::MAX)
        );
    }
}
