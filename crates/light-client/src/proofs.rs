//! Account and market state-proof verification against a verified checkpoint.
//!
//! A light client answers balance / position / market queries by verifying an
//! incremental Merkle proof (produced by the `state-tree` crate) against a
//! *verified* checkpoint's `state_root`. The returned [`VerifiedValue`] is only
//! [`Verification::Verified`] when the proof checks against the current tip; a
//! proof that checks only against a superseded root is labeled
//! [`Verification::Stale`]; anything else — including a tampered leaf, path, or
//! root, or a query made before any checkpoint verified — is
//! [`Verification::Unverified`]. There is no path that upgrades a failed proof.

use crypto::hash_node;
use state_tree::{verify_account, verify_market};
use types::{AccountId, Hash, MarketId};

use crate::sync::ShardSync;
use crate::verification::VerifiedValue;

/// Fold a leaf up its sibling path to a sub-tree root, mirroring the `state-tree`
/// proof layout. Total: returns `None` for a path that cannot address `index`.
fn fold_subtree(index: usize, leaf: Hash, siblings: &[Hash]) -> Option<Hash> {
    if siblings.len() >= usize::BITS as usize {
        return None;
    }
    if index >> siblings.len() != 0 {
        return None;
    }
    let mut current = leaf;
    let mut idx = index;
    for sibling in siblings {
        current = if idx & 1 == 0 {
            hash_node(current, *sibling)
        } else {
            hash_node(*sibling, current)
        };
        idx >>= 1;
    }
    Some(current)
}

/// Whether `proof` proves account `id`'s leaf is empty (`Hash::ZERO`) — i.e. the
/// account is absent — against `root`. The account sub-tree is the left child of
/// the shard combine; the final proof element is the market sub-tree root.
fn account_absence_verifies(root: Hash, id: AccountId, proof: &[Hash]) -> bool {
    let Ok(index) = id.index() else {
        return false;
    };
    let Some((market_root, path)) = proof.split_last() else {
        return false;
    };
    let Some(account_root) = fold_subtree(index, Hash::ZERO, path) else {
        return false;
    };
    hash_node(account_root, *market_root) == root
}

/// Whether `proof` proves market `id`'s leaf is empty against `root`. Markets are
/// the right child; the final proof element is the account sub-tree root.
fn market_absence_verifies(root: Hash, id: MarketId, proof: &[Hash]) -> bool {
    let Ok(index) = id.index() else {
        return false;
    };
    let Some((account_root, path)) = proof.split_last() else {
        return false;
    };
    let Some(market_root) = fold_subtree(index, Hash::ZERO, path) else {
        return false;
    };
    hash_node(*account_root, market_root) == root
}

/// Verify an account leaf against `sync`'s verified chain.
///
/// Returns the leaf bytes wrapped with the strongest status they earn:
/// verified against the tip, stale against an older verified root, or
/// unverified. Never panics on adversarial `proof` / `leaf_bytes`.
#[must_use]
pub fn verify_account_value(
    sync: &ShardSync,
    id: AccountId,
    leaf_bytes: &[u8],
    proof: &[types::Hash],
) -> VerifiedValue<Vec<u8>> {
    if let Some(tip) = sync.verified_tip() {
        if verify_account(tip.state_root, id, leaf_bytes, proof) {
            return VerifiedValue::verified(leaf_bytes.to_vec(), tip.height);
        }
        for (height, root) in sync.accepted_roots() {
            if verify_account(root, id, leaf_bytes, proof) {
                return VerifiedValue::stale(leaf_bytes.to_vec(), height);
            }
        }
    }
    VerifiedValue::unverified(leaf_bytes.to_vec())
}

/// Verify a market leaf against `sync`'s verified chain. See
/// [`verify_account_value`] for the status semantics.
#[must_use]
pub fn verify_market_value(
    sync: &ShardSync,
    id: MarketId,
    leaf_bytes: &[u8],
    proof: &[types::Hash],
) -> VerifiedValue<Vec<u8>> {
    if let Some(tip) = sync.verified_tip() {
        if verify_market(tip.state_root, id, leaf_bytes, proof) {
            return VerifiedValue::verified(leaf_bytes.to_vec(), tip.height);
        }
        for (height, root) in sync.accepted_roots() {
            if verify_market(root, id, leaf_bytes, proof) {
                return VerifiedValue::stale(leaf_bytes.to_vec(), height);
            }
        }
    }
    VerifiedValue::unverified(leaf_bytes.to_vec())
}

/// Verify a *non-inclusion* (absence) proof for an account against `sync`'s
/// verified chain. The wrapped `bool` is `true` when the account is provably
/// absent (its leaf is empty) at the reported height. A present account's proof
/// will not satisfy this, so inclusion and non-inclusion are distinguished.
#[must_use]
pub fn verify_account_absence(
    sync: &ShardSync,
    id: AccountId,
    proof: &[Hash],
) -> VerifiedValue<bool> {
    if let Some(tip) = sync.verified_tip() {
        if account_absence_verifies(tip.state_root, id, proof) {
            return VerifiedValue::verified(true, tip.height);
        }
        for (height, root) in sync.accepted_roots() {
            if account_absence_verifies(root, id, proof) {
                return VerifiedValue::stale(true, height);
            }
        }
    }
    VerifiedValue::unverified(false)
}

/// Verify a non-inclusion (absence) proof for a market. See
/// [`verify_account_absence`].
#[must_use]
pub fn verify_market_absence(
    sync: &ShardSync,
    id: MarketId,
    proof: &[Hash],
) -> VerifiedValue<bool> {
    if let Some(tip) = sync.verified_tip() {
        if market_absence_verifies(tip.state_root, id, proof) {
            return VerifiedValue::verified(true, tip.height);
        }
        for (height, root) in sync.accepted_roots() {
            if market_absence_verifies(root, id, proof) {
                return VerifiedValue::stale(true, height);
            }
        }
    }
    VerifiedValue::unverified(false)
}
