//! Segmentation-independent commitments to exact logical WAL prefixes.
//!
//! Segment trailers protect each file independently, but their chains restart
//! at rotation. A recovery manifest instead needs one stable commitment to the
//! logical record prefix, regardless of segment sizing or sparse-index policy.
//! This module folds the exact validated record frames in sequence order, then
//! commits the schema version, record count, and optional first/last sequence
//! boundaries into the final digest.

use types::Hash;

/// Prefix-commitment schema version written by this build.
pub const WAL_PREFIX_COMMITMENT_VERSION: u16 = 1;

/// Domain tag for segmentation-independent logical WAL prefix commitments.
pub const DOMAIN_WAL_PREFIX: &[u8] = crypto::DOMAIN_STORAGE_WAL_PREFIX;

const CHAIN_GENESIS_LABEL: &[u8] = b"chain-genesis";
const CHAIN_RECORD_LABEL: &[u8] = b"chain-record";
const COMMITMENT_LABEL: &[u8] = b"commitment";

/// A versioned commitment to an exact validated logical WAL prefix.
///
/// `first_sequence` and `last_sequence` are optional so an empty prefix cannot
/// collide with a real prefix whose boundary sequence is `0`. The digest also
/// commits all metadata fields; they are not unauthenticated annotations.
/// It does not by itself authenticate the WAL, establish freshness, or prevent
/// coherent rollback; those properties require a trusted external anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalPrefixCommitment {
    version: u16,
    record_count: u64,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    digest: Hash,
}

impl WalPrefixCommitment {
    /// Commitment to the empty WAL prefix.
    #[must_use]
    pub fn empty() -> Self {
        PrefixBuilder::new().finish()
    }

    /// Commitment schema version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Number of exact record frames in the committed prefix.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// First sequence in the prefix, or `None` when it is empty.
    #[must_use]
    pub const fn first_sequence(&self) -> Option<u64> {
        self.first_sequence
    }

    /// Last sequence in the prefix, or `None` when it is empty.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    /// Domain-separated digest binding the frames and every metadata field.
    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }
}

/// Incremental builder used by the durable log while walking raw frames.
pub(crate) struct PrefixBuilder {
    record_count: u64,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    chain: Hash,
}

impl PrefixBuilder {
    pub(crate) fn new() -> Self {
        let version = WAL_PREFIX_COMMITMENT_VERSION.to_le_bytes();
        Self {
            record_count: 0,
            first_sequence: None,
            last_sequence: None,
            chain: crypto::hash_domain_parts(DOMAIN_WAL_PREFIX, &[CHAIN_GENESIS_LABEL, &version]),
        }
    }

    pub(crate) fn push(&mut self, sequence: u64, exact_frame: &[u8]) -> Option<()> {
        self.record_count = self.record_count.checked_add(1)?;
        self.first_sequence.get_or_insert(sequence);
        self.last_sequence = Some(sequence);
        self.chain = crypto::hash_domain_parts(
            DOMAIN_WAL_PREFIX,
            &[CHAIN_RECORD_LABEL, self.chain.as_bytes(), exact_frame],
        );
        Some(())
    }

    pub(crate) fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    pub(crate) fn finish(self) -> WalPrefixCommitment {
        let version = WAL_PREFIX_COMMITMENT_VERSION.to_le_bytes();
        let count = self.record_count.to_le_bytes();
        let first = encode_optional_sequence(self.first_sequence);
        let last = encode_optional_sequence(self.last_sequence);
        let digest = crypto::hash_domain_parts(
            DOMAIN_WAL_PREFIX,
            &[
                COMMITMENT_LABEL,
                &version,
                &count,
                &first,
                &last,
                self.chain.as_bytes(),
            ],
        );
        WalPrefixCommitment {
            version: WAL_PREFIX_COMMITMENT_VERSION,
            record_count: self.record_count,
            first_sequence: self.first_sequence,
            last_sequence: self.last_sequence,
            digest,
        }
    }
}

fn encode_optional_sequence(sequence: Option<u64>) -> [u8; 9] {
    let mut encoded = [0u8; 9];
    if let Some(sequence) = sequence {
        encoded[0] = 1;
        encoded[1..].copy_from_slice(&sequence.to_le_bytes());
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_distinct_from_sequence_zero() {
        let empty = WalPrefixCommitment::empty();
        let mut zero = PrefixBuilder::new();
        zero.push(0, b"frame-zero").unwrap();
        let zero = zero.finish();
        assert_eq!(empty.first_sequence(), None);
        assert_eq!(empty.last_sequence(), None);
        assert_eq!(zero.first_sequence(), Some(0));
        assert_eq!(zero.last_sequence(), Some(0));
        assert_ne!(empty.digest(), zero.digest());
    }

    #[test]
    fn final_digest_binds_metadata_envelope() {
        let mut one = PrefixBuilder::new();
        one.push(7, b"same-frame").unwrap();
        let one = one.finish();

        let version = WAL_PREFIX_COMMITMENT_VERSION.to_le_bytes();
        let wrong_count = 2u64.to_le_bytes();
        let first = encode_optional_sequence(Some(7));
        let last = encode_optional_sequence(Some(7));
        let mut raw = PrefixBuilder::new();
        raw.push(7, b"same-frame").unwrap();
        let forged = crypto::hash_domain_parts(
            DOMAIN_WAL_PREFIX,
            &[
                COMMITMENT_LABEL,
                &version,
                &wrong_count,
                &first,
                &last,
                raw.chain.as_bytes(),
            ],
        );
        assert_ne!(one.digest(), forged);
    }
}
