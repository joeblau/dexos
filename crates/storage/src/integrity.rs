//! Cryptographic segment integrity beyond per-record CRC-32.
//!
//! Each durable segment commits a **chain-hash** over every framed record byte
//! range. The chain is domain-separated SHA-256 via `crypto::hash_domain`, so a
//! single flipped byte (after CRC recompute) still fails segment verification
//! unless the attacker also rewrites the sealed trailer tip.
//!
//! Domain tag: `dexos:storage:wal-chain:v1`.

use types::Hash;

/// Domain tag for WAL chain-hash mixing.
pub const DOMAIN_WAL_CHAIN: &[u8] = b"dexos:storage:wal-chain:v1";

/// Genesis chain tip for an empty record region.
#[must_use]
pub fn chain_genesis() -> Hash {
    crypto::hash_domain(DOMAIN_WAL_CHAIN, &[])
}

/// Mix one framed record into the running chain tip.
///
/// `frame` is the complete encoded record (length prefix through CRC).
#[must_use]
pub fn chain_mix(prev: Hash, frame: &[u8]) -> Hash {
    crypto::hash_domain_parts(DOMAIN_WAL_CHAIN, &[prev.as_bytes(), frame])
}

/// Fold every framed record in `records_region` into a chain tip.
///
/// Caller must already have verified per-record framing (or accept that a
/// structural decode failure aborts before this is called). This walks frames by
/// the declared length field without allocating payloads.
///
/// # Errors
/// Returns `None` if a length field is truncated or inconsistent.
pub fn chain_over_records(records_region: &[u8], max_record_bytes: usize) -> Option<Hash> {
    let mut tip = chain_genesis();
    let mut off = 0usize;
    while off < records_region.len() {
        if records_region.len() - off < 4 {
            return None;
        }
        let declared = u32::from_le_bytes(records_region[off..off + 4].try_into().ok()?);
        let total = usize::try_from(declared).ok()?;
        if total < crate::record::FRAME_OVERHEAD || total > max_record_bytes {
            return None;
        }
        if off.saturating_add(total) > records_region.len() {
            return None;
        }
        tip = chain_mix(tip, &records_region[off..off + total]);
        off += total;
    }
    Some(tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Record, PROTOCOL_VERSION};

    fn frame(seq: u64, payload: &[u8]) -> Vec<u8> {
        Record {
            protocol_version: PROTOCOL_VERSION,
            sequence: seq,
            timestamp: 0,
            command_type: 1,
            payload: payload.to_vec(),
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn chain_is_order_sensitive() {
        let a = frame(1, b"a");
        let b = frame(2, b"b");
        let mut tip_ab = chain_genesis();
        tip_ab = chain_mix(tip_ab, &a);
        tip_ab = chain_mix(tip_ab, &b);
        let mut tip_ba = chain_genesis();
        tip_ba = chain_mix(tip_ba, &b);
        tip_ba = chain_mix(tip_ba, &a);
        assert_ne!(tip_ab, tip_ba);
    }

    #[test]
    fn chain_over_records_matches_incremental() {
        let a = frame(1, b"hello");
        let b = frame(2, b"world");
        let mut region = a.clone();
        region.extend_from_slice(&b);
        let mut tip = chain_genesis();
        tip = chain_mix(tip, &a);
        tip = chain_mix(tip, &b);
        assert_eq!(
            chain_over_records(&region, crate::limits::DEFAULT_MAX_RECORD_BYTES),
            Some(tip)
        );
    }

    #[test]
    fn bit_flip_changes_tip() {
        let a = frame(1, b"payload");
        let mut bad = a.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        // Even if CRC is left wrong, chain over the byte range differs.
        assert_ne!(
            chain_mix(chain_genesis(), &a),
            chain_mix(chain_genesis(), &bad)
        );
    }
}
