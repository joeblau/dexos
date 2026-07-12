//! `storage` — deterministic command log and snapshot store for the DexOS
//! exchange kernel.
//!
//! The crate provides cooperating pieces:
//!
//! * [`Record`] / [`RecordRef`] — checksummed framing for opaque command
//!   payloads, with operational size caps that reject hostile lengths before
//!   allocation.
//! * [`SegmentedLog`] — in-memory append-only log with sparse indexes, segment
//!   binary search, and suffix-scaled truncation (useful for pure tests and
//!   engines that stage commands before durability).
//! * [`DurableLog`] — OS-backed segmented WAL with configurable
//!   [`SyncPolicy`] (`fdatasync` after ack under [`SyncPolicy::Always`], RPO=0),
//!   chain-hash segment integrity beyond CRC-32, crash recovery of torn tails,
//!   and deterministic index rebuild.
//! * [`Snapshot`] — versioned, self-verifying state checkpoint with
//!   [`Snapshot::install_atomic`] (temp → fsync → rename).
//! * [`replay`] — reconstruct engine state from a snapshot plus the log tail.
//!
//! The storage layer never interprets payloads; the engine supplies the `apply`
//! transition to [`replay`], keeping this crate dependent only on `types` and
//! `crypto` (plus `std` for the durable path).

#![forbid(unsafe_code)]

mod crc;
mod durable;
mod integrity;
mod limits;
mod log;
mod record;
mod replay;
mod snapshot;

pub use crc::crc32;
pub use durable::{DurableConfig, DurableError, DurableLog, DurableRecords, SyncPolicy};
pub use integrity::{chain_genesis, chain_mix, chain_over_records, DOMAIN_WAL_CHAIN};
pub use limits::{
    DEFAULT_INDEX_STRIDE, DEFAULT_MAX_RECORD_BYTES, DEFAULT_MAX_SNAPSHOT_STATE_BYTES,
    INTEGRITY_CHAIN_HASH, SEGMENT_TRAILER_LEN, SEGMENT_TRAILER_MAGIC, SEGMENT_TRAILER_VERSION,
};
pub use log::{LogError, Records, Segment, SegmentedLog, DEFAULT_SEGMENT_BYTES};
pub use record::{
    decode_ref_bounded, peek_declared_len, Record, RecordError, RecordRef, FRAME_OVERHEAD,
    PROTOCOL_VERSION,
};
pub use replay::replay;
pub use snapshot::{Snapshot, SnapshotError, SNAPSHOT_VERSION};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "storage";

/// Documented recovery-point objective for [`SyncPolicy::Always`].
///
/// After a successful [`DurableLog::append`] under `Always`, the record has been
/// `fdatasync`'d. Process crash or `kill -9` after that return cannot lose the
/// acknowledged record (RPO = 0 for acks).
pub const RPO_ALWAYS_SYNC: &str =
    "RPO=0 for acknowledged appends under SyncPolicy::Always (fdatasync per append)";

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash;

    /// A tiny in-test linear congruential generator (not `rand`/`proptest`) so
    /// the "property" tests are fully deterministic and reproducible.
    struct Lcg(u64);
    impl Lcg {
        fn new(seed: u64) -> Self {
            Self(seed ^ 0x9E37_79B9_7F4A_7C15)
        }
        fn next_u64(&mut self) -> u64 {
            // Numerical Recipes LCG constants.
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn upto(&mut self, bound: usize) -> usize {
            usize::try_from(self.next_u64()).unwrap() % bound
        }
        fn byte(&mut self) -> u8 {
            u8::try_from(self.next_u64() >> 56).unwrap_or(0)
        }
        fn bytes(&mut self, max_len: usize) -> Vec<u8> {
            let len = self.upto(max_len + 1);
            (0..len).map(|_| self.byte()).collect()
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "storage");
    }

    #[test]
    fn property_records_round_trip_through_log_in_order() {
        let mut lcg = Lcg::new(0xDEAD_BEEF);
        for _ in 0..200 {
            let count = 1 + lcg.upto(40);
            let mut log = SegmentedLog::new(1 + lcg.upto(256));

            let mut expected = Vec::new();
            let mut seq = lcg.next_u64() % 100;
            for _ in 0..count {
                let ts = lcg.next_u64();
                let cmd = u16::try_from(lcg.next_u64() % 65_536).unwrap();
                let payload = lcg.bytes(48);
                log.append(seq, ts, cmd, &payload).unwrap();
                expected.push((seq, ts, cmd, payload));
                // Consecutive sequence keeps both verify() and replay() happy.
                seq += 1;
            }

            // iter round-trips every record with an identical payload.
            let got: Vec<Record> = log.iter().map(|r| r.unwrap()).collect();
            assert_eq!(got.len(), expected.len());
            for (rec, (s, ts, cmd, pl)) in got.iter().zip(expected.iter()) {
                assert_eq!(rec.sequence, *s);
                assert_eq!(rec.timestamp, *ts);
                assert_eq!(rec.command_type, *cmd);
                assert_eq!(&rec.payload, pl);
            }

            // Whole-log verification: checksums + strictly consecutive sequences.
            log.verify().unwrap();

            // Replay applies exactly the appended records in order.
            let mut replayed = Vec::new();
            replay(&log, None, |rec| replayed.push(rec.sequence)).unwrap();
            let want: Vec<u64> = expected.iter().map(|(s, ..)| *s).collect();
            assert_eq!(replayed, want);
        }
    }

    #[test]
    fn property_single_bit_flip_is_detected() {
        let mut lcg = Lcg::new(0x0BAD_F00D);
        for _ in 0..300 {
            let rec = Record {
                protocol_version: PROTOCOL_VERSION,
                sequence: lcg.next_u64(),
                timestamp: lcg.next_u64(),
                command_type: u16::try_from(lcg.next_u64() % 65_536).unwrap(),
                payload: lcg.bytes(32),
            };
            let good = rec.encode().unwrap();
            let byte_idx = lcg.upto(good.len());
            let bit = u32::try_from(lcg.next_u64() % 8).unwrap();
            let mut bad = good.clone();
            bad[byte_idx] ^= 1u8 << bit;
            if bad == good {
                continue;
            }
            // A flip anywhere either fails to decode or decodes to a different
            // record; it must never masquerade as the original valid record.
            match Record::decode(&bad) {
                Err(_) => {}
                Ok((decoded, _)) => assert_ne!(decoded, rec),
            }
        }
    }

    #[test]
    fn never_panics_on_arbitrary_record_bytes() {
        let mut lcg = Lcg::new(0xF00D_CAFE);
        for _ in 0..2_000 {
            let bytes = lcg.bytes(96);
            let _ = Record::decode(&bytes);
        }
        for len in 0..(FRAME_OVERHEAD + 4) {
            let _ = Record::decode(&vec![0xFFu8; len]);
        }
    }

    #[test]
    fn never_panics_on_arbitrary_snapshot_bytes() {
        let mut lcg = Lcg::new(0x1234_5678_9ABC_DEF0);
        for _ in 0..2_000 {
            let bytes = lcg.bytes(128);
            let _ = Snapshot::decode(&bytes);
        }
        for len in 0..80 {
            let _ = Snapshot::decode(&vec![0u8; len]);
            let _ = Snapshot::decode(&vec![0xAAu8; len]);
        }
    }

    #[test]
    fn deterministic_replay_is_reproducible_across_snapshot_boundary() {
        // Build a log, snapshot at K, and confirm snapshot+tail replay matches a
        // full replay bit-for-bit.
        let mut log = SegmentedLog::new(48);
        for seq in 1..=12u64 {
            log.append(seq, seq, 1, format!("op{seq}").as_bytes())
                .unwrap();
        }

        // Full replay from genesis.
        let mut full = Hash::ZERO;
        replay(&log, None, |rec| full = mix(full, &rec.payload)).unwrap();

        // Reconstruct the state at K, snapshot it, then replay only the tail.
        let k = 7u64;
        let mut at_k = Hash::ZERO;
        replay(&log, None, |rec| {
            if rec.sequence <= k {
                at_k = mix(at_k, &rec.payload);
            }
        })
        .unwrap();
        let snap = Snapshot::new(at_k, k, b"opaque-state".to_vec());
        assert!(snap.verify(at_k));

        let mut tail = snap.state_root();
        replay(&log, Some(&snap), |rec| tail = mix(tail, &rec.payload)).unwrap();
        assert_eq!(tail, full);
    }

    #[test]
    fn crash_torn_tail_is_discarded_and_replay_matches() {
        // Root captured "before shutdown" at sequence 6.
        let mut log = SegmentedLog::new(40);
        for seq in 1..=6u64 {
            log.append(seq, seq, 1, format!("c{seq}").as_bytes())
                .unwrap();
        }
        let mut pre_crash = Hash::ZERO;
        replay(&log, None, |rec| pre_crash = mix(pre_crash, &rec.payload)).unwrap();

        // The writer then appends 7,8 and dies mid-record. Model recovery as
        // truncating back to the last durable checkpoint (6).
        log.append(7, 7, 1, b"c7").unwrap();
        log.append(8, 8, 1, b"c8-torn").unwrap();
        log.truncate_after(6).unwrap();

        let mut recovered = Hash::ZERO;
        replay(&log, None, |rec| recovered = mix(recovered, &rec.payload)).unwrap();
        assert_eq!(recovered, pre_crash);
        assert_eq!(log.last_sequence(), Some(6));
    }

    #[test]
    fn allocation_gates_cover_record_size_classes() {
        // 64 B, 4 KiB, and 1 MiB payload classes encode under the default max;
        // one byte over the max is rejected without requiring a successful
        // multi-gig decode path.
        for payload_len in [64usize, 4 * 1024, 1024 * 1024 - FRAME_OVERHEAD] {
            let payload = vec![0xABu8; payload_len];
            let rec = Record {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                timestamp: 0,
                command_type: 1,
                payload,
            };
            let bytes = rec.encode().unwrap();
            assert!(bytes.len() <= DEFAULT_MAX_RECORD_BYTES);
            let (back, n) = Record::decode(&bytes).unwrap();
            assert_eq!(n, bytes.len());
            assert_eq!(back.payload.len(), payload_len);
        }
        // Hostile length at the u32 max is rejected as ExceedsMax before any
        // attempt to allocate that many payload bytes.
        let mut hostile = vec![0u8; FRAME_OVERHEAD];
        hostile[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Record::decode(&hostile),
            Err(RecordError::ExceedsMax { .. })
        ));
    }

    /// Deterministic state-mixing function standing in for an engine transition.
    fn mix(acc: Hash, payload: &[u8]) -> Hash {
        let mut buf = acc.as_bytes().to_vec();
        buf.extend_from_slice(payload);
        crypto::hash_leaf(&buf)
    }
}
