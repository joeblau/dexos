//! Versioned, self-verifying state snapshots.
//!
//! A [`Snapshot`] pairs an engine state root (`types::Hash`) with the opaque
//! serialized state bytes and the sequence number the state reflects. It is
//! self-verifying in two independent ways:
//!
//! * a CRC-32 over the whole encoded frame catches truncation and bit flips at
//!   decode time, and
//! * a domain-separated content digest of the state bytes (via `crypto`) is
//!   embedded and re-checked, so a snapshot cannot silently disagree with its
//!   own payload.
//!
//! [`Snapshot::verify`] additionally compares the embedded state root with a
//! caller-supplied expected root. This checks the envelope binding only: a
//! higher layer must decode state, validate it, recompute the engine root, and
//! compare against an authenticated checkpoint before accepting a restore.
//!
//! On disk, snapshots are published with [`Snapshot::install_atomic`]: reserve
//! a unique sibling temp file, write and `fsync` it, `rename` it into place, then
//! `fsync` the immediate parent directory on Unix. For power-loss durability,
//! production callers must pre-provision the parent hierarchy durably; syncing
//! the leaf parent cannot publish ancestors newly created by `create_dir_all`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crc::crc32;
use crate::fsutil::sync_dir;
use crate::limits::DEFAULT_MAX_SNAPSHOT_STATE_BYTES;
use types::Hash;

/// Snapshot format version written by this build.
pub const SNAPSHOT_VERSION: u16 = 1;

const VER_SIZE: usize = 2;
const SEQ_SIZE: usize = 8;
const ROOT_SIZE: usize = 32;
const DIGEST_SIZE: usize = 32;
const LEN_SIZE: usize = 4;
const CRC_SIZE: usize = 4;
const HEADER_SIZE: usize = VER_SIZE + SEQ_SIZE + ROOT_SIZE + DIGEST_SIZE + LEN_SIZE;

/// Monotonic per-process nonce for atomically reserved snapshot temp files.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Bound stale-file collision retries so a hostile directory cannot spin us forever.
const MAX_TEMP_FILE_ATTEMPTS: usize = 128;

/// Fixed overhead of an encoded snapshot, excluding the state bytes.
const SNAP_OVERHEAD: usize = VER_SIZE + SEQ_SIZE + ROOT_SIZE + DIGEST_SIZE + LEN_SIZE + CRC_SIZE;

/// Errors produced while decoding, verifying, or installing a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// The buffer is smaller than the minimum encoded snapshot.
    #[error("snapshot buffer too short: have {have}, need at least {need}")]
    TooShort {
        /// Bytes available.
        have: usize,
        /// Minimum bytes required.
        need: usize,
    },
    /// The declared state length is inconsistent with the buffer.
    #[error("snapshot declared state length {declared} invalid for {available} available bytes")]
    BadLength {
        /// State length declared in the header.
        declared: usize,
        /// Bytes actually available after the header.
        available: usize,
    },
    /// The declared state length exceeds the operational maximum.
    #[error("snapshot state length {declared} exceeds max {max}")]
    ExceedsMax {
        /// State length declared in the header.
        declared: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Bytes followed the one exact frame declared by the header.
    #[error(
        "snapshot has trailing bytes: expected exactly {expected} bytes, observed at least {actual_at_least}"
    )]
    TrailingBytes {
        /// Exact encoded frame length declared by the header.
        expected: usize,
        /// Lower bound on bytes observed (streaming stops after one sentinel).
        actual_at_least: usize,
    },
    /// The state is larger than can be framed in a `u32` length field.
    #[error("snapshot state of {0} bytes exceeds maximum framable size")]
    StateTooLarge(usize),
    /// The frame CRC did not match (truncation or corruption).
    #[error("snapshot checksum mismatch: stored {stored:#010x}, computed {computed:#010x}")]
    ChecksumMismatch {
        /// Checksum read from the frame.
        stored: u32,
        /// Recomputed checksum.
        computed: u32,
    },
    /// The embedded content digest did not match the state bytes.
    #[error("snapshot content digest mismatch")]
    DigestMismatch,
    /// The snapshot version is not understood by this build.
    #[error("unsupported snapshot version {0}")]
    UnsupportedVersion(u16),
    /// Filesystem I/O failed during load or atomic install.
    #[error("snapshot I/O error: {0}")]
    Io(#[from] io::Error),
}

impl PartialEq for SnapshotError {
    fn eq(&self, other: &Self) -> bool {
        use SnapshotError::*;
        match (self, other) {
            (TooShort { have: a, need: b }, TooShort { have: c, need: d }) => a == c && b == d,
            (
                BadLength {
                    declared: a,
                    available: b,
                },
                BadLength {
                    declared: c,
                    available: d,
                },
            ) => a == c && b == d,
            (
                ExceedsMax {
                    declared: a,
                    max: b,
                },
                ExceedsMax {
                    declared: c,
                    max: d,
                },
            ) => a == c && b == d,
            (
                TrailingBytes {
                    expected: a,
                    actual_at_least: b,
                },
                TrailingBytes {
                    expected: c,
                    actual_at_least: d,
                },
            ) => a == c && b == d,
            (StateTooLarge(a), StateTooLarge(b)) => a == b,
            (
                ChecksumMismatch {
                    stored: a,
                    computed: b,
                },
                ChecksumMismatch {
                    stored: c,
                    computed: d,
                },
            ) => a == c && b == d,
            (DigestMismatch, DigestMismatch) => true,
            (UnsupportedVersion(a), UnsupportedVersion(b)) => a == b,
            (Io(a), Io(b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}

impl Eq for SnapshotError {}

/// A versioned, self-verifying state snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    version: u16,
    state_root: Hash,
    last_sequence: u64,
    content_digest: Hash,
    state: Vec<u8>,
}

/// Domain-separated content digest of snapshot state bytes.
fn digest(state: &[u8]) -> Hash {
    crypto::hash_leaf(state)
}

impl Snapshot {
    /// Build a snapshot for `state` reflecting the engine at `last_sequence`
    /// with committed root `state_root`.
    ///
    /// The content digest is computed once here and re-verified on every decode
    /// and [`Self::verify`] call.
    #[must_use]
    pub fn new(state_root: Hash, last_sequence: u64, state: Vec<u8>) -> Self {
        let content_digest = digest(&state);
        Self {
            version: SNAPSHOT_VERSION,
            state_root,
            last_sequence,
            content_digest,
            state,
        }
    }

    /// Format version of this snapshot.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// The committed engine state root captured in this snapshot.
    #[must_use]
    pub const fn state_root(&self) -> Hash {
        self.state_root
    }

    /// Sequence number the snapshot state reflects.
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Borrow the opaque serialized state bytes.
    #[must_use]
    pub fn state(&self) -> &[u8] {
        &self.state
    }

    /// Domain-separated digest embedded for self-consistency of `state`.
    ///
    /// This is not an external trust anchor: a party able to replace the file
    /// can replace both state and digest. Authoritative recovery must bind it
    /// through a trusted manifest/checkpoint and recompute the engine root.
    #[must_use]
    pub const fn content_digest(&self) -> Hash {
        self.content_digest
    }

    /// Verify the snapshot against an `expected_root`.
    ///
    /// Returns `true` only if the version is supported, the embedded content
    /// digest matches the state bytes, and the embedded state root equals
    /// `expected_root`. This deliberately total predicate checks the envelope;
    /// it does not decode state or recompute an engine root.
    #[must_use]
    pub fn verify(&self, expected_root: Hash) -> bool {
        self.version == SNAPSHOT_VERSION
            && self.content_digest == digest(&self.state)
            && self.state_root == expected_root
    }

    /// Encode the snapshot to a self-describing byte frame.
    ///
    /// # Errors
    /// Returns [`SnapshotError::StateTooLarge`] if the state does not fit in the
    /// `u32` length field.
    pub fn encode(&self) -> Result<Vec<u8>, SnapshotError> {
        let state_len = u32::try_from(self.state.len())
            .map_err(|_| SnapshotError::StateTooLarge(self.state.len()))?;
        let mut buf = Vec::with_capacity(SNAP_OVERHEAD + self.state.len());
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.last_sequence.to_le_bytes());
        buf.extend_from_slice(self.state_root.as_bytes());
        buf.extend_from_slice(self.content_digest.as_bytes());
        buf.extend_from_slice(&state_len.to_le_bytes());
        buf.extend_from_slice(&self.state);
        let checksum = crc32(&buf);
        buf.extend_from_slice(&checksum.to_le_bytes());
        Ok(buf)
    }

    /// Decode a snapshot from a byte frame using [`DEFAULT_MAX_SNAPSHOT_STATE_BYTES`].
    ///
    /// # Errors
    /// Returns a [`SnapshotError`] describing the first problem found.
    pub fn decode(bytes: &[u8]) -> Result<Snapshot, SnapshotError> {
        Self::decode_bounded(bytes, DEFAULT_MAX_SNAPSHOT_STATE_BYTES)
    }

    /// Decode a snapshot, rejecting state lengths above `max_state_bytes` before
    /// allocating the state buffer.
    ///
    /// # Errors
    /// Returns a [`SnapshotError`] describing the first problem found.
    pub fn decode_bounded(bytes: &[u8], max_state_bytes: usize) -> Result<Snapshot, SnapshotError> {
        if bytes.len() < SNAP_OVERHEAD {
            return Err(SnapshotError::TooShort {
                have: bytes.len(),
                need: SNAP_OVERHEAD,
            });
        }

        // Verify the frame checksum first: it covers everything but the CRC.
        let crc_start = bytes.len() - CRC_SIZE;
        let stored =
            u32::from_le_bytes(take::<4>(bytes, crc_start).ok_or(SnapshotError::TooShort {
                have: bytes.len(),
                need: SNAP_OVERHEAD,
            })?);
        let computed = crc32(&bytes[..crc_start]);
        if stored != computed {
            return Err(SnapshotError::ChecksumMismatch { stored, computed });
        }

        let mut off = 0usize;
        let version = u16::from_le_bytes(field::<2>(bytes, &mut off)?);
        let last_sequence = u64::from_le_bytes(field::<8>(bytes, &mut off)?);
        let state_root = Hash::from_bytes(field::<32>(bytes, &mut off)?);
        let content_digest = Hash::from_bytes(field::<32>(bytes, &mut off)?);
        let declared = u32::from_le_bytes(field::<4>(bytes, &mut off)?);
        let state_len = usize::try_from(declared).map_err(|_| SnapshotError::BadLength {
            declared: usize::MAX,
            available: crc_start.saturating_sub(off),
        })?;

        if state_len > max_state_bytes {
            return Err(SnapshotError::ExceedsMax {
                declared: state_len,
                max: max_state_bytes,
            });
        }

        let available = crc_start.saturating_sub(off);
        if state_len != available {
            return Err(SnapshotError::BadLength {
                declared: state_len,
                available,
            });
        }
        let state = bytes[off..crc_start].to_vec();

        if version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }
        if content_digest != digest(&state) {
            return Err(SnapshotError::DigestMismatch);
        }

        Ok(Snapshot {
            version,
            state_root,
            last_sequence,
            content_digest,
            state,
        })
    }

    /// Load and decode a snapshot file from `path`.
    ///
    /// # Errors
    /// Returns I/O or decode errors.
    pub fn load(path: &Path) -> Result<Snapshot, SnapshotError> {
        Self::load_bounded(path, DEFAULT_MAX_SNAPSHOT_STATE_BYTES)
    }

    /// Load a snapshot while bounding all reads and allocation by the state
    /// length declared in its fixed header.
    ///
    /// Only the fixed header is read first. The declared state length is
    /// rejected before payload allocation when it exceeds `max_state_bytes`;
    /// then exactly the declared state plus CRC and one sentinel byte are read.
    /// The sentinel makes a concurrently grown or maliciously padded file fail
    /// closed without reading the unbounded suffix.
    ///
    /// # Errors
    /// Returns I/O or decode errors, including [`SnapshotError::ExceedsMax`]
    /// before state allocation and [`SnapshotError::TrailingBytes`] when the
    /// file contains anything after its one declared frame.
    pub fn load_bounded(path: &Path, max_state_bytes: usize) -> Result<Snapshot, SnapshotError> {
        let mut file = File::open(path)?;
        let mut header = [0u8; HEADER_SIZE];
        let mut header_read = 0usize;
        while header_read < HEADER_SIZE {
            let count = file.read(&mut header[header_read..])?;
            if count == 0 {
                return Err(SnapshotError::TooShort {
                    have: header_read,
                    need: SNAP_OVERHEAD,
                });
            }
            header_read += count;
        }

        let declared = u32::from_le_bytes(
            take::<LEN_SIZE>(&header, HEADER_SIZE - LEN_SIZE).ok_or(SnapshotError::TooShort {
                have: HEADER_SIZE,
                need: HEADER_SIZE,
            })?,
        );
        let state_len = usize::try_from(declared).map_err(|_| SnapshotError::BadLength {
            declared: usize::MAX,
            available: 0,
        })?;
        if state_len > max_state_bytes {
            return Err(SnapshotError::ExceedsMax {
                declared: state_len,
                max: max_state_bytes,
            });
        }

        let expected = SNAP_OVERHEAD
            .checked_add(state_len)
            .ok_or(SnapshotError::StateTooLarge(state_len))?;
        let tail_len = state_len
            .checked_add(CRC_SIZE)
            .ok_or(SnapshotError::StateTooLarge(state_len))?;
        let read_limit = u64::try_from(tail_len)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut bytes = Vec::with_capacity(expected.saturating_add(1));
        bytes.extend_from_slice(&header);
        file.take(read_limit).read_to_end(&mut bytes)?;
        let observed_tail = bytes.len().saturating_sub(HEADER_SIZE);

        if observed_tail < tail_len {
            return Err(SnapshotError::TooShort {
                have: bytes.len(),
                need: expected,
            });
        }
        if observed_tail > tail_len {
            return Err(SnapshotError::TrailingBytes {
                expected,
                actual_at_least: bytes.len(),
            });
        }

        Self::decode_bounded(&bytes, max_state_bytes)
    }

    /// Atomically install this snapshot at `path`.
    ///
    /// Atomically reserves a unique sibling temporary file without following
    /// pre-existing symlinks, writes and `fsync`s it, renames it into place,
    /// then `fsync`s the immediate parent directory on Unix. A crash mid-write
    /// leaves either the previous snapshot or a temp file — never a torn file
    /// at `path`.
    ///
    /// For full power-loss durability, the parent hierarchy must already have
    /// been durably provisioned. This method creates missing directories for
    /// convenience but does not fsync every newly created ancestor.
    ///
    /// # Errors
    /// Returns encode or I/O errors.
    pub fn install_atomic(&self, path: &Path) -> Result<(), SnapshotError> {
        let bytes = self.encode()?;
        let parent = snapshot_parent(path);
        fs::create_dir_all(parent)?;

        let (tmp, mut file) = create_temp_sibling(path)?;
        if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(error.into());
        }
        drop(file);

        if let Err(error) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(error.into());
        }
        sync_dir(parent)?;
        Ok(())
    }
}

/// Immediate directory containing `path`; a bare relative filename lives in
/// the current directory rather than in the invalid empty path returned by
/// `Path::parent`.
fn snapshot_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Atomically reserve a unique sibling temp file for an install.
fn create_temp_sibling(path: &Path) -> io::Result<(PathBuf, File)> {
    create_temp_sibling_with(path, std::process::id(), &TEMP_FILE_COUNTER)
}

/// Atomically reserve a sibling temp file, retrying stale-name collisions.
fn create_temp_sibling_with(
    path: &Path,
    process_id: u32,
    counter: &AtomicU64,
) -> io::Result<(PathBuf, File)> {
    let mut last_collision = None;
    for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
        let nonce = counter.fetch_add(1, Ordering::Relaxed);
        let tmp = temp_sibling_path(path, process_id, nonce);
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }

    Err(last_collision.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a unique snapshot temp file",
        )
    }))
}

/// Construct one PID/counter-qualified sibling temp path.
fn temp_sibling_path(path: &Path, process_id: u32, nonce: u64) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "snapshot".into());
    name.push(format!(".tmp.{process_id}.{nonce}"));
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

/// Copy `N` bytes at `at`, returning `None` if out of range.
fn take<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at + N).and_then(|s| s.try_into().ok())
}

/// Read a fixed `N`-byte field at `*off`, advancing the cursor.
fn field<const N: usize>(bytes: &[u8], off: &mut usize) -> Result<[u8; N], SnapshotError> {
    let out = take::<N>(bytes, *off).ok_or(SnapshotError::TooShort {
        have: bytes.len(),
        need: *off + N,
    })?;
    *off += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("dexos-snap-{label}-{nanos}"))
    }

    fn temp_siblings(dir: &Path, destination: &Path) -> Vec<PathBuf> {
        let prefix = format!(
            "{}.tmp.",
            destination
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect()
    }

    #[test]
    fn round_trip_and_verify() {
        let snap = Snapshot::new(root(7), 42, b"engine-state".to_vec());
        let bytes = snap.encode().unwrap();
        let back = Snapshot::decode(&bytes).unwrap();
        assert_eq!(back, snap);
        assert_eq!(back.last_sequence(), 42);
        assert_eq!(back.state(), b"engine-state");
        assert_eq!(back.content_digest(), digest(b"engine-state"));
        assert!(back.verify(root(7)));
    }

    #[test]
    fn verify_rejects_wrong_root() {
        let snap = Snapshot::new(root(1), 5, b"s".to_vec());
        assert!(snap.verify(root(1)));
        assert!(!snap.verify(root(2)));
        assert!(!snap.verify(Hash::ZERO));
    }

    #[test]
    fn empty_state_round_trips() {
        let snap = Snapshot::new(Hash::ZERO, 0, Vec::new());
        let bytes = snap.encode().unwrap();
        let back = Snapshot::decode(&bytes).unwrap();
        assert!(back.verify(Hash::ZERO));
    }

    #[test]
    fn bit_flip_fails_checksum() {
        let snap = Snapshot::new(root(3), 9, b"important-state".to_vec());
        let mut bytes = snap.encode().unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        assert!(matches!(
            Snapshot::decode(&bytes),
            Err(SnapshotError::ChecksumMismatch { .. }) | Err(SnapshotError::DigestMismatch)
        ));
    }

    #[test]
    fn truncation_fails_typed() {
        let snap = Snapshot::new(root(3), 9, b"important-state".to_vec());
        let bytes = snap.encode().unwrap();
        for cut in 0..bytes.len() {
            // Every truncation is a typed error, never a panic.
            assert!(Snapshot::decode(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn tampered_state_length_rejected() {
        let snap = Snapshot::new(root(3), 9, b"abcdef".to_vec());
        let mut bytes = snap.encode().unwrap();
        // The length field sits after ver+seq+root+digest.
        let len_off = VER_SIZE + SEQ_SIZE + ROOT_SIZE + DIGEST_SIZE;
        let bogus = u32::try_from(bytes.len()).unwrap();
        bytes[len_off..len_off + 4].copy_from_slice(&bogus.to_le_bytes());
        // Recompute CRC so we exercise the length check, not the CRC check.
        let crc_start = bytes.len() - CRC_SIZE;
        let crc = crc32(&bytes[..crc_start]);
        bytes[crc_start..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            Snapshot::decode(&bytes),
            Err(SnapshotError::BadLength { .. })
        ));
    }

    #[test]
    fn hostile_state_length_exceeds_max() {
        let snap = Snapshot::new(root(1), 1, b"tiny".to_vec());
        let mut bytes = snap.encode().unwrap();
        let len_off = VER_SIZE + SEQ_SIZE + ROOT_SIZE + DIGEST_SIZE;
        // Claim a huge state; recompute CRC so ExceedsMax (not checksum) fires.
        // available bytes after header still = 4, so BadLength would also fire
        // if we checked equality first — we check max before equality.
        bytes[len_off..len_off + 4].copy_from_slice(&1_000_000u32.to_le_bytes());
        let crc_start = bytes.len() - CRC_SIZE;
        let crc = crc32(&bytes[..crc_start]);
        bytes[crc_start..].copy_from_slice(&crc.to_le_bytes());
        match Snapshot::decode_bounded(&bytes, 8) {
            Err(SnapshotError::ExceedsMax { declared, max }) => {
                assert_eq!(declared, 1_000_000);
                assert_eq!(max, 8);
            }
            other => panic!("expected ExceedsMax, got {other:?}"),
        }
    }

    #[test]
    fn bounded_load_accepts_zero_and_exact_limit() {
        let dir = temp_path("bounded-limits");
        fs::create_dir_all(&dir).unwrap();

        let empty_path = dir.join("empty.snap");
        Snapshot::new(root(1), 0, Vec::new())
            .install_atomic(&empty_path)
            .unwrap();
        assert!(Snapshot::load_bounded(&empty_path, 0).is_ok());

        let exact_path = dir.join("exact.snap");
        Snapshot::new(root(2), 7, vec![0xAB; 8])
            .install_atomic(&exact_path)
            .unwrap();
        let loaded = Snapshot::load_bounded(&exact_path, 8).unwrap();
        assert_eq!(loaded.state().len(), 8);
        assert!(matches!(
            Snapshot::load_bounded(&exact_path, 7),
            Err(SnapshotError::ExceedsMax {
                declared: 8,
                max: 7
            })
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bounded_load_rejects_hostile_header_before_payload_read() {
        let dir = temp_path("hostile-header");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hostile.snap");

        let mut header = [0u8; HEADER_SIZE];
        header[HEADER_SIZE - LEN_SIZE..].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, header).unwrap();
        assert!(matches!(
            Snapshot::load_bounded(&path, 32),
            Err(SnapshotError::ExceedsMax { max: 32, .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bounded_load_rejects_trailing_bytes_with_one_sentinel() {
        let dir = temp_path("trailing");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trailing.snap");
        let encoded = Snapshot::new(root(3), 9, b"x".to_vec()).encode().unwrap();
        let expected = encoded.len();
        let mut padded = encoded;
        padded.extend(std::iter::repeat_n(0xCC, 1024 * 1024));
        fs::write(&path, padded).unwrap();

        assert_eq!(
            Snapshot::load_bounded(&path, 1),
            Err(SnapshotError::TrailingBytes {
                expected,
                actual_at_least: expected + 1,
            })
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bounded_file_load_rejects_every_truncation() {
        let dir = temp_path("file-truncations");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("truncated.snap");
        let encoded = Snapshot::new(root(4), 11, b"state-payload".to_vec())
            .encode()
            .unwrap();
        for cut in 0..encoded.len() {
            fs::write(&path, &encoded[..cut]).unwrap();
            assert!(
                Snapshot::load_bounded(&path, 64).is_err(),
                "cut {cut} unexpectedly decoded"
            );
        }
        fs::write(&path, &encoded).unwrap();
        assert!(Snapshot::load_bounded(&path, 64).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn atomic_install_round_trip() {
        let dir = temp_path("dir");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.snap");
        let snap = Snapshot::new(root(9), 100, b"durable-state".to_vec());
        snap.install_atomic(&path).unwrap();
        let loaded = Snapshot::load(&path).unwrap();
        assert_eq!(loaded, snap);
        assert!(loaded.verify(root(9)));
        assert!(temp_siblings(&dir, &path).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_install_accepts_bare_relative_destination() {
        let nonce = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            ".dexos-relative-snapshot-{}-{nonce}.snap",
            std::process::id()
        ));
        assert_eq!(snapshot_parent(&path), Path::new("."));
        let snapshot = Snapshot::new(root(19), 23, b"relative-state".to_vec());

        snapshot.install_atomic(&path).unwrap();
        assert_eq!(Snapshot::load(&path).unwrap(), snapshot);
        assert!(temp_siblings(Path::new("."), &path).is_empty());
        fs::remove_file(&path).unwrap();
        sync_dir(Path::new(".")).unwrap();
    }

    #[test]
    fn atomic_install_replaces_previous() {
        let dir = temp_path("replace");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.snap");
        Snapshot::new(root(1), 1, b"v1".to_vec())
            .install_atomic(&path)
            .unwrap();
        Snapshot::new(root(2), 2, b"v2".to_vec())
            .install_atomic(&path)
            .unwrap();
        let loaded = Snapshot::load(&path).unwrap();
        assert_eq!(loaded.state(), b"v2");
        assert_eq!(loaded.last_sequence(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn temp_reservation_retries_collision_without_mutating_it() {
        let dir = temp_path("temp-collision");
        fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("state.snap");
        let process_id = 4_242;
        let counter = AtomicU64::new(17);
        let collision = temp_sibling_path(&destination, process_id, 17);
        fs::write(&collision, b"stale-owner-data").unwrap();

        let (reserved, file) =
            create_temp_sibling_with(&destination, process_id, &counter).unwrap();
        assert_eq!(reserved, temp_sibling_path(&destination, process_id, 18));
        assert_eq!(fs::read(&collision).unwrap(), b"stale-owner-data");

        drop(file);
        fs::remove_file(reserved).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn temp_reservation_does_not_follow_symlink_collision() {
        use std::os::unix::fs::symlink;

        let dir = temp_path("temp-symlink");
        fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("state.snap");
        let symlink_target = dir.join("must-not-change");
        fs::write(&symlink_target, b"sentinel").unwrap();

        let process_id = 7_777;
        let counter = AtomicU64::new(31);
        let collision = temp_sibling_path(&destination, process_id, 31);
        symlink(&symlink_target, &collision).unwrap();

        let (reserved, file) =
            create_temp_sibling_with(&destination, process_id, &counter).unwrap();
        assert_eq!(reserved, temp_sibling_path(&destination, process_id, 32));
        assert!(fs::symlink_metadata(&collision)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&symlink_target).unwrap(), b"sentinel");

        drop(file);
        fs::remove_file(reserved).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_atomic_installs_publish_one_complete_snapshot() {
        let dir = temp_path("concurrent-installs");
        fs::create_dir_all(&dir).unwrap();
        let destination = Arc::new(dir.join("state.snap"));
        let workers = 8u8;
        let barrier = Arc::new(Barrier::new(usize::from(workers)));

        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                let destination = Arc::clone(&destination);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let snapshot =
                        Snapshot::new(root(worker + 1), u64::from(worker), vec![worker; 64 * 1024]);
                    barrier.wait();
                    snapshot.install_atomic(&destination)
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        let installed = Snapshot::load(&destination).unwrap();
        let winner = u8::try_from(installed.last_sequence()).unwrap();
        assert!(winner < workers);
        assert_eq!(installed.state(), vec![winner; 64 * 1024]);
        assert!(installed.verify(root(winner + 1)));
        assert!(temp_siblings(&dir, &destination).is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn atomic_install_cleans_temp_when_rename_fails() {
        let dir = temp_path("rename-failure");
        fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("state.snap");
        fs::create_dir(&destination).unwrap();

        let result = Snapshot::new(root(1), 1, b"state".to_vec()).install_atomic(&destination);
        assert!(matches!(result, Err(SnapshotError::Io(_))));
        assert!(destination.is_dir());
        assert!(temp_siblings(&dir, &destination).is_empty());
        let _ = fs::remove_dir_all(dir);
    }
}
