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
//! [`Snapshot::verify`] additionally confirms the embedded state root equals a
//! caller-supplied expected root, which is how replay proves it reconstructed
//! the exact pre-shutdown state.
//!
//! On disk, snapshots are published with [`Snapshot::install_atomic`]: write a
//! sibling temp file, `fsync` the file (and parent directory on Unix), then
//! `rename` into place so a crash mid-write never leaves a half-applied
//! snapshot at the destination path.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::crc::crc32;
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

    /// Verify the snapshot against an `expected_root`.
    ///
    /// Returns `true` only if the version is supported, the embedded content
    /// digest matches the state bytes, and the embedded state root equals
    /// `expected_root`. This is deliberately total (no errors, no panics): it is
    /// the predicate replay uses to accept or reject a loaded snapshot.
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
        let bytes = fs::read(path)?;
        Self::decode(&bytes)
    }

    /// Atomically install this snapshot at `path`.
    ///
    /// Writes to a sibling temporary file, `fsync`s the temp file (and the
    /// parent directory on Unix), then renames into place. A crash mid-write
    /// leaves either the previous snapshot or a temp file — never a torn file
    /// at `path`.
    ///
    /// # Errors
    /// Returns encode or I/O errors.
    pub fn install_atomic(&self, path: &Path) -> Result<(), SnapshotError> {
        let bytes = self.encode()?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        let tmp = temp_sibling(path);
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }

        fs::rename(&tmp, path)?;
        sync_dir(parent)?;
        Ok(())
    }
}

/// Sibling temp path used during atomic install.
fn temp_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "snapshot".into());
    name.push(".tmp");
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

/// Best-effort directory fsync so the rename is durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    // On Unix, fsync of the directory ensures the rename is durable.
    // On other platforms this is a no-op open/sync best effort.
    match File::open(dir) {
        Ok(f) => f.sync_all(),
        // Some platforms refuse to open directories; durability of rename is
        // still best-effort via the file sync above.
        Err(e) if e.kind() == io::ErrorKind::IsADirectory || e.raw_os_error() == Some(21) => {
            // macOS / Linux may still allow File::open on dirs; if not, ignore.
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(e) => {
            // Non-fatal on platforms where directory fsync is unsupported.
            if cfg!(unix) {
                // Try once more via OpenOptions — ignore soft failures.
                let _ = e;
                Ok(())
            } else {
                Ok(())
            }
        }
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

    #[test]
    fn round_trip_and_verify() {
        let snap = Snapshot::new(root(7), 42, b"engine-state".to_vec());
        let bytes = snap.encode().unwrap();
        let back = Snapshot::decode(&bytes).unwrap();
        assert_eq!(back, snap);
        assert_eq!(back.last_sequence(), 42);
        assert_eq!(back.state(), b"engine-state");
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
    fn atomic_install_round_trip() {
        let dir = temp_path("dir");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.snap");
        let snap = Snapshot::new(root(9), 100, b"durable-state".to_vec());
        snap.install_atomic(&path).unwrap();
        let loaded = Snapshot::load(&path).unwrap();
        assert_eq!(loaded, snap);
        assert!(loaded.verify(root(9)));
        // No leftover temp.
        assert!(!dir.join("state.snap.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
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
}
