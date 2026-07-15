//! Crate-private filesystem durability helpers shared by durable storage.

use std::io;
use std::path::Path;

/// Fsync a directory so metadata mutations inside it (file creates, unlinks,
/// renames) are durable across power loss.
///
/// Per POSIX crash semantics (ext4/XFS), fsyncing a file makes its *bytes*
/// durable but not its *directory entry*: a segment created and appended to
/// can vanish wholesale after a crash unless the parent directory is itself
/// fsynced. This helper is strict and fail-closed — any failure propagates as
/// an I/O error instead of acknowledging a write whose dirent could still
/// disappear.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Non-Unix stub: directories generally cannot be opened and fsynced (e.g.
/// Windows has no directory-fd fsync), and the platform provides metadata
/// durability through different mechanisms. Documented no-op.
#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn sync_dir_succeeds_on_existing_dir() {
        sync_dir(&std::env::temp_dir()).unwrap();
    }

    #[test]
    fn sync_dir_missing_dir_fails_closed() {
        // Fail-closed contract: an invalid directory must surface as a typed
        // I/O error, never a silent Ok that fakes durability.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let missing = std::env::temp_dir().join(format!("dexos-fsutil-missing-{nanos}"));
        let err = sync_dir(&missing);
        assert!(err.is_err(), "expected I/O error for missing dir");
    }
}
