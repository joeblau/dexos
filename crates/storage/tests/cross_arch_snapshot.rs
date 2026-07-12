//! Cross-architecture snapshot transfer fixture.
//!
//! Builds a canonical on-disk snapshot from a fixed byte stream, then verifies
//! the snapshot reloads bit-identically. Digests of the snapshot file and the
//! state root are architecture-stable (little-endian fixed-width fields only)
//! and are printed for multi-arch CI comparison.
//!
//! Environment:
//! - `CROSS_ARCH_SNAPSHOT_OUT` — if set, write the snapshot file there (export).
//! - `CROSS_ARCH_SNAPSHOT_IN` — if set, load and verify that path (import/transfer).

use std::path::{Path, PathBuf};

use storage::{DurableConfig, DurableLog, Snapshot, SyncPolicy};
use types::Hash;

/// Deterministic pseudo-state used only for wire integrity / transfer tests.
fn state_bytes() -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"DEXOS-CROSS-ARCH-STATE-v1");
    for i in 0u32..32 {
        out.extend_from_slice(&i.to_le_bytes());
        out.extend_from_slice(&(i.wrapping_mul(0x9E37_79B9)).to_le_bytes());
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let d = crypto::hash_domain(b"dexos:test:file-digest:v1", bytes);
    d.as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn tempfile_dir() -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!(
        "dexos-cross-arch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn build_and_digest(dir: &Path) -> (PathBuf, String, String, String) {
    let log_dir = dir.join("log");
    std::fs::create_dir_all(&log_dir).unwrap();

    // Exercise the durable WAL path with Always-sync (production RPO=0).
    let cfg = DurableConfig::new(&log_dir).with_sync(SyncPolicy::Always);
    let mut log = DurableLog::open(cfg).expect("open durable log");
    for i in 0..32u64 {
        let payload = format!("cmd-{i:04}-payload-bytes").into_bytes();
        log.append(i + 1, 1_700_000_000 + i, (i % 7) as u16, &payload)
            .expect("append");
    }
    log.verify().expect("wal integrity");

    let state = state_bytes();
    let root: Hash = crypto::hash_domain(b"dexos:test:cross-arch-root:v1", &state);
    let snap = Snapshot::new(root, 32, state.clone());
    let snap_path = dir.join("state.snap");
    snap.install_atomic(&snap_path).expect("atomic install");

    let loaded = Snapshot::load(&snap_path).expect("load");
    assert_eq!(loaded.state(), state.as_slice());
    assert_eq!(loaded.state_root(), root);
    assert_eq!(loaded.last_sequence(), 32);

    let file_bytes = std::fs::read(&snap_path).expect("read snap file");
    let snap_sha = sha256_hex(&file_bytes);
    let root_hex = root
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let wire_sha = sha256_hex(&state);

    (snap_path, snap_sha, root_hex, wire_sha)
}

#[test]
fn cross_arch_snapshot_round_trip_and_digests() {
    let dir = tempfile_dir();
    let (snap_path, snap_sha, root_hex, wire_sha) = build_and_digest(&dir);

    // Architecture-stable digests for multi-arch CI.
    println!("snapshot_sha256={snap_sha}");
    println!("state_root={root_hex}");
    println!("wire_corpus_sha256={wire_sha}");

    // Self-consistency of the fixture generator.
    assert_eq!(wire_sha, sha256_hex(&state_bytes()));

    if let Ok(out) = std::env::var("CROSS_ARCH_SNAPSHOT_OUT") {
        let dest = PathBuf::from(out);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::copy(&snap_path, &dest).expect("export snapshot");
        std::fs::write(
            dest.with_extension("digest"),
            format!("snapshot_sha256={snap_sha}\nstate_root={root_hex}\nwire_corpus_sha256={wire_sha}\n"),
        )
        .unwrap();
        println!("exported snapshot to {}", dest.display());
    }

    if let Ok(inp) = std::env::var("CROSS_ARCH_SNAPSHOT_IN") {
        let foreign_path = PathBuf::from(&inp);
        let foreign = Snapshot::load(&foreign_path).expect("import foreign snapshot");
        let local_state = state_bytes();
        let local_root = crypto::hash_domain(b"dexos:test:cross-arch-root:v1", &local_state);
        assert_eq!(
            foreign.state(),
            local_state.as_slice(),
            "cross-arch import must match local state bytes"
        );
        assert_eq!(foreign.state_root(), local_root);
        let foreign_bytes = std::fs::read(&foreign_path).unwrap();
        assert_eq!(
            sha256_hex(&foreign_bytes),
            snap_sha,
            "cross-arch snapshot file bytes must match"
        );
        println!("imported and verified foreign snapshot from {inp}");
    }
}

#[test]
fn two_hosts_produce_identical_snapshot_file_bytes() {
    // Simulates two architectures by building the fixture twice in process;
    // multi-arch CI additionally transfers the file between runners.
    let a = tempfile_dir();
    let b = tempfile_dir();
    let (pa, sa, ra, wa) = build_and_digest(&a);
    let (pb, sb, rb, wb) = build_and_digest(&b);
    assert_eq!(sa, sb);
    assert_eq!(ra, rb);
    assert_eq!(wa, wb);
    assert_eq!(
        std::fs::read(&pa).unwrap(),
        std::fs::read(&pb).unwrap(),
        "snapshot files must be byte-identical"
    );
}
