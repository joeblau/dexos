//! Replay / duplicate suppression.
//!
//! [`ReplayWindow`] is a sliding-window anti-replay filter (in the style of the
//! IPsec AH/ESP sequence window, RFC 6479): it accepts each sequence number at
//! most once and rejects duplicates and stale (out-of-window) replays, while
//! tolerating bounded reordering. All arithmetic is `u64` end-to-end — sequence
//! numbers are never truncated to a narrower type — so the full 64-bit sequence
//! space is usable before [`types::SequenceNumber`] exhaustion is signalled
//! upstream.
//!
//! Storage is a modular ring of `Option<u64>` slots (`slots[seq % window]`), so
//! a sequential advance is **O(1)** — no bitmap word shifts. Semantics match the
//! classical sliding window: in-window reordering is accepted once; out-of-window
//! and duplicate sequences are rejected.
//!
//! [`PeerDedup`] layers a bounded per-peer set of windows on top, keyed on
//! [`crate::PeerId`], to give *at-most-once* delivery across multiple
//! connections / paths to the same logical peer (multipath + connection
//! migration).

use std::collections::HashMap;

use crate::error::TransportError;
use crate::peer::PeerId;
use crate::util::as_usize;

/// Largest supported window (in sequence numbers).
pub const MAX_WINDOW: u64 = 4096;
/// Default window width.
pub const DEFAULT_WINDOW: u64 = 1024;

/// A sliding-window anti-replay filter over a single monotonic sequence space.
///
/// Memory is exactly `window` slots of `Option<u64>` — bounded and fixed at
/// construction. Slot `i` holds `Some(seq)` when sequence `seq` with
/// `seq % window == i` has been accepted and is still inside the live window.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Window width in sequence numbers (1..=[`MAX_WINDOW`]).
    window: u64,
    /// Highest sequence number accepted so far (valid once `seen_any`).
    highest: u64,
    /// Whether any sequence has been accepted yet.
    seen_any: bool,
    /// Modular slots: `slots[seq % window] == Some(seq)` means `seq` was seen.
    slots: Vec<Option<u64>>,
}

impl ReplayWindow {
    /// Create a window of `window` sequence numbers, clamped to
    /// `1..=MAX_WINDOW`.
    pub fn new(window: u64) -> Self {
        let window = window.clamp(1, MAX_WINDOW);
        let words = as_usize(window);
        Self {
            window,
            highest: 0,
            seen_any: false,
            slots: vec![None; words],
        }
    }

    /// Window width in sequence numbers.
    pub fn window(&self) -> u64 {
        self.window
    }

    fn slot_index(&self, seq: u64) -> usize {
        // `window` is in 1..=MAX_WINDOW, so the remainder always fits `usize`.
        as_usize(seq % self.window)
    }

    /// Test-and-record `seq`.
    ///
    /// Returns `true` if `seq` is fresh (and records it); `false` if it is a
    /// duplicate or a stale replay that has already slid out of the window.
    /// Reordered-but-in-window sequences are accepted exactly once.
    ///
    /// Sequential advances (and large jumps) are **O(1)**: only the modular
    /// slot for `seq` is written; no bitmap shift is performed.
    pub fn check(&mut self, seq: u64) -> bool {
        let idx = self.slot_index(seq);
        if !self.seen_any {
            self.seen_any = true;
            self.highest = seq;
            self.slots[idx] = Some(seq);
            return true;
        }
        if seq > self.highest {
            // Accept and advance highest. Older sequences fall out of the
            // window by the stale check below; modular overwrite handles reuse.
            self.highest = seq;
            self.slots[idx] = Some(seq);
            return true;
        }
        let diff = self.highest - seq;
        if diff >= self.window {
            return false; // stale: already slid out of the window
        }
        if self.slots[idx] == Some(seq) {
            return false; // duplicate
        }
        self.slots[idx] = Some(seq);
        true
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW)
    }
}

/// A bounded set of per-peer [`ReplayWindow`]s giving at-most-once delivery
/// across all connections/paths that authenticate to the same [`PeerId`].
///
/// The table is bounded to `max_peers` entries: admitting a genuinely new peer
/// once the table is full returns [`TransportError::DedupCapacity`] rather than
/// growing without limit, keeping memory bounded under connection churn.
#[derive(Debug)]
pub struct PeerDedup {
    windows: HashMap<PeerId, ReplayWindow>,
    window: u64,
    max_peers: usize,
}

impl PeerDedup {
    /// Create a dedup table with the given per-peer window and peer cap.
    pub fn new(window: u64, max_peers: usize) -> Self {
        Self {
            windows: HashMap::new(),
            window,
            max_peers,
        }
    }

    /// Number of tracked peers.
    pub fn tracked_peers(&self) -> usize {
        self.windows.len()
    }

    /// Test-and-record `(peer, seq)`.
    ///
    /// `Ok(true)` if fresh, `Ok(false)` if a duplicate/stale replay, and
    /// `Err(DedupCapacity)` if a new peer cannot be admitted because the table
    /// is full.
    pub fn accept(&mut self, peer: PeerId, seq: u64) -> Result<bool, TransportError> {
        if let Some(w) = self.windows.get_mut(&peer) {
            return Ok(w.check(seq));
        }
        if self.windows.len() >= self.max_peers {
            return Err(TransportError::DedupCapacity);
        }
        let mut w = ReplayWindow::new(self.window);
        let fresh = w.check(seq);
        self.windows.insert(peer, w);
        Ok(fresh)
    }

    /// Drop a peer's window (e.g. on final disconnect) to reclaim its slot.
    pub fn forget(&mut self, peer: &PeerId) {
        self.windows.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_new_rejects_duplicate() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check(1));
        assert!(!w.check(1)); // duplicate
        assert!(w.check(2));
        assert!(!w.check(2));
    }

    #[test]
    fn tolerates_bounded_reordering() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check(10));
        assert!(w.check(8)); // reordered, still in window
        assert!(w.check(9));
        assert!(!w.check(8)); // duplicate of a reordered arrival
        assert!(!w.check(9));
        assert!(!w.check(10));
    }

    #[test]
    fn rejects_stale_out_of_window_replays() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check(1000));
        // 1000 - 64 = 936 is the oldest still-in-window sequence.
        assert!(!w.check(900)); // slid out -> rejected
        assert!(w.check(1001));
        assert!(w.check(940)); // still in window
    }

    #[test]
    fn large_jump_clears_window_without_truncation() {
        let mut w = ReplayWindow::new(1024);
        assert!(w.check(5));
        // A jump far larger than the window near the top of the u64 space must
        // not truncate or panic; everything below the new window is stale.
        assert!(w.check(u64::MAX - 10));
        assert!(!w.check(5));
        assert!(w.check(u64::MAX - 11));
        assert!(w.check(u64::MAX));
        assert!(!w.check(u64::MAX));
    }

    #[test]
    fn multiword_shift_preserves_marks() {
        // Window spanning what used to be multiple bitmap words; advance by a
        // non-aligned amount and confirm previously-seen marks are preserved /
        // duplicates still caught under the modular-slot representation.
        let mut w = ReplayWindow::new(256);
        for s in [100u64, 120, 150, 200] {
            assert!(w.check(s));
        }
        // advance highest by 37
        assert!(w.check(237));
        // originals still recognised as duplicates while in window
        for s in [100u64, 120, 150, 200, 237] {
            assert!(!w.check(s), "seq {s} should be a duplicate");
        }
        // a fresh in-window sequence between them is accepted once
        assert!(w.check(101));
        assert!(!w.check(101));
    }

    #[test]
    fn sequential_advance_is_idempotent_for_all_window_widths() {
        // O(1) sequential traffic must remain correct for every supported width:
        // each new sequence is accepted once; an immediate retry is a duplicate.
        for window in [1u64, 2, 7, 64, 65, 128, 1024, 4096] {
            let mut w = ReplayWindow::new(window);
            assert_eq!(w.window(), window.clamp(1, MAX_WINDOW));
            for seq in 0..512u64 {
                assert!(
                    w.check(seq),
                    "window={window}: first accept of {seq} must succeed"
                );
                assert!(
                    !w.check(seq),
                    "window={window}: immediate retry of {seq} must be a duplicate"
                );
            }
            // A sequence that has slid out of the window is stale.
            if 512 > window {
                let stale = 512 - window - 1;
                assert!(
                    !w.check(stale),
                    "window={window}: seq {stale} should be stale after advancing to 511"
                );
            }
        }
    }

    #[test]
    fn peer_dedup_at_most_once_and_bounded() {
        let mut d = PeerDedup::new(1024, 2);
        let a = PeerId::from([1u8; 32]);
        let b = PeerId::from([2u8; 32]);
        let c = PeerId::from([3u8; 32]);

        assert!(d.accept(a, 5).unwrap());
        assert!(!d.accept(a, 5).unwrap()); // duplicate for same peer
        assert!(d.accept(b, 5).unwrap()); // different peer, same seq is fine
                                          // Table is now full (2 peers); a genuinely new peer is refused.
        assert!(matches!(d.accept(c, 1), Err(TransportError::DedupCapacity)));
        // Existing peers keep working.
        assert!(d.accept(a, 6).unwrap());
        // Freeing a slot admits the new peer.
        d.forget(&b);
        assert!(d.accept(c, 1).unwrap());
    }

    #[test]
    fn never_panics_on_arbitrary_sequence_stream_property() {
        // Deterministic LCG feeds an arbitrary stream of sequence numbers and
        // window widths; the filter must never panic and must be idempotent
        // (an immediately-repeated accept is always a duplicate).
        let mut state: u64 = 0xdead_beef_cafe_f00d;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            state
        };
        for _ in 0..2000 {
            let window = next() % (MAX_WINDOW + 8); // exercises clamping too
            let mut w = ReplayWindow::new(window);
            let mut last_accepted: Option<u64> = None;
            for _ in 0..64 {
                let seq = next();
                let accepted = w.check(seq);
                if accepted {
                    last_accepted = Some(seq);
                }
                // A sequence just accepted is always a duplicate if retried.
                if let Some(s) = last_accepted {
                    assert!(!w.check(s));
                }
            }
        }
    }
}
