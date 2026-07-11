//! Network-impairment and adversarial-frame injection.
//!
//! For each transmitted packet the [`Impairer`] draws a deterministic disposition —
//! deliver, drop, duplicate, and/or delay — from the seeded RNG, so two runs with the
//! same seed produce an identical decision sequence. A [`DedupSet`] collapses the
//! duplicates a 100%-duplication run creates back to one logical order. The
//! adversarial generator emits frames the node decoder is expected to reject without
//! panicking.

use std::collections::HashSet;

use codec::{TrafficClass, FRAME_HEADER_LEN, FRAME_MAGIC, MAX_FRAME_PAYLOAD};

use crate::config::{Adversarial, Impairment};
use crate::rng::Lcg;

/// What happens to a single transmitted packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketDisposition {
    /// Whether the original copy is delivered at all.
    pub delivered: bool,
    /// Whether a duplicate copy is also delivered.
    pub duplicated: bool,
    /// Extra delay applied to the delivery, nanoseconds.
    pub delay_ns: u64,
    /// Whether this packet is held back a slot (reordered).
    pub reordered: bool,
}

impl PacketDisposition {
    /// Number of copies that actually arrive (0, 1, or 2).
    #[must_use]
    pub const fn arrivals(&self) -> u32 {
        let base = if self.delivered { 1 } else { 0 };
        base + if self.duplicated { 1 } else { 0 }
    }
}

/// Deterministic packet-impairment decision maker.
#[derive(Debug, Clone)]
pub struct Impairer {
    rng: Lcg,
}

impl Impairer {
    /// Create an impairer seeded deterministically.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Lcg::new(seed),
        }
    }

    /// Draw the disposition for the next packet under `impair`. The draw order is
    /// fixed (loss, dup, reorder, jitter) so the sequence is reproducible.
    pub fn decide(&mut self, impair: &Impairment) -> PacketDisposition {
        let dropped = self.rng.chance(impair.loss_ratio);
        let duplicated = !dropped && self.rng.chance(impair.dup_ratio);
        let reordered = self.rng.chance(impair.reorder_ratio);
        let base = impair.extra_latency_us.saturating_mul(1000);
        let jitter = self
            .rng
            .jitter(impair.latency_jitter_us.saturating_mul(1000));
        PacketDisposition {
            delivered: !dropped,
            duplicated,
            delay_ns: base.saturating_add(jitter),
            reordered,
        }
    }
}

/// Collapses duplicate transmissions of the same logical order to one.
#[derive(Debug, Clone, Default)]
pub struct DedupSet {
    seen: HashSet<u128>,
    duplicates: u64,
}

impl DedupSet {
    /// Create an empty dedup set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a delivery with the given dedup key. Returns `true` if this is the
    /// first time the key is seen (a new logical order), `false` for a duplicate.
    pub fn observe(&mut self, key: u128) -> bool {
        if self.seen.insert(key) {
            true
        } else {
            self.duplicates = self.duplicates.saturating_add(1);
            false
        }
    }

    /// Number of distinct logical orders seen.
    #[must_use]
    pub fn unique(&self) -> u64 {
        u64::try_from(self.seen.len()).unwrap_or(u64::MAX)
    }

    /// Number of duplicate deliveries collapsed.
    #[must_use]
    pub const fn duplicates(&self) -> u64 {
        self.duplicates
    }
}

/// Generates frames intended to be rejected by the node decoder without panicking.
#[derive(Debug, Clone)]
pub struct AdversarialGenerator {
    rng: Lcg,
    cfg: Adversarial,
}

impl AdversarialGenerator {
    /// Create a generator with the given config and seed.
    #[must_use]
    pub fn new(cfg: Adversarial, seed: u64) -> Self {
        Self {
            rng: Lcg::new(seed),
            cfg,
        }
    }

    /// Produce the next adversarial frame's raw bytes. The bytes deliberately violate
    /// the frame contract (bad magic, truncation, impossible length, or garbage) so a
    /// conformant decoder rejects them.
    #[must_use]
    pub fn next_frame(&mut self) -> Vec<u8> {
        let choice = self.rng.below(4);
        match choice {
            0 => self.bad_magic(),
            1 => self.truncated(),
            2 if self.rng.chance(self.cfg.oversized_ratio) => self.oversized_length(),
            _ => self.garbage(),
        }
    }

    fn garbage(&mut self) -> Vec<u8> {
        let len = self
            .rng
            .below(u64::try_from(self.cfg.max_garbage_len.max(1)).unwrap_or(64));
        let len = usize::try_from(len).unwrap_or(0);
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(u8::try_from(self.rng.next_u64() & 0xFF).unwrap_or(0));
        }
        // Guarantee rejection regardless of the random draw: force a non-magic prefix
        // so a full-length garbage frame fails `BadMagic` and a short one `Truncated`.
        if out.len() >= 2 {
            let bad = (FRAME_MAGIC ^ 0xFFFF).to_le_bytes();
            out[0] = bad[0];
            out[1] = bad[1];
        }
        out
    }

    fn bad_magic(&mut self) -> Vec<u8> {
        // Valid length but wrong magic word.
        let mut out = vec![0u8; FRAME_HEADER_LEN];
        // Deliberately not FRAME_MAGIC.
        let bad = FRAME_MAGIC ^ 0xFFFF;
        out[0..2].copy_from_slice(&bad.to_le_bytes());
        out
    }

    fn truncated(&mut self) -> Vec<u8> {
        // Fewer bytes than a header.
        let len = self
            .rng
            .below(u64::try_from(FRAME_HEADER_LEN).unwrap_or(19));
        let len = usize::try_from(len).unwrap_or(0);
        vec![0u8; len]
    }

    fn oversized_length(&mut self) -> Vec<u8> {
        // Valid magic/version but a payload length beyond the maximum, with no body.
        let mut out = vec![0u8; FRAME_HEADER_LEN];
        out[0..2].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
        out[2..4].copy_from_slice(&1u16.to_le_bytes()); // version
        out[4] = TrafficClass::NewOrder.priority();
        // Claim an impossible payload length in the length field (last 4 header bytes).
        let bogus = u32::try_from(MAX_FRAME_PAYLOAD)
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let start = FRAME_HEADER_LEN - 4;
        out[start..FRAME_HEADER_LEN].copy_from_slice(&bogus.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Frame;
    use types::{Ratio, RATIO_SCALE};

    #[test]
    fn full_loss_drops_everything() {
        let impair = Impairment {
            loss_ratio: Ratio::from_raw(RATIO_SCALE),
            ..Impairment::default()
        };
        let mut imp = Impairer::new(1);
        for _ in 0..1000 {
            let d = imp.decide(&impair);
            assert!(!d.delivered);
            assert_eq!(d.arrivals(), 0);
        }
    }

    #[test]
    fn full_duplication_doubles() {
        let impair = Impairment {
            dup_ratio: Ratio::from_raw(RATIO_SCALE),
            ..Impairment::default()
        };
        let mut imp = Impairer::new(1);
        for _ in 0..1000 {
            let d = imp.decide(&impair);
            assert!(d.delivered);
            assert!(d.duplicated);
            assert_eq!(d.arrivals(), 2);
        }
    }

    #[test]
    fn loss_rate_within_tolerance() {
        let impair = Impairment {
            loss_ratio: Ratio::from_raw(RATIO_SCALE / 10), // 10%
            ..Impairment::default()
        };
        let mut imp = Impairer::new(7);
        let mut dropped = 0u32;
        let n = 100_000u32;
        for _ in 0..n {
            if !imp.decide(&impair).delivered {
                dropped += 1;
            }
        }
        assert!((9_000..11_000).contains(&dropped), "dropped={dropped}");
    }

    #[test]
    fn same_seed_identical_decisions() {
        let impair = Impairment {
            loss_ratio: Ratio::from_raw(200_000),
            dup_ratio: Ratio::from_raw(150_000),
            reorder_ratio: Ratio::from_raw(100_000),
            extra_latency_us: 10,
            latency_jitter_us: 5,
        };
        let mut a = Impairer::new(0xABCD);
        let mut b = Impairer::new(0xABCD);
        for _ in 0..5000 {
            assert_eq!(a.decide(&impair), b.decide(&impair));
        }
    }

    #[test]
    fn dedup_collapses_duplicates() {
        let mut set = DedupSet::new();
        // Deliver key 1 three times, key 2 twice.
        assert!(set.observe(1));
        assert!(!set.observe(1));
        assert!(!set.observe(1));
        assert!(set.observe(2));
        assert!(!set.observe(2));
        assert_eq!(set.unique(), 2);
        assert_eq!(set.duplicates(), 3);
    }

    #[test]
    fn adversarial_frames_are_rejected_not_panicked() {
        let cfg = Adversarial {
            enabled: true,
            malformed_ratio: Ratio::from_raw(RATIO_SCALE),
            oversized_ratio: Ratio::from_raw(RATIO_SCALE / 2),
            max_garbage_len: 40,
        };
        let mut gen = AdversarialGenerator::new(cfg, 123);
        for _ in 0..10_000 {
            let bytes = gen.next_frame();
            // The decoder must never panic and must reject these frames.
            let result = Frame::decode(&bytes);
            assert!(result.is_err(), "adversarial frame unexpectedly decoded");
        }
    }
}
