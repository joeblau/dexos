//! Full-path timestamp pipeline and clock-synchronised latency computation.
//!
//! Every order that traverses the system is stamped at ten stages, from the client
//! send to the final checkpoint. Each stamp carries the clock offset of whichever
//! node recorded it, so differencing two stamps corrects for cross-region clock skew
//! and can never produce a physically impossible negative stage latency.

/// The ten pipeline stages, in causal order along the main request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Client emits the order.
    ClientSend,
    /// Gateway receives the bytes.
    GatewayReceive,
    /// Signature verification completes.
    SignatureVerified,
    /// Sequencer ingests the command.
    SequencerReceive,
    /// Risk checks complete.
    RiskComplete,
    /// Matching completes.
    MatchComplete,
    /// Execution receipt is sent back.
    ReceiptSent,
    /// Client receives the receipt.
    ClientReceive,
    /// Certificate over the batch is formed.
    CertificateFormed,
    /// Checkpoint containing the batch is finalised.
    CheckpointFinalized,
}

/// Number of pipeline stages.
pub const STAGE_COUNT: usize = 10;

impl Stage {
    /// Dense array index for this stage.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Stage::ClientSend => 0,
            Stage::GatewayReceive => 1,
            Stage::SignatureVerified => 2,
            Stage::SequencerReceive => 3,
            Stage::RiskComplete => 4,
            Stage::MatchComplete => 5,
            Stage::ReceiptSent => 6,
            Stage::ClientReceive => 7,
            Stage::CertificateFormed => 8,
            Stage::CheckpointFinalized => 9,
        }
    }

    /// All stages in causal order.
    #[must_use]
    pub const fn all() -> [Stage; STAGE_COUNT] {
        [
            Stage::ClientSend,
            Stage::GatewayReceive,
            Stage::SignatureVerified,
            Stage::SequencerReceive,
            Stage::RiskComplete,
            Stage::MatchComplete,
            Stage::ReceiptSent,
            Stage::ClientReceive,
            Stage::CertificateFormed,
            Stage::CheckpointFinalized,
        ]
    }

    /// Stable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Stage::ClientSend => "client_send",
            Stage::GatewayReceive => "gateway_receive",
            Stage::SignatureVerified => "signature_verified",
            Stage::SequencerReceive => "sequencer_receive",
            Stage::RiskComplete => "risk_complete",
            Stage::MatchComplete => "match_complete",
            Stage::ReceiptSent => "receipt_sent",
            Stage::ClientReceive => "client_receive",
            Stage::CertificateFormed => "certificate_formed",
            Stage::CheckpointFinalized => "checkpoint_finalized",
        }
    }
}

/// A raw timestamp plus the clock offset of the node that recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockStamp {
    /// Raw nanosecond reading from the local clock (includes its offset).
    pub raw_ns: u64,
    /// This clock's offset from the global timebase, nanoseconds (can be negative).
    pub offset_ns: i64,
}

impl ClockStamp {
    /// Offset-corrected time on the global timebase.
    #[must_use]
    pub fn corrected(self) -> i128 {
        i128::from(self.raw_ns) - i128::from(self.offset_ns)
    }
}

/// Errors computing latencies from an incomplete or skewed record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimingError {
    /// A required stage was never stamped.
    #[error("missing timestamp for a required stage")]
    MissingStamp,
    /// The corrected delta was negative (should not happen after correction).
    #[error("negative stage delta after clock correction")]
    NegativeDelta,
    /// The corrected delta did not fit in a `u64`.
    #[error("stage delta out of range")]
    OutOfRange,
}

/// Full-path timestamps for one logical order.
#[derive(Debug, Clone, Default)]
pub struct FullPathTimestamps {
    stamps: [Option<ClockStamp>; STAGE_COUNT],
}

impl FullPathTimestamps {
    /// Create an empty record.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stamps: [None; STAGE_COUNT],
        }
    }

    /// Record a stamp for `stage` with an explicit clock offset.
    pub fn record(&mut self, stage: Stage, raw_ns: u64, offset_ns: i64) {
        self.stamps[stage.index()] = Some(ClockStamp { raw_ns, offset_ns });
    }

    /// Fetch a stamp if present.
    #[must_use]
    pub fn get(&self, stage: Stage) -> Option<ClockStamp> {
        self.stamps[stage.index()]
    }

    /// Offset-corrected delta `to - from` in nanoseconds on the global timebase.
    ///
    /// # Errors
    /// [`TimingError::MissingStamp`] if either stamp is absent, [`TimingError::NegativeDelta`]
    /// if the corrected difference is negative, or [`TimingError::OutOfRange`] if it
    /// overflows `u64`.
    pub fn delta(&self, from: Stage, to: Stage) -> Result<u64, TimingError> {
        let a = self.get(from).ok_or(TimingError::MissingStamp)?;
        let b = self.get(to).ok_or(TimingError::MissingStamp)?;
        let diff = b.corrected() - a.corrected();
        if diff < 0 {
            return Err(TimingError::NegativeDelta);
        }
        u64::try_from(diff).map_err(|_| TimingError::OutOfRange)
    }

    /// End-to-end latency: client send to client receive.
    ///
    /// # Errors
    /// See [`FullPathTimestamps::delta`].
    pub fn end_to_end(&self) -> Result<u64, TimingError> {
        self.delta(Stage::ClientSend, Stage::ClientReceive)
    }

    /// Time from client send to checkpoint finality.
    ///
    /// # Errors
    /// See [`FullPathTimestamps::delta`].
    pub fn to_finality(&self) -> Result<u64, TimingError> {
        self.delta(Stage::ClientSend, Stage::CheckpointFinalized)
    }

    /// Per-stage latencies along the main path (`ClientSend`→…→`ClientReceive`),
    /// returned as `(from, to, ns)` triples for present, non-negative segments.
    #[must_use]
    pub fn stage_latencies(&self) -> Vec<(Stage, Stage, u64)> {
        const MAIN_PATH: [Stage; 8] = [
            Stage::ClientSend,
            Stage::GatewayReceive,
            Stage::SignatureVerified,
            Stage::SequencerReceive,
            Stage::RiskComplete,
            Stage::MatchComplete,
            Stage::ReceiptSent,
            Stage::ClientReceive,
        ];
        let mut out = Vec::with_capacity(MAIN_PATH.len() - 1);
        for pair in MAIN_PATH.windows(2) {
            let (from, to) = (pair[0], pair[1]);
            if let Ok(ns) = self.delta(from, to) {
                out.push((from, to, ns));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a record with no clock skew and hand-computable stage costs.
    fn sample() -> FullPathTimestamps {
        let mut t = FullPathTimestamps::new();
        // client_send=0, then +100, +50, +30, +40, +20, +10, +200 (return leg).
        t.record(Stage::ClientSend, 0, 0);
        t.record(Stage::GatewayReceive, 100, 0);
        t.record(Stage::SignatureVerified, 150, 0);
        t.record(Stage::SequencerReceive, 180, 0);
        t.record(Stage::RiskComplete, 220, 0);
        t.record(Stage::MatchComplete, 240, 0);
        t.record(Stage::ReceiptSent, 250, 0);
        t.record(Stage::ClientReceive, 450, 0);
        t.record(Stage::CertificateFormed, 260, 0);
        t.record(Stage::CheckpointFinalized, 5_000, 0);
        t
    }

    #[test]
    fn per_stage_deltas_are_exact() {
        let t = sample();
        assert_eq!(
            t.delta(Stage::ClientSend, Stage::GatewayReceive).unwrap(),
            100
        );
        assert_eq!(
            t.delta(Stage::GatewayReceive, Stage::SignatureVerified)
                .unwrap(),
            50
        );
        assert_eq!(
            t.delta(Stage::SignatureVerified, Stage::SequencerReceive)
                .unwrap(),
            30
        );
        assert_eq!(
            t.delta(Stage::MatchComplete, Stage::ReceiptSent).unwrap(),
            10
        );
    }

    #[test]
    fn end_to_end_and_finality() {
        let t = sample();
        assert_eq!(t.end_to_end().unwrap(), 450);
        assert_eq!(t.to_finality().unwrap(), 5_000);
    }

    #[test]
    fn stage_latencies_cover_main_path() {
        let t = sample();
        let stages = t.stage_latencies();
        assert_eq!(stages.len(), 7);
        let total: u64 = stages.iter().map(|(_, _, ns)| *ns).sum();
        assert_eq!(total, 450);
    }

    #[test]
    fn missing_stamp_is_error() {
        let mut t = FullPathTimestamps::new();
        t.record(Stage::ClientSend, 0, 0);
        assert_eq!(t.end_to_end(), Err(TimingError::MissingStamp));
    }

    #[test]
    fn clock_offset_prevents_negative_cross_region_delta() {
        // Client in a region 2_000ns fast; gateway on the global timebase.
        // Raw gateway (5_000) < raw client (6_000) would look negative naively.
        let mut t = FullPathTimestamps::new();
        t.record(Stage::ClientSend, 6_000, 2_000); // corrected 4_000
        t.record(Stage::GatewayReceive, 5_000, 0); // corrected 5_000
                                                   // Naive raw diff = -1_000; corrected diff = +1_000.
        assert_eq!(
            t.delta(Stage::ClientSend, Stage::GatewayReceive).unwrap(),
            1_000
        );
    }

    #[test]
    fn uncorrected_skew_would_be_negative() {
        // Same stamps but pretend both clocks are on the global timebase (offset 0):
        // the delta is genuinely negative and reported as such.
        let mut t = FullPathTimestamps::new();
        t.record(Stage::ClientSend, 6_000, 0);
        t.record(Stage::GatewayReceive, 5_000, 0);
        assert_eq!(
            t.delta(Stage::ClientSend, Stage::GatewayReceive),
            Err(TimingError::NegativeDelta)
        );
    }
}
