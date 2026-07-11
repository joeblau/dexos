//! Deterministic in-process simulation engine and result reporting.
//!
//! [`run_scenario`] drives a generated order stream through the full-path timestamp
//! pipeline for every configured region, applies network impairment, collapses
//! duplicate transmissions, and aggregates per-stage and end-to-end latency
//! percentiles into a [`LoadReport`]. The whole path is synchronous and seeded, so two
//! runs with the same scenario produce a bit-identical command sequence and equivalent
//! aggregate percentiles. Multiple regions start from a shared [`SyncBarrier`] and
//! merge into one report with per-region and combined percentiles.

use crate::command::{CommandKind, SessionState};
use crate::config::{LoadConfig, LoadScenario, RegionConfig};
use crate::impairment::{DedupSet, Impairer};
use crate::metrics::{Percentiles, SampleSet};
use crate::rng::Lcg;
use crate::timing::{FullPathTimestamps, Stage};
use crate::util::{fnv1a_64, fold_u64, json_escape};
use crate::workload::{oracle_update_count, SubscriberState};

/// Upper bound on simulated events per region so an enormous configured rate cannot
/// make a run unbounded. The reported `planned_orders` still reflects the full rate.
const MAX_EVENTS_PER_REGION: u64 = 200_000;

/// Deterministic per-stage processing costs, nanoseconds (base + jitter span).
const SIG_COST: u64 = 8_000;
const SEQ_COST: u64 = 5_000;
const RISK_COST: u64 = 12_000;
const MATCH_COST: u64 = 15_000;
const RECEIPT_COST: u64 = 4_000;
const CERT_COST: u64 = 20_000_000; // ~20 ms to form a certificate
const CHECKPOINT_COST: u64 = 200_000_000; // ~200 ms to finalise a checkpoint
const PROC_JITTER: u64 = 3_000;
const CERT_JITTER: u64 = 5_000_000;
const CHECKPOINT_JITTER: u64 = 50_000_000;
/// Large epoch base so negative clock offsets never underflow a raw `u64` stamp.
const EPOCH_BASE_NS: u64 = 1u64 << 50;

/// Errors from running the load generator.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The scenario or flat config was invalid.
    #[error("invalid configuration: {0}")]
    Config(#[from] crate::config::ConfigError),
}

/// A synchronisation barrier all regions arrive at before generating load.
#[derive(Debug, Clone)]
pub struct SyncBarrier {
    expected: usize,
    arrived: usize,
    start_ns: u64,
}

impl SyncBarrier {
    /// Create a barrier expecting `expected` participants, releasing at `start_ns`.
    #[must_use]
    pub fn new(expected: usize, start_ns: u64) -> Self {
        Self {
            expected,
            arrived: 0,
            start_ns,
        }
    }

    /// Mark a participant as arrived; returns the shared start timestamp.
    pub fn arrive(&mut self) -> u64 {
        self.arrived = self.arrived.saturating_add(1);
        self.start_ns
    }

    /// Whether every expected participant has arrived.
    #[must_use]
    pub fn released(&self) -> bool {
        self.arrived >= self.expected
    }
}

/// Per-region measurement summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionReport {
    /// Region name.
    pub name: String,
    /// Configured users.
    pub users: u32,
    /// Whether the region is cross-region from the sequencer.
    pub cross_region: bool,
    /// Commands generated in this region.
    pub generated: u64,
    /// Packets delivered (including duplicates).
    pub delivered: u64,
    /// Packets dropped.
    pub dropped: u64,
    /// End-to-end receipt latency percentiles.
    pub receipt: Percentiles,
    /// Market-data sequence gaps detected in this region.
    pub gaps: u64,
    /// Oracle updates emitted in this region.
    pub oracle_updates: u64,
    /// Samples dropped due to fixed buffer capacity.
    pub dropped_samples: u64,
}

/// Aggregate result of a load run. `planned_orders` is retained for CLI compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadReport {
    /// Orders the plan would submit over its duration at the base rate.
    pub planned_orders: u64,
    /// Commands actually generated in the (bounded) simulation.
    pub generated_commands: u64,
    /// New-order commands generated.
    pub new_orders: u64,
    /// Cancel commands generated.
    pub cancels: u64,
    /// Replace commands generated.
    pub replaces: u64,
    /// Packets delivered (including duplicates).
    pub delivered_packets: u64,
    /// Packets dropped by loss injection.
    pub dropped_packets: u64,
    /// Duplicate deliveries collapsed by dedup.
    pub duplicate_deliveries: u64,
    /// Distinct logical orders executed exactly once after dedup.
    pub unique_orders_executed: u64,
    /// Fingerprint of the generated command sequence (reproducibility check).
    pub command_sequence_hash: u64,
    /// Latency samples dropped due to fixed-capacity buffers.
    pub dropped_samples: u64,
    /// Combined end-to-end receipt latency percentiles.
    pub end_to_end: Percentiles,
    /// Same-region receipt latency percentiles.
    pub same_region_receipt: Percentiles,
    /// Cross-region receipt latency percentiles.
    pub cross_region_receipt: Percentiles,
    /// Checkpoint-finality latency percentiles.
    pub finality: Percentiles,
    /// Total oracle updates emitted.
    pub oracle_updates: u64,
    /// Total market-data sequence gaps detected.
    pub market_data_gaps: u64,
    /// Clock-synchronisation method label recorded for the run.
    pub clock_method: String,
    /// Seed used, so the run can be reproduced.
    pub seed: u64,
    /// Per-region breakdown.
    pub regions: Vec<RegionReport>,
}

impl LoadReport {
    /// Same-region receipt p99 (target: < 50 ms).
    #[must_use]
    pub fn same_region_receipt_p99_ns(&self) -> u64 {
        self.same_region_receipt.p99
    }

    /// Cross-region receipt p95 (target: < 180 ms).
    #[must_use]
    pub fn cross_region_receipt_p95_ns(&self) -> u64 {
        self.cross_region_receipt.p95
    }

    /// Checkpoint-finality p95 (target: < 500 ms).
    #[must_use]
    pub fn checkpoint_finality_p95_ns(&self) -> u64 {
        self.finality.p95
    }

    /// Render the report as a valid machine-readable JSON document. Produced only at
    /// run end; contains only integers and strings, no floating point.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push('{');
        s.push_str(&format!("\"seed\":{},", self.seed));
        s.push_str(&format!(
            "\"clock_method\":\"{}\",",
            json_escape(&self.clock_method)
        ));
        s.push_str(&format!("\"planned_orders\":{},", self.planned_orders));
        s.push_str(&format!(
            "\"generated_commands\":{},",
            self.generated_commands
        ));
        s.push_str(&format!("\"new_orders\":{},", self.new_orders));
        s.push_str(&format!("\"cancels\":{},", self.cancels));
        s.push_str(&format!("\"replaces\":{},", self.replaces));
        s.push_str(&format!(
            "\"delivered_packets\":{},",
            self.delivered_packets
        ));
        s.push_str(&format!("\"dropped_packets\":{},", self.dropped_packets));
        s.push_str(&format!(
            "\"duplicate_deliveries\":{},",
            self.duplicate_deliveries
        ));
        s.push_str(&format!(
            "\"unique_orders_executed\":{},",
            self.unique_orders_executed
        ));
        s.push_str(&format!(
            "\"command_sequence_hash\":{},",
            self.command_sequence_hash
        ));
        s.push_str(&format!("\"dropped_samples\":{},", self.dropped_samples));
        s.push_str(&format!("\"oracle_updates\":{},", self.oracle_updates));
        s.push_str(&format!("\"market_data_gaps\":{},", self.market_data_gaps));
        s.push_str(&format!(
            "\"end_to_end\":{},",
            percentiles_json(&self.end_to_end)
        ));
        s.push_str(&format!(
            "\"same_region_receipt\":{},",
            percentiles_json(&self.same_region_receipt)
        ));
        s.push_str(&format!(
            "\"cross_region_receipt\":{},",
            percentiles_json(&self.cross_region_receipt)
        ));
        s.push_str(&format!(
            "\"finality\":{},",
            percentiles_json(&self.finality)
        ));
        s.push_str("\"regions\":[");
        for (i, r) in self.regions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&region_json(r));
        }
        s.push_str("]}");
        s
    }
}

fn percentiles_json(p: &Percentiles) -> String {
    format!(
        "{{\"count\":{},\"p50\":{},\"p90\":{},\"p95\":{},\"p99\":{},\"p999\":{},\"max\":{}}}",
        p.count, p.p50, p.p90, p.p95, p.p99, p.p999, p.max
    )
}

fn region_json(r: &RegionReport) -> String {
    format!(
        "{{\"name\":\"{}\",\"users\":{},\"cross_region\":{},\"generated\":{},\"delivered\":{},\"dropped\":{},\"gaps\":{},\"oracle_updates\":{},\"dropped_samples\":{},\"receipt\":{}}}",
        json_escape(&r.name),
        r.users,
        r.cross_region,
        r.generated,
        r.delivered,
        r.dropped,
        r.gaps,
        r.oracle_updates,
        r.dropped_samples,
        percentiles_json(&r.receipt)
    )
}

/// Mutable accumulators for one region's simulation.
struct RegionAccumulator {
    end_to_end: SampleSet,
    finality: SampleSet,
    generated: u64,
    new_orders: u64,
    cancels: u64,
    replaces: u64,
    delivered: u64,
    dropped: u64,
    dedup: DedupSet,
    hash: u64,
    gaps: u64,
    oracle_updates: u64,
}

impl RegionAccumulator {
    fn new(capacity: usize) -> Self {
        Self {
            end_to_end: SampleSet::new(capacity),
            finality: SampleSet::new(capacity),
            generated: 0,
            new_orders: 0,
            cancels: 0,
            replaces: 0,
            delivered: 0,
            dropped: 0,
            dedup: DedupSet::new(),
            hash: fnv1a_64(b"dexos.loadgen.stream.v1"),
            gaps: 0,
            oracle_updates: 0,
        }
    }
}

/// Run the full scenario deterministically and produce a merged report.
///
/// # Errors
/// Returns [`LoadError::Config`] if the scenario fails validation.
pub fn run_scenario(scenario: &LoadScenario) -> Result<LoadReport, LoadError> {
    scenario.validate()?;

    let total_users = scenario.total_users().max(1);
    let mut barrier = SyncBarrier::new(scenario.regions.len(), EPOCH_BASE_NS);

    // Combined sample buffers.
    let cap = scenario.sample_capacity;
    let mut combined_e2e = SampleSet::new(cap);
    let mut same_region = SampleSet::new(cap);
    let mut cross_region = SampleSet::new(cap);
    let mut combined_finality = SampleSet::new(cap);

    let mut region_reports = Vec::with_capacity(scenario.regions.len());
    let mut totals = Totals::default();

    for (region_index, region) in scenario.regions.iter().enumerate() {
        let start_ns = barrier.arrive();
        let acc = run_region(scenario, region, region_index, total_users, start_ns);

        // Fold this region's samples into the combined and class-specific buffers.
        for &v in acc.end_to_end.as_slice() {
            combined_e2e.record(v);
            if region.cross_region {
                cross_region.record(v);
            } else {
                same_region.record(v);
            }
        }
        for &v in acc.finality.as_slice() {
            combined_finality.record(v);
        }

        totals.accumulate(&acc);
        region_reports.push(RegionReport {
            name: region.name.clone(),
            users: region.users,
            cross_region: region.cross_region,
            generated: acc.generated,
            delivered: acc.delivered,
            dropped: acc.dropped,
            receipt: acc.end_to_end.percentiles(),
            gaps: acc.gaps,
            oracle_updates: acc.oracle_updates,
            dropped_samples: acc
                .end_to_end
                .dropped()
                .saturating_add(acc.finality.dropped()),
        });
    }

    let dropped_samples = combined_e2e
        .dropped()
        .saturating_add(same_region.dropped())
        .saturating_add(cross_region.dropped())
        .saturating_add(combined_finality.dropped());

    Ok(LoadReport {
        planned_orders: scenario.planned_actions(),
        generated_commands: totals.generated,
        new_orders: totals.new_orders,
        cancels: totals.cancels,
        replaces: totals.replaces,
        delivered_packets: totals.delivered,
        dropped_packets: totals.dropped,
        duplicate_deliveries: totals.duplicate_deliveries,
        unique_orders_executed: totals.unique_orders,
        command_sequence_hash: totals.hash,
        dropped_samples,
        end_to_end: combined_e2e.percentiles(),
        same_region_receipt: same_region.percentiles(),
        cross_region_receipt: cross_region.percentiles(),
        finality: combined_finality.percentiles(),
        oracle_updates: totals.oracle_updates,
        market_data_gaps: totals.gaps,
        clock_method: scenario.clock_method.label().to_string(),
        seed: scenario.seed,
        regions: region_reports,
    })
}

#[derive(Default)]
struct Totals {
    generated: u64,
    new_orders: u64,
    cancels: u64,
    replaces: u64,
    delivered: u64,
    dropped: u64,
    duplicate_deliveries: u64,
    unique_orders: u64,
    hash: u64,
    gaps: u64,
    oracle_updates: u64,
}

impl Totals {
    fn accumulate(&mut self, acc: &RegionAccumulator) {
        self.generated = self.generated.saturating_add(acc.generated);
        self.new_orders = self.new_orders.saturating_add(acc.new_orders);
        self.cancels = self.cancels.saturating_add(acc.cancels);
        self.replaces = self.replaces.saturating_add(acc.replaces);
        self.delivered = self.delivered.saturating_add(acc.delivered);
        self.dropped = self.dropped.saturating_add(acc.dropped);
        self.duplicate_deliveries = self
            .duplicate_deliveries
            .saturating_add(acc.dedup.duplicates());
        self.unique_orders = self.unique_orders.saturating_add(acc.dedup.unique());
        // Combine region hashes order-independently would lose info; fold in order.
        self.hash = fold_u64(self.hash, acc.hash);
        self.gaps = self.gaps.saturating_add(acc.gaps);
        self.oracle_updates = self.oracle_updates.saturating_add(acc.oracle_updates);
    }
}

fn run_region(
    scenario: &LoadScenario,
    region: &RegionConfig,
    region_index: usize,
    total_users: u64,
    start_ns: u64,
) -> RegionAccumulator {
    let mut acc = RegionAccumulator::new(scenario.sample_capacity);

    // Independent, reproducible RNG streams derived from the seed and region index.
    let gen_seed = fold_u64(
        fold_u64(scenario.seed, 0x6E5F_0001),
        u64::try_from(region_index).unwrap_or(0),
    );
    let imp_seed = fold_u64(
        fold_u64(scenario.seed, 0x1A2B_0002),
        u64::try_from(region_index).unwrap_or(0),
    );
    let mut rng = Lcg::new(gen_seed);
    let mut impairer = Impairer::new(imp_seed);

    // One session per user, bounded so a huge population stays tractable.
    let user_count = u64::from(region.users).clamp(1, MAX_EVENTS_PER_REGION);
    let mut sessions: Vec<SessionState> = (0..user_count)
        .map(|i| {
            let sid = u32::try_from(
                i + (u64::try_from(region_index).unwrap_or(0)) * MAX_EVENTS_PER_REGION,
            )
            .unwrap_or(u32::MAX);
            SessionState::new(sid)
        })
        .collect();

    let offset_ns = region.clock_offset_us.saturating_mul(1000);
    let region_users = u64::from(region.users).max(1);
    let mut session_cursor = 0usize;
    let mut budget = MAX_EVENTS_PER_REGION;

    for second in 0..scenario.duration_secs {
        // Region's share of the aggregate base rate.
        let base_region_rate = u128::from(scenario.orders_per_second)
            .saturating_mul(u128::from(region_users))
            / u128::from(total_users);
        let base_region_rate = u64::try_from(base_region_rate).unwrap_or(u64::MAX);
        let target = scenario
            .burst
            .rate_at(second, base_region_rate, scenario.duration_secs);

        for i in 0..target {
            if budget == 0 {
                break;
            }
            budget -= 1;

            let idx = session_cursor % sessions.len();
            let session = &mut sessions[idx];
            session_cursor = session_cursor.wrapping_add(1);
            let cmd = session.next_command(&mut rng, scenario);
            acc.hash = fold_u64(acc.hash, cmd.content_hash());
            acc.generated = acc.generated.saturating_add(1);
            match cmd.kind {
                CommandKind::NewOrder => acc.new_orders = acc.new_orders.saturating_add(1),
                CommandKind::Cancel => acc.cancels = acc.cancels.saturating_add(1),
                CommandKind::Replace => acc.replaces = acc.replaces.saturating_add(1),
            }

            // Client send time on the global timebase, spread across the second.
            let within = if target == 0 {
                0
            } else {
                i.saturating_mul(1_000_000_000) / target
            };
            let true_send = start_ns
                .saturating_add(second.saturating_mul(1_000_000_000))
                .saturating_add(within);

            let disp = impairer.decide(&scenario.impairment);
            let arrivals = disp.arrivals();
            if arrivals == 0 {
                acc.dropped = acc.dropped.saturating_add(1);
                continue;
            }
            acc.delivered = acc.delivered.saturating_add(u64::from(arrivals));
            acc.dropped = acc
                .dropped
                .saturating_add(if disp.delivered { 0 } else { 1 });

            // Dedup: every arrival carries the same key; only the first executes.
            for _ in 0..arrivals {
                acc.dedup.observe(cmd.dedup_key());
            }

            // Build the full-path timestamps and record latencies.
            let stamps = build_stamps(
                region,
                &scenario.impairment,
                &mut rng,
                true_send,
                offset_ns,
                disp.delay_ns,
            );
            if let Ok(e2e) = stamps.end_to_end() {
                acc.end_to_end.record(e2e);
            }
            if let Ok(fin) = stamps.to_finality() {
                acc.finality.record(fin);
            }
        }
    }

    // Oracle updates for the region (evenly interleaved; higher priority class).
    acc.oracle_updates =
        oracle_update_count(scenario.oracle.updates_per_second, scenario.duration_secs);

    // Market-data subscriber gap detection under injected loss.
    acc.gaps = simulate_market_data(scenario, &mut impairer);

    acc
}

fn build_stamps(
    region: &RegionConfig,
    impair: &crate::config::Impairment,
    rng: &mut Lcg,
    true_send: u64,
    offset_ns: i64,
    injected_delay_ns: u64,
) -> FullPathTimestamps {
    let mut t = FullPathTimestamps::new();
    let net_base = region
        .base_latency_us
        .saturating_add(impair.extra_latency_us)
        .saturating_mul(1000);
    let net_jitter_span = region
        .jitter_us
        .saturating_add(impair.latency_jitter_us)
        .saturating_mul(1000);
    let leg_out = net_base
        .saturating_add(rng.jitter(net_jitter_span))
        .saturating_add(injected_delay_ns);
    let leg_in = net_base.saturating_add(rng.jitter(net_jitter_span));

    // Client stamp carries the region clock offset; server stamps are on the global
    // timebase (offset 0), so corrected deltas cancel skew and stay non-negative.
    t.record(
        Stage::ClientSend,
        apply_offset(true_send, offset_ns),
        offset_ns,
    );
    let gw = true_send.saturating_add(leg_out);
    t.record(Stage::GatewayReceive, gw, 0);
    let sig = gw
        .saturating_add(SIG_COST)
        .saturating_add(rng.jitter(PROC_JITTER));
    t.record(Stage::SignatureVerified, sig, 0);
    let seq = sig
        .saturating_add(SEQ_COST)
        .saturating_add(rng.jitter(PROC_JITTER));
    t.record(Stage::SequencerReceive, seq, 0);
    let risk = seq
        .saturating_add(RISK_COST)
        .saturating_add(rng.jitter(PROC_JITTER));
    t.record(Stage::RiskComplete, risk, 0);
    let matched = risk
        .saturating_add(MATCH_COST)
        .saturating_add(rng.jitter(PROC_JITTER));
    t.record(Stage::MatchComplete, matched, 0);
    let receipt = matched
        .saturating_add(RECEIPT_COST)
        .saturating_add(rng.jitter(PROC_JITTER));
    t.record(Stage::ReceiptSent, receipt, 0);
    let client_recv = receipt.saturating_add(leg_in);
    t.record(
        Stage::ClientReceive,
        apply_offset(client_recv, offset_ns),
        offset_ns,
    );
    let cert = matched
        .saturating_add(CERT_COST)
        .saturating_add(rng.jitter(CERT_JITTER));
    t.record(Stage::CertificateFormed, cert, 0);
    let checkpoint = cert
        .saturating_add(CHECKPOINT_COST)
        .saturating_add(rng.jitter(CHECKPOINT_JITTER));
    t.record(Stage::CheckpointFinalized, checkpoint, 0);
    t
}

/// Apply a clock offset to a true (global) time, producing the raw local reading.
/// Saturates at zero to keep the result a valid `u64`; the large [`EPOCH_BASE_NS`]
/// base makes saturation unreachable for realistic offsets.
fn apply_offset(true_ns: u64, offset_ns: i64) -> u64 {
    let v = i128::from(true_ns) + i128::from(offset_ns);
    if v < 0 {
        0
    } else {
        u64::try_from(v).unwrap_or(u64::MAX)
    }
}

fn simulate_market_data(scenario: &LoadScenario, impairer: &mut Impairer) -> u64 {
    let md = &scenario.market_data;
    if md.subscribers == 0 || md.updates_per_second == 0 {
        return 0;
    }
    let total = md
        .updates_per_second
        .saturating_mul(scenario.duration_secs)
        .min(MAX_EVENTS_PER_REGION);
    let mut sub = SubscriberState::new();
    for seq in 0..total {
        // Drop a message per the loss ratio; the subscriber then sees a gap.
        let disp = impairer.decide(&scenario.impairment);
        if disp.delivered {
            sub.observe(seq);
        }
    }
    sub.gaps()
}

/// Build a tokio-free runtime entry point matching the historical signature.
///
/// # Errors
/// Returns [`LoadError::Config`] if the flat config is invalid.
pub fn run_blocking(config: LoadConfig) -> Result<LoadReport, LoadError> {
    config.validate()?;
    run_scenario(&config.to_scenario())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BurstKind, BurstPattern, Impairment, MarketDataWorkload, OracleWorkload};
    use std::time::Duration;
    use types::{Ratio, RATIO_SCALE};

    fn small_scenario() -> LoadScenario {
        LoadScenario {
            seed: 42,
            orders_per_second: 100,
            duration_secs: 5,
            sample_capacity: 4096,
            ..LoadScenario::default()
        }
    }

    #[test]
    fn deterministic_reproduction() {
        let s = small_scenario();
        let a = run_scenario(&s).unwrap();
        let b = run_scenario(&s).unwrap();
        assert_eq!(a.command_sequence_hash, b.command_sequence_hash);
        assert_eq!(a.generated_commands, b.generated_commands);
        assert_eq!(a.end_to_end, b.end_to_end);
        assert_eq!(a.finality, b.finality);
    }

    #[test]
    fn different_seed_changes_stream() {
        let mut a = small_scenario();
        let mut b = small_scenario();
        a.seed = 1;
        b.seed = 2;
        let ra = run_scenario(&a).unwrap();
        let rb = run_scenario(&b).unwrap();
        assert_ne!(ra.command_sequence_hash, rb.command_sequence_hash);
    }

    #[test]
    fn generated_matches_rate_times_duration_when_unbounded() {
        let s = small_scenario();
        let r = run_scenario(&s).unwrap();
        // 100/s * 5s = 500 planned; single region gets full rate.
        assert_eq!(r.planned_orders, 500);
        assert_eq!(r.generated_commands, 500);
        assert_eq!(r.new_orders + r.cancels + r.replaces, 500);
    }

    #[test]
    fn full_duplication_executes_each_order_once() {
        let mut s = small_scenario();
        s.impairment = Impairment {
            dup_ratio: Ratio::from_raw(RATIO_SCALE), // 100% duplication
            ..Impairment::default()
        };
        let r = run_scenario(&s).unwrap();
        // Every packet duplicated => two deliveries per order, one unique execution.
        assert_eq!(r.unique_orders_executed, r.generated_commands);
        assert_eq!(r.duplicate_deliveries, r.generated_commands);
        assert_eq!(r.delivered_packets, r.generated_commands * 2);
    }

    #[test]
    fn cancel_ratio_reflected_in_mix() {
        let mut s = small_scenario();
        s.orders_per_second = 2000;
        s.duration_secs = 10;
        s.cancel_ratio = Ratio::from_raw(500_000); // 0.5
        let r = run_scenario(&s).unwrap();
        // Cancels only fire once orders exist, so expect a substantial but sub-half
        // fraction. Assert it is clearly non-trivial.
        assert!(r.cancels > 0);
        assert!(r.cancels < r.generated_commands);
        assert!(r.new_orders > 0);
    }

    #[test]
    fn same_region_receipt_meets_target() {
        let s = small_scenario();
        let r = run_scenario(&s).unwrap();
        // Target: same-region receipt p99 < 50 ms.
        assert!(
            r.same_region_receipt_p99_ns() < 50_000_000,
            "{}",
            r.same_region_receipt_p99_ns()
        );
        // Finality p95 < 500 ms.
        assert!(r.checkpoint_finality_p95_ns() < 500_000_000);
    }

    #[test]
    fn cross_region_bucket_populates() {
        let mut s = small_scenario();
        s.regions = vec![
            RegionConfig {
                name: "home".into(),
                users: 50,
                cross_region: false,
                base_latency_us: 200,
                jitter_us: 50,
                clock_offset_us: 0,
            },
            RegionConfig {
                name: "far".into(),
                users: 50,
                cross_region: true,
                base_latency_us: 4000,
                jitter_us: 300,
                clock_offset_us: -2500,
            },
        ];
        let r = run_scenario(&s).unwrap();
        assert_eq!(r.regions.len(), 2);
        assert!(r.cross_region_receipt.count > 0);
        assert!(r.same_region_receipt.count > 0);
        // Cross-region latency should exceed same-region latency.
        assert!(r.cross_region_receipt.p95 > r.same_region_receipt.p95);
        // Target: cross-region receipt p95 < 180 ms.
        assert!(r.cross_region_receipt_p95_ns() < 180_000_000);
    }

    #[test]
    fn oracle_updates_counted() {
        let mut s = small_scenario();
        s.oracle = OracleWorkload {
            updates_per_second: 10,
        };
        let r = run_scenario(&s).unwrap();
        assert_eq!(r.oracle_updates, 50); // 10/s * 5s
    }

    #[test]
    fn market_data_gaps_detected_under_loss() {
        let mut s = small_scenario();
        s.market_data = MarketDataWorkload {
            subscribers: 1,
            updates_per_second: 1000,
        };
        s.impairment = Impairment {
            loss_ratio: Ratio::from_raw(100_000), // 10% loss
            ..Impairment::default()
        };
        let r = run_scenario(&s).unwrap();
        assert!(r.market_data_gaps > 0, "expected gaps under loss");
    }

    #[test]
    fn no_gaps_without_loss() {
        let mut s = small_scenario();
        s.market_data = MarketDataWorkload {
            subscribers: 1,
            updates_per_second: 500,
        };
        let r = run_scenario(&s).unwrap();
        assert_eq!(r.market_data_gaps, 0);
    }

    #[test]
    fn three_region_merged_report() {
        let mut s = small_scenario();
        s.regions = vec![
            RegionConfig {
                name: "a".into(),
                users: 30,
                cross_region: false,
                base_latency_us: 200,
                jitter_us: 50,
                clock_offset_us: 0,
            },
            RegionConfig {
                name: "b".into(),
                users: 30,
                cross_region: true,
                base_latency_us: 3000,
                jitter_us: 200,
                clock_offset_us: 1500,
            },
            RegionConfig {
                name: "c".into(),
                users: 30,
                cross_region: true,
                base_latency_us: 5000,
                jitter_us: 400,
                clock_offset_us: -3000,
            },
        ];
        let r = run_scenario(&s).unwrap();
        assert_eq!(r.regions.len(), 3);
        assert!(r.end_to_end.count > 0);
        // Combined count equals sum of region receipt counts.
        let region_sum: u64 = r.regions.iter().map(|x| x.receipt.count).sum();
        assert_eq!(r.end_to_end.count, region_sum);
    }

    #[test]
    fn json_export_is_well_formed() {
        let s = small_scenario();
        let r = run_scenario(&s).unwrap();
        let json = r.to_json();
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"command_sequence_hash\""));
        assert!(json.contains("\"same_region_receipt\""));
        // Balanced braces.
        let opens = json.matches('{').count();
        let closes = json.matches('}').count();
        assert_eq!(opens, closes);
    }

    #[test]
    fn json_reproducible_across_runs() {
        let s = small_scenario();
        assert_eq!(
            run_scenario(&s).unwrap().to_json(),
            run_scenario(&s).unwrap().to_json()
        );
    }

    #[test]
    fn run_blocking_compat() {
        let c = LoadConfig {
            target: "127.0.0.1:9000".into(),
            users: 100,
            market: "BTC-PERP".into(),
            orders_per_second: 1000,
            cancel_ratio: 0.7,
            duration: Duration::from_secs(3),
        };
        let r = run_blocking(c).unwrap();
        assert_eq!(r.planned_orders, 3000);
    }

    #[test]
    fn odd_configs_never_panic() {
        let mut r = Lcg::new(0xF00D);
        for _ in 0..200 {
            let impairment = Impairment {
                loss_ratio: Ratio::from_raw(i64::try_from(r.below(1_000_001)).unwrap_or(0)),
                dup_ratio: Ratio::from_raw(i64::try_from(r.below(1_000_001)).unwrap_or(0)),
                reorder_ratio: Ratio::from_raw(i64::try_from(r.below(1_000_001)).unwrap_or(0)),
                extra_latency_us: r.below(1000),
                latency_jitter_us: r.below(1000),
            };
            let burst = BurstPattern {
                kind: match r.below(3) {
                    0 => BurstKind::Steady,
                    1 => BurstKind::Bursty,
                    _ => BurstKind::Ramp,
                },
                peak_multiplier: u32::try_from(r.below(5)).unwrap_or(1),
                burst_secs: r.below(4),
                idle_secs: r.below(4),
            };
            let s = LoadScenario {
                seed: r.next_u64(),
                orders_per_second: r.below(5000),
                duration_secs: r.below(8),
                market_count: u32::try_from(r.below(10)).unwrap_or(1).max(1),
                cancel_ratio: Ratio::from_raw(i64::try_from(r.below(1_000_001)).unwrap_or(0)),
                replace_ratio: Ratio::from_raw(0),
                sample_capacity: usize::try_from(r.below(500)).unwrap_or(1).max(1),
                impairment,
                burst,
                ..LoadScenario::default()
            };
            // Some of these may fail validation; that is fine, just never panic.
            let _ = run_scenario(&s);
        }
    }
}
