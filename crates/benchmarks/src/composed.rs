//! Fail-closed measurement contract for the composed global validator benchmark.
//!
//! Component microbenchmarks remain useful diagnostics, but they cannot prove the
//! global target. This module validates artifacts produced by a real route from
//! signed order RPC through durable execution and Minimmit finalization. Missing
//! stages, counters, samples, fingerprints, or finality evidence are failures.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema shared by the workload manifest, run artifacts, and gate output.
pub const COMPOSED_SCHEMA_VERSION: u32 = 1;
/// Headline threshold from epic #567.
pub const TARGET_EFFECTIVE_ORDERS_PER_SECOND: u64 = 20_000_000;
/// Required untimed warmup before each measured interval.
pub const MIN_WARMUP_SECONDS: u64 = 60;
/// Required synchronized steady-state interval.
pub const MIN_STEADY_SECONDS: u64 = 600;
/// Required number of consecutive passing runs.
pub const REQUIRED_RUNS: usize = 3;

/// Immutable workload definition used by comparable baseline and optimized runs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadManifest {
    pub schema_version: u32,
    pub workload_id: String,
    pub offered_orders_per_second: u64,
    pub action_mix_bps: ActionMix,
    pub scale: WorkloadScale,
    pub auth: AuthPolicy,
    pub shard_count: u16,
    pub durability_mode: String,
    pub consensus: ConsensusContract,
    pub regions: Vec<RegionWorkload>,
    pub phases: RunPhases,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionMix {
    pub new: u16,
    pub cancel: u16,
    pub replace: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadScale {
    pub markets: u32,
    pub accounts: u64,
    pub resting_orders_per_side: u32,
    pub fill_fanout_p99: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthPolicy {
    pub session_identity: String,
    pub batch_authentication: String,
    pub replay_window: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusContract {
    pub n: u16,
    pub f: u16,
    pub m: u16,
    pub l: u16,
    pub checkpoint_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegionWorkload {
    pub name: String,
    pub offered_load_bps: u16,
    pub validators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunPhases {
    pub warmup_seconds: u64,
    pub steady_seconds: u64,
    pub drain_seconds: u64,
}

/// Complete evidence for one synchronized composed-path run.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedRun {
    pub schema_version: u32,
    pub run_id: String,
    pub workload_sha256: String,
    pub exact_command: String,
    pub target_reachable: bool,
    pub warmup_seconds: u64,
    pub steady_state_ns: u64,
    pub raw_samples: RawSamples,
    pub provenance: ProvenanceFingerprint,
    pub route: ProductionRoute,
    pub counts: Reconciliation,
    pub backlog: FinalityBacklog,
    pub receipt_latency_ns: LatencySummary,
    pub finality_latency_ns: LatencySummary,
    pub throughput: ThroughputBreakdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSamples {
    pub path: String,
    pub sha256: String,
    pub one_second_intervals: u64,
    pub complete: bool,
}

/// Fields required to decide whether two artifacts are compatible measurements.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceFingerprint {
    pub git_sha: String,
    pub git_dirty: bool,
    pub cargo_lock_sha256: String,
    pub rustc: String,
    pub llvm: String,
    pub profile: String,
    pub features: String,
    pub rustflags: String,
    pub cpu: String,
    pub microcode: String,
    pub numa: String,
    pub kernel: String,
    pub governor: String,
    pub affinity: String,
    pub nic: String,
    pub nic_driver: String,
    pub nic_firmware: String,
    pub nic_offloads: String,
    pub mtu: u32,
    pub topology: String,
}

/// Non-empty evidence references prove that every production stage participated.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionRoute {
    pub signed_rpc: String,
    pub decode_admission: String,
    pub canonical_sequence: String,
    pub durable_journal: String,
    pub execution_orderbook_risk: String,
    pub state_root: String,
    pub receipt: String,
    pub minimmit_checkpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    pub offered: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub executed: u64,
    pub receipted: u64,
    pub finalized: u64,
    pub accepted_new_orders: u64,
    pub accepted_cancel_orders: u64,
    pub accepted_replace_orders: u64,
    pub retries_excluded: u64,
    pub duplicates_excluded: u64,
    pub sequence_gaps: u64,
    pub nic_drops: u64,
    pub unexplained_loss: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityBacklog {
    pub pre_run: u64,
    pub end_of_steady: u64,
    pub after_two_checkpoint_intervals: u64,
    /// Signed least-squares or endpoint slope in finalized commands per second.
    pub steady_slope_per_second: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LatencySummary {
    pub count: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub p999: u64,
    pub max: u64,
    pub coordinated_omission_corrected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThroughputBreakdown {
    pub aggregate: ScopeThroughput,
    pub per_region: Vec<ScopeThroughput>,
    pub per_node: Vec<ScopeThroughput>,
    pub per_shard: Vec<ScopeThroughput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeThroughput {
    pub name: String,
    pub effective_orders: u64,
    pub interval_ns: u64,
}

/// Machine-readable result of validating a single run.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RunEvaluation {
    pub run_id: String,
    pub effective_orders: u64,
    pub effective_orders_per_second: u64,
    pub new_orders_per_second: u64,
    pub passed: bool,
    pub violations: Vec<String>,
}

/// Three-run target result. Every supplied run result is retained.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CampaignEvaluation {
    pub schema_version: u32,
    pub target_effective_orders_per_second: u64,
    pub required_consecutive_runs: usize,
    pub passed: bool,
    pub violations: Vec<String>,
    pub runs: Vec<RunEvaluation>,
}

/// Load and validate the immutable TOML workload, returning its SHA-256 digest.
pub fn load_manifest(path: &Path) -> Result<(WorkloadManifest, String), String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let text =
        std::str::from_utf8(&raw).map_err(|e| format!("{} is not UTF-8: {e}", path.display()))?;
    let manifest: WorkloadManifest =
        toml::from_str(text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let violations = validate_manifest(&manifest);
    if !violations.is_empty() {
        return Err(violations.join("; "));
    }
    Ok((manifest, sha256_hex(&raw)))
}

/// Validate one real composed-path artifact against the workload contract.
#[must_use]
pub fn evaluate_run(
    manifest: &WorkloadManifest,
    manifest_sha256: &str,
    run: &ComposedRun,
) -> RunEvaluation {
    let mut v = validate_manifest(manifest);
    if run.schema_version != COMPOSED_SCHEMA_VERSION {
        v.push("run schema_version is unsupported".into());
    }
    if run.workload_sha256 != manifest_sha256 {
        v.push("run workload hash does not match the committed manifest".into());
    }
    if run.run_id.trim().is_empty() || run.exact_command.trim().is_empty() {
        v.push("run_id and exact reproduction command are required".into());
    }
    if !run.target_reachable {
        v.push("target was unreachable".into());
    }
    if run.warmup_seconds < MIN_WARMUP_SECONDS {
        v.push(format!("warmup must be at least {MIN_WARMUP_SECONDS}s"));
    }
    let required_ns = manifest.phases.steady_seconds.saturating_mul(1_000_000_000);
    if run.steady_state_ns != required_ns {
        v.push(format!(
            "steady interval must equal the manifest's {}s",
            manifest.phases.steady_seconds
        ));
    }
    validate_samples(&run.raw_samples, run.steady_state_ns, &mut v);
    validate_provenance(&run.provenance, &mut v);
    validate_route(&run.route, &mut v);
    validate_counts(&run.counts, &mut v);
    validate_action_mix(manifest, &run.counts, &mut v);
    let expected_offered = manifest
        .offered_orders_per_second
        .checked_mul(manifest.phases.steady_seconds);
    if expected_offered != Some(run.counts.offered) {
        v.push("offered count does not match the immutable workload rate/interval".into());
    }
    validate_latency(
        &run.receipt_latency_ns,
        run.counts.receipted,
        "receipt",
        &mut v,
    );
    validate_latency(
        &run.finality_latency_ns,
        run.counts.finalized,
        "finality",
        &mut v,
    );
    if run.backlog.steady_slope_per_second > 0 {
        v.push("finality backlog has a positive steady-state slope".into());
    }
    if run.backlog.after_two_checkpoint_intervals > run.backlog.pre_run {
        v.push("finality backlog did not return to its pre-run level within two intervals".into());
    }

    let effective = run
        .counts
        .accepted
        .min(run.counts.executed)
        .min(run.counts.finalized);
    validate_throughput(
        manifest,
        &run.throughput,
        effective,
        run.steady_state_ns,
        &mut v,
    );
    let rate = rate_per_second(effective, run.steady_state_ns);
    if !rate_meets_target(effective, run.steady_state_ns) {
        v.push(format!(
            "effective finalized throughput {rate}/s is below {TARGET_EFFECTIVE_ORDERS_PER_SECOND}/s"
        ));
    }

    RunEvaluation {
        run_id: run.run_id.clone(),
        effective_orders: effective,
        effective_orders_per_second: rate,
        new_orders_per_second: rate_per_second(run.counts.accepted_new_orders, run.steady_state_ns),
        passed: v.is_empty(),
        violations: v,
    }
}

/// Require exactly three ordered, compatible, consecutive passing run artifacts.
#[must_use]
pub fn evaluate_campaign(
    manifest: &WorkloadManifest,
    manifest_sha256: &str,
    runs: &[ComposedRun],
) -> CampaignEvaluation {
    let results: Vec<_> = runs
        .iter()
        .map(|run| evaluate_run(manifest, manifest_sha256, run))
        .collect();
    let mut violations = Vec::new();
    if runs.len() != REQUIRED_RUNS {
        violations.push(format!(
            "campaign requires exactly {REQUIRED_RUNS} consecutive runs, got {}",
            runs.len()
        ));
    }
    let mut ids = BTreeSet::new();
    for run in runs {
        if !ids.insert(run.run_id.as_str()) {
            violations.push(format!("duplicate run_id '{}'", run.run_id));
        }
    }
    if let Some(first) = runs.first() {
        for run in &runs[1..] {
            if !compatible_fingerprint(&first.provenance, &run.provenance) {
                violations.push(format!(
                    "run '{}' has incompatible host/build provenance",
                    run.run_id
                ));
            }
        }
    }
    if results.iter().any(|r| !r.passed) {
        violations.push("one or more consecutive runs failed the composed gate".into());
    }
    CampaignEvaluation {
        schema_version: COMPOSED_SCHEMA_VERSION,
        target_effective_orders_per_second: TARGET_EFFECTIVE_ORDERS_PER_SECOND,
        required_consecutive_runs: REQUIRED_RUNS,
        passed: violations.is_empty(),
        violations,
        runs: results,
    }
}

fn validate_manifest(m: &WorkloadManifest) -> Vec<String> {
    let mut v = Vec::new();
    if m.schema_version != COMPOSED_SCHEMA_VERSION {
        v.push("manifest schema_version is unsupported".into());
    }
    if m.workload_id.trim().is_empty() {
        v.push("workload_id is required".into());
    }
    if m.offered_orders_per_second < TARGET_EFFECTIVE_ORDERS_PER_SECOND {
        v.push(format!(
            "offered load must be at least {TARGET_EFFECTIVE_ORDERS_PER_SECOND}/s"
        ));
    }
    let mix = u32::from(m.action_mix_bps.new)
        + u32::from(m.action_mix_bps.cancel)
        + u32::from(m.action_mix_bps.replace);
    if mix != 10_000 {
        v.push("new/cancel/replace basis points must sum to 10000".into());
    }
    if m.scale.markets == 0 || m.scale.accounts == 0 || m.scale.resting_orders_per_side == 0 {
        v.push("market/account/book scale must be nonzero".into());
    }
    if m.auth.session_identity.trim().is_empty()
        || m.auth.batch_authentication.trim().is_empty()
        || m.auth.replay_window == 0
    {
        v.push("session authentication and replay policy must be fixed".into());
    }
    if m.shard_count == 0 || m.durability_mode.trim().is_empty() || m.durability_mode == "none" {
        v.push("shard count and durable journal mode must be fixed".into());
    }
    let c = &m.consensus;
    if c.n < 6
        || u32::from(c.n) < 5u32.saturating_mul(u32::from(c.f)).saturating_add(1)
        || c.m != c.f.saturating_mul(2).saturating_add(1)
        || c.l != c.n.saturating_sub(c.f)
        || !(node::config::CHECKPOINT_INTERVAL_MIN_MS..=node::config::CHECKPOINT_INTERVAL_MAX_MS)
            .contains(&c.checkpoint_interval_ms)
    {
        v.push("Minimmit n/f/M/L or checkpoint interval is invalid".into());
    }
    let expected = ["london", "new-york", "tokyo"];
    let names: BTreeSet<_> = m.regions.iter().map(|r| r.name.as_str()).collect();
    if expected.iter().any(|name| !names.contains(name)) || m.regions.len() != 3 {
        v.push("workload must define exactly London, New York, and Tokyo".into());
    }
    let region_bps: u32 = m
        .regions
        .iter()
        .map(|r| u32::from(r.offered_load_bps))
        .sum();
    if region_bps != 10_000
        || m.regions
            .iter()
            .any(|r| !(3_000..=3_667).contains(&r.offered_load_bps) || r.validators.is_empty())
    {
        v.push("regional load must sum to 10000 bps, approximately one third each".into());
    }
    if m.phases.warmup_seconds < MIN_WARMUP_SECONDS
        || m.phases.steady_seconds != MIN_STEADY_SECONDS
        || m.phases.drain_seconds.saturating_mul(1000) < c.checkpoint_interval_ms.saturating_mul(2)
    {
        v.push(
            "phases must provide >=60s warmup, 600s steady, and two checkpoint intervals of drain"
                .into(),
        );
    }
    v
}

fn validate_samples(s: &RawSamples, steady_ns: u64, v: &mut Vec<String>) {
    let required = steady_ns / 1_000_000_000;
    if !s.complete || s.path.trim().is_empty() || !is_sha256(&s.sha256) {
        v.push("complete raw samples with path and SHA-256 are required".into());
    }
    if s.one_second_intervals != required {
        v.push("raw one-second samples must cover the exact steady interval".into());
    }
}

fn validate_provenance(p: &ProvenanceFingerprint, v: &mut Vec<String>) {
    let required = [
        &p.git_sha,
        &p.cargo_lock_sha256,
        &p.rustc,
        &p.llvm,
        &p.profile,
        &p.features,
        &p.rustflags,
        &p.cpu,
        &p.microcode,
        &p.numa,
        &p.kernel,
        &p.governor,
        &p.affinity,
        &p.nic,
        &p.nic_driver,
        &p.nic_firmware,
        &p.nic_offloads,
        &p.topology,
    ];
    if required.iter().any(|s| s.trim().is_empty())
        || !is_sha256(&p.cargo_lock_sha256)
        || p.mtu == 0
    {
        v.push("full build, CPU, OS, NIC, affinity, and topology fingerprint is required".into());
    }
}

fn validate_route(r: &ProductionRoute, v: &mut Vec<String>) {
    let stages = [
        &r.signed_rpc,
        &r.decode_admission,
        &r.canonical_sequence,
        &r.durable_journal,
        &r.execution_orderbook_risk,
        &r.state_root,
        &r.receipt,
        &r.minimmit_checkpoint,
    ];
    if stages.iter().any(|s| s.trim().is_empty()) {
        v.push("every signed-RPC through Minimmit-finalization route stage needs evidence".into());
    }
}

fn validate_counts(c: &Reconciliation, v: &mut Vec<String>) {
    if c.accepted.saturating_add(c.rejected) != c.offered {
        v.push("offered != accepted + rejected".into());
    }
    if c.accepted != c.executed || c.accepted != c.receipted || c.accepted != c.finalized {
        v.push("accepted/executed/receipted/finalized counts do not reconcile".into());
    }
    if c.accepted_new_orders
        .checked_add(c.accepted_cancel_orders)
        .and_then(|value| value.checked_add(c.accepted_replace_orders))
        != Some(c.accepted)
    {
        v.push("accepted action counts do not conserve accepted commands".into());
    }
    if c.sequence_gaps != 0 || c.nic_drops != 0 || c.unexplained_loss != 0 {
        v.push("sequence gaps, NIC drops, or unexplained loss are nonzero".into());
    }
}

fn validate_action_mix(m: &WorkloadManifest, c: &Reconciliation, v: &mut Vec<String>) {
    for (name, actual, expected_bps) in [
        ("new", c.accepted_new_orders, m.action_mix_bps.new),
        ("cancel", c.accepted_cancel_orders, m.action_mix_bps.cancel),
        (
            "replace",
            c.accepted_replace_orders,
            m.action_mix_bps.replace,
        ),
    ] {
        let actual_scaled = u128::from(actual).saturating_mul(10_000);
        let expected_scaled = u128::from(c.accepted).saturating_mul(u128::from(expected_bps));
        if actual_scaled.abs_diff(expected_scaled) > u128::from(c.accepted) {
            v.push(format!(
                "accepted {name} action mix differs from the manifest by more than one basis point"
            ));
        }
    }
}

fn validate_latency(l: &LatencySummary, expected: u64, name: &str, v: &mut Vec<String>) {
    if l.count != expected {
        v.push(format!("{name} latency sample count does not reconcile"));
    }
    if !l.coordinated_omission_corrected {
        v.push(format!("{name} latency is not coordinated-omission safe"));
    }
    if !(l.p50 <= l.p95 && l.p95 <= l.p99 && l.p99 <= l.p999 && l.p999 <= l.max) {
        v.push(format!("{name} latency percentiles are not monotone"));
    }
}

fn validate_throughput(
    manifest: &WorkloadManifest,
    t: &ThroughputBreakdown,
    effective: u64,
    ns: u64,
    v: &mut Vec<String>,
) {
    if t.aggregate.name != "global"
        || t.aggregate.effective_orders != effective
        || t.aggregate.interval_ns != ns
    {
        v.push("aggregate throughput does not match reconciled effective count/interval".into());
    }
    let regions: BTreeSet<_> = t.per_region.iter().map(|s| s.name.as_str()).collect();
    let expected_regions: BTreeSet<_> = manifest.regions.iter().map(|r| r.name.as_str()).collect();
    if t.per_region.len() != expected_regions.len() || regions != expected_regions {
        v.push("per-region throughput is incomplete".into());
    }
    let nodes: BTreeSet<_> = t.per_node.iter().map(|s| s.name.as_str()).collect();
    let expected_nodes: BTreeSet<_> = manifest
        .regions
        .iter()
        .flat_map(|r| r.validators.iter().map(String::as_str))
        .collect();
    if t.per_node.len() != expected_nodes.len() || nodes != expected_nodes {
        v.push("per-node throughput does not cover the manifest validator set exactly".into());
    }
    let shards: BTreeSet<_> = t.per_shard.iter().map(|s| s.name.as_str()).collect();
    if t.per_shard.len() != usize::from(manifest.shard_count) || shards.len() != t.per_shard.len() {
        v.push("per-shard throughput does not cover the configured unique shard count".into());
    }
    if t.per_region
        .iter()
        .chain(t.per_node.iter())
        .chain(t.per_shard.iter())
        .any(|s| s.name.trim().is_empty() || s.interval_ns != ns)
    {
        v.push("throughput scopes must use the synchronized interval".into());
    }
    let effective = u128::from(effective);
    for (name, scopes) in [
        ("region", t.per_region.as_slice()),
        ("node", t.per_node.as_slice()),
        ("shard", t.per_shard.as_slice()),
    ] {
        let total = scopes.iter().fold(0u128, |sum, scope| {
            sum.saturating_add(u128::from(scope.effective_orders))
        });
        if total != effective {
            v.push(format!(
                "per-{name} throughput does not conserve the global count"
            ));
        }
    }
}

fn compatible_fingerprint(a: &ProvenanceFingerprint, b: &ProvenanceFingerprint) -> bool {
    a.cargo_lock_sha256 == b.cargo_lock_sha256
        && a.rustc == b.rustc
        && a.llvm == b.llvm
        && a.profile == b.profile
        && a.features == b.features
        && a.rustflags == b.rustflags
        && a.cpu == b.cpu
        && a.microcode == b.microcode
        && a.numa == b.numa
        && a.kernel == b.kernel
        && a.governor == b.governor
        && a.affinity == b.affinity
        && a.nic == b.nic
        && a.nic_driver == b.nic_driver
        && a.nic_firmware == b.nic_firmware
        && a.nic_offloads == b.nic_offloads
        && a.mtu == b.mtu
        && a.topology == b.topology
}

fn rate_per_second(count: u64, interval_ns: u64) -> u64 {
    if interval_ns == 0 {
        return 0;
    }
    u64::try_from(u128::from(count).saturating_mul(1_000_000_000) / u128::from(interval_ns))
        .unwrap_or(u64::MAX)
}

fn rate_meets_target(count: u64, interval_ns: u64) -> bool {
    interval_ns != 0
        && u128::from(count).saturating_mul(1_000_000_000)
            >= u128::from(TARGET_EFFECTIVE_ORDERS_PER_SECOND)
                .saturating_mul(u128::from(interval_ns))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> (WorkloadManifest, String) {
        load_manifest(Path::new("workloads/global-20m-v1.toml")).expect("committed manifest")
    }

    #[test]
    fn committed_unoptimized_baseline_uses_run_schema_and_fails_closed() {
        let (manifest, hash) = manifest();
        let raw = std::fs::read("artifacts/20m/baseline-unoptimized-v1.json")
            .expect("committed baseline");
        let run: ComposedRun = serde_json::from_slice(&raw).expect("ComposedRun schema");
        let result = evaluate_run(&manifest, &hash, &run);
        assert!(!result.passed);
        assert_eq!(result.effective_orders_per_second, 0);
        assert!(result
            .violations
            .iter()
            .any(|v| v == "target was unreachable"));

        let archived = std::fs::read("artifacts/20m/baseline-unoptimized-v1-evaluation.json")
            .expect("committed baseline evaluation");
        let archived: CampaignEvaluation =
            serde_json::from_slice(&archived).expect("CampaignEvaluation schema");
        assert_eq!(archived, evaluate_campaign(&manifest, &hash, &[run]));
    }

    fn latency(count: u64) -> LatencySummary {
        LatencySummary {
            count,
            p50: 10,
            p95: 20,
            p99: 30,
            p999: 40,
            max: 50,
            coordinated_omission_corrected: true,
        }
    }

    fn passing_run(id: &str, hash: &str) -> ComposedRun {
        let ns = 600_000_000_000;
        let accepted = 12_000_000_000;
        let offered = 14_400_000_000;
        let scope = |name: &str, n| ScopeThroughput {
            name: name.into(),
            effective_orders: n,
            interval_ns: ns,
        };
        let partition = |names: Vec<String>| {
            let count = u64::try_from(names.len()).unwrap_or(1).max(1);
            let base = accepted / count;
            let remainder = accepted % count;
            names
                .into_iter()
                .enumerate()
                .map(|(index, name)| {
                    let extra = u64::from(u64::try_from(index).unwrap_or(u64::MAX) < remainder);
                    scope(&name, base.saturating_add(extra))
                })
                .collect()
        };
        ComposedRun {
            schema_version: 1,
            run_id: id.into(),
            workload_sha256: hash.into(),
            exact_command: "campaign run --manifest global-20m-v1.toml".into(),
            target_reachable: true,
            warmup_seconds: 60,
            steady_state_ns: ns,
            raw_samples: RawSamples {
                path: format!("raw/{id}.jsonl"),
                sha256: "a".repeat(64),
                one_second_intervals: 600,
                complete: true,
            },
            provenance: ProvenanceFingerprint {
                git_sha: "1".repeat(40),
                git_dirty: false,
                cargo_lock_sha256: "b".repeat(64),
                rustc: "rustc 1.92.0".into(),
                llvm: "LLVM 21".into(),
                profile: "release".into(),
                features: "minimmit,production".into(),
                rustflags: "-C target-cpu=native".into(),
                cpu: "test-cpu".into(),
                microcode: "test-microcode".into(),
                numa: "node0".into(),
                kernel: "test-kernel".into(),
                governor: "performance".into(),
                affinity: "0-63".into(),
                nic: "test-nic".into(),
                nic_driver: "test-driver".into(),
                nic_firmware: "test-firmware".into(),
                nic_offloads: "documented".into(),
                mtu: 9000,
                topology: "london-new-york-tokyo-doublezero".into(),
            },
            route: ProductionRoute {
                signed_rpc: "rpc.log".into(),
                decode_admission: "admission.log".into(),
                canonical_sequence: "sequence.log".into(),
                durable_journal: "wal.log".into(),
                execution_orderbook_risk: "execution.log".into(),
                state_root: "roots.jsonl".into(),
                receipt: "receipts.jsonl".into(),
                minimmit_checkpoint: "finality.jsonl".into(),
            },
            counts: Reconciliation {
                offered,
                accepted,
                rejected: offered - accepted,
                executed: accepted,
                receipted: accepted,
                finalized: accepted,
                accepted_new_orders: 8_400_000_000,
                accepted_cancel_orders: 2_400_000_000,
                accepted_replace_orders: 1_200_000_000,
                retries_excluded: 0,
                duplicates_excluded: 0,
                sequence_gaps: 0,
                nic_drops: 0,
                unexplained_loss: 0,
            },
            backlog: FinalityBacklog {
                pre_run: 10,
                end_of_steady: 10,
                after_two_checkpoint_intervals: 10,
                steady_slope_per_second: 0,
            },
            receipt_latency_ns: latency(accepted),
            finality_latency_ns: latency(accepted),
            throughput: ThroughputBreakdown {
                aggregate: scope("global", accepted),
                per_region: vec![
                    scope("london", 4_000_000_000),
                    scope("new-york", 4_000_000_000),
                    scope("tokyo", 4_000_000_000),
                ],
                per_node: partition(
                    [
                        "lon-validator-0",
                        "lon-validator-1",
                        "nyc-validator-0",
                        "nyc-validator-1",
                        "tyo-validator-0",
                        "tyo-validator-1",
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                ),
                per_shard: partition((0..256).map(|i| format!("shard-{i}")).collect()),
            },
        }
    }

    #[test]
    fn committed_manifest_is_valid_and_hashed() {
        let (m, hash) = manifest();
        assert_eq!(m.workload_id, "global-orders-20m-v1");
        assert!(is_sha256(&hash));
    }

    #[test]
    fn doublezero_topology_matches_the_composed_manifest() {
        let (manifest, _) = manifest();
        let raw = std::fs::read_to_string("../../deploy/doublezero/topology.toml")
            .expect("committed DoubleZero topology");
        let topology: toml::Value = toml::from_str(&raw).expect("valid topology TOML");
        assert_eq!(
            topology
                .get("logical_shards")
                .and_then(toml::Value::as_integer),
            Some(i64::from(manifest.shard_count))
        );
        let committee = topology
            .get("committee")
            .and_then(toml::Value::as_table)
            .expect("committee table");
        for (field, value) in [
            ("n", manifest.consensus.n),
            ("f", manifest.consensus.f),
            ("m", manifest.consensus.m),
            ("l", manifest.consensus.l),
        ] {
            assert_eq!(
                committee.get(field).and_then(toml::Value::as_integer),
                Some(i64::from(value)),
                "committee {field} drifted"
            );
        }
        let validators = topology
            .get("validators")
            .and_then(toml::Value::as_array)
            .expect("validator array");
        let actual: BTreeSet<_> = validators
            .iter()
            .filter_map(|v| v.get("name"))
            .filter_map(toml::Value::as_str)
            .collect();
        let expected: BTreeSet<_> = manifest
            .regions
            .iter()
            .flat_map(|region| region.validators.iter().map(String::as_str))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn three_complete_composed_runs_pass() {
        let (m, hash) = manifest();
        let runs = [
            passing_run("run-1", &hash),
            passing_run("run-2", &hash),
            passing_run("run-3", &hash),
        ];
        let result = evaluate_campaign(&m, &hash, &runs);
        assert!(result.passed, "{:?}", result.violations);
        assert!(result.runs.iter().all(|r| r.passed));
    }

    #[test]
    fn incomplete_or_nonconserving_topology_cannot_pass() {
        let (m, hash) = manifest();
        let mut run = passing_run("bad-topology", &hash);
        run.throughput.per_node.pop();
        run.throughput.per_shard[0].effective_orders = run.throughput.per_shard[0]
            .effective_orders
            .saturating_add(1);
        let result = evaluate_run(&m, &hash, &run);
        assert!(!result.passed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.contains("validator set exactly")));
        assert!(result
            .violations
            .iter()
            .any(|v| v.contains("per-shard throughput does not conserve")));
    }

    #[test]
    fn microbenchmark_or_missing_finality_cannot_pass() {
        let (m, hash) = manifest();
        let mut run = passing_run("component-only", &hash);
        run.route.minimmit_checkpoint.clear();
        run.counts.finalized = 0;
        run.finality_latency_ns.count = 0;
        let result = evaluate_run(&m, &hash, &run);
        assert!(!result.passed);
        assert!(result.violations.iter().any(|x| x.contains("Minimmit")));
        assert_eq!(result.effective_orders_per_second, 0);
    }

    #[test]
    fn rounded_rate_cannot_false_pass_target() {
        let (m, hash) = manifest();
        let mut run = passing_run("just-under", &hash);
        let under = 11_999_999_999;
        run.counts.offered = under;
        run.counts.accepted = under;
        run.counts.executed = under;
        run.counts.receipted = under;
        run.counts.finalized = under;
        run.counts.accepted_new_orders = under;
        run.receipt_latency_ns.count = under;
        run.finality_latency_ns.count = under;
        run.throughput.aggregate.effective_orders = under;
        let result = evaluate_run(&m, &hash, &run);
        assert!(!result.passed);
        assert!(result
            .violations
            .iter()
            .any(|x| x.contains("below 20000000")));
    }

    #[test]
    fn malformed_manifest_fails_closed() {
        let (mut m, _) = manifest();
        m.action_mix_bps.replace = 0;
        let hash = "0".repeat(64);
        let result = evaluate_run(&m, &hash, &passing_run("bad", &hash));
        assert!(!result.passed);
        assert!(result.violations.iter().any(|x| x.contains("sum to 10000")));
    }
}
