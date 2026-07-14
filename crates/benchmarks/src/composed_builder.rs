//! Build a composed-run artifact from authenticated regional packed reports.
//!
//! The builder performs structural reconciliation before emitting an artifact.
//! Performance below the headline target remains representable as an honest
//! failing run, while missing or internally inconsistent evidence is rejected.

use std::collections::BTreeSet;

use loadgen::{
    ControlAuthenticator, DistributedPackedAgentReport, NanoHistogram, PackedCompletionBoundary,
    PackedLifecycleCounters, PackedSteadyInterval,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::composed::{
    ComposedRun, FinalityBacklog, LatencySummary, ProductionRoute, ProvenanceFingerprint,
    RawSamples, Reconciliation, ScopeThroughput, ThroughputBreakdown, WorkloadManifest,
    COMPOSED_SCHEMA_VERSION,
};

/// Lifecycle totals attributed to one canonical region, validator owner, or shard.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCounters {
    pub name: String,
    pub offered: u64,
    pub accepted: u64,
    pub executed: u64,
    pub finalized: u64,
}

/// Operator-collected evidence that cannot be derived from load-agent receipts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedRunEvidence {
    pub schema_version: u32,
    pub run_id: u128,
    pub exact_command: String,
    pub target_reachable: bool,
    pub provenance: ProvenanceFingerprint,
    pub route: ProductionRoute,
    pub backlog: FinalityBacklog,
    /// Canonical ownership attribution, not replicated validator execution totals.
    pub per_node: Vec<ScopeCounters>,
    /// Canonical ownership attribution for every configured logical shard.
    pub per_shard: Vec<ScopeCounters>,
    pub retries_excluded: u64,
    pub duplicates_excluded: u64,
    pub sequence_gaps: u64,
    pub nic_drops: u64,
    pub unexplained_loss: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RawPackedCampaign<'a> {
    schema_version: u32,
    agents: Vec<&'a DistributedPackedAgentReport>,
    evidence: &'a ComposedRunEvidence,
}

/// Render the exact raw input in deterministic region/agent order.
pub fn render_raw_campaign(
    agents: &[DistributedPackedAgentReport],
    evidence: &ComposedRunEvidence,
) -> Result<Vec<u8>, String> {
    let mut ordered: Vec<_> = agents.iter().collect();
    ordered.sort_by(|a, b| {
        let left = &a.assignment.assignment;
        let right = &b.assignment.assignment;
        (&left.region, &left.agent_id).cmp(&(&right.region, &right.agent_id))
    });
    serde_json::to_vec_pretty(&RawPackedCampaign {
        schema_version: COMPOSED_SCHEMA_VERSION,
        agents: ordered,
        evidence,
    })
    .map_err(|error| format!("serialize raw campaign: {error}"))
}

/// Reconcile authenticated agent reports and operator evidence into one run.
pub fn build_composed_run(
    manifest: &WorkloadManifest,
    manifest_sha256: &str,
    agents: &[DistributedPackedAgentReport],
    authenticator: &ControlAuthenticator,
    evidence: ComposedRunEvidence,
    raw_path: String,
    raw_sha256: String,
) -> Result<ComposedRun, String> {
    if evidence.schema_version != COMPOSED_SCHEMA_VERSION {
        return Err("evidence schema_version is unsupported".into());
    }
    if !is_sha256(manifest_sha256) {
        return Err("manifest SHA-256 is malformed".into());
    }
    validate_evidence(&evidence)?;
    if agents.len() != manifest.regions.len() {
        return Err(format!(
            "expected {} regional agent reports, got {}",
            manifest.regions.len(),
            agents.len()
        ));
    }
    if raw_path.trim().is_empty() || !is_sha256(&raw_sha256) {
        return Err("raw artifact path and lowercase SHA-256 are required".into());
    }

    let expected_regions: BTreeSet<_> = manifest.regions.iter().map(|r| r.name.as_str()).collect();
    let mut regions = BTreeSet::new();
    let mut agent_ids = BTreeSet::new();
    let mut nonce_namespaces = BTreeSet::new();
    let mut identity_ranges = Vec::with_capacity(agents.len());
    let mut synchronized_start = None;
    let mut global = PackedLifecycleCounters::default();
    let mut accepted_new_orders = 0u64;
    let mut accepted_cancel_orders = 0u64;
    let mut accepted_replace_orders = 0u64;
    let mut receipt_histogram = NanoHistogram::default();
    let mut finality_histogram = NanoHistogram::default();
    let mut per_region = Vec::with_capacity(agents.len());

    for agent in agents {
        validate_agent(manifest, evidence.run_id, agent, authenticator)?;
        let assignment = &agent.assignment.assignment;
        if !regions.insert(assignment.region.as_str()) {
            return Err(format!(
                "duplicate regional report for '{}'",
                assignment.region
            ));
        }
        if !agent_ids.insert(assignment.agent_id.as_str()) {
            return Err(format!("duplicate agent_id '{}'", assignment.agent_id));
        }
        if !nonce_namespaces.insert(assignment.nonce_namespace) {
            return Err("agent nonce namespaces overlap".into());
        }
        if synchronized_start.is_some_and(|start| start != assignment.start_unix_ns) {
            return Err("agent assignments do not share one synchronized start".into());
        }
        synchronized_start = Some(assignment.start_unix_ns);
        identity_ranges.push(assignment.client_id_start..assignment.client_id_end);
        checked_add_counters(&mut global, agent.report.counters)?;
        accepted_new_orders = checked_add(
            accepted_new_orders,
            agent
                .report
                .steady_intervals
                .iter()
                .map(|interval| interval.accepted_new_records)
                .try_fold(0u64, checked_add)?,
        )?;
        accepted_cancel_orders = checked_add(
            accepted_cancel_orders,
            agent
                .report
                .steady_intervals
                .iter()
                .map(|interval| interval.accepted_cancel_records)
                .try_fold(0u64, checked_add)?,
        )?;
        accepted_replace_orders = checked_add(
            accepted_replace_orders,
            agent
                .report
                .steady_intervals
                .iter()
                .map(|interval| interval.accepted_replace_records)
                .try_fold(0u64, checked_add)?,
        )?;
        receipt_histogram
            .checked_merge(&agent.report.execution_receipt_ns)
            .map_err(|error| format!("merge receipt histograms: {error}"))?;
        finality_histogram
            .checked_merge(&agent.report.finality_receipt_ns)
            .map_err(|error| format!("merge finality histograms: {error}"))?;
        per_region.push(scope_throughput(
            &assignment.region,
            agent.report.counters,
            agent.report.elapsed_ns,
        ));
    }
    if regions != expected_regions {
        return Err("agent reports do not cover the manifest regions exactly".into());
    }
    identity_ranges.sort_by_key(|range| range.start);
    if identity_ranges
        .windows(2)
        .any(|ranges| ranges[0].end > ranges[1].start)
    {
        return Err("agent client identity ranges overlap".into());
    }
    per_region.sort_by(|a, b| a.name.cmp(&b.name));

    let receipted = global
        .executed_records
        .checked_add(global.failed_records)
        .ok_or_else(|| "lifecycle counter overflow".to_string())?;
    let rejected = global
        .offered_records
        .checked_sub(global.admitted_records)
        .ok_or_else(|| "accepted records exceed offered records".to_string())?;
    let expected_offered = manifest
        .offered_orders_per_second
        .checked_mul(manifest.phases.steady_seconds)
        .ok_or_else(|| "manifest offered count overflow".to_string())?;
    if global.offered_records != expected_offered {
        return Err(format!(
            "global offered count {} does not match manifest {}",
            global.offered_records, expected_offered
        ));
    }
    validate_action_mix(
        manifest,
        accepted_new_orders,
        accepted_cancel_orders,
        accepted_replace_orders,
        global.executed_records,
    )?;
    let interval_ns = manifest
        .phases
        .steady_seconds
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "steady interval overflow".to_string())?;

    let expected_nodes: BTreeSet<_> = manifest
        .regions
        .iter()
        .flat_map(|region| region.validators.iter().map(String::as_str))
        .collect();
    validate_scopes("node", &evidence.per_node, Some(&expected_nodes), global)?;
    validate_scopes("shard", &evidence.per_shard, None, global)?;
    if evidence.per_shard.len() != usize::from(manifest.shard_count) {
        return Err(format!(
            "expected {} shard scopes, got {}",
            manifest.shard_count,
            evidence.per_shard.len()
        ));
    }

    let per_node = evidence
        .per_node
        .iter()
        .map(|scope| scope_from_counters(scope, interval_ns))
        .collect();
    let per_shard = evidence
        .per_shard
        .iter()
        .map(|scope| scope_from_counters(scope, interval_ns))
        .collect();
    let effective = global
        .admitted_records
        .min(global.executed_records)
        .min(global.finalized_records);

    Ok(ComposedRun {
        schema_version: COMPOSED_SCHEMA_VERSION,
        run_id: evidence.run_id.to_string(),
        workload_sha256: manifest_sha256.to_string(),
        exact_command: evidence.exact_command,
        target_reachable: evidence.target_reachable,
        warmup_seconds: manifest.phases.warmup_seconds,
        steady_state_ns: interval_ns,
        raw_samples: RawSamples {
            path: raw_path,
            sha256: raw_sha256,
            one_second_intervals: manifest.phases.steady_seconds,
            complete: true,
        },
        provenance: evidence.provenance,
        route: evidence.route,
        counts: Reconciliation {
            offered: global.offered_records,
            accepted: global.admitted_records,
            rejected,
            executed: global.executed_records,
            receipted,
            finalized: global.finalized_records,
            accepted_new_orders,
            accepted_cancel_orders,
            accepted_replace_orders,
            retries_excluded: evidence.retries_excluded,
            duplicates_excluded: evidence.duplicates_excluded,
            sequence_gaps: evidence.sequence_gaps,
            nic_drops: evidence.nic_drops,
            unexplained_loss: evidence.unexplained_loss,
        },
        backlog: evidence.backlog,
        receipt_latency_ns: latency_summary(&receipt_histogram),
        finality_latency_ns: latency_summary(&finality_histogram),
        throughput: ThroughputBreakdown {
            aggregate: ScopeThroughput {
                name: "global".into(),
                effective_orders: effective,
                interval_ns,
            },
            per_region,
            per_node,
            per_shard,
        },
    })
}

fn validate_agent(
    manifest: &WorkloadManifest,
    run_id: u128,
    agent: &DistributedPackedAgentReport,
    authenticator: &ControlAuthenticator,
) -> Result<(), String> {
    agent
        .verify(authenticator)
        .map_err(|error| format!("agent report authentication: {error}"))?;
    let assignment = &agent.assignment.assignment;
    if assignment.run_id != run_id
        || assignment.agent_id.trim().is_empty()
        || assignment.region.trim().is_empty()
        || assignment.rate == 0
        || assignment.connections == 0
        || assignment.client_id_start >= assignment.client_id_end
        || assignment.client_id_end - assignment.client_id_start
            != u64::from(assignment.connections)
        || assignment.start_unix_ns == 0
        || assignment.targets.is_empty()
    {
        return Err(format!(
            "invalid authenticated identity for agent '{}'",
            assignment.agent_id
        ));
    }
    let regional_bps = manifest
        .regions
        .iter()
        .find(|region| region.name == assignment.region)
        .ok_or_else(|| format!("agent '{}' has an unknown region", assignment.agent_id))?
        .offered_load_bps;
    let actual_share = u128::from(assignment.rate).saturating_mul(10_000);
    let expected_share =
        u128::from(manifest.offered_orders_per_second).saturating_mul(u128::from(regional_bps));
    if actual_share.abs_diff(expected_share) > u128::from(manifest.offered_orders_per_second) {
        return Err(format!(
            "agent '{}' offered share differs from the manifest by more than one basis point",
            assignment.agent_id
        ));
    }
    if assignment.phases.warmup_secs != manifest.phases.warmup_seconds
        || assignment.phases.steady_secs != manifest.phases.steady_seconds
        || assignment.phases.drain_secs < manifest.phases.drain_seconds
    {
        return Err(format!(
            "agent '{}' phase schedule does not match",
            assignment.agent_id
        ));
    }
    let report = &agent.report;
    let expected_ns = assignment
        .phases
        .steady_secs
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "steady interval overflow".to_string())?;
    if report.mode != "live-authenticated-packed"
        || report.target_profile != "validator"
        || report.completion_boundary != PackedCompletionBoundary::Finalized
        || !(32..=128).contains(&report.batch_size)
        || report.elapsed_ns != expected_ns
        || report.steady_intervals.len()
            != usize::try_from(assignment.phases.steady_secs)
                .map_err(|_| "steady interval count overflow".to_string())?
    {
        return Err(format!(
            "agent '{}' report contract does not match",
            assignment.agent_id
        ));
    }

    let mut counters = PackedLifecycleCounters::default();
    let mut admission = NanoHistogram::default();
    let mut execution = NanoHistogram::default();
    let mut finality = NanoHistogram::default();
    let mut highest_checkpoint: Option<u64> = None;
    let mut interval_rate = None;
    for (index, interval) in report.steady_intervals.iter().enumerate() {
        validate_interval(agent, index, interval)?;
        if let Some(rate) = interval_rate {
            if interval.counters.offered_records != rate {
                return Err(format!(
                    "agent '{}' interval rate drifted",
                    assignment.agent_id
                ));
            }
        } else {
            interval_rate = Some(interval.counters.offered_records);
        }
        checked_add_counters(&mut counters, interval.counters)?;
        admission
            .checked_merge(&interval.admission_receipt_ns)
            .map_err(|error| format!("merge admission intervals: {error}"))?;
        execution
            .checked_merge(&interval.execution_receipt_ns)
            .map_err(|error| format!("merge execution intervals: {error}"))?;
        finality
            .checked_merge(&interval.finality_receipt_ns)
            .map_err(|error| format!("merge finality intervals: {error}"))?;
        highest_checkpoint = match (highest_checkpoint, interval.highest_checkpoint) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
    }
    if counters != report.counters
        || admission != report.admission_receipt_ns
        || execution != report.execution_receipt_ns
        || finality != report.finality_receipt_ns
        || highest_checkpoint != report.highest_checkpoint
        || report.planned_records != report.counters.offered_records
    {
        return Err(format!(
            "agent '{}' cumulative report does not equal its raw intervals",
            assignment.agent_id
        ));
    }
    let rate =
        interval_rate.ok_or_else(|| format!("agent '{}' has no intervals", assignment.agent_id))?;
    if rate != assignment.rate {
        return Err(format!(
            "agent '{}' interval rate does not match its assignment",
            assignment.agent_id
        ));
    }
    if report.warmup_planned_records
        != rate
            .checked_mul(assignment.phases.warmup_secs)
            .ok_or_else(|| "warmup count overflow".to_string())?
    {
        return Err(format!(
            "agent '{}' warmup count does not match",
            assignment.agent_id
        ));
    }
    if report.highest_checkpoint.is_none() && report.counters.finalized_records > 0 {
        return Err(format!(
            "agent '{}' omitted its finalized checkpoint",
            assignment.agent_id
        ));
    }
    validate_lifecycle(
        &report.counters,
        &report.admission_receipt_ns,
        &report.execution_receipt_ns,
        &report.finality_receipt_ns,
        report.batch_size,
        &assignment.agent_id,
    )
}

fn validate_evidence(evidence: &ComposedRunEvidence) -> Result<(), String> {
    if evidence.exact_command.trim().is_empty() {
        return Err("exact campaign command is required".into());
    }
    let provenance = &evidence.provenance;
    let required_provenance = [
        &provenance.git_sha,
        &provenance.rustc,
        &provenance.llvm,
        &provenance.profile,
        &provenance.features,
        &provenance.rustflags,
        &provenance.cpu,
        &provenance.microcode,
        &provenance.numa,
        &provenance.kernel,
        &provenance.governor,
        &provenance.affinity,
        &provenance.nic,
        &provenance.nic_driver,
        &provenance.nic_firmware,
        &provenance.nic_offloads,
        &provenance.topology,
    ];
    if required_provenance
        .iter()
        .any(|value| value.trim().is_empty())
        || !is_sha256(&provenance.cargo_lock_sha256)
        || provenance.mtu == 0
    {
        return Err("complete build, host, NIC, and topology provenance is required".into());
    }
    let route = &evidence.route;
    let route_stages = [
        &route.signed_rpc,
        &route.decode_admission,
        &route.canonical_sequence,
        &route.durable_journal,
        &route.execution_orderbook_risk,
        &route.state_root,
        &route.receipt,
        &route.minimmit_checkpoint,
    ];
    if route_stages.iter().any(|value| value.trim().is_empty()) {
        return Err("every production route stage needs an evidence reference".into());
    }
    Ok(())
}

fn validate_interval(
    agent: &DistributedPackedAgentReport,
    index: usize,
    interval: &PackedSteadyInterval,
) -> Result<(), String> {
    let attributed = interval
        .accepted_new_records
        .checked_add(interval.accepted_cancel_records)
        .and_then(|value| value.checked_add(interval.accepted_replace_records));
    if interval.ordinal
        != u64::try_from(index).map_err(|_| "interval ordinal overflow".to_string())?
        || !interval.action_attribution_complete
        || attributed != Some(interval.counters.executed_records)
    {
        return Err(format!(
            "agent '{}' interval {index} is incomplete",
            agent.assignment.assignment.agent_id
        ));
    }
    validate_lifecycle(
        &interval.counters,
        &interval.admission_receipt_ns,
        &interval.execution_receipt_ns,
        &interval.finality_receipt_ns,
        agent.report.batch_size,
        &format!("{} interval {index}", agent.assignment.assignment.agent_id),
    )
}

fn validate_action_mix(
    manifest: &WorkloadManifest,
    new_orders: u64,
    cancels: u64,
    replaces: u64,
    total: u64,
) -> Result<(), String> {
    if new_orders
        .checked_add(cancels)
        .and_then(|value| value.checked_add(replaces))
        != Some(total)
    {
        return Err("action-attributed counts do not conserve executed commands".into());
    }
    for (name, actual, expected_bps) in [
        ("new", new_orders, manifest.action_mix_bps.new),
        ("cancel", cancels, manifest.action_mix_bps.cancel),
        ("replace", replaces, manifest.action_mix_bps.replace),
    ] {
        let actual_scaled = u128::from(actual).saturating_mul(10_000);
        let expected_scaled = u128::from(total).saturating_mul(u128::from(expected_bps));
        if actual_scaled.abs_diff(expected_scaled) > u128::from(total) {
            return Err(format!(
                "realized {name} action mix differs from the manifest by more than one basis point"
            ));
        }
    }
    Ok(())
}

fn validate_lifecycle(
    counters: &PackedLifecycleCounters,
    admission: &NanoHistogram,
    execution: &NanoHistogram,
    finality: &NanoHistogram,
    batch_size: u8,
    scope: &str,
) -> Result<(), String> {
    let terminal = counters
        .executed_records
        .checked_add(counters.failed_records)
        .ok_or_else(|| "lifecycle counter overflow".to_string())?;
    if counters.offered_records != counters.socket_written_records
        || counters.admitted_records != counters.socket_written_records
        || counters.admitted_records != terminal
        || counters.finalized_records != counters.executed_records
        || counters.socket_written_records
            != counters
                .socket_written_batches
                .checked_mul(u64::from(batch_size))
                .unwrap_or(0)
        || admission.count != counters.admitted_records
        || execution.count != terminal
        || finality.count != counters.finalized_records
        || admission.overflow != 0
        || execution.overflow != 0
        || finality.overflow != 0
    {
        return Err(format!(
            "{scope} lifecycle or latency counts do not reconcile"
        ));
    }
    Ok(())
}

fn validate_scopes(
    kind: &str,
    scopes: &[ScopeCounters],
    expected_names: Option<&BTreeSet<&str>>,
    global: PackedLifecycleCounters,
) -> Result<(), String> {
    let names: BTreeSet<_> = scopes.iter().map(|scope| scope.name.as_str()).collect();
    if names.len() != scopes.len() || scopes.iter().any(|scope| scope.name.trim().is_empty()) {
        return Err(format!(
            "per-{kind} scope names must be nonempty and unique"
        ));
    }
    if expected_names.is_some_and(|expected| expected != &names) {
        return Err(format!(
            "per-{kind} scopes do not cover the manifest exactly"
        ));
    }
    let sum =
        |field: fn(&ScopeCounters) -> u64| scopes.iter().map(field).try_fold(0u64, checked_add);
    if sum(|scope| scope.offered)? != global.offered_records
        || sum(|scope| scope.accepted)? != global.admitted_records
        || sum(|scope| scope.executed)? != global.executed_records
        || sum(|scope| scope.finalized)? != global.finalized_records
    {
        return Err(format!(
            "per-{kind} lifecycle totals do not conserve the global counts"
        ));
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, String> {
    left.checked_add(right)
        .ok_or_else(|| "counter overflow".to_string())
}

fn checked_add_counters(
    left: &mut PackedLifecycleCounters,
    right: PackedLifecycleCounters,
) -> Result<(), String> {
    left.offered_records = checked_add(left.offered_records, right.offered_records)?;
    left.socket_written_batches =
        checked_add(left.socket_written_batches, right.socket_written_batches)?;
    left.socket_written_records =
        checked_add(left.socket_written_records, right.socket_written_records)?;
    left.admitted_records = checked_add(left.admitted_records, right.admitted_records)?;
    left.executed_records = checked_add(left.executed_records, right.executed_records)?;
    left.failed_records = checked_add(left.failed_records, right.failed_records)?;
    left.finalized_records = checked_add(left.finalized_records, right.finalized_records)?;
    Ok(())
}

fn latency_summary(histogram: &NanoHistogram) -> LatencySummary {
    LatencySummary {
        count: histogram.count,
        p50: histogram.percentile_permille(500),
        p95: histogram.percentile_permille(950),
        p99: histogram.percentile_permille(990),
        p999: histogram.percentile_permille(999),
        max: histogram.max,
        coordinated_omission_corrected: true,
    }
}

fn scope_throughput(
    name: &str,
    counters: PackedLifecycleCounters,
    interval_ns: u64,
) -> ScopeThroughput {
    ScopeThroughput {
        name: name.to_string(),
        effective_orders: counters
            .admitted_records
            .min(counters.executed_records)
            .min(counters.finalized_records),
        interval_ns,
    }
}

fn scope_from_counters(scope: &ScopeCounters, interval_ns: u64) -> ScopeThroughput {
    ScopeThroughput {
        name: scope.name.clone(),
        effective_orders: scope.accepted.min(scope.executed).min(scope.finalized),
        interval_ns,
    }
}

/// Lowercase SHA-256 of an artifact byte stream.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::composed::load_manifest;
    use loadgen::{
        partition_plan, AgentDescriptor, AuthenticatedAssignment, ControllerPlan, LivePackedReport,
        PackedSteadyInterval, PhaseSchedule,
    };

    fn manifest() -> WorkloadManifest {
        let (mut manifest, _) =
            load_manifest(Path::new("workloads/global-20m-v1.toml")).expect("manifest");
        manifest.phases.steady_seconds = 1;
        manifest.offered_orders_per_second = 96;
        manifest.action_mix_bps = crate::composed::ActionMix {
            new: 6_875,
            cancel: 1_875,
            replace: 1_250,
        };
        manifest
    }

    fn authenticator() -> ControlAuthenticator {
        ControlAuthenticator::new(&[0x42; 32]).expect("control key")
    }

    fn agent(
        id: &str,
        region: &str,
        seed: u8,
        authenticator: &ControlAuthenticator,
    ) -> DistributedPackedAgentReport {
        let counters = PackedLifecycleCounters {
            offered_records: 32,
            socket_written_batches: 1,
            socket_written_records: 32,
            admitted_records: 32,
            executed_records: 32,
            failed_records: 0,
            finalized_records: 32,
        };
        let mut admission = NanoHistogram::default();
        let mut execution = NanoHistogram::default();
        let mut finality = NanoHistogram::default();
        admission.record_n(10, 32);
        execution.record_n(20, 32);
        finality.record_n(30, 32);
        let interval = PackedSteadyInterval {
            ordinal: 0,
            counters,
            accepted_new_records: 22,
            accepted_cancel_records: 6,
            accepted_replace_records: 4,
            action_attribution_complete: true,
            admission_receipt_ns: admission.clone(),
            execution_receipt_ns: execution.clone(),
            finality_receipt_ns: finality.clone(),
            highest_checkpoint: Some(7),
        };
        let target = format!("{region}-validator:9000");
        let descriptor = AgentDescriptor {
            id: id.into(),
            region: region.into(),
            max_rate: 32,
            max_connections: 1,
            allowed_targets: vec![target.clone()],
            clock_uncertainty_ns: 1,
        };
        let assignment = partition_plan(
            &ControllerPlan {
                run_id: 99,
                start_unix_ns: 10_000_000_000,
                total_rate: 32,
                total_connections: 1,
                client_id_base: u64::from(seed) * 100,
                seed: u64::from(seed),
                phases: PhaseSchedule {
                    warmup_secs: 60,
                    steady_secs: 1,
                    drain_secs: 2,
                    cooldown_secs: 1,
                },
                targets: vec![target],
            },
            &[descriptor],
            0,
        )
        .expect("assignment")
        .remove(0);
        let envelope = AuthenticatedAssignment::new(assignment, [seed; 32], authenticator);
        DistributedPackedAgentReport::authenticated(
            envelope,
            LivePackedReport {
                mode: "live-authenticated-packed".into(),
                target_profile: "validator".into(),
                completion_boundary: PackedCompletionBoundary::Finalized,
                batch_size: 32,
                planned_records: 32,
                warmup_planned_records: 1_920,
                elapsed_ns: 1_000_000_000,
                drain_elapsed_ns: 1,
                counters,
                admission_receipt_ns: admission,
                execution_receipt_ns: execution,
                finality_receipt_ns: finality,
                highest_checkpoint: Some(7),
                steady_intervals: vec![interval],
            },
            authenticator,
        )
        .expect("authenticated report")
    }

    fn partition_scopes(names: Vec<String>, total: u64) -> Vec<ScopeCounters> {
        let count = u64::try_from(names.len()).expect("scope count");
        names
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let index = u64::try_from(index).expect("index");
                let value = total / count + u64::from(index < total % count);
                ScopeCounters {
                    name,
                    offered: value,
                    accepted: value,
                    executed: value,
                    finalized: value,
                }
            })
            .collect()
    }

    fn evidence(manifest: &WorkloadManifest) -> ComposedRunEvidence {
        let nodes = manifest
            .regions
            .iter()
            .flat_map(|region| region.validators.iter().cloned())
            .collect();
        let shards = (0..manifest.shard_count)
            .map(|index| format!("shard-{index:03}"))
            .collect();
        ComposedRunEvidence {
            schema_version: 1,
            run_id: 99,
            exact_command: "market-loadgen agent ...".into(),
            target_reachable: true,
            provenance: ProvenanceFingerprint {
                git_sha: "1".repeat(40),
                git_dirty: false,
                cargo_lock_sha256: "2".repeat(64),
                rustc: "rustc".into(),
                llvm: "llvm".into(),
                profile: "release".into(),
                features: "production".into(),
                rustflags: "native".into(),
                cpu: "cpu".into(),
                microcode: "microcode".into(),
                numa: "numa".into(),
                kernel: "kernel".into(),
                governor: "performance".into(),
                affinity: "pinned".into(),
                nic: "nic".into(),
                nic_driver: "driver".into(),
                nic_firmware: "firmware".into(),
                nic_offloads: "offloads".into(),
                mtu: 9000,
                topology: "london-new-york-tokyo".into(),
            },
            route: ProductionRoute {
                signed_rpc: "signed".into(),
                decode_admission: "admitted".into(),
                canonical_sequence: "sequence".into(),
                durable_journal: "journal".into(),
                execution_orderbook_risk: "execution".into(),
                state_root: "root".into(),
                receipt: "receipt".into(),
                minimmit_checkpoint: "checkpoint".into(),
            },
            backlog: FinalityBacklog {
                pre_run: 0,
                end_of_steady: 0,
                after_two_checkpoint_intervals: 0,
                steady_slope_per_second: 0,
            },
            per_node: partition_scopes(nodes, 96),
            per_shard: partition_scopes(shards, 96),
            retries_excluded: 0,
            duplicates_excluded: 0,
            sequence_gaps: 0,
            nic_drops: 0,
            unexplained_loss: 0,
        }
    }

    #[test]
    fn builds_only_after_every_raw_scope_reconciles() {
        let manifest = manifest();
        let authenticator = authenticator();
        let agents = vec![
            agent("tokyo-agent", "tokyo", 3, &authenticator),
            agent("london-agent", "london", 1, &authenticator),
            agent("ny-agent", "new-york", 2, &authenticator),
        ];
        let evidence = evidence(&manifest);
        let raw = render_raw_campaign(&agents, &evidence).expect("raw campaign");
        let run = build_composed_run(
            &manifest,
            &"a".repeat(64),
            &agents,
            &authenticator,
            evidence,
            "raw/run-99.json".into(),
            sha256_hex(&raw),
        )
        .expect("composed run");
        assert_eq!(run.counts.accepted, 96);
        assert_eq!(run.counts.accepted_new_orders, 66);
        assert_eq!(run.receipt_latency_ns.count, 96);
        assert_eq!(run.finality_latency_ns.count, 96);
        assert_eq!(run.throughput.per_region[0].name, "london");
        assert_eq!(run.throughput.per_shard.len(), 256);
    }

    #[test]
    fn rejects_histogram_drift_and_scope_loss() {
        let manifest = manifest();
        let authenticator = authenticator();
        let mut agents = vec![
            agent("london-agent", "london", 1, &authenticator),
            agent("ny-agent", "new-york", 2, &authenticator),
            agent("tokyo-agent", "tokyo", 3, &authenticator),
        ];
        agents[0].report.execution_receipt_ns.record(99);
        let error = build_composed_run(
            &manifest,
            &"a".repeat(64),
            &agents,
            &authenticator,
            evidence(&manifest),
            "raw.json".into(),
            "b".repeat(64),
        )
        .expect_err("tampered report must fail");
        assert!(error.contains("authentication"));

        let agents = vec![
            agent("london-agent", "london", 1, &authenticator),
            agent("ny-agent", "new-york", 2, &authenticator),
            agent("tokyo-agent", "tokyo", 3, &authenticator),
        ];
        let mut bad_evidence = evidence(&manifest);
        bad_evidence.per_shard[0].finalized = 0;
        assert!(build_composed_run(
            &manifest,
            &"a".repeat(64),
            &agents,
            &authenticator,
            bad_evidence,
            "raw.json".into(),
            "b".repeat(64),
        )
        .is_err());
    }
}
