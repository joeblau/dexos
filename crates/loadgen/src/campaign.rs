//! Extended multi-process campaign driver used for 20M qualification runs.
//!
//! The primary crate API keeps the packed production runner stable. This
//! namespace exposes the independent controller/agent campaign stack and its
//! protocol-conformant reference sink without colliding with the packed runner's
//! similarly named control-plane and sink types.

pub use crate::campaign_distributed::{
    build_distributed_plan, control_proof, merge_agent_metrics, run_distributed_agent,
    run_distributed_agent_with_shutdown, run_distributed_controller, verify_control_proof,
    AgentAdvertisement, AgentMetricDelta, AgentPartition, AgentState, DistributedError,
    DistributedPlan, DistributedRunReport, HeartbeatTracker,
};
pub use crate::command::LiveOrder;
pub use crate::config::{
    ratio_from_unit_f64, AccountMaterial, Adversarial, ControlPlaneConfig, EndpointConfig,
    Impairment, LoadScenario, MarketModelConfig, MarketRegime, OperationMix, OracleWorkload,
    OrderFlowConfig, OutputConfig, RegionConfig, RunMode, RunRole, TargetKind, ThresholdConfig,
    TlsClientConfig,
};
pub use crate::engine::run_scenario;
pub use crate::market::{
    parse_replay, pick_market_index, pick_quantity, pick_side, pick_time_in_force, MarketModel,
    ReplayError, ReplayEvent, SyntheticBbo,
};
pub use crate::measured::{
    decode_submit, receipt_frame, run_measured, submit_frame, MeasuredReport, MSG_RECEIPT,
    MSG_RECONCILE, MSG_RECONCILE_ACK, MSG_SUBMIT,
};
pub use crate::metrics::{
    ActionCounters, ActionHistograms, ConservationError, HistogramMergeError, HistogramSummary,
    LatencyHistogram, OutcomeCounters, HISTOGRAM_BUCKETS, HISTOGRAM_SUB_BUCKETS,
};
pub use crate::protocol::{
    EncodedMetadata, EncodedOperation, ProtocolAdapter, ProtocolAdapterError, ProtocolOutcome,
    ProtocolSlot,
};
pub use crate::runtime::{
    run_local_live, run_local_live_with_progress, run_local_live_with_shutdown,
    run_partitioned_live, run_partitioned_live_with_progress, run_partitioned_live_with_shutdown,
    ActionLatencyReport, HistogramReport, IntervalCounters, IntervalReport, LiveError, LiveReport,
    MetricDimension, RejectionCounters,
};
pub use crate::scheduler::{
    OpenLoopScheduler, PhaseTimeline, RunPhase, ScheduleBatch, NANOS_PER_SECOND,
};
pub use crate::sink::{
    reference_sink_tls_acceptor, serve_reference_sink, serve_reference_sink_tls,
    ReferenceSinkConfig, SinkCounters, SinkError, SinkFaultMode, SinkHistogramReport, SinkSnapshot,
};
pub use crate::topology::{
    partition_weighted, preflight_topology, redistribute_healthy, ConnectionAssignment,
    ResolvedTopology, TopologyError,
};
