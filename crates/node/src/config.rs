//! TOML configuration schema and validating loader for a DexOS node.
//!
//! The schema mirrors the operator-facing `[node]`/`[network]`/`[consensus]`/
//! `[storage]`/`[rpc]`/`[performance]` layout one-to-one. All configuration is
//! treated as untrusted input: malformed or out-of-range values return a typed
//! [`ConfigError`] and never panic or silently truncate.
//!
//! Configuration lives in the `node` crate — outside the deterministic execution
//! core — so the core never links serde/toml.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use consensus::MinimmitCommittee;
use crypto::Validator;
use serde::{Deserialize, Serialize};

/// Checkpoint cadence is bounded to 50–100 ms by the consensus design.
pub const CHECKPOINT_INTERVAL_MIN_MS: u64 = 50;
/// Upper bound of the configurable checkpoint cadence.
pub const CHECKPOINT_INTERVAL_MAX_MS: u64 = 100;
/// Smallest meaningful network delay estimate (one millisecond).
pub const DELTA_MIN_MS: u64 = 1;
/// Maximum delay estimate accepted before startup (one minute).
pub const DELTA_MAX_MS: u64 = 60_000;

const fn default_delta_ms() -> u64 {
    100
}

/// Smallest permitted log segment size, in megabytes. A zero-sized segment can
/// never hold a framed record, so it is rejected rather than silently accepted.
pub const SEGMENT_SIZE_MIN_MB: u64 = 1;
/// Largest permitted log segment size, in megabytes (64 GiB). Bounding this keeps
/// the megabyte→byte conversion well clear of `usize` overflow on any target.
pub const SEGMENT_SIZE_MAX_MB: u64 = 65_536;

/// Maximum permitted drain timeout (10 minutes). Larger values almost certainly
/// indicate a unit mistake and are rejected rather than hanging shutdown.
pub const DRAIN_TIMEOUT_MAX_MS: u64 = 600_000;

/// A role a node may assume. A node may hold multiple roles simultaneously,
/// but each role may appear at most once (see [`NodeConfig::validate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Participates in BFT finality voting.
    Validator,
    /// Orders and executes commands as the active sequencer.
    Sequencer,
    /// Certifies execution results / sequence ranges.
    Witness,
    /// Accepts and forwards signed client requests.
    Gateway,
    /// Produces signed price/resolution observations.
    Oracle,
    /// Holds a threshold custody signing share.
    Custody,
    /// Read-only observer of external chains and network state.
    Observer,
}

impl Role {
    /// Roles that mutate canonical state and are therefore forbidden in `--light` mode.
    pub const fn is_consensus_bearing(self) -> bool {
        matches!(self, Role::Validator | Role::Sequencer | Role::Custody)
    }

    /// Roles that require a validator-set descriptor on disk.
    pub const fn requires_validator_set(self) -> bool {
        matches!(
            self,
            Role::Validator | Role::Sequencer | Role::Witness | Role::Custody
        )
    }

    /// Lowercase wire name, matching the config/CLI spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Validator => "validator",
            Role::Sequencer => "sequencer",
            Role::Witness => "witness",
            Role::Gateway => "gateway",
            Role::Oracle => "oracle",
            Role::Custody => "custody",
            Role::Observer => "observer",
        }
    }
}

/// `[node]` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// Human-readable node name.
    pub name: String,
    /// Deployment region tag (e.g. `ap-northeast`).
    pub region: String,
    /// Whether this node runs in light mode.
    pub light: bool,
    /// Roles this node assumes (unique; order preserved).
    pub roles: Vec<Role>,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            name: "marketd".to_string(),
            region: "local".to_string(),
            light: false,
            roles: Vec::new(),
        }
    }
}

/// `[network]` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    /// Listen address for peer connections.
    pub listen: String,
    /// Static bootstrap peer addresses.
    pub bootstrap_peers: Vec<String>,
    /// Enable QUIC reliable sessions.
    pub enable_quic: bool,
    /// Enable datagram market-data dissemination.
    pub enable_datagrams: bool,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:9000".to_string(),
            bootstrap_peers: Vec::new(),
            // Defaults stay off so configs that omit the keys remain valid on
            // builds without the `quic` feature. When compiled with `quic`,
            // operators may set both to true; `validate` fails closed if the
            // binary lacks the implementation (never a silent no-op).
            enable_quic: false,
            enable_datagrams: false,
        }
    }
}

/// `[consensus]` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusSection {
    /// Checkpoint cadence in milliseconds (bounded to 50–100).
    pub checkpoint_interval_ms: u64,
    /// Estimated one-way network delay; view timers are armed for `2 * delta_ms`.
    #[serde(default = "default_delta_ms")]
    pub delta_ms: u64,
    /// Number of sequences per epoch.
    pub epoch_length: u64,
    /// Path to the validator-set descriptor.
    pub validator_set_path: String,
}

impl Default for ConsensusSection {
    fn default() -> Self {
        Self {
            checkpoint_interval_ms: 100,
            delta_ms: default_delta_ms(),
            epoch_length: 100_000,
            validator_set_path: "validators.toml".to_string(),
        }
    }
}

/// `[storage]` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    /// Data directory for the command log and snapshots.
    pub data_dir: String,
    /// Snapshot interval in sequences.
    pub snapshot_interval_sequences: u64,
    /// Log segment size in megabytes.
    pub segment_size_mb: u64,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            data_dir: "./data".to_string(),
            snapshot_interval_sequences: 1_000_000,
            segment_size_mb: 1024,
        }
    }
}

/// `[rpc]` section.
///
/// Beyond the listen address and read-only switch, the transport keys map
/// one-to-one onto [`rpc::ServerConfig`] / [`rpc::WorkBudgetConfig`] so the
/// production TLS and DoS-hardening posture is fully expressible from the
/// operator config. Every transport key defaults to the corresponding
/// [`rpc::ServerConfig::default`] value (asserted by test), so configs that
/// omit them behave exactly as before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcSection {
    /// Listen address for the public RPC surface.
    pub listen: String,
    /// Whether the RPC surface is read-only.
    pub read_only: bool,
    /// PEM-encoded TLS 1.3 certificate chain. Must be set together with
    /// `tls_key_path` (both-or-neither); when both are set the composition
    /// root serves [`rpc::TlsMode::Required`] built via
    /// [`rpc::acceptor_from_pem`]. Relative paths resolve against the config
    /// file's directory.
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    /// PEM-encoded PKCS#8 private key paired with `tls_cert_path`
    /// (both-or-neither).
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
    /// Optional PEM-encoded client-certificate roots enabling mTLS client
    /// verification. Requires `tls_cert_path` and `tls_key_path`.
    #[serde(default)]
    pub tls_client_ca_path: Option<PathBuf>,
    /// Process-wide ceiling on concurrently served RPC connections.
    #[serde(default = "default_rpc_max_connections")]
    pub max_connections: usize,
    /// Maximum concurrent connections admitted from a single source IP.
    #[serde(default = "default_rpc_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    /// Sustained per-IP connection admissions per second. `0` together with
    /// `rate_burst = 0` disables per-IP rate limiting (both-or-neither).
    #[serde(default = "default_rpc_rate_per_ip_per_sec")]
    pub rate_per_ip_per_sec: u64,
    /// Per-IP connection burst (token-bucket capacity). `0` together with
    /// `rate_per_ip_per_sec = 0` disables per-IP rate limiting.
    #[serde(default = "default_rpc_rate_burst")]
    pub rate_burst: u64,
    /// Maximum idle time (ms) waiting for the next request frame header.
    #[serde(default = "default_rpc_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Maximum time (ms) to receive a frame payload once its header arrived.
    #[serde(default = "default_rpc_read_timeout_ms")]
    pub read_timeout_ms: u64,
    /// Maximum time (ms) to flush a response to a stalled reader.
    #[serde(default = "default_rpc_write_timeout_ms")]
    pub write_timeout_ms: u64,
    /// Maximum time (ms) a single backend dispatch may run before the
    /// connection is failed closed.
    #[serde(default = "default_rpc_dispatch_timeout_ms")]
    pub dispatch_timeout_ms: u64,
    /// Process-wide maximum concurrent dispatches (blocking-pool tasks).
    #[serde(default = "default_rpc_max_in_flight_requests")]
    pub max_in_flight_requests: usize,
    /// Process-wide maximum bytes retained by in-flight request frames.
    #[serde(default = "default_rpc_max_in_flight_bytes")]
    pub max_in_flight_bytes: usize,
    /// Per-connection concurrent-dispatch ceiling.
    #[serde(default = "default_rpc_max_in_flight_requests_per_conn")]
    pub max_in_flight_requests_per_conn: usize,
    /// Per-connection in-flight request-frame byte ceiling.
    #[serde(default = "default_rpc_max_in_flight_bytes_per_conn")]
    pub max_in_flight_bytes_per_conn: usize,
}

// Serde field defaults for `[rpc]`. Literals mirror `rpc::ServerConfig::default()`
// / `rpc::WorkBudgetConfig::default()`; the `rpc_defaults_mirror_server_config`
// test asserts the mirror so drift fails CI rather than silently diverging.
fn default_rpc_max_connections() -> usize {
    4_096
}
fn default_rpc_max_connections_per_ip() -> u32 {
    64
}
fn default_rpc_rate_per_ip_per_sec() -> u64 {
    32
}
fn default_rpc_rate_burst() -> u64 {
    64
}
fn default_rpc_idle_timeout_ms() -> u64 {
    30_000
}
fn default_rpc_read_timeout_ms() -> u64 {
    10_000
}
fn default_rpc_write_timeout_ms() -> u64 {
    10_000
}
fn default_rpc_dispatch_timeout_ms() -> u64 {
    5_000
}
fn default_rpc_max_in_flight_requests() -> usize {
    1_024
}
fn default_rpc_max_in_flight_bytes() -> usize {
    64 * 1024 * 1024
}
fn default_rpc_max_in_flight_requests_per_conn() -> usize {
    1
}
fn default_rpc_max_in_flight_bytes_per_conn() -> usize {
    1024 * 1024
}

impl Default for RpcSection {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_string(),
            read_only: false,
            tls_cert_path: None,
            tls_key_path: None,
            tls_client_ca_path: None,
            max_connections: default_rpc_max_connections(),
            max_connections_per_ip: default_rpc_max_connections_per_ip(),
            rate_per_ip_per_sec: default_rpc_rate_per_ip_per_sec(),
            rate_burst: default_rpc_rate_burst(),
            idle_timeout_ms: default_rpc_idle_timeout_ms(),
            read_timeout_ms: default_rpc_read_timeout_ms(),
            write_timeout_ms: default_rpc_write_timeout_ms(),
            dispatch_timeout_ms: default_rpc_dispatch_timeout_ms(),
            max_in_flight_requests: default_rpc_max_in_flight_requests(),
            max_in_flight_bytes: default_rpc_max_in_flight_bytes(),
            max_in_flight_requests_per_conn: default_rpc_max_in_flight_requests_per_conn(),
            max_in_flight_bytes_per_conn: default_rpc_max_in_flight_bytes_per_conn(),
        }
    }
}

impl RpcSection {
    /// True when this section requests TLS: both `tls_cert_path` and
    /// `tls_key_path` are set. [`NodeConfig::validate`] rejects a half-set pair,
    /// so post-validate this is equivalent to "any TLS key present".
    pub fn tls_configured(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    /// The per-IP connection rate limit expressed by this section, or `None`
    /// when rate limiting is disabled (`rate_per_ip_per_sec = 0` and
    /// `rate_burst = 0`).
    pub fn per_ip_rate(&self) -> Option<rpc::RateLimit> {
        (self.rate_per_ip_per_sec > 0 || self.rate_burst > 0).then_some(rpc::RateLimit {
            per_sec: self.rate_per_ip_per_sec,
            burst: self.rate_burst,
        })
    }

    /// The in-flight work budget expressed by this section.
    pub fn work_budget(&self) -> rpc::WorkBudgetConfig {
        rpc::WorkBudgetConfig {
            max_in_flight_requests: self.max_in_flight_requests,
            max_in_flight_bytes: self.max_in_flight_bytes,
            max_in_flight_requests_per_conn: self.max_in_flight_requests_per_conn,
            max_in_flight_bytes_per_conn: self.max_in_flight_bytes_per_conn,
        }
    }

    /// Build the transport [`rpc::ServerConfig`] expressed by this section,
    /// constructing [`Duration`]s from the `_ms` keys here in the composition
    /// layer. Fields the schema does not expose (`max_tracked_ips`,
    /// `max_payload`, `drain_timeout`) keep their [`rpc::ServerConfig::default`]
    /// values.
    ///
    /// `tls` is injected by the caller because building
    /// [`rpc::TlsMode::Required`] reads the PEM files named by
    /// `tls_cert_path` / `tls_key_path` / `tls_client_ca_path` from disk via
    /// [`rpc::acceptor_from_pem`] — this method performs no I/O. Tracked by
    /// composition issue #312: when the RPC listener is wired into the
    /// runtime, the composition root must load those PEMs and pass
    /// `TlsMode::Required(acceptor)`
    /// whenever [`Self::tls_configured`] is true.
    pub fn server_config(&self, tls: rpc::TlsMode) -> rpc::ServerConfig {
        rpc::ServerConfig {
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            per_ip_rate: self.per_ip_rate(),
            idle_timeout: Duration::from_millis(self.idle_timeout_ms),
            read_timeout: Duration::from_millis(self.read_timeout_ms),
            write_timeout: Duration::from_millis(self.write_timeout_ms),
            tls,
            work: self.work_budget(),
            dispatch_timeout: Duration::from_millis(self.dispatch_timeout_ms),
            ..rpc::ServerConfig::default()
        }
    }
}

/// `[performance]` section.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceSection {
    /// Pin subsystem threads to cores (Linux/macOS).
    pub pin_threads: bool,
    /// Busy-poll ingress queues.
    pub busy_poll: bool,
    /// Graceful drain deadline in milliseconds. `0` = default (30s).
    #[serde(default)]
    pub drain_timeout_ms: u64,
}

/// Log line format for the process-wide tracing subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-oriented `fmt` subscriber (default for local dev).
    #[default]
    Text,
    /// Structured JSON lines for production log aggregators.
    Json,
}

/// `[observability]` section — logging and metrics scrape endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilitySection {
    /// Log format: `text` (default) or `json` (production).
    #[serde(default)]
    pub log_format: LogFormat,
    /// Optional listen address for Prometheus `/metrics` (and `/livez`/`/readyz`).
    /// Empty string disables the scrape server.
    #[serde(default)]
    pub metrics_listen: String,
}

impl Default for ObservabilitySection {
    fn default() -> Self {
        Self {
            log_format: LogFormat::Text,
            metrics_listen: String::new(),
        }
    }
}

/// A fully-parsed, validated node configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// `[node]` section.
    #[serde(default)]
    pub node: NodeSection,
    /// `[network]` section.
    #[serde(default)]
    pub network: NetworkSection,
    /// `[consensus]` section.
    #[serde(default)]
    pub consensus: ConsensusSection,
    /// `[storage]` section.
    #[serde(default)]
    pub storage: StorageSection,
    /// `[rpc]` section.
    #[serde(default)]
    pub rpc: RpcSection,
    /// `[performance]` section.
    #[serde(default)]
    pub performance: PerformanceSection,
    /// `[observability]` section.
    #[serde(default)]
    pub observability: ObservabilitySection,
}

/// CLI-supplied overrides that take precedence over file values.
#[derive(Debug, Clone, Default)]
pub struct ConfigOverrides {
    /// Force light mode on.
    pub light: bool,
    /// Replace the configured role set (when non-empty).
    pub roles: Vec<Role>,
}

/// Errors from loading or validating a [`NodeConfig`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("could not read config file '{path}': {source}")]
    Io {
        /// The path that failed to read.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The TOML failed to parse or contained unknown/typed-mismatched fields.
    #[error("invalid config syntax: {0}")]
    Parse(#[from] toml::de::Error),

    /// A numeric field was outside its permitted range.
    #[error("field '{field}' = {value} is out of range [{min}, {max}]")]
    OutOfRange {
        /// The offending field name.
        field: &'static str,
        /// The provided value.
        value: u64,
        /// Inclusive lower bound.
        min: u64,
        /// Inclusive upper bound.
        max: u64,
    },

    /// The configuration was internally contradictory.
    #[error("invalid configuration: {0}")]
    Validation(String),

    /// A feature flag or mode selected behavior this release does not yet
    /// implement. Rather than silently ignore it — which would let an operator
    /// believe a capability is active when it is not — the node fails closed at
    /// startup and reports how to make the configuration valid.
    #[error("unsupported configuration '{field}': {detail}")]
    Unsupported {
        /// The offending field, e.g. `network.enable_quic`.
        field: &'static str,
        /// Why the setting is unsupported and how to make the config valid.
        detail: &'static str,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorFile {
    validators: Vec<ValidatorEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorEntry {
    #[allow(dead_code)]
    name: String,
    public_key: String,
    #[allow(dead_code)]
    region: String,
    /// Minimmit voting weight (unit weight is the only supported policy today).
    weight: u64,
}

/// Parse and validate the operator validator descriptor as a Minimmit committee.
///
/// The production default intentionally requires at least six members: smaller
/// unit committees derive `f = 0` and therefore provide no Byzantine tolerance.
fn load_minimmit_committee(path: &Path, epoch: u64) -> Result<MinimmitCommittee, ConfigError> {
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let descriptor: ValidatorFile = toml::from_str(&text)?;
    if descriptor.validators.len() < 6 {
        return Err(ConfigError::OutOfRange {
            field: "consensus.validators.count",
            value: u64::try_from(descriptor.validators.len()).unwrap_or(u64::MAX),
            min: 6,
            max: u64::from(u16::MAX),
        });
    }
    let mut validators = Vec::with_capacity(descriptor.validators.len());
    for entry in descriptor.validators {
        let bytes = hex::decode(&entry.public_key).map_err(|_| {
            ConfigError::Validation(format!(
                "validator '{}' has a non-hex public_key",
                entry.name
            ))
        })?;
        let public_key: [u8; 32] = bytes.try_into().map_err(|_| {
            ConfigError::Validation(format!(
                "validator '{}' public_key must encode exactly 32 bytes",
                entry.name
            ))
        })?;
        validators.push(Validator {
            public_key,
            weight: entry.weight,
        });
    }
    MinimmitCommittee::new_unit(epoch, validators).map_err(|err| {
        ConfigError::Validation(format!(
            "consensus validator set is not a valid unit-weight Minimmit committee: {err}"
        ))
    })
}

impl NodeConfig {
    /// Parse and validate a configuration from a TOML string (no filesystem checks).
    ///
    /// The input is untrusted; any error is returned as [`ConfigError`] without
    /// panicking. Path *existence* is checked by [`Self::load`].
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: NodeConfig = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read, parse, and validate a configuration file.
    ///
    /// Relative paths in the file (`validator_set_path`, `data_dir`) are resolved
    /// against the config file's parent directory before validation.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let mut cfg: NodeConfig = toml::from_str(&text)?;
        if let Some(dir) = path.parent() {
            cfg.resolve_relative_paths(dir);
        }
        cfg.validate()?;
        cfg.validate_paths()?;
        Ok(cfg)
    }

    /// Resolve relative path fields against `base` (typically the config file dir).
    fn resolve_relative_paths(&mut self, base: &Path) {
        self.consensus.validator_set_path =
            resolve_against(base, &self.consensus.validator_set_path);
        self.storage.data_dir = resolve_against(base, &self.storage.data_dir);
        for path in [
            &mut self.rpc.tls_cert_path,
            &mut self.rpc.tls_key_path,
            &mut self.rpc.tls_client_ca_path,
        ]
        .into_iter()
        .flatten()
        {
            *path = resolve_path_against(base, path);
        }
    }

    /// Apply CLI overrides on top of file values, then re-validate all startup
    /// invariants, including filesystem-backed role requirements.
    ///
    /// Overrides may add a consensus-bearing role after [`Self::load`] checked
    /// the original role set. Re-running only [`Self::validate`] here would let
    /// that role bypass the required validator-set load.
    pub fn with_overrides(mut self, overrides: &ConfigOverrides) -> Result<Self, ConfigError> {
        if overrides.light {
            self.node.light = true;
        }
        if !overrides.roles.is_empty() {
            self.node.roles = overrides.roles.clone();
        }
        self.validate()?;
        self.validate_paths()?;
        Ok(self)
    }

    /// Validate cross-field invariants (no filesystem I/O).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.node.name.trim().is_empty() {
            return Err(ConfigError::Validation(
                "node.name must not be empty".to_string(),
            ));
        }
        if self.node.region.trim().is_empty() {
            return Err(ConfigError::Validation(
                "node.region must not be empty".to_string(),
            ));
        }

        self.validate_unique_roles()?;

        let ms = self.consensus.checkpoint_interval_ms;
        if !(CHECKPOINT_INTERVAL_MIN_MS..=CHECKPOINT_INTERVAL_MAX_MS).contains(&ms) {
            return Err(ConfigError::OutOfRange {
                field: "consensus.checkpoint_interval_ms",
                value: ms,
                min: CHECKPOINT_INTERVAL_MIN_MS,
                max: CHECKPOINT_INTERVAL_MAX_MS,
            });
        }
        let delta_ms = self.consensus.delta_ms;
        if !(DELTA_MIN_MS..=DELTA_MAX_MS).contains(&delta_ms) {
            return Err(ConfigError::OutOfRange {
                field: "consensus.delta_ms",
                value: delta_ms,
                min: DELTA_MIN_MS,
                max: DELTA_MAX_MS,
            });
        }
        if self.consensus.epoch_length == 0 {
            return Err(ConfigError::Validation(
                "consensus.epoch_length must be greater than zero".to_string(),
            ));
        }
        if self.requires_validator_set() && self.consensus.validator_set_path.trim().is_empty() {
            return Err(ConfigError::Validation(
                "consensus.validator_set_path is required for validator/sequencer/witness/custody roles"
                    .to_string(),
            ));
        }

        self.validate_storage()?;
        self.validate_listen_addresses()?;
        self.validate_rpc()?;
        self.reject_unsupported_features()?;

        if self.node.light {
            if let Some(bad) = self.node.roles.iter().find(|r| r.is_consensus_bearing()) {
                return Err(ConfigError::Validation(format!(
                    "light node cannot assume consensus-bearing role '{}'; light nodes do not \
                     vote, execute canonical state, or hold custody shares",
                    bad.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Filesystem checks performed by [`Self::load`] after path resolution.
    pub fn validate_paths(&self) -> Result<(), ConfigError> {
        if self.requires_validator_set() {
            let path = Path::new(&self.consensus.validator_set_path);
            if !path.is_file() {
                return Err(ConfigError::Validation(format!(
                    "consensus.validator_set_path '{}' does not exist or is not a file \
                     (required for roles {:?})",
                    self.consensus.validator_set_path,
                    self.node
                        .roles
                        .iter()
                        .filter(|r| r.requires_validator_set())
                        .map(|r| r.as_str())
                        .collect::<Vec<_>>()
                )));
            }
            load_minimmit_committee(path, 0)?;
        }
        if self.storage.data_dir.trim().is_empty() {
            return Err(ConfigError::Validation(
                "storage.data_dir must not be empty".to_string(),
            ));
        }
        // data_dir may not exist yet (created at bootstrap); reject only if a
        // non-directory file occupies the path.
        let data = Path::new(&self.storage.data_dir);
        if data.exists() && !data.is_dir() {
            return Err(ConfigError::Validation(format!(
                "storage.data_dir '{}' exists and is not a directory",
                self.storage.data_dir
            )));
        }
        // TLS PEM inputs must exist at load so a mistyped path fails at startup,
        // not when the acceptor is (later) constructed.
        for (field, path) in [
            ("rpc.tls_cert_path", &self.rpc.tls_cert_path),
            ("rpc.tls_key_path", &self.rpc.tls_key_path),
            ("rpc.tls_client_ca_path", &self.rpc.tls_client_ca_path),
        ] {
            if let Some(p) = path {
                if !p.is_file() {
                    return Err(ConfigError::Validation(format!(
                        "{field} '{}' does not exist or is not a file",
                        p.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// True when any configured role needs a validator-set file.
    fn requires_validator_set(&self) -> bool {
        self.node.roles.iter().any(|r| r.requires_validator_set())
    }

    /// Reject duplicate roles (named in the error). Preserves canonical order.
    fn validate_unique_roles(&self) -> Result<(), ConfigError> {
        let mut seen = Vec::with_capacity(self.node.roles.len());
        for role in &self.node.roles {
            if seen.contains(role) {
                return Err(ConfigError::Validation(format!(
                    "duplicate node role '{}'; each role may appear at most once",
                    role.as_str()
                )));
            }
            seen.push(*role);
        }
        Ok(())
    }

    /// Range-check the `[storage]` settings so a pathological value fails closed
    /// at startup rather than surfacing later as a division-by-zero or an
    /// overflowing segment allocation once the durable journal is wired.
    fn validate_storage(&self) -> Result<(), ConfigError> {
        if self.storage.data_dir.trim().is_empty() {
            return Err(ConfigError::Validation(
                "storage.data_dir must not be empty".to_string(),
            ));
        }
        if self.storage.snapshot_interval_sequences == 0 {
            return Err(ConfigError::Validation(
                "storage.snapshot_interval_sequences must be greater than zero".to_string(),
            ));
        }
        let mb = self.storage.segment_size_mb;
        if !(SEGMENT_SIZE_MIN_MB..=SEGMENT_SIZE_MAX_MB).contains(&mb) {
            return Err(ConfigError::OutOfRange {
                field: "storage.segment_size_mb",
                value: mb,
                min: SEGMENT_SIZE_MIN_MB,
                max: SEGMENT_SIZE_MAX_MB,
            });
        }
        Ok(())
    }

    /// Parse listen addresses so a typo fails at load, not at bind.
    fn validate_listen_addresses(&self) -> Result<(), ConfigError> {
        parse_listen("network.listen", &self.network.listen)?;
        parse_listen("rpc.listen", &self.rpc.listen)?;
        if !self.observability.metrics_listen.trim().is_empty() {
            parse_listen(
                "observability.metrics_listen",
                &self.observability.metrics_listen,
            )?;
        }
        for (i, peer) in self.network.bootstrap_peers.iter().enumerate() {
            // Bootstrap peers may be hostnames; require host:port form at minimum.
            if peer.trim().is_empty() {
                return Err(ConfigError::Validation(format!(
                    "network.bootstrap_peers[{i}] must not be empty"
                )));
            }
            if !peer.contains(':') {
                return Err(ConfigError::Validation(format!(
                    "network.bootstrap_peers[{i}] = '{peer}' must be host:port"
                )));
            }
        }
        let drain = self.performance.drain_timeout_ms;
        if drain > DRAIN_TIMEOUT_MAX_MS {
            return Err(ConfigError::OutOfRange {
                field: "performance.drain_timeout_ms",
                value: drain,
                min: 0,
                max: DRAIN_TIMEOUT_MAX_MS,
            });
        }
        Ok(())
    }

    /// Validate the `[rpc]` transport posture so an inexpressible combination
    /// fails closed at load rather than surfacing at bind time (or worse,
    /// silently serving cleartext where the operator intended TLS).
    fn validate_rpc(&self) -> Result<(), ConfigError> {
        let rpc = &self.rpc;

        // TLS identity is both-or-neither: a certificate chain without its
        // private key (or vice versa) cannot build any `rpc::TlsMode` and is
        // therefore an unsupported posture, not a silently-cleartext one.
        match (&rpc.tls_cert_path, &rpc.tls_key_path) {
            (Some(_), None) => {
                return Err(ConfigError::Unsupported {
                    field: "rpc.tls_cert_path",
                    detail: "tls_cert_path is set without rpc.tls_key_path; TLS 1.3 needs the \
                             certificate chain and its PKCS#8 private key together — set both \
                             (TLS required) or neither (cleartext, tests/loopback only)",
                });
            }
            (None, Some(_)) => {
                return Err(ConfigError::Unsupported {
                    field: "rpc.tls_key_path",
                    detail: "tls_key_path is set without rpc.tls_cert_path; TLS 1.3 needs the \
                             certificate chain and its PKCS#8 private key together — set both \
                             (TLS required) or neither (cleartext, tests/loopback only)",
                });
            }
            _ => {}
        }
        if rpc.tls_client_ca_path.is_some() && !rpc.tls_configured() {
            return Err(ConfigError::Unsupported {
                field: "rpc.tls_client_ca_path",
                detail: "mTLS client verification requires rpc.tls_cert_path and \
                         rpc.tls_key_path; set the server certificate pair or remove \
                         tls_client_ca_path",
            });
        }
        for (field, path) in [
            ("rpc.tls_cert_path", &rpc.tls_cert_path),
            ("rpc.tls_key_path", &rpc.tls_key_path),
            ("rpc.tls_client_ca_path", &rpc.tls_client_ca_path),
        ] {
            if let Some(p) = path {
                if p.as_os_str().is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "{field} must not be empty when set"
                    )));
                }
            }
        }

        // Per-IP rate limiting is both-or-neither: a positive rate with a zero
        // burst admits nothing, and a positive burst with a zero rate never
        // refills. Both are almost certainly operator mistakes.
        if (rpc.rate_per_ip_per_sec == 0) != (rpc.rate_burst == 0) {
            return Err(ConfigError::Validation(format!(
                "rpc.rate_per_ip_per_sec = {} and rpc.rate_burst = {} are contradictory; \
                 set both positive (rate limiting on) or both zero (rate limiting off)",
                rpc.rate_per_ip_per_sec, rpc.rate_burst
            )));
        }

        for (field, is_zero) in [
            ("rpc.max_connections", rpc.max_connections == 0),
            (
                "rpc.max_connections_per_ip",
                rpc.max_connections_per_ip == 0,
            ),
            ("rpc.idle_timeout_ms", rpc.idle_timeout_ms == 0),
            ("rpc.read_timeout_ms", rpc.read_timeout_ms == 0),
            ("rpc.write_timeout_ms", rpc.write_timeout_ms == 0),
            ("rpc.dispatch_timeout_ms", rpc.dispatch_timeout_ms == 0),
            (
                "rpc.max_in_flight_requests",
                rpc.max_in_flight_requests == 0,
            ),
            ("rpc.max_in_flight_bytes", rpc.max_in_flight_bytes == 0),
            (
                "rpc.max_in_flight_requests_per_conn",
                rpc.max_in_flight_requests_per_conn == 0,
            ),
            (
                "rpc.max_in_flight_bytes_per_conn",
                rpc.max_in_flight_bytes_per_conn == 0,
            ),
        ] {
            if is_zero {
                return Err(ConfigError::Validation(format!(
                    "{field} must be greater than zero"
                )));
            }
        }
        Ok(())
    }

    /// Reject feature flags and modes whose implementations have not landed in
    /// this release (or were not compiled in). Silently no-oping them would let
    /// an operator believe a capability is active when it is not.
    fn reject_unsupported_features(&self) -> Result<(), ConfigError> {
        // Real QUIC + native datagrams require the `quic` feature on `network`
        // (enabled by default via `node`'s `quic` feature). Without it, both
        // flags must stay false — never a silent no-op.
        if self.network.enable_quic && !network::quic_supported() {
            return Err(ConfigError::Unsupported {
                field: "network.enable_quic",
                detail: "QUIC transport was not compiled into this binary \
                         (build with --features quic); set network.enable_quic = false \
                         or rebuild with the quic feature",
            });
        }
        if self.network.enable_datagrams {
            if !self.network.enable_quic {
                return Err(ConfigError::Unsupported {
                    field: "network.enable_datagrams",
                    detail: "native datagrams require QUIC (network.enable_quic = true); \
                             TCP multiplexes 'datagrams' onto the ordered byte stream \
                             with reduced HOL guarantees and is not a substitute",
                });
            }
            if !network::quic_supported() {
                return Err(ConfigError::Unsupported {
                    field: "network.enable_datagrams",
                    detail: "QUIC datagram support was not compiled into this binary \
                             (build with --features quic); set network.enable_datagrams = false \
                             or rebuild with the quic feature",
                });
            }
        }
        // pin_threads is implemented on Linux/macOS; reject only elsewhere.
        if self.performance.pin_threads && !crate::threading::pinning_supported() {
            return Err(ConfigError::Unsupported {
                field: "performance.pin_threads",
                detail: "core pinning is not supported on this platform; \
                         set performance.pin_threads = false",
            });
        }
        if self.performance.busy_poll {
            return Err(ConfigError::Unsupported {
                field: "performance.busy_poll",
                detail: "busy-polled ingress is not implemented in this release; \
                         set performance.busy_poll = false",
            });
        }
        Ok(())
    }

    /// The roles this node will actually run, honoring light-mode restrictions.
    /// Order is the canonical config order; duplicates are impossible post-validate.
    pub fn effective_roles(&self) -> Vec<Role> {
        if self.node.light {
            self.node
                .roles
                .iter()
                .copied()
                .filter(|r| !r.is_consensus_bearing())
                .collect()
        } else {
            self.node.roles.clone()
        }
    }
}

fn parse_listen(field: &'static str, value: &str) -> Result<SocketAddr, ConfigError> {
    value.parse::<SocketAddr>().map_err(|e| {
        ConfigError::Validation(format!(
            "{field} = '{value}' is not a valid socket address: {e}"
        ))
    })
}

fn resolve_against(base: &Path, value: &str) -> String {
    let p = Path::new(value);
    if p.is_absolute() || value.is_empty() {
        value.to_string()
    } else {
        base.join(p)
            .components()
            .collect::<PathBuf>()
            .display()
            .to_string()
    }
}

fn resolve_path_against(base: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() || value.as_os_str().is_empty() {
        value.to_path_buf()
    } else {
        base.join(value).components().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_toml() -> &'static str {
        r#"
[node]
name = "tokyo-1"
region = "ap-northeast"
light = false
roles = ["validator", "witness", "gateway"]

[network]
listen = "0.0.0.0:9000"
bootstrap_peers = ["1.2.3.4:9000"]
enable_quic = false
enable_datagrams = false

[consensus]
checkpoint_interval_ms = 100
epoch_length = 100000
validator_set_path = "validators.toml"

[storage]
data_dir = "./data"
snapshot_interval_sequences = 1000000
segment_size_mb = 1024

[rpc]
listen = "0.0.0.0:8080"
read_only = false
tls_cert_path = "certs/rpc-chain.pem"
tls_key_path = "certs/rpc-key.pem"
tls_client_ca_path = "certs/client-roots.pem"
max_connections = 2048
max_connections_per_ip = 16
rate_per_ip_per_sec = 8
rate_burst = 24
idle_timeout_ms = 20000
read_timeout_ms = 4000
write_timeout_ms = 3000
dispatch_timeout_ms = 1500
max_in_flight_requests = 256
max_in_flight_bytes = 8388608
max_in_flight_requests_per_conn = 2
max_in_flight_bytes_per_conn = 262144

[performance]
pin_threads = false
busy_poll = false
drain_timeout_ms = 15000

[observability]
log_format = "json"
metrics_listen = "127.0.0.1:9100"
"#
    }

    #[test]
    fn parses_all_sections_including_observability() {
        let cfg = NodeConfig::from_toml_str(full_toml()).expect("valid config");
        assert_eq!(cfg.node.name, "tokyo-1");
        assert_eq!(
            cfg.node.roles,
            vec![Role::Validator, Role::Witness, Role::Gateway]
        );
        assert_eq!(cfg.network.bootstrap_peers, vec!["1.2.3.4:9000"]);
        assert_eq!(cfg.consensus.epoch_length, 100_000);
        assert_eq!(cfg.storage.segment_size_mb, 1024);
        assert!(!cfg.rpc.read_only);
        assert!(cfg.rpc.tls_configured());
        assert_eq!(cfg.rpc.max_connections, 2048);
        assert_eq!(cfg.observability.log_format, LogFormat::Json);
        assert_eq!(cfg.observability.metrics_listen, "127.0.0.1:9100");
        assert_eq!(cfg.performance.drain_timeout_ms, 15_000);
    }

    #[test]
    fn round_trips_through_toml() {
        let cfg = NodeConfig::from_toml_str(full_toml()).unwrap();
        let serialized = toml::to_string(&cfg).unwrap();
        let reparsed = NodeConfig::from_toml_str(&serialized).unwrap();
        assert_eq!(cfg, reparsed);
    }

    #[test]
    fn empty_config_uses_defaults() {
        let cfg = NodeConfig::from_toml_str("").unwrap();
        assert_eq!(cfg, NodeConfig::default());
        assert_eq!(cfg.consensus.checkpoint_interval_ms, 100);
    }

    #[test]
    fn default_config_round_trips_through_toml() {
        let cfg = NodeConfig::default();
        let serialized = toml::to_string(&cfg).unwrap();
        let reparsed = NodeConfig::from_toml_str(&serialized).unwrap();
        assert_eq!(cfg, reparsed);
    }

    #[test]
    fn rpc_transport_toml_maps_to_server_config() {
        let cfg = NodeConfig::from_toml_str(full_toml()).expect("valid config");
        assert_eq!(
            cfg.rpc.tls_cert_path.as_deref(),
            Some(Path::new("certs/rpc-chain.pem"))
        );
        assert_eq!(
            cfg.rpc.tls_key_path.as_deref(),
            Some(Path::new("certs/rpc-key.pem"))
        );
        assert_eq!(
            cfg.rpc.tls_client_ca_path.as_deref(),
            Some(Path::new("certs/client-roots.pem"))
        );
        assert!(cfg.rpc.tls_configured());

        let sc = cfg.rpc.server_config(rpc::TlsMode::Disabled);
        assert_eq!(sc.max_connections, 2048);
        assert_eq!(sc.max_connections_per_ip, 16);
        assert_eq!(
            sc.per_ip_rate,
            Some(rpc::RateLimit {
                per_sec: 8,
                burst: 24
            })
        );
        assert_eq!(sc.idle_timeout, Duration::from_millis(20_000));
        assert_eq!(sc.read_timeout, Duration::from_millis(4_000));
        assert_eq!(sc.write_timeout, Duration::from_millis(3_000));
        assert_eq!(sc.dispatch_timeout, Duration::from_millis(1_500));
        assert_eq!(sc.work.max_in_flight_requests, 256);
        assert_eq!(sc.work.max_in_flight_bytes, 8 * 1024 * 1024);
        assert_eq!(sc.work.max_in_flight_requests_per_conn, 2);
        assert_eq!(sc.work.max_in_flight_bytes_per_conn, 256 * 1024);
        assert!(matches!(sc.tls, rpc::TlsMode::Disabled));

        // Unexposed knobs keep their rpc defaults.
        let d = rpc::ServerConfig::default();
        assert_eq!(sc.max_tracked_ips, d.max_tracked_ips);
        assert_eq!(sc.max_payload, d.max_payload);
        assert_eq!(sc.drain_timeout, d.drain_timeout);
    }

    #[test]
    fn rpc_defaults_mirror_server_config_defaults() {
        // A config that omits every transport key — including a pre-#418
        // `[rpc]` section with only listen/read_only — must map exactly onto
        // `rpc::ServerConfig::default()`.
        let expected = rpc::ServerConfig::default();
        for toml_src in ["", "[rpc]\nlisten = \"127.0.0.1:8080\"\nread_only = true"] {
            let cfg = NodeConfig::from_toml_str(toml_src).expect("valid config");
            assert!(cfg.rpc.tls_cert_path.is_none());
            assert!(cfg.rpc.tls_key_path.is_none());
            assert!(cfg.rpc.tls_client_ca_path.is_none());
            assert!(!cfg.rpc.tls_configured());

            let sc = cfg.rpc.server_config(rpc::TlsMode::Disabled);
            assert_eq!(sc.max_connections, expected.max_connections);
            assert_eq!(sc.max_connections_per_ip, expected.max_connections_per_ip);
            assert_eq!(sc.per_ip_rate, expected.per_ip_rate);
            assert_eq!(sc.idle_timeout, expected.idle_timeout);
            assert_eq!(sc.read_timeout, expected.read_timeout);
            assert_eq!(sc.write_timeout, expected.write_timeout);
            assert_eq!(sc.dispatch_timeout, expected.dispatch_timeout);
            assert_eq!(sc.max_tracked_ips, expected.max_tracked_ips);
            assert_eq!(sc.max_payload, expected.max_payload);
            assert_eq!(sc.drain_timeout, expected.drain_timeout);
            assert_eq!(
                sc.work.max_in_flight_requests,
                expected.work.max_in_flight_requests
            );
            assert_eq!(
                sc.work.max_in_flight_bytes,
                expected.work.max_in_flight_bytes
            );
            assert_eq!(
                sc.work.max_in_flight_requests_per_conn,
                expected.work.max_in_flight_requests_per_conn
            );
            assert_eq!(
                sc.work.max_in_flight_bytes_per_conn,
                expected.work.max_in_flight_bytes_per_conn
            );
            assert!(matches!(sc.tls, rpc::TlsMode::Disabled));
        }
    }

    #[test]
    fn rejects_unknown_rpc_field() {
        // Typo'd key (`tls_cert` instead of `tls_cert_path`) must fail parse,
        // never silently serve cleartext.
        let toml = "[rpc]\nlisten = \"127.0.0.1:8080\"\nread_only = false\ntls_cert = \"x.pem\"";
        assert!(matches!(
            NodeConfig::from_toml_str(toml),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn rejects_tls_cert_without_key() {
        let toml =
            "[rpc]\nlisten = \"127.0.0.1:8080\"\nread_only = false\ntls_cert_path = \"x.pem\"";
        let err = NodeConfig::from_toml_str(toml).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Unsupported {
                    field: "rpc.tls_cert_path",
                    ..
                }
            ),
            "expected unsupported half-TLS posture, got {err:?}"
        );
    }

    #[test]
    fn rejects_tls_key_without_cert() {
        let mut cfg = NodeConfig::default();
        cfg.rpc.tls_key_path = Some(PathBuf::from("x.key"));
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Unsupported {
                field: "rpc.tls_key_path",
                ..
            })
        ));
    }

    #[test]
    fn rejects_client_ca_without_server_cert_pair() {
        let mut cfg = NodeConfig::default();
        cfg.rpc.tls_client_ca_path = Some(PathBuf::from("roots.pem"));
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Unsupported {
                field: "rpc.tls_client_ca_path",
                ..
            })
        ));
    }

    #[test]
    fn rejects_contradictory_rpc_rate_pair() {
        // Positive rate with zero burst admits nothing; zero rate with positive
        // burst never refills. Both are rejected; both-zero disables limiting.
        let mut cfg = NodeConfig::default();
        cfg.rpc.rate_burst = 0;
        assert!(matches!(cfg.validate(), Err(ConfigError::Validation(_))));

        let mut cfg = NodeConfig::default();
        cfg.rpc.rate_per_ip_per_sec = 0;
        assert!(matches!(cfg.validate(), Err(ConfigError::Validation(_))));

        let mut cfg = NodeConfig::default();
        cfg.rpc.rate_per_ip_per_sec = 0;
        cfg.rpc.rate_burst = 0;
        cfg.validate().expect("both-zero disables rate limiting");
        assert_eq!(cfg.rpc.per_ip_rate(), None);
    }

    #[test]
    fn rejects_zero_rpc_limits_and_timeouts() {
        for mutate in [
            (|c: &mut NodeConfig| c.rpc.max_connections = 0) as fn(&mut NodeConfig),
            |c| c.rpc.max_connections_per_ip = 0,
            |c| c.rpc.idle_timeout_ms = 0,
            |c| c.rpc.read_timeout_ms = 0,
            |c| c.rpc.write_timeout_ms = 0,
            |c| c.rpc.dispatch_timeout_ms = 0,
            |c| c.rpc.max_in_flight_requests = 0,
            |c| c.rpc.max_in_flight_bytes = 0,
            |c| c.rpc.max_in_flight_requests_per_conn = 0,
            |c| c.rpc.max_in_flight_bytes_per_conn = 0,
        ] {
            let mut cfg = NodeConfig::default();
            mutate(&mut cfg);
            assert!(
                matches!(cfg.validate(), Err(ConfigError::Validation(_))),
                "zeroed rpc limit must be rejected"
            );
        }
    }

    #[test]
    fn rejects_checkpoint_interval_out_of_range() {
        let toml = "[consensus]\ncheckpoint_interval_ms = 40\nepoch_length = 10\nvalidator_set_path = \"v\"";
        let err = NodeConfig::from_toml_str(toml).unwrap_err();
        assert!(
            matches!(err, ConfigError::OutOfRange { field, .. } if field.ends_with("checkpoint_interval_ms"))
        );

        let toml = "[consensus]\ncheckpoint_interval_ms = 250\nepoch_length = 10\nvalidator_set_path = \"v\"";
        assert!(matches!(
            NodeConfig::from_toml_str(toml),
            Err(ConfigError::OutOfRange { .. })
        ));
    }

    #[test]
    fn delta_is_defaulted_and_bounded() {
        let legacy = "[consensus]\ncheckpoint_interval_ms = 100\nepoch_length = 10\nvalidator_set_path = \"v\"";
        assert_eq!(
            NodeConfig::from_toml_str(legacy)
                .unwrap()
                .consensus
                .delta_ms,
            100
        );
        let invalid = "[consensus]\ncheckpoint_interval_ms = 100\ndelta_ms = 0\nepoch_length = 10\nvalidator_set_path = \"v\"";
        assert!(matches!(
            NodeConfig::from_toml_str(invalid),
            Err(ConfigError::OutOfRange {
                field: "consensus.delta_ms",
                ..
            })
        ));
    }

    #[test]
    fn rejects_unknown_role() {
        let toml = "[node]\nname=\"n\"\nregion=\"r\"\nlight=false\nroles=[\"banana\"]";
        assert!(matches!(
            NodeConfig::from_toml_str(toml),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn rejects_unknown_field() {
        let toml = "[node]\nname=\"n\"\nregion=\"r\"\nlight=false\nroles=[]\nbogus=1";
        assert!(matches!(
            NodeConfig::from_toml_str(toml),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn rejects_light_node_with_consensus_role() {
        for bad in ["validator", "sequencer", "custody"] {
            let toml = format!("[node]\nname=\"n\"\nregion=\"r\"\nlight=true\nroles=[\"{bad}\"]");
            assert!(
                matches!(
                    NodeConfig::from_toml_str(&toml),
                    Err(ConfigError::Validation(_))
                ),
                "light + {bad} should be rejected"
            );
        }
    }

    #[test]
    fn light_mode_filters_consensus_roles_from_effective_set() {
        let toml = "[node]\nname=\"n\"\nregion=\"r\"\nlight=true\nroles=[\"gateway\",\"observer\"]";
        let cfg = NodeConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.effective_roles(), vec![Role::Gateway, Role::Observer]);
    }

    #[test]
    fn overrides_take_precedence_over_file() {
        let base = NodeConfig::from_toml_str("").unwrap();
        let cfg = base
            .with_overrides(&ConfigOverrides {
                light: false,
                roles: vec![Role::Gateway, Role::Observer],
            })
            .unwrap();
        assert_eq!(cfg.node.roles, vec![Role::Gateway, Role::Observer]);
    }

    #[test]
    fn overrides_cannot_bypass_consensus_role_path_validation() {
        let mut base = NodeConfig::from_toml_str("").unwrap();
        base.consensus.validator_set_path = std::env::temp_dir()
            .join(format!(
                "dexos-missing-validators-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .display()
            .to_string();

        let err = base
            .with_overrides(&ConfigOverrides {
                light: false,
                roles: vec![Role::Validator],
            })
            .unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation(ref message) if message.contains("validator_set_path")),
            "{err}"
        );
    }

    #[test]
    fn rejects_duplicate_roles_with_name() {
        let toml =
            "[node]\nname=\"n\"\nregion=\"r\"\nlight=false\nroles=[\"gateway\",\"validator\",\"gateway\"]";
        let err = NodeConfig::from_toml_str(toml).unwrap_err();
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("duplicate"), "{msg}");
                assert!(msg.contains("gateway"), "{msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_listen_addresses() {
        let mut cfg = NodeConfig::default();
        cfg.network.listen = "not-an-addr".into();
        assert!(matches!(cfg.validate(), Err(ConfigError::Validation(_))));

        let mut cfg = NodeConfig::default();
        cfg.rpc.listen = "8080".into(); // missing host
        assert!(matches!(cfg.validate(), Err(ConfigError::Validation(_))));

        let mut cfg = NodeConfig::default();
        cfg.observability.metrics_listen = "localhost".into();
        assert!(matches!(cfg.validate(), Err(ConfigError::Validation(_))));
    }

    #[test]
    fn default_config_disables_unimplemented_features() {
        let cfg = NodeConfig::default();
        assert!(!cfg.network.enable_quic);
        assert!(!cfg.network.enable_datagrams);
        assert!(!cfg.performance.pin_threads);
        assert!(!cfg.performance.busy_poll);
        cfg.validate().expect("default config must be valid");
    }

    #[test]
    fn quic_flag_requires_compiled_support() {
        let mut cfg = NodeConfig::default();
        cfg.network.enable_quic = true;
        if network::quic_supported() {
            cfg.validate()
                .expect("enable_quic must be accepted when the quic feature is compiled in");
        } else {
            assert!(matches!(
                cfg.validate(),
                Err(ConfigError::Unsupported {
                    field: "network.enable_quic",
                    ..
                })
            ));
        }
    }

    #[test]
    fn datagrams_require_quic_enabled() {
        let mut cfg = NodeConfig::default();
        // Datagrams without QUIC: always rejected (TCP is not a substitute).
        cfg.network.enable_datagrams = true;
        cfg.network.enable_quic = false;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Unsupported {
                field: "network.enable_datagrams",
                ..
            })
        ));

        cfg.network.enable_quic = true;
        if network::quic_supported() {
            cfg.validate()
                .expect("datagrams + quic accepted when feature is present");
        } else {
            let err = cfg.validate().unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::Unsupported {
                        field: "network.enable_datagrams",
                        ..
                    } | ConfigError::Unsupported {
                        field: "network.enable_quic",
                        ..
                    }
                ),
                "expected unsupported quic/datagrams, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_busy_poll() {
        let mut cfg = NodeConfig::default();
        cfg.performance.busy_poll = true;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Unsupported {
                field: "performance.busy_poll",
                ..
            })
        ));
    }

    #[test]
    fn pin_threads_allowed_on_supported_platforms() {
        let mut cfg = NodeConfig::default();
        cfg.performance.pin_threads = true;
        if crate::threading::pinning_supported() {
            cfg.validate().expect("pin_threads ok on this platform");
        } else {
            assert!(matches!(
                cfg.validate(),
                Err(ConfigError::Unsupported {
                    field: "performance.pin_threads",
                    ..
                })
            ));
        }
    }

    #[test]
    fn quic_flag_through_full_toml_load_is_feature_gated() {
        let toml = "[network]\nlisten = \"0.0.0.0:9000\"\nbootstrap_peers = []\n\
                    enable_quic = true\nenable_datagrams = false";
        let result = NodeConfig::from_toml_str(toml);
        if network::quic_supported() {
            result.expect("quic enabled config valid with feature");
        } else {
            assert!(matches!(
                result,
                Err(ConfigError::Unsupported {
                    field: "network.enable_quic",
                    ..
                })
            ));
        }
    }

    #[test]
    fn rejects_pathological_storage_settings() {
        let mut cfg = NodeConfig::default();
        cfg.storage.snapshot_interval_sequences = 0;
        assert!(matches!(cfg.validate(), Err(ConfigError::Validation(_))));

        let mut cfg = NodeConfig::default();
        cfg.storage.segment_size_mb = 0;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::OutOfRange {
                field: "storage.segment_size_mb",
                ..
            })
        ));

        let mut cfg = NodeConfig::default();
        cfg.storage.segment_size_mb = SEGMENT_SIZE_MAX_MB + 1;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::OutOfRange {
                field: "storage.segment_size_mb",
                ..
            })
        ));

        let mut cfg = NodeConfig::default();
        cfg.storage.segment_size_mb = SEGMENT_SIZE_MAX_MB;
        cfg.validate().expect("max segment size is in range");
    }

    #[test]
    fn load_requires_validators_file_for_consensus_roles() {
        let dir = std::env::temp_dir().join(format!(
            "dexos-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("node.toml");
        let validators = dir.join("validators.toml");
        fs::write(
            &cfg_path,
            r#"
[node]
name = "t"
region = "r"
light = false
roles = ["validator"]

[network]
listen = "127.0.0.1:19000"
bootstrap_peers = []
enable_quic = false
enable_datagrams = false

[consensus]
checkpoint_interval_ms = 100
epoch_length = 10
validator_set_path = "validators.toml"

[storage]
data_dir = "./data"
snapshot_interval_sequences = 1000
segment_size_mb = 64

[rpc]
listen = "127.0.0.1:18080"
read_only = false
"#,
        )
        .unwrap();

        // Missing validators.toml → fail.
        let err = NodeConfig::load(&cfg_path).unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation(ref m) if m.contains("validator_set_path")),
            "{err}"
        );

        let descriptor = |count: u8| {
            (0u8..count)
            .map(|i| {
                let public_key = crypto::KeyPair::from_seed(&[i; 32]).public();
                format!(
                    "[[validators]]\nname = \"v{i}\"\npublic_key = \"{}\"\nregion = \"test\"\nweight = 1\n",
                    hex::encode(public_key)
                )
            })
            .collect::<String>()
        };
        fs::write(&validators, descriptor(3)).unwrap();
        assert!(matches!(
            NodeConfig::load(&cfg_path),
            Err(ConfigError::OutOfRange {
                field: "consensus.validators.count",
                value: 3,
                min: 6,
                ..
            })
        ));
        fs::write(&validators, descriptor(6)).unwrap();
        let cfg = NodeConfig::load(&cfg_path).expect("with validators file");
        assert!(Path::new(&cfg.consensus.validator_set_path).is_file());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_resolves_and_requires_tls_files() {
        let dir = std::env::temp_dir().join(format!(
            "dexos-cfg-tls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("node.toml");
        fs::write(
            &cfg_path,
            r#"
[rpc]
listen = "127.0.0.1:18080"
read_only = false
tls_cert_path = "rpc.pem"
tls_key_path = "rpc.key"
"#,
        )
        .unwrap();

        // Missing PEM files → fail closed at load.
        let err = NodeConfig::load(&cfg_path).unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation(ref m) if m.contains("rpc.tls_cert_path")),
            "{err}"
        );

        fs::write(dir.join("rpc.pem"), "cert\n").unwrap();
        fs::write(dir.join("rpc.key"), "key\n").unwrap();
        let cfg = NodeConfig::load(&cfg_path).expect("with pem files present");
        // Relative paths resolve against the config file's directory.
        let cert = cfg.rpc.tls_cert_path.as_deref().unwrap();
        assert!(cert.is_absolute() && cert.is_file(), "{}", cert.display());
        assert!(cfg.rpc.tls_configured());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..4096 {
            let mut buf = Vec::new();
            let len = usize::try_from(state % 96).unwrap_or(0);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                buf.push(state.to_le_bytes()[0]);
            }
            if let Ok(text) = std::str::from_utf8(&buf) {
                let _ = NodeConfig::from_toml_str(text);
            }
        }
    }
}
