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

use serde::{Deserialize, Serialize};

/// Checkpoint cadence is bounded to 50–100 ms by the consensus design.
pub const CHECKPOINT_INTERVAL_MIN_MS: u64 = 50;
/// Upper bound of the configurable checkpoint cadence.
pub const CHECKPOINT_INTERVAL_MAX_MS: u64 = 100;

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
    /// Number of sequences per epoch.
    pub epoch_length: u64,
    /// Path to the validator-set descriptor.
    pub validator_set_path: String,
}

impl Default for ConsensusSection {
    fn default() -> Self {
        Self {
            checkpoint_interval_ms: 100,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcSection {
    /// Listen address for the public RPC surface.
    pub listen: String,
    /// Whether the RPC surface is read-only.
    pub read_only: bool,
}

impl Default for RpcSection {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_string(),
            read_only: false,
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
    }

    /// Apply CLI overrides on top of file values, then re-validate.
    pub fn with_overrides(mut self, overrides: &ConfigOverrides) -> Result<Self, ConfigError> {
        if overrides.light {
            self.node.light = true;
        }
        if !overrides.roles.is_empty() {
            self.node.roles = overrides.roles.clone();
        }
        self.validate()?;
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
                roles: vec![Role::Validator, Role::Sequencer],
            })
            .unwrap();
        assert_eq!(cfg.node.roles, vec![Role::Validator, Role::Sequencer]);
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

        fs::write(&validators, "validators = []\n").unwrap();
        let cfg = NodeConfig::load(&cfg_path).expect("with validators file");
        assert!(Path::new(&cfg.consensus.validator_set_path).is_file());
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
