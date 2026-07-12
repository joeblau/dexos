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
use std::path::Path;

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

/// A role a node may assume. A node may hold multiple roles simultaneously.
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
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// Human-readable node name.
    pub name: String,
    /// Deployment region tag (e.g. `ap-northeast`).
    pub region: String,
    /// Whether this node runs in light mode.
    pub light: bool,
    /// Roles this node assumes.
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
            // Fail closed by default: neither the QUIC session layer nor datagram
            // dissemination is wired into the node yet, so the safe default is off.
            // Requesting either explicitly is rejected by `validate`.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceSection {
    /// Pin subsystem threads to cores.
    pub pin_threads: bool,
    /// Busy-poll ingress queues.
    pub busy_poll: bool,
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
    /// Parse and validate a configuration from a TOML string.
    ///
    /// The input is untrusted; any error is returned as [`ConfigError`] without
    /// panicking.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: NodeConfig = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read, parse, and validate a configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&text)
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

    /// Validate cross-field invariants. Called by every constructor.
    pub fn validate(&self) -> Result<(), ConfigError> {
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
        self.validate_storage()?;
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

    /// Range-check the `[storage]` settings so a pathological value fails closed
    /// at startup rather than surfacing later as a division-by-zero or an
    /// overflowing segment allocation once the durable journal is wired.
    fn validate_storage(&self) -> Result<(), ConfigError> {
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

    /// Reject feature flags and modes whose implementations have not landed in
    /// this release. Silently no-oping them would let an operator believe a
    /// capability (QUIC sessions, datagram dissemination, core pinning,
    /// busy-polled ingress, a forced SIMD ISA) is active when it is not, so the
    /// node refuses to start until each is set back to a supported value.
    fn reject_unsupported_features(&self) -> Result<(), ConfigError> {
        if self.network.enable_quic {
            return Err(ConfigError::Unsupported {
                field: "network.enable_quic",
                detail: "QUIC reliable sessions are not implemented in this release; \
                         set network.enable_quic = false",
            });
        }
        if self.network.enable_datagrams {
            return Err(ConfigError::Unsupported {
                field: "network.enable_datagrams",
                detail: "datagram market-data dissemination is not implemented in this \
                         release; set network.enable_datagrams = false",
            });
        }
        if self.performance.pin_threads {
            return Err(ConfigError::Unsupported {
                field: "performance.pin_threads",
                detail: "core pinning uses a portable no-op backend in this release; \
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
"#
    }

    #[test]
    fn parses_all_six_sections() {
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
        // gateway + observer are legal for a light node.
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

    // --- fail-closed rejection of unsupported settings (issue #312, AC #5) ---

    #[test]
    fn default_config_disables_unimplemented_features() {
        // The honest default must be the supported one, so an operator who edits
        // nothing never unknowingly requests a capability the node cannot deliver.
        let cfg = NodeConfig::default();
        assert!(!cfg.network.enable_quic);
        assert!(!cfg.network.enable_datagrams);
        assert!(!cfg.performance.pin_threads);
        assert!(!cfg.performance.busy_poll);
        // And it validates cleanly.
        cfg.validate().expect("default config must be valid");
    }

    #[test]
    fn rejects_unsupported_quic() {
        let mut cfg = NodeConfig::default();
        cfg.network.enable_quic = true;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Unsupported {
                field: "network.enable_quic",
                ..
            })
        ));
    }

    #[test]
    fn rejects_unsupported_datagrams() {
        let mut cfg = NodeConfig::default();
        cfg.network.enable_datagrams = true;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Unsupported {
                field: "network.enable_datagrams",
                ..
            })
        ));
    }

    #[test]
    fn rejects_unsupported_thread_pinning_and_busy_poll() {
        let mut cfg = NodeConfig::default();
        cfg.performance.pin_threads = true;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Unsupported {
                field: "performance.pin_threads",
                ..
            })
        ));

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
    fn unsupported_flag_rejected_through_full_toml_load() {
        // The rejection is enforced by the public loader, not just field access:
        // a real operator file that enables QUIC fails closed at load time.
        let toml = "[network]\nlisten = \"0.0.0.0:9000\"\nbootstrap_peers = []\n\
                    enable_quic = true\nenable_datagrams = false";
        assert!(matches!(
            NodeConfig::from_toml_str(toml),
            Err(ConfigError::Unsupported {
                field: "network.enable_quic",
                ..
            })
        ));
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

        // A boundary value inside the range is accepted.
        let mut cfg = NodeConfig::default();
        cfg.storage.segment_size_mb = SEGMENT_SIZE_MAX_MB;
        cfg.validate().expect("max segment size is in range");
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Deterministic pseudo-random byte soup; the loader must always return a
        // Result (parse or validation error), never panic, never truncate.
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
