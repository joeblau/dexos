//! Node-level error types.

use std::io;

/// Errors raised while constructing or running a [`crate::Node`].
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// A configuration value was invalid or self-contradictory.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),

    /// The async runtime could not be constructed.
    #[error("failed to build async runtime: {0}")]
    Runtime(#[source] io::Error),

    /// A subsystem task panicked or was cancelled.
    #[error("subsystem task '{role}' failed to join: {source}")]
    Join {
        /// The role whose handler failed.
        role: String,
        /// The underlying join error.
        #[source]
        source: tokio::task::JoinError,
    },
}
