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

    /// Graceful drain did not finish before the configured deadline.
    #[error(
        "drain timed out with {outstanding} subsystem task(s) still running \
         (deadline {deadline_ms} ms)"
    )]
    DrainTimeout {
        /// Tasks that had not finished when the deadline elapsed.
        outstanding: usize,
        /// Configured deadline in milliseconds.
        deadline_ms: u64,
    },

    /// One or more shutdown flush hooks failed (journal, RPC, network, …).
    #[error("shutdown flush failed: {detail}")]
    Flush {
        /// Combined failure detail.
        detail: String,
    },

    /// A critical supervised task exited unexpectedly.
    #[error("critical task '{role}' failed: {detail}")]
    CriticalTask {
        /// Task / role name.
        role: String,
        /// Failure detail.
        detail: String,
    },

    /// `pin_threads=true` but the host cannot apply affinity.
    #[error("thread pinning failed: {detail}")]
    PinningUnsupported {
        /// Operator-visible detail.
        detail: String,
    },
}
