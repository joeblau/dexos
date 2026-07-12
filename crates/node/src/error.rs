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

    /// A shutdown flush hook failed while shutdown was already failing for
    /// another reason. Both failures are preserved: the primary error is the
    /// source and the flush detail is appended, mirroring how multiple hook
    /// failures within one flush phase are joined.
    #[error("{primary}; shutdown flush also failed: {flush_detail}")]
    FlushDuringFailedShutdown {
        /// The failure that made shutdown fail first.
        #[source]
        primary: Box<NodeError>,
        /// Aggregated detail from the flush hook failure(s).
        flush_detail: String,
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

impl NodeError {
    /// Attach a later shutdown-flush failure to this (earlier, primary) error
    /// so neither is dropped. Two flush failures merge into one aggregated
    /// [`NodeError::Flush`] — mirroring how `FlushHooks` joins hook failures
    /// within a phase — while any other primary keeps its type and carries the
    /// flush detail alongside as [`NodeError::FlushDuringFailedShutdown`].
    pub(crate) fn with_flush_failure(self, flush: NodeError) -> Self {
        let flush_detail = match flush {
            NodeError::Flush { detail } => detail,
            other => other.to_string(),
        };
        match self {
            NodeError::Flush { detail } => NodeError::Flush {
                detail: format!("{detail}; {flush_detail}"),
            },
            NodeError::FlushDuringFailedShutdown {
                primary,
                flush_detail: existing,
            } => NodeError::FlushDuringFailedShutdown {
                primary,
                flush_detail: format!("{existing}; {flush_detail}"),
            },
            primary => NodeError::FlushDuringFailedShutdown {
                primary: Box::new(primary),
                flush_detail,
            },
        }
    }
}
