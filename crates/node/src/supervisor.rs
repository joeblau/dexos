//! Supervision of critical subsystem tasks.
//!
//! Each role handler is a long-lived critical task. An unexpected exit — panic,
//! error, or early return while the node still expects the task to run —
//! immediately marks readiness false and requests a coordinated shutdown. The
//! process then exits nonzero via [`NodeError`].

use crate::error::NodeError;

/// Why a supervised task ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskExitReason {
    /// Clean stop after the node-wide shutdown signal.
    CleanShutdown {
        /// Envelopes processed by the handler.
        processed: u64,
    },
    /// Task returned while the node was still running (bug or unrecoverable).
    Unexpected {
        /// Operator-visible detail.
        detail: String,
    },
    /// Task panicked.
    Panic {
        /// Panic payload, best-effort display.
        detail: String,
    },
}

impl TaskExitReason {
    /// True when this exit is an unrecoverable failure for a critical task.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        !matches!(self, TaskExitReason::CleanShutdown { .. })
    }
}

/// Notification that a supervised task terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEvent {
    /// Subsystem / role name.
    pub name: String,
    /// Terminal reason.
    pub reason: TaskExitReason,
}

/// Classify a handler completion observed during the run phase.
///
/// Before shutdown is requested, any completion is a failure for a critical
/// long-lived task. After shutdown, only panics/errors remain failures.
#[must_use]
pub fn classify_exit(shutting_down: bool, join_result: Result<u64, String>) -> TaskExitReason {
    match join_result {
        Ok(processed) if shutting_down => TaskExitReason::CleanShutdown { processed },
        Ok(_) => TaskExitReason::Unexpected {
            detail: "handler returned before shutdown".into(),
        },
        Err(detail) if detail.contains("panic") || detail.contains("panicked") => {
            TaskExitReason::Panic { detail }
        }
        Err(detail) => TaskExitReason::Unexpected { detail },
    }
}

/// Map a failure reason into a process-level error.
#[must_use]
pub fn failure_to_error(name: impl Into<String>, reason: &TaskExitReason) -> Option<NodeError> {
    if !reason.is_failure() {
        return None;
    }
    Some(NodeError::CriticalTask {
        role: name.into(),
        detail: format!("{reason:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness::Readiness;

    #[test]
    fn clean_shutdown_is_not_failure() {
        assert!(!TaskExitReason::CleanShutdown { processed: 1 }.is_failure());
        assert!(TaskExitReason::Unexpected { detail: "x".into() }.is_failure());
        assert!(TaskExitReason::Panic { detail: "p".into() }.is_failure());
    }

    #[test]
    fn early_exit_before_stop_is_failure() {
        let r = classify_exit(false, Ok(0));
        assert!(r.is_failure());
        let r = classify_exit(true, Ok(3));
        assert!(!r.is_failure());
    }

    #[test]
    fn panic_reason_marks_not_ready() {
        let readiness = Readiness::new();
        readiness.mark_ready();
        let reason = classify_exit(false, Err("task panicked at line 1".into()));
        assert!(matches!(reason, TaskExitReason::Panic { .. }));
        if let Some(err) = failure_to_error("boom", &reason) {
            readiness.mark_not_ready(err.to_string());
        }
        assert!(!readiness.is_ready());
        assert!(readiness.reason().contains("boom") || readiness.reason().contains("panic"));
    }
}
