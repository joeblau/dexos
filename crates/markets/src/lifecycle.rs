//! The generic market lifecycle state machine.
//!
//! States are [`types::MarketLifecycle`]; this module owns the *legal transition
//! graph* and the validated [`advance`] operation. The graph is total: for any
//! `(from, to)` pair the machine returns either the new state or a typed
//! [`LifecycleError`], never a panic.
//!
//! ```text
//! Draft ─▶ Staked ─▶ Bootstrapping ─▶ Open ─▶ Closed ─▶ PendingResolution
//!                          │            ▲ │                   │  │
//!                          ▼            │ ▼                   ▼  ▼
//!                        Halted ◀───────┘ Halted          Disputed  Resolved/Invalid
//!                          │                                  │        │
//!                          ▼                                  ▼        ▼
//!                       Archived                       Resolved/Invalid ─▶ Settled ─▶ Archived
//! ```

use types::MarketLifecycle;

use crate::error::LifecycleError;

/// Every lifecycle state, in canonical order. Used by exhaustive tests and by
/// reachability analysis.
pub const ALL_LIFECYCLE_STATES: [MarketLifecycle; 12] = [
    MarketLifecycle::Draft,
    MarketLifecycle::Staked,
    MarketLifecycle::Bootstrapping,
    MarketLifecycle::Open,
    MarketLifecycle::Halted,
    MarketLifecycle::Closed,
    MarketLifecycle::PendingResolution,
    MarketLifecycle::Disputed,
    MarketLifecycle::Resolved,
    MarketLifecycle::Invalid,
    MarketLifecycle::Settled,
    MarketLifecycle::Archived,
];

/// True if `from -> to` is a legal edge in the lifecycle graph.
///
/// This is the single source of truth for the transition matrix; [`advance`]
/// and every command handler defer to it.
#[must_use]
pub fn is_legal_transition(from: MarketLifecycle, to: MarketLifecycle) -> bool {
    use MarketLifecycle::{
        Archived, Bootstrapping, Closed, Disputed, Draft, Halted, Invalid, Open, PendingResolution,
        Resolved, Settled, Staked,
    };
    matches!(
        (from, to),
        (Draft, Staked)
            | (Staked, Bootstrapping)
            | (Bootstrapping, Open)
            | (Bootstrapping, Halted)
            | (Open, Halted)
            | (Open, Closed)
            | (Halted, Open)
            | (Halted, Closed)
            | (Halted, Archived)
            | (Closed, PendingResolution)
            | (PendingResolution, Disputed)
            | (PendingResolution, Resolved)
            | (PendingResolution, Invalid)
            | (Disputed, Resolved)
            | (Disputed, Invalid)
            | (Resolved, Settled)
            | (Invalid, Settled)
            | (Settled, Archived)
    )
}

/// Validate and perform a transition, returning the new state.
///
/// # Errors
/// [`LifecycleError::IllegalTransition`] if `from -> to` is not a legal edge.
pub fn advance(
    from: MarketLifecycle,
    to: MarketLifecycle,
) -> Result<MarketLifecycle, LifecycleError> {
    if is_legal_transition(from, to) {
        Ok(to)
    } else {
        Err(LifecycleError::IllegalTransition { from, to })
    }
}

/// True once the market is in a terminal state (no outgoing edges except from
/// `Settled -> Archived`, and `Archived` itself is fully terminal).
#[must_use]
pub fn is_terminal(state: MarketLifecycle) -> bool {
    matches!(state, MarketLifecycle::Archived)
}

/// True while the market accepts new matching (only `Open`).
#[must_use]
pub fn accepts_orders(state: MarketLifecycle) -> bool {
    matches!(state, MarketLifecycle::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact legal edge set, kept independent from `is_legal_transition` so
    /// the matrix test cannot pass by construction from the same table.
    const LEGAL_EDGES: &[(MarketLifecycle, MarketLifecycle)] = &[
        (MarketLifecycle::Draft, MarketLifecycle::Staked),
        (MarketLifecycle::Staked, MarketLifecycle::Bootstrapping),
        (MarketLifecycle::Bootstrapping, MarketLifecycle::Open),
        (MarketLifecycle::Bootstrapping, MarketLifecycle::Halted),
        (MarketLifecycle::Open, MarketLifecycle::Halted),
        (MarketLifecycle::Open, MarketLifecycle::Closed),
        (MarketLifecycle::Halted, MarketLifecycle::Open),
        (MarketLifecycle::Halted, MarketLifecycle::Closed),
        (MarketLifecycle::Halted, MarketLifecycle::Archived),
        (MarketLifecycle::Closed, MarketLifecycle::PendingResolution),
        (
            MarketLifecycle::PendingResolution,
            MarketLifecycle::Disputed,
        ),
        (
            MarketLifecycle::PendingResolution,
            MarketLifecycle::Resolved,
        ),
        (MarketLifecycle::PendingResolution, MarketLifecycle::Invalid),
        (MarketLifecycle::Disputed, MarketLifecycle::Resolved),
        (MarketLifecycle::Disputed, MarketLifecycle::Invalid),
        (MarketLifecycle::Resolved, MarketLifecycle::Settled),
        (MarketLifecycle::Invalid, MarketLifecycle::Settled),
        (MarketLifecycle::Settled, MarketLifecycle::Archived),
    ];

    #[test]
    fn full_matrix_exactly_the_legal_edges_succeed() {
        for &from in &ALL_LIFECYCLE_STATES {
            for &to in &ALL_LIFECYCLE_STATES {
                let expected = LEGAL_EDGES.contains(&(from, to));
                assert_eq!(
                    is_legal_transition(from, to),
                    expected,
                    "edge {from:?}->{to:?}"
                );
                match advance(from, to) {
                    Ok(next) => {
                        assert!(expected);
                        assert_eq!(next, to);
                    }
                    Err(LifecycleError::IllegalTransition { from: f, to: t }) => {
                        assert!(!expected);
                        assert_eq!((f, t), (from, to));
                    }
                }
            }
        }
        // The graph has exactly 18 legal edges.
        let mut count = 0usize;
        for &from in &ALL_LIFECYCLE_STATES {
            for &to in &ALL_LIFECYCLE_STATES {
                if is_legal_transition(from, to) {
                    count += 1;
                }
            }
        }
        assert_eq!(count, LEGAL_EDGES.len());
    }

    #[test]
    fn all_states_reachable_from_draft() {
        // Breadth-first reachability over the legal graph.
        let mut seen = [false; 12];
        let mut stack = vec![MarketLifecycle::Draft];
        seen[0] = true;
        while let Some(state) = stack.pop() {
            for &to in &ALL_LIFECYCLE_STATES {
                if is_legal_transition(state, to) {
                    let idx = ALL_LIFECYCLE_STATES.iter().position(|&s| s == to).unwrap();
                    if !seen[idx] {
                        seen[idx] = true;
                        stack.push(to);
                    }
                }
            }
        }
        assert!(seen.iter().all(|&b| b), "some states unreachable: {seen:?}");
    }

    // Deterministic in-test LCG.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn state(&mut self) -> MarketLifecycle {
            let i = usize::try_from(self.next_u64() % 12).unwrap();
            ALL_LIFECYCLE_STATES[i]
        }
    }

    #[test]
    fn never_panics_on_arbitrary_state_pairs() {
        let mut r = Lcg(0xA11CE);
        for _ in 0..100_000 {
            let from = r.state();
            let to = r.state();
            // Both the predicate and the validated advance must be total.
            let legal = is_legal_transition(from, to);
            match advance(from, to) {
                Ok(_) => assert!(legal),
                Err(_) => assert!(!legal),
            }
        }
    }

    #[test]
    fn terminal_and_order_acceptance_flags() {
        assert!(is_terminal(MarketLifecycle::Archived));
        assert!(!is_terminal(MarketLifecycle::Settled));
        assert!(accepts_orders(MarketLifecycle::Open));
        assert!(!accepts_orders(MarketLifecycle::Halted));
        assert!(!accepts_orders(MarketLifecycle::Closed));
    }
}
