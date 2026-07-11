//! Guarded market lifecycle state machine.
//!
//! The transition function is *total*: every `(state, event)` pair returns a
//! value (a new state or a typed error) and never panics. This underpins the
//! deterministic-replay requirement — replaying the same event stream always
//! yields the same terminal state.

use serde::{Deserialize, Serialize};
use types::MarketLifecycle;

/// An event that may drive a lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEvent {
    /// Sponsor posts stake (`Draft -> Staked`).
    Stake,
    /// Begin liquidity bootstrapping (`Staked -> Bootstrapping`).
    Bootstrap,
    /// Open for trading (`Staked | Bootstrapping -> Open`).
    Open,
    /// Halt trading (`Open -> Halted`).
    Halt,
    /// Resume trading (`Halted -> Open`).
    Resume,
    /// Close trading, awaiting resolution (`Open | Halted -> Closed`).
    Close,
    /// Move into resolution (`Closed -> PendingResolution`).
    BeginResolution,
    /// Raise a dispute (`PendingResolution -> Disputed`).
    Dispute,
    /// Resolve to a winning outcome / payout vector
    /// (`PendingResolution | Disputed -> Resolved`).
    Resolve,
    /// Resolve as invalid (`PendingResolution | Disputed -> Invalid`).
    Invalidate,
    /// Settle holder positions (`Resolved | Invalid -> Settled`).
    Settle,
    /// Archive a settled market (`Settled -> Archived`).
    Archive,
}

/// A rejected lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("illegal lifecycle transition: {event:?} is not valid from {from:?}")]
pub struct LifecycleError {
    /// The state the market was in.
    pub from: MarketLifecycle,
    /// The event that was rejected.
    pub event: LifecycleEvent,
}

/// Apply `event` to `state`, returning the next state or a [`LifecycleError`].
///
/// Total and panic-free for every input pair.
pub fn transition(
    state: MarketLifecycle,
    event: LifecycleEvent,
) -> Result<MarketLifecycle, LifecycleError> {
    use LifecycleEvent as E;
    use MarketLifecycle as S;
    let next = match (state, event) {
        (S::Draft, E::Stake) => S::Staked,
        (S::Staked, E::Bootstrap) => S::Bootstrapping,
        (S::Staked, E::Open) => S::Open,
        (S::Bootstrapping, E::Open) => S::Open,
        (S::Open, E::Halt) => S::Halted,
        (S::Halted, E::Resume) => S::Open,
        (S::Open, E::Close) => S::Closed,
        (S::Halted, E::Close) => S::Closed,
        (S::Closed, E::BeginResolution) => S::PendingResolution,
        (S::PendingResolution, E::Dispute) => S::Disputed,
        (S::PendingResolution, E::Resolve) => S::Resolved,
        (S::PendingResolution, E::Invalidate) => S::Invalid,
        (S::Disputed, E::Resolve) => S::Resolved,
        (S::Disputed, E::Invalidate) => S::Invalid,
        (S::Resolved, E::Settle) => S::Settled,
        (S::Invalid, E::Settle) => S::Settled,
        (S::Settled, E::Archive) => S::Archived,
        _ => return Err(LifecycleError { from: state, event }),
    };
    Ok(next)
}

/// Fold an event script from `start`, stopping at the first illegal transition.
///
/// Deterministic: identical inputs always produce identical terminal state.
pub fn replay(
    start: MarketLifecycle,
    events: &[LifecycleEvent],
) -> Result<MarketLifecycle, LifecycleError> {
    let mut state = start;
    for e in events {
        state = transition(state, *e)?;
    }
    Ok(state)
}

/// Whether new order entry is permitted. True only in [`MarketLifecycle::Open`].
#[inline]
pub fn is_order_entry_allowed(state: MarketLifecycle) -> bool {
    matches!(state, MarketLifecycle::Open)
}

/// Whether settlement is permitted. True only for a resolved or invalid market.
#[inline]
pub fn is_settlement_allowed(state: MarketLifecycle) -> bool {
    matches!(state, MarketLifecycle::Resolved | MarketLifecycle::Invalid)
}
