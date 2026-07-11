//! Typed error taxonomy for the `markets` crate.
//!
//! Every fallible operation returns one of these; nothing panics on adversarial
//! input. Errors are `Copy`-cheap enums that carry just enough context to be
//! actionable, and the aggregate [`MarketError`] composes the module errors so a
//! command handler can surface a single type.

use types::{ArithError, MarketLifecycle, PayoutVectorError};

/// An illegal or malformed market-lifecycle state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleError {
    /// The `(from, to)` edge is not part of the legal transition graph.
    #[error("illegal lifecycle transition from {from:?} to {to:?}")]
    IllegalTransition {
        /// Current state.
        from: MarketLifecycle,
        /// Attempted next state.
        to: MarketLifecycle,
    },
}

/// A sponsorship / stake-accounting failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SponsorError {
    /// A sponsor with this id is already in the set.
    #[error("sponsor already present")]
    DuplicateSponsor,
    /// No sponsor with this id is in the set.
    #[error("unknown sponsor")]
    UnknownSponsor,
    /// The revenue-share basis points would exceed 10_000 (100%).
    #[error("aggregate revenue share exceeds 10000 bps")]
    RevenueShareExceeded,
    /// Removing/slashing would drop aggregate stake below the requirement.
    #[error("operation would breach stake requirement")]
    StakeRequirementBreach,
    /// The caller is not the current owner of the sponsor set.
    #[error("caller is not the sponsor-set owner")]
    NotOwner,
    /// The sponsor set must retain at least one sponsor.
    #[error("sponsor set may not be emptied")]
    WouldEmptySet,
    /// The failure kind is not objectively measurable, so slashing is refused.
    #[error("fault kind is not objectively slashable")]
    NonSlashableFault,
    /// A fixed-point arithmetic failure.
    #[error("arithmetic error: {0}")]
    Arith(#[from] ArithError),
}

/// A payout / complete-set accounting failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayoutError {
    /// A payout vector's outcome count did not match the market.
    #[error("payout vector outcome count mismatch")]
    OutcomeMismatch,
    /// A redeem asked for more complete sets than are outstanding.
    #[error("insufficient outstanding claims to redeem")]
    InsufficientClaims,
    /// A redeem asked for more collateral than is locked.
    #[error("insufficient locked collateral")]
    InsufficientCollateral,
    /// A non-positive unit count was supplied to mint/redeem.
    #[error("unit count must be positive")]
    NonPositiveUnits,
    /// The rule cannot enumerate a fixed number of outcomes (e.g. custom).
    #[error("payout rule has no enumerable outcome vector")]
    NonEnumerable,
    /// Underlying payout-vector construction error.
    #[error("payout vector error: {0}")]
    Vector(#[from] PayoutVectorError),
    /// A fixed-point arithmetic failure.
    #[error("arithmetic error: {0}")]
    Arith(#[from] ArithError),
}

/// A perpetual funding / mark / settlement failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PerpError {
    /// The price oracle is halted; no deterministic mark can be produced.
    #[error("price oracle halted")]
    OracleHalted,
    /// A fixed-point arithmetic failure (overflow/out-of-range).
    #[error("arithmetic error: {0}")]
    Arith(#[from] ArithError),
}

/// A resolution / dispute-framework failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolutionError {
    /// The certificate names a different market than the one being resolved.
    #[error("resolution certificate market id mismatch")]
    MarketIdMismatch,
    /// The certified payout vector's length disagrees with the market outcomes.
    #[error("resolution payout vector length mismatch")]
    PayoutLengthMismatch,
    /// The quorum's signed message does not bind the certified outcome/evidence.
    #[error("resolution message does not bind the certified outcome")]
    ForgedMessage,
    /// The committee quorum certificate failed verification.
    #[error("resolution quorum verification failed")]
    Quorum(#[from] crypto::QuorumError),
    /// The challenge window is still open, so the resolution is not final.
    #[error("challenge window still open")]
    WindowOpen,
    /// The bounded challenge queue is full.
    #[error("challenge queue is full")]
    ChallengeQueueFull,
    /// This evidence record has already been applied (replay / double-slash).
    #[error("duplicate evidence record")]
    DuplicateEvidence,
    /// Underlying payout-vector construction error.
    #[error("payout vector error: {0}")]
    Vector(#[from] PayoutVectorError),
}

/// Aggregate registry / command-handler error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MarketError {
    /// A market with this id already exists.
    #[error("duplicate market id")]
    DuplicateMarket,
    /// No market with this id exists.
    #[error("unknown market id")]
    UnknownMarket,
    /// A parameter update was out of the permitted range or state.
    #[error("parameter update out of range")]
    ParameterOutOfRange,
    /// The command is not permitted in the market's current lifecycle state.
    #[error("command not permitted in current lifecycle state")]
    WrongLifecycleState,
    /// A lifecycle transition error.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    /// A sponsorship error.
    #[error(transparent)]
    Sponsor(#[from] SponsorError),
    /// A payout / complete-set error.
    #[error(transparent)]
    Payout(#[from] PayoutError),
    /// A perpetual error.
    #[error(transparent)]
    Perp(#[from] PerpError),
    /// A resolution error.
    #[error(transparent)]
    Resolution(#[from] ResolutionError),
    /// A fixed-point arithmetic failure.
    #[error("arithmetic error: {0}")]
    Arith(#[from] ArithError),
}
