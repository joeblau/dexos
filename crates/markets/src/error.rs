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
    /// A dead-heat winner list named the same outcome more than once.
    #[error("duplicate winner in dead-heat set")]
    DuplicateWinner,
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

/// An escrow-ledger failure: the canonical ledger refused an economic move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EscrowError {
    /// The funding (or refund) account has never been funded.
    #[error("unknown ledger account")]
    UnknownAccount,
    /// The funding account cannot cover the requested lock.
    #[error("insufficient available balance: required {required}, available {available}")]
    InsufficientAvailable {
        /// Amount the operation required.
        required: i128,
        /// Amount the account actually held.
        available: i128,
    },
    /// Less value is escrowed than the release / slash asked to move.
    #[error("insufficient escrowed balance")]
    InsufficientEscrow,
    /// A negative amount was supplied to a ledger operation.
    #[error("amount must be non-negative")]
    NegativeAmount,
    /// A market definition tried to inject caller-constructed funded state.
    #[error("market definition carries pre-funded sponsor stake")]
    PrefundedStake,
    /// A committed total failed to reconcile against escrow.
    #[error("registry total does not reconcile to ledger escrow")]
    Reconciliation,
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
    /// Funding epoch was already applied or is not the next sequential epoch.
    #[error("funding epoch not sequential: last {last}, got {got}")]
    DuplicateEpoch {
        /// Last applied epoch (0 = none).
        last: u64,
        /// Epoch presented.
        got: u64,
    },
    /// Fee basis points outside the permitted range.
    #[error("fee bps out of range")]
    FeeOutOfRange,
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
    /// The certificate names a policy commitment other than the market's
    /// committed one (a noncommitted committee, rule, deployment, or version).
    #[error("resolution certificate does not match the committed policy")]
    PolicyMismatch,
    /// The certificate names a round the committed policy does not govern.
    #[error("resolution certificate round mismatch")]
    RoundMismatch,
    /// The certificate authorizes a different transition than the one attempted.
    #[error("resolution certificate phase mismatch")]
    PhaseMismatch,
    /// The market has no committed resolution policy to verify against.
    #[error("market has no committed resolution policy")]
    PolicyNotCommitted,
    /// A resolution policy is already committed for this market.
    #[error("resolution policy already committed")]
    PolicyAlreadyCommitted,
    /// The committed policy has expired and may no longer propose a resolution.
    #[error("resolution policy expired")]
    PolicyExpired,
    /// The proposed challenge deadline is shorter than the committed window.
    #[error("challenge deadline shorter than the committed window")]
    WindowTooShort,
    /// The challenge window has already closed; challenges are no longer accepted.
    #[error("challenge window already closed")]
    WindowClosed,
    /// A resolution has already been proposed for the current round.
    #[error("resolution already proposed for this round")]
    ProposalExists,
    /// No resolution has been proposed yet for the current round.
    #[error("no resolution proposed for this round")]
    NoProposal,
    /// A challenged round cannot be finalized until it is adjudicated.
    #[error("challenged resolution not yet adjudicated")]
    UnresolvedChallenge,
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
    /// Resume rejected: stake, bootstrap liquidity, or oracle health unmet.
    #[error("resume prerequisites not met")]
    ResumePrerequisites,
    /// Archive rejected: outstanding orders, claims, escrow, or disputes remain.
    #[error("archive blocked by outstanding liabilities")]
    ArchiveLiabilities,
    /// Oracle is not healthy enough to open or resume new risk.
    #[error("oracle unhealthy for trading")]
    OracleUnhealthy,
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
    /// An escrow-ledger error.
    #[error(transparent)]
    Escrow(#[from] EscrowError),
    /// A fixed-point arithmetic failure.
    #[error("arithmetic error: {0}")]
    Arith(#[from] ArithError),
}
