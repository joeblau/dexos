//! Shared domain enums, payout vectors, and 32-byte hash/state-root values.

use serde::{Deserialize, Serialize};

use crate::fixed::{Amount, AMOUNT_SCALE};

/// Maximum outcomes in a single market's payout vector. Bounds allocation and
/// worst-case risk scans.
pub const MAX_OUTCOMES: usize = 256;

/// The kind of market, determining payout and risk semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketType {
    /// Perpetual future.
    Perpetual,
    /// Binary (two mutually-exclusive outcomes) prediction market.
    BinaryPrediction,
    /// Multi-outcome prediction market.
    MultiOutcomePrediction,
    /// Action-contingent decision market.
    Decision,
    /// Sports / event market.
    Sports,
    /// Scalar (range) market.
    Scalar,
    /// Custom payout-vector market.
    CustomPayoutVector,
}

/// Generic market lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketLifecycle {
    /// Created but not staked.
    Draft,
    /// Sponsor stake posted.
    Staked,
    /// Bootstrapping liquidity.
    Bootstrapping,
    /// Open for trading.
    Open,
    /// Trading halted.
    Halted,
    /// Closed for trading, awaiting resolution.
    Closed,
    /// Awaiting resolution.
    PendingResolution,
    /// Resolution disputed.
    Disputed,
    /// Resolved.
    Resolved,
    /// Resolved invalid.
    Invalid,
    /// Settled.
    Settled,
    /// Archived.
    Archived,
}

/// Order book side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// Buy side (bid).
    Bid,
    /// Sell side (ask).
    Ask,
}

impl Side {
    /// The opposing side.
    #[inline]
    pub const fn opposite(self) -> Side {
        match self {
            Side::Bid => Side::Ask,
            Side::Ask => Side::Bid,
        }
    }
}

/// Order execution style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderType {
    /// Rest at a limit price.
    Limit,
    /// Execute against the book at any price.
    Market,
    /// Only add liquidity; reject if it would cross.
    PostOnly,
    /// Only reduce an existing position.
    ReduceOnly,
}

/// Time-in-force policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeInForce {
    /// Good-till-cancel.
    Gtc,
    /// Immediate-or-cancel.
    Ioc,
    /// Fill-or-kill.
    Fok,
}

/// Deterministic oracle health state; market behavior changes on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleHealth {
    /// Fresh, sufficient sources.
    Normal,
    /// Degraded but usable.
    Degraded,
    /// Stale beyond tolerance.
    Stale,
    /// Halted.
    Halted,
}

/// Canonical settlement-index convention for a two-outcome scalar (range) market.
///
/// Every crate that builds or consumes a scalar payout vector places the LONG
/// outcome at index 0 and the SHORT outcome at index 1, so the vectors agree by
/// *named* outcome across crate boundaries rather than by an ad-hoc positional
/// convention. Indexing through [`Self::index`] keeps the ordering a single
/// source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarOutcome {
    /// The long side: pays `(value - lower) / (upper - lower)` of one unit.
    Long,
    /// The short side: pays the complement `1 - long`.
    Short,
}

impl ScalarOutcome {
    /// The canonical settlement index of this outcome (LONG = 0, SHORT = 1).
    #[inline]
    pub const fn index(self) -> usize {
        match self {
            ScalarOutcome::Long => 0,
            ScalarOutcome::Short => 1,
        }
    }
}

/// A payout vector: the settlement value of one claim under each possible outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutVector {
    values: Vec<Amount>,
}

/// Payout-vector construction / validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayoutVectorError {
    /// Zero outcomes supplied.
    #[error("payout vector must have at least one outcome")]
    Empty,
    /// More than [`MAX_OUTCOMES`] outcomes supplied.
    #[error("payout vector exceeds the maximum of {MAX_OUTCOMES} outcomes")]
    TooManyOutcomes,
    /// A settlement entry was negative; payouts must be non-negative.
    #[error("payout vector has a negative entry")]
    NegativeEntry,
    /// Every entry was zero, so no collateral would be distributed.
    #[error("payout vector entries sum to zero")]
    ZeroSum,
    /// Entries summed to more than one unit (over-allocation of collateral).
    #[error("payout vector entries sum to more than one unit")]
    OverAllocated,
    /// Entries summed to a positive value below one unit (collateral unassigned).
    #[error("payout vector entries sum to less than one unit")]
    Underfunded,
    /// Summing the entries overflowed the accumulator.
    #[error("payout vector sum overflowed")]
    SumOverflow,
}

impl PayoutVector {
    /// Construct, rejecting empty or over-large vectors (no unbounded allocation).
    ///
    /// This does *not* enforce value conservation: risk-scenario code reuses this
    /// type for arbitrary per-outcome marks (negative, > one unit). Settlement and
    /// certificate paths must additionally call [`Self::validate_conserving`], or
    /// construct through [`Self::new_conserving`].
    pub fn new(values: Vec<Amount>) -> Result<Self, PayoutVectorError> {
        if values.is_empty() {
            return Err(PayoutVectorError::Empty);
        }
        if values.len() > MAX_OUTCOMES {
            return Err(PayoutVectorError::TooManyOutcomes);
        }
        Ok(Self { values })
    }

    /// Construct and require the canonical settlement invariant: non-negative
    /// entries summing to exactly one unit. See [`Self::validate_conserving`].
    ///
    /// # Errors
    /// Any [`PayoutVectorError`] from [`Self::new`] or [`Self::validate_conserving`].
    pub fn new_conserving(values: Vec<Amount>) -> Result<Self, PayoutVectorError> {
        let pv = Self::new(values)?;
        pv.validate_conserving()?;
        Ok(pv)
    }

    /// Validate the canonical settlement invariant: every entry is non-negative
    /// and the entries sum to *exactly* one unit (`Amount::ONE`).
    ///
    /// Enforcing an exact unit sum bounds the per-claim rounding dust of
    /// settlement to sub-unit magnitude and guarantees value conservation
    /// (`credited + dust == locked collateral`). Callers re-validate deserialized
    /// or externally-sourced vectors at every certificate and settlement
    /// boundary; the mutation-free check reports a typed error and never panics.
    ///
    /// # Errors
    /// [`PayoutVectorError::NegativeEntry`], [`PayoutVectorError::ZeroSum`],
    /// [`PayoutVectorError::OverAllocated`], [`PayoutVectorError::Underfunded`], or
    /// [`PayoutVectorError::SumOverflow`].
    pub fn validate_conserving(&self) -> Result<(), PayoutVectorError> {
        let mut total: i128 = 0;
        for v in &self.values {
            if v.raw() < 0 {
                return Err(PayoutVectorError::NegativeEntry);
            }
            total = total
                .checked_add(v.raw())
                .ok_or(PayoutVectorError::SumOverflow)?;
        }
        if total == AMOUNT_SCALE {
            Ok(())
        } else if total == 0 {
            Err(PayoutVectorError::ZeroSum)
        } else if total > AMOUNT_SCALE {
            Err(PayoutVectorError::OverAllocated)
        } else {
            Err(PayoutVectorError::Underfunded)
        }
    }

    /// The number of outcomes.
    #[inline]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the vector has no outcomes (never true for a constructed vector).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The payout values by outcome index.
    #[inline]
    pub fn values(&self) -> &[Amount] {
        &self.values
    }
}

/// A 32-byte domain hash, also used as a state root / commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash(pub [u8; 32]);

/// A state root is a [`Hash`](struct@Hash) over committed state.
pub type StateRoot = Hash;

impl Hash {
    /// The all-zero hash (empty / uninitialized commitment).
    pub const ZERO: Hash = Hash([0u8; 32]);

    /// Construct from raw bytes.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Hash {
        Hash(bytes)
    }

    /// The raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// True if this is the zero hash.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl Default for Hash {
    fn default() -> Self {
        Hash::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payout_vector_bounds() {
        assert_eq!(PayoutVector::new(vec![]), Err(PayoutVectorError::Empty));
        let too_many = vec![Amount::ZERO; MAX_OUTCOMES + 1];
        assert_eq!(
            PayoutVector::new(too_many),
            Err(PayoutVectorError::TooManyOutcomes)
        );
        let ok = PayoutVector::new(vec![Amount::ONE, Amount::ZERO]).unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(ok.values()[0], Amount::ONE);
    }

    #[test]
    fn validate_conserving_accepts_unit_sum_and_rejects_the_rest() {
        // Exactly one unit: conserving.
        let ok =
            PayoutVector::new(vec![Amount::from_raw(400_000), Amount::from_raw(600_000)]).unwrap();
        assert_eq!(ok.validate_conserving(), Ok(()));
        // Winner-takes-all is conserving.
        assert_eq!(
            PayoutVector::new(vec![Amount::ONE, Amount::ZERO])
                .unwrap()
                .validate_conserving(),
            Ok(())
        );
        // Negative entry is rejected even when the total would still be one unit.
        assert_eq!(
            PayoutVector::new(vec![Amount::from_raw(-1), Amount::from_raw(1_000_001)])
                .unwrap()
                .validate_conserving(),
            Err(PayoutVectorError::NegativeEntry)
        );
        // Zero-sum.
        assert_eq!(
            PayoutVector::new(vec![Amount::ZERO, Amount::ZERO])
                .unwrap()
                .validate_conserving(),
            Err(PayoutVectorError::ZeroSum)
        );
        // Over-allocated (sum > one unit).
        assert_eq!(
            PayoutVector::new(vec![Amount::ONE, Amount::ONE])
                .unwrap()
                .validate_conserving(),
            Err(PayoutVectorError::OverAllocated)
        );
        // Underfunded (0 < sum < one unit).
        assert_eq!(
            PayoutVector::new(vec![Amount::from_raw(100), Amount::ZERO])
                .unwrap()
                .validate_conserving(),
            Err(PayoutVectorError::Underfunded)
        );
        // Summation overflow returns a typed error, never a panic.
        assert_eq!(
            PayoutVector::new(vec![Amount::MAX, Amount::MAX])
                .unwrap()
                .validate_conserving(),
            Err(PayoutVectorError::SumOverflow)
        );
    }

    #[test]
    fn new_conserving_mirrors_validate_conserving() {
        assert!(PayoutVector::new_conserving(vec![Amount::ONE, Amount::ZERO]).is_ok());
        assert_eq!(
            PayoutVector::new_conserving(vec![Amount::ONE, Amount::ONE]),
            Err(PayoutVectorError::OverAllocated)
        );
        // Empty still fails at the length gate before any sum check.
        assert_eq!(
            PayoutVector::new_conserving(vec![]),
            Err(PayoutVectorError::Empty)
        );
    }

    #[test]
    fn scalar_outcome_index_is_canonical() {
        assert_eq!(ScalarOutcome::Long.index(), 0);
        assert_eq!(ScalarOutcome::Short.index(), 1);
        assert_ne!(ScalarOutcome::Long, ScalarOutcome::Short);
    }

    #[test]
    fn hash_zero_equality_ordering_roundtrip() {
        assert!(Hash::ZERO.is_zero());
        assert_eq!(Hash::default(), Hash::ZERO);
        let a = Hash::from_bytes([1u8; 32]);
        let b = Hash::from_bytes([2u8; 32]);
        assert!(a < b);
        assert_eq!(a.as_bytes(), &[1u8; 32]);
        assert_ne!(a, Hash::ZERO);
    }

    #[test]
    fn side_opposite_is_involutive() {
        assert_eq!(Side::Bid.opposite(), Side::Ask);
        assert_eq!(Side::Ask.opposite().opposite(), Side::Ask);
    }
}
