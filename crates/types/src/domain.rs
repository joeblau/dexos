//! Shared domain enums, payout vectors, and 32-byte hash/state-root values.

use serde::{Deserialize, Serialize};

use crate::fixed::Amount;

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

/// A payout vector: the settlement value of one claim under each possible outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutVector {
    values: Vec<Amount>,
}

/// Payout-vector construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayoutVectorError {
    /// Zero outcomes supplied.
    #[error("payout vector must have at least one outcome")]
    Empty,
    /// More than [`MAX_OUTCOMES`] outcomes supplied.
    #[error("payout vector exceeds the maximum of {MAX_OUTCOMES} outcomes")]
    TooManyOutcomes,
}

impl PayoutVector {
    /// Construct, rejecting empty or over-large vectors (no unbounded allocation).
    pub fn new(values: Vec<Amount>) -> Result<Self, PayoutVectorError> {
        if values.is_empty() {
            return Err(PayoutVectorError::Empty);
        }
        if values.len() > MAX_OUTCOMES {
            return Err(PayoutVectorError::TooManyOutcomes);
        }
        Ok(Self { values })
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

/// A state root is a [`Hash`] over committed state.
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
