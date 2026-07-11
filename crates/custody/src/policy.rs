//! Per-chain withdrawal policies: per-transaction caps, a cumulative pending
//! cap (the "window"), a minimum-finality-confirmations floor, and a count-based
//! rate limit. All accounting is fixed-point and checked; it never overflows and
//! never authorizes past the configured cap.

use types::Amount;

use crate::chain::ChainId;
use crate::error::CustodyError;
use crate::wire::{Reader, Writer};

/// A per-chain withdrawal policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPolicy {
    /// The chain this policy governs.
    pub chain: ChainId,
    /// Maximum amount allowed in a single withdrawal.
    pub max_per_tx: Amount,
    /// Maximum cumulative pending (authorized-but-unsettled) amount.
    pub max_pending: Amount,
    /// Minimum on-chain confirmations required to authorize.
    pub min_confirmations: u32,
    /// Maximum number of concurrently pending withdrawals.
    pub rate_limit: u32,
}

impl ChainPolicy {
    /// Check a candidate withdrawal against this policy.
    ///
    /// `pending` and `pending_count` are the current cumulative state for the
    /// chain. Returns [`CustodyError::PolicyViolation`] on any breach and
    /// [`CustodyError::Overflow`] only if the accounting itself would wrap
    /// (which is therefore rejected, never silently authorized).
    pub fn check(
        &self,
        amount: Amount,
        confirmations: u32,
        pending: Amount,
        pending_count: u32,
    ) -> Result<(), CustodyError> {
        if amount < Amount::ZERO {
            return Err(CustodyError::PolicyViolation);
        }
        if amount > self.max_per_tx {
            return Err(CustodyError::PolicyViolation);
        }
        if confirmations < self.min_confirmations {
            return Err(CustodyError::PolicyViolation);
        }
        let new_pending = pending.checked_add(amount)?;
        if new_pending > self.max_pending {
            return Err(CustodyError::PolicyViolation);
        }
        let new_count = pending_count.checked_add(1).ok_or(CustodyError::Overflow)?;
        if new_count > self.rate_limit {
            return Err(CustodyError::PolicyViolation);
        }
        Ok(())
    }

    /// Encode the policy for transport / fuzzing.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.chain.get());
        w.i128(self.max_per_tx.raw());
        w.i128(self.max_pending.raw());
        w.u32(self.min_confirmations);
        w.u32(self.rate_limit);
        w.into_vec()
    }

    /// Decode a policy from bytes. Total: arbitrary input yields `Err`.
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        let mut r = Reader::new(bytes);
        let chain = ChainId(r.u64()?);
        let max_per_tx = Amount::from_raw(r.i128()?);
        let max_pending = Amount::from_raw(r.i128()?);
        let min_confirmations = r.u32()?;
        let rate_limit = r.u32()?;
        r.finish()?;
        Ok(Self {
            chain,
            max_per_tx,
            max_pending,
            min_confirmations,
            rate_limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ChainPolicy {
        ChainPolicy {
            chain: ChainId(1),
            max_per_tx: Amount::from_raw(100),
            max_pending: Amount::from_raw(250),
            min_confirmations: 6,
            rate_limit: 3,
        }
    }

    #[test]
    fn compliant_withdrawal_passes() {
        assert!(policy()
            .check(Amount::from_raw(100), 6, Amount::from_raw(100), 1)
            .is_ok());
    }

    #[test]
    fn each_limit_rejected() {
        let p = policy();
        // over per-tx
        assert_eq!(
            p.check(Amount::from_raw(101), 6, Amount::ZERO, 0),
            Err(CustodyError::PolicyViolation)
        );
        // under confirmations
        assert_eq!(
            p.check(Amount::from_raw(50), 5, Amount::ZERO, 0),
            Err(CustodyError::PolicyViolation)
        );
        // over pending cap
        assert_eq!(
            p.check(Amount::from_raw(100), 6, Amount::from_raw(200), 1),
            Err(CustodyError::PolicyViolation)
        );
        // over rate limit
        assert_eq!(
            p.check(Amount::from_raw(1), 6, Amount::ZERO, 3),
            Err(CustodyError::PolicyViolation)
        );
        // negative amount
        assert_eq!(
            p.check(Amount::from_raw(-1), 6, Amount::ZERO, 0),
            Err(CustodyError::PolicyViolation)
        );
    }

    #[test]
    fn pending_accounting_never_overflows() {
        let p = ChainPolicy {
            chain: ChainId(1),
            max_per_tx: Amount::MAX,
            max_pending: Amount::MAX,
            min_confirmations: 0,
            rate_limit: u32::MAX,
        };
        // Adding to a near-MAX pending would wrap -> rejected as Overflow.
        assert_eq!(
            p.check(
                Amount::from_raw(10),
                0,
                Amount::from_raw(Amount::MAX.raw() - 1),
                0
            ),
            Err(CustodyError::Overflow)
        );
    }

    #[test]
    fn decode_never_panics() {
        let mut state = 7u64;
        for _ in 0..10_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = usize::try_from(state % 48).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    state.to_le_bytes()[0]
                })
                .collect();
            let _ = ChainPolicy::decode(&bytes);
        }
        // round trip
        let p = policy();
        assert_eq!(ChainPolicy::decode(&p.encode()).unwrap(), p);
    }
}
