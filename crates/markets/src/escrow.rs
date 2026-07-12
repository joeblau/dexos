//! The canonical market escrow ledger: the single source of truth for every
//! unit of value the market operating system controls.
//!
//! Value never appears from a caller-constructed field. It enters the ledger
//! only through [`EscrowLedger::deposit`] and leaves only through
//! [`EscrowLedger::withdraw`]. Every economic market operation debits a funding
//! account's *available* balance and credits a *typed escrow subaccount*:
//! sponsor stake, bootstrap liquidity, complete-set collateral, the insurance
//! backstop, the settlement-payable protocol account, or the rounding-dust
//! account.
//!
//! # Conservation
//! After every operation the global invariant
//! `total_supply == Σ available + Σ sponsor_stake + Σ bootstrap +
//! Σ complete_set + insurance + protocol + dust`
//! holds ([`EscrowLedger::conservation_holds`]). `total_supply` moves only on
//! deposit (`+`) and finalized withdrawal (`−`); every other operation is a
//! value-preserving transfer between subaccounts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use types::{AccountId, Amount, MarketId, SponsorId};

use crate::error::EscrowError;

fn non_negative(amount: Amount) -> Result<(), EscrowError> {
    if amount.is_negative() {
        Err(EscrowError::NegativeAmount)
    } else {
        Ok(())
    }
}

/// The canonical escrow ledger backing the [`crate::MarketRegistry`].
///
/// Balances are held in deterministic [`BTreeMap`]s keyed by account, market, or
/// `(market, sponsor)` so serialization and the registry state root are
/// bit-identical across independent replays.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowLedger {
    /// Spendable balances by funding account.
    available: BTreeMap<AccountId, Amount>,
    /// Sponsor stake escrow, per `(market, sponsor)`.
    sponsor_stake: BTreeMap<(MarketId, SponsorId), Amount>,
    /// Bootstrap-liquidity escrow, per market.
    bootstrap: BTreeMap<MarketId, Amount>,
    /// Complete-set collateral escrow, per market.
    complete_set: BTreeMap<MarketId, Amount>,
    /// The global insurance backstop (fed by slashing).
    insurance: Amount,
    /// The global settlement-payable protocol account (fed by settlement).
    protocol: Amount,
    /// The global rounding-dust account (fed by settlement dust).
    dust: Amount,
    /// The sum of all subaccounts; changes only on deposit / withdrawal.
    total_supply: Amount,
}

impl EscrowLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ---- queries ----------------------------------------------------------

    /// Total value under the ledger's control.
    #[must_use]
    pub fn total_supply(&self) -> Amount {
        self.total_supply
    }

    /// The insurance backstop balance.
    #[must_use]
    pub fn insurance(&self) -> Amount {
        self.insurance
    }

    /// The settlement-payable protocol balance.
    #[must_use]
    pub fn protocol(&self) -> Amount {
        self.protocol
    }

    /// The accumulated settlement rounding-dust balance.
    #[must_use]
    pub fn dust(&self) -> Amount {
        self.dust
    }

    /// Available (spendable) balance of a funding account.
    ///
    /// # Errors
    /// [`EscrowError::UnknownAccount`] if the account was never funded.
    pub fn available(&self, account: AccountId) -> Result<Amount, EscrowError> {
        self.available
            .get(&account)
            .copied()
            .ok_or(EscrowError::UnknownAccount)
    }

    /// A single sponsor's escrowed stake in a market.
    #[must_use]
    pub fn sponsor_stake(&self, market: MarketId, sponsor: SponsorId) -> Amount {
        self.sponsor_stake
            .get(&(market, sponsor))
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    /// The aggregate escrowed sponsor stake of a market. Uses the same
    /// saturating fold as [`crate::SponsorSet::total_stake`] so the two are
    /// bit-comparable during reconciliation.
    #[must_use]
    pub fn sponsor_stake_total(&self, market: MarketId) -> Amount {
        self.sponsor_stake
            .iter()
            .filter(|((m, _), _)| *m == market)
            .fold(Amount::ZERO, |acc, (_, v)| acc.saturating_add(*v))
    }

    /// The escrowed bootstrap liquidity of a market.
    #[must_use]
    pub fn bootstrap(&self, market: MarketId) -> Amount {
        self.bootstrap.get(&market).copied().unwrap_or(Amount::ZERO)
    }

    /// The escrowed complete-set collateral of a market.
    #[must_use]
    pub fn complete_set(&self, market: MarketId) -> Amount {
        self.complete_set
            .get(&market)
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    // ---- funding (the only supply-changing operations) --------------------

    /// Credit a deposit into an account's available balance, lazily allocating
    /// the account. Increases total supply.
    ///
    /// # Errors
    /// [`EscrowError::NegativeAmount`] or [`EscrowError::Arith`] on overflow.
    pub fn deposit(&mut self, account: AccountId, amount: Amount) -> Result<(), EscrowError> {
        non_negative(amount)?;
        let slot = self.available.entry(account).or_insert(Amount::ZERO);
        *slot = slot.checked_add(amount)?;
        self.total_supply = self.total_supply.checked_add(amount)?;
        Ok(())
    }

    /// Debit a finalized withdrawal from an account's available balance,
    /// removing the value from the ledger. Decreases total supply.
    ///
    /// # Errors
    /// [`EscrowError::UnknownAccount`], [`EscrowError::InsufficientAvailable`],
    /// or an arithmetic failure.
    pub fn withdraw(&mut self, account: AccountId, amount: Amount) -> Result<(), EscrowError> {
        self.debit_available(account, amount)?;
        self.total_supply = self.total_supply.checked_sub(amount)?;
        Ok(())
    }

    // ---- internal balance moves (value preserving) ------------------------

    fn debit_available(&mut self, account: AccountId, amount: Amount) -> Result<(), EscrowError> {
        non_negative(amount)?;
        let bal = self
            .available
            .get_mut(&account)
            .ok_or(EscrowError::UnknownAccount)?;
        if *bal < amount {
            return Err(EscrowError::InsufficientAvailable {
                required: amount.raw(),
                available: bal.raw(),
            });
        }
        *bal = bal.checked_sub(amount)?;
        Ok(())
    }

    fn credit_available(&mut self, account: AccountId, amount: Amount) -> Result<(), EscrowError> {
        non_negative(amount)?;
        let slot = self.available.entry(account).or_insert(Amount::ZERO);
        *slot = slot.checked_add(amount)?;
        Ok(())
    }

    // ---- sponsor stake ----------------------------------------------------

    /// Lock `amount` of `funder`'s available balance into a sponsor's stake
    /// escrow. All checks run before any mutation, so a failure leaves the
    /// ledger untouched.
    ///
    /// # Errors
    /// [`EscrowError::UnknownAccount`], [`EscrowError::InsufficientAvailable`],
    /// or an arithmetic failure.
    pub fn lock_sponsor_stake(
        &mut self,
        market: MarketId,
        sponsor: SponsorId,
        funder: AccountId,
        amount: Amount,
    ) -> Result<(), EscrowError> {
        let next = self.plan_lock(funder, self.sponsor_stake(market, sponsor), amount)?;
        self.debit_available(funder, amount)?;
        self.sponsor_stake.insert((market, sponsor), next);
        Ok(())
    }

    /// Release `amount` of a sponsor's escrowed stake back to `to`'s available
    /// balance (sponsor removal / refund).
    ///
    /// # Errors
    /// [`EscrowError::InsufficientEscrow`] if less than `amount` is escrowed, or
    /// an arithmetic failure.
    pub fn release_sponsor_stake(
        &mut self,
        market: MarketId,
        sponsor: SponsorId,
        to: AccountId,
        amount: Amount,
    ) -> Result<(), EscrowError> {
        non_negative(amount)?;
        let cur = self.sponsor_stake(market, sponsor);
        if cur < amount {
            return Err(EscrowError::InsufficientEscrow);
        }
        let remaining = cur.checked_sub(amount)?;
        self.credit_available(to, amount)?;
        self.set_sponsor_stake(market, sponsor, remaining);
        Ok(())
    }

    /// Move `amount` of a sponsor's escrowed stake to the insurance backstop
    /// (slashing). No value is created; escrow decreases exactly as insurance
    /// increases.
    ///
    /// # Errors
    /// [`EscrowError::InsufficientEscrow`] or an arithmetic failure.
    pub fn slash_sponsor_stake(
        &mut self,
        market: MarketId,
        sponsor: SponsorId,
        amount: Amount,
    ) -> Result<(), EscrowError> {
        non_negative(amount)?;
        let cur = self.sponsor_stake(market, sponsor);
        if cur < amount {
            return Err(EscrowError::InsufficientEscrow);
        }
        let remaining = cur.checked_sub(amount)?;
        let insurance = self.insurance.checked_add(amount)?;
        self.insurance = insurance;
        self.set_sponsor_stake(market, sponsor, remaining);
        Ok(())
    }

    fn set_sponsor_stake(&mut self, market: MarketId, sponsor: SponsorId, value: Amount) {
        if value == Amount::ZERO {
            self.sponsor_stake.remove(&(market, sponsor));
        } else {
            self.sponsor_stake.insert((market, sponsor), value);
        }
    }

    // ---- bootstrap liquidity ----------------------------------------------

    /// Lock `amount` of `funder`'s available balance into a market's bootstrap
    /// escrow.
    ///
    /// # Errors
    /// As [`EscrowLedger::lock_sponsor_stake`].
    pub fn lock_bootstrap(
        &mut self,
        market: MarketId,
        funder: AccountId,
        amount: Amount,
    ) -> Result<(), EscrowError> {
        let next = self.plan_lock(funder, self.bootstrap(market), amount)?;
        self.debit_available(funder, amount)?;
        self.bootstrap.insert(market, next);
        Ok(())
    }

    // ---- complete-set collateral ------------------------------------------

    /// Lock `amount` of `funder`'s available balance into a market's
    /// complete-set collateral escrow (mint).
    ///
    /// # Errors
    /// As [`EscrowLedger::lock_sponsor_stake`].
    pub fn lock_complete_set(
        &mut self,
        market: MarketId,
        funder: AccountId,
        amount: Amount,
    ) -> Result<(), EscrowError> {
        let next = self.plan_lock(funder, self.complete_set(market), amount)?;
        self.debit_available(funder, amount)?;
        self.complete_set.insert(market, next);
        Ok(())
    }

    /// Release `amount` of a market's complete-set collateral back to `to`'s
    /// available balance (redeem).
    ///
    /// # Errors
    /// [`EscrowError::InsufficientEscrow`] or an arithmetic failure.
    pub fn release_complete_set(
        &mut self,
        market: MarketId,
        to: AccountId,
        amount: Amount,
    ) -> Result<(), EscrowError> {
        non_negative(amount)?;
        let cur = self.complete_set(market);
        if cur < amount {
            return Err(EscrowError::InsufficientEscrow);
        }
        let remaining = cur.checked_sub(amount)?;
        self.credit_available(to, amount)?;
        self.set_complete_set(market, remaining);
        Ok(())
    }

    /// Settle a market's complete-set collateral: drain the whole escrow,
    /// routing `credited` to the protocol settlement-payable account and `dust`
    /// to the dust account. Value preserving.
    ///
    /// # Errors
    /// [`EscrowError::Reconciliation`] if `credited + dust` does not equal the
    /// escrowed collateral, or an arithmetic failure.
    pub fn settle_complete_set(
        &mut self,
        market: MarketId,
        credited: Amount,
        dust: Amount,
    ) -> Result<(), EscrowError> {
        non_negative(credited)?;
        non_negative(dust)?;
        let locked = self.complete_set(market);
        if credited.checked_add(dust)? != locked {
            return Err(EscrowError::Reconciliation);
        }
        let protocol = self.protocol.checked_add(credited)?;
        let dust_acct = self.dust.checked_add(dust)?;
        self.protocol = protocol;
        self.dust = dust_acct;
        self.set_complete_set(market, Amount::ZERO);
        Ok(())
    }

    fn set_complete_set(&mut self, market: MarketId, value: Amount) {
        if value == Amount::ZERO {
            self.complete_set.remove(&market);
        } else {
            self.complete_set.insert(market, value);
        }
    }

    /// Validate a lock (available funds present, escrow will not overflow)
    /// without mutating anything, returning the escrow's post-lock value.
    fn plan_lock(
        &self,
        funder: AccountId,
        current_escrow: Amount,
        amount: Amount,
    ) -> Result<Amount, EscrowError> {
        non_negative(amount)?;
        let avail = self.available(funder)?;
        if avail < amount {
            return Err(EscrowError::InsufficientAvailable {
                required: amount.raw(),
                available: avail.raw(),
            });
        }
        current_escrow
            .checked_add(amount)
            .map_err(EscrowError::from)
    }

    // ---- invariant --------------------------------------------------------

    /// Whether the global conservation invariant holds: the sum of every
    /// subaccount equals `total_supply`.
    #[must_use]
    pub fn conservation_holds(&self) -> bool {
        let mut sum = Amount::ZERO;
        let buckets = self
            .available
            .values()
            .chain(self.sponsor_stake.values())
            .chain(self.bootstrap.values())
            .chain(self.complete_set.values());
        for &v in buckets {
            sum = match sum.checked_add(v) {
                Ok(s) => s,
                Err(_) => return false,
            };
        }
        for &g in &[self.insurance, self.protocol, self.dust] {
            sum = match sum.checked_add(g) {
                Ok(s) => s,
                Err(_) => return false,
            };
        }
        sum == self.total_supply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(n: u32) -> AccountId {
        AccountId::new(n)
    }

    fn amt(r: i128) -> Amount {
        Amount::from_raw(r)
    }

    fn mkt(n: u32) -> MarketId {
        MarketId::new(n)
    }

    fn sid(n: u32) -> SponsorId {
        SponsorId::new(n)
    }

    #[test]
    fn deposit_is_the_only_supply_source_and_withdraw_the_only_sink() {
        let mut l = EscrowLedger::new();
        assert_eq!(l.total_supply(), Amount::ZERO);
        assert_eq!(
            l.available(acct(1)).unwrap_err(),
            EscrowError::UnknownAccount
        );
        l.deposit(acct(1), amt(1_000)).unwrap();
        assert_eq!(l.available(acct(1)).unwrap(), amt(1_000));
        assert_eq!(l.total_supply(), amt(1_000));
        assert!(l.conservation_holds());
        // A lock moves value between subaccounts without changing supply.
        l.lock_bootstrap(mkt(1), acct(1), amt(400)).unwrap();
        assert_eq!(l.total_supply(), amt(1_000));
        assert_eq!(l.bootstrap(mkt(1)), amt(400));
        assert_eq!(l.available(acct(1)).unwrap(), amt(600));
        assert!(l.conservation_holds());
        // Withdrawal is the only thing that lowers supply.
        l.withdraw(acct(1), amt(600)).unwrap();
        assert_eq!(l.total_supply(), amt(400));
        assert!(l.conservation_holds());
    }

    #[test]
    fn locks_reject_insufficient_or_negative_and_leave_state_intact() {
        let mut l = EscrowLedger::new();
        l.deposit(acct(1), amt(500)).unwrap();
        // Over-lock: nothing mutates.
        assert!(matches!(
            l.lock_sponsor_stake(mkt(1), sid(1), acct(1), amt(600)),
            Err(EscrowError::InsufficientAvailable {
                required: 600,
                available: 500
            })
        ));
        assert_eq!(l.available(acct(1)).unwrap(), amt(500));
        assert_eq!(l.sponsor_stake(mkt(1), sid(1)), Amount::ZERO);
        // Negative amount rejected.
        assert_eq!(
            l.lock_sponsor_stake(mkt(1), sid(1), acct(1), amt(-1))
                .unwrap_err(),
            EscrowError::NegativeAmount
        );
        // Unknown funder rejected.
        assert_eq!(
            l.lock_sponsor_stake(mkt(1), sid(1), acct(9), amt(1))
                .unwrap_err(),
            EscrowError::UnknownAccount
        );
        assert!(l.conservation_holds());
    }

    #[test]
    fn slash_and_release_only_move_existing_escrow() {
        let mut l = EscrowLedger::new();
        l.deposit(acct(1), amt(1_000)).unwrap();
        l.lock_sponsor_stake(mkt(1), sid(1), acct(1), amt(1_000))
            .unwrap();
        // Cannot slash more than escrowed.
        assert_eq!(
            l.slash_sponsor_stake(mkt(1), sid(1), amt(1_001))
                .unwrap_err(),
            EscrowError::InsufficientEscrow
        );
        l.slash_sponsor_stake(mkt(1), sid(1), amt(400)).unwrap();
        assert_eq!(l.insurance(), amt(400));
        assert_eq!(l.sponsor_stake(mkt(1), sid(1)), amt(600));
        // Release the remainder to a different account.
        l.release_sponsor_stake(mkt(1), sid(1), acct(2), amt(600))
            .unwrap();
        assert_eq!(l.available(acct(2)).unwrap(), amt(600));
        assert_eq!(l.sponsor_stake(mkt(1), sid(1)), Amount::ZERO);
        // Supply is conserved throughout: it never left the ledger.
        assert_eq!(l.total_supply(), amt(1_000));
        assert!(l.conservation_holds());
    }

    #[test]
    fn settle_drains_collateral_into_protocol_and_dust() {
        let mut l = EscrowLedger::new();
        l.deposit(acct(1), amt(1_000)).unwrap();
        l.lock_complete_set(mkt(1), acct(1), amt(1_000)).unwrap();
        // credited + dust must equal the escrowed collateral.
        assert_eq!(
            l.settle_complete_set(mkt(1), amt(900), amt(50))
                .unwrap_err(),
            EscrowError::Reconciliation
        );
        l.settle_complete_set(mkt(1), amt(997), amt(3)).unwrap();
        assert_eq!(l.protocol(), amt(997));
        assert_eq!(l.dust(), amt(3));
        assert_eq!(l.complete_set(mkt(1)), Amount::ZERO);
        assert_eq!(l.total_supply(), amt(1_000));
        assert!(l.conservation_holds());
    }

    // Deterministic LCG property test: no sequence of ledger moves ever breaks
    // conservation.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn property_random_moves_conserve() {
        let mut r = Lcg(0xE5C0_0123);
        let mut l = EscrowLedger::new();
        for _ in 0..20_000 {
            let a = acct(u32::try_from(r.next_u64() % 4).unwrap());
            let m = mkt(u32::try_from(r.next_u64() % 3).unwrap());
            let s = sid(u32::try_from(r.next_u64() % 3).unwrap());
            let v = amt(i128::from(r.next_u64() % 10_000));
            match r.next_u64() % 7 {
                0 => {
                    let _ = l.deposit(a, v);
                }
                1 => {
                    let _ = l.lock_sponsor_stake(m, s, a, v);
                }
                2 => {
                    let _ = l.lock_bootstrap(m, a, v);
                }
                3 => {
                    let _ = l.lock_complete_set(m, a, v);
                }
                4 => {
                    let _ = l.release_complete_set(m, a, v);
                }
                5 => {
                    let _ = l.slash_sponsor_stake(m, s, v);
                }
                _ => {
                    let _ = l.withdraw(a, v);
                }
            }
            assert!(l.conservation_holds());
        }
    }

    #[test]
    fn never_panics_decoding_arbitrary_ledger_bytes() {
        let mut r = Lcg(0xDEAD_10CC);
        for _ in 0..20_000 {
            let len = usize::try_from(r.next_u64() % 128).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| u8::try_from(r.next_u64() % 256).unwrap())
                .collect();
            let _ = postcard::from_bytes::<EscrowLedger>(&bytes);
        }
    }
}
