//! Stablecoin ledger: a Structure-of-Arrays balance store with dense, deterministic
//! account allocation and a global conservation invariant.
//!
//! Every account's stablecoin is partitioned into `available` (spendable),
//! `reserved` (open orders / pending withdrawals), and `locked` (complete sets).
//! `total_supply == sum(available + reserved + locked)` holds after every
//! operation; it changes only on deposit (+) and finalized withdrawal (−).

use state_tree::LeafWriter;
use types::{AccountId, Amount};

use crate::error::ExecutionError;

/// The SoA stablecoin ledger.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    available: Vec<Amount>,
    reserved: Vec<Amount>,
    locked: Vec<Amount>,
    auth_epoch: Vec<u64>,
    total_supply: Amount,
}

fn non_negative(amount: Amount) -> Result<(), ExecutionError> {
    if amount.is_negative() {
        Err(ExecutionError::NegativeAmount)
    } else {
        Ok(())
    }
}

impl Ledger {
    /// A new empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    fn idx(&self, account: AccountId) -> Result<usize, ExecutionError> {
        let i = account
            .index()
            .map_err(|_| ExecutionError::UnknownAccount)?;
        if i >= self.available.len() {
            return Err(ExecutionError::UnknownAccount);
        }
        Ok(i)
    }

    /// Number of accounts.
    pub fn account_count(&self) -> usize {
        self.available.len()
    }

    /// Whether `account` has been allocated.
    pub fn contains(&self, account: AccountId) -> bool {
        self.idx(account).is_ok()
    }

    /// Allocate the next account densely, crediting optional genesis collateral.
    pub fn create_account(&mut self, initial: Amount) -> Result<AccountId, ExecutionError> {
        non_negative(initial)?;
        let id = AccountId::from_index(self.available.len())
            .map_err(|_| ExecutionError::AccountExists)?;
        self.available.push(initial);
        self.reserved.push(Amount::ZERO);
        self.locked.push(Amount::ZERO);
        self.auth_epoch.push(0);
        self.total_supply = self.total_supply.checked_add(initial)?;
        Ok(id)
    }

    /// Available balance.
    pub fn available(&self, account: AccountId) -> Result<Amount, ExecutionError> {
        Ok(self.available[self.idx(account)?])
    }

    /// Reserved balance.
    pub fn reserved(&self, account: AccountId) -> Result<Amount, ExecutionError> {
        Ok(self.reserved[self.idx(account)?])
    }

    /// Locked (in complete sets) balance.
    pub fn locked(&self, account: AccountId) -> Result<Amount, ExecutionError> {
        Ok(self.locked[self.idx(account)?])
    }

    /// Total stablecoin supply held by the ledger.
    pub fn total_supply(&self) -> Amount {
        self.total_supply
    }

    /// Credit a deposit into available. Increases total supply.
    pub fn credit(&mut self, account: AccountId, amount: Amount) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        self.available[i] = self.available[i].checked_add(amount)?;
        self.total_supply = self.total_supply.checked_add(amount)?;
        Ok(())
    }

    /// Move `amount` from available to reserved (open order / pending withdrawal).
    pub fn reserve(&mut self, account: AccountId, amount: Amount) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        if self.available[i] < amount {
            return Err(ExecutionError::InsufficientAvailable {
                required: amount.raw(),
                available: self.available[i].raw(),
            });
        }
        self.available[i] = self.available[i].checked_sub(amount)?;
        self.reserved[i] = self.reserved[i].checked_add(amount)?;
        Ok(())
    }

    /// Move `amount` from reserved back to available.
    pub fn release(&mut self, account: AccountId, amount: Amount) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        if self.reserved[i] < amount {
            return Err(ExecutionError::InsufficientReserved);
        }
        self.reserved[i] = self.reserved[i].checked_sub(amount)?;
        self.available[i] = self.available[i].checked_add(amount)?;
        Ok(())
    }

    /// Lock `amount` from available (complete-set mint).
    pub fn lock(&mut self, account: AccountId, amount: Amount) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        if self.available[i] < amount {
            return Err(ExecutionError::InsufficientAvailable {
                required: amount.raw(),
                available: self.available[i].raw(),
            });
        }
        self.available[i] = self.available[i].checked_sub(amount)?;
        self.locked[i] = self.locked[i].checked_add(amount)?;
        Ok(())
    }

    /// Unlock `amount` back to available (complete-set redeem).
    pub fn unlock(&mut self, account: AccountId, amount: Amount) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        if self.locked[i] < amount {
            return Err(ExecutionError::InsufficientReserved);
        }
        self.locked[i] = self.locked[i].checked_sub(amount)?;
        self.available[i] = self.available[i].checked_add(amount)?;
        Ok(())
    }

    /// Settle a finalized withdrawal: remove `amount` from reserved, leaving the
    /// system. Decreases total supply.
    pub fn settle_withdrawal(
        &mut self,
        account: AccountId,
        amount: Amount,
    ) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        if self.reserved[i] < amount {
            return Err(ExecutionError::InsufficientReserved);
        }
        self.reserved[i] = self.reserved[i].checked_sub(amount)?;
        self.total_supply = self.total_supply.checked_sub(amount)?;
        Ok(())
    }

    /// Bump an account's auth epoch (session authorize/revoke), so the state root
    /// reflects the change deterministically.
    pub fn bump_auth_epoch(&mut self, account: AccountId) -> Result<u64, ExecutionError> {
        let i = self.idx(account)?;
        self.auth_epoch[i] = self.auth_epoch[i].wrapping_add(1);
        Ok(self.auth_epoch[i])
    }

    /// Append this account's canonical ledger fields — `available`, `reserved`,
    /// `locked`, and `auth_epoch` — to `writer`, without emitting a version tag
    /// of its own.
    ///
    /// The engine composes these fields with risk collateral, positions, and
    /// claims into a single committed account leaf (see
    /// [`crate::Engine::account_leaf`]), so settlement and trading state share
    /// one verifiable commitment rather than living in separate ledgers.
    pub fn write_account_fields(
        &self,
        account: AccountId,
        writer: &mut LeafWriter,
    ) -> Result<(), ExecutionError> {
        let i = self.idx(account)?;
        writer
            .field_i128(self.available[i].raw())
            .field_i128(self.reserved[i].raw())
            .field_i128(self.locked[i].raw())
            .field_i64(i64::from_le_bytes(self.auth_epoch[i].to_le_bytes()));
        Ok(())
    }

    /// Canonical leaf bytes for the account's ledger-only commitment (balances
    /// and auth epoch). The engine's committed leaf additionally folds in risk
    /// collateral, positions, and claims.
    pub fn account_leaf(&self, account: AccountId) -> Result<Vec<u8>, ExecutionError> {
        let mut writer = LeafWriter::new();
        self.write_account_fields(account, &mut writer)?;
        Ok(writer.finish())
    }

    /// Verify the conservation invariant (used by tests).
    pub fn conservation_holds(&self) -> bool {
        let mut sum = Amount::ZERO;
        for i in 0..self.available.len() {
            sum = match sum
                .checked_add(self.available[i])
                .and_then(|s| s.checked_add(self.reserved[i]))
                .and_then(|s| s.checked_add(self.locked[i]))
            {
                Ok(v) => v,
                Err(_) => return false,
            };
        }
        sum == self.total_supply
    }
}
