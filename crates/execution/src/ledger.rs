//! Stablecoin ledger: a Structure-of-Arrays balance store with dense, deterministic
//! account allocation and a global conservation invariant.
//!
//! Every account's stablecoin is partitioned into `available` (spendable),
//! `reserved` (pending withdrawals), `locked` (complete sets), and `escrowed`
//! (premium backing resting claim-market bids).
//! `total_supply == sum(available + reserved + locked + escrowed)` holds after
//! every operation; it changes only on deposit (+) and finalized withdrawal (−).

use state_tree::LeafWriter;
use types::{AccountId, Amount, Hash};

use crate::error::ExecutionError;

/// Canonical stored-ledger transition-root schema.
pub const LEDGER_TRANSITION_ROOT_SCHEMA_VERSION: u16 = 1;

/// Fixed-width canonical writer for the ledger's versioned stored-state
/// commitment. Native-width integers and serde layouts are deliberately
/// excluded from the preimage.
#[derive(Default)]
struct TransitionWriter {
    bytes: Vec<u8>,
}

impl TransitionWriter {
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn usize(&mut self, value: usize) -> Result<(), ExecutionError> {
        let value =
            u64::try_from(value).map_err(|_| ExecutionError::StateEncodingOverflow { value })?;
        self.u64(value);
        Ok(())
    }
}

/// The SoA stablecoin ledger.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    available: Vec<Amount>,
    reserved: Vec<Amount>,
    locked: Vec<Amount>,
    /// Premium escrowed by resting claim-market bids. A dedicated partition —
    /// deliberately NOT `reserved`, which reconciles 1:1 against pending
    /// withdrawals — so escrow-at-rest cannot break that invariant.
    escrowed: Vec<Amount>,
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
        self.escrowed.push(Amount::ZERO);
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

    /// Escrowed (resting claim-bid premium) balance.
    pub fn escrowed(&self, account: AccountId) -> Result<Amount, ExecutionError> {
        Ok(self.escrowed[self.idx(account)?])
    }

    /// Total stablecoin supply held by the ledger.
    pub fn total_supply(&self) -> Amount {
        self.total_supply
    }

    /// Validate every dense column and accounting relation required to restore
    /// the ledger as deterministic transition state.
    ///
    /// This check trusts neither cached `total_supply` nor vector alignment. It
    /// rejects negative partitions, checked-sum overflow, and any mismatch
    /// between the recomputed partition sum and the stored supply.
    pub fn validate_transition_invariants(&self) -> Result<(), ExecutionError> {
        let account_slots = self.available.len();
        for (column, actual) in [
            ("reserved", self.reserved.len()),
            ("locked", self.locked.len()),
            ("escrowed", self.escrowed.len()),
            ("auth_epoch", self.auth_epoch.len()),
        ] {
            if actual != account_slots {
                return Err(ExecutionError::StateShape {
                    section: "ledger",
                    column,
                    expected: account_slots,
                    actual,
                });
            }
        }

        if self.total_supply.is_negative() {
            return Err(ExecutionError::StateInvariant(
                "ledger total supply must be non-negative",
            ));
        }

        let mut recomputed = Amount::ZERO;
        for i in 0..account_slots {
            for value in [
                self.available[i],
                self.reserved[i],
                self.locked[i],
                self.escrowed[i],
            ] {
                if value.is_negative() {
                    return Err(ExecutionError::StateInvariant(
                        "ledger balance partitions must be non-negative",
                    ));
                }
                recomputed = recomputed.checked_add(value)?;
            }
        }
        if recomputed != self.total_supply {
            return Err(ExecutionError::StateInvariant(
                "ledger partition sum does not equal total supply",
            ));
        }
        Ok(())
    }

    /// Cryptographic commitment to every stored ledger value that can affect a
    /// future transition.
    ///
    /// Schema v1 records the exact dense account shape, every balance partition,
    /// authorization epochs, and total supply using fixed-width little-endian
    /// fields. Validation runs first so a malformed snapshot cannot obtain an
    /// apparently authoritative root.
    pub fn transition_root_v1(&self) -> Result<Hash, ExecutionError> {
        self.validate_transition_invariants()?;

        let mut writer = TransitionWriter::default();
        writer.u16(LEDGER_TRANSITION_ROOT_SCHEMA_VERSION);
        writer.usize(self.available.len())?;
        for i in 0..self.available.len() {
            writer.usize(i)?;
            writer.i128(self.available[i].raw());
            writer.i128(self.reserved[i].raw());
            writer.i128(self.locked[i].raw());
            writer.i128(self.escrowed[i].raw());
            writer.u64(self.auth_epoch[i]);
        }
        writer.i128(self.total_supply.raw());
        Ok(crypto::hash_domain(
            crypto::DOMAIN_EXECUTION_LEDGER_STATE,
            &writer.bytes,
        ))
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

    /// Move `amount` from available into escrow (premium backing a resting
    /// claim-market bid). Fails closed when available cannot cover it.
    pub fn escrow(&mut self, account: AccountId, amount: Amount) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        if self.available[i] < amount {
            return Err(ExecutionError::InsufficientAvailable {
                required: amount.raw(),
                available: self.available[i].raw(),
            });
        }
        self.available[i] = self.available[i].checked_sub(amount)?;
        self.escrowed[i] = self.escrowed[i].checked_add(amount)?;
        Ok(())
    }

    /// Move `amount` from escrow back to available (cancel / expiry / residual
    /// release of a resting claim-market bid).
    pub fn release_escrow(
        &mut self,
        account: AccountId,
        amount: Amount,
    ) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        if self.escrowed[i] < amount {
            return Err(ExecutionError::InsufficientReserved);
        }
        self.escrowed[i] = self.escrowed[i].checked_sub(amount)?;
        self.available[i] = self.available[i].checked_add(amount)?;
        Ok(())
    }

    /// Settle `amount` of `from`'s escrowed premium into `to`'s available
    /// balance (a fill against a resting claim-market bid). Because the premium
    /// was moved out of `available` when the bid rested, this path cannot fail
    /// on the resting maker's funding.
    pub fn settle_escrow(
        &mut self,
        from: AccountId,
        to: AccountId,
        amount: Amount,
    ) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        if amount.raw() == 0 {
            return Ok(());
        }
        let i = self.idx(from)?;
        let j = self.idx(to)?;
        if self.escrowed[i] < amount {
            return Err(ExecutionError::InsufficientReserved);
        }
        self.escrowed[i] = self.escrowed[i].checked_sub(amount)?;
        self.available[j] = self.available[j].checked_add(amount)?;
        Ok(())
    }

    /// Remove `amount` from locked without crediting available (settlement pool).
    /// Conservation is restored when the caller credits winners' available.
    pub fn consume_locked(
        &mut self,
        account: AccountId,
        amount: Amount,
    ) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
        if self.locked[i] < amount {
            return Err(ExecutionError::InsufficientReserved);
        }
        self.locked[i] = self.locked[i].checked_sub(amount)?;
        Ok(())
    }

    /// Move `amount` of available stablecoin from `from` to `to` (premium cash).
    pub fn transfer_available(
        &mut self,
        from: AccountId,
        to: AccountId,
        amount: Amount,
    ) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        if amount.raw() == 0 {
            return Ok(());
        }
        let i = self.idx(from)?;
        let j = self.idx(to)?;
        if self.available[i] < amount {
            return Err(ExecutionError::InsufficientAvailable {
                required: amount.raw(),
                available: self.available[i].raw(),
            });
        }
        self.available[i] = self.available[i].checked_sub(amount)?;
        self.available[j] = self.available[j].checked_add(amount)?;
        Ok(())
    }

    /// Credit available without changing total supply (settlement from locked pool).
    pub fn credit_available(
        &mut self,
        account: AccountId,
        amount: Amount,
    ) -> Result<(), ExecutionError> {
        non_negative(amount)?;
        let i = self.idx(account)?;
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
        self.validate_transition_invariants().is_ok()
    }

    /// Deliberately break supply conservation for outer-root error propagation
    /// tests. Production code has no unchecked mutation path to this field.
    #[cfg(test)]
    pub(crate) fn corrupt_total_supply_for_test(&mut self) {
        self.total_supply = Amount::from_raw(self.total_supply.raw() + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::ArithError;

    fn amount(raw: i128) -> Amount {
        Amount::from_raw(raw)
    }

    fn rich_ledger() -> Ledger {
        let mut ledger = Ledger::new();
        let first = ledger.create_account(amount(1_000)).unwrap();
        let second = ledger.create_account(amount(500)).unwrap();
        ledger.reserve(first, amount(100)).unwrap();
        ledger.lock(first, amount(200)).unwrap();
        ledger.escrow(first, amount(50)).unwrap();
        ledger
            .transfer_available(second, first, amount(25))
            .unwrap();
        ledger.bump_auth_epoch(first).unwrap();
        ledger.bump_auth_epoch(first).unwrap();
        ledger.bump_auth_epoch(second).unwrap();
        ledger
    }

    #[test]
    fn transition_root_v1_golden_vectors() {
        assert_eq!(
            Ledger::new().transition_root_v1().unwrap(),
            Hash::from_bytes([
                110, 5, 238, 79, 63, 135, 249, 64, 54, 220, 161, 247, 46, 34, 241, 173, 36, 19, 79,
                147, 102, 233, 124, 37, 29, 63, 221, 74, 123, 45, 147, 210,
            ])
        );
        assert_eq!(
            rich_ledger().transition_root_v1().unwrap(),
            Hash::from_bytes([
                164, 225, 194, 34, 80, 9, 231, 94, 104, 14, 11, 127, 52, 149, 152, 142, 65, 140,
                228, 157, 230, 202, 71, 137, 154, 170, 93, 84, 96, 121, 176, 91,
            ])
        );
    }

    #[test]
    fn transition_root_v1_binds_shape_partitions_epochs_and_supply() {
        let base = rich_ledger();
        let root = base.transition_root_v1().unwrap();

        let mut available = base.clone();
        available
            .transfer_available(AccountId::new(0), AccountId::new(1), amount(1))
            .unwrap();
        assert_ne!(available.transition_root_v1().unwrap(), root);

        let mut reserved = base.clone();
        reserved.reserve(AccountId::new(0), amount(1)).unwrap();
        assert_ne!(reserved.transition_root_v1().unwrap(), root);

        let mut locked = base.clone();
        locked.lock(AccountId::new(0), amount(1)).unwrap();
        assert_ne!(locked.transition_root_v1().unwrap(), root);

        let mut escrowed = base.clone();
        escrowed.escrow(AccountId::new(0), amount(1)).unwrap();
        assert_ne!(escrowed.transition_root_v1().unwrap(), root);

        let mut epoch = base.clone();
        epoch.bump_auth_epoch(AccountId::new(0)).unwrap();
        assert_ne!(epoch.transition_root_v1().unwrap(), root);

        let mut supplied = base.clone();
        supplied.credit(AccountId::new(0), amount(1)).unwrap();
        assert_ne!(supplied.transition_root_v1().unwrap(), root);

        let mut shaped = base.clone();
        shaped.create_account(Amount::ZERO).unwrap();
        assert_ne!(shaped.transition_root_v1().unwrap(), root);
    }

    #[test]
    fn transition_root_v1_is_clone_and_replay_deterministic() {
        let a = rich_ledger();
        let b = rich_ledger();
        assert_eq!(a.transition_root_v1(), b.transition_root_v1());
        assert_eq!(a.transition_root_v1(), a.clone().transition_root_v1());
    }

    #[test]
    fn validator_rejects_every_misaligned_column() {
        let base = rich_ledger();
        let expected = base.available.len();

        macro_rules! reject {
            ($field:ident, $column:literal) => {{
                let mut ledger = base.clone();
                ledger.$field.pop();
                assert_eq!(
                    ledger.transition_root_v1(),
                    Err(ExecutionError::StateShape {
                        section: "ledger",
                        column: $column,
                        expected,
                        actual: expected - 1,
                    })
                );
            }};
        }

        reject!(reserved, "reserved");
        reject!(locked, "locked");
        reject!(escrowed, "escrowed");
        reject!(auth_epoch, "auth_epoch");

        let mut longer = base;
        longer.reserved.push(Amount::ZERO);
        assert_eq!(
            longer.transition_root_v1(),
            Err(ExecutionError::StateShape {
                section: "ledger",
                column: "reserved",
                expected,
                actual: expected + 1,
            })
        );
    }

    #[test]
    fn validator_rejects_negative_partitions_and_supply() {
        let base = rich_ledger();
        for corrupt in [
            |ledger: &mut Ledger| ledger.available[0] = amount(-1),
            |ledger: &mut Ledger| ledger.reserved[0] = amount(-1),
            |ledger: &mut Ledger| ledger.locked[0] = amount(-1),
            |ledger: &mut Ledger| ledger.escrowed[0] = amount(-1),
        ] {
            let mut ledger = base.clone();
            corrupt(&mut ledger);
            assert_eq!(
                ledger.transition_root_v1(),
                Err(ExecutionError::StateInvariant(
                    "ledger balance partitions must be non-negative"
                ))
            );
        }

        let mut negative_supply = base;
        negative_supply.total_supply = amount(-1);
        assert_eq!(
            negative_supply.transition_root_v1(),
            Err(ExecutionError::StateInvariant(
                "ledger total supply must be non-negative"
            ))
        );
    }

    #[test]
    fn validator_rejects_sum_overflow_and_supply_mismatch() {
        let mut overflow = Ledger {
            available: vec![amount(i128::MAX)],
            reserved: vec![amount(1)],
            locked: vec![Amount::ZERO],
            escrowed: vec![Amount::ZERO],
            auth_epoch: vec![0],
            total_supply: amount(i128::MAX),
        };
        assert_eq!(
            overflow.transition_root_v1(),
            Err(ExecutionError::Arith(ArithError::Overflow))
        );
        assert!(!overflow.conservation_holds());

        overflow.reserved[0] = Amount::ZERO;
        overflow.total_supply = amount(i128::MAX - 1);
        assert_eq!(
            overflow.transition_root_v1(),
            Err(ExecutionError::StateInvariant(
                "ledger partition sum does not equal total supply"
            ))
        );
        assert!(!overflow.conservation_holds());
    }
}
