//! Canonical, bounded Ledger v1 state encoding and direct restoration.

use types::{AccountId, Amount};

use super::{Ledger, LedgerStateError, LedgerStateLimits, LEDGER_TRANSITION_ROOT_SCHEMA_VERSION};
use crate::error::ExecutionError;

const FIXED_BYTES: usize = 26;
const ROW_BYTES: usize = 80;
const MAX_ACCOUNT_SLOTS: u64 = u32::MAX as u64 + 1;

struct StateWriter {
    bytes: Vec<u8>,
}

impl StateWriter {
    fn try_with_capacity(capacity: usize) -> Result<Self, LedgerStateError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| LedgerStateError::Allocation {
                resource: "encoded bytes",
            })?;
        Ok(Self { bytes })
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
}

#[derive(Clone, Copy)]
struct StateReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StateReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], LedgerStateError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if len > remaining {
            return Err(LedgerStateError::Truncated {
                offset: self.offset,
                needed: len,
                remaining,
            });
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..self.offset])
    }

    fn u16(&mut self) -> Result<u16, LedgerStateError> {
        let mut raw = [0; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, LedgerStateError> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn i128(&mut self) -> Result<i128, LedgerStateError> {
        let mut raw = [0; 16];
        raw.copy_from_slice(self.take(16)?);
        Ok(i128::from_le_bytes(raw))
    }

    fn finish(self) -> Result<(), LedgerStateError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(LedgerStateError::TrailingBytes { remaining })
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ScannedState {
    account_slots: usize,
}

impl Ledger {
    /// Encode the canonical Ledger v1 state used verbatim as the
    /// [`Self::transition_root_v1`] preimage.
    ///
    /// Schema v1 preserves every dense allocated row, all four balance
    /// partitions, every authorization-epoch bit, and the checked stored
    /// supply. The exact fixed-width image size is checked before allocation.
    pub fn encode_state_v1_bounded(&self, max_bytes: usize) -> Result<Vec<u8>, LedgerStateError> {
        let encoded_len = self.validate_state_v1()?;
        self.write_state_v1_bounded(encoded_len, max_bytes)
    }

    fn write_state_v1_bounded(
        &self,
        encoded_len: usize,
        max_bytes: usize,
    ) -> Result<Vec<u8>, LedgerStateError> {
        if encoded_len > max_bytes {
            return Err(LedgerStateError::EncodedBytesLimit {
                actual: encoded_len,
                max: max_bytes,
            });
        }

        let account_slots =
            u64::try_from(self.available.len()).map_err(|_| LedgerStateError::NativeWidth {
                field: "account slots",
                value: u64::MAX,
            })?;
        let mut writer = StateWriter::try_with_capacity(encoded_len)?;
        writer.u16(LEDGER_TRANSITION_ROOT_SCHEMA_VERSION);
        writer.u64(account_slots);
        for i in 0..self.available.len() {
            writer.u64(u64::try_from(i).map_err(|_| LedgerStateError::NativeWidth {
                field: "account row",
                value: u64::MAX,
            })?);
            writer.i128(self.available[i].raw());
            writer.i128(self.reserved[i].raw());
            writer.i128(self.locked[i].raw());
            writer.i128(self.escrowed[i].raw());
            writer.u64(self.auth_epoch[i]);
        }
        writer.i128(self.total_supply.raw());
        if writer.bytes.len() != encoded_len {
            return Err(LedgerStateError::CanonicalEncodingMismatch);
        }
        Ok(writer.bytes)
    }

    /// Decode and directly restore canonical Ledger v1 state under independent
    /// byte and account-slot limits.
    ///
    /// The first pass allocates nothing: it checks the full image bound,
    /// schema, count and identifier namespaces, exact `26 + 80 * N` size,
    /// dense row ordinals, non-negative partitions, checked conservation, and
    /// exact EOF. Only then does a second pass reserve all five dense columns
    /// and construct them directly, without replaying public mutations.
    ///
    /// This codec establishes canonical representation and Ledger-local
    /// validity only. Authentication, freshness, and cross-component Engine
    /// relations remain the checkpoint reader's responsibility.
    pub fn decode_state_v1_bounded(
        bytes: &[u8],
        limits: &LedgerStateLimits,
    ) -> Result<Self, LedgerStateError> {
        let scanned = Self::scan_state_v1(bytes, limits)?;
        let rebuilt = Self::restore_state_v1(bytes, scanned)?;
        let canonical = rebuilt.encode_state_v1_bounded(limits.max_encoded_bytes)?;
        if canonical != bytes {
            return Err(LedgerStateError::CanonicalEncodingMismatch);
        }
        drop(canonical);

        let expected_root = crypto::hash_domain(crypto::DOMAIN_EXECUTION_LEDGER_STATE, bytes);
        let rebuilt_root =
            rebuilt
                .transition_root_v1()
                .map_err(|_| LedgerStateError::InvalidValue {
                    field: "rebuilt Ledger transition invariants",
                })?;
        if rebuilt_root != expected_root {
            return Err(LedgerStateError::RootMismatch);
        }
        Ok(rebuilt)
    }

    /// Keep the public transition-root signature and its historical validation
    /// errors while sharing the codec's one canonical writer.
    pub(super) fn encode_state_v1_for_transition_root(&self) -> Result<Vec<u8>, ExecutionError> {
        let account_slots = u64::try_from(self.available.len()).map_err(|_| {
            ExecutionError::StateEncodingOverflow {
                value: self.available.len(),
            }
        })?;
        let encoded_len = Self::encoded_len(account_slots).map_err(|_| {
            ExecutionError::StateEncodingOverflow {
                value: self.available.len(),
            }
        })?;
        self.write_state_v1_bounded(encoded_len, usize::MAX)
            .map_err(|error| match error {
                LedgerStateError::NativeWidth { .. }
                | LedgerStateError::AccountIdNamespace { .. }
                | LedgerStateError::ArithmeticOverflow { .. } => {
                    ExecutionError::StateEncodingOverflow {
                        value: self.available.len(),
                    }
                }
                LedgerStateError::Allocation { .. } => ExecutionError::StateInvariant(
                    "ledger transition-state encoding allocation failed",
                ),
                _ => ExecutionError::StateInvariant(
                    "ledger transition-state encoding failed after validation",
                ),
            })
    }

    fn validate_state_v1(&self) -> Result<usize, LedgerStateError> {
        let account_slots = self.available.len();
        for (column, actual) in [
            ("reserved", self.reserved.len()),
            ("locked", self.locked.len()),
            ("escrowed", self.escrowed.len()),
            ("auth_epoch", self.auth_epoch.len()),
        ] {
            if actual != account_slots {
                return Err(LedgerStateError::StateShape {
                    column,
                    expected: account_slots,
                    actual,
                });
            }
        }

        let account_slots =
            u64::try_from(account_slots).map_err(|_| LedgerStateError::NativeWidth {
                field: "account slots",
                value: u64::MAX,
            })?;
        Self::check_account_namespace(account_slots)?;

        if self.total_supply.is_negative() {
            return Err(LedgerStateError::InvalidValue {
                field: "total supply must be non-negative",
            });
        }
        let mut recomputed = 0i128;
        for i in 0..self.available.len() {
            for (field, value) in [
                ("available balance must be non-negative", self.available[i]),
                ("reserved balance must be non-negative", self.reserved[i]),
                ("locked balance must be non-negative", self.locked[i]),
                ("escrowed balance must be non-negative", self.escrowed[i]),
            ] {
                if value.is_negative() {
                    return Err(LedgerStateError::InvalidValue { field });
                }
                recomputed = recomputed.checked_add(value.raw()).ok_or(
                    LedgerStateError::ArithmeticOverflow {
                        field: "partition sum",
                    },
                )?;
            }
        }
        if recomputed != self.total_supply.raw() {
            return Err(LedgerStateError::InvalidValue {
                field: "partition sum does not equal total supply",
            });
        }
        Self::encoded_len(account_slots)
    }

    fn encoded_len(account_slots: u64) -> Result<usize, LedgerStateError> {
        let row_bytes = account_slots.checked_mul(ROW_BYTES as u64).ok_or(
            LedgerStateError::ArithmeticOverflow {
                field: "account rows encoded size",
            },
        )?;
        let encoded_len = (FIXED_BYTES as u64).checked_add(row_bytes).ok_or(
            LedgerStateError::ArithmeticOverflow {
                field: "encoded size",
            },
        )?;
        usize::try_from(encoded_len).map_err(|_| LedgerStateError::NativeWidth {
            field: "encoded size",
            value: encoded_len,
        })
    }

    fn limit_as_u64(limit: usize) -> u64 {
        u64::try_from(limit).unwrap_or(u64::MAX)
    }

    fn check_account_namespace(account_slots: u64) -> Result<(), LedgerStateError> {
        if account_slots > MAX_ACCOUNT_SLOTS {
            Err(LedgerStateError::AccountIdNamespace { account_slots })
        } else {
            Ok(())
        }
    }

    fn scan_state_v1(
        bytes: &[u8],
        limits: &LedgerStateLimits,
    ) -> Result<ScannedState, LedgerStateError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(LedgerStateError::EncodedBytesLimit {
                actual: bytes.len(),
                max: limits.max_encoded_bytes,
            });
        }

        let mut reader = StateReader::new(bytes);
        let version = reader.u16()?;
        if version != LEDGER_TRANSITION_ROOT_SCHEMA_VERSION {
            return Err(LedgerStateError::UnsupportedVersion {
                found: version,
                expected: LEDGER_TRANSITION_ROOT_SCHEMA_VERSION,
            });
        }

        let account_slots_raw = reader.u64()?;
        let max_account_slots = Self::limit_as_u64(limits.max_account_slots);
        if account_slots_raw > max_account_slots {
            return Err(LedgerStateError::AccountSlotsLimit {
                actual: account_slots_raw,
                max: max_account_slots,
            });
        }
        Self::check_account_namespace(account_slots_raw)?;
        let account_slots =
            usize::try_from(account_slots_raw).map_err(|_| LedgerStateError::NativeWidth {
                field: "account slots",
                value: account_slots_raw,
            })?;

        let expected_len = Self::encoded_len(account_slots_raw)?;
        if bytes.len() != expected_len {
            return Err(if bytes.len() < expected_len {
                LedgerStateError::Truncated {
                    offset: bytes.len(),
                    needed: expected_len - bytes.len(),
                    remaining: 0,
                }
            } else {
                LedgerStateError::TrailingBytes {
                    remaining: bytes.len() - expected_len,
                }
            });
        }

        let mut recomputed = 0i128;
        for ordinal in 0..account_slots {
            let row = reader.u64()?;
            if row > u64::from(u32::MAX) {
                return Err(LedgerStateError::AccountIdRowNamespace { row });
            }
            let expected_row =
                u64::try_from(ordinal).map_err(|_| LedgerStateError::NativeWidth {
                    field: "account row",
                    value: u64::MAX,
                })?;
            if row != expected_row {
                return Err(LedgerStateError::NonCanonical {
                    field: "account row must equal its dense ordinal",
                });
            }
            // Constructing the typed ID here proves that every accepted dense
            // row is representable by the live Ledger's lookup namespace.
            AccountId::from_index(ordinal)
                .map_err(|_| LedgerStateError::AccountIdRowNamespace { row })?;

            for field in ["available", "reserved", "locked", "escrowed"] {
                let value = reader.i128()?;
                if value < 0 {
                    return Err(LedgerStateError::InvalidValue {
                        field: match field {
                            "available" => "available balance must be non-negative",
                            "reserved" => "reserved balance must be non-negative",
                            "locked" => "locked balance must be non-negative",
                            _ => "escrowed balance must be non-negative",
                        },
                    });
                }
                recomputed =
                    recomputed
                        .checked_add(value)
                        .ok_or(LedgerStateError::ArithmeticOverflow {
                            field: "partition sum",
                        })?;
            }
            let _auth_epoch = reader.u64()?;
        }

        let total_supply = reader.i128()?;
        if total_supply < 0 {
            return Err(LedgerStateError::InvalidValue {
                field: "total supply must be non-negative",
            });
        }
        if recomputed != total_supply {
            return Err(LedgerStateError::InvalidValue {
                field: "partition sum does not equal total supply",
            });
        }
        reader.finish()?;
        Ok(ScannedState { account_slots })
    }

    fn restore_state_v1(bytes: &[u8], scanned: ScannedState) -> Result<Self, LedgerStateError> {
        let mut available = Self::try_reserve_column(scanned.account_slots, "available")?;
        let mut reserved = Self::try_reserve_column(scanned.account_slots, "reserved")?;
        let mut locked = Self::try_reserve_column(scanned.account_slots, "locked")?;
        let mut escrowed = Self::try_reserve_column(scanned.account_slots, "escrowed")?;
        let mut auth_epoch = Self::try_reserve_column(scanned.account_slots, "auth_epoch")?;

        let mut reader = StateReader::new(bytes);
        let _version = reader.u16()?;
        let _account_slots = reader.u64()?;
        for _ in 0..scanned.account_slots {
            let _row = reader.u64()?;
            available.push(Amount::from_raw(reader.i128()?));
            reserved.push(Amount::from_raw(reader.i128()?));
            locked.push(Amount::from_raw(reader.i128()?));
            escrowed.push(Amount::from_raw(reader.i128()?));
            auth_epoch.push(reader.u64()?);
        }
        let total_supply = Amount::from_raw(reader.i128()?);
        reader.finish()?;

        let rebuilt = Self {
            available,
            reserved,
            locked,
            escrowed,
            auth_epoch,
            total_supply,
        };
        rebuilt
            .validate_transition_invariants()
            .map_err(Self::map_transition_invariant_error)?;
        rebuilt.validate_state_v1()?;
        Ok(rebuilt)
    }

    fn map_transition_invariant_error(error: ExecutionError) -> LedgerStateError {
        match error {
            ExecutionError::StateShape {
                column,
                expected,
                actual,
                ..
            } => LedgerStateError::StateShape {
                column,
                expected,
                actual,
            },
            ExecutionError::StateInvariant("ledger balance partitions must be non-negative") => {
                LedgerStateError::InvalidValue {
                    field: "balance partitions must be non-negative",
                }
            }
            ExecutionError::StateInvariant("ledger total supply must be non-negative") => {
                LedgerStateError::InvalidValue {
                    field: "total supply must be non-negative",
                }
            }
            ExecutionError::StateInvariant("ledger partition sum does not equal total supply") => {
                LedgerStateError::InvalidValue {
                    field: "partition sum does not equal total supply",
                }
            }
            ExecutionError::Arith(_) => LedgerStateError::ArithmeticOverflow {
                field: "partition sum",
            },
            _ => LedgerStateError::InvalidValue {
                field: "Ledger transition invariants",
            },
        }
    }

    fn try_reserve_column<T>(
        account_slots: usize,
        resource: &'static str,
    ) -> Result<Vec<T>, LedgerStateError> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(account_slots)
            .map_err(|_| LedgerStateError::Allocation { resource })?;
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use types::Hash;

    use super::*;

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

    fn unrestricted_limits() -> LedgerStateLimits {
        LedgerStateLimits {
            max_encoded_bytes: usize::MAX,
            max_account_slots: usize::MAX,
        }
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_i128(bytes: &mut [u8], offset: usize, value: i128) {
        bytes[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
    }

    fn assert_equivalent(left: &Ledger, right: &Ledger) {
        assert_eq!(
            left.encode_state_v1_bounded(usize::MAX),
            right.encode_state_v1_bounded(usize::MAX)
        );
        assert_eq!(left.transition_root_v1(), right.transition_root_v1());
        assert_eq!(left.account_count(), right.account_count());
        assert_eq!(left.total_supply(), right.total_supply());
        assert!(left.conservation_holds());
        assert!(right.conservation_holds());
        for i in 0..left.account_count() {
            let account = AccountId::from_index(i).unwrap();
            assert!(left.contains(account));
            assert!(right.contains(account));
            assert_eq!(left.available(account), right.available(account));
            assert_eq!(left.reserved(account), right.reserved(account));
            assert_eq!(left.locked(account), right.locked(account));
            assert_eq!(left.escrowed(account), right.escrowed(account));
            assert_eq!(left.account_leaf(account), right.account_leaf(account));
        }
    }

    #[test]
    fn state_v1_exact_preimages_and_existing_roots_are_unchanged() {
        let empty = Ledger::new().encode_state_v1_bounded(26).unwrap();
        assert_eq!(empty.len(), 26);
        assert_eq!(
            empty,
            hex::decode(concat!(
                "0100",
                "0000000000000000",
                "00000000000000000000000000000000",
            ))
            .unwrap()
        );
        assert_eq!(
            crypto::hash_domain(crypto::DOMAIN_EXECUTION_LEDGER_STATE, &empty),
            Hash::from_bytes([
                110, 5, 238, 79, 63, 135, 249, 64, 54, 220, 161, 247, 46, 34, 241, 173, 36, 19, 79,
                147, 102, 233, 124, 37, 29, 63, 221, 74, 123, 45, 147, 210,
            ])
        );

        let rich = rich_ledger().encode_state_v1_bounded(186).unwrap();
        assert_eq!(rich.len(), 186);
        assert_eq!(
            rich,
            hex::decode(concat!(
                "0100",
                "0200000000000000",
                "0000000000000000",
                "a3020000000000000000000000000000",
                "64000000000000000000000000000000",
                "c8000000000000000000000000000000",
                "32000000000000000000000000000000",
                "0200000000000000",
                "0100000000000000",
                "db010000000000000000000000000000",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "0100000000000000",
                "dc050000000000000000000000000000",
            ))
            .unwrap()
        );
        assert_eq!(
            crypto::hash_domain(crypto::DOMAIN_EXECUTION_LEDGER_STATE, &rich),
            Hash::from_bytes([
                164, 225, 194, 34, 80, 9, 231, 94, 104, 14, 11, 127, 52, 149, 152, 142, 65, 140,
                228, 157, 230, 202, 71, 137, 154, 170, 93, 84, 96, 121, 176, 91,
            ])
        );
    }

    #[test]
    fn state_v1_roundtrip_preserves_zero_rows_partitions_supply_and_max_epoch() {
        let mut original = rich_ledger();
        let zero_tail = original.create_account(Amount::ZERO).unwrap();
        original.auth_epoch[zero_tail.index().unwrap()] = u64::MAX;

        let bytes = original.encode_state_v1_bounded(usize::MAX).unwrap();
        let restored =
            Ledger::decode_state_v1_bounded(&bytes, &LedgerStateLimits::default()).unwrap();
        assert_equivalent(&original, &restored);
        assert_eq!(restored.auth_epoch[2], u64::MAX);
        assert_eq!(restored.available(zero_tail), Ok(Amount::ZERO));
        assert_eq!(restored.total_supply(), amount(1_500));
    }

    #[test]
    fn state_v1_encode_and_decode_bounds_are_inclusive() {
        let mut ledger = Ledger::new();
        ledger.create_account(Amount::ZERO).unwrap();
        let bytes = ledger.encode_state_v1_bounded(106).unwrap();
        assert_eq!(bytes.len(), 106);
        assert_eq!(
            ledger.encode_state_v1_bounded(105),
            Err(LedgerStateError::EncodedBytesLimit {
                actual: 106,
                max: 105,
            })
        );

        let inclusive = LedgerStateLimits {
            max_encoded_bytes: 106,
            max_account_slots: 1,
        };
        assert!(Ledger::decode_state_v1_bounded(&bytes, &inclusive).is_ok());

        let too_few_bytes = LedgerStateLimits {
            max_encoded_bytes: 105,
            ..inclusive
        };
        assert_eq!(
            Ledger::decode_state_v1_bounded(&bytes, &too_few_bytes).unwrap_err(),
            LedgerStateError::EncodedBytesLimit {
                actual: 106,
                max: 105,
            }
        );

        let too_few_slots = LedgerStateLimits {
            max_account_slots: 0,
            ..inclusive
        };
        assert_eq!(
            Ledger::decode_state_v1_bounded(&bytes, &too_few_slots).unwrap_err(),
            LedgerStateError::AccountSlotsLimit { actual: 1, max: 0 }
        );
        assert_eq!(
            LedgerStateLimits::default(),
            LedgerStateLimits {
                max_encoded_bytes: 128 * 1024 * 1024,
                max_account_slots: 1 << 20,
            }
        );
    }

    #[test]
    fn state_v1_rejects_every_truncation_and_suffix() {
        let bytes = rich_ledger().encode_state_v1_bounded(usize::MAX).unwrap();
        let limits = LedgerStateLimits::default();
        for cut in 0..bytes.len() {
            assert!(
                Ledger::decode_state_v1_bounded(&bytes[..cut], &limits).is_err(),
                "accepted truncation at byte {cut}",
            );
        }

        for suffix in [&[0u8][..], &[1, 2, 3][..]] {
            let mut suffixed = bytes.clone();
            suffixed.extend_from_slice(suffix);
            assert_eq!(
                Ledger::decode_state_v1_bounded(&suffixed, &limits).unwrap_err(),
                LedgerStateError::TrailingBytes {
                    remaining: suffix.len(),
                }
            );
        }
    }

    #[test]
    fn state_v1_rejects_bad_header_count_namespaces_and_size() {
        let limits = unrestricted_limits();
        let mut empty = Ledger::new().encode_state_v1_bounded(usize::MAX).unwrap();
        put_u16(&mut empty, 0, 2);
        assert_eq!(
            Ledger::decode_state_v1_bounded(&empty, &limits).unwrap_err(),
            LedgerStateError::UnsupportedVersion {
                found: 2,
                expected: 1,
            }
        );

        put_u16(&mut empty, 0, 1);
        put_u64(&mut empty, 2, 1);
        assert!(matches!(
            Ledger::decode_state_v1_bounded(&empty, &limits),
            Err(LedgerStateError::Truncated { .. })
        ));

        let mut one = Ledger::new();
        one.create_account(Amount::ZERO).unwrap();
        let mut one_bytes = one.encode_state_v1_bounded(usize::MAX).unwrap();
        put_u64(&mut one_bytes, 2, 0);
        assert_eq!(
            Ledger::decode_state_v1_bounded(&one_bytes, &limits).unwrap_err(),
            LedgerStateError::TrailingBytes { remaining: 80 }
        );

        put_u64(&mut one_bytes, 2, 2);
        let one_slot_limit = LedgerStateLimits {
            max_encoded_bytes: usize::MAX,
            max_account_slots: 1,
        };
        assert_eq!(
            Ledger::decode_state_v1_bounded(&one_bytes, &one_slot_limit).unwrap_err(),
            LedgerStateError::AccountSlotsLimit { actual: 2, max: 1 }
        );

        #[cfg(target_pointer_width = "64")]
        {
            put_u64(&mut one_bytes, 2, MAX_ACCOUNT_SLOTS + 1);
            assert_eq!(
                Ledger::decode_state_v1_bounded(&one_bytes, &limits).unwrap_err(),
                LedgerStateError::AccountIdNamespace {
                    account_slots: MAX_ACCOUNT_SLOTS + 1,
                }
            );
            put_u64(&mut one_bytes, 2, u64::MAX);
            assert_eq!(
                Ledger::decode_state_v1_bounded(&one_bytes, &limits).unwrap_err(),
                LedgerStateError::AccountIdNamespace {
                    account_slots: u64::MAX,
                }
            );
        }

        #[cfg(target_pointer_width = "32")]
        assert!(matches!(
            Ledger::encoded_len(MAX_ACCOUNT_SLOTS),
            Err(LedgerStateError::NativeWidth {
                field: "encoded size",
                ..
            })
        ));

        assert_eq!(
            Ledger::encoded_len(u64::MAX),
            Err(LedgerStateError::ArithmeticOverflow {
                field: "account rows encoded size",
            })
        );
        assert_eq!(
            Ledger::try_reserve_column::<u64>(usize::MAX, "test column"),
            Err(LedgerStateError::Allocation {
                resource: "test column",
            })
        );
    }

    #[test]
    fn state_v1_rejects_non_dense_or_out_of_namespace_rows() {
        let mut ledger = Ledger::new();
        ledger.create_account(Amount::ZERO).unwrap();
        let limits = unrestricted_limits();
        let bytes = ledger.encode_state_v1_bounded(usize::MAX).unwrap();

        let mut reordered = bytes.clone();
        put_u64(&mut reordered, 10, 1);
        assert_eq!(
            Ledger::decode_state_v1_bounded(&reordered, &limits).unwrap_err(),
            LedgerStateError::NonCanonical {
                field: "account row must equal its dense ordinal",
            }
        );

        let mut out_of_namespace = bytes;
        put_u64(&mut out_of_namespace, 10, u64::from(u32::MAX) + 1);
        assert_eq!(
            Ledger::decode_state_v1_bounded(&out_of_namespace, &limits).unwrap_err(),
            LedgerStateError::AccountIdRowNamespace {
                row: u64::from(u32::MAX) + 1,
            }
        );
    }

    #[test]
    fn state_v1_rejects_negative_partitions_supply_overflow_and_mismatch() {
        let mut ledger = Ledger::new();
        ledger.create_account(Amount::ZERO).unwrap();
        let limits = unrestricted_limits();
        let bytes = ledger.encode_state_v1_bounded(usize::MAX).unwrap();

        for (offset, field) in [
            (18, "available balance must be non-negative"),
            (34, "reserved balance must be non-negative"),
            (50, "locked balance must be non-negative"),
            (66, "escrowed balance must be non-negative"),
        ] {
            let mut negative = bytes.clone();
            put_i128(&mut negative, offset, -1);
            assert_eq!(
                Ledger::decode_state_v1_bounded(&negative, &limits).unwrap_err(),
                LedgerStateError::InvalidValue { field }
            );
        }

        let mut negative_supply = bytes.clone();
        put_i128(&mut negative_supply, 90, -1);
        assert_eq!(
            Ledger::decode_state_v1_bounded(&negative_supply, &limits).unwrap_err(),
            LedgerStateError::InvalidValue {
                field: "total supply must be non-negative",
            }
        );

        let mut overflow = bytes.clone();
        put_i128(&mut overflow, 18, i128::MAX);
        put_i128(&mut overflow, 34, 1);
        put_i128(&mut overflow, 90, i128::MAX);
        assert_eq!(
            Ledger::decode_state_v1_bounded(&overflow, &limits).unwrap_err(),
            LedgerStateError::ArithmeticOverflow {
                field: "partition sum",
            }
        );

        let mut mismatch = bytes;
        put_i128(&mut mismatch, 18, 1);
        assert_eq!(
            Ledger::decode_state_v1_bounded(&mismatch, &limits).unwrap_err(),
            LedgerStateError::InvalidValue {
                field: "partition sum does not equal total supply",
            }
        );
    }

    #[test]
    fn state_v1_decoder_never_panics_on_arbitrary_bounded_bytes() {
        let limits = LedgerStateLimits {
            max_encoded_bytes: 512,
            max_account_slots: 8,
        };
        let mut state = 0xA5A5_0123_7654_FEDCu64;
        for len in 0..=512usize {
            let mut bytes = vec![0; len];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state.to_le_bytes()[0];
            }
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _ = Ledger::decode_state_v1_bounded(&bytes, &limits);
                }))
                .is_ok(),
                "decoder panicked for {len} bytes",
            );
        }

        // Keep a valid deep shape while corrupting every individual byte so
        // fuzz coverage reaches row, partition, epoch, and supply parsing
        // instead of almost always stopping at a random version or count.
        let canonical = rich_ledger().encode_state_v1_bounded(usize::MAX).unwrap();
        for offset in 0..canonical.len() {
            for replacement in [0, 1, 0x7f, 0x80, 0xff] {
                let mut mutated = canonical.clone();
                mutated[offset] = replacement;
                assert!(
                    catch_unwind(AssertUnwindSafe(|| {
                        let _ = Ledger::decode_state_v1_bounded(&mutated, &limits);
                    }))
                    .is_ok(),
                    "decoder panicked after mutating byte {offset}",
                );
            }
        }
    }

    #[test]
    fn state_v1_successful_continuation_matches_every_public_mutation() {
        let mut original = Ledger::new();
        let first = original.create_account(amount(1_000)).unwrap();
        let second = original.create_account(amount(500)).unwrap();
        let third = original.create_account(Amount::ZERO).unwrap();
        original.auth_epoch[first.index().unwrap()] = u64::MAX;
        let bytes = original.encode_state_v1_bounded(usize::MAX).unwrap();
        let mut restored =
            Ledger::decode_state_v1_bounded(&bytes, &LedgerStateLimits::default()).unwrap();
        assert_equivalent(&original, &restored);

        assert_eq!(
            original.bump_auth_epoch(first),
            restored.bump_auth_epoch(first)
        );
        assert_eq!(original.auth_epoch[0], 0);
        assert_equivalent(&original, &restored);

        macro_rules! apply_both {
            ($method:ident($($argument:expr),* $(,)?)) => {{
                assert_eq!(
                    original.$method($($argument),*),
                    restored.$method($($argument),*)
                );
                assert_equivalent(&original, &restored);
            }};
        }

        apply_both!(credit(third, amount(100)));
        apply_both!(reserve(first, amount(120)));
        apply_both!(release(first, amount(50)));
        apply_both!(lock(first, amount(200)));
        apply_both!(unlock(first, amount(40)));
        apply_both!(escrow(first, amount(30)));
        apply_both!(release_escrow(first, amount(10)));
        apply_both!(settle_escrow(first, second, amount(5)));
        apply_both!(transfer_available(second, third, amount(25)));

        // `consume_locked` intentionally creates a non-conserving intermediate;
        // compare only after its paired settlement credit restores the boundary.
        assert_eq!(
            original.consume_locked(first, amount(15)),
            restored.consume_locked(first, amount(15))
        );
        assert_eq!(
            original.credit_available(third, amount(15)),
            restored.credit_available(third, amount(15))
        );
        assert_equivalent(&original, &restored);

        apply_both!(settle_withdrawal(first, amount(50)));
        let next_original = original.create_account(amount(7)).unwrap();
        let next_restored = restored.create_account(amount(7)).unwrap();
        assert_eq!(next_original, AccountId::new(3));
        assert_eq!(next_original, next_restored);
        assert_equivalent(&original, &restored);
    }

    #[test]
    fn state_v1_failed_continuation_preserves_each_valid_boundary() {
        let mut original = rich_ledger();
        let bytes = original.encode_state_v1_bounded(usize::MAX).unwrap();
        let mut restored =
            Ledger::decode_state_v1_bounded(&bytes, &LedgerStateLimits::default()).unwrap();

        type Failure = fn(&mut Ledger) -> Result<(), ExecutionError>;
        let failures: [Failure; 10] = [
            |ledger| ledger.credit(AccountId::new(0), amount(-1)),
            |ledger| ledger.reserve(AccountId::new(99), amount(1)),
            |ledger| ledger.reserve(AccountId::new(0), amount(10_000)),
            |ledger| ledger.release(AccountId::new(0), amount(10_000)),
            |ledger| ledger.unlock(AccountId::new(0), amount(10_000)),
            |ledger| ledger.release_escrow(AccountId::new(0), amount(10_000)),
            |ledger| ledger.settle_escrow(AccountId::new(0), AccountId::new(1), amount(10_000)),
            |ledger| {
                ledger.transfer_available(AccountId::new(0), AccountId::new(1), amount(10_000))
            },
            |ledger| ledger.consume_locked(AccountId::new(0), amount(10_000)),
            |ledger| ledger.settle_withdrawal(AccountId::new(0), amount(10_000)),
        ];

        for fail in failures {
            let original_before = original.encode_state_v1_bounded(usize::MAX).unwrap();
            let restored_before = restored.encode_state_v1_bounded(usize::MAX).unwrap();
            assert_eq!(fail(&mut original), fail(&mut restored));
            assert_eq!(
                original.encode_state_v1_bounded(usize::MAX).unwrap(),
                original_before
            );
            assert_eq!(
                restored.encode_state_v1_bounded(usize::MAX).unwrap(),
                restored_before
            );
            assert_equivalent(&original, &restored);
        }
    }
}
