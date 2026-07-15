//! Canonical, bounded ReplayGuard v1 state encoding and direct restoration.

use std::collections::{HashMap, VecDeque};

use types::{AccountId, Amount, Hash, MarketId, Quantity};

use super::{
    ExecutionError, ExecutionReceipt, KeyDomain, ReceiptKind, ReplayGuard,
    ReplayLocalValidationError, ReplayStateError, ReplayStateLimits, ReplayTransitionWriter,
    REPLAY_TRANSITION_ROOT_SCHEMA_VERSION,
};

const FIXED_BYTES: usize = 34;
const WATERMARK_BYTES: usize = 13;
const RECORD_PREFIX_BYTES: usize = 45;
const MIN_RECEIPT_BYTES: usize = 41;
const FIFO_SLOT_BYTES: usize = 13;

#[derive(Debug, Clone, Copy)]
struct ScannedState {
    window: usize,
    watermarks: usize,
    records: usize,
    fifo: usize,
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

    fn remaining(self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ReplayStateError> {
        let remaining = self.remaining();
        if len > remaining {
            return Err(ReplayStateError::Truncated {
                offset: self.offset,
                needed: len,
                remaining,
            });
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..self.offset])
    }

    fn u8(&mut self) -> Result<u8, ReplayStateError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, ReplayStateError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(ReplayStateError::InvalidTag { field, value }),
        }
    }

    fn u16(&mut self) -> Result<u16, ReplayStateError> {
        let mut raw = [0; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> Result<u32, ReplayStateError> {
        let mut raw = [0; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, ReplayStateError> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn i64(&mut self) -> Result<i64, ReplayStateError> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(i64::from_le_bytes(raw))
    }

    fn i128(&mut self) -> Result<i128, ReplayStateError> {
        let mut raw = [0; 16];
        raw.copy_from_slice(self.take(16)?);
        Ok(i128::from_le_bytes(raw))
    }

    fn hash(&mut self) -> Result<Hash, ReplayStateError> {
        let mut raw = [0; 32];
        raw.copy_from_slice(self.take(32)?);
        Ok(Hash::from_bytes(raw))
    }

    fn receipt(&mut self) -> Result<ExecutionReceipt, ReplayStateError> {
        let sequence = self.u64()?;
        let kind = match self.u8()? {
            0 => ReceiptKind::AccountCreated(AccountId::new(self.u32()?)),
            1 => ReceiptKind::Credited(AccountId::new(self.u32()?), Amount::from_raw(self.i128()?)),
            2 => ReceiptKind::WithdrawalRequested(self.u64()?),
            3 => ReceiptKind::WithdrawalFinalized(self.u64()?),
            4 => ReceiptKind::SessionUpdated,
            5 => ReceiptKind::MarketUpdated(MarketId::new(self.u32()?)),
            6 => ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(self.i64()?),
                rested: self.bool("order receipt rested boolean")?,
            },
            7 => ReceiptKind::Cancelled(self.u32()?),
            8 => ReceiptKind::CompleteSet(Amount::from_raw(self.i128()?)),
            9 => ReceiptKind::WalletBound,
            10 => ReceiptKind::ProtocolUpgraded(self.u16()?),
            11 => ReceiptKind::Liquidated {
                account: AccountId::new(self.u32()?),
                insurance_drawn: Amount::from_raw(self.i128()?),
                socialized_loss: Amount::from_raw(self.i128()?),
            },
            12 => ReceiptKind::FundingApplied {
                market: MarketId::new(self.u32()?),
                epoch: self.u64()?,
            },
            13 => ReceiptKind::MarketResolved {
                market: MarketId::new(self.u32()?),
                winning_outcome: self.u16()?,
            },
            14 => ReceiptKind::MarketSettled {
                market: MarketId::new(self.u32()?),
                paid: Amount::from_raw(self.i128()?),
            },
            value => {
                return Err(ReplayStateError::InvalidTag {
                    field: "receipt kind",
                    value,
                });
            }
        };
        let state_root = self.hash()?;
        Ok(ExecutionReceipt {
            sequence,
            kind,
            state_root,
        })
    }

    fn ensure_minimum_repeated(
        self,
        count: usize,
        width: usize,
        fixed_tail: usize,
        field: &'static str,
    ) -> Result<(), ReplayStateError> {
        let needed = count
            .checked_mul(width)
            .and_then(|value| value.checked_add(fixed_tail))
            .ok_or(ReplayStateError::ArithmeticOverflow { field })?;
        let remaining = self.remaining();
        if remaining < needed {
            return Err(ReplayStateError::Truncated {
                offset: self.offset,
                needed,
                remaining,
            });
        }
        Ok(())
    }

    fn finish(self) -> Result<(), ReplayStateError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(ReplayStateError::TrailingBytes { remaining })
        }
    }
}

impl ReplayGuard {
    /// Encode the complete canonical ReplayGuard v1 transition state.
    pub(crate) fn encode_state_v1_bounded(
        &self,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ReplayStateError> {
        self.validate_for_codec()?;
        self.write_state_v1_bounded(max_bytes)
    }

    /// Decode and directly restore canonical ReplayGuard v1 state under
    /// independent byte, window, watermark, and retained-record limits.
    ///
    /// This codec validates only ReplayGuard-local representation and
    /// continuation invariants. Principal/account existence, engine sequence,
    /// account-leaf, and withdrawal-sidecar relations require authoritative
    /// outer Engine context and deliberately remain external.
    pub(crate) fn decode_state_v1_bounded(
        bytes: &[u8],
        limits: &ReplayStateLimits,
    ) -> Result<Self, ReplayStateError> {
        let scanned = Self::scan_state_v1(bytes, limits)?;
        let rebuilt = Self::restore_state_v1(bytes, scanned)?;
        rebuilt.validate_for_codec()?;

        let canonical = rebuilt.encode_state_v1_bounded(limits.max_encoded_bytes)?;
        if canonical != bytes {
            return Err(ReplayStateError::CanonicalEncodingMismatch);
        }
        drop(canonical);

        let expected_root = crypto::hash_domain(crypto::DOMAIN_EXECUTION_REPLAY_STATE, bytes);
        let rebuilt_root = rebuilt.transition_root_v1().map_err(|error| match error {
            ExecutionError::StateInvariant(
                "replay transition-state validation allocation failed"
                | "replay transition-state encoding allocation failed",
            ) => ReplayStateError::Allocation {
                resource: "transition-root verification",
            },
            _ => ReplayStateError::InvalidValue {
                field: "rebuilt ReplayGuard transition invariants",
            },
        })?;
        if rebuilt_root != expected_root {
            return Err(ReplayStateError::RootMismatch);
        }
        Ok(rebuilt)
    }

    /// Keep the transition-root API and its exact historical invariant errors
    /// while routing it through the codec's sole canonical emitter.
    pub(super) fn encode_state_v1_for_transition_root(&self) -> Result<Vec<u8>, ExecutionError> {
        self.validate_transition_invariants()?;
        self.write_state_v1_bounded(usize::MAX)
            .map_err(|error| match error {
                ReplayStateError::NativeWidth { .. }
                | ReplayStateError::ArithmeticOverflow { .. } => {
                    ExecutionError::StateEncodingOverflow { value: self.window }
                }
                ReplayStateError::Allocation { .. } => ExecutionError::StateInvariant(
                    "replay transition-state encoding allocation failed",
                ),
                _ => ExecutionError::StateInvariant(
                    "replay transition-state encoding failed after validation",
                ),
            })
    }

    fn validate_for_codec(&self) -> Result<(), ReplayStateError> {
        self.validate_local_invariants()
            .map_err(|error| match error {
                ReplayLocalValidationError::Invariant(field) => {
                    ReplayStateError::InvalidValue { field }
                }
                ReplayLocalValidationError::Allocation(resource) => {
                    ReplayStateError::Allocation { resource }
                }
            })
    }

    fn write_state_v1_bounded(&self, max_bytes: usize) -> Result<Vec<u8>, ReplayStateError> {
        let encoded_len = self.encoded_len_v1()?;
        if encoded_len > max_bytes {
            return Err(ReplayStateError::EncodedBytesLimit {
                actual: encoded_len,
                max: max_bytes,
            });
        }

        let window = Self::usize_as_u64("window", self.window)?;
        let watermark_count = Self::usize_as_u64("watermarks", self.watermark.len())?;
        let record_count = Self::usize_as_u64("records", self.records.len())?;
        let fifo_count = Self::usize_as_u64("FIFO entries", self.order.len())?;

        let mut watermarks = Vec::new();
        watermarks
            .try_reserve_exact(self.watermark.len())
            .map_err(|_| ReplayStateError::Allocation {
                resource: "sorted watermarks",
            })?;
        watermarks.extend(
            self.watermark
                .iter()
                .map(|(&(principal, domain), &value)| (principal, domain, value)),
        );
        watermarks.sort_unstable();

        let mut slots = Vec::new();
        slots
            .try_reserve_exact(self.records.len())
            .map_err(|_| ReplayStateError::Allocation {
                resource: "sorted record slots",
            })?;
        slots.extend(self.records.keys().copied());
        slots.sort_unstable();

        let mut writer = ReplayTransitionWriter::try_with_capacity(encoded_len)?;
        writer.u16(REPLAY_TRANSITION_ROOT_SCHEMA_VERSION);
        writer.u64(window);
        writer.u64(watermark_count);
        for (principal, domain, value) in watermarks {
            writer.u32(principal);
            writer.u8(domain);
            writer.u64(value);
        }

        writer.u64(record_count);
        for slot @ (principal, domain, key) in slots {
            let (digest, receipt) =
                self.records
                    .get(&slot)
                    .ok_or(ReplayStateError::InvalidValue {
                        field: "record disappeared during immutable encoding",
                    })?;
            writer.u32(principal);
            writer.u8(domain);
            writer.u64(key);
            writer.hash(*digest);
            Self::write_receipt(&mut writer, receipt);
        }

        writer.u64(fifo_count);
        for &(principal, domain, key) in &self.order {
            writer.u32(principal);
            writer.u8(domain);
            writer.u64(key);
        }
        if writer.bytes.len() != encoded_len {
            return Err(ReplayStateError::CanonicalEncodingMismatch);
        }
        Ok(writer.bytes)
    }

    fn encoded_len_v1(&self) -> Result<usize, ReplayStateError> {
        let mut encoded_len = FIXED_BYTES;
        encoded_len = Self::add_repeated_len(
            encoded_len,
            self.watermark.len(),
            WATERMARK_BYTES,
            "watermarks",
        )?;
        for (_, receipt) in self.records.values() {
            encoded_len = encoded_len
                .checked_add(RECORD_PREFIX_BYTES)
                .and_then(|value| value.checked_add(Self::receipt_encoded_len(&receipt.kind)))
                .ok_or(ReplayStateError::ArithmeticOverflow {
                    field: "record bytes",
                })?;
        }
        Self::add_repeated_len(
            encoded_len,
            self.order.len(),
            FIFO_SLOT_BYTES,
            "FIFO entries",
        )
    }

    const fn receipt_encoded_len(kind: &ReceiptKind) -> usize {
        // sequence + tag + variant payload + state root
        match kind {
            ReceiptKind::AccountCreated(_) => 45,
            ReceiptKind::Credited(_, _) => 61,
            ReceiptKind::WithdrawalRequested(_) => 49,
            ReceiptKind::WithdrawalFinalized(_) => 49,
            ReceiptKind::SessionUpdated => 41,
            ReceiptKind::MarketUpdated(_) => 45,
            ReceiptKind::OrderApplied { .. } => 50,
            ReceiptKind::Cancelled(_) => 45,
            ReceiptKind::CompleteSet(_) => 57,
            ReceiptKind::WalletBound => 41,
            ReceiptKind::ProtocolUpgraded(_) => 43,
            ReceiptKind::Liquidated { .. } => 77,
            ReceiptKind::FundingApplied { .. } => 53,
            ReceiptKind::MarketResolved { .. } => 47,
            ReceiptKind::MarketSettled { .. } => 61,
        }
    }

    fn add_repeated_len(
        current: usize,
        count: usize,
        width: usize,
        field: &'static str,
    ) -> Result<usize, ReplayStateError> {
        count
            .checked_mul(width)
            .and_then(|value| current.checked_add(value))
            .ok_or(ReplayStateError::ArithmeticOverflow { field })
    }

    fn usize_as_u64(field: &'static str, value: usize) -> Result<u64, ReplayStateError> {
        u64::try_from(value).map_err(|_| ReplayStateError::NativeWidth {
            field,
            value: u64::MAX,
        })
    }

    fn u64_as_usize(field: &'static str, value: u64) -> Result<usize, ReplayStateError> {
        usize::try_from(value).map_err(|_| ReplayStateError::NativeWidth { field, value })
    }

    fn check_limit(
        resource: &'static str,
        actual: u64,
        limit: usize,
    ) -> Result<(), ReplayStateError> {
        let max = u64::try_from(limit).unwrap_or(u64::MAX);
        if actual > max {
            Err(ReplayStateError::ResourceLimit {
                resource,
                actual,
                max,
            })
        } else {
            Ok(())
        }
    }

    fn scan_state_v1(
        bytes: &[u8],
        limits: &ReplayStateLimits,
    ) -> Result<ScannedState, ReplayStateError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(ReplayStateError::EncodedBytesLimit {
                actual: bytes.len(),
                max: limits.max_encoded_bytes,
            });
        }

        let mut reader = StateReader::new(bytes);
        let version = reader.u16()?;
        if version != REPLAY_TRANSITION_ROOT_SCHEMA_VERSION {
            return Err(ReplayStateError::UnsupportedVersion {
                found: version,
                expected: REPLAY_TRANSITION_ROOT_SCHEMA_VERSION,
            });
        }

        let window_raw = reader.u64()?;
        Self::check_limit("window", window_raw, limits.max_window)?;
        let window = Self::u64_as_usize("window", window_raw)?;

        let watermark_count_raw = reader.u64()?;
        Self::check_limit("watermarks", watermark_count_raw, limits.max_watermarks)?;
        let watermark_count = Self::u64_as_usize("watermarks", watermark_count_raw)?;
        reader.ensure_minimum_repeated(watermark_count, WATERMARK_BYTES, 16, "watermark bytes")?;
        let mut previous_watermark = None;
        for _ in 0..watermark_count {
            let principal = reader.u32()?;
            let domain = reader.u8()?;
            Self::validate_domain(domain, "watermark")?;
            let _value = reader.u64()?;
            let key = (principal, domain);
            if previous_watermark.is_some_and(|previous| key <= previous) {
                return Err(ReplayStateError::NonCanonical {
                    field: "watermarks must be strictly ordered by principal and domain",
                });
            }
            previous_watermark = Some(key);
        }

        let record_count_raw = reader.u64()?;
        Self::check_limit("records", record_count_raw, limits.max_records)?;
        let record_count = Self::u64_as_usize("records", record_count_raw)?;
        if record_count > window {
            return Err(ReplayStateError::InvalidValue {
                field: "replay records exceed the configured window",
            });
        }
        reader.ensure_minimum_repeated(
            record_count,
            RECORD_PREFIX_BYTES + MIN_RECEIPT_BYTES,
            8,
            "record bytes",
        )?;
        let mut previous_slot = None;
        for _ in 0..record_count {
            let principal = reader.u32()?;
            let domain = reader.u8()?;
            Self::validate_domain(domain, "record")?;
            let key = reader.u64()?;
            let slot = (principal, domain, key);
            if previous_slot.is_some_and(|previous| slot <= previous) {
                return Err(ReplayStateError::NonCanonical {
                    field: "records must be strictly ordered by principal, domain, and key",
                });
            }
            previous_slot = Some(slot);
            let _digest = reader.hash()?;
            let receipt = reader.receipt()?;
            Self::validate_scanned_record_receipt(principal, domain, key, &receipt)?;
        }

        let fifo_count_raw = reader.u64()?;
        Self::check_limit("FIFO entries", fifo_count_raw, limits.max_records)?;
        let fifo_count = Self::u64_as_usize("FIFO entries", fifo_count_raw)?;
        if fifo_count != record_count {
            return Err(ReplayStateError::InvalidValue {
                field: "replay FIFO and record map have different lengths",
            });
        }
        reader.ensure_minimum_repeated(fifo_count, FIFO_SLOT_BYTES, 0, "FIFO entry bytes")?;
        for _ in 0..fifo_count {
            let _principal = reader.u32()?;
            let domain = reader.u8()?;
            Self::validate_domain(domain, "FIFO")?;
            let _key = reader.u64()?;
        }
        reader.finish()?;

        Ok(ScannedState {
            window,
            watermarks: watermark_count,
            records: record_count,
            fifo: fifo_count,
        })
    }

    fn validate_domain(domain: u8, section: &'static str) -> Result<(), ReplayStateError> {
        if domain == KeyDomain::Order.tag() || domain == KeyDomain::Withdrawal.tag() {
            Ok(())
        } else {
            Err(ReplayStateError::InvalidValue {
                field: match section {
                    "watermark" => "replay watermark has an unknown key domain",
                    "record" | "FIFO" => "replay FIFO has an unknown key domain",
                    _ => "replay state has an unknown key domain",
                },
            })
        }
    }

    /// Allocation-free receipt validation used by the first pass.
    fn validate_scanned_record_receipt(
        principal: u32,
        domain: u8,
        key: u64,
        receipt: &ExecutionReceipt,
    ) -> Result<(), ReplayStateError> {
        match (domain, &receipt.kind) {
            (domain, ReceiptKind::OrderApplied { filled, .. })
                if domain == KeyDomain::Order.tag() =>
            {
                if filled.raw() < 0 {
                    return Err(ReplayStateError::InvalidValue {
                        field: "replay order receipt has a negative filled quantity",
                    });
                }
                Ok(())
            }
            (domain, ReceiptKind::WithdrawalRequested(withdrawal_id))
                if domain == KeyDomain::Withdrawal.tag() =>
            {
                if *withdrawal_id != super::derive_withdrawal_id(principal, key) {
                    return Err(ReplayStateError::InvalidValue {
                        field: "replay withdrawal receipt id does not match its command key",
                    });
                }
                Ok(())
            }
            (domain, _) if domain == KeyDomain::Order.tag() => {
                Err(ReplayStateError::InvalidValue {
                    field: "replay order key has a non-order receipt",
                })
            }
            (domain, _) if domain == KeyDomain::Withdrawal.tag() => {
                Err(ReplayStateError::InvalidValue {
                    field: "replay withdrawal key has a non-withdrawal receipt",
                })
            }
            _ => Err(ReplayStateError::InvalidValue {
                field: "replay state has an unknown key domain",
            }),
        }
    }

    fn restore_state_v1(bytes: &[u8], scanned: ScannedState) -> Result<Self, ReplayStateError> {
        let mut reader = StateReader::new(bytes);
        let _version = reader.u16()?;
        let _window = reader.u64()?;

        let mut watermark = HashMap::new();
        watermark
            .try_reserve(scanned.watermarks)
            .map_err(|_| ReplayStateError::Allocation {
                resource: "watermark map",
            })?;
        let decoded_watermarks = Self::u64_as_usize("watermarks", reader.u64()?)?;
        if decoded_watermarks != scanned.watermarks {
            return Err(ReplayStateError::CanonicalEncodingMismatch);
        }
        for _ in 0..scanned.watermarks {
            let principal = reader.u32()?;
            let domain = reader.u8()?;
            let value = reader.u64()?;
            if watermark.insert((principal, domain), value).is_some() {
                return Err(ReplayStateError::NonCanonical {
                    field: "watermark map contains a duplicate key",
                });
            }
        }

        let mut records = HashMap::new();
        records
            .try_reserve(scanned.records)
            .map_err(|_| ReplayStateError::Allocation {
                resource: "record map",
            })?;
        let decoded_records = Self::u64_as_usize("records", reader.u64()?)?;
        if decoded_records != scanned.records {
            return Err(ReplayStateError::CanonicalEncodingMismatch);
        }
        for _ in 0..scanned.records {
            let slot = (reader.u32()?, reader.u8()?, reader.u64()?);
            let digest = reader.hash()?;
            let receipt = reader.receipt()?;
            if records.insert(slot, (digest, receipt)).is_some() {
                return Err(ReplayStateError::NonCanonical {
                    field: "record map contains a duplicate slot",
                });
            }
        }

        let mut order = VecDeque::new();
        order
            .try_reserve_exact(scanned.fifo)
            .map_err(|_| ReplayStateError::Allocation {
                resource: "FIFO entries",
            })?;
        let decoded_fifo = Self::u64_as_usize("FIFO entries", reader.u64()?)?;
        if decoded_fifo != scanned.fifo {
            return Err(ReplayStateError::CanonicalEncodingMismatch);
        }
        for _ in 0..scanned.fifo {
            order.push_back((reader.u32()?, reader.u8()?, reader.u64()?));
        }
        reader.finish()?;

        Ok(Self {
            window: scanned.window,
            watermark,
            records,
            order,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;
    use crate::idempotency::{derive_withdrawal_id, GuardDecision, KeyBinding};

    fn binding(principal: u32, domain: KeyDomain, key: u64, digest: u8) -> KeyBinding {
        KeyBinding {
            principal,
            domain,
            key,
            digest: Hash::from_bytes([digest; 32]),
        }
    }

    fn receipt_for(binding: &KeyBinding, sequence: u64, root: u8) -> ExecutionReceipt {
        let kind = match binding.domain {
            KeyDomain::Order => ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(i64::try_from(binding.key % 97).unwrap()),
                rested: binding.key.is_multiple_of(2),
            },
            KeyDomain::Withdrawal => ReceiptKind::WithdrawalRequested(derive_withdrawal_id(
                binding.principal,
                binding.key,
            )),
        };
        ExecutionReceipt {
            sequence,
            kind,
            state_root: Hash::from_bytes([root; 32]),
        }
    }

    fn append(guard: &mut ReplayGuard, binding: &KeyBinding, sequence: u64, root: u8) {
        assert!(matches!(guard.classify(binding), GuardDecision::Fresh));
        guard.reserve(binding);
        guard.finalize(binding, receipt_for(binding, sequence, root));
    }

    fn rich_guard() -> ReplayGuard {
        let mut guard = ReplayGuard::with_window(32);
        for index in 0..12_u64 {
            let principal = u32::try_from(index + 20).unwrap();
            let domain = if index % 2 == 0 {
                KeyDomain::Order
            } else {
                KeyDomain::Withdrawal
            };
            let binding = binding(
                principal,
                domain,
                index + 100,
                u8::try_from(index + 1).unwrap(),
            );
            let kind = match domain {
                KeyDomain::Order => ReceiptKind::OrderApplied {
                    filled: Quantity::from_raw(i64::try_from(index + 7).unwrap()),
                    rested: index % 4 == 0,
                },
                KeyDomain::Withdrawal => {
                    ReceiptKind::WithdrawalRequested(derive_withdrawal_id(principal, index + 100))
                }
            };
            guard.reserve(&binding);
            guard.finalize(
                &binding,
                ExecutionReceipt {
                    sequence: index + 200,
                    kind,
                    state_root: Hash::from_bytes([u8::try_from(index + 33).unwrap(); 32]),
                },
            );
        }
        guard
    }

    fn two_record_guard() -> ReplayGuard {
        let mut guard = ReplayGuard::with_window(2);
        append(&mut guard, &binding(1, KeyDomain::Order, 5, 0x11), 10, 0x31);
        append(
            &mut guard,
            &binding(2, KeyDomain::Withdrawal, 7, 0x22),
            11,
            0x32,
        );
        guard
    }

    fn exact_limits(guard: &ReplayGuard, bytes: &[u8]) -> ReplayStateLimits {
        ReplayStateLimits {
            max_encoded_bytes: bytes.len(),
            max_window: guard.window,
            max_watermarks: guard.watermark.len(),
            max_records: guard.records.len(),
        }
    }

    fn decode(bytes: &[u8]) -> Result<ReplayGuard, ReplayStateError> {
        ReplayGuard::decode_state_v1_bounded(bytes, &ReplayStateLimits::default())
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn all_receipt_kinds() -> Vec<ReceiptKind> {
        vec![
            ReceiptKind::AccountCreated(AccountId::new(1)),
            ReceiptKind::Credited(AccountId::new(2), Amount::from_raw(3)),
            ReceiptKind::WithdrawalRequested(4),
            ReceiptKind::WithdrawalFinalized(5),
            ReceiptKind::SessionUpdated,
            ReceiptKind::MarketUpdated(MarketId::new(6)),
            ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(7),
                rested: true,
            },
            ReceiptKind::Cancelled(8),
            ReceiptKind::CompleteSet(Amount::from_raw(9)),
            ReceiptKind::WalletBound,
            ReceiptKind::ProtocolUpgraded(10),
            ReceiptKind::Liquidated {
                account: AccountId::new(11),
                insurance_drawn: Amount::from_raw(12),
                socialized_loss: Amount::from_raw(13),
            },
            ReceiptKind::FundingApplied {
                market: MarketId::new(14),
                epoch: 15,
            },
            ReceiptKind::MarketResolved {
                market: MarketId::new(16),
                winning_outcome: 17,
            },
            ReceiptKind::MarketSettled {
                market: MarketId::new(18),
                paid: Amount::from_raw(19),
            },
        ]
    }

    #[test]
    fn empty_and_rich_v1_payloads_match_frozen_lengths_and_roots() {
        let empty = ReplayGuard::with_window(0);
        let empty_bytes = empty.encode_state_v1_bounded(usize::MAX).unwrap();
        assert_eq!(empty_bytes.len(), 34);
        assert_eq!(
            hex::encode(&empty_bytes),
            concat!(
                "0100",
                "0000000000000000",
                "0000000000000000",
                "0000000000000000",
                "0000000000000000"
            )
        );
        assert_eq!(
            empty.transition_root_v1().unwrap(),
            Hash::from_bytes([
                28, 118, 249, 53, 111, 190, 171, 99, 240, 215, 58, 61, 189, 132, 99, 252, 216, 19,
                134, 165, 140, 169, 164, 4, 29, 192, 139, 214, 168, 88, 128, 1,
            ])
        );

        let rich = rich_guard();
        let rich_bytes = rich.encode_state_v1_bounded(usize::MAX).unwrap();
        assert_eq!(rich_bytes.len(), 1_480);
        assert_eq!(
            crypto::hash_domain(crypto::DOMAIN_EXECUTION_REPLAY_STATE, &rich_bytes),
            Hash::from_bytes([
                239, 112, 47, 250, 31, 166, 221, 115, 215, 52, 40, 121, 153, 78, 133, 9, 101, 91,
                9, 156, 97, 161, 184, 123, 130, 63, 168, 133, 132, 77, 176, 126,
            ])
        );
        assert_eq!(
            rich.transition_root_v1().unwrap(),
            crypto::hash_domain(crypto::DOMAIN_EXECUTION_REPLAY_STATE, &rich_bytes,)
        );
    }

    #[test]
    fn all_fifteen_receipt_tags_roundtrip_with_frozen_widths_and_corpus() {
        let kinds = all_receipt_kinds();
        let expected_widths = [45, 61, 49, 49, 41, 45, 50, 45, 57, 41, 43, 77, 53, 47, 61];
        let mut corpus = Vec::new();
        let mut expected_receipts = Vec::new();
        for (kind, expected_width) in kinds.into_iter().zip(expected_widths) {
            let receipt = ExecutionReceipt {
                sequence: 0x0102_0304_0506_0708,
                kind,
                state_root: Hash::from_bytes([0xAB; 32]),
            };
            let mut writer = ReplayTransitionWriter::default();
            ReplayGuard::write_receipt(&mut writer, &receipt);
            assert_eq!(writer.bytes.len(), expected_width);
            corpus.extend_from_slice(&writer.bytes);
            expected_receipts.push(receipt);
        }
        assert_eq!(corpus.len(), 764);
        assert_eq!(
            crypto::hash_domain(crypto::DOMAIN_EXECUTION_REPLAY_STATE, &corpus),
            Hash::from_bytes([
                212, 247, 138, 95, 87, 126, 135, 203, 244, 174, 60, 11, 254, 196, 255, 64, 147,
                236, 30, 239, 121, 177, 40, 21, 245, 98, 101, 73, 6, 207, 105, 205,
            ])
        );

        let mut reader = StateReader::new(&corpus);
        for expected in expected_receipts {
            assert_eq!(reader.receipt().unwrap(), expected);
        }
        reader.finish().unwrap();
    }

    #[test]
    fn rich_roundtrip_is_byte_root_and_state_identical() {
        let original = rich_guard();
        let bytes = original.encode_state_v1_bounded(usize::MAX).unwrap();
        let restored =
            ReplayGuard::decode_state_v1_bounded(&bytes, &exact_limits(&original, &bytes)).unwrap();
        assert_eq!(restored.encode_state_v1_bounded(usize::MAX).unwrap(), bytes);
        assert_eq!(restored.transition_root_v1(), original.transition_root_v1());
        assert_eq!(restored.window, original.window);
        assert_eq!(restored.watermark, original.watermark);
        assert_eq!(restored.records, original.records);
        assert_eq!(restored.order, original.order);
    }

    #[test]
    fn watermark_only_zero_and_nonzero_windows_roundtrip_without_repair() {
        for window in [0, 8] {
            let mut original = ReplayGuard::with_window(window);
            original.reserve(&binding(3, KeyDomain::Order, 0, 1));
            original.reserve(&binding(3, KeyDomain::Withdrawal, u64::MAX, 2));
            original.reserve(&binding(4, KeyDomain::Order, 99, 3));
            let bytes = original.encode_state_v1_bounded(usize::MAX).unwrap();
            let restored = decode(&bytes).unwrap();
            assert!(restored.records.is_empty());
            assert!(restored.order.is_empty());
            assert_eq!(restored.watermark, original.watermark);
            assert!(matches!(
                restored.classify(&binding(3, KeyDomain::Order, 0, 1)),
                GuardDecision::Expired
            ));
            assert!(matches!(
                restored.classify(&binding(3, KeyDomain::Withdrawal, u64::MAX, 9)),
                GuardDecision::Expired
            ));
            assert!(matches!(
                restored.classify(&binding(5, KeyDomain::Order, 0, 1)),
                GuardDecision::Fresh
            ));
            assert_eq!(restored.encode_state_v1_bounded(usize::MAX).unwrap(), bytes);
        }
    }

    #[test]
    fn maximum_key_sequence_and_opaque_receipt_material_roundtrip() {
        let max_window = ReplayGuard::with_window(usize::MAX);
        let max_window_bytes = max_window.encode_state_v1_bounded(usize::MAX).unwrap();
        let restored_max_window = ReplayGuard::decode_state_v1_bounded(
            &max_window_bytes,
            &exact_limits(&max_window, &max_window_bytes),
        )
        .unwrap();
        assert_eq!(restored_max_window.window, usize::MAX);

        let mut original = ReplayGuard::with_window(1);
        let max_binding = binding(u32::MAX, KeyDomain::Order, u64::MAX, 0);
        let receipt = ExecutionReceipt {
            sequence: u64::MAX,
            kind: ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(i64::MAX),
                rested: true,
            },
            state_root: Hash::from_bytes([0xFE; 32]),
        };
        original.reserve(&max_binding);
        original.finalize(&max_binding, receipt.clone());
        let bytes = original.encode_state_v1_bounded(usize::MAX).unwrap();
        let restored = decode(&bytes).unwrap();
        match restored.classify(&max_binding) {
            GuardDecision::Replay(replayed) => assert_eq!(replayed, receipt),
            decision => panic!("expected opaque receipt replay, got {decision:?}"),
        }
        assert!(matches!(
            restored.classify(&binding(u32::MAX, KeyDomain::Order, u64::MAX - 1, 0)),
            GuardDecision::Expired
        ));
    }

    #[test]
    fn restored_continuation_preserves_classification_and_global_fifo_eviction() {
        let first = binding(9, KeyDomain::Order, 50, 0x10);
        let second = binding(1, KeyDomain::Withdrawal, 7, 0x20);
        let third = binding(9, KeyDomain::Withdrawal, 3, 0x30);
        let mut control = ReplayGuard::with_window(3);
        append(&mut control, &first, 10, 0xA1);
        append(&mut control, &second, 12, 0xA2);
        append(&mut control, &third, 15, 0xA3);
        let bytes = control.encode_state_v1_bounded(usize::MAX).unwrap();
        let mut restored = decode(&bytes).unwrap();

        for candidate in [&first, &second, &third] {
            assert!(matches!(
                control.classify(candidate),
                GuardDecision::Replay(_)
            ));
            assert!(matches!(
                restored.classify(candidate),
                GuardDecision::Replay(_)
            ));
            let changed = binding(candidate.principal, candidate.domain, candidate.key, 0xEE);
            assert!(matches!(
                control.classify(&changed),
                GuardDecision::Conflict
            ));
            assert!(matches!(
                restored.classify(&changed),
                GuardDecision::Conflict
            ));
        }
        let stale_absent = binding(9, KeyDomain::Order, 49, 1);
        assert!(matches!(
            control.classify(&stale_absent),
            GuardDecision::Expired
        ));
        assert!(matches!(
            restored.classify(&stale_absent),
            GuardDecision::Expired
        ));

        let fourth = binding(0, KeyDomain::Order, 1, 0x40);
        append(&mut control, &fourth, 20, 0xA4);
        append(&mut restored, &fourth, 20, 0xA4);
        assert_eq!(
            control.order.front(),
            Some(&(1, KeyDomain::Withdrawal.tag(), 7))
        );
        assert_eq!(restored.order, control.order);
        assert!(matches!(control.classify(&first), GuardDecision::Expired));
        assert!(matches!(restored.classify(&first), GuardDecision::Expired));
        assert_eq!(
            restored.encode_state_v1_bounded(usize::MAX).unwrap(),
            control.encode_state_v1_bounded(usize::MAX).unwrap()
        );
        assert_eq!(restored.transition_root_v1(), control.transition_root_v1());
    }

    #[test]
    fn restored_zero_window_continuation_never_materializes_records() {
        let mut control = ReplayGuard::with_window(0);
        let first = binding(1, KeyDomain::Withdrawal, 4, 1);
        append(&mut control, &first, 0, 0x51);
        let bytes = control.encode_state_v1_bounded(usize::MAX).unwrap();
        let mut restored = decode(&bytes).unwrap();
        let second = binding(1, KeyDomain::Withdrawal, 9, 2);
        append(&mut control, &second, 3, 0x52);
        append(&mut restored, &second, 3, 0x52);
        assert!(restored.records.is_empty());
        assert!(restored.order.is_empty());
        assert_eq!(restored.watermark, control.watermark);
        assert!(matches!(restored.classify(&first), GuardDecision::Expired));
        assert!(matches!(restored.classify(&second), GuardDecision::Expired));
    }

    #[test]
    fn retained_record_below_higher_watermark_and_same_keys_stay_distinct() {
        let order = binding(1, KeyDomain::Order, 5, 0x11);
        let withdrawal = binding(1, KeyDomain::Withdrawal, 5, 0x22);
        let other_principal = binding(2, KeyDomain::Order, 5, 0x33);
        let mut original = ReplayGuard::with_window(4);
        append(&mut original, &order, 1, 0x61);
        append(&mut original, &withdrawal, 2, 0x62);
        append(&mut original, &other_principal, 3, 0x63);
        // This accepted watermark-ahead state cannot be reconstructed from the
        // retained records and therefore pins direct restoration.
        original.reserve(&binding(1, KeyDomain::Order, 9, 0x44));

        let bytes = original.encode_state_v1_bounded(usize::MAX).unwrap();
        let restored = decode(&bytes).unwrap();
        for candidate in [&order, &withdrawal, &other_principal] {
            assert!(matches!(
                restored.classify(candidate),
                GuardDecision::Replay(_)
            ));
        }
        assert!(matches!(
            restored.classify(&binding(1, KeyDomain::Order, 5, 0xFF)),
            GuardDecision::Conflict
        ));
        assert!(matches!(
            restored.classify(&binding(1, KeyDomain::Order, 6, 0x44)),
            GuardDecision::Expired
        ));
        assert!(matches!(
            restored.classify(&binding(1, KeyDomain::Order, 10, 0x44)),
            GuardDecision::Fresh
        ));
        assert_eq!(restored.watermark(1, KeyDomain::Order), Some(9));
        assert_eq!(restored.encode_state_v1_bounded(usize::MAX).unwrap(), bytes);
    }

    #[test]
    fn every_independent_limit_is_inclusive_and_exclusive() {
        let guard = rich_guard();
        let bytes = guard.encode_state_v1_bounded(usize::MAX).unwrap();
        let exact = exact_limits(&guard, &bytes);
        ReplayGuard::decode_state_v1_bounded(&bytes, &exact).unwrap();
        assert_eq!(guard.encode_state_v1_bounded(bytes.len()).unwrap(), bytes);
        assert_eq!(
            guard.encode_state_v1_bounded(bytes.len() - 1),
            Err(ReplayStateError::EncodedBytesLimit {
                actual: bytes.len(),
                max: bytes.len() - 1,
            })
        );

        let mut limited = exact;
        limited.max_encoded_bytes -= 1;
        assert!(matches!(
            ReplayGuard::decode_state_v1_bounded(&bytes, &limited),
            Err(ReplayStateError::EncodedBytesLimit { .. })
        ));
        let mut limited = exact;
        limited.max_window -= 1;
        assert!(matches!(
            ReplayGuard::decode_state_v1_bounded(&bytes, &limited),
            Err(ReplayStateError::ResourceLimit {
                resource: "window",
                ..
            })
        ));
        let mut limited = exact;
        limited.max_watermarks -= 1;
        assert!(matches!(
            ReplayGuard::decode_state_v1_bounded(&bytes, &limited),
            Err(ReplayStateError::ResourceLimit {
                resource: "watermarks",
                ..
            })
        ));
        let mut limited = exact;
        limited.max_records -= 1;
        assert!(matches!(
            ReplayGuard::decode_state_v1_bounded(&bytes, &limited),
            Err(ReplayStateError::ResourceLimit {
                resource: "records",
                ..
            })
        ));
    }

    #[test]
    fn every_truncation_and_appended_suffix_is_rejected() {
        let guard = two_record_guard();
        let bytes = guard.encode_state_v1_bounded(usize::MAX).unwrap();
        assert_eq!(bytes.len(), 275);
        for cut in 0..bytes.len() {
            assert!(
                decode(&bytes[..cut]).is_err(),
                "truncation at byte {cut} unexpectedly decoded"
            );
        }
        for suffix_len in 1..=32 {
            let mut suffixed = bytes.clone();
            suffixed.extend(std::iter::repeat_n(0xA5, suffix_len));
            assert_eq!(
                decode(&suffixed).unwrap_err(),
                ReplayStateError::TrailingBytes {
                    remaining: suffix_len
                }
            );
        }
    }

    #[test]
    fn schema_tags_boolean_and_count_bombs_are_typed() {
        let guard = two_record_guard();
        let bytes = guard.encode_state_v1_bounded(usize::MAX).unwrap();

        let mut changed = bytes.clone();
        changed[0..2].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            decode(&changed),
            Err(ReplayStateError::UnsupportedVersion { .. })
        ));

        // Frozen two-record layout: first order receipt tag=105, bool=114;
        // second withdrawal receipt tag=200.
        let mut changed = bytes.clone();
        changed[105] = 0xFF;
        assert_eq!(
            decode(&changed).unwrap_err(),
            ReplayStateError::InvalidTag {
                field: "receipt kind",
                value: 0xFF,
            }
        );
        let mut changed = bytes.clone();
        changed[114] = 2;
        assert_eq!(
            decode(&changed).unwrap_err(),
            ReplayStateError::InvalidTag {
                field: "order receipt rested boolean",
                value: 2,
            }
        );

        let mut changed = bytes.clone();
        put_u64(&mut changed, 10, u64::MAX);
        assert!(matches!(
            decode(&changed),
            Err(ReplayStateError::ResourceLimit {
                resource: "watermarks",
                ..
            })
        ));

        #[cfg(target_pointer_width = "64")]
        {
            let empty = ReplayGuard::with_window(0)
                .encode_state_v1_bounded(usize::MAX)
                .unwrap();
            let mut changed = empty;
            put_u64(&mut changed, 2, u64::MAX);
            put_u64(&mut changed, 18, u64::MAX);
            let permissive = ReplayStateLimits {
                max_encoded_bytes: usize::MAX,
                max_window: usize::MAX,
                max_watermarks: usize::MAX,
                max_records: usize::MAX,
            };
            assert_eq!(
                ReplayGuard::decode_state_v1_bounded(&changed, &permissive).unwrap_err(),
                ReplayStateError::ArithmeticOverflow {
                    field: "record bytes"
                }
            );
        }
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn native_width_conversion_is_typed_on_32_bit_targets() {
        assert_eq!(
            ReplayGuard::u64_as_usize("test", u64::MAX).unwrap_err(),
            ReplayStateError::NativeWidth {
                field: "test",
                value: u64::MAX,
            }
        );
    }

    #[test]
    fn numeric_map_order_and_duplicates_are_rejected_before_restore() {
        let guard = two_record_guard();
        let bytes = guard.encode_state_v1_bounded(usize::MAX).unwrap();
        // Header is 18 bytes, followed by two fixed 13-byte watermarks.
        let mut changed = bytes.clone();
        changed[18..44].rotate_left(13);
        assert!(matches!(
            decode(&changed),
            Err(ReplayStateError::NonCanonical {
                field: "watermarks must be strictly ordered by principal and domain"
            })
        ));
        let mut changed = bytes.clone();
        changed[31..36].copy_from_slice(&bytes[18..23]);
        assert!(matches!(
            decode(&changed),
            Err(ReplayStateError::NonCanonical {
                field: "watermarks must be strictly ordered by principal and domain"
            })
        ));

        let mut orders = ReplayGuard::with_window(2);
        append(&mut orders, &binding(7, KeyDomain::Order, 5, 1), 1, 1);
        append(&mut orders, &binding(7, KeyDomain::Order, 6, 2), 2, 2);
        let bytes = orders.encode_state_v1_bounded(usize::MAX).unwrap();
        // 18-byte header + one watermark + record count = record start 39;
        // both order records are exactly 95 bytes.
        assert_eq!(bytes.len(), 263);
        let mut changed = bytes.clone();
        changed[39..229].rotate_left(95);
        assert!(matches!(
            decode(&changed),
            Err(ReplayStateError::NonCanonical {
                field: "records must be strictly ordered by principal, domain, and key"
            })
        ));
        let mut changed = bytes;
        let first_slot = changed[39..52].to_vec();
        changed[134..147].copy_from_slice(&first_slot);
        assert!(matches!(
            decode(&changed),
            Err(ReplayStateError::NonCanonical {
                field: "records must be strictly ordered by principal, domain, and key"
            })
        ));
    }

    #[test]
    fn corrupt_watermark_record_fifo_and_receipt_relations_are_rejected() {
        let guard = two_record_guard();
        let bytes = guard.encode_state_v1_bounded(usize::MAX).unwrap();
        // Layout is pinned by the 275-byte assertion in the truncation test.
        let mut mutations: Vec<Vec<u8>> = Vec::new();

        let mut changed = bytes.clone();
        put_u64(&mut changed, 2, 1); // records exceed window
        mutations.push(changed);

        let mut changed = bytes.clone();
        put_u64(&mut changed, 241, 1); // FIFO/map cardinality mismatch
        mutations.push(changed);

        let mut changed = bytes.clone();
        changed[22] = 9; // watermark domain
        mutations.push(changed);

        let mut changed = bytes.clone();
        changed[56] = 9; // record domain
        mutations.push(changed);

        let mut changed = bytes.clone();
        changed[253] = 9; // FIFO domain
        mutations.push(changed);

        let mut changed = bytes.clone();
        put_u64(&mut changed, 254, 99); // FIFO references missing record
        mutations.push(changed);

        let mut changed = bytes.clone();
        let first_fifo = changed[249..262].to_vec();
        changed[262..275].copy_from_slice(&first_fifo); // duplicate FIFO slot
        mutations.push(changed);

        let mut changed = bytes.clone();
        put_u64(&mut changed, 23, 4); // first record key 5 exceeds HWM
        mutations.push(changed);

        let mut changed = bytes.clone();
        put_u64(&mut changed, 192, 10); // receipt sequence not globally strict
        mutations.push(changed);

        let mut changed = bytes.clone();
        changed[106..114].copy_from_slice(&(-1_i64).to_le_bytes());
        mutations.push(changed);

        let mut changed = bytes.clone();
        changed[200] = 3; // same-width non-request withdrawal receipt
        mutations.push(changed);

        let mut changed = bytes;
        put_u64(&mut changed, 201, 0); // wrong derived withdrawal id
        mutations.push(changed);

        for (index, mutation) in mutations.iter().enumerate() {
            assert!(
                decode(mutation).is_err(),
                "corruption case {index} unexpectedly decoded"
            );
        }
    }

    #[test]
    fn decreasing_per_domain_fifo_keys_are_rejected_even_with_increasing_sequences() {
        let mut guard = ReplayGuard::with_window(2);
        append(&mut guard, &binding(7, KeyDomain::Order, 5, 1), 1, 1);
        append(&mut guard, &binding(7, KeyDomain::Order, 6, 2), 2, 2);
        let mut bytes = guard.encode_state_v1_bounded(usize::MAX).unwrap();
        // Records begin at 39 and are 95 bytes. Swap their sequence values, then
        // reverse the two 13-byte FIFO slots at offset 229.
        put_u64(&mut bytes, 84, 2);
        put_u64(&mut bytes, 179, 1);
        bytes[237..263].rotate_left(13);
        assert_eq!(
            decode(&bytes).unwrap_err(),
            ReplayStateError::InvalidValue {
                field: "replay FIFO keys are not strictly increasing per principal and domain"
            }
        );
    }

    #[test]
    fn arbitrary_single_byte_mutations_never_panic() {
        let bytes = rich_guard().encode_state_v1_bounded(usize::MAX).unwrap();
        for index in 0..bytes.len() {
            for mask in [1, 0x80, 0xFF] {
                let mut changed = bytes.clone();
                changed[index] ^= mask;
                let result = catch_unwind(AssertUnwindSafe(|| decode(&changed)));
                assert!(
                    result.is_ok(),
                    "mutation at {index} with mask {mask:#x} panicked"
                );
            }
        }
    }

    #[test]
    fn arbitrary_bounded_byte_images_never_panic() {
        let mut seed = 0xD1CE_C0DE_5EED_F00D_u64;
        for case in 0..2_048_usize {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = usize::try_from(seed % 513).unwrap();
            let mut bytes = Vec::with_capacity(len);
            for index in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let byte = (seed >> ((index % 8) * 8)) & u64::from(u8::MAX);
                bytes.push(u8::try_from(byte).unwrap());
            }
            let result = catch_unwind(AssertUnwindSafe(|| decode(&bytes)));
            assert!(result.is_ok(), "random image case {case} panicked");
        }
    }
}
