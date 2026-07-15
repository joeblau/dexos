//! Canonical, bounded RiskEngine v1 state encoding and direct restoration.

use std::collections::{BTreeSet, HashSet};

use types::{Amount, PayoutVector, Price, Quantity, Ratio};

use super::*;
use crate::{
    RiskStateError, RiskStateLimits, MAX_ACCOUNT_CAPACITY, MAX_MARKET_CAPACITY,
    RISK_TRANSITION_ROOT_SCHEMA_VERSION,
};

#[derive(Default)]
struct TransitionWriter {
    bytes: Vec<u8>,
}

impl TransitionWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn len(&mut self, value: usize) -> Result<(), RiskError> {
        let encoded =
            u64::try_from(value).map_err(|_| RiskError::StateEncodingOverflow { value })?;
        self.u64(encoded);
        Ok(())
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

    fn take(&mut self, len: usize) -> Result<&'a [u8], RiskStateError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if len > remaining {
            return Err(RiskStateError::Truncated {
                offset: self.offset,
                needed: len,
                remaining,
            });
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..self.offset])
    }

    fn u8(&mut self) -> Result<u8, RiskStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RiskStateError> {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> Result<u32, RiskStateError> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, RiskStateError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn i64(&mut self) -> Result<i64, RiskStateError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(i64::from_le_bytes(raw))
    }

    fn i128(&mut self) -> Result<i128, RiskStateError> {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(self.take(16)?);
        Ok(i128::from_le_bytes(raw))
    }

    fn finish(self) -> Result<(), RiskStateError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(RiskStateError::TrailingBytes { remaining })
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RiskStateShape {
    accounts: usize,
    perps: usize,
    payouts: usize,
    payout_values: usize,
    markets: usize,
    marks: usize,
    risk_groups: usize,
    market_limits: usize,
    holders: usize,
    portfolio_limit: usize,
    liquidation_fifo: usize,
    liquidation_present: usize,
}

impl RiskStateShape {
    fn encoded_len(self) -> Result<usize, RiskError> {
        let mut len = 123usize;
        for (field, count, width) in [
            ("account slots", self.accounts, 139usize),
            ("perp positions", self.perps, 20),
            ("payout positions", self.payouts, 16),
            ("payout values", self.payout_values, 16),
            ("market slots", self.markets, 19),
            ("marks", self.marks, 8),
            ("risk groups", self.risk_groups, 4),
            ("market limits", self.market_limits, 16),
            ("market holders", self.holders, 8),
            ("portfolio limit", self.portfolio_limit, 16),
            ("liquidation FIFO", self.liquidation_fifo, 4),
            ("liquidation membership", self.liquidation_present, 4),
        ] {
            let bytes = count
                .checked_mul(width)
                .ok_or(RiskError::StateSizeOverflow { field })?;
            len = len
                .checked_add(bytes)
                .ok_or(RiskError::StateSizeOverflow { field })?;
        }
        Ok(len)
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodedHeader {
    config: RiskConfig,
    max_accounts: usize,
    max_markets: usize,
}

#[derive(Debug, Clone, Copy)]
struct ScannedState {
    header: DecodedHeader,
    shape: RiskStateShape,
}

impl RiskEngine {
    /// Encode canonical RiskEngine v1 state under an independent byte bound.
    ///
    /// These bytes are verbatim the preimage of [`Self::transition_root_v1`].
    /// The exact size and every transition invariant are checked before the
    /// output allocation is attempted.
    pub fn encode_state_v1_bounded(&self, max_bytes: usize) -> Result<Vec<u8>, RiskStateError> {
        self.validate_transition_invariants()?;
        let shape = self
            .state_shape_v1_unchecked()
            .map_err(Self::map_state_size_error)?;
        let encoded_len = shape.encoded_len().map_err(Self::map_state_size_error)?;
        if encoded_len > max_bytes {
            return Err(RiskStateError::EncodedBytesLimit {
                actual: encoded_len,
                max: max_bytes,
            });
        }
        let mut writer = TransitionWriter::with_capacity(encoded_len);
        self.write_state_v1(&mut writer)?;
        assert_eq!(
            writer.bytes.len(),
            encoded_len,
            "v1 risk-state size preflight must equal emitted bytes"
        );
        Ok(writer.bytes)
    }

    /// Decode and directly restore canonical RiskEngine v1 state.
    ///
    /// A first, allocation-free pass validates fixed-width structure, canonical
    /// tags/order, exact length, and every independent/cumulative resource
    /// bound. A second pass constructs primary vectors directly, rebuilds caches,
    /// holder indexes, and queue membership, and compares each rebuilt value to
    /// its committed representation. No account, fill, or liquidation mutation
    /// API is replayed.
    ///
    /// This proves bounded canonical state only. The caller remains responsible
    /// for authenticating the expected root and checkpoint freshness.
    pub fn decode_state_v1_bounded(
        bytes: &[u8],
        limits: &RiskStateLimits,
    ) -> Result<Self, RiskStateError> {
        let scanned = Self::scan_state_v1(bytes, limits)?;
        let rebuilt = Self::restore_state_v1(bytes, scanned)?;
        let canonical = rebuilt.encode_state_v1_bounded(limits.max_encoded_bytes)?;
        if canonical != bytes {
            return Err(RiskStateError::CanonicalEncodingMismatch);
        }
        let expected_root = crypto::hash_domain(crypto::DOMAIN_RISK_STATE, bytes);
        if rebuilt.transition_root_v1()? != expected_root {
            return Err(RiskStateError::RootMismatch);
        }
        Ok(rebuilt)
    }

    pub(super) fn encode_state_v1_for_root(&self) -> Result<Vec<u8>, RiskError> {
        self.validate_transition_invariants()?;
        self.encode_state_v1_unchecked_for_root()
    }

    pub(super) fn encode_state_v1_unchecked_for_root(&self) -> Result<Vec<u8>, RiskError> {
        let shape = self.state_shape_v1_unchecked()?;
        let encoded_len = shape.encoded_len()?;
        let mut writer = TransitionWriter::with_capacity(encoded_len);
        self.write_state_v1(&mut writer)?;
        assert_eq!(
            writer.bytes.len(),
            encoded_len,
            "v1 risk-state size preflight must equal emitted bytes"
        );
        Ok(writer.bytes)
    }

    fn state_shape_v1_unchecked(&self) -> Result<RiskStateShape, RiskError> {
        let mut shape = RiskStateShape {
            accounts: self.used.len(),
            markets: self.marks.len(),
            portfolio_limit: usize::from(self.portfolio_limit.is_some()),
            liquidation_fifo: self.liq_queue.len(),
            liquidation_present: self.liq_queue.present_accounts_sorted().len(),
            ..RiskStateShape::default()
        };
        for positions in &self.perp {
            shape.perps =
                shape
                    .perps
                    .checked_add(positions.len())
                    .ok_or(RiskError::StateSizeOverflow {
                        field: "perp positions",
                    })?;
        }
        for positions in &self.payout {
            shape.payouts =
                shape
                    .payouts
                    .checked_add(positions.len())
                    .ok_or(RiskError::StateSizeOverflow {
                        field: "payout positions",
                    })?;
            for position in positions {
                shape.payout_values = shape
                    .payout_values
                    .checked_add(position.payout.values().len())
                    .ok_or(RiskError::StateSizeOverflow {
                        field: "payout values",
                    })?;
            }
        }
        shape.marks = self.marks.iter().filter(|mark| mark.is_some()).count();
        shape.risk_groups = self
            .risk_group
            .iter()
            .filter(|group| group.is_some())
            .count();
        shape.market_limits = self
            .market_limit
            .iter()
            .filter(|limit| limit.is_some())
            .count();
        for holders in &self.market_holders {
            shape.holders =
                shape
                    .holders
                    .checked_add(holders.len())
                    .ok_or(RiskError::StateSizeOverflow {
                        field: "market holders",
                    })?;
        }
        Ok(shape)
    }

    fn write_state_v1(&self, writer: &mut TransitionWriter) -> Result<(), RiskError> {
        writer.u16(RISK_TRANSITION_ROOT_SCHEMA_VERSION);

        writer.i64(self.config.initial_margin.raw());
        writer.i64(self.config.maintenance_margin.raw());
        writer.i64(self.config.max_leverage.raw());
        writer.len(self.config.max_accounts)?;
        writer.len(self.config.max_markets)?;
        writer.len(self.max_accounts)?;
        writer.len(self.max_markets)?;

        writer.len(self.used.len())?;
        for i in 0..self.used.len() {
            writer.len(i)?;
            writer.bool(self.used[i]);
            writer.bool(self.open[i]);
            writer.u8(Self::margin_mode_tag(self.margin_mode[i]));
            writer.i128(self.collateral[i].raw());

            writer.len(self.perp[i].len())?;
            for position in &self.perp[i] {
                writer.u32(position.market.get());
                writer.i64(position.net_qty.raw());
                writer.i64(position.avg_entry.raw());
            }

            writer.len(self.payout[i].len())?;
            for position in &self.payout[i] {
                writer.len(position.payout.values().len())?;
                for value in position.payout.values() {
                    writer.i128(value.raw());
                }
                writer.i64(position.signed_qty.raw());
            }

            writer.i128(self.cached_equity[i].raw());
            writer.i128(self.cached_exposure[i].raw());
            writer.i128(self.cached_scenario[i].raw());
            writer.i128(self.cached_im[i].raw());
            writer.i128(self.cached_mm[i].raw());
            writer.i128(self.reserved_resting[i].raw());
        }

        writer.len(self.marks.len())?;
        for i in 0..self.marks.len() {
            writer.len(i)?;
            if let Some(mark) = self.marks[i] {
                writer.u8(1);
                writer.i64(mark.raw());
            } else {
                writer.u8(0);
            }
            if let Some(group) = self.risk_group[i] {
                writer.u8(1);
                writer.u32(group);
            } else {
                writer.u8(0);
            }
            if let Some(limit) = self.market_limit[i] {
                writer.u8(1);
                writer.i128(limit.raw());
            } else {
                writer.u8(0);
            }
            writer.len(self.market_holders[i].len())?;
            for holder in &self.market_holders[i] {
                writer.len(*holder)?;
            }
        }

        if let Some(limit) = self.portfolio_limit {
            writer.u8(1);
            writer.i128(limit.raw());
        } else {
            writer.u8(0);
        }
        writer.i128(self.insurance.balance().raw());

        writer.len(self.liq_queue.len())?;
        for account in self.liq_queue.iter_fifo() {
            writer.u32(account.get());
        }
        let present = self.liq_queue.present_accounts_sorted();
        writer.len(present.len())?;
        for account in present {
            writer.u32(account.get());
        }
        writer.i128(self.socialized_total.raw());
        Ok(())
    }

    fn usize_as_u64(field: &'static str, value: usize) -> Result<u64, RiskStateError> {
        u64::try_from(value).map_err(|_| RiskStateError::NativeWidth {
            field,
            value: u64::MAX,
        })
    }

    fn u64_as_usize(field: &'static str, value: u64) -> Result<usize, RiskStateError> {
        usize::try_from(value).map_err(|_| RiskStateError::NativeWidth { field, value })
    }

    fn limit_as_u64(limit: usize) -> u64 {
        u64::try_from(limit).unwrap_or(u64::MAX)
    }

    fn map_state_size_error(error: RiskError) -> RiskStateError {
        match error {
            RiskError::StateSizeOverflow { field } => RiskStateError::ArithmeticOverflow { field },
            other => RiskStateError::RiskInvariant(other),
        }
    }

    fn check_limit(
        resource: &'static str,
        actual: u64,
        limit: usize,
    ) -> Result<(), RiskStateError> {
        let max = Self::limit_as_u64(limit);
        if actual > max {
            Err(RiskStateError::ResourceLimit {
                resource,
                actual,
                max,
            })
        } else {
            Ok(())
        }
    }

    fn add_count(
        current: &mut usize,
        amount: u64,
        resource: &'static str,
        limit: usize,
    ) -> Result<usize, RiskStateError> {
        Self::check_limit(resource, amount, limit)?;
        let amount = Self::u64_as_usize(resource, amount)?;
        *current = current
            .checked_add(amount)
            .ok_or(RiskStateError::ArithmeticOverflow { field: resource })?;
        Self::check_limit(resource, Self::usize_as_u64(resource, *current)?, limit)?;
        Ok(amount)
    }

    fn read_bool(
        reader: &mut StateReader<'_>,
        field: &'static str,
    ) -> Result<bool, RiskStateError> {
        match reader.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(RiskStateError::InvalidTag { field, value }),
        }
    }

    fn read_margin_mode(reader: &mut StateReader<'_>) -> Result<MarginMode, RiskStateError> {
        match reader.u8()? {
            0 => Ok(MarginMode::Isolated),
            1 => Ok(MarginMode::Cross),
            value => Err(RiskStateError::InvalidTag {
                field: "margin mode",
                value,
            }),
        }
    }

    fn read_option_tag(
        reader: &mut StateReader<'_>,
        field: &'static str,
    ) -> Result<bool, RiskStateError> {
        match reader.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(RiskStateError::InvalidTag { field, value }),
        }
    }

    fn scan_state_v1(
        bytes: &[u8],
        limits: &RiskStateLimits,
    ) -> Result<ScannedState, RiskStateError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(RiskStateError::EncodedBytesLimit {
                actual: bytes.len(),
                max: limits.max_encoded_bytes,
            });
        }
        let mut reader = StateReader::new(bytes);
        let version = reader.u16()?;
        if version != RISK_TRANSITION_ROOT_SCHEMA_VERSION {
            return Err(RiskStateError::UnsupportedVersion {
                found: version,
                expected: RISK_TRANSITION_ROOT_SCHEMA_VERSION,
            });
        }

        let initial_margin = reader.i64()?;
        let maintenance_margin = reader.i64()?;
        let max_leverage = reader.i64()?;
        if initial_margin <= 0
            || maintenance_margin <= 0
            || max_leverage <= 0
            || maintenance_margin > initial_margin
        {
            return Err(RiskStateError::InvalidValue {
                field:
                    "risk ratios must be positive and maintenance must not exceed initial margin",
            });
        }

        let configured_accounts_raw = reader.u64()?;
        if configured_accounts_raw == 0
            || configured_accounts_raw
                > Self::usize_as_u64("hard account capacity", MAX_ACCOUNT_CAPACITY)?
        {
            return Err(RiskStateError::InvalidValue {
                field: "configured account capacity is outside the hard resource budget",
            });
        }
        Self::check_limit(
            "account capacity",
            configured_accounts_raw,
            limits.max_account_capacity,
        )?;
        let configured_accounts =
            Self::u64_as_usize("configured account capacity", configured_accounts_raw)?;

        let configured_markets_raw = reader.u64()?;
        if configured_markets_raw == 0
            || configured_markets_raw
                > Self::usize_as_u64("hard market capacity", MAX_MARKET_CAPACITY)?
        {
            return Err(RiskStateError::InvalidValue {
                field: "configured market capacity is outside the hard resource budget",
            });
        }
        Self::check_limit(
            "market capacity",
            configured_markets_raw,
            limits.max_market_capacity,
        )?;
        let configured_markets =
            Self::u64_as_usize("configured market capacity", configured_markets_raw)?;

        let effective_accounts_raw = reader.u64()?;
        Self::check_limit(
            "account capacity",
            effective_accounts_raw,
            limits.max_account_capacity,
        )?;
        let effective_markets_raw = reader.u64()?;
        Self::check_limit(
            "market capacity",
            effective_markets_raw,
            limits.max_market_capacity,
        )?;
        if effective_accounts_raw != configured_accounts_raw
            || effective_markets_raw != configured_markets_raw
        {
            return Err(RiskStateError::InvalidValue {
                field: "effective capacities do not equal configured capacities",
            });
        }

        let account_slots_raw = reader.u64()?;
        Self::check_limit("account slots", account_slots_raw, limits.max_account_slots)?;
        if account_slots_raw > effective_accounts_raw {
            return Err(RiskStateError::InvalidValue {
                field: "account slots exceed effective account capacity",
            });
        }
        let account_slots = Self::u64_as_usize("account slots", account_slots_raw)?;
        let mut shape = RiskStateShape {
            accounts: account_slots,
            ..RiskStateShape::default()
        };

        for i in 0..account_slots {
            let row = reader.u64()?;
            if row != Self::usize_as_u64("account row", i)? {
                return Err(RiskStateError::NonCanonical {
                    field: "account row index does not match dense order",
                });
            }
            let used = Self::read_bool(&mut reader, "used account")?;
            let open = Self::read_bool(&mut reader, "open account")?;
            let mode = Self::read_margin_mode(&mut reader)?;
            let collateral = reader.i128()?;

            let perp_count_raw = reader.u64()?;
            Self::check_limit(
                "perp positions per account",
                perp_count_raw,
                limits.max_perp_positions_per_account,
            )?;
            if perp_count_raw > effective_markets_raw {
                return Err(RiskStateError::InvalidValue {
                    field: "perp position count exceeds effective market capacity",
                });
            }
            let perp_count = Self::add_count(
                &mut shape.perps,
                perp_count_raw,
                "total perp positions",
                limits.max_total_perp_positions,
            )?;
            for _ in 0..perp_count {
                let market = reader.u32()?;
                if u64::from(market) >= effective_markets_raw {
                    return Err(RiskStateError::InvalidValue {
                        field: "perp market exceeds effective market capacity",
                    });
                }
                let _net_qty = reader.i64()?;
                let _avg_entry = reader.i64()?;
            }

            let payout_count_raw = reader.u64()?;
            Self::check_limit(
                "payout positions per account",
                payout_count_raw,
                limits.max_payout_positions_per_account,
            )?;
            let payout_count = Self::add_count(
                &mut shape.payouts,
                payout_count_raw,
                "total payout positions",
                limits.max_total_payout_positions,
            )?;
            for _ in 0..payout_count {
                let values_raw = reader.u64()?;
                let type_limit =
                    Self::usize_as_u64("payout outcome type bound", types::MAX_OUTCOMES)?;
                if values_raw == 0 || values_raw > type_limit {
                    return Err(RiskStateError::InvalidValue {
                        field: "payout outcome count is outside the type bound",
                    });
                }
                Self::check_limit(
                    "outcomes per payout",
                    values_raw,
                    limits.max_outcomes_per_payout,
                )?;
                let values = Self::add_count(
                    &mut shape.payout_values,
                    values_raw,
                    "total payout values",
                    limits.max_total_payout_values,
                )?;
                for _ in 0..values {
                    let _value = reader.i128()?;
                }
                let _signed_qty = reader.i64()?;
            }

            let cached = [
                reader.i128()?,
                reader.i128()?,
                reader.i128()?,
                reader.i128()?,
                reader.i128()?,
            ];
            let reserved = reader.i128()?;
            if open && !used {
                return Err(RiskStateError::InvalidValue {
                    field: "an open account slot is not marked used",
                });
            }
            if !used
                && (mode != MarginMode::Isolated
                    || collateral != 0
                    || perp_count != 0
                    || payout_count != 0
                    || cached != [0; 5]
                    || reserved != 0)
            {
                return Err(RiskStateError::InvalidValue {
                    field: "unused account slot is not normalized",
                });
            }
            if used
                && !open
                && (collateral != 0
                    || perp_count != 0
                    || payout_count != 0
                    || cached != [0; 5]
                    || reserved != 0)
            {
                return Err(RiskStateError::InvalidValue {
                    field: "closed account slot is not normalized",
                });
            }
            if open && reserved < 0 {
                return Err(RiskStateError::InvalidValue {
                    field: "resting reservation is negative",
                });
            }
        }

        let market_slots_raw = reader.u64()?;
        Self::check_limit("market slots", market_slots_raw, limits.max_market_slots)?;
        if market_slots_raw > effective_markets_raw {
            return Err(RiskStateError::InvalidValue {
                field: "market slots exceed effective market capacity",
            });
        }
        let market_slots = Self::u64_as_usize("market slots", market_slots_raw)?;
        shape.markets = market_slots;
        for i in 0..market_slots {
            let row = reader.u64()?;
            if row != Self::usize_as_u64("market row", i)? {
                return Err(RiskStateError::NonCanonical {
                    field: "market row index does not match dense order",
                });
            }
            if Self::read_option_tag(&mut reader, "mark price")? {
                let _mark = reader.i64()?;
                shape.marks += 1;
            }
            if Self::read_option_tag(&mut reader, "risk group")? {
                let _group = reader.u32()?;
                shape.risk_groups += 1;
            }
            if Self::read_option_tag(&mut reader, "market limit")? {
                if reader.i128()? < 0 {
                    return Err(RiskStateError::InvalidValue {
                        field: "market limit is negative",
                    });
                }
                shape.market_limits += 1;
            }

            let holder_count_raw = reader.u64()?;
            Self::check_limit(
                "holders per market",
                holder_count_raw,
                limits.max_holders_per_market,
            )?;
            if holder_count_raw > account_slots_raw {
                return Err(RiskStateError::InvalidValue {
                    field: "market holder count exceeds account slots",
                });
            }
            let holder_count = Self::add_count(
                &mut shape.holders,
                holder_count_raw,
                "total market holders",
                limits.max_total_market_holders,
            )?;
            let mut previous = None;
            for _ in 0..holder_count {
                let holder = reader.u64()?;
                if holder >= account_slots_raw {
                    return Err(RiskStateError::InvalidValue {
                        field: "market holder references an unknown account slot",
                    });
                }
                if previous.is_some_and(|prior| holder <= prior) {
                    return Err(RiskStateError::NonCanonical {
                        field: "market holders must be strictly ascending",
                    });
                }
                previous = Some(holder);
            }
        }

        if Self::read_option_tag(&mut reader, "portfolio limit")? {
            if reader.i128()? < 0 {
                return Err(RiskStateError::InvalidValue {
                    field: "portfolio limit is negative",
                });
            }
            shape.portfolio_limit = 1;
        }
        if reader.i128()? < 0 {
            return Err(RiskStateError::InvalidValue {
                field: "insurance balance is negative",
            });
        }

        let fifo_raw = reader.u64()?;
        Self::check_limit(
            "liquidation entries",
            fifo_raw,
            limits.max_liquidation_entries,
        )?;
        if fifo_raw > account_slots_raw {
            return Err(RiskStateError::InvalidValue {
                field: "liquidation entry count exceeds account slots",
            });
        }
        let fifo = Self::u64_as_usize("liquidation FIFO", fifo_raw)?;
        shape.liquidation_fifo = fifo;
        for _ in 0..fifo {
            if u64::from(reader.u32()?) >= account_slots_raw {
                return Err(RiskStateError::InvalidValue {
                    field: "liquidation FIFO references an unknown account slot",
                });
            }
        }
        let present_raw = reader.u64()?;
        Self::check_limit(
            "liquidation entries",
            present_raw,
            limits.max_liquidation_entries,
        )?;
        if present_raw != fifo_raw {
            return Err(RiskStateError::InvalidValue {
                field: "liquidation FIFO and membership lengths disagree",
            });
        }
        let present = Self::u64_as_usize("liquidation membership", present_raw)?;
        shape.liquidation_present = present;
        let mut previous = None;
        for _ in 0..present {
            let account = reader.u32()?;
            if u64::from(account) >= account_slots_raw {
                return Err(RiskStateError::InvalidValue {
                    field: "liquidation membership references an unknown account slot",
                });
            }
            if previous.is_some_and(|prior| account <= prior) {
                return Err(RiskStateError::NonCanonical {
                    field: "liquidation membership must be strictly ascending",
                });
            }
            previous = Some(account);
        }
        if reader.i128()? < 0 {
            return Err(RiskStateError::InvalidValue {
                field: "socialized-loss total is negative",
            });
        }
        reader.finish()?;

        let expected_len = shape.encoded_len().map_err(Self::map_state_size_error)?;
        if expected_len != bytes.len() {
            return Err(RiskStateError::NonCanonical {
                field: "fixed-width v1 image length does not match declared counts",
            });
        }

        Ok(ScannedState {
            header: DecodedHeader {
                config: RiskConfig {
                    initial_margin: Ratio::from_raw(initial_margin),
                    maintenance_margin: Ratio::from_raw(maintenance_margin),
                    max_leverage: Ratio::from_raw(max_leverage),
                    max_accounts: configured_accounts,
                    max_markets: configured_markets,
                },
                max_accounts: configured_accounts,
                max_markets: configured_markets,
            },
            shape,
        })
    }

    fn restore_state_v1(bytes: &[u8], scanned: ScannedState) -> Result<Self, RiskStateError> {
        let mut reader = StateReader::new(bytes);
        let _version = reader.u16()?;
        let _initial_margin = reader.i64()?;
        let _maintenance_margin = reader.i64()?;
        let _max_leverage = reader.i64()?;
        let _configured_accounts = reader.u64()?;
        let _configured_markets = reader.u64()?;
        let _effective_accounts = reader.u64()?;
        let _effective_markets = reader.u64()?;

        let mut engine = RiskEngine::new(scanned.header.config);
        engine.max_accounts = scanned.header.max_accounts;
        engine.max_markets = scanned.header.max_markets;
        let accounts = Self::u64_as_usize("account slots", reader.u64()?)?;
        debug_assert_eq!(accounts, scanned.shape.accounts);

        engine.used = Vec::with_capacity(accounts);
        engine.open = Vec::with_capacity(accounts);
        engine.margin_mode = Vec::with_capacity(accounts);
        engine.collateral = Vec::with_capacity(accounts);
        engine.perp = Vec::with_capacity(accounts);
        engine.payout = Vec::with_capacity(accounts);
        engine.cached_equity = vec![Amount::ZERO; accounts];
        engine.cached_exposure = vec![Amount::ZERO; accounts];
        engine.cached_scenario = vec![Amount::ZERO; accounts];
        engine.cached_im = vec![Amount::ZERO; accounts];
        engine.cached_mm = vec![Amount::ZERO; accounts];
        engine.reserved_resting = Vec::with_capacity(accounts);
        let mut expected_caches = Vec::with_capacity(accounts);

        for i in 0..accounts {
            let _row = reader.u64()?;
            let used = Self::read_bool(&mut reader, "used account")?;
            let open = Self::read_bool(&mut reader, "open account")?;
            let mode = Self::read_margin_mode(&mut reader)?;
            let collateral = Amount::from_raw(reader.i128()?);

            let perp_count = Self::u64_as_usize("perp positions", reader.u64()?)?;
            let mut perps = Vec::with_capacity(perp_count);
            let mut seen_markets = HashSet::with_capacity(perp_count);
            for _ in 0..perp_count {
                let market = MarketId::new(reader.u32()?);
                if !seen_markets.insert(market) {
                    return Err(RiskStateError::NonCanonical {
                        field: "an account contains duplicate perp markets",
                    });
                }
                perps.push(PerpPosition {
                    market,
                    net_qty: Quantity::from_raw(reader.i64()?),
                    avg_entry: Price::from_raw(reader.i64()?),
                });
            }

            let payout_count = Self::u64_as_usize("payout positions", reader.u64()?)?;
            let mut payouts = Vec::with_capacity(payout_count);
            for _ in 0..payout_count {
                let values_count = Self::u64_as_usize("payout values", reader.u64()?)?;
                let mut values = Vec::with_capacity(values_count);
                for _ in 0..values_count {
                    values.push(Amount::from_raw(reader.i128()?));
                }
                let payout = PayoutVector::new(values).map_err(RiskError::from)?;
                payouts.push(PayoutPosition::new(
                    payout,
                    Quantity::from_raw(reader.i64()?),
                ));
            }

            let expected = CachedColumns {
                equity: Amount::from_raw(reader.i128()?),
                exposure: Amount::from_raw(reader.i128()?),
                scenario: Amount::from_raw(reader.i128()?),
                im: Amount::from_raw(reader.i128()?),
                mm: Amount::from_raw(reader.i128()?),
            };
            let reserved = Amount::from_raw(reader.i128()?);

            debug_assert_eq!(i, engine.used.len());
            engine.used.push(used);
            engine.open.push(open);
            engine.margin_mode.push(mode);
            engine.collateral.push(collateral);
            engine.perp.push(perps);
            engine.payout.push(payouts);
            engine.reserved_resting.push(reserved);
            expected_caches.push(expected);
        }

        let markets = Self::u64_as_usize("market slots", reader.u64()?)?;
        debug_assert_eq!(markets, scanned.shape.markets);
        engine.marks = Vec::with_capacity(markets);
        engine.risk_group = Vec::with_capacity(markets);
        engine.market_limit = Vec::with_capacity(markets);
        engine.market_holders = (0..markets).map(|_| BTreeSet::new()).collect();
        for (account, positions) in engine.perp.iter().enumerate() {
            for position in positions {
                if position.net_qty.raw() == 0 {
                    continue;
                }
                let market = position.market.index().map_err(RiskError::from)?;
                let holders =
                    engine
                        .market_holders
                        .get_mut(market)
                        .ok_or(RiskStateError::InvalidValue {
                            field: "non-flat perp has no allocated market holder index",
                        })?;
                holders.insert(account);
            }
        }

        for i in 0..markets {
            let _row = reader.u64()?;
            let mark = if Self::read_option_tag(&mut reader, "mark price")? {
                Some(Price::from_raw(reader.i64()?))
            } else {
                None
            };
            let group = if Self::read_option_tag(&mut reader, "risk group")? {
                Some(reader.u32()?)
            } else {
                None
            };
            let limit = if Self::read_option_tag(&mut reader, "market limit")? {
                Some(Amount::from_raw(reader.i128()?))
            } else {
                None
            };
            engine.marks.push(mark);
            engine.risk_group.push(group);
            engine.market_limit.push(limit);

            let holder_count = Self::u64_as_usize("market holders", reader.u64()?)?;
            if holder_count != engine.market_holders[i].len() {
                return Err(RiskStateError::InvalidValue {
                    field: "encoded market holders disagree with non-flat perp positions",
                });
            }
            let mut expected = engine.market_holders[i].iter().copied();
            for _ in 0..holder_count {
                let holder = Self::u64_as_usize("market holder", reader.u64()?)?;
                if expected.next() != Some(holder) {
                    return Err(RiskStateError::InvalidValue {
                        field: "encoded market holders disagree with non-flat perp positions",
                    });
                }
            }
            debug_assert!(expected.next().is_none());
        }

        engine.portfolio_limit = if Self::read_option_tag(&mut reader, "portfolio limit")? {
            Some(Amount::from_raw(reader.i128()?))
        } else {
            None
        };
        engine.insurance = InsuranceFund::new(Amount::from_raw(reader.i128()?));

        let fifo_count = Self::u64_as_usize("liquidation FIFO", reader.u64()?)?;
        let mut fifo = Vec::with_capacity(fifo_count);
        let mut fifo_members = HashSet::with_capacity(fifo_count);
        for _ in 0..fifo_count {
            let account = AccountId::new(reader.u32()?);
            if !fifo_members.insert(account) {
                return Err(RiskStateError::NonCanonical {
                    field: "liquidation FIFO contains a duplicate account",
                });
            }
            let index = account.index().map_err(RiskError::from)?;
            if index >= engine.used.len() || !engine.used[index] || !engine.open[index] {
                return Err(RiskStateError::InvalidValue {
                    field: "liquidation FIFO references an unknown or closed account",
                });
            }
            fifo.push(account);
        }
        let present_count = Self::u64_as_usize("liquidation membership", reader.u64()?)?;
        if present_count != fifo_members.len() {
            return Err(RiskStateError::InvalidValue {
                field: "liquidation FIFO and membership index disagree",
            });
        }
        for _ in 0..present_count {
            let account = AccountId::new(reader.u32()?);
            if !fifo_members.contains(&account) {
                return Err(RiskStateError::InvalidValue {
                    field: "liquidation FIFO and membership index disagree",
                });
            }
        }
        engine.liq_queue = LiquidationQueue::from_fifo_checked(fifo)?;
        engine.socialized_total = Amount::from_raw(reader.i128()?);
        reader.finish()?;

        for (i, expected) in expected_caches.iter().enumerate() {
            let computed = engine.compute_columns(i)?;
            if computed != *expected {
                return Err(RiskStateError::InvalidValue {
                    field: "encoded cached account columns disagree with primary risk state",
                });
            }
            engine.write_columns(i, &computed);
        }
        engine.validate_transition_invariants()?;
        Ok(engine)
    }
}
