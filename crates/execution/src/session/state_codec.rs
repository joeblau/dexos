//! Canonical, bounded SessionRegistry v1 state encoding and direct restoration.

use std::collections::{HashMap, HashSet};

use types::{Amount, Hash, MarketId};

use super::{
    Session, SessionRegistry, SessionStateError, SessionStateLimits, TransitionWriter,
    SESSION_TRANSITION_ROOT_SCHEMA_VERSION,
};

const HEADER_BYTES: usize = 10;
const SESSION_FIXED_BYTES: usize = 93;
const SESSION_TAIL_AFTER_MARKET_COUNT: usize = 48;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SessionStateShape {
    sessions: usize,
    markets: usize,
    consumed_nonces: usize,
}

impl SessionStateShape {
    fn encoded_len(self) -> Result<usize, SessionStateError> {
        let sessions = self.sessions.checked_mul(SESSION_FIXED_BYTES).ok_or(
            SessionStateError::ArithmeticOverflow {
                field: "session entries",
            },
        )?;
        let markets = self
            .markets
            .checked_mul(4)
            .ok_or(SessionStateError::ArithmeticOverflow {
                field: "session markets",
            })?;
        let consumed =
            self.consumed_nonces
                .checked_mul(8)
                .ok_or(SessionStateError::ArithmeticOverflow {
                    field: "consumed nonces",
                })?;
        HEADER_BYTES
            .checked_add(sessions)
            .and_then(|len| len.checked_add(markets))
            .and_then(|len| len.checked_add(consumed))
            .ok_or(SessionStateError::ArithmeticOverflow {
                field: "encoded state length",
            })
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

    fn remaining(self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn require(self, needed: usize) -> Result<(), SessionStateError> {
        let remaining = self.remaining();
        if needed > remaining {
            Err(SessionStateError::Truncated {
                offset: self.offset,
                needed,
                remaining,
            })
        } else {
            Ok(())
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SessionStateError> {
        self.require(len)?;
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..self.offset])
    }

    fn u8(&mut self) -> Result<u8, SessionStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SessionStateError> {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> Result<u32, SessionStateError> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, SessionStateError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn i128(&mut self) -> Result<i128, SessionStateError> {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(self.take(16)?);
        Ok(i128::from_le_bytes(raw))
    }

    fn key(&mut self) -> Result<[u8; 32], SessionStateError> {
        let mut key = [0u8; 32];
        key.copy_from_slice(self.take(32)?);
        Ok(key)
    }

    fn finish(self) -> Result<(), SessionStateError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(SessionStateError::TrailingBytes { remaining })
        }
    }
}

impl SessionRegistry {
    /// Encode canonical SessionRegistry v1 state under an independent byte bound.
    ///
    /// The returned bytes are verbatim the preimage of
    /// [`Self::transition_root_v1`]. Every transition invariant and the exact
    /// output size are checked before the output allocation is attempted.
    pub fn encode_state_v1_bounded(&self, max_bytes: usize) -> Result<Vec<u8>, SessionStateError> {
        self.validate_state_v1()?;
        let shape = self.state_shape_v1()?;
        let encoded_len = shape.encoded_len()?;
        if encoded_len > max_bytes {
            return Err(SessionStateError::EncodedBytesLimit {
                actual: encoded_len,
                max: max_bytes,
            });
        }

        let mut writer = TransitionWriter::default();
        writer.bytes.try_reserve_exact(encoded_len).map_err(|_| {
            SessionStateError::AllocationFailed {
                resource: "encoded session state",
            }
        })?;
        self.write_state_v1_unchecked(&mut writer)?;
        if writer.bytes.len() != encoded_len {
            return Err(SessionStateError::CanonicalEncodingMismatch);
        }
        Ok(writer.bytes)
    }

    /// Decode and directly restore canonical SessionRegistry v1 state.
    ///
    /// The first pass performs no allocation while validating fixed-width
    /// structure, canonical ordering, exact length, and every independent and
    /// cumulative resource bound. Only then does a second pass fallibly reserve
    /// and directly populate the private map, vectors, and sets; authorization
    /// and nonce-consumption mutation APIs are never replayed.
    ///
    /// This proves bounded canonical state only. The caller remains responsible
    /// for authenticating the expected root and checkpoint freshness.
    pub fn decode_state_v1_bounded(
        bytes: &[u8],
        limits: &SessionStateLimits,
    ) -> Result<Self, SessionStateError> {
        let scanned = Self::scan_state_v1(bytes, limits)?;
        let rebuilt = Self::restore_state_v1(bytes, scanned)?;
        let canonical = rebuilt.encode_state_v1_bounded(limits.max_encoded_bytes)?;
        if canonical != bytes {
            return Err(SessionStateError::CanonicalEncodingMismatch);
        }

        let expected_root = crypto::hash_domain(crypto::DOMAIN_EXECUTION_SESSION_STATE, bytes);
        let rebuilt_root = rebuilt.transition_root_v1_checked()?;
        if rebuilt_root != expected_root {
            return Err(SessionStateError::RootMismatch);
        }
        Ok(rebuilt)
    }

    pub(super) fn transition_root_v1_checked(&self) -> Result<Hash, SessionStateError> {
        let bytes = self.encode_state_v1_bounded(usize::MAX)?;
        Ok(crypto::hash_domain(
            crypto::DOMAIN_EXECUTION_SESSION_STATE,
            &bytes,
        ))
    }

    fn validate_state_v1(&self) -> Result<(), SessionStateError> {
        for session in self.sessions.values() {
            if session.max_notional.is_negative() {
                return Err(SessionStateError::InvalidValue {
                    field: "session maximum notional must be nonnegative",
                });
            }
            if session.nonce_start > session.nonce_end {
                return Err(SessionStateError::InvalidValue {
                    field: "session nonce range must be ordered",
                });
            }
            if session
                .consumed
                .iter()
                .any(|nonce| !(session.nonce_start..=session.nonce_end).contains(nonce))
            {
                return Err(SessionStateError::InvalidValue {
                    field: "consumed nonce must lie inside the authorized range",
                });
            }
        }
        Ok(())
    }

    fn state_shape_v1(&self) -> Result<SessionStateShape, SessionStateError> {
        let mut shape = SessionStateShape {
            sessions: self.sessions.len(),
            ..SessionStateShape::default()
        };
        for session in self.sessions.values() {
            let mut markets = Vec::new();
            markets
                .try_reserve_exact(session.allowed_markets.len())
                .map_err(|_| SessionStateError::AllocationFailed {
                    resource: "session market size preflight",
                })?;
            markets.extend(session.allowed_markets.iter().map(|market| market.get()));
            markets.sort_unstable();
            markets.dedup();
            shape.markets = shape.markets.checked_add(markets.len()).ok_or(
                SessionStateError::ArithmeticOverflow {
                    field: "total session markets",
                },
            )?;
            shape.consumed_nonces = shape
                .consumed_nonces
                .checked_add(session.consumed.len())
                .ok_or(SessionStateError::ArithmeticOverflow {
                    field: "total consumed nonces",
                })?;
        }
        Ok(shape)
    }

    fn usize_as_u64(field: &'static str, value: usize) -> Result<u64, SessionStateError> {
        u64::try_from(value).map_err(|_| SessionStateError::ArithmeticOverflow { field })
    }

    fn u64_as_usize(field: &'static str, value: u64) -> Result<usize, SessionStateError> {
        usize::try_from(value).map_err(|_| SessionStateError::NativeWidth { field, value })
    }

    fn check_limit(
        resource: &'static str,
        actual: u64,
        max: usize,
    ) -> Result<(), SessionStateError> {
        let max = Self::usize_as_u64(resource, max)?;
        if actual > max {
            Err(SessionStateError::ResourceLimit {
                resource,
                actual,
                max,
            })
        } else {
            Ok(())
        }
    }

    fn add_count(
        total: &mut usize,
        count: u64,
        resource: &'static str,
        max: usize,
    ) -> Result<usize, SessionStateError> {
        let count = Self::u64_as_usize(resource, count)?;
        let next = total
            .checked_add(count)
            .ok_or(SessionStateError::ArithmeticOverflow { field: resource })?;
        Self::check_limit(resource, Self::usize_as_u64(resource, next)?, max)?;
        *total = next;
        Ok(count)
    }

    fn checked_required_bytes(
        element_count: usize,
        element_width: usize,
        remaining_sessions: usize,
        fixed_tail: usize,
    ) -> Result<usize, SessionStateError> {
        let elements = element_count.checked_mul(element_width).ok_or(
            SessionStateError::ArithmeticOverflow {
                field: "nested session entries",
            },
        )?;
        let sessions = remaining_sessions.checked_mul(SESSION_FIXED_BYTES).ok_or(
            SessionStateError::ArithmeticOverflow {
                field: "remaining session entries",
            },
        )?;
        elements
            .checked_add(fixed_tail)
            .and_then(|bytes| bytes.checked_add(sessions))
            .ok_or(SessionStateError::ArithmeticOverflow {
                field: "minimum remaining session bytes",
            })
    }

    fn scan_state_v1(
        bytes: &[u8],
        limits: &SessionStateLimits,
    ) -> Result<SessionStateShape, SessionStateError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(SessionStateError::EncodedBytesLimit {
                actual: bytes.len(),
                max: limits.max_encoded_bytes,
            });
        }

        let mut reader = StateReader::new(bytes);
        let version = reader.u16()?;
        if version != SESSION_TRANSITION_ROOT_SCHEMA_VERSION {
            return Err(SessionStateError::UnsupportedVersion {
                found: version,
                expected: SESSION_TRANSITION_ROOT_SCHEMA_VERSION,
            });
        }

        let session_count_raw = reader.u64()?;
        Self::check_limit("sessions", session_count_raw, limits.max_sessions)?;
        let session_count = Self::u64_as_usize("sessions", session_count_raw)?;
        let minimum_len = SessionStateShape {
            sessions: session_count,
            ..SessionStateShape::default()
        }
        .encoded_len()?;
        if minimum_len > bytes.len() {
            return Err(SessionStateError::Truncated {
                offset: reader.offset,
                needed: minimum_len.saturating_sub(HEADER_BYTES),
                remaining: reader.remaining(),
            });
        }

        let mut shape = SessionStateShape {
            sessions: session_count,
            ..SessionStateShape::default()
        };
        let mut previous_session = None;
        for index in 0..session_count {
            let account = reader.u32()?;
            let session_key = reader.key()?;
            let current = (account, session_key);
            if previous_session.is_some_and(|previous| current <= previous) {
                return Err(SessionStateError::NonCanonical {
                    field: "sessions must be strictly ordered by numeric account then session key",
                });
            }
            previous_session = Some(current);

            let scope_tag = reader.u8()?;
            if scope_tag > 1 {
                return Err(SessionStateError::InvalidTag {
                    field: "market scope",
                    value: scope_tag,
                });
            }
            let market_count_raw = reader.u64()?;
            Self::check_limit(
                "markets per session",
                market_count_raw,
                limits.max_markets_per_session,
            )?;
            if market_count_raw > u64::from(u32::MAX) + 1 {
                return Err(SessionStateError::InvalidValue {
                    field: "distinct session market count exceeds the u32 key space",
                });
            }
            if (scope_tag == 0 && market_count_raw != 0)
                || (scope_tag == 1 && market_count_raw == 0)
            {
                return Err(SessionStateError::NonCanonical {
                    field: "market scope tag and count disagree",
                });
            }
            let market_count = Self::add_count(
                &mut shape.markets,
                market_count_raw,
                "total session markets",
                limits.max_total_markets,
            )?;
            let remaining_sessions = session_count - index - 1;
            reader.require(Self::checked_required_bytes(
                market_count,
                4,
                remaining_sessions,
                SESSION_TAIL_AFTER_MARKET_COUNT,
            )?)?;

            let mut previous_market = None;
            for _ in 0..market_count {
                let market = reader.u32()?;
                if previous_market.is_some_and(|previous| market <= previous) {
                    return Err(SessionStateError::NonCanonical {
                        field: "explicit session markets must be strictly ascending",
                    });
                }
                previous_market = Some(market);
            }

            if reader.i128()? < 0 {
                return Err(SessionStateError::InvalidValue {
                    field: "session maximum notional must be nonnegative",
                });
            }
            let _expires_at = reader.u64()?;
            let nonce_start = reader.u64()?;
            let nonce_end = reader.u64()?;
            if nonce_start > nonce_end {
                return Err(SessionStateError::InvalidValue {
                    field: "session nonce range must be ordered",
                });
            }

            let consumed_count_raw = reader.u64()?;
            Self::check_limit(
                "consumed nonces per session",
                consumed_count_raw,
                limits.max_consumed_nonces_per_session,
            )?;
            let nonce_span = u128::from(nonce_end) - u128::from(nonce_start) + 1;
            if u128::from(consumed_count_raw) > nonce_span {
                return Err(SessionStateError::InvalidValue {
                    field: "consumed nonce count exceeds the authorized range",
                });
            }
            let consumed_count = Self::add_count(
                &mut shape.consumed_nonces,
                consumed_count_raw,
                "total consumed nonces",
                limits.max_total_consumed_nonces,
            )?;
            reader.require(Self::checked_required_bytes(
                consumed_count,
                8,
                remaining_sessions,
                0,
            )?)?;

            let mut previous_nonce = None;
            for _ in 0..consumed_count {
                let nonce = reader.u64()?;
                if !(nonce_start..=nonce_end).contains(&nonce) {
                    return Err(SessionStateError::InvalidValue {
                        field: "consumed nonce must lie inside the authorized range",
                    });
                }
                if previous_nonce.is_some_and(|previous| nonce <= previous) {
                    return Err(SessionStateError::NonCanonical {
                        field: "consumed nonces must be strictly ascending",
                    });
                }
                previous_nonce = Some(nonce);
            }
        }

        reader.finish()?;
        if shape.encoded_len()? != bytes.len() {
            return Err(SessionStateError::NonCanonical {
                field: "fixed-width v1 image length does not match declared counts",
            });
        }
        Ok(shape)
    }

    fn restore_state_v1(
        bytes: &[u8],
        scanned: SessionStateShape,
    ) -> Result<Self, SessionStateError> {
        let mut reader = StateReader::new(bytes);
        let _version = reader.u16()?;
        let session_count = Self::u64_as_usize("sessions", reader.u64()?)?;
        debug_assert_eq!(session_count, scanned.sessions);

        let mut sessions = HashMap::new();
        sessions
            .try_reserve(session_count)
            .map_err(|_| SessionStateError::AllocationFailed {
                resource: "session registry",
            })?;
        for _ in 0..session_count {
            let account = reader.u32()?;
            let session_key = reader.key()?;
            let _scope_tag = reader.u8()?;
            let market_count = Self::u64_as_usize("markets per session", reader.u64()?)?;
            let mut allowed_markets = Vec::new();
            allowed_markets
                .try_reserve_exact(market_count)
                .map_err(|_| SessionStateError::AllocationFailed {
                    resource: "session markets",
                })?;
            for _ in 0..market_count {
                allowed_markets.push(MarketId::new(reader.u32()?));
            }

            let max_notional = Amount::from_raw(reader.i128()?);
            let expires_at = reader.u64()?;
            let nonce_start = reader.u64()?;
            let nonce_end = reader.u64()?;
            let consumed_count = Self::u64_as_usize("consumed nonces per session", reader.u64()?)?;
            let mut consumed = HashSet::new();
            consumed.try_reserve(consumed_count).map_err(|_| {
                SessionStateError::AllocationFailed {
                    resource: "consumed nonces",
                }
            })?;
            for _ in 0..consumed_count {
                if !consumed.insert(reader.u64()?) {
                    return Err(SessionStateError::NonCanonical {
                        field: "consumed nonces must be unique",
                    });
                }
            }

            let replaced = sessions.insert(
                (account, session_key),
                Session {
                    allowed_markets,
                    max_notional,
                    expires_at,
                    nonce_start,
                    nonce_end,
                    consumed,
                },
            );
            if replaced.is_some() {
                return Err(SessionStateError::NonCanonical {
                    field: "session keys must be unique",
                });
            }
        }
        reader.finish()?;

        let rebuilt = Self { sessions };
        rebuilt.validate_state_v1()?;
        Ok(rebuilt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_and_aggregate_arithmetic_overflow_is_typed() {
        assert!(matches!(
            SessionStateShape {
                sessions: usize::MAX,
                ..SessionStateShape::default()
            }
            .encoded_len(),
            Err(SessionStateError::ArithmeticOverflow { .. })
        ));

        let mut total = usize::MAX;
        assert!(matches!(
            SessionRegistry::add_count(&mut total, 1, "test aggregate", usize::MAX,),
            Err(SessionStateError::ArithmeticOverflow {
                field: "test aggregate"
            })
        ));
    }
}
