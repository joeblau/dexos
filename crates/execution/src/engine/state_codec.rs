//! Canonical, bounded Engine v1 state encoding.
//!
//! The image composes the complete canonical bytes of every child transition
//! machine with the Engine-owned maps and sidecars. It is intentionally a
//! one-way artifact for now: authentication, freshness, persistence, and direct
//! restoration belong to later checkpoint layers.

use std::collections::{HashMap, HashSet};
use std::hash::Hash as StdHash;

use types::Hash;

use super::{
    market_lifecycle_tag, market_type_tag, oracle_health_tag, side_tag, Engine, EngineStateError,
    ENGINE_STATE_SCHEMA_VERSION,
};
use crate::error::ExecutionError;

struct StateWriter {
    bytes: Vec<u8>,
}

impl StateWriter {
    fn try_with_capacity(capacity: usize) -> Result<Self, EngineStateError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| EngineStateError::Allocation {
                resource: "encoded Engine bytes",
            })?;
        Ok(Self { bytes })
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

    fn i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn hash(&mut self, value: Hash) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn len(&mut self, field: &'static str, value: usize) -> Result<(), EngineStateError> {
        self.u64(usize_as_u64(field, value)?);
        Ok(())
    }

    fn length_prefixed(
        &mut self,
        field: &'static str,
        value: &[u8],
    ) -> Result<(), EngineStateError> {
        self.len(field, value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}

struct BookImage {
    market: u32,
    instrument: u16,
    bytes: Vec<u8>,
}

struct ChildImages {
    ledger: Vec<u8>,
    sessions: Vec<u8>,
    risk: Vec<u8>,
    replay: Vec<u8>,
    books: Vec<BookImage>,
}

fn usize_as_u64(field: &'static str, value: usize) -> Result<u64, EngineStateError> {
    u64::try_from(value).map_err(|_| EngineStateError::NativeWidth { field, value })
}

fn add_len(total: &mut usize, amount: usize, field: &'static str) -> Result<(), EngineStateError> {
    *total = total
        .checked_add(amount)
        .ok_or(EngineStateError::ArithmeticOverflow { field })?;
    Ok(())
}

fn add_repeated_len(
    total: &mut usize,
    count: usize,
    width: usize,
    field: &'static str,
) -> Result<(), EngineStateError> {
    usize_as_u64(field, count)?;
    let amount = count
        .checked_mul(width)
        .ok_or(EngineStateError::ArithmeticOverflow { field })?;
    add_len(total, amount, field)
}

fn enforce_image_bound(required_at_least: usize, max: usize) -> Result<(), EngineStateError> {
    if required_at_least > max {
        Err(EngineStateError::EncodedBytesLimit {
            required_at_least,
            max,
        })
    } else {
        Ok(())
    }
}

fn retain_child_len(
    encoded_len: &mut usize,
    child_len: usize,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), EngineStateError> {
    usize_as_u64(field, child_len)?;
    add_len(encoded_len, child_len, field)?;
    enforce_image_bound(*encoded_len, max_bytes)
}

fn sorted_copy_keys<K, V>(
    map: &HashMap<K, V>,
    resource: &'static str,
) -> Result<Vec<K>, EngineStateError>
where
    K: Copy + Eq + Ord + StdHash,
{
    let mut keys = Vec::new();
    keys.try_reserve_exact(map.len())
        .map_err(|_| EngineStateError::Allocation { resource })?;
    keys.extend(map.keys().copied());
    keys.sort_unstable();
    Ok(keys)
}

fn sorted_set_refs<'a, K>(
    set: &'a HashSet<K>,
    resource: &'static str,
) -> Result<Vec<&'a K>, EngineStateError>
where
    K: Eq + Ord + StdHash,
{
    let mut values = Vec::new();
    values
        .try_reserve_exact(set.len())
        .map_err(|_| EngineStateError::Allocation { resource })?;
    values.extend(set.iter());
    values.sort_unstable();
    Ok(values)
}

impl Engine {
    /// Encode the complete canonical Engine v1 state under an independent byte
    /// bound.
    ///
    /// The image contains every value committed by [`Self::transition_root_v1`]
    /// and embeds that root as a completeness assertion for a future restore
    /// path. It stores complete canonical child images rather than roots alone.
    /// Hash-map layout, COW/allocator representation, the worker-local matching
    /// backend, leaf scratch, Merkle node arrays, and the optional StateTree root
    /// cache are deliberately excluded.
    ///
    /// Encoding first validates the complete source Engine. Non-child framing
    /// is sized before any child image is retained, cumulative child bytes are
    /// rejected as soon as they cross `max_bytes`, and only an accepted image
    /// proceeds to transition-root computation and final assembly. The exact
    /// accepted size is checked before the outer output buffer is allocated.
    ///
    /// `max_bytes` bounds the returned image length, not peak process memory.
    /// During root computation and final assembly, the retained child images
    /// coexist with one current child preimage or the exact output buffer, so
    /// canonical buffers can approach twice the accepted image size, excluding
    /// allocator slack, sorting storage, validation workspace, and child-codec
    /// internals. This is not a hostile-decoder or process-OOM safety claim.
    /// The API also does not authenticate the bytes, establish checkpoint
    /// freshness, persist the image, or make it safe to restore; those remain
    /// separate future layers.
    pub fn encode_state_v1_bounded(&self, max_bytes: usize) -> Result<Vec<u8>, EngineStateError> {
        self.validate_recovery_invariants()?;
        let book_keys = sorted_copy_keys(&self.books, "sorted book keys")?;
        let non_child_len = self.encoded_state_non_child_len_v1(book_keys.len())?;
        enforce_image_bound(non_child_len, max_bytes)?;
        let (children, encoded_len) =
            self.encode_child_images_v1(max_bytes, non_child_len, book_keys)?;
        // Compute the independently established completeness root only after
        // every canonical child image has fit the caller's cumulative bound.
        // The existing root path may re-encode one child at a time, but it can
        // no longer materialize a child larger than an already-accepted image.
        let source_transition_root = self.transition_root_v1()?;

        let market_ids = sorted_copy_keys(&self.markets, "sorted market keys")?;
        let reserve_keys = sorted_copy_keys(&self.order_reserves, "sorted reserve keys")?;
        let claim_accounts = sorted_copy_keys(&self.claims, "sorted claim-account keys")?;
        let claim_escrow_keys = sorted_copy_keys(&self.claim_escrows, "sorted claim-escrow keys")?;
        let mint_keys = sorted_copy_keys(&self.mint_locked, "sorted mint-lock keys")?;
        let deposits = sorted_set_refs(&self.deposits_seen, "sorted deposit keys")?;
        let withdrawal_ids = sorted_copy_keys(&self.withdrawals, "sorted withdrawal keys")?;
        let wallet_accounts = sorted_copy_keys(&self.wallets, "sorted wallet keys")?;

        let mut writer = StateWriter::try_with_capacity(encoded_len)?;
        writer.u16(ENGINE_STATE_SCHEMA_VERSION);
        writer.hash(source_transition_root);
        writer.u16(self.protocol_version);
        match self.last_seq {
            Some(sequence) => {
                writer.u8(1);
                writer.u64(sequence);
            }
            None => {
                writer.u8(0);
                writer.u64(0);
            }
        }
        writer.len("account tree capacity", self.tree.account_capacity())?;
        writer.len("market tree capacity", self.tree.market_capacity())?;

        writer.length_prefixed("Ledger child bytes", &children.ledger)?;
        writer.length_prefixed("SessionRegistry child bytes", &children.sessions)?;
        writer.length_prefixed("RiskEngine child bytes", &children.risk)?;
        writer.length_prefixed("ReplayGuard child bytes", &children.replay)?;

        writer.len("markets", market_ids.len())?;
        for market_id in market_ids {
            let market = self.markets.get(&market_id).ok_or({
                EngineStateError::InvalidEngine(ExecutionError::StateInvariant(
                    "market disappeared during immutable Engine encoding",
                ))
            })?;
            writer.u32(market_id);
            writer.u8(market_type_tag(market.market_type));
            writer.u16(market.outcomes);
            writer.i64(market.mark_price.raw());
            writer.u8(market_lifecycle_tag(market.lifecycle));
            writer.u8(oracle_health_tag(market.oracle_health));
            writer.i32(market.maker_fee_bps);
            writer.i32(market.taker_fee_bps);
            writer.u64(market.last_funding_epoch);
            match market.winning_outcome {
                Some(winner) => {
                    writer.u8(1);
                    writer.u16(winner);
                }
                None => {
                    writer.u8(0);
                    writer.u16(0);
                }
            }
        }

        writer.len("books", children.books.len())?;
        for book in &children.books {
            writer.u32(book.market);
            writer.u16(book.instrument);
            writer.length_prefixed("OrderBook child bytes", &book.bytes)?;
        }

        writer.len("order reserves", reserve_keys.len())?;
        for (market, instrument, order_id) in reserve_keys {
            let reserve = self
                .order_reserves
                .get(&(market, instrument, order_id))
                .ok_or({
                    EngineStateError::InvalidEngine(ExecutionError::StateInvariant(
                        "order reserve disappeared during immutable Engine encoding",
                    ))
                })?;
            writer.u32(market);
            writer.u16(instrument);
            writer.u64(order_id);
            writer.u32(reserve.account.get());
            writer.i128(reserve.reserved.raw());
            writer.i64(reserve.qty_remaining.raw());
        }

        writer.len("claim accounts", claim_accounts.len())?;
        for account in claim_accounts {
            let markets = self.claims.get(&account).ok_or({
                EngineStateError::InvalidEngine(ExecutionError::StateInvariant(
                    "claim account disappeared during immutable Engine encoding",
                ))
            })?;
            writer.u32(account);
            writer.len("claim markets", markets.len())?;
            for (&market, balances) in markets {
                writer.u32(market);
                writer.len("claim balance values", balances.len())?;
                for balance in balances {
                    writer.i128(balance.raw());
                }
            }
        }

        writer.len("bid premium escrows", self.bid_premium_escrow.len())?;
        for (&(account, market), amount) in self.bid_premium_escrow.iter() {
            writer.u32(account);
            writer.u32(market);
            writer.i128(amount.raw());
        }

        writer.len("ask claim escrows", self.ask_claims_escrow.len())?;
        for (&(account, market, instrument), amount) in self.ask_claims_escrow.iter() {
            writer.u32(account);
            writer.u32(market);
            writer.u16(instrument);
            writer.i128(amount.raw());
        }

        writer.len("claim-order escrows", claim_escrow_keys.len())?;
        for (market, instrument, order_id) in claim_escrow_keys {
            let escrow = self
                .claim_escrows
                .get(&(market, instrument, order_id))
                .ok_or({
                    EngineStateError::InvalidEngine(ExecutionError::StateInvariant(
                        "claim-order escrow disappeared during immutable Engine encoding",
                    ))
                })?;
            writer.u32(market);
            writer.u16(instrument);
            writer.u64(order_id);
            writer.u32(escrow.account.get());
            writer.u8(side_tag(escrow.side));
            writer.i128(escrow.premium.raw());
            writer.i128(escrow.claims.raw());
        }

        writer.len("mint locks", mint_keys.len())?;
        for (account, market) in mint_keys {
            let amount = self.mint_locked.get(&(account, market)).ok_or({
                EngineStateError::InvalidEngine(ExecutionError::StateInvariant(
                    "mint lock disappeared during immutable Engine encoding",
                ))
            })?;
            writer.u32(account);
            writer.u32(market);
            writer.i128(amount.raw());
        }

        writer.len("deposit keys", deposits.len())?;
        for deposit in deposits {
            writer.u32(deposit.0);
            writer.length_prefixed("deposit transaction bytes", &deposit.1)?;
            writer.u32(deposit.2);
        }

        writer.len("withdrawals", withdrawal_ids.len())?;
        for withdrawal_id in withdrawal_ids {
            let withdrawal = self.withdrawals.get(&withdrawal_id).ok_or({
                EngineStateError::InvalidEngine(ExecutionError::StateInvariant(
                    "withdrawal disappeared during immutable Engine encoding",
                ))
            })?;
            writer.u64(withdrawal_id);
            writer.u32(withdrawal.account.get());
            writer.i128(withdrawal.amount.raw());
            writer.bool(withdrawal.finalized);
        }

        writer.len("wallet bindings", wallet_accounts.len())?;
        for account in wallet_accounts {
            let wallet = self.wallets.get(&account).ok_or({
                EngineStateError::InvalidEngine(ExecutionError::StateInvariant(
                    "wallet binding disappeared during immutable Engine encoding",
                ))
            })?;
            writer.u32(account);
            writer.u32(wallet.chain_id);
            writer.length_prefixed("wallet address bytes", &wallet.address)?;
        }

        if writer.bytes.len() != encoded_len {
            return Err(EngineStateError::EncodingSizeMismatch {
                expected: encoded_len,
                actual: writer.bytes.len(),
            });
        }
        Ok(writer.bytes)
    }

    fn encode_child_images_v1(
        &self,
        max_bytes: usize,
        mut encoded_len: usize,
        book_keys: Vec<(u32, u16)>,
    ) -> Result<(ChildImages, usize), EngineStateError> {
        let ledger = self.ledger.encode_state_v1_bounded(max_bytes)?;
        retain_child_len(
            &mut encoded_len,
            ledger.len(),
            "Ledger child bytes",
            max_bytes,
        )?;
        let sessions = self.sessions.encode_state_v1_bounded(max_bytes)?;
        retain_child_len(
            &mut encoded_len,
            sessions.len(),
            "SessionRegistry child bytes",
            max_bytes,
        )?;
        let risk = self.risk.encode_state_v1_bounded(max_bytes)?;
        retain_child_len(
            &mut encoded_len,
            risk.len(),
            "RiskEngine child bytes",
            max_bytes,
        )?;
        let replay = self.replay.encode_state_v1_bounded(max_bytes)?;
        retain_child_len(
            &mut encoded_len,
            replay.len(),
            "ReplayGuard child bytes",
            max_bytes,
        )?;

        let mut books = Vec::new();
        books
            .try_reserve_exact(book_keys.len())
            .map_err(|_| EngineStateError::Allocation {
                resource: "encoded OrderBook child images",
            })?;
        for (market, instrument) in book_keys {
            let book = self.books.get(&(market, instrument)).ok_or({
                EngineStateError::InvalidEngine(ExecutionError::StateInvariant(
                    "book disappeared during immutable Engine encoding",
                ))
            })?;
            let bytes = book.encode_state_v3_bounded(max_bytes).map_err(|source| {
                EngineStateError::Book {
                    market,
                    instrument,
                    source,
                }
            })?;
            retain_child_len(
                &mut encoded_len,
                bytes.len(),
                "OrderBook child bytes",
                max_bytes,
            )?;
            books.push(BookImage {
                market,
                instrument,
                bytes,
            });
        }
        Ok((
            ChildImages {
                ledger,
                sessions,
                risk,
                replay,
                books,
            },
            encoded_len,
        ))
    }

    fn encoded_state_non_child_len_v1(&self, book_count: usize) -> Result<usize, EngineStateError> {
        let mut encoded_len = 0usize;

        // version + source transition root + protocol + last-sequence option
        // + exact account/market tree capacities.
        add_len(&mut encoded_len, 2 + 32 + 2 + 1 + 8 + 8 + 8, "fixed header")?;
        // Four child-image length prefixes; their bytes are added only as each
        // image is successfully produced under the cumulative bound.
        add_len(&mut encoded_len, 4 * 8, "child-image framing")?;

        add_len(&mut encoded_len, 8, "market count")?;
        add_repeated_len(&mut encoded_len, self.markets.len(), 36, "markets")?;

        add_len(&mut encoded_len, 8, "book count")?;
        add_repeated_len(&mut encoded_len, book_count, 4 + 2 + 8, "book framing")?;

        add_len(&mut encoded_len, 8, "order-reserve count")?;
        add_repeated_len(
            &mut encoded_len,
            self.order_reserves.len(),
            42,
            "order reserves",
        )?;

        add_len(&mut encoded_len, 8, "claim-account count")?;
        usize_as_u64("claim accounts", self.claims.len())?;
        for markets in self.claims.values() {
            add_len(&mut encoded_len, 4 + 8, "claim account")?;
            usize_as_u64("claim markets", markets.len())?;
            for balances in markets.values() {
                add_len(&mut encoded_len, 4 + 8, "claim market")?;
                add_repeated_len(&mut encoded_len, balances.len(), 16, "claim balance values")?;
            }
        }

        add_len(&mut encoded_len, 8, "bid-premium-escrow count")?;
        add_repeated_len(
            &mut encoded_len,
            self.bid_premium_escrow.len(),
            24,
            "bid premium escrows",
        )?;
        add_len(&mut encoded_len, 8, "ask-claim-escrow count")?;
        add_repeated_len(
            &mut encoded_len,
            self.ask_claims_escrow.len(),
            26,
            "ask claim escrows",
        )?;
        add_len(&mut encoded_len, 8, "claim-order-escrow count")?;
        add_repeated_len(
            &mut encoded_len,
            self.claim_escrows.len(),
            51,
            "claim-order escrows",
        )?;
        add_len(&mut encoded_len, 8, "mint-lock count")?;
        add_repeated_len(&mut encoded_len, self.mint_locked.len(), 24, "mint locks")?;

        add_len(&mut encoded_len, 8, "deposit-key count")?;
        usize_as_u64("deposit keys", self.deposits_seen.len())?;
        for (_, source_tx, _) in self.deposits_seen.iter() {
            usize_as_u64("deposit transaction bytes", source_tx.len())?;
            add_len(&mut encoded_len, 4 + 8, "deposit key framing")?;
            add_len(
                &mut encoded_len,
                source_tx.len(),
                "deposit transaction bytes",
            )?;
            add_len(&mut encoded_len, 4, "deposit event index")?;
        }

        add_len(&mut encoded_len, 8, "withdrawal count")?;
        add_repeated_len(&mut encoded_len, self.withdrawals.len(), 29, "withdrawals")?;

        add_len(&mut encoded_len, 8, "wallet-binding count")?;
        usize_as_u64("wallet bindings", self.wallets.len())?;
        for wallet in self.wallets.values() {
            usize_as_u64("wallet address bytes", wallet.address.len())?;
            add_len(&mut encoded_len, 4 + 4 + 8, "wallet framing")?;
            add_len(
                &mut encoded_len,
                wallet.address.len(),
                "wallet address bytes",
            )?;
        }

        Ok(encoded_len)
    }
}
