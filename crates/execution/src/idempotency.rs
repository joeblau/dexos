//! Durable, payload-bound command idempotency: exactly-once command retries.
//!
//! Command-level deduplication runs *before* any subsystem mutation. Each
//! idempotency-carrying command binds an authenticated principal and a monotonic
//! key — an order `client_id` or a withdrawal `nonce` — to the *canonical
//! digest* of the command's payload and to the receipt the command produced. A
//! retry is resolved as one of:
//!
//! * [`GuardDecision::Replay`] — a byte-identical retry: the original receipt is
//!   returned and no delta is re-applied;
//! * [`GuardDecision::Conflict`] — the same key with a different payload;
//! * [`GuardDecision::Expired`] — the key was already processed but its receipt
//!   has aged out of the bounded window, so it can neither be replayed nor
//!   safely re-executed;
//! * [`GuardDecision::Fresh`] — a new key that advances the principal's
//!   high-water mark.
//!
//! Exactly-once survives both a bounded cache and a process restart. The
//! per-principal high-water mark is committed into the legacy account leaf,
//! while canonical EngineState v1 additionally commits the window, retained
//! receipts, and exact FIFO eviction order because they change retry results and
//! whether a retry consumes the next sequence. Because keys are monotonic per
//! principal per domain, an evicted key is still recognised as already-processed
//! by the watermark and can never execute a second time.

use std::collections::{HashMap, HashSet, VecDeque};

use state_tree::LeafWriter;
use types::{Hash, OrderType, Side, TimeInForce};

use crate::command::{Command, ExecutionReceipt, PlaceOrder, ReceiptKind, RequestWithdrawal};
use crate::error::ExecutionError;

// The standalone decoder remains staged for the future outer Engine restore
// path. The encoder is now composed by EngineState v1, while decode-only items
// remain exercised by this module's tests.
#[allow(dead_code)]
mod state;
#[allow(dead_code)]
mod state_codec;

pub use state::ReplayStateError;
pub(crate) use state::ReplayStateLimits;

/// Canonical complete replay-guard transition-root schema.
pub const REPLAY_TRANSITION_ROOT_SCHEMA_VERSION: u16 = 1;

#[derive(Default)]
struct ReplayTransitionWriter {
    bytes: Vec<u8>,
}

impl ReplayTransitionWriter {
    fn try_with_capacity(capacity: usize) -> Result<Self, ReplayStateError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ReplayStateError::Allocation {
                resource: "encoded bytes",
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

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn hash(&mut self, value: Hash) {
        self.bytes.extend_from_slice(value.as_bytes());
    }
}

enum ReplayLocalValidationError {
    Invariant(&'static str),
    Allocation(&'static str),
}

/// Idempotency key domain. Order `client_id`s and withdrawal `nonce`s occupy
/// separate key spaces per principal and can never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyDomain {
    /// A [`PlaceOrder`] keyed by `client_id`.
    Order,
    /// A [`RequestWithdrawal`] keyed by `nonce`.
    Withdrawal,
}

impl KeyDomain {
    /// Stable one-byte tag mixed into keys and digests.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            KeyDomain::Order => 0,
            KeyDomain::Withdrawal => 1,
        }
    }
}

/// The idempotency binding a command carries: the principal/domain/key it
/// commits to plus the canonical digest of its payload.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyBinding {
    /// Authenticated principal (the acting account id).
    pub(crate) principal: u32,
    /// Key namespace.
    pub(crate) domain: KeyDomain,
    /// The monotonic idempotency key (`client_id` or `nonce`).
    pub(crate) key: u64,
    /// Canonical digest binding the key to the full command payload.
    pub(crate) digest: Hash,
}

/// What the guard decided for a bound command.
#[derive(Debug, Clone)]
pub(crate) enum GuardDecision {
    /// A brand-new key: proceed, then [`ReplayGuard::finalize`] the receipt.
    Fresh,
    /// A byte-identical retry: return this receipt without re-applying.
    Replay(ExecutionReceipt),
    /// The same key was seen with a different payload.
    Conflict,
    /// The key was processed but its receipt aged out of the bounded window.
    Expired,
}

type Slot = (u32, u8, u64);

/// A durable, bounded, payload-bound command-idempotency guard.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReplayGuard {
    /// Maximum number of `(key -> receipt)` records retained for exact replay.
    window: usize,
    /// Highest key committed per `(principal, domain)`. Folded into the state
    /// root via the account leaf, so it survives snapshot/WAL recovery.
    watermark: HashMap<(u32, u8), u64>,
    /// Bounded FIFO cache of recent `(digest, receipt)` for exact replay.
    records: HashMap<Slot, (Hash, ExecutionReceipt)>,
    /// Insertion order backing deterministic FIFO eviction of `records`. Both
    /// representations are part of canonical EngineState transition state.
    order: VecDeque<Slot>,
}

impl ReplayGuard {
    /// A guard retaining at most `window` recent receipts. A zero window still
    /// enforces exactly-once via the watermark, but cannot replay original
    /// receipts (every retry of a processed key becomes [`GuardDecision::Expired`]).
    pub(crate) fn with_window(window: usize) -> Self {
        Self {
            window,
            watermark: HashMap::new(),
            records: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Classify a bound command without mutating any state.
    pub(crate) fn classify(&self, b: &KeyBinding) -> GuardDecision {
        let slot = (b.principal, b.domain.tag(), b.key);
        if let Some((digest, receipt)) = self.records.get(&slot) {
            return if *digest == b.digest {
                GuardDecision::Replay(receipt.clone())
            } else {
                GuardDecision::Conflict
            };
        }
        if self
            .watermark
            .get(&(b.principal, b.domain.tag()))
            .is_some_and(|&hwm| b.key <= hwm)
        {
            return GuardDecision::Expired;
        }
        GuardDecision::Fresh
    }

    /// Advance the committed high-water mark for a fresh key *before* the command
    /// mutates any subsystem. Reserving up front (rather than after `apply`)
    /// folds the watermark into the same commit as the command's own effects, so
    /// the receipt's state root already reflects it.
    pub(crate) fn reserve(&mut self, b: &KeyBinding) {
        self.watermark
            .entry((b.principal, b.domain.tag()))
            .and_modify(|h| {
                if b.key > *h {
                    *h = b.key;
                }
            })
            .or_insert(b.key);
    }

    /// Restore the watermark captured immediately before [`Self::reserve`].
    /// Used only by the execution engine's bounded in-place undo journal.
    pub(crate) fn restore_reservation(&mut self, b: &KeyBinding, previous: Option<u64>) {
        let key = (b.principal, b.domain.tag());
        match previous {
            Some(value) => {
                self.watermark.insert(key, value);
            }
            None => {
                self.watermark.remove(&key);
            }
        }
    }

    /// Reserve the bounded replay window in one warmup allocation rather than
    /// growing its map/deque geometrically during steady-state execution.
    pub(crate) fn prepare_window(&mut self) {
        self.records
            .reserve(self.window.saturating_sub(self.records.len()));
        self.order
            .reserve(self.window.saturating_sub(self.order.len()));
    }

    /// Record the receipt for a freshly applied key in the bounded window so an
    /// exact retry can replay it. The legacy account tree commits only the
    /// watermark, while canonical EngineState commits this cache because its
    /// presence changes retry output and sequence consumption.
    ///
    /// Only ever called after a [`GuardDecision::Fresh`] classification, so the
    /// slot is novel; a [`debug_assert`] pins that invariant.
    pub(crate) fn finalize(&mut self, b: &KeyBinding, receipt: ExecutionReceipt) {
        if self.window == 0 {
            return;
        }
        let slot = (b.principal, b.domain.tag(), b.key);
        debug_assert!(
            !self.records.contains_key(&slot),
            "finalize called for an already-recorded key",
        );
        // Evict deterministically (FIFO by insertion order) to stay within the
        // window, so identical command streams evict identically across replays.
        while self.order.len() >= self.window {
            match self.order.pop_front() {
                Some(evicted) => {
                    self.records.remove(&evicted);
                }
                None => break,
            }
        }
        self.order.push_back(slot);
        self.records.insert(slot, (b.digest, receipt));
    }

    /// The committed high-water mark for `(principal, domain)`, if any key has
    /// been processed. Used to fold the watermark into the account leaf.
    pub(crate) fn watermark(&self, principal: u32, domain: KeyDomain) -> Option<u64> {
        self.watermark.get(&(principal, domain.tag())).copied()
    }

    /// Remove one durable watermark for outer recovery-corruption tests.
    #[cfg(test)]
    pub(crate) fn remove_watermark_for_test(&mut self, principal: u32, domain: KeyDomain) {
        self.watermark.remove(&(principal, domain.tag()));
    }

    /// Canonical commitment to the complete replay guard, including the exact
    /// result-affecting receipt window and FIFO eviction order.
    pub(crate) fn transition_root_v1(&self) -> Result<Hash, ExecutionError> {
        let bytes = self.encode_state_v1_for_transition_root()?;
        Ok(crypto::hash_domain(
            crypto::DOMAIN_EXECUTION_REPLAY_STATE,
            &bytes,
        ))
    }

    /// Validate replay relations that require authoritative engine context and
    /// therefore cannot be checked by the guard in isolation.
    pub(crate) fn validate_engine_context(
        &self,
        account_count: usize,
        last_sequence: Option<u64>,
    ) -> Result<(), ExecutionError> {
        if self.watermark.keys().any(|&(principal, _)| {
            usize::try_from(principal).map_or(true, |index| index >= account_count)
        }) {
            return Err(ExecutionError::StateInvariant(
                "replay principal does not reference an existing ledger account",
            ));
        }
        if !self.watermark.is_empty() && last_sequence.is_none() {
            return Err(ExecutionError::StateInvariant(
                "replay state exists without a consumed engine sequence",
            ));
        }
        if let Some(last_sequence) = last_sequence {
            if self
                .records
                .values()
                .any(|(_, receipt)| receipt.sequence > last_sequence)
            {
                return Err(ExecutionError::StateInvariant(
                    "replay receipt sequence exceeds the engine sequence",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_transition_invariants(&self) -> Result<(), ExecutionError> {
        self.validate_local_invariants()
            .map_err(|error| match error {
                ReplayLocalValidationError::Invariant(message) => {
                    ExecutionError::StateInvariant(message)
                }
                ReplayLocalValidationError::Allocation(_resource) => {
                    ExecutionError::StateInvariant(
                        "replay transition-state validation allocation failed",
                    )
                }
            })
    }

    fn validate_local_invariants(&self) -> Result<(), ReplayLocalValidationError> {
        if self.records.len() > self.window {
            return Err(ReplayLocalValidationError::Invariant(
                "replay records exceed the configured window",
            ));
        }
        if self.order.len() != self.records.len() {
            return Err(ReplayLocalValidationError::Invariant(
                "replay FIFO and record map have different lengths",
            ));
        }

        let known_domain =
            |domain| domain == KeyDomain::Order.tag() || domain == KeyDomain::Withdrawal.tag();
        for &(_, domain) in self.watermark.keys() {
            if !known_domain(domain) {
                return Err(ReplayLocalValidationError::Invariant(
                    "replay watermark has an unknown key domain",
                ));
            }
        }

        let mut ordered = HashSet::new();
        ordered
            .try_reserve(self.order.len())
            .map_err(|_| ReplayLocalValidationError::Allocation("replay FIFO validation set"))?;
        let mut previous_sequence = None;
        let mut previous_key = HashMap::new();
        previous_key
            .try_reserve(self.order.len())
            .map_err(|_| ReplayLocalValidationError::Allocation("replay key validation map"))?;
        for &slot @ (principal, domain, key) in &self.order {
            if !known_domain(domain) {
                return Err(ReplayLocalValidationError::Invariant(
                    "replay FIFO has an unknown key domain",
                ));
            }
            if !ordered.insert(slot) {
                return Err(ReplayLocalValidationError::Invariant(
                    "replay FIFO contains a duplicate slot",
                ));
            }
            let (_, receipt) =
                self.records
                    .get(&slot)
                    .ok_or(ReplayLocalValidationError::Invariant(
                        "replay FIFO references a missing record",
                    ))?;
            if self
                .watermark
                .get(&(principal, domain))
                .is_none_or(|watermark| *watermark < key)
            {
                return Err(ReplayLocalValidationError::Invariant(
                    "replay record exceeds its durable watermark",
                ));
            }
            if previous_sequence.is_some_and(|previous| receipt.sequence <= previous) {
                return Err(ReplayLocalValidationError::Invariant(
                    "replay FIFO receipts are not strictly sequence ordered",
                ));
            }
            previous_sequence = Some(receipt.sequence);
            if previous_key
                .insert((principal, domain), key)
                .is_some_and(|previous| key <= previous)
            {
                return Err(ReplayLocalValidationError::Invariant(
                    "replay FIFO keys are not strictly increasing per principal and domain",
                ));
            }

            match (domain, &receipt.kind) {
                (domain, ReceiptKind::OrderApplied { filled, .. })
                    if domain == KeyDomain::Order.tag() =>
                {
                    if filled.raw() < 0 {
                        return Err(ReplayLocalValidationError::Invariant(
                            "replay order receipt has a negative filled quantity",
                        ));
                    }
                }
                (domain, ReceiptKind::WithdrawalRequested(withdrawal_id))
                    if domain == KeyDomain::Withdrawal.tag() =>
                {
                    if *withdrawal_id != derive_withdrawal_id(principal, key) {
                        return Err(ReplayLocalValidationError::Invariant(
                            "replay withdrawal receipt id does not match its command key",
                        ));
                    }
                }
                (domain, _) if domain == KeyDomain::Order.tag() => {
                    return Err(ReplayLocalValidationError::Invariant(
                        "replay order key has a non-order receipt",
                    ));
                }
                (domain, _) if domain == KeyDomain::Withdrawal.tag() => {
                    return Err(ReplayLocalValidationError::Invariant(
                        "replay withdrawal key has a non-withdrawal receipt",
                    ));
                }
                _ => unreachable!("known replay domain checked above"),
            }
        }
        if self.records.keys().any(|slot| !ordered.contains(slot)) {
            return Err(ReplayLocalValidationError::Invariant(
                "replay record map contains a slot missing from FIFO order",
            ));
        }
        Ok(())
    }

    /// Retained withdrawal requests whose provenance is still reconstructible
    /// from the bounded receipt window. Evicted requests remain protected by a
    /// watermark but intentionally cannot be reverse-mapped to a withdrawal id
    /// without adding request provenance to a later state schema.
    pub(crate) fn retained_withdrawal_requests(
        &self,
    ) -> impl Iterator<Item = (u32, u64, u64)> + '_ {
        self.records
            .iter()
            .filter_map(
                |(&(principal, domain, key), (_, receipt))| match &receipt.kind {
                    ReceiptKind::WithdrawalRequested(withdrawal_id)
                        if domain == KeyDomain::Withdrawal.tag() =>
                    {
                        Some((principal, key, *withdrawal_id))
                    }
                    _ => None,
                },
            )
    }

    fn write_receipt(writer: &mut ReplayTransitionWriter, receipt: &ExecutionReceipt) {
        writer.u64(receipt.sequence);
        match &receipt.kind {
            ReceiptKind::AccountCreated(account) => {
                writer.u8(0);
                writer.u32(account.get());
            }
            ReceiptKind::Credited(account, amount) => {
                writer.u8(1);
                writer.u32(account.get());
                writer.i128(amount.raw());
            }
            ReceiptKind::WithdrawalRequested(withdrawal_id) => {
                writer.u8(2);
                writer.u64(*withdrawal_id);
            }
            ReceiptKind::WithdrawalFinalized(withdrawal_id) => {
                writer.u8(3);
                writer.u64(*withdrawal_id);
            }
            ReceiptKind::SessionUpdated => writer.u8(4),
            ReceiptKind::MarketUpdated(market) => {
                writer.u8(5);
                writer.u32(market.get());
            }
            ReceiptKind::OrderApplied { filled, rested } => {
                writer.u8(6);
                writer.i64(filled.raw());
                writer.bool(*rested);
            }
            ReceiptKind::Cancelled(count) => {
                writer.u8(7);
                writer.u32(*count);
            }
            ReceiptKind::CompleteSet(amount) => {
                writer.u8(8);
                writer.i128(amount.raw());
            }
            ReceiptKind::WalletBound => writer.u8(9),
            ReceiptKind::ProtocolUpgraded(version) => {
                writer.u8(10);
                writer.u16(*version);
            }
            ReceiptKind::Liquidated {
                account,
                insurance_drawn,
                socialized_loss,
            } => {
                writer.u8(11);
                writer.u32(account.get());
                writer.i128(insurance_drawn.raw());
                writer.i128(socialized_loss.raw());
            }
            ReceiptKind::FundingApplied { market, epoch } => {
                writer.u8(12);
                writer.u32(market.get());
                writer.u64(*epoch);
            }
            ReceiptKind::MarketResolved {
                market,
                winning_outcome,
            } => {
                writer.u8(13);
                writer.u32(market.get());
                writer.u16(*winning_outcome);
            }
            ReceiptKind::MarketSettled { market, paid } => {
                writer.u8(14);
                writer.u32(market.get());
                writer.i128(paid.raw());
            }
        }
        writer.hash(receipt.state_root);
    }

    /// Test-only cache-policy rewrite used to prove canonical EngineState binds
    /// result-affecting replay receipt material.
    #[cfg(test)]
    pub(crate) fn discard_receipt_cache_for_test(&mut self) {
        self.records.clear();
        self.order.clear();
    }
}

/// The idempotency binding for a command, or `None` for commands that carry no
/// idempotency key (their replay protection lives elsewhere: monotonic sequence,
/// deposit-certificate dedup, or natural idempotence).
pub(crate) fn command_binding(command: &Command) -> Option<KeyBinding> {
    match command {
        Command::PlaceOrder(c) => Some(KeyBinding {
            principal: c.account.get(),
            domain: KeyDomain::Order,
            key: c.client_id,
            digest: place_order_digest(c),
        }),
        Command::RequestWithdrawal(c) => Some(KeyBinding {
            principal: c.account.get(),
            domain: KeyDomain::Withdrawal,
            key: c.nonce,
            digest: withdrawal_digest(c),
        }),
        _ => None,
    }
}

/// A deterministic withdrawal id derived from the authenticated request, so an
/// exact replay resolves to the same id and the id never depends on a mutable
/// counter that a partial recovery could desynchronise. Non-wrapping by
/// construction (a truncated domain-separated digest).
pub(crate) fn derive_withdrawal_id(account: u32, nonce: u64) -> u64 {
    // Exact LeafWriter v1 bytes on the stack. This helper also runs while a
    // bounded ReplayGuard image is being validated, where an infallible heap
    // allocation would turn memory pressure into an abort instead of a typed
    // decoder error.
    let mut bytes = [0u8; 14];
    let mut at = 0usize;
    put(
        &mut bytes,
        &mut at,
        &state_tree::LEAF_ENCODING_VERSION.to_le_bytes(),
    );
    put(&mut bytes, &mut at, &account.to_le_bytes());
    put(&mut bytes, &mut at, &nonce.to_le_bytes());
    debug_assert_eq!(at, bytes.len());
    let h = crypto::hash_domain(crypto::DOMAIN_COMMAND, &bytes);
    let b = h.as_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Canonical digest over a [`PlaceOrder`]'s economically meaningful payload. The
/// authorization envelope is deliberately excluded: it carries a per-retry
/// volatile timestamp for session keys, and session replays are already blocked
/// by single-use session nonces.
fn place_order_digest(c: &PlaceOrder) -> Hash {
    // Exact LeafWriter v1 bytes, assembled on the stack. PlaceOrder has a
    // fixed-width schema, so a heap-backed generic writer on every hot command
    // is unnecessary. The golden test below pins equality to LeafWriter.
    let mut bytes = [0u8; 66];
    let mut at = 0usize;
    put(
        &mut bytes,
        &mut at,
        &state_tree::LEAF_ENCODING_VERSION.to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut at,
        &u32::from(KeyDomain::Order.tag()).to_le_bytes(),
    );
    put(&mut bytes, &mut at, &c.account.get().to_le_bytes());
    put(&mut bytes, &mut at, &c.market.get().to_le_bytes());
    put(&mut bytes, &mut at, &c.order_id.get().to_le_bytes());
    put(&mut bytes, &mut at, &side_tag(c.side).to_le_bytes());
    put(
        &mut bytes,
        &mut at,
        &order_type_tag(c.order_type).to_le_bytes(),
    );
    put(&mut bytes, &mut at, &tif_tag(c.tif).to_le_bytes());
    put(&mut bytes, &mut at, &c.price.raw().to_le_bytes());
    put(&mut bytes, &mut at, &c.quantity.raw().to_le_bytes());
    put(&mut bytes, &mut at, &c.client_id.to_le_bytes());
    put(&mut bytes, &mut at, &u32::from(c.reduce_only).to_le_bytes());
    put(&mut bytes, &mut at, &u32::from(c.instrument).to_le_bytes());
    debug_assert_eq!(at, bytes.len());
    crypto::hash_domain(crypto::DOMAIN_COMMAND, &bytes)
}

fn put<const N: usize>(out: &mut [u8; N], at: &mut usize, value: &[u8]) {
    let end = *at + value.len();
    out[*at..end].copy_from_slice(value);
    *at = end;
}

/// Canonical digest over a [`RequestWithdrawal`]'s payload. Withdrawals are
/// master-key only, so the authorization envelope carries no volatile fields and
/// is excluded for symmetry with [`place_order_digest`].
fn withdrawal_digest(c: &RequestWithdrawal) -> Hash {
    let mut w = LeafWriter::new();
    w.field_u32(u32::from(KeyDomain::Withdrawal.tag()))
        .field_u32(c.account.get())
        .field_i128(c.amount.raw())
        .field_i64(i64::from_le_bytes(c.nonce.to_le_bytes()))
        .field_u32(c.destination_chain)
        .field_bytes(&c.destination_address);
    crypto::hash_domain(crypto::DOMAIN_COMMAND, &w.finish())
}

const fn side_tag(s: Side) -> u32 {
    match s {
        Side::Bid => 0,
        Side::Ask => 1,
    }
}

const fn order_type_tag(t: OrderType) -> u32 {
    match t {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
        OrderType::ReduceOnly => 3,
    }
}

const fn tif_tag(t: TimeInForce) -> u32 {
    match t {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::ReceiptKind;
    use types::{AccountId, Amount, MarketId, Quantity};

    fn receipt(seq: u64, id: u64) -> ExecutionReceipt {
        ExecutionReceipt {
            sequence: seq,
            kind: ReceiptKind::WithdrawalRequested(id),
            state_root: Hash::ZERO,
        }
    }

    fn binding(principal: u32, key: u64, digest_byte: u8) -> KeyBinding {
        KeyBinding {
            principal,
            domain: KeyDomain::Withdrawal,
            key,
            digest: Hash::from_bytes([digest_byte; 32]),
        }
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

    fn rich_replay_guard() -> ReplayGuard {
        let mut guard = ReplayGuard::with_window(32);
        for index in 0..12_u64 {
            let principal = u32::try_from(index + 20).unwrap();
            let key = index + 100;
            let domain = if index % 2 == 0 {
                KeyDomain::Order
            } else {
                KeyDomain::Withdrawal
            };
            let binding = KeyBinding {
                principal,
                domain,
                key,
                digest: Hash::from_bytes([u8::try_from(index + 1).unwrap(); 32]),
            };
            let kind = match domain {
                KeyDomain::Order => ReceiptKind::OrderApplied {
                    filled: Quantity::from_raw(i64::try_from(index + 7).unwrap()),
                    rested: index % 4 == 0,
                },
                KeyDomain::Withdrawal => {
                    ReceiptKind::WithdrawalRequested(derive_withdrawal_id(principal, key))
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

    fn assert_invariant(guard: &ReplayGuard, message: &'static str) {
        assert_eq!(
            guard.transition_root_v1(),
            Err(ExecutionError::StateInvariant(message))
        );
    }

    fn encoded_receipt(kind: ReceiptKind) -> Vec<u8> {
        let mut writer = ReplayTransitionWriter::default();
        ReplayGuard::write_receipt(
            &mut writer,
            &ExecutionReceipt {
                sequence: 0x0102_0304_0506_0708,
                kind,
                state_root: Hash::from_bytes([0xAB; 32]),
            },
        );
        writer.bytes
    }

    fn assert_receipt_payload_bound(left: ReceiptKind, right: ReceiptKind) {
        assert_ne!(encoded_receipt(left), encoded_receipt(right));
    }

    #[test]
    fn replay_transition_root_v1_golden_vectors() {
        assert_eq!(
            ReplayGuard::with_window(0).transition_root_v1().unwrap(),
            Hash::from_bytes([
                28, 118, 249, 53, 111, 190, 171, 99, 240, 215, 58, 61, 189, 132, 99, 252, 216, 19,
                134, 165, 140, 169, 164, 4, 29, 192, 139, 214, 168, 88, 128, 1,
            ])
        );
        assert_eq!(
            rich_replay_guard().transition_root_v1().unwrap(),
            Hash::from_bytes([
                239, 112, 47, 250, 31, 166, 221, 115, 215, 52, 40, 121, 153, 78, 133, 9, 101, 91,
                9, 156, 97, 161, 184, 123, 130, 63, 168, 133, 132, 77, 176, 126,
            ])
        );
    }

    #[test]
    fn replay_transition_root_v1_binds_complete_guard_state() {
        let base = rich_replay_guard();
        let root = base.transition_root_v1().unwrap();

        let mut changed = base.clone();
        changed.window += 1;
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        *changed.watermark.values_mut().next().unwrap() += 1;
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        changed.records.get_mut(&changed.order[0]).unwrap().0 = Hash::from_bytes([0xEE; 32]);
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        let last = *changed.order.back().unwrap();
        changed.records.get_mut(&last).unwrap().1.sequence += 1;
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        let first = changed.order[0];
        let ReceiptKind::OrderApplied { filled, rested } =
            &mut changed.records.get_mut(&first).unwrap().1.kind
        else {
            panic!("first rich replay record must be an order");
        };
        *filled = Quantity::from_raw(filled.raw() + 1);
        *rested = !*rested;
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        changed
            .records
            .get_mut(&changed.order[0])
            .unwrap()
            .1
            .state_root = Hash::from_bytes([0xDD; 32]);
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        changed.records.clear();
        changed.order.clear();
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        let old_slot = changed.order[0];
        let record = changed.records.remove(&old_slot).unwrap();
        let watermark = changed.watermark.remove(&(old_slot.0, old_slot.1)).unwrap();
        let new_slot = (old_slot.0 + 1_000, old_slot.1, old_slot.2);
        changed.records.insert(new_slot, record);
        changed.order[0] = new_slot;
        changed
            .watermark
            .insert((new_slot.0, new_slot.1), watermark);
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        let old_slot = changed.order[0];
        let record = changed.records.remove(&old_slot).unwrap();
        let new_slot = (old_slot.0, old_slot.1, old_slot.2 + 1);
        changed.records.insert(new_slot, record);
        changed.order[0] = new_slot;
        changed
            .watermark
            .insert((new_slot.0, new_slot.1), new_slot.2);
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut changed = base.clone();
        let old_slot = changed.order[0];
        let mut record = changed.records.remove(&old_slot).unwrap();
        let new_slot = (old_slot.0, KeyDomain::Withdrawal.tag(), old_slot.2);
        record.1.kind =
            ReceiptKind::WithdrawalRequested(derive_withdrawal_id(new_slot.0, new_slot.2));
        changed.records.insert(new_slot, record);
        changed.order[0] = new_slot;
        changed
            .watermark
            .insert((new_slot.0, new_slot.1), new_slot.2);
        assert_ne!(changed.transition_root_v1().unwrap(), root);

        let mut corrupt = base;
        corrupt.order.swap(0, 1);
        assert_invariant(
            &corrupt,
            "replay FIFO receipts are not strictly sequence ordered",
        );
    }

    #[test]
    fn replay_transition_root_v1_distinguishes_every_receipt_variant() {
        let mut encodings = Vec::new();
        for kind in all_receipt_kinds() {
            let mut writer = ReplayTransitionWriter::default();
            ReplayGuard::write_receipt(
                &mut writer,
                &ExecutionReceipt {
                    sequence: 1,
                    kind,
                    state_root: Hash::from_bytes([0xBB; 32]),
                },
            );
            assert!(
                !encodings.contains(&writer.bytes),
                "receipt variants must have unique tags"
            );
            encodings.push(writer.bytes);
        }
    }

    #[test]
    fn replay_receipt_encoding_v1_golden_and_binds_every_payload_field() {
        let mut writer = ReplayTransitionWriter::default();
        for kind in all_receipt_kinds() {
            writer.bytes.extend_from_slice(&encoded_receipt(kind));
        }
        assert_eq!(
            crypto::hash_domain(crypto::DOMAIN_EXECUTION_REPLAY_STATE, &writer.bytes),
            Hash::from_bytes([
                212, 247, 138, 95, 87, 126, 135, 203, 244, 174, 60, 11, 254, 196, 255, 64, 147,
                236, 30, 239, 121, 177, 40, 21, 245, 98, 101, 73, 6, 207, 105, 205,
            ])
        );

        assert_receipt_payload_bound(
            ReceiptKind::AccountCreated(AccountId::new(1)),
            ReceiptKind::AccountCreated(AccountId::new(2)),
        );
        assert_receipt_payload_bound(
            ReceiptKind::Credited(AccountId::new(1), Amount::from_raw(2)),
            ReceiptKind::Credited(AccountId::new(2), Amount::from_raw(2)),
        );
        assert_receipt_payload_bound(
            ReceiptKind::Credited(AccountId::new(1), Amount::from_raw(2)),
            ReceiptKind::Credited(AccountId::new(1), Amount::from_raw(3)),
        );
        assert_receipt_payload_bound(
            ReceiptKind::WithdrawalRequested(1),
            ReceiptKind::WithdrawalRequested(2),
        );
        assert_receipt_payload_bound(
            ReceiptKind::WithdrawalFinalized(1),
            ReceiptKind::WithdrawalFinalized(2),
        );
        assert_receipt_payload_bound(
            ReceiptKind::MarketUpdated(MarketId::new(1)),
            ReceiptKind::MarketUpdated(MarketId::new(2)),
        );
        assert_receipt_payload_bound(
            ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(1),
                rested: false,
            },
            ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(2),
                rested: false,
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(1),
                rested: false,
            },
            ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(1),
                rested: true,
            },
        );
        assert_receipt_payload_bound(ReceiptKind::Cancelled(1), ReceiptKind::Cancelled(2));
        assert_receipt_payload_bound(
            ReceiptKind::CompleteSet(Amount::from_raw(1)),
            ReceiptKind::CompleteSet(Amount::from_raw(2)),
        );
        assert_receipt_payload_bound(
            ReceiptKind::ProtocolUpgraded(1),
            ReceiptKind::ProtocolUpgraded(2),
        );
        assert_receipt_payload_bound(
            ReceiptKind::Liquidated {
                account: AccountId::new(1),
                insurance_drawn: Amount::from_raw(2),
                socialized_loss: Amount::from_raw(3),
            },
            ReceiptKind::Liquidated {
                account: AccountId::new(2),
                insurance_drawn: Amount::from_raw(2),
                socialized_loss: Amount::from_raw(3),
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::Liquidated {
                account: AccountId::new(1),
                insurance_drawn: Amount::from_raw(2),
                socialized_loss: Amount::from_raw(3),
            },
            ReceiptKind::Liquidated {
                account: AccountId::new(1),
                insurance_drawn: Amount::from_raw(4),
                socialized_loss: Amount::from_raw(3),
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::Liquidated {
                account: AccountId::new(1),
                insurance_drawn: Amount::from_raw(2),
                socialized_loss: Amount::from_raw(3),
            },
            ReceiptKind::Liquidated {
                account: AccountId::new(1),
                insurance_drawn: Amount::from_raw(2),
                socialized_loss: Amount::from_raw(4),
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::FundingApplied {
                market: MarketId::new(1),
                epoch: 2,
            },
            ReceiptKind::FundingApplied {
                market: MarketId::new(2),
                epoch: 2,
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::FundingApplied {
                market: MarketId::new(1),
                epoch: 2,
            },
            ReceiptKind::FundingApplied {
                market: MarketId::new(1),
                epoch: 3,
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::MarketResolved {
                market: MarketId::new(1),
                winning_outcome: 2,
            },
            ReceiptKind::MarketResolved {
                market: MarketId::new(2),
                winning_outcome: 2,
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::MarketResolved {
                market: MarketId::new(1),
                winning_outcome: 2,
            },
            ReceiptKind::MarketResolved {
                market: MarketId::new(1),
                winning_outcome: 3,
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::MarketSettled {
                market: MarketId::new(1),
                paid: Amount::from_raw(2),
            },
            ReceiptKind::MarketSettled {
                market: MarketId::new(2),
                paid: Amount::from_raw(2),
            },
        );
        assert_receipt_payload_bound(
            ReceiptKind::MarketSettled {
                market: MarketId::new(1),
                paid: Amount::from_raw(2),
            },
            ReceiptKind::MarketSettled {
                market: MarketId::new(1),
                paid: Amount::from_raw(3),
            },
        );
    }

    #[test]
    fn replay_transition_root_v1_canonicalizes_hash_layout() {
        let base = rich_replay_guard();
        let mut rebuilt = base.clone();

        let mut watermarks: Vec<_> = base.watermark.iter().map(|(k, v)| (*k, *v)).collect();
        watermarks.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        rebuilt.watermark = watermarks.into_iter().collect();

        let mut records: Vec<_> = base
            .records
            .iter()
            .map(|(slot, record)| (*slot, record.clone()))
            .collect();
        records.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        rebuilt.records = records.into_iter().collect();

        assert_eq!(
            rebuilt.transition_root_v1().unwrap(),
            base.transition_root_v1().unwrap()
        );
    }

    #[test]
    fn replay_transition_root_v1_rejects_corrupt_state() {
        let base = rich_replay_guard();

        let mut changed = base.clone();
        changed.window = 1;
        assert_invariant(&changed, "replay records exceed the configured window");

        let mut changed = base.clone();
        changed.order.pop_back();
        assert_invariant(
            &changed,
            "replay FIFO and record map have different lengths",
        );

        let mut changed = base.clone();
        changed.order[1] = changed.order[0];
        assert_invariant(&changed, "replay FIFO contains a duplicate slot");

        let mut changed = base.clone();
        changed.watermark.insert((999, 9), 1);
        assert_invariant(&changed, "replay watermark has an unknown key domain");

        let mut changed = base.clone();
        let old_slot = changed.order[0];
        let record = changed.records.remove(&old_slot).unwrap();
        let unknown_slot = (old_slot.0, 9, old_slot.2);
        changed.records.insert(unknown_slot, record);
        changed.order[0] = unknown_slot;
        assert_invariant(&changed, "replay FIFO has an unknown key domain");

        let mut changed = base.clone();
        changed.order[0] = (999, KeyDomain::Order.tag(), 1);
        assert_invariant(&changed, "replay FIFO references a missing record");

        let mut changed = base;
        let (principal, domain, key) = changed.order[0];
        changed.watermark.insert((principal, domain), key - 1);
        assert_invariant(&changed, "replay record exceeds its durable watermark");
    }

    #[test]
    fn replay_transition_root_v1_rejects_unreachable_receipts() {
        let base = rich_replay_guard();

        let mut changed = base.clone();
        let first = changed.order[0];
        changed.records.get_mut(&first).unwrap().1.kind = ReceiptKind::SessionUpdated;
        assert_invariant(&changed, "replay order key has a non-order receipt");

        let mut changed = base.clone();
        let second = changed.order[1];
        changed.records.get_mut(&second).unwrap().1.kind = ReceiptKind::SessionUpdated;
        assert_invariant(
            &changed,
            "replay withdrawal key has a non-withdrawal receipt",
        );

        let mut changed = base.clone();
        let second = changed.order[1];
        let ReceiptKind::WithdrawalRequested(withdrawal_id) =
            &mut changed.records.get_mut(&second).unwrap().1.kind
        else {
            panic!("second rich replay record must be a withdrawal");
        };
        *withdrawal_id ^= 1;
        assert_invariant(
            &changed,
            "replay withdrawal receipt id does not match its command key",
        );

        let mut changed = base.clone();
        let first = changed.order[0];
        let ReceiptKind::OrderApplied { filled, .. } =
            &mut changed.records.get_mut(&first).unwrap().1.kind
        else {
            panic!("first rich replay record must be an order");
        };
        *filled = Quantity::from_raw(-1);
        assert_invariant(
            &changed,
            "replay order receipt has a negative filled quantity",
        );

        let mut changed = base.clone();
        let first_sequence = changed.records.get(&changed.order[0]).unwrap().1.sequence;
        let second = changed.order[1];
        changed.records.get_mut(&second).unwrap().1.sequence = first_sequence;
        assert_invariant(
            &changed,
            "replay FIFO receipts are not strictly sequence ordered",
        );

        let mut changed = ReplayGuard::with_window(2);
        for (key, sequence) in [(5, 1), (6, 2)] {
            let binding = KeyBinding {
                principal: 1,
                domain: KeyDomain::Order,
                key,
                digest: Hash::from_bytes([u8::try_from(key).unwrap(); 32]),
            };
            changed.reserve(&binding);
            changed.finalize(
                &binding,
                ExecutionReceipt {
                    sequence,
                    kind: ReceiptKind::OrderApplied {
                        filled: Quantity::from_raw(1),
                        rested: true,
                    },
                    state_root: Hash::ZERO,
                },
            );
        }
        let old_second = changed.order[1];
        let record = changed.records.remove(&old_second).unwrap();
        let reordered_second = (old_second.0, old_second.1, 4);
        changed.records.insert(reordered_second, record);
        changed.order[1] = reordered_second;
        assert_invariant(
            &changed,
            "replay FIFO keys are not strictly increasing per principal and domain",
        );
    }

    #[test]
    fn replay_engine_context_rejects_cross_component_corruption() {
        let base = rich_replay_guard();
        assert_eq!(base.validate_engine_context(100, Some(1_000)), Ok(()));

        assert_eq!(
            base.validate_engine_context(1, Some(1_000)),
            Err(ExecutionError::StateInvariant(
                "replay principal does not reference an existing ledger account"
            ))
        );
        assert_eq!(
            base.validate_engine_context(100, None),
            Err(ExecutionError::StateInvariant(
                "replay state exists without a consumed engine sequence"
            ))
        );
        assert_eq!(
            base.validate_engine_context(100, Some(200)),
            Err(ExecutionError::StateInvariant(
                "replay receipt sequence exceeds the engine sequence"
            ))
        );
        assert_eq!(
            ReplayGuard::with_window(10).validate_engine_context(0, None),
            Ok(())
        );
    }

    #[test]
    fn fresh_then_exact_replay_returns_original_receipt() {
        let mut g = ReplayGuard::with_window(8);
        let b = binding(1, 5, 0xAA);
        assert!(matches!(g.classify(&b), GuardDecision::Fresh));
        g.reserve(&b);
        g.finalize(&b, receipt(10, 42));
        // Exact retry replays the original receipt without re-applying.
        match g.classify(&b) {
            GuardDecision::Replay(r) => assert_eq!(r, receipt(10, 42)),
            other => panic!("expected replay, got {other:?}"),
        }
    }

    #[test]
    fn same_key_different_payload_conflicts() {
        let mut g = ReplayGuard::with_window(8);
        let b = binding(1, 5, 0xAA);
        g.reserve(&b);
        g.finalize(&b, receipt(10, 42));
        // Same principal + key, different digest.
        let changed = binding(1, 5, 0xBB);
        assert!(matches!(g.classify(&changed), GuardDecision::Conflict));
    }

    #[test]
    fn eviction_leaves_processed_key_recognised_as_expired() {
        // A window of one: recording a second key evicts the first receipt, but
        // the watermark still recognises the first key as processed.
        let mut g = ReplayGuard::with_window(1);
        let first = binding(1, 5, 0xAA);
        g.reserve(&first);
        g.finalize(&first, receipt(10, 42));
        let second = binding(1, 6, 0xCC);
        g.reserve(&second);
        g.finalize(&second, receipt(11, 43));
        // The first key's receipt is gone, but a retry is never re-executed.
        assert!(matches!(g.classify(&first), GuardDecision::Expired));
        // The most-recent key still replays.
        assert!(matches!(g.classify(&second), GuardDecision::Replay(_)));
    }

    #[test]
    fn watermark_rejects_stale_lower_keys() {
        let mut g = ReplayGuard::with_window(0);
        let b = binding(1, 5, 0xAA);
        g.reserve(&b);
        // With a zero window nothing is retained, but the watermark still blocks
        // re-execution of the processed key and any lower key.
        assert!(matches!(
            g.classify(&binding(1, 5, 0xAA)),
            GuardDecision::Expired
        ));
        assert!(matches!(
            g.classify(&binding(1, 4, 0xAA)),
            GuardDecision::Expired
        ));
        // A higher key on the same principal is still fresh.
        assert!(matches!(
            g.classify(&binding(1, 6, 0xAA)),
            GuardDecision::Fresh
        ));
        // A different principal is independent.
        assert!(matches!(
            g.classify(&binding(2, 1, 0xAA)),
            GuardDecision::Fresh
        ));
    }

    #[test]
    fn watermark_exposed_per_domain() {
        let mut g = ReplayGuard::with_window(4);
        g.reserve(&KeyBinding {
            principal: 7,
            domain: KeyDomain::Order,
            key: 3,
            digest: Hash::ZERO,
        });
        assert_eq!(g.watermark(7, KeyDomain::Order), Some(3));
        assert_eq!(g.watermark(7, KeyDomain::Withdrawal), None);
    }

    #[test]
    fn derived_withdrawal_id_is_deterministic_and_key_dependent() {
        let a = derive_withdrawal_id(3, 1);
        assert_eq!(a, 16_797_745_059_889_606_235);

        let mut reference = LeafWriter::new();
        reference
            .field_u32(3)
            .field_i64(i64::from_le_bytes(1_u64.to_le_bytes()));
        let reference_hash = crypto::hash_domain(crypto::DOMAIN_COMMAND, reference.as_bytes());
        let reference_bytes = reference_hash.as_bytes();
        assert_eq!(
            a,
            u64::from_le_bytes([
                reference_bytes[0],
                reference_bytes[1],
                reference_bytes[2],
                reference_bytes[3],
                reference_bytes[4],
                reference_bytes[5],
                reference_bytes[6],
                reference_bytes[7],
            ]),
            "stack encoding must remain byte-identical to canonical LeafWriter v1",
        );
        assert_eq!(a, derive_withdrawal_id(3, 1));
        assert_ne!(a, derive_withdrawal_id(3, 2));
        assert_ne!(a, derive_withdrawal_id(4, 1));
    }

    #[test]
    fn place_order_digest_changes_with_any_economic_field() {
        use types::{MarketId, OrderId, Price, Quantity};
        let base = PlaceOrder {
            account: AccountId::new(1),
            market: MarketId::new(0),
            order_id: OrderId::new(9),
            side: Side::Bid,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price::from_raw(1_000_000),
            quantity: Quantity::from_raw(2_000_000),
            client_id: 5,
            reduce_only: false,
            instrument: 0,
            auth: crate::command::Authorization::Master,
        };
        let d = place_order_digest(&base);
        assert_eq!(
            d,
            Hash::from_bytes([
                97, 93, 68, 19, 189, 107, 188, 126, 216, 151, 245, 137, 96, 29, 216, 81, 60, 35,
                98, 60, 178, 144, 233, 161, 100, 114, 155, 67, 191, 40, 0, 32,
            ])
        );
        let mut reference = LeafWriter::new();
        reference
            .field_u32(u32::from(KeyDomain::Order.tag()))
            .field_u32(base.account.get())
            .field_u32(base.market.get())
            .field_i64(i64::from_le_bytes(base.order_id.get().to_le_bytes()))
            .field_u32(side_tag(base.side))
            .field_u32(order_type_tag(base.order_type))
            .field_u32(tif_tag(base.tif))
            .field_i64(base.price.raw())
            .field_i64(base.quantity.raw())
            .field_i64(i64::from_le_bytes(base.client_id.to_le_bytes()))
            .field_u32(u32::from(base.reduce_only))
            .field_u32(u32::from(base.instrument));
        assert_eq!(
            d,
            crypto::hash_domain(crypto::DOMAIN_COMMAND, reference.as_bytes()),
            "stack encoding must remain byte-identical to canonical LeafWriter v1",
        );
        macro_rules! changed {
            ($field:ident = $value:expr) => {{
                let mut command = base.clone();
                command.$field = $value;
                assert_ne!(
                    d,
                    place_order_digest(&command),
                    concat!(stringify!($field), " must be digest-bound")
                );
            }};
        }
        changed!(account = AccountId::new(2));
        changed!(market = MarketId::new(1));
        changed!(order_id = OrderId::new(10));
        changed!(side = Side::Ask);
        changed!(order_type = OrderType::Market);
        changed!(tif = TimeInForce::Ioc);
        changed!(price = Price::from_raw(1_000_001));
        changed!(quantity = Quantity::from_raw(2_000_001));
        changed!(client_id = 6);
        changed!(reduce_only = true);
        changed!(instrument = 1);

        // Every authorization field is deliberately excluded from the digest.
        let mut reauthed = base.clone();
        reauthed.auth = crate::command::Authorization::Session {
            session_key: [9u8; 32],
            nonce: u64::MAX,
            now: u64::MAX,
        };
        assert_eq!(d, place_order_digest(&reauthed));

        let binding = command_binding(&Command::PlaceOrder(base)).unwrap();
        assert_eq!(binding.principal, 1);
        assert_eq!(binding.domain, KeyDomain::Order);
        assert_eq!(binding.key, 5);
        assert_eq!(binding.digest, d);
    }

    #[test]
    fn withdrawal_digest_golden_binds_every_payload_field_and_excludes_auth() {
        let base = RequestWithdrawal {
            account: AccountId::new(7),
            amount: Amount::from_raw(0x0102_0304_0506_0708_1112_1314_1516_1718),
            nonce: 0x2122_2324_2526_2728,
            destination_chain: 0x3132_3334,
            destination_address: vec![0x41, 0x42, 0x43, 0x44, 0x45],
            auth: crate::command::Authorization::Master,
        };
        let digest = withdrawal_digest(&base);
        assert_eq!(
            digest,
            Hash::from_bytes([
                95, 175, 54, 23, 164, 202, 104, 5, 1, 143, 66, 66, 124, 43, 209, 66, 131, 70, 107,
                153, 34, 16, 15, 0, 130, 22, 131, 46, 228, 45, 239, 223,
            ])
        );

        let mut reference = LeafWriter::new();
        reference
            .field_u32(u32::from(KeyDomain::Withdrawal.tag()))
            .field_u32(base.account.get())
            .field_i128(base.amount.raw())
            .field_i64(i64::from_le_bytes(base.nonce.to_le_bytes()))
            .field_u32(base.destination_chain)
            .field_bytes(&base.destination_address);
        assert_eq!(
            digest,
            crypto::hash_domain(crypto::DOMAIN_COMMAND, reference.as_bytes())
        );

        macro_rules! changed {
            ($field:ident = $value:expr) => {{
                let mut command = base.clone();
                command.$field = $value;
                assert_ne!(
                    digest,
                    withdrawal_digest(&command),
                    concat!(stringify!($field), " must be digest-bound")
                );
            }};
        }
        changed!(account = AccountId::new(8));
        changed!(amount = Amount::from_raw(base.amount.raw() + 1));
        changed!(nonce = base.nonce + 1);
        changed!(destination_chain = base.destination_chain + 1);
        changed!(destination_address = vec![0x41, 0x42, 0x43, 0x44, 0x46]);

        let mut reauthed = base.clone();
        reauthed.auth = crate::command::Authorization::Session {
            session_key: [0xAA; 32],
            nonce: u64::MAX,
            now: u64::MAX,
        };
        assert_eq!(digest, withdrawal_digest(&reauthed));

        let binding = command_binding(&Command::RequestWithdrawal(base)).unwrap();
        assert_eq!(binding.principal, 7);
        assert_eq!(binding.domain, KeyDomain::Withdrawal);
        assert_eq!(binding.key, 0x2122_2324_2526_2728);
        assert_eq!(binding.digest, digest);
    }
}
