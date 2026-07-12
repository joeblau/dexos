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
//! per-principal high-water mark is committed into the versioned account leaf
//! (and therefore the state root), while the receipt window is a deterministic,
//! replay-rebuilt cache. Because keys are monotonic per principal per domain, an
//! evicted key is still recognised as already-processed by the watermark and can
//! never execute a second time.

use std::collections::{HashMap, VecDeque};

use state_tree::LeafWriter;
use types::{Hash, OrderType, Side, TimeInForce};

use crate::command::{Command, ExecutionReceipt, PlaceOrder, RequestWithdrawal};

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
    /// Insertion order backing deterministic FIFO eviction of `records`.
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

    /// Record the receipt for a freshly applied key in the bounded window so an
    /// exact retry can replay it. The window is a local, replay-rebuilt cache and
    /// is *not* part of the committed root; only [`Self::reserve`] mutates
    /// committed state.
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
    let mut w = LeafWriter::new();
    w.field_u32(account)
        .field_i64(i64::from_le_bytes(nonce.to_le_bytes()));
    let h = crypto::hash_domain(crypto::DOMAIN_COMMAND, &w.finish());
    let b = h.as_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Canonical digest over a [`PlaceOrder`]'s economically meaningful payload. The
/// authorization envelope is deliberately excluded: it carries a per-retry
/// volatile timestamp for session keys, and session replays are already blocked
/// by single-use session nonces.
fn place_order_digest(c: &PlaceOrder) -> Hash {
    let mut w = LeafWriter::new();
    w.field_u32(u32::from(KeyDomain::Order.tag()))
        .field_u32(c.account.get())
        .field_u32(c.market.get())
        .field_i64(i64::from_le_bytes(c.order_id.get().to_le_bytes()))
        .field_u32(side_tag(c.side))
        .field_u32(order_type_tag(c.order_type))
        .field_u32(tif_tag(c.tif))
        .field_i64(c.price.raw())
        .field_i64(c.quantity.raw())
        .field_i64(i64::from_le_bytes(c.client_id.to_le_bytes()))
        .field_u32(u32::from(c.reduce_only));
    crypto::hash_domain(crypto::DOMAIN_COMMAND, &w.finish())
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
    use types::AccountId;

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
            auth: crate::command::Authorization::Master,
        };
        let d = place_order_digest(&base);
        let mut changed = base.clone();
        changed.quantity = Quantity::from_raw(2_000_001);
        assert_ne!(d, place_order_digest(&changed));
        // The volatile authorization envelope is excluded from the digest.
        let mut reauthed = base;
        reauthed.auth = crate::command::Authorization::Session {
            session_key: [9u8; 32],
            nonce: 0,
            now: 1,
        };
        assert_eq!(d, place_order_digest(&reauthed));
    }
}
