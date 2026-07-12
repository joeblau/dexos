//! Lowering: the compile-time contract between the RPC control plane and the
//! deterministic execution engine.
//!
//! [`rpc::Command`] documents itself as "the canonical command a control
//! request lowers to — the shape the live engine consumes", but the `rpc`
//! crate deliberately does not depend on `execution`, so nothing in the
//! workspace ever enforced that the two command sets stay in lock-step. They
//! drifted silently (issue #429): rpc's `PlaceOrder` carries a `leverage`
//! ratio and lacks the engine's `order_id` / `client_id` / `reduce_only` /
//! `instrument` / `auth` fields, and rpc has variants (`Basket`,
//! `StakeMarket`) the engine has no equivalent for. This module — living in
//! `node`, the only crate that depends on both — is the single bridge, and it
//! is written so the contract is enforced by the type system:
//!
//! * [`lower`] matches **exhaustively** over [`rpc::Command`] with no
//!   wildcard arm, and destructures **every field by name** (no `..`) in each
//!   lowered arm. Adding a variant to `rpc::Command`, or a field to a lowered
//!   variant, fails to compile until a lowering decision is made here.
//! * Each [`execution::Command`] payload is constructed **by name with every
//!   field spelled out** (never functional-update syntax), so adding a field
//!   to an engine command also fails to compile here.
//! * [`control_plane_produces`] matches exhaustively over
//!   [`execution::Command`], so adding a variant to the **engine** enum
//!   likewise fails to compile until it is classified.
//!
//! Together: adding a variant to either enum, or a field to any command
//! either side of the bridge, breaks this file's compilation. That is the
//! drift guard.
//!
//! # Fail-closed policy
//!
//! A control command that cannot be expressed faithfully in the engine
//! command set is **rejected with a typed error**, never approximated:
//! guessing at routing or authorization semantics on a trading engine is how
//! funds are lost. See [`LoweringError`] for the individual cases.

use types::{OrderId, OrderType};

use execution::{
    Authorization, AuthorizeSession, BindWallet, CancelAll, CancelOrder, PlaceOrder, ReplaceOrder,
    RequestWithdrawal, RevokeSession, Timestamp,
};
use rpc::{ControlMeta, SessionScope};

/// Nanoseconds per millisecond: rpc [`SessionScope::expiry`] is unix
/// **milliseconds**, while [`execution::Timestamp`] (and the session
/// registry's expiry comparison) is **nanoseconds** of sequencer network
/// time. Lowering converts with a checked multiply; see
/// [`LoweringError::SessionExpiryOverflow`].
const NANOS_PER_MILLI: u64 = 1_000_000;

/// Placeholder stamped into [`Authorization::Session::now`] by the lowering
/// layer.
///
/// `now` is *sequencer-assigned* network time (see [`Authorization::Session`]
/// docs): it does not exist yet when a control request is lowered at the RPC
/// edge — the sequencer stamps it when the command enters the canonical log.
/// The placeholder is `u64::MAX`, chosen to fail **closed**: the session
/// registry rejects a session as expired when `now > expires_at`, so a
/// command whose `now` was never re-stamped by the sequencer is rejected as
/// expired rather than silently granted an expiry-check bypass (which a `0`
/// placeholder would produce). Sequencer wiring MUST overwrite this field
/// with real network time before the command is applied.
pub const UNSTAMPED_SESSION_NOW: Timestamp = u64::MAX;

/// The canonical EVM chain id pinned for control-plane wallet bindings and
/// withdrawal destinations.
///
/// The rpc control schema hard-commits to EVM — [`rpc::BindWalletParams`] and
/// [`rpc::RequestWithdrawalParams`] both document their address fields as "a
/// 20-byte EVM address" — but carries **no chain selector**, while the engine
/// keys wallet bindings and withdrawals by numeric chain id
/// ([`BindWallet::chain_id`], [`RequestWithdrawal::destination_chain`]).
/// Until the control schema grows an explicit chain field, lowering pins the
/// protocol's canonical EVM chain id (1, the id used throughout the
/// execution / chain-adapter suites). This is a deliberate, *documented*
/// single-chain restriction — a deployment adding a second EVM chain must
/// extend the rpc command schema first, at which point the exhaustive
/// destructuring in [`lower`] forces this constant to be revisited.
pub const CANONICAL_EVM_CHAIN_ID: u32 = 1;

/// The instrument / outcome coordinate assigned to control-plane orders.
///
/// rpc's `PlaceOrder` has no outcome coordinate; the engine's
/// [`PlaceOrder::instrument`] routes fills to a claim ledger and documents
/// `0` as the perpetual coordinate — and declares `0` its own serde default.
/// Lowered orders therefore target coordinate `0`. Placing outcome-specific
/// orders on multi-outcome markets through the control plane requires an rpc
/// schema extension, not a guess here.
const DEFAULT_INSTRUMENT: u16 = 0;

/// A control command that could not be lowered into the engine command set.
///
/// Every variant is a *refusal to guess*: the mapping either does not exist
/// or would silently change semantics, so lowering fails closed with a typed
/// error instead of approximating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LoweringError {
    /// The rpc variant has no equivalent in the deterministic engine command
    /// set at all (e.g. `Basket`, `StakeMarket`).
    #[error("control command has no engine equivalent: {0}")]
    Unsupported(&'static str),

    /// The variant has an engine equivalent, but this particular value cannot
    /// be encoded faithfully — lowering it would silently change semantics
    /// (e.g. a deny-all session scope, which the engine's empty-list wildcard
    /// encoding would invert into allow-all).
    #[error("control command is not faithfully representable in the engine command set: {0}")]
    Unrepresentable(&'static str),

    /// A session expiry in unix milliseconds does not fit the engine's
    /// nanosecond clock after conversion.
    #[error("session expiry of {millis} unix ms overflows the engine's nanosecond clock")]
    SessionExpiryOverflow {
        /// The out-of-range expiry, in unix milliseconds as received.
        millis: u64,
    },
}

/// Build the engine [`Authorization`] for a mutating command from the control
/// envelope.
///
/// Mapping decision: [`ControlMeta::session_pubkey`] present means the
/// command was authorized by a delegated session key, so it lowers to
/// [`Authorization::Session`] carrying that key and the envelope nonce (the
/// engine consumes the nonce exactly once for replay protection); absent
/// means the account root key signed, which is [`Authorization::Master`].
/// The envelope's `signer` / `signature` fields are deliberately not carried:
/// cryptographic verification happens at the RPC gate before sequencing, and
/// the engine trusts the sequenced origin, enforcing only the *stateful* half
/// of authorization (see [`Authorization`] docs). `now` is the fail-closed
/// [`UNSTAMPED_SESSION_NOW`] placeholder the sequencer must overwrite.
fn authorization(meta: &ControlMeta) -> Authorization {
    match meta.session_pubkey {
        Some(session_key) => Authorization::Session {
            session_key,
            nonce: meta.nonce,
            now: UNSTAMPED_SESSION_NOW,
        },
        None => Authorization::Master,
    }
}

/// Lower a canonical RPC control command into the deterministic engine
/// command the live engine actually consumes.
///
/// This is the production bridge issue #429 found missing: before it, the two
/// `Command` enums were structurally incompatible and nothing in the
/// workspace noticed. The match below is exhaustive with no wildcard arm and
/// every lowered arm destructures all fields by name, so any drift in either
/// crate's command shapes fails compilation here (see the module docs for the
/// full drift-guard construction).
///
/// # Errors
///
/// Returns a [`LoweringError`] — never panics, never approximates — when the
/// command has no engine equivalent ([`LoweringError::Unsupported`]), when a
/// particular value cannot be encoded without changing semantics
/// ([`LoweringError::Unrepresentable`]), or when a session expiry overflows
/// the engine clock ([`LoweringError::SessionExpiryOverflow`]).
pub fn lower(
    cmd: &rpc::Command,
    meta: &rpc::ControlMeta,
) -> Result<execution::Command, LoweringError> {
    match cmd {
        // ------------------------------------------------------------------
        // PlaceOrder — the variant whose drift motivated issue #429.
        //
        // Field decisions:
        // * `order_id` <- meta.nonce: the engine's `order_id` is documented
        //   as *client-assigned*; the control plane's unique per-command
        //   identity is the (client_id, nonce) idempotency pair, so the nonce
        //   is the client-assigned id. A retransmit (same nonce) lowers to
        //   the same order id, preserving at-most-once semantics.
        // * `client_id` <- meta.client_id: same idempotency pair.
        // * `reduce_only` <- (order_type == ReduceOnly): the engine margins
        //   off the boolean flag (engine.rs pretrade/risk path), and the only
        //   way the rpc schema expresses reduce-only intent is the order
        //   type; deriving the flag is the faithful mapping, not a guess.
        // * `instrument` <- DEFAULT_INSTRUMENT (0): see the constant's docs.
        // * `leverage` is DROPPED: the engine's `PlaceOrder` has no leverage
        //   field by design — effective leverage is derived by the risk
        //   subsystem as notional/equity and capped by `RiskConfig::
        //   max_leverage`, and a session's `max_leverage` bound is RPC-gate
        //   policy (`rpc::SessionScope`). A per-order leverage *request* is a
        //   gateway-side margin-preview concern the deterministic engine
        //   never consumes, so carrying it further would invent semantics.
        rpc::Command::PlaceOrder {
            account,
            market,
            side,
            order_type,
            price,
            quantity,
            time_in_force,
            leverage: _, // dropped — see the mapping notes above.
        } => Ok(execution::Command::PlaceOrder(PlaceOrder {
            account: *account,
            market: *market,
            order_id: OrderId::new(meta.nonce),
            side: *side,
            order_type: *order_type,
            tif: *time_in_force,
            price: *price,
            quantity: *quantity,
            client_id: meta.client_id,
            reduce_only: *order_type == OrderType::ReduceOnly,
            instrument: DEFAULT_INSTRUMENT,
            auth: authorization(meta),
        })),

        // Field-for-field, plus the engine's stateful authorization.
        rpc::Command::CancelOrder {
            account,
            market,
            order_id,
        } => Ok(execution::Command::CancelOrder(CancelOrder {
            market: *market,
            account: *account,
            order_id: *order_id,
            auth: authorization(meta),
        })),

        // The engine cancels per market. `market: None` (all markets) has no
        // single engine command; silently picking one market would drop the
        // rest, so it fails closed. The gateway layer must fan out one
        // engine `CancelAll` per market with open orders.
        rpc::Command::CancelAll { account, market } => match market {
            Some(market) => Ok(execution::Command::CancelAll(CancelAll {
                market: *market,
                account: *account,
                auth: authorization(meta),
            })),
            None => Err(LoweringError::Unrepresentable(
                "cancel_all across all markets: the engine cancels per market; \
                 the gateway must fan out one CancelAll per market",
            )),
        },

        // Field-for-field, plus the engine's stateful authorization.
        rpc::Command::ReplaceOrder {
            account,
            market,
            order_id,
            price,
            quantity,
        } => Ok(execution::Command::ReplaceOrder(ReplaceOrder {
            market: *market,
            account: *account,
            order_id: *order_id,
            price: *price,
            quantity: *quantity,
            auth: authorization(meta),
        })),

        // No engine equivalent (verified by search: `execution` has no
        // basket / atomic multi-order command). Lowering the constituents as
        // independent `PlaceOrder`s would silently break the documented
        // atomicity of `rpc::BasketParams` ("applied atomically"), so this
        // fails closed instead. Fields are irrelevant to a wholesale
        // rejection, hence the `..` — drift inside rejected variants cannot
        // change the outcome.
        rpc::Command::Basket { .. } => Err(LoweringError::Unsupported(
            "basket: the engine has no atomic multi-order command; lowering \
             constituents independently would break basket atomicity",
        )),

        // Scope-encoding decisions:
        // * Market lists INVERT between the crates: rpc's empty list with
        //   `all_markets == false` means deny-all, while the engine treats an
        //   empty `allowed_markets` as a WILDCARD (`Session::
        //   authorizes_market`). So: explicit wildcard -> empty engine list;
        //   non-empty allow-list -> copied verbatim; empty non-wildcard list
        //   (deny-all) is unrepresentable — encoding it would escalate a
        //   deny-all grant into allow-all — and fails closed.
        // * `expires_at` <- expiry (unix ms) converted to the engine's
        //   nanosecond clock with a checked multiply.
        // * `nonce_start`/`nonce_end` <- 0..=u64::MAX: the rpc scope carries
        //   no nonce window, so the full range is granted; per-nonce
        //   single-use replay protection is still enforced by the session
        //   registry regardless of the window.
        // * Dropped policy bits — each is RPC-gate policy the engine never
        //   consumes, and each drop is provably non-escalating:
        //   - `max_leverage`: engine-side leverage is capped by the risk
        //     subsystem's own `RiskConfig::max_leverage`.
        //   - `allow_withdrawal`: the engine unconditionally rejects any
        //     session-authorized withdrawal (`SessionCannotWithdraw`) —
        //     strictly tighter than the flag.
        //   - `allow_session_admin` / `allow_market_create`: the engine's
        //     `AuthorizeSession` / `CreateMarket` commands carry no
        //     per-account authorization at all (the sequenced origin is
        //     trusted); gating who may issue them is the RPC gate's job.
        rpc::Command::AuthorizeSession {
            account,
            session_pubkey,
            scope,
        } => {
            let SessionScope {
                markets,
                all_markets,
                max_notional,
                max_leverage: _,     // dropped — risk subsystem enforces its own cap.
                allow_withdrawal: _, // dropped — engine is strictly tighter (master-only).
                allow_session_admin: _, // dropped — RPC-gate policy; engine has no analogue.
                allow_market_create: _, // dropped — RPC-gate policy; engine has no analogue.
                expiry,
            } = scope;
            let allowed_markets = if *all_markets {
                // Engine wildcard encoding: empty list == every market.
                Vec::new()
            } else if markets.is_empty() {
                return Err(LoweringError::Unrepresentable(
                    "deny-all session scope: the engine encodes an empty market \
                     list as a wildcard, so a deny-all grant cannot be lowered \
                     without escalating it to allow-all",
                ));
            } else {
                markets.clone()
            };
            let expires_at = expiry
                .checked_mul(NANOS_PER_MILLI)
                .ok_or(LoweringError::SessionExpiryOverflow { millis: *expiry })?;
            Ok(execution::Command::AuthorizeSession(AuthorizeSession {
                account: *account,
                session_key: *session_pubkey,
                allowed_markets,
                max_notional: *max_notional,
                expires_at,
                nonce_start: 0,
                nonce_end: u64::MAX,
            }))
        }

        // Field-for-field (`session_pubkey` -> `session_key`).
        rpc::Command::RevokeSession {
            account,
            session_pubkey,
        } => Ok(execution::Command::RevokeSession(RevokeSession {
            account: *account,
            session_key: *session_pubkey,
        })),

        // * `chain_id` <- CANONICAL_EVM_CHAIN_ID: see the constant's docs —
        //   the rpc schema commits to a 20-byte EVM address with no chain
        //   selector.
        // * `address` <- the fixed 20-byte EVM address, widened to the
        //   engine's variable-length encoding.
        // * `signature` is DROPPED: the wallet-control proof is verified at
        //   the RPC/custody gate before sequencing; the engine trusts the
        //   sequenced origin (see `Authorization` docs) and its `BindWallet`
        //   carries no proof field.
        rpc::Command::BindWallet {
            account,
            wallet,
            signature: _, // dropped — verified upstream at the RPC/custody gate.
        } => Ok(execution::Command::BindWallet(BindWallet {
            account: *account,
            chain_id: CANONICAL_EVM_CHAIN_ID,
            address: wallet.to_vec(),
        })),

        // * `nonce` <- meta.nonce: the engine derives the deterministic
        //   withdrawal id from (account, nonce), so an idempotent control
        //   retransmit (same nonce) resolves to the same withdrawal id —
        //   exactly the at-most-once contract `ControlMeta` documents.
        // * `destination_chain` <- CANONICAL_EVM_CHAIN_ID: same single-chain
        //   pin as BindWallet; a withdrawal must never guess its chain, and
        //   the schema cannot express one.
        // * `auth` is built by the shared rule. The engine restricts
        //   withdrawals to `Authorization::Master` (`SessionCannotWithdraw`);
        //   lowering deliberately preserves a session-authorized envelope
        //   as `Session` rather than pre-filtering, keeping that fund-safety
        //   policy in exactly one place — the engine.
        rpc::Command::Withdraw {
            account,
            amount,
            destination,
        } => Ok(execution::Command::RequestWithdrawal(RequestWithdrawal {
            account: *account,
            amount: *amount,
            nonce: meta.nonce,
            destination_chain: CANONICAL_EVM_CHAIN_ID,
            destination_address: destination.to_vec(),
            auth: authorization(meta),
        })),

        // The engine's `CreateMarket` requires a registry-assigned, unique
        // `MarketId` and an initial `mark_price` — an economic input. The
        // control request carries neither (it has `creator` and `symbol`,
        // which the engine command does not consume): id allocation and
        // initial-mark selection belong to the market-registry pipeline at
        // sequencing, and inventing either here (a colliding constant id, a
        // fabricated price) would be exactly the silent guessing this
        // adapter exists to prevent. Fails closed until the control schema
        // and registry wiring carry the missing inputs.
        rpc::Command::CreateMarket { .. } => Err(LoweringError::Unsupported(
            "create_market: the engine command requires a registry-assigned \
             MarketId and an initial mark price, neither of which the control \
             request carries",
        )),

        // No engine equivalent (verified by search: `execution` has no
        // sponsor/staking command — sponsorship lives in the `markets`
        // crate's pipeline, outside the deterministic engine command set).
        rpc::Command::StakeMarket { .. } => Err(LoweringError::Unsupported(
            "stake_market: sponsor staking is settled by the markets \
             sponsorship pipeline; the engine command set has no equivalent",
        )),
    }
}

/// Reverse-direction drift anchor: classifies every engine command by whether
/// this control-plane bridge can produce it.
///
/// [`lower`] guards the rpc → execution direction; this exhaustive match (no
/// wildcard arm) guards the other: adding a variant to
/// [`execution::Command`] fails to compile *here* until it is explicitly
/// classified as control-plane-producible or engine-internal. Commands
/// classified `false` are privileged / pipeline-originated (sequencer,
/// oracle, keeper, registry, custody) and must never be reachable from an
/// external control request.
pub fn control_plane_produces(cmd: &execution::Command) -> bool {
    match cmd {
        execution::Command::PlaceOrder(_)
        | execution::Command::CancelOrder(_)
        | execution::Command::CancelAll(_)
        | execution::Command::ReplaceOrder(_)
        | execution::Command::AuthorizeSession(_)
        | execution::Command::RevokeSession(_)
        | execution::Command::BindWallet(_)
        | execution::Command::RequestWithdrawal(_) => true,
        execution::Command::CreateAccount(_)
        | execution::Command::DepositCredit(_)
        | execution::Command::FinalizeWithdrawal(_)
        | execution::Command::CreateMarket(_)
        | execution::Command::SetMarkPrice(_)
        | execution::Command::MintCompleteSet(_)
        | execution::Command::RedeemCompleteSet(_)
        | execution::Command::ProtocolUpgrade(_)
        | execution::Command::Liquidate(_)
        | execution::Command::SetMarketLifecycle(_)
        | execution::Command::SetOracleHealth(_)
        | execution::Command::ApplyFundingEpoch(_)
        | execution::Command::ResolveMarket(_)
        | execution::Command::SettleMarket(_) => false,
    }
}

// The contract test: one representative value of EVERY rpc::Command variant
// is lowered against a sample envelope and the resulting engine command's
// fields are asserted. The exhaustiveness half of the contract is
// compile-time (see the module docs): adding a variant to either Command
// enum — or a field to any lowered payload — breaks this file's compilation
// before any of these tests even run.
#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        AccountId, Amount, MarketId, MarketType, Price, Quantity, Ratio, Side, TimeInForce,
    };

    /// Signature checking happens at the RPC gate before lowering, so tests
    /// build envelopes directly; the signature bytes are never consumed here.
    fn master_meta() -> ControlMeta {
        ControlMeta {
            client_id: 7,
            nonce: 42,
            session_pubkey: None,
            signer: [0xAA; 32],
            signature: [0x11; 64],
        }
    }

    fn session_meta() -> ControlMeta {
        ControlMeta {
            session_pubkey: Some([0x5E; 32]),
            ..master_meta()
        }
    }

    fn place_order() -> rpc::Command {
        rpc::Command::PlaceOrder {
            account: AccountId::new(3),
            market: MarketId::new(9),
            side: Side::Bid,
            order_type: OrderType::Limit,
            price: Price::from_raw(2_500_000),
            quantity: Quantity::from_raw(4_000_000),
            time_in_force: TimeInForce::Gtc,
            leverage: Ratio::from_raw(5_000_000),
        }
    }

    fn scope(markets: Vec<MarketId>, all_markets: bool) -> SessionScope {
        SessionScope {
            markets,
            all_markets,
            max_notional: Amount::from_raw(1_000_000_000),
            max_leverage: Ratio::from_raw(10_000_000),
            allow_withdrawal: false,
            allow_session_admin: false,
            allow_market_create: false,
            expiry: 1_750_000_000_000, // unix millis
        }
    }

    #[test]
    fn place_order_maps_idempotency_identity_and_master_auth() {
        let meta = master_meta();
        let lowered = lower(&place_order(), &meta).expect("place order lowers");
        let execution::Command::PlaceOrder(o) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(o.account, AccountId::new(3));
        assert_eq!(o.market, MarketId::new(9));
        // (client_id, nonce) -> (client_id, order_id): the client-assigned id.
        assert_eq!(o.order_id, OrderId::new(42));
        assert_eq!(o.client_id, 7);
        assert_eq!(o.side, Side::Bid);
        assert_eq!(o.order_type, OrderType::Limit);
        assert_eq!(o.tif, TimeInForce::Gtc);
        assert_eq!(o.price, Price::from_raw(2_500_000));
        assert_eq!(o.quantity, Quantity::from_raw(4_000_000));
        assert!(!o.reduce_only, "plain limit order must not be reduce-only");
        assert_eq!(
            o.instrument, 0,
            "control orders target the default coordinate"
        );
        assert_eq!(
            o.auth,
            Authorization::Master,
            "no session key => master auth"
        );
    }

    #[test]
    fn place_order_session_auth_carries_key_nonce_and_fails_closed_now() {
        let meta = session_meta();
        let lowered = lower(&place_order(), &meta).expect("place order lowers");
        let execution::Command::PlaceOrder(o) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(
            o.auth,
            Authorization::Session {
                session_key: [0x5E; 32],
                nonce: 42,
                now: UNSTAMPED_SESSION_NOW,
            },
            "session envelopes must lower to session auth with the fail-closed \
             (always-expired) placeholder timestamp the sequencer re-stamps"
        );
    }

    #[test]
    fn reduce_only_order_type_derives_engine_flag() {
        let cmd = rpc::Command::PlaceOrder {
            account: AccountId::new(3),
            market: MarketId::new(9),
            side: Side::Ask,
            order_type: OrderType::ReduceOnly,
            price: Price::from_raw(2_500_000),
            quantity: Quantity::from_raw(1_000_000),
            time_in_force: TimeInForce::Ioc,
            leverage: Ratio::ONE,
        };
        let lowered = lower(&cmd, &master_meta()).expect("reduce-only order lowers");
        let execution::Command::PlaceOrder(o) = lowered else {
            panic!("wrong engine variant");
        };
        assert!(
            o.reduce_only,
            "engine margins off the flag, not the order type"
        );
        assert_eq!(o.order_type, OrderType::ReduceOnly);
    }

    #[test]
    fn cancel_order_lowers_field_for_field() {
        let cmd = rpc::Command::CancelOrder {
            account: AccountId::new(3),
            market: MarketId::new(9),
            order_id: OrderId::new(77),
        };
        let lowered = lower(&cmd, &master_meta()).expect("cancel lowers");
        let execution::Command::CancelOrder(c) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(c.account, AccountId::new(3));
        assert_eq!(c.market, MarketId::new(9));
        assert_eq!(c.order_id, OrderId::new(77));
        assert_eq!(c.auth, Authorization::Master);
    }

    #[test]
    fn cancel_all_single_market_lowers() {
        let cmd = rpc::Command::CancelAll {
            account: AccountId::new(3),
            market: Some(MarketId::new(9)),
        };
        let lowered = lower(&cmd, &session_meta()).expect("scoped cancel-all lowers");
        let execution::Command::CancelAll(c) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(c.market, MarketId::new(9));
        assert_eq!(c.account, AccountId::new(3));
        assert!(matches!(c.auth, Authorization::Session { .. }));
    }

    #[test]
    fn cancel_all_across_all_markets_fails_closed() {
        let cmd = rpc::Command::CancelAll {
            account: AccountId::new(3),
            market: None,
        };
        assert!(matches!(
            lower(&cmd, &master_meta()),
            Err(LoweringError::Unrepresentable(_)),
        ));
    }

    #[test]
    fn replace_order_lowers_field_for_field() {
        let cmd = rpc::Command::ReplaceOrder {
            account: AccountId::new(3),
            market: MarketId::new(9),
            order_id: OrderId::new(77),
            price: Price::from_raw(2_600_000),
            quantity: Quantity::from_raw(3_000_000),
        };
        let lowered = lower(&cmd, &master_meta()).expect("replace lowers");
        let execution::Command::ReplaceOrder(r) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(r.market, MarketId::new(9));
        assert_eq!(r.account, AccountId::new(3));
        assert_eq!(r.order_id, OrderId::new(77));
        assert_eq!(r.price, Price::from_raw(2_600_000));
        assert_eq!(r.quantity, Quantity::from_raw(3_000_000));
        assert_eq!(r.auth, Authorization::Master);
    }

    #[test]
    fn basket_fails_closed_unsupported() {
        let cmd = rpc::Command::Basket {
            account: AccountId::new(3),
            orders: Vec::new(),
        };
        assert!(matches!(
            lower(&cmd, &master_meta()),
            Err(LoweringError::Unsupported(_)),
        ));
    }

    #[test]
    fn authorize_session_allow_list_and_expiry_units() {
        let cmd = rpc::Command::AuthorizeSession {
            account: AccountId::new(3),
            session_pubkey: [0x5E; 32],
            scope: scope(vec![MarketId::new(1), MarketId::new(2)], false),
        };
        let lowered = lower(&cmd, &master_meta()).expect("allow-list scope lowers");
        let execution::Command::AuthorizeSession(a) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(a.account, AccountId::new(3));
        assert_eq!(a.session_key, [0x5E; 32]);
        assert_eq!(a.allowed_markets, vec![MarketId::new(1), MarketId::new(2)]);
        assert_eq!(a.max_notional, Amount::from_raw(1_000_000_000));
        // unix millis -> engine nanoseconds.
        assert_eq!(a.expires_at, 1_750_000_000_000 * 1_000_000);
        // rpc carries no nonce window: full range, single-use still enforced.
        assert_eq!((a.nonce_start, a.nonce_end), (0, u64::MAX));
    }

    #[test]
    fn authorize_session_wildcard_maps_to_engine_empty_list() {
        let cmd = rpc::Command::AuthorizeSession {
            account: AccountId::new(3),
            session_pubkey: [0x5E; 32],
            // Explicit wildcard; a non-empty list alongside it is ignored per
            // rpc's own SessionScope contract.
            scope: scope(vec![MarketId::new(1)], true),
        };
        let lowered = lower(&cmd, &master_meta()).expect("wildcard scope lowers");
        let execution::Command::AuthorizeSession(a) = lowered else {
            panic!("wrong engine variant");
        };
        assert!(
            a.allowed_markets.is_empty(),
            "engine encodes the wildcard as an empty allowed_markets list"
        );
    }

    #[test]
    fn authorize_session_deny_all_scope_fails_closed() {
        // Empty list + all_markets=false is rpc deny-all; the engine's empty
        // list means allow-ALL, so lowering must refuse to escalate.
        let cmd = rpc::Command::AuthorizeSession {
            account: AccountId::new(3),
            session_pubkey: [0x5E; 32],
            scope: scope(Vec::new(), false),
        };
        assert!(matches!(
            lower(&cmd, &master_meta()),
            Err(LoweringError::Unrepresentable(_)),
        ));
    }

    #[test]
    fn authorize_session_expiry_overflow_fails_closed() {
        let mut s = scope(vec![MarketId::new(1)], false);
        s.expiry = u64::MAX; // millis; * 1e6 cannot fit the nanosecond clock.
        let cmd = rpc::Command::AuthorizeSession {
            account: AccountId::new(3),
            session_pubkey: [0x5E; 32],
            scope: s,
        };
        assert_eq!(
            lower(&cmd, &master_meta()),
            Err(LoweringError::SessionExpiryOverflow { millis: u64::MAX }),
        );
    }

    #[test]
    fn revoke_session_lowers_field_for_field() {
        let cmd = rpc::Command::RevokeSession {
            account: AccountId::new(3),
            session_pubkey: [0x5E; 32],
        };
        let lowered = lower(&cmd, &master_meta()).expect("revoke lowers");
        let execution::Command::RevokeSession(r) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(r.account, AccountId::new(3));
        assert_eq!(r.session_key, [0x5E; 32]);
    }

    #[test]
    fn bind_wallet_pins_canonical_evm_chain() {
        let cmd = rpc::Command::BindWallet {
            account: AccountId::new(3),
            wallet: [0xEF; 20],
            signature: vec![1, 2, 3],
        };
        let lowered = lower(&cmd, &master_meta()).expect("bind wallet lowers");
        let execution::Command::BindWallet(b) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(b.account, AccountId::new(3));
        assert_eq!(b.chain_id, CANONICAL_EVM_CHAIN_ID);
        assert_eq!(b.address, vec![0xEF; 20]);
    }

    #[test]
    fn withdraw_lowers_with_nonce_identity_and_master_auth() {
        let cmd = rpc::Command::Withdraw {
            account: AccountId::new(3),
            amount: Amount::from_raw(5_000_000),
            destination: [0xCD; 20],
        };
        let lowered = lower(&cmd, &master_meta()).expect("withdraw lowers");
        let execution::Command::RequestWithdrawal(w) = lowered else {
            panic!("wrong engine variant");
        };
        assert_eq!(w.account, AccountId::new(3));
        assert_eq!(w.amount, Amount::from_raw(5_000_000));
        // Envelope nonce -> withdrawal nonce: retransmits derive the same
        // deterministic withdrawal id in the engine.
        assert_eq!(w.nonce, 42);
        assert_eq!(w.destination_chain, CANONICAL_EVM_CHAIN_ID);
        assert_eq!(w.destination_address, vec![0xCD; 20]);
        assert_eq!(w.auth, Authorization::Master);
    }

    #[test]
    fn withdraw_preserves_session_auth_for_the_engine_to_reject() {
        // The engine — not the lowering layer — owns the master-only
        // withdrawal rule (SessionCannotWithdraw). Lowering must preserve
        // the declared authorization rather than pre-filtering it.
        let cmd = rpc::Command::Withdraw {
            account: AccountId::new(3),
            amount: Amount::from_raw(5_000_000),
            destination: [0xCD; 20],
        };
        let lowered = lower(&cmd, &session_meta()).expect("withdraw lowers");
        let execution::Command::RequestWithdrawal(w) = lowered else {
            panic!("wrong engine variant");
        };
        assert!(matches!(w.auth, Authorization::Session { .. }));
    }

    #[test]
    fn create_market_fails_closed_unsupported() {
        let cmd = rpc::Command::CreateMarket {
            creator: AccountId::new(3),
            market_type: MarketType::Perpetual,
            symbol: "PERP-1".to_string(),
            outcomes: 1,
        };
        assert!(matches!(
            lower(&cmd, &master_meta()),
            Err(LoweringError::Unsupported(_)),
        ));
    }

    #[test]
    fn stake_market_fails_closed_unsupported() {
        let cmd = rpc::Command::StakeMarket {
            market: MarketId::new(9),
            sponsor: types::SponsorId::new(4),
            amount: Amount::from_raw(1_000_000),
        };
        assert!(matches!(
            lower(&cmd, &master_meta()),
            Err(LoweringError::Unsupported(_)),
        ));
    }

    #[test]
    fn reverse_anchor_classifies_lowered_and_internal_commands() {
        let lowered = lower(&place_order(), &master_meta()).expect("place order lowers");
        assert!(control_plane_produces(&lowered));
        let internal = execution::Command::CreateAccount(execution::CreateAccount {
            initial_collateral: Amount::ZERO,
        });
        assert!(!control_plane_produces(&internal));
    }
}
