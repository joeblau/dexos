//! The benchmark suites: bounded, deterministic workloads over the DexOS
//! crates, each producing a [`BenchStat`].
//!
//! Every suite is registered in [`registry`] so `run_all` (and a `marketd
//! benchmark --suite <name>` CLI) can enumerate and select them by their
//! spec-stable name. Workloads are seeded from a fixed constant so operation
//! ordering replays identically across runs.

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use codec::{Frame, PackedOrder, TrafficClass};
use consensus::{
    build_checkpoint_header, checkpoint_hash, execution_commitment_digest, notarize_digest,
    nullify_digest, ExecAttest, MinimmitCommittee, MinimmitReplica, Notarization, Notarize,
    Nullification, Nullify, ThresholdKind,
};
use crypto::{verify_ed25519, verify_ed25519_all, KeyPair, Validator};
use execution::{
    Authorization, Command, DeterministicEngine, Engine, EngineConfig, PlaceOrder, SetMarkPrice,
};
use orderbook::{BookConfig, NewOrder, OrderBook};
use risk::{RiskConfig, RiskEngine};
use state_tree::{verify_account, LeafWriter, StateTree};
use storage::{
    replay, DurableConfig, DurableLog, Record, SegmentedLog, Snapshot, SyncPolicy, PROTOCOL_VERSION,
};
use types::{
    AccountId, Amount, Hash, MarketId, OrderId, OrderType, Price, Quantity, Ratio, SequenceNumber,
    ShardId, Side, TimeInForce,
};

use crate::harness::{bench, Config};
use crate::rng::Lcg;
use crate::stats::BenchStat;

/// A named, runnable benchmark suite.
#[derive(Clone, Copy)]
pub struct Suite {
    /// Spec-stable identifier (also the JSON/report key).
    pub name: &'static str,
    /// Runs the suite under `config`, returning its measured statistics.
    pub run: fn(Config) -> BenchStat,
}

/// Fixed workload seed so every run replays the same operation ordering.
const SEED: u64 = 0x0DEF_ACE0_1234_5678;
static WAL_BENCHMARK_INSTANCE: AtomicU64 = AtomicU64::new(0);

/// All registered suites, in a stable order.
#[must_use]
pub fn registry() -> Vec<Suite> {
    vec![
        Suite {
            name: "order-insertion",
            run: order_insertion,
        },
        Suite {
            name: "order-cancellation",
            run: order_cancellation,
        },
        Suite {
            name: "order-replacement",
            run: order_replacement,
        },
        Suite {
            name: "market-order-execution",
            run: market_order_execution,
        },
        Suite {
            name: "market-order-execution-empty-book",
            run: market_order_execution_empty_book,
        },
        Suite {
            name: "market-order-execution-half-book",
            run: market_order_execution_half_book,
        },
        Suite {
            name: "market-order-execution-full-book",
            run: market_order_execution_full_book,
        },
        Suite {
            name: "market-order-fill-fanout",
            run: market_order_fill_fanout,
        },
        Suite {
            name: "market-depth-plan-materialized",
            run: market_depth_plan_materialized,
        },
        Suite {
            name: "market-depth-plan-summary",
            run: market_depth_plan_summary,
        },
        Suite {
            name: "market-depth-plan-summary-scalar",
            run: market_depth_plan_summary_scalar,
        },
        Suite {
            name: "market-depth-plan-summary-simd",
            run: market_depth_plan_summary_simd,
        },
        Suite {
            name: "command-execution",
            run: command_execution,
        },
        Suite {
            name: "engine-resting-order",
            run: engine_resting_order,
        },
        Suite {
            name: "shard-worker-order",
            run: shard_worker_order,
        },
        Suite {
            name: "packed-batch-admit-128",
            run: packed_batch_admit_128,
        },
        Suite {
            name: "authenticated-packed-batch-admit-128",
            run: authenticated_packed_batch_admit_128,
        },
        Suite {
            name: "risk-check",
            run: risk_check,
        },
        Suite {
            name: "incremental-margin",
            run: incremental_margin,
        },
        Suite {
            name: "liquidation-scan",
            run: liquidation_scan,
        },
        Suite {
            name: "oracle-aggregation",
            run: oracle_aggregation,
        },
        Suite {
            name: "signature-verify-single",
            run: signature_verify_single,
        },
        Suite {
            name: "signature-verify-batch",
            run: signature_verify_batch,
        },
        Suite {
            name: "checkpoint-construction",
            run: checkpoint_construction,
        },
        Suite {
            name: "state-root-update",
            run: state_root_update,
        },
        Suite {
            name: "log-serialization",
            run: log_serialization,
        },
        Suite {
            name: "durable-wal-append",
            run: durable_wal_append,
        },
        Suite {
            name: "snapshot-create-restore",
            run: snapshot_create_restore,
        },
        Suite {
            name: "command-replay",
            run: command_replay,
        },
        Suite {
            name: "peer-message-encode",
            run: peer_message_encode,
        },
        Suite {
            name: "peer-message-decode",
            run: peer_message_decode,
        },
        Suite {
            name: "packed-encode-scalar-32",
            run: packed_encode_scalar_32,
        },
        Suite {
            name: "packed-encode-dispatched-32",
            run: packed_encode_simd_32,
        },
        Suite {
            name: "packed-encode-scalar-64",
            run: packed_encode_scalar_64,
        },
        Suite {
            name: "packed-encode-dispatched-64",
            run: packed_encode_simd_64,
        },
        Suite {
            name: "packed-encode-scalar-128",
            run: packed_encode_scalar_128,
        },
        Suite {
            name: "packed-encode-dispatched-128",
            run: packed_encode_simd_128,
        },
        Suite {
            name: "packed-decode-scalar-32",
            run: packed_decode_scalar_32,
        },
        Suite {
            name: "packed-decode-dispatched-32",
            run: packed_decode_simd_32,
        },
        Suite {
            name: "packed-decode-scalar-64",
            run: packed_decode_scalar_64,
        },
        Suite {
            name: "packed-decode-dispatched-64",
            run: packed_decode_simd_64,
        },
        Suite {
            name: "packed-decode-scalar-128",
            run: packed_decode_scalar_128,
        },
        Suite {
            name: "packed-decode-dispatched-128",
            run: packed_decode_simd_128,
        },
        Suite {
            name: "order-batch-lz4-32",
            run: order_batch_lz4_32,
        },
        Suite {
            name: "order-batch-lz4-64",
            run: order_batch_lz4_64,
        },
        Suite {
            name: "order-batch-lz4-128",
            run: order_batch_lz4_128,
        },
        Suite {
            name: "order-batch-lz4-encode-scalar-32",
            run: order_batch_lz4_encode_scalar_32,
        },
        Suite {
            name: "order-batch-lz4-encode-dispatched-32",
            run: order_batch_lz4_encode_simd_32,
        },
        Suite {
            name: "order-batch-lz4-encode-scalar-64",
            run: order_batch_lz4_encode_scalar_64,
        },
        Suite {
            name: "order-batch-lz4-encode-dispatched-64",
            run: order_batch_lz4_encode_simd_64,
        },
        Suite {
            name: "order-batch-lz4-encode-scalar-128",
            run: order_batch_lz4_encode_scalar_128,
        },
        Suite {
            name: "order-batch-lz4-encode-dispatched-128",
            run: order_batch_lz4_encode_simd_128,
        },
        Suite {
            name: "order-batch-lz4-decode-scalar-32",
            run: order_batch_lz4_decode_scalar_32,
        },
        Suite {
            name: "order-batch-lz4-decode-dispatched-32",
            run: order_batch_lz4_decode_simd_32,
        },
        Suite {
            name: "order-batch-lz4-decode-scalar-64",
            run: order_batch_lz4_decode_scalar_64,
        },
        Suite {
            name: "order-batch-lz4-decode-dispatched-64",
            run: order_batch_lz4_decode_simd_64,
        },
        Suite {
            name: "order-batch-lz4-decode-scalar-128",
            run: order_batch_lz4_decode_scalar_128,
        },
        Suite {
            name: "order-batch-lz4-decode-dispatched-128",
            run: order_batch_lz4_decode_simd_128,
        },
        Suite {
            name: "rpc-request-handling",
            run: rpc_request_handling,
        },
        Suite {
            name: "market-data-fanout",
            run: market_data_fanout,
        },
        Suite {
            name: "consensus-notarize-handling",
            run: consensus_notarize_handling,
        },
        Suite {
            name: "minimmit-digest-6",
            run: minimmit_digest_6,
        },
        Suite {
            name: "minimmit-digest-11",
            run: minimmit_digest_11,
        },
        Suite {
            name: "minimmit-digest-16",
            run: minimmit_digest_16,
        },
        Suite {
            name: "minimmit-vote-admission-6",
            run: minimmit_vote_admission_6,
        },
        Suite {
            name: "minimmit-vote-admission-11",
            run: minimmit_vote_admission_11,
        },
        Suite {
            name: "minimmit-vote-admission-16",
            run: minimmit_vote_admission_16,
        },
        Suite {
            name: "minimmit-certificate-assembly-6",
            run: minimmit_certificate_assembly_6,
        },
        Suite {
            name: "minimmit-certificate-assembly-11",
            run: minimmit_certificate_assembly_11,
        },
        Suite {
            name: "minimmit-certificate-assembly-16",
            run: minimmit_certificate_assembly_16,
        },
        Suite {
            name: "minimmit-certificate-verify-m-6",
            run: minimmit_certificate_verify_m_6,
        },
        Suite {
            name: "minimmit-certificate-verify-m-11",
            run: minimmit_certificate_verify_m_11,
        },
        Suite {
            name: "minimmit-certificate-verify-m-16",
            run: minimmit_certificate_verify_m_16,
        },
        Suite {
            name: "minimmit-certificate-verify-l-6",
            run: minimmit_certificate_verify_l_6,
        },
        Suite {
            name: "minimmit-certificate-verify-l-11",
            run: minimmit_certificate_verify_l_11,
        },
        Suite {
            name: "minimmit-certificate-verify-l-16",
            run: minimmit_certificate_verify_l_16,
        },
        Suite {
            name: "minimmit-certificate-invalid-mix-6",
            run: minimmit_certificate_invalid_mix_6,
        },
        Suite {
            name: "minimmit-certificate-invalid-mix-11",
            run: minimmit_certificate_invalid_mix_11,
        },
        Suite {
            name: "minimmit-certificate-invalid-mix-16",
            run: minimmit_certificate_invalid_mix_16,
        },
        Suite {
            name: "light-client-proof-verify",
            run: light_client_proof_verify,
        },
    ]
}

/// Look up a suite by name.
#[must_use]
pub fn find(name: &str) -> Option<Suite> {
    registry().into_iter().find(|s| s.name == name)
}

/// Gate provenance for a suite: the exact production call path it drives and the
/// scale of its fixtures.
///
/// This is what keeps a performance claim honest. Every current suite is a
/// **microbenchmark** of a single crate call (`microbenchmark == true`), *not* a
/// measurement of the fully composed authenticated-RPC → sequencing → durable-journal
/// → execution/risk/root → receipt/checkpoint path over real sockets and storage. A
/// reader of the report can see, for example, that `market-order-execution` calls
/// `OrderBook::submit` directly against a one-maker book — so the number is an
/// engine-only latency, and must be read as such.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteProvenance {
    /// The suite name (matches [`Suite::name`]).
    pub name: &'static str,
    /// The production call path the suite exercises.
    pub call_path: &'static str,
    /// The fixture scale: book depth, account/position counts, batch sizes, etc.
    pub fixture_scale: &'static str,
    /// `true` for a single-crate microbenchmark; `false` for a composed end-to-end
    /// path. No current suite is end-to-end.
    pub microbenchmark: bool,
}

/// Provenance for a named suite, or `None` if the name is not registered.
#[must_use]
pub fn provenance(name: &str) -> Option<SuiteProvenance> {
    // Resolve the canonical `'static` name from the registry; this also rejects any
    // name that is not actually registered.
    let canonical = registry().into_iter().find(|s| s.name == name)?.name;
    let micro = |call_path, fixture_scale| SuiteProvenance {
        name: canonical,
        call_path,
        fixture_scale,
        microbenchmark: true,
    };
    let p = match canonical {
        "order-insertion" => micro(
            "orderbook::OrderBook::submit (resting bid, no cross)",
            "rolling window of 1024 resting orders across 32 price levels",
        ),
        "order-cancellation" => micro(
            "orderbook::OrderBook::{cancel,submit}",
            "steady 1024 resting orders; O(1) cancel + O(1) rest per op",
        ),
        "order-replacement" => micro(
            "orderbook::OrderBook::replace (in-place cancel-replace)",
            "single resting order alternating price/quantity",
        ),
        "market-order-execution" => micro(
            "orderbook::OrderBook::submit (crossing taker, 1 fill)",
            "one resting maker, replenished each op; engine-only, no sockets/journal",
        ),
        "market-order-execution-empty-book" => micro(
            "orderbook::OrderBook::submit (crossing bid, empty book)",
            "0 resting maker levels; the no-liquidity path",
        ),
        "market-order-execution-half-book" => micro(
            "orderbook::OrderBook::submit (crossing taker, 1 fill)",
            "128 resting maker levels; taker consumes 1, depth held constant",
        ),
        "market-order-execution-full-book" => micro(
            "orderbook::OrderBook::submit (crossing taker, 1 fill)",
            "256 resting maker levels; taker consumes 1, depth held constant",
        ),
        "market-order-fill-fanout" => micro(
            "orderbook::OrderBook::submit (crossing taker, 8 fills)",
            "8 maker levels swept per taker; fan-out of 8 fills from one submit",
        ),
        "market-depth-plan-materialized" => micro(
            "orderbook::OrderBook::plan_match (owned diagnostic plan)",
            "128 ask levels and 128 maker fills; retains one PlannedFill per maker",
        ),
        "market-depth-plan-summary" | "market-depth-plan-summary-simd" => micro(
            "orderbook::OrderBook::plan_match_summary (execution pre-trade risk path)",
            "128 ask levels/fills; detected backend batches exact fixed-point products; no retained fill vector",
        ),
        "market-depth-plan-summary-scalar" => micro(
            "orderbook::OrderBook::plan_match_summary (forced scalar reference)",
            "same 128 ask levels/fills and arithmetic as the SIMD pair; no retained fill vector",
        ),
        "command-execution" => micro(
            "execution::Engine::execute (SetMarkPrice → risk recompute)",
            "1 account, 1 perpetual market; engine-only, no sockets/journal",
        ),
        "engine-resting-order" => micro(
            "execution::Engine::execute (PlaceOrder → orderbook/risk/state root/receipt)",
            "1 funded account, 1 perpetual market; 2200 non-crossing bids, no sockets/journal",
        ),
        "shard-worker-order" => micro(
            "node::ShardIngress → ShardWorker::step → ShardEgress",
            "preallocated SPSC rings, 1 Engine owner, accepted resting order; no socket/journal",
        ),
        "packed-batch-admit-128" => micro(
            "network::OrderBatchCodec::decode_into → node::PackedBatchIngress::try_admit → SPSC",
            "128 authenticated-context records; LZ4/CRC/typed decode/lower/atomic ring publish; no signature/socket/Engine",
        ),
        "authenticated-packed-batch-admit-128" => micro(
            "network::AuthenticatedOrderBatchCodec::verify → replay check → node::PackedBatchIngress::try_admit → SPSC",
            "128 records; Ed25519 destination/session/account/sequence binding + LZ4/CRC/typed decode/lower/atomic ring publish; no socket/Engine",
        ),
        "risk-check" => micro(
            "risk::RiskEngine::check_order (pre-trade)",
            "256 accounts, 1 position each; rotating account set",
        ),
        "incremental-margin" => micro(
            "risk::RiskEngine::apply_fill (per-account recompute)",
            "64 accounts, alternating fills",
        ),
        "liquidation-scan" => micro(
            "risk::RiskEngine::liquidation_candidates (full scan)",
            "1024 accounts, 1 position each",
        ),
        "oracle-aggregation" => micro(
            "integer fixed-point median (oracle aggregation stand-in)",
            "21 feeds, one rotated per op",
        ),
        "signature-verify-single" => {
            micro("crypto::verify_ed25519", "1 signature over a fixed message")
        }
        "signature-verify-batch" => {
            micro("crypto::verify_ed25519_all (batch)", "32 signatures per op")
        }
        "checkpoint-construction" => micro(
            "consensus::{build_checkpoint_header,checkpoint_hash}",
            "8 command + 8 execution leaf hashes; no consensus round, no sockets",
        ),
        "state-root-update" => micro(
            "state_tree::StateTree::set_account + root",
            "4096-account tree, 256-byte leaves",
        ),
        "log-serialization" => micro(
            "storage::Record::encode",
            "single 64-byte-payload record; in-memory, no fsync/disk",
        ),
        "durable-wal-append" => micro(
            "storage::DurableLog::append (borrowed payload into reusable frame)",
            "single active segment, 64-byte payload, SyncPolicy::Never; file write included, fsync/rotation excluded",
        ),
        "snapshot-create-restore" => micro(
            "storage::Snapshot::{encode,decode,verify}",
            "256-byte state; in-memory round trip, no disk",
        ),
        "command-replay" => micro(
            "storage::replay over an in-memory SegmentedLog",
            "64 records; in-memory log, no disk",
        ),
        "peer-message-encode" => micro(
            "codec::Frame::encode",
            "single market-data frame; bytes only, no socket",
        ),
        "peer-message-decode" => micro(
            "codec::Frame::decode",
            "single market-data frame; bytes only, no socket",
        ),
        "packed-encode-scalar-32" | "packed-encode-scalar-64" | "packed-encode-scalar-128" => {
            micro(
                "codec::encode_batch_with_backend (scalar reference)",
                "70/20/10 submit/cancel/replace corpus; batch size encoded in suite name",
            )
        }
        "packed-encode-dispatched-32"
        | "packed-encode-dispatched-64"
        | "packed-encode-dispatched-128" => micro(
            "codec::encode_batch_with_backend (runtime-dispatched backend)",
            "same 70/20/10 corpus; production size qualification may select the scalar fallback",
        ),
        "packed-decode-scalar-32" | "packed-decode-scalar-64" | "packed-decode-scalar-128" => {
            micro(
                "codec::decode_batch_with_backend (scalar reference)",
                "70/20/10 packed corpus; batch size encoded in suite name",
            )
        }
        "packed-decode-dispatched-32"
        | "packed-decode-dispatched-64"
        | "packed-decode-dispatched-128" => micro(
            "codec::decode_batch_with_backend (runtime-dispatched backend)",
            "same packed corpus; production size qualification may select the scalar fallback",
        ),
        "order-batch-lz4-32" | "order-batch-lz4-64" | "order-batch-lz4-128" => micro(
            "network::OrderBatchCodec::{encode,decode_into}",
            "compressible 70/20/10 packed corpus; size encoded in suite name; no socket/AEAD",
        ),
        "order-batch-lz4-encode-scalar-32"
        | "order-batch-lz4-encode-scalar-64"
        | "order-batch-lz4-encode-scalar-128" => micro(
            "network::OrderBatchCodec::encode_with_backend (scalar LZ4 reference)",
            "70/20/10 packed corpus; fixed hash table and batch size encoded in suite name",
        ),
        "order-batch-lz4-encode-dispatched-32"
        | "order-batch-lz4-encode-dispatched-64"
        | "order-batch-lz4-encode-dispatched-128" => micro(
            "network::OrderBatchCodec::encode_with_backend (runtime-qualified LZ4 encoder)",
            "same packed corpus; vector match extension at qualified sizes, scalar fallback otherwise",
        ),
        "order-batch-lz4-decode-scalar-32"
        | "order-batch-lz4-decode-scalar-64"
        | "order-batch-lz4-decode-scalar-128" => micro(
            "network::OrderBatchCodec::decode_into_with_backend (scalar LZ4 reference)",
            "precompressed 70/20/10 packed corpus; batch size encoded in suite name",
        ),
        "order-batch-lz4-decode-dispatched-32"
        | "order-batch-lz4-decode-dispatched-64"
        | "order-batch-lz4-decode-dispatched-128" => micro(
            "network::OrderBatchCodec::decode_into_with_backend (runtime vector LZ4 copy kernel)",
            "same precompressed corpus; runtime AVX-512/AVX2/NEON selection with scalar fallback",
        ),
        "rpc-request-handling" => micro(
            "codec decode → dispatch → encode (RPC hot path)",
            "single request; bytes only, no socket, no auth",
        ),
        "market-data-fanout" => micro(
            "codec::Frame::encode → per-subscriber buffer copy",
            "64 subscribers, 1-slot queues; in-process, no sockets",
        ),
        "consensus-notarize-handling" => micro(
            "consensus::MinimmitReplica::admit_notarize (verifies signature)",
            "6-validator Minimmit committee, 1 notarize per op",
        ),
        "minimmit-digest-6" | "minimmit-digest-11" | "minimmit-digest-16" => micro(
            "consensus::{notarize_digest,nullify_digest,execution_commitment_digest}",
            "fixed-stack canonical preimages; committee size encoded in suite name",
        ),
        "minimmit-vote-admission-6"
        | "minimmit-vote-admission-11"
        | "minimmit-vote-admission-16" => micro(
            "consensus::{Notarize,Nullify,ExecAttest}::verify with cached committee keys",
            "one valid vote of every kind plus one invalid signature; committee size encoded in suite name",
        ),
        "minimmit-certificate-assembly-6"
        | "minimmit-certificate-assembly-11"
        | "minimmit-certificate-assembly-16" => micro(
            "consensus::MinimmitCommittee::assemble for M and L signer sets",
            "fixed-stack dedup/bitmap accumulation and owned QC output; committee size encoded in suite name",
        ),
        "minimmit-certificate-verify-m-6"
        | "minimmit-certificate-verify-m-11"
        | "minimmit-certificate-verify-m-16" => micro(
            "consensus::{Notarization,Nullification}::verify at advance threshold M",
            "valid notarize and nullify certificates; committee size encoded in suite name",
        ),
        "minimmit-certificate-verify-l-6"
        | "minimmit-certificate-verify-l-11"
        | "minimmit-certificate-verify-l-16" => micro(
            "consensus::MinimmitCommittee::verify_detailed plus ExecutionCertificate::verify at L",
            "valid ordering and execution certificates; committee size encoded in suite name",
        ),
        "minimmit-certificate-invalid-mix-6"
        | "minimmit-certificate-invalid-mix-11"
        | "minimmit-certificate-invalid-mix-16" => micro(
            "consensus::MinimmitCommittee::verify_detailed invalid-signer attribution",
            "two corrupted signatures; deterministic first invalid index; committee size encoded in suite name",
        ),
        "light-client-proof-verify" => micro(
            "state_tree::verify_account (Merkle proof)",
            "1024-account tree, 64 populated; single membership proof",
        ),
        _ => return None,
    };
    Some(p)
}

/// Provenance for every registered suite, in registry order.
#[must_use]
pub fn all_provenance() -> Vec<SuiteProvenance> {
    registry()
        .iter()
        .filter_map(|s| provenance(s.name))
        .collect()
}

// --------------------------------------------------------------------- helpers

fn price(units: i64) -> Price {
    Price::from_raw(units.saturating_mul(types::PRICE_SCALE))
}

fn qty(units: i64) -> Quantity {
    Quantity::from_raw(units.saturating_mul(types::QTY_SCALE))
}

fn amt(units: i128) -> Amount {
    Amount::from_raw(units.saturating_mul(types::AMOUNT_SCALE))
}

fn bid(order_id: u64, client_id: u64, px: i64, q: i64) -> NewOrder {
    NewOrder {
        order_id: OrderId::new(order_id),
        account: AccountId::new(1),
        side: Side::Bid,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: price(px),
        quantity: qty(q),
        client_id,
        reduce_only: false,
    }
}

fn ask(order_id: u64, client_id: u64, px: i64, q: i64, account: u32) -> NewOrder {
    NewOrder {
        order_id: OrderId::new(order_id),
        account: AccountId::new(account),
        side: Side::Ask,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: price(px),
        quantity: qty(q),
        client_id,
        reduce_only: false,
    }
}

fn default_risk_config() -> RiskConfig {
    RiskConfig::new(
        Ratio::from_raw(100_000),                 // 10% initial
        Ratio::from_raw(50_000),                  // 5% maintenance
        Ratio::from_raw(20 * types::RATIO_SCALE), // 20x
    )
    .unwrap_or(RiskConfig {
        initial_margin: Ratio::ONE,
        maintenance_margin: Ratio::ONE,
        max_leverage: Ratio::ONE,
        max_accounts: risk::DEFAULT_MAX_ACCOUNTS,
        max_markets: risk::DEFAULT_MAX_MARKETS,
    })
}

// ---------------------------------------------------------------- order suites

/// Steady-state insertion of resting bids. The book is bounded to a rolling
/// `WINDOW` of resting orders via an O(1) cancel of the order inserted `WINDOW`
/// steps ago. `WINDOW` is a multiple of the 32 price levels used, so each step
/// adds and cancels at the *same* level — the level never empties and the warm
/// path performs zero allocation.
fn order_insertion(cfg: Config) -> BenchStat {
    const WINDOW: u64 = 1024;
    let mut book = OrderBook::new(BookConfig::default());
    let mut n: u64 = 0;
    bench("order-insertion", cfg, || {
        // Non-crossing bids (no asks present) all rest.
        let px = 100 + i64::try_from(n % 32).unwrap_or(0);
        let r = book.submit(bid(n, n, px, 1));
        black_box(r.is_ok());
        if n >= WINDOW {
            let _ = book.cancel(OrderId::new(n - WINDOW));
        }
        n += 1;
    })
}

/// Steady-state cancellation: cancel a resting order and re-insert a fresh one,
/// holding the resting set at `WINDOW`. O(1) cancel + O(1) rest, no allocation.
fn order_cancellation(cfg: Config) -> BenchStat {
    const WINDOW: u64 = 1024;
    let mut book = OrderBook::new(BookConfig::default());
    let mut next: u64 = 0;
    // Pre-fill WINDOW resting bids.
    for _ in 0..WINDOW {
        let px = 100 + i64::try_from(next % 32).unwrap_or(0);
        let _ = book.submit(bid(next, next, px, 1));
        next += 1;
    }
    let mut cursor: u64 = 0;
    bench("order-cancellation", cfg, || {
        let _ = book.cancel(OrderId::new(cursor));
        let px = 100 + i64::try_from(next % 32).unwrap_or(0);
        let _ = book.submit(bid(next, next, px, 1));
        cursor += 1;
        next += 1;
    })
}

fn depth_scan_fixture(backend: simd::Backend) -> (OrderBook, NewOrder) {
    let mut book = OrderBook::new(BookConfig {
        matching_backend: backend,
        ..BookConfig::default()
    });
    for i in 0..128u64 {
        let _ = book.submit(ask(
            i + 1,
            i + 1,
            100 + i64::try_from(i).unwrap_or(0),
            1,
            u32::try_from(i + 1).unwrap_or(0),
        ));
    }
    let taker = NewOrder {
        order_id: OrderId::new(10_000),
        account: AccountId::new(10_000),
        side: Side::Bid,
        order_type: OrderType::Market,
        tif: TimeInForce::Ioc,
        price: price(227),
        quantity: qty(128),
        client_id: 10_000,
        reduce_only: false,
    };
    (book, taker)
}

/// Former risk path: retain a `PlannedFill` for every maker, then return an
/// owned plan. Kept as a paired component baseline for the aggregate scan.
fn market_depth_plan_materialized(cfg: Config) -> BenchStat {
    let (book, taker) = depth_scan_fixture(simd::Backend::Scalar);
    bench("market-depth-plan-materialized", cfg, || {
        black_box(book.plan_match(&taker).is_ok());
    })
}

/// Current risk path: same deterministic scan and arithmetic without retaining
/// temporary price/fill vectors.
fn market_depth_plan_summary(cfg: Config) -> BenchStat {
    let (book, taker) = depth_scan_fixture(simd::detect());
    bench("market-depth-plan-summary", cfg, || {
        black_box(book.plan_match_summary(&taker).is_ok());
    })
}

/// Full-width scalar reference paired against the detected SIMD summary.
fn market_depth_plan_summary_scalar(cfg: Config) -> BenchStat {
    let (book, taker) = depth_scan_fixture(simd::Backend::Scalar);
    bench("market-depth-plan-summary-scalar", cfg, || {
        black_box(book.plan_match_summary(&taker).is_ok());
    })
}

/// Production match-planning summary with the best runnable SIMD backend.
fn market_depth_plan_summary_simd(cfg: Config) -> BenchStat {
    let (book, taker) = depth_scan_fixture(simd::detect());
    bench("market-depth-plan-summary-simd", cfg, || {
        black_box(book.plan_match_summary(&taker).is_ok());
    })
}

/// Atomic cancel-replace of a resting order in place.
fn order_replacement(cfg: Config) -> BenchStat {
    let mut book = OrderBook::new(BookConfig::default());
    let _ = book.submit(bid(1, 1, 100, 5));
    let mut toggle = false;
    bench("order-replacement", cfg, || {
        // Alternate price/qty so each replace does real work.
        let (px, q) = if toggle { (101, 6) } else { (100, 5) };
        let r = book.replace(OrderId::new(1), price(px), qty(q));
        black_box(r.is_ok());
        toggle = !toggle;
    })
}

/// A crossing taker consuming one resting maker (one fill), with the maker
/// replenished each iteration so the book is bounded. This is the engine-only
/// execution latency suite.
fn market_order_execution(cfg: Config) -> BenchStat {
    let mut book = OrderBook::new(BookConfig::default());
    let mut oid: u64 = 1;
    bench("market-order-execution", cfg, || {
        // Rest one maker ask, then cross it fully with a taker bid.
        let maker = ask(oid, oid, 100, 1, 2);
        let _ = book.submit(maker);
        let taker = bid(oid + 1, oid + 1, 100, 1);
        let r = book.submit(taker);
        black_box(r.is_ok());
        oid += 2;
    })
}

/// Execution against an **empty** book: a marketable bid finds no resting maker and
/// rests instead of filling. Bounds the resting set with an O(1) cancel of the order
/// inserted `WINDOW` steps ago. This is the no-liquidity leg of the book-state matrix.
fn market_order_execution_empty_book(cfg: Config) -> BenchStat {
    const WINDOW: u64 = 1024;
    let mut book = OrderBook::new(BookConfig::default());
    let mut n: u64 = 0;
    bench("market-order-execution-empty-book", cfg, || {
        // No resting asks: the crossing bid finds nothing and rests.
        let r = book.submit(bid(n, n, 100, 1));
        black_box(r.is_ok());
        if n >= WINDOW {
            let _ = book.cancel(OrderId::new(n - WINDOW));
        }
        n += 1;
    })
}

/// Execution against a book resting `prefill` distinct ask levels, crossing the best
/// maker each step and replenishing that level so the depth stays constant. Shared by
/// the half- and full-book legs of the matrix.
fn execution_over_depth(name: &'static str, cfg: Config, prefill: i64) -> BenchStat {
    let mut book = OrderBook::new(BookConfig::default());
    let mut oid: u64 = 1;
    // Pre-fill `prefill` distinct resting ask levels (prices 200..200+prefill).
    for lvl in 0..prefill {
        let _ = book.submit(ask(oid, oid, 200 + lvl, 1, 2));
        oid += 1;
    }
    bench(name, cfg, || {
        // Cross the best resting maker (price 200), then replenish that level so the
        // book stays deep: a taker consuming one maker with `prefill-1` levels resting.
        let r = book.submit(bid(oid, oid, 200, 1));
        black_box(r.is_ok());
        oid += 1;
        let _ = book.submit(ask(oid, oid, 200, 1, 2));
        oid += 1;
    })
}

/// Execution against a **half-depth** resting book (128 levels).
fn market_order_execution_half_book(cfg: Config) -> BenchStat {
    execution_over_depth("market-order-execution-half-book", cfg, 128)
}

/// Execution against a **full-depth** resting book (256 levels).
fn market_order_execution_full_book(cfg: Config) -> BenchStat {
    execution_over_depth("market-order-execution-full-book", cfg, 256)
}

/// Fill fan-out: one crossing taker sweeps `FANOUT` resting makers across `FANOUT`
/// price levels in a single submit, producing `FANOUT` fills. The makers are rebuilt
/// each step so the workload stays bounded.
fn market_order_fill_fanout(cfg: Config) -> BenchStat {
    const FANOUT: i64 = 8;
    let mut book = OrderBook::new(BookConfig::default());
    let mut oid: u64 = 1;
    bench("market-order-fill-fanout", cfg, || {
        for lvl in 0..FANOUT {
            let _ = book.submit(ask(oid, oid, 100 + lvl, 1, 2));
            oid += 1;
        }
        // Taker priced at the top level with quantity FANOUT sweeps every maker.
        let r = book.submit(bid(oid, oid, 100 + FANOUT - 1, FANOUT));
        black_box(r.is_ok());
        oid += 1;
    })
}

/// Apply a `SetMarkPrice` command through the deterministic execution engine
/// (drives risk recomputation) on an established account+market.
fn command_execution(cfg: Config) -> BenchStat {
    let mut engine = Engine::new(EngineConfig::default());
    let mut seq: u64 = 1;
    engine
        .execute(
            SequenceNumber::new(seq),
            Command::CreateAccount(execution::CreateAccount {
                initial_collateral: amt(1_000_000),
            }),
        )
        .ok();
    seq += 1;
    engine
        .execute(
            SequenceNumber::new(seq),
            Command::CreateMarket(execution::CreateMarket {
                market: MarketId::new(0),
                market_type: types::MarketType::Perpetual,
                outcomes: 1,
                mark_price: price(100),
            }),
        )
        .ok();
    seq += 1;
    let mut tick: i64 = 100;
    bench("command-execution", cfg, || {
        tick = if tick == 100 { 101 } else { 100 };
        let r = engine.execute(
            SequenceNumber::new(seq),
            Command::SetMarkPrice(SetMarkPrice {
                market: MarketId::new(0),
                price: price(tick),
            }),
        );
        black_box(r.is_ok());
        seq += 1;
    })
}

/// Accepted resting order through the complete synchronous execution core.
fn engine_resting_order(cfg: Config) -> BenchStat {
    let mut engine = Engine::new(EngineConfig::default());
    let mut seq = 1u64;
    engine
        .execute(
            SequenceNumber::new(seq),
            Command::CreateAccount(execution::CreateAccount {
                initial_collateral: amt(1_000_000),
            }),
        )
        .unwrap();
    seq += 1;
    engine
        .execute(
            SequenceNumber::new(seq),
            Command::CreateMarket(execution::CreateMarket {
                market: MarketId::new(0),
                market_type: types::MarketType::Perpetual,
                outcomes: 1,
                mark_price: price(100),
            }),
        )
        .unwrap();
    seq += 1;
    let mut order_id = 1u64;
    bench("engine-resting-order", cfg, || {
        let result = engine.execute(
            SequenceNumber::new(seq),
            Command::PlaceOrder(PlaceOrder {
                account: AccountId::new(0),
                market: MarketId::new(0),
                order_id: OrderId::new(order_id),
                side: Side::Bid,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: price(1),
                quantity: qty(1),
                client_id: order_id,
                reduce_only: false,
                instrument: 0,
                auth: Authorization::Master,
            }),
        );
        black_box(result.is_ok());
        seq += 1;
        order_id += 1;
    })
}

/// Accepted order through the bounded lock-free shard-owner handoff.
fn shard_worker_order(cfg: Config) -> BenchStat {
    let mut engine = Engine::new(EngineConfig::default());
    let mut seq = 1u64;
    engine
        .execute(
            SequenceNumber::new(seq),
            Command::CreateAccount(execution::CreateAccount {
                initial_collateral: amt(1_000_000),
            }),
        )
        .unwrap();
    seq += 1;
    engine
        .execute(
            SequenceNumber::new(seq),
            Command::CreateMarket(execution::CreateMarket {
                market: MarketId::new(0),
                market_type: types::MarketType::Perpetual,
                outcomes: 1,
                mark_price: price(100),
            }),
        )
        .unwrap();
    seq += 1;
    let (mut ingress, mut worker, mut egress) = node::shard_pipeline(engine, 1024, 1024).unwrap();
    let mut order_id = 1u64;
    bench("shard-worker-order", cfg, || {
        let submitted = ingress.try_submit(node::ShardCommand {
            sequence: SequenceNumber::new(seq),
            command: Command::PlaceOrder(PlaceOrder {
                account: AccountId::new(0),
                market: MarketId::new(0),
                order_id: OrderId::new(order_id),
                side: Side::Bid,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: price(1),
                quantity: qty(1),
                client_id: order_id,
                reduce_only: false,
                instrument: 0,
                auth: Authorization::Master,
            }),
        });
        black_box(submitted.is_ok());
        black_box(worker.step());
        if let Some(effect) = egress.try_recv() {
            black_box(effect.result.is_ok());
        }
        seq += 1;
        order_id += 1;
    })
}

/// Authenticated compressed bytes through CRC, typed packed decode, faithful
/// engine-command lowering, and atomic lock-free publication. The consumer is
/// drained directly so this suite isolates admission from execution, which has
/// its own `shard-worker-order` suite.
fn packed_batch_admit_128(cfg: Config) -> BenchStat {
    const COUNT: usize = 128;
    let records = packed_corpus(COUNT);
    let mut packed = vec![0u8; COUNT * codec::PACKED_SUBMIT_LEN];
    let packed_len = codec::encode_batch_into(&records, &mut packed).unwrap();
    let mut encoder = network::OrderBatchCodec::new();
    let envelope = encoder
        .encode(128, false, &packed[..packed_len])
        .unwrap()
        .bytes
        .to_vec();
    let (mut ingress, mut consumer) = node::shard_command_ring(256).unwrap();
    let mut decoder = node::PackedBatchIngress::new();
    let mut first_sequence = 1u64;

    bench("packed-batch-admit-128", cfg, || {
        let admitted = decoder
            .try_admit(
                &mut ingress,
                &envelope,
                node::AuthenticatedPackedBatch {
                    session_ref: 7,
                    account: AccountId::new(9),
                    authority: node::PackedAuthority::Master,
                    first_sequence: SequenceNumber::new(first_sequence),
                    sequencer_now: 1,
                },
            )
            .unwrap();
        black_box(admitted);
        for _ in 0..COUNT {
            let command = consumer.try_pop().expect("preflighted batch must publish");
            black_box((command.sequence, command.command.command_type()));
        }
        first_sequence = first_sequence.saturating_add(u64::try_from(COUNT).unwrap_or(u64::MAX));
    })
}

/// Signed wrapper verification, strict replay/sequence admission, compressed
/// decode, lowering, and atomic SPSC publication. Envelopes are prepared outside
/// the timed closure so the suite measures the receive path, not load generation.
fn authenticated_packed_batch_admit_128(cfg: Config) -> BenchStat {
    const COUNT: usize = 128;
    let records = packed_corpus(COUNT);
    let mut packed = vec![0u8; COUNT * codec::PACKED_SUBMIT_LEN];
    let packed_len = codec::encode_batch_into(&records, &mut packed).unwrap();
    let signer = KeyPair::from_seed(&[11; 32]);
    let total = usize::try_from(cfg.warmup.saturating_add(cfg.iterations)).unwrap_or(usize::MAX);
    let mut encoder = network::AuthenticatedOrderBatchCodec::new();
    let mut envelopes = Vec::with_capacity(total);
    for index in 0..total {
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        let first_sequence =
            1u64.saturating_add(index.saturating_mul(u64::try_from(COUNT).unwrap_or(u64::MAX)));
        envelopes.push(
            encoder
                .encode(
                    network::OrderBatchBinding {
                        destination: [5; 32],
                        session_ref: 7,
                        account: AccountId::new(9),
                        batch_sequence: index,
                        first_sequence,
                    },
                    &signer,
                    128,
                    false,
                    &packed[..packed_len],
                )
                .unwrap()
                .bytes
                .to_vec(),
        );
    }
    let (mut ingress, mut consumer) = node::shard_command_ring(256).unwrap();
    let mut decoder = node::AuthenticatedPackedBatchIngress::new(node::PackedSession {
        destination: [5; 32],
        session_ref: 7,
        account: AccountId::new(9),
        signer: signer.public(),
        authority: node::PackedAuthority::Master,
        first_batch_sequence: 0,
        first_command_sequence: SequenceNumber::new(1),
        batch_sequence_stride: 1,
        command_sequence_stride: 0,
    });
    let mut index = 0usize;

    bench("authenticated-packed-batch-admit-128", cfg, || {
        let admitted = decoder
            .try_admit(&mut ingress, &envelopes[index], 1)
            .unwrap();
        black_box(admitted);
        for _ in 0..COUNT {
            let command = consumer.try_pop().expect("preflighted batch must publish");
            black_box((command.sequence, command.command.command_type()));
        }
        index = index.saturating_add(1);
    })
}

// ----------------------------------------------------------------- risk suites

fn build_risk_engine(accounts: u32) -> RiskEngine {
    let mut e = RiskEngine::new(default_risk_config());
    e.set_mark_price(MarketId::new(1), price(100)).ok();
    for a in 0..accounts {
        e.open_account(AccountId::new(a), amt(10_000)).ok();
        e.apply_fill(AccountId::new(a), MarketId::new(1), qty(5), price(100))
            .ok();
    }
    e
}

/// Allocation-free pre-trade risk check across a rotating account set.
fn risk_check(cfg: Config) -> BenchStat {
    const ACCOUNTS: u32 = 256;
    let engine = build_risk_engine(ACCOUNTS);
    let mut a: u32 = 0;
    bench("risk-check", cfg, || {
        let r = engine.check_order(AccountId::new(a % ACCOUNTS), amt(100), false);
        black_box(r.is_ok());
        a = a.wrapping_add(1);
    })
}

/// Incremental margin update: apply alternating fills that keep positions
/// bounded while forcing a per-account recompute each iteration.
fn incremental_margin(cfg: Config) -> BenchStat {
    let mut engine = build_risk_engine(64);
    let mut a: u32 = 0;
    let mut buy = true;
    bench("incremental-margin", cfg, || {
        let q = if buy { qty(1) } else { qty(-1) };
        let r = engine.apply_fill(AccountId::new(a % 64), MarketId::new(1), q, price(100));
        black_box(r.is_ok());
        a = a.wrapping_add(1);
        if a.is_multiple_of(64) {
            buy = !buy;
        }
    })
}

/// Liquidation scan streaming the equity/maintenance columns over all accounts.
fn liquidation_scan(cfg: Config) -> BenchStat {
    const ACCOUNTS: u32 = 1024;
    let engine = build_risk_engine(ACCOUNTS);
    bench("liquidation-scan", cfg, || {
        let candidates = engine.liquidation_candidates();
        black_box(candidates.len());
    })
}

// -------------------------------------------------------------- oracle suite

/// Deterministic fixed-point median of a fixed set of oracle prices. A dep-free
/// stand-in for oracle aggregation using integer-only math.
fn median_price(samples: &mut [Price]) -> Price {
    samples.sort_unstable();
    let n = samples.len();
    if n == 0 {
        return Price::ZERO;
    }
    if n % 2 == 1 {
        samples[n / 2]
    } else {
        // Average of the two middle values (integer mean, floor).
        let lo = samples[n / 2 - 1].raw();
        let hi = samples[n / 2].raw();
        Price::from_raw(lo.saturating_add(hi) / 2)
    }
}

fn oracle_aggregation(cfg: Config) -> BenchStat {
    const FEEDS: usize = 21;
    let mut rng = Lcg::new(SEED);
    let base: Vec<Price> = (0..FEEDS)
        .map(|_| price(90 + rng.range_i64(0, 20)))
        .collect();
    let mut scratch = base.clone();
    let mut rot = 0usize;
    bench("oracle-aggregation", cfg, || {
        scratch.copy_from_slice(&base);
        // Rotate one feed so the sort input varies but stays bounded.
        let i = rot % FEEDS;
        scratch[i] = price(90 + i64::try_from(rot % 20).unwrap_or(0));
        let m = median_price(&mut scratch);
        black_box(m.raw());
        rot = rot.wrapping_add(1);
    })
}

// -------------------------------------------------------------- crypto suites

fn signature_verify_single(cfg: Config) -> BenchStat {
    let kp = KeyPair::from_seed(&[7u8; 32]);
    let pk = kp.public();
    let msg = b"dexos-benchmark-message".to_vec();
    let sig = kp.sign(&msg);
    bench("signature-verify-single", cfg, || {
        let r = verify_ed25519(&pk, &msg, &sig);
        black_box(r.is_ok());
    })
}

fn signature_verify_batch(cfg: Config) -> BenchStat {
    const BATCH: usize = 32;
    let mut items = Vec::with_capacity(BATCH);
    for i in 0..BATCH {
        let kp = KeyPair::from_seed(&[u8::try_from(i).unwrap_or(0); 32]);
        let msg = format!("msg-{i}").into_bytes();
        let sig = kp.sign(&msg);
        items.push((kp.public(), msg, sig));
    }
    bench("signature-verify-batch", cfg, || {
        let results = verify_ed25519_all(&items);
        black_box(results.iter().all(|&ok| ok));
    })
}

// ------------------------------------------------------ consensus/storage

fn checkpoint_construction(cfg: Config) -> BenchStat {
    const WIDTH: usize = 8;
    let cmds: Vec<Hash> = (0..WIDTH)
        .map(|i| Hash::from_bytes([u8::try_from(i).unwrap_or(0); 32]))
        .collect();
    let execs: Vec<Hash> = (0..WIDTH)
        .map(|i| Hash::from_bytes([u8::try_from(i + 100).unwrap_or(0); 32]))
        .collect();
    let mut first: u64 = 0;
    bench("checkpoint-construction", cfg, || {
        let last = first + (WIDTH as u64) - 1;
        let header = build_checkpoint_header(
            0,
            ShardId::new(0),
            first,
            last,
            Hash::ZERO,
            Hash::from_bytes([5u8; 32]),
            &cmds,
            &execs,
            Hash::from_bytes([9u8; 32]),
            42,
        );
        if let Ok(h) = header {
            black_box(checkpoint_hash(&h).is_zero());
        }
        first += WIDTH as u64;
    })
}

fn state_root_update(cfg: Config) -> BenchStat {
    let mut tree = StateTree::new(4096, 256);
    let mut a: u32 = 0;
    let mut v: i128 = 0;
    bench("state-root-update", cfg, || {
        let payload = LeafWriter::new().field_u32(a % 4096).field_i128(v).finish();
        let _ = tree.set_account(AccountId::new(a % 4096), &payload);
        black_box(tree.root().is_zero());
        a = a.wrapping_add(1);
        v = v.wrapping_add(1);
    })
}

fn log_serialization(cfg: Config) -> BenchStat {
    let mut rec = Record {
        protocol_version: PROTOCOL_VERSION,
        sequence: 0,
        timestamp: 0,
        command_type: 1,
        payload: vec![0xABu8; 64],
    };
    bench("log-serialization", cfg, || {
        rec.sequence = rec.sequence.wrapping_add(1);
        rec.timestamp = rec.timestamp.wrapping_add(1);
        if let Ok(bytes) = rec.encode() {
            black_box(bytes.len());
        }
    })
}

fn durable_wal_append(cfg: Config) -> BenchStat {
    let instance = WAL_BENCHMARK_INSTANCE.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dexos-durable-wal-benchmark-{}-{instance}",
        std::process::id(),
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let mut log = DurableLog::open(
        DurableConfig::new(&dir)
            .with_sync(SyncPolicy::Never)
            .with_segment_max_bytes(storage::DEFAULT_SEGMENT_BYTES),
    )
    .unwrap();
    let payload = [0xAB; 64];
    let mut sequence = 1u64;
    let stat = bench("durable-wal-append", cfg, || {
        log.append(sequence, sequence, 1, &payload).unwrap();
        sequence = sequence.saturating_add(1);
    });
    drop(log);
    let _ = std::fs::remove_dir_all(dir);
    stat
}

fn snapshot_create_restore(cfg: Config) -> BenchStat {
    let state = vec![0x5Au8; 256];
    let mut seq: u64 = 0;
    bench("snapshot-create-restore", cfg, || {
        seq = seq.wrapping_add(1);
        let root = crypto::hash_leaf(&state);
        let snap = Snapshot::new(root, seq, state.clone());
        if let Ok(bytes) = snap.encode() {
            if let Ok(restored) = Snapshot::decode(&bytes) {
                black_box(restored.verify(root));
            }
        }
    })
}

fn command_replay(cfg: Config) -> BenchStat {
    const RECORDS: u64 = 64;
    let mut log = SegmentedLog::new(4096);
    for seq in 1..=RECORDS {
        log.append(seq, seq, 1, format!("cmd-{seq}").as_bytes())
            .ok();
    }
    bench("command-replay", cfg, || {
        let mut acc = Hash::ZERO;
        let _ = replay(&log, None, |rec| {
            // Cheap deterministic fold standing in for an engine transition.
            let mut sum = acc.as_bytes()[0];
            for b in &rec.payload {
                sum = sum.wrapping_add(*b);
            }
            let mut bytes = *acc.as_bytes();
            bytes[0] = sum;
            acc = Hash::from_bytes(bytes);
        });
        black_box(acc.is_zero());
    })
}

// ------------------------------------------------------------- codec/network

fn packed_corpus(count: usize) -> Vec<PackedOrder> {
    (0..count)
        .map(|i| {
            let id = u64::try_from(i + 1).unwrap_or(u64::MAX);
            match i % 10 {
                0..=6 => PackedOrder::Submit {
                    session_ref: 7,
                    nonce: id,
                    client_id: id,
                    account: AccountId::new(9),
                    market: MarketId::new(3),
                    side: if i & 1 == 0 { Side::Bid } else { Side::Ask },
                    order_type: OrderType::Limit,
                    price: price(100),
                    quantity: qty(1),
                    time_in_force: TimeInForce::Gtc,
                    leverage: Ratio::ONE,
                },
                7..=8 => PackedOrder::Cancel {
                    session_ref: 7,
                    nonce: id,
                    client_id: id,
                    account: AccountId::new(9),
                    market: MarketId::new(3),
                    order_id: OrderId::new(id),
                },
                _ => PackedOrder::Replace {
                    session_ref: 7,
                    nonce: id,
                    client_id: id,
                    account: AccountId::new(9),
                    market: MarketId::new(3),
                    order_id: OrderId::new(id),
                    new_price: price(101),
                    new_quantity: qty(2),
                },
            }
        })
        .collect()
}

fn packed_encode_bench(
    name: &'static str,
    cfg: Config,
    count: usize,
    backend: simd::Backend,
) -> BenchStat {
    let records = packed_corpus(count);
    let mut output = vec![0u8; count * codec::PACKED_SUBMIT_LEN];
    bench(name, cfg, || {
        let encoded = codec::encode_batch_with_backend(&records, backend, &mut output).unwrap();
        black_box(encoded);
    })
}

fn packed_decode_bench(
    name: &'static str,
    cfg: Config,
    count: usize,
    backend: simd::Backend,
) -> BenchStat {
    let records = packed_corpus(count);
    let mut encoded = vec![0u8; count * codec::PACKED_SUBMIT_LEN];
    let encoded_len =
        codec::encode_batch_with_backend(&records, simd::Backend::Scalar, &mut encoded).unwrap();
    let mut output = records.clone();
    bench(name, cfg, || {
        let decoded =
            codec::decode_batch_with_backend(&encoded[..encoded_len], backend, &mut output)
                .unwrap();
        black_box(decoded);
    })
}

macro_rules! packed_bench_wrappers {
    ($count:literal, $enc_scalar:ident, $enc_simd:ident, $dec_scalar:ident, $dec_simd:ident) => {
        fn $enc_scalar(cfg: Config) -> BenchStat {
            packed_encode_bench(
                concat!("packed-encode-scalar-", stringify!($count)),
                cfg,
                $count,
                simd::Backend::Scalar,
            )
        }

        fn $enc_simd(cfg: Config) -> BenchStat {
            packed_encode_bench(
                concat!("packed-encode-dispatched-", stringify!($count)),
                cfg,
                $count,
                simd::detect(),
            )
        }

        fn $dec_scalar(cfg: Config) -> BenchStat {
            packed_decode_bench(
                concat!("packed-decode-scalar-", stringify!($count)),
                cfg,
                $count,
                simd::Backend::Scalar,
            )
        }

        fn $dec_simd(cfg: Config) -> BenchStat {
            packed_decode_bench(
                concat!("packed-decode-dispatched-", stringify!($count)),
                cfg,
                $count,
                simd::detect(),
            )
        }
    };
}

packed_bench_wrappers!(
    32,
    packed_encode_scalar_32,
    packed_encode_simd_32,
    packed_decode_scalar_32,
    packed_decode_simd_32
);
packed_bench_wrappers!(
    64,
    packed_encode_scalar_64,
    packed_encode_simd_64,
    packed_decode_scalar_64,
    packed_decode_simd_64
);
packed_bench_wrappers!(
    128,
    packed_encode_scalar_128,
    packed_encode_simd_128,
    packed_decode_scalar_128,
    packed_decode_simd_128
);

fn order_batch_lz4_bench(name: &'static str, cfg: Config, count: usize) -> BenchStat {
    let records = packed_corpus(count);
    let mut packed = vec![0u8; count * codec::PACKED_SUBMIT_LEN];
    let packed_len =
        codec::encode_batch_with_backend(&records, simd::Backend::Scalar, &mut packed).unwrap();
    let mut batch_codec = network::OrderBatchCodec::new();
    let mut decoded = vec![0u8; network::ORDER_BATCH_MAX_UNCOMPRESSED];
    let record_count = u8::try_from(count).unwrap_or(u8::MAX);
    bench(name, cfg, || {
        let encoded = batch_codec
            .encode(record_count, false, &packed[..packed_len])
            .unwrap();
        let result = network::OrderBatchCodec::decode_into(encoded.bytes, &mut decoded).unwrap();
        black_box(result.records.len());
    })
}

fn order_batch_lz4_32(cfg: Config) -> BenchStat {
    order_batch_lz4_bench("order-batch-lz4-32", cfg, 32)
}

fn order_batch_lz4_64(cfg: Config) -> BenchStat {
    order_batch_lz4_bench("order-batch-lz4-64", cfg, 64)
}

fn order_batch_lz4_128(cfg: Config) -> BenchStat {
    order_batch_lz4_bench("order-batch-lz4-128", cfg, 128)
}

fn order_batch_lz4_encode_bench(
    name: &'static str,
    cfg: Config,
    count: usize,
    backend: simd::Backend,
) -> BenchStat {
    let records = packed_corpus(count);
    let mut packed = vec![0u8; count * codec::PACKED_SUBMIT_LEN];
    let packed_len =
        codec::encode_batch_with_backend(&records, simd::Backend::Scalar, &mut packed).unwrap();
    let mut batch_codec = network::OrderBatchCodec::new();
    let record_count = u8::try_from(count).unwrap_or(u8::MAX);
    bench(name, cfg, || {
        let encoded = batch_codec
            .encode_with_backend(record_count, false, &packed[..packed_len], backend)
            .unwrap();
        black_box((encoded.bytes.len(), encoded.raw));
    })
}

macro_rules! lz4_encode_bench_wrappers {
    ($count:literal, $scalar:ident, $vector:ident) => {
        fn $scalar(cfg: Config) -> BenchStat {
            order_batch_lz4_encode_bench(
                concat!("order-batch-lz4-encode-scalar-", stringify!($count)),
                cfg,
                $count,
                simd::Backend::Scalar,
            )
        }

        fn $vector(cfg: Config) -> BenchStat {
            order_batch_lz4_encode_bench(
                concat!("order-batch-lz4-encode-dispatched-", stringify!($count)),
                cfg,
                $count,
                simd::detect(),
            )
        }
    };
}

lz4_encode_bench_wrappers!(
    32,
    order_batch_lz4_encode_scalar_32,
    order_batch_lz4_encode_simd_32
);
lz4_encode_bench_wrappers!(
    64,
    order_batch_lz4_encode_scalar_64,
    order_batch_lz4_encode_simd_64
);
lz4_encode_bench_wrappers!(
    128,
    order_batch_lz4_encode_scalar_128,
    order_batch_lz4_encode_simd_128
);

fn order_batch_lz4_decode_bench(
    name: &'static str,
    cfg: Config,
    count: usize,
    backend: simd::Backend,
) -> BenchStat {
    let records = packed_corpus(count);
    let mut packed = vec![0u8; count * codec::PACKED_SUBMIT_LEN];
    let packed_len =
        codec::encode_batch_with_backend(&records, simd::Backend::Scalar, &mut packed).unwrap();
    let mut batch_codec = network::OrderBatchCodec::new();
    let record_count = u8::try_from(count).unwrap_or(u8::MAX);
    let envelope = batch_codec
        .encode(record_count, false, &packed[..packed_len])
        .unwrap()
        .bytes
        .to_vec();
    let mut decoded = vec![0u8; network::ORDER_BATCH_MAX_UNCOMPRESSED];
    bench(name, cfg, || {
        let result =
            network::OrderBatchCodec::decode_into_with_backend(&envelope, &mut decoded, backend)
                .unwrap();
        black_box(result.records.len());
    })
}

macro_rules! lz4_decode_bench_wrappers {
    ($count:literal, $scalar:ident, $vector:ident) => {
        fn $scalar(cfg: Config) -> BenchStat {
            order_batch_lz4_decode_bench(
                concat!("order-batch-lz4-decode-scalar-", stringify!($count)),
                cfg,
                $count,
                simd::Backend::Scalar,
            )
        }

        fn $vector(cfg: Config) -> BenchStat {
            order_batch_lz4_decode_bench(
                concat!("order-batch-lz4-decode-dispatched-", stringify!($count)),
                cfg,
                $count,
                simd::detect(),
            )
        }
    };
}

lz4_decode_bench_wrappers!(
    32,
    order_batch_lz4_decode_scalar_32,
    order_batch_lz4_decode_simd_32
);
lz4_decode_bench_wrappers!(
    64,
    order_batch_lz4_decode_scalar_64,
    order_batch_lz4_decode_simd_64
);
lz4_decode_bench_wrappers!(
    128,
    order_batch_lz4_decode_scalar_128,
    order_batch_lz4_decode_simd_128
);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MarketUpdate {
    market: u32,
    sequence: u64,
    price: i64,
    quantity: i64,
}

fn sample_frame(seq: u64) -> Frame {
    let update = MarketUpdate {
        market: 1,
        sequence: seq,
        price: 100_000_000,
        quantity: 5_000_000,
    };
    let payload = codec::encode(&update).unwrap_or_default();
    Frame {
        class: TrafficClass::MarketData,
        msg_type: 7,
        sequence: seq,
        payload,
    }
}

fn peer_message_encode(cfg: Config) -> BenchStat {
    let mut seq: u64 = 0;
    bench("peer-message-encode", cfg, || {
        seq = seq.wrapping_add(1);
        let frame = sample_frame(seq);
        if let Ok(bytes) = frame.encode() {
            black_box(bytes.len());
        }
    })
}

fn peer_message_decode(cfg: Config) -> BenchStat {
    let encoded = sample_frame(1).encode().unwrap_or_default();
    bench("peer-message-decode", cfg, || {
        if let Ok((frame, consumed)) = Frame::decode(&encoded) {
            black_box(consumed);
            black_box(frame.payload.len());
        }
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcRequest {
    method: u32,
    account: u32,
    argument: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcResponse {
    ok: bool,
    result: u64,
}

fn rpc_request_handling(cfg: Config) -> BenchStat {
    let request = RpcRequest {
        method: 3,
        account: 42,
        argument: 1_000,
    };
    let request_bytes = codec::encode(&request).unwrap_or_default();
    bench("rpc-request-handling", cfg, || {
        // Decode request -> dispatch -> encode response, the RPC hot path.
        if let Ok(req) = codec::decode::<RpcRequest>(&request_bytes) {
            let result = u64::from(req.method)
                .wrapping_mul(u64::from(req.account))
                .wrapping_add(req.argument);
            let resp = RpcResponse { ok: true, result };
            if let Ok(bytes) = codec::encode(&resp) {
                black_box(bytes.len());
            }
        }
    })
}

fn market_data_fanout(cfg: Config) -> BenchStat {
    const SUBSCRIBERS: usize = 64;
    // Bounded per-subscriber queues (ring of one slot: last message wins).
    let mut queues: Vec<Vec<u8>> = vec![Vec::new(); SUBSCRIBERS];
    let mut seq: u64 = 0;
    bench("market-data-fanout", cfg, || {
        seq = seq.wrapping_add(1);
        let frame = sample_frame(seq);
        if let Ok(bytes) = frame.encode() {
            for q in &mut queues {
                q.clear();
                q.extend_from_slice(&bytes);
            }
        }
        black_box(queues[0].len());
    })
}

struct MinimmitBenchFixture {
    committee: MinimmitCommittee,
    notarize: Notarize,
    nullify: Nullify,
    exec_attest: ExecAttest,
    invalid_notarize: Notarize,
    m_signers: Vec<(u16, [u8; 64])>,
    l_signers: Vec<(u16, [u8; 64])>,
    m_notarization: Notarization,
    m_nullification: Nullification,
    l_notarization: Notarization,
    execution_certificate: consensus::Certificate,
    invalid_certificate: consensus::Certificate,
}

fn minimmit_fixture(n: usize) -> MinimmitBenchFixture {
    let keys: Vec<_> = (0..n)
        .map(|index| {
            let seed = u8::try_from(index).unwrap_or(0).saturating_add(41);
            KeyPair::from_seed(&[seed; 32])
        })
        .collect();
    let validators = keys
        .iter()
        .map(|key| Validator {
            public_key: key.public(),
            weight: 1,
        })
        .collect();
    let committee = MinimmitCommittee::new_unit(7, validators).expect("valid Minimmit fixture");
    let block_hash = Hash::from_bytes([0x71; 32]);
    let execution_root = Hash::from_bytes([0xE1; 32]);
    let notarize_message = notarize_digest(7, 19, block_hash);
    let nullify_message = nullify_digest(7, 19);
    let execution_message = execution_commitment_digest(7, 19, 23, block_hash, execution_root);
    let sign_prefix = |message: Hash, count: u64| {
        (0..count)
            .map(|index| {
                let index = u16::try_from(index).expect("fixture index fits u16");
                (index, keys[usize::from(index)].sign(message.as_bytes()))
            })
            .collect::<Vec<_>>()
    };
    let m_signers = sign_prefix(notarize_message, committee.advance_threshold());
    let l_signers = sign_prefix(notarize_message, committee.finalize_threshold());
    let m_notarization = Notarization {
        epoch: 7,
        view: 19,
        block_hash,
        cert: committee
            .assemble(notarize_message, &m_signers)
            .expect("valid M certificate"),
    };
    let m_nullification_signers = sign_prefix(nullify_message, committee.advance_threshold());
    let m_nullification = Nullification {
        epoch: 7,
        view: 19,
        cert: committee
            .assemble(nullify_message, &m_nullification_signers)
            .expect("valid nullification"),
    };
    let l_notarization = Notarization {
        epoch: 7,
        view: 19,
        block_hash,
        cert: committee
            .assemble(notarize_message, &l_signers)
            .expect("valid L certificate"),
    };
    let execution_signers = sign_prefix(execution_message, committee.finalize_threshold());
    let execution_certificate = committee
        .assemble(execution_message, &execution_signers)
        .expect("valid execution certificate");
    let notarize = Notarize {
        epoch: 7,
        view: 19,
        block_hash,
        validator_index: 0,
        signature: keys[0].sign(notarize_message.as_bytes()),
    };
    let nullify = Nullify {
        epoch: 7,
        view: 19,
        validator_index: 1,
        signature: keys[1].sign(nullify_message.as_bytes()),
    };
    let exec_attest = ExecAttest {
        epoch: 7,
        view: 19,
        height: 23,
        block_hash,
        execution_root,
        validator_index: 2,
        signature: keys[2].sign(execution_message.as_bytes()),
    };
    let mut invalid_notarize = notarize.clone();
    invalid_notarize.signature[0] ^= 0x80;
    let mut invalid_certificate = l_notarization.cert.clone();
    invalid_certificate.signatures[1][3] ^= 0x40;
    invalid_certificate.signatures[3][5] ^= 0x20;

    MinimmitBenchFixture {
        committee,
        notarize,
        nullify,
        exec_attest,
        invalid_notarize,
        m_signers,
        l_signers,
        m_notarization,
        m_nullification,
        l_notarization,
        execution_certificate,
        invalid_certificate,
    }
}

fn minimmit_digest(cfg: Config, n: usize, name: &'static str) -> BenchStat {
    let block = Hash::from_bytes([0x71; 32]);
    let execution = Hash::from_bytes([0xE1; 32]);
    bench(name, cfg, || {
        black_box(n);
        black_box(notarize_digest(7, 19, block));
        black_box(nullify_digest(7, 19));
        black_box(execution_commitment_digest(7, 19, 23, block, execution));
    })
}

fn verify_notarize_vote(vote: &Notarize, committee: &MinimmitCommittee) -> bool {
    vote.epoch == committee.epoch()
        && committee
            .cached_key(vote.validator_index)
            .is_some_and(|key| {
                key.verify(
                    notarize_digest(vote.epoch, vote.view, vote.block_hash).as_bytes(),
                    &vote.signature,
                )
                .is_ok()
            })
}

fn verify_nullify_vote(vote: &Nullify, committee: &MinimmitCommittee) -> bool {
    vote.epoch == committee.epoch()
        && committee
            .cached_key(vote.validator_index)
            .is_some_and(|key| {
                key.verify(
                    nullify_digest(vote.epoch, vote.view).as_bytes(),
                    &vote.signature,
                )
                .is_ok()
            })
}

fn minimmit_vote_admission(cfg: Config, n: usize, name: &'static str) -> BenchStat {
    let fixture = minimmit_fixture(n);
    bench(name, cfg, || {
        black_box(verify_notarize_vote(&fixture.notarize, &fixture.committee));
        black_box(verify_nullify_vote(&fixture.nullify, &fixture.committee));
        black_box(fixture.exec_attest.verify(&fixture.committee).is_ok());
        black_box(!verify_notarize_vote(
            &fixture.invalid_notarize,
            &fixture.committee,
        ));
    })
}

fn minimmit_certificate_assembly(cfg: Config, n: usize, name: &'static str) -> BenchStat {
    let fixture = minimmit_fixture(n);
    let message = notarize_digest(
        fixture.m_notarization.epoch,
        fixture.m_notarization.view,
        fixture.m_notarization.block_hash,
    );
    bench(name, cfg, || {
        black_box(
            fixture
                .committee
                .assemble(message, &fixture.m_signers)
                .is_ok(),
        );
        black_box(
            fixture
                .committee
                .assemble(message, &fixture.l_signers)
                .is_ok(),
        );
    })
}

fn minimmit_certificate_verify_m(cfg: Config, n: usize, name: &'static str) -> BenchStat {
    let fixture = minimmit_fixture(n);
    bench(name, cfg, || {
        black_box(fixture.m_notarization.verify(&fixture.committee).is_ok());
        black_box(fixture.m_nullification.verify(&fixture.committee).is_ok());
    })
}

fn minimmit_certificate_verify_l(cfg: Config, n: usize, name: &'static str) -> BenchStat {
    let fixture = minimmit_fixture(n);
    bench(name, cfg, || {
        black_box(
            fixture
                .committee
                .verify_detailed(&fixture.l_notarization.cert, ThresholdKind::Finalize)
                .is_ok(),
        );
        black_box(
            fixture
                .committee
                .verify_detailed(&fixture.execution_certificate, ThresholdKind::Finalize)
                .is_ok(),
        );
    })
}

fn minimmit_certificate_invalid_mix(cfg: Config, n: usize, name: &'static str) -> BenchStat {
    let fixture = minimmit_fixture(n);
    bench(name, cfg, || {
        black_box(
            fixture
                .committee
                .verify_detailed(&fixture.invalid_certificate, ThresholdKind::Finalize)
                .is_err(),
        );
    })
}

fn minimmit_digest_6(cfg: Config) -> BenchStat {
    minimmit_digest(cfg, 6, "minimmit-digest-6")
}
fn minimmit_digest_11(cfg: Config) -> BenchStat {
    minimmit_digest(cfg, 11, "minimmit-digest-11")
}
fn minimmit_digest_16(cfg: Config) -> BenchStat {
    minimmit_digest(cfg, 16, "minimmit-digest-16")
}
fn minimmit_vote_admission_6(cfg: Config) -> BenchStat {
    minimmit_vote_admission(cfg, 6, "minimmit-vote-admission-6")
}
fn minimmit_vote_admission_11(cfg: Config) -> BenchStat {
    minimmit_vote_admission(cfg, 11, "minimmit-vote-admission-11")
}
fn minimmit_vote_admission_16(cfg: Config) -> BenchStat {
    minimmit_vote_admission(cfg, 16, "minimmit-vote-admission-16")
}
fn minimmit_certificate_assembly_6(cfg: Config) -> BenchStat {
    minimmit_certificate_assembly(cfg, 6, "minimmit-certificate-assembly-6")
}
fn minimmit_certificate_assembly_11(cfg: Config) -> BenchStat {
    minimmit_certificate_assembly(cfg, 11, "minimmit-certificate-assembly-11")
}
fn minimmit_certificate_assembly_16(cfg: Config) -> BenchStat {
    minimmit_certificate_assembly(cfg, 16, "minimmit-certificate-assembly-16")
}
fn minimmit_certificate_verify_m_6(cfg: Config) -> BenchStat {
    minimmit_certificate_verify_m(cfg, 6, "minimmit-certificate-verify-m-6")
}
fn minimmit_certificate_verify_m_11(cfg: Config) -> BenchStat {
    minimmit_certificate_verify_m(cfg, 11, "minimmit-certificate-verify-m-11")
}
fn minimmit_certificate_verify_m_16(cfg: Config) -> BenchStat {
    minimmit_certificate_verify_m(cfg, 16, "minimmit-certificate-verify-m-16")
}
fn minimmit_certificate_verify_l_6(cfg: Config) -> BenchStat {
    minimmit_certificate_verify_l(cfg, 6, "minimmit-certificate-verify-l-6")
}
fn minimmit_certificate_verify_l_11(cfg: Config) -> BenchStat {
    minimmit_certificate_verify_l(cfg, 11, "minimmit-certificate-verify-l-11")
}
fn minimmit_certificate_verify_l_16(cfg: Config) -> BenchStat {
    minimmit_certificate_verify_l(cfg, 16, "minimmit-certificate-verify-l-16")
}
fn minimmit_certificate_invalid_mix_6(cfg: Config) -> BenchStat {
    minimmit_certificate_invalid_mix(cfg, 6, "minimmit-certificate-invalid-mix-6")
}
fn minimmit_certificate_invalid_mix_11(cfg: Config) -> BenchStat {
    minimmit_certificate_invalid_mix(cfg, 11, "minimmit-certificate-invalid-mix-11")
}
fn minimmit_certificate_invalid_mix_16(cfg: Config) -> BenchStat {
    minimmit_certificate_invalid_mix(cfg, 16, "minimmit-certificate-invalid-mix-16")
}

fn consensus_notarize_handling(cfg: Config) -> BenchStat {
    const N: u32 = 6;
    let mut kps = Vec::new();
    let mut vals = Vec::new();
    for i in 0..N {
        let kp = KeyPair::from_seed(&[u8::try_from(i).unwrap_or(0); 32]);
        vals.push(Validator {
            public_key: kp.public(),
            weight: 1,
        });
        kps.push(kp);
    }
    let committee = MinimmitCommittee::new_unit(0, vals).expect("six-validator committee");
    let block = Hash::from_bytes([7u8; 32]);
    let digest = notarize_digest(0, 0, block);
    let vote = Notarize {
        epoch: 0,
        view: 0,
        block_hash: block,
        validator_index: 0,
        signature: kps[0].sign(digest.as_bytes()),
    };
    bench("consensus-notarize-handling", cfg, || {
        // A fresh replica each op isolates signature-verifying tally admission.
        let (mut replica, _) = MinimmitReplica::new(committee.clone(), 1, Hash::ZERO, 0)
            .expect("valid benchmark replica");
        let r = replica.admit_notarize(&vote);
        black_box(r.is_ok());
    })
}

fn light_client_proof_verify(cfg: Config) -> BenchStat {
    let mut tree = StateTree::new(1024, 256);
    let target = AccountId::new(3);
    let leaf = LeafWriter::new()
        .field_u32(3)
        .field_i128(1_000_000)
        .finish();
    for a in 0..64u32 {
        let p = LeafWriter::new()
            .field_u32(a)
            .field_i128(i128::from(a) * 10)
            .finish();
        let _ = tree.set_account(AccountId::new(a), &p);
    }
    let _ = tree.set_account(target, &leaf);
    let root = tree.root();
    let proof = tree.account_proof(target).unwrap_or_default();
    bench("light-client-proof-verify", cfg, || {
        let ok = verify_account(root, target, &leaf, &proof);
        black_box(ok);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Config {
        Config {
            iterations: 32,
            warmup: 4,
        }
    }

    #[test]
    fn every_suite_runs_and_populates_a_stat() {
        for suite in registry() {
            let stat = (suite.run)(small());
            assert_eq!(stat.name, suite.name, "suite name mismatch");
            assert_eq!(stat.iterations, 32, "suite {} iters", suite.name);
            assert!(
                stat.percentiles_monotonic(),
                "suite {} percentiles not monotonic",
                suite.name
            );
        }
    }

    #[test]
    fn every_registered_suite_has_provenance() {
        for suite in registry() {
            let p = provenance(suite.name)
                .unwrap_or_else(|| panic!("no provenance for {}", suite.name));
            assert_eq!(p.name, suite.name);
            assert!(!p.call_path.is_empty(), "{} call_path empty", suite.name);
            assert!(
                !p.fixture_scale.is_empty(),
                "{} fixture_scale empty",
                suite.name
            );
            assert!(
                p.microbenchmark,
                "{} should be a microbenchmark",
                suite.name
            );
        }
        assert_eq!(all_provenance().len(), registry().len());
        assert!(provenance("no-such-suite").is_none());
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn minimmit_accepted_vote_assembly_and_certificate_verification_are_allocation_free() {
        for n in [6, 11, 16] {
            let fixture = minimmit_fixture(n);
            let (allocations, bytes) = crate::measure_allocations(|| {
                black_box(notarize_digest(
                    fixture.notarize.epoch,
                    fixture.notarize.view,
                    fixture.notarize.block_hash,
                ));
                black_box(nullify_digest(fixture.nullify.epoch, fixture.nullify.view));
                black_box(
                    fixture
                        .committee
                        .assemble(
                            notarize_digest(
                                fixture.m_notarization.epoch,
                                fixture.m_notarization.view,
                                fixture.m_notarization.block_hash,
                            ),
                            &fixture.m_signers,
                        )
                        .unwrap(),
                );
                black_box(
                    fixture
                        .committee
                        .assemble(
                            notarize_digest(
                                fixture.l_notarization.epoch,
                                fixture.l_notarization.view,
                                fixture.l_notarization.block_hash,
                            ),
                            &fixture.l_signers,
                        )
                        .unwrap(),
                );
                assert!(verify_notarize_vote(&fixture.notarize, &fixture.committee));
                assert!(verify_nullify_vote(&fixture.nullify, &fixture.committee));
                fixture.exec_attest.verify(&fixture.committee).unwrap();
                fixture.m_notarization.verify(&fixture.committee).unwrap();
                fixture.m_nullification.verify(&fixture.committee).unwrap();
                fixture
                    .committee
                    .verify_detailed(&fixture.l_notarization.cert, ThresholdKind::Finalize)
                    .unwrap();
                fixture
                    .committee
                    .verify_detailed(&fixture.execution_certificate, ThresholdKind::Finalize)
                    .unwrap();
            });
            assert_eq!(
                (allocations, bytes),
                (0, 0),
                "n={n} accepted Minimmit vote/QC processing allocated"
            );
        }
    }

    #[test]
    fn fill_fanout_workload_produces_multiple_fills() {
        // Prove the fan-out matrix does real multi-fill work: 1 taker, 8 makers, 8 fills.
        let mut book = OrderBook::new(BookConfig::default());
        let mut oid = 1u64;
        for lvl in 0..8i64 {
            book.submit(ask(oid, oid, 100 + lvl, 1, 2)).unwrap();
            oid += 1;
        }
        let res = book.submit(bid(oid, oid, 107, 8)).unwrap();
        assert_eq!(res.fills.len(), 8, "taker should sweep all 8 makers");
    }

    #[test]
    fn full_book_cross_fills_exactly_one_maker() {
        let mut book = OrderBook::new(BookConfig::default());
        let mut oid = 1u64;
        for lvl in 0..256i64 {
            book.submit(ask(oid, oid, 200 + lvl, 1, 2)).unwrap();
            oid += 1;
        }
        let res = book.submit(bid(oid, oid, 200, 1)).unwrap();
        assert_eq!(res.fills.len(), 1, "taker at best price crosses one maker");
    }

    #[test]
    fn empty_book_cross_rests_without_fills() {
        let mut book = OrderBook::new(BookConfig::default());
        let res = book.submit(bid(1, 1, 100, 1)).unwrap();
        assert!(res.fills.is_empty(), "no makers means no fills");
    }

    #[test]
    fn registry_names_are_unique() {
        let names: Vec<&str> = registry().iter().map(|s| s.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate suite name");
    }

    #[test]
    fn find_selects_exactly_one() {
        assert!(find("order-insertion").is_some());
        assert!(find("does-not-exist").is_none());
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn insertion_and_cancellation_are_zero_alloc_steady_state() {
        // Warm path of the bounded book must not allocate per op.
        let ins = order_insertion(Config {
            iterations: 2000,
            warmup: 2000,
        });
        assert!(ins.alloc_measured);
        assert_eq!(ins.allocations, 0, "order-insertion allocated on warm path");

        let can = order_cancellation(Config {
            iterations: 2000,
            warmup: 2000,
        });
        assert_eq!(
            can.allocations, 0,
            "order-cancellation allocated on warm path"
        );
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn market_depth_summary_is_zero_alloc_after_warmup() {
        let mut book = OrderBook::new(BookConfig::default());
        for i in 0..128u64 {
            book.submit(ask(
                i + 1,
                i + 1,
                100 + i64::try_from(i).unwrap(),
                1,
                u32::try_from(i + 1).unwrap(),
            ))
            .unwrap();
        }
        let taker = NewOrder {
            order_id: OrderId::new(10_000),
            account: AccountId::new(10_000),
            side: Side::Bid,
            order_type: OrderType::Market,
            tif: TimeInForce::Ioc,
            price: price(227),
            quantity: qty(128),
            client_id: 10_000,
            reduce_only: false,
        };
        let expected = book.plan_match_summary(&taker).unwrap();
        let (allocations, bytes) = crate::measure_allocations(|| {
            assert_eq!(book.plan_match_summary(&taker).unwrap(), expected);
        });
        assert_eq!(allocations, 0, "aggregate depth scan allocated");
        assert_eq!(bytes, 0, "aggregate depth scan allocated bytes");
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn engine_transaction_snapshot_is_zero_alloc() {
        let engine = Engine::new(EngineConfig::default());
        let (allocations, bytes) = crate::measure_allocations(|| {
            black_box(engine.clone());
        });
        assert_eq!(allocations, 0, "Engine transaction snapshot allocated");
        assert_eq!(bytes, 0, "Engine transaction snapshot allocated bytes");
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn accepted_engine_resting_orders_are_zero_alloc_after_warmup() {
        let stat = engine_resting_order(Config {
            iterations: 256,
            warmup: 64,
        });
        assert!(stat.alloc_measured);
        assert_eq!(
            stat.allocations, 0,
            "accepted Engine::execute resting orders allocated"
        );
        assert_eq!(stat.bytes_allocated, 0, "accepted orders allocated bytes");
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn shard_owner_handoff_is_zero_alloc_after_warmup() {
        let stat = shard_worker_order(Config {
            iterations: 256,
            warmup: 64,
        });
        assert!(stat.alloc_measured);
        assert_eq!(stat.allocations, 0, "shard owner path allocated");
        assert_eq!(stat.bytes_allocated, 0, "shard owner path allocated bytes");
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn packed_batch_admission_is_zero_alloc_after_construction() {
        let stat = packed_batch_admit_128(Config {
            iterations: 64,
            warmup: 8,
        });
        assert!(stat.alloc_measured);
        assert_eq!(stat.allocations, 0, "packed batch admission allocated");
        assert_eq!(
            stat.bytes_allocated, 0,
            "packed batch admission allocated bytes"
        );
    }

    #[test]
    fn median_price_is_correct() {
        let mut odd = [price(1), price(3), price(2)];
        assert_eq!(median_price(&mut odd), price(2));
        let mut even = [price(1), price(3), price(2), price(4)];
        // middle two are 2 and 3 -> floor(mean) = 2.5 -> 2500000 raw
        assert_eq!(
            median_price(&mut even).raw(),
            (price(2).raw() + price(3).raw()) / 2
        );
        assert_eq!(median_price(&mut []), Price::ZERO);
    }

    #[test]
    fn batch_scales_over_single() {
        // Batch verification amortizes: its per-op work covers many signatures.
        let single = signature_verify_single(small());
        let batch = signature_verify_batch(small());
        // Batch verifies 32 signatures per op, so a batch op costs more than one
        // single verification but far less than 32 of them (amortized speedup).
        assert!(batch.p50_ns >= single.p50_ns);
    }

    #[test]
    fn production_order_batch_compression_sizes_are_pinned() {
        for (count, expected_input, expected_payload, expected_wire) in [
            (32usize, 1696usize, 531usize, 551usize),
            (64, 3392, 988, 1008),
            (128, 6768, 1927, 1947),
        ] {
            let records = packed_corpus(count);
            let mut packed = vec![0u8; count * codec::PACKED_SUBMIT_LEN];
            let packed_len =
                codec::encode_batch_with_backend(&records, simd::Backend::Scalar, &mut packed)
                    .unwrap();
            let mut batch_codec = network::OrderBatchCodec::new();
            let encoded = batch_codec
                .encode(
                    u8::try_from(count).unwrap_or(u8::MAX),
                    false,
                    &packed[..packed_len],
                )
                .unwrap();
            assert_eq!(packed_len, expected_input);
            assert_eq!(
                encoded.bytes.len() - network::ORDER_BATCH_HEADER_LEN,
                expected_payload
            );
            assert_eq!(encoded.bytes.len(), expected_wire);
            assert!(!encoded.raw);
        }
    }
}
