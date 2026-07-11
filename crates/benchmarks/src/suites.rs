//! The benchmark suites: bounded, deterministic workloads over the DexOS
//! crates, each producing a [`BenchStat`].
//!
//! Every suite is registered in [`registry`] so `run_all` (and a `marketd
//! benchmark --suite <name>` CLI) can enumerate and select them by their
//! spec-stable name. Workloads are seeded from a fixed constant so operation
//! ordering replays identically across runs.

use std::hint::black_box;

use serde::{Deserialize, Serialize};

use codec::{Frame, TrafficClass};
use consensus::{
    build_checkpoint_header, checkpoint_hash, vote_digest, Committee, Vote, VoteCollector,
    VotePhase,
};
use crypto::{batch_verify_ed25519, verify_ed25519, KeyPair, Validator};
use execution::{Command, DeterministicEngine, Engine, EngineConfig, SetMarkPrice};
use orderbook::{BookConfig, NewOrder, OrderBook};
use risk::{RiskConfig, RiskEngine};
use state_tree::{verify_account, LeafWriter, StateTree};
use storage::{replay, Record, SegmentedLog, Snapshot, PROTOCOL_VERSION};
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
            name: "command-execution",
            run: command_execution,
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
            name: "rpc-request-handling",
            run: rpc_request_handling,
        },
        Suite {
            name: "market-data-fanout",
            run: market_data_fanout,
        },
        Suite {
            name: "consensus-vote-handling",
            run: consensus_vote_handling,
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
        let results = batch_verify_ed25519(&items);
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

fn consensus_vote_handling(cfg: Config) -> BenchStat {
    const N: u32 = 4;
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
    let committee = Committee::new_bft(0, vals).unwrap_or_else(|_| {
        // Should not happen with a valid non-empty set; fall back to a 1-node set.
        let kp = KeyPair::from_seed(&[0u8; 32]);
        Committee::new_bft(
            0,
            vec![Validator {
                public_key: kp.public(),
                weight: 1,
            }],
        )
        .expect("single-validator committee")
    });
    let block = Hash::from_bytes([7u8; 32]);
    let digest = vote_digest(0, 0, 1, VotePhase::Commit, block);
    let vote = Vote {
        epoch: 0,
        view: 0,
        height: 1,
        phase: VotePhase::Commit,
        block_hash: block,
        validator_index: 0,
        signature: kps[0].sign(digest.as_bytes()),
    };
    bench("consensus-vote-handling", cfg, || {
        // A fresh collector each op isolates the signature-verifying add_vote.
        let mut collector = VoteCollector::new();
        let r = collector.add_vote(&committee, &vote);
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
}
