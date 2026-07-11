#![deny(unsafe_code)]
//! `simulation` — a deterministic network + consensus simulator and
//! fault-injection harness for DexOS.
//!
//! The crate models an N-node BFT cluster as a **discrete-event system**: there
//! is no async runtime, no threads, and no wall clock. Logical time is a `u64`
//! nanosecond counter advanced by a [`Scheduler`], and the *only* source of
//! nondeterminism is a seeded [`SimRng`]. Given a seed, a whole run — every
//! message delay, drop, duplicate, reorder, crash, Byzantine choice, and the
//! resulting finalized state roots — is byte-for-byte reproducible.
//!
//! # Building blocks
//!
//! - [`SimRng`] — seedable LCG + SplitMix64 PRNG (integer-only, no floats).
//! - [`Scheduler`] — monotonic virtual-clock event queue ordered by
//!   `(time, tie_break)`.
//! - [`Transport`] — fault injection: delay, jitter, drop, duplicate, reorder,
//!   partition, and clock drift, with message accounting; plus a
//!   priority-scheduled [`PriorityLink`] proving P0 traffic is never starved.
//! - [`Node`] — a real [`consensus::BftEngine`] driven over the network, with
//!   honest and Byzantine behaviors and crash / restart recovery.
//! - [`Cluster`] — the orchestrator that runs a [`SimConfig`] to a [`SimResult`].
//! - [`StateRootOracle`] — the safety oracle: surviving honest nodes must hold
//!   a bit-identical finalized state root.
//! - [`scenario`] — the ready-made fault matrix.
//!
//! # Safety property
//!
//! Across the fault matrix (including up to `f` Byzantine nodes in a `3f+1`
//! set), all surviving honest nodes agree on identical finalized state roots,
//! and re-running a seed reproduces byte-identical results.

pub mod cluster;
pub mod node;
pub mod oracle;
pub mod rng;
pub mod scenario;
pub mod scheduler;
pub mod transport;

pub use cluster::{percentile, Cluster, SimConfig, SimError, SimResult};
pub use node::{
    byzantine_block, canonical_block, Behavior, Envelope, Node, NodeId, Outgoing, Payload, Target,
};
pub use oracle::{Divergence, StateRootOracle};
pub use rng::SimRng;
pub use scheduler::{Dispatched, Scheduler, Time};
pub use transport::{LinkFaults, PriorityLink, Routing, Transport, TransportStats};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "simulation";

#[cfg(test)]
mod tests {
    use super::*;

    use codec::TrafficClass;
    use consensus::{Committee, Proposal, Sequencer, SequencerError, Vote};
    use crypto::{KeyPair, Validator};
    use types::{Hash, SequenceNumber, ShardId};

    // ---- deterministic in-test LCG (independent of the crate's SimRng) ------

    struct Lcg(u64);
    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed ^ 0xA5A5_5A5A_1234_9876)
        }
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut z = self.0;
            z = (z ^ (z >> 31)).wrapping_mul(0x7FB5_D329_728E_A185);
            z ^ (z >> 29)
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            let mut v = Vec::with_capacity(len);
            while v.len() < len {
                v.extend_from_slice(&self.next().to_le_bytes());
            }
            v.truncate(len);
            v
        }
    }

    fn committee(n: u32) -> Committee {
        let mut vals = Vec::new();
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            let kp = KeyPair::from_seed(&seed);
            vals.push(Validator {
                public_key: kp.public(),
                weight: 1,
            });
        }
        Committee::new_bft(0, vals).unwrap()
    }

    // ---- crate identity -----------------------------------------------------

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "simulation");
    }

    // ---- scheduler: clock + tie-break --------------------------------------

    #[test]
    fn scheduler_clock_is_monotonic() {
        let mut s = Scheduler::<u32>::new();
        s.schedule_at(50, 1);
        s.schedule_at(10, 2);
        s.schedule_at(10, 3);
        s.schedule_after(0, 4); // clamps to now == 0
        let mut last = 0u64;
        while let Some(d) = s.pop() {
            assert!(d.time >= last, "clock moved backward");
            assert_eq!(d.time, s.now());
            last = d.time;
        }
    }

    #[test]
    fn scheduler_tie_break_is_fifo() {
        let mut s = Scheduler::<u32>::new();
        // Three events at the same time dispatch in insertion order.
        s.schedule_at(100, 10);
        s.schedule_at(100, 20);
        s.schedule_at(100, 30);
        let a = s.pop().unwrap();
        let b = s.pop().unwrap();
        let c = s.pop().unwrap();
        assert_eq!((a.event, b.event, c.event), (10, 20, 30));
        assert!(a.tie_break < b.tie_break && b.tie_break < c.tie_break);
    }

    #[test]
    fn property_scheduler_never_dispatches_out_of_order() {
        // Arbitrary insertions must dispatch in nondecreasing (time, tie_break).
        for seed in 0..16u64 {
            let mut lcg = Lcg::new(seed);
            let mut s = Scheduler::<u64>::new();
            let count = 500 + (lcg.next() % 500);
            for i in 0..count {
                let t = lcg.next() % 10_000;
                s.schedule_at(t, i);
            }
            let mut prev: Option<(Time, u64)> = None;
            while let Some(d) = s.pop() {
                let key = (d.time, d.tie_break);
                if let Some(p) = prev {
                    assert!(key >= p, "out-of-order dispatch: {key:?} after {p:?}");
                }
                prev = Some(key);
            }
        }
    }

    // ---- transport: individual fault modes ---------------------------------

    #[test]
    fn transport_delay_is_deterministic() {
        let mut t = Transport::new(LinkFaults::latent(1_000, 0));
        let mut rng = SimRng::new(7);
        match t.route(0, 1, 100, &mut rng) {
            Routing::Deliver(times) => {
                assert_eq!(times, vec![1_100]); // now(100) + base(1000)
            }
            Routing::Dropped => panic!("unexpected drop"),
        }
    }

    #[test]
    fn transport_drop_mode() {
        let mut faults = LinkFaults::PERFECT;
        faults.drop_permille = 1000; // always drop
        let mut t = Transport::new(faults);
        let mut rng = SimRng::new(1);
        for _ in 0..50 {
            assert_eq!(t.route(0, 1, 0, &mut rng), Routing::Dropped);
        }
        let s = t.stats();
        assert_eq!(s.delivered_once, 0);
        assert_eq!(s.dropped, 50);
        assert!(s.ledger_balances());
    }

    #[test]
    fn transport_duplicate_mode() {
        let mut faults = LinkFaults::PERFECT;
        faults.dup_permille = 1000; // always duplicate
        faults.max_dups = 2;
        let mut t = Transport::new(faults);
        let mut rng = SimRng::new(2);
        let mut saw_dup = false;
        for _ in 0..50 {
            if let Routing::Deliver(times) = t.route(0, 1, 0, &mut rng) {
                assert!(!times.is_empty());
                if times.len() > 1 {
                    saw_dup = true;
                }
            }
        }
        assert!(saw_dup, "duplication never fired");
        assert!(t.stats().duplicated > 0);
    }

    #[test]
    fn transport_reorder_adds_delay() {
        let mut faults = LinkFaults::PERFECT;
        faults.reorder_permille = 1000;
        faults.reorder_spread_ns = 5_000;
        let mut t = Transport::new(faults);
        let mut rng = SimRng::new(3);
        let mut saw_late = false;
        for _ in 0..50 {
            if let Routing::Deliver(times) = t.route(0, 1, 0, &mut rng) {
                if times[0] > 0 {
                    saw_late = true;
                }
            }
        }
        assert!(saw_late, "reorder never displaced a delivery in time");
    }

    #[test]
    fn transport_partition_mode() {
        let mut t = Transport::new(LinkFaults::PERFECT);
        t.partition(vec![0, 0, 1, 1]);
        let mut rng = SimRng::new(4);
        // Cross-group: dropped.
        assert_eq!(t.route(0, 2, 0, &mut rng), Routing::Dropped);
        // Same group: delivered.
        assert!(matches!(t.route(0, 1, 0, &mut rng), Routing::Deliver(_)));
        // Self is always reliable, even across a partition boundary.
        assert!(matches!(t.route(2, 2, 0, &mut rng), Routing::Deliver(_)));
        t.heal();
        assert!(matches!(t.route(0, 2, 0, &mut rng), Routing::Deliver(_)));
    }

    #[test]
    fn property_transport_ledger_balances() {
        // sent == delivered_once + dropped, and duplicates only when configured.
        for seed in 0..24u64 {
            let mut lcg = Lcg::new(seed);
            let dup_on = lcg.next().is_multiple_of(2);
            let faults = LinkFaults {
                base_delay_ns: 500,
                jitter_ns: 250,
                drop_permille: u32::try_from(lcg.next() % 400).unwrap_or(0),
                dup_permille: if dup_on {
                    u32::try_from(lcg.next() % 500).unwrap_or(0)
                } else {
                    0
                },
                max_dups: if dup_on { 3 } else { 0 },
                reorder_permille: u32::try_from(lcg.next() % 300).unwrap_or(0),
                reorder_spread_ns: 2_000,
            };
            let mut t = Transport::new(faults);
            let mut rng = SimRng::new(seed.wrapping_mul(31));
            for _ in 0..400 {
                let _ = t.route(0, 1, 0, &mut rng);
            }
            let s = t.stats();
            assert!(s.ledger_balances(), "ledger imbalance for seed {seed}");
            assert_eq!(s.sent, 400);
            if !dup_on {
                assert_eq!(s.duplicated, 0, "duplicates with dup disabled");
            }
        }
    }

    // ---- priority: P0 not starved behind P7 --------------------------------

    #[test]
    fn priority_link_serves_p0_before_p7() {
        let mut link = PriorityLink::<u32>::new(1024);
        // Saturate with market data (P7), then inject one consensus msg (P0).
        for i in 0..100 {
            link.enqueue(TrafficClass::MarketData, i);
        }
        link.enqueue(TrafficClass::Consensus, 9999);
        // A single-item service budget must yield the P0 message first.
        let served = link.drain(1);
        assert_eq!(served, vec![9999]);
    }

    #[test]
    fn priority_link_p0_survives_saturating_load() {
        // Under a bounded queue and continuous P7 pressure, an interleaved P0
        // is always the next item served — never starved, never evicted.
        let mut link = PriorityLink::<u64>::new(64);
        for step in 0..500u64 {
            for _ in 0..4 {
                link.enqueue(TrafficClass::MarketData, step);
            }
            link.enqueue(TrafficClass::Consensus, 1_000_000 + step);
            let out = link.pop().unwrap();
            assert_eq!(out, 1_000_000 + step, "P0 was starved at step {step}");
        }
        // The bound held: capacity never exceeded, and eviction only hit P7.
        assert!(link.depth() <= 64);
        assert!(link.evicted() > 0);
    }

    // ---- cluster: happy path finalizes -------------------------------------

    #[test]
    fn happy_path_three_and_four_nodes_agree() {
        for n in [3u32, 4u32] {
            let res = Cluster::run(scenario::happy_path(n, 5, 42)).unwrap();
            assert!(res.all_finalized(5), "n={n} did not finalize all heights");
            let root = res.agree().unwrap_or_else(|e| panic!("n={n}: {e}"));
            assert!(!root.is_zero());
            assert_eq!(res.heights_completed, 5);
        }
    }

    #[test]
    fn checkpoints_agree_across_nodes() {
        let res = Cluster::run(scenario::happy_path(4, 4, 11)).unwrap();
        // Every survivor produced the same checkpoint new_state_root and
        // command_root at each height.
        let reference = &res.survivor_checkpoints[0].1;
        for (_, cps) in &res.survivor_checkpoints {
            assert_eq!(cps.len(), reference.len());
            for (a, b) in cps.iter().zip(reference.iter()) {
                assert_eq!(a.new_state_root, b.new_state_root);
                assert_eq!(a.command_root, b.command_root);
            }
        }
    }

    // ---- determinism --------------------------------------------------------

    #[test]
    fn same_seed_reproduces_identical_results() {
        let cfg = scenario::packet_loss(4, 6, 2024, 150, 120);
        let a = Cluster::run(cfg.clone()).unwrap();
        let b = Cluster::run(cfg).unwrap();
        assert_eq!(a.trace_digest, b.trace_digest, "trace digests diverged");
        assert_eq!(a.survivor_roots, b.survivor_roots, "roots diverged");
        assert_eq!(a.steps, b.steps);
    }

    #[test]
    fn different_seeds_generally_differ_in_trace() {
        let a = Cluster::run(scenario::packet_loss(4, 6, 1, 200, 100)).unwrap();
        let b = Cluster::run(scenario::packet_loss(4, 6, 2, 200, 100)).unwrap();
        // Same safety outcome, but distinct schedules.
        assert_ne!(a.trace_digest, b.trace_digest);
        assert_eq!(a.agree().unwrap(), b.agree().unwrap());
    }

    // ---- partition heals and reconverges -----------------------------------

    #[test]
    fn partition_heals_and_nodes_reconverge() {
        let cfg = scenario::partition_heal(4, 4, 77, vec![0, 0, 1, 1], 40_000);
        let res = Cluster::run(cfg).unwrap();
        assert!(res.all_finalized(4), "did not reconverge after heal");
        let root = res.agree().unwrap();
        assert!(!root.is_zero());
    }

    // ---- leader failover ----------------------------------------------------

    #[test]
    fn leader_failover_continues_and_meets_targets() {
        let res = Cluster::run(scenario::leader_failover(4, 3, 5)).unwrap();
        assert!(res.all_finalized(3));
        res.agree().unwrap();
        let failover = res.failover_time_ns.expect("expected a view change");
        // Logical failover target: < 1 second.
        assert!(
            failover < 1_000_000_000,
            "failover {failover}ns exceeded 1s"
        );
        // Checkpoint finality p95 target: < 500 ms (logical).
        let p95 = res.p95_finality_ns().unwrap();
        assert!(p95 < 500_000_000, "p95 {p95}ns exceeded 500ms");
    }

    // ---- crash + restart recovery ------------------------------------------

    #[test]
    fn crash_and_restart_recovers_bit_identically() {
        let cfg = scenario::crash_restart(4, 4, 314, 3, 0, 2_000_000);
        let res = Cluster::run(cfg.clone()).unwrap();
        assert!(res.all_finalized(4), "recovered cluster missing heights");
        res.agree().unwrap();
        // Deterministic replay reproduces the same final roots.
        let res2 = Cluster::run(cfg).unwrap();
        assert_eq!(res.survivor_roots, res2.survivor_roots);
        assert_eq!(res.trace_digest, res2.trace_digest);
    }

    #[test]
    fn deterministic_replay_reproduces_state_roots() {
        let cfg = scenario::happy_path(4, 3, 555);
        let before = Cluster::run(cfg.clone()).unwrap();
        let after = Cluster::run(cfg).unwrap();
        assert_eq!(before.survivor_roots, after.survivor_roots);
    }

    // ---- Byzantine safety (3f+1) -------------------------------------------

    #[test]
    fn f_byzantine_cannot_break_agreement_seed_sweep() {
        // Safety across a seed sweep with f=1 equivocating voter in a 3f+1 set.
        const SEEDS: u64 = 64;
        for seed in 0..SEEDS {
            let res = Cluster::run(scenario::byzantine_equivocation(1, 3, seed)).unwrap();
            match res.agree() {
                Ok(_) => {}
                Err(e) => panic!("SAFETY VIOLATION at seed {seed}: {e}"),
            }
            assert!(res.all_finalized(3), "liveness failed at seed {seed}");
            assert!(
                res.equivocations_detected > 0,
                "equivocation not detected at seed {seed}"
            );
        }
    }

    #[test]
    fn invalid_signatures_are_rejected_without_divergence() {
        let res = Cluster::run(scenario::invalid_signatures(1, 3, 88)).unwrap();
        assert!(res.all_finalized(3));
        res.agree().unwrap();
    }

    #[test]
    fn leader_equivocation_is_detected() {
        let res = Cluster::run(scenario::equivocating_leader(4, 3, 99)).unwrap();
        assert!(
            res.forks_detected > 0,
            "leader equivocation/fork not detected"
        );
        assert!(res.all_finalized(3));
        res.agree().unwrap();
    }

    // ---- clock drift --------------------------------------------------------

    #[test]
    fn clock_drift_preserves_state_roots() {
        let res = Cluster::run(scenario::clock_drift(4, 4, 123)).unwrap();
        assert!(res.all_finalized(4));
        res.agree().unwrap();
    }

    // ---- oracle: mutation / divergence detection ---------------------------

    #[test]
    fn oracle_passes_clean_fails_on_divergence() {
        let clean = vec![
            (0u32, Hash::from_bytes([7; 32])),
            (1u32, Hash::from_bytes([7; 32])),
            (2u32, Hash::from_bytes([7; 32])),
        ];
        assert_eq!(
            StateRootOracle::agree(&clean).unwrap(),
            Hash::from_bytes([7; 32])
        );

        let mut diverged = clean;
        diverged[2].1 = Hash::from_bytes([8; 32]); // inject a mutation
        match StateRootOracle::agree(&diverged) {
            Err(Divergence::Disagreement { majority, outliers }) => {
                assert_eq!(majority, Hash::from_bytes([7; 32]));
                assert_eq!(outliers, vec![(2u32, Hash::from_bytes([8; 32]))]);
            }
            other => panic!("expected disagreement, got {other:?}"),
        }

        assert_eq!(StateRootOracle::agree(&[]), Err(Divergence::Empty));
    }

    // ---- sequence gap detection --------------------------------------------

    #[test]
    fn sequence_gap_is_detected_and_halts() {
        let mut seq = Sequencer::new(ShardId::new(0));
        seq.ingest(SequenceNumber::new(0), Hash::ZERO).unwrap();
        seq.ingest(SequenceNumber::new(1), Hash::ZERO).unwrap();
        // A gap (skipping 2) is reported; the command past the gap is not
        // applied — recovery halts.
        let before = seq.len();
        let err = seq.ingest(SequenceNumber::new(3), Hash::ZERO).unwrap_err();
        assert_eq!(
            err,
            SequencerError::Gap {
                expected: 2,
                got: 3
            }
        );
        assert_eq!(seq.len(), before, "command past the gap must not apply");
    }

    // ---- never panics on adversarial injected bytes ------------------------

    #[test]
    fn never_panics_on_adversarial_bytes() {
        let mut node = Node::new(0, &[1u8; 32], committee(4), Behavior::Honest);
        let mut lcg = Lcg::new(0xFEED_FACE);
        for _ in 0..4000 {
            let len = usize::try_from(lcg.next() % 300).unwrap_or(0);
            let bytes = lcg.bytes(len);
            // Untrusted decode paths are total: they return Result, never panic.
            if let Ok(p) = codec::decode::<Proposal>(&bytes) {
                let env = Envelope {
                    from: 1,
                    to: 0,
                    payload: Payload::Proposal(p),
                };
                let _ = node.handle(&env, 0);
            }
            if let Ok(v) = codec::decode::<Vote>(&bytes) {
                let env = Envelope {
                    from: 1,
                    to: 0,
                    payload: Payload::Vote(v),
                };
                let _ = node.handle(&env, 0);
            }
        }
    }

    // ---- soak (bounded, virtual-time) --------------------------------------

    #[test]
    fn bounded_soak_is_deterministic_and_agrees() {
        // A CI-scale soak. Raising `heights` extends the virtual-time soak
        // without changing the assertions (bit-identical roots, no divergence).
        let heights = 120;
        let cfg = scenario::soak(4, heights, 0xDEAD_BEEF);
        let a = Cluster::run(cfg.clone()).unwrap();
        assert!(
            a.all_finalized(heights),
            "soak did not finalize all heights"
        );
        let root_a = a.agree().unwrap();

        // Deterministic replay: identical trace and final root.
        let b = Cluster::run(cfg).unwrap();
        assert_eq!(a.trace_digest, b.trace_digest);
        assert_eq!(root_a, b.agree().unwrap());
    }

    // ---- rng determinism property ------------------------------------------

    #[test]
    fn sim_rng_is_reproducible_and_bounded() {
        let mut a = SimRng::new(0x1234);
        let mut b = SimRng::new(0x1234);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        // `below` respects its bound.
        let mut r = SimRng::new(5);
        for _ in 0..1000 {
            assert!(r.below(7) < 7);
        }
        assert_eq!(r.below(0), 0);
        // chance_permille edges.
        let mut r2 = SimRng::new(6);
        assert!(!r2.chance_permille(0));
        assert!(r2.chance_permille(1000));
    }
}
