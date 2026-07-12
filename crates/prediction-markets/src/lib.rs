//! `prediction-markets` — binary and multi-outcome prediction markets.
//!
//! This crate models the *market* layer for prediction/event/scalar markets on
//! top of the deterministic [`types`] primitives. It is pure, integer-only, and
//! self-contained: it depends only on [`types`] (fixed-point scalars, ids, domain
//! enums) and [`crypto`] (evidence-hash commitments). It has no dependency on the
//! order book, matching engine, network, storage, or async runtime.
//!
//! # Building blocks
//! - [`OutcomeSet`] — mutually-exclusive, exhaustive outcomes; binary or N-outcome.
//! - [`ClaimId`] / [`ClaimKind`] — YES and synthetic-NO claims. A `NO_i` claim is
//!   the complete set minus `YES_i`; see [`OutcomeSet::no_claim_complement`].
//! - [`ClaimBook`] — the complete-set collateral ledger: [`ClaimBook::mint`],
//!   [`ClaimBook::redeem`], and [`ClaimBook::transfer`] maintain the invariant
//!   that each outcome's outstanding claims equal the locked collateral.
//! - [`Resolution`] — winner-take-all, dead-heat splits, explicit/partial payout
//!   vectors, custom rules, scalar value→fraction mapping, and invalid refunds.
//! - [`ClaimBook::settle`] — value-conserving settlement math (credited total
//!   equals locked collateral to the micro-unit via largest-remainder rounding).
//! - [`Committee`] — k-of-n threshold resolution committees.
//! - [`PredictionMarketDefinition`] — the immutable market definition and rules.
//! - [`transition`] — the guarded, total lifecycle state machine.
//!
//! # Determinism
//! Every operation is integer-only and total: no floating point, no panics on
//! adversarial input, and identical inputs always produce bit-identical output.
#![forbid(unsafe_code)]

pub mod committee;
pub mod completeset;
pub mod definition;
pub mod lifecycle;
pub mod outcome;
pub mod scalar;
pub mod settlement;

pub use committee::{
    Committee, CommitteeDecision, CommitteeError, Equivocation, ResolutionClaim, ResolutionRound,
    ResolverId, ResolverVote, TallyOutcome, DOMAIN_RESOLVER_COMMITTEE, DOMAIN_RESOLVER_VOTE,
    MAX_RESOLVERS,
};
pub use completeset::{ClaimBook, CompleteSetError, Settlement};
pub use definition::{
    evidence_hash, ChallengeWindow, PredictionMarketDefinition, ResolutionRules, DOMAIN_RESOLUTION,
};
pub use lifecycle::{
    is_order_entry_allowed, is_settlement_allowed, replay, transition, LifecycleError,
    LifecycleEvent,
};
pub use outcome::{ClaimId, ClaimKind, OutcomeError, OutcomeId, OutcomeSet};
pub use scalar::{ScalarError, ScalarRange};
pub use settlement::{no_claim_fraction, PayoutFractions, Resolution, SettlementError};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "prediction-markets";

#[cfg(test)]
mod tests {
    use super::*;
    use types::{AccountId, Amount, MarketId, MarketLifecycle, MarketType, Ratio, RATIO_SCALE};

    /// Deterministic in-test LCG (not the `rand` crate) for reproducible
    /// "property" tests.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 {
                0
            } else {
                self.next_u64() % n
            }
        }
    }

    const ALL_STATES: [MarketLifecycle; 12] = [
        MarketLifecycle::Draft,
        MarketLifecycle::Staked,
        MarketLifecycle::Bootstrapping,
        MarketLifecycle::Open,
        MarketLifecycle::Halted,
        MarketLifecycle::Closed,
        MarketLifecycle::PendingResolution,
        MarketLifecycle::Disputed,
        MarketLifecycle::Resolved,
        MarketLifecycle::Invalid,
        MarketLifecycle::Settled,
        MarketLifecycle::Archived,
    ];

    const ALL_EVENTS: [LifecycleEvent; 12] = [
        LifecycleEvent::Stake,
        LifecycleEvent::Bootstrap,
        LifecycleEvent::Open,
        LifecycleEvent::Halt,
        LifecycleEvent::Resume,
        LifecycleEvent::Close,
        LifecycleEvent::BeginResolution,
        LifecycleEvent::Dispute,
        LifecycleEvent::Resolve,
        LifecycleEvent::Invalidate,
        LifecycleEvent::Settle,
        LifecycleEvent::Archive,
    ];

    fn acct(n: u32) -> AccountId {
        AccountId::new(n)
    }
    fn amt(units: i128) -> Amount {
        Amount::from_raw(units)
    }

    // ---- Outcome set --------------------------------------------------------

    #[test]
    fn outcome_set_rejects_empty_duplicate_and_non_binary() {
        assert_eq!(OutcomeSet::new(vec![]), Err(OutcomeError::Empty));
        assert_eq!(
            OutcomeSet::new(vec![OutcomeId(1), OutcomeId(1)]),
            Err(OutcomeError::Duplicate)
        );
        // Binary market must be exactly two outcomes.
        let three = OutcomeSet::sequential(3).unwrap();
        assert_eq!(three.require_binary(), Err(OutcomeError::NotBinary));
        assert!(OutcomeSet::binary().require_binary().is_ok());
    }

    #[test]
    fn definition_enforces_binary_shape() {
        let rules = ResolutionRules::new(
            evidence_hash(b"criteria"),
            ChallengeWindow::new(0, 10),
            None,
        );
        let bad = PredictionMarketDefinition::new(
            MarketId::new(1),
            MarketType::BinaryPrediction,
            OutcomeSet::sequential(3).unwrap(),
            rules.clone(),
        );
        assert_eq!(bad, Err(OutcomeError::NotBinary));
        assert!(PredictionMarketDefinition::new(
            MarketId::new(1),
            MarketType::BinaryPrediction,
            OutcomeSet::binary(),
            rules,
        )
        .is_ok());
    }

    #[test]
    fn outcomes_are_exhaustive_and_mutually_exclusive_and_no_maps_deterministically() {
        let mut r = Lcg(0xA11CE);
        for _ in 0..2_000 {
            let n = usize::try_from(r.below(16) + 1).unwrap();
            let set = OutcomeSet::sequential(n).unwrap();
            // Exhaustive & mutually exclusive: every index present exactly once,
            // and index_of round-trips.
            for (i, o) in set.outcomes().iter().enumerate() {
                assert_eq!(set.index_of(*o).unwrap(), i);
                assert!(set.contains(*o));
            }
            // Synthetic NO maps deterministically to the complement basket.
            for o in set.outcomes() {
                let a = set.no_claim_complement(*o).unwrap();
                let b = set.no_claim_complement(*o).unwrap();
                assert_eq!(a, b);
                assert_eq!(a.len(), n - 1);
                assert!(a
                    .iter()
                    .all(|c| c.outcome != *o && c.kind == ClaimKind::Yes));
            }
        }
    }

    // ---- Codec round-trip ---------------------------------------------------

    #[test]
    fn codec_round_trip_is_bit_identical() {
        let mut r = Lcg(0xC0DEC);
        for _ in 0..1_000 {
            let n = usize::try_from(r.below(8) + 1).unwrap();
            let outcomes = OutcomeSet::sequential(n).unwrap();
            let committee = if r.below(2) == 0 {
                Some(
                    Committee::new(r.next_u64(), vec![[1u8; 32], [2u8; 32], [3u8; 32]], 2).unwrap(),
                )
            } else {
                None
            };
            let rules = ResolutionRules::new(
                evidence_hash(&r.next_u64().to_le_bytes()),
                ChallengeWindow::new(r.next_u64(), r.next_u64()),
                committee,
            );
            let mt = if n == 2 {
                MarketType::BinaryPrediction
            } else {
                MarketType::MultiOutcomePrediction
            };
            let def = PredictionMarketDefinition::new(
                MarketId::new(u32::try_from(r.below(1000)).unwrap()),
                mt,
                outcomes.clone(),
                rules,
            )
            .unwrap();

            // Definition round-trip + byte-identity.
            let bytes = postcard::to_allocvec(&def).unwrap();
            let back: PredictionMarketDefinition = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(def, back);
            assert_eq!(bytes, postcard::to_allocvec(&back).unwrap());

            // OutcomeSet round-trip + byte-identity.
            let ob = postcard::to_allocvec(&outcomes).unwrap();
            let oback: OutcomeSet = postcard::from_bytes(&ob).unwrap();
            assert_eq!(outcomes, oback);
            assert_eq!(ob, postcard::to_allocvec(&oback).unwrap());
        }
    }

    // ---- Lifecycle ----------------------------------------------------------

    #[test]
    fn lifecycle_legal_and_illegal_transitions() {
        use LifecycleEvent as E;
        use MarketLifecycle as S;
        // A representative set of legal transitions.
        let legal = [
            (S::Draft, E::Stake, S::Staked),
            (S::Staked, E::Bootstrap, S::Bootstrapping),
            (S::Bootstrapping, E::Open, S::Open),
            (S::Staked, E::Open, S::Open),
            (S::Open, E::Halt, S::Halted),
            (S::Halted, E::Resume, S::Open),
            (S::Open, E::Close, S::Closed),
            (S::Halted, E::Close, S::Closed),
            (S::Closed, E::BeginResolution, S::PendingResolution),
            (S::PendingResolution, E::Dispute, S::Disputed),
            (S::PendingResolution, E::Resolve, S::Resolved),
            (S::PendingResolution, E::Invalidate, S::Invalid),
            (S::Disputed, E::Resolve, S::Resolved),
            (S::Disputed, E::Invalidate, S::Invalid),
            (S::Resolved, E::Settle, S::Settled),
            (S::Invalid, E::Settle, S::Settled),
            (S::Settled, E::Archive, S::Archived),
        ];
        for (from, ev, to) in legal {
            assert_eq!(transition(from, ev), Ok(to));
        }
        // Representative illegal transitions.
        for (from, ev) in [
            (S::Draft, E::Open),
            (S::Open, E::Settle),
            (S::Archived, E::Stake),
            (S::Resolved, E::Resolve),
            (S::Settled, E::Resolve),
        ] {
            assert_eq!(
                transition(from, ev),
                Err(LifecycleError { from, event: ev })
            );
        }
    }

    #[test]
    fn lifecycle_transition_is_total_and_never_panics() {
        let mut r = Lcg(0xF00D);
        for _ in 0..100_000 {
            let s = ALL_STATES[usize::try_from(r.below(12)).unwrap()];
            let e = ALL_EVENTS[usize::try_from(r.below(12)).unwrap()];
            // Total: returns Ok or a typed Err for every pair; no panic.
            let _ = transition(s, e);
        }
    }

    #[test]
    fn order_entry_and_settlement_gates_are_exhaustive() {
        for s in ALL_STATES {
            assert_eq!(
                is_order_entry_allowed(s),
                s == MarketLifecycle::Open,
                "order entry gate wrong for {s:?}"
            );
            assert_eq!(
                is_settlement_allowed(s),
                matches!(s, MarketLifecycle::Resolved | MarketLifecycle::Invalid),
                "settlement gate wrong for {s:?}"
            );
        }
    }

    #[test]
    fn lifecycle_replay_is_deterministic() {
        let script = [
            LifecycleEvent::Stake,
            LifecycleEvent::Open,
            LifecycleEvent::Halt,
            LifecycleEvent::Resume,
            LifecycleEvent::Close,
            LifecycleEvent::BeginResolution,
            LifecycleEvent::Resolve,
            LifecycleEvent::Settle,
        ];
        let a = replay(MarketLifecycle::Draft, &script).unwrap();
        let b = replay(MarketLifecycle::Draft, &script).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, MarketLifecycle::Settled);
    }

    // ---- Complete-set mint/redeem/transfer ---------------------------------

    #[test]
    fn redeem_requires_every_outcome_and_never_partially_unlocks() {
        let outcomes = OutcomeSet::sequential(3).unwrap();
        let mut book = ClaimBook::new(&outcomes);
        book.mint(acct(1), amt(5_000_000)).unwrap();
        // Move away all of outcome 1 so holder no longer holds a full complete set.
        book.transfer(acct(1), acct(2), 1, amt(5_000_000)).unwrap();
        assert_eq!(
            book.redeem(acct(1), amt(1_000_000)),
            Err(CompleteSetError::InsufficientClaims)
        );
        // Locked collateral unchanged after the failed redeem (no partial unlock).
        assert_eq!(book.locked_collateral(), amt(5_000_000));
        // A holder with a full complete set can redeem.
        book.transfer(acct(2), acct(1), 1, amt(5_000_000)).unwrap();
        book.redeem(acct(1), amt(2_000_000)).unwrap();
        assert_eq!(book.locked_collateral(), amt(3_000_000));
    }

    #[test]
    fn complete_set_invariant_holds_over_random_ops() {
        let mut r = Lcg(0x5EED);
        let outcomes = OutcomeSet::sequential(4).unwrap();
        let mut book = ClaimBook::new(&outcomes);
        for _ in 0..20_000 {
            let holder = acct(u32::try_from(r.below(5)).unwrap());
            let a = amt(i128::from(r.below(1_000_000) + 1));
            match r.below(3) {
                0 => {
                    let _ = book.mint(holder, a);
                }
                1 => {
                    let _ = book.redeem(holder, a);
                }
                _ => {
                    let to = acct(u32::try_from(r.below(5)).unwrap());
                    let i = usize::try_from(r.below(4)).unwrap();
                    let _ = book.transfer(holder, to, i, a);
                }
            }
            // Invariant: every outcome's outstanding claims == locked collateral.
            let locked = book.locked_collateral();
            for i in 0..outcomes.len() {
                assert_eq!(book.outstanding(i), locked);
            }
        }
    }

    // ---- Settlement: hand-computed cases -----------------------------------

    /// Build a book where each outcome `i` is wholly held by account `i+1`.
    fn one_outcome_per_holder(outcomes: &OutcomeSet, units: i128) -> ClaimBook {
        let mut book = ClaimBook::new(outcomes);
        book.mint(acct(1), amt(units)).unwrap();
        for i in 1..outcomes.len() {
            book.transfer(acct(1), acct(u32::try_from(i + 1).unwrap()), i, amt(units))
                .unwrap();
        }
        book
    }

    #[test]
    fn binary_winner_take_all() {
        let outcomes = OutcomeSet::binary();
        let book = one_outcome_per_holder(&outcomes, 10_000_000); // A=out0, B=out1
        let s = book
            .settle(&outcomes, &Resolution::Winner(OutcomeId(0)))
            .unwrap();
        assert_eq!(s.credit_of(acct(1)), amt(10_000_000));
        assert_eq!(s.credit_of(acct(2)), amt(0));
        assert_eq!(s.total_credited(), amt(10_000_000));
        assert!(s.is_conserved());
    }

    #[test]
    fn multi_outcome_explicit_vector() {
        let outcomes = OutcomeSet::sequential(3).unwrap();
        let book = one_outcome_per_holder(&outcomes, 9_000_000);
        // 0.5 / 0.3 / 0.2
        let pf = PayoutFractions::new(vec![
            Ratio::from_raw(500_000),
            Ratio::from_raw(300_000),
            Ratio::from_raw(200_000),
        ])
        .unwrap();
        let s = book.settle(&outcomes, &Resolution::Vector(pf)).unwrap();
        assert_eq!(s.credit_of(acct(1)), amt(4_500_000));
        assert_eq!(s.credit_of(acct(2)), amt(2_700_000));
        assert_eq!(s.credit_of(acct(3)), amt(1_800_000));
        assert_eq!(s.total_credited(), amt(9_000_000));
    }

    #[test]
    fn dead_heat_splits_equally() {
        let outcomes = OutcomeSet::sequential(3).unwrap();
        let book = one_outcome_per_holder(&outcomes, 6_000_000);
        let s = book
            .settle(
                &outcomes,
                &Resolution::DeadHeat(vec![OutcomeId(0), OutcomeId(1)]),
            )
            .unwrap();
        assert_eq!(s.credit_of(acct(1)), amt(3_000_000));
        assert_eq!(s.credit_of(acct(2)), amt(3_000_000));
        assert_eq!(s.credit_of(acct(3)), amt(0));
        assert_eq!(s.total_credited(), amt(6_000_000));
    }

    #[test]
    fn scalar_value_maps_to_fraction_exactly() {
        let outcomes = OutcomeSet::binary();
        let book = one_outcome_per_holder(&outcomes, 8_000_000);
        let range = ScalarRange::new(amt(0), amt(100_000_000)).unwrap();
        // value 25.0 -> long fraction 0.25
        let s = book
            .settle(
                &outcomes,
                &Resolution::Scalar {
                    range,
                    value: amt(25_000_000),
                },
            )
            .unwrap();
        assert_eq!(s.credit_of(acct(1)), amt(2_000_000)); // long: 8 * 0.25
        assert_eq!(s.credit_of(acct(2)), amt(6_000_000)); // short: 8 * 0.75
        assert_eq!(s.total_credited(), amt(8_000_000));
    }

    #[test]
    fn scalar_clamps_beyond_bounds() {
        let range = ScalarRange::new(amt(10_000_000), amt(20_000_000)).unwrap();
        // below lower -> long fraction 0
        assert_eq!(range.long_fraction(amt(0)).unwrap(), Ratio::from_raw(0));
        // above upper -> long fraction 1
        assert_eq!(
            range.long_fraction(amt(999_000_000)).unwrap(),
            Ratio::from_raw(RATIO_SCALE)
        );
        // exact midpoint -> 0.5, and the pair sums to 1.0
        let [long, short] = range.fractions(amt(15_000_000)).unwrap();
        assert_eq!(long, Ratio::from_raw(500_000));
        assert_eq!(long.raw() + short.raw(), RATIO_SCALE);
    }

    #[test]
    fn partial_vector_refunds_shortfall_equally() {
        let outcomes = OutcomeSet::binary();
        let book = one_outcome_per_holder(&outcomes, 10_000_000);
        // raw [0.6, 0.0] sums to 0.6; shortfall 0.4 split equally -> [0.8, 0.2]
        let pf = PayoutFractions::new(vec![Ratio::from_raw(600_000), Ratio::from_raw(0)]).unwrap();
        assert_eq!(
            pf.normalized(),
            vec![Ratio::from_raw(800_000), Ratio::from_raw(200_000)]
        );
        let s = book.settle(&outcomes, &Resolution::Vector(pf)).unwrap();
        assert_eq!(s.credit_of(acct(1)), amt(8_000_000));
        assert_eq!(s.credit_of(acct(2)), amt(2_000_000));
        assert_eq!(s.total_credited(), amt(10_000_000));
    }

    #[test]
    fn invalid_refunds_complete_sets_equally() {
        let outcomes = OutcomeSet::sequential(4).unwrap();
        // Split holders: A holds only outcome 0; B holds outcomes 1,2,3.
        let mut book = ClaimBook::new(&outcomes);
        book.mint(acct(1), amt(4_000_000)).unwrap();
        for i in 1..4 {
            book.transfer(acct(1), acct(2), i, amt(4_000_000)).unwrap();
        }
        let s = book.settle(&outcomes, &Resolution::Invalid).unwrap();
        // Equal 1/4 refund: A recovers 1 outcome's worth, B recovers three.
        assert_eq!(s.credit_of(acct(1)), amt(1_000_000));
        assert_eq!(s.credit_of(acct(2)), amt(3_000_000));
        assert_eq!(s.total_credited(), amt(4_000_000));

        // A holder of a full complete set is refunded in full under INVALID.
        let single = OutcomeSet::sequential(1).unwrap();
        let full = one_outcome_per_holder(&single, 7_000_000);
        let s2 = full.settle(&single, &Resolution::Invalid).unwrap();
        assert_eq!(s2.credit_of(acct(1)), amt(7_000_000));
    }

    #[test]
    fn synthetic_no_equivalence() {
        // NO_i fraction equals the sum of the YES fractions of every other outcome.
        let outcomes = OutcomeSet::sequential(4).unwrap();
        let pf = PayoutFractions::new(vec![
            Ratio::from_raw(100_000),
            Ratio::from_raw(250_000),
            Ratio::from_raw(400_000),
            Ratio::from_raw(250_000),
        ])
        .unwrap();
        let norm = Resolution::Vector(pf).to_fractions(&outcomes).unwrap();
        for (i, fi) in norm.iter().enumerate() {
            let no = no_claim_fraction(&norm, i).unwrap();
            let others: i64 = norm
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, f)| f.raw())
                .sum();
            assert_eq!(no.raw(), others);
            assert_eq!(no.raw() + fi.raw(), RATIO_SCALE);
        }
    }

    // ---- Settlement: value-conservation property ---------------------------

    #[test]
    fn settlement_conserves_locked_collateral() {
        let mut r = Lcg(0xBEEF);
        for _ in 0..3_000 {
            let n = usize::try_from(r.below(6) + 2).unwrap();
            let outcomes = OutcomeSet::sequential(n).unwrap();
            let mut book = ClaimBook::new(&outcomes);
            // Mint to several holders, then scatter individual claims by transfer.
            for h in 1..=4u32 {
                let a = amt(i128::from(r.below(2_000_000) + 1));
                book.mint(acct(h), a).unwrap();
            }
            for _ in 0..12 {
                let from = acct(u32::try_from(r.below(4) + 1).unwrap());
                let to = acct(u32::try_from(r.below(6) + 1).unwrap());
                let i = usize::try_from(r.below(u64::try_from(n).unwrap())).unwrap();
                let bal = book.balance(from, i).raw();
                if bal > 0 {
                    let a = amt(i128::from(r.below(u64::try_from(bal).unwrap()) + 1).min(bal));
                    let _ = book.transfer(from, to, i, a);
                }
            }
            // Random valid partial payout vector (raw sum <= 1.0).
            let mut raws = Vec::with_capacity(n);
            let mut remaining = RATIO_SCALE;
            for _ in 0..n {
                let take = i64::try_from(r.below(u64::try_from(remaining + 1).unwrap())).unwrap();
                raws.push(Ratio::from_raw(take));
                remaining -= take;
            }
            let pf = PayoutFractions::new(raws).unwrap();
            let s = book.settle(&outcomes, &Resolution::Vector(pf)).unwrap();
            // Exact conservation: credited total equals locked collateral.
            assert_eq!(s.total_credited(), book.locked_collateral());
            assert!(s.is_conserved());
            // No single credit exceeds the locked collateral, and none is negative.
            for c in s.credits().values() {
                assert!(c.raw() <= book.locked_collateral().raw());
                assert!(c.raw() >= 0);
            }
        }
    }

    // ---- Committee ----------------------------------------------------------

    #[test]
    fn committee_accepts_authenticated_quorum_and_rejects_below() {
        use crypto::KeyPair;

        let keys: Vec<KeyPair> = (0..3u8).map(|i| KeyPair::from_seed(&[i; 32])).collect();
        let members: Vec<[u8; 32]> = keys.iter().map(KeyPair::public).collect();
        let committee = Committee::new(0, members, 2).unwrap();

        let round = ResolutionRound {
            deployment: types::Hash::from_bytes([0xDE; 32]),
            epoch: 0,
            market_binding: types::Hash::from_bytes([0xAB; 32]),
            round: 1,
            expiry: 100,
        };
        let win = ResolutionClaim {
            outcome: OutcomeId(1),
            payout_digest: evidence_hash(b"winner-take-all outcome 1"),
            evidence_hash: evidence_hash(b"news report"),
        };
        let lose = ResolutionClaim {
            outcome: OutcomeId(0),
            payout_digest: evidence_hash(b"winner-take-all outcome 0"),
            evidence_hash: evidence_hash(b"news report"),
        };

        // Two of three sign the same claim -> accepted.
        let votes = [
            ResolverVote::signed(round, win, ResolverId(0), &keys[0]),
            ResolverVote::signed(round, win, ResolverId(1), &keys[1]),
            ResolverVote::signed(round, lose, ResolverId(2), &keys[2]),
        ];
        assert_eq!(
            committee.tally(&round, 0, &votes).decision,
            CommitteeDecision::Accepted {
                claim: win,
                votes: 2
            }
        );

        // Only one distinct signer for the leading claim -> insufficient.
        let votes2 = [
            ResolverVote::signed(round, win, ResolverId(0), &keys[0]),
            ResolverVote::signed(round, lose, ResolverId(1), &keys[1]),
        ];
        assert_eq!(
            committee.tally(&round, 0, &votes2).decision,
            CommitteeDecision::Insufficient { leader_votes: 1 }
        );

        // Bad construction.
        assert_eq!(Committee::new(0, vec![], 1), Err(CommitteeError::Empty));
        assert_eq!(
            Committee::new(0, vec![[1u8; 32]], 2),
            Err(CommitteeError::BadThreshold)
        );
    }

    // ---- Never panics on arbitrary bytes -----------------------------------

    #[test]
    fn decode_and_settle_never_panic_on_arbitrary_bytes() {
        let outcomes = OutcomeSet::sequential(3).unwrap();
        let mut book = ClaimBook::new(&outcomes);
        book.mint(acct(1), amt(1_000_000)).unwrap();
        let mut r = Lcg(0xDEAD_BEEF);
        for _ in 0..50_000 {
            let len = usize::try_from(r.below(48)).unwrap();
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(r.next_u64().to_le_bytes()[0]);
            }
            // Arbitrary evidence bytes never panic.
            let _ = evidence_hash(&buf);
            // Arbitrary decode targets are total (Ok or typed Err), never panic.
            let _ = postcard::from_bytes::<PredictionMarketDefinition>(&buf);
            let _ = postcard::from_bytes::<OutcomeSet>(&buf);
            let _ = postcard::from_bytes::<PayoutFractions>(&buf);
            if let Ok(res) = postcard::from_bytes::<Resolution>(&buf) {
                // Settling a decoded (untrusted) resolution never panics and never
                // over-credits: a successful settlement conserves collateral.
                if let Ok(s) = book.settle(&outcomes, &res) {
                    assert!(s.total_credited().raw() <= book.locked_collateral().raw());
                    assert!(s.is_conserved());
                }
            }
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "prediction-markets");
    }
}
