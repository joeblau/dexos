use super::*;
use consensus::{MinimmitCommittee, MinimmitReplica, ValidatorSetUpdate};
use crypto::{KeyPair, Validator};
use types::Hash;

#[test]
fn minimmit_rejects_under_sized_committees() {
    assert!(Cluster::run(SimConfig::clean(5, 1, 1)).is_err());
}

#[test]
fn s1_honest_replicas_agree_and_execution_finalize() {
    let mut config = scenario::happy_path(6, 4, 7);
    config.max_steps = 10_000;
    let result = Cluster::run(config).unwrap();
    assert!(
        result.all_finalized(4),
        "finalized={:?} steps={} transport={:?}",
        result.survivor_finalized,
        result.steps,
        result.transport
    );
    result.agree().unwrap();
    assert_eq!(result.heights_completed, 4);
}

#[test]
fn s2_byzantine_equivocation_cannot_form_conflicting_finality() {
    for seed in 0..8 {
        let result = Cluster::run(scenario::byzantine_equivocation(1, 3, seed)).unwrap();
        assert!(result.all_finalized(3), "seed {seed}");
        result.agree().unwrap();
        assert!(result.equivocations_detected > 0);
    }
}

#[test]
fn s3_invalid_signatures_never_count() {
    let result = Cluster::run(scenario::invalid_signatures(1, 3, 19)).unwrap();
    assert!(result.all_finalized(3));
    result.agree().unwrap();
}

#[test]
fn s4_equivocating_leader_advances_without_conflicting_finality() {
    let result = Cluster::run(scenario::equivocating_leader(6, 3, 29)).unwrap();
    assert!(result.all_finalized(3));
    result.agree().unwrap();
    assert!(result.forks_detected > 0);
}

#[test]
fn l2_crashed_leader_advances_on_two_delta_timer() {
    let result = Cluster::run(scenario::leader_failover(6, 3, 31)).unwrap();
    assert!(result.all_finalized(3));
    result.agree().unwrap();
    assert!(result.failover_time_ns.is_some());
}

#[test]
fn l4_partition_heal_and_r7_reconverge() {
    let result = Cluster::run(scenario::partition_heal(
        6,
        3,
        41,
        vec![0, 0, 0, 1, 1, 1],
        400_000,
    ))
    .unwrap();
    assert!(result.all_finalized(3));
    result.agree().unwrap();
}

#[test]
fn deterministic_replay_is_bit_identical() {
    let mut config = scenario::packet_loss(6, 2, 53, 20, 20);
    config.max_steps = 5_000;
    let first = Cluster::run(config.clone()).unwrap();
    let second = Cluster::run(config).unwrap();
    assert_eq!(first.trace_digest, second.trace_digest);
    assert_eq!(first.survivor_roots, second.survivor_roots);
    assert!(
        first.all_finalized(2),
        "finalized={:?} steps={}",
        first.survivor_finalized,
        first.steps
    );
}

#[test]
fn epoch_change_revalidates_minimmit_sizing_and_restarts_view_zero() {
    let keys: Vec<KeyPair> = (0u8..6)
        .map(|index| KeyPair::from_seed(&[index.saturating_add(1); 32]))
        .collect();
    let validators: Vec<Validator> = keys
        .iter()
        .map(|key| Validator {
            public_key: key.public(),
            weight: 1,
        })
        .collect();
    let committee = MinimmitCommittee::new_unit(0, validators.clone()).unwrap();
    let (mut replica, _) =
        MinimmitReplica::new_with_signer(committee, 0, Hash::ZERO, 0, keys[0].clone()).unwrap();
    replica.schedule_update(ValidatorSetUpdate {
        activation_epoch: 1,
        validators,
    });
    let effects = replica.activate_epoch(1).unwrap();
    assert_eq!(replica.epoch(), 1);
    assert_eq!(replica.view(), 0);
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, consensus::minimmit::Effect::ArmTimer { view: 0 })));
}
