//! Actual hot-child contention and independent admission across three voters.

use super::scope_authority::{Admission, Clock};
use super::*;
use crate::consensus::store::{
    AcceptedClientWriteReceiverHoldForTest, AcceptedClientWriteReceiverTestOutcome,
};
use crate::scope_authority::tests::{execution, identity};
use crate::scope_authority::*;
use crate::scope_batch::tests::{create, key, value};
use crate::scope_batch::*;
use crate::scope_scheduler::{
    ClassBudget, ScopeSchedulerBudgets, ScopeSchedulerKey, ScopeSchedulerOwner, ScopeWorkClass,
};
use std::sync::atomic::AtomicU64;

// Events and committed state order this fixture. This generous test-only guard
// detects a hang under host load; the Emergency bound below counts rounds.
const HANG_GUARD: Duration = Duration::from_secs(60);

#[test]
fn scope_batch_forwarded_reserved_lane_requires_established_emergency() {
    use crate::consensus::store::scheduling::ForwardWorkClass;
    use crate::consensus::store::{ForwardConsumerScope, ForwardMutationRequest};
    use crate::consensus::{SessionConsensusRequestId, SessionMutationIntent};
    use crate::StoreError;
    let authority = crate::scope_authority::tests::admitted();
    let request = ScopeBatchRequest::in_lane(
        authority.view.stamp().unwrap(),
        [9; 16],
        7,
        1,
        vec![create(1, &[])],
        vec![],
    )
    .unwrap();
    for intent in [
        SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: request.clone(),
        })),
        SessionMutationIntent::ScopeBatchCancel(Box::new(ScopeBatchCancelCommand {
            attempt: request.attempt().unwrap(),
        })),
    ] {
        let mut forwarded = ForwardMutationRequest {
            request_id: SessionConsensusRequestId::from_bytes([9; 16]),
            intent,
            required_consumer_scope: ForwardConsumerScope::Internal,
            work_class: ForwardWorkClass::Declared(ScopeWorkClass::Emergency),
        };
        assert_eq!(forwarded.scheduling().unwrap().1, ScopeWorkClass::Emergency);
        for class in [
            ScopeWorkClass::Normal,
            ScopeWorkClass::EmergencyClassification,
            ScopeWorkClass::Maintenance,
            ScopeWorkClass::SafetyControl,
        ] {
            forwarded.work_class = ForwardWorkClass::Declared(class);
            assert_eq!(
                forwarded.scheduling(),
                Err(StoreError::TopologyAuthorityRevoked),
                "forwarding cannot bypass reserved lane admission"
            );
        }
        forwarded.work_class = ForwardWorkClass::Inferred;
        assert_eq!(
            forwarded.scheduling(),
            Err(StoreError::TopologyAuthorityRevoked)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_batch_emergency_handoff_wins_hot_child_in_two_rounds_with_normal_lanes_full() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_native("scope_batch_hot_lanes");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    fleet.clock = Some(Arc::new(Clock(AtomicU64::new(0))));
    fleet.open().await;
    let mut holds = Vec::new();
    let mut occupied = Vec::new();
    let mut normal = Vec::new();
    let mut builders = tokio::task::JoinSet::new();
    let mut owner = None;
    let mut coordinator = None;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let follower = (leader + 1) % 3;
        let scope = ScopeId::new(
            fleet.topologies[0].consensus_identity().unwrap(),
            TenantId::from_static("scope-batch-hot-lanes"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let grant = ScopeAuthorityStore::new(
            Arc::new(fleet.stores[leader].clone()),
            scope.clone(),
            Arc::new(Admission),
        )
        .unwrap()
        .admit(
            &identity("worker-1"),
            &ScopeAuthorityRequest::new(
                scope,
                [1; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: execution(1),
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let service = ScopeBatchStore::new(
            Arc::new(fleet.stores[follower].clone()),
            grant.stamp().namespace().clone(),
            Arc::new(Admission),
        )
        .unwrap();
        let reserved = ScopeBatchRequest::in_lane(
            grant.stamp(),
            [250; 16],
            7,
            1,
            vec![create(250, &[])],
            vec![],
        )
        .unwrap();
        for class in [
            ScopeWorkClass::Normal,
            ScopeWorkClass::Maintenance,
            ScopeWorkClass::EmergencyClassification,
            ScopeWorkClass::SafetyControl,
        ] {
            assert_eq!(
                service
                    .execute_classified(&identity("worker-1"), &reserved, class)
                    .await,
                Err(ScopeAuthorityError::Unauthorized.into()),
                "raw public mutation cannot consume the established-Emergency lane"
            );
            assert_eq!(
                service
                    .cancel_classified(&identity("worker-1"), &reserved.attempt().unwrap(), class)
                    .await,
                Err(ScopeAuthorityError::Unauthorized.into()),
                "raw public cancellation cannot consume the established-Emergency lane"
            );
        }
        let seed =
            ScopeBatchRequest::in_lane(grant.stamp(), [2; 16], 0, 1, vec![create(1, &[])], vec![])
                .unwrap();
        let original = service
            .execute(&identity("worker-1"), &seed)
            .await
            .unwrap()
            .rows()[0];
        // The coordinator can build all seven ordinary lanes. The actual store
        // proposal and forwarding pools retain their prescribed production caps.
        owner = Some(
            ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
                ScopeWorkClass::Normal,
                ClassBudget {
                    queued: 24,
                    running: 14,
                },
            ))
            .unwrap(),
        );
        let shared = ScopeBatchCoordinator::open(
            service.clone(),
            identity("worker-1"),
            &grant,
            owner.as_ref().unwrap().scheduler(),
        )
        .await
        .unwrap();
        assert!(shared.ack(shared.completions().next().await.attempt()));
        coordinator = Some(shared.clone());

        // Emergency reads the hot page first, then deliberately loses exactly
        // one apply race to Normal while retaining its reserved lane.
        let read = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let reservation = shared.reserve(ScopeWorkClass::Emergency).await.unwrap();
        let batch = service.clone();
        let ready = read.clone();
        let start = release.clone();
        builders.spawn(async move {
            reservation
                .submit(|context| async move {
                    let row = batch.read(&identity("worker-1"), key(1)).await?.unwrap();
                    ready.notify_one();
                    start.notified().await;
                    context.request(
                        [90; 16],
                        vec![
                            ScopeChildMutation::CompareAndSet {
                                key: key(1),
                                expected: row.revision(),
                                value: value(90),
                                claims: vec![],
                            },
                            create(90, &[]),
                        ],
                        vec![],
                    )
                })
                .await
                .unwrap()
        });
        tokio::time::timeout(HANG_GUARD, read.notified())
            .await
            .unwrap();
        let ordinary_per_scope = ScopeSchedulerBudgets::default().normal.running.div_ceil(2);
        for lane in 0..7 {
            let hold = (usize::from(lane) < ordinary_per_scope)
                .then(|| Arc::new(AcceptedClientWriteReceiverHoldForTest::default()));
            if let Some(hold) = &hold {
                fleet.stores[leader].inject_accepted_client_write_receiver_outcome(
                    AcceptedClientWriteReceiverTestOutcome::HoldUntilReleased(hold.clone()),
                );
                holds.push(hold.clone());
            }
            normal.push(
                shared
                    .reserve_lane(lane, ScopeWorkClass::Normal)
                    .await
                    .unwrap()
                    .submit(|context| async move {
                        context.request(
                            [10 + lane; 16],
                            vec![ScopeChildMutation::CompareAndSet {
                                key: key(1),
                                expected: original,
                                value: value(10 + lane),
                                claims: vec![],
                            }],
                            vec![],
                        )
                    })
                    .await
                    .unwrap(),
            );
            if let Some(hold) = hold {
                tokio::time::timeout(HANG_GUARD, hold.entered.notified())
                    .await
                    .unwrap();
            }
        }
        let mut progress = fleet.stores[follower].inner.raft.metrics();
        tokio::time::timeout(HANG_GUARD, async {
            while service
                .read(&identity("worker-1"), key(1))
                .await
                .unwrap()
                .unwrap()
                .revision()
                == original
            {
                progress
                    .changed()
                    .await
                    .expect("replica progress remains observable");
            }
        })
        .await
        .expect("the held first Normal response has committed its hot-page update");
        assert!(shared.lane_status()[..7].iter().all(|lane| lane.occupied));

        // Occupy all remaining real ordinary/maintenance proposal and forwarding
        // credits on every voter. This also catches an accidental shared pool.
        for store in &fleet.stores {
            for pool in [
                &store.inner.proposal_admission,
                &store.inner.forward_admission,
            ] {
                for class in [ScopeWorkClass::Normal, ScopeWorkClass::Maintenance] {
                    let mut n = 100;
                    while pool.available_in_class_for_test(class) > 0 {
                        occupied.push(
                            pool.acquire_for(ScopeSchedulerKey::from_bytes([n; 32]), class)
                                .await
                                .unwrap(),
                        );
                        n += 1;
                    }
                }
            }
        }
        assert!(normal.iter().all(|handle| shared.lane_status()
            [usize::from(handle.attempt().lane())]
        .oldest_unacknowledged
        .is_none()));
        release.notify_one();
        let first = builders.join_next().await.unwrap().unwrap();
        let conflict = tokio::time::timeout(HANG_GUARD, first.completion())
            .await
            .expect("Emergency conflict and cancellation bypass saturated ordinary pools");
        assert!(matches!(
            conflict.outcome(),
            ScopeBatchCompletionOutcome::Cancelled
        ));
        assert!(matches!(
            conflict.refusal(),
            Some(ScopeBatchError::Conflict(_))
        ));
        assert!(shared.ack(conflict.attempt()));
        assert_eq!(first.attempt().sequence(), 1);
        assert!(service
            .read(&identity("worker-1"), key(90))
            .await
            .unwrap()
            .is_none());
        let batch = &service;
        let second = shared
            .reserve(ScopeWorkClass::Emergency)
            .await
            .unwrap()
            .submit(|context| async move {
                let row = batch.read(&identity("worker-1"), key(1)).await?.unwrap();
                context.request(
                    [91; 16],
                    vec![
                        ScopeChildMutation::CompareAndSet {
                            key: key(1),
                            expected: row.revision(),
                            value: value(91),
                            claims: vec![],
                        },
                        create(90, &[]),
                    ],
                    vec![],
                )
            })
            .await
            .unwrap();
        let committed = tokio::time::timeout(HANG_GUARD, second.completion())
            .await
            .expect("the rebuilt Emergency handoff commits in its second round");
        let ScopeBatchCompletionOutcome::Applied(outcome) = committed.outcome() else {
            panic!("second Emergency round did not commit: {committed:?}");
        };
        assert_eq!(second.attempt().sequence(), 2);
        assert_eq!(outcome.rows()[0].generation(), 3);
        assert!(shared.ack(committed.attempt()));
        assert_eq!(
            service
                .read(&identity("worker-1"), key(1))
                .await
                .unwrap()
                .unwrap()
                .value(),
            Some(&value(91))
        );
        assert!(service
            .read(&identity("worker-1"), key(90))
            .await
            .unwrap()
            .is_some());
        assert!(shared.lane_status()[..7].iter().all(|lane| lane.occupied));
    })
    .catch_unwind()
    .await;
    for hold in holds {
        hold.release.notify_one();
    }
    drop(occupied);
    builders.abort_all();
    while builders.join_next().await.is_some() {}
    let drained = tokio::time::timeout(HANG_GUARD, async {
        for handle in normal {
            let completion = handle.completion().await;
            assert!(matches!(
                completion.outcome(),
                ScopeBatchCompletionOutcome::Applied(_) | ScopeBatchCompletionOutcome::Cancelled
            ));
            assert!(coordinator.as_ref().unwrap().ack(completion.attempt()));
        }
    })
    .await;
    if let Some(owner) = owner {
        owner.close();
    }
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    drained.expect("ordinary lanes resolve after releasing proposal capacity");
}
