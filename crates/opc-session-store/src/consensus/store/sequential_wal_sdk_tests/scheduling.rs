//! Native three-voter proposal and forwarding isolation, with real commits.
use super::scope_authority::{Admission, Clock};
use super::*;
use crate::consensus::store::{
    AcceptedClientWriteReceiverHoldForTest, AcceptedClientWriteReceiverTestOutcome,
};
use crate::scope_authority::tests::{execution, identity};
use crate::scope_authority::*;
use crate::scope_batch::tests::create;
use crate::scope_batch::*;
use crate::scope_scheduler::{ScopeSchedulerKey, ScopeWorkClass};
use std::sync::atomic::AtomicU64;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scheduler_three_voters_forward_control_and_emergency_past_saturated_proposals() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_native("scope_scheduler_three_voters");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let mut holds = Vec::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut occupied = Vec::new();
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let follower = (leader + 1) % 3;
        let controller_voter = (leader + 2) % 3;
        let mut scopes = Vec::new();
        let mut requests = Vec::new();
        for n in 1..=10 {
            let scope = ScopeId::new(
                fleet.topologies[0].consensus_identity().unwrap(),
                TenantId::from_static("scheduler-test"),
                NetworkFunctionKind::smf(),
                [n; 32],
            )
            .unwrap();
            let authority = ScopeAuthorityStore::new(
                Arc::new(fleet.stores[leader].clone()),
                scope.clone(),
                Arc::new(Admission),
            )
            .unwrap();
            let grant = authority
                .admit(
                    &identity("worker-1"),
                    &ScopeAuthorityRequest::new(
                        scope.clone(),
                        [n; 16],
                        0,
                        ScopeAuthorityOperation::AdmitInitial {
                            execution: execution(1),
                        },
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let request = ScopeBatchRequest::new(
                grant.stamp(),
                [n + 20; 16],
                0,
                vec![create(n, &[n])],
                vec![],
            )
            .unwrap();
            scopes.push(grant.stamp().namespace().clone());
            requests.push(request);
        }
        let batch_service = |voter: usize, namespace: &ScopeNamespace| {
            ScopeBatchStore::new(
                Arc::new(fleet.stores[voter].clone()),
                namespace.clone(),
                Arc::new(Admission),
            )
            .unwrap()
        };
        // Hold every Normal proposal slot in the leader's real accepted-write
        // supervisor, after acceptance but before the caller receives a result.
        for n in 0..8 {
            let hold = Arc::new(AcceptedClientWriteReceiverHoldForTest::default());
            fleet.stores[leader].inject_accepted_client_write_receiver_outcome(
                AcceptedClientWriteReceiverTestOutcome::HoldUntilReleased(Arc::clone(&hold)),
            );
            let service = batch_service(leader, &scopes[n]);
            let request = requests[n].clone();
            tasks.spawn(async move {
                service
                    .execute(&identity("worker-1"), &request)
                    .await
                    .map(|_| ())
            });
            tokio::time::timeout(Duration::from_secs(5), hold.entered.notified())
                .await
                .expect("Normal proposal accepted");
            holds.push(hold);
        }
        // Fill the remaining Normal and Maintenance capacity at both real
        // admission boundaries on every voter. The leader's eight accepted
        // writes already hold all of its Normal execution credits. Inspect
        // actual capacity so an incorrectly shared pool has no escape slots.
        for store in &fleet.stores {
            for pool in [
                &store.inner.proposal_admission,
                &store.inner.forward_admission,
            ] {
                for class in [ScopeWorkClass::Normal, ScopeWorkClass::Maintenance] {
                    let mut key = 100;
                    while pool.available_in_class_for_test(class) > 0 {
                        occupied.push(
                            pool.acquire_for(ScopeSchedulerKey::from_bytes([key; 32]), class)
                                .await
                                .unwrap(),
                        );
                        key += 1;
                    }
                }
            }
        }
        let wave_service = batch_service(leader, &scopes[8]);
        let wave_request = requests[8].clone();
        tasks.spawn(async move {
            wave_service
                .execute(&identity("worker-1"), &wave_request)
                .await
                .map(|_| ())
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while fleet.stores[leader]
                .inner
                .proposal_admission
                .snapshot()
                .class(ScopeWorkClass::Normal)
                .start_waiting
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ordinary proposal wave waits at the leader");
        let emergency = batch_service(follower, &scopes[9]);
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            emergency.execute_classified(
                &identity("worker-1"),
                &requests[9],
                ScopeWorkClass::Emergency,
            ),
        )
        .await
        .expect("Emergency passes held ordinary proposals")
        .unwrap();
        assert_eq!(outcome.revision(), 1);
        assert_eq!(
            emergency
                .execute_classified(&identity("worker-1"), &requests[9], ScopeWorkClass::Normal)
                .await
                .unwrap(),
            outcome,
            "changing scheduling metadata preserves the exact canonical replay"
        );
        assert_eq!(
            emergency
                .execute_classified(
                    &identity("worker-1"),
                    &requests[9],
                    ScopeWorkClass::SafetyControl
                )
                .await,
            Err(ScopeAuthorityError::Unauthorized.into()),
            "a worker cannot declare control even on a replay"
        );
        assert_eq!(
            emergency
                .execute_classified(
                    &identity("worker-2"),
                    &requests[9],
                    ScopeWorkClass::Emergency
                )
                .await,
            Err(ScopeAuthorityError::Unauthorized.into()),
            "declaration never substitutes for own-scope execution authentication"
        );
        let control_scope = ScopeId::new(
            fleet.topologies[0].consensus_identity().unwrap(),
            TenantId::from_static("scheduler-test"),
            NetworkFunctionKind::smf(),
            [11; 32],
        )
        .unwrap();
        let control = ScopeAuthorityStore::new(
            Arc::new(fleet.stores[controller_voter].clone()),
            control_scope.clone(),
            Arc::new(Admission),
        )
        .unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            control.execute(
                &identity("worker-1"),
                &ScopeAuthorityRequest::new(
                    control_scope,
                    [99; 16],
                    0,
                    ScopeAuthorityOperation::AdmitInitial {
                        execution: execution(1),
                    },
                )
                .unwrap(),
            ),
        )
        .await
        .expect("SafetyControl passes held ordinary proposals")
        .unwrap();
        assert_eq!(tasks.len(), 9);
        assert!(
            tasks.try_join_next().is_none(),
            "ordinary callers remain held or queued while both privileged commits finish"
        );
        let counts = fleet.stores[leader].inner.proposal_admission.snapshot();
        assert_eq!(counts.class(ScopeWorkClass::Normal).running, 8);
        assert_eq!(counts.class(ScopeWorkClass::Maintenance).running, 1);
    })
    .catch_unwind()
    .await;
    for hold in &holds {
        hold.release.notify_one();
    }
    drop(occupied);
    let joined = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(outcome) = tasks.join_next().await {
            outcome.unwrap().unwrap();
        }
    })
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    joined.expect("all ordinary work resumes without rejection or a retry ceiling");
}
