//! Real native quorum, full payload, lost reply, compaction and cold reopen.

use super::scope_lease::{compact, Admission, Clock};
use super::*;
use crate::scope_batch::tests::{claim, create, key, value};
use crate::scope_batch::*;
use crate::scope_lease::tests::{bounds, execution, identity};
use crate::scope_lease::*;
use std::sync::atomic::AtomicU64;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_batch_native_follower_catches_up_over_eighty_small_batches() {
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_native("scope_batch_catchup");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let lagging = (leader + 1) % 3;
        let scope = ScopeLeaseId::new(
            fleet.topologies[0].consensus_identity().unwrap(),
            TenantId::from_static("scope-batch-catchup"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let authority = ScopeLeaseStore::new(
            Arc::new(fleet.stores[leader].clone()),
            scope.clone(),
            clock.clone(),
            Arc::new(Admission),
        )
        .unwrap();
        let service = |store: &ConsensusSessionStore| {
            ScopeBatchStore::new(
                Arc::new(store.clone()),
                scope.clone(),
                clock.clone(),
                Arc::new(Admission),
            )
            .unwrap()
        };
        authority
            .execute(
                &identity("controller"),
                &ScopeLeaseRequest::new(
                    scope.clone(),
                    [1; 16],
                    0,
                    ScopeLeaseOperation::Select {
                        execution: execution(1),
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let granted = authority
            .execute(
                &identity("worker-1"),
                &ScopeLeaseRequest::new(
                    scope.clone(),
                    [2; 16],
                    1,
                    ScopeLeaseOperation::Acquire {
                        execution: execution(1),
                        selection: 1,
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        service(&fleet.stores[lagging])
            .current(&identity("worker-1"))
            .await
            .unwrap();
        // Keep this a replication test: the disconnected follower must not
        // campaign while its append path is deliberately unavailable.
        fleet.stores[lagging]
            .inner
            .raft
            .runtime_config()
            .elect(false);
        let muted = fleet.peers[lagging].handler.write().await.take();
        let first = fleet.stores[leader].status().applied_index.unwrap() + 1;
        let batches = service(&fleet.stores[leader]);
        for n in 1..=80u8 {
            let request = ScopeBatchRequest::new(
                granted.permit().unwrap(),
                [n + 2; 16],
                u64::from(n - 1),
                vec![create(n, &[n])],
                vec![ScopeCounterMutation::new(0, u64::from(n - 1), u64::from(n)).unwrap()],
            )
            .unwrap();
            assert_eq!(
                batches
                    .execute(&identity("worker-1"), &request)
                    .await
                    .unwrap()
                    .revision(),
                u64::from(n)
            );
        }
        let last = fleet.stores[leader].status().applied_index.unwrap();
        assert_eq!(last, first + 79);
        assert!(fleet.stores[lagging].status().applied_index.unwrap() < last);
        // Exercise the exact 64-entry range used by follower replication,
        // before healing, so a budget regression fails at its actual cause.
        let wal = fleet.stores[leader]
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .clone();
        let page = tokio::task::spawn_blocking(move || {
            wal.native_log_read(first, Some(first + 64), Some(64))
        })
        .await
        .unwrap()
        .expect("64 small batch log entries must fit the unchanged verification budget");
        assert_eq!(page.len(), 64);
        assert_eq!(page.last().unwrap().log_id.index, first + 63);
        drop(page);
        *fleet.peers[lagging].handler.write().await = muted;
        tokio::time::timeout(Duration::from_secs(30), async {
            while fleet.stores[lagging]
                .status()
                .applied_index
                .is_none_or(|applied| applied < last)
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the isolated follower must apply the entire retained batch prefix");
        fleet.stores[lagging]
            .inner
            .raft
            .runtime_config()
            .elect(true);
        for store in &fleet.stores {
            let batches = service(store);
            let view = batches.current(&identity("worker-1")).await.unwrap();
            assert_eq!(view.revision(), 80);
            assert_eq!(view.counters()[0], 80);
            for n in 1..=80 {
                let row = batches
                    .read(&identity("worker-1"), key(n))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(row.value(), Some(&value(n)));
                assert_eq!(row.revision().birth(), u64::from(n));
                assert_eq!(row.revision().generation(), 1);
                assert_eq!(row.claims(), &[claim(n)]);
            }
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_batch_requires_every_voter_then_commits_one_command_and_recovers_exact_rows() {
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_native("scope_batch_full");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let minority = (leader + 1) % 3;
        let scope = ScopeLeaseId::new(
            fleet.topologies[0].consensus_identity().unwrap(),
            TenantId::from_static("scope-batch-full"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let lease_service = |store: &ConsensusSessionStore| {
            ScopeLeaseStore::new(
                Arc::new(store.clone()),
                scope.clone(),
                clock.clone(),
                Arc::new(Admission),
            )
            .unwrap()
        };
        let batch_service = |store: &ConsensusSessionStore| {
            ScopeBatchStore::new(
                Arc::new(store.clone()),
                scope.clone(),
                clock.clone(),
                Arc::new(Admission),
            )
            .unwrap()
        };
        let request = |id, revision, operation| {
            ScopeLeaseRequest::new(scope.clone(), [id; 16], revision, operation).unwrap()
        };
        let selected = request(
            1,
            0,
            ScopeLeaseOperation::Select {
                execution: execution(1),
            },
        );
        let acquire = request(
            2,
            1,
            ScopeLeaseOperation::Acquire {
                execution: execution(1),
                selection: 1,
            },
        );
        let authority = lease_service(&fleet.stores[leader]);
        let service = batch_service(&fleet.stores[leader]);
        fleet.stores[minority]
            .inner
            .scope_profile_supported
            .store(false, Ordering::Release);
        let before = fleet.stores[leader].status().applied_index;
        assert_eq!(
            authority.execute(&identity("controller"), &selected).await,
            Err(ScopeLeaseError::ProfileNotActivated),
            "a supporting majority cannot activate without the remaining voter"
        );
        let model = ScopeState::empty(scope.clone())
            .transition(&selected, bounds(0))
            .unwrap()
            .transition(&acquire, bounds(0))
            .unwrap();
        let uncommitted = ScopeBatchRequest::new(
            model.view.permit().unwrap(),
            [3; 16],
            0,
            vec![create(1, &[1])],
            vec![],
        )
        .unwrap();
        assert_eq!(
            service.execute(&identity("worker-1"), &uncommitted).await,
            Err(ScopeBatchError::Scope(ScopeLeaseError::ProfileNotActivated))
        );
        assert_eq!(
            fleet.stores[leader].status().applied_index,
            before,
            "refused activation proposes no scope command"
        );
        fleet.stores[minority]
            .inner
            .scope_profile_supported
            .store(true, Ordering::Release);
        authority
            .execute(&identity("controller"), &selected)
            .await
            .unwrap();
        let granted = authority
            .execute(&identity("worker-1"), &acquire)
            .await
            .unwrap();
        let permit = granted.permit().unwrap();

        let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(value(1).envelope()).unwrap();
        let overhead = envelope.encode().unwrap().len() - envelope.ciphertext_and_tag.len();
        envelope
            .ciphertext_and_tag
            .resize(MAX_SCOPE_CHILD_VALUE_BYTES - overhead, 1);
        let maximum = ScopeSealedValue::new(envelope.encode().unwrap()).unwrap();
        let mut mutations: Vec<_> = (1..=64).map(|n| create(n, &[])).collect();
        mutations[0] = ScopeChildMutation::Create {
            key: key(1),
            value: maximum.clone(),
            claims: (1..=8).map(claim).collect(),
        };
        let full = ScopeBatchRequest::new(
            permit,
            [4; 16],
            0,
            mutations,
            vec![ScopeCounterMutation::new(0, 0, 64).unwrap()],
        )
        .unwrap();
        assert!(serde_json::to_vec(&full).unwrap().len() < MAX_SCOPE_BATCH_COMMAND_BYTES);
        assert_eq!(
            service.execute(&identity("intruder"), &full).await,
            Err(ScopeBatchError::Scope(ScopeLeaseError::Unauthorized))
        );
        // The durable unanimous certificate now permits ordinary quorum use.
        let muted = fleet.peers[minority].handler.write().await.take();
        let before = fleet.stores[leader].status().applied_index.unwrap();
        let outcome = service.execute(&identity("worker-1"), &full).await.unwrap();
        assert_eq!(
            fleet.stores[leader].status().applied_index,
            Some(before + 1),
            "64 children, claims and counters are one application command"
        );
        *fleet.peers[minority].handler.write().await = muted;
        assert_eq!(outcome.rows().len(), 64);
        assert_eq!(outcome.counters()[0], 64);
        assert_eq!(
            service
                .read(&identity("worker-1"), key(1))
                .await
                .unwrap()
                .unwrap()
                .value(),
            Some(&maximum)
        );

        let replacement = ScopeBatchRequest::new(
            permit,
            [5; 16],
            1,
            vec![
                ScopeChildMutation::CompareAndSet {
                    key: key(1),
                    expected: outcome.rows()[0],
                    value: value(9),
                    claims: (1..=8).map(claim).collect(),
                },
                ScopeChildMutation::CompareAndSet {
                    key: key(2),
                    expected: outcome.rows()[1],
                    value: maximum.clone(),
                    claims: vec![],
                },
            ],
            vec![],
        )
        .unwrap();
        let before = fleet.stores[leader].status().applied_index.unwrap();
        fleet.stores[leader].inject_accepted_client_write_receiver_outcome(
            crate::consensus::store::AcceptedClientWriteReceiverTestOutcome::ForwardToLeader,
        );
        let ambiguous = service.execute(&identity("worker-1"), &replacement).await;
        assert!(ambiguous.is_ok() || ambiguous == Err(ScopeBatchError::OutcomeUnknown));
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if service
                    .current(&identity("worker-1"))
                    .await
                    .is_ok_and(|view| view.revision() == 2)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let replaced = service
            .execute(&identity("worker-1"), &replacement)
            .await
            .unwrap();
        assert_eq!(replaced.rows()[0].birth(), outcome.rows()[0].birth());
        assert_eq!(replaced.rows()[0].generation(), 2);
        assert_eq!(
            fleet.stores[leader].status().applied_index,
            Some(before + 1),
            "lost-reply resolution does not append another command"
        );
        for store in &fleet.stores {
            assert_eq!(
                batch_service(store)
                    .current(&identity("worker-1"))
                    .await
                    .unwrap()
                    .revision(),
                2
            );
            compact(store).await;
        }
        drop(authority);
        drop(service);
        fleet.close().await;
        fleet.open().await;
        for store in &fleet.stores {
            let service = batch_service(store);
            assert_eq!(
                service
                    .current(&identity("worker-1"))
                    .await
                    .unwrap()
                    .counters()[0],
                64
            );
            assert_eq!(
                service
                    .execute(&identity("worker-1"), &replacement)
                    .await
                    .unwrap(),
                replaced
            );
            let row = service
                .read(&identity("worker-1"), key(1))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.revision(), replaced.rows()[0]);
            assert_eq!(row.value(), Some(&value(9)));
            assert_eq!(row.claims().len(), 8);
            assert!(service
                .read(&identity("worker-1"), key(64))
                .await
                .unwrap()
                .is_some());
            assert_eq!(
                service
                    .read(&identity("worker-1"), key(2))
                    .await
                    .unwrap()
                    .unwrap()
                    .value(),
                Some(&maximum)
            );
            assert_eq!(
                store
                    .inner
                    .private_wal
                    .as_ref()
                    .unwrap()
                    .native_sql_fallback_count()
                    .unwrap(),
                0
            );
        }
        let service = batch_service(&fleet.stores[0]);
        let delete = ScopeBatchRequest::new(
            permit,
            [6; 16],
            2,
            vec![ScopeChildMutation::Delete {
                key: key(1),
                expected: replaced.rows()[0],
            }],
            vec![ScopeCounterMutation::new(0, 64, 63).unwrap()],
        )
        .unwrap();
        service
            .execute(&identity("worker-1"), &delete)
            .await
            .unwrap();
        assert!(service
            .read(&identity("worker-1"), key(1))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            service.execute(&identity("worker-1"), &full).await,
            Err(ScopeBatchError::RevisionConflict)
        );
        let recreate = ScopeBatchRequest::new(
            permit,
            [7; 16],
            3,
            vec![create(1, &[1])],
            vec![ScopeCounterMutation::new(0, 63, 64).unwrap()],
        )
        .unwrap();
        let recreated = service
            .execute(&identity("worker-1"), &recreate)
            .await
            .unwrap();
        assert_eq!(recreated.rows()[0].birth(), 65);
        let stale = ScopeBatchRequest::new(
            permit,
            [8; 16],
            4,
            vec![ScopeChildMutation::Delete {
                key: key(1),
                expected: replaced.rows()[0],
            }],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            service.execute(&identity("worker-1"), &stale).await,
            Err(ScopeBatchError::Conflict(_))
        ));
        assert_eq!(
            service
                .read(&identity("worker-1"), key(1))
                .await
                .unwrap()
                .unwrap()
                .revision(),
            recreated.rows()[0]
        );
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
