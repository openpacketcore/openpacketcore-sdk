//! Live native persistence, compaction and cold reopen with thousands of renewals.

use super::*;
use crate::scope_lease::tests::{at, bounds, execution, identity};
use crate::scope_lease::*;
use std::sync::atomic::AtomicU64;

#[derive(Debug)]
struct Clock(AtomicU64);
impl crate::Clock for Clock {
    fn now_utc(&self) -> opc_types::Timestamp {
        at(self.0.load(Ordering::SeqCst) as i64)
    }
}
impl ScopeLeaseClock for Clock {
    fn bounds(&self) -> Result<ScopeClockBounds, ScopeLeaseError> {
        Ok(bounds(self.0.load(Ordering::SeqCst) as i64))
    }
}
struct Admission;
#[async_trait]
impl ScopeLeaseAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &crate::SessionConsumerIdentity,
        _: &ScopeLeaseId,
        claim: Option<&ScopeExecution>,
        action: ScopeLeaseAction,
    ) -> Result<(), ScopeLeaseError> {
        let permitted = match action {
            ScopeLeaseAction::Select => authenticated == &identity("controller"),
            _ => authenticated == &identity("worker-1"),
        } && claim.is_none_or(|claim| claim == &execution(1));
        permitted.then_some(()).ok_or(ScopeLeaseError::Unauthorized)
    }
}

async fn compact(store: &ConsensusSessionStore) -> u64 {
    use crate::consensus::test_support::{
        consensus_local_durable_progress_for_test, trigger_consensus_log_purge_through_for_test,
        trigger_consensus_snapshot_for_test,
    };
    let applied = store.status().applied_index.unwrap();
    trigger_consensus_snapshot_for_test(store).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while consensus_local_durable_progress_for_test(store)
            .snapshot_index
            .is_none_or(|cut| cut < applied)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    trigger_consensus_log_purge_through_for_test(store, applied)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while consensus_local_durable_progress_for_test(store)
            .purged_index
            .is_none_or(|cut| cut < applied)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    store
        .inner
        .private_wal
        .as_ref()
        .unwrap()
        .with_native_read(|state| Ok(state.current_snapshot().unwrap().3))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_lease_construction_ignores_owner_contention_but_reads_retain_admission() {
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_native("scope_lease_construction");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let configured = fleet.topologies[0].consensus_identity().unwrap();
        let scope = ScopeLeaseId::new(
            configured,
            TenantId::from_static("scope-construction"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let other_cluster = ScopeLeaseId::new(
            SessionConsensusIdentity::new(
                ConsensusClusterId::new("another-scope-cluster").unwrap(),
                configured.configuration_id(),
                configured.configuration_epoch(),
            ),
            TenantId::from_static("scope-construction"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        for store in &fleet.stores {
            let wal = store.inner.private_wal.as_ref().unwrap();
            let (discovery, constructed, wrong_cluster) = wal
                .with_native_owner_held_for_test(|| {
                    // Ordinary apply and snapshot publication own this same
                    // mutex. No membership change or follower lag is needed
                    // to make synchronous authority discovery unavailable.
                    (
                        store.consumer_scope(),
                        ScopeLeaseStore::new(
                            Arc::new(store.clone()),
                            scope.clone(),
                            clock.clone(),
                            Arc::new(Admission),
                        ),
                        ScopeLeaseStore::new(
                            Arc::new(store.clone()),
                            other_cluster.clone(),
                            clock.clone(),
                            Arc::new(Admission),
                        ),
                    )
                })
                .unwrap();
            assert!(discovery.is_err(), "the real authority reader is busy");
            let authority = constructed
                .expect("constructing a scope handle must not require an idle authority reader");
            assert!(matches!(wrong_cluster, Err(ScopeLeaseError::Unauthorized)));

            let caller = identity("worker-1");
            let view = authority.current(&caller).await.unwrap();
            assert_eq!(view.revision(), 0);
            assert!(view.permit().is_none());

            // A constructed handle is not traffic authority. Revocation must
            // still prevent both reads and minting a committed permit.
            store.inner.admitted.store(false, Ordering::Release);
            let refused_read = authority.current(&caller).await;
            let refused_grant = authority
                .grant(
                    &caller,
                    &ScopeLeaseRequest::new(
                        scope.clone(),
                        [1; 16],
                        0,
                        ScopeLeaseOperation::Acquire {
                            execution: execution(1),
                            selection: 1,
                        },
                    )
                    .unwrap(),
                )
                .await;
            store.inner.admitted.store(true, Ordering::Release);
            assert_eq!(refused_read, Err(ScopeLeaseError::Unavailable));
            assert!(matches!(refused_grant, Err(ScopeLeaseError::Unavailable)));
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_lease_four_thousand_renewals_keep_native_checkpoint_and_snapshots_bounded() {
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_native("scope_lease_bound");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    // Whole-second logical times make the outer response metadata exactly
    // comparable too; SystemClock's fractional digit count can vary by a byte.
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let scope = ScopeLeaseId::new(
            fleet.stores[0]
                .consumer_scope()
                .unwrap()
                .consensus_identity(),
            TenantId::from_static("scope-bound"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let service = |store: &ConsensusSessionStore| {
            ScopeLeaseStore::new(
                Arc::new(store.clone()),
                scope.clone(),
                clock.clone(),
                Arc::new(Admission),
            )
            .unwrap()
        };
        let authority = service(&fleet.stores[0]);
        let request = |revision, id: u64, operation| {
            ScopeLeaseRequest::new(
                scope.clone(),
                u128::from(id).to_le_bytes(),
                revision,
                operation,
            )
            .unwrap()
        };
        authority
            .execute(
                &identity("controller"),
                &request(
                    0,
                    1,
                    ScopeLeaseOperation::Select {
                        execution: execution(1),
                    },
                ),
            )
            .await
            .unwrap();
        let mut view = authority
            .execute(
                &identity("worker-1"),
                &request(
                    1,
                    2,
                    ScopeLeaseOperation::Acquire {
                        execution: execution(1),
                        selection: 1,
                    },
                ),
            )
            .await
            .unwrap();
        let mut first = None;
        for n in 1..=4096 {
            clock.0.store(n, Ordering::SeqCst);
            view = authority
                .execute(
                    &identity("worker-1"),
                    &request(
                        view.revision(),
                        n + 2,
                        ScopeLeaseOperation::Renew {
                            permit: view.permit().unwrap().clone(),
                        },
                    ),
                )
                .await
                .unwrap();
            if n == 1024 || n == 4096 {
                let mut footprint = Vec::new();
                let mut sizes = Vec::new();
                for store in &fleet.stores {
                    assert_eq!(
                        service(store).current(&identity("worker-1")).await.unwrap(),
                        view
                    );
                    let wal = store.inner.private_wal.as_ref().unwrap();
                    let counts = wal
                        .with_native_read(|state| Ok(state.scope_checkpoint_footprint_for_test()))
                        .unwrap();
                    assert_eq!(
                        (counts.0, counts.2, counts.3),
                        (1, 0, 0),
                        "one checkpoint, no session rows or watches"
                    );
                    assert!(
                        counts.1 < 9216,
                        "fixed encoded checkpoint plus bounded response metadata"
                    );
                    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
                    footprint.push(counts.1);
                    sizes.push(compact(store).await);
                }
                if let Some((old_rows, old_sizes)) = &first {
                    assert_eq!(
                        &footprint, old_rows,
                        "renewals retain exactly the same serialized row bytes"
                    );
                    for (new, old) in sizes.iter().zip(old_sizes) {
                        assert!(
                            new <= &(old + 512),
                            "compacted snapshots must not grow with renewal history"
                        );
                    }
                } else {
                    first = Some((footprint, sizes));
                }
            }
        }
        drop(authority);
        let expected = view;
        fleet.close().await;
        fleet.open().await;
        for store in &fleet.stores {
            assert_eq!(
                service(store).current(&identity("worker-1")).await.unwrap(),
                expected
            );
            let wal = store.inner.private_wal.as_ref().unwrap();
            assert_eq!(
                wal.with_native_read(|state| Ok(state.scope_checkpoint_footprint_for_test().0))
                    .unwrap(),
                1
            );
            assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
