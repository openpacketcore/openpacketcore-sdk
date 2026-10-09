//! Live native persistence, compaction and cold reopen with thousands of successions.

use super::*;
use crate::scope_authority::tests::{at, execution, identity};
use crate::scope_authority::*;
use std::sync::atomic::AtomicU64;

#[derive(Debug)]
pub(super) struct Clock(pub(super) AtomicU64);
impl crate::Clock for Clock {
    fn now_utc(&self) -> opc_types::Timestamp {
        at(self.0.load(Ordering::SeqCst) as i64)
    }
}
pub(super) struct Admission;
#[async_trait]
impl ScopeAuthorityAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &crate::SessionConsumerIdentity,
        _: &ScopeId,
        claim: Option<&ScopeExecution>,
        _: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        if authenticated == &identity("controller") {
            return Ok(ScopeAuthorityRole::ScopeController);
        }
        if authenticated == &identity("worker-1")
            && claim.is_none_or(|value| {
                value == &execution(1) || value == &boot(value.admission_generation())
            })
        {
            Ok(ScopeAuthorityRole::Worker)
        } else {
            Err(ScopeAuthorityError::Unauthorized)
        }
    }
    async fn verify_closure(
        &self,
        _: &crate::SessionConsumerIdentity,
        _: &ScopeAuthorityStamp,
        _: &ScopeClosureEvidence,
        _: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        Ok(())
    }
}
fn boot(generation: u64) -> ScopeExecution {
    let process = u128::from(generation).to_le_bytes();
    let mut key = [0; 32];
    key[..16].copy_from_slice(&process);
    key[16..].copy_from_slice(&process);
    ScopeExecution::new(identity("worker-1"), generation, [1; 16], process, key).unwrap()
}

pub(super) async fn compact(store: &ConsensusSessionStore) -> u64 {
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
async fn scope_authority_construction_ignores_owner_contention_but_reads_retain_admission() {
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_native("scope_authority_construction");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let configured = fleet.topologies[0].consensus_identity().unwrap();
        let scope = ScopeId::new(
            configured,
            TenantId::from_static("scope-construction"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let other_cluster = ScopeId::new(
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
                    let configured_scope = ScopeId::new(
                        fleet.topologies[0].consensus_identity().unwrap(),
                        TenantId::from_static("scope-construction"),
                        NetworkFunctionKind::smf(),
                        [1; 32],
                    )
                    .unwrap();
                    assert_eq!(configured_scope, scope);
                    // Ordinary apply and snapshot publication own this same
                    // mutex. No membership change or follower lag is needed
                    // to make synchronous authority discovery unavailable.
                    (
                        store.consumer_scope(),
                        ScopeAuthorityStore::new(
                            Arc::new(store.clone()),
                            configured_scope,
                            Arc::new(Admission),
                        ),
                        ScopeAuthorityStore::new(
                            Arc::new(store.clone()),
                            other_cluster.clone(),
                            Arc::new(Admission),
                        ),
                    )
                })
                .unwrap();
            assert!(discovery.is_err(), "the real authority reader is busy");
            let authority = constructed
                .expect("constructing a scope handle must not require an idle authority reader");
            assert!(matches!(
                wrong_cluster,
                Err(ScopeAuthorityError::Unauthorized)
            ));

            let caller = identity("worker-1");
            let view = authority.current(&caller).await.unwrap();
            assert_eq!(view.revision(), 0);
            assert!(view.stamp().is_none());

            // A constructed handle is not traffic authority. Revocation must
            // still prevent both reads and minting a committed authority.
            store.inner.admitted.store(false, Ordering::Release);
            let refused_read = authority.current(&caller).await;
            let refused_grant = authority
                .admit(
                    &caller,
                    &ScopeAuthorityRequest::new(
                        scope.clone(),
                        [1; 16],
                        0,
                        ScopeAuthorityOperation::AdmitInitial {
                            execution: execution(1),
                        },
                    )
                    .unwrap(),
                )
                .await;
            store.inner.admitted.store(true, Ordering::Release);
            assert_eq!(refused_read, Err(ScopeAuthorityError::Unavailable));
            assert!(matches!(
                refused_grant,
                Err(ScopeAuthorityError::Unavailable)
            ));
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_authority_four_thousand_successions_keep_native_checkpoint_and_snapshots_bounded() {
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_native("scope_authority_bound");
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    // Whole-second logical times make the outer response metadata exactly
    // comparable too; SystemClock's fractional digit count can vary by a byte.
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let scope = ScopeId::new(
            fleet.topologies[0].consensus_identity().unwrap(),
            TenantId::from_static("scope-bound"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let service = |store: &ConsensusSessionStore| {
            ScopeAuthorityStore::new(Arc::new(store.clone()), scope.clone(), Arc::new(Admission))
                .unwrap()
        };
        let authority = service(&fleet.stores[0]);
        let request = |revision, id: u64, operation| {
            ScopeAuthorityRequest::new(
                scope.clone(),
                u128::from(id).to_le_bytes(),
                revision,
                operation,
            )
            .unwrap()
        };
        let mut view = authority
            .execute(
                &identity("worker-1"),
                &request(
                    0,
                    2,
                    ScopeAuthorityOperation::AdmitInitial {
                        execution: execution(1),
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
                        ScopeAuthorityOperation::SucceedClosed {
                            predecessor: view.stamp().unwrap().clone(),
                            execution: boot(n + 1),
                            evidence: ScopeClosureEvidence::new(
                                ScopeClosureKind::FinalTermination,
                                [1; 32],
                            )
                            .unwrap(),
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
                    assert_eq!(
                        counts.4, 1,
                        "only one cluster activation receipt, no succession history"
                    );
                    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
                    footprint.push(counts.1);
                    sizes.push(compact(store).await);
                }
                if let Some((old_rows, old_sizes)) = &first {
                    assert_eq!(
                        &footprint, old_rows,
                        "successions retain exactly the same serialized row bytes"
                    );
                    for (new, old) in sizes.iter().zip(old_sizes) {
                        assert!(
                            new <= &(old + 512),
                            "compacted snapshots must not grow with succession history"
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
