use super::scope_authority::{Admission, Clock};
use super::*;
use crate::scope_authority::tests::{execution, identity};
use crate::scope_authority::*;
use crate::scope_batch::tests::{claim, create, key, value};
use crate::scope_batch::*;
use std::sync::atomic::AtomicU64;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_child_read_current_is_complete_ordered_read_only_and_authority_bound() {
    for native in [false, true] {
        let snapshots =
            tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
        let mut fleet = Fleet::new_with_mode("scope_child_read", native);
        fleet.snapshot_root = Some(snapshots.path().to_path_buf());
        fleet.clock = Some(Arc::new(Clock(AtomicU64::new(0))));
        fleet.open().await;
        let result = AssertUnwindSafe(async {
            let scope = ScopeId::new(
                fleet.topologies[0].consensus_identity().unwrap(),
                TenantId::from_static("child-read"),
                NetworkFunctionKind::smf(),
                [1; 32],
            )
            .unwrap();
            let leader = fleet
                .stores
                .iter()
                .position(|store| store.status().leader_id == Some(store.status().node_id))
                .unwrap();
            let authority = ScopeAuthorityStore::new(
                Arc::new(fleet.stores[leader].clone()),
                scope.clone(),
                Arc::new(Admission),
            )
            .unwrap();
            let granted = authority
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
            let service = |index: usize| {
                ScopeBatchStore::new(
                    Arc::new(fleet.stores[index].clone()),
                    granted.stamp().namespace().clone(),
                    Arc::new(Admission),
                )
                .unwrap()
            };
            let writer = service(leader);
            let created = writer
                .execute(
                    &identity("worker-1"),
                    &ScopeBatchRequest::in_lane(
                        granted.stamp(),
                        [2; 16],
                        0,
                        1,
                        (1..=32).map(|n| create(n, &[n])).collect(),
                        vec![],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let removed = writer
                .execute(
                    &identity("worker-1"),
                    &ScopeBatchRequest::in_lane(
                        granted.stamp(),
                        [3; 16],
                        0,
                        2,
                        vec![ScopeChildMutation::Delete {
                            key: key(2),
                            expected: created.rows()[1],
                        }],
                        vec![],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let before = writer.reopen(&identity("worker-1")).await.unwrap();
            let applied = fleet.stores[leader].status().applied_index;
            for index in 0..3 {
                let reader = service(index);
                let rows = reader
                    .read_current(
                        &identity("worker-1"),
                        granted.stamp(),
                        &[key(32), key(2), key(99), key(1)],
                    )
                    .await
                    .unwrap();
                assert_eq!(rows.len(), 4);
                assert!(rows[1].is_none(), "tombstone is absent");
                assert!(rows[2].is_none(), "missing key is absent");
                for (entry, child, position) in [(0, 32, 31), (3, 1, 0)] {
                    let row = rows[entry].as_ref().unwrap();
                    assert_eq!(row.namespace(), granted.stamp().namespace());
                    assert_eq!(row.key(), key(child));
                    assert_eq!(row.revision(), created.rows()[position]);
                    assert_eq!(row.batch_revision(), created.revision());
                    assert_eq!(row.claims(), &[claim(child)]);
                    assert_eq!(row.value(), Some(&value(child)));
                }
                assert!(matches!(
                    reader
                        .read_current(&identity("controller"), granted.stamp(), &[key(1)])
                        .await,
                    Err(ScopeChildReadError::Batch(ScopeBatchError::Scope(
                        ScopeAuthorityError::Unauthorized
                    )))
                ));
            }
            assert_eq!(
                fleet.stores[leader].status().applied_index,
                applied,
                "reads append no application command"
            );
            assert_eq!(
                writer.reopen(&identity("worker-1")).await.unwrap(),
                before,
                "reads consume no lane, sequence, receipt or counter"
            );
            let recreated = writer
                .execute(
                    &identity("worker-1"),
                    &ScopeBatchRequest::in_lane(
                        granted.stamp(),
                        [4; 16],
                        0,
                        3,
                        vec![create(2, &[2])],
                        vec![],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(created.rows()[1].birth(), recreated.rows()[0].birth());
            assert!(removed.revision() < recreated.revision());
            let row = writer
                .read_current(&identity("worker-1"), granted.stamp(), &[key(2)])
                .await
                .unwrap()
                .remove(0)
                .unwrap();
            assert_eq!(row.revision(), recreated.rows()[0]);
            assert_eq!(row.batch_revision(), recreated.revision());
            authority
                .execute(
                    &identity("worker-1"),
                    &ScopeAuthorityRequest::new(
                        granted.stamp().scope().clone(),
                        [5; 16],
                        granted.stamp().revision(),
                        ScopeAuthorityOperation::Close {
                            current: granted.stamp().clone(),
                            evidence: ScopeClosureEvidence::new(
                                ScopeClosureKind::LocalQuiescence,
                                [5; 32],
                            )
                            .unwrap(),
                        },
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert!(matches!(
                writer
                    .read_current(&identity("worker-1"), granted.stamp(), &[key(1)])
                    .await,
                Err(ScopeChildReadError::Batch(ScopeBatchError::Scope(
                    ScopeAuthorityError::StaleAuthority
                )))
            ));
        })
        .catch_unwind()
        .await;
        fleet.close().await;
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}
