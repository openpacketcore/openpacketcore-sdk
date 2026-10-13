use super::scope_authority::{Admission, Clock};
use super::*;
use crate::scope_authority::tests::{execution, identity};
use crate::scope_authority::*;
use crate::scope_batch::tests::{claim, create, key, value};
use crate::scope_batch::*;
use crate::sqlite::consensus::scope_payload_decode_observer;
use std::sync::atomic::AtomicU64;

async fn child_read_authority_fixture(fleet: &Fleet) -> (usize, CommittedScopeAuthority) {
    let leader = fleet
        .stores
        .iter()
        .position(|store| store.status().leader_id == Some(store.status().node_id))
        .unwrap();
    let scope = ScopeId::new(
        fleet.topologies[0].consensus_identity().unwrap(),
        TenantId::from_static("child-read-refusal"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
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
    (leader, granted)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_child_read_three_large_children_refuse_the_whole_observation() {
    let mut failure = None;
    for native in [false, true] {
        let snapshots =
            tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
        let mut fleet = Fleet::new_with_mode("scope_child_read_aggregate_bound", native);
        fleet.snapshot_root = Some(snapshots.path().to_path_buf());
        fleet.clock = Some(Arc::new(Clock(AtomicU64::new(0))));
        fleet.open().await;
        let result = AssertUnwindSafe(async {
            let (leader, granted) = child_read_authority_fixture(&fleet).await;
            let store = &fleet.stores[leader];
            let reader = ScopeBatchStore::new(
                Arc::new(store.clone()),
                granted.stamp().namespace().clone(),
                Arc::new(Admission),
            )
            .unwrap();
            let encoded = value(1).envelope().to_vec();
            let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(&encoded).unwrap();
            let overhead = encoded.len() - envelope.ciphertext_and_tag.len();
            envelope
                .ciphertext_and_tag
                .resize(MAX_SCOPE_CHILD_VALUE_BYTES - 4096 - overhead, 1);
            let large = ScopeSealedValue::new(envelope.encode().unwrap()).unwrap();
            let observer =
                scope_payload_decode_observer::Scope::new(granted.stamp().scope().clone(), 100_000);
            for tag in 1..=3 {
                let before = observer.counts();
                let started = Instant::now();
                let result = reader
                    .execute(
                        &identity("worker-1"),
                        &ScopeBatchRequest::in_lane(
                            granted.stamp(),
                            [tag + 1; 16],
                            0,
                            u64::from(tag),
                            vec![ScopeChildMutation::Create {
                                key: key(tag),
                                value: large.clone(),
                                claims: vec![],
                            }],
                            vec![],
                        )
                        .unwrap(),
                    )
                    .await;
                let elapsed = started.elapsed();
                scope_payload_decode_observer::report(serde_json::json!({
                    "case": "large-observation-setup", "tag": tag, "native": native,
                    "success": result.is_ok(), "elapsed_us": elapsed.as_micros(),
                    "counts": observer.counts().since(&before),
                }));
                result.unwrap_or_else(|error| {
                    panic!("large child {tag} setup (native={native}): {error}")
                });
            }
            let pair = reader
                .read_current(&identity("worker-1"), granted.stamp(), &[key(1), key(2)])
                .await
                .unwrap();
            assert_eq!(
                pair.len(),
                2,
                "two individually valid near-1-MiB children fit"
            );
            assert!(pair
                .iter()
                .all(|row| row.as_ref().unwrap().value() == Some(&large)));
            let applied = store.status().applied_index;
            let barriers = store.scope_read_barrier_count_for_test();
            assert_eq!(
                reader
                    .read_current(
                        &identity("worker-1"),
                        granted.stamp(),
                        &[key(1), key(2), key(3)]
                    )
                    .await,
                Err(ScopeChildReadError::ObservationTooLarge)
            );
            assert_eq!(store.scope_read_barrier_count_for_test(), barriers + 1);
            assert_eq!(
                store.status().applied_index,
                applied,
                "refusal appends no command"
            );
        })
        .catch_unwind()
        .await;
        fleet.close().await;
        if let Err(panic) = result {
            failure.get_or_insert(panic);
        }
    }
    if let Some(panic) = failure {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_child_read_retired_incarnation_has_the_exact_store_error() {
    // This fixture needs a stored retirement, which has no proposal operation.
    // Use the ordinary SQLite store: editing the private WAL's verified SQL
    // projection would correctly trip its corruption guard before the read.
    let directory = tempfile::tempdir().unwrap();
    let topology = super::super::membership_tests::singleton_topology();
    let scope = ScopeId::new(
        topology.consensus_identity().unwrap(),
        TenantId::from_static("child-read-retired"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let store = ConsensusSessionStore::open_with_clock(
        topology,
        SqliteSessionBackend::open(directory.path().join("store.sqlite")).unwrap(),
        directory.path().join("snapshots"),
        BTreeMap::new(),
        Arc::new(Clock(AtomicU64::new(0))),
        super::super::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    let result = AssertUnwindSafe(async {
        assert!(store.inner.private_wal.is_none());
        let authority =
            ScopeAuthorityStore::new(Arc::new(store.clone()), scope.clone(), Arc::new(Admission))
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
        let reader = ScopeBatchStore::new(
            Arc::new(store.clone()),
            granted.stamp().namespace().clone(),
            Arc::new(Admission),
        )
        .unwrap();
        assert_eq!(
            reader
                .read_current(&identity("worker-1"), granted.stamp(), &[key(1)])
                .await
                .unwrap(),
            vec![None]
        );

        // Seed a validated, monotonic retirement in the real backend, then exercise
        // the public read, its barrier, capture, header decode and error mapping.
        let physical = granted.stamp().scope().key().unwrap();
        let conn = store.inner.backend.lock_connection_for_test().await;
        let mut record = crate::sqlite::ops::get_raw_sync(&conn, &physical)
            .unwrap()
            .unwrap();
        let previous = ScopeAuthorityCheckpoint::from_record(&record).unwrap();
        let retired =
            crate::scope_authority::tests::retired_store_fixture(&previous.state().unwrap(), 2);
        let body = retired.encode().unwrap();
        let mut bytes = (body.len() as u16).to_le_bytes().to_vec();
        bytes.extend_from_slice(&body);
        bytes.resize(MAX_SCOPE_AUTHORITY_RECORD_BYTES, 0);
        record.generation = crate::Generation::new(retired.view.revision());
        record.payload = crate::EncryptedSessionPayload::new(bytes);
        let checkpoint = ScopeAuthorityCheckpoint::from_record(&record).unwrap();
        assert!(
            checkpoint.can_replace(&previous),
            "the fixture advances durable retirement floors"
        );
        crate::sqlite::ops::insert_or_replace_scope_record_sync(&conn, &record).unwrap();
        drop(conn);
        let barriers = store.scope_read_barrier_count_for_test();
        assert_eq!(
            reader
                .read_current(&identity("worker-1"), granted.stamp(), &[key(1)])
                .await,
            Err(ScopeChildReadError::Batch(ScopeBatchError::Scope(
                ScopeAuthorityError::Retired
            )))
        );
        assert_eq!(store.scope_read_barrier_count_for_test(), barriers + 1);
    })
    .catch_unwind()
    .await;
    let shutdown = store.shutdown().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    shutdown.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_child_read_current_uses_one_cut_before_and_after_concurrent_commits() {
    run_cut_cases(&[
        ScopeChildReadStage::BeforeCapture,
        ScopeChildReadStage::AfterCapture,
        ScopeChildReadStage::BetweenKeys,
    ])
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_child_read_current_keeps_its_original_cut_between_keys() {
    run_cut_cases(&[ScopeChildReadStage::BetweenKeys]).await;
}

async fn run_cut_cases(stages: &[ScopeChildReadStage]) {
    let mut failure = None;
    for native in [false, true] {
        let snapshots =
            tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
        let mut fleet = Fleet::new_with_mode("scope_child_read_cut", native);
        fleet.snapshot_root = Some(snapshots.path().to_path_buf());
        fleet.clock = Some(Arc::new(Clock(AtomicU64::new(0))));
        fleet.open().await;
        let result = AssertUnwindSafe(async {
            let leader = fleet
                .stores
                .iter()
                .position(|store| store.status().leader_id == Some(store.status().node_id))
                .unwrap();
            let store = &fleet.stores[leader];
            for (case, stage) in stages.iter().copied().enumerate() {
                let scope = ScopeId::new(
                    fleet.topologies[0].consensus_identity().unwrap(),
                    TenantId::from_static("child-cut"),
                    NetworkFunctionKind::smf(),
                    [case as u8 + 1; 32],
                )
                .unwrap();
                let authority = ScopeAuthorityStore::new(
                    Arc::new(store.clone()),
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
                let writer = ScopeBatchStore::new(
                    Arc::new(store.clone()),
                    granted.stamp().namespace().clone(),
                    Arc::new(Admission),
                )
                .unwrap();
                let created = writer
                    .execute(
                        &identity("worker-1"),
                        &ScopeBatchRequest::in_lane(
                            granted.stamp(),
                            [2; 16],
                            0,
                            1,
                            vec![create(1, &[1]), create(2, &[2])],
                            vec![],
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let barriers = store.scope_read_barrier_count_for_test();
                let pause = store.pause_next_scope_child_read_for_test(stage);
                let reader = writer.clone();
                let stamp = granted.stamp().clone();
                let read = tokio::spawn(async move {
                    reader
                        .read_current(&identity("worker-1"), &stamp, &[key(1), key(2)])
                        .await
                });
                tokio::time::timeout(Duration::from_secs(10), pause.reached())
                    .await
                    .unwrap();
                assert_eq!(store.scope_read_barrier_count_for_test(), barriers + 1);

                // Both replacements commit atomically while the reader is at
                // the named boundary. A per-key cut would mix generations.
                if stage != ScopeChildReadStage::BeforeCapture {
                    writer
                        .execute(
                            &identity("worker-1"),
                            &ScopeBatchRequest::in_lane(
                                granted.stamp(),
                                [3; 16],
                                0,
                                2,
                                (1..=2)
                                    .map(|n| ScopeChildMutation::CompareAndSet {
                                        key: key(n),
                                        expected: created.rows()[usize::from(n - 1)],
                                        value: value(n + 10),
                                        claims: vec![claim(n + 10)],
                                    })
                                    .collect(),
                                vec![],
                            )
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                }
                // Close before capture must fail. Close after capture cannot
                // change that cut's authority or force a later child snapshot.
                if stage != ScopeChildReadStage::BetweenKeys {
                    authority
                        .execute(
                            &identity("worker-1"),
                            &ScopeAuthorityRequest::new(
                                granted.stamp().scope().clone(),
                                [4; 16],
                                granted.stamp().revision(),
                                ScopeAuthorityOperation::Close {
                                    current: granted.stamp().clone(),
                                    evidence: ScopeClosureEvidence::new(
                                        ScopeClosureKind::LocalQuiescence,
                                        [4; 32],
                                    )
                                    .unwrap(),
                                },
                            )
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                }
                pause.release();
                let observation = read.await.unwrap();
                if stage == ScopeChildReadStage::BeforeCapture {
                    assert!(matches!(
                        observation,
                        Err(ScopeChildReadError::Batch(ScopeBatchError::Scope(
                            ScopeAuthorityError::StaleAuthority
                        )))
                    ));
                } else {
                    let rows = observation.unwrap();
                    assert_eq!(rows.len(), 2);
                    for (n, row) in (1..=2).zip(rows) {
                        let row = row.unwrap();
                        assert_eq!(row.key(), key(n));
                        assert_eq!(row.revision(), created.rows()[usize::from(n - 1)]);
                        assert_eq!(row.batch_revision(), created.revision());
                        assert_eq!(row.value(), Some(&value(n)));
                        assert_eq!(row.claims(), &[claim(n)]);
                    }
                }
            }
        })
        .catch_unwind()
        .await;
        fleet.close().await;
        // Exercise and drain both adapters even when the first one rejects a
        // deliberately mutated implementation. Every original assertion stays
        // fatal after both backend runs have reported their evidence.
        if let Err(panic) = result {
            failure.get_or_insert(panic);
        }
    }
    if let Some(panic) = failure {
        std::panic::resume_unwind(panic);
    }
}

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
                let barriers = fleet.stores[index].scope_read_barrier_count_for_test();
                let rows = reader
                    .read_current(
                        &identity("worker-1"),
                        granted.stamp(),
                        &[key(32), key(2), key(99), key(1)],
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    fleet.stores[index].scope_read_barrier_count_for_test(),
                    barriers + 1,
                    "all keys and authority use exactly one complete barrier"
                );
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
                for keys in [vec![], vec![key(1), key(1)], (1..=33).map(key).collect()] {
                    assert!(matches!(
                        reader
                            .read_current(&identity("worker-1"), granted.stamp(), &keys)
                            .await,
                        Err(ScopeChildReadError::Batch(ScopeBatchError::InvalidRequest))
                    ));
                }
                assert_eq!(
                    fleet.stores[index].scope_read_barrier_count_for_test(),
                    barriers + 1,
                    "invalid or unauthorized requests enter no barrier"
                );
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
