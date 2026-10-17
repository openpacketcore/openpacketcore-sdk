use super::*;
use opc_consensus::engine::{CommittedLeaderId, Membership};

fn node(id: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(id).expect("node ID")
}

fn members() -> BTreeSet<ConsensusNodeId> {
    [1, 2, 3].map(node).into_iter().collect()
}

fn first_chunk() -> RepairChunk {
    RepairChunk {
        vote: Vote::new_committed(7, node(1)),
        meta: SnapshotMeta {
            last_log_id: Some(LogId::new(CommittedLeaderId::new(7, node(1)), 9)),
            last_membership: StoredMembership::new(
                Some(LogId::new(CommittedLeaderId::new(1, node(1)), 0)),
                Membership::new(vec![members()], members()),
            ),
            snapshot_id: "verified-snapshot".to_owned(),
        },
        offset: 0,
        bytes: vec![0x53; CHUNK_BYTES],
        done: false,
    }
}

#[tokio::test]
async fn checkpoint_reuse_requires_exact_source_vote_and_complete_snapshot_metadata() {
    let directory = tempfile::tempdir().expect("snapshot directory");
    let first = first_chunk();
    let download = RepairDownload {
        source: node(1),
        vote: first.vote,
        meta: first.meta,
        snapshot: Box::new(
            crate::consensus::snapshot_file::ConfigSnapshotFile::create(
                directory.path().join("checkpoint.part"),
            )
            .await
            .expect("checkpoint file"),
        ),
        offset: CHUNK_BYTES as u64,
        chunk: None,
        done: false,
        rediscover: true,
    };
    assert!(same_repair_snapshot(&download, node(1), &first_chunk()));
    assert!(!same_repair_snapshot(&download, node(2), &first_chunk()));

    for vote in [
        Vote::new_committed(8, node(1)),
        Vote::new_committed(7, node(2)),
        Vote::new(7, node(1)),
    ] {
        let mut changed = first_chunk();
        changed.vote = vote;
        assert!(!same_repair_snapshot(&download, node(1), &changed));
    }
    let mut changed = first_chunk();
    changed.meta.snapshot_id = "replacement-snapshot".to_owned();
    assert!(!same_repair_snapshot(&download, node(1), &changed));
    changed = first_chunk();
    changed.meta.last_log_id = Some(LogId::new(CommittedLeaderId::new(7, node(1)), 10));
    assert!(!same_repair_snapshot(&download, node(1), &changed));
    changed = first_chunk();
    changed.meta.last_membership = StoredMembership::new(
        Some(LogId::new(CommittedLeaderId::new(2, node(1)), 1)),
        Membership::new(vec![members()], members()),
    );
    assert!(!same_repair_snapshot(&download, node(1), &changed));
    changed = first_chunk();
    let replaced_members = BTreeSet::from([node(1), node(2), node(4)]);
    changed.meta.last_membership = StoredMembership::new(
        *changed.meta.last_membership.log_id(),
        Membership::new(vec![replaced_members.clone()], replaced_members),
    );
    assert!(!same_repair_snapshot(&download, node(1), &changed));
}

#[test]
fn discovery_rejects_invalid_authority_membership_and_first_chunk_shape() {
    assert!(valid_first_repair_chunk(
        node(1),
        &first_chunk(),
        &members()
    ));
    assert!(!valid_first_repair_chunk(
        node(2),
        &first_chunk(),
        &members()
    ));

    let mut invalid = first_chunk();
    invalid.vote = Vote::new(7, node(1));
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.meta.last_log_id = None;
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.meta.last_membership = StoredMembership::new(
        *invalid.meta.last_membership.log_id(),
        Membership::new(
            vec![members(), BTreeSet::from([node(1), node(2)])],
            members(),
        ),
    );
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.offset = 1;
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.bytes.push(0x53);
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.bytes.clear();
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid.done = true;
    assert!(valid_first_repair_chunk(node(1), &invalid, &members()));
}

#[tokio::test]
async fn repair_source_waits_for_snapshot_progress_before_fetching() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let identity = opc_consensus::ConsensusIdentity::new(
            opc_consensus::ConsensusClusterId::new("repair-snapshot-progress").unwrap(),
            opc_consensus::ConsensusConfigurationId::from_bytes([0x73; 32]),
            opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node(1), BTreeSet::from([node(1)]))
                .expect("singleton topology");
        let backend = SqliteBackend::in_memory_for_test().await.expect("backend");
        let hooks = Arc::clone(&backend.consensus_snapshot_test_hooks);
        let store = ConsensusConfigStore::open_with_operation_timeout(
            topology,
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Duration::from_secs(3),
        )
        .await
        .expect("store");
        store.initialize_cluster().await.expect("singleton leader");
        let required = store.inner.raft.metrics().borrow().last_log_index;
        assert!(required.is_some());
        assert!(store.inner.raft.metrics().borrow().snapshot.is_none());

        hooks.pause_build.store(true, Ordering::Release);
        let reads_before = hooks.reads_started.load(Ordering::Acquire);
        let source = store.clone();
        let repair = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(3),
                source.repair_snapshot_chunk(None, Instant::now() + Duration::from_secs(3)),
            )
            .await
        });
        hooks.build_started.notified().await;
        // These real core messages flush metrics while the snapshot cut is
        // unchanged. Their watch updates must not cause GetSnapshot requests.
        for _ in 0..5 {
            store
                .inner
                .raft
                .with_raft_state(|_| ())
                .await
                .expect("live core");
        }
        let premature_reads = hooks.reads_started.load(Ordering::Acquire) - reads_before;
        hooks.pause_build.store(false, Ordering::Release);
        hooks.resume_build.notify_one();
        let chunk = repair
            .await
            .expect("repair source joined")
            .expect("repair source request stayed bounded")
            .expect("repair source snapshot");
        let running = store.inner.raft.metrics().borrow().running_state.clone();
        store.shutdown().await.expect("shutdown source");
        assert!(
            running.is_ok(),
            "snapshot request must leave the leader alive"
        );
        assert!(chunk.meta.last_log_id.map(|log| log.index) >= required);
        assert_eq!(chunk.offset, 0);
        assert_eq!(
            premature_reads, 0,
            "snapshot fetch must wait for actual snapshot progress, not metrics flushes"
        );
    })
    .await
    .expect("snapshot progress regression must complete within its bound");
}

#[tokio::test]
async fn repair_source_retriggers_after_an_older_build_swallows_its_request() {
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let identity = opc_consensus::ConsensusIdentity::new(
            opc_consensus::ConsensusClusterId::new("repair-snapshot-retrigger").unwrap(),
            opc_consensus::ConsensusConfigurationId::from_bytes([0x74; 32]),
            opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node(1), BTreeSet::from([node(1)]))
                .expect("singleton topology");
        let backend = SqliteBackend::in_memory_for_test().await.expect("backend");
        let hooks = Arc::clone(&backend.consensus_snapshot_test_hooks);
        let store = ConsensusConfigStore::open_with_operation_timeout(
            topology,
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Duration::from_secs(3),
        )
        .await
        .expect("store");
        store.initialize_cluster().await.expect("singleton leader");
        let old_cut = store.inner.raft.metrics().borrow().last_applied;
        hooks.pause_captured_build.store(true, Ordering::Release);
        store.trigger_snapshot().await.expect("start older build");
        hooks.build_captured.notified().await;

        // The builder already copied its SQLite cut. This real later entry
        // must also be present in the first repair snapshot.
        let applied = store
            .inner
            .raft
            .client_write(super::super::super::ConfigConsensusCommand {
                schema_version: super::super::super::CONFIG_CONSENSUS_COMMAND_VERSION,
                identity,
                request_id: opc_consensus::ConsensusRequestId::from_bytes([0x74; 16]),
                logical_time: opc_types::Timestamp::now_utc(),
                intent: ConfigMutationIntent::MarkConfirmed {
                    tx_id: opc_types::TxId::new(),
                },
            })
            .await
            .expect("later entry commits and applies")
            .log_id;
        store
            .inner
            .raft
            .wait(None)
            .applied_index_at_least(Some(applied.index), "required repair cut")
            .await
            .unwrap();
        assert!(Some(applied) > old_cut);
        let reads_before = hooks.reads_started.load(Ordering::Acquire);
        let repair = store.repair_snapshot_chunk(None, Instant::now() + Duration::from_secs(3));
        tokio::pin!(repair);
        assert!(poll_fn(|cx| Poll::Ready(repair.as_mut().poll(cx)))
            .await
            .is_pending());
        // These acknowledged core messages also ensure the repair's trigger
        // has been processed while the first builder is still held.
        for _ in 0..5 {
            store.inner.raft.with_raft_state(|_| ()).await.unwrap();
            assert!(poll_fn(|cx| Poll::Ready(repair.as_mut().poll(cx)))
                .await
                .is_pending());
        }
        assert_eq!(hooks.reads_started.load(Ordering::Acquire), reads_before);
        assert_eq!(hooks.builds_started.load(Ordering::Acquire), 1);
        hooks.pause_captured_build.store(false, Ordering::Release);
        hooks.resume_captured_build.notify_one();
        let chunk = repair.await.expect("repair owns the fresh build trigger");
        let running = store.inner.raft.metrics().borrow().running_state.clone();
        store.shutdown().await.expect("shutdown source");
        assert!(running.is_ok());
        assert!(chunk
            .meta
            .last_log_id
            .is_some_and(|cut| cut.index >= applied.index));
        assert_eq!(chunk.offset, 0);
        assert_eq!(hooks.builds_started.load(Ordering::Acquire), 2);
        assert_eq!(
            hooks.reads_started.load(Ordering::Acquire) - reads_before,
            1
        );
    })
    .await
    .expect("swallowed-trigger recovery stays within the original request budget");
}

struct PublishedBuildRelease(Arc<crate::consensus::storage::SnapshotTestHooks>);

impl Drop for PublishedBuildRelease {
    fn drop(&mut self) {
        self.0.pause_published_build.store(false, Ordering::Release);
    }
}

async fn published_build_watchdog(operation: impl std::future::Future<Output = ()>) {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let (finished, mut watchdog) = tokio::sync::oneshot::channel();
    let worker = std::thread::spawn(move || {
        let result = held.recv_timeout(Duration::from_secs(30));
        let _ = finished.send(result);
    });
    tokio::select! {
        () = operation => {},
        result = &mut watchdog => panic!("snapshot publication watchdog expired: {result:?}"),
    }
    drop(release);
    assert!(matches!(
        watchdog.await.unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
    worker.join().unwrap();
}

async fn published_build_source() -> (
    tempfile::TempDir,
    ConsensusConfigStore,
    Arc<crate::consensus::storage::SnapshotTestHooks>,
) {
    let directory = tempfile::tempdir().expect("snapshot directory");
    let identity = opc_consensus::ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::new("snapshot-publication").unwrap(),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x76; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology = ConfigConsensusTopology::try_new(identity, node(1), BTreeSet::from([node(1)]))
        .expect("singleton topology");
    let backend = SqliteBackend::in_memory_for_test().await.expect("backend");
    let hooks = Arc::clone(&backend.consensus_snapshot_test_hooks);
    let store = ConsensusConfigStore::open_with_operation_timeout(
        topology,
        backend,
        directory.path().join("snapshots"),
        BTreeMap::new(),
        Duration::from_secs(3),
    )
    .await
    .expect("store");
    store.initialize_cluster().await.expect("singleton leader");
    let applied = store
        .inner
        .raft
        .client_write(super::super::super::ConfigConsensusCommand {
            schema_version: super::super::super::CONFIG_CONSENSUS_COMMAND_VERSION,
            identity,
            request_id: opc_consensus::ConsensusRequestId::from_bytes([0x76; 16]),
            logical_time: opc_types::Timestamp::now_utc(),
            intent: ConfigMutationIntent::MarkConfirmed {
                tx_id: opc_types::TxId::new(),
            },
        })
        .await
        .expect("initial entry commits")
        .log_id;
    store
        .inner
        .raft
        .wait(None)
        .applied_index_at_least(Some(applied.index), "initial applied cut")
        .await
        .expect("applied metrics");
    let mut metrics = store.inner.raft.metrics();
    store.trigger_snapshot().await.expect("initial snapshot");
    loop {
        if metrics.borrow_and_update().snapshot == Some(applied) {
            break;
        }
        metrics
            .changed()
            .await
            .expect("initial snapshot publication");
    }
    assert_eq!(hooks.builds_returned_ok.load(Ordering::Acquire), 1);
    (directory, store, hooks)
}

#[tokio::test]
async fn snapshot_publication_overdue_commit_without_reader_remains_healthy() {
    published_build_watchdog(async {
        let (_directory, store, hooks) = published_build_source().await;
        let _release = PublishedBuildRelease(Arc::clone(&hooks));
        hooks.pause_published_build.store(true, Ordering::Release);
        store.trigger_snapshot().await.expect("second build");
        hooks.build_published.notified().await;
        // The durable publication committed. Only the blocking worker's
        // return is held, modeling a delayed authorized commit completion.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::time::resume();
        store
            .inner
            .raft
            .with_raft_state(|_| ())
            .await
            .expect("core still healthy");
        assert_eq!(hooks.builds_returned_ok.load(Ordering::Acquire), 1);
        hooks.pause_published_build.store(false, Ordering::Release);
        while hooks.builds_returned_ok.load(Ordering::Acquire) < 2 {
            hooks.build_returned_ok.notified().await;
        }
        let snapshot = store
            .inner
            .raft
            .get_snapshot()
            .await
            .expect("healthy read")
            .expect("published snapshot");
        assert!(snapshot.meta.last_log_id.is_some());
        let running = store.inner.raft.metrics().borrow().running_state.clone();
        store.shutdown().await.expect("shutdown control");
        assert!(running.is_ok());
    })
    .await;
}

#[tokio::test]
async fn snapshot_publication_reader_survives_an_overdue_commit() {
    published_build_watchdog(async {
        let (_directory, store, hooks) = published_build_source().await;
        let _release = PublishedBuildRelease(Arc::clone(&hooks));
        let previous = store
            .inner
            .raft
            .get_snapshot()
            .await
            .unwrap()
            .unwrap()
            .meta;
        hooks.pause_published_build.store(true, Ordering::Release);
        store.trigger_snapshot().await.expect("second build");
        hooks.build_published.notified().await;
        let raft = store.inner.raft.clone();
        let mut read = tokio::spawn(async move { raft.get_snapshot().await });
        let outcome = tokio::select! {
            result = &mut read => result.expect("independent read joined"),
            () = hooks.read_gate_blocked.notified() => {
                // Advance only when the read is queued on the held gate.
                // An independent reader completes with real filesystem time.
                assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(61)).await;
                tokio::time::resume();
                read.await.expect("queued read joined")
            },
        };
        let running = if let Err(error) = &outcome {
            assert!(format!("{error:?}").contains("snapshot read gate timed out"));
            let mut metrics = store.inner.raft.metrics();
            loop {
                let state = metrics.borrow_and_update().running_state.clone();
                if state.is_err() {
                    break state;
                }
                metrics.changed().await.expect("engine failure publication");
            }
        } else {
            store.inner.raft.metrics().borrow().running_state.clone()
        };
        assert_eq!(hooks.builds_returned_ok.load(Ordering::Acquire), 1);
        hooks.pause_published_build.store(false, Ordering::Release);
        while hooks.builds_returned_ok.load(Ordering::Acquire) < 2 {
            hooks.build_returned_ok.notified().await;
        }
        let shutdown = store.shutdown().await;
        assert!(
            running.is_ok(),
            "a read queued behind an otherwise successful build must not kill the engine: {running:?}"
        );
        let snapshot = outcome.expect("snapshot remains readable").unwrap();
        assert_eq!(snapshot.meta, previous);
        assert!(shutdown.is_ok());
    })
    .await;
}
