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
