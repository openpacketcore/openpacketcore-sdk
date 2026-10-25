use super::*;

#[tokio::test]
async fn voter_snapshot_rejects_incomparable_vote_before_staging() {
    let directory = tempfile::tempdir().unwrap();
    let local = member(1, 1).identity.node_id();
    let source = member(2, 1).identity.node_id();
    let snapshots = directory.path().join("snapshots");
    let store = ConsensusConfigStore::open_with_voter_slots(
        genesis(),
        local,
        SqliteBackend::in_memory_for_test().await.unwrap(),
        &snapshots,
        Arc::new(Resolver(Arc::new(Network::default()))),
    )
    .await
    .unwrap();
    store.disable_automatic_elections_for_test();
    let current_vote = Vote::new(5, local);
    store
        .inner
        .raft
        .vote(VoteRequest {
            vote: current_vote,
            last_log_id: None,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap(),
        current_vote
    );
    let rpc = InstallSnapshotRequest::<ConfigRaftTypeConfig> {
        vote: Vote::new(5, source),
        meta: SnapshotMeta {
            last_log_id: None,
            last_membership: Default::default(),
            snapshot_id: "incomparable-voter-transfer".into(),
        },
        offset: 0,
        data: b"must not stage".to_vec(),
        done: false,
    };
    assert_eq!(rpc.vote.partial_cmp(&current_vote), None);
    let engine_response = store
        .inner
        .raft
        .install_snapshot(rpc.clone())
        .await
        .unwrap();
    assert_eq!(engine_response.vote, current_vote);
    assert_eq!(std::fs::read_dir(&snapshots).unwrap().count(), 0);
    let profile = store.inner.voter_profile.as_ref().unwrap();
    let response = profile
        .receive_snapshot(
            &store,
            source,
            rpc,
            None,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    let result: Result<
        InstallSnapshotResponse<ConsensusNodeId>,
        RaftError<ConsensusNodeId, InstallSnapshotError>,
    > = decode_config_wire(&response.result.unwrap()).unwrap();
    assert_eq!(result.unwrap().vote, engine_response.vote);
    let staged = std::fs::read_dir(&snapshots).unwrap().count();
    let retained = profile.incoming.lock().await.is_some();
    store.shutdown().await.unwrap();
    assert_eq!(
        staged, 0,
        "an engine-rejected incomparable vote must not create staging"
    );
    assert!(
        !retained,
        "an engine-rejected vote must not retain a receiver"
    );
}

#[tokio::test]
async fn shutdown_discards_partial_snapshot_and_reopens_with_old_handles_alive() {
    let directory = tempfile::tempdir().unwrap();
    let network = Arc::new(Network::default());
    let backend = SqliteBackend::open_with_audit_key(
        directory.path().join("config.sqlite"),
        true,
        0,
        crate::AuditKey::new([42; 32]).unwrap(),
    )
    .await
    .unwrap();
    let snapshots = directory.path().join("snapshots");
    let local = member(1, 1).identity.node_id();
    let store = ConsensusConfigStore::open_with_voter_slots(
        genesis(),
        local,
        backend.clone(),
        &snapshots,
        Arc::new(Resolver(network.clone())),
    )
    .await
    .unwrap();
    let profile = store.inner.voter_profile.as_ref().unwrap().clone();
    let source = member(2, 1).identity.node_id();
    let request = InstallSnapshotRequest {
        vote: opc_consensus::engine::Vote::new_committed(1, source),
        meta: opc_consensus::engine::SnapshotMeta {
            last_log_id: None,
            last_membership: Default::default(),
            snapshot_id: "interrupted-shutdown-transfer".into(),
        },
        offset: 0,
        data: b"partial snapshot".to_vec(),
        done: false,
    };
    let response = profile
        .receive_snapshot(
            &store,
            source,
            request.clone(),
            None,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(response.result.is_ok());
    let path = {
        let incoming = profile.incoming.lock().await;
        snapshots.join(incoming.as_ref().unwrap().data.path().file_name().unwrap())
    };
    assert!(path.is_file());
    tokio::time::timeout(Duration::from_secs(10), store.shutdown())
        .await
        .expect("shutdown must release its partial transfer within the existing budget")
        .expect("shutdown must finish while old handles stay alive");
    assert!(profile.incoming.lock().await.is_none());
    assert!(!path.exists(), "shutdown removes the interrupted transfer");
    assert!(profile
        .receive_snapshot(
            &store,
            source,
            request,
            None,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .is_err());
    let reopened = ConsensusConfigStore::open_with_voter_slots(
        genesis(),
        local,
        backend,
        &snapshots,
        Arc::new(Resolver(network)),
    )
    .await
    .expect("restart must not require dropping old public store handles");
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn replacement_awaits_one_snapshot_read_beyond_its_rpc_budget() {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let mut watchdog =
        tokio::task::spawn_blocking(move || held.recv_timeout(Duration::from_secs(10)));
    let operation = async {
        let directory = tempfile::tempdir().unwrap();
        let identity = genesis()
            .current_configuration()
            .identity(genesis().cluster_instance, genesis().manifest_digest)
            .unwrap();
        let node = member(1, 1).identity.node_id();
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let backend = SqliteBackend::in_memory_for_test().await.unwrap();
        let hooks = backend.consensus_snapshot_test_hooks.clone();
        let work_hooks = backend.consensus_snapshot_work_hooks.clone();
        let store = ConsensusConfigStore::open_with_operation_timeout(
            topology,
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        store.initialize_cluster().await.unwrap();
        let required = store.inner.raft.metrics().borrow().last_log_index.unwrap();
        let vote = store
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap();
        store
            .wait_for_snapshot_cut(
                Some(required),
                vote,
                tokio::time::Instant::now() + Duration::from_secs(3),
            )
            .await
            .unwrap();
        let reads_before = hooks.reads_started.load(Ordering::Acquire);
        let verifications_before = work_hooks.envelope_verifications();
        hooks.pause_open_read.store(true, Ordering::Release);
        let source = store.clone();
        let read =
            tokio::spawn(async move { source.read_replacement_snapshot(required, vote).await });
        hooks.read_opened.notified().await;
        // Freeze only while the opened-descriptor hook prevents filesystem work.
        // Several RPC deadlines pass, but this accepted read must remain owned.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(12)).await;
        tokio::time::resume();
        assert!(
            !read.is_finished(),
            "the storage read must outlive its RPC budget"
        );
        assert_eq!(
            hooks.reads_started.load(Ordering::Acquire) - reads_before,
            1
        );
        hooks.pause_open_read.store(false, Ordering::Release);
        hooks.resume_read.notify_one();
        let (snapshot, evidence, length) = read
            .await
            .unwrap()
            .expect("accepted snapshot read completes");
        assert!(length > 0);
        assert_eq!(
            verifications_before + 1,
            work_hooks.envelope_verifications(),
            "the replacement read verifies the whole file exactly once and reuses that digest"
        );
        assert!(snapshot.meta.last_log_id.unwrap().index >= required);
        assert_eq!(evidence.snapshot_id, snapshot.meta.snapshot_id);
        assert_eq!(evidence.cut.index, snapshot.meta.last_log_id.unwrap().index);
        assert_eq!(
            hooks.reads_started.load(Ordering::Acquire) - reads_before,
            1
        );
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
        store.shutdown().await.unwrap();
    };
    tokio::select! {
        () = operation => {},
        result = &mut watchdog => panic!("replacement read watchdog expired: {result:?}"),
    }
    drop(release);
    assert!(matches!(
        watchdog.await.unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
}

#[test]
fn resent_final_chunk_matches_only_the_identical_finalized_artifact() {
    use opc_consensus::engine::{
        CommittedLeaderId, LogId, Membership, SnapshotMeta, StoredMembership,
    };

    let node = member(1, 1).identity.node_id();
    let peer = member(2, 1).identity.node_id();
    let vote = Vote::new_committed(5, node);
    let meta = SnapshotMeta {
        last_log_id: Some(LogId::new(CommittedLeaderId::new(5, node), 9)),
        last_membership: StoredMembership::new(
            None,
            Membership::new(
                vec![BTreeSet::from([node, peer])],
                BTreeSet::from([node, peer]),
            ),
        ),
        snapshot_id: "finalized-snapshot".to_owned(),
    };
    let marker = FinalizedSnapshot {
        source: node,
        vote,
        meta: meta.clone(),
        replacement: Some([0x11; 32]),
        offset: 4096,
    };
    let rpc = InstallSnapshotRequest {
        vote,
        meta: meta.clone(),
        offset: 4096,
        data: Vec::new(),
        done: true,
    };
    assert!(finalized_matches(&marker, node, &rpc, Some([0x11; 32])));

    // A different artifact, replacement, offset, source or non-final transfer
    // must never receive the idempotent success.
    let mut changed = rpc.clone();
    changed.meta.snapshot_id = "other-snapshot".to_owned();
    assert!(!finalized_matches(
        &marker,
        node,
        &changed,
        Some([0x11; 32])
    ));
    let mut changed = rpc.clone();
    changed.offset = 4095;
    assert!(!finalized_matches(
        &marker,
        node,
        &changed,
        Some([0x11; 32])
    ));
    let mut changed = rpc.clone();
    changed.done = false;
    assert!(!finalized_matches(
        &marker,
        node,
        &changed,
        Some([0x11; 32])
    ));
    assert!(!finalized_matches(&marker, peer, &rpc, Some([0x11; 32])));
    assert!(!finalized_matches(&marker, node, &rpc, None));
}
