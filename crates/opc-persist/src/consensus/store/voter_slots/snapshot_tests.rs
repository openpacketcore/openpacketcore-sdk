use super::*;

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
        let (snapshot, evidence) = read
            .await
            .unwrap()
            .expect("accepted snapshot read completes");
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
