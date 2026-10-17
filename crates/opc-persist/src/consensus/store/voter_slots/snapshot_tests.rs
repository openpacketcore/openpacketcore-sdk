use super::*;

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
