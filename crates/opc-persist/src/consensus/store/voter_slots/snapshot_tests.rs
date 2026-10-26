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
    store.inner.raft.runtime_config().elect(false);
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
        let Some(IncomingSnapshotState::Receiving(assembly)) = incoming.as_ref() else {
            panic!("partial snapshot retains its receiving artifact");
        };
        snapshots.join(assembly.data.path().file_name().unwrap())
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
    let rpc = InstallSnapshotRequest {
        vote,
        meta: meta.clone(),
        offset: 4096,
        data: Vec::new(),
        done: true,
    };
    let marker = FinalizedSnapshot::new(node, &rpc, Some([0x11; 32]));
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
async fn replay_data_bearing_final_chunk(single_chunk: bool) {
    use crate::consensus::snapshot_file::test_io::{watchdog, Latency, Phase};

    watchdog(async {
        let fleet = Fleet::open().await;
        for node in &fleet.nodes {
            node.inner.raft.runtime_config().elect(false);
        }
        let source = &fleet.nodes[0];
        let target = &fleet.nodes[1];
        let profile = target.inner.voter_profile.as_ref().unwrap();
        let required = source.inner.raft.metrics().borrow().last_log_index.unwrap();
        let vote = source
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap();
        let (mut snapshot, _, _) = source
            .read_replacement_snapshot(required, vote)
            .await
            .unwrap();
        let mut bytes = Vec::new();
        snapshot.snapshot.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.len() > 32 * 1024);
        let offset = if single_chunk { 0 } else { 32 * 1024 };
        if offset != 0 {
            let first = profile
                .receive_snapshot(
                    target,
                    source.inner.local_node_id,
                    InstallSnapshotRequest {
                        vote,
                        meta: snapshot.meta.clone(),
                        offset: 0,
                        data: bytes[..offset].to_vec(),
                        done: false,
                    },
                    None,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                )
                .await
                .unwrap();
            assert!(first.result.is_ok());
        }
        let final_chunk = InstallSnapshotRequest {
            vote,
            meta: snapshot.meta.clone(),
            offset: offset as u64,
            data: bytes[offset..].to_vec(),
            done: true,
        };
        assert!(!final_chunk.data.is_empty());
        let mut latency = Latency::new(fleet.directories[1].path(), Phase::Read);
        let first = latency
            .run(
                Duration::ZERO,
                profile.receive_snapshot(
                    target,
                    source.inner.local_node_id,
                    final_chunk.clone(),
                    None,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                ),
            )
            .await
            .unwrap();
        assert!(first.result.is_ok());
        let verified = latency.verifications();
        assert!(verified > 0);
        let replay = latency
            .run(
                Duration::ZERO,
                profile.receive_snapshot(
                    target,
                    source.inner.local_node_id,
                    final_chunk.clone(),
                    None,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                ),
            )
            .await;
        let verified_after_replay = latency.verifications();
        let mut changed = final_chunk;
        changed.data[0] ^= 1;
        let rejected = latency
            .run(
                Duration::ZERO,
                profile.receive_snapshot(
                    target,
                    source.inner.local_node_id,
                    changed,
                    None,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                ),
            )
            .await;
        let verified_after_mismatch = latency.verifications();
        drop(latency);
        fleet.close().await;
        assert_eq!(
            replay.expect("the same final chunk replays its accepted result"),
            first
        );
        assert_eq!(
            verified_after_replay, verified,
            "replay cannot inspect or install twice"
        );
        assert_eq!(rejected, Err(VoterReplacementError::InvalidTransition));
        assert_eq!(
            verified_after_mismatch, verified,
            "mismatched final data is refused before inspection"
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_single_chunk_replays_its_final_receipt() {
    replay_data_bearing_final_chunk(true).await;
}

#[tokio::test]
async fn snapshot_progress_nonempty_final_chunk_replays_its_final_receipt() {
    replay_data_bearing_final_chunk(false).await;
}
#[tokio::test]
async fn snapshot_progress_failed_final_inspection_can_restart_from_zero() {
    use crate::consensus::snapshot_file::test_io::{watchdog, Latency, Phase};

    watchdog(async {
        let fleet = Fleet::open().await;
        for node in &fleet.nodes {
            node.inner.raft.runtime_config().elect(false);
        }
        let source = &fleet.nodes[0];
        let target = &fleet.nodes[1];
        let profile = target.inner.voter_profile.as_ref().unwrap();
        let required = source.inner.raft.metrics().borrow().last_log_index.unwrap();
        let vote = source
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap();
        let (mut snapshot, _, _) = source
            .read_replacement_snapshot(required, vote)
            .await
            .unwrap();
        let mut bytes = Vec::new();
        snapshot.snapshot.read_to_end(&mut bytes).await.unwrap();
        let request = InstallSnapshotRequest {
            vote,
            meta: snapshot.meta.clone(),
            offset: 0,
            data: bytes,
            done: true,
        };
        let mut latency = Latency::new(fleet.directories[1].path(), Phase::Read);
        let rejected = latency
            .run(
                storage::SNAPSHOT_OPERATION_TIMEOUT + Duration::from_secs(1),
                profile.receive_snapshot(
                    target,
                    source.inner.local_node_id,
                    request.clone(),
                    None,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                ),
            )
            .await;
        assert_eq!(rejected, Err(VoterReplacementError::InvalidTransition));
        assert_eq!(latency.verifications(), 1);
        drop(latency);
        let retried = profile
            .receive_snapshot(
                target,
                source.inner.local_node_id,
                request,
                None,
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await;
        fleet.close().await;
        assert!(retried
            .expect("a rejected inspection must allow a fresh transfer")
            .result
            .is_ok());
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_replacement_chunk_read_is_bounded_and_retryable() {
    use crate::consensus::snapshot_file::test_io::{watchdog, Latency, Phase};
    use crate::consensus::snapshot_file::ConfigSnapshotFile;

    watchdog(async {
        let directory = tempfile::tempdir().unwrap();
        let mut file = ConfigSnapshotFile::create(directory.path().join("snapshot.part"))
            .await
            .unwrap();
        let mut bytes = vec![0x74; 2 * 1024 * 1024];
        bytes[128 * 1024..256 * 1024].fill(0x75);
        file.write_all(&bytes).await.unwrap();
        file.sync_all().await.unwrap();
        let mut latency = Latency::new(directory.path(), Phase::Read);
        let started = tokio::time::Instant::now();
        let chunk = latency
            .run(
                Duration::from_secs(12),
                read_replacement_chunk(&mut file, 128 * 1024),
            )
            .await
            .unwrap();
        assert!(started.elapsed() > Duration::from_secs(10));
        assert_eq!(chunk, bytes[128 * 1024..256 * 1024]);
        {
            let stalled = read_replacement_chunk(&mut file, 128 * 1024);
            tokio::pin!(stalled);
            let held = tokio::select! {
                step = latency.progress.recv() => step.unwrap(),
                result = &mut stalled => panic!("chunk did not reach its storage gate: {result:?}"),
            };
            tokio::time::pause();
            tokio::time::advance(storage::SNAPSHOT_OPERATION_TIMEOUT + Duration::from_secs(1))
                .await;
            assert_eq!(stalled.await, Err(VoterReplacementError::Unavailable));
            tokio::time::resume();
            drop(held);
        }
        drop(latency);
        let retried = read_replacement_chunk(&mut file, 128 * 1024).await.unwrap();
        assert_eq!(
            retried, chunk,
            "retry restarts from the acknowledged offset"
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_replacement_verifies_its_large_reader_once() {
    use crate::consensus::snapshot_file::test_io::{watchdog, Latency, Phase};
    use crate::consensus::storage::snapshot_progress_tests::{large_commands, PAYLOAD_BYTES};
    use sha2::Digest;
    use tokio::io::AsyncSeekExt;

    watchdog(async {
        let directory = tempfile::tempdir().unwrap();
        let identity = genesis()
            .current_configuration()
            .identity(genesis().cluster_instance, genesis().manifest_digest)
            .unwrap();
        let node = member(1, 1).identity.node_id();
        let backend = SqliteBackend::open_with_audit_key(
            directory.path().join("config.sqlite"),
            true,
            0,
            crate::AuditKey::new([0x68; 32]).unwrap(),
        )
        .await
        .unwrap();
        let commands = large_commands(identity, backend.audit_key());
        let store = ConsensusConfigStore::open_with_operation_timeout(
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        store.initialize_cluster().await.unwrap();
        for command in commands {
            assert!(store
                .inner
                .raft
                .client_write(command)
                .await
                .unwrap()
                .data
                .result
                .is_ok());
        }
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
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        let mut latency = Latency::new(directory.path(), Phase::Read);
        let started = tokio::time::Instant::now();
        let result = latency
            .run(
                Duration::from_secs(2),
                store.read_replacement_snapshot(required, vote),
            )
            .await;
        let verifications = latency.verifications();
        drop(latency);
        store.shutdown().await.unwrap();
        let (mut snapshot, evidence, _) = result.expect("progressing read survives the RPC budget");
        assert!(started.elapsed() > Duration::from_secs(10));
        assert!(
            tokio::io::AsyncSeekExt::seek(&mut snapshot.snapshot, std::io::SeekFrom::End(0))
                .await
                .unwrap()
                > PAYLOAD_BYTES
        );
        assert!(snapshot.meta.last_log_id.unwrap().index >= required);
        assert_eq!(snapshot.meta.snapshot_id, evidence.snapshot_id);
        let payload_length = snapshot
            .snapshot
            .verified_envelope()
            .unwrap()
            .payload_length;
        snapshot
            .snapshot
            .seek(std::io::SeekFrom::Start(0))
            .await
            .unwrap();
        let mut payload = Vec::new();
        (&mut snapshot.snapshot)
            .take(payload_length)
            .read_to_end(&mut payload)
            .await
            .unwrap();
        assert_eq!(payload.len() as u64, payload_length);
        assert_eq!(
            <[u8; 32]>::from(sha2::Sha256::digest(&payload)),
            evidence.digest
        );
        assert_eq!(
            verifications, 1,
            "replacement evidence reuses the descriptor's verified digest"
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_resent_final_chunk_joins_the_accepted_install() {
    use crate::consensus::snapshot_file::test_io::{watchdog, Latency, Phase};
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    watchdog(async {
        let fleet = Fleet::open().await;
        for node in &fleet.nodes {
            node.inner.raft.runtime_config().elect(false);
        }
        let source = &fleet.nodes[0];
        let target = fleet.nodes[1].clone();
        let profile = target.inner.voter_profile.as_ref().unwrap().clone();
        let required = source.inner.raft.metrics().borrow().last_log_index.unwrap();
        let vote = source
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap();
        let (mut snapshot, _, _) = source
            .read_replacement_snapshot(required, vote)
            .await
            .unwrap();
        let mut bytes = Vec::new();
        snapshot.snapshot.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.len() > 32 * 1024, "exercise a nonzero final cursor");
        for (index, chunk) in bytes.chunks(32 * 1024).enumerate() {
            let reply = profile
                .receive_snapshot(
                    &target,
                    source.inner.local_node_id,
                    InstallSnapshotRequest {
                        vote,
                        meta: snapshot.meta.clone(),
                        offset: (index * 32 * 1024) as u64,
                        data: chunk.to_vec(),
                        done: false,
                    },
                    None,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                )
                .await
                .unwrap();
            assert!(reply.result.is_ok());
        }
        let final_chunk = || InstallSnapshotRequest {
            vote,
            meta: snapshot.meta.clone(),
            offset: bytes.len() as u64,
            data: Vec::new(),
            done: true,
        };
        let mut latency = Latency::new(fleet.directories[1].path(), Phase::Read);
        let first = profile.receive_snapshot(
            &target,
            source.inner.local_node_id,
            final_chunk(),
            None,
            tokio::time::Instant::now() + Duration::from_secs(10),
        );
        tokio::pin!(first);
        let held = tokio::select! {
            step = latency.progress.recv() => step.unwrap(),
            result = &mut first => panic!("install did not reach file inspection: {result:?}"),
        };
        // Inspection owns the assembled file now. The sender can retry this
        // exact nonzero final cursor before SnapshotInstalled becomes visible.
        let retry = profile.receive_snapshot(
            &target,
            source.inner.local_node_id,
            final_chunk(),
            None,
            tokio::time::Instant::now() + Duration::from_secs(10),
        );
        tokio::pin!(retry);
        let mut early = poll_fn(|cx| Poll::Ready(retry.as_mut().poll(cx))).await;
        if early.is_pending() {
            // Flush the retry's earlier vote query while inspection is still
            // held, then poll through its actual incoming-transfer decision.
            target.inner.raft.with_raft_state(|_| ()).await.unwrap();
            early = poll_fn(|cx| Poll::Ready(retry.as_mut().poll(cx))).await;
        }
        let joined_pending = early.is_pending();
        held.send(()).unwrap();
        let (first, retry) = latency
            .run(Duration::ZERO, async {
                let first = first.await;
                let retry = match early {
                    Poll::Ready(result) => result,
                    Poll::Pending => retry.await,
                };
                (first, retry)
            })
            .await;
        assert!(first.unwrap().result.is_ok());
        assert!(retry
            .expect("resent final chunk joins or replays the same install")
            .result
            .is_ok());
        assert!(
            joined_pending,
            "the retry waits for the accepted inspection"
        );
        assert_eq!(
            latency.verifications(),
            1,
            "inspection and install share the verified descriptor"
        );
        let replay = profile
            .receive_snapshot(
                &target,
                source.inner.local_node_id,
                final_chunk(),
                None,
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(replay.result.is_ok());
        for change in 0..7 {
            let mut changed = final_chunk();
            let mut sender = source.inner.local_node_id;
            let mut replacement = None;
            match change {
                0 => changed.data.push(0x91),
                1 => changed.meta.snapshot_id.push_str("-stale"),
                2 => changed.vote = Vote::new_committed(vote.leader_id.term + 1, sender),
                3 => sender = fleet.nodes[2].inner.local_node_id,
                4 => replacement = Some([0x92; 32]),
                5 => changed.offset = 0,
                6 => changed.done = false,
                _ => unreachable!(),
            }
            assert_eq!(
                profile
                    .receive_snapshot(
                        &target,
                        sender,
                        changed,
                        replacement,
                        tokio::time::Instant::now() + Duration::from_secs(10),
                    )
                    .await,
                Err(VoterReplacementError::InvalidTransition)
            );
        }
        assert_eq!(latency.verifications(), 1);
        drop(latency);
        fleet.network.handlers.write().unwrap().clear();
        for node in &fleet.nodes {
            node.shutdown().await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_final_receipt_waits_for_the_definitive_engine_result() {
    use crate::consensus::snapshot_file::test_io::watchdog;
    use crate::consensus::storage::snapshot_progress_tests::large_commands;
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    watchdog(async {
        let fleet = Fleet::open().await;
        for node in &fleet.nodes {
            node.inner.raft.runtime_config().elect(false);
        }
        let source = &fleet.nodes[0];
        let target = &fleet.nodes[1];
        let profile = target.inner.voter_profile.as_ref().unwrap();
        // Keep the target behind a real committed cut. Openraft correctly
        // ignores a snapshot whose cut is already applied, which would never
        // exercise the storage install gate held below.
        fleet
            .network
            .paused_replication_to
            .store(target.inner.local_node_id.get(), Ordering::SeqCst);
        let command = large_commands(source.inner.identity, source.inner.backend.audit_key())
            .into_iter()
            .next()
            .unwrap();
        let applied = source.inner.raft.client_write(command).await.unwrap();
        assert!(applied.data.result.is_ok());
        let required = applied.log_id.index;
        let vote = source
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap();
        let (mut snapshot, _, _) = source
            .read_replacement_snapshot(required, vote)
            .await
            .unwrap();
        assert!(snapshot.meta.last_log_id > target.inner.raft.metrics().borrow().last_applied);
        let mut bytes = Vec::new();
        snapshot.snapshot.read_to_end(&mut bytes).await.unwrap();
        let request = || InstallSnapshotRequest {
            vote,
            meta: snapshot.meta.clone(),
            offset: 0,
            data: bytes.clone(),
            done: true,
        };
        let gate = profile.core.snapshot_build_gate.clone().lock_owned().await;
        let first = profile.receive_snapshot(
            target,
            source.inner.local_node_id,
            request(),
            None,
            tokio::time::Instant::now() + Duration::from_secs(10),
        );
        tokio::pin!(first);
        tokio::select! {
            () = profile.core.snapshot_test_hooks.install_gate_blocked.notified() => {},
            result = &mut first => panic!("install never reached its owned engine callback: {result:?}"),
        }
        // The artifact has passed inspection and dispatch. A caller's RPC
        // deadline cannot become the retained result of this accepted install.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(12)).await;
        tokio::time::resume();
        let first_early = poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx))).await;
        let first_pending = first_early.is_pending();
        let retry = profile.receive_snapshot(
            target,
            source.inner.local_node_id,
            request(),
            None,
            tokio::time::Instant::now() + Duration::from_secs(10),
        );
        tokio::pin!(retry);
        let retry_early = poll_fn(|cx| Poll::Ready(retry.as_mut().poll(cx))).await;
        let retry_pending = retry_early.is_pending();
        let receipt_pending = {
            let incoming = profile.incoming.lock().await;
            let Some(IncomingSnapshotState::Accepted { completion, .. }) = incoming.as_ref() else {
                panic!("the dispatched install must retain its final receipt");
            };
            let pending = completion.borrow().is_none();
            pending
        };
        drop(gate);
        // The engine may be awaiting purge's application fence while storage
        // installs the snapshot. Its serialized vote query must wait until the
        // held installation can finish; do not deadlock the fixture on it.
        target.inner.raft.with_raft_state(|_| ()).await.unwrap();
        let first = match first_early {
            Poll::Ready(result) => result,
            Poll::Pending => first.await,
        };
        let retry = match retry_early {
            Poll::Ready(result) => result,
            Poll::Pending => retry.await,
        };
        fleet.network.handlers.write().unwrap().clear();
        for node in &fleet.nodes {
            node.shutdown().await.unwrap();
        }
        assert!(first_pending, "the receipt must await definitive engine completion");
        assert!(retry_pending, "a retry must join the same still-pending result");
        assert!(receipt_pending, "an RPC timeout is not a completed install receipt");
        assert!(first.unwrap().result.is_ok());
        assert!(retry.unwrap().result.is_ok());
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_shutdown_releases_pending_receipt_waiters() {
    use crate::consensus::snapshot_file::test_io::watchdog;
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    watchdog(async {
        let fleet = Fleet::open().await;
        let target = fleet.nodes[1].clone();
        let profile = target.inner.voter_profile.as_ref().unwrap().clone();
        // A newly created admission runtime has not attached its engine and
        // cannot use the established-voter acknowledgement fast path.
        let pending_admission = ConfigVoterAdmission::new(
            target.inner.local_node_id,
            Arc::new(Reader(profile.core.clone())),
        )
        .await
        .unwrap();
        assert!(!pending_admission.local_voting_admitted());
        let pending_profile = ConfigVoterProfile {
            admission: pending_admission,
            transport: profile.transport.clone(),
            core: profile.core.clone(),
            incoming: tokio::sync::Mutex::new(None),
        };
        let waiting_store = target.clone();
        let waiting_profile = profile.clone();
        let (_completed, completion) = tokio::sync::watch::channel(None);
        let (started, pending) = tokio::sync::oneshot::channel();
        let mut waiter = tokio::spawn(async move {
            let wait = waiting_profile.await_snapshot_receipt(
                &waiting_store,
                completion,
                tokio::time::Instant::now() + Duration::from_secs(10),
            );
            tokio::pin!(wait);
            assert!(poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx)))
                .await
                .is_pending());
            started.send(()).unwrap();
            wait.await
        });
        pending.await.unwrap();
        target.shutdown().await.unwrap();
        let finished = tokio::time::timeout(Duration::from_secs(1), &mut waiter).await;
        let response = match finished {
            Ok(response) => Some(response.unwrap()),
            Err(_) => {
                waiter.abort();
                let _ = waiter.await;
                None
            }
        };
        let ack = pending_profile
            .wait_candidate_ack(
                &target,
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await;
        assert_eq!(
            profile
                .wait_candidate_ack(
                    &target,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                )
                .await,
            Ok(()),
            "an established voter retains its immediate replication acknowledgement"
        );
        drop(pending_profile);
        drop(profile);
        drop(target);
        fleet.close().await;
        assert_eq!(
            response,
            Some(Err(VoterReplacementError::Unavailable)),
            "shutdown must release the owned receipt waiter before its RPC deadline"
        );
        assert_eq!(ack, Err(VoterReplacementError::Unavailable));
    })
    .await;
}
