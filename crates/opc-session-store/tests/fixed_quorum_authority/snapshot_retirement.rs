use super::*;
use bytes::Bytes;
use opc_consensus::engine::{EmptyNode, SnapshotMeta, Vote};
use opc_consensus::{decode_bounded, DURABLE_OPENRAFT_PROFILE};
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use opc_session_store::test_support::{
    append_consensus_padding_entry_for_test, consensus_local_durable_progress_for_test,
    consensus_native_current_snapshot_for_test, trigger_consensus_log_purge_through_for_test,
    ConsensusEngineStateForTest,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, Generation,
    SessionConsensusRpcFamily, StateClass, StateType, StoredSessionRecord,
};
use std::os::unix::fs::MetadataExt as _;
use std::sync::Mutex;

// Decode the production wire shape without exposing the private Raft config.
#[derive(serde::Deserialize)]
struct SnapshotChunk {
    _vote: Vote<SessionConsensusNodeId>,
    _meta: SnapshotMeta<SessionConsensusNodeId, EmptyNode>,
    offset: u64,
    data: Vec<u8>,
    done: bool,
}

struct PausedSnapshotHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
    first_chunk: Mutex<Option<Vec<u8>>>,
    entered: tokio::sync::Notify,
    released: AtomicBool,
    release: tokio::sync::Notify,
}

impl fmt::Debug for PausedSnapshotHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PausedSnapshotHandler")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for PausedSnapshotHandler {
    async fn handle(
        &self,
        sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        let snapshot = request.family == SessionConsensusRpcFamily::InstallSnapshot;
        if snapshot {
            let chunk: SnapshotChunk = decode_bounded(&request.payload).unwrap();
            let mut first = self.first_chunk.lock().unwrap();
            if first.is_none() {
                assert_eq!(0, chunk.offset);
                assert!(
                    !chunk.done,
                    "fixture must need another production-sized chunk"
                );
                *first = Some(chunk.data);
            }
        }
        let response = self.inner.handle(sender, request).await;
        if snapshot {
            let result: Result<
                opc_consensus::engine::raft::InstallSnapshotResponse<SessionConsensusNodeId>,
                opc_consensus::engine::error::RaftError<
                    SessionConsensusNodeId,
                    opc_consensus::engine::error::InstallSnapshotError,
                >,
            > = decode_bounded(response.result.as_ref().expect("snapshot RPC admitted")).unwrap();
            assert!(
                result.is_ok(),
                "voter accepts the gated snapshot chunk: {result:?}"
            );
            self.entered.notify_one();
            // Also hold retries if the normal RPC deadline expires while the
            // test publishes S2. No timer decides the read/build interleaving.
            loop {
                let released = self.release.notified();
                if self.released.load(Ordering::SeqCst) {
                    break;
                }
                released.await;
            }
        }
        response
    }
}

async fn wait_for_progress(
    store: &ConsensusSessionStore,
    ready: impl Fn(opc_session_store::test_support::ConsensusLocalDurableProgressForTest) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let progress = consensus_local_durable_progress_for_test(store);
            assert_eq!(
                ConsensusEngineStateForTest::Running,
                progress.engine_state,
                "{progress:?}"
            );
            if ready(progress) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("native voter reaches the required snapshot frontier");
}

async fn write_large_record(store: &ConsensusSessionStore, ordinal: u8) {
    let key = SessionKey {
        tenant: TenantId::new("snapshot-retirement").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![ordinal]).try_into().unwrap(),
    };
    let lease = store
        .acquire(
            &key,
            OwnerId::new("snapshot-owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let key_id = KeyId::new("synthetic-snapshot-key").unwrap();
    let state_type = StateType::from_static("snapshot-retirement");
    let aad = EnvelopeAad::session(
        key.tenant.clone(),
        1,
        SessionAad::new(
            key.nf_kind.as_str(),
            "synthetic-digest",
            state_type.as_str(),
            1,
            lease.fence().get(),
            "synthetic-backend",
        )
        .unwrap(),
    );
    let payload = CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: key_id.clone(),
        nonce: vec![ordinal; AES_256_GCM_SIV_NONCE_LEN],
        aad: serialize_bound_aad(&aad, &key_id).unwrap(),
        ciphertext_and_tag: vec![ordinal; 512 * 1024 + AEAD_TAG_LEN],
    }
    .encode()
    .unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type,
        expires_at: None,
        payload: EncryptedSessionPayload::try_envelope(payload).unwrap(),
    };
    assert_eq!(
        CompareAndSetResult::Success,
        store
            .compare_and_set(CompareAndSet {
                key,
                lease,
                expected_generation: None,
                new_record: record,
            })
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn native_leader_streams_retired_snapshot_without_stopping_engine() {
    let (directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let leader = (0..3)
        .find(|index| {
            let status = stores[*index].status();
            status.leader_id == Some(status.node_id)
        })
        .unwrap();
    let lagging = (leader + 1) % 3;
    // Keep the production 1 MiB transfer chunk size. Three bounded synthetic
    // records force the actual engine to read again after the gated response.
    // Prepare them before disconnecting a voter so this work does not consume
    // its unchanged election timeout on shared runners.
    for ordinal in 1..=3 {
        write_large_record(&stores[leader], ordinal).await;
    }
    let ready_index = consensus_local_durable_progress_for_test(&stores[leader]).applied_index;
    wait_for_progress(&stores[lagging], |p| p.applied_index >= ready_index).await;
    let isolation_started = std::time::Instant::now();
    for ((source, target), peer) in &paths {
        if *source == lagging || *target == lagging {
            peer.set_enabled(false);
        }
    }
    let predecessor_index = append_consensus_padding_entry_for_test(&stores[leader], [0xE1; 16])
        .await
        .unwrap();
    trigger_consensus_snapshot_for_test(&stores[leader])
        .await
        .unwrap();
    wait_for_progress(&stores[leader], |p| {
        p.snapshot_index == Some(predecessor_index)
    })
    .await;
    let snapshot_directory = directory.path().join(format!("snapshots-{leader}"));
    let predecessor_path = fixed_published_snapshot_path(
        &stores[leader],
        &database_paths[leader],
        &snapshot_directory,
    )
    .unwrap();
    assert!(
        consensus_native_current_snapshot_for_test(&stores[leader])
            .unwrap()
            .0,
        "production opener attaches the native log"
    );
    let predecessor = std::fs::File::open(&predecessor_path).unwrap();
    let original = std::fs::read(&predecessor_path).unwrap();
    assert!(original.len() > DURABLE_OPENRAFT_PROFILE.snapshot_chunk_bytes as usize);
    trigger_consensus_log_purge_through_for_test(&stores[leader], predecessor_index)
        .await
        .unwrap();
    wait_for_progress(&stores[leader], |p| {
        p.purged_index == Some(predecessor_index)
    })
    .await;

    let paused = Arc::new(PausedSnapshotHandler {
        inner: stores[lagging].rpc_handler(),
        first_chunk: Mutex::new(None),
        entered: tokio::sync::Notify::new(),
        released: AtomicBool::new(false),
        release: tokio::sync::Notify::new(),
    });
    paths
        .get(&(leader, lagging))
        .unwrap()
        .install(paused.clone())
        .await;
    for peer in paths.values() {
        peer.set_enabled(true);
    }
    eprintln!(
        "lagging voter isolation: {:?}; unchanged minimum election timeout: {} ms",
        isolation_started.elapsed(),
        opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_min_millis,
    );
    tokio::time::timeout(Duration::from_secs(10), paused.entered.notified())
        .await
        .expect("lagging voter receives the first non-final snapshot chunk");
    let prefix = paused.first_chunk.lock().unwrap().clone().unwrap();
    assert_eq!(original[..prefix.len()], prefix);

    let successor_index = append_consensus_padding_entry_for_test(&stores[leader], [0xE2; 16])
        .await
        .unwrap();
    trigger_consensus_snapshot_for_test(&stores[leader])
        .await
        .unwrap();
    wait_for_progress(&stores[leader], |p| {
        p.snapshot_index == Some(successor_index)
    })
    .await;
    assert!(
        !predecessor_path.exists(),
        "real native publication retires S1 while streaming"
    );
    assert_eq!(0, predecessor.metadata().unwrap().nlink());
    paused.released.store(true, Ordering::SeqCst);
    paused.release.notify_waiters();

    // Check the leader on every iteration: the old implementation reports
    // StorageIo(Snapshot, Read) as soon as transport reads the retired inode.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let leader_progress = consensus_local_durable_progress_for_test(&stores[leader]);
            assert_eq!(
                ConsensusEngineStateForTest::Running,
                leader_progress.engine_state,
                "leader stopped after predecessor retirement: {leader_progress:?}"
            );
            let follower = consensus_local_durable_progress_for_test(&stores[lagging]);
            assert_eq!(ConsensusEngineStateForTest::Running, follower.engine_state);
            if follower.snapshot_index >= Some(predecessor_index)
                && follower.applied_index >= Some(successor_index)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("lagging voter installs the retained stream and catches up");
    let after = append_consensus_padding_entry_for_test(&stores[leader], [0xE3; 16])
        .await
        .expect("same leader still commits after successor publication and transfer");
    for store in &stores {
        wait_for_progress(store, |p| p.applied_index >= Some(after)).await;
    }
    let status = stores[leader].status();
    assert_eq!(Some(status.node_id), status.leader_id);
    shutdown_fixed_cluster_for_reopen(&stores, &paths).await;
}
