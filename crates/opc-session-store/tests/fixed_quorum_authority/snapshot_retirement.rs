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
    consensus_native_current_snapshot_for_test, pause_consensus_snapshot_publication_for_test,
    trigger_consensus_log_purge_through_for_test, wait_for_consensus_progress_for_test,
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
    meta: SnapshotMeta<SessionConsensusNodeId, EmptyNode>,
    offset: u64,
    data: Vec<u8>,
    done: bool,
}

#[derive(Clone, Debug, Default)]
struct TransferProgress {
    bytes: usize,
    chunks: usize,
    complete: bool,
}

struct PausedSnapshotHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
    expected: Arc<Vec<u8>>,
    expected_index: u64,
    first_chunk: Mutex<Option<Vec<u8>>>,
    progress: tokio::sync::watch::Sender<TransferProgress>,
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
        let chunk = (request.family == SessionConsensusRpcFamily::InstallSnapshot)
            .then(|| decode_bounded::<SnapshotChunk>(&request.payload).unwrap());
        if let Some(chunk) = &chunk {
            assert_eq!(
                chunk.meta.last_log_id.map(|log| log.index),
                Some(self.expected_index),
                "the already-admitted predecessor must finish without a replacement transfer"
            );
            let progress = self.progress.borrow().clone();
            assert!(!progress.complete, "snapshot must complete exactly once");
            assert_eq!(
                chunk.offset, progress.bytes as u64,
                "no retried or skipped chunk"
            );
            assert_eq!(
                self.expected[progress.bytes..progress.bytes + chunk.data.len()],
                chunk.data,
                "every byte must come from the retained predecessor"
            );
            let mut first = self.first_chunk.lock().unwrap();
            if first.is_none() {
                assert_eq!(0, chunk.offset);
                assert!(
                    !chunk.done,
                    "fixture must need another production-sized chunk"
                );
                *first = Some(chunk.data.clone());
            } else {
                assert!(
                    self.released.load(Ordering::SeqCst),
                    "retire before the next read"
                );
            }
        }
        let response = self.inner.handle(sender, request).await;
        if let Some(chunk) = chunk {
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
            self.progress.send_modify(|progress| {
                progress.bytes += chunk.data.len();
                progress.chunks += 1;
                progress.complete = chunk.done;
            });
            self.entered.notify_one();
            // S2 is already prepared. Only its publication and retirement
            // happen while this response is held; construction consumes none
            // of the normal snapshot RPC's deadline.
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
    let progress = tokio::time::timeout(
        Duration::from_secs(10),
        wait_for_consensus_progress_for_test(store, &ready),
    )
    .await
    .expect("native voter reaches the required snapshot frontier");
    assert_eq!(
        ConsensusEngineStateForTest::Running,
        progress.engine_state,
        "{progress:?}"
    );
    assert!(
        ready(progress),
        "engine progress closed before the required frontier: {progress:?}"
    );
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
    // Prepare the byte image before forcing the lagging voter to miss a log.
    for ordinal in 1..=3 {
        write_large_record(&stores[leader], ordinal).await;
    }
    let ready_index = consensus_local_durable_progress_for_test(&stores[leader]).applied_index;
    wait_for_progress(&stores[lagging], |p| p.applied_index >= ready_index).await;
    // This regression controls snapshot retirement, not leader election. The
    // pinned engine's per-node switch prevents the disconnected voter from
    // advancing its term, however long building and purging the snapshot take.
    // Ticks, leader heartbeats, replication and explicit votes stay enabled.
    stores[lagging].set_automatic_election_for_test(false);
    let disconnected_term = stores[lagging].status().term;
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
    let original = Arc::new(std::fs::read(&predecessor_path).unwrap());
    assert!(original.len() > DURABLE_OPENRAFT_PROFILE.snapshot_chunk_bytes as usize);
    trigger_consensus_log_purge_through_for_test(&stores[leader], predecessor_index)
        .await
        .unwrap();
    wait_for_progress(&stores[leader], |p| {
        p.purged_index == Some(predecessor_index)
    })
    .await;

    // Build the successor before beginning the transfer. Pause after its
    // verification and before the real publisher can retire the predecessor.
    // This makes the critical interleaving independent of snapshot build time.
    let publication = pause_consensus_snapshot_publication_for_test(&stores[leader]);
    let successor_index = append_consensus_padding_entry_for_test(&stores[leader], [0xE2; 16])
        .await
        .unwrap();
    trigger_consensus_snapshot_for_test(&stores[leader])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), publication.wait_prepared())
        .await
        .expect("successor is prepared before admitting the predecessor transfer");
    assert!(
        predecessor_path.exists(),
        "preparation must not retire the predecessor"
    );

    let paused = Arc::new(PausedSnapshotHandler {
        inner: stores[lagging].rpc_handler(),
        expected: original.clone(),
        expected_index: predecessor_index,
        first_chunk: Mutex::new(None),
        progress: tokio::sync::watch::channel(TransferProgress::default()).0,
        entered: tokio::sync::Notify::new(),
        released: AtomicBool::new(false),
        release: tokio::sync::Notify::new(),
    });
    paths
        .get(&(leader, lagging))
        .unwrap()
        .install(paused.clone())
        .await;
    assert_eq!(
        disconnected_term,
        stores[lagging].status().term,
        "the disconnected voter must not campaign while building the snapshot"
    );
    for peer in paths.values() {
        peer.set_enabled(true);
    }
    tokio::time::timeout(Duration::from_secs(10), paused.entered.notified())
        .await
        .expect("lagging voter receives the first non-final snapshot chunk");
    let prefix = paused.first_chunk.lock().unwrap().clone().unwrap();
    assert_eq!(original[..prefix.len()], prefix);

    publication.release();
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

    // Observe every leader metrics change: the old implementation reports
    // StorageIo(Snapshot, Read) as soon as transport reads the retired inode.
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            progress = wait_for_consensus_progress_for_test(&stores[leader], |p| {
                p.engine_state != ConsensusEngineStateForTest::Running
            }) => panic!("leader stopped after predecessor retirement: {progress:?}"),
            follower = async {
                let mut transfer = paused.progress.subscribe();
                transfer.wait_for(|progress| progress.complete).await.unwrap();
                wait_for_consensus_progress_for_test(&stores[lagging], |p| {
                    p.snapshot_index >= Some(predecessor_index)
                        && p.applied_index >= Some(successor_index)
                }).await
            } => {
                assert_eq!(ConsensusEngineStateForTest::Running, follower.engine_state, "{follower:?}");
                assert!(follower.snapshot_index >= Some(predecessor_index), "{follower:?}");
                assert!(follower.applied_index >= Some(successor_index), "{follower:?}");
            }
        }
    })
    .await
    .expect("lagging voter installs the retained stream and catches up");
    let transferred = paused.progress.borrow().clone();
    assert_eq!(transferred.bytes, original.len());
    assert!(
        transferred.chunks > 1 && transferred.complete,
        "{transferred:?}"
    );
    // Catch-up has refreshed this voter's leader contact. Restore campaigns
    // only now, so an expired isolation-era timer cannot race reconnection.
    stores[lagging].set_automatic_election_for_test(true);
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
