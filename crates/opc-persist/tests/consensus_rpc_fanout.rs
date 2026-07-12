use async_trait::async_trait;
use opc_persist::{
    AppendEntriesRequest, AppendEntriesResponse, ClusterMembership, ConsensusClock,
    ConsensusConfigStore, ConsensusPeer, InstallSnapshotRequest, InstallSnapshotResponse,
    RequestVoteRequest, RequestVoteResponse, Role, RollbackTarget, SqliteBackend, StoredConfig,
    TimeoutNowRequest, TimeoutNowResponse,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn test_audit_key() -> opc_persist::AuditKey {
    opc_persist::AuditKey::new([0xA5; 32]).unwrap()
}

async fn leader_store(
    temp_dir: &tempfile::TempDir,
    membership: Vec<usize>,
) -> Arc<ConsensusConfigStore> {
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(
            temp_dir.path().join("fanout.db"),
            true,
            0,
            test_audit_key(),
        )
        .await
        .unwrap(),
    );
    let store = Arc::new(
        ConsensusConfigStore::new(
            0,
            backend,
            Some(ClusterMembership {
                cluster_id: "fanout-test".to_string(),
                node_id: 0,
                voting_members: membership,
                non_voting_members: vec![],
                old_voting_members: None,
                removed_members: vec![],
                epoch: 1,
            }),
            Some(ConsensusClock {
                election_timeout_min: Duration::from_secs(60),
                election_timeout_max: Duration::from_secs(60),
                heartbeat_interval: Duration::from_secs(60),
                enable_timers: false,
            }),
        )
        .await
        .unwrap(),
    );
    {
        let mut state = store.state.lock().await;
        state.role = Role::Leader;
        state.current_term = 1;
    }
    store
}

#[derive(Debug)]
struct BoundedCatchupPeer {
    node_id: usize,
    append_calls: AtomicUsize,
}

impl BoundedCatchupPeer {
    fn new(node_id: usize) -> Self {
        Self {
            node_id,
            append_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ConsensusPeer for BoundedCatchupPeer {
    fn node_id(&self) -> usize {
        self.node_id
    }

    async fn request_vote(
        &self,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, opc_persist::PersistError> {
        Ok(RequestVoteResponse {
            term: req.term,
            vote_granted: true,
        })
    }

    async fn append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, opc_persist::PersistError> {
        let call = self.append_calls.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(AppendEntriesResponse {
            term: req.term,
            success: call > 64,
        })
    }

    async fn install_snapshot(
        &self,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, opc_persist::PersistError> {
        Ok(InstallSnapshotResponse {
            term: req.term,
            success: false,
        })
    }

    async fn load_latest_consensus_rpc(
        &self,
    ) -> Result<Option<StoredConfig>, opc_persist::PersistError> {
        Ok(None)
    }

    async fn load_rollback_consensus_rpc(
        &self,
        _target: RollbackTarget,
    ) -> Result<StoredConfig, opc_persist::PersistError> {
        Err(opc_persist::PersistError::rollback_not_found())
    }

    async fn timeout_now(
        &self,
        req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, opc_persist::PersistError> {
        Ok(TimeoutNowResponse {
            term: req.term,
            success: true,
        })
    }
}

async fn wait_for_calls(peer: &BoundedCatchupPeer, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while peer.append_calls.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn background_catchup_stops_at_64_rpcs_and_a_later_trigger_resumes() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = leader_store(&temp_dir, vec![0, 1]).await;
    let peer = Arc::new(BoundedCatchupPeer::new(1));
    store.add_peer(1, peer.clone()).await;
    store.state.lock().await.next_index.insert(1, 130);

    ConsensusConfigStore::trigger_replication_static(
        Arc::clone(&store.inner),
        Arc::clone(&store.peers),
        Arc::clone(&store.state),
        Arc::clone(&store.commit_notifier),
        store.node_id,
        Arc::clone(&store.metrics),
    );
    wait_for_calls(&peer, 64).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(peer.append_calls.load(Ordering::SeqCst), 64);

    ConsensusConfigStore::trigger_replication_static(
        Arc::clone(&store.inner),
        Arc::clone(&store.peers),
        Arc::clone(&store.state),
        Arc::clone(&store.commit_notifier),
        store.node_id,
        Arc::clone(&store.metrics),
    );
    wait_for_calls(&peer, 65).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(peer.append_calls.load(Ordering::SeqCst), 65);
}

#[tokio::test]
async fn synchronous_catchup_stops_at_64_rpcs_and_the_next_pass_resumes() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = leader_store(&temp_dir, vec![0, 1]).await;
    let peer = Arc::new(BoundedCatchupPeer::new(1));
    store.add_peer(1, peer.clone()).await;
    store.state.lock().await.next_index.insert(1, 130);

    store.replicate_to_peers_sync().await.unwrap();
    assert_eq!(peer.append_calls.load(Ordering::SeqCst), 64);

    store.replicate_to_peers_sync().await.unwrap();
    assert_eq!(peer.append_calls.load(Ordering::SeqCst), 65);
}

#[derive(Debug)]
struct BlockingReplicationPeer {
    node_id: usize,
    calls: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    release: Arc<tokio::sync::Semaphore>,
}

impl BlockingReplicationPeer {
    fn new(node_id: usize) -> Self {
        Self {
            node_id,
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }

    async fn wait_for_calls(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.calls.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replication RPC did not enter");
    }

    fn release_one(&self) {
        self.release.add_permits(1);
    }

    fn release_many(&self) {
        self.release.add_permits(128);
    }
}

#[async_trait]
impl ConsensusPeer for BlockingReplicationPeer {
    fn node_id(&self) -> usize {
        self.node_id
    }

    async fn request_vote(
        &self,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, opc_persist::PersistError> {
        Ok(RequestVoteResponse {
            term: req.term,
            vote_granted: true,
        })
    }

    async fn append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, opc_persist::PersistError> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let permit = Arc::clone(&self.release)
            .acquire_owned()
            .await
            .expect("test release semaphore closed");
        permit.forget();
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(AppendEntriesResponse {
            term: req.term,
            success: true,
        })
    }

    async fn install_snapshot(
        &self,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, opc_persist::PersistError> {
        Ok(InstallSnapshotResponse {
            term: req.term,
            success: true,
        })
    }

    async fn load_latest_consensus_rpc(
        &self,
    ) -> Result<Option<StoredConfig>, opc_persist::PersistError> {
        Ok(None)
    }

    async fn load_rollback_consensus_rpc(
        &self,
        _target: RollbackTarget,
    ) -> Result<StoredConfig, opc_persist::PersistError> {
        Err(opc_persist::PersistError::rollback_not_found())
    }

    async fn timeout_now(
        &self,
        req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, opc_persist::PersistError> {
        Ok(TimeoutNowResponse {
            term: req.term,
            success: true,
        })
    }
}

#[tokio::test]
async fn replication_passes_are_serialized_per_peer_and_background_triggers_coalesce() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = leader_store(&temp_dir, vec![0, 1]).await;
    let peer = Arc::new(BlockingReplicationPeer::new(1));
    store.add_peer(1, peer.clone()).await;

    ConsensusConfigStore::trigger_replication_static(
        Arc::clone(&store.inner),
        Arc::clone(&store.peers),
        Arc::clone(&store.state),
        Arc::clone(&store.commit_notifier),
        store.node_id,
        Arc::clone(&store.metrics),
    );
    peer.wait_for_calls(1).await;

    // Every additional background trigger for this peer must coalesce while
    // the first logical pass is active. A synchronous durability pass waits on
    // the same gate instead of creating an overlapping RPC stream.
    for _ in 0..32 {
        ConsensusConfigStore::trigger_replication_static(
            Arc::clone(&store.inner),
            Arc::clone(&store.peers),
            Arc::clone(&store.state),
            Arc::clone(&store.commit_notifier),
            store.node_id,
            Arc::clone(&store.metrics),
        );
    }
    let sync_store = Arc::clone(&store);
    let sync = tokio::spawn(async move { sync_store.replicate_to_peers_sync().await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(peer.max_active.load(Ordering::SeqCst), 1);

    peer.release_one();
    peer.wait_for_calls(2).await;
    assert_eq!(peer.max_active.load(Ordering::SeqCst), 1);
    peer.release_one();
    tokio::time::timeout(Duration::from_secs(2), sync)
        .await
        .expect("synchronous pass remained blocked")
        .unwrap()
        .unwrap();

    // Do not leave a very late scheduled background task blocked in the test
    // runtime. Such a task is still serialized; it simply started after the
    // active pass ended and therefore was not eligible for coalescing.
    peer.release_many();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let calls_before_later_trigger = peer.calls.load(Ordering::SeqCst);

    // Coalescing is not a permanent suppression: a later trigger starts a new
    // bounded pass after the active one has completed.
    ConsensusConfigStore::trigger_replication_static(
        Arc::clone(&store.inner),
        Arc::clone(&store.peers),
        Arc::clone(&store.state),
        Arc::clone(&store.commit_notifier),
        store.node_id,
        Arc::clone(&store.metrics),
    );
    peer.wait_for_calls(calls_before_later_trigger + 1).await;
    assert_eq!(peer.max_active.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stale_replication_response_cannot_regress_a_newer_term_progress_cursor() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = leader_store(&temp_dir, vec![0, 1]).await;
    let peer = Arc::new(BlockingReplicationPeer::new(1));
    store.add_peer(1, peer.clone()).await;
    store.state.lock().await.next_index.insert(1, 1);

    ConsensusConfigStore::trigger_replication_static(
        Arc::clone(&store.inner),
        Arc::clone(&store.peers),
        Arc::clone(&store.state),
        Arc::clone(&store.commit_notifier),
        store.node_id,
        Arc::clone(&store.metrics),
    );
    peer.wait_for_calls(1).await;

    store.inner.consensus_set_state(2, None).await.unwrap();
    {
        let mut state = store.state.lock().await;
        state.current_term = 2;
        state.role = Role::Leader;
        state.next_index.insert(1, 7);
        state.match_index.insert(1, 6);
    }
    peer.release_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while peer.active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stale replication response did not complete");

    let state = store.state.lock().await;
    assert_eq!(state.current_term, 2);
    assert_eq!(state.next_index.get(&1), Some(&7));
    assert_eq!(state.match_index.get(&1), Some(&6));
}

#[derive(Debug)]
struct BarrierVotePeer {
    node_id: usize,
    entered: Arc<tokio::sync::Barrier>,
    release: Arc<tokio::sync::Barrier>,
}

#[async_trait]
impl ConsensusPeer for BarrierVotePeer {
    fn node_id(&self) -> usize {
        self.node_id
    }

    async fn request_vote(
        &self,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, opc_persist::PersistError> {
        self.entered.wait().await;
        self.release.wait().await;
        Ok(RequestVoteResponse {
            term: req.term,
            vote_granted: true,
        })
    }

    async fn append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, opc_persist::PersistError> {
        Ok(AppendEntriesResponse {
            term: req.term,
            success: true,
        })
    }

    async fn install_snapshot(
        &self,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, opc_persist::PersistError> {
        Ok(InstallSnapshotResponse {
            term: req.term,
            success: true,
        })
    }

    async fn load_latest_consensus_rpc(
        &self,
    ) -> Result<Option<StoredConfig>, opc_persist::PersistError> {
        Ok(None)
    }

    async fn load_rollback_consensus_rpc(
        &self,
        _target: RollbackTarget,
    ) -> Result<StoredConfig, opc_persist::PersistError> {
        Err(opc_persist::PersistError::rollback_not_found())
    }

    async fn timeout_now(
        &self,
        req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, opc_persist::PersistError> {
        Ok(TimeoutNowResponse {
            term: req.term,
            success: true,
        })
    }
}

#[tokio::test]
async fn election_vote_requests_are_fanned_out_concurrently() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = leader_store(&temp_dir, vec![0, 1, 2]).await;
    store.state.lock().await.role = Role::Follower;
    let entered = Arc::new(tokio::sync::Barrier::new(3));
    let release = Arc::new(tokio::sync::Barrier::new(3));
    for node_id in [1, 2] {
        store
            .add_peer(
                node_id,
                Arc::new(BarrierVotePeer {
                    node_id,
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                }),
            )
            .await;
    }

    let campaign_store = Arc::clone(&store);
    let campaign = tokio::spawn(async move { campaign_store.campaign().await });
    tokio::time::timeout(Duration::from_millis(250), entered.wait())
        .await
        .expect("both vote requests were not in flight together");
    release.wait().await;
    campaign.await.unwrap().unwrap();
    assert_eq!(store.get_role().await, Role::Leader);
}
