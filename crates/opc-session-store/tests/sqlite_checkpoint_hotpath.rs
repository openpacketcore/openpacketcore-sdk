//! Deterministic real-file qualification for SQLite's automatic checkpoint.
//!
//! This target is deliberately feature-gated. It opens the normal
//! `SqliteSessionBackend` writer profile through a non-default test VFS, then
//! drives an actual three-voter fixed-quorum request through Openraft.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity};
use opc_session_store::{
    derive_fixed_durable_quorum_consensus_identity, ConsensusSessionStore,
    PlacementResiliencePolicy, QuorumReplicaDescriptor, QuorumTopologyConfig,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionBackend, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SqliteSessionBackend, ValidatedQuorumTopology,
};
use opc_sqlite_file_control_sys::{
    block_test_main_sync, install_test_main_sync_block_vfs, TEST_MAIN_SYNC_BLOCK_VFS_NAME,
};

const VOTERS: usize = 3;
const FIXED_QUORUM_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

fn main_sync_vfs_test_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[derive(Clone)]
struct LoopbackPeer {
    target: SessionConsensusNodeId,
    identity: ConsensusIdentity,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
}

impl LoopbackPeer {
    fn new(target: SessionConsensusNodeId, identity: ConsensusIdentity) -> Self {
        Self {
            target,
            identity,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }

    async fn clear(&self) {
        *self.handler.write().await = None;
    }
}

impl fmt::Debug for LoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoopbackPeer(<redacted>)")
    }
}

#[async_trait]
impl SessionConsensusPeer for LoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.target
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        Some(self.identity)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("sdk-704-voter-{index}")).expect("fixed test replica ID")
}

fn members() -> Vec<QuorumReplicaDescriptor> {
    (0..VOTERS)
        .map(|index| {
            QuorumReplicaDescriptor::new(
                replica_id(index),
                ReplicaEndpoint::new(format!("sdk-704-voter-{index}.invalid"), 7443)
                    .expect("fixed test endpoint"),
                ReplicaTlsIdentity::new(format!("spiffe://test/session/sdk-704/{index}"))
                    .expect("fixed test TLS identity"),
                ReplicaFailureDomain::new(format!("sdk-704-zone-{index}"))
                    .expect("fixed test failure domain"),
                ReplicaBackingIdentity::new(format!("sdk-704-backing-{index}"))
                    .expect("fixed test backing identity"),
            )
        })
        .collect()
}

fn fixed_topology(
    local_index: usize,
    members: Vec<QuorumReplicaDescriptor>,
) -> ValidatedQuorumTopology {
    let cluster_id =
        ConsensusClusterId::new("sdk-704-checkpoint-hotpath").expect("fixed test cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("fixed test configuration epoch");
    let placement_policy = PlacementResiliencePolicy::default();
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let identity = derive_fixed_durable_quorum_consensus_identity(
        cluster_id,
        epoch,
        &fingerprints,
        placement_policy,
    );
    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
        QuorumTopologyConfig::new_consensus(replica_id(local_index), members, identity),
        placement_policy,
    )
    .expect("exact three-voter fixed topology")
}

async fn start_fixed_quorum_with_main_sync_vfs(
    directory: &Path,
) -> (
    Vec<ConsensusSessionStore>,
    Vec<SqliteSessionBackend>,
    Vec<Arc<LoopbackPeer>>,
    Vec<PathBuf>,
) {
    let members = members();
    let topologies = (0..VOTERS)
        .map(|index| fixed_topology(index, members.clone()))
        .collect::<Vec<_>>();
    let node_ids = topologies
        .iter()
        .map(|topology| {
            topology
                .local_consensus_node_id()
                .expect("fixed voter node ID")
        })
        .collect::<Vec<_>>();
    let database_paths = (0..VOTERS)
        .map(|index| directory.join(format!("voter-{index}.sqlite")))
        .collect::<Vec<PathBuf>>();
    let backends = database_paths
        .iter()
        .map(|path| {
            // This differs from production only at `Connection::open`: both
            // paths call `finish_file_open` and thus the identical primary
            // writer WAL/EXTRA/autocheckpoint profile and Raft SQLite state.
            SqliteSessionBackend::open_with_vfs_for_test(path, TEST_MAIN_SYNC_BLOCK_VFS_NAME)
                .expect("open VFS-backed fixed voter")
        })
        .collect::<Vec<_>>();

    let identity = topologies[0]
        .consensus_identity()
        .expect("fixed quorum identity");
    let mut peers = BTreeMap::new();
    for source in 0..VOTERS {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                peers.insert(
                    (source, target),
                    Arc::new(LoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::with_capacity(VOTERS);
    for source in 0..VOTERS {
        let configured_peers = (0..VOTERS)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = peers
                    .get(&(source, target))
                    .expect("exact fixed loopback peer")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        stores.push(
            ConsensusSessionStore::open_fixed_durable_quorum(
                topologies[source].clone(),
                backends[source].clone(),
                directory.join(format!("snapshots-{source}")),
                configured_peers,
            )
            .await
            .expect("open exact fixed voter"),
        );
    }
    for ((_, target), peer) in &peers {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for initialized in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        initialized.expect("initialize exact fixed quorum");
    }
    assert!(stores.iter().all(|store| {
        store
            .consumer_scope()
            .is_ok_and(|scope| scope.consensus_identity() == identity)
    }));
    (
        stores,
        backends,
        peers.into_values().collect(),
        database_paths,
    )
}

async fn ready_leader(stores: &[ConsensusSessionStore]) -> usize {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let readiness = futures_util::future::join_all(
                stores
                    .iter()
                    .map(ConsensusSessionStore::probe_durable_readiness),
            )
            .await;
            let statuses = stores
                .iter()
                .map(ConsensusSessionStore::status)
                .collect::<Vec<_>>();
            if readiness.iter().all(|report| report.is_ready())
                && statuses.iter().all(|status| status.admitted)
                && statuses
                    .first()
                    .and_then(|status| status.leader_id)
                    .is_some_and(|leader| {
                        statuses
                            .iter()
                            .all(|status| status.leader_id == Some(leader))
                    })
            {
                let leader = statuses[0].leader_id.expect("known fixed-quorum leader");
                return statuses
                    .iter()
                    .position(|status| status.node_id == leader)
                    .expect("leader is an exact fixed voter");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixed quorum reaches durable readiness")
}

fn reset_proactive_checkpoint_cadence(stores: &[ConsensusSessionStore]) -> usize {
    let batch =
        usize::try_from(ConsensusSessionStore::proactive_checkpoint_cadence_batch_for_test())
            .expect("checkpoint cadence fits test loop");
    assert!(
        batch > 1,
        "proactive checkpoint cadence cannot run per write"
    );
    for store in stores {
        store.reset_proactive_checkpoint_cadence_for_test();
        assert_eq!(
            store.proactive_checkpoint_cadence_remaining_for_test(),
            Some(u64::try_from(batch).expect("checkpoint cadence is representable")),
            "each file-backed store starts the exact fixed checkpoint cadence"
        );
    }
    batch
}

async fn write_one_proactive_checkpoint_cadence_batch(
    stores: &[ConsensusSessionStore],
    leader: usize,
    batch: usize,
) {
    for _ in 0..batch {
        tokio::time::timeout(
            FIXED_QUORUM_OPERATION_TIMEOUT,
            stores[leader].max_replication_sequence(),
        )
        .await
        .expect("accepted response completes while filling checkpoint cadence")
        .expect("fixed-quorum response succeeds while filling checkpoint cadence");
    }
}

async fn shutdown_fixed_quorum(stores: &[ConsensusSessionStore], peers: &[Arc<LoopbackPeer>]) {
    for peer in peers {
        peer.clear().await;
    }
    for shutdown in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::shutdown)).await
    {
        shutdown.expect("shut down exact fixed quorum");
    }
}

fn checkpoint_attempts(stores: &[ConsensusSessionStore]) -> u64 {
    stores
        .iter()
        .map(|store| store.diagnostic_snapshot().proactive_checkpoint_attempts)
        .sum()
}

fn checkpoint_completions(stores: &[ConsensusSessionStore]) -> u64 {
    stores
        .iter()
        .map(|store| store.diagnostic_snapshot().proactive_checkpoint_completed)
        .sum()
}

fn checkpoint_failures(stores: &[ConsensusSessionStore]) -> u64 {
    stores
        .iter()
        .map(|store| store.diagnostic_snapshot().proactive_checkpoint_failures)
        .sum()
}

fn assert_fixed_checkpoint_resources(stores: &[ConsensusSessionStore]) {
    assert!(stores.iter().all(|store| {
        let snapshot = store.diagnostic_snapshot();
        snapshot.proactive_checkpoint_queue_high_water <= 1
            && snapshot.proactive_checkpoint_worker_high_water <= 1
    }));
    assert!(stores.iter().any(|store| {
        let snapshot = store.diagnostic_snapshot();
        snapshot.proactive_checkpoint_queue_high_water == 1
            && snapshot.proactive_checkpoint_worker_high_water == 1
    }));
}

async fn wait_for_checkpoint(
    stores: &[ConsensusSessionStore],
    predicate: impl Fn() -> bool,
    expectation: &'static str,
) {
    tokio::time::timeout(FIXED_QUORUM_OPERATION_TIMEOUT, async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect(expectation);
    assert_fixed_checkpoint_resources(stores);
}

fn exact_machine_state(path: &Path) -> (i64, Vec<u8>, Option<String>, i64) {
    let connection = rusqlite::Connection::open(path).expect("open committed SQLite state");
    connection
        .query_row(
            "SELECT application_sequence, last_digest, logical_time, watch_sequence \
             FROM consensus_machine WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read exact committed consensus machine state")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn green_proactive_checkpoint_main_sync_does_not_block_accepted_fixed_quorum_response() {
    let _vfs_test_gate = main_sync_vfs_test_gate().lock().await;
    install_test_main_sync_block_vfs().expect("register main-sync blocking VFS");
    let directory = tempfile::tempdir().expect("checkpoint RED directory");
    let (stores, backends, peers, database_paths) =
        start_fixed_quorum_with_main_sync_vfs(directory.path()).await;
    let leader = ready_leader(&stores).await;
    let cadence_batch = reset_proactive_checkpoint_cadence(&stores);

    for backend in &backends {
        assert_eq!(
            backend
                .wal_autocheckpoint_for_test()
                .await
                .expect("read normal primary checkpoint threshold"),
            1000,
            "the synchronous automatic-checkpoint fallback remains unchanged"
        );
    }
    let attempts_before = checkpoint_attempts(&stores);
    let completions_before = checkpoint_completions(&stores);
    let mut main_sync = block_test_main_sync();
    let stores_for_response = stores.clone();
    let response = tokio::spawn(async move {
        write_one_proactive_checkpoint_cadence_batch(&stores_for_response, leader, cadence_batch)
            .await;
    });

    assert!(
        tokio::task::block_in_place(|| main_sync.wait_until_main_sync(Duration::from_secs(2))),
        "one proactive PASSIVE checkpoint must enter a main-file sync"
    );
    tokio::time::timeout(FIXED_QUORUM_OPERATION_TIMEOUT, response)
        .await
        .expect("held proactive checkpoint does not block accepted response")
        .expect("fixed-quorum cadence task succeeds");
    assert!(
        checkpoint_attempts(&stores) > attempts_before,
        "the held main sync belongs to a proactively signalled checkpoint lane"
    );
    assert!(
        main_sync.main_sync_count() >= 1,
        "the VFS observed main-file sync"
    );
    assert!(
        main_sync.wal_sync_count() >= 1,
        "the VFS delegated WAL commit sync"
    );

    // These are real V2/consensus writes. While the sole held lane owns its
    // checkpoint, two further fixed cadences can retain at most its one
    // pending request; the following full-lane cadence cannot allocate more
    // queue capacity or make an accepted response await the worker.
    write_one_proactive_checkpoint_cadence_batch(&stores, leader, cadence_batch).await;
    write_one_proactive_checkpoint_cadence_batch(&stores, leader, cadence_batch).await;
    assert_fixed_checkpoint_resources(&stores);
    let expected_state = exact_machine_state(&database_paths[leader]);

    main_sync.release();
    wait_for_checkpoint(
        &stores,
        || checkpoint_completions(&stores) > completions_before,
        "released proactive checkpoint completes",
    )
    .await;
    shutdown_fixed_quorum(&stores, &peers).await;
    drop(stores);
    drop(backends);

    let reopened = SqliteSessionBackend::open(&database_paths[leader])
        .expect("reopen durable consensus backing database");
    assert_eq!(
        exact_machine_state(&database_paths[leader]),
        expected_state,
        "restart reads the exact committed consensus state after checkpoint drain"
    );
    drop(reopened);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proactive_checkpoint_failure_is_recorded_and_next_checkpoint_recovers() {
    let _vfs_test_gate = main_sync_vfs_test_gate().lock().await;
    install_test_main_sync_block_vfs().expect("register main-sync blocking VFS");
    let directory = tempfile::tempdir().expect("checkpoint worker failure directory");
    let (stores, _backends, peers, _database_paths) =
        start_fixed_quorum_with_main_sync_vfs(directory.path()).await;
    let leader = ready_leader(&stores).await;
    let cadence_batch = reset_proactive_checkpoint_cadence(&stores);

    let failures_before = checkpoint_failures(&stores);
    let mut main_sync = block_test_main_sync();
    write_one_proactive_checkpoint_cadence_batch(&stores, leader, cadence_batch).await;
    assert!(
        tokio::task::block_in_place(|| main_sync.wait_until_main_sync(Duration::from_secs(2))),
        "the deterministic failure seam holds the proactive worker checkpoint"
    );
    main_sync.fail_and_release();
    wait_for_checkpoint(
        &stores,
        || checkpoint_failures(&stores) > failures_before,
        "one PASSIVE checkpoint failure is counted",
    )
    .await;

    let completions_before = checkpoint_completions(&stores);
    write_one_proactive_checkpoint_cadence_batch(&stores, leader, cadence_batch).await;
    wait_for_checkpoint(
        &stores,
        || checkpoint_completions(&stores) > completions_before,
        "checkpoint worker recovers after a one-shot SQLite failure",
    )
    .await;
    shutdown_fixed_quorum(&stores, &peers).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proactive_checkpoint_shutdown_waits_for_held_worker_then_reopens() {
    let _vfs_test_gate = main_sync_vfs_test_gate().lock().await;
    install_test_main_sync_block_vfs().expect("register main-sync blocking VFS");
    let directory = tempfile::tempdir().expect("checkpoint shutdown directory");
    let (stores, backends, peers, database_paths) =
        start_fixed_quorum_with_main_sync_vfs(directory.path()).await;
    let leader = ready_leader(&stores).await;
    let cadence_batch = reset_proactive_checkpoint_cadence(&stores);

    let mut main_sync = block_test_main_sync();
    write_one_proactive_checkpoint_cadence_batch(&stores, leader, cadence_batch).await;
    assert!(
        tokio::task::block_in_place(|| main_sync.wait_until_main_sync(Duration::from_secs(2))),
        "proactive worker is held at its main-file checkpoint sync"
    );
    let expected_state = exact_machine_state(&database_paths[leader]);

    let stores_for_shutdown = stores.clone();
    let peers_for_shutdown = peers.clone();
    let mut shutdown = Box::pin(tokio::spawn(async move {
        shutdown_fixed_quorum(&stores_for_shutdown, &peers_for_shutdown).await;
    }));
    tokio::task::yield_now().await;
    assert!(
        matches!(futures_util::poll!(&mut shutdown), std::task::Poll::Pending),
        "store shutdown retains the held lane instead of detaching it"
    );
    main_sync.release();
    tokio::time::timeout(FIXED_QUORUM_OPERATION_TIMEOUT, shutdown)
        .await
        .expect("released checkpoint permits worker join")
        .expect("shutdown task succeeds");
    drop(stores);
    drop(backends);

    let reopened = SqliteSessionBackend::open(&database_paths[leader])
        .expect("reopen after worker retirement");
    assert_eq!(
        exact_machine_state(&database_paths[leader]),
        expected_state,
        "worker retirement leaves exact committed consensus state"
    );
    drop(reopened);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proactive_checkpoint_cancelled_shutdown_retries_the_retained_worker_join() {
    let _vfs_test_gate = main_sync_vfs_test_gate().lock().await;
    install_test_main_sync_block_vfs().expect("register main-sync blocking VFS");
    let directory = tempfile::tempdir().expect("checkpoint cancellation directory");
    let (stores, backends, peers, database_paths) =
        start_fixed_quorum_with_main_sync_vfs(directory.path()).await;
    let leader = ready_leader(&stores).await;
    let cadence_batch = reset_proactive_checkpoint_cadence(&stores);
    let mut worker_observation =
        backends[leader].proactive_checkpoint_worker_observation_for_test();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            worker_observation.wait_for_worker_count(1),
        )
        .await
        .expect("leader checkpoint worker starts"),
        "the selected file-backed store owns one checkpoint worker"
    );

    let mut main_sync = block_test_main_sync();
    write_one_proactive_checkpoint_cadence_batch(&stores, leader, cadence_batch).await;
    assert!(
        tokio::task::block_in_place(|| main_sync.wait_until_main_sync(Duration::from_secs(2))),
        "proactive worker is held at its main-file checkpoint sync"
    );
    assert!(
        stores[leader]
            .diagnostic_snapshot()
            .proactive_checkpoint_attempts
            > 0,
        "the selected shutdown target has entered its proactive checkpoint lane"
    );
    let expected_state = exact_machine_state(&database_paths[leader]);

    for peer in &peers {
        peer.clear().await;
    }
    let shutdown_join = backends[leader].observe_proactive_checkpoint_shutdown_join_for_test();
    let leader_store = stores[leader].clone();
    let first_shutdown = tokio::spawn(async move { leader_store.shutdown().await });
    assert!(
        tokio::task::block_in_place(|| shutdown_join.wait_until_entered(Duration::from_secs(2))),
        "first shutdown owns the shared worker join handle before cancellation"
    );
    first_shutdown.abort();
    assert!(
        first_shutdown
            .await
            .expect_err("aborted first shutdown task")
            .is_cancelled(),
        "the first shutdown is cancelled while it awaits the held worker"
    );

    let leader_store = stores[leader].clone();
    let mut retry_shutdown = Box::pin(tokio::spawn(async move { leader_store.shutdown().await }));
    tokio::task::yield_now().await;
    assert!(
        matches!(
            futures_util::poll!(&mut retry_shutdown),
            std::task::Poll::Pending
        ),
        "retry shutdown keeps awaiting the retained worker rather than a detached task"
    );
    main_sync.release();
    tokio::time::timeout(FIXED_QUORUM_OPERATION_TIMEOUT, retry_shutdown)
        .await
        .expect("released checkpoint permits retry join")
        .expect("retry shutdown task succeeds")
        .expect("leader store shuts down after retry");
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            worker_observation.wait_for_worker_count(0),
        )
        .await
        .expect("retry shutdown retires the worker before reopen"),
        "the retained worker exits before reopening its SQLite backing file"
    );

    for (index, store) in stores.iter().enumerate() {
        if index != leader {
            store.shutdown().await.expect("shut down remaining voter");
        }
    }
    drop(stores);
    drop(backends);

    let reopened = SqliteSessionBackend::open(&database_paths[leader])
        .expect("reopen after cancellation-safe worker retirement");
    assert_eq!(
        exact_machine_state(&database_paths[leader]),
        expected_state,
        "retry join leaves exact committed consensus state"
    );
    drop(reopened);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proactive_checkpoint_idle_shutdown_retains_its_stop_signal() {
    let _vfs_test_gate = main_sync_vfs_test_gate().lock().await;
    install_test_main_sync_block_vfs().expect("register main-sync blocking VFS");
    let directory = tempfile::tempdir().expect("checkpoint idle shutdown directory");
    let (stores, backends, peers, _database_paths) =
        start_fixed_quorum_with_main_sync_vfs(directory.path()).await;
    let leader = ready_leader(&stores).await;
    let cadence_batch = reset_proactive_checkpoint_cadence(&stores);

    // This guard stops the leader's lane precisely after its stop-state check
    // and before its next receive registration. A non-retained notification
    // could be lost in this gap and leave shutdown waiting forever.
    let idle_wait = backends[leader].hold_proactive_checkpoint_before_idle_receive_for_test();
    write_one_proactive_checkpoint_cadence_batch(&stores, leader, cadence_batch).await;
    assert!(
        tokio::task::block_in_place(|| idle_wait.wait_until_entered(Duration::from_secs(2))),
        "leader checkpoint worker reaches the deterministic idle receive seam"
    );

    for peer in &peers {
        peer.clear().await;
    }
    let leader_store = stores[leader].clone();
    let mut shutdown = Box::pin(tokio::spawn(async move { leader_store.shutdown().await }));
    tokio::task::yield_now().await;
    assert!(
        matches!(futures_util::poll!(&mut shutdown), std::task::Poll::Pending),
        "shutdown waits for the deliberately paused idle checkpoint worker"
    );
    idle_wait.release();
    tokio::time::timeout(FIXED_QUORUM_OPERATION_TIMEOUT, shutdown)
        .await
        .expect("retained stop state releases the idle worker")
        .expect("shutdown task succeeds")
        .expect("leader store shuts down");
    for (index, store) in stores.iter().enumerate() {
        if index != leader {
            store.shutdown().await.expect("shut down remaining voter");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proactive_checkpoint_worker_retires_when_the_final_store_is_dropped() {
    let _vfs_test_gate = main_sync_vfs_test_gate().lock().await;
    install_test_main_sync_block_vfs().expect("register main-sync blocking VFS");
    let directory = tempfile::tempdir().expect("checkpoint worker retirement directory");
    let (stores, backends, peers, _database_paths) =
        start_fixed_quorum_with_main_sync_vfs(directory.path()).await;
    let leader = ready_leader(&stores).await;
    let mut observation = backends[leader].proactive_checkpoint_worker_observation_for_test();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), observation.wait_for_worker_count(1),)
            .await
            .expect("store-scoped checkpoint worker starts"),
        "the selected file-backed store owns one checkpoint worker"
    );

    // No explicit shutdown occurs here. Clearing the loopback handler releases
    // its final store reference; then dropping the stores must drop the lane
    // sender. The idle receiver returns `None` and releases its secondary
    // SQLite connection, witnessed by the fixed worker count returning to 0.
    for peer in &peers {
        peer.clear().await;
    }
    drop(peers);
    drop(stores);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), observation.wait_for_worker_count(0),)
            .await
            .expect("final store drop retires the checkpoint worker"),
        "no idle worker or secondary SQLite connection self-retains"
    );
}
