//! A former leader must stop reading its suffix before conflict truncation.

use super::*;
use opc_consensus::engine::raft::AppendEntriesResponse;
use opc_consensus::engine::{CommittedLeaderId, LogId, Vote};

// The entries vector is deliberately empty. Keep the exact engine request
// field order and use its real vote/log types without exposing a storage port.
#[derive(Serialize)]
struct ConflictingEmptyAppend {
    vote: Vote<SessionConsensusNodeId>,
    prev_log_id: Option<LogId<SessionConsensusNodeId>>,
    entries: Vec<()>,
    leader_commit: Option<LogId<SessionConsensusNodeId>>,
}

// A follower may accept only the already matched prefix of an append. Keep
// returning that exact prefix for this one proposal, without ever delivering
// its entry. Unlike a timed delay, this cannot arrive after the cut changes.
#[derive(Debug)]
struct PrefixOnlyAppend {
    inner: Arc<dyn SessionConsensusRpcHandler>,
    request_id: [u8; 16],
    matched: LogId<SessionConsensusNodeId>,
    responses: Arc<AtomicUsize>,
}

#[async_trait]
impl SessionConsensusRpcHandler for PrefixOnlyAppend {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::AppendEntries
            && contains_bytes(&request.payload, &self.request_id)
        {
            self.responses.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            let reply: Result<
                AppendEntriesResponse<SessionConsensusNodeId>,
                RaftError<SessionConsensusNodeId>,
            > = Ok(AppendEntriesResponse::PartialSuccess(Some(self.matched)));
            return SessionConsensusWireResponse {
                result: Ok(encode_bounded(&reply).expect("bounded exact prefix reply")),
            };
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

fn retained_sql_log_id(cluster: &TestCluster, node: usize) -> LogId<SessionConsensusNodeId> {
    let connection = rusqlite::Connection::open_with_flags(
        cluster
            ._directory
            .path()
            .join(format!("node-{node}.sqlite")),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("independent read-only log witness");
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT entry_json FROM consensus_log ORDER BY log_index DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("physical retained log entry");
    #[derive(Deserialize)]
    struct LogIdentity {
        log_id: LogId<SessionConsensusNodeId>,
    }
    serde_json::from_slice::<LogIdentity>(&bytes)
        .expect("independent exact log identity")
        .log_id
}

fn retained_sql_log_end(cluster: &TestCluster, node: usize) -> u64 {
    retained_sql_log_id(cluster, node).index
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_leader_stops_replication_before_truncating_its_uncommitted_suffix() {
    let mut cluster = TestCluster::start().await;
    cluster._directory.disable_cleanup(true);
    cluster._snapshot_directory.disable_cleanup(true);
    eprintln!(
        "sdk_stepdown_fixture sql={:?} snapshots={:?}",
        cluster._directory.path(),
        cluster._snapshot_directory.path(),
    );
    let (leader, _, term) = cluster.observed_leader();
    let store = &cluster.stores[leader];
    store.activate_fenced_transition_capability().await.unwrap();
    cluster.wait_all_ready(RECOVERY_TIMEOUT).await.unwrap();
    let key = session_key(b"stepdown-uncommitted-suffix");
    let observation = store.observe_fenced_transition(&key).await.unwrap();
    let (request, _) = fenced_acquire_create_request(
        key,
        owner("stepdown-suffix-owner"),
        observation.current_fence(),
        [0xD7; 16],
        Duration::from_secs(30),
        b"sealed-stepdown-suffix",
    );
    let before_id = retained_sql_log_id(&cluster, leader);
    let before = before_id.index;
    let mut response_counts = Vec::new();
    for follower in 0..MEMBER_COUNT {
        if follower == leader {
            continue;
        }
        assert_eq!(retained_sql_log_id(&cluster, follower), before_id);
        let responses = Arc::new(AtomicUsize::new(0));
        cluster.paths[&(leader, follower)].install(Arc::new(PrefixOnlyAppend {
            inner: cluster.stores[follower].rpc_handler(),
            request_id: *request.request_id().as_bytes(),
            matched: before_id,
            responses: responses.clone(),
        }));
        response_counts.push(responses);
    }
    // Retain only this leader's controlled outbound streams. A follower
    // must not elect a different committed leader in the term used by the
    // explicit higher-vote RPC below, including during the public timeout.
    for ((sender, _), path) in &cluster.paths {
        if *sender != leader {
            path.set_enabled(false);
        }
    }
    let outcome = store.fenced_transition(request.clone()).await;
    assert!(matches!(
        outcome,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    ));
    assert!(response_counts
        .iter()
        .all(|count| count.load(Ordering::SeqCst) > 1));
    let tail = retained_sql_log_end(&cluster, leader);
    assert_eq!(
        tail,
        before + 1,
        "the original public operation appended a real suffix"
    );
    assert!(store.status().applied_index < Some(tail));
    for follower in 0..MEMBER_COUNT {
        if follower != leader {
            assert!(retained_sql_log_end(&cluster, follower) < tail);
        }
    }

    let successor = (0..MEMBER_COUNT).find(|node| *node != leader).unwrap();
    let successor_id = cluster.stores[successor].status().node_id;
    let identity = consensus_identity(&(0..MEMBER_COUNT).map(member).collect::<Vec<_>>());
    let higher_vote = Vote::new_committed(term + 1, successor_id);
    let rpc = ConflictingEmptyAppend {
        vote: higher_vote,
        prev_log_id: Some(LogId::new(
            CommittedLeaderId::new(term + 1, successor_id),
            tail,
        )),
        entries: Vec::new(),
        leader_commit: None,
    };
    let envelope = SessionConsensusWireRequest::try_new(
        identity,
        successor_id,
        SessionConsensusRpcFamily::AppendEntries,
        encode_bounded(&rpc).expect("bounded conflicting append"),
    )
    .unwrap();
    let response = tokio::time::timeout(
        RECOVERY_TIMEOUT,
        store.rpc_handler().handle(successor_id, envelope),
    )
    .await
    .expect("configured higher-vote peer completes conflict handling");
    let decoded: Result<
        AppendEntriesResponse<SessionConsensusNodeId>,
        RaftError<SessionConsensusNodeId>,
    > = decode_bounded(&response.result.expect("scoped append transport")).unwrap();
    assert_eq!(decoded, Ok(AppendEntriesResponse::Conflict));
    assert_eq!(retained_sql_log_end(&cluster, leader), tail - 1);
    assert!(store.status().term > term);
    assert_ne!(store.status().leader_id, Some(store.status().node_id));

    // The removed suffix stays absent during the original one-second
    // negative guard. It is not a timeout for recovery or a storage exemption.
    let negative_guard = Instant::now() + Duration::from_secs(1);
    loop {
        let health = store.persistence_health();
        assert!(
            health.engine_running && health.storage_failure.is_none(),
            "a superseded replication reader killed the recovering voter: {health:?}"
        );
        assert!(retained_sql_log_end(&cluster, leader) < tail);
        if Instant::now() >= negative_guard {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    for follower in 0..MEMBER_COUNT {
        if follower != leader {
            cluster.paths[&(leader, follower)].install(cluster.stores[follower].rpc_handler());
        }
    }
    for path in cluster.paths.values() {
        path.set_enabled(true);
    }
    cluster.wait_all_ready(RECOVERY_TIMEOUT).await.unwrap();
    assert!(matches!(
        store.fenced_transition_status(&request).await.unwrap(),
        FencedTransitionStatus::NotFound
    ));
    let committed = store.fenced_transition(request.clone()).await.unwrap();
    assert_eq!(
        store.fenced_transition(request.clone()).await.unwrap(),
        committed
    );
    assert!(matches!(
        store.fenced_transition_status(&request).await.unwrap(),
        FencedTransitionStatus::Recorded(result) if result.as_ref() == &Ok(committed)
    ));
    for store in &cluster.stores {
        store.shutdown().await.unwrap();
    }
}
