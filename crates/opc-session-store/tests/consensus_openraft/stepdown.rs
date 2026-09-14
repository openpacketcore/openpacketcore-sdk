//! A former leader must stop reading its suffix before conflict truncation.

use super::*;
use opc_consensus::engine::raft::AppendEntriesResponse;
use opc_consensus::engine::{LogId, Vote};

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
    prefix_only: Arc<AtomicBool>,
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
        if self.prefix_only.load(Ordering::SeqCst) {
            return SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Unavailable),
            };
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

fn retained_sql_log_id(cluster: &TestCluster, node: usize) -> LogId<SessionConsensusNodeId> {
    retained_sql_log_id_at(cluster, node, None)
}

fn retained_sql_log_id_at(
    cluster: &TestCluster,
    node: usize,
    index: Option<u64>,
) -> LogId<SessionConsensusNodeId> {
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
            "SELECT entry_json FROM consensus_log WHERE (?1 IS NULL OR log_index = ?1) ORDER BY log_index DESC LIMIT 1",
            [index],
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
    let _election_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("existing election qualification permit");
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
    let setup_deadline = tokio::time::Instant::now() + RECOVERY_TIMEOUT;
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
    // The observation commits a logical-time entry on a majority. Establish
    // the exact persisted prefix on every voter before installing the fault;
    // readiness before that observation does not prove its final entry arrived.
    tokio::time::timeout_at(setup_deadline, async {
        loop {
            if (0..MEMBER_COUNT).all(|node| retained_sql_log_id(&cluster, node) == before_id) {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("all voters persist the exact setup prefix before the fault");
    assert!(
        tokio::time::Instant::now() <= setup_deadline,
        "exact setup prefix must be observed within the original setup deadline"
    );
    let before = before_id.index;
    let mut response_counts = Vec::new();
    let prefix_only = Arc::new(AtomicBool::new(false));
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
            prefix_only: prefix_only.clone(),
        }));
        response_counts.push(responses);
    }
    // Retain only this leader's controlled outbound streams until the exact
    // public timeout and its uncommitted SQL suffix have been observed.
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

    // Elect the successor with the actual surviving majority. Retain old
    // prefix replies but prevent unrelated old-leader traffic from resetting
    // their election. No successor RPC reaches the former leader yet.
    prefix_only.store(true, Ordering::SeqCst);
    let survivors = (0..MEMBER_COUNT)
        .filter(|index| *index != leader)
        .collect::<Vec<_>>();
    for ((sender, receiver), path) in &cluster.paths {
        if *sender != leader && *receiver != leader {
            path.set_enabled(true);
        }
    }
    let (successor_id, successor_term) = tokio::time::timeout(RECOVERY_TIMEOUT, async {
        loop {
            let reports = futures_util::future::join_all(
                survivors
                    .iter()
                    .map(|index| cluster.stores[*index].probe_durable_readiness()),
            )
            .await;
            let statuses = survivors
                .iter()
                .map(|index| cluster.stores[*index].status())
                .collect::<Vec<_>>();
            if let Some(candidate) = statuses[0].leader_id {
                let next_term = statuses[0].term;
                if next_term > term
                    && candidate != store.status().node_id
                    && reports.iter().all(DurableReadinessReport::is_ready)
                    && statuses.iter().all(|status| {
                        status.leader_id == Some(candidate)
                            && status.term == next_term
                            && status.applied_index >= Some(tail)
                    })
                {
                    break (candidate, next_term);
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("actual surviving majority elects and commits its higher term");
    let successor = survivors
        .iter()
        .copied()
        .find(|index| cluster.stores[*index].status().node_id == successor_id)
        .unwrap();
    let conflict = retained_sql_log_id_at(&cluster, successor, Some(tail));
    assert!(survivors
        .iter()
        .all(|index| retained_sql_log_id_at(&cluster, *index, Some(tail)) == conflict));
    assert_eq!(conflict.leader_id.term, successor_term);
    assert_eq!(
        store.status().term,
        term,
        "old replication readers still own the old term"
    );
    assert_eq!(retained_sql_log_end(&cluster, leader), tail);
    eprintln!("sdk_stepdown_real_majority term={successor_term} leader={successor_id:?} committed_conflict={conflict:?} old_tail={tail}");
    let identity = consensus_identity(&(0..MEMBER_COUNT).map(member).collect::<Vec<_>>());
    let rpc = ConflictingEmptyAppend {
        vote: Vote::new_committed(successor_term, successor_id),
        prev_log_id: Some(conflict),
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
