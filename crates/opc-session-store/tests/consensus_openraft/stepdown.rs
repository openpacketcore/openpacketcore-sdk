//! A former leader must stop reading its suffix before conflict truncation.

use super::*;
use opc_consensus::engine::raft::AppendEntriesResponse;
use opc_consensus::engine::{LogId, Vote};
use std::cell::RefCell;
use std::future::Future;
use std::sync::Condvar;

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
    retained_sql_log_id_from(
        &cluster
            ._directory
            .path()
            .join(format!("node-{node}.sqlite")),
        index,
    )
}

fn retained_sql_log_id_from(path: &Path, index: Option<u64>) -> LogId<SessionConsensusNodeId> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
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

async fn wait_for_stepdown_publication(store: &ConsensusSessionStore, previous_term: u64) {
    #[cfg(feature = "test-control")]
    store
        .wait_for_status_for_test(|status| {
            status.term > previous_term && status.leader_id != Some(status.node_id)
        })
        .await;
    #[cfg(not(feature = "test-control"))]
    loop {
        let status = store.status();
        if status.term > previous_term && status.leader_id != Some(status.node_id) {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// The pinned engine reports metrics after sending its response. Hold that
// publication event itself: an already-ready response need not wake anyone.
// No engine state or published metrics are replaced by this scheduling fault.
struct PublicationHold {
    log_cut: Option<(PathBuf, u64)>,
    metrics_prefix: String,
    before_publication: tokio::sync::Notify,
    deadline: tokio::time::Instant,
    held: AtomicBool,
    released: StdMutex<bool>,
    release: Condvar,
}

impl PublicationHold {
    fn before_publication(&self) {
        let released = self.released.lock().expect("publication hold mutex");
        if *released {
            return;
        }
        if let Some((path, truncated_end)) = &self.log_cut {
            if retained_sql_log_id_from(path, None).index != *truncated_end {
                return;
            }
        }
        self.held.store(true, Ordering::Release);
        self.before_publication.notify_one();
        let (released, _) = self
            .release
            .wait_timeout_while(
                released,
                self.deadline
                    .saturating_duration_since(tokio::time::Instant::now()),
                |released| !*released,
            )
            .expect("publication hold wait");
        let completed = *released;
        // Do not poison the release guard if the fixture watchdog expires.
        drop(released);
        assert!(
            completed,
            "publication hold exceeded the shared recovery deadline"
        );
    }

    fn release(&self) {
        *self.released.lock().expect("publication hold mutex") = true;
        self.release.notify_all();
    }
}

struct ReleasePublication(Arc<PublicationHold>);

impl Drop for ReleasePublication {
    fn drop(&mut self) {
        self.0.release();
    }
}

async fn receive_response<F: Future>(
    response: F,
    publication: &Arc<PublicationHold>,
    deadline: tokio::time::Instant,
) -> F::Output {
    let response = tokio::time::timeout_at(deadline, response)
        .await
        .expect("configured higher-vote peer completes conflict handling");
    tokio::time::timeout_at(deadline, async {
        while !publication.held.load(Ordering::Acquire) {
            publication.before_publication.notified().await;
        }
    })
    .await
    .expect("engine acknowledges the publication hold within the shared deadline");
    response
}

// Openraft 2e1fb7455752455a3505b354d003d6effa55985d emits this event
// immediately before tx_metrics.send(). An engine update that changes the event
// must update this fixture: a missing hold fails within the shared deadline.
// This acknowledgment also lets the channel regression force a response to
// arrive before its first receiver poll, without relying on thread timing.
struct PublicationEvents(Arc<StdMutex<Option<Arc<PublicationHold>>>>);

impl tracing::Subscriber for PublicationEvents {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_event() && metadata.target() == "openraft::core::raft_core"
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        unreachable!("the publication observer enables events only")
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let publication = self.0.lock().expect("publication observer mutex").clone();
        if let Some(publication) = publication {
            let mut message = Message(String::new());
            event.record(&mut message);
            if message.0.starts_with(&publication.metrics_prefix) {
                publication.before_publication();
            }
        }
    }
}

#[tokio::test]
async fn publication_hold_survives_response_before_first_poll() {
    let deadline = tokio::time::Instant::now() + RECOVERY_TIMEOUT;
    let publication = Arc::new(PublicationHold {
        // This regression isolates the exact channel schedule. The full
        // stepdown fixture below also witnesses real SQL and Raft metrics.
        log_cut: None,
        metrics_prefix: "report_metrics: ready-response".to_owned(),
        before_publication: tokio::sync::Notify::new(),
        deadline,
        held: AtomicBool::new(false),
        released: StdMutex::new(false),
        release: Condvar::new(),
    });
    let _release_publication = ReleasePublication(publication.clone());
    let dispatch = tracing::Dispatch::new(PublicationEvents(Arc::new(StdMutex::new(Some(
        publication.clone(),
    )))));
    let (respond, response) = tokio::sync::oneshot::channel();
    let (publish, mut published) = tokio::sync::watch::channel(false);
    let responder = std::thread::spawn(move || {
        // The pinned call_core sends its request before polling this exact
        // channel type. Deschedule the receiver until the sender reaches
        // its publication event: send() cannot invoke an unregistered wake.
        respond.send(()).expect("response receiver remains alive");
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::debug!(target: "openraft::core::raft_core", "report_metrics: ready-response");
        });
        publish
            .send(true)
            .expect("publication receiver remains alive");
    });
    tokio::time::timeout_at(deadline, publication.before_publication.notified())
        .await
        .expect("sender reached publication before the first receiver poll");
    receive_response(response, &publication, deadline)
        .await
        .expect("response was sent before its first poll");
    assert!(
        publication.held.load(Ordering::Acquire),
        "an immediately ready response must still hold publication"
    );
    let observation = published.wait_for(|published| *published);
    tokio::pin!(observation);
    assert!(
        futures_util::poll!(observation.as_mut()).is_pending(),
        "publication remains pending after the already-ready response"
    );
    publication.release();
    tokio::time::timeout_at(deadline, observation)
        .await
        .expect("publication completes within the same deadline")
        .expect("publication sender remains alive until it publishes");
    responder.join().expect("publication sender completes");
}

thread_local! {
    static PUBLICATION_DISPATCH: RefCell<Option<tracing::dispatcher::DefaultGuard>> =
        const { RefCell::new(None) };
}

#[test]
fn superseded_leader_stops_replication_before_truncating_its_uncommitted_suffix() {
    let publication = Arc::new(StdMutex::new(None));
    let dispatch = tracing::Dispatch::new(PublicationEvents(publication.clone()));
    let worker_dispatch = dispatch.clone();
    // A task-local subscriber would miss events on the engine's spawned
    // tasks. Install this observer only on this fixture's runtime threads.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .on_thread_start(move || {
            PUBLICATION_DISPATCH.with(|guard| {
                *guard.borrow_mut() = Some(tracing::dispatcher::set_default(&worker_dispatch));
            });
        })
        .on_thread_stop(|| {
            PUBLICATION_DISPATCH.with(|guard| {
                guard.borrow_mut().take();
            });
        })
        .build()
        .expect("stepdown fixture runtime");
    tracing::dispatcher::with_default(&dispatch, || {
        runtime.block_on(stepdown_scenario(publication));
    });
}

async fn stepdown_scenario(publication_events: Arc<StdMutex<Option<Arc<PublicationHold>>>>) {
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
    let stepdown_deadline = tokio::time::Instant::now() + RECOVERY_TIMEOUT;
    let publication = Arc::new(PublicationHold {
        log_cut: Some((
            cluster
                ._directory
                .path()
                .join(format!("node-{leader}.sqlite")),
            tail - 1,
        )),
        metrics_prefix: format!(
            "report_metrics: Metrics{{id:{}, Follower, term:{successor_term},",
            store.status().node_id
        ),
        before_publication: tokio::sync::Notify::new(),
        deadline: stepdown_deadline,
        held: AtomicBool::new(false),
        released: StdMutex::new(false),
        release: Condvar::new(),
    });
    // Unwind must release the engine even when an assertion detects the race.
    let _release_publication = ReleasePublication(publication.clone());
    *publication_events
        .lock()
        .expect("publication observer mutex") = Some(publication.clone());
    let handler = store.rpc_handler();
    let response = receive_response(
        handler.handle(successor_id, envelope),
        &publication,
        stepdown_deadline,
    )
    .await;
    let decoded: Result<
        AppendEntriesResponse<SessionConsensusNodeId>,
        RaftError<SessionConsensusNodeId>,
    > = decode_bounded(&response.result.expect("scoped append transport")).unwrap();
    assert_eq!(decoded, Ok(AppendEntriesResponse::Conflict));
    assert_eq!(retained_sql_log_end(&cluster, leader), tail - 1);
    assert!(
        publication.held.load(Ordering::Acquire),
        "the actual publication event holds the engine before metrics publication"
    );
    let stepdown = async {
        // Response delivery precedes metrics publication. Observe that actual
        // publication within the original response budget before asserting.
        tokio::time::timeout_at(
            stepdown_deadline,
            wait_for_stepdown_publication(store, term),
        )
        .await
        .expect("stepdown metrics publish within the original response deadline");
        assert!(store.status().term > term);
        assert_ne!(store.status().leader_id, Some(store.status().node_id));
    };
    tokio::pin!(stepdown);
    assert!(
        futures_util::poll!(stepdown.as_mut()).is_pending(),
        "post-stepdown assertions wait while publication is held"
    );
    publication.release();
    stepdown.await;

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
