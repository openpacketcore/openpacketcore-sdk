//! Compare surviving-quorum lease service after a planned voter shutdown.

use super::*;

// The caller's existing renewal budget, independent of the consensus engine's
// election and complete-operation budgets. No production timer is changed.
const CALLER_RENEWAL_BUDGET: Duration = Duration::from_secs(5);

async fn surviving_quorum_renewal_after_shutdown(stop_leader: bool) {
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (leader, leader_id, term) = cluster.observed_leader();
    let stopped = if stop_leader {
        leader
    } else {
        (leader + 1) % MEMBER_COUNT
    };
    let survivor = (0..MEMBER_COUNT)
        .find(|index| *index != stopped && *index != leader)
        .expect("a surviving follower");
    let key = session_key(b"planned-shutdown-lease");
    let lease = cluster.stores[survivor]
        .acquire(
            &key,
            owner("planned-shutdown-owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("establish the lease through the surviving follower");
    let lease = cluster.stores[survivor]
        .renew(&lease, Duration::from_secs(30))
        .await
        .expect("baseline renewal through the same surviving follower");
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("all three voters are ready before one planned shutdown");
    assert_eq!(cluster.observed_leader(), (leader, leader_id, term));

    let preparing = tokio::time::Instant::now();
    let preparation = cluster.stores[stopped].prepare_shutdown();
    tokio::pin!(preparation);
    let observed_preparation =
        tokio::time::timeout_at(preparing + CALLER_RENEWAL_BUDGET, &mut preparation).await;
    let preparation_within_budget = observed_preparation.is_ok();
    let preparation_result = match observed_preparation {
        Ok(result) => result,
        Err(_) => preparation.await,
    };
    let preparation_elapsed = preparing.elapsed();
    let prepared = preparation_result.is_ok();
    // The public shutdown contract removes the replication handler only after
    // preparation. This makes the subsequent renewal depend on the survivors.
    cluster.isolate(stopped);
    let closing = Instant::now();
    cluster.stores[stopped]
        .shutdown()
        .await
        .expect("the exact selected voter closes cleanly");
    let close_elapsed = closing.elapsed();
    let survivor_status = cluster.stores[survivor].status();
    let same_term_at_dispatch = survivor_status.term == term;
    let old_leader_at_dispatch = survivor_status.leader_id == Some(leader_id);
    let started = tokio::time::Instant::now();
    let renewal = cluster.stores[survivor].renew(&lease, Duration::from_secs(30));
    tokio::pin!(renewal);
    let observed = tokio::time::timeout_at(started + CALLER_RENEWAL_BUDGET, &mut renewal).await;
    let within_budget = observed.is_ok();
    // A caller deadline does not cancel an accepted mutation. Retain the
    // original future to settlement and do not dispatch a replacement renew.
    let terminal = match observed {
        Ok(result) => result,
        Err(_) => renewal.await,
    };
    let renewal_elapsed = started.elapsed();
    let completed = terminal.is_ok();
    if let Ok(renewed) = &terminal {
        assert_eq!(renewed.key(), lease.key());
        assert_eq!(renewed.owner(), lease.owner());
        assert_eq!(renewed.fence(), lease.fence());
    }
    let survivors = (0..MEMBER_COUNT)
        .filter(|index| *index != stopped)
        .collect::<Vec<_>>();
    let recovered = tokio::time::timeout(RECOVERY_TIMEOUT, async {
        loop {
            let reports = futures_util::future::join_all(
                survivors
                    .iter()
                    .map(|index| cluster.stores[*index].probe_durable_readiness()),
            )
            .await;
            if reports.iter().all(DurableReadinessReport::is_ready) {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .is_ok();
    let closed =
        futures_util::future::join_all(cluster.stores.iter().map(ConsensusSessionStore::shutdown))
            .await;
    eprintln!(
        "planned_shutdown stop_leader={stop_leader} same_term_at_dispatch={same_term_at_dispatch} old_leader_at_dispatch={old_leader_at_dispatch} preparation_ms={} prepared={prepared} preparation_within_budget={preparation_within_budget} close_ms={} renewal_ms={} within_budget={within_budget} terminal_success={completed} surviving_quorum_recovered={recovered}",
        preparation_elapsed.as_millis(),
        close_elapsed.as_millis(),
        renewal_elapsed.as_millis(),
    );
    assert!(
        closed.iter().all(Result::is_ok),
        "all stores finish closing"
    );
    assert!(recovered, "the unchanged surviving majority recovers");
    assert!(prepared && preparation_within_budget, "planned preparation establishes fresh successor authority within the unchanged caller budget");
    assert_eq!(old_leader_at_dispatch, !stop_leader);
    assert_eq!(same_term_at_dispatch, !stop_leader);
    assert!(
        within_budget && completed,
        "one planned voter shutdown must preserve the surviving caller's existing renewal budget"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_shutdown_preserves_surviving_lease_renewal() {
    surviving_quorum_renewal_after_shutdown(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_shutdown_preserves_surviving_lease_renewal() {
    surviving_quorum_renewal_after_shutdown(true).await;
}

struct PausedHandoffHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
    captured: tokio::sync::mpsc::Sender<SessionConsensusWireRequest>,
    release: tokio::sync::watch::Receiver<bool>,
}

impl fmt::Debug for PausedHandoffHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PausedHandoffHandler(<redacted>)")
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for PausedHandoffHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::LeadershipTransfer {
            self.captured
                .send(request.clone())
                .await
                .expect("bounded capture");
            let mut release = self.release.clone();
            while !*release.borrow_and_update() {
                if release.changed().await.is_err() {
                    return SessionConsensusWireResponse {
                        result: Err(SessionConsensusPeerError::Unavailable),
                    };
                }
            }
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

fn pause_leader_handoff(
    cluster: &TestCluster,
    leader: usize,
) -> (
    tokio::sync::mpsc::Receiver<SessionConsensusWireRequest>,
    tokio::sync::watch::Sender<bool>,
) {
    let (captured, receiver) = tokio::sync::mpsc::channel(8);
    let (release, released) = tokio::sync::watch::channel(false);
    for target in 0..MEMBER_COUNT {
        if target != leader {
            cluster.paths[&(leader, target)].install(Arc::new(PausedHandoffHandler {
                inner: cluster.stores[target].rpc_handler(),
                captured: captured.clone(),
                release: released.clone(),
            }));
        }
    }
    (receiver, release)
}

async fn close_cluster(cluster: &TestCluster) {
    let results =
        futures_util::future::join_all(cluster.stores.iter().map(ConsensusSessionStore::shutdown))
            .await;
    assert!(
        results.iter().all(Result::is_ok),
        "every storage owner closes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_preparation_observer_keeps_one_owned_handoff_and_admission_closed() {
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (leader, _, _) = cluster.observed_leader();
    let (mut captured, release) = pause_leader_handoff(&cluster, leader);
    let store = cluster.stores[leader].clone();
    let observer = tokio::spawn(async move { store.prepare_shutdown().await });
    let first = tokio::time::timeout(CALLER_RENEWAL_BUDGET, captured.recv())
        .await
        .expect("handoff reaches authenticated transport")
        .expect("first exact handoff request");
    observer.abort();
    assert!(observer
        .await
        .expect_err("cancelled observer")
        .is_cancelled());
    assert!(!cluster.stores[leader]
        .probe_durable_readiness()
        .await
        .is_ready());
    let clone = cluster.stores[leader].clone();
    let retained = clone.prepare_shutdown();
    tokio::pin!(retained);
    assert!(futures_util::poll!(&mut retained).is_pending());
    release.send_replace(true);
    tokio::time::timeout(CALLER_RENEWAL_BUDGET, &mut retained)
        .await
        .expect("owned preparation remains bounded")
        .expect("clone observes original successful preparation");
    let second = captured
        .try_recv()
        .expect("selected successor receives handoff");
    assert_eq!(
        first, second,
        "one exact request is delivered to each survivor"
    );
    assert!(
        captured.try_recv().is_err(),
        "no replacement preparation was dispatched"
    );
    assert!(!cluster.stores[leader]
        .probe_durable_readiness()
        .await
        .is_ready());
    cluster.stores[leader]
        .prepare_shutdown()
        .await
        .expect("retained success");
    assert!(
        captured.try_recv().is_err(),
        "completed result is retained without replay"
    );
    close_cluster(&cluster).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handoff_rejects_wrong_sender_scope_and_payload_before_engine_mutation() {
    use opc_consensus::engine::raft::TransferLeaderError;

    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (leader, leader_id, term) = cluster.observed_leader();
    let (mut captured, release) = pause_leader_handoff(&cluster, leader);
    let store = cluster.stores[leader].clone();
    let preparation = tokio::spawn(async move { store.prepare_shutdown().await });
    let exact = tokio::time::timeout(CALLER_RENEWAL_BUDGET, captured.recv())
        .await
        .expect("exact request reaches transport")
        .expect("captured engine-issued handoff");
    let follower = (leader + 1) % MEMBER_COUNT;
    let other = (leader + 2) % MEMBER_COUNT;
    let handler = cluster.stores[follower].rpc_handler();
    let other_id = cluster.stores[other].status().node_id;
    assert_eq!(
        handler.handle(other_id, exact.clone()).await.result,
        Err(SessionConsensusPeerError::ScopeMismatch),
        "authenticated peer must match the envelope sender"
    );
    let mut forged_sender = exact.clone();
    forged_sender.sender = other_id;
    assert_eq!(
        handler.handle(other_id, forged_sender).await.result,
        Err(SessionConsensusPeerError::ScopeMismatch),
        "envelope sender must also match the engine-issued leader vote"
    );
    let mut wrong_scope = exact.clone();
    wrong_scope.identity = consensus_identity_for_cluster(
        &(0..MEMBER_COUNT).map(member).collect::<Vec<_>>(),
        "unrelated-synthetic-cluster",
        1,
    );
    assert_eq!(
        handler.handle(leader_id, wrong_scope).await.result,
        Err(SessionConsensusPeerError::ScopeMismatch)
    );
    for (payload, rejection) in [
        (Vec::new(), SessionConsensusPeerError::Protocol),
        // The existing outer service classifies an invalid bounded envelope
        // as ScopeMismatch before the engine payload decoder can run.
        (vec![0; 1_025], SessionConsensusPeerError::ScopeMismatch),
    ] {
        let invalid = SessionConsensusWireRequest {
            payload,
            ..exact.clone()
        };
        assert_eq!(
            handler.handle(leader_id, invalid).await.result,
            Err(rejection)
        );
    }
    for store in &cluster.stores {
        let status = store.status();
        assert_eq!(status.term, term, "invalid inputs cannot start an election");
        assert_eq!(status.leader_id, Some(leader_id));
    }
    release.send_replace(true);
    tokio::time::timeout(CALLER_RENEWAL_BUDGET, preparation)
        .await
        .expect("valid handoff still completes")
        .expect("owned preparation task")
        .expect("valid handoff accepted");
    let stale = handler
        .handle(leader_id, exact)
        .await
        .result
        .expect("bounded engine refusal");
    assert_eq!(
        decode_bounded::<Result<(), RaftError<SessionConsensusNodeId, TransferLeaderError>>>(
            &stale
        )
        .expect("decode stale request refusal"),
        Err(RaftError::APIError(TransferLeaderError::VoteChanged)),
        "old exact request cannot release the successor's vote lease"
    );
    close_cluster(&cluster).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_surviving_quorum_retains_failed_preparation_without_readmission_or_replay() {
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (leader, _, term) = cluster.observed_leader();
    let survivor = (leader + 1) % MEMBER_COUNT;
    let key = session_key(b"failed-planned-retirement");
    let lease = cluster.stores[survivor]
        .acquire(
            &key,
            owner("retained-retirement-owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("existing lease before partition");
    cluster.isolate(leader);
    let first = cluster.stores[leader].prepare_shutdown().await;
    assert!(first.is_err(), "no successor proof without surviving peers");
    assert!(!cluster.stores[leader]
        .probe_durable_readiness()
        .await
        .is_ready());
    cluster.heal(leader);
    tokio::time::timeout(RECOVERY_TIMEOUT, async {
        loop {
            let status = cluster.stores[survivor].status();
            if status.term > term
                && status.leader_id != Some(cluster.stores[leader].status().node_id)
                && cluster.stores[survivor]
                    .probe_durable_readiness()
                    .await
                    .is_ready()
            {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("survivors elect normally without the retiring voter campaigning");
    let retained = cluster.stores[leader].prepare_shutdown();
    tokio::pin!(retained);
    assert!(
        matches!(
            futures_util::poll!(&mut retained),
            std::task::Poll::Ready(Err(_))
        ),
        "a later caller sees the original terminal failure without another attempt"
    );
    assert!(!cluster.stores[leader]
        .probe_durable_readiness()
        .await
        .is_ready());
    let renewed = cluster.stores[survivor]
        .renew(&lease, Duration::from_secs(60))
        .await
        .expect("surviving service recovers under the original fence");
    assert_eq!(renewed.fence(), lease.fence());
    close_cluster(&cluster).await;
}
