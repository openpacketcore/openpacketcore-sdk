//! The qualification child observes a clone-wide drain through bounded API
//! waits. Timing out one observer never completes or cancels the owned drain.

use super::*;
use tokio::sync::{oneshot, watch};
use tokio::time::{advance, timeout, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn normal_qualification_shutdown_hands_off_and_joins_the_store() {
    let cluster = opc_session_testkit::ConsensusTestCluster::start(3).await;
    let leader_id = cluster.store(0).status().leader_id.unwrap();
    let leader = (0..3)
        .find(|index| cluster.store(*index).status().node_id == leader_id)
        .unwrap();
    let survivor = (leader + 1) % 3;
    let store = Arc::new(cluster.store(leader));
    let term = store.status().term;
    let lease = cluster
        .store(survivor)
        .acquire(
            &qualification_traffic_key(survivor).unwrap(),
            OwnerId::new("qualification-shutdown-owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let protected = EncryptingSessionBackend::new(
        Arc::clone(&store),
        Arc::new(MemoryKeyProvider::new()),
        "qualification-shutdown-fixture".to_owned(),
    );
    let mut node = QualificationNode {
        store,
        #[cfg(all(target_os = "linux", feature = "test-control"))]
        storage_fence_armed_for_test: false,
        protected,
        // The real fixture's replication handlers remain installed until the
        // command finishes, just as the node's listener must remain available.
        server: None,
        consumer_server: None,
        consumer_transport: None,
        consumer_delayed_response: Arc::new(AtomicBool::new(false)),
        consumer_response_hold_gate: Arc::new(QualificationConsumerResponseHoldGate::new(4)),
        consumer_ambiguity_witness_hold_gate: Arc::new(QualificationConsumerResponseHoldGate::new(
            1,
        )),
        transport: QualificationTransportRuntime::FoundationPlaintext,
        leases: HashMap::new(),
        next_lease_retention_sequence: 1,
        node_index: leader,
        member_count: 3,
        configured_voter_ids: (0..3)
            .map(|index| cluster.store(index).status().node_id.get())
            .collect(),
        traffic_schedule_bound: false,
        traffic: None,
        traffic_acquire_journal: None,
        concurrent_watches: HashMap::new(),
        empty_vote_dispatches: Arc::new(AtomicU64::new(0)),
        rpc_gate: QualificationConsensusRpcGate::available(),
        roster_attestation_root: qualification_roster_attestation_trust_root(),
        fixed_consensus_identity: cluster.consensus_identity(),
        isolated_scale: None,
        isolated_scale_clock: None,
    };
    let reply = node.handle(QualificationNodeCommand::Shutdown).await;
    let engine_stopped = !node.store.persistence_health().engine_running;
    let after = cluster.store(survivor).status();
    cluster.set_node_online(leader, false);
    let renewal = timeout(
        Duration::from_secs(5),
        cluster
            .store(survivor)
            .renew(&lease, Duration::from_secs(60)),
    )
    .await;
    node.stop_server().await;
    drop(node);
    cluster.shutdown().await;

    assert!(matches!(reply, QualificationNodeReply::ShuttingDown));
    assert!(
        engine_stopped,
        "normal shutdown must join the actual store before replying"
    );
    assert_ne!(after.leader_id, Some(leader_id));
    assert!(after.term > term);
    let renewed = renewal
        .expect("survivors retain the five-second caller budget")
        .expect("survivors retain lease authority");
    assert_eq!(renewed.fence(), lease.fence());
    assert_eq!(renewed.owner(), lease.owner());
}

fn unavailable() -> StoreError {
    StoreError::BackendUnavailable("fixed shutdown observation unavailable".to_owned())
}

async fn bounded_observation(
    mut completion: watch::Receiver<Option<Result<(), StoreError>>>,
) -> Result<(), StoreError> {
    timeout(Duration::from_millis(10), async {
        loop {
            let state = completion.borrow_and_update().clone();
            if let Some(result) = state {
                return result;
            }
            completion.changed().await.map_err(|_| unavailable())?;
        }
    })
    .await
    .unwrap_or_else(|_| Err(unavailable()))
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_retains_the_same_owned_drain_after_an_observer_timeout() {
    let (complete, completion) = watch::channel(None);
    let (release, released) = oneshot::channel();
    let drain = tokio::spawn(async move {
        released.await.expect("release the one owned drain");
        complete.send_replace(Some(Ok(())));
    });
    let deadline = Instant::now() + Duration::from_millis(45);
    let joined = tokio::spawn(async move {
        join_qualification_shutdown_before(deadline, || bounded_observation(completion.clone()))
            .await
    });
    tokio::task::yield_now().await;
    advance(Duration::from_millis(11)).await;
    tokio::task::yield_now().await;
    let prematurely_finished = joined.is_finished();
    let drain_still_owned = !drain.is_finished();
    release
        .send(())
        .expect("observer timeout retained the drain");
    drain.await.expect("join the one actual drain");
    let result = joined.await.expect("join the qualification observer");
    assert!(drain_still_owned, "the first wait did not finish the drain");
    assert!(
        !prematurely_finished,
        "one API timeout is not a terminal drain result"
    );
    assert_eq!(
        result,
        Ok(()),
        "only actual drain completion permits shutdown"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_preserves_one_absolute_control_deadline() {
    let (complete, completion) = watch::channel(None);
    let started = Instant::now();
    let deadline = started + Duration::from_millis(45);
    let result =
        join_qualification_shutdown_before(deadline, || bounded_observation(completion.clone()))
            .await;
    assert!(
        result.is_err(),
        "an unfinished drain cannot pass the deadline"
    );
    assert_eq!(
        Instant::now(),
        deadline,
        "API waits share one control deadline"
    );
    assert!(
        complete.borrow().is_none(),
        "timeout cannot invent drain completion"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_preserves_an_already_completed_storage_failure() {
    let error = unavailable();
    let (_complete, completion) = watch::channel(Some(Err(error.clone())));
    let started = Instant::now();
    let result = join_qualification_shutdown_before(started + Duration::from_millis(45), || {
        bounded_observation(completion.clone())
    })
    .await;
    assert_eq!(result, Err(error));
    assert_eq!(
        Instant::now(),
        started,
        "a latched failure is terminal without a wait"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_accepts_an_already_completed_drain() {
    let (_complete, completion) = watch::channel(Some(Ok(())));
    let started = Instant::now();
    assert_eq!(
        join_qualification_shutdown_before(started + Duration::from_millis(45), || {
            bounded_observation(completion.clone())
        })
        .await,
        Ok(())
    );
    assert_eq!(Instant::now(), started);
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_does_not_start_an_observation_at_the_expired_control_deadline() {
    let calls = std::cell::Cell::new(0);
    let result = join_qualification_shutdown_before(Instant::now(), || {
        calls.set(calls.get() + 1);
        std::future::ready(Ok(()))
    })
    .await;
    assert!(result.is_err());
    assert_eq!(
        calls.get(),
        0,
        "the inclusive cutoff forbids a new observation"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_rejects_a_ready_result_that_consumed_the_control_budget() {
    let deadline = Instant::now() + Duration::from_millis(45);
    let result = join_qualification_shutdown_before(deadline, || async {
        advance(Duration::from_millis(45)).await;
        Ok(())
    })
    .await;
    assert!(
        result.is_err(),
        "a late ready result cannot bypass the cutoff"
    );
    assert_eq!(Instant::now(), deadline);
}
