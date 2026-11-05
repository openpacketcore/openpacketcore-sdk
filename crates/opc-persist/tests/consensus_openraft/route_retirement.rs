//! Configuration-store leader-route rediscovery regressions (#1049).
//!
//! These real three-node fixtures run in the serial all-features end-to-end lane.
//!
//! The configuration store previously waited for the complete operation
//! deadline on a leader-routed call even after its own engine had already named
//! the successor. These tests black-hole one follower-to-leader forward route.
//! With an observed successor the write must be re-offered through that
//! successor after the stale-leader route grace; without a successor the
//! complete operation bound and its typed ambiguous outcome are preserved.

use super::*;

use opc_consensus::DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE;

/// The test fixture declares its own complete operation budget:
/// `ThreeNodeCluster::start()` builds every store with a 3 s operation timeout
/// (`build_with_election_offset` -> `build_with_operation_timeout(..., 3 s)`),
/// matching the `DECLARED` convention in `consensus_openraft.rs`.
const DECLARED_OPERATION_BUDGET: Duration = Duration::from_secs(3);

/// Upper allowance for the declared operation budget, matching the existing
/// stalled-forward fixture ceiling.
const DECLARED_OPERATION_CEILING: Duration = Duration::from_millis(3_250);

/// One decoded forwarded-mutation round trip plus at most one stale-route
/// refresh backoff after the route is re-offered. It is not a second election
/// or a second operation deadline.
const ROUTE_REDISCOVERY_ALLOWANCE: Duration = Duration::from_millis(500);

/// Wait until the follower really transmitted the (black-holed) forwarded
/// mutation, so the leader loss happens with the call already outstanding.
async fn wait_for_forward_mutation_attempt(path: &LoopbackPeer, prior: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if path.forward_mutation_attempts() > prior {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("forwarded mutation reaches the peer");
}

/// Advance the paused protocol clock past the survivors' committed-vote leases
/// from the current leader, so a replacement campaign can win immediately
/// instead of waiting for a randomized election timeout. The caller first stops
/// leader traffic because accepted heartbeats refresh the committed-vote lease.
async fn advance_past_committed_vote_leases(cluster: &ThreeNodeCluster, voters: [usize; 2]) {
    for node in voters {
        cluster.stores[node]
            .wait_for_vote_lease_expiry_for_test()
            .await
            .expect("committed-vote lease expiry");
    }
}

#[tokio::test(start_paused = true)]
async fn routed_write_rediscovers_the_successor_after_a_black_holed_lost_leader() {
    // Form the cluster on wall-clock time; only protocol observations below run
    // on the paused protocol clock.
    tokio::time::resume();
    let cluster = ThreeNodeCluster::start().await;
    tokio::time::pause();

    let stale_leader = cluster.leader();
    let stale_leader_id = cluster.stores[stale_leader].status().node_id;
    let follower = (0..3).find(|node| *node != stale_leader).expect("follower");
    let successor = (0..3)
        .find(|node| *node != stale_leader && *node != follower)
        .expect("successor voter");

    // Exactly one survivor campaigns; the follower only votes, so the
    // replacement election has no split round.
    cluster.stores[follower].disable_automatic_elections_for_test();
    cluster.stores[successor].disable_automatic_elections_for_test();
    cluster.stores[stale_leader].disable_automatic_elections_for_test();

    for survivor in [follower, successor] {
        cluster.paths[&(stale_leader, survivor)].set_enabled(false);
    }

    // A campaign cannot win before the survivors' committed-vote leases from
    // the current leader expire. Advance through those exact leases on the
    // paused clock before the write, so the deterministic replacement election
    // fits the fixture's declared operation budget.
    advance_past_committed_vote_leases(&cluster, [follower, successor]).await;

    let path = cluster
        .paths
        .get(&(follower, stale_leader))
        .expect("follower-to-leader path")
        .clone();
    let prior_attempts = path.forward_mutation_attempts();
    path.stall_family(ConsensusRpcFamily::ForwardMutation, true);

    let request_id = ConfigConsensusRequestId::from_bytes([0x49; 16]);
    let tx_id = TxId::new();
    let record = commit(tx_id, None, 1, 0x49);
    let records_audit = audit(tx_id);
    let replay = attested(record.clone(), records_audit.clone());
    let follower_store = cluster.stores[follower].clone();
    let write_started = tokio::time::Instant::now();
    let write = tokio::spawn(async move {
        follower_store
            .append_commit_idempotent(request_id, attested(record, records_audit))
            .await
    });
    wait_for_forward_mutation_attempt(&path, prior_attempts).await;

    // Lose the leader while the forwarded call is outstanding: the two
    // survivors form a fresh majority and elect the successor. The vote leases
    // are already expired, so the triggered campaign has no lease wait.
    cluster.isolate(stale_leader);
    cluster.stores[successor]
        .trigger_election_for_test()
        .await
        .expect("successor starts one normal campaign");
    cluster.stores[follower]
        .wait_for_raft_status_for_test(|status| {
            status
                .leader_id
                .is_some_and(|leader| leader != stale_leader_id)
        })
        .await
        .expect("follower observes the successor");
    let observed_at = tokio::time::Instant::now();

    let result = tokio::time::timeout(
        DECLARED_OPERATION_BUDGET + ROUTE_REDISCOVERY_ALLOWANCE,
        write,
    )
    .await
    .expect("routed write finishes inside the declared operation budget")
    .expect("write task");
    result.expect("write commits through the successor");
    let completed_at = tokio::time::Instant::now();

    assert_eq!(
        path.forward_mutation_attempts(),
        prior_attempts + 1,
        "the abandoned lost-leader route is not retried after the successor is observed"
    );
    let rediscovery = completed_at.saturating_duration_since(observed_at);
    assert!(
        rediscovery >= DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE,
        "the route is not abandoned before the stale-leader grace bound: {rediscovery:?}"
    );
    assert!(
        rediscovery <= DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE + ROUTE_REDISCOVERY_ALLOWANCE,
        "the route is abandoned and re-offered within the grace bound: {rediscovery:?}"
    );
    assert!(
        completed_at.saturating_duration_since(write_started) < DECLARED_OPERATION_BUDGET,
        "leader loss cannot consume the fixture's complete operation budget"
    );

    // Exactly-once: the abandoned attempt committed nothing, the successor
    // commit is the only revision, and the same request identity replays.
    let latest = cluster.stores[follower]
        .load_latest()
        .await
        .expect("linearizable committed head")
        .expect("committed configuration");
    assert_eq!(latest.record.tx_id, tx_id);
    assert_eq!(latest.record.version, ConfigVersion::new(1));
    cluster.stores[follower]
        .append_commit_idempotent(request_id, replay)
        .await
        .expect("same request identity replays the committed result");
    let replayed = cluster.stores[follower]
        .load_latest()
        .await
        .expect("linearizable committed head")
        .expect("committed configuration");
    assert_eq!(replayed.record.tx_id, tx_id);
    assert_eq!(replayed.record.version, ConfigVersion::new(1));

    cluster.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn unanswered_forward_without_a_successor_fails_closed_at_the_operation_bound() {
    tokio::time::resume();
    let cluster = ThreeNodeCluster::start().await;
    tokio::time::pause();

    let leader = cluster.leader();
    let follower = (0..3).find(|node| *node != leader).expect("follower");
    let path = cluster
        .paths
        .get(&(follower, leader))
        .expect("follower-to-leader path")
        .clone();
    let prior_attempts = path.forward_mutation_attempts();
    path.stall_family(ConsensusRpcFamily::ForwardMutation, true);

    let request_id = ConfigConsensusRequestId::from_bytes([0x4A; 16]);
    let tx_id = TxId::new();
    let follower_store = cluster.stores[follower].clone();
    let started = tokio::time::Instant::now();
    let write = tokio::spawn(async move {
        follower_store
            .append_commit_idempotent(
                request_id,
                attested(commit(tx_id, None, 1, 0x4A), audit(tx_id)),
            )
            .await
    });
    wait_for_forward_mutation_attempt(&path, prior_attempts).await;

    let error = tokio::time::timeout(
        DECLARED_OPERATION_BUDGET + ROUTE_REDISCOVERY_ALLOWANCE,
        write,
    )
    .await
    .expect("the declared operation budget bounds the unanswered forward")
    .expect("write task")
    .expect_err("an unanswered forward to a live leader stays ambiguous");
    assert!(matches!(error.kind(), PersistErrorKind::OutcomeUnknown));
    let elapsed = started.elapsed();
    assert!(
        elapsed >= DECLARED_OPERATION_BUDGET,
        "a route with no observed successor keeps the complete operation bound: {elapsed:?}"
    );
    assert!(
        elapsed <= DECLARED_OPERATION_CEILING,
        "the fixture's declared operation budget is not stretched: {elapsed:?}"
    );
    assert_eq!(path.forward_mutation_attempts(), prior_attempts + 1);

    cluster.shutdown().await;
}
