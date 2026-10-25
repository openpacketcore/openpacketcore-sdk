//! Configuration-consensus check-quorum authority regressions (#1048).
//!
//! A leader that cannot obtain a quorum acknowledgement within the fixed
//! Openraft leader lease must not keep holding clients. The store therefore
//! withholds new-proposal, local-authority, forwarded-mutation and read-barrier
//! authority with typed retryable "no leader" outcomes, and restores it
//! automatically once a quorum acknowledgement arrives. It never fabricates a
//! vote and changes no election, heartbeat or quorum timing.
//!
//! The fixtures drop only *AppendEntries responses*: followers still receive
//! heartbeats and keep their leader view and lease, while the leader receives
//! no quorum acknowledgement. No wall-clock sleeps are used; the paused
//! protocol clock drives detection and recovery.

use super::*;

use opc_persist::{ConfigLocalAuthorityOutcome, ConfigQuorumLeaseState};

fn quorum_lease() -> Duration {
    Duration::from_millis(DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis)
}

fn heartbeat_interval() -> Duration {
    Duration::from_millis(DURABLE_CONSENSUS_TIMING_PROFILE.append_entries_timeout_millis)
}

#[derive(Clone, Copy, Debug)]
enum LeaseExpectation {
    Available,
    NoQuorum,
}

fn lease_matches(state: ConfigQuorumLeaseState, expected: LeaseExpectation) -> bool {
    matches!(
        (state, expected),
        (
            ConfigQuorumLeaseState::Available,
            LeaseExpectation::Available
        ) | (
            ConfigQuorumLeaseState::NoQuorum { .. },
            LeaseExpectation::NoQuorum
        )
    )
}

/// Poll the typed quorum-lease state on the paused protocol clock. The fixture
/// supplies the virtual deadline.
async fn wait_for_quorum_lease_state(
    store: &ConsensusConfigStore,
    expected: LeaseExpectation,
    deadline: Duration,
) -> tokio::time::Instant {
    let started = tokio::time::Instant::now();
    loop {
        let state = store.quorum_lease_state();
        if lease_matches(state, expected) {
            return tokio::time::Instant::now();
        }
        assert!(
            started.elapsed() < deadline,
            "quorum lease state {expected:?} was not reached before {deadline:?}: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn leader_without_acknowledged_quorum_withholds_authority_until_renewed() {
    tokio::time::resume();
    let cluster = ThreeNodeCluster::start().await;
    tokio::time::pause();

    let leader = cluster.leader();
    let leader_id = cluster.stores[leader].status().node_id;
    let followers = (0..3).filter(|node| *node != leader).collect::<Vec<_>>();
    assert_eq!(
        ConfigQuorumLeaseState::Available,
        cluster.stores[leader].quorum_lease_state(),
        "a freshly formed leader with steady acknowledgements is not fenced"
    );

    // Black-hole only the AppendEntries responses towards the leader: every
    // follower still processes each heartbeat and keeps its leader view.
    for follower in &followers {
        cluster
            .paths
            .get(&(leader, *follower))
            .expect("leader-to-follower path")
            .drop_append_entries_responses(true);
    }
    let dropped_at = tokio::time::Instant::now();

    // The newest acknowledgement is at most one heartbeat old, so the fixed
    // leader lease cannot have expired five seconds later.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        ConfigQuorumLeaseState::Available,
        cluster.stores[leader].quorum_lease_state(),
        "leader authority is withheld only after the fixed quorum-authority ceiling"
    );

    // Detection is bounded by the lease plus one heartbeat-flush interval and
    // cannot precede the lease less one heartbeat of acknowledgement age.
    let detected_at = wait_for_quorum_lease_state(
        &cluster.stores[leader],
        LeaseExpectation::NoQuorum,
        quorum_lease() + heartbeat_interval() + Duration::from_secs(1),
    )
    .await;
    let detection = detected_at.saturating_duration_since(dropped_at);
    assert!(
        detection + Duration::from_millis(50) >= quorum_lease() - heartbeat_interval(),
        "detection cannot precede the engine leader lease less one heartbeat: {detection:?}"
    );
    assert!(
        detection <= quorum_lease() + heartbeat_interval() + Duration::from_millis(100),
        "detection is bounded by the lease plus one heartbeat flush: {detection:?}"
    );
    let ConfigQuorumLeaseState::NoQuorum {
        millis_since_quorum_ack,
    } = cluster.stores[leader].quorum_lease_state()
    else {
        panic!("typed no-quorum state expected");
    };
    assert!(
        millis_since_quorum_ack
            > u64::try_from(quorum_lease().as_millis()).expect("lease millis fit u64"),
        "the reported acknowledgement age is older than the fixed quorum-authority ceiling"
    );

    // Followers still name the old leader: this exact scenario means the
    // leader must not hold their forwarded traffic.
    for follower in &followers {
        assert_eq!(
            Some(leader_id),
            cluster.stores[*follower].status().leader_id,
            "follower keeps its leader view while responses are black-holed"
        );
    }

    // Local proposals are rejected as retryable unavailability before any
    // proposal is attempted, with bounded latency and no committed effect.
    let committed_before = cluster.stores[leader].status().committed_index;
    let leader_request = ConfigConsensusRequestId::from_bytes([0xD1; 16]);
    let leader_tx = TxId::new();
    let started = tokio::time::Instant::now();
    let leader_error = cluster.stores[leader]
        .append_commit_idempotent(
            leader_request,
            attested(commit(leader_tx, None, 1, 0xD1), audit(leader_tx)),
        )
        .await
        .expect_err("a leader without an acknowledged quorum withholds new proposals");
    assert!(
        matches!(leader_error.kind(), PersistErrorKind::Unavailable),
        "withheld leader proposal is typed retryable: {leader_error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "withheld leader proposal returns without waiting for the operation deadline"
    );
    assert_eq!(
        committed_before,
        cluster.stores[leader].status().committed_index,
        "a withheld proposal commits nothing"
    );

    // Local writer-of-record authority reports "no leader" (empty hint) so
    // management callers retry instead of routing back to this node.
    assert_eq!(
        ConfigLocalAuthorityOutcome::Retry { leader_hint: None },
        cluster.stores[leader].ensure_local_authority().await
    );
    assert_eq!(
        ConfigLocalAuthorityOutcome::Retry { leader_hint: None },
        cluster.stores[leader]
            .ensure_local_authority_at_config_head(None, ConfigVersion::INITIAL)
            .await
    );

    // A follower's forwarded mutation receives the leader's definite
    // not-applied no-quorum reply instead of being held to its deadline.
    let follower = followers[0];
    let follower_request = ConfigConsensusRequestId::from_bytes([0xD2; 16]);
    let follower_tx = TxId::new();
    let started = tokio::time::Instant::now();
    let forwarded_error = cluster.stores[follower]
        .append_commit_idempotent(
            follower_request,
            attested(commit(follower_tx, None, 1, 0xD2), audit(follower_tx)),
        )
        .await
        .expect_err("forwarded mutation to a no-quorum leader is rejected");
    assert!(
        matches!(forwarded_error.kind(), PersistErrorKind::Unavailable),
        "forwarded no-quorum rejection is typed retryable: {forwarded_error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "forwarded no-quorum rejection returns without route-refresh waiting"
    );
    assert_eq!(
        committed_before,
        cluster.stores[leader].status().committed_index,
        "forwarded no-quorum rejection commits nothing"
    );

    // Renew the acknowledgements: authority must return automatically within
    // one heartbeat flush and proposals must work again.
    for follower in &followers {
        cluster
            .paths
            .get(&(leader, *follower))
            .expect("leader-to-follower path")
            .drop_append_entries_responses(false);
    }
    let healed_at = tokio::time::Instant::now();
    let renewed_at = wait_for_quorum_lease_state(
        &cluster.stores[leader],
        LeaseExpectation::Available,
        heartbeat_interval() + Duration::from_secs(1),
    )
    .await;
    let recovery = renewed_at.saturating_duration_since(healed_at);
    assert!(
        recovery <= heartbeat_interval() * 2 + Duration::from_millis(100),
        "authority is restored within one acknowledgement heartbeat plus the one-flush recovery debounce: {recovery:?}"
    );
    #[cfg(feature = "dangerous-test-hooks")]
    assert!(
        cluster.stores[leader].quorum_lease_last_recovery_observations_for_test() >= 2,
        "recovery consumes the two-observation debounce instead of restoring on one marginal acknowledgement"
    );
    let recovery_request = ConfigConsensusRequestId::from_bytes([0xD3; 16]);
    let recovery_tx = TxId::new();
    cluster.stores[leader]
        .append_commit_idempotent(
            recovery_request,
            attested(commit(recovery_tx, None, 1, 0xD3), audit(recovery_tx)),
        )
        .await
        .expect("proposals resume after a quorum acknowledgement renews the lease");
    assert!(
        cluster.stores[leader]
            .status()
            .committed_index
            .is_some_and(|committed| committed_before.is_none_or(|before| committed > before)),
        "the renewed leader commits a proposal"
    );

    cluster.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn steady_quorum_acknowledgements_never_withhold_leader_authority() {
    tokio::time::resume();
    let cluster = ThreeNodeCluster::start().await;
    tokio::time::pause();

    let leader = cluster.leader();
    let lease = quorum_lease();
    // Keep the healthy cluster running for longer than the fixed quorum-authority ceiling
    // with every heartbeat acknowledged: authority is never withheld.
    let mut elapsed = Duration::ZERO;
    while elapsed < lease * 3 {
        tokio::time::sleep(heartbeat_interval()).await;
        elapsed += heartbeat_interval();
        assert_eq!(
            ConfigQuorumLeaseState::Available,
            cluster.stores[leader].quorum_lease_state(),
            "a leader whose quorum keeps acknowledging is never fenced"
        );
    }
    #[cfg(feature = "dangerous-test-hooks")]
    assert_eq!(
        0,
        cluster.stores[leader].quorum_lease_last_recovery_observations_for_test(),
        "a never-fenced leader never enters the recovery debounce"
    );
    let request = ConfigConsensusRequestId::from_bytes([0xE1; 16]);
    let tx_id = TxId::new();
    cluster.stores[leader]
        .append_commit_idempotent(
            request,
            attested(commit(tx_id, None, 1, 0xE1), audit(tx_id)),
        )
        .await
        .expect("healthy leader keeps accepting proposals");
    cluster.shutdown().await;
}
