//! A voter cut off from consensus traffic must not depose a healthy leader.
//!
//! Each time its election timer fires, a cut-off voter would otherwise start
//! a campaign and persist a higher term. When it can be reached again, the
//! leader sees that term in an AppendEntries response and steps down although
//! a quorum served it throughout. Pre-Vote, carried on its own RPC family,
//! keeps the voter's term unchanged because no quorum would grant it.

use super::*;

/// How long the voter is cut off: past its first campaign and one retry.
fn isolation() -> Duration {
    let max = Duration::from_millis(DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis);
    max * 2 + Duration::from_millis(DURABLE_OPENRAFT_PROFILE.heartbeat_interval_millis) * 3
}

#[tokio::test]
async fn cut_off_voter_rejoins_without_deposing_the_leader() {
    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (leader, leader_id, term) = cluster.observed_leader();
    let cut_off = (0..MEMBER_COUNT)
        .find(|index| *index != leader)
        .expect("a follower");

    cluster.isolate(cut_off);
    let started = Instant::now();
    let mut writes = 0_u64;
    let mut highest_cut_off_term = term;
    while started.elapsed() < isolation() {
        // The other voters keep committing while the voter is cut off.
        let key = session_key(format!("pre-vote-isolated-{writes}").as_bytes());
        cluster.stores[leader]
            .acquire(
                &key,
                owner("pre-vote-isolated-owner"),
                Duration::from_secs(30),
            )
            .await
            .expect("the remaining quorum keeps committing");
        writes += 1;
        highest_cut_off_term = highest_cut_off_term.max(cluster.stores[cut_off].status().term);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(writes > 0);

    cluster.heal(cut_off);
    let healed = Instant::now();
    while healed.elapsed() < isolation() / 2 {
        for (index, store) in cluster.stores.iter().enumerate() {
            let status = store.status();
            assert_eq!(
                status.term, term,
                "voter {index} stays in the healthy leader's term after the cut-off voter returns: {status:?}"
            );
            assert_ne!(
                status.leader_id,
                Some(cluster.stores[cut_off].status().node_id),
                "the returning voter never leads"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        highest_cut_off_term, term,
        "the cut-off voter never raised its term"
    );

    let key = session_key(b"pre-vote-after-heal");
    cluster.stores[cut_off]
        .acquire(
            &key,
            owner("pre-vote-healed-owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("the returning voter forwards to the unchanged leader");
    let statuses = cluster
        .stores
        .iter()
        .map(ConsensusSessionStore::status)
        .collect::<Vec<_>>();
    assert!(
        statuses
            .iter()
            .all(|status| status.term == term && status.leader_id == Some(leader_id)),
        "the healthy leader keeps leading in its term: {statuses:?}"
    );
}
