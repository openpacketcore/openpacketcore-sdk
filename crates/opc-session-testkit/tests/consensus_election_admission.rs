//! A voter whose local credentials admit no authenticated connection must
//! not campaign, and must rejoin without deposing the leader (#1005).
//!
//! Without this, an isolated voter whose certificate is in its rotation drain
//! window or has expired raises its term on every election timeout. When fresh
//! credentials let it reconnect, the healthy leader sees that higher term in a
//! response, steps down, and the cluster loses its leader for a full election.

use std::time::Duration;

use opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE;
use opc_session_testkit::ConsensusTestCluster;

const MEMBERS: usize = 3;
const ELECTION_TIMEOUT_MAX: Duration =
    Duration::from_millis(DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis);
const LEADER_DEADLINE: Duration = Duration::from_secs(60);

/// Wait until every member reports the same known leader in the same term.
async fn stable_leader(cluster: &ConsensusTestCluster) -> (usize, u64) {
    tokio::time::timeout(LEADER_DEADLINE, async {
        loop {
            let statuses = (0..MEMBERS)
                .map(|index| cluster.store(index).status())
                .collect::<Vec<_>>();
            let leader = statuses[0].leader_id;
            if leader.is_some()
                && statuses
                    .iter()
                    .all(|status| status.leader_id == leader && status.term == statuses[0].term)
            {
                if let Some(index) = statuses
                    .iter()
                    .position(|status| Some(status.node_id) == leader)
                {
                    return (index, statuses[0].term);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the fleet elects one stable leader")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_without_admitted_credentials_neither_campaigns_nor_deposes_the_leader() {
    let cluster = ConsensusTestCluster::start(MEMBERS).await;
    let (leader, term) = stable_leader(&cluster).await;
    let voter = (leader + 1) % MEMBERS;

    // The voter's credentials stop admitting connections, and it is cut off.
    cluster.set_local_credentials_admitted(voter, false);
    cluster.set_node_online(voter, false);
    // Three maximum election timeouts: an admitted voter would campaign at
    // least twice in this interval.
    tokio::time::sleep(ELECTION_TIMEOUT_MAX * 3).await;
    assert_eq!(
        cluster.store(voter).status().term,
        term,
        "a voter whose credentials admit no connection does not raise its term"
    );
    assert_eq!(
        cluster.store(leader).status().leader_id,
        Some(cluster.store(leader).status().node_id),
        "the survivors keep their leader"
    );

    // Fresh credentials admit connections again and the voter reconnects.
    cluster.set_local_credentials_admitted(voter, true);
    cluster.set_node_online(voter, true);
    let (rejoined_leader, rejoined_term) = stable_leader(&cluster).await;
    assert_eq!(
        (rejoined_leader, rejoined_term),
        (leader, term),
        "the voter rejoins as a follower of the same leader in the same term"
    );
    cluster.shutdown().await;
}
