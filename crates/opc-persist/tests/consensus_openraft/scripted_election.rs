use super::*;

use opc_consensus::engine::{
    error::RaftError,
    raft::{VoteRequest, VoteResponse},
    Vote,
};
use opc_consensus::test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
use tokio::sync::{watch, Semaphore};
use tokio::time::Instant;

#[path = "../../../opc-consensus/tests/reelection/schedule.rs"]
pub(super) mod schedule;

/// Hold the first automatic survivor campaign until the test has observed the
/// sender's persisted self-vote and the peer's unchanged preceding term.
pub(super) struct FirstVote {
    source: ConfigConsensusNodeId,
    term: u64,
    sent: watch::Sender<Option<(Instant, VoteRequest<ConfigConsensusNodeId>)>>,
    release: Semaphore,
    replied: watch::Sender<Option<(Instant, VoteResponse<ConfigConsensusNodeId>)>>,
}

impl FirstVote {
    pub(super) async fn before_delivery(&self, request: &ConsensusWireRequest) {
        assert_eq!(
            request.sender, self.source,
            "only the scheduled voter campaigns"
        );
        let (_, vote): (u16, VoteRequest<ConfigConsensusNodeId>) =
            opc_consensus::decode_bounded(&request.payload).expect("vote request");
        assert_eq!(vote.vote, Vote::new(self.term, self.source));
        assert!(self
            .sent
            .send_replace(Some((Instant::now(), vote)))
            .is_none());
        self.release
            .acquire()
            .await
            .expect("release first vote")
            .forget();
    }

    pub(super) fn after_delivery(&self, response: &ConsensusWireResponse) {
        let (_, vote): (
            u16,
            Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
        ) = opc_consensus::decode_bounded(response.result.as_ref().expect("vote wire response"))
            .expect("vote response");
        assert!(self
            .replied
            .send_replace(Some((Instant::now(), vote.expect("peer vote"))))
            .is_none());
    }
}

pub(super) struct ElectedCluster {
    pub cluster: ThreeNodeCluster,
    pub first_id: TxId,
    pub old_leader: usize,
    pub old_leader_id: ConfigConsensusNodeId,
    pub old_term: u64,
    pub survivors: Vec<usize>,
    pub new_leader_id: ConfigConsensusNodeId,
    pub new_term: u64,
}

pub(super) async fn elect_survivor() -> ElectedCluster {
    let config = durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap();
    // The unchanged engine maps these to 5.75s and 7.25s, respectively. Their
    // lease-plus-timeout deadlines land on different production ticker slots.
    let early_sample = 1_u64 << 62;
    let late_sample = 3_u64 << 62;
    let calibration = ElectionRngScript::new([early_sample, late_sample]);
    let (early_timeout, late_timeout) = calibration
        .scope(async {
            (
                Duration::from_millis(
                    config.new_rand_election_timeout::<ScriptedElectionRuntime>(),
                ),
                Duration::from_millis(
                    config.new_rand_election_timeout::<ScriptedElectionRuntime>(),
                ),
            )
        })
        .await;
    calibration.assert_exhausted();
    let schedule = schedule::ElectionSchedule::new(&config, early_timeout);
    let late_schedule = schedule::ElectionSchedule::new(&config, late_timeout);
    let scripts = [
        ElectionRngScript::new([late_sample; 2]),
        ElectionRngScript::new([early_sample; 2]),
        ElectionRngScript::new([late_sample; 1]),
    ];
    let started = Instant::now();
    let cluster = ThreeNodeCluster::build_with_election_scripts(
        [[0x55; 32]; 3],
        FixtureStorage::Legacy,
        None,
        Some(&scripts),
    )
    .await;
    for script in &scripts {
        schedule::tick_registered(&mut script.sleeps(), started, schedule.tick).await;
    }
    let (one, two, three) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster(),
    );
    one.expect("initialize node one");
    two.expect("initialize node two");
    three.expect("initialize node three");
    let initial_leader = cluster.stores[0].status().node_id;
    while !cluster
        .stores
        .iter()
        .all(|store| store.status().leader_id == Some(initial_leader))
    {
        tokio::task::yield_now().await;
    }
    cluster.wait_ready().await;
    let first_id = TxId::new();
    cluster.stores[0]
        .append_attested_commit(attested(commit(first_id, None, 1, 10), audit(first_id)))
        .await
        .expect("replicated first commit");
    for store in &cluster.stores {
        store
            .wait_for_committed_change(ConfigVersion::INITIAL)
            .await
            .expect("equal pre-failover history");
    }
    let old_leader = cluster.leader();
    assert_eq!(old_leader, 0);
    let old_leader_id = cluster.stores[old_leader].status().node_id;
    let old_term = cluster.stores[old_leader].status().term;
    let survivors = vec![1, 2];
    let expected_leader = cluster.stores[1].status().node_id;
    let gate = Arc::new(FirstVote {
        source: expected_leader,
        term: old_term + 1,
        sent: watch::channel(None).0,
        release: Semaphore::new(0),
        replied: watch::channel(None).0,
    });
    for path in [(1, 2), (2, 1)] {
        *cluster.paths[&path].election_vote.lock().unwrap() = Some(gate.clone());
    }
    cluster.isolate(old_leader);
    let isolated = Instant::now();
    assert_eq!(
        isolated, started,
        "formation and disk work consume no protocol time"
    );
    let bound = schedule.campaign(Duration::ZERO, Duration::ZERO, true);
    assert!(bound < late_schedule.campaign(Duration::ZERO, Duration::ZERO, true));
    // Every production tick is delivered at its own phase. No manual election
    // trigger or campaign retry is used, and no time passes during disk work.
    let mut tick = schedule.tick;
    while tick <= bound {
        tokio::time::advance(started + tick - Instant::now()).await;
        for script in &scripts {
            schedule::tick_registered(&mut script.sleeps(), started + tick, schedule.tick).await;
        }
        tick += schedule.tick;
    }
    let (sent_at, request) = gate
        .sent
        .subscribe()
        .wait_for(Option::is_some)
        .await
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(sent_at - isolated, bound);
    assert_eq!(cluster.stores[1].status().term, old_term + 1);
    assert_eq!(cluster.stores[2].status().term, old_term);
    assert_eq!(cluster.stores[1].status().leader_id, None);
    assert_eq!(
        request.last_log_id.map(|id| id.index),
        cluster.stores[2].status().applied_index
    );
    gate.release.add_permits(1);
    let (replied_at, response) = gate
        .replied
        .subscribe()
        .wait_for(Option::is_some)
        .await
        .unwrap()
        .clone()
        .unwrap();
    assert!(response.vote_granted);
    assert_eq!(response.vote, request.vote);
    assert_eq!(replied_at - isolated, bound);
    let (new_leader_id, new_term) = loop {
        let one = cluster.stores[1].status();
        let two = cluster.stores[2].status();
        if one.leader_id == Some(expected_leader)
            && two.leader_id == one.leader_id
            && one.term == old_term + 1
            && two.term == one.term
        {
            break (expected_leader, one.term);
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(
        isolated.elapsed(),
        bound,
        "both survivors elect at the computed protocol bound"
    );
    for script in &scripts {
        script.finish();
    }
    for path in [(1, 2), (2, 1)] {
        *cluster.paths[&path].election_vote.lock().unwrap() = None;
    }
    ElectedCluster {
        cluster,
        first_id,
        old_leader,
        old_leader_id,
        old_term,
        survivors,
        new_leader_id,
        new_term,
    }
}
