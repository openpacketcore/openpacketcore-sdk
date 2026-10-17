//! Explicit real-engine leadership changes for bounded functional fixtures.

use super::*;
use opc_consensus::engine::{
    error::RaftError,
    raft::{VoteRequest, VoteResponse},
    Vote,
};

#[derive(Clone, Debug)]
struct Exchange {
    source: SessionConsensusNodeId,
    target: SessionConsensusNodeId,
    request: VoteRequest<SessionConsensusNodeId>,
    response: VoteResponse<SessionConsensusNodeId>,
}

#[derive(Default)]
pub(crate) struct VoteObservation(std::sync::Mutex<Vec<Exchange>>);

impl VoteObservation {
    pub(crate) fn record(
        &self,
        target: SessionConsensusNodeId,
        request: &SessionConsensusWireRequest,
        response: &SessionConsensusWireResponse,
    ) {
        let vote = opc_consensus::decode_bounded(&request.payload).expect("real vote request");
        let reply: Result<VoteResponse<SessionConsensusNodeId>, RaftError<SessionConsensusNodeId>> =
            opc_consensus::decode_bounded(response.result.as_ref().expect("vote wire response"))
                .expect("real vote response");
        self.0.lock().unwrap().push(Exchange {
            source: request.sender,
            target,
            request: vote,
            response: reply.expect("engine vote response"),
        });
    }
}

/// A designated campaign in a three-member functional fixture.
///
/// Prepare before partitioning the current leader. `elect_once` observes real
/// lease expiry and requests one persisted, transported Openraft campaign.
/// Keep this guard until rejoined members are ready for a designated-campaign
/// scenario. For automatic failover, drop it after setup and before introducing
/// the fault, then observe recovery without calling `elect_once`.
#[must_use]
pub struct ControlledConsensusElection<'a> {
    cluster: &'a ConsensusTestCluster,
    old: usize,
    candidate: usize,
    term: u64,
    prefix: u64,
    requested: bool,
    votes: Arc<VoteObservation>,
}

impl ConsensusTestCluster {
    /// Synchronize the applied prefix and suppress competing automatic
    /// campaigns during setup. Drop the returned guard before the fault when
    /// testing automatic failover. Retain it only for a designated campaign.
    /// Normal operation deadlines remain active throughout.
    pub async fn prepare_election(&self, candidate: usize) -> ControlledConsensusElection<'_> {
        assert_eq!(
            self.stores.len(),
            3,
            "controlled election requires three voters"
        );
        let leader = self.stores[0]
            .status()
            .leader_id
            .expect("ready initial leader");
        let old = self
            .stores
            .iter()
            .position(|store| store.status().node_id == leader)
            .unwrap();
        assert!(
            candidate < self.stores.len() && candidate != old,
            "designated survivor"
        );
        assert!(
            !self.election_controlled.swap(true, Ordering::AcqRel),
            "one election guard per fixture"
        );
        let status = self.stores[old].status();
        let election = ControlledConsensusElection {
            cluster: self,
            old,
            candidate,
            term: status.term,
            prefix: status.applied_index.expect("committed initial prefix"),
            requested: false,
            votes: Arc::default(),
        };
        for store in &self.stores {
            store.set_automatic_election_for_test(false);
        }
        tokio::time::timeout(CONSENSUS_TEST_TRANSITION_TIMEOUT, async {
            for (index, store) in self.stores.iter().enumerate() {
                if index != old {
                    store
                        .wait_for_status_for_test(|status| {
                            status.leader_id == Some(leader)
                                && status.term == election.term
                                && status.applied_index >= Some(election.prefix)
                        })
                        .await;
                }
            }
        })
        .await
        .expect("normal-time successor prefix synchronization");
        for path in self.paths.values() {
            *path.election_observation.lock().unwrap() = Some(election.votes.clone());
        }
        election
    }
}

impl ControlledConsensusElection<'_> {
    /// Elect the prepared survivor once, after every path incident to the old
    /// leader is isolated. The unchanged 30-second acquisition bound includes
    /// quiescence, actual lease expiry, real votes and fresh quorum authority.
    pub async fn elect_once(&mut self) {
        assert!(!self.requested, "one designated campaign, without a retry");
        self.requested = true;
        tokio::time::timeout(Duration::from_secs(30), async {
            for ((source, target), path) in &self.cluster.paths {
                if *source == self.old || *target == self.old {
                    assert!(
                        !path.online.load(Ordering::Acquire),
                        "isolate old-leader traffic before campaigning"
                    );
                    let _quiesced = path.admitted.write().await;
                }
            }
            for (index, store) in self.cluster.stores.iter().enumerate() {
                if index != self.old {
                    store.wait_for_vote_lease_expiry_for_test().await.unwrap();
                }
            }
            self.cluster.stores[self.candidate]
                .trigger_election_for_test()
                .await
                .unwrap();
            let leader = self.cluster.stores[self.candidate].status().node_id;
            for (index, store) in self.cluster.stores.iter().enumerate() {
                if index != self.old {
                    store
                        .wait_for_status_for_test(|status| {
                            status.leader_id == Some(leader)
                                && status.term == self.term + 1
                                && status.applied_index >= Some(self.prefix)
                        })
                        .await;
                    assert!(
                        store.probe_durable_readiness().await.is_ready(),
                        "fresh survivor quorum authority"
                    );
                }
            }
            let votes = self.votes.0.lock().unwrap();
            assert_eq!(
                votes.len(),
                1,
                "one real peer vote, no competing or repeated campaign"
            );
            let vote = &votes[0];
            assert_eq!(vote.source, leader);
            assert_ne!(vote.target, self.cluster.stores[self.old].status().node_id);
            assert_eq!(vote.request.vote, Vote::new(self.term + 1, leader));
            assert!(vote.request.last_log_id.map(|id| id.index) >= Some(self.prefix));
            assert!(vote.response.vote_granted);
            assert_eq!(vote.response.vote, vote.request.vote);
        })
        .await
        .expect("consensus test node did not become durable-ready within 30 seconds");
    }
}

impl Drop for ControlledConsensusElection<'_> {
    fn drop(&mut self) {
        for path in self.cluster.paths.values() {
            *path.election_observation.lock().unwrap() = None;
        }
        for store in &self.cluster.stores {
            store.set_automatic_election_for_test(true);
        }
        self.cluster
            .election_controlled
            .store(false, Ordering::Release);
    }
}
