use super::*;

use opc_consensus::engine::{
    error::RaftError,
    raft::{VoteRequest, VoteResponse},
    Vote,
};
use opc_consensus::test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
use scripted_election::schedule::{self, ElectionSchedule};
use tokio::sync::{watch, Barrier};
use tokio::time::Instant;

#[derive(Clone)]
struct Exchange {
    source: ConfigConsensusNodeId,
    sent_at: Instant,
    replied_at: Instant,
    request: VoteRequest<ConfigConsensusNodeId>,
    response: VoteResponse<ConfigConsensusNodeId>,
}

/// Deliver the first two requests only after both real candidates self-vote.
pub(super) struct SplitVote {
    term: u64,
    arrivals: watch::Sender<Vec<(Instant, VoteRequest<ConfigConsensusNodeId>)>>,
    both_candidates: Barrier,
    replies: watch::Sender<Vec<Exchange>>,
}

impl SplitVote {
    pub(super) async fn before_delivery(&self, request: &ConsensusWireRequest) {
        let (_, vote): (u16, VoteRequest<ConfigConsensusNodeId>) =
            opc_consensus::decode_bounded(&request.payload).expect("retention vote request");
        assert_eq!(
            vote.vote,
            Vote::new(vote.vote.leader_id.term, request.sender)
        );
        assert!(
            matches!(vote.vote.leader_id.term, term if term == self.term || term == self.term + 1)
        );
        let first_round = vote.vote.leader_id.term == self.term;
        self.arrivals.send_modify(|arrivals| {
            arrivals.push((Instant::now(), vote));
        });
        if first_round {
            self.both_candidates.wait().await;
        }
    }

    pub(super) fn after_delivery(
        &self,
        source: ConfigConsensusNodeId,
        response: &ConsensusWireResponse,
    ) {
        let (_, response): (
            u16,
            Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
        ) = opc_consensus::decode_bounded(response.result.as_ref().expect("retention vote wire"))
            .expect("retention vote response");
        let response = response.expect("real peer vote");
        let (sent_at, request) = self
            .arrivals
            .borrow()
            .iter()
            .find(|(_, request)| request.vote == Vote::new(response.vote.leader_id.term, source))
            .cloned()
            .expect("response belongs to actual request");
        self.replies.send_modify(|replies| {
            replies.push(Exchange {
                source,
                sent_at,
                replied_at: Instant::now(),
                request,
                response,
            });
        });
    }
}

pub(super) struct RetentionElection {
    pub scripts: [ElectionRngScript; 3],
    pub offset: Duration,
    started: Instant,
    schedule: ElectionSchedule,
}

impl RetentionElection {
    pub(super) async fn new() -> Self {
        let config = durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap();
        // The same raw sample and ticker offset as the sibling one-split test.
        let sample = 3_u64 << 62;
        let calibration = ElectionRngScript::new([sample]);
        let sampled_timeout = calibration
            .scope(async {
                Duration::from_millis(config.new_rand_election_timeout::<ScriptedElectionRuntime>())
            })
            .await;
        calibration.assert_exhausted();
        let schedule = ElectionSchedule::new(&config, sampled_timeout);
        Self {
            scripts: [
                ElectionRngScript::new([sample; 2]),
                ElectionRngScript::new([sample; 3]),
                ElectionRngScript::new([sample; 2]),
            ],
            offset: schedule.tick / 6,
            started: Instant::now(),
            schedule,
        }
    }

    pub(super) async fn elect(
        &self,
        cluster: &ThreeNodeCluster,
        original_leader: usize,
        old_id: ConfigConsensusNodeId,
        old_term: u64,
    ) -> usize {
        assert_eq!(original_leader, 0);
        let isolated = Instant::now();
        assert_eq!(isolated - self.started, self.offset);
        let first = self.schedule.campaign(self.offset, Duration::ZERO, true);
        let second = self.schedule.campaign(self.offset, self.offset, true);
        let retry = self.schedule.campaign(first, Duration::ZERO, false);
        let election_bound = retry - self.offset;
        assert!(election_bound > CLUSTER_TRANSITION_TIMEOUT);
        assert!(retry < self.schedule.campaign(second, self.offset, false));
        assert!(
            second - first < DURABLE_CONSENSUS_TIMING_PROFILE.rpc_timeout(ConsensusRpcFamily::Vote)
        );
        let gate = Arc::new(SplitVote {
            term: old_term + 1,
            arrivals: watch::channel(Vec::new()).0,
            both_candidates: Barrier::new(2),
            replies: watch::channel(Vec::new()).0,
        });
        for path in [(1, 2), (2, 1)] {
            *cluster.paths[&path].retention_vote.lock().unwrap() = Some(gate.clone());
        }
        let drive = async {
            let mut instants = vec![(self.offset + CLUSTER_TRANSITION_TIMEOUT, None)];
            for index in 1..3 {
                let phase = if index == 2 {
                    self.offset
                } else {
                    Duration::ZERO
                };
                schedule::tick_registered(
                    &mut self.scripts[index].sleeps(),
                    self.started + phase,
                    self.schedule.tick,
                )
                .await;
                let mut tick = phase + self.schedule.tick;
                while tick <= retry {
                    instants.push((tick, Some(index)));
                    tick += self.schedule.tick;
                }
            }
            instants.sort_unstable();
            for (tick, index) in instants {
                tokio::time::advance(self.started + tick - Instant::now()).await;
                if let Some(index) = index {
                    schedule::tick_registered(
                        &mut self.scripts[index].sleeps(),
                        self.started + tick,
                        self.schedule.tick,
                    )
                    .await;
                } else {
                    // The former aggregate wait expires before this legal
                    // schedule can win. Both real split votes remain denied.
                    assert_eq!(isolated.elapsed(), CLUSTER_TRANSITION_TIMEOUT);
                    assert_eq!(gate.replies.borrow().len(), 2);
                    for store in &cluster.stores[1..] {
                        let state = store.status();
                        assert_eq!(state.term, old_term + 1);
                        assert_eq!(state.leader_id, None);
                    }
                }
                if tick == first {
                    gate.arrivals
                        .subscribe()
                        .wait_for(|arrivals| arrivals.len() == 1)
                        .await
                        .unwrap();
                    assert_eq!(cluster.stores[1].status().term, old_term + 1);
                    assert_eq!(cluster.stores[2].status().term, old_term);
                }
                if tick == second {
                    gate.replies
                        .subscribe()
                        .wait_for(|replies| replies.len() == 2)
                        .await
                        .unwrap();
                    assert!(gate
                        .replies
                        .borrow()
                        .iter()
                        .all(|reply| !reply.response.vote_granted));
                    eprintln!("retention election: real split at {:?}/{:?}; old guard {:?}; computed bound {:?}", first, second, CLUSTER_TRANSITION_TIMEOUT, election_bound);
                }
            }
        };
        // The finite schedule drives every tick and the real vote deliveries.
        // Observe its result without coupling it to host scheduling latency.
        let election = async {
            loop {
                for index in 0..3 {
                    if index == original_leader {
                        continue;
                    }
                    let state = cluster.stores[index].status();
                    if state.term > old_term
                        && state.leader_id == Some(state.node_id)
                        && state.node_id != old_id
                    {
                        return index;
                    }
                }
                tokio::task::yield_now().await;
            }
        };
        tokio::pin!(election);
        let replacement = tokio::select! {
            result = election.as_mut() => result,
            () = drive => election.await,
        };
        let expected_leader = cluster.stores[1].status().node_id;
        while !cluster.stores[1..].iter().all(|store| {
            let state = store.status();
            state.term == old_term + 2 && state.leader_id == Some(expected_leader)
        }) {
            tokio::task::yield_now().await;
        }
        assert_eq!(replacement, 1);
        assert_eq!(isolated.elapsed(), election_bound);
        let replies = gate.replies.borrow();
        assert_eq!(replies.len(), 3, "one split and one automatic retry");
        for exchange in replies
            .iter()
            .filter(|reply| reply.request.vote.leader_id.term == old_term + 1)
        {
            let target = if exchange.source == cluster.stores[1].status().node_id {
                cluster.stores[2].status().node_id
            } else {
                cluster.stores[1].status().node_id
            };
            assert_eq!(
                exchange.request.vote,
                Vote::new(old_term + 1, exchange.source)
            );
            assert_eq!(exchange.response.vote, Vote::new(old_term + 1, target));
            assert!(!exchange.response.vote_granted);
            assert_eq!(
                exchange.sent_at - self.started,
                if exchange.source == expected_leader {
                    first
                } else {
                    second
                }
            );
            assert_eq!(exchange.replied_at - self.started, second);
        }
        let winning = replies
            .iter()
            .find(|reply| reply.response.vote_granted)
            .unwrap();
        assert_eq!(
            winning.request.vote,
            Vote::new(old_term + 2, expected_leader)
        );
        assert_eq!(winning.response.vote, winning.request.vote);
        assert_eq!(winning.sent_at - self.started, retry);
        assert_eq!(winning.replied_at - self.started, retry);
        drop(replies);
        for script in &self.scripts {
            script.finish();
        }
        for path in [(1, 2), (2, 1)] {
            *cluster.paths[&path].retention_vote.lock().unwrap() = None;
        }
        replacement
    }
}
