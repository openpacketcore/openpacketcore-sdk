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

#[path = "../../../opc-consensus/tests/reelection/ticks.rs"]
pub(super) mod ticks;

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
    runtime_origin: Instant,
    schedule: ElectionSchedule,
}

impl RetentionElection {
    pub(super) async fn new(runtime_origin: Instant) -> Self {
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
            runtime_origin,
            schedule,
        }
    }

    fn last_tick(&self, index: usize) -> (Instant, Instant) {
        // These are the two followers: they have no replication worker sleeps.
        // On normal time, recording sleep_until occurs after its deadline was
        // computed, so deadline - recorded_at is slightly less than one tick.
        self.scripts[index]
            .sleeps()
            .borrow()
            .last()
            .copied()
            .expect("registered ticker")
    }

    async fn advance_to(&self, at: Instant, ticks: &ticks::ProcessedTicks) {
        // Tokio rounds deadlines up to milliseconds from runtime creation.
        // Setup used normal time, so its recorded deadlines need not lie on
        // that grid. Align the healthy ticker wakes before deriving phases.
        let millis = (at - self.runtime_origin).as_nanos().div_ceil(1_000_000);
        let at = self.runtime_origin
            + Duration::from_millis(u64::try_from(millis).expect("finite fixture clock"));
        let due: Vec<_> = (1..3)
            .filter(|index| self.last_tick(*index).1 <= at)
            .map(|index| (index, self.scripts[index].sleeps().borrow().len()))
            .collect();
        tokio::time::advance(at - Instant::now()).await;
        for (index, sent_ticks) in due {
            schedule::tick_registered(&mut self.scripts[index].sleeps(), at, self.schedule.tick)
                .await;
            ticks.wait(index as u64 + 1, at, sent_ticks).await;
        }
    }

    /// Setup ran on real time. Drain any queued ticks, then legally delay one
    /// ticker wake while the leader is healthy to retain the one-split phase
    /// spacing. Every advance waits for the follower cores, not just tickers.
    /// The command after this method anchors both follower leases at one time.
    pub(super) async fn settle(&mut self, ticks: &ticks::ProcessedTicks) {
        // A deadline just before the pause can still occupy the next wheel
        // slot. Reach that slot before waiting for an overdue tick to drain.
        self.advance_to(Instant::now(), ticks).await;
        let now = Instant::now();
        for index in 1..3 {
            self.scripts[index]
                .sleeps()
                .wait_for(|sleeps| sleeps.last().is_some_and(|(_, deadline)| *deadline > now))
                .await
                .expect("ticker settled after pause");
            let (at, _) = self.last_tick(index);
            let registrations = self.scripts[index].sleeps().borrow().len();
            if registrations > 1 {
                ticks.wait(index as u64 + 1, at, registrations - 1).await;
            }
        }
        // First make node 2's next tick precede node 3's. Deferring the
        // earlier wake by less than one tick then gives the desired spacing.
        if self.last_tick(2).1 < self.last_tick(1).1 {
            self.advance_to(self.last_tick(2).1, ticks).await;
        }
        let first = self.last_tick(1).1;
        let second = self.last_tick(2).1;
        assert!(
            first < second,
            "independently registered normal-clock tickers"
        );
        if second - first >= self.offset {
            self.advance_to(second - self.offset, ticks).await;
            self.advance_to(second, ticks).await;
        } else {
            self.advance_to(first, ticks).await;
            self.advance_to(first + self.offset, ticks).await;
        }
        // Derive phases from the real registrations, including any wake delay.
        self.started = self.last_tick(1).0;
        assert_eq!(self.last_tick(2).0 - self.started, self.offset);
        assert_eq!(Instant::now(), self.last_tick(2).0);
    }

    pub(super) async fn elect(
        &self,
        cluster: &ThreeNodeCluster,
        original_leader: usize,
        old_id: ConfigConsensusNodeId,
        old_term: u64,
        ticks: &ticks::ProcessedTicks,
    ) -> usize {
        assert_eq!(original_leader, 0);
        let isolated = Instant::now();
        assert_eq!(isolated - self.started, self.offset);
        let phases = [self.last_tick(1).0, self.last_tick(2).0].map(|at| at - self.started);
        let first = self.schedule.campaign(self.offset, phases[0], true);
        let second = self.schedule.campaign(self.offset, phases[1], true);
        let retry = self.schedule.campaign(first, phases[0], false);
        let election_bound = retry - self.offset;
        assert!(election_bound > CLUSTER_TRANSITION_TIMEOUT);
        assert!(retry < self.schedule.campaign(second, phases[1], false));
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
                let phase = phases[index - 1];
                schedule::tick_registered(
                    &mut self.scripts[index].sleeps(),
                    self.started + phase,
                    self.schedule.tick,
                )
                .await;
                let sent_ticks = self.scripts[index].sleeps().borrow().len() - 1;
                ticks
                    .wait(index as u64 + 1, self.started + phase, sent_ticks)
                    .await;
                let mut tick = phase + self.schedule.tick;
                while tick <= retry {
                    instants.push((tick, Some(index)));
                    tick += self.schedule.tick;
                }
            }
            instants.sort_unstable();
            for (tick, index) in instants {
                // Count before the advance: the winning campaign can create
                // replication-worker sleeps after this final follower tick.
                let sent_ticks = index.map(|index| self.scripts[index].sleeps().borrow().len());
                tokio::time::advance(self.started + tick - Instant::now()).await;
                if let Some(index) = index {
                    schedule::tick_registered(
                        &mut self.scripts[index].sleeps(),
                        self.started + tick,
                        self.schedule.tick,
                    )
                    .await;
                    ticks
                        .wait(index as u64 + 1, self.started + tick, sent_ticks.unwrap())
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
                    eprintln!(
                        "retention election: real split at {first:?}/{second:?}; \
                         old guard {CLUSTER_TRANSITION_TIMEOUT:?}; \
                         computed bound {election_bound:?}"
                    );
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
