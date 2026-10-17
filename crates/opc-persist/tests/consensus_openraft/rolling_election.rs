//! Finite election inputs for the retained mixed-protocol rollout.

use super::*;

use opc_consensus::engine::{
    error::RaftError,
    raft::{PreVoteRequest, PreVoteResponse, VoteRequest, VoteResponse},
    Vote,
};
use opc_consensus::test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
use scripted_election::schedule::{self, ElectionSchedule};
use tokio::sync::{oneshot, watch, Barrier};
use tokio::time::Instant;
use tracing::Instrument;

#[path = "../../../opc-consensus/tests/reelection/delivery.rs"]
mod delivery;
pub(super) use delivery::TickDelivery;

const EARLY: u64 = 0;
const LATE: u64 = 3_u64 << 62;

#[derive(Clone)]
struct Exchange {
    target: ConfigConsensusNodeId,
    sent_at: Instant,
    replied_at: Instant,
    request: VoteRequest<ConfigConsensusNodeId>,
    response: VoteResponse<ConfigConsensusNodeId>,
}

/// Only reorder actual requests: each split is delivered after both candidates
/// have persisted their own votes. The real handlers produce every response.
pub(crate) struct VoteGate {
    first_term: u64,
    split_rounds: u64,
    arrivals: watch::Sender<
        Vec<(
            ConfigConsensusNodeId,
            Instant,
            VoteRequest<ConfigConsensusNodeId>,
        )>,
    >,
    both_candidates: Barrier,
    both_pre_votes: Barrier,
    replies: watch::Sender<Vec<Exchange>>,
}

impl VoteGate {
    pub(crate) async fn after_pre_vote(
        &self,
        request: &ConsensusWireRequest,
        response: &ConsensusWireResponse,
    ) {
        let (_, rpc): (u16, PreVoteRequest<ConfigConsensusNodeId>) =
            opc_consensus::decode_bounded(&request.payload).unwrap();
        let (_, reply): (
            u16,
            Result<PreVoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
        ) = opc_consensus::decode_bounded(response.result.as_ref().unwrap()).unwrap();
        assert!(
            reply.unwrap().vote_granted,
            "equal logs permit both inquiries"
        );
        if rpc.vote.leader_id.term < self.first_term + self.split_rounds {
            self.both_pre_votes.wait().await;
        }
    }

    pub(crate) async fn before_delivery(
        &self,
        target: ConfigConsensusNodeId,
        request: &ConsensusWireRequest,
    ) {
        let (_, vote): (u16, VoteRequest<ConfigConsensusNodeId>) =
            opc_consensus::decode_bounded(&request.payload).expect("rolling vote request");
        let term = vote.vote.leader_id.term;
        assert_eq!(vote.vote, Vote::new(term, request.sender));
        assert!((self.first_term..=self.first_term + self.split_rounds).contains(&term));
        self.arrivals.send_modify(|arrivals| {
            arrivals.push((target, Instant::now(), vote));
        });
        if term < self.first_term + self.split_rounds {
            self.both_candidates.wait().await;
        }
    }

    pub(crate) fn after_delivery(
        &self,
        source: ConfigConsensusNodeId,
        target: ConfigConsensusNodeId,
        response: &ConsensusWireResponse,
    ) {
        let (_, response): (
            u16,
            Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
        ) = opc_consensus::decode_bounded(response.result.as_ref().expect("rolling vote wire"))
            .expect("rolling vote response");
        let response = response.expect("real rolling peer vote");
        let (_, sent_at, request) = self
            .arrivals
            .borrow()
            .iter()
            .find(|(peer, _, request)| {
                *peer == target && request.vote == Vote::new(response.vote.leader_id.term, source)
            })
            .cloned()
            .expect("response belongs to actual request");
        self.replies.send_modify(|replies| {
            replies.push(Exchange {
                target,
                sent_at,
                replied_at: Instant::now(),
                request,
                response,
            })
        });
    }

    async fn observed(&self, count: usize) -> Vec<Exchange> {
        self.replies
            .subscribe()
            .wait_for(|replies| replies.len() >= count)
            .await
            .expect("real vote replies")
            .clone()
    }
}

pub(super) struct RollingElection {
    scripts: [Option<ElectionRngScript>; 3],
    ticks: TickDelivery,
    runtime_origin: Instant,
    early: ElectionSchedule,
    late: ElectionSchedule,
    leader_stops: usize,
}

impl RollingElection {
    pub(super) async fn new(runtime_origin: Instant, ticks: TickDelivery) -> Self {
        let config = durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap();
        let calibration = ElectionRngScript::new([EARLY, LATE]);
        let (early, late) = calibration
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
        Self {
            scripts: [None, None, None],
            ticks,
            runtime_origin,
            early: ElectionSchedule::new(&config, early),
            late: ElectionSchedule::new(&config, late),
            leader_stops: 0,
        }
    }

    fn script(&self, index: usize) -> &ElectionRngScript {
        self.scripts[index]
            .as_ref()
            .expect("scripted running voter")
    }

    fn clock_slot(&self, at: Instant) -> Instant {
        let millis = (at - self.runtime_origin).as_nanos().div_ceil(1_000_000);
        self.runtime_origin + Duration::from_millis(u64::try_from(millis).unwrap())
    }

    pub(super) async fn align_empty(&self) {
        tokio::time::advance(self.clock_slot(Instant::now()) - Instant::now()).await;
    }

    pub(super) async fn open(
        &mut self,
        fleet: &mut RetainedFleet,
        index: usize,
        protocol: Protocol,
        early: bool,
    ) {
        assert!(self.scripts[index].is_none());
        self.ticks.reset_after_shutdown(index as u64 + 1);
        let script = ElectionRngScript::new([if early { EARLY } else { LATE }]);
        script
            .scope(
                fleet
                    .open(index, protocol, CLUSTER_TRANSITION_TIMEOUT)
                    .instrument(delivery::node_span(index as u64 + 1)),
            )
            .await;
        assert_eq!(
            script.draws().len(),
            1,
            "construction samples one election timeout"
        );
        script.assert_exhausted();
        self.scripts[index] = Some(script);
    }

    async fn advance(&self, at: Instant, indices: &[usize]) {
        tokio::time::advance(at - Instant::now()).await;
        for &index in indices {
            schedule::tick_registered(&mut self.script(index).sleeps(), at, self.late.tick).await;
            self.ticks.wait(index as u64 + 1, at).await;
        }
    }

    pub(super) async fn observe_reopened(
        &self,
        fleet: &RetainedFleet,
        indices: &[usize],
        retained_leader: ConfigConsensusNodeId,
    ) {
        let started = Instant::now();
        let old_term = fleet.store(0).status().term;
        for &index in indices {
            assert_eq!(self.script(index).draws()[0].0, started);
            schedule::tick_registered(&mut self.script(index).sleeps(), started, self.late.tick)
                .await;
            assert_eq!(fleet.store(index).status().term, old_term);
        }
        let stores = indices
            .iter()
            .map(|&index| fleet.store(index).clone())
            .collect::<Vec<_>>();
        if stores
            .iter()
            .any(|store| store.status().node_id == retained_leader)
        {
            // A retained committed self-vote restores its leader at startup.
            // No campaign or new term is required when that voter is present.
            wait_for_leader(&stores, retained_leader, old_term).await;
            assert_eq!(Instant::now(), started);
            for &index in indices {
                assert_eq!(self.script(index).draws().len(), 1);
            }
        } else {
            // The final two-current-voter recovery also works when the absent
            // legacy voter last led. Only the early voter's real timer expires
            // before the observed majority election; no campaign is forced.
            assert_eq!(indices, &[0, 1]);
            assert_eq!(self.script(0).draws()[0].1, EARLY);
            assert_eq!(self.script(1).draws()[0].1, LATE);
            self.script(0).plan_next([LATE]);
            let gate = Arc::new(VoteGate {
                first_term: old_term + 1,
                split_rounds: 0,
                arrivals: watch::channel(Vec::new()).0,
                both_candidates: Barrier::new(2),
                both_pre_votes: Barrier::new(2),
                replies: watch::channel(Vec::new()).0,
            });
            *fleet.paths[&(0, 1)].rolling_vote.lock().unwrap() = Some(gate.clone());
            let bound = self.early.campaign(Duration::ZERO, Duration::ZERO, true);
            assert!(bound < self.late.campaign(Duration::ZERO, Duration::ZERO, true));
            let mut tick = self.early.tick;
            while tick <= bound {
                self.advance(started + tick, indices).await;
                tick += self.early.tick;
            }
            let replies = gate.observed(1).await;
            assert_eq!(replies.len(), 1);
            let won = &replies[0];
            assert_eq!(won.sent_at - started, bound);
            assert_eq!(won.replied_at - started, bound);
            assert!(won.response.vote_granted);
            let leader = fleet.store(0).status().node_id;
            assert_eq!(won.request.vote, Vote::new(old_term + 1, leader));
            assert_eq!(won.response.vote, won.request.vote);
            wait_for_leader(&stores, leader, old_term + 1).await;
            assert_eq!(started.elapsed(), bound);
            *fleet.paths[&(0, 1)].rolling_vote.lock().unwrap() = None;
        }
        for &index in indices {
            self.script(index).assert_exhausted();
        }
    }

    // Start the original write when its leader stops. A legal two-split retry
    // outlasts that call's deadline; recover with the same commit after election.
    pub(super) async fn stop_and_elect(
        &mut self,
        fleet: &mut RetainedFleet,
        index: usize,
        live: &[usize],
        writer: usize,
    ) {
        assert!(live.contains(&writer), "the in-flight writer must survive");
        let state = fleet.store(index).status();
        if state.leader_id != Some(state.node_id) {
            fleet.stop_disconnected(index).await;
            self.scripts[index].take().unwrap().finish();
            fleet.append(writer).await;
            return;
        }
        self.leader_stops += 1;
        let split_rounds = if self.leader_stops == 2 { 2 } else { 1 };
        tokio::time::pause();
        schedule::with_frozen_time(async {
            // Delay each healthy ticker by at most one tick to align its next
            // wake. Completion is observed at the core, including the leader.
            self.advance(self.clock_slot(Instant::now() + self.late.tick), &[0, 1, 2])
                .await;
            // Replay the existing request to give every follower the same
            // committed-vote instant without adding a configuration version.
            let stored = fleet.store(index).load_latest().await.unwrap().unwrap();
            assert_eq!(stored.record.tx_id, fleet.head);
            let before = fleet.store(index).status().applied_index;
            fleet
                .store(index)
                .append_attested_commit(attested(stored.record, audit(fleet.head)))
                .await
                .expect("head replay anchors retained voter leases");
            while fleet.store(index).status().applied_index <= before {
                tokio::task::yield_now().await;
            }
            let anchor = fleet.store(index).status().applied_index;
            while !(0..3).all(|node| fleet.store(node).status().applied_index >= anchor) {
                tokio::task::yield_now().await;
            }
            let old_term = fleet.store(index).status().term;
            fleet.stop_disconnected(index).await;
            self.scripts[index].take().unwrap().finish();
            let gate = Arc::new(VoteGate {
                first_term: old_term + 1,
                split_rounds,
                arrivals: watch::channel(Vec::new()).0,
                both_candidates: Barrier::new(2),
                both_pre_votes: Barrier::new(2),
                replies: watch::channel(Vec::new()).0,
            });
            let paths = [(live[0], live[1]), (live[1], live[0])];
            for path in paths {
                *fleet.paths[&path].rolling_vote.lock().unwrap() = Some(gate.clone());
            }
            for &node in live {
                assert_eq!(self.script(node).draws().last().unwrap().1, LATE);
            }
            if split_rounds == 1 {
                self.script(live[0]).plan_next([EARLY, LATE]);
                self.script(live[1]).plan_next([LATE]);
            } else {
                self.script(live[0]).plan_next([LATE, EARLY, LATE]);
                self.script(live[1]).plan_next([LATE, LATE]);
            }
            let stores = live
                .iter()
                .map(|&node| fleet.store(node).clone())
                .collect::<Vec<_>>();
            assert!(stores
                .iter()
                .all(|store| store.status().leader_id == Some(state.node_id)));
            let started = Instant::now();
            if split_rounds == 1 {
                let append = async {
                    assert_eq!(Instant::now(), started, "write starts at the leader stop");
                    fleet.append(writer).await;
                    assert_eq!(
                        fleet.store(writer).status().leader_id,
                        Some(fleet.store(live[0]).status().node_id),
                    );
                    eprintln!("rolling write: voter {} in-flight append committed at {:?}, successor {}", writer + 1, started.elapsed(), live[0] + 1);
                };
                tokio::join!(biased;
                    append,
                    self.elect_survivors(&stores, live, old_term, split_rounds, &gate, None),
                );
            } else {
                let next = TxId::new();
                let record = commit(next, Some(fleet.head), fleet.version + 1, 2);
                let records_audit = audit(next);
                let (expired, observed_expiry) = oneshot::channel();
                let append = async {
                    assert_eq!(Instant::now(), started, "write starts at the leader stop");
                    let error = fleet
                        .store(writer)
                        .append_attested_commit(attested(record.clone(), records_audit.clone()))
                        .await
                        .expect_err("two real split votes outlast the unchanged write deadline");
                    assert!(matches!(error.kind(), PersistErrorKind::OutcomeUnknown));
                    assert_eq!(Instant::now(), started + CLUSTER_TRANSITION_TIMEOUT);
                    assert_eq!(gate.replies.borrow().len(), 4);
                    for store in &stores {
                        assert_eq!(store.status().leader_id, None);
                        assert_eq!(store.status().term, old_term + 2);
                    }
                    eprintln!("rolling write: OutcomeUnknown at {CLUSTER_TRANSITION_TIMEOUT:?} with both survivors leaderless");
                    expired.send(()).expect("election awaits the actual write result");
                };
                tokio::join!(biased;
                    append,
                    self.elect_survivors(
                        &stores, live, old_term, split_rounds, &gate, Some(observed_expiry)
                    ),
                );
                // Attestation claims are one-shot, but these exact retained
                // record/audit inputs reproduce the same deterministic request ID.
                fleet
                    .store(writer)
                    .append_attested_commit(attested(record, records_audit))
                    .await
                    .expect("same-ID write recovers after the real successor is observed");
                fleet.head = next;
                fleet.version += 1;
                eprintln!("rolling write: same-ID recovery committed after the two-split successor");
            }
            for path in paths {
                *fleet.paths[&path].rolling_vote.lock().unwrap() = None;
            }
        })
        .await;
    }

    async fn elect_survivors(
        &self,
        stores: &[ConsensusConfigStore],
        live: &[usize],
        old_term: u64,
        split_rounds: u64,
        gate: &VoteGate,
        mut observed_expiry: Option<oneshot::Receiver<()>>,
    ) {
        let started = Instant::now();
        assert_eq!(observed_expiry.is_some(), split_rounds == 2);
        let mut splits = vec![self.late.campaign(Duration::ZERO, Duration::ZERO, true)];
        for _ in 1..split_rounds {
            splits.push(
                self.late
                    .campaign(*splits.last().unwrap(), Duration::ZERO, false),
            );
        }
        let last_split = *splits.last().unwrap();
        let bound = self.early.campaign(last_split, Duration::ZERO, false);
        assert!(bound < self.late.campaign(last_split, Duration::ZERO, false));
        let expected = stores[0].status().node_id;
        let mut instants = Vec::new();
        let mut tick = self.late.tick;
        while tick <= bound {
            instants.push((tick, true));
            tick += self.late.tick;
        }
        if split_rounds == 2 {
            assert!(splits[0] < CLUSTER_TRANSITION_TIMEOUT);
            assert!(splits[1] < CLUSTER_TRANSITION_TIMEOUT);
            assert!(CLUSTER_TRANSITION_TIMEOUT < bound);
            instants.push((CLUSTER_TRANSITION_TIMEOUT, false));
        } else {
            assert!(bound < CLUSTER_TRANSITION_TIMEOUT);
        }
        instants.sort_unstable();
        for (at, is_tick) in instants {
            if is_tick {
                self.advance(started + at, live).await;
            } else {
                tokio::time::advance(started + at - Instant::now()).await;
                observed_expiry
                    .take()
                    .expect("two-split write deadline observation")
                    .await
                    .expect("actual write expires before advancing to the next split");
                assert_eq!(Instant::now(), started + CLUSTER_TRANSITION_TIMEOUT);
            }
            if let Some(round) = splits.iter().position(|&split| split == at) {
                let replies = gate.observed(2 * (round + 1)).await;
                assert_eq!(replies.len(), 2 * (round + 1));
                for reply in &replies[2 * round..] {
                    assert_eq!(reply.sent_at - started, at);
                    assert_eq!(reply.replied_at - started, at);
                    assert!(!reply.response.vote_granted);
                    assert_eq!(
                        reply.response.vote,
                        Vote::new(old_term + round as u64 + 1, reply.target)
                    );
                }
                for store in stores {
                    assert_eq!(store.status().leader_id, None);
                    assert_eq!(store.status().term, old_term + round as u64 + 1);
                }
                eprintln!(
                    "rolling election: split {} at {at:?}; computed election bound {bound:?}",
                    round + 1
                );
            }
        }
        let replies = gate.observed(2 * split_rounds as usize + 1).await;
        assert_eq!(replies.len(), 2 * split_rounds as usize + 1);
        let won = replies.last().unwrap();
        assert_eq!(won.sent_at - started, bound);
        assert_eq!(won.replied_at - started, bound);
        assert!(won.response.vote_granted);
        assert_eq!(
            won.request.vote,
            Vote::new(old_term + split_rounds + 1, expected)
        );
        assert_eq!(won.response.vote, won.request.vote);
        wait_for_leader(stores, expected, old_term + split_rounds + 1).await;
        assert_eq!(started.elapsed(), bound);
        for &node in live {
            self.script(node).assert_exhausted();
        }
        eprintln!(
            "rolling election: {expected:?} won at {bound:?} after {split_rounds} real splits"
        );
    }

    pub(super) fn finish(&self) {
        for script in self.scripts.iter().flatten() {
            script.finish();
        }
    }
}

async fn wait_for_leader(
    stores: &[ConsensusConfigStore],
    leader: ConfigConsensusNodeId,
    term: u64,
) {
    while !stores.iter().all(|store| {
        let status = store.status();
        status.leader_id == Some(leader) && status.term == term
    }) {
        tokio::task::yield_now().await;
    }
}
