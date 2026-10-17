//! Legal automatic election schedules outside the fixture acquisition bound.

use super::*;
use futures_util::FutureExt;
use opc_consensus::engine::{
    error::RaftError,
    raft::{PreVoteRequest, PreVoteResponse, VoteRequest, VoteResponse},
    Vote,
};
use opc_consensus::test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
use opc_persist::ConfigLocalAuthorityOutcome;
use std::panic::AssertUnwindSafe;
use tokio::sync::{watch, Barrier};
use tokio::time::Instant;

#[path = "../../../opc-consensus/tests/reelection/delivery.rs"]
pub(super) mod delivery;
#[path = "../../../opc-consensus/tests/reelection/schedule.rs"]
pub(super) mod schedule;

const EARLY_SAMPLE: u64 = 1_u64 << 62;
const LATE_SAMPLE: u64 = 3_u64 << 62;

#[derive(Clone, Debug)]
struct VoteExchange {
    source: ConfigConsensusNodeId,
    target: ConfigConsensusNodeId,
    at: Instant,
    response: VoteResponse<ConfigConsensusNodeId>,
}

#[derive(Debug)]
pub(super) struct VoteGate {
    term: u64,
    arrivals: watch::Sender<Vec<(Instant, VoteRequest<ConfigConsensusNodeId>)>>,
    both_candidates: Option<Barrier>,
    both_pre_votes: Barrier,
    replies: watch::Sender<Vec<VoteExchange>>,
}

impl VoteGate {
    pub(super) async fn deliver(
        &self,
        target: ConfigConsensusNodeId,
        handler: Arc<dyn ConsensusRpcHandler>,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        if request.family == ConsensusRpcFamily::PreVote {
            let (_, rpc): (u16, PreVoteRequest<ConfigConsensusNodeId>) =
                opc_consensus::decode_bounded(&request.payload).unwrap();
            let response = handler.handle(request.sender, request).await;
            let (_, reply): (
                u16,
                Result<PreVoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
            ) = opc_consensus::decode_bounded(response.result.as_ref().unwrap()).unwrap();
            assert!(
                reply.unwrap().vote_granted,
                "both inquiries succeed before crossing real votes"
            );
            if rpc.vote.leader_id.term < self.term + 3 {
                self.both_pre_votes.wait().await;
            }
            return response;
        }
        if request.family != ConsensusRpcFamily::Vote {
            return handler.handle(request.sender, request).await;
        }
        self.before_delivery(&request).await;
        let source = request.sender;
        let response = handler.handle(source, request).await;
        self.after_delivery(source, target, &response);
        response
    }

    pub(super) async fn before_delivery(&self, request: &ConsensusWireRequest) {
        let (_, vote): (u16, VoteRequest<ConfigConsensusNodeId>) =
            opc_consensus::decode_bounded(&request.payload).expect("real vote request");
        assert!((self.term..=self.term + 3).contains(&vote.vote.leader_id.term));
        assert_eq!(vote.vote.leader_id.voted_for(), Some(request.sender));
        let split = vote.vote.leader_id.term < self.term + 3;
        self.arrivals.send_modify(|arrivals| {
            assert!(
                arrivals.iter().all(|(_, seen)| seen.vote != vote.vote),
                "one request from each candidate"
            );
            arrivals.push((Instant::now(), vote));
        });
        if let Some(barrier) = &self.both_candidates {
            if !split {
                return;
            }
            // Each request exists only after its sender has saved its own
            // vote. Deliver both after that point, forcing a real split vote.
            barrier.wait().await;
        }
    }

    pub(super) fn after_delivery(
        &self,
        source: ConfigConsensusNodeId,
        target: ConfigConsensusNodeId,
        response: &ConsensusWireResponse,
    ) {
        let (_, response): (
            u16,
            Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
        ) = opc_consensus::decode_bounded(response.result.as_ref().expect("vote wire response"))
            .expect("vote response");
        self.replies.send_modify(|replies| {
            replies.push(VoteExchange {
                source,
                target,
                at: Instant::now(),
                response: response.expect("real peer vote"),
            });
        });
    }
}

pub(super) struct SuccessfulElection {
    pub scripts: [ElectionRngScript; 3],
    runtime_origin: Instant,
    early: schedule::ElectionSchedule,
    late: schedule::ElectionSchedule,
    ticks: delivery::TickDelivery,
    _tracing: tracing::subscriber::DefaultGuard,
}

impl SuccessfulElection {
    pub(super) async fn new(runtime_origin: Instant) -> Self {
        let (ticks, tracing) = delivery::TickDelivery::install();
        let config = durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap();
        let calibration = ElectionRngScript::new([EARLY_SAMPLE, LATE_SAMPLE]);
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
            scripts: [
                ElectionRngScript::new([LATE_SAMPLE; 2]),
                ElectionRngScript::new([EARLY_SAMPLE; 2]),
                ElectionRngScript::new([LATE_SAMPLE]),
            ],
            runtime_origin,
            early: schedule::ElectionSchedule::new(&config, early),
            late: schedule::ElectionSchedule::new(&config, late),
            ticks,
            _tracing: tracing,
        }
    }

    async fn pause_after_follower_tick(&self) {
        let mut sleeps = self.scripts[1].sleeps();
        let before = sleeps.borrow().len();
        tokio::time::timeout(
            Duration::from_secs(30),
            sleeps.wait_for(|sleeps| sleeps.len() > before),
        )
        .await
        .expect("follower ticker re-registers on normal time")
        .expect("follower ticker remains live");
        tokio::time::pause();
    }

    /// Only the finite election phase uses frozen time. Delay the already
    /// running tickers by at most one tick to align their next registrations,
    /// then send the normal read-index heartbeats to anchor both real leases.
    async fn align_and_anchor(&self, quorum: &ProjectionCluster, old_leader: usize) -> Instant {
        let millis = (Instant::now() + self.early.tick - self.runtime_origin)
            .as_nanos()
            .div_ceil(1_000_000);
        let started = self.runtime_origin
            + Duration::from_millis(u64::try_from(millis).expect("finite election clock"));
        tokio::time::advance(started - Instant::now()).await;
        for (store, script) in quorum.stores.iter().zip(&self.scripts) {
            schedule::tick_registered(&mut script.sleeps(), started, self.early.tick).await;
            self.ticks.wait(store.status().node_id.get(), started).await;
        }
        assert_eq!(
            quorum.stores[old_leader].ensure_local_authority().await,
            ConfigLocalAuthorityOutcome::LocalAuthority
        );
        for store in &quorum.stores[1..] {
            loop {
                if store.vote_updated_at_for_test().await.unwrap() == Some(started) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        started
    }
}

#[tokio::test(start_paused = true)]
async fn automatic_repeated_split_outlasts_thirty_second_acquisition() {
    let runtime_origin = Instant::now();
    tokio::time::resume();
    let mut election = SuccessfulElection::new(runtime_origin).await;
    election.scripts = [
        ElectionRngScript::new([LATE_SAMPLE; 2]),
        ElectionRngScript::new([LATE_SAMPLE; 4]),
        ElectionRngScript::new([
            LATE_SAMPLE,
            LATE_SAMPLE,
            LATE_SAMPLE,
            EARLY_SAMPLE,
            LATE_SAMPLE,
        ]),
    ];
    let quorum =
        ProjectionCluster::start_with_election_scripts(None, Some(&election.scripts)).await;
    let old_leader = quorum.leader();
    assert_eq!(old_leader, 0);
    let initial = quorum.stores[0].status();
    assert_eq!(initial.applied_index, Some(1));
    // Equal durable prefixes allow both candidates to retry at the same tick.
    // A peer with a shorter log instead receives the engine's additional
    // smaller-log backoff after a rejection; that is a separate scenario.
    for index in 2..=13_u8 {
        let error = quorum.stores[0]
            .clear_recovery_required_idempotent(
                opc_consensus::ConsensusRequestId::from_bytes([index; 16]),
                TxId::new(),
            )
            .await
            .expect_err("replicated absent-transaction result");
        assert!(matches!(
            error.kind(),
            opc_persist::PersistErrorKind::RollbackNotFound
        ));
        for store in &quorum.stores {
            let expected = u64::from(index);
            tokio::time::timeout(
                Duration::from_secs(30),
                store.wait_for_raft_status_for_test(|status| {
                    status.applied_index == Some(expected)
                        && status.committed_index == Some(expected)
                }),
            )
            .await
            .expect("normal-time prefix setup deadline")
            .unwrap();
        }
    }
    election.pause_after_follower_tick().await;
    schedule::with_frozen_time(async {
        let started = election.align_and_anchor(&quorum, old_leader).await;
        let gate = Arc::new(VoteGate {
            term: initial.term + 1,
            arrivals: watch::channel(Vec::new()).0,
            both_candidates: Some(Barrier::new(2)),
            both_pre_votes: Barrier::new(2),
            replies: watch::channel(Vec::new()).0,
        });
        quorum.observe_votes(Some(gate.clone()));
        quorum.isolate_and_quiesce(old_leader).await;
        eprintln!("election_phase fixture=config elapsed_ms=0 phase=isolated equal_prefix=13");
        let first = election.late.campaign(Duration::ZERO, Duration::ZERO, true);
        let second = election.late.campaign(first, Duration::ZERO, false);
        let third = election.late.campaign(second, Duration::ZERO, false);
        let success = election.early.campaign(third, Duration::ZERO, false);
        assert_eq!(first, Duration::from_millis(15_300));
        assert_eq!(second, Duration::from_millis(22_600));
        assert_eq!(third, Duration::from_millis(29_900));
        assert_eq!(success, Duration::from_millis(35_700));
        let drive = async {
            for millis in (100..=30_000).step_by(100) {
                let elapsed = Duration::from_millis(millis);
                let at = started + elapsed;
                tokio::time::advance(at - Instant::now()).await;
                for (index, script) in election.scripts.iter().enumerate() {
                    schedule::tick_registered(&mut script.sleeps(), at, election.late.tick).await;
                    election.ticks.wait(index as u64 + 1, at).await;
                }
                if let Some(round) = [first, second, third]
                    .iter()
                    .position(|time| *time == elapsed)
                {
                    let count = (round + 1) * 2;
                    let replies = gate
                        .replies
                        .subscribe()
                        .wait_for(|replies| replies.len() == count)
                        .await
                        .unwrap()
                        .clone();
                    for exchange in &replies[count - 2..] {
                        assert_eq!(exchange.at, at);
                        assert!(!exchange.response.vote_granted);
                        assert_eq!(
                            exchange.response.vote,
                            Vote::new(initial.term + count as u64 / 2, exchange.target)
                        );
                        assert_ne!(exchange.source, exchange.target);
                    }
                    for (observed_at, request) in &gate.arrivals.borrow()[count - 2..] {
                        assert_eq!(*observed_at, at);
                        assert!(matches!(
                            request.vote.leader_id.voted_for().map(|node| node.get()),
                            Some(2 | 3)
                        ));
                        assert_eq!(request.last_log_id.map(|id| id.index), Some(13));
                    }
                    for script in &election.scripts[1..] {
                        let draws = script.draws();
                        assert_eq!(draws.len(), round + 2);
                        assert_eq!(draws.last().unwrap().0, at);
                    }
                    eprintln!(
                        "election_phase fixture=config elapsed_ms={} phase=split_and_resampled",
                        millis
                    );
                }
            }
        };
        let (result, ()) = tokio::join!(
            AssertUnwindSafe(quorum.wait_promoted(old_leader)).catch_unwind(),
            drive
        );
        assert_eq!(Instant::now() - started, Duration::from_secs(30));
        let panic = result.expect_err("three legal split campaigns exceed the unchanged 30s bound");
        let message = panic
            .downcast_ref::<String>()
            .expect("original helper panic");
        assert!(message.starts_with("surviving quorum failed to elect a new leader:"));
        eprintln!("acquisition_deadline fixture=config elapsed_ms=30000 failed_campaigns=3");
        for (index, expected) in [(1, 13), (2, 13)] {
            let status = quorum.stores[index].status();
            assert_eq!(status.term, initial.term + 3);
            assert_eq!(status.leader_id, None);
            assert_eq!(status.applied_index, Some(expected));
            assert_eq!(status.committed_index, Some(expected));
        }
        tokio::time::advance(started + success - Instant::now()).await;
        for (index, script) in election.scripts.iter().enumerate() {
            schedule::tick_registered(&mut script.sleeps(), started + success, election.late.tick)
                .await;
            election
                .ticks
                .wait(index as u64 + 1, started + success)
                .await;
        }
        let replies = gate
            .replies
            .subscribe()
            .wait_for(|replies| replies.len() == 7)
            .await
            .unwrap()
            .clone();
        assert_eq!(replies[6].at, started + success);
        assert_eq!(replies[6].source, quorum.stores[2].status().node_id);
        assert!(replies[6].response.vote_granted);
        for store in &quorum.stores[1..] {
            store
                .wait_for_raft_status_for_test(|status| {
                    status.leader_id == Some(quorum.stores[2].status().node_id)
                        && status.term == initial.term + 4
                })
                .await
                .unwrap();
        }
        assert_eq!(
            quorum.stores[2].ensure_local_authority().await,
            ConfigLocalAuthorityOutcome::LocalAuthority
        );
        assert_eq!(Instant::now() - started, success);
        eprintln!("automatic_recovery fixture=config elapsed_ms=35700 campaign=4");
        quorum.observe_votes(None);
        quorum.shutdown().await;
        for script in &election.scripts {
            script.finish();
        }
    })
    .await;
}

pub(super) struct Election {
    pub scripts: [ElectionRngScript; 3],
    started: Instant,
    early: schedule::ElectionSchedule,
    late: schedule::ElectionSchedule,
    delivery: delivery::TickDelivery,
    _guard: tracing::subscriber::DefaultGuard,
}

impl Election {
    pub async fn new() -> Self {
        let (delivery, guard) = delivery::TickDelivery::install();
        let config = durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap();
        let early_sample = 1_u64 << 62;
        let late_sample = 3_u64 << 62;
        let calibration = ElectionRngScript::new([early_sample, late_sample]);
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
            scripts: [
                ElectionRngScript::new([late_sample; 2]),
                ElectionRngScript::new([early_sample; 2]),
                ElectionRngScript::new([late_sample; 1]),
            ],
            started: Instant::now(),
            early: schedule::ElectionSchedule::new(&config, early),
            late: schedule::ElectionSchedule::new(&config, late),
            delivery,
            _guard: guard,
        }
    }

    pub async fn elect_survivor(self, cluster: &ProjectionCluster, old_leader: usize) -> usize {
        assert_eq!(old_leader, 0, "canonical initial leader");
        assert_eq!(
            Instant::now(),
            self.started,
            "disk work did not consume protocol time"
        );
        let term = cluster.stores[1].status().term;
        let expected = cluster.stores[1].status().node_id;
        let bound = self.early.campaign(Duration::ZERO, Duration::ZERO, true);
        assert!(bound < self.late.campaign(Duration::ZERO, Duration::ZERO, true));
        for script in &self.scripts[1..] {
            schedule::tick_registered(&mut script.sleeps(), self.started, self.early.tick).await;
        }
        let mut tick = self.early.tick;
        while tick <= bound {
            tokio::time::advance(self.started + tick - Instant::now()).await;
            for (index, script) in self.scripts.iter().enumerate().skip(1) {
                schedule::tick_registered(
                    &mut script.sleeps(),
                    self.started + tick,
                    self.early.tick,
                )
                .await;
                self.delivery
                    .wait(
                        cluster.stores[index].status().node_id.get(),
                        self.started + tick,
                    )
                    .await;
            }
            tick += self.early.tick;
        }
        while !cluster.stores[1..].iter().all(|store| {
            let status = store.status();
            status.leader_id == Some(expected) && status.term == term + 1
        }) {
            tokio::task::yield_now().await;
        }
        assert_eq!(self.started.elapsed(), bound);
        for script in &self.scripts {
            script.finish();
        }
        1
    }
}
