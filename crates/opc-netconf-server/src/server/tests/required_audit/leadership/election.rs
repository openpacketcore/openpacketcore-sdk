//! Controlled inputs for real NETCONF audit-voter elections.

use super::*;
use futures_util::FutureExt;
use opc_consensus::engine::{
    error::RaftError,
    raft::{VoteRequest, VoteResponse},
    Vote,
};
use opc_consensus::test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
use std::panic::AssertUnwindSafe;
use tokio::sync::{watch, Barrier};
use tokio::time::Instant;

#[path = "../../../../../../opc-consensus/tests/reelection/delivery.rs"]
pub(super) mod delivery;
#[path = "../../../../../../opc-consensus/tests/reelection/schedule.rs"]
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
    replies: watch::Sender<Vec<VoteExchange>>,
}

pub(super) trait Voters {
    fn stores(&self) -> &[Arc<ConsensusConfigStore>];
    fn observe_votes(&self, gate: Option<Arc<VoteGate>>);
    async fn isolate_and_quiesce(&self, node: usize);
    async fn leader_except(&self, excluded: Option<usize>) -> usize;
}

impl VoteGate {
    pub(super) fn observe(term: u64) -> Arc<Self> {
        Arc::new(Self {
            term,
            arrivals: watch::channel(Vec::new()).0,
            both_candidates: None,
            replies: watch::channel(Vec::new()).0,
        })
    }

    pub(super) async fn assert_one_granted_vote(
        &self,
        source: ConfigConsensusNodeId,
        target: ConfigConsensusNodeId,
        committed: u64,
    ) {
        let replies = self
            .replies
            .subscribe()
            .wait_for(|replies| !replies.is_empty())
            .await
            .unwrap()
            .clone();
        assert_eq!(replies.len(), 1, "one real peer vote, without a retry");
        assert_eq!(replies[0].source, source);
        assert_eq!(replies[0].target, target);
        assert!(replies[0].response.vote_granted);
        assert_eq!(replies[0].response.vote, Vote::new(self.term, source));
        let arrivals = self.arrivals.borrow();
        assert_eq!(arrivals.len(), 1, "no competing automatic campaign");
        assert_eq!(arrivals[0].1.vote, replies[0].response.vote);
        assert!(arrivals[0].1.last_log_id.map(|id| id.index) >= Some(committed));
    }

    pub(super) async fn before_delivery(&self, request: &ConsensusWireRequest) {
        let (_, vote): (u16, VoteRequest<ConfigConsensusNodeId>) =
            opc_consensus::decode_bounded(&request.payload).expect("real vote request");
        assert_eq!(vote.vote, Vote::new(self.term, request.sender));
        self.arrivals.send_modify(|arrivals| {
            assert!(
                arrivals.iter().all(|(_, seen)| seen.vote != vote.vote),
                "one request from each candidate"
            );
            arrivals.push((Instant::now(), vote));
        });
        if let Some(barrier) = &self.both_candidates {
            // Each request exists only after its sender has saved its own
            // vote. Deliver both after that point, forcing exactly one split.
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
            TRANSITION_TIMEOUT,
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
    async fn align_and_anchor(&self, quorum: &impl Voters, old_leader: usize) -> Instant {
        let millis = (Instant::now() + self.early.tick - self.runtime_origin)
            .as_nanos()
            .div_ceil(1_000_000);
        let started = self.runtime_origin
            + Duration::from_millis(u64::try_from(millis).expect("finite election clock"));
        tokio::time::advance(started - Instant::now()).await;
        for (store, script) in quorum.stores().iter().zip(&self.scripts) {
            schedule::tick_registered(&mut script.sleeps(), started, self.early.tick).await;
            self.ticks.wait(store.status().node_id.get(), started).await;
        }
        assert_eq!(
            quorum.stores()[old_leader].ensure_local_authority().await,
            ConfigLocalAuthorityOutcome::LocalAuthority
        );
        for store in &quorum.stores()[1..] {
            loop {
                if store.vote_updated_at_for_test().await.unwrap() == Some(started) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        started
    }

    pub(super) async fn elect_survivor(self, quorum: &impl Voters, old_leader: usize) -> usize {
        assert_eq!(old_leader, 0);
        let stores = quorum.stores();
        let old = stores[old_leader].status();
        let committed = old.committed_index.expect("committed audit prefix");
        // Deliberately stronger than log containment: this scenario elects a
        // follower that has already APPLIED its predecessor's audit prefix.
        // It does not cover applying that last debt for the first time after
        // election. Keep setup's own timers active while waiting for it.
        tokio::time::timeout(
            TRANSITION_TIMEOUT,
            stores[1].wait_for_raft_status_for_test(|status| {
                status.leader_id == Some(old.node_id)
                    && status.term == old.term
                    && status.applied_index >= Some(committed)
            }),
        )
        .await
        .expect("designated candidate applies the audit prefix before isolation")
        .unwrap();
        self.pause_after_follower_tick().await;
        let result = schedule::with_frozen_time(
            AssertUnwindSafe(self.elect_frozen(quorum, old_leader, old.term, committed))
                .catch_unwind(),
        )
        .await;
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }

    async fn elect_frozen(
        self,
        quorum: &impl Voters,
        old_leader: usize,
        old_term: u64,
        committed: u64,
    ) -> usize {
        let started = self.align_and_anchor(quorum, old_leader).await;
        let stores = quorum.stores();
        let nodes: Vec<_> = stores.iter().map(|store| store.status().node_id).collect();
        let expected = nodes[1];
        let applied = stores[1].status();
        assert_eq!(applied.term, old_term);
        assert_eq!(applied.leader_id, Some(nodes[old_leader]));
        assert!(
            applied.applied_index >= Some(committed),
            "applied-prefix precondition"
        );
        let gate = Arc::new(VoteGate {
            term: old_term + 1,
            arrivals: watch::channel(Vec::new()).0,
            both_candidates: None,
            replies: watch::channel(Vec::new()).0,
        });
        quorum.observe_votes(Some(gate.clone()));
        quorum.isolate_and_quiesce(old_leader).await;
        assert_eq!(Instant::now(), started);
        let elected_at = self.early.campaign(Duration::ZERO, Duration::ZERO, true);
        assert!(elected_at < TRANSITION_TIMEOUT);
        assert!(elected_at < self.late.campaign(Duration::ZERO, Duration::ZERO, true));
        let driving = async {
            let mut tick = self.early.tick;
            while tick <= elected_at {
                tokio::time::advance(started + tick - Instant::now()).await;
                for (index, script) in self.scripts.iter().enumerate() {
                    schedule::tick_registered(
                        &mut script.sleeps(),
                        started + tick,
                        self.early.tick,
                    )
                    .await;
                    self.ticks.wait(nodes[index].get(), started + tick).await;
                }
                tick += self.early.tick;
            }
        };
        let (new_leader, ()) = tokio::join!(quorum.leader_except(Some(old_leader)), driving);
        assert_eq!(new_leader, 1);
        assert_eq!(Instant::now() - started, elected_at);
        for store in &stores[1..] {
            store
                .wait_for_raft_status_for_test(|status| {
                    status.leader_id == Some(expected) && status.term == old_term + 1
                })
                .await
                .unwrap();
        }
        let arrivals = gate.arrivals.borrow().clone();
        assert_eq!(arrivals.len(), 1, "one automatic campaign, without a retry");
        assert_eq!(arrivals[0].0, started + elected_at);
        assert_eq!(arrivals[0].1.vote, Vote::new(old_term + 1, expected));
        assert!(arrivals[0].1.last_log_id.map(|id| id.index) >= Some(committed));
        let replies = gate.replies.borrow().clone();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].source, expected);
        assert_eq!(replies[0].at, started + elected_at);
        assert!(replies[0].response.vote_granted);
        assert_eq!(replies[0].response.vote, arrivals[0].1.vote);
        quorum.observe_votes(None);
        for script in self.scripts {
            script.finish();
        }
        new_leader
    }
}

#[tokio::test(start_paused = true)]
async fn split_vote_reproduces_authority_timeout() {
    let runtime_origin = Instant::now();
    tokio::time::resume();
    let mut election = SuccessfulElection::new(runtime_origin).await;
    election.scripts = std::array::from_fn(|_| ElectionRngScript::new([LATE_SAMPLE; 2]));
    let quorum = Quorum::start_scripted(Some(&election.scripts)).await;
    let old_leader = quorum.leader_except(None).await;
    assert_eq!(old_leader, 0);
    let initial = quorum.stores[old_leader].status();
    assert_eq!(initial.applied_index, Some(1));
    assert_eq!(initial.committed_index, Some(1));
    // Real replicated commands establish the historical index shape. Unknown
    // transaction recovery-marker clears have a durable NotFound outcome and add one
    // log entry each; these synthetic payloads do not claim to reconstruct the
    // historical audit contents or random seed.
    for index in 2..=13_u8 {
        if index == 13 {
            quorum.paths[&(0, 1)]
                .hold_log_entries
                .store(true, Ordering::Release);
        }
        let error = quorum.stores[old_leader]
            .clear_recovery_required_idempotent(
                opc_consensus::ConsensusRequestId::from_bytes([index; 16]),
                opc_types::TxId::new(),
            )
            .await
            .expect_err("absent transaction has a replicated NotFound outcome");
        assert!(
            matches!(
                error.kind(),
                opc_persist::PersistErrorKind::RollbackNotFound
            ),
            "expected durable NotFound at log index {index}, got {error:?}"
        );
        for (node, store) in quorum.stores.iter().enumerate() {
            let expected = if node == 1 && index == 13 {
                12
            } else {
                u64::from(index)
            };
            tokio::time::timeout(
                TRANSITION_TIMEOUT,
                store.wait_for_raft_status_for_test(|status| {
                    status.applied_index == Some(expected)
                        && status.committed_index == Some(expected)
                }),
            )
            .await
            .expect("normal-time prefix setup retains its diagnostic deadline")
            .unwrap();
        }
    }
    election.pause_after_follower_tick().await;
    schedule::with_frozen_time(async {
        let started = election.align_and_anchor(&quorum, old_leader).await;
        let schedule = &election.late;
        let scripts = &election.scripts;
        let ticks = &election.ticks;
        for (index, expected) in [(1, 12), (2, 13)] {
            let status = quorum.stores[index].status();
            assert_eq!(status.applied_index, Some(expected));
            assert_eq!(status.committed_index, Some(expected));
        }
        let gate = Arc::new(VoteGate {
            term: initial.term + 1,
            arrivals: watch::channel(Vec::new()).0,
            both_candidates: Some(Barrier::new(2)),
            replies: watch::channel(Vec::new()).0,
        });
        for path in [(1, 2), (2, 1)] {
            *quorum.paths[&path].election_vote.lock().unwrap() = Some(gate.clone());
        }
        quorum.isolate_and_quiesce(old_leader).await;
        assert_eq!(Instant::now(), started);
        let split_at = schedule.campaign(Duration::ZERO, Duration::ZERO, true);
        let retry_at = schedule.campaign(split_at, Duration::ZERO, false);
        assert_eq!(split_at, Duration::from_secs(18));
        assert_eq!(retry_at, Duration::from_secs(27));
        assert!(retry_at > TRANSITION_TIMEOUT);

        let driving = async {
            let mut tick = schedule.tick;
            while tick < TRANSITION_TIMEOUT {
                tokio::time::advance(started + tick - Instant::now()).await;
                for (index, script) in scripts.iter().enumerate() {
                    schedule::tick_registered(&mut script.sleeps(), started + tick, schedule.tick)
                        .await;
                    ticks.wait(index as u64 + 1, started + tick).await;
                }
                if tick == split_at {
                    let replies = gate
                        .replies
                        .subscribe()
                        .wait_for(|replies| replies.len() == 2)
                        .await
                        .unwrap()
                        .clone();
                    for exchange in replies {
                        assert_ne!(exchange.source, exchange.target);
                        assert_eq!(exchange.at, started + split_at);
                        assert_eq!(
                            exchange.response.vote,
                            Vote::new(gate.term, exchange.target)
                        );
                        assert!(!exchange.response.vote_granted);
                    }
                    let arrivals = gate.arrivals.borrow().clone();
                    assert_eq!(arrivals.len(), 2);
                    for (at, vote) in arrivals {
                        assert_eq!(at, started + split_at);
                        let expected = if vote.vote
                            == Vote::new(gate.term, ConfigConsensusNodeId::new(2).unwrap())
                        {
                            12
                        } else {
                            13
                        };
                        assert_eq!(vote.last_log_id.map(|id| id.index), Some(expected));
                    }
                }
                tick += schedule.tick;
            }
            for store in &quorum.stores[1..] {
                let status = store.status();
                assert_eq!(status.term, initial.term + 1);
                assert_eq!(status.leader_id, None);
            }
            assert_eq!(gate.replies.borrow().len(), 2);
            tokio::time::advance(started + TRANSITION_TIMEOUT - Instant::now()).await;
        };
        // Keep the original helper and deadline as a negative control. A legal
        // split cannot prove fresh authority before the next production tick.
        let (result, ()) = tokio::join!(
            AssertUnwindSafe(quorum.leader_except(Some(old_leader))).catch_unwind(),
            driving
        );
        assert_eq!(Instant::now() - started, TRANSITION_TIMEOUT);
        let panic = result.expect_err("the next campaign is outside the original bound");
        let message = panic
            .downcast_ref::<String>()
            .expect("authority timeout panic");
        assert!(message.starts_with("quorum did not establish fresh local authority: Elapsed(())"));
        assert!(message.contains("excluded=Some(0)"));
        assert!(message.contains("probes=0"));
        for (index, expected) in [(1, 12), (2, 13)] {
            let status = quorum.stores[index].status();
            assert_eq!(status.term, initial.term + 1);
            assert_eq!(status.leader_id, None);
            assert_eq!(status.applied_index, Some(expected));
            assert_eq!(status.committed_index, Some(expected));
        }
        quorum.shutdown().await;
        for script in scripts {
            script.finish();
        }
        // RED evidence: preserve the original helper's failure after checking
        // the exact historical index shape. The final negative control catches it.
        std::panic::resume_unwind(panic);
    })
    .await;
}
