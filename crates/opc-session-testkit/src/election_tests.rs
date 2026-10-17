//! Controlled real automatic campaigns, with the original acquisition waiters.

use super::*;
use futures_util::FutureExt;
use opc_consensus::engine::{
    error::RaftError,
    raft::{VoteRequest, VoteResponse},
    Vote,
};
use opc_consensus::test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
use opc_session_store::{OwnerId, SessionKey, SessionKeyType, SessionLeaseManager};
use std::panic::AssertUnwindSafe;
use tokio::sync::{watch, Barrier};
use tokio::time::Instant;

#[path = "../../opc-consensus/tests/reelection/delivery.rs"]
pub(super) mod delivery;
#[path = "../../opc-consensus/tests/reelection/schedule.rs"]
mod schedule;

const EARLY: u64 = 1_u64 << 62;
const LATE: u64 = 3_u64 << 62;

#[derive(Clone, Debug)]
struct Exchange {
    source: SessionConsensusNodeId,
    target: SessionConsensusNodeId,
    at: Instant,
    request: VoteRequest<SessionConsensusNodeId>,
    response: VoteResponse<SessionConsensusNodeId>,
}

pub(super) struct VoteGate {
    first_term: u64,
    split: bool,
    crossing: Barrier,
    exchanges: watch::Sender<Vec<Exchange>>,
}

impl VoteGate {
    pub(super) async fn deliver(
        &self,
        target: SessionConsensusNodeId,
        handler: Arc<dyn SessionConsensusRpcHandler>,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family != SessionConsensusRpcFamily::Vote {
            return handler.handle(request.sender, request).await;
        }
        let source = request.sender;
        let vote: VoteRequest<SessionConsensusNodeId> =
            opc_consensus::decode_bounded(&request.payload).unwrap();
        assert!((self.first_term..=self.first_term + 2).contains(&vote.vote.leader_id.term));
        if self.split && vote.vote.leader_id.term < self.first_term + 2 {
            // Both requests exist only after their real self-votes persist.
            self.crossing.wait().await;
        }
        let response = handler.handle(source, request).await;
        let reply: Result<VoteResponse<SessionConsensusNodeId>, RaftError<SessionConsensusNodeId>> =
            opc_consensus::decode_bounded(response.result.as_ref().unwrap()).unwrap();
        self.exchanges.send_modify(|exchanges| {
            exchanges.push(Exchange {
                source,
                target,
                at: Instant::now(),
                request: vote,
                response: reply.unwrap(),
            })
        });
        response
    }

    async fn observed(&self, count: usize) -> Vec<Exchange> {
        self.exchanges
            .subscribe()
            .wait_for(|exchanges| exchanges.len() == count)
            .await
            .unwrap()
            .clone()
    }
}

fn nodes() -> [SessionConsensusNodeId; 3] {
    let cluster = opc_consensus::ConsensusClusterId::new("session-consensus-testkit").unwrap();
    std::array::from_fn(|index| {
        opc_consensus::derive_node_id(
            cluster,
            format!("consensus-test-replica-{index}").as_bytes(),
        )
        .unwrap()
    })
}

fn key(index: usize) -> SessionKey {
    SessionKey {
        tenant: opc_types::TenantId::new("election-tests").unwrap(),
        nf_kind: opc_types::NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: bytes::Bytes::from(format!("lease-{index}"))
            .try_into()
            .unwrap(),
    }
}

async fn replicated_cluster(
    scripts: &[ElectionRngScript],
    old: usize,
    short: usize,
    nodes: [SessionConsensusNodeId; 3],
    unequal: bool,
) -> ConsensusTestCluster {
    let cluster = ConsensusTestCluster::start_controlled(
        3,
        false,
        opc_session_store::FencedTransitionV2Profile::V2,
        Some(scripts),
    )
    .await;
    for (store, node) in cluster.stores.iter().zip(nodes) {
        assert_eq!(store.status().node_id, node);
    }
    let initial = cluster.stores[old].status();
    assert_eq!(initial.leader_id, Some(nodes[old]));
    for index in 0..2 {
        if unequal && index == 1 {
            cluster.paths[&(old, short)]
                .hold_log_entries
                .store(true, Ordering::Release);
        }
        cluster.stores[old]
            .acquire(
                &key(index),
                OwnerId::new("election-owner").unwrap(),
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let committed = cluster.stores[old].status().applied_index.unwrap();
        for (node, store) in cluster.stores.iter().enumerate() {
            let expected = if unequal && index == 1 && node == short {
                committed - 1
            } else {
                committed
            };
            tokio::time::timeout(
                Duration::from_secs(30),
                store.wait_for_status_for_test(|status| status.applied_index == Some(expected)),
            )
            .await
            .expect("normal-time replicated prefix");
        }
    }
    cluster
}

#[tokio::test(start_paused = true)]
async fn automatic_repeated_split_outlasts_both_acquisition_envelopes() {
    let origin = Instant::now();
    tokio::time::resume();
    let (ticks, _observer) = delivery::TickDelivery::install();
    let config = durable_openraft_config(DurableOpenraftDomain::SessionState).unwrap();
    let calibration = ElectionRngScript::new([EARLY, LATE]);
    let (early, late) = calibration
        .scope(async {
            (
                config.new_rand_election_timeout::<ScriptedElectionRuntime>(),
                config.new_rand_election_timeout::<ScriptedElectionRuntime>(),
            )
        })
        .await;
    calibration.finish();
    let early = schedule::ElectionSchedule::new(&config, Duration::from_millis(early));
    let late = schedule::ElectionSchedule::new(&config, Duration::from_millis(late));
    let nodes = nodes();
    let old = (0..3).min_by_key(|index| nodes[*index]).unwrap();
    let survivors: Vec<_> = (0..3).filter(|index| *index != old).collect();
    let short = survivors[0];
    let long = survivors[1];
    let scripts: Vec<_> = (0..3)
        .map(|index| {
            ElectionRngScript::new(if index == old {
                vec![LATE; 2]
            } else if index == short {
                vec![LATE; 3]
            } else {
                vec![LATE, LATE, EARLY, LATE]
            })
        })
        .collect();
    // Repeated splits use equal durable prefixes. An unequal rejection makes
    // the shorter node back off by the engine's additional smaller-log delay;
    // the separate unequal-log control below exercises that rejection.
    let cluster = replicated_cluster(&scripts, old, short, nodes, false).await;
    let initial = cluster.stores[old].status();
    let short_prefix = cluster.stores[short].status().applied_index.unwrap();
    let long_prefix = cluster.stores[long].status().applied_index.unwrap();
    assert_eq!(long_prefix, short_prefix);
    let mut sleeps = scripts[short].sleeps();
    let before = sleeps.borrow().len();
    tokio::time::timeout(
        Duration::from_secs(30),
        sleeps.wait_for(|sleeps| sleeps.len() > before),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::pause();
    let result = schedule::with_frozen_time(async {
        let millis = (Instant::now() + late.tick - origin)
            .as_nanos()
            .div_ceil(1_000_000);
        let started = origin + Duration::from_millis(millis.try_into().unwrap());
        tokio::time::advance(started - Instant::now()).await;
        for (index, script) in scripts.iter().enumerate() {
            schedule::tick_registered(&mut script.sleeps(), started, late.tick).await;
            ticks.wait(nodes[index].get(), started).await;
        }
        assert!(cluster.stores[old]
            .probe_durable_readiness()
            .await
            .is_ready());
        for index in &survivors {
            while cluster.stores[*index]
                .vote_updated_at_for_test()
                .await
                .unwrap()
                != Some(started)
            {
                tokio::task::yield_now().await;
            }
        }
        let gate = Arc::new(VoteGate {
            first_term: initial.term + 1,
            split: true,
            crossing: Barrier::new(2),
            exchanges: watch::channel(Vec::new()).0,
        });
        for path in cluster.paths.values() {
            *path.election_vote.lock().unwrap() = Some(gate.clone());
        }
        cluster.set_node_online(old, false);
        for ((source, target), path) in &cluster.paths {
            if *source == old || *target == old {
                let _quiesced = path.admitted.write().await;
            }
        }
        eprintln!(
            "election_phase fixture=session elapsed_ms=0 phase=isolated equal_prefix={long_prefix}"
        );
        let first = late.campaign(Duration::ZERO, Duration::ZERO, true);
        let second = late.campaign(first, Duration::ZERO, false);
        let success = early.campaign(second, Duration::ZERO, false);
        assert_eq!(first, Duration::from_secs(18));
        assert_eq!(second, Duration::from_secs(27));
        assert_eq!(success, Duration::from_secs(33));
        let (done26, at26) = tokio::sync::oneshot::channel();
        let (done30, at30) = tokio::sync::oneshot::channel();
        let surviving_stores: Vec<_> = survivors
            .iter()
            .map(|index| cluster.stores[*index].clone())
            .collect();
        let wait26 = async {
            let result = AssertUnwindSafe(ConsensusTestCluster::wait_ready_stores(
                &surviving_stores,
                false,
            ))
            .catch_unwind()
            .await;
            assert_eq!(Instant::now() - started, Duration::from_secs(26));
            eprintln!("acquisition_deadline fixture=session_fleet elapsed_ms=26000");
            done26.send(()).unwrap();
            result
        };
        let wait30 = async {
            // The helper checks its deadline after each real readiness probe.
            // A probe already awaiting its own operation deadline need not
            // return exactly at 30 s. Observe the original acquisition budget
            // directly instead of freezing time while waiting for that probe.
            let result = tokio::time::timeout_at(
                started + Duration::from_secs(30),
                AssertUnwindSafe(cluster.wait_node_durable_ready(long)).catch_unwind(),
            )
            .await;
            assert_eq!(Instant::now() - started, Duration::from_secs(30));
            eprintln!("acquisition_deadline fixture=session_node elapsed_ms=30000");
            done30.send(()).unwrap();
            result
        };
        let drive = async {
            let mut at26 = Some(at26);
            for seconds in (3..=24).step_by(3).chain([26, 27, 30]) {
                let at = started + Duration::from_secs(seconds);
                tokio::time::advance(at - Instant::now()).await;
                if seconds % 3 == 0 {
                    for (index, script) in scripts.iter().enumerate() {
                        schedule::tick_registered(&mut script.sleeps(), at, late.tick).await;
                        ticks.wait(nodes[index].get(), at).await;
                    }
                }
                if seconds == 18 || seconds == 27 {
                    let count = if seconds == 18 { 2 } else { 4 };
                    for exchange in &gate.observed(count).await[count - 2..] {
                        assert_eq!(exchange.at, at);
                        assert!(!exchange.response.vote_granted);
                        assert_eq!(
                            exchange.response.vote,
                            Vote::new(initial.term + count as u64 / 2, exchange.target)
                        );
                        let expected = if exchange.source == nodes[short] {
                            short_prefix
                        } else {
                            long_prefix
                        };
                        assert_eq!(
                            exchange.request.last_log_id.map(|id| id.index),
                            Some(expected)
                        );
                    }
                }
                if seconds == 18 || seconds == 27 {
                    for index in &survivors {
                        let draws = scripts[*index].draws();
                        assert_eq!(draws.len(), if seconds == 18 { 2 } else { 3 });
                        assert_eq!(draws.last().unwrap().0, at);
                    }
                    eprintln!(
                        "election_phase fixture=session elapsed_ms={} phase=split_and_resampled",
                        seconds * 1000
                    );
                }
                // A waiter must fail at its own deadline before the clock advances.
                if seconds == 26 {
                    at26.take().unwrap().await.unwrap();
                }
            }
            at30.await.unwrap();
        };
        let (result26, result30, ()) = tokio::join!(wait26, wait30, drive);
        assert_eq!(Instant::now() - started, Duration::from_secs(30));
        let panic26 = result26.expect_err("the unchanged 26s helper cannot cover two splits");
        assert_eq!(
            panic26
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic26.downcast_ref::<&str>().copied()),
            Some("consensus test fleet did not become durable-ready")
        );
        match result30 {
            Ok(Err(panic30)) => assert_eq!(
                panic30
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic30.downcast_ref::<&str>().copied()),
                Some("consensus test node did not become durable-ready")
            ),
            Err(_) => {}
            Ok(Ok(())) => panic!("two legal splits must prevent acquisition within 30 seconds"),
        }
        for (index, prefix) in [(short, short_prefix), (long, long_prefix)] {
            let status = cluster.stores[index].status();
            assert_eq!(status.term, initial.term + 2);
            assert_eq!(status.leader_id, None);
            assert_eq!(status.applied_index, Some(prefix));
        }
        tokio::time::advance(started + success - Instant::now()).await;
        for (index, script) in scripts.iter().enumerate() {
            schedule::tick_registered(&mut script.sleeps(), started + success, late.tick).await;
            ticks.wait(nodes[index].get(), started + success).await;
        }
        let exchanges = gate.observed(5).await;
        assert_eq!(exchanges[4].source, nodes[long]);
        assert!(exchanges[4].response.vote_granted);
        assert_eq!(exchanges[4].at, started + success);
        for index in &survivors {
            cluster.stores[*index]
                .wait_for_status_for_test(|status| {
                    status.leader_id == Some(nodes[long]) && status.term == initial.term + 3
                })
                .await;
            assert!(cluster.stores[*index]
                .probe_durable_readiness()
                .await
                .is_ready());
        }
        assert_eq!(Instant::now() - started, success);
        eprintln!("automatic_recovery fixture=session elapsed_ms=33000 campaign=3");
        for path in cluster.paths.values() {
            *path.election_vote.lock().unwrap() = None;
        }
        cluster.shutdown().await;
        for script in &scripts {
            script.finish();
        }
        panic26
    })
    .await;
    // RED checkpoint: surface the original deadline failure after cleanup.
    std::panic::resume_unwind(result);
}

#[tokio::test(start_paused = true)]
async fn unequal_log_rejects_first_automatic_campaign_without_a_competing_self_vote() {
    let origin = Instant::now();
    tokio::time::resume();
    let (ticks, _observer) = delivery::TickDelivery::install();
    let config = durable_openraft_config(DurableOpenraftDomain::SessionState).unwrap();
    let calibration = ElectionRngScript::new([EARLY]);
    let sample = calibration
        .scope(async { config.new_rand_election_timeout::<ScriptedElectionRuntime>() })
        .await;
    calibration.finish();
    let schedule = schedule::ElectionSchedule::new(&config, Duration::from_millis(sample));
    let nodes = nodes();
    let old = (0..3).min_by_key(|index| nodes[*index]).unwrap();
    let survivors: Vec<_> = (0..3).filter(|index| *index != old).collect();
    let short = survivors[0];
    let long = survivors[1];
    let scripts: Vec<_> = (0..3)
        .map(|index| {
            ElectionRngScript::new(if index == old {
                vec![LATE; 2]
            } else if index == short {
                vec![EARLY, LATE]
            } else {
                vec![LATE]
            })
        })
        .collect();
    let cluster = replicated_cluster(&scripts, old, short, nodes, true).await;
    let term = cluster.stores[old].status().term;
    let short_prefix = cluster.stores[short].status().applied_index.unwrap();
    let long_prefix = cluster.stores[long].status().applied_index.unwrap();
    assert_eq!(long_prefix, short_prefix + 1);
    let mut sleeps = scripts[short].sleeps();
    let before = sleeps.borrow().len();
    tokio::time::timeout(
        Duration::from_secs(30),
        sleeps.wait_for(|sleeps| sleeps.len() > before),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::pause();
    schedule::with_frozen_time(async {
        let millis = (Instant::now() + schedule.tick - origin)
            .as_nanos()
            .div_ceil(1_000_000);
        let started = origin + Duration::from_millis(millis.try_into().unwrap());
        tokio::time::advance(started - Instant::now()).await;
        for (index, script) in scripts.iter().enumerate() {
            schedule::tick_registered(&mut script.sleeps(), started, schedule.tick).await;
            ticks.wait(nodes[index].get(), started).await;
        }
        assert!(cluster.stores[old]
            .probe_durable_readiness()
            .await
            .is_ready());
        for index in &survivors {
            while cluster.stores[*index]
                .vote_updated_at_for_test()
                .await
                .unwrap()
                != Some(started)
            {
                tokio::task::yield_now().await;
            }
        }
        let gate = Arc::new(VoteGate {
            first_term: term + 1,
            split: false,
            crossing: Barrier::new(2),
            exchanges: watch::channel(Vec::new()).0,
        });
        for path in cluster.paths.values() {
            *path.election_vote.lock().unwrap() = Some(gate.clone());
        }
        cluster.set_node_online(old, false);
        for ((source, target), path) in &cluster.paths {
            if *source == old || *target == old {
                let _quiesced = path.admitted.write().await;
            }
        }
        let first = schedule.campaign(Duration::ZERO, Duration::ZERO, true);
        assert_eq!(first, Duration::from_secs(15));
        assert!(
            first > schedule.lease,
            "rejection occurs after the committed lease expires"
        );
        for seconds in (3..=15).step_by(3) {
            let at = started + Duration::from_secs(seconds);
            tokio::time::advance(at - Instant::now()).await;
            for (index, script) in scripts.iter().enumerate() {
                schedule::tick_registered(&mut script.sleeps(), at, schedule.tick).await;
                ticks.wait(nodes[index].get(), at).await;
            }
        }
        let exchanges = gate.observed(1).await;
        let exchange = &exchanges[0];
        assert_eq!(exchange.at, started + first);
        assert_eq!(exchange.source, nodes[short]);
        assert_eq!(exchange.target, nodes[long]);
        assert_eq!(exchange.request.vote, Vote::new(term + 1, nodes[short]));
        assert_eq!(
            exchange.request.last_log_id.map(|id| id.index),
            Some(short_prefix)
        );
        assert!(!exchange.response.vote_granted);
        assert_eq!(
            exchange.response.last_log_id.map(|id| id.index),
            Some(long_prefix)
        );
        assert_eq!(
            exchange.response.vote,
            Vote::new_committed(term, nodes[old]),
            "the rejecting voter never cast a competing self-vote"
        );
        assert_eq!(
            scripts[long].draws().len(),
            1,
            "only construction sampled on the rejecting voter"
        );
        assert_eq!(
            scripts[short].draws().len(),
            2,
            "the real automatic candidate resampled"
        );
        assert_eq!(scripts[short].draws()[1].0, started + first);
        assert_eq!(cluster.stores[short].status().term, term + 1);
        assert_eq!(cluster.stores[short].status().leader_id, None);
        eprintln!("election_phase fixture=session_unequal elapsed_ms=15000 phase=log_rejection_without_competing_vote");
        for path in cluster.paths.values() {
            *path.election_vote.lock().unwrap() = None;
        }
        cluster.shutdown().await;
        for script in &scripts {
            script.finish();
        }
    })
    .await;
}
