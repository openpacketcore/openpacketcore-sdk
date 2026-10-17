//! A partition and successor election with all three durable voters live.
//! A healthy leader rejects a forced Pre-Vote without changing any vote. After
//! partitioning it, the survivors split once and elect the successor inside
//! 26 seconds. The former ten-second waiter remains a negative control.

use super::*;
use std::sync::atomic::AtomicBool;

use opc_consensus::engine::{
    error::RaftError,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, PreVoteRequest, PreVoteResponse, VoteRequest,
        VoteResponse,
    },
    Vote,
};
use opc_consensus::test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
use tokio::sync::{watch, Barrier};
use tokio::time::Instant;

#[path = "../../../../../opc-consensus/tests/reelection/schedule.rs"]
pub(super) mod schedule;
#[path = "../../../../../opc-consensus/tests/reelection/delivery.rs"]
pub(super) mod ticks;

#[derive(Clone, Debug)]
struct Exchange {
    source: SessionConsensusNodeId,
    target: SessionConsensusNodeId,
    sent: Instant,
    replied: Instant,
    request: VoteRequest<SessionConsensusNodeId>,
    response: VoteResponse<SessionConsensusNodeId>,
}

#[derive(Clone, Debug)]
struct PreVoteExchange {
    source: SessionConsensusNodeId,
    target: SessionConsensusNodeId,
    sent: Instant,
    replied: Instant,
    request: PreVoteRequest<SessionConsensusNodeId>,
    response: PreVoteResponse<SessionConsensusNodeId>,
}

/// Delay genuine grants until both survivors have queried their peer, then
/// cross their persisted real votes. No RPC response or engine state is forged.
pub(super) struct VoteGate {
    candidates: [SessionConsensusNodeId; 2],
    old: SessionConsensusNodeId,
    partitioned: AtomicBool,
    split_term: u64,
    pre_vote_crossing: Barrier,
    crossing: Barrier,
    pre_votes: watch::Sender<Vec<PreVoteExchange>>,
    exchanges: watch::Sender<Vec<Exchange>>,
}

impl VoteGate {
    pub(super) async fn deliver(
        &self,
        target: SessionConsensusNodeId,
        handler: Arc<dyn SessionConsensusRpcHandler>,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        let source = request.sender;
        if self.partitioned.load(Ordering::Acquire) && (source == self.old || target == self.old) {
            return SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Unavailable),
            };
        }
        let sent = Instant::now();
        if request.family == crate::consensus::SessionConsensusRpcFamily::PreVote {
            let vote: PreVoteRequest<SessionConsensusNodeId> =
                opc_consensus::decode_bounded(&request.payload).expect("real Pre-Vote request");
            let response = handler.handle(source, request).await;
            let reply: Result<
                PreVoteResponse<SessionConsensusNodeId>,
                RaftError<SessionConsensusNodeId>,
            > = opc_consensus::decode_bounded(
                response.result.as_ref().expect("Pre-Vote wire response"),
            )
            .expect("real Pre-Vote response");
            let reply = reply.expect("engine Pre-Vote response");
            eprintln!(
                "void election: Pre-Vote {source:?}->{target:?} request={vote:?} reply={reply:?} at={sent:?}"
            );
            let cross = vote.vote.leader_id.term == self.split_term
                && reply.vote_granted
                && self.candidates.contains(&source)
                && self.candidates.contains(&target);
            self.pre_votes.send_modify(|exchanges| {
                exchanges.push(PreVoteExchange {
                    source,
                    target,
                    sent,
                    replied: Instant::now(),
                    request: vote,
                    response: reply,
                });
            });
            if cross {
                self.pre_vote_crossing.wait().await;
                eprintln!("void election: release crossed Pre-Vote {source:?}->{target:?}");
            }
            return response;
        }
        if request.family != crate::consensus::SessionConsensusRpcFamily::Vote {
            if request.family == crate::consensus::SessionConsensusRpcFamily::AppendEntries {
                let append: AppendEntriesRequest<crate::consensus::SessionRaftTypeConfig> =
                    opc_consensus::decode_bounded(&request.payload).expect("real append request");
                eprintln!("void election: append {source:?}->{target:?} vote={:?} prev={:?} last={:?} commit={:?} at={sent:?}", append.vote, append.prev_log_id, append.entries.last().map(|entry| entry.log_id), append.leader_commit);
                let response = handler.handle(source, request).await;
                let reply = response.result.as_ref().map(|payload| {
                    opc_consensus::decode_bounded::<
                        Result<
                            AppendEntriesResponse<SessionConsensusNodeId>,
                            RaftError<SessionConsensusNodeId>,
                        >,
                    >(payload)
                });
                eprintln!(
                    "void election: append reply {source:?}->{target:?} {reply:?} at={:?}",
                    Instant::now()
                );
                return response;
            }
            return handler.handle(source, request).await;
        }
        let vote: VoteRequest<SessionConsensusNodeId> =
            opc_consensus::decode_bounded(&request.payload).expect("real vote request");
        eprintln!("void election: real Vote {source:?}->{target:?} request={vote:?}");
        if vote.vote.leader_id.term == self.split_term
            && self.candidates.contains(&source)
            && self.candidates.contains(&target)
        {
            self.crossing.wait().await;
        }
        let response = handler.handle(source, request).await;
        let reply: Result<VoteResponse<SessionConsensusNodeId>, RaftError<SessionConsensusNodeId>> =
            opc_consensus::decode_bounded(response.result.as_ref().expect("vote wire response"))
                .expect("real vote response");
        eprintln!(
            "void election: real Vote reply {source:?}->{target:?} {reply:?} at={:?}",
            Instant::now()
        );
        self.exchanges.send_modify(|exchanges| {
            exchanges.push(Exchange {
                source,
                target,
                sent,
                replied: Instant::now(),
                request: vote,
                response: reply.expect("engine vote response"),
            });
        });
        response
    }

    async fn observed(&self, count: usize) -> Vec<Exchange> {
        self.exchanges
            .subscribe()
            .wait_for(|exchanges| exchanges.len() >= count)
            .await
            .expect("vote observations")
            .clone()
    }

    async fn observed_pre_votes(&self, count: usize) -> Vec<PreVoteExchange> {
        self.pre_votes
            .subscribe()
            .wait_for(|exchanges| exchanges.len() >= count)
            .await
            .expect("Pre-Vote observations")
            .clone()
    }
}

pub(super) struct VoidElection {
    pub scripts: Vec<ElectionRngScript>,
    started: Instant,
    runtime_origin: Instant,
    ticks: ticks::TickDelivery,
    old: usize,
    successor: usize,
    early: schedule::ElectionSchedule,
    late: schedule::ElectionSchedule,
}

impl VoidElection {
    pub(super) async fn new(
        fleet: &Fleet,
        runtime_origin: Instant,
        ticks: ticks::TickDelivery,
    ) -> Self {
        let config = durable_openraft_config(DurableOpenraftDomain::SessionState).unwrap();
        // Use the engine's own gen_range mapping and the unchanged SDK timers.
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
        let old = fleet
            .peers
            .iter()
            .enumerate()
            .min_by_key(|(_, peer)| peer.node)
            .unwrap()
            .0;
        let successor = (old + 1) % fleet.peers.len();
        let scripts = (0..fleet.peers.len())
            .map(|index| {
                // Construction and bootstrap sample normally. The successor
                // then makes one healthy inquiry, two partitioned inquiries,
                // and a successful retry; the other survivor campaigns once.
                ElectionRngScript::new(if index == old {
                    vec![early_sample; 2]
                } else if index == successor {
                    vec![early_sample; 5]
                } else {
                    vec![late_sample; 2]
                })
            })
            .collect();
        Self {
            scripts,
            started: Instant::now(),
            runtime_origin,
            ticks,
            old,
            successor,
            early: schedule::ElectionSchedule::new(&config, early),
            late: schedule::ElectionSchedule::new(&config, late),
        }
    }

    pub(super) async fn pause_after_follower_tick(&self) {
        let mut sleeps = self.scripts[self.successor].sleeps();
        let before = sleeps.borrow().len();
        let registered = tokio::time::timeout(
            Duration::from_secs(30),
            sleeps.wait_for(|sleeps| sleeps.len() > before),
        )
        .await
        .expect("successor ticker re-registers before the pause")
        .expect("successor ticker remains live")
        .last()
        .expect("registered successor ticker")
        .0;
        tokio::time::pause();
        eprintln!(
            "void election pause after successor ticker registration: {:?}",
            Instant::now() - registered
        );
    }

    /// Normal-time setup can leave different ticker phases and queued ticks.
    /// Delay their next wake together while the leader is still healthy, then
    /// observe every actual send and completed core handler before proceeding.
    async fn settle(&mut self, fleet: &Fleet) -> Vec<Duration> {
        let next = Instant::now() + self.early.tick;
        let millis = (next - self.runtime_origin).as_nanos().div_ceil(1_000_000);
        let at = self.runtime_origin
            + Duration::from_millis(u64::try_from(millis).expect("finite fixture clock"));
        tokio::time::advance(at - Instant::now()).await;
        let mut registrations = Vec::new();
        for (index, script) in self.scripts.iter().enumerate() {
            schedule::tick_registered(&mut script.sleeps(), at, self.early.tick).await;
            self.ticks
                .wait(fleet.stores[index].status().node_id.get(), at)
                .await;
            registrations.push(
                script
                    .sleeps()
                    .borrow()
                    .iter()
                    .rev()
                    .find(|(registered, deadline)| {
                        *registered == at && *deadline == at + self.early.tick
                    })
                    .expect("actual aligned ticker registration")
                    .0,
            );
        }
        self.started = registrations[self.old];
        let phases: Vec<_> = registrations
            .into_iter()
            .map(|registered| registered - self.started)
            .collect();
        assert!(phases.iter().all(|phase| *phase == Duration::ZERO));
        phases
    }

    async fn anchor_followers(
        &self,
        fleet: &Fleet,
        request: &FencedTransitionV2Request,
        void_first: bool,
    ) {
        // Replaying the already-decided operation still submits a real Raft
        // command. All three applied frontiers must include that new entry,
        // anchoring the committed follower votes at this one paused instant.
        let before = fleet.stores[self.old].status().applied_index;
        if void_first {
            fleet.stores[self.old]
                .fenced_transition_v2_void(request)
                .await
                .expect("VOID replay anchors follower votes");
        } else {
            fleet.stores[self.old]
                .fenced_transition_v2(request.clone())
                .await
                .expect("original receipt replay anchors follower votes");
        }
        eprintln!("void election: existing decision replay returned");
        while fleet.stores[self.old].status().applied_index <= before {
            tokio::task::yield_now().await;
        }
        let anchor = fleet.stores[self.old].status().applied_index;
        eprintln!("void election: local replay applied at {anchor:?}");
        while !fleet
            .stores
            .iter()
            .all(|store| store.status().applied_index >= anchor)
        {
            tokio::task::yield_now().await;
        }
        eprintln!("void election: all voters applied replay");
    }

    async fn advance_all(&self, fleet: &Fleet, at: Instant) {
        tokio::time::advance(at - Instant::now()).await;
        for (index, script) in self.scripts.iter().enumerate() {
            schedule::tick_registered(&mut script.sleeps(), at, self.early.tick).await;
            self.ticks
                .wait(fleet.stores[index].status().node_id.get(), at)
                .await;
        }
    }

    pub(super) async fn change_leader(
        &mut self,
        fleet: &Fleet,
        request: &FencedTransitionV2Request,
        void_first: bool,
    ) {
        eprintln!("void election: aligning healthy ticks");
        let phases = self.settle(fleet).await;
        eprintln!("void election: healthy ticks aligned");
        let old = &fleet.stores[self.old];
        let successor = &fleet.stores[self.successor];
        let remaining = (0..fleet.stores.len())
            .find(|index| *index != self.old && *index != self.successor)
            .unwrap();
        let old_id = old.status().node_id;
        let successor_id = successor.status().node_id;
        let remaining_id = fleet.stores[remaining].status().node_id;
        let old_term = old.status().term;
        assert_eq!(old.status().leader_id, Some(old_id));
        let old_updated = old
            .inner
            .raft
            .with_raft_state(|state| {
                state
                    .vote_last_modified()
                    .expect("committed bootstrap vote has a timestamp")
            })
            .await
            .unwrap();
        // A leader's bootstrap vote timestamp can expire while real quorum
        // acknowledgements stay fresh. Such a leader must reject Pre-Vote.
        while Instant::now() <= old_updated + self.early.lease {
            self.advance_all(fleet, Instant::now() + self.early.tick)
                .await;
        }
        self.started = Instant::now();
        eprintln!("void election: bootstrap lease aged; replaying existing decision");
        self.anchor_followers(fleet, request, void_first).await;
        old.inner.raft.ensure_linearizable().await.unwrap();
        assert!(self.started > old_updated + self.early.lease);
        let applied = old.status().applied_index;
        let mut before = Vec::new();
        for store in &fleet.stores {
            assert_eq!(
                store.persistence_mode(),
                crate::SessionPersistenceMode::Durable
            );
            assert_eq!(store.status().applied_index, applied);
            assert_eq!(store.status().leader_id, Some(old_id));
            before.push(
                store
                    .inner
                    .raft
                    .with_raft_state(|state| (*state.vote_ref(), state.vote_last_modified()))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            before[self.old],
            (Vote::new_committed(old_term, old_id), Some(old_updated))
        );
        for index in [self.successor, remaining] {
            assert_eq!(
                before[index],
                (Vote::new_committed(old_term, old_id), Some(self.started))
            );
        }
        let gate = Arc::new(VoteGate {
            candidates: [successor_id, remaining_id],
            old: old_id,
            partitioned: AtomicBool::new(false),
            split_term: old_term + 1,
            pre_vote_crossing: Barrier::new(2),
            crossing: Barrier::new(2),
            pre_votes: watch::channel(Vec::new()).0,
            exchanges: watch::channel(Vec::new()).0,
        });
        for peer in &fleet.peers {
            *peer.election_votes.lock().unwrap() = Some(gate.clone());
        }
        // Retain real native-authority lock contention: the Pre-Vote handler
        // must wait for the owner without advancing paused protocol time.
        let mut contended = fleet.stores[remaining]
            .inner
            .backend
            .fixed_quorum_native_contention
            .subscribe();
        let wal = Arc::clone(
            fleet.stores[remaining]
                .inner
                .private_wal
                .as_ref()
                .expect("native authority owner"),
        );
        let (entered, holding) = tokio::sync::oneshot::channel();
        let (release, releasing) = std::sync::mpsc::channel();
        let holder = tokio::task::spawn_blocking(move || {
            wal.with_native_owner_held_for_test(|| {
                entered.send(()).expect("owner hold awaited");
                releasing
                    .recv_timeout(Duration::from_secs(30))
                    .expect("real authority contention observed");
                std::thread::sleep(Duration::from_millis(200));
            })
            .expect("hold native authority owner");
        });
        holding.await.expect("actual native owner held");
        eprintln!("void election: native owner held; starting healthy inquiry");
        successor.inner.raft.trigger().elect().await.unwrap();
        contended
            .changed()
            .await
            .expect("real authority lock contention");
        eprintln!("void election: native authority contention observed");
        release.send(()).expect("release contended native owner");
        let initial = gate.observed_pre_votes(2).await;
        eprintln!("void election: both healthy inquiry refusals observed");
        holder.await.expect("join native authority hold");
        assert_eq!(initial.len(), 2);
        for exchange in &initial {
            assert_eq!(exchange.source, successor_id);
            assert_ne!(exchange.target, successor_id);
            assert_eq!(exchange.request.vote, Vote::new(old_term + 1, successor_id));
            assert!(
                !exchange.response.vote_granted,
                "healthy quorum denies the forced inquiry"
            );
            assert_eq!(
                exchange.response.vote,
                Vote::new_committed(old_term, old_id)
            );
            assert_eq!(exchange.sent, self.started);
            assert_eq!(exchange.replied, self.started);
        }
        for (store, expected) in fleet.stores.iter().zip(&before) {
            let actual = store
                .inner
                .raft
                .with_raft_state(|state| (*state.vote_ref(), state.vote_last_modified()))
                .await
                .unwrap();
            assert_eq!(
                &actual, expected,
                "Pre-Vote changes neither votes nor their timestamps"
            );
        }
        assert!(gate.exchanges.borrow().is_empty());
        gate.partitioned.store(true, Ordering::Release);
        eprintln!("void election: old leader partitioned");
        for store in &fleet.stores {
            store.inner.raft.runtime_config().elect(true);
        }
        // The early survivor retries once before the peer's lease expires,
        // then holds a genuine grant until that peer's automatic campaign.
        let denied_at = self
            .early
            .campaign(Duration::ZERO, phases[self.successor], false);
        let first_grant = self
            .early
            .campaign(denied_at, phases[self.successor], false);
        let split_at = self.late.campaign(Duration::ZERO, phases[remaining], true);
        let bound = self.early.campaign(split_at, phases[self.successor], false);
        assert!(denied_at < self.early.lease && self.early.lease < first_grant);
        assert!(first_grant < split_at);
        assert!(
            split_at - first_grant < Duration::from_secs(5),
            "held grant stays inside the RPC timeout"
        );
        assert!(bound < self.late.campaign(split_at, phases[remaining], false));
        assert!(bound < Duration::from_secs(26));
        let former_limit = Duration::from_secs(10);
        assert!(former_limit < split_at && split_at < bound);
        let expired = watch::channel(false).0;
        let wait = async {
            let result = tokio::time::timeout(former_limit, async {
                loop {
                    if fleet
                        .stores
                        .iter()
                        .all(|store| store.status().leader_id == Some(successor_id))
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            expired.send_replace(true);
            result
        };
        let drive = async {
            let mut tick = self.early.tick;
            while tick <= bound {
                self.advance_all(fleet, self.started + tick).await;
                if tick == former_limit {
                    expired.subscribe().wait_for(|done| *done).await.unwrap();
                    assert!(fleet
                        .stores
                        .iter()
                        .all(|store| store.status().leader_id != Some(successor_id)));
                }
                if tick == denied_at {
                    eprintln!("void election: observing denied inquiry at {tick:?}");
                    let queries = gate.observed_pre_votes(3).await;
                    assert_eq!(queries.len(), 3);
                    let exchange = &queries[2];
                    assert_eq!(exchange.source, successor_id);
                    assert_eq!(exchange.target, remaining_id);
                    assert!(!exchange.response.vote_granted);
                    assert_eq!(
                        exchange.response.vote,
                        Vote::new_committed(old_term, old_id)
                    );
                    assert_eq!(exchange.sent - self.started, denied_at);
                    assert_eq!(exchange.replied - self.started, denied_at);
                    assert!(gate.exchanges.borrow().is_empty());
                }
                if tick == first_grant {
                    eprintln!("void election: observing held grant at {tick:?}");
                    let queries = gate.observed_pre_votes(4).await;
                    assert_eq!(queries.len(), 4);
                    assert!(queries[3].response.vote_granted);
                    assert_eq!(queries[3].source, successor_id);
                    assert_eq!(queries[3].target, remaining_id);
                    assert_eq!(
                        queries[3].response.vote,
                        Vote::new_committed(old_term, old_id)
                    );
                    assert!(
                        gate.exchanges.borrow().is_empty(),
                        "one held Pre-Vote is not a real vote"
                    );
                    for index in [self.successor, remaining] {
                        assert_eq!(fleet.stores[index].status().term, old_term);
                    }
                }
                if tick == split_at {
                    eprintln!("void election: observing crossed real votes at {tick:?}");
                    let queries = gate.observed_pre_votes(5).await;
                    eprintln!(
                        "void election: both split inquiries observed; awaiting persisted votes"
                    );
                    assert_eq!(queries.len(), 5);
                    assert_eq!(queries[4].source, remaining_id);
                    assert_eq!(queries[4].target, successor_id);
                    assert!(queries[4].response.vote_granted);
                    assert_eq!(
                        queries[4].response.vote,
                        Vote::new_committed(old_term, old_id)
                    );
                    let split = gate.observed(2).await;
                    assert_eq!(split.len(), 2);
                    for exchange in &split {
                        assert_eq!(
                            exchange.request.vote,
                            Vote::new(old_term + 1, exchange.source)
                        );
                        assert!(
                            !exchange.response.vote_granted,
                            "persisted self-votes split this term"
                        );
                        assert_eq!(
                            exchange.response.vote,
                            Vote::new(old_term + 1, exchange.target)
                        );
                        assert_eq!(exchange.sent - self.started, split_at);
                        assert_eq!(exchange.replied - self.started, split_at);
                    }
                    for index in [self.successor, remaining] {
                        let store = &fleet.stores[index];
                        assert_eq!(
                            store.inner.raft.metrics().borrow().vote,
                            Vote::new(old_term + 1, store.status().node_id)
                        );
                    }
                }
                tick += self.early.tick;
            }
            let exchanges = gate.observed(3).await;
            eprintln!(
                "void election: winning persisted vote observed at {:?}",
                self.started.elapsed()
            );
            assert_eq!(exchanges.len(), 3);
            let winning = &exchanges[2];
            assert_eq!(winning.source, successor_id);
            assert_eq!(winning.target, remaining_id);
            assert_eq!(winning.request.vote, Vote::new(old_term + 2, successor_id));
            assert!(winning.response.vote_granted);
            assert_eq!(winning.response.vote, winning.request.vote);
            assert_eq!(winning.sent - self.started, bound);
            assert_eq!(winning.replied - self.started, bound);
            let queries = gate.observed_pre_votes(6).await;
            assert_eq!(queries.len(), 6);
            assert_eq!(queries[5].source, successor_id);
            assert_eq!(queries[5].target, remaining_id);
            assert!(queries[5].response.vote_granted);
            assert_eq!(
                queries[5].request.vote,
                Vote::new(old_term + 2, successor_id)
            );
            for index in [self.successor, remaining] {
                fleet.stores[index]
                    .inner
                    .raft
                    .wait(None)
                    .vote(
                        Vote::new_committed(old_term + 2, successor_id),
                        "survivor election",
                    )
                    .await
                    .unwrap();
                eprintln!(
                    "void election: committed survivor vote observed on {:?}",
                    fleet.stores[index].status().node_id
                );
            }
            gate.partitioned.store(false, Ordering::Release);
            eprintln!("void election: healed former leader; triggering heartbeat");
            successor.inner.raft.trigger().heartbeat().await.unwrap();
            // The former leader's replication stream can still be in its
            // unreachable-peer backoff. The existing read fence sends fresh
            // probes to every voter, so run it before waiting at this frozen
            // instant for the healed peer to observe the committed vote.
            successor.inner.raft.ensure_linearizable().await.unwrap();
            eprintln!("void election: successor linearizability confirmed");
            while !fleet.stores.iter().all(|store| {
                store.status().leader_id == Some(successor_id)
                    && store.status().term == old_term + 2
            }) {
                tokio::task::yield_now().await;
            }
            eprintln!("void election: all voters observed successor");
            assert_eq!(self.started.elapsed(), bound);
            for script in &self.scripts {
                script.finish();
            }
            for peer in &fleet.peers {
                *peer.election_votes.lock().unwrap() = None;
            }
            eprintln!("void election: all durable voters agree at {bound:?}; pre_votes={queries:?}; votes={exchanges:?}");
        };
        let (result, ()) = tokio::join!(wait, drive);
        assert!(
            result.is_err(),
            "the former ten-second wait excludes this valid successor election"
        );
    }
}
