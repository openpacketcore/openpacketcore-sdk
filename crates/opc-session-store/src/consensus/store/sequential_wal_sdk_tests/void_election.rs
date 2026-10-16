//! A legal successor-election schedule with all three durable voters live.
//! The forced campaign meets a committed lease; the next automatic campaigns
//! split, and the designated successor wins its computed retry. The original
//! ten-second waiter is retained as a negative control, not a completion bound.

use super::*;

use opc_consensus::engine::{
    error::RaftError,
    raft::{VoteRequest, VoteResponse},
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

/// Deliver real RPCs. The successor schedule holds crossing requests until
/// both self-votes persist; lease setup collects each pair of real replies
/// before either can produce a new leader and a committed heartbeat.
pub(super) struct VoteGate {
    candidates: [SessionConsensusNodeId; 2],
    split_term: Option<u64>,
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
        if request.family != crate::consensus::SessionConsensusRpcFamily::Vote {
            return handler.handle(request.sender, request).await;
        }
        let source = request.sender;
        let vote: VoteRequest<SessionConsensusNodeId> =
            opc_consensus::decode_bounded(&request.payload).expect("real vote request");
        let sent = Instant::now();
        if Some(vote.vote.leader_id.term) == self.split_term
            && self.candidates.contains(&source)
            && self.candidates.contains(&target)
        {
            self.crossing.wait().await;
        }
        let response = handler.handle(source, request).await;
        let reply: Result<VoteResponse<SessionConsensusNodeId>, RaftError<SessionConsensusNodeId>> =
            opc_consensus::decode_bounded(response.result.as_ref().expect("vote wire response"))
                .expect("real vote response");
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
        if self.split_term.is_none() {
            self.crossing.wait().await;
        }
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
        let early_sample = 0;
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
                // Construction samples once; each real campaign resamples.
                // Lease setup elects the successor and then the old leader
                // once each. The original successor schedule follows with
                // its forced denial, split, and winning retry.
                ElectionRngScript::new(if index == old {
                    vec![early_sample, early_sample, early_sample, late_sample]
                } else if index == successor {
                    vec![
                        early_sample,
                        early_sample,
                        early_sample,
                        early_sample,
                        late_sample,
                    ]
                } else {
                    vec![late_sample]
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
        while fleet.stores[self.old].status().applied_index <= before {
            tokio::task::yield_now().await;
        }
        let anchor = fleet.stores[self.old].status().applied_index;
        while !fleet
            .stores
            .iter()
            .all(|store| store.status().applied_index >= anchor)
        {
            tokio::task::yield_now().await;
        }
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

    /// A replicated command refreshes followers, but the leader's own vote
    /// retains its bootstrap timestamp. Exercise that expired-lease case, then
    /// elect away and back through real RPCs at controlled instants. The new
    /// committed vote establishes the lease required by the original denial.
    async fn renew_leader_lease(
        &mut self,
        fleet: &Fleet,
        phases: &[Duration],
        request: &FencedTransitionV2Request,
        void_first: bool,
    ) {
        let old = &fleet.stores[self.old];
        let successor = &fleet.stores[self.successor];
        let old_id = old.status().node_id;
        let successor_id = successor.status().node_id;
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
        // Setup may already have expired this lease. Otherwise keep the real
        // heartbeats running until the first tick strictly beyond its observed
        // expiry, so every run covers the slow-setup precondition as well.
        while Instant::now() <= old_updated + self.early.lease {
            self.advance_all(fleet, Instant::now() + self.early.tick)
                .await;
        }
        self.started = Instant::now();
        self.anchor_followers(fleet, request, void_first).await;
        let unchanged = old
            .inner
            .raft
            .with_raft_state(|state| (*state.vote_ref(), state.vote_last_modified()))
            .await
            .unwrap();
        assert_eq!(
            unchanged,
            (Vote::new_committed(old_term, old_id), Some(old_updated))
        );
        assert!(self.started > old_updated + self.early.lease);
        let gate = Arc::new(VoteGate {
            candidates: [old_id, successor_id],
            split_term: None,
            crossing: Barrier::new(2),
            exchanges: watch::channel(Vec::new()).0,
        });
        for peer in &fleet.peers {
            *peer.election_votes.lock().unwrap() = Some(gate.clone());
        }
        successor.inner.raft.trigger().elect().await.unwrap();
        let first = gate.observed(2).await;
        assert_eq!(first.len(), 2);
        for exchange in &first {
            assert_eq!(exchange.source, successor_id);
            assert_ne!(exchange.target, successor_id);
            assert_eq!(exchange.request.vote, Vote::new(old_term + 1, successor_id));
            assert_eq!(exchange.response.vote_granted, exchange.target == old_id);
            assert_eq!(
                exchange.response.vote,
                if exchange.target == old_id {
                    exchange.request.vote
                } else {
                    Vote::new_committed(old_term, old_id)
                }
            );
            assert_eq!(exchange.sent, self.started);
            assert_eq!(exchange.replied, self.started);
        }
        while !fleet.stores.iter().all(|store| {
            store.status().leader_id == Some(successor_id)
                && store.inner.raft.metrics().borrow().vote
                    == Vote::new_committed(old_term + 1, successor_id)
        }) {
            tokio::task::yield_now().await;
        }
        self.anchor_followers(fleet, request, void_first).await;
        let successor_updated = successor
            .inner
            .raft
            .with_raft_state(|state| {
                state
                    .vote_last_modified()
                    .expect("temporary leader has a committed vote")
            })
            .await
            .unwrap();
        assert_eq!(successor_updated, self.started);
        // Return leadership at the first ticker slot strictly after the
        // temporary leader's lease, before either follower can auto-campaign.
        let renewal = self.early.tick
            * u32::try_from(self.early.lease.as_nanos() / self.early.tick.as_nanos() + 1)
                .expect("finite lease setup");
        assert!(renewal > self.early.lease);
        for (index, phase) in phases.iter().copied().enumerate() {
            if index != self.successor {
                assert!(renewal < self.early.campaign(Duration::ZERO, phase, true));
            }
        }
        let mut tick = self.early.tick;
        while tick <= renewal {
            self.advance_all(fleet, self.started + tick).await;
            tick += self.early.tick;
        }
        // Core tick completion does not imply that the remaining voter has
        // handled the resulting heartbeat. A replay must reach every applied
        // frontier before this election relies on that voter's renewed lease.
        self.anchor_followers(fleet, request, void_first).await;
        let remaining = (0..fleet.stores.len())
            .find(|index| *index != self.old && *index != self.successor)
            .unwrap();
        let remaining_vote = fleet.stores[remaining]
            .inner
            .raft
            .with_raft_state(|state| (*state.vote_ref(), state.vote_last_modified()))
            .await
            .unwrap();
        assert_eq!(
            remaining_vote,
            (
                Vote::new_committed(old_term + 1, successor_id),
                Some(self.started + renewal)
            ),
            "the remaining voter has the observed fresh denial lease"
        );
        let temporary_leader_vote = successor
            .inner
            .raft
            .with_raft_state(|state| (*state.vote_ref(), state.vote_last_modified()))
            .await
            .unwrap();
        assert_eq!(
            temporary_leader_vote,
            (
                Vote::new_committed(old_term + 1, successor_id),
                Some(successor_updated)
            ),
            "the replay leaves the temporary leader's expired lease unchanged"
        );
        assert!(self.started + renewal > successor_updated + self.early.lease);
        assert_eq!(Instant::now(), self.started + renewal);
        old.inner.raft.trigger().elect().await.unwrap();
        let renewed = gate.observed(4).await;
        assert_eq!(renewed.len(), 4);
        for exchange in &renewed[2..] {
            assert_eq!(exchange.source, old_id);
            assert_ne!(exchange.target, old_id);
            assert_eq!(exchange.request.vote, Vote::new(old_term + 2, old_id));
            assert_eq!(
                exchange.response.vote_granted,
                exchange.target == successor_id
            );
            assert_eq!(
                exchange.response.vote,
                if exchange.target == successor_id {
                    exchange.request.vote
                } else {
                    Vote::new_committed(old_term + 1, successor_id)
                }
            );
            assert_eq!(exchange.sent - self.started, renewal);
            assert_eq!(exchange.replied - self.started, renewal);
        }
        while !fleet.stores.iter().all(|store| {
            store.status().leader_id == Some(old_id)
                && store.inner.raft.metrics().borrow().vote
                    == Vote::new_committed(old_term + 2, old_id)
        }) {
            tokio::task::yield_now().await;
        }
        assert_eq!(self.started.elapsed(), renewal);
        self.started = Instant::now();
        let renewed_at = old
            .inner
            .raft
            .with_raft_state(|state| state.vote_last_modified())
            .await
            .unwrap();
        assert_eq!(
            renewed_at,
            Some(self.started),
            "fresh old-leader lease inside frozen time"
        );
        for peer in &fleet.peers {
            *peer.election_votes.lock().unwrap() = None;
        }
        eprintln!(
            "void election: renewed old leader's committed lease at frozen {renewal:?}; \
             exchanges={renewed:?}"
        );
    }

    pub(super) async fn change_leader(
        &mut self,
        fleet: &Fleet,
        request: &FencedTransitionV2Request,
        void_first: bool,
    ) {
        let phases = self.settle(fleet).await;
        self.renew_leader_lease(fleet, &phases, request, void_first)
            .await;
        self.anchor_followers(fleet, request, void_first).await;
        // Every voter participates in the original automatic split and retry.
        // Only normal-time setup and explicit lease preparation suppress it.
        for store in &fleet.stores {
            store.inner.raft.runtime_config().elect(true);
        }
        let old = &fleet.stores[self.old];
        let successor = &fleet.stores[self.successor];
        let old_id = old.status().node_id;
        let successor_id = successor.status().node_id;
        let old_term = old.status().term;
        assert_eq!(old.status().leader_id, Some(old_id));
        let applied = old.status().applied_index;
        for store in &fleet.stores {
            assert_eq!(
                store.persistence_mode(),
                crate::SessionPersistenceMode::Durable
            );
            while store.status().applied_index != applied {
                tokio::task::yield_now().await;
            }
            assert_eq!(store.status().leader_id, Some(old_id));
        }
        for (index, script) in self.scripts.iter().enumerate() {
            schedule::tick_registered(
                &mut script.sleeps(),
                self.started + phases[index],
                self.early.tick,
            )
            .await;
        }
        assert_eq!(Instant::now(), self.started);
        let gate = Arc::new(VoteGate {
            candidates: [old_id, successor_id],
            split_term: Some(old_term + 2),
            crossing: Barrier::new(2),
            exchanges: watch::channel(Vec::new()).0,
        });
        for peer in &fleet.peers {
            *peer.election_votes.lock().unwrap() = Some(gate.clone());
        }
        // A preempted WAL writer may still hold State after publishing a
        // completion. Require real authority contention before releasing a
        // 200 ms wall-time hold; neither contention nor release advances the
        // protocol clock or changes the handler's real Vote response.
        let remaining = (0..fleet.stores.len())
            .find(|index| *index != self.old && *index != self.successor)
            .unwrap();
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
            eprintln!("void election: native owner released after observed contention and 200 ms");
        });
        holding.await.expect("actual native owner held");
        successor.inner.raft.trigger().elect().await.unwrap();
        contended
            .changed()
            .await
            .expect("real authority lock contention");
        release.send(()).expect("release contended native owner");
        let initial = gate.observed(2).await;
        holder.await.expect("join native authority hold");
        eprintln!("void election: initial forced campaign replies={initial:?}");
        assert_eq!(initial.len(), 2);
        for exchange in &initial {
            assert_eq!(exchange.source, successor_id);
            assert_eq!(exchange.request.vote, Vote::new(old_term + 1, successor_id));
            assert!(
                !exchange.response.vote_granted,
                "committed leader lease denies the forced campaign"
            );
            assert_eq!(
                exchange.response.vote,
                Vote::new_committed(old_term, old_id)
            );
            assert_eq!(exchange.sent, self.started);
            assert_eq!(exchange.replied, self.started);
        }
        // A real heartbeat learns the candidate's higher term. No voter is
        // stopped, no lease is shortened, and no engine state is overwritten.
        old.inner.raft.trigger().heartbeat().await.unwrap();
        while old.inner.raft.metrics().borrow().vote != Vote::new(old_term + 1, successor_id) {
            tokio::task::yield_now().await;
        }
        eprintln!(
            "void election: old leader learned the higher term at {:?}",
            self.started.elapsed()
        );
        let first = self
            .early
            .campaign(Duration::ZERO, phases[self.successor], false);
        assert_eq!(
            first,
            self.early.campaign(Duration::ZERO, phases[self.old], false)
        );
        let bound = self.early.campaign(first, phases[self.successor], false);
        assert!(bound < self.late.campaign(first, phases[self.old], false));
        let remaining = (0..fleet.stores.len())
            .find(|index| *index != self.old && *index != self.successor)
            .unwrap();
        assert!(bound < self.late.campaign(Duration::ZERO, phases[remaining], true));
        let former_limit = Duration::from_secs(10);
        assert!(first < former_limit && former_limit < bound);
        let expired = watch::channel(false).0;
        // Retain the exact former waiter to prove that this legal schedule
        // crosses its deadline. The driver still requires actual agreement
        // on the designated successor at the independently computed bound.
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
            let mut tick = phases[self.old] + self.early.tick;
            while tick <= bound {
                if Instant::now() < self.started + former_limit
                    && self.started + former_limit < self.started + tick
                {
                    tokio::time::advance(self.started + former_limit - Instant::now()).await;
                    expired.subscribe().wait_for(|done| *done).await.unwrap();
                    assert!(fleet
                        .stores
                        .iter()
                        .all(|store| store.status().leader_id != Some(successor_id)));
                    eprintln!(
                        "void election: former deadline {former_limit:?} expired; \
                         computed successor campaign {bound:?}"
                    );
                }
                tokio::time::advance(self.started + tick - Instant::now()).await;
                for (index, script) in self.scripts.iter().enumerate() {
                    schedule::tick_registered(
                        &mut script.sleeps(),
                        self.started + tick,
                        self.early.tick,
                    )
                    .await;
                    self.ticks
                        .wait(
                            fleet.stores[index].status().node_id.get(),
                            self.started + tick,
                        )
                        .await;
                }
                if tick == first {
                    let split = gate.observed(6).await;
                    eprintln!("void election: automatic split replies={:?}", &split[2..]);
                    assert_eq!(split.len(), 6);
                    for exchange in &split[2..] {
                        assert_eq!(
                            exchange.request.vote,
                            Vote::new(old_term + 2, exchange.source)
                        );
                        assert!(
                            !exchange.response.vote_granted,
                            "real self-votes and the remaining leader lease split this term"
                        );
                        assert_eq!(exchange.sent - self.started, first);
                        assert_eq!(exchange.replied - self.started, first);
                    }
                    assert_eq!(
                        old.inner.raft.metrics().borrow().vote,
                        Vote::new(old_term + 2, old_id)
                    );
                    assert_eq!(
                        successor.inner.raft.metrics().borrow().vote,
                        Vote::new(old_term + 2, successor_id)
                    );
                }
                tick += self.early.tick;
            }
            let exchanges = gate.observed(8).await;
            assert_eq!(exchanges.len(), 8);
            for exchange in &exchanges[6..] {
                assert_eq!(exchange.source, successor_id);
                assert_ne!(exchange.target, successor_id);
                assert_eq!(exchange.request.vote, Vote::new(old_term + 3, successor_id));
                assert!(exchange.response.vote_granted);
                assert_eq!(exchange.response.vote, exchange.request.vote);
                assert_eq!(exchange.sent - self.started, bound);
                assert_eq!(exchange.replied - self.started, bound);
            }
            while !fleet.stores.iter().all(|store| {
                store.status().leader_id == Some(successor_id)
                    && store.status().term == old_term + 3
            }) {
                tokio::task::yield_now().await;
            }
            assert_eq!(self.started.elapsed(), bound);
            for script in &self.scripts {
                script.finish();
            }
            for peer in &fleet.peers {
                *peer.election_votes.lock().unwrap() = None;
            }
            eprintln!(
                "void election: all three voters agree on designated successor at {bound:?}; \
                 exchanges={exchanges:?}"
            );
        };
        let (result, ()) = tokio::join!(wait, drive);
        assert!(
            result.is_err(),
            "the former ten-second wait excludes this valid successor election"
        );
    }
}
