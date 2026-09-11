//! Real Raft completion, election and cached-response schedules.

use super::*;
use opc_consensus::{decode_roster_bounded, engine::raft::VoteResponse};

struct CompletionHold(Arc<AcceptedClientWriteReceiverHoldForTest>);

impl CompletionHold {
    fn new(store: &ConsensusSessionStore) -> Self {
        let hold = Arc::new(AcceptedClientWriteReceiverHoldForTest::default());
        store.inject_accepted_client_write_receiver_outcome(
            AcceptedClientWriteReceiverTestOutcome::HoldUntilReleased(Arc::clone(&hold)),
        );
        Self(hold)
    }

    fn release(&self) {
        self.0.release.notify_one();
    }
}

impl Drop for CompletionHold {
    fn drop(&mut self) {
        self.release();
    }
}

enum ReplyFilter {
    AppendAtOrAfter(u64),
    GrantedVote,
}

enum CapturedRequest {
    Append(AppendEntriesRequest<SessionRaftTypeConfig>),
    Vote(VoteRequest<SessionConsensusNodeId>),
}

/// Exactly one actual successful response, retaining its original request.
/// No response is synthesized or enlarged by this transport.
pub(super) struct ReplyHold {
    sender: SessionConsensusNodeId,
    filter: ReplyFilter,
    captured: Mutex<Option<CapturedRequest>>,
    entered: tokio::sync::Notify,
    release: tokio::sync::watch::Sender<bool>,
    delivered: std::sync::atomic::AtomicBool,
}

struct ReplyRelease(Arc<ReplyHold>);

impl ReplyRelease {
    fn new(peer: &Peer, sender: SessionConsensusNodeId, minimum_index: u64) -> Self {
        Self::install(peer, sender, ReplyFilter::AppendAtOrAfter(minimum_index))
    }

    fn vote(peer: &Peer, sender: SessionConsensusNodeId) -> Self {
        Self::install(peer, sender, ReplyFilter::GrantedVote)
    }

    fn install(peer: &Peer, sender: SessionConsensusNodeId, filter: ReplyFilter) -> Self {
        let (release, _) = tokio::sync::watch::channel(false);
        let hold = Arc::new(ReplyHold {
            sender,
            filter,
            captured: Mutex::new(None),
            entered: tokio::sync::Notify::new(),
            release,
            delivered: std::sync::atomic::AtomicBool::new(false),
        });
        assert!(peer
            .held_reply
            .lock()
            .unwrap()
            .replace(Arc::clone(&hold))
            .is_none());
        Self(hold)
    }

    fn release(&self) {
        self.0.release.send_replace(true);
    }
}

impl Drop for ReplyRelease {
    fn drop(&mut self) {
        self.release();
    }
}

impl ReplyHold {
    fn append(&self) -> AppendEntriesRequest<SessionRaftTypeConfig> {
        match self.captured.lock().unwrap().as_ref().unwrap() {
            CapturedRequest::Append(request) => request.clone(),
            CapturedRequest::Vote(_) => panic!("expected actual append request"),
        }
    }

    fn vote(&self) -> VoteRequest<SessionConsensusNodeId> {
        match self.captured.lock().unwrap().as_ref().unwrap() {
            CapturedRequest::Vote(request) => request.clone(),
            CapturedRequest::Append(_) => panic!("expected actual vote request"),
        }
    }

    pub(super) async fn after_response(
        &self,
        request: SessionConsensusWireRequest,
        response: &SessionConsensusWireResponse,
    ) {
        if request.sender != self.sender {
            return;
        }
        let Ok(payload) = &response.result else {
            return;
        };
        let payload =
            persistence_protocol::unwrap_payload(SessionPersistenceMode::Async, payload).unwrap();
        let capture = match self.filter {
            ReplyFilter::AppendAtOrAfter(minimum_index) => {
                let Some(append) = append_request(&request) else {
                    return;
                };
                if !append_last(&append).is_some_and(|last| last.index >= minimum_index)
                    || !matches!(
                        decode_bounded::<
                            Result<
                                AppendEntriesResponse<SessionConsensusNodeId>,
                                RaftError<SessionConsensusNodeId>,
                            >,
                        >(payload),
                        Ok(Ok(AppendEntriesResponse::Success))
                    )
                {
                    return;
                }
                CapturedRequest::Append(append)
            }
            ReplyFilter::GrantedVote => {
                if request.family != SessionConsensusRpcFamily::Vote {
                    return;
                }
                let wire = persistence_protocol::unwrap_payload(
                    SessionPersistenceMode::Async,
                    &request.payload,
                )
                .unwrap();
                let vote: VoteRequest<SessionConsensusNodeId> = decode_bounded(wire).unwrap();
                let Ok(Ok(response)) = decode_bounded::<
                    Result<VoteResponse<SessionConsensusNodeId>, RaftError<SessionConsensusNodeId>>,
                >(payload) else {
                    return;
                };
                if !response.vote_granted || response.vote != vote.vote {
                    return;
                }
                CapturedRequest::Vote(vote)
            }
        };
        {
            let mut captured = self.captured.lock().unwrap();
            if captured.is_some() {
                return;
            }
            *captured = Some(capture);
        }
        self.entered.notify_one();
        let mut release = self.release.subscribe();
        while !*release.borrow_and_update() {
            release.changed().await.unwrap();
        }
        self.delivered.store(true, Ordering::Release);
    }
}

pub(super) fn append_request(
    request: &SessionConsensusWireRequest,
) -> Option<AppendEntriesRequest<SessionRaftTypeConfig>> {
    if !matches!(
        request.family,
        SessionConsensusRpcFamily::AppendEntries | SessionConsensusRpcFamily::AppendEntriesRoster
    ) {
        return None;
    }
    let payload =
        persistence_protocol::unwrap_payload(SessionPersistenceMode::Async, &request.payload)
            .unwrap();
    Some(
        if request.family == SessionConsensusRpcFamily::AppendEntriesRoster {
            decode_roster_bounded(payload).unwrap()
        } else {
            decode_bounded(payload).unwrap()
        },
    )
}

pub(super) fn append_last(
    append: &AppendEntriesRequest<SessionRaftTypeConfig>,
) -> Option<LogId<SessionConsensusNodeId>> {
    append
        .entries
        .last()
        .map(|entry| entry.log_id)
        .or(append.prev_log_id)
}

pub(super) async fn until(mut check: impl FnMut() -> bool, message: &str) {
    tokio::time::timeout(OPERATION_BOUND, async {
        while !check() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{message}"));
}

pub(super) async fn wait_for_lease_expiry(store: &ConsensusSessionStore) {
    let modified = store
        .inner
        .raft
        .with_raft_state(|state| state.vote_last_modified())
        .await
        .unwrap()
        .unwrap();
    // Fixture setup waits for the real pinned engine lease. No operation is
    // in progress, and neither election settings nor the 800 ms API change.
    let lease = Duration::from_millis(session_raft_config().unwrap().election_timeout_max);
    tokio::time::sleep_until(modified + lease + Duration::from_millis(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_old_completion_cannot_certify_a_new_leader() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let old = fleet.leader();
        let recovering = (old + 1) % 3;
        let next = (old + 2) % 3;
        let provider = provider();
        let first = create_request(fleet.store(old), 1, &provider).await;
        let outcome = create(fleet.store(old), &first).await;
        fleet
            .store(old)
            .activate_fenced_transition_capability()
            .await
            .unwrap();
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &outcome).await;
            store.drain_async_persistence().await.unwrap();
        }
        fleet.close(recovering).await;
        fleet
            .open(recovering, SessionPersistenceMode::Async)
            .await
            .unwrap();
        let cold = fleet.store(recovering).clone();
        let old_store = fleet.store(old).clone();
        let next_store = fleet.store(next).clone();
        let vote = old_store.inner.raft.metrics().borrow().vote;
        wait_for_lease_expiry(&old_store).await;
        assert_eq!(old_store.inner.raft.metrics().borrow().vote, vote);
        let request = cold
            .inner
            .persistence_protocol
            .quarantine_before(tokio::time::Instant::now() + OPERATION_BOUND)
            .await
            .unwrap();
        let before = old_store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap();
        let hold = CompletionHold::new(&old_store);
        let started = tokio::time::Instant::now();
        let pending = {
            let cold = cold.clone();
            let leader = fleet.peers[old].node;
            tokio::spawn(async move {
                cold.call_peer::<_, ColdQuorumCut>(
                    leader,
                    SessionConsensusRpcFamily::ReadBarrier,
                    &request,
                    started + OPERATION_BOUND,
                )
                .await
            })
        };
        tokio::time::timeout(OPERATION_BOUND, hold.0.entered.notified())
            .await
            .unwrap();
        until(
            || {
                let first = old_store.inner.raft.metrics().borrow().last_applied;
                first.is_some_and(|log| log.index > before)
                    && first == next_store.inner.raft.metrics().borrow().last_applied
            },
            "the held recovery proposal really applies through the surviving quorum",
        )
        .await;
        let old_applied = old_store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .unwrap();
        assert_eq!(
            old_applied.leader_id,
            CommittedLeaderId::new(vote.leader_id.term, fleet.peers[old].node)
        );
        next_store.inner.raft.trigger().elect().await.unwrap();
        until(
            || {
                let new_vote = next_store.inner.raft.metrics().borrow().vote;
                new_vote.is_committed()
                    && new_vote.leader_id.term > vote.leader_id.term
                    && new_vote.leader_id.voted_for() == Some(fleet.peers[next].node)
                    && old_store.inner.raft.metrics().borrow().vote == new_vote
            },
            "a real higher-term leader is elected before the old completion is released",
        )
        .await;
        hold.release();
        assert!(matches!(
            pending.await.unwrap(),
            Err(ConsensusPeerCallFailure::AuthenticatedRejection(
                SessionConsensusPeerError::Rejected
            ))
        ));
        assert!(started.elapsed() < OPERATION_BOUND);
        assert!(!cold.inner.persistence_protocol.is_active());
        until(
            || {
                let applied = next_store.inner.raft.metrics().borrow().last_applied;
                applied.is_some_and(|log| log.leader_id.term > vote.leader_id.term)
                    && applied == old_store.inner.raft.metrics().borrow().last_applied
            },
            "the new leader's ordinary entry applies before checking the old leader's rejection",
        )
        .await;
        // A former leader cannot issue a lower-vote certificate after the
        // actual higher-vote quorum has elected its successor.
        let before_rejected = old_store.inner.raft.metrics().borrow().last_log_index;
        assert!(matches!(
            cold.call_peer::<_, ColdQuorumCut>(
                fleet.peers[old].node,
                SessionConsensusRpcFamily::ReadBarrier,
                &request,
                tokio::time::Instant::now() + OPERATION_BOUND
            )
            .await,
            Err(ConsensusPeerCallFailure::AuthenticatedRejection(
                SessionConsensusPeerError::Rejected
            ))
        ));
        assert_eq!(
            old_store.inner.raft.metrics().borrow().last_log_index,
            before_rejected
        );
        let initialized = tokio::time::Instant::now();
        cold.initialize_cluster().await.unwrap();
        assert!(initialized.elapsed() < OPERATION_BOUND);
        let cut = fleet.peers[next].last_cut.lock().unwrap().unwrap();
        assert!(cut.vote.leader_id.term > vote.leader_id.term);
        assert!(cut.barrier.index > old_applied.index);
        assert_ne!(cut.request.nonce, request.nonce);
        // A duplicate purpose/nonce has a real cached application result.
        // It must not be relabeled as the newly appended certificate entry.
        assert!(matches!(
            cold.call_peer::<_, ColdQuorumCut>(
                fleet.peers[next].node,
                SessionConsensusRpcFamily::ReadBarrier,
                &cut.request,
                tokio::time::Instant::now() + OPERATION_BOUND
            )
            .await,
            Err(ConsensusPeerCallFailure::AuthenticatedRejection(
                SessionConsensusPeerError::Rejected
            ))
        ));
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &outcome).await;
        }
        let second = create_request(&next_store, 2, &provider).await;
        let second_outcome = create(&next_store, &second).await;
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &second, &second_outcome).await;
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_cached_append_success_cannot_commit_a_fresh_cold_barrier() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let leader = fleet.leader();
        let recovering = (leader + 1) % 3;
        let other = (leader + 2) % 3;
        let live = fleet.store(leader).clone();
        let provider = provider();
        let first = create_request(&live, 1, &provider).await;
        let first_outcome = create(&live, &first).await;
        live.activate_fenced_transition_capability().await.unwrap();
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
            store.drain_async_persistence().await.unwrap();
        }
        let second = create_request(&live, 2, &provider).await;
        let minimum = live.inner.raft.metrics().borrow().last_log_index.unwrap() + 1;
        let hold = ReplyRelease::new(&fleet.peers[recovering], fleet.peers[leader].node, minimum);
        let second_outcome = create(&live, &second).await;
        tokio::time::timeout(OPERATION_BOUND, hold.0.entered.notified()).await.unwrap();
        let request = hold.0.append();
        let cached = request.entries.last().map(|entry| entry.log_id).or(request.prev_log_id).unwrap();
        assert!(cached.index >= minimum);
        assert_eq!(request.vote, live.inner.raft.metrics().borrow().vote);
        assert!(!hold.0.delivered.load(Ordering::Acquire));
        fleet.close(recovering).await;
        fleet.open(recovering, SessionPersistenceMode::Async).await.unwrap();
        let cold = fleet.store(recovering).clone();
        assert!(!cold.inner.persistence_protocol.is_active());
        let before = live.inner.raft.metrics().borrow().last_log_index.unwrap();
        assert!(before >= cached.index);
        // Permit the existing generic read-index preflight at the old range,
        // then prevent the remaining follower from receiving any new entry.
        // The real new recovery proposal consequently has no append quorum.
        *fleet.peers[other].blocked_append_above.lock().unwrap() = Some((fleet.peers[leader].node, before));
        let initialization = cold.initialize_cluster();
        tokio::pin!(initialization);
        tokio::select! {
            result = &mut initialization => panic!("cold initialization completed before its new barrier: {result:?}"),
            () = until(|| live.inner.raft.metrics().borrow().last_log_index.is_some_and(|index| index > before), "leader must append a new cold barrier without a live majority") => {}
        }
        let new_index = live.inner.raft.metrics().borrow().last_log_index.unwrap();
        assert!(new_index > cached.index);
        hold.release();
        until(|| hold.0.delivered.load(Ordering::Acquire), "the actual pre-crash success is delivered").await;
        until(|| live.inner.raft.metrics().borrow().replication.as_ref()
            .and_then(|replication| replication.get(&fleet.peers[recovering].node)).copied().flatten() == Some(cached),
            "pinned Raft accounts the cached response only to its exact original range").await;
        assert!(live.inner.raft.metrics().borrow().last_applied.unwrap().index < new_index);
        assert!(matches!(initialization.await, Err(ConsensusSessionStoreOpenError::RecoveryRequired)));
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(live.inner.raft.metrics().borrow().last_applied.unwrap().index < new_index);
        *fleet.peers[other].blocked_append_above.lock().unwrap() = None;
        let started = tokio::time::Instant::now();
        cold.initialize_cluster().await.unwrap();
        assert!(started.elapsed() < OPERATION_BOUND);
        let cut = fleet.peers[leader].last_cut.lock().unwrap().unwrap();
        assert!(cut.barrier.index > new_index);
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
            assert_recorded(store, &second, &second_outcome).await;
        }
    }).catch_unwind().await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_forgotten_vote_cannot_finish_a_stale_five_voter_campaign() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(5);
    let faults = (0..5)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect::<Vec<_>>();
    let result = AssertUnwindSafe(async {
        for (index, fault) in faults.iter().enumerate() {
            let fault = Arc::clone(fault);
            let hook: GenerationHook = Arc::new(move || {
                if fault.load(Ordering::Acquire) {
                    Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
                } else {
                    Ok(())
                }
            });
            fleet
                .open_with_hook(index, SessionPersistenceMode::Async, Some(hook))
                .await
                .unwrap();
        }
        fleet.form().await;
        let leader = fleet.leader();
        let forgotten = (leader + 1) % 5;
        let candidate = (leader + 2) % 5;
        let survivors = [leader, (leader + 3) % 5, (leader + 4) % 5];
        let live = fleet.store(leader).clone();
        let contender = fleet.store(candidate).clone();
        let provider = provider();
        let first = create_request(&live, 1, &provider).await;
        let first_outcome = create(&live, &first).await;
        live.activate_fenced_transition_capability().await.unwrap();
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
            store.inner.raft.runtime_config().elect(false);
        }
        let retained = live.inner.raft.metrics().borrow().last_applied.unwrap();
        let retained_vote = live.inner.raft.metrics().borrow().vote;
        assert!(retained_vote.is_committed());
        until(
            || {
                fleet.stores.iter().flatten().all(|store| {
                    let metrics = store.inner.raft.metrics();
                    let current = metrics.borrow();
                    current.vote == retained_vote
                        && current.last_applied == Some(retained)
                        && current.last_log_index == Some(retained.index)
                })
            },
            "every voter has the same actual retained log before the old campaign",
        )
        .await;
        for store in fleet.stores.iter().flatten() {
            store.drain_async_persistence().await.unwrap();
        }
        until(
            || {
                fleet.stores.iter().flatten().all(|store| {
                    let progress = store.persistence_health().asynchronous.unwrap();
                    progress.captured_generation.is_none()
                        && progress.completed_generation == progress.resident_generation
                })
            },
            "all selected generations precede the controlled forgotten vote",
        )
        .await;
        let selected = fleet.selector(forgotten);
        let completed = fleet
            .store(forgotten)
            .persistence_health()
            .asynchronous
            .unwrap()
            .completed_generation;

        // A and B stop hearing the old leader; C/D/E remain a live majority.
        // B's only reachable external voter is A, so even its real cached
        // grant plus B's self-vote cannot elect B in this five-voter set.
        for survivor in survivors {
            fleet.set_link(survivor, forgotten, false);
            fleet.set_link(survivor, candidate, false);
            fleet.set_link(candidate, survivor, false);
        }
        tokio::join!(
            wait_for_lease_expiry(fleet.store(forgotten)),
            wait_for_lease_expiry(&contender)
        );
        let hold = ReplyRelease::vote(&fleet.peers[forgotten], fleet.peers[candidate].node);
        faults[forgotten].store(true, Ordering::Release);
        let campaign_started = tokio::time::Instant::now();
        contender.inner.raft.trigger().elect().await.unwrap();
        tokio::time::timeout(OPERATION_BOUND, hold.0.entered.notified())
            .await
            .unwrap();
        let campaign = hold.0.vote();
        assert_eq!(campaign.last_log_id, Some(retained));
        assert!(campaign.vote.leader_id.term > retained_vote.leader_id.term);
        assert!(!campaign.vote.is_committed());
        assert_eq!(
            campaign.vote.leader_id.voted_for(),
            Some(fleet.peers[candidate].node)
        );
        assert_eq!(contender.inner.raft.metrics().borrow().vote, campaign.vote);
        assert_eq!(
            fleet.store(forgotten).inner.raft.metrics().borrow().vote,
            campaign.vote
        );
        assert!(!hold.0.delivered.load(Ordering::Acquire));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(failure) = fleet
                    .store(forgotten)
                    .persistence_health()
                    .asynchronous
                    .unwrap()
                    .background_failure
                {
                    assert_eq!(failure.os_error, Some(libc::ENOSPC));
                    assert_eq!(failure.kind, crate::SessionStorageFailureKind::StorageFull);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the real generation write containing A's new vote fails");
        assert_eq!(fleet.selector(forgotten), selected);
        assert_eq!(
            fleet
                .store(forgotten)
                .persistence_health()
                .asynchronous
                .unwrap()
                .completed_generation,
            completed
        );
        assert!(fleet.close_result(forgotten).await.is_err());
        assert_eq!(fleet.selector(forgotten), selected);
        fleet
            .open(forgotten, SessionPersistenceMode::Async)
            .await
            .unwrap();
        let cold = fleet.store(forgotten).clone();
        // The public opener restores storage before Raft::new spawns its
        // core, but the metrics watch starts with an empty vote. First check
        // the independently restored storage, then require the same exact
        // vote from the engine within the existing fixture operation bound.
        let mut restored_log = crate::sqlite::consensus::wal::adapter::WalLogStore::new(
            Arc::clone(cold.inner.private_wal.as_ref().unwrap()),
        );
        assert_eq!(
            opc_consensus::engine::storage::RaftLogStorage::read_vote(&mut restored_log)
                .await
                .unwrap(),
            Some(retained_vote)
        );
        drop(restored_log);
        until(
            || cold.inner.raft.metrics().borrow().vote == retained_vote,
            "startup publishes the independently restored committed vote",
        )
        .await;
        assert_eq!(cold.inner.raft.metrics().borrow().vote, retained_vote);
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
        for survivor in survivors {
            assert_eq!(
                fleet.store(survivor).inner.raft.metrics().borrow().vote,
                retained_vote
            );
            fleet.set_link(survivor, forgotten, true);
        }
        let initialized = tokio::time::Instant::now();
        cold.initialize_cluster().await.unwrap();
        assert!(initialized.elapsed() < OPERATION_BOUND);
        let cut = fleet.peers[leader].last_cut.lock().unwrap().unwrap();
        assert_eq!(cut.vote, retained_vote);
        assert_eq!(cut.requester, fleet.peers[forgotten].node);
        assert!(cut.barrier.index > retained.index);
        assert!(cold.inner.persistence_protocol.is_active() && cold.status().admitted);
        assert_eq!(cold.inner.raft.metrics().borrow().vote, retained_vote);
        until(
            || {
                survivors.iter().all(|index| {
                    fleet
                        .store(*index)
                        .inner
                        .raft
                        .metrics()
                        .borrow()
                        .last_applied
                        .is_some_and(|last| persistence_protocol::covers(last, cut.barrier))
                })
            },
            "C/D/E actually apply their fresh barrier without A's lost vote",
        )
        .await;
        hold.release();
        until(
            || hold.0.delivered.load(Ordering::Acquire),
            "deliver A's original actual grant to B after A's cold rejoin",
        )
        .await;
        assert!(
            campaign_started.elapsed()
                < Duration::from_millis(session_raft_config().unwrap().election_timeout_min)
        );
        assert_eq!(contender.inner.raft.metrics().borrow().vote, campaign.vote);
        assert_ne!(
            contender.status().leader_id,
            Some(fleet.peers[candidate].node)
        );

        // Let the surviving voters' actual leases expire before asking again:
        // their rejection must come from the new log prefix, not a fresh lease.
        for survivor in survivors {
            fleet
                .store(survivor)
                .inner
                .raft
                .runtime_config()
                .elect(false);
            if survivor != leader {
                fleet.set_link(leader, survivor, false);
            }
        }
        join_all(
            survivors
                .iter()
                .map(|index| wait_for_lease_expiry(fleet.store(*index))),
        )
        .await;
        for survivor in survivors {
            let modified = fleet
                .store(survivor)
                .inner
                .raft
                .with_raft_state(|state| state.vote_last_modified())
                .await
                .unwrap()
                .unwrap();
            assert!(
                tokio::time::Instant::now()
                    > modified
                        + Duration::from_millis(
                            session_raft_config().unwrap().election_timeout_max
                        )
            );
            fleet.set_link(candidate, survivor, true);
            let response =
                    contender
                        .call_peer::<_, Result<
                            VoteResponse<SessionConsensusNodeId>,
                            RaftError<SessionConsensusNodeId>,
                        >>(
                            fleet.peers[survivor].node,
                            SessionConsensusRpcFamily::Vote,
                            &campaign,
                            tokio::time::Instant::now() + OPERATION_BOUND,
                        )
                        .await
                        .unwrap()
                        .unwrap();
            assert!(!response.vote_granted);
            assert_eq!(response.vote, retained_vote);
            assert!(response
                .last_log_id
                .is_some_and(|last| persistence_protocol::covers(last, cut.barrier)));
            assert_eq!(
                fleet.store(survivor).inner.raft.metrics().borrow().vote,
                retained_vote
            );
        }
        assert_eq!(contender.inner.raft.metrics().borrow().vote, campaign.vote);
        assert_ne!(
            contender.status().leader_id,
            Some(fleet.peers[candidate].node)
        );

        // A fresh candidate carrying the barrier can win a real election.
        // Keep the old contender isolated until that committed vote exists.
        let successor = survivors[1];
        let next = fleet.store(successor).clone();
        next.inner.raft.trigger().elect().await.unwrap();
        until(
            || {
                let vote = next.inner.raft.metrics().borrow().vote;
                vote.is_committed()
                    && vote.leader_id.term > retained_vote.leader_id.term
                    && vote.leader_id.voted_for() == Some(fleet.peers[successor].node)
                    && survivors
                        .iter()
                        .all(|index| fleet.store(*index).inner.raft.metrics().borrow().vote == vote)
            },
            "a candidate with the fresh barrier wins the surviving real majority",
        )
        .await;
        let elected = next.inner.raft.metrics().borrow().vote;
        for sender in 0..5 {
            for target in 0..5 {
                fleet.set_link(sender, target, true);
            }
        }
        until(
            || {
                fleet
                    .stores
                    .iter()
                    .flatten()
                    .all(|store| store.inner.raft.metrics().borrow().vote == elected)
            },
            "the committed successor catches up the old candidate and reopened voter",
        )
        .await;
        for store in fleet.stores.iter().flatten() {
            store.inner.raft.runtime_config().elect(true);
            assert_recorded(store, &first, &first_outcome).await;
        }
        let second = create_request(&next, 2, &provider).await;
        let second_outcome = create(&next, &second).await;
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &second, &second_outcome).await;
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
