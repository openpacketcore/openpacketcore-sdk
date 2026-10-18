//! Live log pressure and automatic recovery through actual multi-voter stores.

use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;
use opc_consensus::DURABLE_OPENRAFT_PROFILE;

#[cfg(feature = "test-control")]
#[path = "write_retention.rs"]
mod write_retention;

#[path = "snapshot_progress.rs"]
mod snapshot_progress;

#[path = "pressure_round.rs"]
mod pressure_round;

const WAIT: Duration = Duration::from_secs(60);

#[cfg(feature = "test-control")]
struct SlowAcceptedReply {
    stores: Vec<ConsensusSessionStore>,
    holds: Vec<Arc<AcceptedClientWriteReceiverHoldForTest>>,
    release: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(feature = "test-control")]
impl SlowAcceptedReply {
    fn arm(fleet: &Fleet) -> Self {
        let mut held = Self::hold(fleet);
        let releasing = held.holds.clone();
        held.release = Some(tokio::spawn(async move {
            futures_util::future::select_all(
                releasing
                    .iter()
                    .map(|hold| Box::pin(hold.entered.notified())),
            )
            .await;
            tokio::time::sleep(OPERATION_BOUND + Duration::from_millis(100)).await;
            for hold in releasing {
                hold.release.notify_one();
            }
        }));
        held
    }

    fn hold(fleet: &Fleet) -> Self {
        let stores = fleet.stores.iter().flatten().cloned().collect::<Vec<_>>();
        let holds = stores
            .iter()
            .map(|store| {
                let hold = Arc::new(AcceptedClientWriteReceiverHoldForTest::default());
                store.inject_accepted_client_write_receiver_outcome(
                    AcceptedClientWriteReceiverTestOutcome::HoldUntilReleased(Arc::clone(&hold)),
                );
                hold
            })
            .collect::<Vec<_>>();
        Self {
            stores,
            holds,
            release: None,
        }
    }
}

#[cfg(feature = "test-control")]
impl Drop for SlowAcceptedReply {
    fn drop(&mut self) {
        if let Some(release) = &self.release {
            release.abort();
        }
        for hold in &self.holds {
            hold.release.notify_one();
        }
        for store in &self.stores {
            store
                .inner
                .accepted_receiver_test_outcomes
                .lock()
                .unwrap()
                .clear();
        }
    }
}

#[cfg(feature = "test-control")]
fn recovery_reply_kind(reply: &ForwardMutationReply) -> &'static str {
    match reply {
        ForwardMutationReply::Applied(response) if response.result.is_ok() => "applied",
        ForwardMutationReply::Applied(_) => "rejected",
        ForwardMutationReply::RecordExpiryPreflight(_) => "record-expiry-preflight",
        ForwardMutationReply::NotLeader { .. } => "not-leader",
        ForwardMutationReply::Unavailable => "unavailable",
        ForwardMutationReply::OutcomeUnknown => "outcome-unknown",
        ForwardMutationReply::FencedTransitionActivation(_) => "activation",
        ForwardMutationReply::LogPressure => "log-pressure",
    }
}

async fn fleet(mode: SessionPersistenceMode) -> Fleet {
    let mut fleet = Fleet::new(3);
    for index in 0..3 {
        fleet.open(index, mode).await.unwrap();
    }
    fleet.form().await;
    fleet
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_full_follower_keeps_heartbeats_and_leadership() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let source = fleet.store(leader);
        let follower = fleet.store((leader + 1) % 3);
        follower
            .inner
            .raft_handler
            .set_log_admission_window_for_test(1);
        let vote = source.inner.raft.metrics().borrow().vote;
        let command = repeated_command(source);
        let started = tokio::time::Instant::now();
        // Keep real elections enabled beyond the full leader lease plus the
        // maximum election timeout (8 + 8 seconds). Data appends carry the
        // heartbeats throughout this interval; no synthetic empty RPC helps.
        while started.elapsed() < Duration::from_secs(35) {
            let reply = propose(
                source,
                &command,
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await;
            assert!(
                matches!(reply, ForwardMutationReply::Applied(ref response)
                if response.result.is_ok()),
                "live write must commit: {reply:?}"
            );
            let observed = follower.inner.raft.metrics().borrow().clone();
            if observed.vote != vote {
                eprintln!(
                    "follower_election_probe elapsed_ms={} follower={observed} leader={}",
                    started.elapsed().as_millis(),
                    source.inner.raft.metrics().borrow().clone()
                );
            }
            assert_eq!(source.inner.raft.metrics().borrow().vote, vote);
            assert_eq!(
                follower.inner.raft.metrics().borrow().vote,
                vote,
                "a full follower must keep receiving the leader's data heartbeats"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let through = source.inner.raft.metrics().borrow().last_applied.unwrap();
        follower
            .inner
            .raft
            .wait(Some(Duration::from_secs(10)))
            .applied_index_at_least(Some(through.index), "full follower applies all writes")
            .await
            .unwrap();
        assert_eq!(source.inner.raft.metrics().borrow().vote, vote);
        assert_eq!(follower.inner.raft.metrics().borrow().vote, vote);
        assert!(follower.log_pressure_snapshot().retained_rows > 1);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_full_majority_commits_accepted_write() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let source = fleet.store(leader);
        for index in 0..3 {
            if index != leader {
                fleet
                    .store(index)
                    .inner
                    .raft_handler
                    .set_log_admission_window_for_test(1);
            }
        }
        let before = source.inner.raft.metrics().borrow().last_applied.unwrap();
        let reply = propose(
            source,
            &repeated_command(source),
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await;
        assert!(
            matches!(reply, ForwardMutationReply::Applied(ref response)
            if response.result.is_ok()),
            "follower pressure cannot strand an accepted write: {reply:?}"
        );
        for index in 0..3 {
            fleet
                .store(index)
                .inner
                .raft
                .wait(Some(Duration::from_secs(10)))
                .applied_index_at_least(Some(before.index + 1), "accepted write on every voter")
                .await
                .unwrap();
            assert!(fleet
                .store(index)
                .inner
                .raft
                .metrics()
                .borrow()
                .running_state
                .is_ok());
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_cold_barrier_uses_reserved_headroom() {
    let mut fleet = fleet(SessionPersistenceMode::Async).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let source = fleet.store(leader);
        source
            .inner
            .raft_handler
            .set_log_admission_window_for_test(1);
        let sender = fleet.store((leader + 1) % 3).inner.local_node_id;
        let before = source.inner.raft.metrics().borrow().last_applied.unwrap();
        let nonce = SessionConsensusRequestId::new();
        let payload = encode_bounded(&(
            *persistence_protocol::COLD_BARRIER_WIRE,
            SessionConsensusRequestId::new(),
            1_u64,
            nonce,
        ))
        .unwrap();
        let response = source.handle_async_cold_barrier(sender, &payload).await;
        let cut: ColdQuorumCut = decode_bounded(
            &response
                .result
                .expect("authenticated cold barrier must pass the full ordinary window"),
        )
        .unwrap();
        assert_eq!(cut.request.nonce, nonce);
        assert_eq!(cut.requester, sender);
        assert!(cut.barrier.index > before.index);
        assert_eq!(cut.vote, source.inner.raft.metrics().borrow().vote);
        assert!(
            !source.inner.raft_handler.log_admission.has_capacity(),
            "the cold barrier does not open ordinary admission"
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

fn repeated_command(store: &ConsensusSessionStore) -> SessionConsensusCommand {
    SessionConsensusCommand {
        schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
        identity: store.inner.storage_identity,
        request_id: SessionConsensusRequestId::from_bytes([0xB6; 16]),
        logical_time: store.inner.clock.now_utc(),
        intent: SessionMutationIntent::Authorized {
            origin: store.inner.local_node_id,
            authority_identity: store.inner.storage_identity,
            mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
        },
    }
}

async fn propose(
    store: &ConsensusSessionStore,
    command: &SessionConsensusCommand,
    deadline: tokio::time::Instant,
) -> ForwardMutationReply {
    propose_class(store, command, deadline, ScopeWorkClass::Normal).await
}

async fn propose_class(
    store: &ConsensusSessionStore,
    command: &SessionConsensusCommand,
    deadline: tokio::time::Instant,
    class: ScopeWorkClass,
) -> ForwardMutationReply {
    let reservation = store
        .inner
        .proposal_admission
        .reserve_for(ScopeSchedulerKey::INTERNAL, class)
        .await
        .unwrap();
    let proposal_permit = match store
        .start_proposal_before(reservation, &command.intent, deadline)
        .await
    {
        Ok(permit) => permit,
        Err(reply) => return reply,
    };
    let operation_guard = store
        .inner
        .topology_coordinator
        .operation_gate()
        .read_owned()
        .await;
    store
        .propose_on_local_leader(
            ForwardMutationRequest {
                request_id: command.request_id,
                intent: SessionMutationIntent::AdvanceLogicalTime,
                required_consumer_scope: ForwardConsumerScope::Internal,
                work_class: ForwardWorkClass::Inferred,
            },
            LocalProposalAuthority {
                origin: store.inner.local_node_id,
                allows_operator_recovery: false,
                persistence_stamp: store.inner.persistence_protocol.operation_stamp(),
                fixed_raw_v2_snapshot: false,
            },
            command.logical_time,
            LocalProposalExecution {
                proposal_permit,
                operation_guard: Some(operation_guard),
                persistence_submission: None,
                cohort_freeze: None,
                cold_completion: None,
            },
            None,
            deadline,
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_emergency_commits_while_ordinary_waits() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let source = fleet.store(fleet.leader());
        for store in fleet.stores.iter().flatten() {
            store
                .inner
                .raft_handler
                .set_log_admission_window_for_test(1);
        }
        let command = repeated_command(source);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut ordinary = Box::pin(propose(source, &command, deadline));
        assert!(futures_util::poll!(&mut ordinary).is_pending());
        let before = source.inner.raft.metrics().borrow().last_applied.unwrap();
        let reply = propose_class(source, &command, deadline, ScopeWorkClass::Emergency).await;
        assert!(
            matches!(reply, ForwardMutationReply::Applied(ref response)
            if response.result.is_ok()),
            "emergency reaches final proposal and commits: {reply:?}"
        );
        assert!(futures_util::poll!(&mut ordinary).is_pending());
        for store in fleet.stores.iter().flatten() {
            store
                .inner
                .raft
                .wait(Some(Duration::from_secs(10)))
                .applied_index_at_least(Some(before.index + 1), "emergency applied by all voters")
                .await
                .unwrap();
        }
        assert!(!source.inner.raft_handler.log_admission.has_capacity());
        drop(ordinary);
        assert_eq!(
            source.inner.proposal_admission.available_permits(),
            SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_demoted_requests_reroute_with_original_deadline() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let source = fleet.store(leader);
        let successor = fleet.store((leader + 1) % 3);
        let other = fleet.store((leader + 2) % 3);
        source
            .inner
            .raft_handler
            .set_log_admission_window_for_test(1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let command = repeated_command(source);
        let mut waiting = Box::pin(propose(source, &command, deadline));
        assert!(futures_util::poll!(&mut waiting).is_pending());
        let request = source
            .inner
            .raft
            .begin_leadership_transfer(successor.inner.local_node_id)
            .await
            .unwrap();
        for target in [other, successor] {
            let result: Result<
                (),
                RaftError<SessionConsensusNodeId, opc_consensus::engine::raft::TransferLeaderError>,
            > = source
                .call_peer(
                    target.inner.local_node_id,
                    SessionConsensusRpcFamily::LeadershipTransfer,
                    &request,
                    deadline,
                )
                .await
                .unwrap();
            result.unwrap();
        }
        let reply = waiting.await;
        assert!(
            matches!(reply, ForwardMutationReply::NotLeader { .. }),
            "parked proposal redirects on demotion: {reply:?}"
        );
        successor
            .inner
            .raft
            .wait(Some(Duration::from_secs(10)))
            .current_leader(successor.inner.local_node_id, "successor elected")
            .await
            .unwrap();
        assert!(tokio::time::Instant::now() < deadline);
        let reply = propose(successor, &command, deadline).await;
        assert!(
            matches!(reply, ForwardMutationReply::Applied(ref response)
            if response.result.is_ok()),
            "rerouted proposal retains its original deadline: {reply:?}"
        );
        assert_eq!(
            source.inner.proposal_admission.available_permits(),
            SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS
        );
        assert!(
            !source.inner.raft_handler.log_admission.has_capacity(),
            "redirect did not depend on local reclamation"
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

async fn seed_to(store: &ConsensusSessionStore, command: &SessionConsensusCommand, target: u64) {
    let mut last = store.inner.raft.metrics().borrow().last_log_index.unwrap();
    while last < target {
        let count = (target - last).min(DURABLE_OPENRAFT_PROFILE.max_payload_entries);
        let replies = tokio::time::timeout(
            WAIT,
            join_all((0..count).map(|_| store.inner.raft.client_write(command.clone()))),
        )
        .await
        .unwrap();
        for reply in replies {
            let reply = reply.unwrap_or_else(|error| {
                panic!(
                    "seed failed: {error:?}; last={last} target={target}; pressure={:?}; metrics={:?}",
                    store.log_pressure_snapshot(),
                    store.inner.raft.metrics().borrow(),
                )
            });
            assert!(reply.data.result.is_ok());
            assert!(reply.log_id.index > last);
            last = reply.log_id.index;
        }
    }
    store
        .inner
        .raft
        .wait(Some(WAIT))
        .applied_index_at_least(Some(target), "seeded log applied")
        .await
        .unwrap();
}

async fn expired_snapshot_attempt(mode: SessionPersistenceMode) {
    let mut fleet = fleet(mode).await;
    let held = ReleaseIo(vec![Arc::new(SnapshotArtifactGate::new())]);
    let result = AssertUnwindSafe(async {
        let store = fleet.store(fleet.leader());
        store
            .inner
            .storage_shutdown
            .set_snapshot_limits_for_test(Duration::from_millis(500), Duration::from_secs(5));
        let gate = held.0[0].clone();
        gate.arm();
        store
            .inner
            .storage_shutdown
            .pause_next_snapshot_publication_for_test(gate.clone());
        let before = store.inner.raft.metrics().borrow().last_applied.unwrap();
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), gate.wait_started())
            .await
            .unwrap();
        assert_eq!(store.inner.raft.metrics().borrow().snapshot, None);
        assert!(store
            .inner
            .terminal_recovery_handoff_consumer
            .snapshot_worker_is_active_for_test());
        let reply = propose(
            store,
            &repeated_command(store),
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await;
        assert!(
            matches!(reply, ForwardMutationReply::Applied(ref response)
            if response.result.is_ok()),
            "primary work progresses during the held build: {reply:?}"
        );
        // Never release the first attempt. Only cancellation and an automatic
        // fresh attempt can publish this newer cut.
        store
            .inner
            .raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |metrics| metrics.snapshot.is_some_and(|cut| cut.index > before.index),
                "expired snapshot retries without releasing the original stall",
            )
            .await
            .unwrap();
        assert!(store.inner.storage_shutdown.snapshot_retries_for_test() >= 1);
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
        assert_eq!(
            store.inner.raft.metrics().borrow().current_leader,
            Some(store.inner.local_node_id)
        );
    })
    .catch_unwind()
    .await;
    drop(held);
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_snapshot_attempt_expires_and_retries_durable() {
    expired_snapshot_attempt(SessionPersistenceMode::Durable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_snapshot_attempt_expires_and_retries_async() {
    expired_snapshot_attempt(SessionPersistenceMode::Async).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_blocked_snapshot_owner_cannot_hold_leadership() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let store = fleet.store(leader);
        store
            .inner
            .storage_shutdown
            .set_snapshot_limits_for_test(Duration::from_millis(500), Duration::from_secs(1));
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let held = store
            .inner
            .terminal_recovery_handoff_consumer
            .pause_snapshot_verification_for_test(gate.clone());
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), gate.wait_started())
            .await
            .unwrap();
        let owner = store.inner.storage_shutdown.snapshot_owner_for_test();
        assert!(owner.is_retained());
        let command = repeated_command(store);
        seed_to(
            store,
            &command,
            DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
                + DURABLE_OPENRAFT_PROFILE.retained_logs
                + 64,
        )
        .await;
        let window = store.log_pressure_snapshot().retained_rows;
        store
            .inner
            .raft_handler
            .set_log_admission_window_for_test(window);
        let original = store.inner.raft.metrics().borrow().vote;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut waiting = Box::pin(propose(store, &command, deadline));
        assert!(futures_util::poll!(&mut waiting).is_pending());
        let reply = waiting.await;
        assert!(
            matches!(reply, ForwardMutationReply::NotLeader { .. }),
            "snapshot no-progress bound must redirect the waiting proposal: {reply:?}"
        );
        let elected = store
            .inner
            .raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |metrics| {
                    metrics.vote.is_committed()
                        && metrics.vote.leader_id.term > original.leader_id.term
                        && metrics
                            .current_leader
                            .is_some_and(|node| node != store.inner.local_node_id)
                },
                "automatic snapshot-progress handoff",
            )
            .await
            .unwrap();
        let successor = fleet
            .stores
            .iter()
            .flatten()
            .find(|candidate| Some(candidate.inner.local_node_id) == elected.current_leader)
            .unwrap();
        let reply = propose(successor, &command, deadline).await;
        assert!(
            matches!(reply, ForwardMutationReply::Applied(ref response)
            if response.result.is_ok()),
            "new leader commits while the old worker remains held: {reply:?}"
        );
        assert!(store
            .inner
            .terminal_recovery_handoff_consumer
            .snapshot_worker_is_active_for_test());
        assert!(
            owner.is_retained(),
            "expiry cannot retire the actual held snapshot owner"
        );
        assert!(
            owner.is_same_owner(&store.inner.storage_shutdown.snapshot_owner_for_test()),
            "no replacement snapshot worker starts while the original worker holds the gate"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().snapshot,
            None,
            "the cancelled generation must not publish its old cut"
        );
        assert!(store.inner.storage_shutdown.snapshot_retries_for_test() >= 1);
        // Only cleanup releases the noncancellable worker. Its late result may
        // retire its resources, but cannot publish. The queued retry must take
        // a new cut and reclaim this node's retained log as a follower.
        let through = successor
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .unwrap();
        store
            .inner
            .raft
            .wait(Some(Duration::from_secs(10)))
            .applied_index_at_least(Some(through.index), "held owner does not block replication")
            .await
            .unwrap();
        drop(held);
        store
            .inner
            .raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |metrics| {
                    metrics
                        .snapshot
                        .is_some_and(|cut| cut.index >= through.index)
                        && metrics
                            .last_log_index
                            .map_or(0, |index| index + 1)
                            .saturating_sub(metrics.purged.map_or(0, |cut| cut.index + 1))
                            < window
                },
                "automatic fresh snapshot and purge after old owner retirement",
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "{error:?}; retries={}; phase={}; held_owner_retained={}; same_owner={}",
                    store.inner.storage_shutdown.snapshot_retries_for_test(),
                    {
                        #[cfg(feature = "test-control")]
                        {
                            store.inner.backend.snapshot_observation().phase_for_test()
                        }
                        #[cfg(not(feature = "test-control"))]
                        {
                            "not instrumented"
                        }
                    },
                    owner.is_retained(),
                    owner.is_same_owner(&store.inner.storage_shutdown.snapshot_owner_for_test())
                )
            });
        assert!(
            !owner.is_retained(),
            "the released cancelled worker must actually retire"
        );
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_definite_engine_rejection_releases_live_capacity() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result =
        AssertUnwindSafe(async {
            let follower = (fleet.leader() + 1) % 3;
            let store = fleet.store(follower);
            let before = store.log_pressure_snapshot();
            store
                .inner
                .raft_handler
                .set_log_admission_window_for_test(before.retained_rows + 1);
            let command = repeated_command(store);
            for _ in 0..3 {
                let reply = propose(store, &command, tokio::time::Instant::now() + WAIT).await;
                assert!(
                    matches!(reply, ForwardMutationReply::NotLeader { .. }),
                    "actual engine rejection: {reply:?}"
                );
                assert_eq!(store.log_pressure_snapshot().pending_entries, 0,
                "a definite non-append rejection cannot wait for an unrelated metrics publication");
                assert!(store.inner.raft_handler.log_admission.has_capacity());
            }
        })
        .catch_unwind()
        .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

struct ReleaseAcceptedReply(Arc<AcceptedClientWriteReceiverHoldForTest>);

impl Drop for ReleaseAcceptedReply {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}

async fn cancelled_proposal(mode: SessionPersistenceMode) {
    let mut fleet = fleet(mode).await;
    let result = AssertUnwindSafe(async {
        let store = fleet.store(fleet.leader());
        let before = store.log_pressure_snapshot().retained_rows;
        let last = store.inner.raft.metrics().borrow().last_log_index.unwrap();
        store
            .inner
            .raft_handler
            .set_log_admission_window_for_test(before + 2);
        let command = repeated_command(store);
        let hold =
            ReleaseAcceptedReply(Arc::new(AcceptedClientWriteReceiverHoldForTest::default()));
        store.inject_accepted_client_write_receiver_outcome(
            AcceptedClientWriteReceiverTestOutcome::HoldUntilReleased(hold.0.clone()),
        );
        let pending = {
            let store = store.clone();
            let command = command.clone();
            tokio::spawn(async move {
                propose(&store, &command, tokio::time::Instant::now() + WAIT).await
            })
        };
        tokio::time::timeout(WAIT, hold.0.entered.notified())
            .await
            .unwrap();
        store
            .inner
            .raft
            .wait(Some(WAIT))
            .applied_index_at_least(Some(last + 1), "accepted command applied")
            .await
            .unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert_eq!(store.log_pressure_snapshot().pending_entries, 1);
        assert_eq!(
            propose(
                store,
                &command,
                tokio::time::Instant::now() + Duration::from_millis(40)
            )
            .await,
            ForwardMutationReply::Unavailable
        );
        assert_eq!(
            store.log_pressure_snapshot().pending_entries,
            1,
            "caller cancellation cannot recycle the completion owner's growth credit"
        );
        drop(hold);
        store
            .inner
            .raft_handler
            .log_admission
            .ready_before(tokio::time::Instant::now() + WAIT)
            .await
            .unwrap();
        assert_eq!(store.log_pressure_snapshot().pending_entries, 0);
        let reply = propose(store, &command, tokio::time::Instant::now() + WAIT).await;
        assert!(
            matches!(&reply, ForwardMutationReply::Applied(response) if response.result.is_ok()),
            "released completion restores capacity: {reply:?}"
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_cancelled_proposal_keeps_growth_durable() {
    cancelled_proposal(SessionPersistenceMode::Durable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_cancelled_proposal_keeps_growth_async() {
    cancelled_proposal(SessionPersistenceMode::Async).await;
}

struct ReleaseIo(Vec<Arc<SnapshotArtifactGate>>);

impl Drop for ReleaseIo {
    fn drop(&mut self) {
        for gate in &self.0 {
            gate.release();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_cancelled_follower_append_owns_real_flush_and_authority() {
    use crate::sqlite::consensus::wal::{owner::IoHookForTest, Point};
    use opc_consensus::engine::{Entry, EntryPayload, LogId};

    let mut fleet = Fleet::new(3);
    let release = ReleaseIo(
        (0..3)
            .map(|_| Arc::new(SnapshotArtifactGate::new()))
            .collect(),
    );
    let result = AssertUnwindSafe(async {
        for index in 0..3 {
            let gate = release.0[index].clone();
            let hook: IoHookForTest = Arc::new(move |point| {
                if point == Point::BeforeCutPublish {
                    gate.block_if_armed_blocking();
                }
                Ok(())
            });
            fleet.open_with_all_hooks(index, SessionPersistenceMode::Durable, None, None, Some(hook))
                .await.unwrap();
        }
        fleet.form().await;
        let leader = fleet.leader();
        let follower = (leader + 1) % 3;
        let source = fleet.store(leader);
        let store = fleet.store(follower);
        store.inner.raft.runtime_config().elect(false);
        let previous = source.inner.raft.metrics().borrow().last_applied.unwrap();
        store.inner.raft.wait(Some(WAIT))
            .applied_index_at_least(Some(previous.index), "initial follower application").await.unwrap();
        fleet.set_link(leader, follower, false);
        let before = store.log_pressure_snapshot();
        store.inner.raft_handler.set_log_admission_window_for_test(before.retained_rows + 1);
        let vote = source.inner.raft.metrics().borrow().vote;
        let request = wire(store, source.inner.local_node_id, SessionPersistenceMode::Durable,
            SessionConsensusRpcFamily::AppendEntries, &AppendEntriesRequest::<SessionRaftTypeConfig> {
                vote,
                prev_log_id: Some(previous),
                leader_commit: Some(previous),
                entries: vec![Entry {
                    log_id: LogId::new(CommittedLeaderId::new(vote.leader_id.term, source.inner.local_node_id), previous.index + 1),
                    payload: EntryPayload::Normal(repeated_command(source)),
                }],
            });
        release.0[follower].arm();
        let pending = {
            let handler = store.inner.raft_handler.clone();
            let sender = source.inner.local_node_id;
            tokio::spawn(async move {
                handler.handle_before(sender, request, tokio::time::Instant::now() + WAIT).await
            })
        };
        tokio::time::timeout(WAIT, release.0[follower].wait_started()).await.unwrap();
        assert_eq!(store.log_pressure_snapshot().pending_entries, 1);
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert_eq!(store.log_pressure_snapshot().pending_entries, 1);
        assert!(!store.inner.raft_handler.log_admission.has_capacity());
        let mut drained = Box::pin(store.inner.peer_directory.begin_membership_apply());
        assert!(futures_util::poll!(&mut drained).is_pending(),
            "cancelled transport still owns its authority guard while the actual append flush is held");
        release.0[follower].release();
        let guard = tokio::time::timeout(WAIT, drained).await.unwrap();
        assert_eq!(store.log_pressure_snapshot().pending_entries, 0);
        assert_eq!(store.inner.raft.metrics().borrow().last_log_index, Some(previous.index + 1));
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
        drop(guard);
    }).catch_unwind().await;
    drop(release);
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[cfg(feature = "test-control")]
async fn blocked_build(
    mode: SessionPersistenceMode,
    window: u64,
    cycles: usize,
    handoff_before_release: bool,
) {
    let mut fleet = fleet(mode).await;
    let result = AssertUnwindSafe(async {
        let command = repeated_command(fleet.store(fleet.leader()));
        for _ in 0..cycles {
            let store = fleet.store(fleet.leader());
            store.inner.raft_handler.set_log_admission_window_for_test(window);
            let gate = Arc::new(SnapshotArtifactGate::new());
            let guard = store.inner.terminal_recovery_handoff_consumer
                .pause_snapshot_publication_for_test(gate.clone());
            gate.arm();
            store.inner.raft.trigger().snapshot().await.unwrap();
            tokio::time::timeout(WAIT, gate.wait_started()).await.unwrap();
            let before = store.inner.raft.metrics().borrow().clone();
            let target = match before.purged {
                Some(purged) => purged.index + window - 8,
                None => window - 9,
            };
            seed_to(store, &command, target).await;
            // The last eight entries go through both SDK admission boundaries.
            for _ in 0..8 {
                let reply = propose(store, &command, tokio::time::Instant::now() + WAIT).await;
                assert!(matches!(&reply, ForwardMutationReply::Applied(response) if response.result.is_ok()), "window fill: {reply:?}; kind={}", recovery_reply_kind(&reply));
            }
            store.inner.raft.wait(Some(WAIT))
                .applied_index_at_least(Some(target + 8), "admitted window applied").await.unwrap();
            assert_eq!(store.log_pressure_snapshot().retained_rows, window);
            let deadline = tokio::time::Instant::now() + Duration::from_millis(40);
            assert_eq!(propose(store, &command, deadline).await, ForwardMutationReply::Unavailable);
            assert_eq!(store.log_pressure_snapshot().retained_rows, window);
            assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
            assert_eq!(store.inner.raft.metrics().borrow().snapshot, before.snapshot);
            assert_eq!(store.inner.proposal_admission.available_permits(), SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS);
            if handoff_before_release {
                let mut metrics = store.inner.raft.metrics();
                let elected = tokio::time::timeout(WAIT, metrics.wait_for(|current| {
                    current.vote.is_committed()
                        && current.vote.leader_id.term > before.vote.leader_id.term
                        && current.current_leader.is_some_and(|node| node != store.inner.local_node_id)
                })).await.expect("held builder must trigger automatic pressure handoff")
                    .unwrap().clone();
                assert_ne!(elected.current_leader, Some(store.inner.local_node_id));
                assert_eq!(store.log_pressure_snapshot().retained_rows, window);
                assert_eq!(elected.snapshot, before.snapshot);
            }
            // Releasing the stalled build is the only intervention. The engine
            // and SDK must select the next snapshot and purge without a manual trigger.
            drop(guard);
            let resumed = std::time::Instant::now();
            let deadline = tokio::time::Instant::now() + WAIT;
            // Pressure may already have transferred the vote while the builder
            // was held. The supported write keeps one fresh identity across
            // that reroute; a local-only proposal cannot recover on a follower.
            let reply = tokio::time::timeout_at(deadline, store.submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::AdvanceLogicalTime,
                None,
                deadline,
            )).await.expect("automatic recovery retains its original deadline");
            assert!(matches!(&reply, Ok(response) if response.result.is_ok()), "automatic recovery: {reply:?}; elapsed={:?}; active={}; snapshot-phase={:?}; pressure: {:?}; metrics: {:?}", resumed.elapsed(), store.inner.persistence_protocol.is_active(), store.inner.backend.snapshot_observation().phase_for_test(), store.log_pressure_snapshot(), store.inner.raft.metrics().borrow());
            assert!(reply.unwrap().raft_log_index > target + 8,
                "recovery must commit a fresh request after the full window");
            let mut metrics = store.inner.raft.metrics();
            tokio::time::timeout(WAIT, async {
                while store.log_pressure_snapshot().retained_rows >= window {
                    metrics.changed().await.unwrap();
                }
            }).await.expect("automatic purge clears live pressure");
            assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
        }
    }).catch_unwind().await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_build_recovers_three_cycles_durable() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    blocked_build(SessionPersistenceMode::Durable, window, 3, false).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_build_recovers_three_cycles_async() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    blocked_build(SessionPersistenceMode::Async, window, 3, false).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_build_recovers_after_pressure_handoff() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    blocked_build(SessionPersistenceMode::Async, window, 1, true).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_cold_recovery_keeps_quarantine_and_commits_at_full_window() {
    let mut fleet = fleet(SessionPersistenceMode::Async).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let store = fleet.store(leader);
        let gate = Arc::new(SnapshotArtifactGate::new());
        let guard = store
            .inner
            .terminal_recovery_handoff_consumer
            .pause_snapshot_publication_for_test(gate.clone());
        gate.arm();
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(WAIT, gate.wait_started())
            .await
            .unwrap();
        let initial = store.inner.raft.metrics().borrow().last_applied.unwrap();
        let command = repeated_command(store);
        let end = initial.index + DURABLE_OPENRAFT_PROFILE.logs_per_snapshot + 64;
        seed_to(store, &command, end).await;
        drop(guard);
        store
            .inner
            .raft
            .wait(Some(WAIT))
            .snapshot(initial, "old build finishes before restart")
            .await
            .unwrap();
        for store in fleet.stores.iter().flatten() {
            store
                .inner
                .raft
                .wait(Some(WAIT))
                .applied_index_at_least(Some(end), "all voters retain the same committed tail")
                .await
                .unwrap();
        }
        majority_protocol::cold(&mut fleet).await;
        assert_eq!(
            fleet
                .store(leader)
                .inner
                .backend
                .snapshot_observation()
                .phase_for_test(),
            "",
            "reopened snapshot worker has not started before live-pressure injection"
        );
        for store in fleet.stores.iter().flatten() {
            wait_for_restored_cold_metrics(store).await;
            let pressure = store.log_pressure_snapshot();
            store
                .inner
                .raft_handler
                .set_log_admission_window_for_test(pressure.retained_rows);
            assert!(!store.inner.persistence_protocol.is_active());
        }
        let cold = fleet.store(leader);
        assert!(
            cold.log_pressure_snapshot().entries_since_snapshot
                >= DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        );
        let before = cold.inner.raft.metrics().borrow().snapshot;
        let mut metrics = cold.inner.raft.metrics();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), async {
                loop {
                    if metrics.borrow_and_update().snapshot != before {
                        break;
                    }
                    metrics.changed().await.unwrap();
                }
            })
            .await
            .is_err(),
            "quarantined state is not autonomously snapshotted by admission maintenance"
        );
        assert_eq!(
            cold.inner.backend.snapshot_observation().phase_for_test(),
            "",
            "quarantine prevents starting a build, including one that has not yet published"
        );
        majority_protocol::recover(&fleet).await;
        assert!(fleet
            .stores
            .iter()
            .flatten()
            .all(|store| store.inner.persistence_protocol.is_active()));
        assert!(fleet.stores.iter().flatten().all(|store| store
            .inner
            .raft
            .metrics()
            .borrow()
            .running_state
            .is_ok()));
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

async fn select_snapshot(store: &ConsensusSessionStore) {
    let applied = store.inner.raft.metrics().borrow().last_applied.unwrap();
    let mut metrics = store.inner.raft.metrics();
    tokio::time::timeout(WAIT, async {
        let mut retry = tokio::time::interval(Duration::from_secs(1));
        loop {
            if metrics
                .borrow_and_update()
                .snapshot
                .is_some_and(|cut| cut.index >= applied.index)
            {
                return;
            }
            tokio::select! {
                result = metrics.changed() => result.unwrap(),
                _ = retry.tick() => store.inner.raft.trigger().snapshot().await.unwrap(),
            }
        }
    })
    .await
    .expect("setup snapshot selected");
}

#[cfg(feature = "test-control")]
async fn blocked_transfer(
    mode: SessionPersistenceMode,
    window: u64,
    cycles: usize,
    slow_reply: bool,
) {
    let mut fleet = fleet(mode).await;
    let result = AssertUnwindSafe(async {
        for _ in 0..cycles {
            let leader = fleet.leader();
            let follower = (leader + 1) % 3;
            let store = fleet.store(leader);
            let follower_store = fleet.store(follower);
            follower_store.inner.raft.runtime_config().elect(false);
            let command = repeated_command(store);
            store.inner.raft_handler.set_log_admission_window_for_test(window);
            // Start from a caught-up voter and a compact live leader window.
            select_snapshot(store).await;
            let mut metrics = store.inner.raft.metrics();
            tokio::time::timeout(WAIT, async {
                while store.log_pressure_snapshot().retained_rows > 2 * DURABLE_OPENRAFT_PROFILE.retained_logs {
                    metrics.changed().await.unwrap();
                }
            }).await.unwrap();
            let last = store.inner.raft.metrics().borrow().last_log_index.unwrap();
            follower_store.inner.raft.wait(Some(WAIT))
                .applied_index_at_least(Some(last), "follower caught up before isolation").await.unwrap();
            fleet.set_link(leader, follower, false);
            let gate = Arc::new(SnapshotArtifactGate::new());
            let hold = store.inner.peer_directory.pause_snapshot_transfer_for_test(
                follower_store.inner.local_node_id, gate.clone(),
            );
            gate.arm();
            seed_to(store, &command, last + DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
                + DURABLE_OPENRAFT_PROFILE.retained_logs + 64).await;
            tokio::time::timeout(WAIT, gate.wait_started()).await.unwrap();
            fleet.set_link(leader, follower, true);
            let held_cut = hold.cut();
            // Select a newer cut whose purge target crosses the actual transfer.
            seed_to(store, &command, held_cut + DURABLE_OPENRAFT_PROFILE.retained_logs + 64).await;
            select_snapshot(store).await;
            let before = store.inner.raft.metrics().borrow().clone();
            assert!(before.snapshot.unwrap().index > held_cut + DURABLE_OPENRAFT_PROFILE.retained_logs);
            assert!(before.purged.is_none_or(|purged| purged.index <= held_cut));
            let target = match before.purged {
                Some(purged) => purged.index + window - 8,
                None => window - 9,
            };
            seed_to(store, &command, target).await;
            for _ in 0..8 {
                let reply = propose(store, &command, tokio::time::Instant::now() + WAIT).await;
                assert!(matches!(&reply, ForwardMutationReply::Applied(response) if response.result.is_ok()),
                    "transfer window fill: {reply:?}");
            }
            store.inner.raft.wait(Some(WAIT))
                .applied_index_at_least(Some(target + 8), "transfer window applied").await.unwrap();
            assert_eq!(store.log_pressure_snapshot().retained_rows, window);
            assert_eq!(store.inner.raft.metrics().borrow().purged, before.purged,
                "the engine retains the prefix pinned by its real snapshot transfer");
            assert_eq!(propose(store, &command, tokio::time::Instant::now() + Duration::from_millis(40)).await,
                ForwardMutationReply::Unavailable);
            assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
            // Keep the real transfer held until automatic pressure recovery
            // changes the leader. The supported write owns this one immutable
            // request across that reroute; no test-triggered snapshot or purge
            // helps reclaim the original voter's prefix.
            let resumed = std::time::Instant::now();
            let deadline = tokio::time::Instant::now() + WAIT;
            let original_vote = store.inner.raft.metrics().borrow().vote;
            let _slow_reply = slow_reply.then(|| SlowAcceptedReply::arm(&fleet));
            // The fill command deliberately replays one receipt. Recovery
            // needs a fresh identity once, then retains it across every route.
            let request_id = SessionConsensusRequestId::new();
            let submitter = store.clone();
            let (write, _) = recovery_test_control::run(
                deadline.into_std(),
                Duration::from_millis(100),
                async move {
                    submitter.submit_request_before(
                        request_id,
                        SessionMutationIntent::AdvanceLogicalTime,
                        None,
                        tokio::time::Instant::now() + WAIT,
                    ).await
                },
            );
            tokio::time::timeout_at(deadline, async {
                let handoff = async {
                    let mut metrics = store.inner.raft.metrics();
                    let elected = metrics.wait_for(|current| {
                        current.vote.is_committed()
                            && current.vote.leader_id.term > original_vote.leader_id.term
                            && current.current_leader.is_some_and(|node| node != store.inner.local_node_id)
                    }).await.unwrap().clone();
                    assert_ne!(elected.current_leader, Some(store.inner.local_node_id),
                        "full-window recovery must actually transfer leadership");
                    eprintln!("log_admission_transfer releasing mode={mode:?} window={window} held_cut={held_cut} target={target} before={before:?}; elected={elected:?}");
                    drop(hold);
                };
                let (reply, ()) = tokio::join!(
                    write,
                    handoff,
                );
                assert!(matches!(&reply, Ok(response) if response.result.is_ok()),
                    "transfer recovery: {reply:?}; voters={:?}",
                    fleet.stores.iter().flatten().map(|store| (
                        store.inner.local_node_id,
                        store.log_pressure_snapshot(),
                        store.inner.raft.metrics().borrow().clone(),
                        store.inner.persistence_protocol.is_active(),
                        store.inner.backend.snapshot_observation().phase_for_test(),
                    )).collect::<Vec<_>>());
                let response = reply.unwrap();
                assert!(response.raft_log_index > target + 8,
                    "the retained request must be committed after filling the window");
                eprintln!("log_admission_transfer committed mode={mode:?} window={window} raft_log_index={} elapsed_millis={} original_voter={:?}",
                    response.raft_log_index, resumed.elapsed().as_millis(),
                    store.inner.raft.metrics().borrow().clone());
                let mut metrics = store.inner.raft.metrics();
                while store.log_pressure_snapshot().retained_rows >= window {
                    metrics.changed().await.unwrap();
                }
            }).await.inspect_err(|error| {
                eprintln!("log_admission_transfer recovery deadline mode={mode:?} window={window} elapsed_millis={} error={error:?}; voters={:?}",
                    resumed.elapsed().as_millis(),
                    fleet.stores.iter().flatten().map(|store| (
                        store.inner.local_node_id,
                        store.log_pressure_snapshot(),
                        store.inner.raft.metrics().borrow().clone(),
                        store.inner.persistence_protocol.is_active(),
                        store.inner.backend.snapshot_observation().phase_for_test(),
                    )).collect::<Vec<_>>());
            }).expect("handoff, committed write and original-voter reclamation share the original recovery deadline");
            assert!(store.log_pressure_snapshot().retained_rows < window);
            assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
            eprintln!("log_admission_transfer mode={mode:?} window={window} resumed_millis={}", resumed.elapsed().as_millis());
        }
    }).catch_unwind().await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_transfer_recovers_three_cycles_durable() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    blocked_transfer(SessionPersistenceMode::Durable, window, 3, false).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_transfer_recovers_three_cycles_async() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    blocked_transfer(SessionPersistenceMode::Async, window, 3, false).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_transfer_recovers_with_slow_reply() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    blocked_transfer(SessionPersistenceMode::Durable, window, 1, true).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_full_window_blocked_build_durable() {
    blocked_build(
        SessionPersistenceMode::Durable,
        crate::consensus::SESSION_CONSENSUS_LOG_HIGH_WATER_ROWS,
        1,
        false,
    )
    .await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_full_window_blocked_build_async() {
    blocked_build(
        SessionPersistenceMode::Async,
        crate::consensus::SESSION_CONSENSUS_LOG_HIGH_WATER_ROWS,
        1,
        false,
    )
    .await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_full_window_blocked_transfer_durable() {
    blocked_transfer(
        SessionPersistenceMode::Durable,
        crate::consensus::SESSION_CONSENSUS_LOG_HIGH_WATER_ROWS,
        1,
        false,
    )
    .await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_full_window_blocked_transfer_async() {
    blocked_transfer(
        SessionPersistenceMode::Async,
        crate::consensus::SESSION_CONSENSUS_LOG_HIGH_WATER_ROWS,
        1,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_expired_directory_scan_retains_snapshot_owner() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let store = fleet.store(fleet.leader());
        select_snapshot(store).await;
        let previous = store.inner.raft.metrics().borrow().snapshot.unwrap();
        let reply = propose(
            store,
            &repeated_command(store),
            tokio::time::Instant::now() + WAIT,
        )
        .await;
        assert!(
            matches!(reply, ForwardMutationReply::Applied(ref response) if response.result.is_ok())
        );
        store
            .inner
            .storage_shutdown
            .set_snapshot_limits_for_test(Duration::from_millis(500), Duration::from_secs(5));
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let held = store
            .inner
            .terminal_recovery_handoff_consumer
            .pause_snapshot_verification_for_test(gate.clone());
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), gate.wait_started())
            .await
            .unwrap();
        let owner = store.inner.storage_shutdown.snapshot_owner_for_test();
        assert!(
            owner.is_retained(),
            "the current-artifact scan owns this attempt"
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            while store.inner.storage_shutdown.snapshot_retries_for_test() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            owner.is_retained(),
            "expiry must retain the real directory-validation worker owner"
        );
        assert!(owner.is_same_owner(&store.inner.storage_shutdown.snapshot_owner_for_test()));
        assert!(store
            .inner
            .terminal_recovery_handoff_consumer
            .snapshot_worker_is_active_for_test());
        assert_eq!(store.inner.raft.metrics().borrow().snapshot, Some(previous));
        drop(held);
        store
            .inner
            .raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |metrics| {
                    metrics
                        .snapshot
                        .is_some_and(|cut| cut.index > previous.index)
                },
                "fresh cut after expired directory worker actually retires",
            )
            .await
            .unwrap();
        assert!(!owner.is_retained());
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_shutdown_retains_published_snapshot_completion() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let store = fleet.store(fleet.leader());
        store
            .inner
            .storage_shutdown
            .set_snapshot_limits_for_test(Duration::from_millis(500), Duration::from_secs(5));
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let held = store
            .inner
            .terminal_recovery_handoff_consumer
            .pause_snapshot_completion_for_test(gate.clone());
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), gate.wait_started())
            .await
            .expect("snapshot reaches committed completion");
        let owner = store.inner.storage_shutdown.snapshot_owner_for_test();
        assert!(
            owner.is_retained(),
            "committed completion retains its owner"
        );
        assert!(store.inner.raft.metrics().borrow().snapshot.is_none());
        let shutdown = store.shutdown().await;
        assert!(
            shutdown.is_err(),
            "shutdown must remain pending until committed completion retires: {shutdown:?}"
        );
        assert!(
            owner.is_retained(),
            "stopping snapshot attempts cannot abandon a committed completion owner"
        );
        assert!(owner.is_same_owner(&store.inner.storage_shutdown.snapshot_owner_for_test()));
        assert!(store
            .inner
            .terminal_recovery_handoff_consumer
            .snapshot_worker_is_active_for_test());
        drop(held);
        store.shutdown().await.expect("released completion drains");
        assert!(!owner.is_retained());
        assert!(!store
            .inner
            .terminal_recovery_handoff_consumer
            .snapshot_worker_is_active_for_test());
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
