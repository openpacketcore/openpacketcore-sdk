//! Live log pressure and automatic recovery through actual multi-voter stores.

use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;
#[cfg(feature = "test-control")]
use opc_consensus::DURABLE_OPENRAFT_PROFILE;

const WAIT: Duration = Duration::from_secs(60);

async fn fleet(mode: SessionPersistenceMode) -> Fleet {
    let mut fleet = Fleet::new(3);
    for index in 0..3 {
        fleet.open(index, mode).await.unwrap();
    }
    fleet.form().await;
    fleet
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
    let reservation = store
        .inner
        .proposal_admission
        .reserve_for(ScopeSchedulerKey::INTERNAL, ScopeWorkClass::Normal)
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

#[cfg(feature = "test-control")]
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
            let reply = reply.unwrap();
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
async fn blocked_build(mode: SessionPersistenceMode, window: u64, cycles: usize) {
    let mut fleet = fleet(mode).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let store = fleet.store(leader);
        let command = repeated_command(store);
        store.inner.raft_handler.set_log_admission_window_for_test(window);
        for _ in 0..cycles {
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
                assert!(matches!(&reply, ForwardMutationReply::Applied(response) if response.result.is_ok()), "window fill: {reply:?}");
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
            // Releasing the stalled build is the only intervention. The engine
            // and SDK must select the next snapshot and purge without a manual trigger.
            drop(guard);
            let reply = propose(store, &command, tokio::time::Instant::now() + WAIT).await;
            assert!(matches!(&reply, ForwardMutationReply::Applied(response) if response.result.is_ok()), "automatic recovery: {reply:?}; pressure: {:?}; metrics: {:?}", store.log_pressure_snapshot(), store.inner.raft.metrics().borrow());
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
    blocked_build(SessionPersistenceMode::Durable, window, 3).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_build_recovers_three_cycles_async() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    blocked_build(SessionPersistenceMode::Async, window, 3).await;
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

#[cfg(feature = "test-control")]
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
async fn blocked_transfer(mode: SessionPersistenceMode, window: u64, cycles: usize) {
    let mut fleet = fleet(mode).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let follower = (leader + 1) % 3;
        let store = fleet.store(leader);
        let follower_store = fleet.store(follower);
        follower_store.inner.raft.runtime_config().elect(false);
        let command = repeated_command(store);
        store.inner.raft_handler.set_log_admission_window_for_test(window);
        for _ in 0..cycles {
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
            // Resume the same transfer. No further snapshot or purge is triggered
            // by the test, and the leader must clear backpressure on its own.
            let resumed = std::time::Instant::now();
            drop(hold);
            let reply = propose(store, &command, tokio::time::Instant::now() + WAIT).await;
            assert!(matches!(&reply, ForwardMutationReply::Applied(response) if response.result.is_ok()),
                "transfer recovery: {reply:?}; pressure: {:?}", store.log_pressure_snapshot());
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
    blocked_transfer(SessionPersistenceMode::Durable, window, 3).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_transfer_recovers_three_cycles_async() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    blocked_transfer(SessionPersistenceMode::Async, window, 3).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_full_window_blocked_build_durable() {
    blocked_build(
        SessionPersistenceMode::Durable,
        crate::consensus::SESSION_CONSENSUS_LOG_HIGH_WATER_ROWS,
        1,
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
    )
    .await;
}
