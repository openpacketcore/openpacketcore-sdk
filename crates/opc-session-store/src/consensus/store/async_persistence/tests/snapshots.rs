//! Actual compacted-prefix installation and cancellation through ordinary
//! Async stores. Each public operation keeps its 800 ms bound; snapshot
//! construction and controlled recovery stages have separate fixture bounds.

use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;
use crate::consensus::storage::{
    FixedInstallSourceCopyGateGuard, SnapshotInstallAppliedProgressGateGuard,
};
use opc_consensus::engine::error::{Fatal, InstallSnapshotError};
use opc_consensus::engine::raft::{InstallSnapshotRequest, InstallSnapshotResponse};
use opc_consensus::engine::StoredMembership;

struct Story {
    leader: usize,
    follower: usize,
    first: FencedTransitionV2Request,
    first_outcome: FencedTransitionOutcome,
    second: FencedTransitionV2Request,
    second_outcome: FencedTransitionOutcome,
    base: InstallSnapshotRequest<SessionRaftTypeConfig>,
    covering: InstallSnapshotRequest<SessionRaftTypeConfig>,
    cut: ColdQuorumCut,
}

async fn snapshot(store: &ConsensusSessionStore) -> InstallSnapshotRequest<SessionRaftTypeConfig> {
    let applied = store.inner.raft.metrics().borrow().last_applied.unwrap();
    store.inner.raft.trigger().snapshot().await.unwrap();
    store
        .inner
        .raft
        .wait(Some(Duration::from_secs(5)))
        .snapshot(applied, "ordinary snapshot publication")
        .await
        .unwrap();
    let snapshot = store.inner.raft.get_snapshot().await.unwrap().unwrap();
    assert!(snapshot
        .meta
        .last_log_id
        .is_some_and(|last| last.index >= applied.index));
    let data = tokio::fs::read(snapshot.snapshot.path()).await.unwrap();
    assert!(
        data.len() < SessionConsensusRpcFamily::InstallSnapshot.max_request_payload_bytes() / 2
    );
    InstallSnapshotRequest {
        vote: store.inner.raft.metrics().borrow().vote,
        meta: snapshot.meta,
        offset: 0,
        data,
        done: true,
    }
}

async fn send_snapshot(
    cold: &ConsensusSessionStore,
    sender: SessionConsensusNodeId,
    request: &InstallSnapshotRequest<SessionRaftTypeConfig>,
) -> SessionConsensusWireResponse {
    let response = cold
        .rpc_handler()
        .handle(
            sender,
            wire(
                cold,
                sender,
                SessionPersistenceMode::Async,
                SessionConsensusRpcFamily::InstallSnapshot,
                request,
            ),
        )
        .await;
    if response.result.is_err() {
        eprintln!(
            "async snapshot response: index={:?} result={:?} health={:?} engine={:?}",
            request.meta.last_log_id,
            response.result.as_ref().err(),
            cold.persistence_health(),
            cold.inner.raft.metrics().borrow().running_state
        );
    }
    response
}

fn decode_snapshot(
    response: SessionConsensusWireResponse,
    stage: &str,
) -> Result<
    InstallSnapshotResponse<SessionConsensusNodeId>,
    Box<RaftError<SessionConsensusNodeId, InstallSnapshotError>>,
> {
    let payload = response
        .result
        .unwrap_or_else(|error| panic!("{stage}: {error:?}"));
    decode_bounded::<
        Result<
            InstallSnapshotResponse<SessionConsensusNodeId>,
            RaftError<SessionConsensusNodeId, InstallSnapshotError>,
        >,
    >(persistence_protocol::unwrap_payload(SessionPersistenceMode::Async, &payload).unwrap())
    .unwrap()
    .map_err(Box::new)
}

async fn prepare(fleet: &mut Fleet) -> Story {
    fleet.start().await;
    let leader = fleet.leader();
    let follower = (leader + 1) % 3;
    let provider = provider();
    let first = create_request(fleet.store(leader), 1, &provider).await;
    let first_outcome = create(fleet.store(leader), &first).await;
    fleet
        .store(leader)
        .activate_fenced_transition_capability()
        .await
        .unwrap();
    for store in fleet.stores.iter().flatten() {
        assert_recorded(store, &first, &first_outcome).await;
        store.drain_async_persistence().await.unwrap();
    }
    let old_applied = fleet
        .store(follower)
        .inner
        .raft
        .metrics()
        .borrow()
        .last_applied
        .unwrap();
    fleet.close(follower).await;
    let second = create_request(fleet.store(leader), 2, &provider).await;
    let second_outcome = create(fleet.store(leader), &second).await;
    let base = snapshot(fleet.store(leader)).await;
    assert!(base.meta.last_log_id.unwrap().index > old_applied.index);
    // Keep engine replication under explicit control after the cut is accepted.
    // The real cold request still reaches the live leader and its other voter.
    for sender in 0..3 {
        if sender != follower {
            fleet.set_link(sender, follower, false);
        }
    }
    fleet
        .open(follower, SessionPersistenceMode::Async)
        .await
        .unwrap();
    let cold = fleet.store(follower);
    let request = cold
        .inner
        .persistence_protocol
        .quarantine_before(tokio::time::Instant::now() + OPERATION_BOUND)
        .await
        .unwrap();
    let cut = cold
        .call_peer::<_, ColdQuorumCut>(
            fleet.peers[leader].node,
            SessionConsensusRpcFamily::ReadBarrier,
            &request,
            tokio::time::Instant::now() + OPERATION_BOUND,
        )
        .await
        .unwrap();
    assert!(cut.request == request);
    assert_eq!(cut.requester, cold.inner.local_node_id);
    assert!(cut.barrier.index > base.meta.last_log_id.unwrap().index);
    let covering = snapshot(fleet.store(leader)).await;
    assert!(persistence_protocol::covers(
        covering.meta.last_log_id.unwrap(),
        cut.barrier
    ));
    fleet
        .store(leader)
        .inner
        .raft
        .trigger()
        .purge_log(cut.barrier.index)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fleet
                .store(leader)
                .inner
                .raft
                .metrics()
                .borrow()
                .purged
                .is_some_and(|purged| purged.index >= cut.barrier.index)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("actual leader log purge covers the certified barrier");
    cold.inner
        .persistence_protocol
        .accept_cut_before(cut, tokio::time::Instant::now() + OPERATION_BOUND)
        .await
        .unwrap();
    Story {
        leader,
        follower,
        first,
        first_outcome,
        second,
        second_outcome,
        base,
        covering,
        cut,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_cold_repair_rejects_wrong_authority_and_requires_real_append() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let story = prepare(&mut fleet).await;
        let live = fleet.store(story.leader).clone();
        let cold = fleet.store(story.follower).clone();
        let leader = fleet.peers[story.leader].node;
        let before = cold.inner.raft.metrics().borrow().clone();
        let snapshots = live.status().completed_snapshot_count;
        let cut = story.cut;
        for (reason, bad) in [
            (
                "scope",
                ColdQuorumCut {
                    identity: SessionConsensusIdentity::new(
                        cut.identity.cluster_id(),
                        cut.identity.configuration_id(),
                        ConsensusConfigurationEpoch::new(
                            cut.identity.configuration_epoch().get() + 1,
                        )
                        .unwrap(),
                    ),
                    ..cut
                },
            ),
            (
                "requester",
                ColdQuorumCut {
                    requester: leader,
                    ..cut
                },
            ),
            (
                "voters",
                ColdQuorumCut {
                    voters: [0; 32],
                    ..cut
                },
            ),
            (
                "uncommitted vote",
                ColdQuorumCut {
                    vote: Vote::new(cut.vote.leader_id.term, leader),
                    ..cut
                },
            ),
            (
                "other leader",
                ColdQuorumCut {
                    vote: Vote::new_committed(cut.vote.leader_id.term, cold.inner.local_node_id),
                    ..cut
                },
            ),
            (
                "barrier lineage",
                ColdQuorumCut {
                    barrier: LogId::new(
                        CommittedLeaderId::new(cut.vote.leader_id.term + 1, leader),
                        cut.barrier.index,
                    ),
                    ..cut
                },
            ),
            (
                "membership",
                ColdQuorumCut {
                    membership: Some(cut.barrier),
                    ..cut
                },
            ),
            (
                "unapplied barrier",
                ColdQuorumCut {
                    barrier: LogId::new(cut.barrier.leader_id, cut.barrier.index + 1_000),
                    ..cut
                },
            ),
        ] {
            let response = cold
                .call_peer::<_, ()>(
                    leader,
                    SessionConsensusRpcFamily::ReadBarrier,
                    &persistence_protocol::ColdRepairRequest::new(bad),
                    tokio::time::Instant::now() + OPERATION_BOUND,
                )
                .await;
            assert!(
                matches!(
                    response,
                    Err(ConsensusPeerCallFailure::AuthenticatedRejection(
                        SessionConsensusPeerError::Rejected
                    ))
                ),
                "invalid repair {reason}: {response:?}"
            );
            assert_eq!(live.status().completed_snapshot_count, snapshots);
            let metrics = cold.inner.raft.metrics();
            let current = metrics.borrow();
            assert_eq!(current.vote, before.vote);
            assert_eq!(current.last_log_index, before.last_log_index);
            assert_eq!(current.last_applied, before.last_applied);
            assert_eq!(current.snapshot, before.snapshot);
        }
        let appends = fleet.peers[story.follower]
            .successful_appends
            .load(Ordering::Acquire);
        *fleet.peers[story.follower]
            .blocked_append_above
            .lock()
            .unwrap() = Some((leader, cut.barrier.index - 1));
        fleet.set_link(story.leader, story.follower, true);
        let repair = persistence_protocol::ColdRepairRequest::new(cut);
        assert!(cold
            .call_peer::<_, ()>(
                leader,
                SessionConsensusRpcFamily::ReadBarrier,
                &repair,
                tokio::time::Instant::now() + OPERATION_BOUND,
            )
            .await
            .is_err());
        assert!(cold
            .inner
            .raft
            .metrics()
            .borrow()
            .snapshot
            .is_some_and(|last| { persistence_protocol::covers(last, cut.barrier) }));
        assert!(cold
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .is_some_and(|last| { persistence_protocol::covers(last, cut.barrier) }));
        assert_eq!(
            fleet.peers[story.follower]
                .successful_appends
                .load(Ordering::Acquire),
            appends
        );
        assert!(!cold
            .activate_caught_up_async_before(tokio::time::Instant::now() + OPERATION_BOUND)
            .await
            .unwrap());
        assert!(!cold.status().admitted);
        assert_eq!(
            cold.probe_fixed_quorum_readiness()
                .await
                .traffic_authority(),
            FixedQuorumTrafficAuthority::RecoveryRequired
        );
        *fleet.peers[story.follower]
            .blocked_append_above
            .lock()
            .unwrap() = None;
        cold.call_peer::<_, ()>(
            leader,
            SessionConsensusRpcFamily::ReadBarrier,
            &repair,
            tokio::time::Instant::now() + OPERATION_BOUND,
        )
        .await
        .unwrap();
        assert!(
            fleet.peers[story.follower]
                .successful_appends
                .load(Ordering::Acquire)
                > appends
        );
        let initialized = tokio::time::Instant::now();
        cold.initialize_cluster().await.unwrap();
        assert!(initialized.elapsed() < OPERATION_BOUND);
        assert_eq!(cold.inner.raft.metrics().borrow().vote, cut.vote);
        assert_eq!(live.inner.raft.metrics().borrow().vote, cut.vote);
        assert_recorded(&cold, &story.first, &story.first_outcome).await;
        assert_recorded(&cold, &story.second, &story.second_outcome).await;
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

async fn install_base(cold: &ConsensusSessionStore, sender: SessionConsensusNodeId, story: &Story) {
    assert_eq!(
        decode_snapshot(
            send_snapshot(cold, sender, &story.base).await,
            "pre-barrier base install"
        )
        .unwrap()
        .vote,
        story.cut.vote
    );
    cold.inner
        .raft
        .wait(Some(Duration::from_secs(3)))
        .applied_index(
            Some(story.base.meta.last_log_id.unwrap().index),
            "older snapshot applied",
        )
        .await
        .unwrap();
    assert!(!cold.inner.persistence_protocol.is_active());
    assert!(!cold
        .activate_caught_up_async_before(tokio::time::Instant::now() + OPERATION_BOUND)
        .await
        .unwrap());
    assert_eq!(
        cold.probe_fixed_quorum_readiness()
            .await
            .traffic_authority(),
        FixedQuorumTrafficAuthority::RecoveryRequired
    );
    // The real install dispatches a separate log purge. Let that legitimate
    // background generation finish before byte-exact rejection assertions.
    cold.drain_async_persistence().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let progress = cold.persistence_health().asynchronous.unwrap();
            if progress.completed_generation == progress.resident_generation
                && progress.captured_generation.is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pre-barrier base and its real purge have completed persistence");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_compacted_snapshot_cancellation_fences_replacement_and_reopens() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let story = prepare(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        let sender = fleet.peers[story.leader].node;
        install_base(&cold, sender, &story).await;
        let selected_base = fleet.selector(story.follower);
        let applied_base = cold.inner.raft.metrics().borrow().last_applied;

        // Metadata alone cannot substitute a different lineage, full vote or
        // membership at the identical certified index.
        for wrong in 0..3 {
            let mut request = story.covering.clone();
            match wrong {
                0 => {
                    request.meta.last_log_id = Some(LogId::new(
                        CommittedLeaderId::new(story.cut.vote.leader_id.term + 1, sender),
                        story.covering.meta.last_log_id.unwrap().index,
                    ))
                }
                1 => request.vote = Vote::new(story.cut.vote.leader_id.term, sender),
                2 => {
                    request.meta.last_membership = StoredMembership::new(
                        Some(LogId::new(
                            CommittedLeaderId::new(story.cut.vote.leader_id.term, sender),
                            story.cut.membership.unwrap().index + 1,
                        )),
                        request.meta.last_membership.membership().clone(),
                    )
                }
                _ => unreachable!(),
            }
            assert_eq!(
                send_snapshot(&cold, sender, &request).await.result,
                Err(SessionConsensusPeerError::Rejected)
            );
            assert_eq!(fleet.selector(story.follower), selected_base);
            assert_eq!(
                cold.inner.raft.metrics().borrow().last_applied,
                applied_base
            );
            assert_eq!(cold.inner.raft.metrics().borrow().vote, story.cut.vote);
        }

        let directory = fleet
            .directory
            .path()
            .join(format!("snapshots-{}", story.follower));
        let before = Arc::new(SnapshotArtifactGate::new());
        let after = Arc::new(SnapshotArtifactGate::new());
        before.arm();
        after.arm();
        let _before =
            FixedInstallSourceCopyGateGuard::for_live_directory(&directory, Arc::clone(&before));
        let _after =
            SnapshotInstallAppliedProgressGateGuard::install(directory, Arc::clone(&after));
        let installing = {
            let cold = cold.clone();
            let request = story.covering.clone();
            tokio::spawn(async move { send_snapshot(&cold, sender, &request).await })
        };
        tokio::time::timeout(Duration::from_secs(3), before.wait_started())
            .await
            .expect("real final installation reaches the pre-publication hold");
        assert_eq!(fleet.selector(story.follower), selected_base);
        assert_eq!(
            cold.inner
                .persistence_protocol
                .cold_rpc_admission
                .available_permits(),
            15
        );
        installing.abort();
        assert!(installing.await.unwrap_err().is_cancelled());
        let new_request = {
            let replacement = cold
                .inner
                .persistence_protocol
                .quarantine_before(tokio::time::Instant::now() + OPERATION_BOUND);
            tokio::pin!(replacement);
            assert!(futures_util::poll!(replacement.as_mut()).is_pending());

            before.release();
            tokio::time::timeout(Duration::from_secs(3), after.wait_started())
                .await
                .expect("cancelled caller leaves actual installation owned through publication");
            assert_eq!(
                cold.inner
                    .private_wal
                    .as_ref()
                    .unwrap()
                    .with_native_read(|native| Ok(native.applied()))
                    .unwrap(),
                story.covering.meta.last_log_id
            );
            assert!(
                futures_util::poll!(replacement.as_mut()).is_pending(),
                "replacement must also drain post-publication engine completion"
            );
            assert!(!cold.inner.persistence_protocol.is_active());
            after.release();
            replacement.await.unwrap()
        };
        assert_ne!(new_request.nonce, story.cut.request.nonce);
        assert_eq!(new_request.incarnation, story.cut.request.incarnation);
        assert_eq!(new_request.attempt, story.cut.request.attempt + 1);
        tokio::time::timeout(Duration::from_secs(1), async {
            while cold
                .inner
                .persistence_protocol
                .cold_rpc_admission
                .available_permits()
                != 16
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!cold.inner.persistence_protocol.is_active());
        assert_eq!(
            cold.inner
                .persistence_protocol
                .accept_cut_before(story.cut, tokio::time::Instant::now() + OPERATION_BOUND)
                .await,
            Err(SessionConsensusPeerError::Rejected)
        );
        assert!(!cold
            .activate_caught_up_async_before(tokio::time::Instant::now() + OPERATION_BOUND)
            .await
            .unwrap());

        for sender in 0..3 {
            if sender != story.follower {
                fleet.set_link(sender, story.follower, true);
            }
        }
        let initialized = tokio::time::Instant::now();
        cold.initialize_cluster().await.unwrap();
        assert!(initialized.elapsed() < OPERATION_BOUND);
        let fresh = fleet.peers[story.leader].last_cut.lock().unwrap().unwrap();
        assert!(fresh.barrier.index > story.cut.barrier.index);
        assert_ne!(fresh.request.nonce, story.cut.request.nonce);
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &story.first, &story.first_outcome).await;
            assert_recorded(store, &story.second, &story.second_outcome).await;
        }
        // A local export must retain the installed source required by native
        // reopening; exercise that ordinary lifecycle and another live cut.
        let local = snapshot(&cold).await;
        assert!(
            local.meta.last_log_id.unwrap().index > story.covering.meta.last_log_id.unwrap().index
        );
        cold.drain_async_persistence().await.unwrap();
        fleet.close(story.follower).await;
        drop(cold);
        fleet
            .open(story.follower, SessionPersistenceMode::Async)
            .await
            .unwrap();
        assert!(!fleet.store(story.follower).status().admitted);
        let reopened = tokio::time::Instant::now();
        fleet
            .store(story.follower)
            .initialize_cluster()
            .await
            .unwrap();
        assert!(reopened.elapsed() < OPERATION_BOUND);
        assert_recorded(
            fleet.store(story.follower),
            &story.first,
            &story.first_outcome,
        )
        .await;
        assert_recorded(
            fleet.store(story.follower),
            &story.second,
            &story.second_outcome,
        )
        .await;
        assert!(fleet
            .store(story.follower)
            .probe_fixed_quorum_readiness()
            .await
            .traffic_authority()
            .is_granted());
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_failed_final_snapshot_keeps_cold_admission_and_selected_prefix() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let story = prepare(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        let sender = fleet.peers[story.leader].node;
        install_base(&cold, sender, &story).await;
        let selected = fleet.selector(story.follower);
        let applied = cold
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .with_native_read(|native| Ok(native.applied()))
            .unwrap();
        let mut corrupted = story.covering.clone();
        let middle = corrupted.data.len() / 2;
        corrupted.data[middle] ^= 0x40;
        let started = tokio::time::Instant::now();
        let error = decode_snapshot(
            send_snapshot(&cold, sender, &corrupted).await,
            "corrupted final install",
        )
        .expect_err("the real completed snapshot stream must reject its corrupted database");
        assert!(started.elapsed() < OPERATION_BOUND);
        let RaftError::Fatal(fatal @ Fatal::StorageError(_)) = *error else {
            panic!("corrupted install must retain its actual storage error: {error:?}");
        };
        assert!(fatal.to_string().contains("checksum"), "{fatal}");
        assert_eq!(cold.inner.raft.metrics().borrow().running_state, Err(fatal));
        assert!(!cold.persistence_health().engine_running);
        tokio::time::timeout(OPERATION_BOUND, async {
            while cold
                .inner
                .persistence_protocol
                .cold_rpc_admission
                .available_permits()
                != 16
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed snapshot's real engine work and admission guard drain");
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
        assert_eq!(fleet.selector(story.follower), selected);
        assert_eq!(
            cold.inner
                .private_wal
                .as_ref()
                .unwrap()
                .with_native_read(|native| Ok(native.applied()))
                .unwrap(),
            applied
        );
        assert!(!cold
            .activate_caught_up_async_before(tokio::time::Instant::now() + OPERATION_BOUND)
            .await
            .unwrap());
        assert_eq!(
            cold.probe_fixed_quorum_readiness()
                .await
                .traffic_authority(),
            FixedQuorumTrafficAuthority::RecoveryRequired
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
