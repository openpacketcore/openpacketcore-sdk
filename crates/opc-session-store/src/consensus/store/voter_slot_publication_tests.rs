use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;
use crate::sqlite::consensus::wal::Point;
use futures_util::FutureExt;
use opc_consensus::engine::storage::RaftLogStorage;
use std::panic::AssertUnwindSafe;

struct ReleasePublication(Arc<SnapshotArtifactGate>);

impl Drop for ReleasePublication {
    fn drop(&mut self) {
        self.0.release();
    }
}

async fn publication_fleet() -> (Fleet, Arc<SnapshotArtifactGate>) {
    publication_fleet_on_slot(2).await
}

async fn publication_fleet_on_slot(slot: u16) -> (Fleet, Arc<SnapshotArtifactGate>) {
    let publication = Arc::new(SnapshotArtifactGate::new());
    let hook = publication.clone();
    let fleet = Fleet::open_size_with_io_hook(
        3,
        Some((
            slot,
            Arc::new(move |point| {
                if point == Point::AfterCutPublish {
                    hook.block_if_armed_blocking();
                }
                Ok(())
            }),
        )),
    )
    .await;
    (fleet, publication)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_status_waits_for_the_leaders_strict_wal_publication() {
    let (fleet, publication) = publication_fleet_on_slot(1).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = fleet.nodes[0].clone();
        let vote = leader.inner.raft.metrics().borrow().vote;
        let mut log = crate::sqlite::consensus::wal::adapter::WalLogStore::new(Arc::clone(
            leader.inner.private_wal.as_ref().unwrap(),
        ));
        publication.arm();
        // Republish the same vote through the real WAL adapter. Holding an
        // engine log append here would also block its quorum-read command.
        let write = tokio::spawn(async move { log.save_vote(&vote).await });
        tokio::time::timeout(Duration::from_secs(5), publication.wait_started())
            .await
            .expect("the leader must enter the strict publication interval");
        assert_eq!(
            leader
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .native_voter_slot_state()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        // A quorum read can finish while the leader's own durable cut is still
        // unpublished. The public status call must then wait for that cut.
        tokio::time::timeout(
            Duration::from_secs(5),
            leader.inner.raft.ensure_linearizable(),
        )
        .await
        .expect("the quorum read is independent of local publication")
        .unwrap();
        let authority = VoterReplacementAuthorization::new(
            fleet.genesis().cluster_instance,
            BTreeSet::from([SlotId::new(3).unwrap()]),
            "spiffe://example.test/recovery-controller".into(),
            public(&member(21, 1)),
            [19; 32],
            Duration::from_secs(90),
        )
        .unwrap();
        let mut status = tokio::spawn(async move {
            leader
                .voter_replacement_status(
                    &authority,
                    "spiffe://example.test/recovery-controller",
                    SlotId::new(3).unwrap(),
                    opc_consensus::ConsensusRequestId::from_bytes([0xD3; 16]),
                    [0xD3; 32],
                )
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut status)
                .await
                .is_err(),
            "status must wait for the leader's publication instead of returning Unavailable"
        );
        publication.release();
        assert!(tokio::time::timeout(Duration::from_secs(5), status)
            .await
            .expect("publication must wake the pending status read")
            .unwrap()
            .unwrap()
            .is_none());
        tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_status_waits_for_a_survivors_strict_wal_publication() {
    let (mut fleet, publication) = publication_fleet().await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = fleet.nodes[0].clone();
        fleet
            .network
            .handlers
            .write()
            .unwrap()
            .remove(&member(3, 1).identity.node_id());
        fleet.nodes.pop().unwrap().shutdown().await.unwrap();
        tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
        let prepared = leader
            .replace_voter(fleet.verified_request(&fleet.genesis(), 3))
            .await
            .unwrap();
        let retained = prepared.table().replacement.as_ref().unwrap();
        fleet.nodes[1]
            .inner
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(retained.evidence.prepare.index), "survivor Prepare")
            .await
            .unwrap();

        publication.arm();
        let writer = leader.clone();
        let write = tokio::spawn(async move {
            writer
                .inner
                .raft
                .client_write(probe_marker(&writer, 0xD1, 1))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), publication.wait_started())
            .await
            .expect("the follower must enter the strict publication interval");
        assert_eq!(
            fleet.nodes[1]
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .native_voter_slot_state()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        let authority = VoterReplacementAuthorization::new(
            fleet.genesis().cluster_instance,
            BTreeSet::from([SlotId::new(3).unwrap()]),
            "spiffe://example.test/recovery-controller".into(),
            public(&member(21, 1)),
            [19; 32],
            Duration::from_secs(90),
        )
        .unwrap();
        fleet
            .network
            .observe_empty_append_to
            .store(member(2, 1).identity.node_id().get(), Ordering::SeqCst);
        let request_id = retained.attestation.request_id;
        let request_digest = retained.attestation.request_digest;
        let mut status = tokio::spawn(async move {
            leader
                .voter_replacement_status(
                    &authority,
                    "spiffe://example.test/recovery-controller",
                    SlotId::new(3).unwrap(),
                    request_id,
                    request_digest,
                )
                .await
        });
        tokio::time::timeout(
            Duration::from_secs(5),
            fleet.network.empty_append_started.notified(),
        )
        .await
        .expect("a read probe must reach the follower while publication is held");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut status)
                .await
                .is_err(),
            "the read must wait for publication instead of reporting no surviving quorum"
        );
        publication.release();
        let observed = tokio::time::timeout(Duration::from_secs(5), status)
            .await
            .expect("publication must wake the pending read")
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            observed.table().replacement.as_ref().unwrap().attestation,
            retained.attestation
        );
        tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_publication_wait_honors_deadline_and_storage_failure() {
    let (fleet, publication) = publication_fleet().await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        publication.arm();
        let leader = fleet.nodes[0].clone();
        let write = tokio::spawn(async move {
            leader
                .inner
                .raft
                .client_write(probe_marker(&leader, 0xD2, 1))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), publication.wait_started())
            .await
            .unwrap();
        let wal = fleet.nodes[1].inner.private_wal.as_ref().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            wal.with_durable_voter_slots_until(deadline, |native| native.voter_slot_state()),
        )
        .await
        .expect("waiting for publication must respect the original deadline")
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(tokio::time::Instant::now() >= deadline);
        assert_eq!(
            wal.native_voter_slot_state().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "deadline expiry must not expose unpublished voter state"
        );

        let waiting = wal.with_durable_voter_slots_until(
            tokio::time::Instant::now() + Duration::from_secs(5),
            |native| native.voter_slot_state(),
        );
        tokio::pin!(waiting);
        assert!(waiting.as_mut().now_or_never().is_none());
        wal.fence_for_test().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("a storage failure must wake the already pending read")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        publication.release();
        // The two other voters still form a quorum despite the injected fault.
        tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .catch_unwind()
    .await;
    fleet.network.handlers.write().unwrap().clear();
    for (index, node) in fleet.nodes.into_iter().enumerate() {
        let closed = node.shutdown().await;
        if index != 1 {
            closed.unwrap();
        }
        // The deliberately fenced follower may report its injected failure.
    }
    result.unwrap();
}

async fn hold_vote_publication(
    store: &ConsensusSessionStore,
    publication: &SnapshotArtifactGate,
) -> tokio::task::JoinHandle<Result<(), opc_consensus::engine::StorageError<SessionConsensusNodeId>>>
{
    let vote = store.inner.raft.metrics().borrow().vote;
    let mut log = crate::sqlite::consensus::wal::adapter::WalLogStore::new(
        store.inner.private_wal.as_ref().unwrap().clone(),
    );
    publication.arm();
    let write = tokio::spawn(async move { log.save_vote(&vote).await });
    tokio::time::timeout(Duration::from_secs(5), publication.wait_started())
        .await
        .unwrap();
    assert_eq!(
        store
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .native_voter_slot_state()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock,
    );
    write
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_state_and_replacement_wait_for_strict_publication() {
    let (fleet, publication) = publication_fleet_on_slot(1).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = &fleet.nodes[0];
        let write = hold_vote_publication(leader, &publication).await;
        let state = leader.voter_slot_state();
        let replacement = leader.replace_voter(fleet.verified_request(&fleet.genesis(), 3));
        tokio::pin!(state, replacement);
        assert!(
            state.as_mut().now_or_never().is_none(),
            "state must wait for strict publication"
        );
        assert!(
            replacement.as_mut().now_or_never().is_none(),
            "replacement must wait before deciding intent absence"
        );
        publication.release();
        assert_eq!(state.await.unwrap().table(), &fleet.genesis());
        assert_eq!(
            replacement.await,
            Err(VoterReplacementError::TargetStillLive)
        );
        write.await.unwrap().unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_control_replies_wait_for_strict_publication() {
    use super::super::voter_slots::{ControlReply, ControlRequest};
    let (fleet, publication) = publication_fleet_on_slot(1).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = &fleet.nodes[0];
        let profile = leader.inner.voter_profile.as_ref().unwrap();
        let write = hold_vote_publication(leader, &publication).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let marker = VoterSlotLogId { term: 1, index: 1 };
        let snapshot = profile.control(
            leader,
            ControlRequest::SnapshotInstalled {
                request_digest: [1; 32],
                evidence: VoterSnapshotEvidence {
                    cut: marker,
                    snapshot_id: "unselected".into(),
                    digest: [2; 32],
                },
            },
            deadline,
        );
        let applied = profile.control(
            leader,
            ControlRequest::AppliedMarker {
                request_digest: [1; 32],
                marker,
            },
            deadline,
        );
        tokio::pin!(snapshot, applied);
        assert!(
            snapshot.as_mut().now_or_never().is_none(),
            "snapshot proof must wait before evaluating its state"
        );
        assert!(
            applied.as_mut().now_or_never().is_none(),
            "marker proof must wait before evaluating its state"
        );
        publication.release();
        // Invalid evidence is still refused, but only after reading a complete
        // publication. A transient interval is not a storage failure.
        for reply in [snapshot.await, applied.await] {
            assert!(
                matches!(reply, Err(VoterReplacementError::InvalidTransition)),
                "{reply:?}"
            );
            assert!(!matches!(
                reply,
                Ok(ControlReply::SnapshotInstalled(_) | ControlReply::AppliedMarker(_))
            ));
        }
        write.await.unwrap().unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_leader_preflight_waits_for_strict_publication() {
    let (fleet, publication) = publication_fleet_on_slot(1).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = &fleet.nodes[0];
        let admission = leader
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .clone();
        let request = fleet
            .verified_request(&fleet.genesis(), 3)
            .request()
            .clone();
        let write = hold_vote_publication(leader, &publication).await;
        let (entered, mut probe) = tokio::sync::oneshot::channel();
        let call = admission.run_leader_intent(
            request,
            tokio::time::Instant::now() + Duration::from_secs(5),
            move || async move {
                entered.send(()).unwrap();
                Err(VoterReplacementError::TargetStillLive)
            },
            || async { panic!("a refused preflight cannot dispatch") },
        );
        tokio::pin!(call);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut call)
                .await
                .is_err(),
            "leader admission must wait before probing liveness"
        );
        assert!(matches!(
            probe.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        publication.release();
        assert_eq!(
            call.await,
            Err::<(), _>(VoterReplacementError::TargetStillLive)
        );
        probe.await.unwrap();
        write.await.unwrap().unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_snapshot_admission_waits_for_strict_publication() {
    let (fleet, publication) = publication_fleet_on_slot(1).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = &fleet.nodes[0];
        let admission = leader
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .clone();
        let write = hold_vote_publication(leader, &publication).await;
        let table = fleet.genesis();
        let members = table
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect();
        let call = admission.run_snapshot(
            table,
            members,
            tokio::time::Instant::now() + Duration::from_secs(5),
            || async { Ok(()) },
        );
        tokio::pin!(call);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut call)
                .await
                .is_err(),
            "snapshot admission must wait for strict publication"
        );
        publication.release();
        call.await.unwrap();
        write.await.unwrap().unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_intent_recheck_waits_for_strict_publication_after_liveness() {
    let (mut fleet, publication) = publication_fleet_on_slot(1).await;
    let old = fleet.nodes.pop().unwrap();
    fleet.network.disconnect_and_shutdown(&old).await;
    drop(old);
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = fleet.nodes[0].clone();
        let admission = leader
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .clone();
        let request = fleet
            .verified_request(&fleet.genesis(), 3)
            .request()
            .clone();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let held = publication.clone();
        let call = admission.run_leader_intent(
            request,
            tokio::time::Instant::now() + Duration::from_secs(5),
            move || async move {
                let write = hold_vote_publication(&leader, &held).await;
                entered.send(write).unwrap();
                Ok(())
            },
            || async { Ok(()) },
        );
        tokio::pin!(call);
        let write = tokio::select! {
            result = &mut call => panic!("intent completed before liveness: {result:?}"),
            write = ready => write.unwrap(),
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut call)
                .await
                .is_err(),
            "the second intent read must wait within the same request budget"
        );
        publication.release();
        call.await.unwrap();
        write.await.unwrap().unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_snapshot_completion_waits_for_strict_publication_after_dispatch() {
    let (fleet, publication) = publication_fleet_on_slot(1).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = fleet.nodes[0].clone();
        let admission = leader
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .clone();
        let table = fleet.genesis();
        let members = table
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let held = publication.clone();
        let task_admission = admission.clone();
        let mut call = tokio::spawn(async move {
            task_admission
                .run_snapshot(
                    table,
                    members,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                    move || async move {
                        let write = hold_vote_publication(&leader, &held).await;
                        entered.send(write).unwrap();
                        Ok(())
                    },
                )
                .await
        });
        let write = ready.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut call)
                .await
                .is_err(),
            "completion must reconcile a strict publication after dispatch"
        );
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        assert!(
            !write.is_finished(),
            "caller cancellation cannot cancel accepted WAL work"
        );
        publication.release();
        write.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(5), admission.reconcile())
            .await
            .unwrap()
            .unwrap();
        assert!(admission.local_voting_admitted());
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_control_publication_preserves_original_deadline_and_failure() {
    use super::super::voter_slots::ControlRequest;
    let (fleet, publication) = publication_fleet_on_slot(2).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let node = &fleet.nodes[1];
        let profile = node.inner.voter_profile.as_ref().unwrap();
        let write = hold_vote_publication(node, &publication).await;
        let marker = || ControlRequest::AppliedMarker {
            request_digest: [1; 32],
            marker: VoterSlotLogId { term: 1, index: 1 },
        };
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            profile.control(node, marker(), deadline),
        )
        .await
        .unwrap();
        assert!(
            matches!(result, Err(VoterReplacementError::Deadline)),
            "{result:?}"
        );
        assert!(tokio::time::Instant::now() >= deadline);
        let waiting = profile.control(
            node,
            marker(),
            tokio::time::Instant::now() + Duration::from_secs(5),
        );
        tokio::pin!(waiting);
        assert!(waiting.as_mut().now_or_never().is_none());
        node.inner
            .private_wal
            .as_ref()
            .unwrap()
            .fence_for_test()
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap();
        assert!(
            matches!(result, Err(VoterReplacementError::Unavailable)),
            "{result:?}"
        );
        publication.release();
        assert!(
            write.await.unwrap().is_err(),
            "the fenced writer cannot acknowledge the held vote"
        );
    })
    .catch_unwind()
    .await;
    fleet.network.handlers.write().unwrap().clear();
    for (index, node) in fleet.nodes.into_iter().enumerate() {
        let closed = node.shutdown().await;
        if index != 1 {
            closed.unwrap();
        }
    }
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_candidate_ack_waits_for_strict_publication_without_the_coordinator_lock() {
    let (fleet, publication) = publication_fleet_on_slot(2).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let target = fleet.nodes[1].clone();
        let profile = target.inner.voter_profile.as_ref().unwrap().clone();
        let mut incoming = fleet.genesis();
        incoming
            .apply_control(
                &VoterSlotControl::Begin(Box::new(
                    fleet
                        .verified_request(&fleet.genesis(), 2)
                        .request()
                        .clone(),
                )),
                VoterSlotLogId {
                    term: 10,
                    index: 100,
                },
            )
            .unwrap();
        let members = fleet
            .genesis()
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release_dispatch, dispatched) = tokio::sync::oneshot::channel();
        let held = publication.clone();
        let installer = target.clone();
        let admission = profile.admission.clone();
        let snapshot = tokio::spawn(async move {
            admission
                .run_snapshot(
                    incoming,
                    members,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                    move || async move {
                        // The verified snapshot barrier closes local admission while
                        // the engine still lists this identity. Keep its coordinator
                        // lock held so the acknowledgement must use publication only.
                        assert!(!installer
                            .inner
                            .voter_profile
                            .as_ref()
                            .unwrap()
                            .admission
                            .local_voting_admitted());
                        let write = hold_vote_publication(&installer, &held).await;
                        entered.send(write).unwrap();
                        let _ = dispatched.await;
                        Ok(())
                    },
                )
                .await
        });
        let write = ready.await.unwrap();
        let ack = profile.wait_candidate_ack(
            &target.inner.raft,
            target.inner.local_node_id,
            tokio::time::Instant::now() + Duration::from_secs(5),
        );
        tokio::pin!(ack);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut ack)
                .await
                .is_err(),
            "candidate acknowledgement must wait for its durable table"
        );
        publication.release();
        tokio::time::timeout(Duration::from_secs(1), ack)
            .await
            .unwrap()
            .unwrap();
        write.await.unwrap().unwrap();
        assert!(
            !snapshot.is_finished(),
            "acknowledgement cannot require the snapshot coordinator lock"
        );
        release_dispatch.send(()).unwrap();
        snapshot.await.unwrap().unwrap();
        assert!(profile.admission.local_voting_admitted());
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}
