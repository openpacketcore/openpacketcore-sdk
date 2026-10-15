//! Delayed real publication must not turn functional snapshot checks into
//! measurements of the host's disk or scheduling latency.

use super::*;

async fn reopen_installed_snapshot(
    fleet: &mut Fleet,
) -> (Story, InstallSnapshotRequest<SessionRaftTypeConfig>) {
    let story = prepare(fleet).await;
    let cold = fleet.store(story.follower).clone();
    let sender = fleet.peers[story.leader].node;
    install_base(&cold, sender, &story).await;
    decode_snapshot(
        install_fixture_snapshot(&cold, sender, &story.covering).await,
        "covering snapshot before local export",
    )
    .unwrap();
    // Match the replacement in the cancellation scenario: the completed
    // old install cannot supply authority for this fresh catch-up attempt.
    let replacement = quarantine_snapshot(&cold).await.unwrap();
    assert_ne!(replacement.nonce, story.cut.request.nonce);
    assert_eq!(replacement.attempt, story.cut.request.attempt + 1);
    for sender in 0..3 {
        if sender != story.follower {
            fleet.set_link(sender, story.follower, true);
        }
    }
    initialize_snapshot(&cold).await.unwrap();
    let local = snapshot(&cold).await;
    assert!(local.meta.last_log_id.unwrap().index > story.covering.meta.last_log_id.unwrap().index);
    drain_snapshot(&cold).await.unwrap();
    fleet.close(story.follower).await;
    drop(cold);
    fleet
        .open(story.follower, SessionPersistenceMode::Async)
        .await
        .unwrap();
    assert!(!fleet.store(story.follower).status().admitted);
    (story, local)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_base_install_waits_for_real_publication() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let story = prepare(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        let sender = fleet.peers[story.leader].node;
        let directory = fleet
            .directory
            .path()
            .join(format!("snapshots-{}", story.follower));
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let held =
            FixedInstallSourceCopyGateGuard::for_live_directory(&directory, Arc::clone(&gate));
        let (installed, early) = clock::run(async move {
            let _held = held;
            let install = AssertUnwindSafe(install_base(&cold, sender, &story)).catch_unwind();
            tokio::pin!(install);
            tokio::select! {
                () = gate.wait_started() => {},
                _ = install.as_mut() => panic!("base install escaped copy hold"),
            }
            assert!(!cold.inner.persistence_protocol.is_active());
            tokio::time::advance(OPERATION_BOUND + Duration::from_millis(1)).await;
            let early = futures_util::poll!(install.as_mut());
            gate.release();
            match early {
                std::task::Poll::Ready(result) => (result, true),
                std::task::Poll::Pending => (install.await, false),
            }
        })
        .await;
        assert!(
            installed.is_ok(),
            "functional base install expired before real publication"
        );
        assert!(
            !early,
            "functional base install completed while publication was held"
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_snapshot_reopen_waits_for_real_quorum_cut() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let (story, local) = reopen_installed_snapshot(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        assert!(!cold.status().admitted);
        let hold =
            races::ReplyRelease::cold_cut(&fleet.peers[story.leader], cold.inner.local_node_id);
        let (initialized, early, cut) = clock::run(async move {
            let initialize = initialize_snapshot(&cold);
            tokio::pin!(initialize);
            tokio::select! {
                () = hold.wait_started() => {},
                result = initialize.as_mut() => panic!("rejoin escaped cut hold: {result:?}"),
            }
            let cut = hold.cut();
            assert!(!cold.inner.persistence_protocol.is_active());
            assert!(!cold.status().admitted);
            tokio::time::advance(OPERATION_BOUND + Duration::from_millis(1)).await;
            let early = futures_util::poll!(initialize.as_mut());
            hold.release();
            match early {
                std::task::Poll::Ready(result) => (result, true, cut),
                std::task::Poll::Pending => (initialize.await, false, cut),
            }
        })
        .await;
        assert_eq!(
            initialized,
            Ok(()),
            "functional snapshot rejoin expired before actual quorum cut"
        );
        assert!(
            !early,
            "functional rejoin completed while certification was held"
        );
        assert!(cut.barrier.index > local.meta.last_log_id.unwrap().index);
        assert_ne!(cut.request.nonce, story.cut.request.nonce);
        let repaired = fleet.store(story.follower);
        assert_recorded(repaired, &story.first, &story.first_outcome).await;
        assert_recorded(repaired, &story.second, &story.second_outcome).await;
        assert!(repaired.status().admitted);
        assert!(repaired
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
async fn snapshot_install_deadline_does_not_cancel_accepted_publication() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let story = prepare(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        let sender = fleet.peers[story.leader].node;
        let directory = fleet
            .directory
            .path()
            .join(format!("snapshots-{}", story.follower));
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let held =
            FixedInstallSourceCopyGateGuard::for_live_directory(&directory, Arc::clone(&gate));
        let base = story.base.clone();
        let receiver = cold.clone();
        clock::run(async move {
            let _held = held;
            let started = tokio::time::Instant::now();
            // Exercise the public handler directly, without the functional
            // fixture wrapper. Accepted engine work owns its original guard.
            let install = send_snapshot(&receiver, sender, &base);
            tokio::pin!(install);
            tokio::select! {
                () = gate.wait_started() => {},
                _ = install.as_mut() => panic!("install returned before real source-copy hold"),
            }
            tokio::time::advance(OPERATION_BOUND - Duration::from_millis(1)).await;
            assert!(futures_util::poll!(install.as_mut()).is_pending());
            tokio::time::advance(Duration::from_millis(1)).await;
            assert_eq!(
                install.await.result,
                Err(SessionConsensusPeerError::Timeout)
            );
            assert_eq!(started.elapsed(), OPERATION_BOUND);
            assert_eq!(
                receiver
                    .inner
                    .persistence_protocol
                    .cold_rpc_admission
                    .available_permits(),
                15
            );
            assert!(!receiver.inner.persistence_protocol.is_active());
            assert!(!receiver.status().admitted);
            gate.release();
        })
        .await;
        cold.inner
            .raft
            .wait(Some(Duration::from_secs(3)))
            .applied_index(
                Some(story.base.meta.last_log_id.unwrap().index),
                "accepted install completes after caller expiry",
            )
            .await
            .unwrap();
        assert_eq!(
            cold.inner
                .persistence_protocol
                .cold_rpc_admission
                .available_permits(),
            16
        );
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_reopen_deadline_cannot_admit_a_held_quorum_cut() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let (story, local) = reopen_installed_snapshot(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        let hold =
            races::ReplyRelease::cold_cut(&fleet.peers[story.leader], cold.inner.local_node_id);
        let cut = clock::run(async move {
            let started = tokio::time::Instant::now();
            let initialize = cold.initialize_cluster();
            tokio::pin!(initialize);
            tokio::select! {
                () = hold.wait_started() => {},
                result = initialize.as_mut() => panic!("rejoin escaped cut hold: {result:?}"),
            }
            let cut = hold.cut();
            tokio::time::advance(OPERATION_BOUND - Duration::from_millis(1)).await;
            assert!(futures_util::poll!(initialize.as_mut()).is_pending());
            tokio::time::advance(Duration::from_millis(1)).await;
            assert_eq!(
                initialize.await,
                Err(ConsensusSessionStoreOpenError::RecoveryRequired)
            );
            assert_eq!(started.elapsed(), OPERATION_BOUND);
            assert!(!cold.inner.persistence_protocol.is_active());
            assert!(!cold.status().admitted);
            hold.release();
            cut
        })
        .await;
        assert!(cut.barrier.index > local.meta.last_log_id.unwrap().index);
        assert_ne!(cut.request.nonce, story.cut.request.nonce);
        let cold = fleet.store(story.follower);
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
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
