//! Functional snapshot steps wait for the real work despite caller-clock delay.

use super::*;

struct ReleaseGate(Arc<SnapshotArtifactGate>);

impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_corrupted_install_waits_for_storage_error() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let story = prepare(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        let sender = fleet.peers[story.leader].node;
        install_base(&cold, sender, &story).await;
        let selected = fleet.selector(story.follower);
        let applied = cold.inner.raft.metrics().borrow().last_applied;
        let mut corrupted = story.covering.clone();
        let middle = corrupted.data.len() / 2;
        corrupted.data[middle] ^= 0x40;
        let directory = fleet
            .directory
            .path()
            .join(format!("snapshots-{}", story.follower));
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let held =
            FixedInstallSourceCopyGateGuard::for_live_directory(&directory, Arc::clone(&gate));
        let release = ReleaseGate(Arc::clone(&gate));
        let receiver = cold.clone();
        let (installed, early) = clock::run(async move {
            let _held = held;
            let _release = release;
            let install =
                AssertUnwindSafe(install_corrupted_snapshot(&receiver, sender, &corrupted))
                    .catch_unwind();
            tokio::pin!(install);
            tokio::select! {
                () = gate.wait_started() => {},
                _ = install.as_mut() => panic!("corrupt install escaped the copy hold"),
            }
            assert!(!receiver.inner.persistence_protocol.is_active());
            tokio::time::advance(OPERATION_BOUND + Duration::from_millis(1)).await;
            let early = futures_util::poll!(install.as_mut());
            gate.release();
            match early {
                std::task::Poll::Ready(result) => (result, true),
                std::task::Poll::Pending => (install.await, false),
            }
        })
        .await;
        assert!(installed.is_ok(), "functional corrupted install expired");
        assert!(!early, "corrupted install completed while copy was held");
        let error = installed.unwrap();
        let RaftError::Fatal(fatal @ Fatal::StorageError(_)) = *error else {
            panic!("corrupted install lost its storage error: {error:?}");
        };
        assert!(fatal.to_string().contains("checksum"), "{fatal}");
        assert_eq!(cold.inner.raft.metrics().borrow().running_state, Err(fatal));
        assert_eq!(fleet.selector(story.follower), selected);
        assert_eq!(cold.inner.raft.metrics().borrow().last_applied, applied);
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_snapshot_drain_waits_for_real_publication() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let gate = Arc::new(SnapshotArtifactGate::new());
    let release = ReleaseGate(Arc::clone(&gate));
    let result = AssertUnwindSafe(async {
        let writer_gate = Arc::clone(&gate);
        fleet
            .open_with_hook(
                0,
                SessionPersistenceMode::Async,
                Some(Arc::new(move || {
                    writer_gate.block_if_armed_blocking();
                    Ok(())
                })),
            )
            .await
            .unwrap();
        for index in [1, 2] {
            fleet
                .open(index, SessionPersistenceMode::Async)
                .await
                .unwrap();
        }
        fleet.form().await;
        let store = fleet.store(0).clone();
        drain_snapshot(&store).await.unwrap();
        gate.arm();
        let leader = fleet.store(fleet.leader());
        let request = create_request(leader, 1702, &provider()).await;
        let outcome = create(leader, &request).await;
        assert_recorded(&store, &request, &outcome).await;
        let wal = Arc::clone(store.inner.private_wal.as_ref().unwrap());
        let cut = wal.request_async_persistence().unwrap();
        clock::watchdog(gate.wait_started(), "real writer reaches the drain hold").await;
        let (drained, early) = clock::run(async move {
            let drain = drain_snapshot(&store);
            tokio::pin!(drain);
            assert!(futures_util::poll!(drain.as_mut()).is_pending());
            tokio::time::advance(OPERATION_BOUND + Duration::from_millis(1)).await;
            let early = futures_util::poll!(drain.as_mut());
            gate.release();
            match early {
                std::task::Poll::Ready(result) => (result, true),
                std::task::Poll::Pending => (drain.await, false),
            }
        })
        .await;
        assert!(
            drained.is_ok(),
            "functional snapshot drain expired: {drained:?}"
        );
        assert!(!early, "drain completed while its writer was held");
        let progress = drained.unwrap().asynchronous.unwrap();
        assert!(progress.completed_generation >= cut.0);
        assert!(progress.completed_sequence >= cut.1);
    })
    .catch_unwind()
    .await;
    drop(release);
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_snapshot_replacement_waits_for_engine_completion() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let story = prepare(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        let sender = fleet.peers[story.leader].node;
        install_base(&cold, sender, &story).await;
        let directory = fleet
            .directory
            .path()
            .join(format!("snapshots-{}", story.follower));
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let held = SnapshotInstallAppliedProgressGateGuard::install(directory, Arc::clone(&gate));
        let release = ReleaseGate(Arc::clone(&gate));
        let receiver = cold.clone();
        let covering = story.covering.clone();
        let installing =
            tokio::spawn(
                async move { install_fixture_snapshot(&receiver, sender, &covering).await },
            );
        clock::watchdog(
            gate.wait_started(),
            "real install reaches its completion hold",
        )
        .await;
        assert_eq!(
            cold.inner
                .private_wal
                .as_ref()
                .unwrap()
                .with_native_read(|native| Ok(native.applied()))
                .unwrap(),
            story.covering.meta.last_log_id
        );
        let receiver = cold.clone();
        let (replacement, early) = clock::run(async move {
            let _held = held;
            let _release = release;
            let replacement = quarantine_snapshot(&receiver);
            tokio::pin!(replacement);
            assert!(futures_util::poll!(replacement.as_mut()).is_pending());
            assert!(!receiver.inner.persistence_protocol.is_active());
            tokio::time::advance(OPERATION_BOUND + Duration::from_millis(1)).await;
            let early = futures_util::poll!(replacement.as_mut());
            gate.release();
            match early {
                std::task::Poll::Ready(result) => (result, true),
                std::task::Poll::Pending => (replacement.await, false),
            }
        })
        .await;
        decode_snapshot(installing.await.unwrap(), "held covering install").unwrap();
        assert!(
            replacement.is_ok(),
            "functional snapshot replacement expired"
        );
        assert!(
            !early,
            "replacement completed while old engine work was held"
        );
        let replacement = replacement.unwrap();
        assert_ne!(replacement.nonce, story.cut.request.nonce);
        assert_eq!(replacement.incarnation, story.cut.request.incarnation);
        assert_eq!(replacement.attempt, story.cut.request.attempt + 1);
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_snapshot_certification_waits_for_real_quorum_cut() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        let story = prepare(&mut fleet).await;
        let cold = fleet.store(story.follower).clone();
        let leader = fleet.peers[story.leader].node;
        let hold =
            races::ReplyRelease::cold_cut(&fleet.peers[story.leader], cold.inner.local_node_id);
        let receiver = cold.clone();
        let (certified, early, captured) = clock::run(async move {
            let certification =
                AssertUnwindSafe(certify_snapshot(&receiver, leader)).catch_unwind();
            tokio::pin!(certification);
            tokio::select! {
                () = hold.wait_started() => {},
                _ = certification.as_mut() => panic!("certification escaped the reply hold"),
            }
            let captured = hold.cut();
            assert!(!receiver.inner.persistence_protocol.is_active());
            assert!(!receiver.status().admitted);
            tokio::time::advance(OPERATION_BOUND + Duration::from_millis(1)).await;
            let early = futures_util::poll!(certification.as_mut());
            hold.release();
            match early {
                std::task::Poll::Ready(result) => (result, true, captured),
                std::task::Poll::Pending => (certification.await, false, captured),
            }
        })
        .await;
        assert!(
            certified.is_ok(),
            "functional snapshot certification expired"
        );
        assert!(
            !early,
            "certification completed while its real reply was held"
        );
        assert!(certified.unwrap() == captured);
        assert_ne!(captured.request.nonce, story.cut.request.nonce);
        assert!(captured.barrier.index > story.cut.barrier.index);
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
