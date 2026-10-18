//! Failed replication listeners must not turn storage drain into a handoff.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_listener_drain_sends_no_handoff_and_joins_native_storage() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let leader = fleet.leader();
        let store = fleet.store(leader).clone();
        let keys = provider();
        let request = create_request(&store, 71, keys.as_ref()).await;
        let outcome = create(&store, &request).await;
        fleet.ready().await;
        // The listener has failed and joined its accepted handlers. Outbound
        // transports remain observable, just as in an embedder's failure path.
        *fleet.peers[leader].handler.write().await = None;
        assert!(fleet.peers[leader].handler.read().await.is_none());
        store
            .shutdown_unplanned()
            .await
            .expect("failed-listener storage drain");
        assert!(!store.status().admitted);
        assert_eq!(
            store.shutdown_with_report().await.unwrap(),
            opc_consensus::PlannedShutdownOutcome::Fallback {
                reason: opc_consensus::PlannedShutdownFallback::Unplanned,
            }
        );
        assert!(
            store.prepare_shutdown().await.is_err(),
            "late preparation cannot start a handoff"
        );
        assert_eq!(
            store.persistence_health().storage_state,
            SessionStorageState::Closed
        );
        assert!(!store.persistence_health().engine_running);
        let lock = std::fs::File::open(
            fleet
                .directory
                .path()
                .join(format!("node-{leader}.sqlite.native-wal/LOCK")),
        )
        .unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("completed drain releases the physical writer ownership lock");
        drop(lock);
        assert_eq!(
            fleet
                .peers
                .iter()
                .map(|peer| peer.leadership_transfers.load(Ordering::Acquire))
                .sum::<u64>(),
            0,
            "a known failed replication listener must never initiate leadership transfer"
        );
        // Drain preserves accepted work and the ordinary authority checks on
        // reopen; successful local closure alone never grants traffic.
        let close_proof = fleet
            .directory
            .path()
            .join(format!("node-{leader}.sqlite.native-wal/ASYNC-CLOSED"));
        assert!(
            close_proof.is_file(),
            "joined active ownership retains its exact close proof"
        );
        drop(store);
        fleet.close_clean(leader).await.unwrap();
        fleet
            .open(leader, SessionPersistenceMode::Async)
            .await
            .unwrap();
        assert!(!close_proof.exists(), "reopen consumes the proof once");
        assert_eq!(
            fleet.store(leader).persistence_health().recovery,
            Some(SessionAsyncRecoveryState::Active)
        );
        assert!(!fleet.store(leader).status().admitted);
        clock::initialize(fleet.store(leader)).await.unwrap();
        fleet.ready().await;
        assert_recorded(fleet.store(leader), &request, &outcome).await;
    })
    .catch_unwind()
    .await;
    for index in 0..fleet.stores.len() {
        let _ = fleet.close_and_join_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

struct ReleaseWriter(Arc<crate::consensus::snapshot::SnapshotArtifactGate>);

impl Drop for ReleaseWriter {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_listener_drain_survives_cancelled_and_timed_out_clones() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let gate = Arc::new(crate::consensus::snapshot::SnapshotArtifactGate::new());
    let release = ReleaseWriter(Arc::clone(&gate));
    let result = AssertUnwindSafe(async {
        let held_writer = fleet
            .peers
            .iter()
            .enumerate()
            .min_by_key(|(_, peer)| peer.node)
            .unwrap()
            .0;
        let writer_gate = Arc::clone(&gate);
        fleet
            .open_with_hook(
                held_writer,
                SessionPersistenceMode::Async,
                Some(Arc::new(move || {
                    writer_gate.block_if_armed_blocking();
                    Ok(())
                })),
            )
            .await
            .unwrap();
        for index in (0..3).filter(|index| *index != held_writer) {
            fleet
                .open(index, SessionPersistenceMode::Async)
                .await
                .unwrap();
        }
        fleet.form().await;
        let leader = fleet.leader();
        assert_eq!(
            leader, held_writer,
            "the canonical bootstrap voter owns the held writer"
        );
        let store = fleet.store(leader).clone();
        let request = create_request(&store, 72, &provider()).await;
        for voter in fleet.stores.iter().flatten() {
            clock::drain(voter).await.unwrap();
        }
        gate.arm();
        create(&store, &request).await;
        tokio::time::timeout(Duration::from_secs(3), gate.wait_started())
            .await
            .unwrap();
        *fleet.peers[leader].handler.write().await = None;
        assert!(store.shutdown_unplanned().now_or_never().is_none());
        assert!(
            !store.status().admitted,
            "cancelling the observer cannot restore admission"
        );
        let first = store.clone();
        let second = store.clone();
        let (one, two) = tokio::join!(first.shutdown_unplanned(), second.shutdown());
        assert_eq!(one, Err(consensus_unavailable()));
        assert_eq!(two, Err(consensus_unavailable()));
        assert_eq!(
            store.persistence_health().storage_state,
            SessionStorageState::Draining
        );
        let lock = std::fs::File::open(
            fleet
                .directory
                .path()
                .join(format!("node-{leader}.sqlite.native-wal/LOCK")),
        )
        .unwrap();
        assert_eq!(
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        assert!(store.prepare_shutdown().await.is_err());
        gate.release();
        store.shutdown_unplanned().await.unwrap();
        assert_eq!(
            store.persistence_health().storage_state,
            SessionStorageState::Closed
        );
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        assert_eq!(
            fleet
                .peers
                .iter()
                .map(|peer| peer.leadership_transfers.load(Ordering::Acquire))
                .sum::<u64>(),
            0
        );
    })
    .catch_unwind()
    .await;
    drop(release);
    for index in 0..fleet.stores.len() {
        let _ = fleet.close_and_join_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
