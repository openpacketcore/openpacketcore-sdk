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
            .shutdown()
            .await
            .expect("failed-listener storage drain");
        assert!(!store.status().admitted);
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
        drop(store);
        fleet.close_clean(leader).await.unwrap();
        fleet
            .open(leader, SessionPersistenceMode::Async)
            .await
            .unwrap();
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
