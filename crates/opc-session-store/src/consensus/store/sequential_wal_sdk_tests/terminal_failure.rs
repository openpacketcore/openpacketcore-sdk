use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_failure_is_shared_by_store_clones_and_not_by_healthy_voters() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new_native("terminal-failure");
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let store = fleet.stores[0].clone();
        let clone = store.clone();
        let mut first = Box::pin(store.terminal_failure());
        let mut second = Box::pin(clone.terminal_failure());
        assert!(first.as_mut().now_or_never().is_none());
        assert!(second.as_mut().now_or_never().is_none());
        store
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .fence_for_test()
            .unwrap();
        let reasons = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(first, second, store.terminal_failure())
        })
        .await
        .expect("public clone-wide signal");
        let reason = crate::SessionStoreTerminalFailure::StorageFenced;
        assert_eq!(reasons, (reason, reason, reason));
        for healthy in &fleet.stores[1..] {
            assert!(healthy.terminal_failure().now_or_never().is_none());
        }
    })
    .catch_unwind()
    .await;
    for peer in &fleet.peers {
        *peer.handler.write().await = None;
    }
    let shutdown = join_all(fleet.stores.iter().map(ConsensusSessionStore::shutdown)).await;
    assert!(shutdown[0].is_err());
    for (store, result) in fleet.stores[1..].iter().zip(&shutdown[1..]) {
        assert!(result.is_ok());
        assert!(store.terminal_failure().now_or_never().is_none());
    }
    result.unwrap();
}
