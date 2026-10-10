use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_drains_an_rpc_handler_before_the_store_reopens() {
    let mut fleet = Fleet::open().await;
    let node = member(2, 1).identity.node_id();
    let old_handler = Arc::downgrade(fleet.network.handlers.read().unwrap().get(&node).unwrap());
    let (started, arrived) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    *fleet.network.held_response.lock().unwrap() = Some(HeldResponse {
        node,
        started,
        release: resume,
    });
    tokio::time::timeout(Duration::from_secs(10), arrived)
        .await
        .expect("a real authenticated RPC must reach the held response")
        .unwrap();

    let mut disconnect = Box::pin(fleet.network.disconnect(node));
    let first_poll = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(std::future::Future::poll(disconnect.as_mut(), cx))
    })
    .await;
    assert!(
        first_poll.is_pending(),
        "removing a route must wait for its already-dispatched RPC handler"
    );
    assert!(!fleet.network.handlers.read().unwrap().contains_key(&node));

    let store = fleet.nodes.remove(1);
    store.shutdown().await.unwrap();
    drop(store);
    let reopen = || async {
        let directory = fleet.directories[1].path();
        let backend = SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap();
        ConsensusSessionStore::open_with_voter_slots_and_integrity(
            topology(2),
            genesis(),
            node,
            backend,
            directory.join("snapshots"),
            Arc::new(Resolver(fleet.network.clone())),
            super::super::super::SnapshotIntegrityPolicy::PortableVerified,
        )
        .await
    };
    // The retained public handler owns the directory even after shutdown.
    assert!(old_handler.strong_count() > 0);
    assert!(matches!(
        reopen().await,
        Err(ConsensusSessionStoreOpenError::StorageUnavailable)
    ));

    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), &mut disconnect)
        .await
        .expect("disconnect must finish when the held response releases its handler");
    assert_eq!(old_handler.strong_count(), 0);
    let reopened = reopen().await.unwrap();
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .insert(node, reopened.rpc_handler());
    fleet.nodes.insert(1, reopened);
    drop(disconnect);
    fleet.close().await;
}
