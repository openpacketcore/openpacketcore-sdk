use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_store_owner_refuses_reopen_until_its_release() {
    let mut fleet = Fleet::open_pristine_with_io_hook(3, None).await;
    let node = member(2, 1).identity.node_id();
    let owner = fleet.nodes.remove(1);
    fleet.network.disconnect_and_shutdown(&owner).await;
    let reopen = || async {
        let directory = fleet.directories[1].path();
        ConsensusSessionStore::open_with_voter_slots_and_integrity(
            fleet.topology(2),
            fleet.genesis(),
            node,
            SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap(),
            directory.join("snapshots"),
            Arc::new(Resolver(fleet.network.clone())),
            super::super::super::SnapshotIntegrityPolicy::PortableVerified,
        )
        .await
    };
    let refused = matches!(
        reopen().await,
        Err(ConsensusSessionStoreOpenError::StorageUnavailable)
    );
    drop(owner);
    let reopened = reopen().await.unwrap();
    fleet.nodes.insert(1, reopened);
    fleet.close().await;
    assert!(
        refused,
        "shutdown must not release a retained owner's exclusion"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incompatible_reopen_preserves_the_retained_voter_identity() {
    let mut fleet = Fleet::open_pristine_with_io_hook(3, None).await;
    let node = member(2, 1).identity.node_id();
    let owner = fleet.nodes.remove(1);
    fleet.network.disconnect_and_shutdown(&owner).await;
    drop(owner);
    let directory = fleet.directories[1].path();
    let mut incompatible = fleet.genesis();
    incompatible.slots[1].member.key_digest[0] ^= 1;
    incompatible.manifest_digest =
        Sha256::digest(encode_voter_slot_table(&incompatible).unwrap()).into();
    let refused = matches!(
        ConsensusSessionStore::open_with_voter_slots_and_integrity(
            topology_from_table(incompatible.clone(), 2),
            incompatible,
            node,
            SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap(),
            directory.join("snapshots"),
            Arc::new(Resolver(fleet.network.clone())),
            super::super::super::SnapshotIntegrityPolicy::PortableVerified,
        )
        .await,
        Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)
    );
    let reopened = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        fleet.topology(2),
        fleet.genesis(),
        node,
        SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap(),
        directory.join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        super::super::super::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.voter_slot_state().await.unwrap().table(),
        &fleet.genesis()
    );
    fleet.nodes.insert(1, reopened);
    fleet.close().await;
    assert!(
        refused,
        "a different enrollment key must require identity replacement"
    );
}

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
            fleet.topology(2),
            fleet.genesis(),
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
