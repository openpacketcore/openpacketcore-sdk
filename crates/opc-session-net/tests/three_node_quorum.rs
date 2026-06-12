use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use opc_session_net::{RemoteSessionBackend, SessionReplicationServer};
use opc_session_store::backend::{CompareAndSet, CompareAndSetResult, SessionBackend};
use opc_session_store::fake::FakeSessionBackend;
use opc_session_store::lease::SessionLeaseManager;
use opc_session_store::model::{
    FenceToken, Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType,
};
use opc_session_store::quorum::{FencedSessionReplica, QuorumSessionStore};
use opc_session_store::record::{EncryptedSessionPayload, StoredSessionRecord};
use opc_types::{NetworkFunctionKind, TenantId};

fn test_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-a").unwrap(),
        nf_kind: NetworkFunctionKind::new("smf").unwrap(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"test-session"),
    }
}

fn test_record(
    key: &SessionKey,
    owner: &OwnerId,
    fence: FenceToken,
    generation: Generation,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key: key.clone(),
        generation,
        owner: owner.clone(),
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("test").unwrap(),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"payload"),
    }
}

async fn start_server() -> (
    SocketAddr,
    FakeSessionBackend,
    opc_session_net::server::ServerHandle,
) {
    let backend = FakeSessionBackend::new();
    let server = SessionReplicationServer::new(Arc::new(backend.clone()), None);
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    (addr, backend, handle)
}

#[tokio::test]
async fn test_three_node_quorum_kill_and_restart() {
    // 1. Spin up 3 servers
    let (addr1, backend1, handle1) = start_server().await;
    let (addr2, _backend2, handle2) = start_server().await;
    let (addr3, _backend3, handle3) = start_server().await;

    // 2. Create 3 remote clients
    let remote1 = Arc::new(RemoteSessionBackend::new(addr1, None, None));
    let remote2 = Arc::new(RemoteSessionBackend::new(addr2, None, None));
    let remote3 = Arc::new(RemoteSessionBackend::new(addr3, None, None));

    // 3. Wrap in quorum replicas
    let replica1 = FencedSessionReplica::new(1, remote1.clone());
    let replica2 = FencedSessionReplica::new(2, remote2.clone());
    let replica3 = FencedSessionReplica::new(3, remote3.clone());

    let quorum =
        QuorumSessionStore::new(vec![replica1.clone(), replica2.clone(), replica3.clone()]);

    // 4. Lease and write conformance
    let key = test_key();
    let owner = OwnerId::new("owner-1").unwrap();

    let lease = quorum
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(lease.key(), &key);
    assert_eq!(lease.owner(), &owner);

    let record = test_record(&key, &owner, lease.fence(), Generation::new(1));
    let cas_result = quorum
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_result, CompareAndSetResult::Success);

    // Read back
    let read = quorum.get(&key).await.unwrap();
    assert_eq!(read.as_ref(), Some(&record));

    // 5. Kill one server mid-stream
    handle1.abort();

    // Wait a moment for the connection to drop
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. Assert quorum writes still succeed (2 of 3 is a quorum)
    let lease2 = quorum.renew(&lease, Duration::from_secs(60)).await.unwrap();
    let record2 = test_record(&key, &owner, lease2.fence(), Generation::new(2));
    let cas_result2 = quorum
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease2.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: record2.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_result2, CompareAndSetResult::Success);

    // 7. Restart the server
    let server1_new = SessionReplicationServer::new(Arc::new(backend1.clone()), None);
    let (handle1_new, addr1_new) = server1_new.listen(addr1).await.unwrap();

    // Update the remote to point to the new address
    let remote1_new = Arc::new(RemoteSessionBackend::new(addr1_new, None, None));
    let replica1_new = FencedSessionReplica::new(1, remote1_new.clone());

    // Create a new quorum with the restarted replica
    let quorum2 = QuorumSessionStore::new(vec![replica1_new, replica2.clone(), replica3.clone()]);

    // Wait for things to settle
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 8. Assert read-repair / resync behavior
    // The restarted replica should be repaired on the next read
    let read_repaired = quorum2.get(&key).await.unwrap();
    assert_eq!(read_repaired.as_ref(), Some(&record2));

    // Cleanup
    handle1_new.abort();
    handle2.abort();
    handle3.abort();
}

#[tokio::test]
async fn test_persistent_connection_reconnect_after_restart() {
    let (addr, backend, handle) = start_server().await;
    let remote = Arc::new(RemoteSessionBackend::new(addr, None, None));

    // Warm up the persistent connection.
    let key = test_key();
    assert_eq!(remote.get(&key).await.unwrap(), None);

    // Kill the server. The old TCP connection may linger until the next write.
    handle.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Restart a server on the same address with the same backend state.
    let server = SessionReplicationServer::new(Arc::new(backend.clone()), None);
    let (handle_new, _addr_new) = server.listen(addr).await.unwrap();

    // The next request must transparently reconnect rather than fail.
    assert_eq!(remote.get(&key).await.unwrap(), None);

    handle_new.abort();
}

#[tokio::test]
async fn test_in_flight_request_surfaces_error_on_disconnect() {
    let (addr, _backend, handle) = start_server().await;

    // Short deadline so reconnect attempts expire before any restart.
    let remote = Arc::new(RemoteSessionBackend::new(
        addr,
        None,
        Some(Duration::from_millis(300)),
    ));

    // Warm up the persistent connection.
    let key = test_key();
    assert_eq!(remote.get(&key).await.unwrap(), None);

    // Kill the server while a request is about to be issued.
    handle.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let start = tokio::time::Instant::now();
    let result = remote.get(&key).await;
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "expected backend-unavailable error after disconnect, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "request hung instead of failing within deadline: {elapsed:?}"
    );
}

#[tokio::test]
async fn test_batch_and_delete() {
    let (addr1, _backend1, handle1) = start_server().await;
    let (addr2, _backend2, handle2) = start_server().await;
    let (addr3, _backend3, handle3) = start_server().await;

    let remote1 = Arc::new(RemoteSessionBackend::new(addr1, None, None));
    let remote2 = Arc::new(RemoteSessionBackend::new(addr2, None, None));
    let remote3 = Arc::new(RemoteSessionBackend::new(addr3, None, None));

    let replica1 = FencedSessionReplica::new(1, remote1);
    let replica2 = FencedSessionReplica::new(2, remote2);
    let replica3 = FencedSessionReplica::new(3, remote3);

    let quorum = QuorumSessionStore::new(vec![replica1, replica2, replica3]);

    let key = test_key();
    let owner = OwnerId::new("owner-batch").unwrap();

    let lease = quorum
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let record = test_record(&key, &owner, lease.fence(), Generation::new(1));

    let batch_results = quorum
        .batch(vec![
            opc_session_store::backend::SessionOp::Get { key: key.clone() },
            opc_session_store::backend::SessionOp::CompareAndSet(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: record.clone(),
            }),
            opc_session_store::backend::SessionOp::Get { key: key.clone() },
        ])
        .await
        .unwrap();

    assert_eq!(batch_results.len(), 3);
    assert!(matches!(
        batch_results[0],
        opc_session_store::backend::SessionOpResult::Get(Ok(None))
    ));
    assert!(matches!(
        batch_results[1],
        opc_session_store::backend::SessionOpResult::CompareAndSet(Ok(
            CompareAndSetResult::Success
        ))
    ));
    assert!(matches!(
        batch_results[2],
        opc_session_store::backend::SessionOpResult::Get(Ok(Some(_)))
    ));

    // Delete fenced
    quorum.delete_fenced(&lease).await.unwrap();
    let read = quorum.get(&key).await.unwrap();
    assert_eq!(read, None);

    handle1.abort();
    handle2.abort();
    handle3.abort();
}

#[tokio::test]
async fn test_replication_log_and_watch() {
    let (addr1, _backend1, handle1) = start_server().await;
    let (addr2, _backend2, handle2) = start_server().await;
    let (addr3, _backend3, handle3) = start_server().await;

    let remote1 = Arc::new(RemoteSessionBackend::new(addr1, None, None));
    let remote2 = Arc::new(RemoteSessionBackend::new(addr2, None, None));
    let remote3 = Arc::new(RemoteSessionBackend::new(addr3, None, None));

    let replica1 = FencedSessionReplica::new(1, remote1);
    let replica2 = FencedSessionReplica::new(2, remote2);
    let replica3 = FencedSessionReplica::new(3, remote3);

    let quorum = QuorumSessionStore::new(vec![replica1, replica2, replica3]);

    let key = test_key();
    let owner = OwnerId::new("owner-watch").unwrap();

    let lease = quorum
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let record = test_record(&key, &owner, lease.fence(), Generation::new(1));

    quorum
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    // Check replication log
    let max_seq = quorum.max_replication_sequence().await.unwrap();
    assert!(max_seq >= 2); // lease acquisition + CAS

    let log = quorum.get_replication_log(1, 10).await.unwrap();
    assert!(!log.is_empty());

    // Watch
    let mut watch_stream = quorum.watch(1).await.unwrap();
    let first_entry = watch_stream.next().await;
    assert!(first_entry.is_some());

    handle1.abort();
    handle2.abort();
    handle3.abort();
}

/// A deadline that fires mid-exchange must poison the connection: the next
/// request has to reconnect rather than reuse a connection whose pending
/// (stale) response would otherwise be read as the new request's reply.
#[tokio::test]
async fn test_timeout_mid_exchange_forces_reconnect() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let conn_count = connections.clone();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let n = conn_count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                // Speak the handshake on every connection.
                let hello: Request = match read_frame(&mut r, 1 << 20).await {
                    Ok(req) => req,
                    Err(_) => return,
                };
                assert!(matches!(hello, Request::Hello { .. }));
                write_frame(
                    &mut w,
                    &Response::HelloAck {
                        contract_version: CONTRACT_VERSION,
                    },
                )
                .await
                .unwrap();

                loop {
                    let req: Request = match read_frame(&mut r, 1 << 20).await {
                        Ok(req) => req,
                        Err(_) => return,
                    };
                    if n == 0 {
                        // First connection: swallow the request forever so the
                        // client's deadline fires mid-exchange.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    }
                    // Later connections answer promptly.
                    if let Request::Get { .. } = req {
                        write_frame(&mut w, &Response::Get(Ok(None))).await.unwrap();
                    }
                }
            });
        }
    });

    let remote = RemoteSessionBackend::new(addr, None, Some(Duration::from_millis(300)));
    let key = test_key();

    // First request hits the stalling connection and must fail at the
    // deadline rather than hang.
    let start = tokio::time::Instant::now();
    let first = remote.get(&key).await;
    assert!(first.is_err(), "stalled request must surface an error");
    assert!(start.elapsed() < Duration::from_secs(2));

    // Second request must succeed via a NEW connection - reusing the stalled
    // one would read no (or the wrong) response.
    let second = remote.get(&key).await;
    assert_eq!(second.unwrap(), None);
    assert!(
        connections.load(Ordering::SeqCst) >= 2,
        "client must reconnect after a timed-out exchange"
    );
}
