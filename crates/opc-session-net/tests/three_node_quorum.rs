use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{RemoteSessionBackend, SessionReplicationServer};
use opc_session_store::backend::{
    CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp, SessionBackend,
};
use opc_session_store::fake::FakeSessionBackend;
use opc_session_store::lease::SessionLeaseManager;
use opc_session_store::model::{
    FenceToken, Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType,
};
use opc_session_store::quorum::{FencedSessionReplica, QuorumSessionStore};
use opc_session_store::record::{EncryptedSessionPayload, StoredSessionRecord};
use opc_tls::TlsConfigBuilder;
use opc_types::{NetworkFunctionKind, TenantId};

#[derive(Clone)]
struct TestMtls {
    server_config: Arc<opc_tls::ServerConfig>,
    client_config: Arc<opc_tls::ClientConfig>,
}

fn test_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-a").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
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

fn mtls_configs() -> TestMtls {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Session Net Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let (server_cert, server_key) = signed_leaf(
        &ca_cert,
        &ca_key,
        "Session Server",
        "spiffe://test-domain/tenant/test/ns/default/sa/session-server/nf/smf/instance/0",
    );
    let (client_cert, client_key) = signed_leaf(
        &ca_cert,
        &ca_key,
        "Session Client",
        "spiffe://test-domain/tenant/test/ns/default/sa/session-client/nf/smf/instance/0",
    );
    let server_state = identity_state_from_pem(
        &(server_cert.pem() + &ca_cert.pem()),
        &server_key.serialize_pem(),
        &ca_cert.pem(),
    );
    let client_state = identity_state_from_pem(
        &(client_cert.pem() + &ca_cert.pem()),
        &client_key.serialize_pem(),
        &ca_cert.pem(),
    );
    let (_server_tx, server_rx) = tokio::sync::watch::channel(Some(server_state));
    let (_client_tx, client_rx) = tokio::sync::watch::channel(Some(client_state));
    let server_config = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_server_config()
        .expect("server tls config");
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_client_config()
        .expect("client tls config");

    TestMtls {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
    }
}

fn signed_leaf(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    common_name: &str,
    spiffe_id: &str,
) -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("spiffe id"),
    ));
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(1);

    let key = rcgen::KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, ca_cert, ca_key).expect("leaf cert");
    (cert, key)
}

fn identity_state_from_pem(
    cert_chain_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> opc_identity::IdentityState {
    let ca_certs = parse_certs_pem(ca_pem).expect("ca pem");
    let cert_chain = parse_certs_pem(cert_chain_pem).expect("cert chain pem");
    let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
    let mut trust_bundles = opc_identity::TrustBundleSet::new();
    trust_bundles.insert(TrustBundle {
        trust_domain,
        certificates: ca_certs,
    });
    let private_key = parse_key_pem(key_pem).expect("key pem");
    build_identity_state(cert_chain, private_key, trust_bundles).expect("identity state")
}

async fn start_server(
    mtls: &TestMtls,
) -> (
    SocketAddr,
    FakeSessionBackend,
    opc_session_net::server::ServerHandle,
) {
    let backend = FakeSessionBackend::new();
    start_server_with_backend(mtls, backend).await
}

async fn start_server_with_backend(
    mtls: &TestMtls,
    backend: FakeSessionBackend,
) -> (
    SocketAddr,
    FakeSessionBackend,
    opc_session_net::server::ServerHandle,
) {
    let server =
        SessionReplicationServer::new(Arc::new(backend.clone()), mtls.server_config.clone());
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    (addr, backend, handle)
}

#[tokio::test]
async fn stalled_connection_is_reaped_after_idle_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend = FakeSessionBackend::new();
    let mtls = mtls_configs();
    let server = SessionReplicationServer::new(Arc::new(backend), mtls.server_config.clone())
        .with_max_connections(1)
        .with_idle_timeout(Duration::from_millis(150));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

    // Connect and send only a partial length prefix (2 of 4 bytes), then stall
    // — the classic slowloris move.
    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    stalled.write_all(&[0x00, 0x00]).await.unwrap();
    stalled.flush().await.unwrap();

    // The server must reap the idle connection rather than hold its slot
    // forever: a TLS alert byte or EOF are both acceptable, but the read must
    // complete once the server closes the stalled handshake.
    let mut buf = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buf))
        .await
        .expect("server should close the stalled connection within the timeout")
        .expect("read from reaped connection");

    drop(handle);
}

#[tokio::test]
async fn plaintext_rebuild_is_rejected_before_backend_dispatch() {
    let mtls = mtls_configs();
    let backend = FakeSessionBackend::new();
    let server =
        SessionReplicationServer::new(Arc::new(backend.clone()), mtls.server_config.clone())
            .with_idle_timeout(Duration::from_millis(150));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = opc_session_net::protocol::write_frame(
        &mut stream,
        &opc_session_net::Request::Hello {
            contract_version: opc_session_net::protocol::CONTRACT_VERSION,
            node_id: "plaintext-peer".to_string(),
        },
    )
    .await;
    let _ = opc_session_net::protocol::write_frame(
        &mut stream,
        &opc_session_net::Request::RebuildReplicationState {
            entries: vec![ReplicationEntry {
                sequence: 1,
                tx_id: "plaintext-rebuild".to_string(),
                op: ReplicationOp::AcquireLease {
                    key: test_key(),
                    owner: OwnerId::new("plaintext-owner").unwrap(),
                    fence: FenceToken::new(1),
                    credential_id: 1,
                    ttl: Duration::from_secs(60),
                    expires_at: opc_types::Timestamp::now_utc(),
                },
                timestamp: opc_types::Timestamp::now_utc(),
            }],
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(backend.max_replication_sequence().await.unwrap(), 0);
    handle.abort();
}

#[tokio::test]
async fn test_three_node_quorum_kill_and_restart() {
    // 1. Spin up 3 servers
    let mtls = mtls_configs();
    let (addr1, backend1, handle1) = start_server(&mtls).await;
    let (addr2, _backend2, handle2) = start_server(&mtls).await;
    let (addr3, _backend3, handle3) = start_server(&mtls).await;

    // 2. Create 3 remote clients
    let remote1 = Arc::new(RemoteSessionBackend::new(
        addr1,
        mtls.client_config.clone(),
        None,
    ));
    let remote2 = Arc::new(RemoteSessionBackend::new(
        addr2,
        mtls.client_config.clone(),
        None,
    ));
    let remote3 = Arc::new(RemoteSessionBackend::new(
        addr3,
        mtls.client_config.clone(),
        None,
    ));

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
    let server1_new =
        SessionReplicationServer::new(Arc::new(backend1.clone()), mtls.server_config.clone());
    let (handle1_new, addr1_new) = server1_new.listen(addr1).await.unwrap();

    // Update the remote to point to the new address
    let remote1_new = Arc::new(RemoteSessionBackend::new(
        addr1_new,
        mtls.client_config.clone(),
        None,
    ));
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
    let mtls = mtls_configs();
    let (addr, backend, handle) = start_server(&mtls).await;
    let remote = Arc::new(RemoteSessionBackend::new(
        addr,
        mtls.client_config.clone(),
        None,
    ));

    // Warm up the persistent connection.
    let key = test_key();
    assert_eq!(remote.get(&key).await.unwrap(), None);

    // Kill the server. The old TCP connection may linger until the next write.
    handle.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Restart a server on the same address with the same backend state.
    let server =
        SessionReplicationServer::new(Arc::new(backend.clone()), mtls.server_config.clone());
    let (handle_new, _addr_new) = server.listen(addr).await.unwrap();

    // The next request must transparently reconnect rather than fail.
    assert_eq!(remote.get(&key).await.unwrap(), None);

    handle_new.abort();
}

#[tokio::test]
async fn capabilities_uses_cached_success_after_disconnect() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls).await;
    let remote = RemoteSessionBackend::new(
        addr,
        mtls.client_config.clone(),
        Some(Duration::from_millis(200)),
    );

    let warmed = remote.capabilities().await;
    assert!(
        warmed.atomic_compare_and_set && warmed.monotonic_fencing_token && warmed.batch_write,
        "expected warmed remote capabilities to reflect the full backend"
    );

    handle.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let after_disconnect = remote.capabilities().await;
    assert_eq!(
        after_disconnect, warmed,
        "capability transport failures must not silently downgrade a warmed remote backend"
    );
}

#[tokio::test]
async fn test_in_flight_request_surfaces_error_on_disconnect() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls).await;

    // Short deadline so reconnect attempts expire before any restart.
    let remote = Arc::new(RemoteSessionBackend::new(
        addr,
        mtls.client_config.clone(),
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
#[cfg(feature = "insecure-test")]
async fn direct_cas_retry_after_dropped_response_reports_success() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    let backend = Arc::new(FakeSessionBackend::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let first_cas = Arc::new(AtomicBool::new(true));
    let cas_request_ids = Arc::new(Mutex::new(Vec::new()));

    let server = {
        let backend = backend.clone();
        let first_cas = first_cas.clone();
        let cas_request_ids = cas_request_ids.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let backend = backend.clone();
                let first_cas = first_cas.clone();
                let cas_request_ids = cas_request_ids.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();
                    let hello: Request = read_frame(&mut r, 1 << 20).await.unwrap();
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
                        match req {
                            Request::AcquireLease { key, owner, ttl } => {
                                let res = backend.acquire(&key, owner, ttl).await;
                                write_frame(&mut w, &Response::AcquireLease(res))
                                    .await
                                    .unwrap();
                            }
                            Request::CompareAndSet { op, request_id } => {
                                let request_id =
                                    request_id.expect("direct CAS must carry an idempotency key");
                                let mut ids = cas_request_ids.lock().await;
                                let first_seen_id = ids.first().cloned();
                                ids.push(request_id.clone());
                                drop(ids);

                                if first_cas.swap(false, Ordering::SeqCst) {
                                    let res = backend.compare_and_set(op).await;
                                    assert_eq!(res.as_ref(), Ok(&CompareAndSetResult::Success));
                                    return;
                                }

                                if first_seen_id.as_ref() == Some(&request_id) {
                                    write_frame(
                                        &mut w,
                                        &Response::CompareAndSet(Ok(CompareAndSetResult::Success)),
                                    )
                                    .await
                                    .unwrap();
                                } else {
                                    let res = backend.compare_and_set(op).await;
                                    write_frame(&mut w, &Response::CompareAndSet(res))
                                        .await
                                        .unwrap();
                                }
                            }
                            other => panic!("unexpected request in CAS retry test: {other:?}"),
                        }
                    }
                });
            }
        })
    };

    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)));
    let key = test_key();
    let owner = OwnerId::new("owner-retry").unwrap();
    let lease = remote
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let result = remote
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(&key, &owner, lease.fence(), Generation::new(1)),
        })
        .await
        .unwrap();

    assert_eq!(result, CompareAndSetResult::Success);
    let ids = cas_request_ids.lock().await;
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1], "retry must reuse the same CAS request id");

    server.abort();
}

#[tokio::test]
async fn test_batch_and_delete() {
    let mtls = mtls_configs();
    let (addr1, _backend1, handle1) = start_server(&mtls).await;
    let (addr2, _backend2, handle2) = start_server(&mtls).await;
    let (addr3, _backend3, handle3) = start_server(&mtls).await;

    let remote1 = Arc::new(RemoteSessionBackend::new(
        addr1,
        mtls.client_config.clone(),
        None,
    ));
    let remote2 = Arc::new(RemoteSessionBackend::new(
        addr2,
        mtls.client_config.clone(),
        None,
    ));
    let remote3 = Arc::new(RemoteSessionBackend::new(
        addr3,
        mtls.client_config.clone(),
        None,
    ));

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
    let mtls = mtls_configs();
    let (addr1, _backend1, handle1) = start_server(&mtls).await;
    let (addr2, _backend2, handle2) = start_server(&mtls).await;
    let (addr3, _backend3, handle3) = start_server(&mtls).await;

    let remote1 = Arc::new(RemoteSessionBackend::new(
        addr1,
        mtls.client_config.clone(),
        None,
    ));
    let remote2 = Arc::new(RemoteSessionBackend::new(
        addr2,
        mtls.client_config.clone(),
        None,
    ));
    let remote3 = Arc::new(RemoteSessionBackend::new(
        addr3,
        mtls.client_config.clone(),
        None,
    ));

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
#[cfg(feature = "insecure-test")]
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

    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(300)));
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
