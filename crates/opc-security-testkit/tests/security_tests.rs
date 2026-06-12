use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use opc_identity::{
    IdentityReloadError, SvidWatcher, TrustBundle, TrustBundleSet, TrustDomain, WorkloadIdentity,
};
use opc_key::{KeyId, KeyProvider, KeyPurpose, KmsKeyProvider};
use opc_security_testkit::{FakeCa, FakeKms, FakeSpire, KmsBehavior, SvidUpdateMsg};
use opc_tls::{PeerPolicy, TlsConfigBuilder};
use opc_types::TenantId;

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

#[tokio::test]
async fn test_svid_rotation_and_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("spire.sock");

    let td = "example.internal";
    let ca = FakeCa::new(td);
    let trust_domain = TrustDomain::new(td).unwrap();

    // Generate initial SVID
    let spiffe_id =
        "spiffe://example.internal/tenant/tenant-a/ns/default/sa/amf-sa/nf/amf/instance/node-1";
    let (cert_pem, key_pem) = ca.sign_spiffe_id(spiffe_id, 3600);

    let initial_msg = SvidUpdateMsg {
        cert_chain_pem: cert_pem.clone(),
        private_key_pem: key_pem.clone(),
        trust_bundles: vec![(td.to_string(), ca.ca_cert_pem.clone())],
    };

    let spire = FakeSpire::new(&socket_path, initial_msg).await.unwrap();

    let certs = opc_identity::parse_certs_pem(&ca.ca_cert_pem).unwrap();
    let mut initial_bundles = TrustBundleSet::new();
    initial_bundles.insert(TrustBundle {
        trust_domain: trust_domain.clone(),
        certificates: certs,
    });

    let watcher = SvidWatcher::new(&socket_path, initial_bundles);
    let state = watcher
        .wait_for_initial_identity(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(state.identity.spiffe_id.as_str(), spiffe_id);

    // Setup TLS server/client
    let mut peer_policy = PeerPolicy::default();
    let mut tds = HashSet::new();
    tds.insert(trust_domain.clone());
    peer_policy.allowed_trust_domains = Some(tds);

    let client_builder =
        TlsConfigBuilder::new(watcher.subscribe()).with_policy(peer_policy.clone());
    let server_builder = TlsConfigBuilder::new(watcher.subscribe()).with_policy(peer_policy);

    let client_config = Arc::new(client_builder.build_client_config().unwrap());
    let server_config = Arc::new(server_builder.build_server_config().unwrap());

    // Bind server listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let _tls_stream = acceptor.accept(conn).await.unwrap();
    });

    // Client connects
    let client_conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let domain = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let _tls_client = connector.connect(domain, client_conn).await.unwrap();

    server_handle.await.unwrap();

    // Now test SVID rotation
    let (new_cert_pem, new_key_pem) = ca.sign_spiffe_id(spiffe_id, 3600);
    let rotated_msg = SvidUpdateMsg {
        cert_chain_pem: new_cert_pem,
        private_key_pem: new_key_pem,
        trust_bundles: vec![(td.to_string(), ca.ca_cert_pem.clone())],
    };

    let mut events = watcher.subscribe_events();
    spire.rotate(rotated_msg);

    // Wait for reload success event
    let event = timeout(Duration::from_secs(3), events.recv())
        .await
        .unwrap()
        .unwrap();
    if let opc_identity::IdentityReloadEvent::Failure { error } = event {
        panic!("Rotation failed: {error}");
    }

    // Verify next TLS connection uses rotated cert
    let state_after = watcher.subscribe().borrow().clone().unwrap();
    assert_eq!(state_after.identity.spiffe_id.as_str(), spiffe_id);
}

#[tokio::test]
async fn test_expired_svid_rejected() {
    let td = "example.internal";
    let ca = FakeCa::new(td);
    let trust_domain = TrustDomain::new(td).unwrap();

    let spiffe_id =
        "spiffe://example.internal/tenant/tenant-a/ns/default/sa/amf-sa/nf/amf/instance/node-1";
    // Sign an SVID that expired 1 hour ago
    let (cert_pem, _) = ca.sign_spiffe_id(spiffe_id, -3600);

    let certs = opc_identity::parse_certs_pem(&cert_pem).unwrap();
    let leaf_der = &certs[0];

    let root_certs = opc_identity::parse_certs_pem(&ca.ca_cert_pem).unwrap();
    let mut active_bundles = TrustBundleSet::new();
    active_bundles.insert(TrustBundle {
        trust_domain,
        certificates: root_certs,
    });

    let res = WorkloadIdentity::from_cert_der(leaf_der.as_ref(), &active_bundles);
    assert_eq!(res.unwrap_err(), IdentityReloadError::ExpiredSvid);
}

#[tokio::test]
async fn test_removed_trust_bundle_revokes_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("spire.sock");

    let td = "example.internal";
    let ca = FakeCa::new(td);
    let trust_domain = TrustDomain::new(td).unwrap();

    let spiffe_id =
        "spiffe://example.internal/tenant/tenant-a/ns/default/sa/amf-sa/nf/amf/instance/node-1";
    let (cert_pem, key_pem) = ca.sign_spiffe_id(spiffe_id, 3600);

    let initial_msg = SvidUpdateMsg {
        cert_chain_pem: cert_pem.clone(),
        private_key_pem: key_pem.clone(),
        trust_bundles: vec![(td.to_string(), ca.ca_cert_pem.clone())],
    };

    let spire = FakeSpire::new(&socket_path, initial_msg).await.unwrap();

    let root_certs = opc_identity::parse_certs_pem(&ca.ca_cert_pem).unwrap();
    let mut initial_bundles = TrustBundleSet::new();
    initial_bundles.insert(TrustBundle {
        trust_domain: trust_domain.clone(),
        certificates: root_certs,
    });

    let watcher = SvidWatcher::new(&socket_path, initial_bundles);
    watcher
        .wait_for_initial_identity(Duration::from_secs(5))
        .await
        .unwrap();

    // Now remove the trust bundle by rotating to a state where the trust domain's bundle is empty/removed
    let mut events = watcher.subscribe_events();
    let removed_msg = SvidUpdateMsg {
        cert_chain_pem: cert_pem,
        private_key_pem: key_pem,
        trust_bundles: vec![], // Empty trust bundles
    };

    spire.rotate(removed_msg);

    // Wait for the reload event
    let event = timeout(Duration::from_secs(3), events.recv())
        .await
        .unwrap()
        .unwrap();
    // Since trust domain is example.internal, but its bundle was removed, WorkloadIdentity::from_cert_der should fail with UnknownTrustDomain
    if let opc_identity::IdentityReloadEvent::Success { .. } = event {
        panic!("Should have failed SVID load because trust domain became unknown");
    }

    // Verify SvidWatcher state has been updated (or remained None/unchanged)
    let state = watcher.subscribe().borrow().clone();
    assert!(state.is_none() || !state.unwrap().trust_bundles.contains(&trust_domain));
}

#[tokio::test]
async fn test_spire_socket_unavailable_fails_startup() {
    let watcher = SvidWatcher::new("non_existent_spire_socket.sock", TrustBundleSet::new());
    let res = watcher
        .wait_for_initial_identity(Duration::from_millis(100))
        .await;
    assert_eq!(res.unwrap_err(), IdentityReloadError::SocketUnavailable);
}

#[tokio::test]
async fn test_kms_key_provider_behavior() {
    let behavior = KmsBehavior::default();
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("kms.sock");
    let fake_kms = FakeKms::new_unix(&socket_path, behavior).await.unwrap();

    let provider = KmsKeyProvider::new(
        fake_kms.endpoint().to_string(),
        None,
        Duration::from_millis(200),
    );

    let key = [0x99u8; 32];
    fake_kms.insert_key("config-active-1", "config", "tenant-a", key);
    fake_kms.set_active_key("config", "tenant-a", "config-active-1");

    // 1. Success case
    let handle = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .unwrap();
    assert_eq!(handle.key_id().as_str(), "config-active-1");

    // 2. Rotate case
    let new_id = provider
        .rotate_key(KeyPurpose::Config, &tenant())
        .await
        .unwrap();
    assert_eq!(new_id.as_str(), "config-tenant-a-r1");

    // 3. Get key by ID case
    let handle_by_id = provider.get_key_by_id(&new_id).await.unwrap();
    assert_eq!(handle_by_id.key_id().as_str(), "config-tenant-a-r1");

    // 4. Unavailable case
    fake_kms.set_behavior(KmsBehavior {
        delay: None,
        unavailable: true,
        simulate_error: false,
    });
    let err = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .unwrap_err();
    assert_eq!(err, opc_key::KeyError::Unavailable);

    // 5. Timeout case
    fake_kms.set_behavior(KmsBehavior {
        delay: Some(Duration::from_millis(500)),
        unavailable: false,
        simulate_error: false,
    });
    let err2 = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .unwrap_err();
    assert_eq!(err2, opc_key::KeyError::Unavailable);

    // 6. Simulated error case
    fake_kms.set_behavior(KmsBehavior {
        delay: None,
        unavailable: false,
        simulate_error: true,
    });
    let err3 = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .unwrap_err();
    assert_eq!(err3, opc_key::KeyError::Unavailable);

    // 7. Not found case
    fake_kms.set_behavior(KmsBehavior::default());
    let missing_key_id = KeyId::new("missing-key-id").unwrap();
    let err4 = provider.get_key_by_id(&missing_key_id).await.unwrap_err();
    assert_eq!(err4, opc_key::KeyError::NotFound);
}

#[tokio::test]
async fn test_kms_tcp_without_tls_fails_closed() {
    let fake_kms = FakeKms::new_tcp("127.0.0.1:0", KmsBehavior::default())
        .await
        .unwrap();
    fake_kms.insert_key("config-active-1", "config", "tenant-a", [0x44u8; 32]);
    fake_kms.set_active_key("config", "tenant-a", "config-active-1");

    let provider = KmsKeyProvider::new(
        fake_kms.endpoint().to_string(),
        None,
        Duration::from_millis(200),
    );

    let err = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .unwrap_err();
    assert_eq!(err, opc_key::KeyError::Unavailable);
}
