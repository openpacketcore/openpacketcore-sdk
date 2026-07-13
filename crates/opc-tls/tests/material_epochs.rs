use opc_identity::{
    build_identity_state, IdentityState, SvidDocument, TrustBundle, TrustBundleSet,
};
use opc_tls::{
    TlsConfigBuilder, TlsHandshakeRunError, TlsMaterialAvailability, TlsMaterialController,
    TlsMaterialError, TlsMaterialReloadReason, MAX_TLS_CONCURRENT_HANDSHAKES,
    MAX_TLS_HANDSHAKE_EPOCH_RETRIES,
};
use opc_types::{SpiffeId, Timestamp};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

const CLIENT_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/client-0";
const OTHER_CLIENT_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/client-1";
const SERVER_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/server-0";

struct TestMaterial {
    state: IdentityState,
    leaf_der: Vec<u8>,
}

fn test_ca(name: &str) -> (rcgen::Certificate, KeyPair) {
    let mut parameters = CertificateParams::default();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    parameters.distinguished_name.push(DnType::CommonName, name);
    let key = KeyPair::generate().expect("generate CA key");
    let certificate = parameters.self_signed(&key).expect("sign CA");
    (certificate, key)
}

fn material(
    spiffe_id: &str,
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
    validity: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
) -> TestMaterial {
    let now = time::OffsetDateTime::now_utc();
    let (not_before, not_after) = validity.unwrap_or((
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    ));
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("SPIFFE test identity"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate leaf key");
    let certificate = parameters.signed_by(&key, ca, ca_key).expect("sign leaf");
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: opc_identity::TrustDomain::new("example.test").expect("trust domain"),
        certificates: vec![ca.der().clone()],
    });
    let state = build_identity_state(
        vec![certificate.der().clone(), ca.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        bundles,
    )
    .expect("valid test material");
    TestMaterial {
        leaf_der: certificate.der().as_ref().to_vec(),
        state,
    }
}

fn unchecked_temporal_material(
    baseline: &IdentityState,
    spiffe_id: &str,
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> IdentityState {
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("SPIFFE test identity"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate temporal leaf key");
    let certificate = parameters
        .signed_by(&key, ca, ca_key)
        .expect("sign temporal leaf");
    let mut identity = baseline.identity.clone();
    identity.expires_at = Timestamp::from_offset_datetime(not_after);
    IdentityState {
        identity,
        svid: SvidDocument {
            spiffe_id: SpiffeId::new(spiffe_id).expect("SPIFFE test identity"),
            cert_chain: vec![certificate.der().clone(), ca.der().clone()],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            expires_at: Timestamp::from_offset_datetime(not_after),
        },
        trust_bundles: baseline.trust_bundles.clone(),
    }
}

fn complete_handshake_with_phase(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
    rotate_phase: usize,
    rotate: &mut impl FnMut(),
) {
    if rotate_phase == 0 {
        rotate();
    }
    let mut client_flight_seen = false;
    let mut server_flight_seen = false;
    for _ in 0..32 {
        let mut progressed = false;
        let mut client_flight = Vec::new();
        if client
            .write_tls(&mut client_flight)
            .expect("write client TLS")
            > 0
        {
            progressed = true;
            server
                .read_tls(&mut Cursor::new(client_flight))
                .expect("read client TLS");
            server.process_new_packets().expect("process client TLS");
            if !client_flight_seen {
                client_flight_seen = true;
                if rotate_phase == 1 {
                    rotate();
                }
            }
        }

        let mut server_flight = Vec::new();
        if server
            .write_tls(&mut server_flight)
            .expect("write server TLS")
            > 0
        {
            progressed = true;
            client
                .read_tls(&mut Cursor::new(server_flight))
                .expect("read server TLS");
            client.process_new_packets().expect("process server TLS");
            if !server_flight_seen {
                server_flight_seen = true;
                if rotate_phase == 2 {
                    rotate();
                }
            }
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            if rotate_phase == 3 {
                rotate();
            }
            return;
        }
        assert!(progressed, "TLS handshake stopped making progress");
    }
    panic!("TLS handshake exceeded the bounded exchange");
}

#[tokio::test]
async fn controller_pins_identity_retains_invalid_candidates_and_versions_rollbacks() {
    let (ca, ca_key) = test_ca("stable CA");
    let (other_ca, other_ca_key) = test_ca("other CA");
    let material_a = material(CLIENT_ID, &ca, &ca_key, None);
    let material_b = material(CLIENT_ID, &ca, &ca_key, None);
    let other_identity = material(OTHER_CLIENT_ID, &ca, &ca_key, None);
    let (source_tx, source_rx) = watch::channel(Some(material_a.state.clone()));
    let controller = TlsMaterialController::new(source_rx);
    assert_eq!(controller.status().epoch().get(), 1);

    source_tx
        .send(Some(other_identity.state))
        .expect("publish changed identity");
    let status = controller.status();
    assert_eq!(status.epoch().get(), 1);
    assert_eq!(
        status.reason(),
        Some(TlsMaterialReloadReason::LocalIdentityChanged)
    );
    assert_eq!(
        status.availability(),
        TlsMaterialAvailability::RetainingLastGood
    );

    let mut wrong_key = material_b.state.clone();
    wrong_key.svid.private_key = material_a.state.svid.private_key.clone_key();
    source_tx.send(Some(wrong_key)).expect("publish wrong key");
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::PrivateKeyMismatch)
    );
    assert_eq!(controller.status().epoch().get(), 1);

    let other_chain = material(CLIENT_ID, &other_ca, &other_ca_key, None);
    let mut wrong_chain = other_chain.state;
    wrong_chain.trust_bundles = material_a.state.trust_bundles.clone();
    source_tx
        .send(Some(wrong_chain))
        .expect("publish wrong chain");
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::InvalidCertificateChain)
    );

    let mut invalid_trust = material_b.state.clone();
    invalid_trust
        .trust_bundles
        .bundles
        .get_mut(&opc_identity::TrustDomain::new("example.test").expect("invalid trust domain key"))
        .expect("candidate trust bundle")
        .certificates = vec![rustls_pki_types::CertificateDer::from(vec![0xde, 0xad])];
    source_tx
        .send(Some(invalid_trust))
        .expect("publish invalid trust");
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::InvalidCertificateChain)
    );

    let now = time::OffsetDateTime::now_utc();
    let expired = unchecked_temporal_material(
        &material_a.state,
        CLIENT_ID,
        &ca,
        &ca_key,
        now - time::Duration::minutes(2),
        now - time::Duration::minutes(1),
    );
    source_tx.send(Some(expired)).expect("publish expired");
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::ExpiredMaterial)
    );

    let future = unchecked_temporal_material(
        &material_a.state,
        CLIENT_ID,
        &ca,
        &ca_key,
        now + time::Duration::minutes(1),
        now + time::Duration::minutes(2),
    );
    source_tx.send(Some(future)).expect("publish future");
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::NotYetValidMaterial)
    );

    let mut overlapping_trust = material_b.state.clone();
    overlapping_trust
        .trust_bundles
        .bundles
        .get_mut(&opc_identity::TrustDomain::new("example.test").expect("trust domain key"))
        .expect("candidate trust bundle")
        .certificates
        .push(other_ca.der().clone());
    source_tx
        .send(Some(overlapping_trust))
        .expect("publish generation B");
    assert_eq!(controller.status().epoch().get(), 2);
    source_tx
        .send(Some(material_a.state))
        .expect("publish rollback A");
    assert_eq!(controller.status().epoch().get(), 3);

    let shared_client = TlsConfigBuilder::from_material_controller(controller.clone())
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("shared client config");
    let shared_server = TlsConfigBuilder::from_material_controller(controller.clone())
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("shared server config");
    assert_eq!(shared_client.material_status().epoch().get(), 3);
    source_tx
        .send(Some(material_b.state.clone()))
        .expect("publish shared-controller update");
    assert_eq!(shared_client.material_status().epoch().get(), 4);
    assert_eq!(shared_server.material_status().epoch().get(), 4);

    let explicit = TlsMaterialController::new_pinned(
        source_tx.subscribe(),
        SpiffeId::new(OTHER_CLIENT_ID).expect("explicit pin"),
    );
    assert_eq!(
        explicit.status().reason(),
        Some(TlsMaterialReloadReason::LocalIdentityChanged)
    );
    assert_eq!(
        explicit.status().availability(),
        TlsMaterialAvailability::Unavailable
    );
}

#[tokio::test]
async fn rotation_in_each_handshake_phase_retries_without_mixed_material() {
    for rotate_phase in 0..=4 {
        let (ca, ca_key) = test_ca(&format!("phase-{rotate_phase} CA"));
        let client_a = material(CLIENT_ID, &ca, &ca_key, None);
        let client_b = material(CLIENT_ID, &ca, &ca_key, None);
        let server = material(SERVER_ID, &ca, &ca_key, None);
        let (client_tx, client_rx) = watch::channel(Some(client_a.state.clone()));
        let (_server_tx, server_rx) = watch::channel(Some(server.state));
        let client_controller = TlsMaterialController::new(client_rx);
        let server_controller = TlsMaterialController::new(server_rx);
        let client_config = TlsConfigBuilder::from_material_controller(client_controller)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("client config");
        let server_config = TlsConfigBuilder::from_material_controller(server_controller)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("server config");
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed_client_leaves = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

        let outcome = client_config
            .run_handshake({
                let server_config = server_config.clone();
                let client_tx = client_tx.clone();
                let attempts = attempts.clone();
                let observed_client_leaves = observed_client_leaves.clone();
                let client_b_state = client_b.state.clone();
                move |client_attempt| {
                    let server_attempt = server_config
                        .begin_handshake()
                        .expect("server handshake snapshot");
                    let client_tx = client_tx.clone();
                    let attempts = attempts.clone();
                    let observed_client_leaves = observed_client_leaves.clone();
                    let client_b_state = client_b_state.clone();
                    async move {
                        let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                        let mut rotated = false;
                        let mut rotate = || {
                            if attempt == 0 && !rotated {
                                rotated = true;
                                client_tx
                                    .send(Some(client_b_state.clone()))
                                    .expect("rotate client material");
                            }
                        };
                        let mut client = rustls::ClientConnection::new(
                            client_attempt.rustls_config(),
                            ServerName::try_from("localhost")
                                .expect("server name")
                                .to_owned(),
                        )
                        .expect("client connection");
                        let mut server =
                            rustls::ServerConnection::new(server_attempt.rustls_config())
                                .expect("server connection");
                        complete_handshake_with_phase(
                            &mut client,
                            &mut server,
                            rotate_phase,
                            &mut rotate,
                        );
                        if rotate_phase == 4 {
                            rotate();
                        }
                        server_attempt.admit()?;
                        let peer_leaf = server
                            .peer_certificates()
                            .and_then(|chain| chain.first())
                            .expect("client peer certificate")
                            .as_ref()
                            .to_vec();
                        observed_client_leaves
                            .lock()
                            .expect("observed leaf lock")
                            .push(peer_leaf.clone());
                        Ok::<_, TlsMaterialError>(peer_leaf)
                    }
                }
            })
            .await
            .expect("bounded epoch retry");

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(outcome.admission().epoch().get(), 2);
        assert_eq!(outcome.value(), &client_b.leaf_der);
        let observed = observed_client_leaves.lock().expect("observed leaf lock");
        assert_eq!(observed.as_slice(), &[client_a.leaf_der, client_b.leaf_der]);
    }
}

#[tokio::test]
async fn repeated_rotation_is_retry_bounded_and_cancellation_safe() {
    let (ca, ca_key) = test_ca("retry CA");
    let initial = material(CLIENT_ID, &ca, &ca_key, None);
    let (source_tx, source_rx) = watch::channel(Some(initial.state));
    let config = TlsConfigBuilder::from_material_controller(TlsMaterialController::new(source_rx))
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("client config");
    let attempts = Arc::new(AtomicUsize::new(0));
    let rotation_state = material(CLIENT_ID, &ca, &ca_key, None).state;

    let result = config
        .run_handshake({
            let attempts = attempts.clone();
            let source_tx = source_tx.clone();
            let rotation_state = rotation_state.clone();
            move |_attempt| {
                let attempts = attempts.clone();
                let source_tx = source_tx.clone();
                let next = rotation_state.clone();
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    source_tx.send(Some(next)).expect("rotate every attempt");
                    Ok::<_, ()>(())
                }
            }
        })
        .await;
    assert!(matches!(
        &result,
        Err(TlsHandshakeRunError::Material(
            TlsMaterialError::EpochRetryLimit
        ))
    ));
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        MAX_TLS_HANDSHAKE_EPOCH_RETRIES + 1
    );

    let stale_error_attempts = Arc::new(AtomicUsize::new(0));
    let stale_rotation = material(CLIENT_ID, &ca, &ca_key, None).state;
    let recovered = config
        .run_handshake({
            let stale_error_attempts = stale_error_attempts.clone();
            let source_tx = source_tx.clone();
            let stale_rotation = stale_rotation.clone();
            move |_attempt| {
                let attempt = stale_error_attempts.fetch_add(1, Ordering::SeqCst);
                let source_tx = source_tx.clone();
                let next = stale_rotation.clone();
                async move {
                    if attempt == 0 {
                        source_tx
                            .send(Some(next))
                            .expect("rotate during failed TLS attempt");
                        Err("secret TLS parser text")
                    } else {
                        Ok(())
                    }
                }
            }
        })
        .await
        .expect("stale operation error is retried");
    assert_eq!(stale_error_attempts.load(Ordering::SeqCst), 2);
    assert!(recovered.admission().epoch().get() > 1);

    let cancelled = tokio::time::timeout(
        Duration::from_millis(20),
        config.run_handshake(|_attempt| std::future::pending::<Result<(), ()>>()),
    )
    .await;
    assert!(cancelled.is_err());
    assert!(config.begin_handshake().is_ok());
    assert_eq!(format!("{:?}", result), "Err(Material(EpochRetryLimit))");

    let secret_error = TlsHandshakeRunError::Operation("spiffe://secret/identity");
    assert_eq!(format!("{secret_error:?}"), "Operation([redacted])");
    assert_eq!(secret_error.to_string(), "TLS handshake operation failed");
}

#[tokio::test]
async fn concurrent_handshake_operations_are_bounded_and_drop_cancellable() {
    let (ca, ca_key) = test_ca("concurrency CA");
    let initial = material(CLIENT_ID, &ca, &ca_key, None);
    let (_source_tx, source_rx) = watch::channel(Some(initial.state));
    let config = TlsConfigBuilder::from_material_controller(TlsMaterialController::new(source_rx))
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("client config");
    let entered = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..MAX_TLS_CONCURRENT_HANDSHAKES {
        let config = config.clone();
        let entered = entered.clone();
        tasks.push(tokio::spawn(async move {
            let _ = config
                .run_handshake(|_attempt| {
                    entered.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<Result<(), ()>>()
                })
                .await;
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while entered.load(Ordering::SeqCst) != MAX_TLS_CONCURRENT_HANDSHAKES {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fill handshake gate");

    let extra_config = config.clone();
    let extra_entered = entered.clone();
    let extra = tokio::spawn(async move {
        let _ = extra_config
            .run_handshake(|_attempt| {
                extra_entered.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<(), ()>>()
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        entered.load(Ordering::SeqCst),
        MAX_TLS_CONCURRENT_HANDSHAKES
    );

    for task in &tasks {
        task.abort();
    }
    extra.abort();
    for task in tasks {
        let _ = task.await;
    }
    let _ = extra.await;
    assert!(config.begin_handshake().is_ok());
    let after_cancellation = tokio::time::timeout(
        Duration::from_secs(1),
        config.run_handshake(|_attempt| std::future::ready(Ok::<_, ()>(()))),
    )
    .await
    .expect("cancelled handshakes release their permits");
    assert!(after_cancellation.is_ok());
}

#[tokio::test]
async fn last_good_expiry_fails_closed_with_stable_status() {
    let (ca, ca_key) = test_ca("expiry CA");
    let now = time::OffsetDateTime::now_utc();
    let short = material(
        CLIENT_ID,
        &ca,
        &ca_key,
        Some((
            now - time::Duration::minutes(1),
            now + time::Duration::seconds(2),
        )),
    );
    let (source_tx, source_rx) = watch::channel(Some(short.state));
    let controller = TlsMaterialController::new(source_rx);
    assert_eq!(
        controller.status().availability(),
        TlsMaterialAvailability::Ready
    );
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::LastGoodExpired)
    );
    assert_eq!(
        controller.status().availability(),
        TlsMaterialAvailability::Unavailable
    );
    assert!(matches!(
        TlsConfigBuilder::from_material_controller(controller)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("client config")
            .begin_handshake(),
        Err(TlsMaterialError::Unavailable)
    ));
    drop(source_tx);
}
