use opc_identity::{
    build_identity_state, IdentityState, SvidDocument, TrustBundle, TrustBundleSet,
};
use opc_tls::{
    peer_tls_identity_from_client_connection, peer_tls_identity_from_server_connection,
    TlsConfigBuilder, TlsHandshakeRunError, TlsMaterialAvailability, TlsMaterialController,
    TlsMaterialError, TlsMaterialReloadReason, MAX_TLS_CONCURRENT_HANDSHAKES,
    MAX_TLS_HANDSHAKE_EPOCH_RETRIES, MAX_TLS_MATERIAL_CHAIN_CERTIFICATES,
    MAX_TLS_MATERIAL_PRIVATE_KEY_BYTES, MAX_TLS_MATERIAL_TOTAL_BYTES,
    MAX_TLS_MATERIAL_TRUST_ANCHORS, MAX_TLS_MATERIAL_TRUST_BUNDLES,
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

type TestIssuer = rcgen::CertifiedIssuer<'static, KeyPair>;

fn test_ca(name: &str) -> TestIssuer {
    let mut parameters = CertificateParams::default();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    parameters.distinguished_name.push(DnType::CommonName, name);
    let key = KeyPair::generate().expect("generate CA key");
    rcgen::CertifiedIssuer::self_signed(parameters, key).expect("sign CA")
}

fn test_ca_with_validity(
    name: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> TestIssuer {
    let mut parameters = CertificateParams::default();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    parameters.distinguished_name.push(DnType::CommonName, name);
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate bounded CA key");
    rcgen::CertifiedIssuer::self_signed(parameters, key).expect("sign bounded CA")
}

fn material(
    spiffe_id: &str,
    ca: &TestIssuer,
    validity: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
) -> TestMaterial {
    let now = time::OffsetDateTime::now_utc();
    let (not_before, not_after) = validity.unwrap_or((
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    ));
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("SPIFFE test identity"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate leaf key");
    let certificate = parameters.signed_by(&key, ca).expect("sign leaf");
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

fn test_intermediate_ca(
    root: &TestIssuer,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> TestIssuer {
    let mut parameters = CertificateParams::default();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    parameters
        .distinguished_name
        .push(DnType::CommonName, "short-lived intermediate");
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate intermediate key");
    rcgen::CertifiedIssuer::signed_by(parameters, key, root).expect("sign intermediate")
}

fn material_via_intermediate(
    spiffe_id: &str,
    intermediate: &TestIssuer,
    root: &TestIssuer,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> TestMaterial {
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("SPIFFE test identity"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate leaf key");
    let certificate = parameters
        .signed_by(&key, intermediate)
        .expect("sign leaf through intermediate");
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: opc_identity::TrustDomain::new("example.test").expect("trust domain"),
        certificates: vec![root.der().clone()],
    });
    let state = build_identity_state(
        vec![
            certificate.der().clone(),
            intermediate.der().clone(),
            root.der().clone(),
        ],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        bundles,
    )
    .expect("valid intermediate test material");
    TestMaterial {
        leaf_der: certificate.der().as_ref().to_vec(),
        state,
    }
}

fn material_via_root(
    spiffe_id: &str,
    root: &TestIssuer,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
    present_root: bool,
) -> TestMaterial {
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("SPIFFE test identity"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate leaf key");
    let certificate = parameters
        .signed_by(&key, root)
        .expect("sign root-issued leaf");
    let mut cert_chain = vec![certificate.der().clone()];
    if present_root {
        cert_chain.push(root.der().clone());
    }
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: opc_identity::TrustDomain::new("example.test").expect("trust domain"),
        certificates: vec![root.der().clone()],
    });
    let state = build_identity_state(
        cert_chain,
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        bundles,
    )
    .expect("valid root-issued test material");
    TestMaterial {
        leaf_der: certificate.der().as_ref().to_vec(),
        state,
    }
}

fn unchecked_intermediate_temporal_material(
    baseline: &IdentityState,
    spiffe_id: &str,
    root: &TestIssuer,
    intermediate_validity: (time::OffsetDateTime, time::OffsetDateTime),
    leaf_validity: (time::OffsetDateTime, time::OffsetDateTime),
) -> IdentityState {
    let (intermediate_not_before, intermediate_not_after) = intermediate_validity;
    let (leaf_not_before, leaf_not_after) = leaf_validity;
    let intermediate = test_intermediate_ca(root, intermediate_not_before, intermediate_not_after);
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("SPIFFE test identity"),
    ));
    parameters.not_before = leaf_not_before;
    parameters.not_after = leaf_not_after;
    let key = KeyPair::generate().expect("generate temporal-chain leaf key");
    let certificate = parameters
        .signed_by(&key, &intermediate)
        .expect("sign temporal-chain leaf");
    let mut identity = baseline.identity.clone();
    identity.expires_at = Timestamp::from_offset_datetime(leaf_not_after);
    IdentityState {
        identity,
        svid: SvidDocument {
            spiffe_id: SpiffeId::new(spiffe_id).expect("SPIFFE test identity"),
            cert_chain: vec![
                certificate.der().clone(),
                intermediate.der().clone(),
                root.der().clone(),
            ],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            expires_at: Timestamp::from_offset_datetime(leaf_not_after),
        },
        trust_bundles: baseline.trust_bundles.clone(),
    }
}

fn unchecked_temporal_material(
    baseline: &IdentityState,
    spiffe_id: &str,
    ca: &TestIssuer,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> IdentityState {
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("SPIFFE test identity"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate temporal leaf key");
    let certificate = parameters.signed_by(&key, ca).expect("sign temporal leaf");
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

fn assert_limit_rejection_retains_epoch(controller: &TlsMaterialController, epoch: u64) {
    let status = controller.status();
    assert_eq!(status.epoch().get(), epoch);
    assert_eq!(
        status.availability(),
        TlsMaterialAvailability::RetainingLastGood
    );
    assert_eq!(
        status.reason(),
        Some(TlsMaterialReloadReason::MaterialLimitExceeded)
    );
    let debug = format!("{status:?}");
    assert!(!debug.contains("spiffe://"));
    assert!(!debug.contains("BEGIN"));
}

#[tokio::test]
async fn controller_pins_identity_retains_invalid_candidates_and_versions_rollbacks() {
    let ca = test_ca("stable CA");
    let other_ca = test_ca("other CA");
    let material_a = material(CLIENT_ID, &ca, None);
    let material_b = material(CLIENT_ID, &ca, None);
    let other_identity = material(OTHER_CLIENT_ID, &ca, None);
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

    let other_chain = material(CLIENT_ID, &other_ca, None);
    let mut wrong_chain = other_chain.state;
    wrong_chain.trust_bundles = material_a.state.trust_bundles.clone();
    source_tx
        .send(Some(wrong_chain))
        .expect("publish wrong chain");
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::InvalidCertificateChain)
    );

    let mut malformed_chain = material_b.state.clone();
    malformed_chain
        .svid
        .cert_chain
        .insert(1, rustls_pki_types::CertificateDer::from(vec![0xde, 0xad]));
    source_tx
        .send(Some(malformed_chain))
        .expect("publish malformed chain");
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::InvalidCertificateChain)
    );
    assert_eq!(controller.status().epoch().get(), 1);

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

#[test]
fn controller_rejects_oversized_candidates_and_retains_last_good() {
    let ca = test_ca("bounded CA");
    let baseline = material(CLIENT_ID, &ca, None).state;
    let (source_tx, source_rx) = watch::channel(Some(baseline.clone()));
    let controller = TlsMaterialController::new(source_rx);
    assert_eq!(controller.status().epoch().get(), 1);

    let mut oversized_chain = baseline.clone();
    while oversized_chain.svid.cert_chain.len() <= MAX_TLS_MATERIAL_CHAIN_CERTIFICATES {
        oversized_chain.svid.cert_chain.push(ca.der().clone());
    }
    source_tx
        .send(Some(oversized_chain))
        .expect("publish oversized chain");
    assert_limit_rejection_retains_epoch(&controller, 1);

    let mut oversized_key = baseline.clone();
    oversized_key.svid.private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![
        0x5a;
        MAX_TLS_MATERIAL_PRIVATE_KEY_BYTES
            + 1
    ]));
    source_tx
        .send(Some(oversized_key))
        .expect("publish oversized key");
    assert_limit_rejection_retains_epoch(&controller, 1);

    let mut oversized_bundles = baseline.clone();
    for index in 0..MAX_TLS_MATERIAL_TRUST_BUNDLES {
        let trust_domain = opc_identity::TrustDomain::new(format!("limit-{index}.example.test"))
            .expect("bounded trust domain");
        oversized_bundles.trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: vec![ca.der().clone()],
        });
    }
    source_tx
        .send(Some(oversized_bundles))
        .expect("publish oversized bundle count");
    assert_limit_rejection_retains_epoch(&controller, 1);

    let mut oversized_anchors = baseline.clone();
    oversized_anchors
        .trust_bundles
        .bundles
        .values_mut()
        .next()
        .expect("baseline trust bundle")
        .certificates = vec![ca.der().clone(); MAX_TLS_MATERIAL_TRUST_ANCHORS + 1];
    source_tx
        .send(Some(oversized_anchors))
        .expect("publish oversized anchor count");
    assert_limit_rejection_retains_epoch(&controller, 1);

    let mut oversized_total = baseline;
    oversized_total
        .trust_bundles
        .bundles
        .values_mut()
        .next()
        .expect("baseline trust bundle")
        .certificates
        .push(rustls_pki_types::CertificateDer::from(vec![
            0xa5;
            MAX_TLS_MATERIAL_TOTAL_BYTES
                + 1
        ]));
    source_tx
        .send(Some(oversized_total))
        .expect("publish oversized aggregate material");
    assert_limit_rejection_retains_epoch(&controller, 1);
}

#[tokio::test]
async fn rotation_in_each_handshake_phase_retries_without_mixed_material() {
    for rotate_phase in 0..=4 {
        let ca = test_ca(&format!("phase-{rotate_phase} CA"));
        let client_a = material(CLIENT_ID, &ca, None);
        let client_b = material(CLIENT_ID, &ca, None);
        let server = material(SERVER_ID, &ca, None);
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
    let ca = test_ca("retry CA");
    let initial = material(CLIENT_ID, &ca, None);
    let (source_tx, source_rx) = watch::channel(Some(initial.state));
    let config = TlsConfigBuilder::from_material_controller(TlsMaterialController::new(source_rx))
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("client config");
    let attempts = Arc::new(AtomicUsize::new(0));
    let rotation_state = material(CLIENT_ID, &ca, None).state;

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
    let stale_rotation = material(CLIENT_ID, &ca, None).state;
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
    let ca = test_ca("concurrency CA");
    let initial = material(CLIENT_ID, &ca, None);
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
    let ca = test_ca("expiry CA");
    let now = time::OffsetDateTime::now_utc();
    let short = material(
        CLIENT_ID,
        &ca,
        Some((
            now - time::Duration::minutes(1),
            now + time::Duration::seconds(2),
        )),
    );
    let mut malformed_after_expiry = material(CLIENT_ID, &ca, None).state;
    malformed_after_expiry.svid.private_key = material(CLIENT_ID, &ca, None)
        .state
        .svid
        .private_key
        .clone_key();
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
    source_tx
        .send(Some(malformed_after_expiry))
        .expect("publish malformed candidate after expiry");
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::LastGoodExpired),
        "the authoritative unavailable reason remains expiry"
    );
    drop(source_tx);
    let _ = controller.status();
    let _ = controller.status();
    assert!(matches!(
        TlsConfigBuilder::from_material_controller(controller)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("client config")
            .begin_handshake(),
        Err(TlsMaterialError::Unavailable)
    ));
}

#[test]
fn initial_malformed_svid_without_predecessor_is_rejected_as_svid() {
    let ca = test_ca("initial malformed metrics CA");
    let mut malformed = material(CLIENT_ID, &ca, None).state;
    malformed.svid.private_key = material(CLIENT_ID, &ca, None)
        .state
        .svid
        .private_key
        .clone_key();
    let (_source_tx, source_rx) = watch::channel(Some(malformed));
    let controller = TlsMaterialController::new(source_rx);

    assert_eq!(controller.status().epoch().get(), 0);
    assert_eq!(
        controller.status().reason(),
        Some(TlsMaterialReloadReason::PrivateKeyMismatch)
    );
}

#[test]
fn intermediate_temporal_failures_are_classified_before_initial_and_update_rebuilds() {
    let root = test_ca("temporal intermediate root");
    let baseline = material(CLIENT_ID, &root, None).state;
    let base = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("second-aligned test time");
    let scenarios = [
        (
            base - time::Duration::hours(2),
            base - time::Duration::hours(1),
            TlsMaterialReloadReason::ExpiredMaterial,
        ),
        (
            base + time::Duration::hours(1),
            base + time::Duration::hours(2),
            TlsMaterialReloadReason::NotYetValidMaterial,
        ),
    ];

    for (intermediate_not_before, intermediate_not_after, expected_reason) in scenarios {
        let candidate = unchecked_intermediate_temporal_material(
            &baseline,
            CLIENT_ID,
            &root,
            (intermediate_not_before, intermediate_not_after),
            (
                base - time::Duration::minutes(1),
                base + time::Duration::hours(4),
            ),
        );

        let (_initial_tx, initial_rx) = watch::channel(Some(candidate.clone()));
        let initial = TlsMaterialController::new(initial_rx);
        assert_eq!(initial.status().epoch().get(), 0);
        assert_eq!(
            initial.status().availability(),
            TlsMaterialAvailability::Unavailable
        );
        assert_eq!(initial.status().reason(), Some(expected_reason));
        assert!(initial.status().certificate_chain_expires_at().is_none());

        let (update_tx, update_rx) = watch::channel(Some(baseline.clone()));
        let update = TlsMaterialController::new(update_rx);
        assert_eq!(update.status().epoch().get(), 1);
        update_tx
            .send(Some(candidate))
            .expect("publish temporal intermediate candidate");
        assert_eq!(update.status().epoch().get(), 1);
        assert_eq!(
            update.status().availability(),
            TlsMaterialAvailability::RetainingLastGood
        );
        assert_eq!(update.status().reason(), Some(expected_reason));
        assert!(update.status().certificate_chain_expires_at().is_some());
    }
}

#[tokio::test]
async fn intermediate_expiry_bounds_local_and_peer_chain_evidence() {
    let root = test_ca("chain-expiry root");
    let base = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("second-aligned test time");
    // Leave ample setup headroom on loaded CI workers before crossing the
    // real wall-clock X.509 boundary.
    let intermediate_not_after = base + time::Duration::seconds(10);
    let leaf_not_after = base + time::Duration::hours(1);
    let expected_chain_expiry = Timestamp::from_offset_datetime(intermediate_not_after);
    let intermediate = test_intermediate_ca(
        &root,
        base - time::Duration::minutes(1),
        intermediate_not_after,
    );
    let client = material_via_intermediate(
        CLIENT_ID,
        &intermediate,
        &root,
        base - time::Duration::minutes(1),
        leaf_not_after,
    );
    let server = material_via_intermediate(
        SERVER_ID,
        &intermediate,
        &root,
        base - time::Duration::minutes(1),
        leaf_not_after,
    );
    let (_client_tx, client_rx) = watch::channel(Some(client.state));
    let (_server_tx, server_rx) = watch::channel(Some(server.state));
    let client_controller = TlsMaterialController::new(client_rx);
    let server_controller = TlsMaterialController::new(server_rx);

    for status in [client_controller.status(), server_controller.status()] {
        assert_eq!(
            status.certificate_chain_expires_at(),
            Some(expected_chain_expiry)
        );
        assert!(status.leaf_expires_at().expect("leaf expiry") > expected_chain_expiry);
    }

    let client_config = TlsConfigBuilder::from_material_controller(client_controller.clone())
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("client config");
    let server_config = TlsConfigBuilder::from_material_controller(server_controller.clone())
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("server config");
    let client_attempt = client_config.begin_handshake().expect("client snapshot");
    let server_attempt = server_config.begin_handshake().expect("server snapshot");
    assert_eq!(
        client_attempt.certificate_chain_expires_at(),
        expected_chain_expiry
    );
    assert_eq!(
        server_attempt.certificate_chain_expires_at(),
        expected_chain_expiry
    );
    assert!(client_attempt.leaf_expires_at() > expected_chain_expiry);
    assert!(server_attempt.leaf_expires_at() > expected_chain_expiry);

    let mut client_connection = rustls::ClientConnection::new(
        client_attempt.rustls_config(),
        ServerName::try_from("localhost")
            .expect("server name")
            .to_owned(),
    )
    .expect("client connection");
    let mut server_connection =
        rustls::ServerConnection::new(server_attempt.rustls_config()).expect("server connection");
    complete_handshake_with_phase(
        &mut client_connection,
        &mut server_connection,
        usize::MAX,
        &mut || {},
    );

    let server_peer = peer_tls_identity_from_client_connection(&client_connection)
        .expect("authenticated server evidence");
    assert_eq!(server_peer.spiffe_id().as_str(), SERVER_ID);
    assert_eq!(
        server_peer.certificate_chain_expires_at(),
        expected_chain_expiry
    );
    assert!(server_peer.leaf_expires_at() > expected_chain_expiry);
    let client_peer = peer_tls_identity_from_server_connection(&server_connection)
        .expect("authenticated client evidence");
    assert_eq!(client_peer.spiffe_id().as_str(), CLIENT_ID);
    assert_eq!(
        client_peer.certificate_chain_expires_at(),
        expected_chain_expiry
    );
    assert!(client_peer.leaf_expires_at() > expected_chain_expiry);

    for admission in [
        client_attempt.admit().expect("admit client"),
        server_attempt.admit().expect("admit server"),
    ] {
        assert_eq!(
            admission.certificate_chain_expires_at(),
            expected_chain_expiry
        );
        assert!(admission.leaf_expires_at() > expected_chain_expiry);
    }

    let remaining = (intermediate_not_after - time::OffsetDateTime::now_utc())
        .try_into()
        .unwrap_or(Duration::ZERO);
    tokio::time::sleep(remaining.saturating_add(Duration::from_millis(100))).await;
    for controller in [client_controller, server_controller] {
        let status = controller.status();
        assert_eq!(status.availability(), TlsMaterialAvailability::Unavailable);
        assert_eq!(
            status.reason(),
            Some(TlsMaterialReloadReason::LastGoodExpired)
        );
        assert!(status.leaf_expires_at().is_none());
        assert!(status.certificate_chain_expires_at().is_none());
    }
    assert!(matches!(
        client_config.begin_handshake(),
        Err(TlsMaterialError::Unavailable)
    ));
    assert!(matches!(
        server_config.begin_handshake(),
        Err(TlsMaterialError::Unavailable)
    ));
}

#[test]
fn only_redundantly_presented_roots_bound_local_and_peer_chain_expiry() {
    let base = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("second-aligned test time");
    let root_not_after = base + time::Duration::hours(1);
    let leaf_not_after = base + time::Duration::hours(2);
    let expected_root_expiry = Timestamp::from_offset_datetime(root_not_after);
    let expected_leaf_expiry = Timestamp::from_offset_datetime(leaf_not_after);
    let root = test_ca_with_validity(
        "presentation-boundary root",
        base - time::Duration::hours(1),
        root_not_after,
    );
    let trust_bundle_only_root = material_via_root(
        CLIENT_ID,
        &root,
        base - time::Duration::minutes(1),
        leaf_not_after,
        false,
    );
    let redundantly_presented_root = material_via_root(
        SERVER_ID,
        &root,
        base - time::Duration::minutes(1),
        leaf_not_after,
        true,
    );
    let (_client_tx, client_rx) = watch::channel(Some(trust_bundle_only_root.state));
    let (_server_tx, server_rx) = watch::channel(Some(redundantly_presented_root.state));
    let client_controller = TlsMaterialController::new(client_rx);
    let server_controller = TlsMaterialController::new(server_rx);
    assert_eq!(
        client_controller.status().certificate_chain_expires_at(),
        Some(expected_leaf_expiry)
    );
    assert_eq!(
        server_controller.status().certificate_chain_expires_at(),
        Some(expected_root_expiry)
    );

    let client_config = TlsConfigBuilder::from_material_controller(client_controller)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("client config");
    let server_config = TlsConfigBuilder::from_material_controller(server_controller)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("server config");
    let client_attempt = client_config.begin_handshake().expect("client snapshot");
    let server_attempt = server_config.begin_handshake().expect("server snapshot");
    assert_eq!(
        client_attempt.certificate_chain_expires_at(),
        expected_leaf_expiry
    );
    assert_eq!(
        server_attempt.certificate_chain_expires_at(),
        expected_root_expiry
    );
    let mut client_connection = rustls::ClientConnection::new(
        client_attempt.rustls_config(),
        ServerName::try_from("localhost")
            .expect("server name")
            .to_owned(),
    )
    .expect("client connection");
    let mut server_connection =
        rustls::ServerConnection::new(server_attempt.rustls_config()).expect("server connection");
    complete_handshake_with_phase(
        &mut client_connection,
        &mut server_connection,
        usize::MAX,
        &mut || {},
    );

    let server_peer = peer_tls_identity_from_client_connection(&client_connection)
        .expect("authenticated server evidence");
    assert_eq!(server_peer.leaf_expires_at(), expected_leaf_expiry);
    assert_eq!(
        server_peer.certificate_chain_expires_at(),
        expected_root_expiry
    );
    let client_peer = peer_tls_identity_from_server_connection(&server_connection)
        .expect("authenticated client evidence");
    assert_eq!(client_peer.leaf_expires_at(), expected_leaf_expiry);
    assert_eq!(
        client_peer.certificate_chain_expires_at(),
        expected_leaf_expiry
    );
}
