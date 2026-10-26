use super::*;
use opc_diameter_transport::{DiameterFrameLimits, DiameterTlsPolicyError, DiameterTlsVersion};

#[tokio::test]
async fn explicit_compatibility_accepts_a_tls12_only_peer() {
    let ca = test_ca();
    let (_source, receiver) = watch::channel(Some(identity_state(SERVER_ID, &ca)));
    let config = TlsConfigBuilder::new(receiver)
        .allow_any_trusted_peer()
        .with_compat_mode(true)
        .build_authenticated_server_config()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = DiameterTlsPolicy::tls12_compatibility(DiameterFrameLimits::default());
    let acceptor = DiameterTlsAcceptor::new(config, expected(CLIENT_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
    });
    let tcp = TcpStream::connect(address).await.unwrap();
    let raw = tokio_rustls::TlsConnector::from(Arc::new(raw_tls12_client_config(&ca)))
        .connect(server_name(), tcp)
        .await;
    assert!(raw.is_ok(), "TLS 1.2 handshake: {:?}", raw.err());
    let server = server.await.unwrap().unwrap();
    assert_eq!(server.evidence().version(), DiameterTlsVersion::Tls12);
    assert_eq!(
        server.evidence().peer_identity().spiffe_id().as_str(),
        CLIENT_ID
    );
}

fn rsa_identity(spiffe_id: &str, ca: &TestCa) -> IdentityState {
    let key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(
            include_bytes!("../../../opc-proto-ikev2/tests/data/rsa2048_pkcs8.der").as_slice(),
        ),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let mut params = CertificateParams::default();
    params
        .subject_alt_names
        .push(SanType::URI(spiffe_id.try_into().unwrap()));
    let cert = params.signed_by(&key, ca).unwrap();
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").unwrap(),
        certificates: vec![ca.der().clone()],
    });
    build_identity_state(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        bundles,
    )
    .unwrap()
}

fn compatibility_material(rsa: bool) -> TestTlsMaterial {
    let ca = test_ca();
    let make = if rsa { rsa_identity } else { identity_state };
    let (client_source, client_rx) = watch::channel(Some(make(CLIENT_ID, &ca)));
    let (server_source, server_rx) = watch::channel(Some(make(SERVER_ID, &ca)));
    let client = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .with_compat_mode(true)
        .build_authenticated_client_config()
        .unwrap();
    let server = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .with_compat_mode(true)
        .build_authenticated_server_config()
        .unwrap();
    TestTlsMaterial {
        _ca: ca,
        _client_source: client_source,
        _server_source: server_source,
        client,
        server,
    }
}

#[tokio::test]
async fn tls12_certificate_suites_carry_diameter_in_both_directions() {
    for (cipher, rsa) in [
        (DiameterTlsCipher::EcdheEcdsaAes128GcmSha256, false),
        (DiameterTlsCipher::EcdheEcdsaAes256GcmSha384, false),
        (DiameterTlsCipher::EcdheRsaAes128GcmSha256, true),
        (DiameterTlsCipher::EcdheRsaAes256GcmSha384, true),
        (DiameterTlsCipher::DheRsaAes128GcmSha256, true),
    ] {
        let policy = DiameterTlsPolicy::tls12_compatibility(DiameterFrameLimits::default())
            .with_allowed_ciphers(&[cipher])
            .unwrap();
        let (_material, mut client, mut server) =
            negotiated_direct_connections_with(compatibility_material(rsa), policy).await;
        for connection in [&mut client, &mut server] {
            assert_eq!(connection.evidence().version(), DiameterTlsVersion::Tls12);
            assert_eq!(connection.evidence().cipher(), cipher);
            assert!(connection.readiness().unwrap().traffic_ready);
        }
        assert_eq!(
            client.evidence().peer_identity().spiffe_id().as_str(),
            SERVER_ID
        );
        assert_eq!(
            server.evidence().peer_identity().spiffe_id().as_str(),
            CLIENT_ID
        );
        let request = application_request();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (sent, received) = tokio::join!(
            client.send_message(&request, deadline),
            server.receive_message(deadline)
        );
        assert!(sent.unwrap().is_protected());
        assert_eq!(received.unwrap().0, request);
        let response = OwnedMessage {
            header: Header::new(
                CommandFlags::answer(false, false),
                request.header.command_code,
                APP_ID,
                request.header.hop_by_hop_identifier,
                request.header.end_to_end_identifier,
            ),
            raw_avps: Bytes::new(),
        };
        let (sent, received) = tokio::join!(
            server.send_message(&response, deadline),
            client.receive_message(deadline)
        );
        assert!(sent.unwrap().is_protected());
        assert_eq!(received.unwrap().0, response);
    }
}

#[tokio::test]
async fn compatibility_keeps_tls13_preferred_and_retires_on_material_loss() {
    let policy = DiameterTlsPolicy::tls12_compatibility(DiameterFrameLimits::default());
    let (material, client, server) =
        negotiated_direct_connections_with(compatibility_material(false), policy).await;
    assert_eq!(client.evidence().version(), DiameterTlsVersion::Tls13);
    assert_eq!(server.evidence().version(), DiameterTlsVersion::Tls13);
    drop((client, server));
    let policy = policy
        .with_allowed_ciphers(&[DiameterTlsCipher::EcdheEcdsaAes128GcmSha256])
        .unwrap();
    let (material, mut client, _server) =
        negotiated_direct_connections_with(material, policy).await;
    assert_eq!(client.evidence().version(), DiameterTlsVersion::Tls12);
    material._client_source.send(None).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while client.readiness() != Err(opc_diameter_transport::DiameterTlsError::Retired) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TLS 1.2 retains material-epoch retirement");
}

#[test]
fn strict_policy_does_not_silently_admit_a_tls12_cipher() {
    assert_eq!(
        DiameterTlsPolicy::default().version(),
        DiameterTlsVersion::Tls13
    );
    assert_eq!(DiameterTlsPolicy::default().allowed_ciphers().count(), 3);
    assert_eq!(
        DiameterTlsPolicy::default()
            .with_allowed_ciphers(&[DiameterTlsCipher::EcdheRsaAes128GcmSha256]),
        Err(DiameterTlsPolicyError::CipherVersionMismatch)
    );
    assert_eq!(
        DiameterTlsPolicy::tls12_compatibility(DiameterFrameLimits::default())
            .with_allowed_ciphers(&[]),
        Err(DiameterTlsPolicyError::EmptyCipherSet)
    );
}

#[tokio::test]
async fn tls12_inband_upgrade_keeps_capabilities_and_application_boundaries() {
    let policy = DiameterTlsPolicy::tls12_compatibility(DiameterFrameLimits::default())
        .with_allowed_ciphers(&[DiameterTlsCipher::EcdheRsaAes128GcmSha256])
        .unwrap();
    exercise_inband_upgrade(
        compatibility_material(true),
        policy,
        DiameterTlsVersion::Tls12,
    )
    .await;
}
