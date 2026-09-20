//! SNI is an additional authenticated name constraint, never peer authority.

use super::*;
use crate::rfc6083::ServerName;

pub(crate) const NAME: &str = "amf.example.test";

pub(crate) fn fixture(names: &[&str], policy: Policy) -> (TestMaterial, Connector, Acceptor) {
    let ca = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let mut parameters = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .expect("synthetic DNS names");
    // A correct CN must not rescue a missing/wrong DNS SAN.
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, NAME);
    parameters.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(SERVER_ID).expect("SPIFFE URI"),
    ));
    parameters.not_before = now - time::Duration::minutes(1);
    parameters.not_after = now + time::Duration::hours(1);
    let key = rcgen::KeyPair::generate().expect("server key");
    let certificate = parameters.signed_by(&key, &ca).expect("server certificate");
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").expect("domain"),
        certificates: vec![ca.der().clone()],
    });
    let state = build_identity_state(
        vec![certificate.der().clone(), ca.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        bundles,
    )
    .expect("server material");
    let (client_source, client_rx) = watch::channel(Some(identity_state(CLIENT_ID, &ca)));
    let (server_source, server_rx) = watch::channel(Some(state));
    let material = TestMaterial {
        _ca: ca,
        client_source,
        _server_source: server_source,
        client_controller: material_controller(&client_rx, CLIENT_ID),
        server_controller: material_controller(&server_rx, SERVER_ID),
    };
    let name = ServerName::new(NAME).expect("bounded name");
    let connector = Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy)
        .expect("connector")
        .with_server_name(name.clone())
        .expect("client name");
    let acceptor = Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy)
        .expect("acceptor")
        .with_server_name(name)
        .expect("server name");
    (material, connector, acceptor)
}

pub(crate) async fn connect_pair(
    connector: &Connector,
    acceptor: &Acceptor,
) -> (
    Result<Connection, Error>,
    Result<Connection, Error>,
    SctpWireLog,
) {
    let (client, server, log) = in_memory_sctp_link(64);
    let deadline = Instant::now() + Duration::from_secs(3);
    let (client, server) = tokio::join!(
        connector.connect(
            Transport::in_memory(client, PayloadProtocol::Ngap),
            deadline
        ),
        acceptor.accept(
            Transport::in_memory(server, PayloadProtocol::Ngap),
            deadline
        ),
    );
    (client, server, log)
}

pub(crate) fn no_application(log: &SctpWireLog) {
    assert!(!log
        .records()
        .iter()
        .any(|r| r.record_header.is_some_and(|h| h[0] == 23)));
}

#[test]
fn bounded_server_names_reject_ambiguous_values_and_redact_diagnostics() {
    for value in [
        "",
        ".",
        "amf.example.test.",
        "127.0.0.1",
        "::1",
        "[::1]",
        "*.example.test",
        "a..test",
        "-a.test",
        "a-.test",
        "a_b.test",
        "a\0.test",
        "a/test",
        "a@test",
        "café.test",
        " a.test",
        "a.test ",
    ] {
        assert_eq!(
            ServerName::new(value).err(),
            Some(Error::PolicyRejected),
            "{value:?}"
        );
    }
    for invalid in [
        format!("{}.test", "a".repeat(64)),
        [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62),
        ]
        .join("."),
    ] {
        assert_eq!(ServerName::new(&invalid).err(), Some(Error::PolicyRejected));
    }
    let maximum = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(maximum.len(), 253);
    assert_eq!(
        ServerName::new(&maximum).expect("maximum").as_str(),
        maximum
    );
    for value in [
        "AMF.Example.TEST",
        "xn--bcher-kva.example",
        "a",
        "3gpp.test",
    ] {
        let name = ServerName::new(value).expect("ASCII name");
        assert_eq!(name.as_str(), value.to_ascii_lowercase());
        assert_eq!(format!("{name:#?}"), "ServerName([redacted])");
    }
}

#[tokio::test]
async fn named_mutual_connections_retain_name_identity_and_streams_across_rekey() {
    for cipher in DtlsSctpPolicy::default().allowed_ciphers() {
        let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 32)
            .expect("streams")
            .with_rekey()
            .with_allowed_ciphers(&[cipher])
            .expect("cipher");
        let (_material, connector, acceptor) =
            fixture(&["alias.example.test", "AMF.EXAMPLE.TEST"], policy);
        let (client, server, _) = connect_pair(&connector, &acceptor).await;
        let mut client = client.expect("named client");
        let mut server = server.expect("named server");
        let material_epoch = client
            .readback()
            .expect("initial evidence")
            .material_epoch();
        for epoch in 1..=3 {
            for connection in [&client, &server] {
                let evidence = connection.readback().expect("completed evidence");
                assert_eq!(evidence.server_name().map(ServerName::as_str), Some(NAME));
                assert_eq!(evidence.record_epoch(), epoch);
                assert_eq!(evidence.cipher(), cipher);
            }
            assert_eq!(client.readback().unwrap().material_epoch(), material_epoch);
            assert_eq!(client.readback().unwrap().expected_peer(), &peer(SERVER_ID));
            assert_eq!(server.readback().unwrap().expected_peer(), &peer(CLIENT_ID));
            let deadline = Instant::now() + Duration::from_secs(3);
            for stream in [0, 1, 15] {
                let payload = [epoch as u8, stream as u8];
                let (sent, received) = tokio::join!(
                    client.send_on_stream(stream, &payload, deadline),
                    server.receive(deadline)
                );
                sent.expect("client record");
                let received = received.expect("server record");
                assert_eq!(
                    (received.stream_id(), received.as_bytes()),
                    (stream, payload.as_slice())
                );
                let (sent, received) = tokio::join!(
                    server.send_on_stream(stream, &payload, deadline),
                    client.receive(deadline)
                );
                sent.expect("server record");
                assert_eq!(received.expect("client record").as_bytes(), payload);
            }
            if epoch < 3 {
                let (c, s) = tokio::join!(client.rekey(deadline), server.rekey(deadline));
                c.expect("same-name client rekey");
                s.expect("same-name server rekey");
            }
        }
    }
}

#[tokio::test]
async fn named_endpoints_refuse_missing_mismatched_names_and_wrong_local_certificate() {
    let policy = generic_policy(PayloadProtocol::Ngap);
    for names in [vec![], vec!["wrong.example.test"], vec!["*.example.test"]] {
        let (_material, connector, acceptor) = fixture(&names, policy);
        let (client, server, log) = connect_pair(&connector, &acceptor).await;
        assert_eq!(server.err(), Some(Error::MaterialNotAdmitted));
        assert!(client.is_err());
        no_application(&log);
    }
    let (material, connector, acceptor) = fixture(&[NAME, "other.example.test"], policy);
    let anonymous_client =
        Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy).unwrap();
    let anonymous_server =
        Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy).unwrap();
    let other_client = connector
        .clone()
        .with_server_name(ServerName::new("other.example.test").unwrap())
        .unwrap();
    for (client_endpoint, server_endpoint) in [
        (&anonymous_client, &acceptor),
        (&connector, &anonymous_server),
        (&other_client, &acceptor),
    ] {
        let (client, server, log) = connect_pair(client_endpoint, server_endpoint).await;
        assert!(client.is_err());
        assert!(server.is_err());
        no_application(&log);
    }
    let (client, server, _) = connect_pair(&anonymous_client, &anonymous_server).await;
    let (client, server) = (client.unwrap(), server.unwrap());
    assert!(client.readback().unwrap().server_name().is_none());
    assert!(server.readback().unwrap().server_name().is_none());
}

#[tokio::test]
async fn matching_dns_name_does_not_replace_exact_spiffe_peer_or_trust() {
    let policy = generic_policy(PayloadProtocol::Ngap);
    let (material, _, acceptor) = fixture(&[NAME], policy);
    let wrong_peer = Connector::new(
        material.client_controller.clone(),
        peer(OTHER_SERVER_ID),
        policy,
    )
    .unwrap()
    .with_server_name(ServerName::new(NAME).unwrap())
    .unwrap();
    let other_material = dtls_material();
    let untrusted = Connector::new(
        other_material.client_controller.clone(),
        peer(SERVER_ID),
        policy,
    )
    .unwrap()
    .with_server_name(ServerName::new(NAME).unwrap())
    .unwrap();
    for connector in [&wrong_peer, &untrusted] {
        let (client, server, log) = connect_pair(connector, &acceptor).await;
        assert!(client.is_err());
        assert!(server.is_err());
        no_application(&log);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated Linux SCTP-AUTH and sender-dry support"]
async fn generic_kernel_sni_preserves_name_through_rekey_and_delivery() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
        "requires a private network namespace"
    );
    let deadline = Instant::now() + Duration::from_secs(40);
    for cipher in DtlsSctpPolicy::default().allowed_ciphers() {
        let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 32)
            .unwrap()
            .with_rekey()
            .with_allowed_ciphers(&[cipher])
            .unwrap();
        let (_material, connector, acceptor) = fixture(&[NAME], policy);
        let (client, server) =
            kernel_associations(true, crate::MAX_DTLS_SCTP_RECORD_BYTES, deadline).await;
        let (client, server) = tokio::join!(
            connector.connect(
                Transport::from_sctp(client, PayloadProtocol::Ngap, 64).unwrap(),
                deadline
            ),
            acceptor.accept(
                Transport::from_sctp(server, PayloadProtocol::Ngap, 64).unwrap(),
                deadline
            ),
        );
        let (mut client, mut server) = (
            client.expect("named native client"),
            server.expect("named native server"),
        );
        for epoch in 1..=3 {
            for connection in [&client, &server] {
                let evidence = connection.readback().expect("native SNI evidence");
                assert_eq!(evidence.server_name().map(ServerName::as_str), Some(NAME));
                assert_eq!(evidence.record_epoch(), epoch);
                assert_eq!(evidence.cipher(), cipher);
            }
            for reverse in [false, true] {
                let (sender, receiver) = if reverse {
                    (&mut server, &mut client)
                } else {
                    (&mut client, &mut server)
                };
                for stream in [0, 1, 15] {
                    let payload = [epoch as u8, stream as u8, u8::from(reverse)];
                    let (sent, received) = tokio::join!(
                        sender.send_on_stream(stream, &payload, deadline),
                        receiver.receive(deadline)
                    );
                    sent.expect("named native send");
                    let received = received.expect("named native receive");
                    assert_eq!(
                        (received.stream_id(), received.as_bytes()),
                        (stream, payload.as_slice())
                    );
                }
            }
            if epoch < 3 {
                let (c, s) = tokio::join!(client.rekey(deadline), server.rekey(deadline));
                c.expect("named native client rekey");
                s.expect("named native server rekey");
            }
        }
        let (closed, peer) = tokio::join!(client.close(deadline), server.receive(deadline));
        closed.expect("named native reciprocal close");
        assert_eq!(peer.err(), Some(Error::PeerClosed));
    }
    println!("native protected SCTP SNI assertions completed: 3 ciphers, 6 transitions per peer");
}
