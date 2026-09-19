//! Independently signed operator-certificate constraints through the public seam.

use super::*;
use crate::rfc6083::{CertificateProfile, CrlPublisher, ServerName};

pub(crate) const VECTORS: &str =
    include_str!("../../../tests/fixtures/rfc6083/nds_certificates.tsv");

pub(crate) fn rows() -> impl Iterator<Item = Vec<&'static str>> {
    VECTORS
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split('\t').collect())
}

pub(crate) fn row(role: &str, case: &str) -> Vec<&'static str> {
    rows()
        .find(|v| v[0] == role && v[1] == case)
        .expect("independent certificate case")
}

pub(crate) fn der(value: &str) -> Vec<u8> {
    independent_der(value)
}

fn roots(rows: &[&[&str]]) -> TrustBundleSet {
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").unwrap(),
        certificates: rows
            .iter()
            .flat_map(|r| r[6].split(',').map(|v| CertificateDer::from(der(v))))
            .collect(),
    });
    bundles
}

pub(crate) fn material(
    row: &[&str],
    bundles: TrustBundleSet,
) -> (watch::Sender<Option<IdentityState>>, TlsMaterialController) {
    let mut chain = vec![CertificateDer::from(der(row[3]))];
    if !row[5].is_empty() {
        chain.push(CertificateDer::from(der(row[5])));
    }
    let state = build_identity_state(
        chain,
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der(row[4]))),
        bundles,
    )
    .expect("synthetic local material");
    let (sender, receiver) = watch::channel(Some(state));
    let controller = material_controller(
        &receiver,
        if row[0] == "client" {
            CLIENT_ID
        } else {
            SERVER_ID
        },
    );
    (sender, controller)
}

pub(crate) fn verifying_material(
    peer: &[&str],
) -> (
    watch::Sender<Option<IdentityState>>,
    TlsMaterialController,
    CrlPublisher,
) {
    let local = row(
        if peer[0] == "client" {
            "server"
        } else {
            "client"
        },
        "valid",
    );
    let (sender, controller) = material(&local, roots(&[&local, peer]));
    let mut publisher = CrlPublisher::new(&controller);
    publisher
        .publish(
            [local.as_slice(), peer]
                .iter()
                .flat_map(|r| r[7].split(',').map(der))
                .collect(),
        )
        .unwrap();
    (sender, controller, publisher)
}

pub(crate) struct Fixture {
    pub(crate) connector: Connector,
    pub(crate) acceptor: Acceptor,
    pub(crate) client_crls: CrlPublisher,
    pub(crate) server_crls: CrlPublisher,
    pub(crate) client_source: watch::Sender<Option<IdentityState>>,
    _server_source: watch::Sender<Option<IdentityState>>,
}

impl Fixture {
    pub(crate) fn new(client_case: &str, server_case: &str, policy: Policy) -> Self {
        let client = row("client", client_case);
        let server = row("server", server_case);
        let bundles = roots(&[&client, &server]);
        let (client_source, client_controller) = material(&client, bundles.clone());
        let (_server_source, server_controller) = material(&server, bundles);
        let lists: Vec<_> = [&client, &server]
            .iter()
            .flat_map(|r| r[7].split(',').map(der))
            .collect();
        let mut client_crls = CrlPublisher::new(&client_controller);
        let mut server_crls = CrlPublisher::new(&server_controller);
        client_crls
            .publish(lists.clone())
            .expect("client complete CRLs");
        server_crls.publish(lists).expect("server complete CRLs");
        let name = ServerName::new(sni::NAME).unwrap();
        let connector =
            Connector::new_with_required_crls(client_crls.source(), peer(SERVER_ID), policy)
                .unwrap()
                .with_certificate_profile(CertificateProfile::NdsAfEcdsa)
                .unwrap()
                .with_server_name(name.clone())
                .unwrap();
        let acceptor =
            Acceptor::new_with_required_crls(server_crls.source(), peer(CLIENT_ID), policy)
                .unwrap()
                .with_certificate_profile(CertificateProfile::NdsAfEcdsa)
                .unwrap()
                .with_server_name(name)
                .unwrap();
        Self {
            connector,
            acceptor,
            client_crls,
            server_crls,
            client_source,
            _server_source,
        }
    }

    pub(crate) async fn pair(
        &self,
    ) -> (
        Result<Connection, Error>,
        Result<Connection, Error>,
        SctpWireLog,
    ) {
        sni::connect_pair(&self.connector, &self.acceptor).await
    }
}

#[test]
fn certificate_profile_requires_explicit_revocation_source() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    assert_eq!(
        Connector::new(material.client_controller, peer(SERVER_ID), policy)
            .unwrap()
            .with_certificate_profile(CertificateProfile::NdsAfEcdsa)
            .err(),
        Some(Error::PolicyRejected)
    );
    assert_eq!(
        Acceptor::new(material.server_controller, peer(CLIENT_ID), policy)
            .unwrap()
            .with_certificate_profile(CertificateProfile::NdsAfEcdsa)
            .err(),
        Some(Error::PolicyRejected)
    );
    assert_eq!(
        format!("{:?}", CertificateProfile::NdsAfEcdsa),
        "NdsAfEcdsa"
    );
}

#[tokio::test]
async fn certificate_profile_accepts_independent_curves_names_roles_and_direct_ca() {
    for case in [
        "valid",
        "p384",
        "stronger-issuer",
        "sha384",
        "country-name",
        "domain-name",
        "optional-eku-absent",
        "direct-tls-anchor",
        "root-unlimited",
    ] {
        let fixture = Fixture::new(case, case, generic_policy(PayloadProtocol::Ngap));
        let (client, server, _) = fixture.pair().await;
        let mut client = client.unwrap_or_else(|e| panic!("{case}: {e:?}"));
        let mut server = server.unwrap_or_else(|e| panic!("{case}: {e:?}"));
        for connection in [&client, &server] {
            let evidence = connection.readback().unwrap();
            assert_eq!(
                evidence.certificate_profile(),
                Some(CertificateProfile::NdsAfEcdsa)
            );
            assert!(evidence.crls().is_some());
            assert_eq!(format!("{evidence:#?}"), "Evidence([redacted])");
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let (sent, received) =
            tokio::join!(client.send(b"profiled", deadline), server.receive(deadline));
        sent.unwrap();
        assert_eq!(received.unwrap().as_bytes(), b"profiled");
        let (a, b) = tokio::join!(client.close(deadline), server.close(deadline));
        a.unwrap();
        b.unwrap();
    }
}

#[tokio::test]
async fn certificate_profile_checks_local_leaf_ca_and_anchor_before_handshake() {
    for role in ["client", "server"] {
        for case in [
            "missing-crldp",
            "leaf-noncritical-ku",
            "tls-ca-depth-one",
            "root-noncritical-ku",
            "root-too-weak",
            "ambiguous-anchor",
        ] {
            let fixture = Fixture::new(
                if role == "client" { case } else { "valid" },
                if role == "server" { case } else { "valid" },
                generic_policy(PayloadProtocol::Ngap),
            );
            let (client, server, log) = fixture.pair().await;
            let error = if role == "client" {
                client.err()
            } else {
                server.err()
            };
            assert_eq!(error, Some(Error::MaterialNotAdmitted), "{role} {case}");
            sni::no_application(&log);
        }
    }
}

#[tokio::test]
async fn certificate_profile_readback_includes_selected_anchor_expiry() {
    let fixture = Fixture::new(
        "anchor-expiry",
        "anchor-expiry",
        generic_policy(PayloadProtocol::Ngap),
    );
    let (client, server, _) = fixture.pair().await;
    let (client, server) = (client.unwrap(), server.unwrap());
    let anchor_expiry = Timestamp::from_offset_datetime(
        time::Date::from_calendar_date(2050, time::Month::January, 1)
            .unwrap()
            .midnight()
            .assume_utc(),
    );
    for connection in [&client, &server] {
        let evidence = connection.readback().unwrap();
        assert_eq!(evidence.local_certificate_expires_at(), anchor_expiry);
        assert_eq!(evidence.peer_certificate_expires_at(), anchor_expiry);
    }
}

#[tokio::test]
async fn certificate_profile_rekey_retains_readback_and_revocation_retires_queued_data() {
    for cipher in DtlsSctpPolicy::default().allowed_ciphers() {
        let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 32)
            .unwrap()
            .with_rekey()
            .with_allowed_ciphers(&[cipher])
            .unwrap();
        let mut fixture = Fixture::new("valid", "valid", policy);
        let (client, server, _) = fixture.pair().await;
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        for epoch in 1..=3 {
            for connection in [&client, &server] {
                let evidence = connection.readback().unwrap();
                assert_eq!(
                    evidence.certificate_profile(),
                    Some(CertificateProfile::NdsAfEcdsa)
                );
                assert_eq!(evidence.record_epoch(), epoch);
                assert_eq!(evidence.cipher(), cipher);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let (sent, received) = tokio::join!(
                client.send_on_stream(15, b"profiled rekey", deadline),
                server.receive(deadline)
            );
            sent.unwrap();
            assert_eq!(received.unwrap().stream_id(), 15);
            if epoch < 3 {
                let (a, b) = tokio::join!(client.rekey(deadline), server.rekey(deadline));
                a.unwrap();
                b.unwrap();
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        client
            .send_on_stream(15, b"queued before CRL retirement", deadline)
            .await
            .unwrap();
        fixture.server_crls.withdraw();
        assert_eq!(server.readback().err(), Some(Error::Retired));
        assert_eq!(server.receive(deadline).await.err(), Some(Error::Retired));
        fixture.client_source.send_replace(None);
        assert_eq!(client.readback().err(), Some(Error::Retired));
        // Both publishers are held through the proof; dropping either is also
        // the already-qualified fail-closed revocation-source lifetime boundary.
        drop(fixture.client_crls);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated Linux SCTP-AUTH and sender-dry support"]
async fn generic_kernel_certificate_profile_preserves_path_through_rekey() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
        "requires a private network namespace"
    );
    let deadline = Instant::now() + Duration::from_secs(40);
    for (index, cipher) in DtlsSctpPolicy::default().allowed_ciphers().enumerate() {
        let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 32)
            .unwrap()
            .with_rekey()
            .with_allowed_ciphers(&[cipher])
            .unwrap();
        let case = ["valid", "p384", "stronger-issuer"][index];
        let fixture = Fixture::new(case, case, policy);
        let (connector, acceptor) = (&fixture.connector, &fixture.acceptor);
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
                assert_eq!(
                    evidence.server_name().map(ServerName::as_str),
                    Some(sni::NAME)
                );
                assert_eq!(
                    evidence.certificate_profile(),
                    Some(CertificateProfile::NdsAfEcdsa)
                );
                assert!(evidence.crls().is_some());
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
    println!("native protected SCTP certificate profile assertions completed: 3 ciphers, 6 transitions per peer");
}
