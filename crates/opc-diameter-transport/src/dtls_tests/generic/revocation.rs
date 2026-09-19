//! Independent CRL fixtures and protected connection lifetime qualification.
use super::*;
use crate::rfc6083::{
    CrlError, CrlPublisher, CrlSource, MAX_CRLS, MAX_CRL_BYTES, MAX_CRL_SET_BYTES,
};

const VECTORS: &str = include_str!("../../../tests/fixtures/rfc6083/revocation.tsv");

#[tokio::test]
async fn independent_revoked_peer_detector() {
    let row: Vec<_> = VECTORS
        .lines()
        .find(|line| line.starts_with("client\trevoked-leaf\t"))
        .expect("independent revoked peer")
        .split('\t')
        .collect();
    let local_ca = test_ca();
    let state = identity_state_with_trust(
        SERVER_ID,
        &local_ca,
        vec![
            local_ca.der().clone(),
            CertificateDer::from(independent_der(row[6])),
        ],
    );
    let (_source, rx) = watch::channel(Some(state));
    let controller = material_controller(&rx, SERVER_ID);
    let mut crls = CrlPublisher::new(&controller);
    crls.publish(row[7].split(',').map(independent_der).collect())
        .unwrap();
    let acceptor = Acceptor::new_with_required_crls(
        crls.source(),
        peer(CLIENT_ID),
        generic_policy(PayloadProtocol::Ngap),
    )
    .unwrap();
    let certificate = dimpl::DtlsCertificate {
        certificate: independent_der(row[3]),
        private_key: independent_der(row[4]),
        intermediates: vec![independent_der(row[5])],
    };
    let mut engine =
        dimpl::Dtls::new_12(raw_rfc6083_config(), certificate, std::time::Instant::now());
    engine.set_active(true);
    let (client, server, _) = in_memory_sctp_link(64);
    let deadline = Instant::now() + Duration::from_secs(5);
    let raw = tokio::spawn(drive_raw_engine_with_ppid(engine, client, deadline, 66));
    let result = acceptor
        .accept(
            Transport::in_memory(server, PayloadProtocol::Ngap),
            deadline,
        )
        .await;
    raw.abort();
    assert_eq!(result.err(), Some(Error::Authentication));
}

fn vectors() -> Vec<Vec<&'static str>> {
    VECTORS
        .lines()
        .filter(|v| !v.starts_with('#'))
        .map(|v| v.split('\t').collect())
        .collect()
}

fn fixture_crls(role: &str, case: &str) -> Vec<Vec<u8>> {
    vectors()
        .into_iter()
        .find(|v| v[0] == role && v[1] == case)
        .unwrap()[7]
        .split(',')
        .map(independent_der)
        .collect()
}

struct Materials {
    local: TlsMaterialController,
    remote: TlsMaterialController,
    local_source: watch::Sender<Option<IdentityState>>,
    _remote_source: watch::Sender<Option<IdentityState>>,
    role: &'static str,
}

impl Materials {
    fn new(role: &'static str) -> Self {
        let row = vectors()
            .into_iter()
            .find(|v| v[0] == role && v[1] == "valid")
            .unwrap();
        let (local_id, remote_id) = if role == "client" {
            (SERVER_ID, CLIENT_ID)
        } else {
            (CLIENT_ID, SERVER_ID)
        };
        let ca = test_ca();
        let state = identity_state_with_trust(
            local_id,
            &ca,
            vec![
                ca.der().clone(),
                CertificateDer::from(independent_der(row[6])),
            ],
        );
        let (local_source, local_rx) = watch::channel(Some(state));
        let local = material_controller(&local_rx, local_id);
        let mut trust = TrustBundleSet::new();
        trust.insert(TrustBundle {
            trust_domain: TrustDomain::new("example.test").unwrap(),
            certificates: vec![
                ca.der().clone(),
                CertificateDer::from(independent_der(row[6])),
            ],
        });
        let state = build_identity_state(
            vec![
                CertificateDer::from(independent_der(row[3])),
                CertificateDer::from(independent_der(row[5])),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(independent_der(row[4]))),
            trust,
        )
        .unwrap();
        let (_remote_source, remote_rx) = watch::channel(Some(state));
        let remote = material_controller(&remote_rx, remote_id);
        Self {
            local,
            remote,
            local_source,
            _remote_source,
            role,
        }
    }

    async fn pair(&self, source: CrlSource) -> (Connection, Connection, SctpWireLog) {
        self.pair_with_policy(source, generic_policy(PayloadProtocol::Ngap))
            .await
    }

    async fn pair_with_policy(
        &self,
        source: CrlSource,
        policy: Policy,
    ) -> (Connection, Connection, SctpWireLog) {
        let (local, remote, log) = in_memory_sctp_link(64);
        let deadline = Instant::now() + Duration::from_secs(5);
        let local = Transport::in_memory(local, PayloadProtocol::Ngap);
        let remote = Transport::in_memory(remote, PayloadProtocol::Ngap);
        let (local, remote) = if self.role == "client" {
            let acceptor =
                Acceptor::new_with_required_crls(source, peer(CLIENT_ID), policy).unwrap();
            let connector = Connector::new(self.remote.clone(), peer(SERVER_ID), policy).unwrap();
            tokio::join!(
                acceptor.accept(local, deadline),
                connector.connect(remote, deadline)
            )
        } else {
            let connector =
                Connector::new_with_required_crls(source, peer(SERVER_ID), policy).unwrap();
            let acceptor = Acceptor::new(self.remote.clone(), peer(CLIENT_ID), policy).unwrap();
            tokio::join!(
                connector.connect(local, deadline),
                acceptor.accept(remote, deadline)
            )
        };
        (local.unwrap(), remote.unwrap(), log)
    }
}

#[tokio::test]
async fn required_crls_retire_queued_nonzero_streams_in_both_roles() {
    for role in ["client", "server"] {
        for replace in [false, true] {
            let material = Materials::new(role);
            let mut publication = CrlPublisher::new(&material.local);
            publication.publish(fixture_crls(role, "valid")).unwrap();
            let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 8).unwrap();
            let (mut local, mut remote, log) = material
                .pair_with_policy(publication.source(), policy)
                .await;
            let deadline = Instant::now() + Duration::from_secs(5);
            remote
                .send_on_stream(2, b"synthetic", deadline)
                .await
                .unwrap();
            let received = local.receive(deadline).await.unwrap();
            assert_eq!(received.stream_id(), 2);
            assert_eq!(received.as_bytes(), b"synthetic");
            remote.send_on_stream(3, b"queued", deadline).await.unwrap();
            if replace {
                publication.publish(fixture_crls(role, "newer")).unwrap();
            } else {
                publication.withdraw();
            }
            assert_eq!(local.readback().err(), Some(Error::Retired));
            let sent = log.records().len();
            assert_eq!(local.receive(deadline).await.err(), Some(Error::Retired));
            assert_eq!(
                local.send_on_stream(1, b"refused", deadline).await.err(),
                Some(Error::Retired)
            );
            assert_eq!(log.records().len(), sent);
        }
    }
}

#[tokio::test]
async fn publication_changes_retire_readback_and_queued_delivery_synchronously() {
    for role in ["client", "server"] {
        for action in [
            "replace",
            "identical",
            "withdraw",
            "drop",
            "malformed",
            "rollback",
            "credential",
        ] {
            let material = Materials::new(role);
            let mut publication = CrlPublisher::new(&material.local);
            publication.publish(fixture_crls(role, "valid")).unwrap();
            let (mut local, mut remote, log) = material.pair(publication.source()).await;
            let mut publication = Some(publication);
            let deadline = Instant::now() + Duration::from_secs(5);
            remote
                .send(b"synthetic queued record one", deadline)
                .await
                .unwrap();
            remote
                .send(b"synthetic queued record two", deadline)
                .await
                .unwrap();
            assert_eq!(
                local.receive(deadline).await.unwrap().as_bytes(),
                b"synthetic queued record one"
            );
            match action {
                "replace" => {
                    publication
                        .as_mut()
                        .unwrap()
                        .publish(fixture_crls(role, "newer"))
                        .unwrap();
                }
                "identical" => {
                    publication
                        .as_mut()
                        .unwrap()
                        .publish(fixture_crls(role, "valid"))
                        .unwrap();
                }
                "withdraw" => publication.as_mut().unwrap().withdraw(),
                "drop" => {
                    drop(publication.take());
                }
                "malformed" => assert_eq!(
                    publication.as_mut().unwrap().publish(vec![vec![0]]).err(),
                    Some(CrlError::ProfileRejected)
                ),
                "rollback" => assert_eq!(
                    publication
                        .as_mut()
                        .unwrap()
                        .publish(fixture_crls(role, "revoked-leaf"))
                        .err(),
                    Some(CrlError::RollbackRejected)
                ),
                "credential" => {
                    material.local_source.send_replace(None);
                }
                _ => unreachable!(),
            }
            // No scheduler yield before readback: watcher scheduling cannot
            // extend the lifetime of an obsolete protection observation.
            assert_eq!(
                local.readback().err(),
                Some(Error::Retired),
                "{role} {action}"
            );
            let sent = log.records().len();
            assert_eq!(local.receive(deadline).await.err(), Some(Error::Retired));
            assert_eq!(
                local.send(b"must not be sent", deadline).await.err(),
                Some(Error::Retired)
            );
            assert_eq!(log.records().len(), sent);
            if let Some(publication) = publication.as_mut() {
                publication.publish(fixture_crls(role, "newer")).unwrap();
                assert_eq!(local.readback().err(), Some(Error::Retired), "no revival");
            }
        }
    }
}

#[tokio::test]
async fn withdrawn_source_interrupts_pending_receive_and_handshake() {
    for role in ["client", "server"] {
        let material = Materials::new(role);
        let mut publication = CrlPublisher::new(&material.local);
        publication.publish(fixture_crls(role, "valid")).unwrap();
        let (mut local, _remote, _) = material.pair(publication.source()).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let receiving = local.receive(deadline);
        tokio::pin!(receiving);
        std::future::poll_fn(|cx| {
            assert!(receiving.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        publication.withdraw();
        let result = tokio::time::timeout(Duration::from_secs(1), receiving)
            .await
            .unwrap();
        assert_eq!(result.err(), Some(Error::Retired));

        let mut publication = CrlPublisher::new(&material.local);
        publication.publish(fixture_crls(role, "valid")).unwrap();
        let (local, _remote, _) = in_memory_sctp_link(64);
        let carrier = Transport::in_memory(local, PayloadProtocol::Ngap);
        let connector = Connector::new_with_required_crls(
            publication.source(),
            peer(SERVER_ID),
            generic_policy(PayloadProtocol::Ngap),
        )
        .unwrap();
        let acceptor = Acceptor::new_with_required_crls(
            publication.source(),
            peer(CLIENT_ID),
            generic_policy(PayloadProtocol::Ngap),
        )
        .unwrap();
        let establishing = async {
            if role == "client" {
                acceptor.accept(carrier, deadline).await
            } else {
                connector.connect(carrier, deadline).await
            }
        };
        tokio::pin!(establishing);
        std::future::poll_fn(|cx| {
            assert!(establishing.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        publication.withdraw();
        let result = tokio::time::timeout(Duration::from_secs(1), establishing)
            .await
            .unwrap();
        assert_eq!(result.err(), Some(Error::Retired));
    }
}

#[tokio::test]
async fn unavailable_and_obsolete_sources_never_fall_back_to_legacy_handshakes() {
    for mode in ["empty", "closed", "epoch"] {
        let material = Materials::new("server");
        let mut publisher = CrlPublisher::new(&material.local);
        if mode != "empty" {
            publisher.publish(fixture_crls("server", "valid")).unwrap();
        }
        let source = publisher.source();
        if mode == "closed" {
            drop(publisher);
        }
        if mode == "epoch" {
            let state = material.local_source.borrow().clone();
            material.local_source.send_replace(None);
            let _ = material.local.status();
            material.local_source.send_replace(state);
            let _ = material.local.status();
        }
        let endpoint = Connector::new_with_required_crls(
            source,
            peer(SERVER_ID),
            generic_policy(PayloadProtocol::Ngap),
        )
        .unwrap();
        let (local, _remote, log) = in_memory_sctp_link(64);
        let result = endpoint
            .connect(
                Transport::in_memory(local, PayloadProtocol::Ngap),
                Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert_eq!(result.err(), Some(Error::MaterialNotAdmitted), "{mode}");
        assert!(log.records().is_empty());
    }
}

#[tokio::test]
async fn publication_bounds_rollback_and_redaction() {
    let material = Materials::new("server");
    let mut publisher = CrlPublisher::new(&material.local);
    for invalid in [
        Vec::new(),
        vec![vec![0]; MAX_CRLS + 1],
        vec![vec![0; MAX_CRL_BYTES + 1]],
        vec![vec![0; MAX_CRL_BYTES]; MAX_CRL_SET_BYTES / MAX_CRL_BYTES + 1],
    ] {
        assert_eq!(
            publisher.publish(invalid).err(),
            Some(CrlError::ProfileRejected)
        );
    }
    let first = publisher.publish(fixture_crls("server", "valid")).unwrap();
    let newer = publisher.publish(fixture_crls("server", "newer")).unwrap();
    assert_ne!(first, newer);
    publisher.withdraw();
    assert_eq!(
        publisher.publish(fixture_crls("server", "valid")).err(),
        Some(CrlError::RollbackRejected)
    );
    assert_eq!(format!("{publisher:?}"), "CrlPublisher([redacted])");
    assert_eq!(format!("{:?}", publisher.source()), "CrlSource([redacted])");
    assert_eq!(format!("{first:?}"), "CrlGeneration([redacted])");
}

fn crl_ca(name: &str) -> TestCa {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap()).unwrap()
}

fn runtime_crl(ca: &TestCa, number: u64, until: time::OffsetDateTime) -> Vec<u8> {
    rcgen::CertificateRevocationListParams {
        this_update: time::OffsetDateTime::now_utc() - time::Duration::minutes(1),
        next_update: until,
        crl_number: rcgen::SerialNumber::from(number),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(ca)
    .unwrap()
    .der()
    .to_vec()
}

#[tokio::test]
async fn crl_expiry_shortens_the_connection_lifetime() {
    // Runtime-generated timing input supplements the stable independent
    // vectors; it is not presented as independent wire provenance.
    let ca = crl_ca("Synthetic short-lived CRL issuer");
    let (_client_source, client_rx) = watch::channel(Some(identity_state(CLIENT_ID, &ca)));
    let (_server_source, server_rx) = watch::channel(Some(identity_state(SERVER_ID, &ca)));
    let client = material_controller(&client_rx, CLIENT_ID);
    let server = material_controller(&server_rx, SERVER_ID);
    let mut publisher = CrlPublisher::new(&client);
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(30);
    publisher
        .publish(vec![runtime_crl(&ca, 1, expires)])
        .unwrap();
    let policy = generic_policy(PayloadProtocol::Ngap);
    let connector =
        Connector::new_with_required_crls(publisher.source(), peer(SERVER_ID), policy).unwrap();
    let acceptor = Acceptor::new(server, peer(CLIENT_ID), policy).unwrap();
    let (local, remote, _) = in_memory_sctp_link(64);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (local, remote) = tokio::join!(
        connector.connect(Transport::in_memory(local, PayloadProtocol::Ngap), deadline),
        acceptor.accept(
            Transport::in_memory(remote, PayloadProtocol::Ngap),
            deadline
        )
    );
    let local = local.unwrap();
    let _remote = remote.unwrap();
    let evidence = local.readback().unwrap();
    assert!(evidence.crls().unwrap().expires_at() < evidence.local_certificate_expires_at());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(local.readback().err(), Some(Error::Retired));
}

#[tokio::test]
async fn bounded_issuer_floors_survive_removal_from_the_current_publication() {
    let material = Materials::new("server");
    let mut publisher = CrlPublisher::new(&material.local);
    let until = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let crls: Vec<_> = (0..MAX_CRLS)
        .map(|i| runtime_crl(&crl_ca(&format!("Synthetic bounded issuer {i}")), 1, until))
        .collect();
    publisher.publish(crls.clone()).unwrap();
    publisher.publish(vec![crls[0].clone()]).unwrap();
    let added = runtime_crl(&crl_ca("Synthetic issuer beyond lifetime bound"), 1, until);
    assert_eq!(
        publisher.publish(vec![added]).err(),
        Some(CrlError::ProfileRejected)
    );
    publisher.publish(crls).unwrap();
}

#[tokio::test]
async fn independent_crls_qualify_both_mutual_authentication_roles() {
    let rows = vectors();
    assert_eq!(rows.len(), 52);
    for row in rows {
        let local_id = if row[0] == "client" {
            SERVER_ID
        } else {
            CLIENT_ID
        };
        let expected_id = if row[0] == "client" {
            CLIENT_ID
        } else {
            SERVER_ID
        };
        let local_ca = test_ca();
        let state = identity_state_with_trust(
            local_id,
            &local_ca,
            vec![
                local_ca.der().clone(),
                CertificateDer::from(independent_der(row[6])),
            ],
        );
        let (_source, rx) = watch::channel(Some(state));
        let controller = material_controller(&rx, local_id);
        let mut publisher = CrlPublisher::new(&controller);
        let publication = publisher.publish(row[7].split(',').map(independent_der).collect());
        if row[2] == "profile" {
            assert_eq!(
                publication.err(),
                Some(CrlError::ProfileRejected),
                "{} {}",
                row[0],
                row[1]
            );
            continue;
        }
        let generation = publication.expect("syntactically supported independent CRLs");
        let mut trust = TrustBundleSet::new();
        trust.insert(TrustBundle {
            trust_domain: TrustDomain::new("example.test").unwrap(),
            certificates: vec![
                local_ca.der().clone(),
                CertificateDer::from(independent_der(row[6])),
            ],
        });
        let remote_state = build_identity_state(
            vec![
                CertificateDer::from(independent_der(row[3])),
                CertificateDer::from(independent_der(row[5])),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(independent_der(row[4]))),
            trust,
        )
        .unwrap();
        let (_remote_source, remote_rx) = watch::channel(Some(remote_state));
        let remote_controller = material_controller(&remote_rx, expected_id);
        let (local, remote, log) = in_memory_sctp_link(64);
        let deadline = Instant::now() + Duration::from_secs(5);
        let carrier = Transport::in_memory(local, PayloadProtocol::Ngap);
        let remote_carrier = Transport::in_memory(remote, PayloadProtocol::Ngap);
        let policy = generic_policy(PayloadProtocol::Ngap);
        let (result, other) = if row[0] == "client" {
            let local =
                Acceptor::new_with_required_crls(publisher.source(), peer(expected_id), policy)
                    .unwrap();
            let remote = Connector::new(remote_controller, peer(local_id), policy).unwrap();
            tokio::join!(
                local.accept(carrier, deadline),
                remote.connect(remote_carrier, deadline)
            )
        } else {
            let local =
                Connector::new_with_required_crls(publisher.source(), peer(expected_id), policy)
                    .unwrap();
            let remote = Acceptor::new(remote_controller, peer(local_id), policy).unwrap();
            tokio::join!(
                local.connect(carrier, deadline),
                remote.accept(remote_carrier, deadline)
            )
        };
        if row[2] == "admit" {
            let connection = result.unwrap_or_else(|e| panic!("{} {}: {e}", row[0], row[1]));
            let readback = connection.readback().unwrap();
            let revocation = readback.crls().expect("required CRL readback");
            assert_eq!(revocation.generation(), generation);
            assert_eq!(revocation.material_epoch(), readback.material_epoch());
            assert_eq!(format!("{revocation:?}"), "CrlEvidence([redacted])");
            assert_eq!(readback.expected_peer(), &peer(expected_id));
        } else {
            assert_eq!(
                result.err(),
                Some(Error::Authentication),
                "{} {}",
                row[0],
                row[1]
            );
        }
        drop(other);
        assert!(log
            .records()
            .iter()
            .all(|v| v.ppid == 66 && v.record_header.is_none_or(|v| v[0] != 23)));
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated Linux SCTP-AUTH and sender-dry support"]
async fn generic_kernel_required_crls_retire_both_roles() {
    for role in ["client", "server"] {
        let material = Materials::new(role);
        let mut publisher = CrlPublisher::new(&material.local);
        let generation = publisher.publish(fixture_crls(role, "valid")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let (client, server) =
            kernel_associations(true, crate::MAX_DTLS_SCTP_RECORD_BYTES, deadline).await;
        let client = Transport::from_sctp(client, PayloadProtocol::Ngap, 64).unwrap();
        let server = Transport::from_sctp(server, PayloadProtocol::Ngap, 64).unwrap();
        let policy = generic_policy(PayloadProtocol::Ngap);
        let (local, remote) = if role == "client" {
            let acceptor =
                Acceptor::new_with_required_crls(publisher.source(), peer(CLIENT_ID), policy)
                    .unwrap();
            let connector =
                Connector::new(material.remote.clone(), peer(SERVER_ID), policy).unwrap();
            tokio::join!(
                acceptor.accept(server, deadline),
                connector.connect(client, deadline)
            )
        } else {
            let connector =
                Connector::new_with_required_crls(publisher.source(), peer(SERVER_ID), policy)
                    .unwrap();
            let acceptor = Acceptor::new(material.remote.clone(), peer(CLIENT_ID), policy).unwrap();
            tokio::join!(
                connector.connect(client, deadline),
                acceptor.accept(server, deadline)
            )
        };
        let mut local = local.expect("native required-CRL handshake");
        let mut remote = remote.expect("native peer handshake");
        assert_eq!(
            local.readback().unwrap().crls().unwrap().generation(),
            generation
        );
        let (sent, received) = tokio::join!(
            remote.send(b"synthetic native revocation record", deadline),
            local.receive(deadline)
        );
        sent.unwrap();
        assert_eq!(
            received.unwrap().as_bytes(),
            b"synthetic native revocation record"
        );
        publisher.withdraw();
        assert_eq!(local.readback().err(), Some(Error::Retired));
        assert_eq!(
            local.send(b"must not escape", deadline).await.err(),
            Some(Error::Retired)
        );
        assert_eq!(local.receive(deadline).await.err(), Some(Error::Retired));
    }
}
