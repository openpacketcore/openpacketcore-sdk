//! DTLS/SCTP transport integration tests over the deterministic in-memory
//! SCTP message seam. These tests prove the RFC 6733 direct-protection
//! sequencing and RFC 6083 PPID-47 carriage without requiring kernel SCTP.

use std::time::Duration;

use bytes::Bytes;
use opc_proto_diameter::base::RESULT_CODE_DIAMETER_SUCCESS;
use opc_proto_diameter::peer::{
    AnswerDiagnostics, CapabilitiesExchangeAnswer, HostIpAddress, PeerCapabilities, PeerIdentity,
    PeerProtectionPolicy, PeerProtectionRequirement, PeerProtectionSequence, PeerSession,
    PeerSessionPolicy,
};
use opc_proto_diameter::{
    ApplicationId, CommandCode, CommandFlags, Header, OwnedMessage, VendorId,
};
use tokio::sync::watch;
use tokio::time::Instant;

use opc_identity::{build_identity_state, IdentityState, TrustBundle, TrustBundleSet, TrustDomain};
use opc_tls::{TlsMaterialController, TlsMaterialStatusReceiver};
use opc_types::SpiffeId;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use opc_diameter_transport::{
    in_memory_sctp_link, DiameterCapabilitiesExchangeOutcome, DiameterDtlsSctpAcceptor,
    DiameterDtlsSctpConnection, DiameterDtlsSctpConnector, DiameterTlsError, DtlsSctpPolicy,
    DtlsSctpVersion, ExpectedPeerIdentity, InMemorySctpEndpoint, SctpMessageIo, SctpWireLog,
    DIAMETER_DTLS_SCTP_PPID,
};

const CLIENT_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/smf/instance/client-0";
const OTHER_CLIENT_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/smf/instance/client-1";
const SERVER_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/aaa/instance/server-0";
const OTHER_SERVER_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/aaa/instance/server-1";
const APP_ID: ApplicationId = ApplicationId::new(16_777_264);

type TestCa = rcgen::CertifiedIssuer<'static, rcgen::KeyPair>;

struct TestMaterial {
    _ca: TestCa,
    client_source: watch::Sender<Option<IdentityState>>,
    _server_source: watch::Sender<Option<IdentityState>>,
    client_rx: watch::Receiver<Option<IdentityState>>,
    server_rx: watch::Receiver<Option<IdentityState>>,
    client_status: TlsMaterialStatusReceiver,
    server_status: TlsMaterialStatusReceiver,
}

fn test_ca() -> TestCa {
    let mut parameters = rcgen::CertificateParams::default();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Diameter DTLS test CA");
    let key = rcgen::KeyPair::generate().expect("generate test CA key");
    rcgen::CertifiedIssuer::self_signed(parameters, key).expect("sign test CA")
}

fn identity_state(spiffe_id: &str, ca: &TestCa) -> IdentityState {
    identity_state_with_trust(spiffe_id, ca, vec![ca.der().clone()])
}

fn identity_state_with_trust(
    spiffe_id: &str,
    ca: &TestCa,
    trusted_certificates: Vec<CertificateDer<'static>>,
) -> IdentityState {
    let now = time::OffsetDateTime::now_utc();
    identity_state_with_validity_and_trust(
        spiffe_id,
        ca,
        trusted_certificates,
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    )
}

fn identity_state_with_validity_and_trust(
    spiffe_id: &str,
    ca: &TestCa,
    trusted_certificates: Vec<CertificateDer<'static>>,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> IdentityState {
    let mut parameters = rcgen::CertificateParams::default();
    parameters.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("valid SPIFFE URI"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = rcgen::KeyPair::generate().expect("generate leaf key");
    let certificate = parameters.signed_by(&key, ca).expect("sign test leaf");
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").expect("trust domain"),
        certificates: trusted_certificates,
    });
    build_identity_state(
        vec![certificate.der().clone(), ca.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        bundles,
    )
    .expect("build identity state")
}

fn material_controller(
    rx: &watch::Receiver<Option<IdentityState>>,
    spiffe_id: &str,
) -> TlsMaterialController {
    TlsMaterialController::new_pinned(
        rx.clone(),
        SpiffeId::new(spiffe_id).expect("valid local SPIFFE ID"),
    )
}

fn dtls_material() -> TestMaterial {
    let ca = test_ca();
    let (client_source, client_rx) = watch::channel(Some(identity_state(CLIENT_ID, &ca)));
    let (server_source, server_rx) = watch::channel(Some(identity_state(SERVER_ID, &ca)));
    let client_status = material_controller(&client_rx, CLIENT_ID).subscribe_material_changes();
    let server_status = material_controller(&server_rx, SERVER_ID).subscribe_material_changes();
    TestMaterial {
        _ca: ca,
        client_source,
        _server_source: server_source,
        client_rx,
        server_rx,
        client_status,
        server_status,
    }
}

fn direct_session(host: &str) -> PeerSession {
    PeerSession::with_policy_and_protection(
        capabilities(host),
        peer_policy(),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::direct_dtls_sctp()),
    )
}

fn capabilities(host: &str) -> PeerCapabilities {
    let mut capabilities = PeerCapabilities::new(
        PeerIdentity::new(host, "example.test"),
        vec![HostIpAddress::ipv4([192, 0, 2, 10])],
        VendorId::new(10_415),
        "transport-test",
    );
    capabilities.auth_application_ids = vec![APP_ID];
    capabilities
}

fn peer_policy() -> PeerSessionPolicy {
    PeerSessionPolicy::default().accept_application(APP_ID)
}

fn application_request() -> OwnedMessage {
    OwnedMessage {
        header: Header::new(
            CommandFlags::request(true),
            CommandCode::new(268),
            APP_ID,
            0x100,
            0x200,
        ),
        raw_avps: Bytes::new(),
    }
}

fn expected(value: &str) -> ExpectedPeerIdentity {
    let origin_host = if value == SERVER_ID || value == OTHER_SERVER_ID {
        "server.example.test"
    } else {
        "client.example.test"
    };
    ExpectedPeerIdentity::new(
        SpiffeId::new(value).expect("valid expected SPIFFE ID"),
        PeerIdentity::new(origin_host, "example.test"),
    )
    .expect("valid expected Diameter identity")
}

fn connector(
    material: &TestMaterial,
    expected_peer: ExpectedPeerIdentity,
    policy: DtlsSctpPolicy,
) -> DiameterDtlsSctpConnector {
    DiameterDtlsSctpConnector::new(
        material.client_rx.clone(),
        material.client_status.clone(),
        expected_peer,
        policy,
    )
}

fn acceptor(
    material: &TestMaterial,
    expected_peer: ExpectedPeerIdentity,
    policy: DtlsSctpPolicy,
) -> DiameterDtlsSctpAcceptor {
    DiameterDtlsSctpAcceptor::new(
        material.server_rx.clone(),
        material.server_status.clone(),
        expected_peer,
        policy,
    )
}

async fn establish_pair(
    material: &TestMaterial,
    client_policy: DtlsSctpPolicy,
    server_policy: DtlsSctpPolicy,
) -> Result<
    (
        DiameterDtlsSctpConnection,
        DiameterDtlsSctpConnection,
        SctpWireLog,
    ),
    DiameterTlsError,
> {
    let (client_io, server_io, log) = in_memory_sctp_link(64);
    let acceptor = acceptor(material, expected(CLIENT_ID), server_policy);
    let connector = connector(material, expected(SERVER_ID), client_policy);
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let client = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await?;
    let server = server
        .await
        .expect("join acceptor")
        .expect("accept Diameter DTLS/SCTP");
    Ok((client, server, log))
}

fn assert_wire_records_only_ppid47(log: &SctpWireLog) {
    let records = log.records();
    assert!(
        records.len() >= 2,
        "handshake must emit DTLS records: {records:?}"
    );
    assert!(
        records
            .iter()
            .all(|record| record.ppid == DIAMETER_DTLS_SCTP_PPID),
        "every emitted record must carry PPID 47: {records:?}"
    );
}

#[tokio::test]
async fn direct_pair_establishes_mutual_dtls13_before_any_diameter_byte() {
    let material = dtls_material();
    let (mut client, mut server, log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");

    assert_eq!(client.evidence().version(), DtlsSctpVersion::Dtls13);
    assert_eq!(server.evidence().version(), DtlsSctpVersion::Dtls13);
    assert_eq!(
        client.evidence().protection().sequence(),
        PeerProtectionSequence::DirectBeforeCapabilities
    );
    assert!(client
        .protection_readiness()
        .expect("client readiness")
        .protected_ready());
    assert!(server
        .protection_readiness()
        .expect("server readiness")
        .protected_ready());

    // Wire evidence: every emission so far is a PPID-47 DTLS record; no
    // readable Diameter byte crossed the link before protection was ready.
    assert_wire_records_only_ppid47(&log);

    let deadline = Instant::now() + Duration::from_secs(5);
    let (sent, received) = tokio::join!(
        client.send_capabilities_request(0x1234, 0x5678, deadline),
        server.receive_capabilities_request(deadline),
    );
    assert!(sent.expect("send CER").is_protected());
    assert_eq!(
        received.expect("receive CER"),
        capabilities("client.example.test")
    );
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: capabilities("server.example.test"),
        diagnostics: AnswerDiagnostics::default(),
    };
    let (emitted, observed) = tokio::join!(
        server.send_capabilities_answer(&answer, deadline),
        client.receive_capabilities_answer(deadline),
    );
    assert!(matches!(
        emitted.expect("emit CEA"),
        DiameterCapabilitiesExchangeOutcome::Negotiated(_)
    ));
    let (_, outcome) = observed.expect("receive CEA");
    assert!(outcome.is_negotiated());
    assert!(client.readiness().expect("client readiness").traffic_ready);
    assert!(server.readiness().expect("server readiness").traffic_ready);

    let request = application_request();
    let (sent, received) = tokio::join!(
        client.send_message(&request, deadline),
        server.receive_message(deadline),
    );
    sent.expect("send application request");
    let (received, _) = received.expect("receive application request");
    assert_eq!(received.header, request.header);

    // The entire session, application traffic included, emitted only PPID 47.
    assert_wire_records_only_ppid47(&log);

    let client_session = client.close(deadline).await.expect("close client");
    let server_session = server.close(deadline).await.expect("close server");
    drop(client_session);
    drop(server_session);
}

#[tokio::test]
async fn dtls12_compatibility_negotiates_when_policy_admits_it() {
    let material = dtls_material();
    let policy = DtlsSctpPolicy::default().with_dtls12_compatibility();
    let (client, server, log) = establish_pair(&material, policy, policy)
        .await
        .expect("establish compatibility association");
    // Both peers support 1.3, so auto-sense must prefer it.
    assert_eq!(client.evidence().version(), DtlsSctpVersion::Dtls13);
    assert_eq!(server.evidence().version(), DtlsSctpVersion::Dtls13);
    assert_wire_records_only_ppid47(&log);
}

#[tokio::test]
async fn wrong_peer_identity_fails_closed_without_diameter_processing() {
    let material = dtls_material();
    let ca = test_ca();
    let (other_source, other_rx) = watch::channel(Some(identity_state(OTHER_SERVER_ID, &ca)));
    let _ = other_source;
    // Client trusts the OTHER server's CA too, so chain validation passes and
    // only the exact-identity check can fail the association.
    let client_state = {
        let now = time::OffsetDateTime::now_utc();
        identity_state_with_validity_and_trust(
            CLIENT_ID,
            &material._ca,
            vec![material._ca.der().clone(), ca.der().clone()],
            now - time::Duration::minutes(1),
            now + time::Duration::hours(1),
        )
    };
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let (client_source, client_rx) = watch::channel(Some(client_state));
    let _ = client_source;
    let client_status = material_controller(&client_rx, CLIENT_ID).subscribe_material_changes();
    let server_status =
        material_controller(&other_rx, OTHER_SERVER_ID).subscribe_material_changes();
    let policy = DtlsSctpPolicy::default();
    let acceptor =
        DiameterDtlsSctpAcceptor::new(other_rx.clone(), server_status, expected(CLIENT_ID), policy);
    let connector = DiameterDtlsSctpConnector::new(
        client_rx.clone(),
        client_status,
        expected(SERVER_ID),
        policy,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let client_result = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await;
    assert_eq!(
        client_result.err(),
        Some(DiameterTlsError::PeerIdentityMismatch)
    );
    let server_result = server.await.expect("join acceptor");
    assert!(server_result.is_err(), "server must fail closed");
}

#[tokio::test]
async fn unknown_ca_fails_closed() {
    let material = dtls_material();
    let stranger_ca = test_ca();
    // The server authenticates with a certificate chain the client does not
    // trust; the server's own view of its chain is coherent.
    let (_server_source, server_rx) = watch::channel(Some(identity_state(SERVER_ID, &stranger_ca)));
    let server_status = material_controller(&server_rx, SERVER_ID).subscribe_material_changes();
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let policy = DtlsSctpPolicy::default();
    let acceptor = DiameterDtlsSctpAcceptor::new(
        server_rx.clone(),
        server_status,
        expected(CLIENT_ID),
        policy,
    );
    let connector = connector(&material, expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let client_result = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await;
    assert_eq!(client_result.err(), Some(DiameterTlsError::Authentication));
    assert!(server.await.expect("join acceptor").is_err());
}

#[tokio::test]
async fn expired_local_material_is_not_admitted() {
    let material = dtls_material();
    let now = time::OffsetDateTime::now_utc();
    // A snapshot that is admissible now but expires almost immediately.
    let short_lived_server = identity_state_with_validity_and_trust(
        SERVER_ID,
        &material._ca,
        vec![material._ca.der().clone()],
        now - time::Duration::minutes(1),
        now + time::Duration::seconds(1),
    );
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let (_server_source, server_rx) = watch::channel(Some(short_lived_server));
    let server_status = material_controller(&server_rx, SERVER_ID).subscribe_material_changes();
    // Let the admitted material expire before the acceptor snapshots it.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let policy = DtlsSctpPolicy::default();
    let acceptor = DiameterDtlsSctpAcceptor::new(
        server_rx.clone(),
        server_status,
        expected(CLIENT_ID),
        policy,
    );
    let connector = connector(&material, expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let client_result = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await;
    assert_eq!(
        server.await.expect("join acceptor").err(),
        Some(DiameterTlsError::MaterialNotAdmitted)
    );
    assert!(client_result.is_err(), "connector must fail closed");
}

fn raw_certificate_with_validity(
    spiffe_id: &str,
    ca: &TestCa,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> dimpl::DtlsCertificate {
    let mut parameters = rcgen::CertificateParams::default();
    parameters.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("valid SPIFFE URI"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = rcgen::KeyPair::generate().expect("generate raw key");
    let certificate = parameters.signed_by(&key, ca).expect("sign raw leaf");
    dimpl::DtlsCertificate {
        certificate: certificate.der().to_vec(),
        private_key: key.serialize_der(),
    }
}

async fn raw_client_against_acceptor(
    material: &TestMaterial,
    certificate: dimpl::DtlsCertificate,
) -> DiameterTlsError {
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let acceptor = acceptor(material, expected(CLIENT_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let config = std::sync::Arc::new(dimpl::Config::default());
    let mut engine = dimpl::Dtls::new_13(config, certificate, std::time::Instant::now());
    engine.set_active(true);
    let raw = tokio::spawn(drive_raw_engine(engine, client_io, deadline));
    let server_result = server.await.expect("join acceptor");
    let _ = raw.await;
    server_result.expect_err("acceptor must reject the peer certificate")
}

#[tokio::test]
async fn not_yet_valid_peer_certificate_fails_closed() {
    let material = dtls_material();
    let now = time::OffsetDateTime::now_utc();
    let certificate = raw_certificate_with_validity(
        CLIENT_ID,
        &material._ca,
        now + time::Duration::hours(1),
        now + time::Duration::hours(2),
    );
    assert_eq!(
        raw_client_against_acceptor(&material, certificate).await,
        DiameterTlsError::Authentication
    );
}

#[tokio::test]
async fn expired_peer_certificate_fails_closed() {
    let material = dtls_material();
    let now = time::OffsetDateTime::now_utc();
    let certificate = raw_certificate_with_validity(
        CLIENT_ID,
        &material._ca,
        now - time::Duration::hours(2),
        now - time::Duration::hours(1),
    );
    assert_eq!(
        raw_client_against_acceptor(&material, certificate).await,
        DiameterTlsError::Authentication
    );
}

#[tokio::test]
async fn cleartext_ppid0_input_fails_closed_before_handshake() {
    let material = dtls_material();
    let (mut client_io, server_io, _log) = in_memory_sctp_link(64);
    let acceptor = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    // A cleartext Diameter CER-sized blob on PPID 0 instead of a ClientHello.
    let mut cleartext = vec![0x01, 0x00, 0x00, 0x14];
    cleartext.resize(20, 0);
    inject_cleartext(&mut client_io, 0, Bytes::from(cleartext)).await;
    let server_result = server.await.expect("join acceptor");
    assert_eq!(server_result.err(), Some(DiameterTlsError::CleartextInput));
}

#[tokio::test]
async fn cleartext_ppid46_input_fails_closed_before_handshake() {
    let material = dtls_material();
    let (mut client_io, server_io, _log) = in_memory_sctp_link(64);
    let acceptor = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let mut cleartext = vec![0x01, 0x00, 0x00, 0x14];
    cleartext.resize(20, 0);
    inject_cleartext(&mut client_io, 46, Bytes::from(cleartext)).await;
    let server_result = server.await.expect("join acceptor");
    assert_eq!(server_result.err(), Some(DiameterTlsError::CleartextInput));
}

async fn inject_cleartext(endpoint: &mut InMemorySctpEndpoint, ppid: u32, payload: Bytes) {
    endpoint
        .send_raw_message(ppid, payload)
        .await
        .expect("inject cleartext");
}

/// Drive a raw dimpl engine as a concurrent task until it errors, closes, or
/// the deadline passes. Returns the engine's terminal disposition.
async fn drive_raw_engine(
    mut engine: dimpl::Dtls,
    mut io: InMemorySctpEndpoint,
    deadline: Instant,
) -> Result<(), ()> {
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut outbound: Vec<Bytes> = Vec::new();
    // dimpl starts the client flight only from handle_timeout.
    engine
        .handle_timeout(std::time::Instant::now())
        .map_err(|_| ())?;
    loop {
        loop {
            match engine.poll_output(&mut buffer) {
                dimpl::Output::Packet(packet) => outbound.push(Bytes::copy_from_slice(packet)),
                dimpl::Output::BufferTooSmall { needed } => buffer.resize(needed, 0),
                dimpl::Output::Timeout(next) => {
                    for record in std::mem::take(&mut outbound) {
                        io.send_raw_message(DIAMETER_DTLS_SCTP_PPID, record)
                            .await
                            .map_err(|_| ())?;
                    }
                    let timer = tokio::time::sleep_until(Instant::from_std(next));
                    tokio::select! {
                        () = tokio::time::sleep_until(deadline) => return Err(()),
                        () = timer => {
                            engine.handle_timeout(std::time::Instant::now()).map_err(|_| ())?;
                        }
                        message = io.receive_message() => {
                            match message.map_err(|_| ())? {
                                Some(message) if message.ppid() == DIAMETER_DTLS_SCTP_PPID => {
                                    engine.handle_packet(message.payload()).map_err(|_| ())?;
                                }
                                Some(_) | None => return Err(()),
                            }
                        }
                    }
                    break;
                }
                dimpl::Output::Connected
                | dimpl::Output::PeerCert(_)
                | dimpl::Output::ApplicationData(_)
                | dimpl::Output::CloseNotify => {}
                _ => {}
            }
        }
    }
}

fn raw_certificate(spiffe_id: &str, ca: &TestCa) -> dimpl::DtlsCertificate {
    let mut parameters = rcgen::CertificateParams::default();
    parameters.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("valid SPIFFE URI"),
    ));
    let key = rcgen::KeyPair::generate().expect("generate raw key");
    let certificate = parameters.signed_by(&key, ca).expect("sign raw leaf");
    dimpl::DtlsCertificate {
        certificate: certificate.der().to_vec(),
        private_key: key.serialize_der(),
    }
}

#[tokio::test]
async fn dtls12_only_peer_against_dtls13_policy_is_rejected() {
    let material = dtls_material();
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let acceptor = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    // A raw DTLS 1.2-only cert-mode client; the 1.3-only acceptor must not
    // fall back.
    let config = std::sync::Arc::new(dimpl::Config::default());
    let mut engine = dimpl::Dtls::new_12(
        config,
        raw_certificate(CLIENT_ID, &material._ca),
        std::time::Instant::now(),
    );
    engine.set_active(true);
    let raw = tokio::spawn(drive_raw_engine(engine, client_io, deadline));
    let server_result = server.await.expect("join acceptor");
    assert!(server_result.is_err(), "downgrade must fail closed");
    let _ = raw.await;
}

#[tokio::test]
async fn psk_only_peer_shares_no_common_security_mechanism() {
    let material = dtls_material();
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    // DTLS 1.2 compatibility on our side: the only suites the PSK client
    // offers are PSK suites, which a certificate-mode endpoint never admits.
    let acceptor = acceptor(
        &material,
        expected(CLIENT_ID),
        DtlsSctpPolicy::default().with_dtls12_compatibility(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    struct FixedPsk;
    impl dimpl::PskResolver for FixedPsk {
        fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
            (identity == b"psk-peer").then(|| b"test-psk-material".to_vec())
        }
    }
    let config = std::sync::Arc::new(
        dimpl::Config::builder()
            .with_psk_client(b"psk-peer".to_vec(), std::sync::Arc::new(FixedPsk))
            .build()
            .expect("psk config"),
    );
    let mut engine = dimpl::Dtls::new_12_psk(config, std::time::Instant::now());
    engine.set_active(true);
    let raw = tokio::spawn(drive_raw_engine(engine, client_io, deadline));
    let server_result = server.await.expect("join acceptor");
    assert!(
        server_result.is_err(),
        "a certificateless peer must fail closed"
    );
    let _ = raw.await;
}

#[tokio::test]
async fn disjoint_cipher_policies_share_no_common_mechanism() {
    let material = dtls_material();
    let client_policy = DtlsSctpPolicy::default()
        .with_allowed_ciphers(&[opc_diameter_transport::DtlsSctpCipher::Chacha20Poly1305Sha256])
        .expect("client cipher policy");
    let server_policy = DtlsSctpPolicy::default()
        .with_allowed_ciphers(&[opc_diameter_transport::DtlsSctpCipher::Aes256GcmSha384])
        .expect("server cipher policy");
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let acceptor = acceptor(&material, expected(CLIENT_ID), server_policy);
    let connector = connector(&material, expected(SERVER_ID), client_policy);
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let client_result = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await;
    assert!(client_result.is_err(), "no common cipher must fail");
    assert!(server.await.expect("join acceptor").is_err());
}

#[tokio::test]
async fn handshake_interruption_fails_closed() {
    let material = dtls_material();
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    drop(client_io);
    let acceptor = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(10);
    let server_result = acceptor
        .accept_direct(
            Box::new(server_io) as Box<dyn SctpMessageIo>,
            direct_session("server.example.test"),
            deadline,
        )
        .await;
    assert_eq!(server_result.err(), Some(DiameterTlsError::Transport));
}

#[tokio::test]
async fn unconfigured_inbound_peer_fails_closed() {
    let material = dtls_material();
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    // The acceptor is configured for a different client identity than the one
    // the connector authenticates with.
    let acceptor = acceptor(
        &material,
        expected(OTHER_CLIENT_ID),
        DtlsSctpPolicy::default(),
    );
    let connector = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(10);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let client_result = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await;
    assert_eq!(
        server.await.expect("join acceptor").err(),
        Some(DiameterTlsError::PeerIdentityMismatch)
    );
    // The client may complete its own handshake before the server's
    // rejection arrives; the association must then be unusable.
    match client_result {
        Err(_) => {}
        Ok(mut connection) => {
            let outcome = connection
                .receive_capabilities_answer(Instant::now() + Duration::from_secs(3))
                .await;
            assert!(outcome.is_err(), "rejected peer cannot exchange CEA");
        }
    }
}

#[tokio::test]
async fn material_epoch_rotation_retires_established_association() {
    let material = dtls_material();
    let (mut client, server, _log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");
    let admitted_epoch = client.evidence().material_epoch();
    assert_eq!(
        admitted_epoch,
        material.client_status.status().epoch(),
        "evidence reports the exact admitted credential epoch"
    );

    // An update the pinned controller cannot accept (a different workload
    // identity) is rejected: the controller retains the last-known-good
    // material and keeps the admitted epoch, so the association survives.
    let rejected_candidate = identity_state(OTHER_CLIENT_ID, &material._ca);
    material
        .client_source
        .send(Some(rejected_candidate))
        .expect("publish invalid candidate");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        client.readiness().is_ok(),
        "invalid update must not retire the admitted epoch"
    );

    // A valid publication advances the coherent epoch and retires the
    // established association within the retirement-task bound.
    material
        .client_source
        .send(Some(identity_state(CLIENT_ID, &material._ca)))
        .expect("publish rotated material");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut retired = false;
    while Instant::now() < deadline {
        if let Err(DiameterTlsError::Retired) = client.readiness() {
            retired = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(retired, "epoch advance retires the association");
    drop(server);
}
