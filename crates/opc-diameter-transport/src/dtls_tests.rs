//! DTLS/SCTP transport tests over the deterministic in-memory
//! SCTP message seam. These tests prove the RFC 6733 direct-protection
//! sequencing and RFC 6083 PPID-47 carriage without requiring kernel SCTP.

use std::num::NonZeroUsize;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::base::{INBAND_SECURITY_ID_TLS, RESULT_CODE_DIAMETER_SUCCESS};
use opc_proto_diameter::peer::{
    build_capabilities_exchange_request, AnswerDiagnostics, CapabilitiesExchangeAnswer,
    HostIpAddress, PeerCapabilities, PeerIdentity, PeerProtectionPolicy, PeerProtectionRequirement,
    PeerProtectionSequence, PeerSession, PeerSessionPolicy,
};
use opc_proto_diameter::{
    ApplicationId, CommandCode, CommandFlags, Header, OwnedMessage, VendorId,
};
use tokio::sync::watch;
use tokio::time::Instant;

use opc_identity::{build_identity_state, IdentityState, TrustBundle, TrustBundleSet, TrustDomain};
use opc_protocol::{Encode, EncodeContext};
use opc_tls::TlsMaterialController;
use opc_types::{SpiffeId, Timestamp};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::frame::encoded_bytes;
use crate::{
    in_memory_sctp_link, DiameterCapabilitiesExchangeOutcome, DiameterDtlsSctpAcceptor,
    DiameterDtlsSctpConnection, DiameterDtlsSctpConnector, DiameterFrameLimits,
    DiameterPeerRuntimeConfig, DiameterTlsError, DiameterTlsPolicyError, DtlsSctpCipher,
    DtlsSctpPolicy, DtlsSctpVersion, ExpectedPeerIdentity, InMemorySctpEndpoint, SctpMessageIo,
    SctpWireLog, DIAMETER_DTLS_SCTP_PPID, MAX_DTLS_SCTP_MESSAGE_BYTES,
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
    client_controller: TlsMaterialController,
    server_controller: TlsMaterialController,
}

fn test_ca() -> TestCa {
    test_ca_with_key(
        rcgen::KeyPair::generate().expect("generate test CA key"),
        "Diameter DTLS test CA",
    )
}

fn test_ca_with_key(key: rcgen::KeyPair, common_name: &str) -> TestCa {
    let mut parameters = rcgen::CertificateParams::default();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    rcgen::CertifiedIssuer::self_signed(parameters, key).expect("sign test CA")
}

fn test_intermediate_ca(root: &TestCa, common_name: &str) -> TestCa {
    let now = time::OffsetDateTime::now_utc();
    test_intermediate_ca_with_validity(
        root,
        common_name,
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    )
}

fn test_intermediate_ca_with_validity(
    root: &TestCa,
    common_name: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> TestCa {
    let mut parameters = rcgen::CertificateParams::default();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = rcgen::KeyPair::generate().expect("generate test intermediate key");
    rcgen::CertifiedIssuer::signed_by(parameters, key, root).expect("sign test intermediate")
}

fn identity_state(spiffe_id: &str, ca: &TestCa) -> IdentityState {
    identity_state_with_trust(spiffe_id, ca, vec![ca.der().clone()])
}

fn identity_state_via_intermediate(
    spiffe_id: &str,
    intermediate: &TestCa,
    root: &TestCa,
) -> IdentityState {
    let now = time::OffsetDateTime::now_utc();
    let mut parameters = rcgen::CertificateParams::default();
    parameters.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("valid SPIFFE URI"),
    ));
    parameters.not_before = now - time::Duration::minutes(1);
    parameters.not_after = now + time::Duration::hours(1);
    let key = rcgen::KeyPair::generate().expect("generate intermediate-chain leaf key");
    let certificate = parameters
        .signed_by(&key, intermediate)
        .expect("sign intermediate-chain leaf");
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").expect("trust domain"),
        certificates: vec![root.der().clone()],
    });
    build_identity_state(
        vec![certificate.der().clone(), intermediate.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        bundles,
    )
    .expect("build intermediate-chain identity state")
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
    let client_controller = material_controller(&client_rx, CLIENT_ID);
    let server_controller = material_controller(&server_rx, SERVER_ID);
    TestMaterial {
        _ca: ca,
        client_source,
        _server_source: server_source,
        client_controller,
        server_controller,
    }
}

fn dtls_material_via_intermediate(root: TestCa) -> TestMaterial {
    let intermediate = test_intermediate_ca(&root, "Diameter DTLS test intermediate");
    dtls_material_via_issuer(root, &intermediate)
}

fn dtls_material_via_issuer(root: TestCa, intermediate: &TestCa) -> TestMaterial {
    let (client_source, client_rx) = watch::channel(Some(identity_state_via_intermediate(
        CLIENT_ID,
        intermediate,
        &root,
    )));
    let (server_source, server_rx) = watch::channel(Some(identity_state_via_intermediate(
        SERVER_ID,
        intermediate,
        &root,
    )));
    let client_controller = material_controller(&client_rx, CLIENT_ID);
    let server_controller = material_controller(&server_rx, SERVER_ID);
    TestMaterial {
        _ca: root,
        client_source,
        _server_source: server_source,
        client_controller,
        server_controller,
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

fn inband_capabilities(host: &str) -> PeerCapabilities {
    let mut value = capabilities(host);
    value.inband_security_ids = vec![INBAND_SECURITY_ID_TLS];
    value
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
    DiameterDtlsSctpConnector::new(material.client_controller.clone(), expected_peer, policy)
        .expect("build DTLS connector")
}

fn acceptor(
    material: &TestMaterial,
    expected_peer: ExpectedPeerIdentity,
    policy: DtlsSctpPolicy,
) -> DiameterDtlsSctpAcceptor {
    DiameterDtlsSctpAcceptor::new(material.server_controller.clone(), expected_peer, policy)
        .expect("build DTLS acceptor")
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
    establish_pair_with_capacity(material, client_policy, server_policy, 64).await
}

async fn establish_pair_with_capacity(
    material: &TestMaterial,
    client_policy: DtlsSctpPolicy,
    server_policy: DtlsSctpPolicy,
    capacity: usize,
) -> Result<
    (
        DiameterDtlsSctpConnection,
        DiameterDtlsSctpConnection,
        SctpWireLog,
    ),
    DiameterTlsError,
> {
    let (client_io, server_io, log) = in_memory_sctp_link(capacity);
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
    assert_wire_records_single_dtls_record(&records);
}

/// RFC 6083 sections 4.7 and 4.8 wire evidence: each sender emits all
/// preceding handshake records and ChangeCipherSpec under initial key 0,
/// proves CCS sender-dry, and then emits Finished as the first message under
/// key 1. No later message may regress to the initial key.
fn assert_rfc6083_auth_epoch_boundary(log: &SctpWireLog) {
    let records = log.records();
    for a_to_b in [true, false] {
        let direction: Vec<_> = records
            .iter()
            .filter(|record| record.a_to_b == a_to_b)
            .collect();
        let first_new_key = direction
            .iter()
            .position(|record| record.auth_key_id == 1)
            .expect("each sender must activate exporter-derived key 1");
        assert!(
            first_new_key > 0,
            "preceding handshake messages must use initial key 0"
        );
        assert!(
            direction[..first_new_key]
                .iter()
                .all(|record| record.auth_key_id == 0),
            "no pre-Finished message may use the exporter key: {direction:?}"
        );
        assert!(
            direction[..first_new_key].iter().any(|record| {
                record
                    .record_header
                    .is_some_and(|header| header[0] == 20 && record.auth_key_id == 0)
            }),
            "ChangeCipherSpec must leave under the old key: {direction:?}"
        );
        assert!(
            direction[first_new_key..]
                .iter()
                .all(|record| record.auth_key_id == 1),
            "no post-transition message may regress to initial key 0: {direction:?}"
        );
        let first = direction[first_new_key];
        let header = first
            .record_header
            .expect("first exporter-key message must be a DTLS record");
        assert_eq!(
            header[0], 22,
            "Finished must be the first exporter-key message: {direction:?}"
        );
        assert_eq!(
            u16::from_be_bytes([header[3], header[4]]),
            1,
            "Finished must be protected in DTLS epoch 1"
        );
    }
}

/// RFC 6083 section 4.1 wire evidence: every emitted SCTP user message
/// carries exactly one complete classic DTLS 1.2 record.
fn assert_wire_records_single_dtls_record(records: &[crate::SctpWireRecord]) {
    let mut classic = 0_usize;
    for record in records {
        if record.ppid != DIAMETER_DTLS_SCTP_PPID {
            continue;
        }
        let header = record
            .record_header
            .expect("PPID-47 emission must retain its record header");
        let bounds = crate::parse_dtls_record_bounds(&header)
            .expect("emission must start with a parseable DTLS record header");
        assert_eq!(
            bounds.record_bytes, record.payload_bytes,
            "exactly one DTLS record per SCTP user message: {record:?}"
        );
        assert!(!bounds.unified, "RFC 6083 profile is DTLS 1.2 only");
        classic += 1;
        let content_type = bounds.content_type.expect("classic content type");
        assert!(
            matches!(content_type, 20..=23 | 26),
            "unexpected classic content type {content_type}"
        );
    }
    assert!(
        classic >= 1,
        "epoch-0 classic records expected: {records:?}"
    );
}

#[tokio::test]
async fn direct_pair_establishes_mutual_rfc6083_dtls12_before_any_diameter_byte() {
    let material = dtls_material();
    let (mut client, mut server, log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");

    assert_eq!(client.evidence().version(), DtlsSctpVersion::Dtls12);
    assert_eq!(server.evidence().version(), DtlsSctpVersion::Dtls12);
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
    assert_rfc6083_auth_epoch_boundary(&log);

    let before_close = log.records().len();
    let (client_session, server_close) =
        tokio::join!(client.close(deadline), server.receive_message(deadline),);
    let client_session = client_session.expect("complete reciprocal close_notify exchange");
    assert!(
        server_close.is_err(),
        "the peer must stop delivering Diameter after close_notify"
    );
    let close_records = &log.records()[before_close..];
    for a_to_b in [true, false] {
        let alerts: Vec<_> = close_records
            .iter()
            .filter(|record| {
                record.a_to_b == a_to_b
                    && record.record_header.is_some_and(|header| header[0] == 21)
            })
            .collect();
        assert_eq!(
            alerts.len(),
            1,
            "each endpoint must send exactly one close_notify: {close_records:?}"
        );
        assert_eq!(
            alerts[0].auth_key_id, 1,
            "both close_notify records use the established exporter key"
        );
    }
    drop(client_session);
}

#[tokio::test]
async fn blocked_reciprocal_alert_send_obeys_protected_read_deadline() {
    let material = dtls_material();
    let (mut client, server, log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");
    // Endpoint A is the connector. Hold its DTLS writes so processing the
    // acceptor's authenticated close_notify blocks while emitting the
    // reciprocal alert.
    log.set_dtls_send_blocked(true, true);
    let server_close =
        tokio::spawn(async move { server.close(Instant::now() + Duration::from_secs(5)).await });
    let error = client
        .receive_message(Instant::now() + Duration::from_millis(50))
        .await
        .expect_err("blocked reciprocal alert must obey read deadline");
    assert_eq!(error, DiameterTlsError::DeadlineExceeded);
    assert!(
        server_close.await.expect("join peer close").is_err(),
        "the timed-out reader closes the whole SCTP association"
    );
}

#[tokio::test]
async fn explicit_close_fails_instead_of_discarding_preceding_application_data() {
    let material = dtls_material();
    let (mut client, mut server, _log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");
    let deadline = Instant::now() + Duration::from_secs(5);
    negotiate_capabilities(&mut client, &mut server, deadline).await;
    server
        .send_message(&application_request(), deadline)
        .await
        .expect("queue authenticated application data before close");

    let (client_close, server_close) =
        tokio::join!(client.close(deadline), server.receive_message(deadline),);
    assert_eq!(
        client_close.expect_err("consuming close cannot discard application data"),
        DiameterTlsError::Transport
    );
    assert!(
        server_close.is_err(),
        "the failed close poisons the entire association"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires Linux kernel SCTP-AUTH and sender-dry support"]
async fn kernel_loopback_completes_real_rfc6083_handshake_and_reciprocal_close() {
    let authentication = opc_sctp::SctpAuthenticationConfig::data();
    let mut server_config =
        opc_sctp::SctpEndpointConfig::one_to_one("127.0.0.1:0".parse().expect("loopback address"));
    server_config.max_message_bytes = crate::MAX_DTLS_SCTP_RECORD_BYTES;
    let endpoint = opc_sctp::SctpEndpoint::bind_with_authentication(server_config, authentication)
        .expect("bind authenticated SCTP listener");
    let server_address = endpoint
        .local_addresses()
        .expect("read SCTP listener address")[0];
    let mut client_config = opc_sctp::SctpConnectConfig::new(server_address);
    client_config.max_message_bytes = crate::MAX_DTLS_SCTP_RECORD_BYTES;
    let client_association = tokio::time::timeout(
        Duration::from_secs(5),
        opc_sctp::SctpAssociation::connect_with_authentication(client_config, authentication),
    )
    .await
    .expect("authenticated SCTP connect timeout")
    .expect("connect authenticated SCTP association");
    let server_association = tokio::time::timeout(Duration::from_secs(5), endpoint.accept())
        .await
        .expect("authenticated SCTP accept timeout")
        .expect("accept authenticated SCTP association");
    let client_io = crate::KernelSctpMessageIo::new(client_association, 64)
        .expect("bind client kernel adapter");
    let server_io = crate::KernelSctpMessageIo::new(server_association, 64)
        .expect("bind server kernel adapter");

    let material = dtls_material();
    let acceptor = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default());
    let connector = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(15);
    let server = tokio::spawn(async move {
        acceptor
            .accept_direct(
                Box::new(server_io) as Box<dyn SctpMessageIo>,
                direct_session("server.example.test"),
                deadline,
            )
            .await
    });
    let mut client = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("complete client RFC 6083 handshake");
    let mut server = server
        .await
        .expect("join kernel acceptor")
        .expect("complete server RFC 6083 handshake");
    negotiate_capabilities(&mut client, &mut server, deadline).await;
    let request = application_request();
    let (sent, received) = tokio::join!(
        client.send_message(&request, deadline),
        server.receive_message(deadline),
    );
    sent.expect("send Diameter over kernel DTLS/SCTP");
    assert_eq!(
        received
            .expect("receive Diameter over kernel DTLS/SCTP")
            .0
            .header,
        request.header
    );
    let (closed, peer) = tokio::join!(client.close(deadline), server.receive_message(deadline));
    closed.expect("complete reciprocal close_notify over kernel SCTP");
    assert!(
        peer.is_err(),
        "peer must stop after reciprocal close_notify"
    );
}

#[tokio::test]
async fn full_intermediate_chains_are_verified_in_both_directions() {
    let material = dtls_material_via_intermediate(test_ca());
    let (client, server, log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("verify both presented intermediate chains");
    assert_eq!(client.evidence().version(), DtlsSctpVersion::Dtls12);
    assert_eq!(server.evidence().version(), DtlsSctpVersion::Dtls12);
    assert_wire_records_only_ppid47(&log);
}

#[tokio::test(start_paused = true)]
async fn intermediate_expiry_bounds_evidence_and_retires_the_association() {
    let now = time::OffsetDateTime::now_utc();
    let root = test_ca();
    let expires_at = now + time::Duration::seconds(5);
    let intermediate = test_intermediate_ca_with_validity(
        &root,
        "short-lived Diameter DTLS intermediate",
        now - time::Duration::minutes(1),
        expires_at,
    );
    let material = dtls_material_via_issuer(root, &intermediate);
    let (mut client, server, _) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish short-lived intermediate chain");
    let expected_expiry = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(expires_at.unix_timestamp())
            .expect("certificate expiry timestamp"),
    );
    assert_eq!(
        client.evidence().local_certificate_expires_at(),
        expected_expiry
    );
    assert_eq!(
        client.evidence().peer_certificate_expires_at(),
        expected_expiry
    );
    assert_eq!(
        server.evidence().local_certificate_expires_at(),
        expected_expiry
    );
    assert_eq!(
        server.evidence().peer_certificate_expires_at(),
        expected_expiry
    );

    tokio::time::advance(Duration::from_secs(6)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
        if client.readiness() == Err(DiameterTlsError::Retired) {
            return;
        }
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    panic!("intermediate expiry must retire the association");
}

#[tokio::test]
async fn rsa_signed_ca_chain_uses_the_same_verifier_algorithms_as_tls_tcp() {
    // Synthetic test-only PKCS#8 fixture already used by opc-proto-ikev2.
    // The intermediate certificate is signed by this RSA root while the DTLS
    // endpoint leaves remain ECDSA, exercising RSA verification in the CA
    // path without adding an RSA DTLS cipher suite.
    let rsa_key_der = PrivatePkcs8KeyDer::from(
        include_bytes!("../../opc-proto-ikev2/tests/data/rsa2048_pkcs8.der").as_slice(),
    );
    let rsa_key =
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&rsa_key_der, &rcgen::PKCS_RSA_SHA256)
            .expect("parse synthetic RSA root key");
    let material =
        dtls_material_via_intermediate(test_ca_with_key(rsa_key, "RSA-signed DTLS test root"));
    let (client, server, _) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("verify RSA-signed intermediate in both directions");
    assert_eq!(
        client.evidence().cipher(),
        server.evidence().cipher(),
        "both endpoints must retain the exact negotiated suite"
    );
}

#[tokio::test]
async fn inband_pair_exchanges_only_cleartext_cer_cea_then_fences_same_association_to_dtls() {
    let material = dtls_material();
    let (client_io, server_io, log) = in_memory_sctp_link(64);
    let policy = DtlsSctpPolicy::default();
    let connector = connector(&material, expected(SERVER_ID), policy);
    let acceptor = acceptor(&material, expected(CLIENT_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(10);
    let client = connector
        .begin_inband(
            Box::new(client_io),
            inband_capabilities("client.example.test"),
            peer_policy(),
        )
        .expect("begin client prelude");
    let server = acceptor
        .begin_inband(
            Box::new(server_io),
            inband_capabilities("server.example.test"),
            peer_policy(),
        )
        .expect("begin server prelude");

    let (client, server) = tokio::join!(
        client.send_capabilities_request(0x1234, 0x5678, deadline),
        server.receive_capabilities_request(deadline),
    );
    let client = client.expect("send cleartext CER");
    let (server, remote) = server.expect("receive cleartext CER");
    assert_eq!(remote, inband_capabilities("client.example.test"));

    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: inband_capabilities("server.example.test"),
        diagnostics: AnswerDiagnostics::default(),
    };
    let (server, client) = tokio::join!(
        server.send_capabilities_answer_and_upgrade(&answer, deadline),
        client.receive_capabilities_answer_and_upgrade(deadline),
    );
    let mut server = server.expect("server DTLS upgrade");
    let (mut client, observed) = client.expect("client DTLS upgrade");
    assert_eq!(observed, answer);
    assert_eq!(
        client.evidence().protection().sequence(),
        PeerProtectionSequence::InbandAfterCapabilities
    );
    assert_eq!(
        server.evidence().protection().sequence(),
        PeerProtectionSequence::InbandAfterCapabilities
    );
    assert!(client.readiness().expect("client readiness").traffic_ready);
    assert!(server.readiness().expect("server readiness").traffic_ready);

    let initial_wire = log.records();
    assert!(initial_wire.len() > 2);
    assert_eq!(initial_wire[0].ppid, opc_sctp::DIAMETER_SCTP_PPID.get());
    assert_eq!(initial_wire[1].ppid, opc_sctp::DIAMETER_SCTP_PPID.get());
    assert!(
        initial_wire[2..]
            .iter()
            .all(|record| record.ppid == DIAMETER_DTLS_SCTP_PPID),
        "the cleartext gate must be irreversibly fenced after CEA: {initial_wire:?}"
    );

    let request = application_request();
    let (sent, received) = tokio::join!(
        client.send_message(&request, deadline),
        server.receive_message(deadline),
    );
    sent.expect("send protected application");
    let (received, _) = received.expect("receive protected application");
    assert_eq!(received.header, request.header);
    let final_wire = log.records();
    assert!(final_wire[2..]
        .iter()
        .all(|record| record.ppid == DIAMETER_DTLS_SCTP_PPID));
}

fn encoded_capabilities_request(
    capabilities: &PeerCapabilities,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
) -> Bytes {
    let message = build_capabilities_exchange_request(
        capabilities,
        hop_by_hop_identifier,
        end_to_end_identifier,
        EncodeContext {
            max_message_len: MAX_DTLS_SCTP_MESSAGE_BYTES,
            ..EncodeContext::default()
        },
    )
    .expect("build test CER");
    encoded_bytes(&message, DiameterFrameLimits::RFC6083).expect("encode test CER")
}

#[tokio::test]
async fn inband_prelude_rejects_foreign_ppid_and_application_command() {
    for (ppid, payload, expected_error) in [
        (
            DIAMETER_DTLS_SCTP_PPID,
            Bytes::from_static(b"not-cleartext-diameter"),
            DiameterTlsError::CleartextInput,
        ),
        (
            opc_sctp::DIAMETER_SCTP_PPID.get(),
            encoded_bytes(&application_request(), DiameterFrameLimits::RFC6083)
                .expect("encode application request"),
            DiameterTlsError::CommandNotAdmitted,
        ),
    ] {
        let material = dtls_material();
        let (mut peer, server_io, _) = in_memory_sctp_link(8);
        let injector = peer.injector();
        let server = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default())
            .begin_inband(
                Box::new(server_io),
                inband_capabilities("server.example.test"),
                peer_policy(),
            )
            .expect("begin in-band responder");
        peer.send_raw_message(ppid, payload)
            .await
            .expect("inject hostile prelude message");
        let error = match server
            .receive_capabilities_request(Instant::now() + Duration::from_secs(2))
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("hostile prelude input must fail"),
        };
        assert_eq!(error, expected_error);
        assert_eq!(
            injector
                .send_raw_message(
                    opc_sctp::DIAMETER_SCTP_PPID.get(),
                    Bytes::from_static(b"closed")
                )
                .await,
            Err(DiameterTlsError::Transport),
            "a failed prelude must close the association"
        );
    }
}

#[tokio::test]
async fn second_cleartext_frame_after_cer_is_rejected_before_dtls_ready() {
    let material = dtls_material();
    let (mut peer, server_io, _) = in_memory_sctp_link(8);
    let server = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default())
        .begin_inband(
            Box::new(server_io),
            inband_capabilities("server.example.test"),
            peer_policy(),
        )
        .expect("begin in-band responder");
    let cer =
        encoded_capabilities_request(&inband_capabilities("client.example.test"), 0x1234, 0x5678);
    peer.send_raw_message(opc_sctp::DIAMETER_SCTP_PPID.get(), cer.clone())
        .await
        .expect("send sole permitted CER");
    peer.send_raw_message(opc_sctp::DIAMETER_SCTP_PPID.get(), cer)
        .await
        .expect("queue prohibited second cleartext frame");
    let (server, _) = server
        .receive_capabilities_request(Instant::now() + Duration::from_secs(2))
        .await
        .expect("receive first CER");
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: inband_capabilities("server.example.test"),
        diagnostics: AnswerDiagnostics::default(),
    };
    assert_eq!(
        server
            .send_capabilities_answer_and_upgrade(&answer, Instant::now() + Duration::from_secs(2))
            .await
            .expect_err("queued second cleartext frame must poison DTLS upgrade"),
        DiameterTlsError::CleartextInput
    );
}

#[tokio::test]
async fn inband_security_downgrade_never_reaches_protected_readiness() {
    let material = dtls_material();
    let (client_io, server_io, _) = in_memory_sctp_link(8);
    let client = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default())
        .begin_inband(
            Box::new(client_io),
            inband_capabilities("client.example.test"),
            peer_policy(),
        )
        .expect("begin in-band initiator");
    let server = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default())
        .begin_inband(
            Box::new(server_io),
            capabilities("server.example.test"),
            peer_policy(),
        )
        .expect("begin responder with no common in-band security");
    let (client, server) = tokio::join!(
        client.send_capabilities_request(0x1234, 0x5678, Instant::now() + Duration::from_secs(2)),
        server.receive_capabilities_request(Instant::now() + Duration::from_secs(2)),
    );
    let client = client.expect("CER emission is permitted");
    match server {
        Err(_) => drop(client),
        Ok((server, _)) => {
            let answer = CapabilitiesExchangeAnswer {
                result_code: RESULT_CODE_DIAMETER_SUCCESS,
                capabilities: capabilities("server.example.test"),
                diagnostics: AnswerDiagnostics::default(),
            };
            let (server, client) = tokio::join!(
                server.send_capabilities_answer_and_upgrade(
                    &answer,
                    Instant::now() + Duration::from_secs(2)
                ),
                client.receive_capabilities_answer_and_upgrade(
                    Instant::now() + Duration::from_secs(2)
                ),
            );
            assert!(
                server.is_err() && client.is_err(),
                "a no-security CEA must fail both association endpoints"
            );
        }
    }
}

#[tokio::test]
async fn cancelling_or_timing_out_inband_receive_closes_the_association() {
    let material = dtls_material();
    let (peer, server_io, _) = in_memory_sctp_link(8);
    let injector = peer.injector();
    let server = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default())
        .begin_inband(
            Box::new(server_io),
            inband_capabilities("server.example.test"),
            peer_policy(),
        )
        .expect("begin in-band responder");
    let task =
        tokio::spawn(server.receive_capabilities_request(Instant::now() + Duration::from_secs(30)));
    tokio::task::yield_now().await;
    task.abort();
    let _ = task.await;
    assert_eq!(
        injector
            .send_raw_message(
                opc_sctp::DIAMETER_SCTP_PPID.get(),
                Bytes::from_static(b"closed")
            )
            .await,
        Err(DiameterTlsError::Transport)
    );

    let material = dtls_material();
    let (peer, server_io, _) = in_memory_sctp_link(8);
    let injector = peer.injector();
    let server = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default())
        .begin_inband(
            Box::new(server_io),
            inband_capabilities("server.example.test"),
            peer_policy(),
        )
        .expect("begin second in-band responder");
    let error = match server.receive_capabilities_request(Instant::now()).await {
        Err(error) => error,
        Ok(_) => panic!("expired receive deadline must fail"),
    };
    assert_eq!(error, DiameterTlsError::DeadlineExceeded);
    assert_eq!(
        injector
            .send_raw_message(
                opc_sctp::DIAMETER_SCTP_PPID.get(),
                Bytes::from_static(b"closed")
            )
            .await,
        Err(DiameterTlsError::Transport)
    );
}

#[tokio::test]
async fn cancelling_inband_answer_wait_closes_the_association() {
    let material = dtls_material();
    let (client_io, peer, _) = in_memory_sctp_link(8);
    let injector = peer.injector();
    let client = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default())
        .begin_inband(
            Box::new(client_io),
            inband_capabilities("client.example.test"),
            peer_policy(),
        )
        .expect("begin in-band initiator")
        .send_capabilities_request(0x1234, 0x5678, Instant::now() + Duration::from_secs(2))
        .await
        .expect("send CER");
    let task = tokio::spawn(
        client.receive_capabilities_answer_and_upgrade(Instant::now() + Duration::from_secs(30)),
    );
    tokio::task::yield_now().await;
    task.abort();
    let _ = task.await;
    assert_eq!(
        injector
            .send_raw_message(
                opc_sctp::DIAMETER_SCTP_PPID.get(),
                Bytes::from_static(b"closed")
            )
            .await,
        Err(DiameterTlsError::Transport)
    );
}

#[tokio::test]
async fn default_policy_negotiates_rfc6083_dtls12() {
    let material = dtls_material();
    let policy = DtlsSctpPolicy::default();
    let (client, server, log) = establish_pair(&material, policy, policy)
        .await
        .expect("establish RFC 6083 association");
    assert_eq!(client.evidence().version(), DtlsSctpVersion::Dtls12);
    assert_eq!(server.evidence().version(), DtlsSctpVersion::Dtls12);
    assert_wire_records_only_ppid47(&log);
}

#[test]
fn connector_clones_reuse_one_startup_validated_engine_configuration() {
    let material = dtls_material();
    let connector = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default());
    let clone = connector.clone();
    assert!(
        connector.shares_engine_config_with(&clone),
        "cloning a connector must not rebuild or revalidate its crypto provider"
    );
}

#[tokio::test]
async fn external_material_budget_wait_obeys_deadline_and_closes_transport() {
    let material = dtls_material();
    let mut active = Vec::with_capacity(opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES);
    for _ in 0..opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES {
        active.push(
            material
                .client_controller
                .begin_external_handshake()
                .await
                .expect("occupy external handshake permit"),
        );
    }

    let connector = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default());
    let (client_io, server_io, _log) = in_memory_sctp_link(8);
    let injector = server_io.injector();
    let error = connector
        .connect_direct(
            Box::new(client_io),
            direct_session("client.example.test"),
            Instant::now() + Duration::from_millis(25),
        )
        .await
        .expect_err("saturated external handshake budget must time out");
    assert_eq!(error, DiameterTlsError::DeadlineExceeded);
    assert_eq!(
        injector
            .send_raw_message(
                opc_sctp::DIAMETER_SCTP_PPID.get(),
                Bytes::from_static(b"closed")
            )
            .await,
        Err(DiameterTlsError::Transport),
        "deadline failure must close the association while it waits for material"
    );
    drop(active);
}

#[tokio::test]
async fn blocked_handshake_send_obeys_deadline_and_closes_transport() {
    let material = dtls_material();
    let connector = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default());
    let (client_io, server_io, log) = in_memory_sctp_link(8);
    let injector = server_io.injector();
    log.set_dtls_send_blocked(true, true);
    let error = connector
        .connect_direct(
            Box::new(client_io),
            direct_session("client.example.test"),
            Instant::now() + Duration::from_millis(25),
        )
        .await
        .expect_err("blocked ClientHello send must time out");
    assert_eq!(error, DiameterTlsError::DeadlineExceeded);
    assert_eq!(
        injector
            .send_raw_message(
                opc_sctp::DIAMETER_SCTP_PPID.get(),
                Bytes::from_static(b"closed")
            )
            .await,
        Err(DiameterTlsError::Transport)
    );
}

#[tokio::test]
async fn cancelling_blocked_handshake_send_closes_transport() {
    let material = dtls_material();
    let connector = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default());
    let (client_io, server_io, log) = in_memory_sctp_link(8);
    let injector = server_io.injector();
    log.set_dtls_send_blocked(true, true);
    let task = tokio::spawn(async move {
        connector
            .connect_direct(
                Box::new(client_io),
                direct_session("client.example.test"),
                Instant::now() + Duration::from_secs(30),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    task.abort();
    let _ = task.await;
    assert_eq!(
        injector
            .send_raw_message(
                opc_sctp::DIAMETER_SCTP_PPID.get(),
                Bytes::from_static(b"closed")
            )
            .await,
        Err(DiameterTlsError::Transport)
    );
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
    let client_controller = material_controller(&client_rx, CLIENT_ID);
    let server_controller = material_controller(&other_rx, OTHER_SERVER_ID);
    let policy = DtlsSctpPolicy::default();
    let acceptor = DiameterDtlsSctpAcceptor::new(server_controller, expected(CLIENT_ID), policy)
        .expect("build test acceptor");
    let connector = DiameterDtlsSctpConnector::new(client_controller, expected(SERVER_ID), policy)
        .expect("build test connector");
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
    let server_controller = material_controller(&server_rx, SERVER_ID);
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let policy = DtlsSctpPolicy::default();
    let acceptor = DiameterDtlsSctpAcceptor::new(server_controller, expected(CLIENT_ID), policy)
        .expect("build test acceptor");
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
    let server_controller = material_controller(&server_rx, SERVER_ID);
    // Let the admitted material expire before the acceptor snapshots it.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let policy = DtlsSctpPolicy::default();
    let acceptor = DiameterDtlsSctpAcceptor::new(server_controller, expected(CLIENT_ID), policy)
        .expect("build test acceptor");
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
        intermediates: Vec::new(),
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
    let config = raw_rfc6083_config();
    let mut engine = dimpl::Dtls::new_12(config, certificate, std::time::Instant::now());
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

async fn send_raw_dtls_datagram(io: &mut InMemorySctpEndpoint, datagram: Bytes) -> Result<(), ()> {
    let mut remaining = datagram.as_ref();
    while !remaining.is_empty() {
        let bounds = crate::parse_dtls_record_bounds(remaining).ok_or(())?;
        if bounds.record_bytes == 0 || bounds.record_bytes > remaining.len() {
            return Err(());
        }
        io.send_raw_message(
            DIAMETER_DTLS_SCTP_PPID,
            Bytes::copy_from_slice(&remaining[..bounds.record_bytes]),
        )
        .await
        .map_err(|_| ())?;
        remaining = &remaining[bounds.record_bytes..];
    }
    Ok(())
}

/// Drive a raw dimpl engine as a concurrent task until it errors, closes, or
/// the deadline passes. Returns the engine's terminal disposition.
async fn drive_raw_engine(
    mut engine: dimpl::Dtls,
    mut io: InMemorySctpEndpoint,
    deadline: Instant,
) -> Result<(), ()> {
    io.begin_direct_dtls().map_err(|_| ())?;
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut outbound: Vec<Bytes> = Vec::new();
    // dimpl starts the client flight only from handle_timeout.
    engine
        .handle_timeout(std::time::Instant::now())
        .map_err(|_| ())?;
    let mut connected = false;
    loop {
        loop {
            match engine.poll_output(&mut buffer) {
                dimpl::Output::Packet(packet) => outbound.push(Bytes::copy_from_slice(packet)),
                dimpl::Output::BufferTooSmall { needed } => buffer.resize(needed, 0),
                dimpl::Output::Timeout(next) => {
                    for datagram in std::mem::take(&mut outbound) {
                        send_raw_dtls_datagram(&mut io, datagram).await?;
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
                dimpl::Output::Rfc6083KeyingMaterial(material) => {
                    io.install_epoch_key(&material, deadline)
                        .await
                        .map_err(|_| ())?;
                }
                dimpl::Output::Rfc6083PrepareChangeCipherSpec => {
                    io.prepare_change_cipher_spec(deadline)
                        .await
                        .map_err(|_| ())?;
                }
                dimpl::Output::Rfc6083PrepareEpoch => {
                    io.prepare_epoch(deadline).await.map_err(|_| ())?;
                }
                dimpl::Output::Rfc6083PrepareCloseNotify => {
                    io.prepare_close_notify(deadline).await.map_err(|_| ())?;
                }
                dimpl::Output::Connected => {
                    if !connected {
                        io.confirm_peer_finished(deadline).await.map_err(|_| ())?;
                        connected = true;
                    }
                }
                dimpl::Output::CloseNotify => return Ok(()),
                dimpl::Output::PeerCert(_)
                | dimpl::Output::PeerCertChain(_)
                | dimpl::Output::ApplicationData(_)
                | dimpl::Output::KeyingMaterial(_, _) => {}
                _ => {}
            }
        }
    }
}

fn raw_rfc6083_config() -> std::sync::Arc<dimpl::Config> {
    std::sync::Arc::new(
        dimpl::Config::builder()
            .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
            .dtls13_cipher_suites(&[])
            .rfc6083_sctp()
            .build()
            .expect("RFC 6083 DTLS 1.2 config"),
    )
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
        intermediates: Vec::new(),
        private_key: key.serialize_der(),
    }
}

fn raw_certificate_via_intermediate(
    spiffe_id: &str,
    signer: &TestCa,
    presented_intermediates: Vec<Vec<u8>>,
) -> dimpl::DtlsCertificate {
    let mut parameters = rcgen::CertificateParams::default();
    parameters.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("valid SPIFFE URI"),
    ));
    let key = rcgen::KeyPair::generate().expect("generate raw intermediate-chain key");
    let certificate = parameters
        .signed_by(&key, signer)
        .expect("sign raw intermediate-chain leaf");
    dimpl::DtlsCertificate {
        certificate: certificate.der().to_vec(),
        intermediates: presented_intermediates,
        private_key: key.serialize_der(),
    }
}

#[tokio::test]
async fn missing_reordered_and_foreign_intermediate_chains_fail_closed() {
    let material = dtls_material();
    let signer = test_intermediate_ca(&material._ca, "expected raw intermediate");
    let foreign = test_intermediate_ca(&material._ca, "foreign raw intermediate");
    let cases = [
        raw_certificate_via_intermediate(CLIENT_ID, &signer, Vec::new()),
        raw_certificate_via_intermediate(
            CLIENT_ID,
            &signer,
            vec![material._ca.der().to_vec(), signer.der().to_vec()],
        ),
        raw_certificate_via_intermediate(CLIENT_ID, &signer, vec![foreign.der().to_vec()]),
    ];
    for certificate in cases {
        assert_eq!(
            raw_client_against_acceptor(&material, certificate).await,
            DiameterTlsError::Authentication
        );
    }
}

#[test]
fn dtls13_over_sctp_is_rejected_at_configuration() {
    let limits = DiameterFrameLimits::new(MAX_DTLS_SCTP_MESSAGE_BYTES).expect("valid limits");
    assert_eq!(
        DtlsSctpPolicy::dtls13(limits),
        Err(DiameterTlsPolicyError::Dtls13OverSctpUnavailable)
    );
}

#[tokio::test]
async fn psk_only_peer_shares_no_common_security_mechanism() {
    let material = dtls_material();
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    // The PSK client offers the certificate suites too, but our
    // certificate-mode endpoint filters PSK
    // suites out and requires a client certificate the peer cannot supply:
    // no mutually acceptable certificate-authenticated mechanism exists.
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
    struct FixedPsk;
    impl dimpl::PskResolver for FixedPsk {
        fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
            (identity == b"psk-peer").then(|| b"test-psk-material".to_vec())
        }
    }
    let config = std::sync::Arc::new(
        dimpl::Config::builder()
            .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
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
async fn connector_rejects_server_that_does_not_request_its_client_certificate() {
    let material = dtls_material();
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let connector = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(10);
    let config = std::sync::Arc::new(
        dimpl::Config::builder()
            .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
            .require_client_certificate(false)
            .dtls13_cipher_suites(&[])
            .rfc6083_sctp()
            .build()
            .expect("non-mutual raw server config"),
    );
    let mut engine = dimpl::Dtls::new_12(
        config,
        raw_certificate(SERVER_ID, &material._ca),
        std::time::Instant::now(),
    );
    engine.set_active(false);
    let raw_server = tokio::spawn(drive_raw_engine(engine, server_io, deadline));

    let result = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await;

    assert_eq!(
        result.err(),
        Some(DiameterTlsError::TlsHandshake),
        "a server that never requests the local certificate is not mutually authenticated"
    );
    assert!(
        raw_server.await.expect("join raw server").is_err(),
        "connector rejection must close the raw server transport"
    );
}

#[tokio::test]
async fn disjoint_cipher_policies_share_no_common_mechanism() {
    let material = dtls_material();
    let client_policy = DtlsSctpPolicy::default()
        .with_allowed_ciphers(&[crate::DtlsSctpCipher::Chacha20Poly1305Sha256])
        .expect("client cipher policy");
    let server_policy = DtlsSctpPolicy::default()
        .with_allowed_ciphers(&[crate::DtlsSctpCipher::Aes256GcmSha384])
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
        material.client_controller.status().epoch(),
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

// ---------------------------------------------------------------------------
// Adversarial-review regression tests
// ---------------------------------------------------------------------------

/// One AVP whose total wire size (with its 8-byte header) is `avp_wire_bytes`.
fn ietf_avp(code: u32, mandatory: bool, value: &[u8]) -> Bytes {
    let declared_length = 8_usize.checked_add(value.len()).expect("AVP length");
    let padded_length = declared_length.checked_add(3).expect("AVP padding") & !3;
    let mut wire = BytesMut::with_capacity(padded_length);
    wire.extend_from_slice(&code.to_be_bytes());
    wire.extend_from_slice(&[
        if mandatory { 0x40 } else { 0 },
        ((declared_length >> 16) & 0xff) as u8,
        ((declared_length >> 8) & 0xff) as u8,
        (declared_length & 0xff) as u8,
    ]);
    wire.extend_from_slice(value);
    wire.resize(padded_length, 0);
    wire.freeze()
}

/// One application request whose total wire length is exactly `wire_len`.
fn padded_application_request(wire_len: usize) -> OwnedMessage {
    const HEADER: usize = 20;
    const AVP_HEADER: usize = 8;
    let value_len = wire_len
        .checked_sub(HEADER + AVP_HEADER)
        .expect("wire length above minimum");
    assert_eq!(value_len % 4, 0, "AVP value must align to 4");
    let mut header = Header::new(
        CommandFlags::request(true),
        CommandCode::new(268),
        APP_ID,
        0x300,
        0x400,
    );
    header.length = wire_len as u32;
    OwnedMessage {
        header,
        raw_avps: ietf_avp(4_000_001, false, &vec![0xAB_u8; value_len]),
    }
}

#[test]
fn policy_rejects_frame_limit_above_record_budget() {
    let over = DiameterFrameLimits::new(MAX_DTLS_SCTP_MESSAGE_BYTES + 1).expect("valid limits");
    assert_eq!(
        DtlsSctpPolicy::rfc6083_dtls12(over),
        Err(DiameterTlsPolicyError::FrameLimitExceedsDtlsRecordBudget)
    );
    let at = DiameterFrameLimits::new(MAX_DTLS_SCTP_MESSAGE_BYTES).expect("valid limits");
    assert!(DtlsSctpPolicy::rfc6083_dtls12(at).is_ok());
}

async fn negotiate_capabilities(
    client: &mut DiameterDtlsSctpConnection,
    server: &mut DiameterDtlsSctpConnection,
    deadline: Instant,
) {
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: capabilities("server.example.test"),
        diagnostics: AnswerDiagnostics::default(),
    };
    let (cer_sent, cer_received) = tokio::join!(
        client.send_capabilities_request(0x1, 0x2, deadline),
        server.receive_capabilities_request(deadline),
    );
    cer_sent.expect("send CER");
    cer_received.expect("receive CER");
    let (cea_emitted, cea_observed) = tokio::join!(
        server.send_capabilities_answer(&answer, deadline),
        client.receive_capabilities_answer(deadline),
    );
    cea_emitted.expect("send CEA");
    cea_observed.expect("receive CEA");
}

#[tokio::test]
async fn dtls_peer_runtime_carries_application_traffic_full_duplex_with_typed_evidence() {
    let material = dtls_material();
    let (mut client, mut server, _log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");
    let deadline = Instant::now() + Duration::from_secs(10);
    negotiate_capabilities(&mut client, &mut server, deadline).await;
    let capacity = NonZeroUsize::new(8).expect("nonzero test capacity");
    let config = DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, Some(7))
        .expect("runtime bounds");
    let client = client.into_peer_runtime(config).expect("client runtime");
    let server = server.into_peer_runtime(config).expect("server runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    let (server_handle, mut server_incoming) = server.into_parts();
    assert_eq!(client_handle.evidence().version(), DtlsSctpVersion::Dtls12);

    let request = application_request();
    let answer = OwnedMessage {
        header: Header::new(
            CommandFlags::answer(false, false),
            CommandCode::new(268),
            APP_ID,
            0x300,
            0x400,
        ),
        raw_avps: Bytes::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let (sent_request, received_request, sent_answer, received_answer) = tokio::join!(
        client_handle.send_application(request.clone(), deadline),
        server_incoming.receive(),
        server_handle.send_application(answer.clone(), deadline),
        client_incoming.receive(),
    );
    assert!(sent_request.expect("send request").is_protected());
    assert_eq!(
        received_request.expect("receive request").into_message(),
        request
    );
    assert!(sent_answer.expect("send answer").is_protected());
    assert_eq!(
        received_answer.expect("receive answer").into_message(),
        answer
    );
}

#[tokio::test]
async fn dtls_runtime_drains_back_to_back_protected_frames_without_false_overflow() {
    let material = dtls_material();
    let (mut client, mut server, _log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");
    let deadline = Instant::now() + Duration::from_secs(10);
    negotiate_capabilities(&mut client, &mut server, deadline).await;
    let mut first = application_request();
    first.header.hop_by_hop_identifier = 0x501;
    first.header.end_to_end_identifier = 0x601;
    let mut second = application_request();
    second.header.hop_by_hop_identifier = 0x502;
    second.header.end_to_end_identifier = 0x602;

    // Queue both complete DTLS records before the server actor exists. Its
    // single owner must drain the valid burst into the configured bounded
    // application queue, not mistake it for an overflow.
    client
        .send_message(&first, deadline)
        .await
        .expect("queue first protected frame");
    client
        .send_message(&second, deadline)
        .await
        .expect("queue second protected frame");
    let capacity = NonZeroUsize::new(2).expect("nonzero test capacity");
    let config =
        DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, None).expect("runtime bounds");
    let server = server.into_peer_runtime(config).expect("server runtime");
    let (_handle, mut incoming) = server.into_parts();
    assert_eq!(
        incoming
            .receive()
            .await
            .expect("receive first")
            .into_message(),
        first
    );
    assert_eq!(
        incoming
            .receive()
            .await
            .expect("receive second")
            .into_message(),
        second
    );
}

#[tokio::test]
async fn dtls_runtime_delivers_frames_preceding_close_notify_before_peer_closed() {
    let material = dtls_material();
    let (mut client, mut server, _log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");
    let deadline = Instant::now() + Duration::from_secs(10);
    negotiate_capabilities(&mut client, &mut server, deadline).await;

    let mut first = application_request();
    first.header.hop_by_hop_identifier = 0x511;
    first.header.end_to_end_identifier = 0x611;
    let mut second = application_request();
    second.header.hop_by_hop_identifier = 0x512;
    second.header.end_to_end_identifier = 0x612;
    client
        .send_message(&first, deadline)
        .await
        .expect("queue first protected frame");
    client
        .send_message(&second, deadline)
        .await
        .expect("queue second protected frame");

    let capacity = NonZeroUsize::new(2).expect("nonzero test capacity");
    let config =
        DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, None).expect("runtime bounds");
    let server = server.into_peer_runtime(config).expect("server runtime");
    let (_handle, mut incoming) = server.into_parts();

    // The runtime processes both records and the immediately following
    // authenticated close_notify before the application starts draining.
    // RFC 6083 requires records before the alert to remain deliverable.
    client
        .close(Instant::now() + Duration::from_secs(5))
        .await
        .expect("complete reciprocal close_notify");
    assert_eq!(
        incoming
            .receive()
            .await
            .expect("deliver first pre-close frame")
            .into_message(),
        first
    );
    assert_eq!(
        incoming
            .receive()
            .await
            .expect("deliver second pre-close frame")
            .into_message(),
        second
    );
    assert_eq!(
        incoming.receive().await.expect_err("queue is now closed"),
        crate::DiameterPeerRuntimeError::Transport(DiameterTlsError::PeerClosed)
    );
}

#[tokio::test]
async fn cancelling_indeterminate_dtls_runtime_send_closes_the_association() {
    let material = dtls_material();
    let (mut client, mut server, _log) = establish_pair_with_capacity(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
        1,
    )
    .await
    .expect("establish protected association");
    let deadline = Instant::now() + Duration::from_secs(10);
    negotiate_capabilities(&mut client, &mut server, deadline).await;

    // Occupy the sole wire slot while the peer deliberately does not read.
    client
        .send_message(&application_request(), deadline)
        .await
        .expect("fill one-message wire queue");
    let capacity = NonZeroUsize::new(2).expect("nonzero test capacity");
    let config =
        DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, None).expect("runtime bounds");
    let runtime = client.into_peer_runtime(config).expect("client runtime");
    let (handle, _incoming) = runtime.into_parts();
    let mut blocked = application_request();
    blocked.header.hop_by_hop_identifier = 0x777;
    blocked.header.end_to_end_identifier = 0x888;
    let task_handle = handle.clone();
    let task = tokio::spawn(async move {
        task_handle
            .send_application(blocked, Instant::now() + Duration::from_secs(5))
            .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    task.abort();
    let _ = task.await;

    let terminal_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if handle.readiness().await.is_err() {
            break;
        }
        assert!(
            Instant::now() < terminal_deadline,
            "cancelled uncertain send must terminally close"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        server
            .receive_message(Instant::now() + Duration::from_secs(1))
            .await
            .is_err()
            || server
                .receive_message(Instant::now() + Duration::from_secs(1))
                .await
                .is_err(),
        "peer must eventually observe the terminal association"
    );
}

#[tokio::test]
async fn record_budget_boundary_message_round_trips() {
    let material = dtls_material();
    let (mut client, mut server, log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");
    let deadline = Instant::now() + Duration::from_secs(10);
    negotiate_capabilities(&mut client, &mut server, deadline).await;

    // Diameter AVP padding makes valid message lengths multiples of four.
    // Exercise the largest valid Diameter frame within the exact DTLS
    // plaintext budget.
    let largest_aligned_message = MAX_DTLS_SCTP_MESSAGE_BYTES & !3;
    let request = padded_application_request(largest_aligned_message);
    let (sent, received) = tokio::join!(
        client.send_message(&request, deadline),
        server.receive_message(deadline),
    );
    sent.expect("send boundary message");
    let (received, _) = received.expect("receive boundary message");
    assert_eq!(received.header, request.header);
    assert_eq!(received.raw_avps, request.raw_avps);
    assert_wire_records_only_ppid47(&log);
}

#[tokio::test]
async fn every_admitted_cipher_keeps_maximum_diameter_frame_within_rfc6083_path_mtu() {
    let material = dtls_material();
    let largest_aligned_message = MAX_DTLS_SCTP_MESSAGE_BYTES & !3;
    for cipher in [
        DtlsSctpCipher::Aes128GcmSha256,
        DtlsSctpCipher::Aes256GcmSha384,
        DtlsSctpCipher::Chacha20Poly1305Sha256,
    ] {
        let policy = DtlsSctpPolicy::default()
            .with_allowed_ciphers(&[cipher])
            .expect("single admitted cipher");
        let (mut client, mut server, log) = establish_pair(&material, policy, policy)
            .await
            .expect("establish protected association");
        assert_eq!(client.evidence().cipher(), cipher);
        assert_eq!(server.evidence().cipher(), cipher);
        let deadline = Instant::now() + Duration::from_secs(10);
        negotiate_capabilities(&mut client, &mut server, deadline).await;

        let before = log.records().len();
        let request = padded_application_request(largest_aligned_message);
        let (sent, received) = tokio::join!(
            client.send_message(&request, deadline),
            server.receive_message(deadline),
        );
        sent.expect("send maximum frame");
        received.expect("receive maximum frame");

        let records = log.records();
        let application_records: Vec<_> = records[before..]
            .iter()
            .filter(|record| {
                record.a_to_b && record.record_header.is_some_and(|header| header[0] == 23)
            })
            .collect();
        assert_eq!(
            application_records.len(),
            1,
            "one Diameter frame must remain one DTLS record for {cipher:?}"
        );
        assert!(
            application_records[0].payload_bytes <= 16_384,
            "encoded record exceeds RFC 6083 path MTU for {cipher:?}: {}",
            application_records[0].payload_bytes
        );
    }
}

#[tokio::test]
async fn oversized_message_fails_with_typed_error() {
    let material = dtls_material();
    let (mut client, mut server, _log) = establish_pair(
        &material,
        DtlsSctpPolicy::default(),
        DtlsSctpPolicy::default(),
    )
    .await
    .expect("establish protected association");
    let deadline = Instant::now() + Duration::from_secs(10);
    negotiate_capabilities(&mut client, &mut server, deadline).await;
    let _ = &server;
    let largest_aligned_message = MAX_DTLS_SCTP_MESSAGE_BYTES & !3;
    let oversized = padded_application_request(largest_aligned_message + 4);
    let outcome = client.send_message(&oversized, deadline).await;
    assert_eq!(outcome.err(), Some(DiameterTlsError::InvalidFrame));
}

#[tokio::test]
async fn cross_trust_domain_anchor_confusion_fails_closed() {
    // CA_A anchors example.test; CA_E anchors evil.test. The client presents
    // an example.test SPIFFE leaf issued by CA_E. Domain-scoped anchor
    // selection must reject it on both sides even though the server also
    // trusts CA_E for evil.test.
    let ca_a = test_ca();
    let ca_e = test_ca();
    let mut server_bundles = TrustBundleSet::new();
    server_bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").expect("domain"),
        certificates: vec![ca_a.der().clone()],
    });
    server_bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("evil.test").expect("domain"),
        certificates: vec![ca_e.der().clone()],
    });
    let now = time::OffsetDateTime::now_utc();
    let mut server_parameters = rcgen::CertificateParams::default();
    server_parameters
        .subject_alt_names
        .push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(SERVER_ID).expect("server URI"),
        ));
    server_parameters.not_before = now - time::Duration::minutes(1);
    server_parameters.not_after = now + time::Duration::hours(1);
    let server_key = rcgen::KeyPair::generate().expect("server key");
    let server_cert = server_parameters
        .signed_by(&server_key, &ca_a)
        .expect("sign server leaf");
    let server_state = build_identity_state(
        vec![server_cert.der().clone(), ca_a.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        server_bundles,
    )
    .expect("coherent server state");

    // Hostile client: example.test identity, but the leaf chains to CA_E.
    // The client's own store anchors example.test at both CAs so its own
    // coherent-state build and its view of the server certificate succeed;
    // the pinned behavior is the server's rejection of the CA_E-issued
    // example.test leaf.
    let client_state = identity_state_with_validity_and_trust(
        CLIENT_ID,
        &ca_e,
        vec![ca_a.der().clone(), ca_e.der().clone()],
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );

    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let (_client_source, client_rx) = watch::channel(Some(client_state));
    let (_server_source, server_rx) = watch::channel(Some(server_state));
    let client_controller = material_controller(&client_rx, CLIENT_ID);
    let server_controller = material_controller(&server_rx, SERVER_ID);
    let policy = DtlsSctpPolicy::default();
    let acceptor = DiameterDtlsSctpAcceptor::new(server_controller, expected(CLIENT_ID), policy)
        .expect("build test acceptor");
    let connector = DiameterDtlsSctpConnector::new(client_controller, expected(SERVER_ID), policy)
        .expect("build test connector");
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
        Some(DiameterTlsError::Authentication),
        "an example.test leaf issued by a foreign-domain CA must be rejected"
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

/// A raw dimpl client peer for tests: drives the engine, reports the
/// handshake, and relays application data in both directions.
struct RawDtlsClient {
    connected: tokio::sync::oneshot::Receiver<Result<(), ()>>,
    commands: tokio::sync::mpsc::Sender<Bytes>,
    inbound: tokio::sync::mpsc::Receiver<Bytes>,
    _task: tokio::task::JoinHandle<()>,
}

fn spawn_raw_dtls12_client(
    spiffe_id: &str,
    ca: &TestCa,
    mut io: InMemorySctpEndpoint,
    deadline: Instant,
) -> RawDtlsClient {
    let config = raw_rfc6083_config();
    let mut engine = dimpl::Dtls::new_12(
        config,
        raw_certificate(spiffe_id, ca),
        std::time::Instant::now(),
    );
    engine.set_active(true);
    let (connected_tx, connected) = tokio::sync::oneshot::channel();
    let (commands, mut command_rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let (inbound_tx, inbound) = tokio::sync::mpsc::channel::<Bytes>(8);
    let task = tokio::spawn(async move {
        if io.begin_direct_dtls().is_err()
            || engine.handle_timeout(std::time::Instant::now()).is_err()
        {
            return;
        }
        let mut buffer = vec![0_u8; 16 * 1024];
        let mut outbound: Vec<Bytes> = Vec::new();
        let mut connected_tx = Some(connected_tx);
        let mut connected = false;
        loop {
            let timer = loop {
                match engine.poll_output(&mut buffer) {
                    dimpl::Output::Packet(packet) => outbound.push(Bytes::copy_from_slice(packet)),
                    dimpl::Output::BufferTooSmall { needed } => buffer.resize(needed, 0),
                    dimpl::Output::Timeout(next) => {
                        break Some(next);
                    }
                    dimpl::Output::Connected => {
                        if !connected {
                            if io.confirm_peer_finished(deadline).await.is_err() {
                                return;
                            }
                            connected = true;
                            if let Some(tx) = connected_tx.take() {
                                let _ = tx.send(Ok(()));
                            }
                        }
                    }
                    dimpl::Output::Rfc6083KeyingMaterial(material) => {
                        if io.install_epoch_key(&material, deadline).await.is_err() {
                            return;
                        }
                    }
                    dimpl::Output::Rfc6083PrepareChangeCipherSpec => {
                        if io.prepare_change_cipher_spec(deadline).await.is_err() {
                            return;
                        }
                    }
                    dimpl::Output::Rfc6083PrepareEpoch => {
                        if io.prepare_epoch(deadline).await.is_err() {
                            return;
                        }
                    }
                    dimpl::Output::Rfc6083PrepareCloseNotify => {
                        if io.prepare_close_notify(deadline).await.is_err() {
                            return;
                        }
                    }
                    dimpl::Output::ApplicationData(data) => {
                        let _ = inbound_tx.try_send(Bytes::copy_from_slice(data));
                    }
                    dimpl::Output::CloseNotify => return,
                    _ => {}
                }
            };
            for datagram in std::mem::take(&mut outbound) {
                if send_raw_dtls_datagram(&mut io, datagram).await.is_err() {
                    return;
                }
            }
            let timer_wait = async {
                if let Some(next) = timer {
                    tokio::time::sleep_until(Instant::from_std(next)).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => return,
                () = timer_wait => {
                    if engine.handle_timeout(std::time::Instant::now()).is_err() {
                        return;
                    }
                }
                command = command_rx.recv() => {
                    let Some(bytes) = command else { return };
                    if engine.send_application_data(&bytes).is_err() {
                        return;
                    }
                }
                message = io.receive_message() => {
                    match message {
                        Ok(Some(message)) if message.ppid() == DIAMETER_DTLS_SCTP_PPID => {
                            if engine.handle_packet(message.payload()).is_err() {
                                return;
                            }
                        }
                        _ => return,
                    }
                }
            }
        }
    });
    RawDtlsClient {
        connected,
        commands,
        inbound,
        _task: task,
    }
}

#[tokio::test]
async fn dtls12_client_completes_handshake_and_capability_exchange() {
    let material = dtls_material();
    let (client_io, server_io, log) = in_memory_sctp_link(64);
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
    let mut raw = spawn_raw_dtls12_client(CLIENT_ID, &material._ca, client_io, deadline);
    raw.connected
        .await
        .expect("raw client reports")
        .expect("raw handshake completes");
    let mut server = server
        .await
        .expect("join acceptor")
        .expect("accept DTLS 1.2 client");
    assert_eq!(server.evidence().version(), DtlsSctpVersion::Dtls12);

    // Complete the canonical direct-sequence CER/CEA over DTLS 1.2.
    let cer = build_capabilities_exchange_request(
        &capabilities("client.example.test"),
        0x111,
        0x222,
        EncodeContext::default(),
    )
    .expect("build raw CER");
    let mut cer_wire = BytesMut::new();
    cer.encode(&mut cer_wire, EncodeContext::default())
        .expect("encode raw CER");
    raw.commands
        .send(cer_wire.freeze())
        .await
        .expect("queue raw CER");
    let received = server
        .receive_capabilities_request(deadline)
        .await
        .expect("receive raw CER");
    assert_eq!(received, capabilities("client.example.test"));
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: capabilities("server.example.test"),
        diagnostics: AnswerDiagnostics::default(),
    };
    let outcome = server
        .send_capabilities_answer(&answer, deadline)
        .await
        .expect("send CEA");
    assert!(outcome.is_negotiated());
    let cea = tokio::time::timeout(Duration::from_secs(5), raw.inbound.recv())
        .await
        .expect("raw client receives CEA")
        .expect("CEA bytes");
    assert!(cea.len() >= 20, "CEA must be a complete Diameter message");

    // Wire evidence scoped to the crate's acceptor emissions: exactly one
    // classic DTLS 1.2 record per SCTP user message, PPID 47 only.
    let ours: Vec<_> = log
        .records()
        .into_iter()
        .filter(|record| !record.a_to_b)
        .collect();
    assert!(!ours.is_empty());
    assert!(ours
        .iter()
        .all(|record| record.ppid == DIAMETER_DTLS_SCTP_PPID));
    for record in &ours {
        let header = record.record_header.expect("acceptor record header");
        let bounds = crate::parse_dtls_record_bounds(&header).expect("parseable record");
        assert_eq!(bounds.record_bytes, record.payload_bytes);
        assert!(!bounds.unified, "DTLS 1.2 uses the classic header");
    }
}

#[tokio::test]
async fn connector_rejects_cleartext_input_before_handshake() {
    let material = dtls_material();
    let (mut server_io, client_io, _log) = in_memory_sctp_link(64);
    let connector = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default());
    let deadline = Instant::now() + Duration::from_secs(10);
    let connect = tokio::spawn(async move {
        connector
            .connect_direct(
                Box::new(client_io) as Box<dyn SctpMessageIo>,
                direct_session("client.example.test"),
                deadline,
            )
            .await
    });
    // Cleartext Diameter-looking bytes on PPID 0 towards the connector
    // before any handshake record arrives.
    let mut cleartext = vec![0x01, 0x00, 0x00, 0x14];
    cleartext.resize(20, 0);
    server_io
        .send_raw_message(0, Bytes::from(cleartext))
        .await
        .expect("inject cleartext");
    let outcome = connect.await.expect("join connector");
    assert_eq!(outcome.err(), Some(DiameterTlsError::CleartextInput));
}

#[tokio::test]
async fn mid_session_foreign_ppid_fails_closed() {
    let material = dtls_material();
    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let injector = client_io.injector();
    let acceptor = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default());
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
    let _client = connector
        .connect_direct(
            Box::new(client_io) as Box<dyn SctpMessageIo>,
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect");
    let mut server = server.await.expect("join acceptor").expect("accept");

    // A foreign-PPID user message mid-session must fail the association
    // closed rather than being delivered or ignored.
    injector
        .send_raw_message(46, Bytes::from_static(b"\x01\x00\x00\x14foreign"))
        .await
        .expect("inject foreign ppid");
    let outcome = server.receive_message(deadline).await;
    assert_eq!(outcome.err(), Some(DiameterTlsError::CleartextInput));
    assert_eq!(
        server.readiness().err(),
        Some(DiameterTlsError::Retired),
        "a foreign-PPID violation poisons the association"
    );
}

#[tokio::test(start_paused = true)]
async fn maximum_connection_age_retires_association() {
    let material = dtls_material();
    let policy = DtlsSctpPolicy::default()
        .with_maximum_connection_age(Duration::from_secs(1))
        .expect("connection age policy");
    let (mut client, _server, _log) = establish_pair(&material, policy, policy)
        .await
        .expect("establish protected association");
    assert!(client.readiness().is_ok());
    // Paused time: advance beyond the connection-age bound and let the
    // retirement watcher run.
    tokio::time::advance(Duration::from_secs(2)).await;
    let mut retired = false;
    for _ in 0..10 {
        tokio::task::yield_now().await;
        if let Err(DiameterTlsError::Retired) = client.readiness() {
            retired = true;
            break;
        }
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    assert!(retired, "connection age bound retires the association");
}

#[tokio::test]
async fn not_yet_valid_local_material_is_not_admitted() {
    let material = dtls_material();
    let now = time::OffsetDateTime::now_utc();
    // Hand-build a not-yet-valid local snapshot: the public builder rejects
    // such chains, so swap the certificate into a coherent state to exercise
    // the admission-time validity check directly.
    let mut state = identity_state(SERVER_ID, &material._ca);
    let mut parameters = rcgen::CertificateParams::default();
    parameters.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(SERVER_ID).expect("server URI"),
    ));
    parameters.not_before = now + time::Duration::hours(1);
    parameters.not_after = now + time::Duration::hours(2);
    let key = rcgen::KeyPair::generate().expect("future key");
    let certificate = parameters
        .signed_by(&key, &material._ca)
        .expect("sign future leaf");
    state.svid.cert_chain = vec![certificate.der().clone(), material._ca.der().clone()];
    state.svid.private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    state.svid.expires_at = Timestamp::from_offset_datetime(now + time::Duration::hours(2));
    state.identity.expires_at = state.svid.expires_at;

    let (client_io, server_io, _log) = in_memory_sctp_link(64);
    let (_server_source, server_rx) = watch::channel(Some(state));
    let server_controller = material_controller(&server_rx, SERVER_ID);
    let policy = DtlsSctpPolicy::default();
    let acceptor = DiameterDtlsSctpAcceptor::new(server_controller, expected(CLIENT_ID), policy)
        .expect("build test acceptor");
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
