use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use opc_identity::{build_identity_state, IdentityState, TrustBundle, TrustBundleSet, TrustDomain};
use opc_proto_diameter::base::{
    APPLICATION_ID_COMMON_MESSAGES, AVP_DISCONNECT_CAUSE, AVP_ORIGIN_HOST, AVP_ORIGIN_REALM,
    INBAND_SECURITY_ID_TLS, RESULT_CODE_DIAMETER_AVP_UNSUPPORTED, RESULT_CODE_DIAMETER_MISSING_AVP,
    RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION, RESULT_CODE_DIAMETER_NO_COMMON_SECURITY,
    RESULT_CODE_DIAMETER_SUCCESS, RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY,
    RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
};
use opc_proto_diameter::peer::{
    build_capabilities_exchange_answer, build_capabilities_exchange_error_answer,
    build_capabilities_exchange_request, build_device_watchdog_answer,
    build_device_watchdog_request, build_disconnect_peer_answer, build_disconnect_peer_request,
    parse_device_watchdog_answer, parse_disconnect_peer_answer, peer_answer_flags,
    peer_request_flags, AnswerDiagnostics, CapabilitiesExchangeAnswer,
    CapabilitiesExchangeErrorAnswer, DeviceWatchdogAnswer, DeviceWatchdogRequest,
    DisconnectPeerAnswer, DisconnectPeerRequest, HostIpAddress, PeerCapabilities, PeerIdentity,
    PeerProcedure, PeerProtectionPolicy, PeerProtectionRequirement, PeerProtectionSequence,
    PeerSession, PeerSessionPolicy,
};
use opc_proto_diameter::{
    ApplicationId, CommandCode, CommandFlags, Header, Message, OwnedMessage, VendorId,
    DIAMETER_HEADER_LEN, MAX_U24,
};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder,
    TlsMaterialAvailability, TlsMaterialReloadReason,
};
use opc_types::SpiffeId;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, SanType};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

use opc_diameter_transport::{
    DiameterCapabilitiesExchangeAnswer, DiameterCapabilitiesExchangeOutcome,
    DiameterConnectionRole, DiameterPeerRuntimeConfig, DiameterPeerRuntimeConfigError,
    DiameterPeerRuntimeError, DiameterTlsAcceptor, DiameterTlsCipher, DiameterTlsConnection,
    DiameterTlsConnector, DiameterTlsPolicy, DiameterWatchdogTwinit, DiameterWatchdogTwinitError,
    ExpectedPeerIdentity, ExpectedPeerIdentityError,
};

const CLIENT_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/smf/instance/client-0";
const OTHER_CLIENT_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/smf/instance/client-1";
const SERVER_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/aaa/instance/server-0";
const APP_ID: ApplicationId = ApplicationId::new(16_777_264);

type TestCa = CertifiedIssuer<'static, KeyPair>;

struct TestTlsMaterial {
    _ca: TestCa,
    _client_source: watch::Sender<Option<IdentityState>>,
    _server_source: watch::Sender<Option<IdentityState>>,
    client: AuthenticatedClientConfig,
    server: AuthenticatedServerConfig,
}

fn test_ca() -> TestCa {
    let mut parameters = CertificateParams::default();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(DnType::CommonName, "Diameter transport test CA");
    let key = KeyPair::generate().expect("generate test CA key");
    CertifiedIssuer::self_signed(parameters, key).expect("sign test CA")
}

fn identity_state(spiffe_id: &str, ca: &TestCa) -> IdentityState {
    identity_state_with_trust(spiffe_id, ca, vec![ca.der().clone()])
}

fn identity_state_with_trust(
    spiffe_id: &str,
    ca: &TestCa,
    trusted_certificates: Vec<rustls_pki_types::CertificateDer<'static>>,
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
    trusted_certificates: Vec<rustls_pki_types::CertificateDer<'static>>,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> IdentityState {
    identity_state_with_validity_trust_and_dns(
        spiffe_id,
        ca,
        trusted_certificates,
        not_before,
        not_after,
        true,
    )
}

fn identity_state_with_validity_trust_and_dns(
    spiffe_id: &str,
    ca: &TestCa,
    trusted_certificates: Vec<rustls_pki_types::CertificateDer<'static>>,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
    include_server_dns_san: bool,
) -> IdentityState {
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("valid SPIFFE URI"),
    ));
    if spiffe_id == SERVER_ID && include_server_dns_san {
        parameters.subject_alt_names.push(SanType::DnsName(
            rcgen::string::Ia5String::try_from("diameter.example.test")
                .expect("valid Diameter DNS name"),
        ));
    }
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate leaf key");
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

fn tls_material() -> TestTlsMaterial {
    let ca = test_ca();
    let (client_source, client_rx) = watch::channel(Some(identity_state(CLIENT_ID, &ca)));
    let (server_source, server_rx) = watch::channel(Some(identity_state(SERVER_ID, &ca)));
    let client = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("build client config");
    let server = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("build server config");
    TestTlsMaterial {
        _ca: ca,
        _client_source: client_source,
        _server_source: server_source,
        client,
        server,
    }
}

fn tls_material_with_spiffe_only_server_certificate() -> TestTlsMaterial {
    let ca = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let (client_source, client_rx) = watch::channel(Some(identity_state(CLIENT_ID, &ca)));
    let server_identity = identity_state_with_validity_trust_and_dns(
        SERVER_ID,
        &ca,
        vec![ca.der().clone()],
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
        false,
    );
    let (server_source, server_rx) = watch::channel(Some(server_identity));
    let client = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("build client config");
    let server = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("build server config");
    TestTlsMaterial {
        _ca: ca,
        _client_source: client_source,
        _server_source: server_source,
        client,
        server,
    }
}

fn tls_material_with_leaf_expiries(
    client_not_after: time::OffsetDateTime,
    server_not_after: time::OffsetDateTime,
) -> TestTlsMaterial {
    let ca = test_ca();
    let not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let (client_source, client_rx) = watch::channel(Some(identity_state_with_validity_and_trust(
        CLIENT_ID,
        &ca,
        vec![ca.der().clone()],
        not_before,
        client_not_after,
    )));
    let (server_source, server_rx) = watch::channel(Some(identity_state_with_validity_and_trust(
        SERVER_ID,
        &ca,
        vec![ca.der().clone()],
        not_before,
        server_not_after,
    )));
    let client = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("build client config");
    let server = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("build server config");
    TestTlsMaterial {
        _ca: ca,
        _client_source: client_source,
        _server_source: server_source,
        client,
        server,
    }
}

fn direct_session(host: &str) -> PeerSession {
    PeerSession::with_policy_and_protection(
        capabilities(host, false),
        peer_policy(),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::direct_tls_tcp()),
    )
}

fn capabilities(host: &str, inband_tls: bool) -> PeerCapabilities {
    let mut capabilities = PeerCapabilities::new(
        PeerIdentity::new(host, "example.test"),
        vec![HostIpAddress::ipv4([192, 0, 2, 10])],
        VendorId::new(10_415),
        "transport-test",
    );
    capabilities.auth_application_ids = vec![APP_ID];
    if inband_tls {
        capabilities.inband_security_ids = vec![INBAND_SECURITY_ID_TLS];
    }
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

fn encode_message(message: &OwnedMessage) -> Bytes {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("encode Diameter message");
    wire.freeze()
}

async fn read_diameter_frame_header<R>(reader: &mut R) -> [u8; DIAMETER_HEADER_LEN]
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; DIAMETER_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .expect("read Diameter header");
    let declared_length =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    assert!(declared_length >= DIAMETER_HEADER_LEN);
    let mut body = vec![0_u8; declared_length - DIAMETER_HEADER_LEN];
    reader
        .read_exact(&mut body)
        .await
        .expect("read Diameter body");
    header
}

async fn read_diameter_frame<R>(reader: &mut R) -> OwnedMessage
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; DIAMETER_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .expect("read Diameter header");
    let declared_length =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    assert!(declared_length >= DIAMETER_HEADER_LEN);
    let mut wire = BytesMut::with_capacity(declared_length);
    wire.extend_from_slice(&header);
    wire.resize(declared_length, 0);
    reader
        .read_exact(&mut wire[DIAMETER_HEADER_LEN..])
        .await
        .expect("read Diameter body");
    OwnedMessage::decode_owned(wire.freeze(), DecodeContext::default())
        .expect("decode complete Diameter frame")
}

fn ietf_avp(code: u32, mandatory: bool, value: &[u8]) -> Bytes {
    let declared_length = 8_usize
        .checked_add(value.len())
        .expect("small synthetic AVP length");
    let padded_length = declared_length
        .checked_add(3)
        .expect("small synthetic AVP padding")
        & !3;
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

fn peer_request_with_avps(
    procedure: PeerProcedure,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    avps: &[Bytes],
) -> OwnedMessage {
    let mut raw_avps = BytesMut::new();
    for avp in avps {
        raw_avps.extend_from_slice(avp);
    }
    OwnedMessage {
        header: Header::new(
            peer_request_flags(procedure),
            procedure.command_code(),
            APPLICATION_ID_COMMON_MESSAGES,
            hop_by_hop_identifier,
            end_to_end_identifier,
        ),
        raw_avps: raw_avps.freeze(),
    }
}

#[derive(Clone, Copy)]
enum ReservedFlagMutation {
    Command,
    FirstAvp,
}

#[derive(Clone, Copy)]
enum ProtocolErrorMutation {
    WrongCorrelation,
    MissingErrorBit,
}

fn add_reserved_flag(message: &OwnedMessage, mutation: ReservedFlagMutation) -> Vec<u8> {
    let mut wire = encode_message(message).to_vec();
    match mutation {
        ReservedFlagMutation::Command => wire[4] |= 0x08,
        ReservedFlagMutation::FirstAvp => wire[DIAMETER_HEADER_LEN + 4] |= 0x10,
    }
    wire
}

fn expected(value: &str) -> ExpectedPeerIdentity {
    let origin_host = if value == SERVER_ID {
        "server.example.test"
    } else {
        "client.example.test"
    };
    expected_with_diameter(value, origin_host, "example.test")
}

fn expected_with_diameter(
    spiffe_id: &str,
    origin_host: &str,
    origin_realm: &str,
) -> ExpectedPeerIdentity {
    ExpectedPeerIdentity::new(
        SpiffeId::new(spiffe_id).expect("valid expected SPIFFE ID"),
        PeerIdentity::new(origin_host, origin_realm),
    )
    .expect("valid expected Diameter identity")
}

fn server_name() -> ServerName<'static> {
    ServerName::try_from("diameter.example.test".to_string()).expect("valid TLS server name")
}

#[test]
fn expected_peer_identity_rejects_empty_or_non_ascii_host_and_realm() {
    for (host, realm, expected_error) in [
        (
            "",
            "example.test",
            ExpectedPeerIdentityError::EmptyOriginHost,
        ),
        (
            "clïent.example.test",
            "example.test",
            ExpectedPeerIdentityError::NonAsciiOriginHost,
        ),
        (
            "client.example.test",
            "",
            ExpectedPeerIdentityError::EmptyOriginRealm,
        ),
        (
            "client.example.test",
            "exämple.test",
            ExpectedPeerIdentityError::NonAsciiOriginRealm,
        ),
    ] {
        let error = ExpectedPeerIdentity::new(
            SpiffeId::new(CLIENT_ID).expect("valid expected SPIFFE ID"),
            PeerIdentity::new(host, realm),
        )
        .expect_err("invalid configured Diameter identity must fail");
        assert_eq!(error, expected_error);
    }
}

#[test]
fn local_capability_builders_reject_non_ascii_diameter_identity() {
    let invalid = capabilities("clïent.example.test", false);
    assert!(build_capabilities_exchange_request(&invalid, 1, 2, EncodeContext::default()).is_err());
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: invalid,
        diagnostics: AnswerDiagnostics::default(),
    };
    assert!(build_capabilities_exchange_answer(&answer, 1, 2, EncodeContext::default()).is_err());
}

fn raw_client_config(
    ca: &TestCa,
    validity: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
) -> tokio_rustls::rustls::ClientConfig {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).expect("add test CA");
    let builder = tokio_rustls::rustls::ClientConfig::builder().with_root_certificates(roots);
    match validity {
        None => builder.with_no_client_auth(),
        Some((not_before, not_after)) => {
            let (chain, key) = raw_client_credentials(ca, not_before, not_after);
            builder
                .with_client_auth_cert(chain, key)
                .expect("build raw client config")
        }
    }
}

fn raw_tls12_client_config(ca: &TestCa) -> tokio_rustls::rustls::ClientConfig {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).expect("add test CA");
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let builder = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS12])
        .expect("enable only TLS 1.2")
        .with_root_certificates(roots);
    let now = time::OffsetDateTime::now_utc();
    let (chain, key) = raw_client_credentials(
        ca,
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );
    builder
        .with_client_auth_cert(chain, key)
        .expect("build TLS 1.2 raw client config")
}

fn raw_client_credentials(
    ca: &TestCa,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut parameters = CertificateParams::default();
    parameters.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(CLIENT_ID).expect("valid client SPIFFE URI"),
    ));
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    let key = KeyPair::generate().expect("generate raw client key");
    let certificate = parameters
        .signed_by(&key, ca)
        .expect("sign raw client certificate");
    (
        vec![certificate.der().clone(), ca.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

async fn assert_tcp_eventually_closed(tcp: &mut TcpStream) {
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut buffer = [0_u8; 256];
        loop {
            match tcp.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("peer must close TCP");
}

async fn assert_tls_eventually_closed<T>(tls: &mut T)
where
    T: AsyncRead + Unpin,
{
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            match tls.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("peer must synchronously close the underlying TCP stream");
}

#[tokio::test]
async fn direct_connector_and_acceptor_admit_mutual_tls_before_diameter() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept Diameter TLS")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect Diameter TLS");
    let mut server = server.await.expect("join server");

    assert_eq!(client.evidence().role(), DiameterConnectionRole::Connector);
    assert_eq!(server.evidence().role(), DiameterConnectionRole::Acceptor);
    assert_eq!(
        client.evidence().peer_identity().spiffe_id().as_str(),
        SERVER_ID
    );
    assert_eq!(
        server.evidence().peer_identity().spiffe_id().as_str(),
        CLIENT_ID
    );
    assert_eq!(
        client.evidence().protection().sequence(),
        PeerProtectionSequence::DirectBeforeCapabilities
    );
    assert_eq!(
        server.evidence().protection().sequence(),
        PeerProtectionSequence::DirectBeforeCapabilities
    );
    assert!(client
        .protection_readiness()
        .expect("active client readiness")
        .protected_ready());
    assert!(server
        .protection_readiness()
        .expect("active server readiness")
        .protected_ready());

    let (sent, received) = tokio::join!(
        client.send_capabilities_request(0x1234, 0x5678, deadline),
        server.receive_capabilities_request(deadline),
    );
    assert!(sent.expect("send canonical direct CER").is_protected());
    assert_eq!(
        received.expect("receive strict direct CER"),
        capabilities("client.example.test", false)
    );
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: capabilities("server.example.test", false),
        diagnostics: AnswerDiagnostics::default(),
    };
    let (emitted, observed) = tokio::join!(
        server.send_capabilities_answer(&answer, deadline),
        client.receive_capabilities_answer(deadline),
    );
    assert!(matches!(
        emitted.expect("emit canonical direct CEA"),
        DiameterCapabilitiesExchangeOutcome::Negotiated(_)
    ));
    let (observed_answer, outcome) = observed.expect("receive correlated direct CEA");
    assert_eq!(
        observed_answer,
        DiameterCapabilitiesExchangeAnswer::Answer(answer)
    );
    assert!(matches!(
        outcome,
        DiameterCapabilitiesExchangeOutcome::Negotiated(_)
    ));
    assert!(client.readiness().expect("negotiated client").traffic_ready);
    assert!(server.readiness().expect("negotiated server").traffic_ready);

    let request = application_request();
    let (sent, received) = tokio::join!(
        client.send_message(&request, deadline),
        server.receive_message(deadline),
    );
    assert!(sent
        .expect("send client application message")
        .is_protected());
    assert_eq!(
        received.expect("receive client application message").0,
        request
    );
    let response = OwnedMessage {
        header: Header::new(
            CommandFlags::answer(false, false),
            CommandCode::new(268),
            APP_ID,
            0x300,
            0x400,
        ),
        raw_avps: Bytes::new(),
    };
    let (sent, received) = tokio::join!(
        server.send_message(&response, deadline),
        client.receive_message(deadline),
    );
    assert!(sent
        .expect("send server application message")
        .is_protected());
    assert_eq!(
        received.expect("receive server application message").0,
        response
    );

    let client_debug = format!("{client:?}");
    assert!(!client_debug.contains(CLIENT_ID));
    assert!(!client_debug.contains(SERVER_ID));
    assert!(!client_debug.contains("127.0.0.1"));
}

#[tokio::test]
async fn direct_capability_roles_and_generic_base_procedure_paths_fail_without_output() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept Diameter TLS")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect Diameter TLS");
    let mut server = server.await.expect("join server");
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: capabilities("server.example.test", false),
        diagnostics: AnswerDiagnostics::default(),
    };

    assert_eq!(
        client
            .receive_capabilities_request(deadline)
            .await
            .expect_err("connector cannot receive CER"),
        opc_diameter_transport::DiameterTlsError::ConnectionRoleMismatch
    );
    assert_eq!(
        client
            .send_capabilities_answer(&answer, deadline)
            .await
            .expect_err("connector cannot send CEA"),
        opc_diameter_transport::DiameterTlsError::ConnectionRoleMismatch
    );
    assert_eq!(
        server
            .send_capabilities_request(1, 2, deadline)
            .await
            .expect_err("acceptor cannot send CER"),
        opc_diameter_transport::DiameterTlsError::ConnectionRoleMismatch
    );
    assert_eq!(
        server
            .receive_capabilities_answer(deadline)
            .await
            .expect_err("acceptor cannot receive CEA"),
        opc_diameter_transport::DiameterTlsError::ConnectionRoleMismatch
    );

    let generic_cer = build_capabilities_exchange_request(
        &capabilities("client.example.test", false),
        0x1111,
        0x2222,
        EncodeContext::default(),
    )
    .expect("build generic CER attempt");
    assert_eq!(
        client
            .send_message(&generic_cer, deadline)
            .await
            .expect_err("generic send cannot emit CER"),
        opc_diameter_transport::DiameterTlsError::CommandNotAdmitted
    );
    let generic_cea =
        build_capabilities_exchange_answer(&answer, 0x1111, 0x2222, EncodeContext::default())
            .expect("build generic CEA attempt");
    assert_eq!(
        server
            .send_message(&generic_cea, deadline)
            .await
            .expect_err("generic send cannot emit CEA"),
        opc_diameter_transport::DiameterTlsError::CommandNotAdmitted
    );

    let (sent, received) = tokio::join!(
        client.send_capabilities_request(0x3333, 0x4444, deadline),
        server.receive_capabilities_request(deadline),
    );
    sent.expect("valid connector CER remains usable");
    received.expect("no rejected operation emitted a frame");
    let (emitted, observed) = tokio::join!(
        server.send_capabilities_answer(&answer, deadline),
        client.receive_capabilities_answer(deadline),
    );
    assert!(emitted.expect("valid acceptor CEA").is_negotiated());
    assert!(observed.expect("valid connector CEA").1.is_negotiated());
}

#[tokio::test]
async fn direct_non_success_cea_is_emitted_as_rejected_then_both_sides_close() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let mut server_capabilities = capabilities("server.example.test", false);
    server_capabilities.auth_application_ids = vec![ApplicationId::new(999)];
    let server_session = PeerSession::with_policy_and_protection(
        server_capabilities.clone(),
        PeerSessionPolicy::default().accept_application(ApplicationId::new(999)),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::direct_tls_tcp()),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, server_session, deadline)
            .await
            .expect("accept Diameter TLS")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect Diameter TLS");
    let mut server = server.await.expect("join server");
    let (sent, received) = tokio::join!(
        client.send_capabilities_request(0x1234, 0x5678, deadline),
        server.receive_capabilities_request(deadline),
    );
    sent.expect("send canonical CER");
    received.expect("receive canonical CER");
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION,
        capabilities: server_capabilities,
        diagnostics: AnswerDiagnostics::default(),
    };
    let (emitted, observed) = tokio::join!(
        server.send_capabilities_answer(&answer, deadline),
        client.receive_capabilities_answer(deadline),
    );
    assert!(matches!(
        emitted.expect("non-success CEA must be flushed"),
        DiameterCapabilitiesExchangeOutcome::Rejected(_)
    ));
    let (received_answer, outcome) = observed.expect("receive non-success CEA before close");
    assert_eq!(
        received_answer,
        DiameterCapabilitiesExchangeAnswer::Answer(answer)
    );
    assert!(matches!(
        outcome,
        DiameterCapabilitiesExchangeOutcome::Rejected(_)
    ));
    assert_eq!(
        client
            .readiness()
            .expect_err("rejected connector must be closed"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    assert_eq!(
        server
            .readiness()
            .expect_err("rejected acceptor must be closed"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
}

#[tokio::test]
async fn cipher_allowlist_filters_handshake_advertisement_and_negotiates_fallback() {
    let provider = tokio_rustls::rustls::crypto::ring::default_provider();
    assert_ne!(
        provider
            .cipher_suites
            .first()
            .map(tokio_rustls::rustls::SupportedCipherSuite::suite),
        Some(tokio_rustls::rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        "test premise requires the restricted suite not to be the default preference"
    );
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default()
        .with_allowed_ciphers(&[DiameterTlsCipher::Chacha20Poly1305Sha256])
        .expect("restrict transport to a supported fallback suite");
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept with filtered TLS provider")
    });
    let client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect with filtered TLS provider");
    let server = server.await.expect("join filtered server");

    assert_eq!(
        client.evidence().cipher(),
        DiameterTlsCipher::Chacha20Poly1305Sha256
    );
    assert_eq!(
        server.evidence().cipher(),
        DiameterTlsCipher::Chacha20Poly1305Sha256
    );
}

#[tokio::test]
async fn direct_connector_first_wire_octet_is_tls_not_diameter() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let capture = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.expect("accept TCP");
        let mut first = [0_u8; 1];
        tcp.read_exact(&mut first).await.expect("read first octet");
        first[0]
    });
    let result = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            Instant::now() + Duration::from_secs(2),
        )
        .await;
    assert!(result.is_err());
    let first = capture.await.expect("join capture");
    assert_eq!(first, 0x16, "TLS handshake record must be first on wire");
    assert_ne!(first, opc_proto_diameter::DIAMETER_VERSION);
}

#[tokio::test]
async fn direct_server_name_is_routing_input_not_dns_authorization() {
    let material = tls_material_with_spiffe_only_server_certificate();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("SPIFFE-authorized server accepts client")
    });
    let routing_name =
        ServerName::try_from("routing-only.invalid".to_string()).expect("valid routing-only SNI");
    let client = connector
        .connect_direct(
            address,
            routing_name,
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("SPIFFE authorization must not require a DNS SAN");
    assert_eq!(
        client.evidence().peer_identity().spiffe_id().as_str(),
        SERVER_ID
    );
    drop(client);
    drop(server.await.expect("join server"));
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_a_healthy_connection_synchronously_closes_the_peer_socket() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let server_config = material.server;
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let handshake = server_config
            .begin_handshake()
            .expect("freeze server material");
        let mut tls = tokio_rustls::TlsAcceptor::from(handshake.rustls_config())
            .accept(tcp)
            .await
            .expect("accept mutual TLS");
        assert_tls_eventually_closed(&mut tls).await;
    });
    let connection = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("connect Diameter TLS");

    drop(connection);
    server.await.expect("healthy drop must close raw TLS peer");
}

#[tokio::test]
async fn direct_acceptor_rejects_and_closes_cleartext_diameter() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(
                tcp,
                direct_session("server.example.test"),
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("cleartext Diameter must fail in TLS framing")
    });
    let mut attacker = TcpStream::connect(address).await.expect("connect attacker");
    attacker
        .write_all(&encode_message(&application_request()))
        .await
        .expect("write cleartext Diameter");
    let error = server.await.expect("join direct acceptor");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::TlsHandshake
    );
    assert_tcp_eventually_closed(&mut attacker).await;
}

#[tokio::test]
async fn direct_acceptor_deadline_closes_an_incomplete_tls_handshake() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_millis(75);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect_err("stalled TLS must hit the absolute deadline")
    });
    let mut attacker = TcpStream::connect(address).await.expect("connect attacker");
    attacker
        .write_all(&[0x16, 0x03, 0x03, 0x00, 0x10])
        .await
        .expect("write incomplete TLS record header");
    let error = server.await.expect("join direct acceptor");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::DeadlineExceeded
    );
    assert_tcp_eventually_closed(&mut attacker).await;
}

#[tokio::test]
async fn direct_acceptor_rejects_a_tls12_downgrade_during_handshake() {
    let ca = test_ca();
    let (server_source, server_rx) = watch::channel(Some(identity_state(SERVER_ID, &ca)));
    let server_config = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .with_compat_mode(true)
        .build_authenticated_server_config()
        .expect("build TLS 1.2-compatible server config");
    let raw_client = raw_tls12_client_config(&ca);
    let _server_source = server_source;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        server_config,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
    });
    let tcp = TcpStream::connect(address)
        .await
        .expect("connect raw client");
    let connect =
        tokio_rustls::TlsConnector::from(Arc::new(raw_client)).connect(server_name(), tcp);
    let (client_result, server_result) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(connect, server)
    })
    .await
    .expect("downgrade rejection must be bounded");
    drop(client_result);
    let error = server_result
        .expect("join direct acceptor")
        .expect_err("TLS 1.2 must not be admitted");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::TlsHandshake
    );
}

#[tokio::test]
async fn direct_acceptor_rejects_an_unconfigured_exact_peer() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let wrong_client =
        "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/smf/instance/other-0";
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(wrong_client),
        DiameterTlsPolicy::default(),
    );
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
    });
    let client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await;
    let server = server.await.expect("join server");
    assert_eq!(
        server.expect_err("wrong inbound identity must fail"),
        opc_diameter_transport::DiameterTlsError::PeerIdentityMismatch
    );
    // The TLS client may finish before the server's post-handshake exact-ID
    // check. If it does, the server's synchronous full-close must become a
    // terminal I/O failure and revoke the client's retained generation.
    if let Ok(mut connection) = client {
        assert_eq!(
            connection
                .receive_message(Instant::now() + Duration::from_secs(1))
                .await
                .expect_err("identity rejection must full-close the peer socket"),
            opc_diameter_transport::DiameterTlsError::Transport
        );
        assert_eq!(
            connection
                .peer_session_snapshot()
                .expect_err("terminal peer close must retire readiness access"),
            opc_diameter_transport::DiameterTlsError::Retired
        );
        let session = connection.close().expect("close rejected peer connection");
        assert!(!session.protection_readiness().protected_ready());
        assert!(!session.readiness().traffic_ready);
    }
}

#[tokio::test]
async fn direct_connector_requires_a_direct_tls_peer_session() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let capabilities = PeerCapabilities::new(
        PeerIdentity::new("client.example.test", "example.test"),
        vec![HostIpAddress::ipv4([192, 0, 2, 10])],
        VendorId::new(10_415),
        "transport-test",
    );
    let wrong_session = PeerSession::with_policy_and_protection(
        capabilities,
        PeerSessionPolicy::default(),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::inband_tls_tcp()),
    );
    let error = connector
        .connect_direct(
            address,
            server_name(),
            wrong_session,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("in-band session must not enter direct connector");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::ProtectionPolicyMismatch
    );
    assert!(TcpStream::connect(address).await.is_ok());
}

#[tokio::test]
async fn direct_mode_reports_malformed_cea_as_capabilities_failure() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let server_config = material.server;
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let handshake = server_config
            .begin_handshake()
            .expect("freeze server material");
        let mut tls = tokio_rustls::TlsAcceptor::from(handshake.rustls_config())
            .accept(tcp)
            .await
            .expect("accept mutual TLS");
        let mut header = [0_u8; DIAMETER_HEADER_LEN];
        tls.read_exact(&mut header).await.expect("read CER header");
        let declared_length =
            (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
        assert!(declared_length >= DIAMETER_HEADER_LEN);
        let mut body = vec![0_u8; declared_length - DIAMETER_HEADER_LEN];
        tls.read_exact(&mut body).await.expect("read CER body");

        let malformed_answer = OwnedMessage {
            header: Header::new(
                peer_answer_flags(PeerProcedure::CapabilitiesExchange, false),
                PeerProcedure::CapabilitiesExchange.command_code(),
                APPLICATION_ID_COMMON_MESSAGES,
                u32::from_be_bytes(header[12..16].try_into().expect("hop-by-hop field")),
                u32::from_be_bytes(header[16..20].try_into().expect("end-to-end field")),
            ),
            // A success CEA without Result-Code, Origin-Host, or Origin-Realm
            // is framed correctly but structurally invalid.
            raw_avps: Bytes::new(),
        };
        tls.write_all(&encode_message(&malformed_answer))
            .await
            .expect("write malformed CEA");
        tls.flush().await.expect("flush malformed CEA");
        assert_tls_eventually_closed(&mut tls).await;
    });

    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect Diameter TLS");
    client
        .send_capabilities_request(0x1234, 0x5678, deadline)
        .await
        .expect("send CER");
    let error = client
        .receive_capabilities_answer(deadline)
        .await
        .expect_err("malformed CEA must not be released");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::CapabilitiesExchangeFailed
    );
    assert_eq!(
        client
            .protection_readiness()
            .expect_err("malformed CEA must retire readiness access"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    assert_eq!(
        client
            .receive_message(Instant::now() + Duration::from_secs(1))
            .await
            .expect_err("terminal framing failure must poison the retained handle"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    let session = client.close().expect("close poisoned client");
    assert!(!session.protection_readiness().protected_ready());
    server.await.expect("join malformed CEA server");
}

#[tokio::test]
async fn direct_connector_returns_exact_correlated_protocol_error_cea_then_closes() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let server_config = material.server;
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let error_answer = CapabilitiesExchangeErrorAnswer {
        result_code: RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        identity: PeerIdentity::new("server.example.test", "example.test"),
        diagnostics: AnswerDiagnostics::default(),
    };
    let server_expected = error_answer.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let handshake = server_config
            .begin_handshake()
            .expect("freeze server material");
        let mut tls = tokio_rustls::TlsAcceptor::from(handshake.rustls_config())
            .accept(tcp)
            .await
            .expect("accept mutual TLS");
        let header = read_diameter_frame_header(&mut tls).await;
        let answer = build_capabilities_exchange_error_answer(
            &server_expected,
            u32::from_be_bytes(header[12..16].try_into().expect("CER hop-by-hop")),
            u32::from_be_bytes(header[16..20].try_into().expect("CER end-to-end")),
            EncodeContext::default(),
        )
        .expect("build correlated protocol-error CEA");
        assert!(answer.header.flags.is_error());
        tls.write_all(&encode_message(&answer))
            .await
            .expect("write protocol-error CEA");
        tls.flush().await.expect("flush protocol-error CEA");
        assert_tls_eventually_closed(&mut tls).await;
    });

    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect Diameter TLS");
    client
        .send_capabilities_request(0x1234, 0x5678, deadline)
        .await
        .expect("send canonical CER");
    let (answer, outcome) = client
        .receive_capabilities_answer(deadline)
        .await
        .expect("return typed protocol-error CEA");
    assert_eq!(
        answer,
        DiameterCapabilitiesExchangeAnswer::ProtocolError(error_answer)
    );
    assert!(matches!(
        outcome,
        DiameterCapabilitiesExchangeOutcome::Rejected(_)
    ));
    assert_eq!(
        client
            .readiness()
            .expect_err("protocol-error outcome must close the connection"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    server.await.expect("join protocol-error server");
}

#[tokio::test]
async fn direct_connector_rejects_uncorrelated_or_missing_e_bit_protocol_error_cea() {
    for (mutation, expected_error) in [
        (
            ProtocolErrorMutation::WrongCorrelation,
            opc_diameter_transport::DiameterTlsError::CommandNotAdmitted,
        ),
        (
            ProtocolErrorMutation::MissingErrorBit,
            opc_diameter_transport::DiameterTlsError::CapabilitiesExchangeFailed,
        ),
    ] {
        let material = tls_material();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server_config = material.server;
        let connector = DiameterTlsConnector::new(
            material.client,
            expected(SERVER_ID),
            DiameterTlsPolicy::default(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let handshake = server_config
                .begin_handshake()
                .expect("freeze server material");
            let mut tls = tokio_rustls::TlsAcceptor::from(handshake.rustls_config())
                .accept(tcp)
                .await
                .expect("accept mutual TLS");
            let header = read_diameter_frame_header(&mut tls).await;
            let hop_by_hop = u32::from_be_bytes(header[12..16].try_into().expect("CER hop-by-hop"));
            let end_to_end = u32::from_be_bytes(header[16..20].try_into().expect("CER end-to-end"));
            let mut answer = build_capabilities_exchange_error_answer(
                &CapabilitiesExchangeErrorAnswer {
                    result_code: RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
                    identity: PeerIdentity::new("server.example.test", "example.test"),
                    diagnostics: AnswerDiagnostics::default(),
                },
                if matches!(mutation, ProtocolErrorMutation::WrongCorrelation) {
                    hop_by_hop.wrapping_add(1)
                } else {
                    hop_by_hop
                },
                end_to_end,
                EncodeContext::default(),
            )
            .expect("build protocol-error CEA");
            if matches!(mutation, ProtocolErrorMutation::MissingErrorBit) {
                answer.header.flags = peer_answer_flags(PeerProcedure::CapabilitiesExchange, false);
            }
            tls.write_all(&encode_message(&answer))
                .await
                .expect("write invalid protocol-error CEA");
            tls.flush().await.expect("flush invalid protocol-error CEA");
            assert_tls_eventually_closed(&mut tls).await;
        });

        let mut client = connector
            .connect_direct(
                address,
                server_name(),
                direct_session("client.example.test"),
                deadline,
            )
            .await
            .expect("connect Diameter TLS");
        client
            .send_capabilities_request(0x1234, 0x5678, deadline)
            .await
            .expect("send canonical CER");
        assert_eq!(
            client
                .receive_capabilities_answer(deadline)
                .await
                .expect_err("invalid protocol-error CEA must fail"),
            expected_error
        );
        assert_eq!(
            client
                .readiness()
                .expect_err("invalid protocol-error CEA must retire connection"),
            opc_diameter_transport::DiameterTlsError::Retired
        );
        server.await.expect("join invalid protocol-error server");
    }
}

#[tokio::test]
async fn direct_mode_reports_malformed_cer_as_capabilities_failure() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let client_config = material.client;
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let mut connection = acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept Diameter TLS");
        connection.receive_capabilities_request(deadline).await
    });
    let handshake = client_config
        .begin_handshake()
        .expect("freeze client material");
    let mut rustls_config = handshake.rustls_config().as_ref().clone();
    rustls_config.alpn_protocols.clear();
    let tcp = TcpStream::connect(address)
        .await
        .expect("connect raw TLS client");
    let mut client = tokio_rustls::TlsConnector::from(Arc::new(rustls_config))
        .connect(server_name(), tcp)
        .await
        .expect("connect mutual TLS");
    let malformed_request = OwnedMessage {
        header: Header::new(
            peer_request_flags(PeerProcedure::CapabilitiesExchange),
            PeerProcedure::CapabilitiesExchange.command_code(),
            APPLICATION_ID_COMMON_MESSAGES,
            0x1234,
            0x5678,
        ),
        // A CER without the mandatory identity and capability AVPs is framed
        // correctly but structurally invalid.
        raw_avps: Bytes::new(),
    };
    client
        .write_all(&encode_message(&malformed_request))
        .await
        .expect("send malformed CER frame");
    client.flush().await.expect("flush malformed CER");
    let error = server
        .await
        .expect("join server")
        .expect_err("malformed CER must not be released");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::CapabilitiesExchangeFailed
    );
    assert_tls_eventually_closed(&mut client).await;
}

#[tokio::test]
async fn inband_cer_rejects_reserved_command_and_avp_flags_before_tls() {
    for (mutation, expected_error) in [
        (
            ReservedFlagMutation::Command,
            opc_diameter_transport::DiameterTlsError::InvalidFrame,
        ),
        (
            ReservedFlagMutation::FirstAvp,
            opc_diameter_transport::DiameterTlsError::CapabilitiesExchangeFailed,
        ),
    ] {
        let material = tls_material();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let acceptor = DiameterTlsAcceptor::new(
            material.server,
            expected(CLIENT_ID),
            DiameterTlsPolicy::default(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            acceptor
                .accept_inband(
                    tcp,
                    capabilities("server.example.test", true),
                    peer_policy(),
                )
                .expect("bind in-band responder")
                .receive_capabilities_request(deadline)
                .await
                .expect_err("reserved CER flag must fail before TLS")
        });
        let request = build_capabilities_exchange_request(
            &capabilities("client.example.test", true),
            0x1234,
            0x5678,
            EncodeContext::default(),
        )
        .expect("build valid CER before reserved-bit mutation");
        let mut attacker = TcpStream::connect(address).await.expect("connect attacker");
        attacker
            .write_all(&add_reserved_flag(&request, mutation))
            .await
            .expect("write reserved-bit CER");
        attacker.flush().await.expect("flush reserved-bit CER");
        assert_eq!(
            server.await.expect("join in-band responder"),
            expected_error
        );
        assert_tcp_eventually_closed(&mut attacker).await;
    }
}

#[tokio::test]
async fn inband_cer_rejects_non_ascii_diameter_identity_on_the_wire() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_inband(
                tcp,
                capabilities("server.example.test", true),
                peer_policy(),
            )
            .expect("bind in-band responder")
            .receive_capabilities_request(deadline)
            .await
            .expect_err("non-ASCII DiameterIdentity must fail before TLS")
    });
    let request = build_capabilities_exchange_request(
        &capabilities("client.example.test", true),
        0x1234,
        0x5678,
        EncodeContext::default(),
    )
    .expect("build valid CER before Unicode mutation");
    let mut wire = encode_message(&request).to_vec();
    let host_offset = wire
        .windows(b"client.example.test".len())
        .position(|window| window == b"client.example.test")
        .expect("find Origin-Host bytes");
    wire[host_offset..host_offset + 2].copy_from_slice(&[0xc3, 0xa9]);
    let mut attacker = TcpStream::connect(address).await.expect("connect attacker");
    attacker.write_all(&wire).await.expect("write Unicode CER");
    attacker.flush().await.expect("flush Unicode CER");
    assert_eq!(
        server.await.expect("join in-band responder"),
        opc_diameter_transport::DiameterTlsError::CapabilitiesExchangeFailed
    );
    assert_tcp_eventually_closed(&mut attacker).await;
}

#[tokio::test]
async fn direct_cea_rejects_reserved_command_and_avp_flags_before_readiness() {
    for (mutation, expected_error) in [
        (
            ReservedFlagMutation::Command,
            opc_diameter_transport::DiameterTlsError::InvalidFrame,
        ),
        (
            ReservedFlagMutation::FirstAvp,
            opc_diameter_transport::DiameterTlsError::CapabilitiesExchangeFailed,
        ),
    ] {
        let material = tls_material();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server_config = material.server;
        let connector = DiameterTlsConnector::new(
            material.client,
            expected(SERVER_ID),
            DiameterTlsPolicy::default(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let handshake = server_config
                .begin_handshake()
                .expect("freeze server material");
            let mut tls = tokio_rustls::TlsAcceptor::from(handshake.rustls_config())
                .accept(tcp)
                .await
                .expect("accept mutual TLS");
            let header = read_diameter_frame_header(&mut tls).await;
            let answer = build_capabilities_exchange_answer(
                &CapabilitiesExchangeAnswer {
                    result_code: RESULT_CODE_DIAMETER_SUCCESS,
                    capabilities: capabilities("server.example.test", false),
                    diagnostics: AnswerDiagnostics::default(),
                },
                u32::from_be_bytes(header[12..16].try_into().expect("CER hop-by-hop")),
                u32::from_be_bytes(header[16..20].try_into().expect("CER end-to-end")),
                EncodeContext::default(),
            )
            .expect("build valid CEA before reserved-bit mutation");
            tls.write_all(&add_reserved_flag(&answer, mutation))
                .await
                .expect("write reserved-bit CEA");
            tls.flush().await.expect("flush reserved-bit CEA");
            assert_tls_eventually_closed(&mut tls).await;
        });

        let mut client = connector
            .connect_direct(
                address,
                server_name(),
                direct_session("client.example.test"),
                deadline,
            )
            .await
            .expect("connect Diameter TLS");
        client
            .send_capabilities_request(0x1234, 0x5678, deadline)
            .await
            .expect("send canonical CER");
        assert_eq!(
            client
                .receive_capabilities_answer(deadline)
                .await
                .expect_err("reserved CEA flag must fail before readiness"),
            expected_error
        );
        assert_eq!(
            client
                .readiness()
                .expect_err("reserved CEA flag must retire connection"),
            opc_diameter_transport::DiameterTlsError::Retired
        );
        server.await.expect("join reserved-bit server");
    }
}

#[tokio::test]
async fn cancelling_receive_after_a_partial_frame_terminally_poisons_connection() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let server_config = material.server.clone();
    let connector = DiameterTlsConnector::new(
        material.client.clone(),
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let (partial_tx, partial_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let handshake = server_config
            .begin_handshake()
            .expect("freeze server material");
        let mut tls = tokio_rustls::TlsAcceptor::from(handshake.rustls_config())
            .accept(tcp)
            .await
            .expect("accept mutual TLS");
        let wire = encode_message(&application_request());
        tls.write_all(&wire[..10])
            .await
            .expect("write partial Diameter header");
        tls.flush().await.expect("flush partial Diameter header");
        partial_tx.send(()).expect("signal partial read");
        assert_tls_eventually_closed(&mut tls).await;
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("connect Diameter TLS");

    {
        let receive = client.receive_message(Instant::now() + Duration::from_secs(5));
        tokio::pin!(receive);
        tokio::select! {
            biased;
            result = &mut receive => panic!("partial read unexpectedly completed: {result:?}"),
            result = partial_rx => result.expect("raw peer must write a partial frame"),
        }
    }

    assert_eq!(
        client
            .protection_readiness()
            .expect_err("cancelled receive must retire readiness access"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    assert_eq!(
        client
            .send_message(
                &application_request(),
                Instant::now() + Duration::from_secs(1)
            )
            .await
            .expect_err("retained handle must not resume after read cancellation"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    let session = client.close().expect("close cancelled client");
    assert!(!session.protection_readiness().protected_ready());
    server.await.expect("join partial-frame server");
}

#[tokio::test]
async fn cancelling_send_after_a_partial_frame_terminally_poisons_connection() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let server_config = material.server.clone();
    let frame_limits = opc_diameter_transport::DiameterFrameLimits::new(MAX_U24 as usize)
        .expect("maximum Diameter frame bound");
    let policy = DiameterTlsPolicy::tls13(frame_limits);
    let connector = DiameterTlsConnector::new(material.client.clone(), expected(SERVER_ID), policy);
    let (partial_tx, partial_rx) = oneshot::channel();
    let (cancelled_tx, cancelled_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let handshake = server_config
            .begin_handshake()
            .expect("freeze server material");
        let mut tls = tokio_rustls::TlsAcceptor::from(handshake.rustls_config())
            .accept(tcp)
            .await
            .expect("accept mutual TLS");
        let mut cer_header = [0_u8; DIAMETER_HEADER_LEN];
        tls.read_exact(&mut cer_header)
            .await
            .expect("read CER header");
        let cer_len = (usize::from(cer_header[1]) << 16)
            | (usize::from(cer_header[2]) << 8)
            | usize::from(cer_header[3]);
        let mut cer_body = vec![0_u8; cer_len - DIAMETER_HEADER_LEN];
        tls.read_exact(&mut cer_body).await.expect("read CER body");
        let answer = CapabilitiesExchangeAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            capabilities: capabilities("server.example.test", false),
            diagnostics: AnswerDiagnostics::default(),
        };
        let cea = build_capabilities_exchange_answer(
            &answer,
            u32::from_be_bytes(cer_header[12..16].try_into().expect("CER hop-by-hop")),
            u32::from_be_bytes(cer_header[16..20].try_into().expect("CER end-to-end")),
            EncodeContext::default(),
        )
        .expect("build correlated CEA");
        tls.write_all(&encode_message(&cea))
            .await
            .expect("write correlated CEA");
        tls.flush().await.expect("flush correlated CEA");
        let mut prefix = [0_u8; 64 * 1024];
        tls.read_exact(&mut prefix)
            .await
            .expect("read a strict prefix of the Diameter frame");
        partial_tx.send(()).expect("signal partial write");
        cancelled_rx
            .await
            .expect("client must cancel the partial write");
        assert_tls_eventually_closed(&mut tls).await;
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("connect Diameter TLS");
    client
        .send_capabilities_request(0x1234, 0x5678, Instant::now() + Duration::from_secs(5))
        .await
        .expect("send CER before large application frame");
    let (_, outcome) = client
        .receive_capabilities_answer(Instant::now() + Duration::from_secs(5))
        .await
        .expect("receive CEA before large application frame");
    assert!(outcome.is_negotiated());
    let oversized_request = OwnedMessage {
        header: Header::new(
            CommandFlags::request(true),
            CommandCode::new(268),
            APP_ID,
            0x1234,
            0x5678,
        ),
        raw_avps: Bytes::from(vec![0_u8; (MAX_U24 as usize) - DIAMETER_HEADER_LEN]),
    };

    {
        let send =
            client.send_message(&oversized_request, Instant::now() + Duration::from_secs(10));
        tokio::pin!(send);
        tokio::select! {
            biased;
            result = &mut send => panic!("partial write unexpectedly completed: {result:?}"),
            result = partial_rx => result.expect("raw peer must read a strict frame prefix"),
        }
    }
    cancelled_tx
        .send(())
        .expect("signal cancellation to raw peer");

    assert_eq!(
        client
            .protection_readiness()
            .expect_err("cancelled send must retire readiness access"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    assert_eq!(
        client
            .receive_message(Instant::now() + Duration::from_secs(1))
            .await
            .expect_err("retained handle must not resume after write cancellation"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    let session = client.close().expect("close cancelled sender");
    assert!(!session.protection_readiness().protected_ready());
    server.await.expect("join partial-write server");
}

#[tokio::test]
async fn inband_typestate_exchanges_only_cer_cea_then_upgrades_same_stream() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let server_capabilities = capabilities("server.example.test", true);
    let client_capabilities = capabilities("client.example.test", true);
    let deadline = Instant::now() + Duration::from_secs(5);

    let server = tokio::spawn({
        let server_capabilities = server_capabilities.clone();
        let expected_client_capabilities = client_capabilities.clone();
        async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let responder = acceptor
                .accept_inband(tcp, server_capabilities.clone(), peer_policy())
                .expect("bind in-band responder");
            let (responder, remote) = responder
                .receive_capabilities_request(deadline)
                .await
                .expect("receive cleartext CER");
            assert_eq!(remote, expected_client_capabilities);
            responder
                .send_capabilities_answer_and_upgrade(
                    &CapabilitiesExchangeAnswer {
                        result_code: RESULT_CODE_DIAMETER_SUCCESS,
                        capabilities: server_capabilities,
                        diagnostics: AnswerDiagnostics::default(),
                    },
                    deadline,
                )
                .await
                .expect("upgrade responder to TLS")
        }
    });

    let initiator = connector
        .connect_inband(
            address,
            server_name(),
            client_capabilities,
            peer_policy(),
            deadline,
        )
        .await
        .expect("connect cleartext in-band TCP");
    let awaiting = initiator
        .send_capabilities_request(0x1111, 0x2222, deadline)
        .await
        .expect("send cleartext CER");
    let (mut client, answer) = awaiting
        .receive_capabilities_answer_and_upgrade(deadline)
        .await
        .expect("receive CEA and upgrade to TLS");
    let mut server = server.await.expect("join server");

    assert_eq!(answer.capabilities, server_capabilities);
    assert_eq!(
        client.evidence().protection().sequence(),
        PeerProtectionSequence::InbandAfterCapabilities
    );
    assert_eq!(
        server.evidence().protection().sequence(),
        PeerProtectionSequence::InbandAfterCapabilities
    );
    assert!(client.readiness().expect("active client").traffic_ready);
    assert!(server.readiness().expect("active server").traffic_ready);

    let request = application_request();
    let (sent, received) = tokio::join!(
        client.send_message(&request, deadline),
        server.receive_message(deadline)
    );
    assert!(sent
        .expect("send protected application request")
        .is_protected());
    let (received, admission) = received.expect("receive protected application request");
    assert_eq!(received.header, request.header);
    assert!(admission.is_protected());
}

#[tokio::test]
async fn inband_no_common_security_fails_before_tls_or_application_readiness() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let server_capabilities = capabilities("server.example.test", false);
    let client_capabilities = capabilities("client.example.test", true);
    let deadline = Instant::now() + Duration::from_secs(3);

    let server = tokio::spawn({
        let server_capabilities = server_capabilities.clone();
        async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let (responder, _) = acceptor
                .accept_inband(tcp, server_capabilities.clone(), peer_policy())
                .expect("bind in-band responder")
                .receive_capabilities_request(deadline)
                .await
                .expect("receive cleartext CER");
            responder
                .send_capabilities_answer_and_upgrade(
                    &CapabilitiesExchangeAnswer {
                        result_code: RESULT_CODE_DIAMETER_NO_COMMON_SECURITY,
                        capabilities: server_capabilities,
                        diagnostics: AnswerDiagnostics::default(),
                    },
                    deadline,
                )
                .await
                .expect_err("no common mechanism must not enter TLS")
        }
    });
    let awaiting = connector
        .connect_inband(
            address,
            server_name(),
            client_capabilities,
            peer_policy(),
            deadline,
        )
        .await
        .expect("connect cleartext in-band TCP")
        .send_capabilities_request(0x1111, 0x2222, deadline)
        .await
        .expect("send cleartext CER");
    let (client_error, server_error) = tokio::join!(
        async {
            awaiting
                .receive_capabilities_answer_and_upgrade(deadline)
                .await
                .expect_err("negative CEA must not enter TLS")
        },
        server
    );
    assert_eq!(
        client_error,
        opc_diameter_transport::DiameterTlsError::CapabilitiesExchangeFailed
    );
    assert_eq!(
        server_error.expect("join responder"),
        opc_diameter_transport::DiameterTlsError::CapabilitiesExchangeFailed
    );
}

#[tokio::test]
async fn inband_responder_closes_on_application_command_before_cer() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_inband(
                tcp,
                capabilities("server.example.test", true),
                peer_policy(),
            )
            .expect("bind responder")
            .receive_capabilities_request(deadline)
            .await
            .expect_err("application traffic before CER must fail")
    });
    let mut attacker = TcpStream::connect(address).await.expect("connect attacker");
    attacker
        .write_all(&encode_message(&application_request()))
        .await
        .expect("write premature application message");
    let error = server.await.expect("join server");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::CommandNotAdmitted
    );
    let mut byte = [0_u8; 1];
    assert_eq!(attacker.read(&mut byte).await.expect("observe close"), 0);
}

#[tokio::test]
async fn inband_responder_rejects_oversize_declaration_before_body() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let frame_limits = opc_diameter_transport::DiameterFrameLimits::new(DIAMETER_HEADER_LEN)
        .expect("header-only frame bound");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::tls13(frame_limits),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_inband(
                tcp,
                capabilities("server.example.test", true),
                peer_policy(),
            )
            .expect("bind responder")
            .receive_capabilities_request(deadline)
            .await
            .expect_err("oversize declaration must fail")
    });
    let mut attacker = TcpStream::connect(address).await.expect("connect attacker");
    let mut header = encode_message(&application_request()).to_vec();
    header[1..4].copy_from_slice(&[0, 0, (DIAMETER_HEADER_LEN + 1) as u8]);
    attacker
        .write_all(&header[..DIAMETER_HEADER_LEN])
        .await
        .expect("write only oversize header");
    let error = server.await.expect("join server");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::InvalidFrame
    );
}

#[tokio::test]
async fn rejected_local_identity_update_retains_epoch_and_live_connection() {
    let material = tls_material();
    let client_config = material.client.clone();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept Diameter TLS")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect Diameter TLS");
    let mut server = server.await.expect("join server");
    let admitted_epoch = client.evidence().material_epoch();

    material
        ._client_source
        .send_replace(Some(identity_state(OTHER_CLIENT_ID, &material._ca)));
    let status = client_config.material_status();
    assert_eq!(status.epoch(), admitted_epoch);
    assert_eq!(
        status.availability(),
        TlsMaterialAvailability::RetainingLastGood
    );
    assert_eq!(
        status.reason(),
        Some(TlsMaterialReloadReason::LocalIdentityChanged)
    );
    let (sent, received) = tokio::join!(
        client.send_capabilities_request(0x1234, 0x5678, deadline),
        server.receive_capabilities_request(deadline),
    );
    sent.expect("retained connection sends canonical CER");
    assert_eq!(
        received.expect("retained connection receives CER"),
        capabilities("client.example.test", false)
    );
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: capabilities("server.example.test", false),
        diagnostics: AnswerDiagnostics::default(),
    };
    let (emitted, observed) = tokio::join!(
        server.send_capabilities_answer(&answer, deadline),
        client.receive_capabilities_answer(deadline),
    );
    assert!(emitted.expect("emit retained CEA").is_negotiated());
    assert!(observed.expect("observe retained CEA").1.is_negotiated());
    assert_eq!(client.evidence().material_epoch(), admitted_epoch);
}

#[tokio::test]
async fn admitted_trust_replacement_retires_an_idle_connection() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept TLS")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect TLS");
    let mut server = server.await.expect("join server");
    let generation = client.generation();
    let replacement_ca = test_ca();
    material
        ._client_source
        .send_replace(Some(identity_state(CLIENT_ID, &replacement_ca)));
    assert_eq!(
        client
            .send_capabilities_request(0x1234, 0x5678, deadline)
            .await
            .expect_err("an immediate ready send must synchronously see trust replacement"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    assert_eq!(
        server
            .receive_capabilities_request(Instant::now() + Duration::from_secs(1))
            .await
            .expect_err("retired sender must deliver no Diameter bytes"),
        opc_diameter_transport::DiameterTlsError::Transport
    );
    assert_eq!(
        client
            .protection_readiness()
            .expect_err("retired readiness access must fail"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    let session = client.close().expect("close retired connection");
    let readiness = session.protection_readiness();
    assert_eq!(readiness.session_generation(), Some(generation));
    assert!(!readiness.protected_ready());
}

#[tokio::test]
async fn credential_source_loss_retires_an_idle_connection() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server.clone(), expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client.clone(), expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept TLS")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect TLS");
    let mut server = server.await.expect("join server");
    let generation = client.generation();

    material._client_source.send_replace(None);
    assert_eq!(
        client
            .peer_session_snapshot()
            .expect_err("idle access must synchronously observe source loss"),
        opc_diameter_transport::DiameterTlsError::Retired
    );
    assert_eq!(
        server
            .receive_capabilities_request(Instant::now() + Duration::from_secs(1))
            .await
            .expect_err("source-loss retirement must close without Diameter bytes"),
        opc_diameter_transport::DiameterTlsError::Transport
    );
    let session = client.close().expect("close source-retired connection");
    let readiness = session.protection_readiness();
    assert_eq!(readiness.session_generation(), Some(generation));
    assert!(!readiness.protected_ready());
}

#[tokio::test]
async fn idle_material_watcher_closes_peer_without_polling_the_connection() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server.clone(), expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client.clone(), expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept TLS")
    });
    let client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect TLS");
    let mut server = server.await.expect("join server");

    material._client_source.send_replace(None);
    let peer_error = tokio::time::timeout(
        Duration::from_secs(1),
        server.receive_capabilities_request(Instant::now() + Duration::from_secs(1)),
    )
    .await
    .expect("idle watcher must close the peer without a client method call")
    .expect_err("watcher-driven close must deliver no Diameter frame");
    assert_eq!(
        peer_error,
        opc_diameter_transport::DiameterTlsError::Transport
    );
    drop(client);
}

#[tokio::test]
async fn local_and_peer_certificate_expiry_each_retire_idle_connections() {
    tokio::join!(
        assert_certificate_expiry_retires(true),
        assert_certificate_expiry_retires(false)
    );
}

async fn assert_certificate_expiry_retires(expire_client_certificate: bool) {
    let now = time::OffsetDateTime::now_utc();
    let short_expiry = now + time::Duration::seconds(5);
    let long_expiry = now + time::Duration::hours(1);
    let material = if expire_client_certificate {
        tls_material_with_leaf_expiries(short_expiry, long_expiry)
    } else {
        tls_material_with_leaf_expiries(long_expiry, short_expiry)
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let handshake_deadline = Instant::now() + Duration::from_secs(3);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(
                tcp,
                direct_session("server.example.test"),
                handshake_deadline,
            )
            .await
            .expect("accept TLS before certificate expiry")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            handshake_deadline,
        )
        .await
        .expect("connect TLS before certificate expiry");
    let _server = server.await.expect("join server");
    let generation = client.generation();
    let result = tokio::time::timeout(Duration::from_secs(7), async {
        loop {
            match client.protection_readiness() {
                Err(error) => break error,
                Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("certificate expiry must retire idle readiness access");
    assert_eq!(result, opc_diameter_transport::DiameterTlsError::Retired);
    let session = client
        .close()
        .expect("close certificate-retired connection");
    let readiness = session.protection_readiness();
    assert_eq!(readiness.session_generation(), Some(generation));
    assert!(!readiness.protected_ready());
}

#[tokio::test]
async fn maximum_authentication_age_retires_an_idle_connection() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default()
        .with_maximum_connection_age(Duration::from_millis(25))
        .expect("short test age");
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept TLS")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect TLS");
    let _server = server.await.expect("join server");
    let generation = client.generation();
    tokio::time::sleep(Duration::from_millis(75)).await;
    let error = client
        .protection_readiness()
        .expect_err("expired authentication age must retire");
    assert_eq!(error, opc_diameter_transport::DiameterTlsError::Retired);
    let session = client.close().expect("close age-retired connection");
    let readiness = session.protection_readiness();
    assert_eq!(readiness.session_generation(), Some(generation));
    assert!(!readiness.protected_ready());
}

#[tokio::test]
async fn direct_mode_accepts_ascii_case_variants_of_diameter_identity() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let mut connection = acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept TLS");
        connection.receive_capabilities_request(deadline).await
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("CLIENT.EXAMPLE.TEST"),
            deadline,
        )
        .await
        .expect("connect TLS");
    client
        .send_capabilities_request(0x1234, 0x5678, deadline)
        .await
        .expect("send case-variant CER");
    let received = server
        .await
        .expect("join server")
        .expect("case-variant identity must be admitted");
    assert_eq!(received.identity.origin_host, "CLIENT.EXAMPLE.TEST");
}

#[tokio::test]
async fn inband_mode_accepts_ascii_case_variants_of_both_diameter_identities() {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server, expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client, expected(SERVER_ID), policy);
    let server_capabilities = capabilities("SERVER.EXAMPLE.TEST", true);
    let client_capabilities = capabilities("CLIENT.EXAMPLE.TEST", true);
    let deadline = Instant::now() + Duration::from_secs(5);

    let server = tokio::spawn({
        let server_capabilities = server_capabilities.clone();
        async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let (responder, remote) = acceptor
                .accept_inband(tcp, server_capabilities.clone(), peer_policy())
                .expect("bind in-band responder")
                .receive_capabilities_request(deadline)
                .await
                .expect("accept case-variant client identity");
            assert_eq!(remote.identity.origin_host, "CLIENT.EXAMPLE.TEST");
            responder
                .send_capabilities_answer_and_upgrade(
                    &CapabilitiesExchangeAnswer {
                        result_code: RESULT_CODE_DIAMETER_SUCCESS,
                        capabilities: server_capabilities,
                        diagnostics: AnswerDiagnostics::default(),
                    },
                    deadline,
                )
                .await
                .expect("upgrade responder to TLS")
        }
    });
    let awaiting = connector
        .connect_inband(
            address,
            server_name(),
            client_capabilities,
            peer_policy(),
            deadline,
        )
        .await
        .expect("connect in-band TCP")
        .send_capabilities_request(0x1111, 0x2222, deadline)
        .await
        .expect("send case-variant CER");
    let (mut client, answer) = awaiting
        .receive_capabilities_answer_and_upgrade(deadline)
        .await
        .expect("accept case-variant server identity");
    let mut server = server.await.expect("join responder");

    assert_eq!(
        answer.capabilities.identity.origin_host,
        "SERVER.EXAMPLE.TEST"
    );
    assert!(client.readiness().expect("active client").traffic_ready);
    assert!(server.readiness().expect("active server").traffic_ready);
}

#[tokio::test]
async fn direct_mode_rejects_authenticated_cert_with_wrong_origin_host_or_realm() {
    for (origin_host, origin_realm) in [
        ("wrong-client.example.test", "example.test"),
        ("client.example.test", "wrong.example.test"),
    ] {
        assert_direct_diameter_identity_rejected(origin_host, origin_realm).await;
    }
}

async fn assert_direct_diameter_identity_rejected(origin_host: &str, origin_realm: &str) {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let mut connection = acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept TLS");
        connection.receive_capabilities_request(deadline).await
    });
    let mut mismatched_capabilities = capabilities(origin_host, false);
    mismatched_capabilities.identity.origin_realm = origin_realm.to_string();
    let mismatched_session = PeerSession::with_policy_and_protection(
        mismatched_capabilities,
        peer_policy(),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::direct_tls_tcp()),
    );
    let mut client = connector
        .connect_direct(address, server_name(), mismatched_session, deadline)
        .await
        .expect("connect TLS");
    let _ = client
        .send_capabilities_request(0x1234, 0x5678, deadline)
        .await;
    let error = server
        .await
        .expect("join server")
        .expect_err("mismatched Diameter identity must not be released");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::PeerIdentityMismatch
    );
}

#[tokio::test]
async fn inband_mode_rejects_wrong_origin_host_or_realm_before_tls() {
    for (origin_host, origin_realm) in [
        ("wrong-client.example.test", "example.test"),
        ("client.example.test", "wrong.example.test"),
    ] {
        assert_inband_diameter_identity_rejected(origin_host, origin_realm).await;
    }
}

async fn assert_inband_diameter_identity_rejected(origin_host: &str, origin_realm: &str) {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let connector = DiameterTlsConnector::new(
        material.client,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_inband(
                tcp,
                capabilities("server.example.test", true),
                peer_policy(),
            )
            .expect("bind in-band responder")
            .receive_capabilities_request(deadline)
            .await
            .expect_err("wrong cleartext Diameter identity must fail before TLS")
    });
    let mut mismatched_capabilities = capabilities(origin_host, true);
    mismatched_capabilities.identity.origin_realm = origin_realm.to_string();
    let initiator = connector
        .connect_inband(
            address,
            server_name(),
            mismatched_capabilities,
            peer_policy(),
            deadline,
        )
        .await
        .expect("connect in-band TCP");
    let _awaiting = initiator
        .send_capabilities_request(0x1111, 0x2222, deadline)
        .await
        .expect("send mismatched CER");
    let error = server.await.expect("join server");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::PeerIdentityMismatch
    );
}

#[tokio::test]
async fn direct_connector_rejects_unknown_server_ca() {
    let client_ca = test_ca();
    let server_ca = test_ca();
    let (client_source, client_rx) = watch::channel(Some(identity_state_with_trust(
        CLIENT_ID,
        &client_ca,
        vec![client_ca.der().clone()],
    )));
    let (server_source, server_rx) = watch::channel(Some(identity_state_with_trust(
        SERVER_ID,
        &server_ca,
        vec![client_ca.der().clone(), server_ca.der().clone()],
    )));
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("build client config");
    let server_config = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("build server config");
    let _sources = (client_source, server_source);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        server_config,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let connector = DiameterTlsConnector::new(
        client_config,
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
    });
    let client_error = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect_err("unknown server CA must fail");
    assert_eq!(
        client_error,
        opc_diameter_transport::DiameterTlsError::Authentication
    );
    assert!(server.await.expect("join server").is_err());
}

#[tokio::test]
async fn direct_acceptor_rejects_missing_expired_and_not_yet_valid_client_certificates() {
    assert_direct_acceptor_rejects_raw_client_certificate(None).await;

    let now = time::OffsetDateTime::now_utc();
    assert_direct_acceptor_rejects_raw_client_certificate(Some((
        now - time::Duration::hours(2),
        now - time::Duration::hours(1),
    )))
    .await;
    assert_direct_acceptor_rejects_raw_client_certificate(Some((
        now + time::Duration::hours(1),
        now + time::Duration::hours(2),
    )))
    .await;
}

async fn assert_direct_acceptor_rejects_raw_client_certificate(
    validity: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
) {
    let material = tls_material();
    let raw_client = raw_client_config(&material._ca, validity);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = DiameterTlsAcceptor::new(
        material.server,
        expected(CLIENT_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
    });
    let tcp = TcpStream::connect(address)
        .await
        .expect("connect raw client");
    let connect =
        tokio_rustls::TlsConnector::from(Arc::new(raw_client)).connect(server_name(), tcp);
    let (client_result, server_result) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(connect, server)
    })
    .await
    .expect("certificate rejection must be bounded");
    drop(client_result);
    let error = server_result
        .expect("join direct acceptor")
        .expect_err("invalid client certificate must be rejected");
    assert_eq!(
        error,
        opc_diameter_transport::DiameterTlsError::Authentication
    );
}

fn runtime_config(origin_state_id: u32) -> DiameterPeerRuntimeConfig {
    let capacity = NonZeroUsize::new(8).expect("nonzero test capacity");
    DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, Some(origin_state_id))
        .expect("valid runtime queue bounds")
}

#[test]
fn peer_runtime_config_rejects_queue_and_frame_timeout_bounds() {
    let one = NonZeroUsize::new(1).expect("nonzero test capacity");
    let too_large = NonZeroUsize::new(tokio::sync::Semaphore::MAX_PERMITS + 1)
        .expect("Tokio's maximum leaves room for an invalid capacity");

    assert_eq!(
        DiameterPeerRuntimeConfig::new(too_large, one, one, None),
        Err(DiameterPeerRuntimeConfigError::CommandQueueTooLarge)
    );
    assert_eq!(
        DiameterPeerRuntimeConfig::new(one, too_large, one, None),
        Err(DiameterPeerRuntimeConfigError::ControlQueueTooLarge)
    );
    assert_eq!(
        DiameterPeerRuntimeConfig::new(one, one, too_large, None),
        Err(DiameterPeerRuntimeConfigError::ApplicationQueueTooLarge)
    );

    let config = DiameterPeerRuntimeConfig::new(one, one, one, None)
        .expect("unit queue capacities are valid");
    assert_eq!(
        config.with_frame_io_timeouts(Duration::ZERO, Duration::from_secs(1)),
        Err(DiameterPeerRuntimeConfigError::FrameCompletionTimeoutZero)
    );
    assert_eq!(
        config.with_frame_io_timeouts(Duration::from_secs(1), Duration::ZERO),
        Err(DiameterPeerRuntimeConfigError::FrameWriteTimeoutZero)
    );
    assert_eq!(
        config.with_frame_io_timeouts(Duration::MAX, Duration::from_secs(1)),
        Err(DiameterPeerRuntimeConfigError::FrameCompletionTimeoutTooLarge)
    );
    assert_eq!(
        config.with_frame_io_timeouts(Duration::from_secs(1), Duration::MAX),
        Err(DiameterPeerRuntimeConfigError::FrameWriteTimeoutTooLarge)
    );
}

#[test]
fn watchdog_twinit_enforces_the_rfc_3539_minimum_and_clock_bound() {
    assert_eq!(
        DiameterWatchdogTwinit::new(DiameterWatchdogTwinit::MINIMUM - Duration::from_nanos(1)),
        Err(DiameterWatchdogTwinitError::BelowMinimum)
    );
    assert_eq!(
        DiameterWatchdogTwinit::new(DiameterWatchdogTwinit::MINIMUM)
            .expect("the RFC minimum is valid")
            .get(),
        DiameterWatchdogTwinit::MINIMUM
    );
    assert_eq!(
        DiameterWatchdogTwinit::new(Duration::MAX),
        Err(DiameterWatchdogTwinitError::TooLarge)
    );
}

async fn negotiated_direct_connections() -> (
    TestTlsMaterial,
    DiameterTlsConnection,
    DiameterTlsConnection,
) {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind runtime listener");
    let address = listener.local_addr().expect("runtime listener address");
    let policy = DiameterTlsPolicy::default();
    let acceptor = DiameterTlsAcceptor::new(material.server.clone(), expected(CLIENT_ID), policy);
    let connector = DiameterTlsConnector::new(material.client.clone(), expected(SERVER_ID), policy);
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept runtime TCP");
        acceptor
            .accept_direct(tcp, direct_session("server.example.test"), deadline)
            .await
            .expect("accept runtime TLS")
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect runtime TLS");
    let mut server = server.await.expect("join runtime acceptor");
    let (sent, received) = tokio::join!(
        client.send_capabilities_request(0x1100, 0x2200, deadline),
        server.receive_capabilities_request(deadline),
    );
    sent.expect("send runtime CER");
    received.expect("receive runtime CER");
    let answer = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: capabilities("server.example.test", false),
        diagnostics: AnswerDiagnostics::default(),
    };
    let (emitted, observed) = tokio::join!(
        server.send_capabilities_answer(&answer, deadline),
        client.receive_capabilities_answer(deadline),
    );
    assert!(emitted.expect("send runtime CEA").is_negotiated());
    assert!(observed.expect("receive runtime CEA").1.is_negotiated());
    (material, client, server)
}

async fn negotiated_client_with_raw_server() -> (
    TestTlsMaterial,
    DiameterTlsConnection,
    tokio_rustls::server::TlsStream<TcpStream>,
) {
    let material = tls_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind raw runtime listener");
    let address = listener.local_addr().expect("raw runtime listener address");
    let server_config = material.server.clone();
    let connector = DiameterTlsConnector::new(
        material.client.clone(),
        expected(SERVER_ID),
        DiameterTlsPolicy::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept raw runtime TCP");
        let handshake = server_config
            .begin_handshake()
            .expect("freeze raw server material");
        let mut tls = tokio_rustls::TlsAcceptor::from(handshake.rustls_config())
            .accept(tcp)
            .await
            .expect("accept raw mutual TLS");
        let header = read_diameter_frame_header(&mut tls).await;
        let answer = build_capabilities_exchange_answer(
            &CapabilitiesExchangeAnswer {
                result_code: RESULT_CODE_DIAMETER_SUCCESS,
                capabilities: capabilities("server.example.test", false),
                diagnostics: AnswerDiagnostics::default(),
            },
            u32::from_be_bytes(header[12..16].try_into().expect("CER hop-by-hop")),
            u32::from_be_bytes(header[16..20].try_into().expect("CER end-to-end")),
            EncodeContext::default(),
        )
        .expect("build raw peer CEA");
        tls.write_all(&encode_message(&answer))
            .await
            .expect("write raw peer CEA");
        tls.flush().await.expect("flush raw peer CEA");
        tls
    });
    let mut client = connector
        .connect_direct(
            address,
            server_name(),
            direct_session("client.example.test"),
            deadline,
        )
        .await
        .expect("connect raw runtime TLS");
    client
        .send_capabilities_request(0x1110, 0x2220, deadline)
        .await
        .expect("send raw runtime CER");
    let (_, outcome) = client
        .receive_capabilities_answer(deadline)
        .await
        .expect("receive raw runtime CEA");
    assert!(outcome.is_negotiated());
    let tls = server.await.expect("join raw runtime negotiation");
    (material, client, tls)
}

#[tokio::test]
async fn peer_runtime_construction_requires_an_entered_tokio_runtime() {
    let (_material, client, _server) = negotiated_direct_connections().await;
    let error = std::thread::spawn(move || {
        client
            .into_peer_runtime(runtime_config(10))
            .expect_err("runtime construction outside Tokio must fail closed")
    })
    .join()
    .expect("join non-Tokio runtime-construction thread");

    assert_eq!(error, DiameterPeerRuntimeError::RuntimeUnavailable);
}

#[test]
fn dropping_owner_tokio_runtime_closes_detached_parts_without_hanging() {
    let (_material_sources, client_handle, mut client_incoming, _server_handle, _server_incoming) =
        std::thread::spawn(|| {
            let owner = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build owner Tokio runtime");
            let detached = owner.block_on(async {
                let (material, client, server) = negotiated_direct_connections().await;
                let material_sources = (
                    material._client_source.clone(),
                    material._server_source.clone(),
                );
                let client = client
                    .into_peer_runtime(runtime_config(10))
                    .expect("start client runtime on owner");
                let server = server
                    .into_peer_runtime(runtime_config(20))
                    .expect("start server runtime on owner");
                let (client_handle, client_incoming) = client.into_parts();
                let (server_handle, server_incoming) = server.into_parts();
                (
                    material_sources,
                    client_handle,
                    client_incoming,
                    server_handle,
                    server_incoming,
                )
            });
            drop(owner);
            detached
        })
        .join()
        .expect("join owner Tokio runtime thread");

    let observer = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build observer Tokio runtime");
    observer.block_on(async {
        let readiness_error =
            tokio::time::timeout(Duration::from_secs(1), client_handle.readiness())
                .await
                .expect("readiness must finish after owner runtime drop")
                .expect_err("readiness must fail after owner runtime drop");
        assert!(matches!(
            readiness_error,
            DiameterPeerRuntimeError::Closed
                | DiameterPeerRuntimeError::Transport(_)
                | DiameterPeerRuntimeError::PeerDisconnected { .. }
        ));

        let send_error = tokio::time::timeout(
            Duration::from_secs(1),
            client_handle.send_application(
                application_request(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .await
        .expect("send must finish after owner runtime drop")
        .expect_err("send must fail after owner runtime drop");
        assert_eq!(send_error, readiness_error);

        let receive_error = tokio::time::timeout(Duration::from_secs(1), client_incoming.receive())
            .await
            .expect("receive must finish after owner runtime drop")
            .expect_err("receive must fail after owner runtime drop");
        assert_eq!(receive_error, readiness_error);
    });
}

#[tokio::test]
async fn credential_retirement_remains_authoritative_after_runtime_conversion() {
    let (material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let (_server_handle, mut server_incoming) = server.into_parts();

    material._client_source.send_replace(None);
    let client_error = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match client_handle.readiness().await {
                Ok(_) => tokio::task::yield_now().await,
                Err(error) => break error,
            }
        }
    })
    .await
    .expect("runtime must observe credential retirement");
    assert_eq!(
        client_error,
        DiameterPeerRuntimeError::Transport(opc_diameter_transport::DiameterTlsError::Retired)
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), server_incoming.receive())
            .await
            .expect("retirement must close the peer runtime")
            .expect_err("retirement must not release an application message"),
        DiameterPeerRuntimeError::Transport(_)
            | DiameterPeerRuntimeError::Closed
            | DiameterPeerRuntimeError::PeerDisconnected { .. }
    ));
}

#[tokio::test]
async fn peer_runtime_times_out_a_partial_frame_after_its_first_octet() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let capacity = NonZeroUsize::new(8).expect("nonzero test capacity");
    let config = DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, Some(10))
        .expect("valid runtime queue bounds")
        .with_frame_io_timeouts(Duration::from_millis(25), Duration::from_secs(1))
        .expect("valid bounded frame timeouts");
    let client = client
        .into_peer_runtime(config)
        .expect("start client runtime");
    let (_client_handle, mut client_incoming) = client.into_parts();

    raw_server
        .write_all(&[opc_proto_diameter::DIAMETER_VERSION])
        .await
        .expect("write first Diameter frame octet");
    raw_server
        .flush()
        .await
        .expect("flush first Diameter frame octet");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client_incoming.receive())
            .await
            .expect("partial-frame timeout must be bounded")
            .expect_err("partial frame must terminate the runtime"),
        DiameterPeerRuntimeError::Transport(
            opc_diameter_transport::DiameterTlsError::DeadlineExceeded
        )
    );
}

#[tokio::test]
async fn peer_runtime_carries_application_traffic_in_both_directions_concurrently() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    let (server_handle, mut server_incoming) = server.into_parts();
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
async fn peer_runtime_rejects_oversize_local_application_without_closing() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let (_server_handle, mut server_incoming) = server.into_parts();

    let limits = opc_diameter_transport::DiameterFrameLimits::default();
    let oversized = OwnedMessage {
        header: Header::new(
            CommandFlags::request(true),
            CommandCode::new(268),
            APP_ID,
            0x5100,
            0x6100,
        ),
        raw_avps: Bytes::from(vec![
            0_u8;
            limits.max_message_len() + 1 - DIAMETER_HEADER_LEN
        ]),
    };
    assert_eq!(
        client_handle
            .send_application(oversized, Instant::now() + Duration::from_secs(1))
            .await
            .expect_err("oversize local frame must fail before transport output"),
        DiameterPeerRuntimeError::Transport(opc_diameter_transport::DiameterTlsError::InvalidFrame)
    );

    let valid = application_request();
    let (sent, received) = tokio::join!(
        client_handle.send_application(valid.clone(), Instant::now() + Duration::from_secs(3),),
        server_incoming.receive(),
    );
    assert!(sent
        .expect("runtime remains usable after local prevalidation failure")
        .is_protected());
    assert_eq!(
        received
            .expect("peer receives the next valid application frame")
            .into_message(),
        valid
    );
}

#[tokio::test]
async fn peer_runtime_rejects_a_watchdog_probe_before_the_peer_is_idle() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let (_server_handle, _server_incoming) = server.into_parts();

    let error = client_handle
        .probe_watchdog(
            0x3100,
            0x4100,
            DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("fresh peer activity must postpone DWR emission");

    assert_eq!(error, DiameterPeerRuntimeError::WatchdogNotDue);
}

#[tokio::test]
async fn peer_runtime_watchdog_jitter_stays_within_the_rfc_3539_range() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;

    let started = Instant::now();
    let probe = tokio::spawn(async move {
        client_handle
            .probe_watchdog(
                0x3200,
                0x4200,
                DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
                Instant::now() + Duration::from_secs(30),
            )
            .await
    });
    let header = read_diameter_frame_header(&mut raw_server).await;
    assert_eq!(
        u32::from_be_bytes([0, header[5], header[6], header[7]]),
        PeerProcedure::DeviceWatchdog.command_code().get()
    );

    assert_eq!(
        probe.await.expect("join unanswered watchdog probe"),
        Err(DiameterPeerRuntimeError::WatchdogSuspect)
    );
    let elapsed = Instant::now().saturating_duration_since(started);
    assert!(elapsed >= Duration::from_secs(4), "elapsed={elapsed:?}");
    assert!(
        elapsed <= Duration::from_millis(8_010),
        "elapsed={elapsed:?}"
    );
}

#[tokio::test]
async fn peer_runtime_accepts_an_exact_late_dwa_after_entering_suspect() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;

    let observed_handle = client_handle.clone();
    let probe = tokio::spawn(async move {
        client_handle
            .probe_watchdog(
                0x3250,
                0x4250,
                DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
                Instant::now() + Duration::from_secs(30),
            )
            .await
    });
    let request_header = read_diameter_frame_header(&mut raw_server).await;
    let hop_by_hop = u32::from_be_bytes(request_header[12..16].try_into().expect("DWR hop-by-hop"));
    let end_to_end = u32::from_be_bytes(request_header[16..20].try_into().expect("DWR end-to-end"));
    assert_eq!(
        probe.await.expect("join unanswered watchdog probe"),
        Err(DiameterPeerRuntimeError::WatchdogSuspect)
    );
    assert!(
        !observed_handle
            .readiness()
            .await
            .expect("suspect runtime remains observable")
            .traffic_ready,
        "suspect peer must stop application admission"
    );

    let inbound_before_reset = observed_handle
        .activity()
        .await
        .expect("activity before watchdog reset")
        .last_inbound();
    tokio::time::advance(Duration::from_millis(1)).await;
    let unrelated_application = application_request();
    raw_server
        .write_all(&encode_message(&unrelated_application))
        .await
        .expect("write unrelated application during watchdog grace");
    raw_server
        .flush()
        .await
        .expect("flush unrelated application during watchdog grace");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client_incoming.receive())
            .await
            .expect("unrelated application delivery must precede the reset interval")
            .expect("unrelated application remains admitted")
            .into_message(),
        unrelated_application
    );
    let activity_after_reset = observed_handle
        .activity()
        .await
        .expect("activity after watchdog reset");
    assert!(activity_after_reset.last_inbound() > inbound_before_reset);
    let pending = observed_handle
        .peer_session_snapshot()
        .await
        .expect("snapshot after unrelated peer activity");
    assert_eq!(pending.watchdog_requests_sent, 1);
    assert_eq!(pending.watchdog_answers_observed, 0);
    assert!(pending.readiness.probing);
    assert!(pending.readiness.traffic_ready);

    let answer = build_device_watchdog_answer(
        &DeviceWatchdogAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: PeerIdentity::new("server.example.test", "example.test"),
            origin_state_id: Some(20),
            diagnostics: AnswerDiagnostics::default(),
        },
        hop_by_hop,
        end_to_end,
        EncodeContext::default(),
    )
    .expect("build exact late DWA");
    raw_server
        .write_all(&encode_message(&answer))
        .await
        .expect("write exact late DWA");
    raw_server.flush().await.expect("flush exact late DWA");

    let completed = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = observed_handle
                .peer_session_snapshot()
                .await
                .expect("late DWA must retain the runtime");
            if snapshot.watchdog_answers_observed == 1 {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("late exact DWA must recover before the second interval");
    assert_eq!(completed.watchdog_requests_sent, 1);
    assert_eq!(completed.watchdog_answers_observed, 1);
    assert!(completed.readiness.negotiated);
}

#[tokio::test]
async fn peer_runtime_closes_after_a_second_watchdog_interval_without_retransmitting() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;

    let _retained_handle = client_handle.clone();
    let probe = tokio::spawn(async move {
        client_handle
            .probe_watchdog(
                0x3260,
                0x4260,
                DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
                Instant::now() + Duration::from_secs(30),
            )
            .await
    });
    let _request_header = read_diameter_frame_header(&mut raw_server).await;
    assert_eq!(
        probe.await.expect("join unanswered watchdog probe"),
        Err(DiameterPeerRuntimeError::WatchdogSuspect)
    );

    let second_interval_started = Instant::now();
    let mut unexpected_wire = [0_u8; 1];
    let (terminal, raw_read) = tokio::join!(
        client_incoming.receive(),
        raw_server.read(&mut unexpected_wire),
    );
    assert_eq!(
        terminal.expect_err("the second unanswered interval must be terminal"),
        DiameterPeerRuntimeError::DeadlineExceeded
    );
    assert!(
        !matches!(raw_read, Ok(count) if count > 0),
        "the runtime must not retransmit DWR during the grace interval"
    );
    let elapsed = Instant::now().saturating_duration_since(second_interval_started);
    assert!(elapsed >= Duration::from_secs(4), "elapsed={elapsed:?}");
    assert!(
        elapsed <= Duration::from_millis(8_010),
        "elapsed={elapsed:?}"
    );
}

#[tokio::test]
async fn peer_runtime_discards_unknown_watchdog_answers_then_rejects_wrong_end_to_end() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    tokio::time::sleep(Duration::from_secs(4)).await;

    let observed_handle = client_handle.clone();
    let probe = tokio::spawn(async move {
        client_handle
            .probe_watchdog(
                0x3300,
                0x4300,
                DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
                Instant::now() + Duration::from_secs(30),
            )
            .await
    });
    let request_header = read_diameter_frame_header(&mut raw_server).await;
    let hop_by_hop = u32::from_be_bytes(request_header[12..16].try_into().expect("DWR hop-by-hop"));
    let end_to_end = u32::from_be_bytes(request_header[16..20].try_into().expect("DWR end-to-end"));
    let answer = DeviceWatchdogAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        identity: PeerIdentity::new("server.example.test", "example.test"),
        origin_state_id: Some(20),
        diagnostics: AnswerDiagnostics::default(),
    };
    let unknown = build_device_watchdog_answer(
        &answer,
        hop_by_hop.wrapping_add(1),
        end_to_end,
        EncodeContext::default(),
    )
    .expect("build unknown DWA");
    for _ in 0..2 {
        raw_server
            .write_all(&encode_message(&unknown))
            .await
            .expect("write unknown DWA");
        raw_server.flush().await.expect("flush unknown DWA");
    }
    let wrong_end_to_end = build_device_watchdog_answer(
        &answer,
        hop_by_hop,
        end_to_end.wrapping_add(1),
        EncodeContext::default(),
    )
    .expect("build wrong-end-to-end DWA");
    raw_server
        .write_all(&encode_message(&wrong_end_to_end))
        .await
        .expect("write wrong-end-to-end DWA");
    raw_server
        .flush()
        .await
        .expect("flush wrong-end-to-end DWA");

    assert_eq!(
        probe.await.expect("join mismatched watchdog probe"),
        Err(DiameterPeerRuntimeError::TransactionMismatch)
    );
    assert_eq!(
        observed_handle
            .readiness()
            .await
            .expect_err("wrong end-to-end identifier is terminal"),
        DiameterPeerRuntimeError::TransactionMismatch
    );
}

#[tokio::test]
async fn correlated_watchdog_answer_with_mtls_mismatched_identity_is_terminal() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    tokio::time::sleep(Duration::from_secs(4)).await;

    let _retained_handle = client_handle.clone();
    let probe = tokio::spawn(async move {
        client_handle
            .probe_watchdog(
                0x3340,
                0x4340,
                DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    let request_header = read_diameter_frame_header(&mut raw_server).await;
    let hop_by_hop = u32::from_be_bytes(request_header[12..16].try_into().expect("DWR hop-by-hop"));
    let end_to_end = u32::from_be_bytes(request_header[16..20].try_into().expect("DWR end-to-end"));
    let mismatched = build_device_watchdog_answer(
        &DeviceWatchdogAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: PeerIdentity::new("other.example.test", "other.test"),
            origin_state_id: None,
            diagnostics: AnswerDiagnostics::default(),
        },
        hop_by_hop,
        end_to_end,
        EncodeContext::default(),
    )
    .expect("build identity-mismatched DWA");
    raw_server
        .write_all(&encode_message(&mismatched))
        .await
        .expect("write identity-mismatched DWA");
    raw_server
        .flush()
        .await
        .expect("flush identity-mismatched DWA");

    assert_eq!(
        probe.await.expect("join identity-mismatched watchdog"),
        Err(DiameterPeerRuntimeError::PeerIdentityMismatch)
    );
    assert_eq!(
        client_incoming
            .receive()
            .await
            .expect_err("identity mismatch must deliver no application message"),
        DiameterPeerRuntimeError::PeerIdentityMismatch
    );
}

#[tokio::test]
async fn local_disconnect_supersedes_an_unanswered_watchdog_after_dpr_emission() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    tokio::time::sleep(Duration::from_secs(4)).await;

    let disconnect_handle = client_handle.clone();
    let watchdog = tokio::spawn(async move {
        client_handle
            .probe_watchdog(
                0x3350,
                0x4350,
                DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
                Instant::now() + Duration::from_secs(30),
            )
            .await
    });
    let watchdog_header = read_diameter_frame_header(&mut raw_server).await;
    assert_eq!(
        u32::from_be_bytes([
            0,
            watchdog_header[5],
            watchdog_header[6],
            watchdog_header[7],
        ]),
        PeerProcedure::DeviceWatchdog.command_code().get()
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if disconnect_handle
                .activity()
                .await
                .expect("runtime activity after DWR")
                .sequence()
                > 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime must commit DWR emission before disconnect");

    let mut disconnect = tokio::spawn(async move {
        disconnect_handle
            .disconnect(
                opc_proto_diameter::peer::DisconnectCause::Rebooting,
                0x5550,
                0x6650,
                Instant::now() + Duration::from_secs(30),
            )
            .await
    });
    tokio::task::yield_now().await;
    let disconnect_header = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::select! {
            result = &mut disconnect => {
                panic!("disconnect completed before DPR emission: {result:?}")
            }
            header = read_diameter_frame_header(&mut raw_server) => header,
        }
    })
    .await
    .expect("local disconnect must emit DPR while DWA is pending");
    assert_eq!(
        u32::from_be_bytes([
            0,
            disconnect_header[5],
            disconnect_header[6],
            disconnect_header[7],
        ]),
        PeerProcedure::DisconnectPeer.command_code().get()
    );
    assert_eq!(
        watchdog.await.expect("join superseded watchdog"),
        Err(DiameterPeerRuntimeError::WatchdogSupersededByDisconnect)
    );

    let hop_by_hop = u32::from_be_bytes(
        disconnect_header[12..16]
            .try_into()
            .expect("DPR hop-by-hop"),
    );
    let end_to_end = u32::from_be_bytes(
        disconnect_header[16..20]
            .try_into()
            .expect("DPR end-to-end"),
    );
    let answer = build_disconnect_peer_answer(
        &DisconnectPeerAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: PeerIdentity::new("server.example.test", "example.test"),
            origin_state_id: Some(20),
            diagnostics: AnswerDiagnostics::default(),
        },
        hop_by_hop,
        end_to_end,
        EncodeContext::default(),
    )
    .expect("build exact DPA");
    raw_server
        .write_all(&encode_message(&answer))
        .await
        .expect("write exact DPA");
    raw_server.flush().await.expect("flush exact DPA");

    assert_eq!(
        disconnect
            .await
            .expect("join disconnect that superseded watchdog")
            .expect("exact DPA completes disconnect")
            .result_code,
        RESULT_CODE_DIAMETER_SUCCESS
    );
}

#[tokio::test(flavor = "current_thread")]
async fn local_disconnect_returns_exact_dpa_after_terminal_is_observable() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let observed_handle = client_handle.clone();
    let (polling, mut polling_rx) = watch::channel(true);
    let (paused, paused_rx) = oneshot::channel();
    let disconnect = tokio::spawn(async move {
        let operation = client_handle.disconnect(
            opc_proto_diameter::peer::DisconnectCause::Rebooting,
            0x5560,
            0x6660,
            Instant::now() + Duration::from_secs(3),
        );
        tokio::pin!(operation);
        let mut paused = Some(paused);
        loop {
            let enabled = *polling_rx.borrow_and_update();
            if !enabled {
                if let Some(paused) = paused.take() {
                    let _ = paused.send(());
                }
                polling_rx
                    .changed()
                    .await
                    .expect("test polling gate remains open");
                continue;
            }
            tokio::select! {
                biased;
                changed = polling_rx.changed() => {
                    changed.expect("test polling gate remains open");
                }
                result = &mut operation => break result,
            }
        }
    });

    let request_header = read_diameter_frame_header(&mut raw_server).await;
    assert_eq!(
        u32::from_be_bytes([0, request_header[5], request_header[6], request_header[7],]),
        PeerProcedure::DisconnectPeer.command_code().get()
    );
    let hop_by_hop = u32::from_be_bytes(request_header[12..16].try_into().expect("DPR hop-by-hop"));
    let end_to_end = u32::from_be_bytes(request_header[16..20].try_into().expect("DPR end-to-end"));

    polling.send_replace(false);
    paused_rx
        .await
        .expect("disconnect completion polling is paused after DPR emission");
    let expected_answer = DisconnectPeerAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        identity: PeerIdentity::new("server.example.test", "example.test"),
        origin_state_id: Some(20),
        diagnostics: AnswerDiagnostics::default(),
    };
    let answer = build_disconnect_peer_answer(
        &expected_answer,
        hop_by_hop,
        end_to_end,
        EncodeContext::default(),
    )
    .expect("build exact DPA");
    raw_server
        .write_all(&encode_message(&answer))
        .await
        .expect("write exact DPA");
    raw_server.flush().await.expect("flush exact DPA");

    let terminal = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match observed_handle.readiness().await {
                Ok(_) => tokio::task::yield_now().await,
                Err(error) => break error,
            }
        }
    })
    .await
    .expect("exact DPA must make local disconnect terminal observable");
    assert_eq!(
        terminal,
        DiameterPeerRuntimeError::PeerDisconnected { peer_cause: None }
    );

    polling.send_replace(true);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), disconnect)
            .await
            .expect("disconnect completion must remain bounded")
            .expect("join local disconnect")
            .expect("exact DPA wins over the subsequently observed terminal state"),
        expected_answer
    );
}

#[tokio::test]
async fn peer_runtime_owns_exact_watchdog_request_answer_transaction() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let (server_handle, _server_incoming) = server.into_parts();

    tokio::time::sleep(Duration::from_secs(4)).await;
    let answer = client_handle
        .probe_watchdog(
            0x3300,
            0x4400,
            DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
            Instant::now() + Duration::from_secs(3),
        )
        .await
        .expect("correlated DWA");
    assert_eq!(answer.result_code, RESULT_CODE_DIAMETER_SUCCESS);
    assert_eq!(answer.origin_state_id, Some(20));
    assert!(answer
        .identity
        .semantically_eq(&PeerIdentity::new("server.example.test", "example.test")));
    assert_eq!(
        client_handle
            .peer_session_snapshot()
            .await
            .expect("client snapshot")
            .watchdog_answers_observed,
        1
    );
    assert_eq!(
        server_handle
            .peer_session_snapshot()
            .await
            .expect("server snapshot")
            .watchdog_requests_received,
        1
    );
}

#[tokio::test]
async fn malformed_peer_requests_receive_exact_bound_error_answers_before_close() {
    const UNKNOWN_MANDATORY_AVP: u32 = 65_000;
    struct Case {
        name: &'static str,
        procedure: PeerProcedure,
        avps: Vec<Bytes>,
        result_code: u32,
        failed_avp_code: u32,
        exact_failed_avp: Option<Bytes>,
    }

    let origin_host = ietf_avp(AVP_ORIGIN_HOST.get(), true, b"server.example.test");
    let origin_realm = ietf_avp(AVP_ORIGIN_REALM.get(), true, b"example.test");
    let disconnect_cause = ietf_avp(AVP_DISCONNECT_CAUSE.get(), true, &0_u32.to_be_bytes());
    let unsupported = ietf_avp(UNKNOWN_MANDATORY_AVP, true, &[0xde, 0xad, 0xbe, 0xef]);
    let cases = vec![
        Case {
            name: "DWR missing Origin-Host",
            procedure: PeerProcedure::DeviceWatchdog,
            avps: vec![origin_realm.clone()],
            result_code: RESULT_CODE_DIAMETER_MISSING_AVP,
            failed_avp_code: AVP_ORIGIN_HOST.get(),
            exact_failed_avp: None,
        },
        Case {
            name: "DWR missing Origin-Realm",
            procedure: PeerProcedure::DeviceWatchdog,
            avps: vec![origin_host.clone()],
            result_code: RESULT_CODE_DIAMETER_MISSING_AVP,
            failed_avp_code: AVP_ORIGIN_REALM.get(),
            exact_failed_avp: None,
        },
        Case {
            name: "DPR missing Origin-Host",
            procedure: PeerProcedure::DisconnectPeer,
            avps: vec![origin_realm.clone(), disconnect_cause.clone()],
            result_code: RESULT_CODE_DIAMETER_MISSING_AVP,
            failed_avp_code: AVP_ORIGIN_HOST.get(),
            exact_failed_avp: None,
        },
        Case {
            name: "DPR missing Origin-Realm",
            procedure: PeerProcedure::DisconnectPeer,
            avps: vec![origin_host.clone(), disconnect_cause.clone()],
            result_code: RESULT_CODE_DIAMETER_MISSING_AVP,
            failed_avp_code: AVP_ORIGIN_REALM.get(),
            exact_failed_avp: None,
        },
        Case {
            name: "DPR missing Disconnect-Cause",
            procedure: PeerProcedure::DisconnectPeer,
            avps: vec![origin_host.clone(), origin_realm.clone()],
            result_code: RESULT_CODE_DIAMETER_MISSING_AVP,
            failed_avp_code: AVP_DISCONNECT_CAUSE.get(),
            exact_failed_avp: None,
        },
        Case {
            name: "DWR unsupported mandatory AVP",
            procedure: PeerProcedure::DeviceWatchdog,
            avps: vec![origin_host, origin_realm, unsupported.clone()],
            result_code: RESULT_CODE_DIAMETER_AVP_UNSUPPORTED,
            failed_avp_code: UNKNOWN_MANDATORY_AVP,
            exact_failed_avp: Some(unsupported),
        },
    ];

    for (index, case) in cases.into_iter().enumerate() {
        let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
        let client = client
            .into_peer_runtime(runtime_config(10))
            .expect("start client runtime");
        let (_client_handle, mut client_incoming) = client.into_parts();
        let hop_by_hop = 0x7000_u32 + u32::try_from(index).expect("small case index");
        let end_to_end = 0x8000_u32 + u32::try_from(index).expect("small case index");
        let request = peer_request_with_avps(case.procedure, hop_by_hop, end_to_end, &case.avps);
        raw_server
            .write_all(&encode_message(&request))
            .await
            .expect("write malformed peer request");
        raw_server
            .flush()
            .await
            .expect("flush malformed peer request");
        let response =
            tokio::time::timeout(Duration::from_secs(2), read_diameter_frame(&mut raw_server))
                .await
                .unwrap_or_else(|_| panic!("{} did not receive an answer", case.name));

        assert_eq!(
            response.header.command_code, request.header.command_code,
            "{}",
            case.name
        );
        assert_eq!(
            response.header.application_id, request.header.application_id,
            "{}",
            case.name
        );
        assert_eq!(
            response.header.flags.is_proxiable(),
            request.header.flags.is_proxiable(),
            "{}",
            case.name
        );
        assert!(!response.header.flags.is_request(), "{}", case.name);
        assert!(response.header.flags.is_error(), "{}", case.name);
        assert_eq!(
            response.header.hop_by_hop_identifier, hop_by_hop,
            "{}",
            case.name
        );
        assert_eq!(
            response.header.end_to_end_identifier, end_to_end,
            "{}",
            case.name
        );

        let borrowed = Message {
            header: response.header.clone(),
            raw_avps: &response.raw_avps,
            tail: &[],
        };
        let (result_code, diagnostics) = match case.procedure {
            PeerProcedure::DeviceWatchdog => {
                let answer = parse_device_watchdog_answer(&borrowed, DecodeContext::default())
                    .unwrap_or_else(|error| panic!("{} DWA parse failed: {error}", case.name));
                (answer.result_code, answer.diagnostics)
            }
            PeerProcedure::DisconnectPeer => {
                let answer = parse_disconnect_peer_answer(&borrowed, DecodeContext::default())
                    .unwrap_or_else(|error| panic!("{} DPA parse failed: {error}", case.name));
                (answer.result_code, answer.diagnostics)
            }
            PeerProcedure::CapabilitiesExchange => {
                panic!("capability exchange is outside this malformed runtime test")
            }
        };
        assert_eq!(result_code, case.result_code, "{}", case.name);
        assert_eq!(diagnostics.failed_avps.len(), 1, "{}", case.name);
        let failed_avp = &diagnostics.failed_avps[0];
        assert!(failed_avp.len() >= 8, "{}", case.name);
        assert_eq!(
            u32::from_be_bytes(failed_avp[..4].try_into().expect("Failed-AVP code")),
            case.failed_avp_code,
            "{}",
            case.name
        );
        if let Some(expected) = case.exact_failed_avp {
            assert_eq!(failed_avp, &expected, "{}", case.name);
        }

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), client_incoming.receive())
                .await
                .unwrap_or_else(|_| panic!("{} runtime did not terminate", case.name))
                .expect_err("malformed request must close after its answer"),
            DiameterPeerRuntimeError::InvalidControlMessage,
            "{}",
            case.name
        );
    }
}

#[tokio::test]
async fn inbound_peer_requests_with_mtls_mismatched_identity_are_terminal() {
    for (index, procedure) in [PeerProcedure::DeviceWatchdog, PeerProcedure::DisconnectPeer]
        .into_iter()
        .enumerate()
    {
        let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
        let client = client
            .into_peer_runtime(runtime_config(10))
            .expect("start client runtime");
        let (_client_handle, mut client_incoming) = client.into_parts();
        let identity = PeerIdentity::new("other.example.test", "other.test");
        let identifier = u32::try_from(index).expect("small request index");
        let request = match procedure {
            PeerProcedure::DeviceWatchdog => build_device_watchdog_request(
                &DeviceWatchdogRequest {
                    identity,
                    origin_state_id: None,
                },
                0x7100 + identifier,
                0x8100 + identifier,
                EncodeContext::default(),
            )
            .expect("build identity-mismatched DWR"),
            PeerProcedure::DisconnectPeer => build_disconnect_peer_request(
                &DisconnectPeerRequest {
                    identity,
                    disconnect_cause: opc_proto_diameter::peer::DisconnectCause::Rebooting,
                    origin_state_id: None,
                },
                0x7100 + identifier,
                0x8100 + identifier,
                EncodeContext::default(),
            )
            .expect("build identity-mismatched DPR"),
            PeerProcedure::CapabilitiesExchange => {
                panic!("capability exchange is outside the runtime identity table")
            }
        };
        raw_server
            .write_all(&encode_message(&request))
            .await
            .expect("write identity-mismatched peer request");
        raw_server
            .flush()
            .await
            .expect("flush identity-mismatched peer request");

        assert_eq!(
            client_incoming
                .receive()
                .await
                .expect_err("identity mismatch must deliver no application message"),
            DiameterPeerRuntimeError::PeerIdentityMismatch,
            "procedure={procedure:?}"
        );
    }
}

#[tokio::test]
async fn peer_runtime_completes_disconnect_then_reports_terminal_state() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let (server_handle, mut server_incoming) = server.into_parts();
    server_handle
        .set_application_quiesced_for_disconnect(true)
        .await
        .expect("declare server application drain");

    let (answer, server_terminal) = tokio::join!(
        client_handle.disconnect(
            opc_proto_diameter::peer::DisconnectCause::Rebooting,
            0x5500,
            0x6600,
            Instant::now() + Duration::from_secs(3),
        ),
        server_incoming.receive(),
    );
    let answer = answer.expect("correlated DPA is returned before closure");
    assert_eq!(answer.result_code, RESULT_CODE_DIAMETER_SUCCESS);
    assert_eq!(answer.origin_state_id, Some(20));
    assert_eq!(
        server_terminal.expect_err("peer DPR closes receive half"),
        DiameterPeerRuntimeError::PeerDisconnected {
            peer_cause: Some(opc_proto_diameter::peer::DisconnectCause::Rebooting),
        }
    );
}

#[tokio::test]
async fn peer_runtime_rejects_disconnect_until_application_traffic_is_quiesced() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let (_server_handle, mut server_incoming) = server.into_parts();

    let (answer, terminal) = tokio::join!(
        client_handle.disconnect(
            opc_proto_diameter::peer::DisconnectCause::Rebooting,
            0x5510,
            0x6610,
            Instant::now() + Duration::from_secs(3),
        ),
        server_incoming.receive(),
    );
    assert_eq!(
        answer
            .expect("a non-quiesced peer still returns a correlated DPA")
            .result_code,
        RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY
    );
    assert_eq!(
        terminal.expect_err("peer DPR closes the receive half after DPA"),
        DiameterPeerRuntimeError::PeerDisconnected {
            peer_cause: Some(opc_proto_diameter::peer::DisconnectCause::Rebooting),
        }
    );
}

#[tokio::test]
async fn peer_runtime_discards_unknown_disconnect_answers_then_rejects_wrong_end_to_end() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let observed_handle = client_handle.clone();
    let disconnect = tokio::spawn(async move {
        client_handle
            .disconnect(
                opc_proto_diameter::peer::DisconnectCause::Rebooting,
                0x5530,
                0x6630,
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    let request_header = read_diameter_frame_header(&mut raw_server).await;
    let hop_by_hop = u32::from_be_bytes(request_header[12..16].try_into().expect("DPR hop-by-hop"));
    let end_to_end = u32::from_be_bytes(request_header[16..20].try_into().expect("DPR end-to-end"));
    let answer = DisconnectPeerAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        identity: PeerIdentity::new("server.example.test", "example.test"),
        origin_state_id: Some(20),
        diagnostics: AnswerDiagnostics::default(),
    };
    let unknown = build_disconnect_peer_answer(
        &answer,
        hop_by_hop.wrapping_add(1),
        end_to_end,
        EncodeContext::default(),
    )
    .expect("build unknown DPA");
    for _ in 0..2 {
        raw_server
            .write_all(&encode_message(&unknown))
            .await
            .expect("write unknown DPA");
        raw_server.flush().await.expect("flush unknown DPA");
    }
    let wrong_end_to_end = build_disconnect_peer_answer(
        &answer,
        hop_by_hop,
        end_to_end.wrapping_add(1),
        EncodeContext::default(),
    )
    .expect("build wrong-end-to-end DPA");
    raw_server
        .write_all(&encode_message(&wrong_end_to_end))
        .await
        .expect("write wrong-end-to-end DPA");
    raw_server
        .flush()
        .await
        .expect("flush wrong-end-to-end DPA");

    assert_eq!(
        disconnect.await.expect("join mismatched disconnect"),
        Err(DiameterPeerRuntimeError::TransactionMismatch)
    );
    assert_eq!(
        observed_handle
            .readiness()
            .await
            .expect_err("wrong end-to-end identifier is terminal"),
        DiameterPeerRuntimeError::TransactionMismatch
    );
}

#[tokio::test]
async fn correlated_disconnect_answer_with_mtls_mismatched_identity_is_terminal() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    let _retained_handle = client_handle.clone();
    let disconnect = tokio::spawn(async move {
        client_handle
            .disconnect(
                opc_proto_diameter::peer::DisconnectCause::Rebooting,
                0x5540,
                0x6640,
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    let request_header = read_diameter_frame_header(&mut raw_server).await;
    let hop_by_hop = u32::from_be_bytes(request_header[12..16].try_into().expect("DPR hop-by-hop"));
    let end_to_end = u32::from_be_bytes(request_header[16..20].try_into().expect("DPR end-to-end"));
    let mismatched = build_disconnect_peer_answer(
        &DisconnectPeerAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: PeerIdentity::new("other.example.test", "other.test"),
            origin_state_id: None,
            diagnostics: AnswerDiagnostics::default(),
        },
        hop_by_hop,
        end_to_end,
        EncodeContext::default(),
    )
    .expect("build identity-mismatched DPA");
    raw_server
        .write_all(&encode_message(&mismatched))
        .await
        .expect("write identity-mismatched DPA");
    raw_server
        .flush()
        .await
        .expect("flush identity-mismatched DPA");

    assert_eq!(
        disconnect
            .await
            .expect("join identity-mismatched disconnect"),
        Err(DiameterPeerRuntimeError::PeerIdentityMismatch)
    );
    assert_eq!(
        client_incoming
            .receive()
            .await
            .expect_err("identity mismatch must deliver no application message"),
        DiameterPeerRuntimeError::PeerIdentityMismatch
    );
}

#[tokio::test(flavor = "current_thread")]
async fn authoritative_close_wins_over_a_late_exact_disconnect_answer() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    let closing_handle = client_handle.clone();
    let disconnect = tokio::spawn(async move {
        client_handle
            .disconnect(
                opc_proto_diameter::peer::DisconnectCause::Rebooting,
                0x5590,
                0x6690,
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    let request_header = read_diameter_frame_header(&mut raw_server).await;
    let hop_by_hop = u32::from_be_bytes(request_header[12..16].try_into().expect("DPR hop-by-hop"));
    let end_to_end = u32::from_be_bytes(request_header[16..20].try_into().expect("DPR end-to-end"));
    let answer = build_disconnect_peer_answer(
        &DisconnectPeerAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: PeerIdentity::new("server.example.test", "example.test"),
            origin_state_id: Some(20),
            diagnostics: AnswerDiagnostics::default(),
        },
        hop_by_hop,
        end_to_end,
        EncodeContext::default(),
    )
    .expect("build exact late DPA");
    let answer_wire = encode_message(&answer);

    let ((), late_write) = tokio::join!(
        biased;
        closing_handle.close(),
        async {
            raw_server.write_all(&answer_wire).await?;
            raw_server.flush().await
        },
    );
    drop(late_write);
    assert_eq!(
        disconnect.await.expect("join closed local disconnect"),
        Err(DiameterPeerRuntimeError::Closed)
    );
    assert_eq!(
        client_incoming
            .receive()
            .await
            .expect_err("authoritative close must remain the public winner"),
        DiameterPeerRuntimeError::Closed
    );
}

#[tokio::test(flavor = "current_thread")]
async fn authoritative_close_wins_over_a_late_peer_disconnect_cause() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    let request = build_disconnect_peer_request(
        &DisconnectPeerRequest {
            identity: PeerIdentity::new("server.example.test", "example.test"),
            disconnect_cause: opc_proto_diameter::peer::DisconnectCause::Busy,
            origin_state_id: Some(20),
        },
        0x55a0,
        0x66a0,
        EncodeContext::default(),
    )
    .expect("build valid late peer DPR");
    let request_wire = encode_message(&request);

    let ((), late_write) = tokio::join!(
        biased;
        client_handle.close(),
        async {
            raw_server.write_all(&request_wire).await?;
            raw_server.flush().await
        },
    );
    drop(late_write);
    assert_eq!(
        client_incoming
            .receive()
            .await
            .expect_err("late peer DPR must not replace the authoritative close"),
        DiameterPeerRuntimeError::Closed
    );
}

#[tokio::test]
async fn admitted_application_traffic_clears_disconnect_quiescence() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let (server_handle, mut server_incoming) = server.into_parts();
    server_handle
        .set_application_quiesced_for_disconnect(true)
        .await
        .expect("declare server application drain");

    let application = application_request();
    let deadline = Instant::now() + Duration::from_secs(3);
    let (sent, received) = tokio::join!(
        client_handle.send_application(application.clone(), deadline),
        server_incoming.receive(),
    );
    sent.expect("send admitted application request");
    assert_eq!(
        received
            .expect("receive admitted application request")
            .into_message(),
        application
    );

    let (answer, terminal) = tokio::join!(
        client_handle.disconnect(
            opc_proto_diameter::peer::DisconnectCause::Rebooting,
            0x5520,
            0x6620,
            Instant::now() + Duration::from_secs(3),
        ),
        server_incoming.receive(),
    );
    assert_eq!(
        answer
            .expect("post-traffic disconnect returns a correlated DPA")
            .result_code,
        RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY
    );
    assert_eq!(
        terminal.expect_err("peer DPR closes the receive half after DPA"),
        DiameterPeerRuntimeError::PeerDisconnected {
            peer_cause: Some(opc_proto_diameter::peer::DisconnectCause::Rebooting),
        }
    );
}

#[tokio::test]
async fn dropping_application_receiver_terminally_closes_runtime() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (_client_handle, mut client_incoming) = client.into_parts();
    let (_server_handle, server_incoming) = server.into_parts();

    drop(server_incoming);
    let error = tokio::time::timeout(Duration::from_secs(1), client_incoming.receive())
        .await
        .expect("peer observes receiver-drop closure")
        .expect_err("receiver drop must not leave a live peer");
    assert!(matches!(
        error,
        DiameterPeerRuntimeError::Transport(_)
            | DiameterPeerRuntimeError::Closed
            | DiameterPeerRuntimeError::PeerDisconnected { .. }
    ));
}

#[tokio::test]
async fn dropping_all_command_handles_terminally_closes_runtime() {
    let (_material, client, server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let server = server
        .into_peer_runtime(runtime_config(20))
        .expect("start server runtime");
    let (_client_handle, mut client_incoming) = client.into_parts();
    let (server_handle, _server_incoming) = server.into_parts();

    drop(server_handle);
    let error = tokio::time::timeout(Duration::from_secs(1), client_incoming.receive())
        .await
        .expect("peer observes last-handle closure")
        .expect_err("dropping every command handle must not leave a read-only peer alive");
    assert!(matches!(
        error,
        DiameterPeerRuntimeError::Transport(_)
            | DiameterPeerRuntimeError::Closed
            | DiameterPeerRuntimeError::PeerDisconnected { .. }
    ));
}

#[tokio::test]
async fn cancelling_enqueued_operation_terminally_closes_runtime() {
    let (_material, client, _server) = negotiated_direct_connections().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    tokio::time::sleep(Duration::from_secs(4)).await;
    let operation = tokio::spawn(async move {
        client_handle
            .probe_watchdog(
                0x7700,
                0x8800,
                DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    operation.abort();
    let _ = operation.await;

    let error = tokio::time::timeout(Duration::from_secs(1), client_incoming.receive())
        .await
        .expect("cancelled operation closes runtime")
        .expect_err("cancelled enqueued operation must be terminal");
    assert!(matches!(
        error,
        DiameterPeerRuntimeError::Transport(_) | DiameterPeerRuntimeError::Closed
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn abort_and_await_closes_retained_handle_synchronously() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, _client_incoming) = client.into_parts();
    let retained_handle = client_handle.clone();
    tokio::time::sleep(Duration::from_secs(4)).await;

    let operation = tokio::spawn(async move {
        client_handle
            .probe_watchdog(
                0x7710,
                0x8810,
                DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid Twinit"),
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    let request_header = read_diameter_frame_header(&mut raw_server).await;
    assert_eq!(
        u32::from_be_bytes([0, request_header[5], request_header[6], request_header[7],]),
        PeerProcedure::DeviceWatchdog.command_code().get()
    );

    operation.abort();
    assert!(operation
        .await
        .expect_err("aborted watchdog task must be cancelled")
        .is_cancelled());
    assert_eq!(
        retained_handle
            .readiness()
            .await
            .expect_err("abort+await must synchronously close retained readiness"),
        DiameterPeerRuntimeError::Closed
    );
    assert_eq!(
        retained_handle
            .peer_session_snapshot()
            .await
            .expect_err("abort+await must synchronously close retained snapshots"),
        DiameterPeerRuntimeError::Closed
    );
}

#[tokio::test(flavor = "current_thread")]
async fn abort_and_await_does_not_release_an_already_buffered_application() {
    let (_material, client, mut raw_server) = negotiated_client_with_raw_server().await;
    let client = client
        .into_peer_runtime(runtime_config(10))
        .expect("start client runtime");
    let (client_handle, mut client_incoming) = client.into_parts();
    let retained_handle = client_handle.clone();

    let application = application_request();
    let watchdog = build_device_watchdog_request(
        &DeviceWatchdogRequest {
            identity: PeerIdentity::new("server.example.test", "example.test"),
            origin_state_id: Some(20),
        },
        0x7720,
        0x8820,
        EncodeContext::default(),
    )
    .expect("build ordering-barrier DWR");
    raw_server
        .write_all(&encode_message(&application))
        .await
        .expect("write application frame to be buffered");
    raw_server
        .write_all(&encode_message(&watchdog))
        .await
        .expect("write ordering-barrier DWR");
    raw_server
        .flush()
        .await
        .expect("flush buffered application and DWR");
    let answer_header = read_diameter_frame_header(&mut raw_server).await;
    assert_eq!(
        u32::from_be_bytes([0, answer_header[5], answer_header[6], answer_header[7],]),
        PeerProcedure::DeviceWatchdog.command_code().get(),
        "receiving DWA proves the preceding application was processed"
    );

    let operation = tokio::spawn(async move {
        client_handle
            .disconnect(
                opc_proto_diameter::peer::DisconnectCause::Rebooting,
                0x7730,
                0x8830,
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    let request_header = read_diameter_frame_header(&mut raw_server).await;
    assert_eq!(
        u32::from_be_bytes([0, request_header[5], request_header[6], request_header[7],]),
        PeerProcedure::DisconnectPeer.command_code().get()
    );

    operation.abort();
    assert!(operation
        .await
        .expect_err("aborted disconnect task must be cancelled")
        .is_cancelled());
    assert_eq!(
        retained_handle
            .readiness()
            .await
            .expect_err("abort+await must synchronously close the retained handle"),
        DiameterPeerRuntimeError::Closed
    );
    assert_eq!(
        client_incoming
            .receive()
            .await
            .expect_err("buffered application must not cross the cancellation boundary"),
        DiameterPeerRuntimeError::Closed
    );
}
