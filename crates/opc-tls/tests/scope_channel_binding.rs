//! RFC026: actual TLS connection binding and interval-only authentication refusal.
use opc_identity::{build_identity_state, IdentityState, TrustBundle, TrustBundleSet, TrustDomain};
use opc_tls::{
    AuthenticationTimeInterval, ChannelBindingDomain, ChannelBindingPurpose, PeerPolicy,
    ScopeTlsConnection, ScopeTlsError, TlsClientHandshake, TlsConfigBuilder, TlsServerHandshake,
};
use opc_types::{InstanceId, SpiffeId, Timestamp};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsConnector;

const CLIENT: &str =
    "spiffe://example.test/tenant/example/ns/example/sa/worker/nf/smf/instance/worker-0";
const SERVER: &str =
    "spiffe://example.test/tenant/example/ns/example/sa/voter/nf/smf/instance/voter-1";

type Issuer = rcgen::CertifiedIssuer<'static, KeyPair>;
fn ca() -> Issuer {
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    rcgen::CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}
fn material(
    id: &str,
    ca: &Issuer,
    start: time::OffsetDateTime,
    end: time::OffsetDateTime,
) -> IdentityState {
    let mut params = CertificateParams::default();
    params.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(id).unwrap(),
    ));
    params.not_before = start;
    params.not_after = end;
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, ca).unwrap();
    let mut roots = TrustBundleSet::new();
    roots.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").unwrap(),
        certificates: vec![ca.der().clone()],
    });
    build_identity_state(
        vec![cert.der().clone(), ca.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        roots,
    )
    .unwrap()
}
struct Pair {
    client: TlsClientHandshake,
    server: TlsServerHandshake,
    client_source: watch::Sender<Option<IdentityState>>,
    _server_source: watch::Sender<Option<IdentityState>>,
    ca: Issuer,
    start: time::OffsetDateTime,
    end: time::OffsetDateTime,
}
fn pair() -> Pair {
    let ca = ca();
    let now = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap();
    let start = now - time::Duration::minutes(10);
    let end = now + time::Duration::minutes(10);
    pair_with_ca(ca, start, end)
}
fn pair_with_ca(ca: Issuer, start: time::OffsetDateTime, end: time::OffsetDateTime) -> Pair {
    let (client_source, client_rx) = watch::channel(Some(material(CLIENT, &ca, start, end)));
    let (server_source, server_rx) = watch::channel(Some(material(SERVER, &ca, start, end)));
    let client = TlsConfigBuilder::new(client_rx)
        .with_policy(PeerPolicy {
            allowed_instances: Some(HashSet::from([InstanceId::new("voter-1").unwrap()])),
            ..Default::default()
        })
        .build_authenticated_client_config()
        .unwrap()
        .begin_handshake()
        .unwrap();
    let server = TlsConfigBuilder::new(server_rx)
        .with_policy(PeerPolicy {
            allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),
            ..Default::default()
        })
        .build_authenticated_server_config()
        .unwrap()
        .begin_handshake()
        .unwrap();
    Pair {
        client,
        server,
        client_source,
        _server_source: server_source,
        ca,
        start,
        end,
    }
}
fn domain() -> ChannelBindingDomain {
    let mut scope = vec![0x11; 32];
    scope.extend_from_slice(b"\0\x07example\0\x03smf");
    scope.extend_from_slice(&[0x22; 32]);
    ChannelBindingDomain::new([0x11; 32], scope).unwrap()
}
fn interval(start: time::OffsetDateTime, end: time::OffsetDateTime) -> AuthenticationTimeInterval {
    AuthenticationTimeInterval::new(
        Timestamp::from_offset_datetime(start),
        Timestamp::from_offset_datetime(end),
    )
    .unwrap()
}
async fn connect(pair: &Pair) -> (ScopeTlsConnection<TcpStream>, ScopeTlsConnection<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            async {
                pair.client
                    .connect_scope(TcpStream::connect(address).await.unwrap(), domain())
                    .await
                    .unwrap()
            },
            async {
                let (stream, _) = listener.accept().await.unwrap();
                pair.server.accept_scope(stream, domain()).await.unwrap()
            }
        )
    })
    .await
    .expect("loopback handshake deadline")
}

#[tokio::test]
async fn actual_tls_endpoints_derive_one_equal_binding_per_purpose() {
    let pair = pair();
    let (client, server) = connect(&pair).await;
    let bounds = interval(pair.start, pair.end - time::Duration::seconds(1));
    let request = client
        .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
        .unwrap();
    let server_request = server
        .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
        .unwrap();
    assert_eq!(request.as_bytes(), server_request.as_bytes());
    let same = client
        .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
        .unwrap();
    assert!(
        std::ptr::eq(request, same),
        "one cached binding per connection/purpose"
    );
    let response = client
        .channel_binding(ChannelBindingPurpose::ScopeResponse, bounds)
        .unwrap();
    assert_ne!(request.as_bytes(), response.as_bytes());
    assert_eq!(format!("{request:?}"), "TlsChannelBinding([redacted])");
    assert_eq!(client.peer_identity().spiffe_id().as_str(), SERVER);
    assert_eq!(server.peer_identity().spiffe_id().as_str(), CLIENT);
    let (second, _) = connect(&pair).await;
    assert_ne!(
        request.as_bytes(),
        second
            .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
            .unwrap()
            .as_bytes()
    );
}

#[tokio::test]
async fn completed_single_now_handshake_does_not_admit_an_interval_crossing_validity() {
    let pair = pair();
    let (client, server) = connect(&pair).await;
    for bounds in [
        interval(
            pair.start - time::Duration::seconds(1),
            pair.start + time::Duration::seconds(1),
        ),
        interval(
            pair.end - time::Duration::seconds(1),
            pair.end + time::Duration::seconds(1),
        ),
    ] {
        assert_eq!(
            client
                .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
                .unwrap_err(),
            ScopeTlsError::AuthTimeUnavailable
        );
        assert_eq!(
            server
                .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
                .unwrap_err(),
            ScopeTlsError::AuthTimeUnavailable
        );
    }
    let peer = client.peer_identity();
    assert_eq!(
        peer.leaf_valid_from(),
        Timestamp::from_offset_datetime(pair.start)
    );
    assert_eq!(
        peer.certificate_chain_valid_from(),
        Timestamp::from_offset_datetime(pair.start)
    );
}

#[tokio::test]
async fn changed_material_invalidates_existing_bindings() {
    let pair = pair();
    let bounds = interval(pair.start, pair.end - time::Duration::seconds(1));
    let (client, _) = connect(&pair).await;
    pair.client_source
        .send(Some(material(CLIENT, &pair.ca, pair.start, pair.end)))
        .unwrap();
    assert_eq!(
        client
            .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
            .unwrap_err(),
        ScopeTlsError::MaterialChanged
    );
}

#[tokio::test]
async fn an_inflight_authentication_guard_rechecks_interval_and_material_after_awaits() {
    let pair = pair();
    let bounds = interval(pair.start, pair.end - time::Duration::seconds(1));
    let (client, server) = connect(&pair).await;
    assert_eq!(client.local_identity().as_str(), CLIENT);
    assert_eq!(server.local_identity().as_str(), SERVER);
    let guard = client.authentication_state(bounds).unwrap();
    guard.revalidate(bounds).unwrap();
    assert_eq!(
        guard.revalidate(interval(pair.start, pair.end + time::Duration::seconds(1))),
        Err(ScopeTlsError::AuthTimeUnavailable)
    );
    pair.client_source
        .send(Some(material(CLIENT, &pair.ca, pair.start, pair.end)))
        .unwrap();
    assert_eq!(
        guard.revalidate(bounds),
        Err(ScopeTlsError::MaterialChanged)
    );
}

#[tokio::test]
async fn unsupported_or_missing_alpn_never_creates_an_admitted_scope_connection() {
    for alpn in [vec![], vec![b"opc-scope/obsolete".to_vec()]] {
        let pair = pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = (*pair.client.rustls_config()).clone();
        config.alpn_protocols = alpn;
        let (_, server) = tokio::join!(
            async {
                TlsConnector::from(Arc::new(config))
                    .connect(
                        ServerName::try_from("ignored.example.test").unwrap(),
                        TcpStream::connect(address).await.unwrap(),
                    )
                    .await
            },
            async {
                let (stream, _) = listener.accept().await.unwrap();
                pair.server.accept_scope(stream, domain()).await
            }
        );
        assert!(server.is_err());
    }
}

#[test]
fn canonical_context_matches_the_normative_vector_and_binds_both_identities() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/rfc/026-scope-authenticated-transport-vectors.json"
    ))
    .unwrap();
    let decode = |s: &str| -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    };
    let scope = decode(vectors["scope"]["transport_bytes_hex"].as_str().unwrap());
    let domain = ChannelBindingDomain::new([0x11; 32], scope).unwrap();
    for (name, purpose) in [
        ("scope-request", ChannelBindingPurpose::ScopeRequest),
        ("scope-response", ChannelBindingPurpose::ScopeResponse),
        ("boot-liveness", ChannelBindingPurpose::BootLiveness),
        ("boot-candidate", ChannelBindingPurpose::BootCandidate),
    ] {
        let vector = vectors["exporters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["purpose"] == name)
            .unwrap();
        let client = SpiffeId::new(vector["client_spiffe"].as_str().unwrap()).unwrap();
        let server = SpiffeId::new(vector["server_spiffe"].as_str().unwrap()).unwrap();
        assert_eq!(
            domain.context_bytes(purpose, &client, &server).unwrap(),
            decode(vector["context_bytes_hex"].as_str().unwrap())
        );
        assert_ne!(
            domain.context_bytes(purpose, &client, &server).unwrap(),
            domain.context_bytes(purpose, &server, &client).unwrap()
        );
    }
    assert!(ChannelBindingDomain::new([0x12; 32], vec![0x11; 70]).is_err());
}

#[tokio::test]
async fn local_and_peer_validity_are_each_required() {
    let mut pair = pair();
    let start = pair.start + time::Duration::minutes(1);
    let end = pair.end - time::Duration::minutes(1);
    pair._server_source
        .send(Some(material(SERVER, &pair.ca, start, end)))
        .unwrap();
    pair.server = TlsConfigBuilder::new(pair._server_source.subscribe())
        .with_policy(PeerPolicy {
            allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),
            ..Default::default()
        })
        .build_authenticated_server_config()
        .unwrap()
        .begin_handshake()
        .unwrap();
    let (client, server) = connect(&pair).await;
    for bounds in [interval(pair.start, start), interval(end, pair.end)] {
        assert_eq!(
            client
                .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
                .unwrap_err(),
            ScopeTlsError::AuthTimeUnavailable,
            "peer interval must be checked"
        );
        assert_eq!(
            server
                .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
                .unwrap_err(),
            ScopeTlsError::AuthTimeUnavailable,
            "local interval must be checked"
        );
    }
}

#[tokio::test]
async fn presented_chain_can_be_narrower_than_the_leaf() {
    let now = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap();
    let start = now - time::Duration::minutes(10);
    let end = now + time::Duration::minutes(10);
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = start + time::Duration::minutes(1);
    params.not_after = end - time::Duration::minutes(1);
    let ca = rcgen::CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let pair = pair_with_ca(ca, start, end);
    let (client, server) = connect(&pair).await;
    assert!(
        client.peer_identity().certificate_chain_valid_from()
            > client.peer_identity().leaf_valid_from()
    );
    assert!(
        client.peer_identity().certificate_chain_expires_at()
            < client.peer_identity().leaf_expires_at()
    );
    for bounds in [
        interval(start, start + time::Duration::minutes(2)),
        interval(end - time::Duration::minutes(2), end),
    ] {
        assert_eq!(
            client
                .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
                .unwrap_err(),
            ScopeTlsError::AuthTimeUnavailable
        );
        assert_eq!(
            server
                .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
                .unwrap_err(),
            ScopeTlsError::AuthTimeUnavailable
        );
    }
}

#[test]
fn invalid_clock_interval_and_noncanonical_scope_never_bind() {
    let now = Timestamp::now_utc();
    assert_eq!(
        AuthenticationTimeInterval::new(now.add_seconds(1).unwrap(), now).unwrap_err(),
        ScopeTlsError::AuthTimeUnavailable
    );
    let valid = domain().scope_bytes().to_vec();
    for length in 0..valid.len() {
        assert!(ChannelBindingDomain::new([0x11; 32], valid[..length].to_vec()).is_err());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(ChannelBindingDomain::new([0x11; 32], trailing).is_err());
    let mut zero_slot = valid;
    let length = zero_slot.len();
    zero_slot[length - 32..].fill(0);
    assert!(ChannelBindingDomain::new([0x11; 32], zero_slot).is_err());
}

#[tokio::test(start_paused = true)]
async fn silent_peer_expires_the_bounded_handshake() {
    let pair = pair();
    let (server, _silent_client) = tokio::io::duplex(1024);
    let before = tokio::time::Instant::now();
    assert_eq!(
        pair.server
            .accept_scope(server, domain())
            .await
            .unwrap_err(),
        ScopeTlsError::HandshakeFailed
    );
    assert_eq!(
        tokio::time::Instant::now() - before,
        std::time::Duration::from_secs(5)
    );
}

#[tokio::test]
async fn tls12_compatibility_configuration_cannot_admit_scope_traffic() {
    let mut pair = pair();
    pair.server = TlsConfigBuilder::new(pair._server_source.subscribe())
        .with_compat_mode(true)
        .with_policy(PeerPolicy {
            allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),
            ..Default::default()
        })
        .build_authenticated_server_config()
        .unwrap()
        .begin_handshake()
        .unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(opc_tls::SpiffeServerCertVerifier::new(
        pair.client_source.subscribe(),
        PeerPolicy {
            allowed_instances: Some(HashSet::from([InstanceId::new("voter-1").unwrap()])),
            ..Default::default()
        },
    )))
    .with_client_cert_resolver(Arc::clone(
        &pair.client.rustls_config().client_auth_cert_resolver,
    ));
    client.alpn_protocols = vec![b"opc-scope/1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (_, server) = tokio::join!(
        async {
            TlsConnector::from(Arc::new(client))
                .connect(
                    ServerName::try_from("ignored.example.test").unwrap(),
                    TcpStream::connect(address).await.unwrap(),
                )
                .await
        },
        async {
            let (stream, _) = listener.accept().await.unwrap();
            pair.server.accept_scope(stream, domain()).await
        }
    );
    assert_eq!(server.unwrap_err(), ScopeTlsError::ProtocolMismatch);
}

#[tokio::test]
async fn authenticated_header_routes_once_before_exporters_are_bound() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pair = pair();
    let (client_io, server_io) = tokio::io::duplex(8192);
    let (client, server) = tokio::join!(
        async {
            let mut stream = pair
                .client
                .connect_scope(client_io, domain())
                .await
                .unwrap();
            stream.write_all(&[0x42; 128]).await.unwrap();
            stream.flush().await.unwrap();
            stream
        },
        async {
            let mut stream = pair.server.accept_scope_unbound(server_io).await.unwrap();
            assert_eq!(stream.peer_identity().spiffe_id().as_str(), CLIENT);
            let mut header = [0; 128];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header, [0x42; 128]);
            stream.bind_scope(domain()).unwrap()
        }
    );
    let bounds = interval(pair.start, pair.end);
    assert_eq!(
        client
            .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
            .unwrap()
            .as_bytes(),
        server
            .channel_binding(ChannelBindingPurpose::ScopeRequest, bounds)
            .unwrap()
            .as_bytes(),
    );
}

#[test]
fn scope_configuration_rejects_compatibility_and_allow_any_before_io() {
    let pair = pair();
    for (compatibility, unconstrained) in [(true, false), (false, true)] {
        let builder = || {
            let mut builder = TlsConfigBuilder::new(pair.client_source.subscribe())
                .with_compat_mode(compatibility);
            if unconstrained {
                builder = builder.allow_any_trusted_peer();
            } else {
                builder = builder.with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("voter-1").unwrap()])),
                    ..Default::default()
                });
            }
            builder
        };
        let client = builder().build_authenticated_client_config().unwrap();
        let server = builder().build_authenticated_server_config().unwrap();
        assert_eq!(
            client.validate_scope_profile(),
            Err(ScopeTlsError::ProtocolMismatch)
        );
        assert_eq!(
            server.validate_scope_profile(),
            Err(ScopeTlsError::ProtocolMismatch)
        );
    }
}
