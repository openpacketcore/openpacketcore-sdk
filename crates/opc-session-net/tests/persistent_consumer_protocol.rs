//! Adversarial wire tests for the revision-2 persistent consumer transport.
//!
//! The peer in these tests deliberately speaks only JSON values.  That keeps
//! the private consumer wire DTOs private while still checking that a live
//! mTLS peer cannot desynchronise a retained client lane.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    PersistentSessionConsumerClient, PersistentSessionConsumerConfig, RemoteAddrResolver,
    SessionConsumerClientError, StatelessSessionConsumerClient, MAX_NEGOTIATED_FRAME_SIZE,
    SESSION_QUORUM_CONSUMER_ALPN, SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
};
use opc_session_store::{
    BackendCapabilities, SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
    SessionConsensusConfigurationId, SessionConsensusIdentity, SessionConsumerResponse,
    SessionConsumerScope,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::SpiffeId;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

struct TestPki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().expect("test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "persistent protocol test CA");
        Self {
            ca: rcgen::CertifiedIssuer::self_signed(parameters, key).expect("test CA certificate"),
        }
    }

    fn client_config(&self, spiffe_id: &str) -> AuthenticatedClientConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("test client mTLS config")
    }

    fn server_config(&self, spiffe_id: &str) -> AuthenticatedServerConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("test server mTLS config")
    }

    fn identity_state(&self, spiffe_id: &str) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "persistent protocol test leaf");
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe_id).expect("test SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("test leaf key");
        let certificate = parameters
            .signed_by(&key, &self.ca)
            .expect("test leaf certificate");
        let certificates =
            parse_certs_pem(&(certificate.pem() + &self.ca.pem())).expect("test certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("test private key");
        let mut bundles = opc_identity::TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("test.example").expect("trust domain"),
            certificates: parse_certs_pem(&self.ca.pem()).expect("test trust bundle"),
        });
        build_identity_state(certificates, private_key, bundles).expect("test identity state")
    }
}

fn spiffe(name: &str) -> String {
    format!("spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{name}")
}

fn scope(marker: u8) -> SessionConsumerScope {
    SessionConsumerScope::new(SessionConsensusIdentity::new(
        SessionConsensusClusterId::from_bytes([marker; 32]),
        SessionConsensusConfigurationId::from_bytes([marker.wrapping_add(1); 32]),
        SessionConsensusConfigurationEpoch::new(1).expect("nonzero epoch"),
    ))
}

fn persistent_client(
    pki: &TestPki,
    address: SocketAddr,
    server_spiffe: &str,
    client_spiffe: &str,
    scope: SessionConsumerScope,
) -> PersistentSessionConsumerClient {
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1));
    PersistentSessionConsumerClient::try_from_stateless(
        stateless,
        PersistentSessionConsumerConfig::try_new(
            1,
            0,
            Duration::from_millis(250),
            1,
            Duration::from_millis(1_500),
            2,
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .expect("one-lane fail-fast config"),
    )
    .expect("persistent client")
}

async fn accept_consumer_tls(
    listener: &TcpListener,
    authenticated: &AuthenticatedServerConfig,
    expected_client: &SpiffeId,
) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
    let (tcp, _) = listener.accept().await.expect("accept TLS socket");
    let handshake = authenticated.begin_handshake().expect("server material");
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![SESSION_QUORUM_CONSUMER_ALPN.to_vec()];
    let stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
        .accept(tcp)
        .await
        .expect("accept consumer mTLS");
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(SESSION_QUORUM_CONSUMER_ALPN),
        "the malicious peer stays on the dedicated consumer ALPN"
    );
    let peer = opc_tls::peer_tls_identity_from_server_connection(stream.get_ref().1)
        .expect("authenticated client SPIFFE identity");
    assert_eq!(
        peer.spiffe_id(),
        expected_client,
        "exact client SPIFFE identity"
    );
    handshake.admit().expect("admit unchanged test material");
    stream
}

async fn read_value<R>(reader: &mut R) -> Value
where
    R: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await.expect("frame length");
    let length = usize::try_from(u32::from_be_bytes(length)).expect("frame length fits usize");
    assert!(
        length <= MAX_NEGOTIATED_FRAME_SIZE,
        "client frame stays capped"
    );
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .expect("frame payload");
    serde_json::from_slice(&payload).expect("valid client JSON frame")
}

async fn write_payload<W>(writer: &mut W, payload: &[u8])
where
    W: AsyncWrite + Unpin,
{
    let length = u32::try_from(payload.len()).expect("test payload fits wire length");
    writer
        .write_all(&length.to_be_bytes())
        .await
        .expect("write frame length");
    writer
        .write_all(payload)
        .await
        .expect("write frame payload");
    writer.flush().await.expect("flush frame");
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
enum CanonicalConsumerWireResponse {
    HelloAck(CanonicalConsumerHelloAck),
    Response(CanonicalConsumerCallResponse),
}

#[derive(Serialize)]
struct CanonicalConsumerHelloAck {
    transport_revision: u16,
    scope: SessionConsumerScope,
}

#[derive(Serialize)]
struct CanonicalConsumerCallResponse {
    // Keep this as a JSON scalar so the zero-correlation adversary can reach
    // the production decoder instead of being rejected by the fixture.
    correlation: Value,
    response: SessionConsumerResponse,
}

fn canonical_response_payload(value: &Value) -> Vec<u8> {
    let response = match value["kind"].as_str() {
        Some("hello_ack") => CanonicalConsumerWireResponse::HelloAck(CanonicalConsumerHelloAck {
            transport_revision: serde_json::from_value(value["body"]["transport_revision"].clone())
                .expect("HelloAck revision"),
            scope: serde_json::from_value(value["body"]["scope"].clone()).expect("HelloAck scope"),
        }),
        Some("response") => {
            CanonicalConsumerWireResponse::Response(CanonicalConsumerCallResponse {
                correlation: value["body"]["correlation"].clone(),
                response: serde_json::from_value(value["body"]["response"].clone())
                    .expect("typed consumer response"),
            })
        }
        other => panic!("unsupported test response kind: {other:?}"),
    };
    serde_json::to_vec(&response).expect("test JSON encodes")
}

async fn write_value<W>(writer: &mut W, value: &Value)
where
    W: AsyncWrite + Unpin,
{
    // The revision-2 transport owns canonical private DTO bytes. Build those
    // bytes from typed public body values so each adversary reaches the exact
    // correlation/frame condition it intends to test.
    let payload = canonical_response_payload(value);
    assert!(
        payload.len() <= MAX_NEGOTIATED_FRAME_SIZE,
        "test frame stays capped"
    );
    write_payload(writer, &payload).await;
}

fn hello_ack(hello: &Value) -> Value {
    json!({
        "kind": "hello_ack",
        "body": {
            "transport_revision": SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
            "scope": hello["body"]["scope"].clone(),
        },
    })
}

fn capability_response(correlation: Value) -> Value {
    json!({
        "kind": "response",
        "body": {
            "correlation": correlation,
            "response": serde_json::to_value(SessionConsumerResponse::Capabilities(
                BackendCapabilities::all_enabled(),
            )).expect("capability response encodes"),
        },
    })
}

async fn accept_hello_and_call(
    listener: &TcpListener,
    authenticated: &AuthenticatedServerConfig,
    expected_client: &SpiffeId,
) -> (
    tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    Value,
) {
    let mut tls = accept_consumer_tls(listener, authenticated, expected_client).await;
    let hello = read_value(&mut tls).await;
    assert_eq!(hello["kind"], "hello", "client starts with consumer Hello");
    write_value(&mut tls, &hello_ack(&hello)).await;
    let call = read_value(&mut tls).await;
    assert_eq!(call["kind"], "call", "application frame follows HelloAck");
    (tls, call)
}

fn assert_typed_protocol_error(
    result: Result<BackendCapabilities, SessionConsumerClientError>,
    server_spiffe: &str,
    client_spiffe: &str,
) {
    let error = result.expect_err("malicious peer must fail closed");
    assert_eq!(error, SessionConsumerClientError::Protocol);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(server_spiffe));
    assert!(!rendered.contains(client_spiffe));
}

#[tokio::test]
async fn hello_ack_revision_and_scope_mismatches_fail_closed_without_a_call() {
    for wrong in ["revision", "scope"] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("hello-{wrong}-server"));
        let client_spiffe = spiffe(&format!("hello-{wrong}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let mut tls = accept_consumer_tls(&listener, &authenticated, &expected_client).await;
            let hello = read_value(&mut tls).await;
            let mut ack = hello_ack(&hello);
            match wrong {
                "revision" => ack["body"]["transport_revision"] = json!(u16::MAX),
                "scope" => ack["body"]["scope"] = serde_json::to_value(scope(9)).expect("scope"),
                _ => unreachable!("fixed test cases"),
            }
            write_value(&mut tls, &ack).await;
            match tokio::time::timeout(Duration::from_millis(100), tls.read_u8()).await {
                Err(_) | Ok(Err(_)) => {}
                Ok(Ok(_)) => panic!("a rejected HelloAck must not permit an application call"),
            }
        });
        let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
        assert_typed_protocol_error(client.capabilities().await, &server_spiffe, &client_spiffe);
        server.await.expect("malicious server");
    }
}

#[tokio::test]
async fn zero_future_and_wrong_variant_responses_fail_closed() {
    for case in ["zero", "future", "wrong_variant"] {
        let pki = TestPki::new();
        let identity_case = case.replace('_', "-");
        let server_spiffe = spiffe(&format!("response-{identity_case}-server"));
        let client_spiffe = spiffe(&format!("response-{identity_case}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let (mut tls, call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            let correlation = match case {
                "zero" => json!(0),
                "future" => json!(2),
                "wrong_variant" => call["body"]["correlation"].clone(),
                _ => unreachable!("fixed test cases"),
            };
            let response = if case == "wrong_variant" {
                json!({
                    "kind": "response",
                    "body": {
                        "correlation": correlation,
                        "response": serde_json::to_value(SessionConsumerResponse::Get(Ok(None)))
                            .expect("wrong response encodes"),
                    },
                })
            } else {
                capability_response(correlation)
            };
            write_value(&mut tls, &response).await;
        });
        let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
        assert_typed_protocol_error(client.capabilities().await, &server_spiffe, &client_spiffe);
        server.await.expect("malicious server");
    }
}

#[tokio::test]
async fn malformed_trailing_and_oversized_response_frames_fail_closed() {
    for case in ["malformed", "trailing", "oversized"] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("frame-{case}-server"));
        let client_spiffe = spiffe(&format!("frame-{case}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let (mut tls, call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            match case {
                "malformed" => write_payload(&mut tls, br#"{"#).await,
                "trailing" => {
                    let mut payload = canonical_response_payload(&capability_response(
                        call["body"]["correlation"].clone(),
                    ));
                    payload.extend_from_slice(br#"{}"#);
                    write_payload(&mut tls, &payload).await;
                }
                "oversized" => {
                    let length = u32::try_from(MAX_NEGOTIATED_FRAME_SIZE + 1)
                        .expect("fixed cap fits wire length");
                    tls.write_all(&length.to_be_bytes())
                        .await
                        .expect("write oversized prefix");
                    tls.flush().await.expect("flush oversized prefix");
                }
                _ => unreachable!("fixed test cases"),
            }
        });
        let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
        assert_typed_protocol_error(client.capabilities().await, &server_spiffe, &client_spiffe);
        server.await.expect("malicious server");
    }
}

#[tokio::test]
async fn duplicate_response_poisons_lane_and_next_call_uses_a_new_connection() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("sequence-server");
    let client_spiffe = spiffe("sequence-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind malicious listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let server = tokio::spawn(async move {
        let (mut tls, first) =
            accept_hello_and_call(&listener, &authenticated, &expected_client).await;
        let first_correlation = first["body"]["correlation"].clone();
        write_value(&mut tls, &capability_response(first_correlation.clone())).await;
        let second = read_value(&mut tls).await;
        assert_eq!(second["body"]["correlation"], json!(2));
        // This is valid JSON but the prior request's correlation: a duplicate
        // and late response while call two is outstanding.
        write_value(&mut tls, &capability_response(first_correlation)).await;

        let (mut fresh_tls, fresh) =
            accept_hello_and_call(&listener, &authenticated, &expected_client).await;
        assert_eq!(fresh["body"]["correlation"], json!(1));
        write_value(
            &mut fresh_tls,
            &capability_response(fresh["body"]["correlation"].clone()),
        )
        .await;
    });
    let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));

    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    assert_typed_protocol_error(client.capabilities().await, &server_spiffe, &client_spiffe);
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled()),
        "a discarded lane must never deliver its late response to a later call"
    );
    server.await.expect("malicious server");
}
