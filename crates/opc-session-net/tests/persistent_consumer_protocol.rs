//! Adversarial wire tests for the revision-2 persistent consumer transport.
//!
//! The peer in these tests deliberately speaks only JSON values.  That keeps
//! the private consumer wire DTOs private while still checking that a live
//! mTLS peer cannot desynchronise a retained client lane.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    PersistentSessionConsumerClient, PersistentSessionConsumerConfig,
    PersistentSessionConsumerExecuteError, RemoteAddrResolver, SessionConsumerClientError,
    SessionConsumerMutationError, StatelessSessionConsumerClient, MAX_NEGOTIATED_FRAME_SIZE,
    SESSION_QUORUM_CONSUMER_ALPN, SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
};
use opc_session_store::{
    checked_session_deadline, BackendCapabilities, CompareAndSet, CompareAndSetResult,
    EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation, OwnerId,
    RestoreScanCursor, RestoreScanCursorProfile, RestoreScanPage, RestoreScanRequest,
    RestoreScanScope, SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
    SessionConsensusConfigurationId, SessionConsensusIdentity, SessionConsumerBatchResult,
    SessionConsumerChange, SessionConsumerLeaseError, SessionConsumerLeaseGrant,
    SessionConsumerOperation, SessionConsumerRejection, SessionConsumerRequest,
    SessionConsumerRequestId, SessionConsumerResponse, SessionConsumerScope,
    SessionConsumerStoreError, SessionKey, SessionKeyType, SessionLeaseManager, SessionOp,
    StateClass, StateType, StoreError, StoredSessionRecord,
    MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES, MAX_SESSION_TTL,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

const SHORT_ACTIVE_FRAME_IDLE: Duration = Duration::from_millis(100);
const SHORT_ACTIVE_FRAME_WAIT: Duration = Duration::from_millis(500);

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

fn mutation_request(
    scope: SessionConsumerScope,
    request_id: SessionConsumerRequestId,
) -> SessionConsumerRequest {
    SessionConsumerRequest::new(
        scope,
        request_id,
        SessionConsumerOperation::AcquireLease {
            key: SessionKey {
                tenant: TenantId::new("protocol-boundary").expect("test tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"opaque-protocol-boundary")
                    .try_into()
                    .expect("bounded stable ID"),
            },
            owner: OwnerId::new("protocol-boundary-owner").expect("test owner"),
            ttl: Duration::from_secs(30),
        },
    )
}

fn semantic_key(stable_id: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("semantic-boundary").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(stable_id)
            .try_into()
            .expect("bounded test stable ID"),
    }
}

fn semantic_record(key: SessionKey, owner: OwnerId, fence: FenceToken) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("persistent-semantic-test"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"opaque-test-payload"),
    }
}

fn semantic_request(
    operation: SessionConsumerOperation,
    request_byte: u8,
) -> SessionConsumerRequest {
    SessionConsumerRequest::new(
        scope(1),
        SessionConsumerRequestId::from_bytes([request_byte; 16]),
        operation,
    )
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

fn persistent_client_with_short_active_frame_idle(
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
    .with_idle_timeout(SHORT_ACTIVE_FRAME_IDLE)
    .with_operation_timeout(Duration::from_secs(1));
    PersistentSessionConsumerClient::try_from_stateless(
        stateless,
        PersistentSessionConsumerConfig::try_new(
            1,
            0,
            Duration::from_millis(250),
            1,
            Duration::from_millis(500),
            1,
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .expect("one-lane short-active-idle config"),
    )
    .expect("persistent client")
}

async fn accept_consumer_tls(
    listener: &TcpListener,
    authenticated: &AuthenticatedServerConfig,
    expected_client: &SpiffeId,
) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
    let (tcp, _) = listener.accept().await.expect("accept TLS socket");
    tcp.set_nodelay(true)
        .expect("malicious fixture preserves the production TCP boundary");
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
    assert!(
        peer.spiffe_id() == expected_client,
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

async fn write_partial_frame<W>(writer: &mut W, boundary: &str)
where
    W: AsyncWrite + Unpin,
{
    match boundary {
        "prefix" => writer
            .write_all(&[0])
            .await
            .expect("write partial frame prefix"),
        "payload" => {
            writer
                .write_all(&2_u32.to_be_bytes())
                .await
                .expect("write partial payload prefix");
            writer
                .write_all(b"{")
                .await
                .expect("write partial frame payload");
        }
        _ => unreachable!("fixed partial-frame boundary"),
    }
    writer.flush().await.expect("flush partial frame");
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
enum CanonicalConsumerWireResponse {
    HelloAck(CanonicalConsumerHelloAck),
    Response(CanonicalConsumerCallResponse),
    WatchEntry(CanonicalConsumerWatchEntry),
}

#[derive(Serialize)]
struct CanonicalConsumerHelloAck {
    transport_revision: u16,
    scope: SessionConsumerScope,
    request_frame_size: u32,
}

#[derive(Serialize)]
struct CanonicalConsumerCallResponse {
    // Keep this as a JSON scalar so the zero-correlation adversary can reach
    // the production decoder instead of being rejected by the fixture.
    correlation: Value,
    response: SessionConsumerResponse,
}

#[derive(Serialize)]
struct CanonicalConsumerWatchEntry {
    correlation: Value,
    entry: Result<SessionConsumerChange, SessionConsumerStoreError>,
}

fn canonical_response_payload(value: &Value) -> Vec<u8> {
    let response = match value["kind"].as_str() {
        Some("hello_ack") => CanonicalConsumerWireResponse::HelloAck(CanonicalConsumerHelloAck {
            transport_revision: serde_json::from_value(value["body"]["transport_revision"].clone())
                .expect("HelloAck revision"),
            scope: serde_json::from_value(value["body"]["scope"].clone()).expect("HelloAck scope"),
            request_frame_size: serde_json::from_value(value["body"]["request_frame_size"].clone())
                .expect("HelloAck request frame size"),
        }),
        Some("response") => {
            CanonicalConsumerWireResponse::Response(CanonicalConsumerCallResponse {
                correlation: value["body"]["correlation"].clone(),
                response: serde_json::from_value(value["body"]["response"].clone())
                    .expect("typed consumer response"),
            })
        }
        Some("watch_entry") => {
            CanonicalConsumerWireResponse::WatchEntry(CanonicalConsumerWatchEntry {
                correlation: value["body"]["correlation"].clone(),
                entry: serde_json::from_value(value["body"]["entry"].clone())
                    .expect("typed watch entry"),
            })
        }
        _ => panic!("unsupported test response kind"),
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
            "request_frame_size": MAX_NEGOTIATED_FRAME_SIZE,
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

fn watch_opened_response(correlation: Value) -> Value {
    json!({
        "kind": "response",
        "body": {
            "correlation": correlation,
            "response": serde_json::to_value(SessionConsumerResponse::WatchOpened)
                .expect("watch-opened response encodes"),
        },
    })
}

fn watch_entry_response(correlation: Value, sequence: u64) -> Value {
    let key = semantic_key(b"partial-frame-watch-entry");
    let change: SessionConsumerChange = serde_json::from_value(json!({
        "sequence": sequence,
        "changes": [{
            "key": serde_json::to_value(key).expect("watch key encodes"),
            "kind": "RecordWritten",
        }],
    }))
    .expect("synthetic watch change decodes");
    json!({
        "kind": "watch_entry",
        "body": {
            "correlation": correlation,
            "entry": serde_json::to_value(Ok::<_, SessionConsumerStoreError>(change))
                .expect("watch entry encodes"),
        },
    })
}

fn rejected_response(correlation: Value, rejection: SessionConsumerRejection) -> Value {
    json!({
        "kind": "response",
        "body": {
            "correlation": correlation,
            "response": serde_json::to_value(SessionConsumerResponse::Rejected(rejection))
                .expect("rejection response encodes"),
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

async fn assert_malicious_semantic_response_is_unconfirmed(
    case: &str,
    request: SessionConsumerRequest,
    response: SessionConsumerResponse,
) {
    let pki = TestPki::new();
    let server_spiffe = spiffe(&format!("semantic-{case}-server"));
    let client_spiffe = spiffe(&format!("semantic-{case}-client"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind malicious listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let expected_request = serde_json::to_value(&request).expect("request encodes");
    let server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&listener, &authenticated, &expected_client).await;
        assert_eq!(
            call["body"]["request"], expected_request,
            "the malicious response is bound to the exact tested request"
        );
        let response = json!({
            "kind": "response",
            "body": {
                "correlation": call["body"]["correlation"].clone(),
                "response": serde_json::to_value(response).expect("semantic response encodes"),
            },
        });
        write_value(&mut tls, &response).await;
    });
    let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
    let request_id = request.request_id();
    let effectful = match request.operation() {
        SessionConsumerOperation::Capabilities
        | SessionConsumerOperation::Get { .. }
        | SessionConsumerOperation::PreflightRecordExpiry { .. }
        | SessionConsumerOperation::ScanRestoreRecords { .. }
        | SessionConsumerOperation::Watch { .. } => false,
        SessionConsumerOperation::Batch { ops } => ops
            .iter()
            .any(|operation| !matches!(operation, SessionOp::Get { .. })),
        _ => true,
    };
    let result = client.execute(&request).await;
    if effectful {
        assert!(matches!(
            result,
            Err(PersistentSessionConsumerExecuteError::OutcomeUnknown { request_id: returned })
                if returned == request_id
        ));
    } else {
        assert_eq!(
            result,
            Err(PersistentSessionConsumerExecuteError::ReadUnavailable {
                cause: SessionConsumerClientError::Protocol,
            })
        );
    }
    let diagnostics = client.diagnostics().await;
    assert_eq!(
        diagnostics.successes, 0,
        "malformed peer data is never a success"
    );
    assert_eq!(
        diagnostics.reconnects, 1,
        "the poisoned lane is never recycled"
    );
    client.shutdown().await;
    server.await.expect("malicious server");
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
async fn negotiated_reduced_request_cap_rejects_a_large_mutation_before_transmission() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("reduced-request-cap-server");
    let client_spiffe = spiffe("reduced-request-cap-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reduced-cap listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let reduced_cap = MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES + 4 * 1024;
    let server = tokio::spawn(async move {
        let mut tls = accept_consumer_tls(&listener, &authenticated, &expected_client).await;
        let hello = read_value(&mut tls).await;
        let mut ack = hello_ack(&hello);
        ack["body"]["request_frame_size"] = json!(reduced_cap);
        write_value(&mut tls, &ack).await;
        match tokio::time::timeout(Duration::from_millis(250), tls.read_u8()).await {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("an over-cap mutation must not write even a frame-prefix byte"),
        }
    });

    let key = semantic_key(b"reduced-request-cap-key");
    let owner = OwnerId::new("reduced-request-cap-owner").expect("test owner");
    let lease = FakeSessionBackend::new()
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .expect("fixture lease");
    // JSON renders 255 with three digits. Three 768-KiB payloads therefore
    // cross the retained 8-MiB-plus-4-KiB negotiated cap with fewer than half
    // the serializer elements of five 1-MiB zero payloads. This keeps the
    // fixture about the negotiated byte boundary rather than racing the real
    // one-second complete-operation budget on loaded and i686 CI runners.
    let payload = vec![255_u8; 768 * 1024];
    let ops = (0..3)
        .map(|_| {
            SessionOp::CompareAndSet(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: StoredSessionRecord {
                    payload: EncryptedSessionPayload::new(&payload),
                    ..semantic_record(key.clone(), owner.clone(), lease.fence())
                },
            })
        })
        .collect::<Vec<_>>();
    let request = semantic_request(SessionConsumerOperation::Batch { ops }, 66);
    let request_bytes = serde_json::to_vec(&request).expect("large request encodes");
    assert!(
        request_bytes.len() > reduced_cap,
        "fixture crosses the authenticated server-advertised request cap"
    );
    assert!(
        request_bytes.len() < MAX_NEGOTIATED_FRAME_SIZE,
        "fixture remains valid at the revision-wide frame cap"
    );

    let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
    match client.execute(&request).await {
        Err(PersistentSessionConsumerExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Protocol,
        }) => {}
        Err(PersistentSessionConsumerExecuteError::NotTransmitted { cause }) => {
            panic!("oversized request had unexpected not-transmitted class: {cause:?}")
        }
        Err(PersistentSessionConsumerExecuteError::ReadUnavailable { cause }) => {
            panic!("oversized mutation had unexpected read-only class: {cause:?}")
        }
        Err(PersistentSessionConsumerExecuteError::OutcomeUnknown { .. }) => {
            panic!("oversized request crossed the transport boundary")
        }
        Err(_) => panic!("oversized request had an unknown future error class"),
        Ok(_) => panic!("oversized request unexpectedly received a response"),
    }
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, 1);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.not_transmitted, 1);
    assert_eq!(diagnostics.outcome_unknown, 0);
    client.shutdown().await;
    server.await.expect("reduced-cap server");
}

#[tokio::test]
async fn partial_hello_ack_expires_at_the_configured_setup_bound() {
    for boundary in ["prefix", "payload"] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("partial-hello-ack-{boundary}-server"));
        let client_spiffe = spiffe(&format!("partial-hello-ack-{boundary}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let mut tls = accept_consumer_tls(&listener, &authenticated, &expected_client).await;
            let hello = read_value(&mut tls).await;
            assert_eq!(hello["kind"], "hello", "client starts with consumer Hello");
            write_partial_frame(&mut tls, boundary).await;
            // Hello is authenticated setup rather than an idle lane. Keep the
            // peer silent past the fixture's 500ms setup cap, independently
            // of its much shorter active-frame idle timeout.
            tokio::time::sleep(Duration::from_millis(750)).await;
        });
        let client = persistent_client_with_short_active_frame_idle(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            scope(1),
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), client.capabilities())
                .await
                .expect("partial HelloAck obeys the configured setup bound"),
            Err(SessionConsumerClientError::Deadline)
        );
        let diagnostics = client.diagnostics().await;
        assert_eq!(diagnostics.hello_attempts, 1);
        assert_eq!(diagnostics.hello_failures, 1);
        client.shutdown().await;
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
async fn authenticated_semantic_response_mismatches_are_unconfirmed_and_poison_the_lane() {
    let requested_key = semantic_key(b"requested-key");
    let wrong_key = semantic_key(b"wrong-key");
    let owner = OwnerId::new("semantic-owner").expect("test owner");
    let wrong_owner = OwnerId::new("wrong-semantic-owner").expect("test owner");

    assert_malicious_semantic_response_is_unconfirmed(
        "get-key",
        semantic_request(
            SessionConsumerOperation::Get {
                key: requested_key.clone(),
            },
            1,
        ),
        SessionConsumerResponse::Get(Ok(Some(semantic_record(
            wrong_key.clone(),
            owner.clone(),
            FenceToken::new(1),
        )))),
    )
    .await;
    assert_malicious_semantic_response_is_unconfirmed(
        "get-ambiguity",
        semantic_request(
            SessionConsumerOperation::Get {
                key: requested_key.clone(),
            },
            2,
        ),
        SessionConsumerResponse::Get(Err(
            opc_session_store::SessionConsumerStoreError::OutcomeUnavailable,
        )),
    )
    .await;

    let backend = FakeSessionBackend::new();
    let lease = backend
        .acquire(&requested_key, owner.clone(), Duration::from_secs(30))
        .await
        .expect("test lease");
    let cas = CompareAndSet {
        key: requested_key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: semantic_record(requested_key.clone(), owner.clone(), lease.fence()),
    };
    assert_malicious_semantic_response_is_unconfirmed(
        "cas-conflict-key",
        semantic_request(
            SessionConsumerOperation::CompareAndSet { op: Box::new(cas) },
            3,
        ),
        SessionConsumerResponse::CompareAndSet(Ok(CompareAndSetResult::Conflict {
            current: Some(semantic_record(
                wrong_key.clone(),
                owner.clone(),
                FenceToken::new(1),
            )),
        })),
    )
    .await;

    let wrong_lease = backend
        .acquire(&wrong_key, wrong_owner.clone(), Duration::from_secs(30))
        .await
        .expect("wrong-key test lease");
    assert_malicious_semantic_response_is_unconfirmed(
        "acquire-key-owner",
        semantic_request(
            SessionConsumerOperation::AcquireLease {
                key: requested_key.clone(),
                owner: owner.clone(),
                ttl: Duration::from_secs(30),
            },
            4,
        ),
        SessionConsumerResponse::AcquireLease(Ok(SessionConsumerLeaseGrant::new(
            wrong_lease.clone(),
            wrong_lease.acquired_at(),
        ))),
    )
    .await;
    assert_malicious_semantic_response_is_unconfirmed(
        "acquire-expired",
        semantic_request(
            SessionConsumerOperation::AcquireLease {
                key: requested_key.clone(),
                owner: owner.clone(),
                ttl: Duration::from_secs(30),
            },
            22,
        ),
        SessionConsumerResponse::AcquireLease(Err(SessionConsumerLeaseError::Expired)),
    )
    .await;
    for (case, requested_ttl) in [
        ("acquire-shorter-ttl", Duration::from_secs(29)),
        ("acquire-longer-ttl", Duration::from_secs(31)),
    ] {
        let mut wrong_ttl = serde_json::to_value(&lease).expect("lease encodes");
        wrong_ttl["expires_at"] = serde_json::to_value(
            checked_session_deadline(lease.acquired_at(), requested_ttl).expect("fixture deadline"),
        )
        .expect("deadline encodes");
        let wrong_ttl = serde_json::from_value(wrong_ttl).expect("wrong-TTL lease decodes");
        assert_malicious_semantic_response_is_unconfirmed(
            case,
            semantic_request(
                SessionConsumerOperation::AcquireLease {
                    key: requested_key.clone(),
                    owner: owner.clone(),
                    ttl: Duration::from_secs(30),
                },
                24,
            ),
            SessionConsumerResponse::AcquireLease(Ok(SessionConsumerLeaseGrant::new(
                wrong_ttl,
                lease.acquired_at(),
            ))),
        )
        .await;
    }

    // These values decode successfully and are bound to the requested
    // acquire, so this proves the consumer reuses the wire-level guard
    // invariants instead of trusting authenticated peer data by shape alone.
    for (case, field, value) in [
        ("acquire-zero-fence", "fence", json!(0)),
        ("acquire-zero-credential", "credential_id", json!(0)),
        (
            "acquire-reversed-lifetime",
            "expires_at",
            json!("1970-01-01T00:00:00Z"),
        ),
    ] {
        let mut malformed = serde_json::to_value(&lease).expect("lease encodes");
        malformed[field] = value;
        let malformed = serde_json::from_value(malformed).expect("malformed lease decodes");
        assert_malicious_semantic_response_is_unconfirmed(
            case,
            semantic_request(
                SessionConsumerOperation::AcquireLease {
                    key: requested_key.clone(),
                    owner: owner.clone(),
                    ttl: Duration::from_secs(30),
                },
                40,
            ),
            SessionConsumerResponse::AcquireLease(Ok(SessionConsumerLeaseGrant::new(
                malformed,
                lease.acquired_at(),
            ))),
        )
        .await;
    }

    let mut forged_renewal = serde_json::to_value(&lease).expect("lease encodes");
    forged_renewal["key"] = serde_json::to_value(&wrong_key).expect("wrong key encodes");
    forged_renewal["owner"] = serde_json::to_value(&wrong_owner).expect("wrong owner encodes");
    forged_renewal["fence"] = json!(lease.fence().get() + 1);
    forged_renewal["credential_id"] = json!(lease.credential_id() + 1);
    let forged_renewal = serde_json::from_value(forged_renewal).expect("forged lease decodes");
    assert_malicious_semantic_response_is_unconfirmed(
        "renew-key-owner-fence-credential",
        semantic_request(
            SessionConsumerOperation::RenewLease {
                lease: lease.clone(),
                ttl: Duration::from_secs(30),
            },
            5,
        ),
        SessionConsumerResponse::RenewLease(Ok(SessionConsumerLeaseGrant::new(
            forged_renewal,
            lease.acquired_at(),
        ))),
    )
    .await;
    assert_malicious_semantic_response_is_unconfirmed(
        "renew-unchanged-lifetime",
        semantic_request(
            SessionConsumerOperation::RenewLease {
                lease: lease.clone(),
                ttl: Duration::from_secs(30),
            },
            25,
        ),
        SessionConsumerResponse::RenewLease(Ok(SessionConsumerLeaseGrant::new(
            lease.clone(),
            lease.acquired_at(),
        ))),
    )
    .await;
    assert_malicious_semantic_response_is_unconfirmed(
        "batch-get-invalid-ttl",
        semantic_request(
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get {
                    key: requested_key.clone(),
                }],
            },
            23,
        ),
        SessionConsumerResponse::Batch(Ok(vec![SessionConsumerBatchResult::Get(Err(
            opc_session_store::SessionConsumerStoreError::InvalidTtl,
        ))])),
    )
    .await;

    for (case, field, value) in [
        ("renew-zero-fence", "fence", json!(0)),
        ("renew-zero-credential", "credential_id", json!(0)),
        (
            "renew-reversed-lifetime",
            "expires_at",
            json!("1970-01-01T00:00:00Z"),
        ),
    ] {
        let mut malformed = serde_json::to_value(&lease).expect("lease encodes");
        malformed[field] = value;
        let malformed = serde_json::from_value(malformed).expect("malformed lease decodes");
        assert_malicious_semantic_response_is_unconfirmed(
            case,
            semantic_request(
                SessionConsumerOperation::RenewLease {
                    lease: lease.clone(),
                    ttl: Duration::from_secs(30),
                },
                50,
            ),
            SessionConsumerResponse::RenewLease(Ok(SessionConsumerLeaseGrant::new(
                malformed,
                lease.acquired_at(),
            ))),
        )
        .await;
    }

    assert_malicious_semantic_response_is_unconfirmed(
        "batch-empty",
        semantic_request(
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get {
                    key: requested_key.clone(),
                }],
            },
            6,
        ),
        SessionConsumerResponse::Batch(Ok(Vec::new())),
    )
    .await;
    assert_malicious_semantic_response_is_unconfirmed(
        "batch-read-ambiguity",
        semantic_request(
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get {
                    key: requested_key.clone(),
                }],
            },
            7,
        ),
        SessionConsumerResponse::Batch(Err(
            opc_session_store::SessionConsumerStoreError::OutcomeUnavailable,
        )),
    )
    .await;
    assert_malicious_semantic_response_is_unconfirmed(
        "batch-reordered",
        semantic_request(
            SessionConsumerOperation::Batch {
                ops: vec![
                    SessionOp::Get {
                        key: requested_key.clone(),
                    },
                    SessionOp::Get {
                        key: wrong_key.clone(),
                    },
                ],
            },
            8,
        ),
        SessionConsumerResponse::Batch(Ok(vec![
            SessionConsumerBatchResult::Get(Ok(Some(semantic_record(
                wrong_key.clone(),
                owner.clone(),
                FenceToken::new(1),
            )))),
            SessionConsumerBatchResult::Get(Ok(Some(semantic_record(
                requested_key.clone(),
                owner.clone(),
                FenceToken::new(1),
            )))),
        ])),
    )
    .await;
    assert_malicious_semantic_response_is_unconfirmed(
        "batch-wrong-variant",
        semantic_request(
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get {
                    key: requested_key.clone(),
                }],
            },
            9,
        ),
        SessionConsumerResponse::Batch(Ok(vec![SessionConsumerBatchResult::CompareAndSet(Ok(
            CompareAndSetResult::Success,
        ))])),
    )
    .await;
    assert_malicious_semantic_response_is_unconfirmed(
        "batch-wrong-key",
        semantic_request(
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get {
                    key: requested_key.clone(),
                }],
            },
            10,
        ),
        SessionConsumerResponse::Batch(Ok(vec![SessionConsumerBatchResult::Get(Ok(Some(
            semantic_record(wrong_key.clone(), owner.clone(), FenceToken::new(1)),
        )))])),
    )
    .await;

    let mut wrong_cursor_page =
        RestoreScanPage::new(Vec::new(), 1, Some(RestoreScanCursor::from_offset(1)));
    wrong_cursor_page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
    assert_malicious_semantic_response_is_unconfirmed(
        "restore-cursor",
        semantic_request(
            SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest::all(1),
            },
            11,
        ),
        SessionConsumerResponse::ScanRestoreRecords(Ok(wrong_cursor_page)),
    )
    .await;

    let mut wrong_scope = RestoreScanScope::all();
    wrong_scope.tenant = Some(TenantId::new("requested-tenant").expect("test tenant"));
    let mut wrong_scope_page = RestoreScanPage::new(
        vec![semantic_record(
            wrong_key.clone(),
            owner.clone(),
            FenceToken::new(1),
        )],
        0,
        None,
    );
    wrong_scope_page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
    assert_malicious_semantic_response_is_unconfirmed(
        "restore-scope",
        semantic_request(
            SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest {
                    scope: wrong_scope,
                    cursor: None,
                    limit: 1,
                },
            },
            12,
        ),
        SessionConsumerResponse::ScanRestoreRecords(Ok(wrong_scope_page)),
    )
    .await;

    let record = semantic_record(requested_key.clone(), owner.clone(), FenceToken::new(1));
    let mut duplicate_record_page = RestoreScanPage::new(vec![record.clone(), record], 0, None);
    duplicate_record_page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
    assert_malicious_semantic_response_is_unconfirmed(
        "restore-record",
        semantic_request(
            SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest::all(2),
            },
            13,
        ),
        SessionConsumerResponse::ScanRestoreRecords(Ok(duplicate_record_page)),
    )
    .await;

    let mut wrong_page = RestoreScanPage::new(Vec::new(), 0, None);
    wrong_page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
    wrong_page.loaded_count = 1;
    assert_malicious_semantic_response_is_unconfirmed(
        "restore-page",
        semantic_request(
            SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest::all(1),
            },
            14,
        ),
        SessionConsumerResponse::ScanRestoreRecords(Ok(wrong_page)),
    )
    .await;
}

#[tokio::test]
async fn local_persistent_validation_failures_are_typed_and_counted_once_before_io() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("local-validation-server");
    let client_spiffe = spiffe("local-validation-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unused listener");
    let client = persistent_client(
        &pki,
        listener.local_addr().expect("listener address"),
        &server_spiffe,
        &client_spiffe,
        scope(2),
    );

    let wrong_scope = semantic_request(SessionConsumerOperation::Capabilities, 60);
    assert!(matches!(
        client.execute(&wrong_scope).await,
        Err(PersistentSessionConsumerExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Scope
        })
    ));

    let watch = SessionConsumerRequest::new(
        scope(2),
        SessionConsumerRequestId::from_bytes([61; 16]),
        SessionConsumerOperation::Watch { start_sequence: 0 },
    );
    assert!(matches!(
        client.execute(&watch).await,
        Err(PersistentSessionConsumerExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Protocol
        })
    ));

    let malformed = semantic_request(
        SessionConsumerOperation::Batch {
            ops: vec![
                SessionOp::Get {
                    key: semantic_key(b"local-oversized-batch"),
                };
                257
            ],
        },
        62,
    );
    let malformed = SessionConsumerRequest::new(
        scope(2),
        malformed.request_id(),
        malformed.operation().clone(),
    );
    assert!(matches!(
        client.execute(&malformed).await,
        Err(PersistentSessionConsumerExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Protocol
        })
    ));

    let invalid_ttl = MAX_SESSION_TTL + Duration::from_nanos(1);
    let key = semantic_key(b"local-invalid-single-ttl");
    let owner = OwnerId::new("local-invalid-single-ttl-owner").expect("test owner");
    let lease = FakeSessionBackend::new()
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .expect("fixture lease");
    for (request_byte, operation) in [
        (
            63,
            SessionConsumerOperation::RefreshTtl {
                lease: lease.clone(),
                ttl: invalid_ttl,
            },
        ),
        (
            64,
            SessionConsumerOperation::AcquireLease {
                key: key.clone(),
                owner,
                ttl: invalid_ttl,
            },
        ),
        (
            65,
            SessionConsumerOperation::RenewLease {
                lease,
                ttl: invalid_ttl,
            },
        ),
    ] {
        let malformed_ttl = SessionConsumerRequest::new(
            scope(2),
            SessionConsumerRequestId::from_bytes([request_byte; 16]),
            operation,
        );
        assert!(matches!(
            client.execute(&malformed_ttl).await,
            Err(PersistentSessionConsumerExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol
            })
        ));
    }

    let diagnostics = client.diagnostics().await;
    assert_eq!(
        diagnostics.setup_attempts, 0,
        "local failures never connect"
    );
    assert_eq!(diagnostics.failures, 6);
    assert_eq!(diagnostics.scope, 1);
    assert_eq!(diagnostics.protocol, 5);
    assert_eq!(diagnostics.not_transmitted, 6);
    assert_eq!(diagnostics.outcome_unknown, 0);
    client.shutdown().await;
}

#[tokio::test]
async fn authenticated_cas_outcome_unavailable_is_typed_unknown_without_poisoning_the_lane() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("cas-outcome-unavailable-server");
    let client_spiffe = spiffe("cas-outcome-unavailable-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind malicious listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let server = tokio::spawn(async move {
        let (mut tls, first) =
            accept_hello_and_call(&listener, &authenticated, &expected_client).await;
        assert_eq!(
            first["body"]["request"]["operation"]["operation"],
            "compare_and_set"
        );
        let response = json!({
            "kind": "response",
            "body": {
                "correlation": first["body"]["correlation"].clone(),
                "response": serde_json::to_value(SessionConsumerResponse::CompareAndSet(Err(
                    opc_session_store::SessionConsumerStoreError::OutcomeUnavailable,
                )))
                .expect("CAS ambiguity response encodes"),
            },
        });
        write_value(&mut tls, &response).await;
        let second = read_value(&mut tls).await;
        assert_eq!(
            second["body"]["request"]["operation"]["operation"], "capabilities",
            "a typed CAS ambiguity does not poison a valid authenticated lane"
        );
        write_value(
            &mut tls,
            &capability_response(second["body"]["correlation"].clone()),
        )
        .await;
    });
    let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
    let backend = FakeSessionBackend::new();
    let key = semantic_key(b"cas-outcome-unavailable-key");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("cas-outcome-unavailable-owner").expect("test owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("test lease");
    let request_id = SessionConsumerRequestId::new();
    let op = CompareAndSet {
        key,
        lease,
        expected_generation: None,
        new_record: semantic_record(
            semantic_key(b"cas-outcome-unavailable-key"),
            OwnerId::new("cas-outcome-unavailable-owner").expect("test owner"),
            FenceToken::new(1),
        ),
    };

    assert!(matches!(
        client.compare_and_set_with_id(request_id, &op).await,
        Err(SessionConsumerMutationError::OutcomeUnknown { request_id: returned })
            if returned == request_id
    ));
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, 1);
    assert_eq!(diagnostics.reconnects, 0);
    assert_eq!(diagnostics.successes, 1);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.outcome_unknown, 1);
    client.shutdown().await;
    server.await.expect("malicious server");
}

#[tokio::test]
async fn batch_ambiguity_and_all_read_unavailability_use_one_canonical_outcome_rule() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("batch-outcome-rule-server");
    let client_spiffe = spiffe("batch-outcome-rule-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind batch outcome listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let server = tokio::spawn(async move {
        let (mut tls, mutation) =
            accept_hello_and_call(&listener, &authenticated, &expected_client).await;
        assert_eq!(
            mutation["body"]["request"]["operation"]["operation"],
            "batch"
        );
        write_value(
            &mut tls,
            &json!({
                "kind": "response",
                "body": {
                    "correlation": mutation["body"]["correlation"].clone(),
                    "response": serde_json::to_value(SessionConsumerResponse::Batch(Ok(vec![
                        SessionConsumerBatchResult::CompareAndSet(Err(
                            SessionConsumerStoreError::OutcomeUnavailable,
                        )),
                    ])))
                    .expect("nested ambiguity encodes"),
                },
            }),
        )
        .await;

        let read = read_value(&mut tls).await;
        assert_eq!(read["body"]["correlation"], json!(2));
        write_value(
            &mut tls,
            &json!({
                "kind": "response",
                "body": {
                    "correlation": read["body"]["correlation"].clone(),
                    "response": serde_json::to_value(SessionConsumerResponse::Batch(Err(
                        SessionConsumerStoreError::Unavailable,
                    )))
                    .expect("all-read unavailability encodes"),
                },
            }),
        )
        .await;

        let capability = read_value(&mut tls).await;
        assert_eq!(capability["body"]["correlation"], json!(3));
        write_value(
            &mut tls,
            &capability_response(capability["body"]["correlation"].clone()),
        )
        .await;
    });

    let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
    let key = semantic_key(b"batch-outcome-rule-key");
    let owner = OwnerId::new("batch-outcome-rule-owner").expect("test owner");
    let lease = FakeSessionBackend::new()
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .expect("fixture lease");
    let mutation_id = SessionConsumerRequestId::new();
    let mutation = SessionOp::CompareAndSet(CompareAndSet {
        key: key.clone(),
        lease,
        expected_generation: None,
        new_record: semantic_record(key.clone(), owner, FenceToken::new(1)),
    });
    assert!(matches!(
        client.batch_with_id(mutation_id, &[mutation]).await,
        Err(SessionConsumerMutationError::OutcomeUnknown { request_id })
            if request_id == mutation_id
    ));

    let read_id = SessionConsumerRequestId::new();
    assert!(matches!(
        client
            .batch_with_id(read_id, &[SessionOp::Get { key }])
            .await,
        Err(SessionConsumerMutationError::Store(
            StoreError::BackendUnavailable(_)
        ))
    ));
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled()),
        "both canonical typed outcomes leave the authenticated lane reusable"
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, 1);
    assert_eq!(diagnostics.reconnects, 0);
    assert_eq!(diagnostics.successes, 1);
    assert_eq!(diagnostics.failures, 2);
    assert_eq!(diagnostics.outcome_unknown, 1);
    client.shutdown().await;
    server.await.expect("batch outcome server");
}

#[tokio::test]
async fn authenticated_outer_lease_unknown_is_counted_as_a_failure_not_a_success() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("outer-outcome-unknown-server");
    let client_spiffe = spiffe("outer-outcome-unknown-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind malicious listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let request_id = SessionConsumerRequestId::new();
    let request = mutation_request(scope(1), request_id);
    let server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&listener, &authenticated, &expected_client).await;
        write_value(
            &mut tls,
            &json!({
                "kind": "response",
                "body": {
                    "correlation": call["body"]["correlation"].clone(),
                    "response": serde_json::to_value(SessionConsumerResponse::OutcomeUnknown(
                        opc_session_store::SessionConsumerOutcomeUnknown::Lease,
                    ))
                    .expect("outcome-unknown response encodes"),
                },
            }),
        )
        .await;
    });
    let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));

    assert_eq!(
        client.execute(&request).await,
        Ok(SessionConsumerResponse::OutcomeUnknown(
            opc_session_store::SessionConsumerOutcomeUnknown::Lease,
        )),
        "the complete typed response remains available for exact caller recovery"
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.successes, 0);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.outcome_unknown, 1);
    assert_eq!(diagnostics.not_transmitted, 0);
    client.shutdown().await;
    server.await.expect("malicious server");
}

#[tokio::test]
async fn cancelled_initial_watch_accounts_the_exact_call_write_boundary_once() {
    // Cancellation while resolve is pending is proven locally
    // NotTransmitted and terminalizes both setup and outcome accounting.
    let pki = TestPki::new();
    let resolve_started = Arc::new(Notify::new());
    let resolver: RemoteAddrResolver = {
        let resolve_started = Arc::clone(&resolve_started);
        Arc::new(move || {
            let resolve_started = Arc::clone(&resolve_started);
            Box::pin(async move {
                resolve_started.notify_one();
                std::future::pending::<std::io::Result<SocketAddr>>().await
            })
        })
    };
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(
            "127.0.0.1"
                .parse::<std::net::IpAddr>()
                .expect("loopback IP")
                .into(),
        ),
        SpiffeId::new(spiffe("watch-cancel-before-server")).expect("server SPIFFE"),
        scope(1),
        pki.client_config(&spiffe("watch-cancel-before-client")),
    )
    .with_operation_timeout(Duration::from_secs(1));
    let before = PersistentSessionConsumerClient::from_stateless(stateless);
    let before_task = {
        let before = before.clone();
        tokio::spawn(async move { before.open_watch(0).await })
    };
    resolve_started.notified().await;
    before_task.abort();
    assert!(before_task.await.is_err(), "caller cancellation wins");
    let diagnostics = before.diagnostics().await;
    assert_eq!(diagnostics.setup_attempts, 1);
    assert_eq!(diagnostics.setup_successes, 0);
    assert_eq!(diagnostics.setup_failures, 1);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.not_transmitted, 1);
    assert_eq!(diagnostics.outcome_unknown, 0);
    assert_eq!(diagnostics.watch_active, 0);
    before.shutdown().await;

    // Cancellation after the authenticated Watch Call was completely read by
    // the peer is never advertised as NotTransmitted. Watch is read-only, so
    // it also never creates mutation-style outcome uncertainty.
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-cancel-after-server");
    let client_spiffe = spiffe("watch-cancel-after-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind watch cancellation listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let call_received = Arc::new(Notify::new());
    let server = {
        let call_received = Arc::clone(&call_received);
        tokio::spawn(async move {
            let (mut tls, call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            assert_eq!(call["body"]["request"]["operation"]["operation"], "watch");
            call_received.notify_one();
            let mut byte = [0_u8; 1];
            match tls.read(&mut byte).await {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                result => panic!("cancelled setup must close the authenticated lane: {result:?}"),
            }
        })
    };
    let after = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
    let after_task = {
        let after = after.clone();
        tokio::spawn(async move { after.open_watch(0).await })
    };
    call_received.notified().await;
    after_task.abort();
    assert!(after_task.await.is_err(), "caller cancellation wins");
    server.await.expect("watch cancellation server");
    let diagnostics = after.diagnostics().await;
    assert_eq!(diagnostics.setup_attempts, 1);
    assert_eq!(diagnostics.setup_successes, 0);
    assert_eq!(diagnostics.setup_failures, 1);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.not_transmitted, 0);
    assert_eq!(diagnostics.outcome_unknown, 0);
    assert_eq!(diagnostics.watch_active, 0);
    after.shutdown().await;
}

#[tokio::test]
async fn pending_request_setup_separates_logical_inflight_from_physical_active() {
    let pki = TestPki::new();
    let resolve_started = Arc::new(Notify::new());
    let resolver: RemoteAddrResolver = {
        let resolve_started = Arc::clone(&resolve_started);
        Arc::new(move || {
            let resolve_started = Arc::clone(&resolve_started);
            Box::pin(async move {
                resolve_started.notify_one();
                std::future::pending::<std::io::Result<SocketAddr>>().await
            })
        })
    };
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(
            "127.0.0.1"
                .parse::<std::net::IpAddr>()
                .expect("loopback IP")
                .into(),
        ),
        SpiffeId::new(spiffe("physical-active-server")).expect("server SPIFFE"),
        scope(1),
        pki.client_config(&spiffe("physical-active-client")),
    )
    .with_operation_timeout(Duration::from_secs(1));
    let client = PersistentSessionConsumerClient::from_stateless(stateless);
    let request = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    resolve_started.notified().await;

    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.inflight, 1, "one logical call is admitted");
    assert_eq!(
        diagnostics.active, 0,
        "DNS setup has not published an authenticated physical lane"
    );
    assert_eq!(diagnostics.max_active, 0);
    assert_eq!(diagnostics.setup_attempts, 1);
    assert_eq!(diagnostics.setup_successes, 0);
    assert_eq!(diagnostics.setup_failures, 0);

    request.abort();
    assert!(request.await.is_err(), "caller cancellation wins");
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.inflight, 0);
    assert_eq!(diagnostics.active, 0);
    assert_eq!(diagnostics.setup_attempts, 1);
    assert_eq!(diagnostics.setup_successes, 0);
    assert_eq!(diagnostics.setup_failures, 1);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.not_transmitted, 1);
    client.shutdown().await;
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
async fn partial_read_only_unary_response_expires_at_the_authenticated_idle_bound() {
    for boundary in ["prefix", "payload"] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("partial-unary-{boundary}-server"));
        let client_spiffe = spiffe(&format!("partial-unary-{boundary}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let (mut tls, _) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            write_partial_frame(&mut tls, boundary).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        });
        let client = persistent_client_with_short_active_frame_idle(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            scope(1),
        );
        assert_eq!(
            tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, client.capabilities())
                .await
                .expect("partial unary response obeys the authenticated idle bound"),
            Err(SessionConsumerClientError::Deadline)
        );
        client.shutdown().await;
        server.await.expect("malicious server");
    }
}

#[tokio::test]
async fn partial_mutation_unary_response_is_unknown_once_without_auto_replay() {
    for boundary in ["prefix", "payload"] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("partial-mutation-{boundary}-server"));
        let client_spiffe = spiffe(&format!("partial-mutation-{boundary}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let request_id =
            SessionConsumerRequestId::from_bytes([if boundary == "prefix" { 1 } else { 2 }; 16]);
        let request = mutation_request(scope(1), request_id);
        let expected_request = serde_json::to_value(&request).expect("mutation request encodes");
        let (replay_checked, replay_check_complete) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut tls, call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            assert!(
                call["body"]["request"] == expected_request,
                "the authenticated mutation preserves its exact durable request body"
            );
            write_partial_frame(&mut tls, boundary).await;
            tokio::time::sleep(Duration::from_millis(125)).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(200), listener.accept())
                    .await
                    .is_err(),
                "a partial post-call response must not trigger automatic mutation replay"
            );
            replay_checked
                .send(())
                .expect("test client waits until no automatic replay is proven");
            let (mut recovery, recovery_call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            assert_eq!(
                recovery_call["body"]["request"]["operation"]["operation"], "capabilities",
                "the next caller reaches a newly established lane"
            );
            write_value(
                &mut recovery,
                &capability_response(recovery_call["body"]["correlation"].clone()),
            )
            .await;
        });
        let client = persistent_client_with_short_active_frame_idle(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            scope(1),
        );
        let error = tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, client.execute(&request))
            .await
            .expect("partial mutation response obeys the authenticated idle bound")
            .expect_err("post-call partial response leaves the durable mutation outcome unknown");
        assert!(matches!(
            error,
            PersistentSessionConsumerExecuteError::OutcomeUnknown { request_id: retry_id }
                if retry_id == request_id
        ));
        replay_check_complete
            .await
            .expect("malicious peer proves there was no automatic replay");
        assert_eq!(
            client.capabilities().await,
            Ok(BackendCapabilities::all_enabled()),
            "the next caller uses a replacement lane after outcome-unknown eviction"
        );
        let diagnostics = client.diagnostics().await;
        assert_eq!(diagnostics.outcome_unknown, 1);
        assert_eq!(diagnostics.setup_successes, 2);
        assert_eq!(diagnostics.reconnects, 1);
        client.shutdown().await;
        server.await.expect("malicious server");
    }
}

#[tokio::test]
async fn partial_initial_watch_open_response_releases_the_isolated_admission() {
    for boundary in ["prefix", "payload"] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("partial-watch-open-{boundary}-server"));
        let client_spiffe = spiffe(&format!("partial-watch-open-{boundary}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let (mut tls, call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            assert_eq!(
                call["body"]["request"]["operation"]["operation"], "watch",
                "initial request is the public Watch operation"
            );
            write_partial_frame(&mut tls, boundary).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(tls);
            let (mut replacement, replacement_call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            assert_eq!(
                replacement_call["body"]["request"]["operation"]["operation"], "watch",
                "replacement request is the public Watch operation"
            );
            write_value(
                &mut replacement,
                &watch_opened_response(replacement_call["body"]["correlation"].clone()),
            )
            .await;
        });
        let client = persistent_client_with_short_active_frame_idle(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            scope(1),
        );
        let result = tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, client.open_watch(0))
            .await
            .expect("partial WatchOpened response obeys the authenticated idle bound");
        assert!(matches!(result, Err(SessionConsumerClientError::Deadline)));
        tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, async {
            while client.diagnostics().await.watch_active != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("initial watch-open failure releases its isolated physical admission");
        let diagnostics = client.diagnostics().await;
        assert_eq!(diagnostics.setup_failures, 1);
        assert_eq!(diagnostics.failures, 1);
        assert_eq!(diagnostics.deadline, 1);
        assert_eq!(diagnostics.not_transmitted, 0);
        assert_eq!(diagnostics.outcome_unknown, 0);
        let replacement = tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, client.open_watch(0))
            .await
            .expect("released watch admission establishes a fresh authenticated watch")
            .expect("released watch admission accepts the replacement watch");
        drop(replacement);
        client.shutdown().await;
        server.await.expect("malicious server");
    }
}

#[tokio::test]
async fn correlated_watch_rejections_preserve_their_typed_setup_classification() {
    for (name, rejection, expected) in [
        (
            "unavailable",
            SessionConsumerRejection::Unavailable,
            SessionConsumerClientError::Unavailable,
        ),
        (
            "scope",
            SessionConsumerRejection::ScopeMismatch,
            SessionConsumerClientError::Scope,
        ),
        (
            "authorization",
            SessionConsumerRejection::Unauthorized,
            SessionConsumerClientError::Authentication,
        ),
        (
            "malformed",
            SessionConsumerRejection::MalformedRequest,
            SessionConsumerClientError::Protocol,
        ),
    ] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("watch-rejection-{name}-server"));
        let client_spiffe = spiffe(&format!("watch-rejection-{name}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind rejecting listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let (mut tls, call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            assert_eq!(
                call["body"]["request"]["operation"]["operation"], "watch",
                "rejection follows the public Watch operation"
            );
            write_value(
                &mut tls,
                &rejected_response(call["body"]["correlation"].clone(), rejection),
            )
            .await;
        });
        let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));

        let result = client.open_watch(0).await;
        assert!(matches!(result, Err(error) if error == expected));
        let diagnostics = client.diagnostics().await;
        assert_eq!(diagnostics.setup_attempts, 1);
        assert_eq!(diagnostics.setup_failures, 1);
        assert_eq!(diagnostics.failures, 1);
        assert_eq!(diagnostics.watch_active, 0);
        assert_eq!(diagnostics.not_transmitted, 0);
        assert_eq!(diagnostics.outcome_unknown, 0);
        if rejection == SessionConsumerRejection::Unavailable {
            assert_eq!(
                diagnostics.protocol, 0,
                "ordinary server unavailability is not wire corruption"
            );
        }

        client.shutdown().await;
        server.await.expect("rejecting server");
    }
}

#[tokio::test]
async fn partial_active_watch_frames_expire_and_release_the_isolated_slot() {
    for boundary in ["prefix", "payload"] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("partial-watch-{boundary}-server"));
        let client_spiffe = spiffe(&format!("partial-watch-{boundary}-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let (mut tls, call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            write_value(
                &mut tls,
                &watch_opened_response(call["body"]["correlation"].clone()),
            )
            .await;
            write_partial_frame(&mut tls, boundary).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        });
        let client = persistent_client_with_short_active_frame_idle(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            scope(1),
        );
        let mut watch = client.open_watch(0).await.expect("WatchOpened is admitted");
        let item = tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, watch.next())
            .await
            .expect("a partial active frame obeys the configured idle bound")
            .expect("reader reports the authenticated transport failure");
        assert!(item.is_err(), "partial frame never becomes a watch entry");
        tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, async {
            while client.diagnostics().await.watch_active != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed-out reader releases its isolated watch slot");
        drop(watch);
        client.shutdown().await;
        server.await.expect("malicious server");
    }
}

#[tokio::test]
#[allow(deprecated)] // Test-only SO_LINGER(0) is the deterministic TCP-reset adversary.
async fn partial_watch_fin_and_reset_are_terminal_on_active_and_replacement_lanes() {
    for boundary in ["prefix", "payload"] {
        for loss in ["fin", "reset"] {
            let pki = TestPki::new();
            let server_spiffe = spiffe(&format!("partial-{boundary}-{loss}-active-server"));
            let client_spiffe = spiffe(&format!("partial-{boundary}-{loss}-active-client"));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind active truncation listener");
            let address = listener.local_addr().expect("listener address");
            let authenticated = pki.server_config(&server_spiffe);
            let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
            let server = tokio::spawn(async move {
                let (mut tls, call) =
                    accept_hello_and_call(&listener, &authenticated, &expected_client).await;
                write_value(
                    &mut tls,
                    &watch_opened_response(call["body"]["correlation"].clone()),
                )
                .await;
                write_partial_frame(&mut tls, boundary).await;
                if loss == "reset" {
                    tls.get_ref()
                        .0
                        .set_linger(Some(Duration::ZERO))
                        .expect("force TCP reset after authenticated truncation");
                }
                drop(tls);
                assert!(
                    tokio::time::timeout(Duration::from_millis(150), listener.accept())
                        .await
                        .is_err(),
                    "a partial authenticated frame never opens a replacement Watch"
                );
            });
            let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
            let mut watch = client.open_watch(0).await.expect("WatchOpened is admitted");
            assert!(
                tokio::time::timeout(Duration::from_millis(500), watch.next())
                    .await
                    .expect("partial loss terminates promptly")
                    .expect("partial loss emits one terminal result")
                    .is_err(),
                "truncation never becomes a valid watch entry"
            );
            assert!(
                watch.next().await.is_none(),
                "terminal result is emitted once"
            );
            assert_eq!(client.diagnostics().await.reconnects, 0);
            client.shutdown().await;
            server.await.expect("active truncation server");

            let pki = TestPki::new();
            let server_spiffe = spiffe(&format!("partial-{boundary}-{loss}-replacement-server"));
            let client_spiffe = spiffe(&format!("partial-{boundary}-{loss}-replacement-client"));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind replacement truncation listener");
            let address = listener.local_addr().expect("listener address");
            let authenticated = pki.server_config(&server_spiffe);
            let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
            let server = tokio::spawn(async move {
                let (mut first_tls, first) =
                    accept_hello_and_call(&listener, &authenticated, &expected_client).await;
                let first_correlation = first["body"]["correlation"].clone();
                write_value(
                    &mut first_tls,
                    &watch_opened_response(first_correlation.clone()),
                )
                .await;
                write_value(&mut first_tls, &watch_entry_response(first_correlation, 1)).await;
                drop(first_tls);

                let (mut replacement_tls, replacement) =
                    accept_hello_and_call(&listener, &authenticated, &expected_client).await;
                assert_eq!(
                    replacement["body"]["request"]["operation"]["start_sequence"],
                    json!(2),
                    "replacement starts after the one caller-visible queued item"
                );
                write_value(
                    &mut replacement_tls,
                    &watch_opened_response(replacement["body"]["correlation"].clone()),
                )
                .await;
                write_partial_frame(&mut replacement_tls, boundary).await;
                if loss == "reset" {
                    replacement_tls
                        .get_ref()
                        .0
                        .set_linger(Some(Duration::ZERO))
                        .expect("force replacement TCP reset after truncation");
                }
                drop(replacement_tls);
                assert!(
                    tokio::time::timeout(Duration::from_millis(150), listener.accept())
                        .await
                        .is_err(),
                    "a truncated replacement cannot begin a third Watch"
                );
            });
            let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));
            let mut watch = client.open_watch(1).await.expect("initial WatchOpened");
            assert_eq!(
                watch
                    .next()
                    .await
                    .expect("first queued item")
                    .expect("valid first item")
                    .sequence(),
                1
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(500), watch.next())
                    .await
                    .expect("replacement truncation terminates promptly")
                    .expect("replacement truncation emits one terminal result")
                    .is_err()
            );
            assert!(
                watch.next().await.is_none(),
                "terminal result is emitted once"
            );
            assert_eq!(
                client.diagnostics().await.reconnects,
                1,
                "only the clean inter-frame loss opens a replacement"
            );
            client.shutdown().await;
            server.await.expect("replacement truncation server");
        }
    }
}

#[tokio::test]
async fn quiet_authenticated_watch_remains_admitted_until_the_peer_closes() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("quiet-watch-server");
    let client_spiffe = spiffe("quiet-watch-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind malicious listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let (quiet_started, quiet_observed) = tokio::sync::oneshot::channel();
    let (allow_close, close_allowed) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&listener, &authenticated, &expected_client).await;
        assert_eq!(
            call["body"]["request"]["operation"]["operation"], "watch",
            "quiet connection is the public Watch operation"
        );
        write_value(
            &mut tls,
            &watch_opened_response(call["body"]["correlation"].clone()),
        )
        .await;
        quiet_started
            .send(())
            .expect("test client waits for the quiet watch");
        close_allowed
            .await
            .expect("test client releases the synchronized quiet peer");
        drop(tls);
    });
    let client = persistent_client_with_short_active_frame_idle(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        scope(1),
    );
    let mut watch = client.open_watch(0).await.expect("WatchOpened is admitted");
    quiet_observed
        .await
        .expect("malicious peer confirms the quiet interval");
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(
        client.diagnostics().await.watch_active,
        1,
        "a quiet authenticated watch remains admitted past three active-frame idle periods"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), watch.next())
            .await
            .is_err(),
        "a quiet watch stays pending rather than fabricating a terminal item"
    );
    allow_close
        .send(())
        .expect("quiet peer remains live until the assertion completes");
    let terminal = tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, watch.next())
        .await
        .expect("peer close terminates the quiet watch within a bounded wait");
    assert!(
        matches!(terminal, None | Some(Err(_))),
        "peer close never manufactures a watch entry"
    );
    tokio::time::timeout(SHORT_ACTIVE_FRAME_WAIT, async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer close releases the isolated quiet-watch admission");
    drop(watch);
    client.shutdown().await;
    server.await.expect("malicious server");
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
    let diagnostics = client.diagnostics().await;
    assert_eq!(
        diagnostics.setup_successes, 2,
        "the poisoned lane is replaced exactly once for the next caller"
    );
    assert_eq!(
        diagnostics.reconnects, 1,
        "one protocol poison records one reconnect, not an implicit retry loop"
    );
    server.await.expect("malicious server");
}

#[tokio::test]
async fn scope_rejection_retires_the_lane_and_resolves_a_fresh_authority() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("scope-transition-server");
    let client_spiffe = spiffe("scope-transition-client");
    let first_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stale-authority listener");
    let first_address = first_listener
        .local_addr()
        .expect("stale authority address");
    let second_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fresh-authority listener");
    let second_address = second_listener
        .local_addr()
        .expect("fresh authority address");
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let first_authenticated = pki.server_config(&server_spiffe);
    let second_authenticated = pki.server_config(&server_spiffe);
    let first_client = expected_client.clone();
    let first_server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&first_listener, &first_authenticated, &first_client).await;
        write_value(
            &mut tls,
            &rejected_response(
                call["body"]["correlation"].clone(),
                SessionConsumerRejection::ScopeMismatch,
            ),
        )
        .await;
        match tokio::time::timeout(Duration::from_millis(150), tls.read_u8()).await {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(_)) => {
                panic!("a scope rejection retires the lane instead of sending another call")
            }
        }
    });
    let second_server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&second_listener, &second_authenticated, &expected_client).await;
        assert_eq!(
            call["body"]["request"]["operation"]["operation"], "capabilities",
            "the caller, not the pool, makes the later fresh-authority request"
        );
        write_value(
            &mut tls,
            &capability_response(call["body"]["correlation"].clone()),
        )
        .await;
    });
    let resolver_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = Arc::clone(&resolver_calls);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        let address = if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            first_address
        } else {
            second_address
        };
        Box::pin(async move { Ok(address) })
    });
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope(1),
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1));
    let client = PersistentSessionConsumerClient::try_from_stateless(
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
    .expect("persistent client");

    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Scope),
        "the first typed authority rejection remains visible to the caller"
    );
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled()),
        "the later caller resolves and authenticates a replacement authority"
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, 2);
    assert_eq!(diagnostics.reconnects, 1);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.scope, 1);
    assert_eq!(diagnostics.successes, 1);
    assert_eq!(diagnostics.not_transmitted, 0);
    assert_eq!(diagnostics.outcome_unknown, 0);
    assert_eq!(resolver_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    client.shutdown().await;
    first_server.await.expect("stale-authority server");
    second_server.await.expect("fresh-authority server");
}

#[tokio::test]
async fn authenticated_unavailable_rejection_is_typed_counted_and_reuses_a_healthy_lane() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("unavailable-rejection-server");
    let client_spiffe = spiffe("unavailable-rejection-client");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind malicious listener");
    let address = listener.local_addr().expect("listener address");
    let authenticated = pki.server_config(&server_spiffe);
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let server = tokio::spawn(async move {
        let (mut tls, first) =
            accept_hello_and_call(&listener, &authenticated, &expected_client).await;
        write_value(
            &mut tls,
            &rejected_response(
                first["body"]["correlation"].clone(),
                SessionConsumerRejection::Unavailable,
            ),
        )
        .await;
        let second = read_value(&mut tls).await;
        assert_eq!(
            second["body"]["request"]["operation"]["operation"], "capabilities",
            "unavailable is request-local and retains the authenticated lane"
        );
        write_value(
            &mut tls,
            &capability_response(second["body"]["correlation"].clone()),
        )
        .await;
    });
    let client = persistent_client(&pki, address, &server_spiffe, &client_spiffe, scope(1));

    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Unavailable)
    );
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, 1);
    assert_eq!(diagnostics.reconnects, 0);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.successes, 1);
    assert_eq!(diagnostics.not_transmitted, 0);
    assert_eq!(diagnostics.outcome_unknown, 0);
    assert_eq!(diagnostics.deadline, 0);
    client.shutdown().await;
    server.await.expect("malicious server");
}

#[tokio::test]
async fn malformed_rejection_retires_the_lane_before_the_next_request() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("malformed-transition-server");
    let client_spiffe = spiffe("malformed-transition-client");
    let first_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind rejecting listener");
    let first_address = first_listener.local_addr().expect("first listener address");
    let second_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind replacement listener");
    let second_address = second_listener
        .local_addr()
        .expect("second listener address");
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let first_authenticated = pki.server_config(&server_spiffe);
    let second_authenticated = pki.server_config(&server_spiffe);
    let first_client = expected_client.clone();
    let first_server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&first_listener, &first_authenticated, &first_client).await;
        write_value(
            &mut tls,
            &rejected_response(
                call["body"]["correlation"].clone(),
                SessionConsumerRejection::MalformedRequest,
            ),
        )
        .await;
        match tokio::time::timeout(Duration::from_millis(150), tls.read_u8()).await {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("a malformed rejection must retire the poisoned lane"),
        }
    });
    let second_server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&second_listener, &second_authenticated, &expected_client).await;
        write_value(
            &mut tls,
            &capability_response(call["body"]["correlation"].clone()),
        )
        .await;
    });
    let resolver_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = Arc::clone(&resolver_calls);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        let address = if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            first_address
        } else {
            second_address
        };
        Box::pin(async move { Ok(address) })
    });
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope(1),
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1));
    let client = PersistentSessionConsumerClient::try_from_stateless(
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
        .expect("persistent test configuration"),
    )
    .expect("persistent client");

    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Protocol)
    );
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, 2);
    assert_eq!(diagnostics.reconnects, 1);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.protocol, 1);
    assert_eq!(diagnostics.successes, 1);
    assert_eq!(diagnostics.not_transmitted, 0);
    assert_eq!(diagnostics.outcome_unknown, 0);
    assert_eq!(resolver_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    client.shutdown().await;
    first_server.await.expect("rejecting server");
    second_server.await.expect("replacement server");
}

#[tokio::test]
async fn unauthorized_rejection_retires_the_lane_and_resolves_a_fresh_authority() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("unauthorized-transition-server");
    let client_spiffe = spiffe("unauthorized-transition-client");
    let first_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stale-authority listener");
    let first_address = first_listener
        .local_addr()
        .expect("stale authority address");
    let second_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fresh-authority listener");
    let second_address = second_listener
        .local_addr()
        .expect("fresh authority address");
    let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
    let first_authenticated = pki.server_config(&server_spiffe);
    let second_authenticated = pki.server_config(&server_spiffe);
    let first_client = expected_client.clone();
    let first_server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&first_listener, &first_authenticated, &first_client).await;
        write_value(
            &mut tls,
            &rejected_response(
                call["body"]["correlation"].clone(),
                SessionConsumerRejection::Unauthorized,
            ),
        )
        .await;
        match tokio::time::timeout(Duration::from_millis(150), tls.read_u8()).await {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("an unauthorized rejection retires the stale authority lane"),
        }
    });
    let second_server = tokio::spawn(async move {
        let (mut tls, call) =
            accept_hello_and_call(&second_listener, &second_authenticated, &expected_client).await;
        write_value(
            &mut tls,
            &capability_response(call["body"]["correlation"].clone()),
        )
        .await;
    });
    let resolver_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = Arc::clone(&resolver_calls);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        let address = if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            first_address
        } else {
            second_address
        };
        Box::pin(async move { Ok(address) })
    });
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope(1),
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1));
    let client = PersistentSessionConsumerClient::try_from_stateless(
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
    .expect("persistent client");

    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Authentication)
    );
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, 2);
    assert_eq!(diagnostics.reconnects, 1);
    assert_eq!(diagnostics.failures, 1);
    assert_eq!(diagnostics.authentication, 1);
    assert_eq!(diagnostics.successes, 1);
    assert_eq!(diagnostics.not_transmitted, 0);
    assert_eq!(diagnostics.outcome_unknown, 0);
    assert_eq!(resolver_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    client.shutdown().await;
    first_server.await.expect("stale-authority server");
    second_server.await.expect("fresh-authority server");
}

#[tokio::test]
async fn stateless_capabilities_classifies_every_authenticated_rejection() {
    for (case, rejection, expected) in [
        (
            "scope",
            SessionConsumerRejection::ScopeMismatch,
            SessionConsumerClientError::Scope,
        ),
        (
            "unauthorized",
            SessionConsumerRejection::Unauthorized,
            SessionConsumerClientError::Authentication,
        ),
        (
            "unavailable",
            SessionConsumerRejection::Unavailable,
            SessionConsumerClientError::Unavailable,
        ),
        (
            "malformed",
            SessionConsumerRejection::MalformedRequest,
            SessionConsumerClientError::Protocol,
        ),
    ] {
        let pki = TestPki::new();
        let server_spiffe = spiffe(&format!("stateless-{case}-rejection-server"));
        let client_spiffe = spiffe(&format!("stateless-{case}-rejection-client"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious listener");
        let address = listener.local_addr().expect("listener address");
        let authenticated = pki.server_config(&server_spiffe);
        let expected_client = SpiffeId::new(&client_spiffe).expect("client SPIFFE");
        let server = tokio::spawn(async move {
            let (mut tls, call) =
                accept_hello_and_call(&listener, &authenticated, &expected_client).await;
            write_value(
                &mut tls,
                &rejected_response(call["body"]["correlation"].clone(), rejection),
            )
            .await;
        });
        let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let client = StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
            scope(1),
            pki.client_config(&client_spiffe),
        )
        .with_operation_timeout(Duration::from_secs(1));

        assert_eq!(client.capabilities().await, Err(expected));
        server.await.expect("malicious server");
    }
}
