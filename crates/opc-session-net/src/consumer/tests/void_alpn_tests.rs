use super::super::{
    consumer_server_alpn_protocols, ConsumerV2CallResponse, SessionQuorumConsumerServerHandle,
    SESSION_QUORUM_CONSUMER_V2_VOID_ALPN,
};
use super::*;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tokio::net::TcpStream;

// Frozen revision-5 control frames and original capability vocabulary. These
// decoders cannot accept either void operation or any new Hello field.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainHello {
    transport_revision: u16,
    scope: SessionConsumerScope,
    expected_server_node_id: u64,
    voter_count: u16,
    roster_commitment: [u8; 32],
    response_frame_size: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainHelloAck {
    transport_revision: u16,
    scope: SessionConsumerScope,
    server_node_id: u64,
    voter_count: u16,
    roster_commitment: [u8; 32],
    request_frame_size: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum MainOperation {
    FencedTransitionV2Capability,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainRequest {
    scope: SessionConsumerScope,
    request_id: Option<FencedTransitionV2RequestId>,
    operation: MainOperation,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainCall {
    correlation: NonZeroU32,
    attempt_nonce: [u8; 16],
    request_commitment: [u8; 32],
    request: MainRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum MainWireRequest {
    Hello(MainHello),
    Call(MainCall),
}

#[derive(Serialize, Deserialize)]
enum MainCapability {
    V2,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum MainResponse {
    FencedTransitionV2Capability(Result<MainCapability, SessionConsumerStoreError>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainCallResponse {
    correlation: NonZeroU32,
    attempt_nonce: [u8; 16],
    request_commitment: [u8; 32],
    response: MainResponse,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum MainWireResponse {
    HelloAck(MainHelloAck),
    Response(MainCallResponse),
}

fn main_hello() -> MainWireRequest {
    let authority = test_consumer_voter_authority();
    MainWireRequest::Hello(MainHello {
        transport_revision: 5,
        scope: scope(),
        expected_server_node_id: authority.node_id().get(),
        voter_count: u16::try_from(authority.voter_count()).unwrap(),
        roster_commitment: *authority.roster_commitment().as_bytes(),
        response_frame_size: super::super::MAX_NEGOTIATED_FRAME_SIZE as u32,
    })
}

fn main_ack() -> MainWireResponse {
    let MainWireRequest::Hello(hello) = main_hello() else {
        unreachable!()
    };
    MainWireResponse::HelloAck(MainHelloAck {
        transport_revision: 5,
        scope: hello.scope,
        server_node_id: hello.expected_server_node_id,
        voter_count: hello.voter_count,
        roster_commitment: hello.roster_commitment,
        request_frame_size: hello.response_frame_size,
    })
}

fn capability(void: bool) -> SessionConsumerV2Request {
    SessionConsumerV2Request::new(
        scope(),
        if void {
            SessionConsumerV2Operation::FencedTransitionV2VoidCapability
        } else {
            SessionConsumerV2Operation::FencedTransitionV2Capability
        },
    )
}

fn one_lane() -> PersistentSessionConsumerConfig {
    PersistentSessionConsumerConfig::try_new(
        1,
        1,
        Duration::from_millis(250),
        1,
        super::super::DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
        1,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .unwrap()
}

async fn read_main<R: tokio::io::AsyncRead + Unpin, T: for<'a> Deserialize<'a> + Serialize>(
    reader: &mut R,
) -> T {
    tokio::time::timeout(
        Duration::from_secs(2),
        super::super::read_consumer_frame(reader, super::super::MAX_NEGOTIATED_FRAME_SIZE),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn write_main<W: tokio::io::AsyncWrite + Unpin, T: Serialize>(writer: &mut W, value: &T) {
    super::super::write_frame_bounded_until(
        writer,
        value,
        super::super::MAX_NEGOTIATED_FRAME_SIZE,
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn void_alpn_baseline_and_opt_in_offers_match_a_frozen_main_server() {
    for opted_in in [false, true] {
        let server_identity = material_spiffe("void-alpn-main-server");
        let material =
            RotatableClientMaterial::new(material_spiffe("void-alpn-main-client").as_str());
        let server_material = material.trusted_server_config(server_identity.as_str());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let accepted = tokio_rustls::LazyConfigAcceptor::new(
                tokio_rustls::rustls::server::Acceptor::default(),
                tcp,
            )
            .await
            .unwrap();
            let offered: Vec<_> = accepted
                .client_hello()
                .alpn()
                .unwrap()
                .map(<[u8]>::to_vec)
                .collect();
            assert_eq!(
                offered,
                if opted_in {
                    vec![
                        b"opc-session-consumer/2-void".to_vec(),
                        b"opc-session-consumer/2".to_vec(),
                    ]
                } else {
                    vec![b"opc-session-consumer/2".to_vec()]
                }
            );
            let handshake = server_material.begin_handshake().unwrap();
            let mut config = handshake.rustls_config().as_ref().clone();
            config.alpn_protocols = vec![
                b"opc-session-consumer/2".to_vec(),
                b"opc-session-consumer/1".to_vec(),
            ];
            let mut tls = accepted.into_stream(Arc::new(config)).await.unwrap();
            handshake.admit().unwrap();
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"opc-session-consumer/2".as_slice())
            );
            let hello: MainWireRequest = read_main(&mut tls).await;
            assert_eq!(
                serde_json::to_vec(&hello).unwrap(),
                serde_json::to_vec(&main_hello()).unwrap()
            );
            write_main(&mut tls, &main_ack()).await;
            // Only the two original calls may reach this frozen decoder. Void
            // checks between them must not close or replace this physical lane.
            for _ in 0..2 {
                let MainWireRequest::Call(call) = read_main(&mut tls).await else {
                    panic!("original Call")
                };
                assert_eq!(call.request.scope, scope());
                assert!(call.request.request_id.is_none());
                write_main(
                    &mut tls,
                    &MainWireResponse::Response(MainCallResponse {
                        correlation: call.correlation,
                        attempt_nonce: call.attempt_nonce,
                        request_commitment: call.request_commitment,
                        response: MainResponse::FencedTransitionV2Capability(Ok(
                            MainCapability::V2,
                        )),
                    }),
                )
                .await;
            }
            let mut byte = [0_u8; 1];
            let closed = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut byte))
                .await
                .unwrap();
            assert!(
                matches!(closed, Ok(0))
                    || matches!(closed, Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof)
            );
        });
        let client = StatelessSessionConsumerClient::new_unattested_for_test(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        );
        let client = if opted_in {
            client.with_fenced_transition_v2_void_transport()
        } else {
            client
        };
        let client =
            PersistentSessionConsumerClient::try_from_stateless(client, one_lane()).unwrap();
        assert!(matches!(
            client.execute_v2(&capability(false)).await,
            Ok(SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
                _
            )))
        ));
        for _ in 0..3 {
            assert!(matches!(
                client.execute_v2(&capability(true)).await,
                Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
                    Err(SessionConsumerStoreError::CapabilityNotSupported)
                ))
            ));
        }
        let original = v2_effectful_request(0x71).await;
        let SessionConsumerV2Operation::FencedTransitionV2 { request } = original.operation()
        else {
            panic!("original")
        };
        let void = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Void {
                request: request.clone(),
            },
        );
        assert!(
            matches!(client.execute_v2(&void).await, Ok(SessionConsumerV2Response::FencedTransitionV2Void { request_id, result: Err(SessionConsumerStoreError::CapabilityNotSupported) }) if request_id == request.request_id())
        );
        assert!(matches!(
            client.execute_v2(&capability(false)).await,
            Ok(SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
                _
            )))
        ));
        assert_eq!(client.v2_diagnostics().setup_attempts, 1);
        client.shutdown().await;
        peer.await.unwrap();
    }
}

struct VoidAlpnConsumer {
    enabled: bool,
    probes: AtomicUsize,
    response: AtomicU8,
    entered: Notify,
    release: Notify,
}

impl VoidAlpnConsumer {
    fn new(enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            enabled,
            probes: AtomicUsize::new(0),
            response: AtomicU8::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
}

#[async_trait::async_trait]
impl SessionQuorumConsumer for VoidAlpnConsumer {
    fn fenced_transition_v2_void_transport_enabled(&self) -> bool {
        self.enabled
    }
    async fn execute(
        &self,
        _: &SessionConsumerAuthorization,
        _: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
    }
    async fn execute_v2(
        &self,
        _: &SessionConsumerAuthorization,
        request: SessionConsumerV2Request,
    ) -> SessionConsumerV2Response {
        match request.operation() {
            SessionConsumerV2Operation::FencedTransitionV2Capability => {
                SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
                    FencedTransitionV2Capability::V2,
                ))
            }
            SessionConsumerV2Operation::FencedTransitionV2VoidCapability => {
                self.probes.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                let response = self.response.load(Ordering::Acquire);
                if response == 3 {
                    self.release.notified().await;
                }
                match response {
                    1 => SessionConsumerV2Response::FencedTransitionV2VoidCapability(Err(
                        SessionConsumerStoreError::CapabilityNotSupported,
                    )),
                    2 => SessionConsumerV2Response::FencedTransitionV2VoidCapability(Err(
                        SessionConsumerStoreError::Unavailable,
                    )),
                    4 => SessionConsumerV2Response::Rejected(
                        SessionConsumerRejection::MalformedRequest,
                    ),
                    _ => SessionConsumerV2Response::FencedTransitionV2VoidCapability(Ok(())),
                }
            }
            _ => SessionConsumerV2Response::Rejected(SessionConsumerRejection::MalformedRequest),
        }
    }
    async fn watch(
        &self,
        _: &SessionConsumerAuthorization,
        _: SessionConsumerScope,
        _: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Err(SessionConsumerRejection::Unavailable)
    }
}

async fn void_service(
    service: Arc<VoidAlpnConsumer>,
) -> (
    SessionQuorumConsumerServerHandle,
    StatelessSessionConsumerClient,
) {
    let client_identity = material_spiffe("void-alpn-client");
    let server_identity = material_spiffe("void-alpn-server");
    let material = RotatableClientMaterial::new(client_identity.as_str());
    let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
        scope(),
        [client_identity],
        std::iter::empty(),
    )
    .unwrap();
    let (server, address) = SessionQuorumConsumerServer::new(
        service,
        material.trusted_server_config(server_identity.as_str()),
        authorizer,
    )
    .listen("127.0.0.1:0".parse().unwrap())
    .await
    .unwrap();
    let client = StatelessSessionConsumerClient::new_unattested_for_test(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        server_identity,
        scope(),
        material.config(),
    );
    (server, client)
}

#[tokio::test]
async fn void_alpn_baseline_server_and_frozen_main_client_keep_exact_selection() {
    for enabled in [false, true] {
        let service = VoidAlpnConsumer::new(enabled);
        let (server, client) = void_service(Arc::clone(&service)).await;
        for opted_in in [false, true] {
            let address = (client.resolve)().await.unwrap();
            let handshake = client.tls_config.begin_handshake().unwrap();
            let mut config = handshake.rustls_config().as_ref().clone();
            config.alpn_protocols = if opted_in {
                vec![
                    b"opc-session-consumer/2-void".to_vec(),
                    b"opc-session-consumer/2".to_vec(),
                ]
            } else {
                vec![b"opc-session-consumer/2".to_vec()]
            };
            let tcp = TcpStream::connect(address).await.unwrap();
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(client.server_name.clone(), tcp)
                .await
                .unwrap();
            handshake.admit().unwrap();
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(if enabled && opted_in {
                    b"opc-session-consumer/2-void".as_slice()
                } else {
                    b"opc-session-consumer/2".as_slice()
                })
            );
            write_main(&mut tls, &main_hello()).await;
            let ack: MainWireResponse = read_main(&mut tls).await;
            assert_eq!(
                serde_json::to_vec(&ack).unwrap(),
                serde_json::to_vec(&main_ack()).unwrap()
            );
            let request = MainRequest {
                scope: scope(),
                request_id: None,
                operation: MainOperation::FencedTransitionV2Capability,
            };
            let mut digest = sha2::Sha256::new();
            digest.update(b"opc-session-consumer-v2-call-phase");
            digest.update(5_u16.to_be_bytes());
            digest.update(serde_json::to_vec(&request).unwrap());
            write_main(
                &mut tls,
                &MainWireRequest::Call(MainCall {
                    correlation: NonZeroU32::MIN,
                    attempt_nonce: [0x77; 16],
                    request_commitment: digest.finalize().into(),
                    request,
                }),
            )
            .await;
            let response: MainWireResponse = read_main(&mut tls).await;
            assert!(matches!(
                response,
                MainWireResponse::Response(MainCallResponse {
                    response: MainResponse::FencedTransitionV2Capability(Ok(MainCapability::V2)),
                    ..
                })
            ));
        }
        assert_eq!(service.probes.load(Ordering::SeqCst), 0);
        server.abort_and_wait().await;
    }
    assert_eq!(
        consumer_server_alpn_protocols(None, false),
        vec![
            b"opc-session-consumer/2".to_vec(),
            b"opc-session-consumer/1".to_vec()
        ]
    );
    for (profile, frozen) in [
        (
            super::super::ConsumerTransportCapability::ProtectedRosterV5,
            b"opc-session-consumer/3".as_slice(),
        ),
        (
            super::super::ConsumerTransportCapability::ProtectedRosterV6,
            b"opc-session-consumer/4".as_slice(),
        ),
    ] {
        assert_eq!(
            consumer_server_alpn_protocols(Some(profile), false),
            vec![
                frozen.to_vec(),
                b"opc-session-consumer/2".to_vec(),
                b"opc-session-consumer/1".to_vec()
            ]
        );
    }
}

#[tokio::test]
async fn void_alpn_definite_capability_is_cached_only_for_the_physical_lane() {
    for first in [0, 1] {
        let service = VoidAlpnConsumer::new(true);
        service.response.store(first, Ordering::Release);
        let (server, client) = void_service(Arc::clone(&service)).await;
        let client = PersistentSessionConsumerClient::try_from_stateless(
            client.with_fenced_transition_v2_void_transport(),
            one_lane(),
        )
        .unwrap();
        for _ in 0..3 {
            let response = client.execute_v2(&capability(true)).await.unwrap();
            let expected = if first == 0 {
                matches!(
                    response,
                    SessionConsumerV2Response::FencedTransitionV2VoidCapability(Ok(()))
                )
            } else {
                matches!(
                    response,
                    SessionConsumerV2Response::FencedTransitionV2VoidCapability(Err(
                        SessionConsumerStoreError::CapabilityNotSupported
                    ))
                )
            };
            assert!(expected, "first={first} response={response:?}");
            service
                .response
                .store(if first == 0 { 1 } else { 0 }, Ordering::Release);
        }
        assert_eq!(service.probes.load(Ordering::SeqCst), 1);
        assert_eq!(client.v2_diagnostics().setup_attempts, 1);
        client.request_reauthentication().unwrap();
        client.execute_v2(&capability(true)).await.unwrap();
        assert_eq!(service.probes.load(Ordering::SeqCst), 2);
        assert_eq!(client.v2_diagnostics().setup_attempts, 2);
        client.shutdown().await;
        server.abort_and_wait().await;
    }
}

#[tokio::test]
async fn void_alpn_protocol_rejection_retires_the_lane_before_a_new_answer() {
    let service = VoidAlpnConsumer::new(true);
    service.response.store(4, Ordering::Release);
    let (server, client) = void_service(Arc::clone(&service)).await;
    let client = PersistentSessionConsumerClient::try_from_stateless(
        client.with_fenced_transition_v2_void_transport(),
        one_lane(),
    )
    .unwrap();
    // The sweep classifies this authenticated rejection as unsupported.
    // The existing protocol requires the physical lane to close; no cached
    // answer may be carried into its replacement connection.
    assert!(matches!(
        client.execute_v2(&capability(true)).await,
        Ok(SessionConsumerV2Response::Rejected(
            SessionConsumerRejection::MalformedRequest
        ))
    ));
    service.response.store(0, Ordering::Release);
    assert!(matches!(
        client.execute_v2(&capability(true)).await,
        Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
            Ok(())
        ))
    ));
    assert_eq!(service.probes.load(Ordering::SeqCst), 2);
    assert_eq!(client.v2_diagnostics().setup_attempts, 2);
    client.shutdown().await;
    server.abort_and_wait().await;
}

#[tokio::test]
async fn void_alpn_marker_does_not_grant_activation_or_cache_unavailability() {
    let service = VoidAlpnConsumer::new(true);
    service.response.store(2, Ordering::Release);
    let (server, client) = void_service(Arc::clone(&service)).await;
    let client = PersistentSessionConsumerClient::try_from_stateless(
        client.with_fenced_transition_v2_void_transport(),
        one_lane(),
    )
    .unwrap();
    for _ in 0..2 {
        assert!(matches!(
            client.execute_v2(&capability(true)).await,
            Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
                Err(SessionConsumerStoreError::Unavailable)
            ))
        ));
    }
    assert_eq!(service.probes.load(Ordering::SeqCst), 2);
    service.response.store(0, Ordering::Release);
    for _ in 0..2 {
        assert!(matches!(
            client.execute_v2(&capability(true)).await,
            Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
                Ok(())
            ))
        ));
    }
    assert_eq!(service.probes.load(Ordering::SeqCst), 3);
    assert_eq!(client.v2_diagnostics().setup_attempts, 1);
    client.shutdown().await;
    server.abort_and_wait().await;
}

#[tokio::test]
async fn void_alpn_first_positive_proof_retires_a_cancelled_competing_lane() {
    use futures_util::{stream::FuturesUnordered, StreamExt as _};
    let service = VoidAlpnConsumer::new(true);
    let winner = VoidAlpnConsumer::new(true);
    service.response.store(3, Ordering::Release);
    winner.response.store(3, Ordering::Release);
    let (server, client) = void_service(Arc::clone(&service)).await;
    let (winner_server, winner_client) = void_service(Arc::clone(&winner)).await;
    let client = PersistentSessionConsumerClient::try_from_stateless(
        client.with_fenced_transition_v2_void_transport(),
        one_lane(),
    )
    .unwrap();
    let winner_client = PersistentSessionConsumerClient::try_from_stateless(
        winner_client.with_fenced_transition_v2_void_transport(),
        one_lane(),
    )
    .unwrap();
    let mut probes = [client.clone(), winner_client.clone()]
        .into_iter()
        .map(|client| async move { client.execute_v2(&capability(true)).await })
        .collect::<FuturesUnordered<_>>();
    tokio::select! {
        _ = probes.next() => panic!("both probes must be in flight"),
        _ = async { tokio::join!(service.entered.notified(), winner.entered.notified()); } => {}
    }
    winner.release.notify_one();
    assert!(matches!(
        probes.next().await.unwrap(),
        Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
            Ok(())
        ))
    ));
    drop(probes);
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.v2_diagnostics().active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled physical actor must retire");
    service.response.store(0, Ordering::Release);
    service.release.notify_one();
    assert!(matches!(
        client.execute_v2(&capability(true)).await,
        Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
            Ok(())
        ))
    ));
    assert_eq!(client.v2_diagnostics().setup_attempts, 2);
    assert_eq!(service.probes.load(Ordering::SeqCst), 2);
    winner_client.execute_v2(&capability(true)).await.unwrap();
    assert_eq!(winner.probes.load(Ordering::SeqCst), 1);
    client.shutdown().await;
    winner_client.shutdown().await;
    server.abort_and_wait().await;
    winner_server.abort_and_wait().await;
}

#[tokio::test]
async fn void_alpn_transport_and_tls_failures_never_seed_unsupported() {
    for failure in 0..4 {
        let server_identity = material_spiffe("void-alpn-failure-server");
        let material =
            RotatableClientMaterial::new(material_spiffe("void-alpn-failure-client").as_str());
        let server_material = material.trusted_server_config(server_identity.as_str());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            for attempt in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                if attempt == 0 && failure == 0 {
                    drop(tcp);
                    continue;
                }
                let handshake = server_material.begin_handshake().unwrap();
                let mut config = handshake.rustls_config().as_ref().clone();
                config.alpn_protocols = if attempt == 0 && failure == 1 {
                    vec![b"unsupported-test-protocol".to_vec()]
                } else {
                    vec![SESSION_QUORUM_CONSUMER_V2_VOID_ALPN.to_vec()]
                };
                let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                    .accept(tcp)
                    .await;
                if attempt == 0 && failure == 1 {
                    assert!(tls.is_err());
                    continue;
                }
                let mut tls = tls.unwrap();
                handshake.admit().unwrap();
                let _: MainWireRequest = read_main(&mut tls).await;
                write_main(&mut tls, &main_ack()).await;
                let ConsumerV2WireRequest::Call(call) = read_main(&mut tls).await else {
                    panic!("void probe")
                };
                assert!(matches!(
                    call.request.operation(),
                    SessionConsumerV2Operation::FencedTransitionV2VoidCapability
                ));
                if attempt == 0 && failure == 2 {
                    drop(tls);
                    continue;
                }
                let mut nonce = call.attempt_nonce;
                if attempt == 0 && failure == 3 {
                    nonce[0] ^= 1;
                }
                write_main(
                    &mut tls,
                    &ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                        correlation: call.correlation,
                        attempt_nonce: nonce,
                        request_commitment: call.request_commitment,
                        response: Box::new(
                            SessionConsumerV2Response::FencedTransitionV2VoidCapability(Ok(())),
                        ),
                    }),
                )
                .await;
                if attempt == 1 {
                    let mut byte = [0_u8; 1];
                    let _ = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut byte))
                        .await
                        .unwrap();
                }
            }
        });
        let client = StatelessSessionConsumerClient::new_unattested_for_test(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_fenced_transition_v2_void_transport();
        let client =
            PersistentSessionConsumerClient::try_from_stateless(client, one_lane()).unwrap();
        let first = client.execute_v2(&capability(true)).await;
        if failure == 3 {
            assert!(matches!(
                first,
                Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
                    Err(SessionConsumerStoreError::CapabilityNotSupported)
                ))
            ));
        } else {
            assert!(
                first.is_err(),
                "transport/TLS failure is unavailable, never unsupported: {first:?}"
            );
        }
        assert!(matches!(
            client.execute_v2(&capability(true)).await,
            Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
                Ok(())
            ))
        ));
        assert_eq!(client.v2_diagnostics().setup_attempts, 2);
        client.shutdown().await;
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn void_alpn_stateless_fallback_sends_no_unknown_frame() {
    let server_identity = material_spiffe("void-alpn-stateless-server");
    let material =
        RotatableClientMaterial::new(material_spiffe("void-alpn-stateless-client").as_str());
    let server_material = material.trusted_server_config(server_identity.as_str());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        for _ in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let handshake = server_material.begin_handshake().unwrap();
            let mut config = handshake.rustls_config().as_ref().clone();
            config.alpn_protocols = vec![
                b"opc-session-consumer/2".to_vec(),
                b"opc-session-consumer/1".to_vec(),
            ];
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(tcp)
                .await
                .unwrap();
            handshake.admit().unwrap();
            let hello: MainWireRequest = read_main(&mut tls).await;
            assert_eq!(
                serde_json::to_vec(&hello).unwrap(),
                serde_json::to_vec(&main_hello()).unwrap()
            );
            write_main(&mut tls, &main_ack()).await;
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut byte))
                .await
                .unwrap();
            assert!(
                matches!(read, Ok(0))
                    || matches!(read, Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof),
                "neither extension may send a Call on /2: {read:?}"
            );
        }
    });
    let client = StatelessSessionConsumerClient::new_unattested_for_test(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        server_identity,
        scope(),
        material.config(),
    )
    .with_fenced_transition_v2_void_transport();
    assert!(matches!(
        client.execute_v2(&capability(true)).await,
        Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(
            Err(SessionConsumerStoreError::CapabilityNotSupported)
        ))
    ));
    let original = v2_effectful_request(0x72).await;
    let SessionConsumerV2Operation::FencedTransitionV2 { request } = original.operation() else {
        panic!("original")
    };
    let void = SessionConsumerV2Request::new(
        scope(),
        SessionConsumerV2Operation::FencedTransitionV2Void {
            request: request.clone(),
        },
    );
    assert!(
        matches!(client.execute_v2(&void).await, Ok(SessionConsumerV2Response::FencedTransitionV2Void { request_id, result: Err(SessionConsumerStoreError::CapabilityNotSupported) }) if request_id == request.request_id())
    );
    peer.await.unwrap();
}
