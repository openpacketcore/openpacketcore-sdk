//! Old startup headers and pre-authentication ALPN failures remain distinct.
use super::*;

#[test]
fn startup_revision_mismatch_is_typed_for_alpn_calls_and_retained_notices() {
    const CHILD: &str = "OPC_STARTUP_REVISION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "scope::startup_tests::revision::startup_revision_mismatch_is_typed_for_alpn_calls_and_retained_notices", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(15), async {
                let root = tempfile::tempdir().unwrap();
                let process = Arc::new(
                    ScopeProcess::new(
                        scope(),
                        [3; 16],
                        BootIdentity::generate().unwrap(),
                        std::fs::File::open(root.path()).unwrap(),
                    )
                    .unwrap(),
                );
                let mut ca_params = rcgen::CertificateParams::default();
                ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                let ca = rcgen::CertifiedIssuer::self_signed(
                    ca_params,
                    rcgen::KeyPair::generate().unwrap(),
                )
                .unwrap();
                let (_client_source, client_rx) = watch::channel(Some(material(ISSUER, &ca)));
                let (_server_source, server_rx) = watch::channel(Some(material(WORKER, &ca)));
                let client = TlsConfigBuilder::new(client_rx)
                    .with_policy(PeerPolicy {
                        allowed_instances: Some(HashSet::from([
                            InstanceId::new("worker-0").unwrap()
                        ])),
                        ..Default::default()
                    })
                    .build_authenticated_client_config()
                    .unwrap();
                let server = TlsConfigBuilder::new(server_rx)
                    .with_policy(PeerPolicy {
                        allowed_instances: Some(HashSet::from([
                            InstanceId::new("issuer-0").unwrap()
                        ])),
                        ..Default::default()
                    })
                    .build_authenticated_server_config()
                    .unwrap();
                let policy = ScopePolicy::new(vec![PrincipalGrant::new(
                    SpiffeId::new(ISSUER).unwrap(),
                    ScopeRole::Controller,
                    vec![scope()],
                )
                .unwrap()])
                .unwrap();
                let token = Arc::new(Token(AtomicUsize::new(0)));
                let responder = BootProofResponder::new(
                    process.clone(),
                    SpiffeId::new(ISSUER).unwrap(),
                    policy.clone(),
                    Arc::new(Clock),
                    token.clone(),
                    server,
                    crate::scope::pool::ProofBudgets::default(),
                )
                .unwrap();

                let (client_io, server_io) = tokio::io::duplex(16384);
                let handshake = client.begin_handshake().unwrap();
                let mut config = (*handshake.rustls_config()).clone();
                config.alpn_protocols = vec![b"opc-scope/1".to_vec()];
                let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
                let (peer, result) = tokio::join!(
                    connector.connect(
                        rustls_pki_types::ServerName::try_from("scope.invalid").unwrap(),
                        client_io
                    ),
                    responder.respond_once(server_io),
                );
                assert!(peer.is_err());
                assert_eq!(result.err(), Some(StartupError::TransportRevisionMismatch));
                assert_eq!(
                    token.0.load(Ordering::SeqCst),
                    0,
                    "a pre-authentication alert cannot read the projected credential"
                );
                for mode in [StartupMode::Liveness, StartupMode::Candidate] {
                    let (header, _, _) = call(mode);
                    let (client_io, server_io) = tokio::io::duplex(16384);
                    let (peer, result) = tokio::join!(
                        async {
                            let mut stream = client
                                .begin_handshake()
                                .unwrap()
                                .connect_scope(client_io, scope().tls_domain().unwrap())
                                .await
                                .unwrap();
                            let mut old = header.encode().unwrap();
                            old[4..6].copy_from_slice(&1u16.to_be_bytes());
                            stream.write_all(&old).await.unwrap();
                            stream.flush().await.unwrap();
                            stream
                        },
                        responder.respond_once(server_io)
                    );
                    assert_eq!(
                        result.err(),
                        Some(StartupError::TransportRevisionMismatch),
                        "old authenticated {mode:?} header is refused without reading its body"
                    );
                    drop(peer);
                }
                assert_eq!(token.0.load(Ordering::SeqCst), 0);
                let (header, payload, _) = call(StartupMode::Candidate);
                let (client_io, server_io) = tokio::io::duplex(16384);
                let (mut peer, session) = tokio::join!(
                    async {
                        let mut stream = client
                            .begin_handshake()
                            .unwrap()
                            .connect_scope(client_io, scope().tls_domain().unwrap())
                            .await
                            .unwrap();
                        stream.write_all(&header.encode().unwrap()).await.unwrap();
                        stream
                            .write_all(&payload.encode(header.method).unwrap())
                            .await
                            .unwrap();
                        stream.flush().await.unwrap();
                        let mut fixed = [0; HEADER_BYTES];
                        stream.read_exact(&mut fixed).await.unwrap();
                        let response = Header::decode(&fixed).unwrap();
                        assert_eq!(response.kind, FrameKind::Proof);
                        assert!(response.matches_attempt(&header));
                        let mut proof = vec![0; response.payload_len];
                        stream.read_exact(&mut proof).await.unwrap();
                        assert!(StartupProof::decode(&proof).is_ok());
                        stream
                    },
                    responder.respond_once(server_io)
                );
                let session = session.expect(
                    "fresh authenticated revision two recovers without restarting the process",
                );
                assert_eq!(token.0.load(Ordering::SeqCst), 1);
                let mut old = header
                    .response(FrameKind::TicketNotice, 256)
                    .unwrap()
                    .encode()
                    .unwrap();
                old[4..6].copy_from_slice(&1u16.to_be_bytes());
                let (_, notice) = tokio::join!(
                    async {
                        peer.write_all(&old).await.unwrap();
                        peer.flush().await.unwrap();
                    },
                    session.receive_ticket_notice(
                        tokio::time::Instant::now() + Duration::from_secs(2),
                        |_| panic!("an old notice cannot deliver a predecessor")
                    )
                );
                assert_eq!(
                    notice.err(),
                    Some(StartupError::TransportRevisionMismatch),
                    "a retained startup connection rejects an old notice before body allocation"
                );
                assert!(process.enter_peer_control().await.is_err());
            })
            .await
            .expect("bounded startup revision fixture");
        });
}
