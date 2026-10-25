//! Issuer requests preserve revision diagnostics and recover on a later probe.
use super::*;
use crate::scope::{proof::StartupMode, wire::*};
use crate::scope::{
    revision_tests::signal, ScopeTransportDirection as Direction, ScopeTransportPurpose as Purpose,
    ScopeTransportRole as Role,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn issuer_revision_mismatch_is_typed_for_alpn_and_both_proof_purposes() {
    const CHILD: &str = "OPC_ISSUER_REVISION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "scope::issuer_tests::revision::issuer_revision_mismatch_is_typed_for_alpn_and_both_proof_purposes", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let mut ca_params=rcgen::CertificateParams::default();ca_params.is_ca=rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca=rcgen::CertifiedIssuer::self_signed(ca_params,rcgen::KeyPair::generate().unwrap()).unwrap();
        let (_client_tx,client_rx)=watch::channel(Some(material(ISSUER,&ca)));let (_server_tx,server_rx)=watch::channel(Some(material(WORKER,&ca)));
        let client=TlsConfigBuilder::new(client_rx).with_policy(PeerPolicy{allowed_instances:Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),..Default::default()}).build_authenticated_client_config().unwrap();
        let server=TlsConfigBuilder::new(server_rx).with_policy(PeerPolicy{allowed_instances:Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])),..Default::default()}).build_authenticated_server_config().unwrap();
        let key=SigningKey::from_slice(&[1;32]).unwrap();let point=key.verifying_key().to_sec1_point(false);
        let jwks=serde_json::to_vec(&json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"one","x":URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),"y":URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..])}]})).unwrap();
        let now=time::OffsetDateTime::now_utc().unix_timestamp();
        let claims=json!({"iss":"https://cluster.test","aud":["openpacketcore-scope-bootstrap"],"sub":"system:serviceaccount:test:worker","iat":now-60,"nbf":now-60,"exp":now+60,"kubernetes.io":{"namespace":"test","pod":{"name":"worker-0","uid":uuid::Uuid::from_bytes([3;16]).to_string()},"serviceaccount":{"name":"worker","uid":uuid::Uuid::from_bytes([6;16]).to_string()}}});
        let input=format!("{}.{}",URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"one"}"#),URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()));
        let signature:Signature=key.sign(input.as_bytes());let token=format!("{input}.{}",URL_SAFE_NO_PAD.encode(signature.to_bytes())).into_bytes();
        let credentials=Arc::new(BootstrapCredentialVerifier::activate("https://cluster.test".into(),"https://cluster.test/openid/v1/jwks".into(),Arc::new(Keys(jwks))).await.unwrap());
        let root=tempfile::tempdir().unwrap();let process=Arc::new(ScopeProcess::new(scope(),[3;16],crate::scope::BootIdentity::generate().unwrap(),std::fs::File::open(root.path()).unwrap()).unwrap());
        let policy=crate::scope::ScopePolicy::new(vec![crate::scope::PrincipalGrant::new(SpiffeId::new(ISSUER).unwrap(),crate::scope::ScopeRole::Controller,vec![scope()]).unwrap()]).unwrap();
        let responder=BootProofResponder::new(process.clone(),SpiffeId::new(ISSUER).unwrap(),policy,Arc::new(Clock),Arc::new(Token(token)),server.clone(),crate::scope::ProofBudgets::default()).unwrap();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let enrollment=PodEnrollment::new(scope(),"test".into(),"worker-0".into(),"worker".into(),[6;16],"worker".into(),[4;16],SpiffeId::new(WORKER).unwrap(),address.port()).unwrap();
        let issuer_clock=Arc::new(IssuerClock(AtomicI64::new(0)));
        let reader=Arc::new(KubernetesBootReader::new(Arc::new(Api{address:Mutex::new(Some(address)),clock:issuer_clock.clone(),expire_on_recheck:false,reads:AtomicUsize::new(0),observe_error:None,revalidate_error:Mutex::new(None),revalidate_container_id:Mutex::new(None)})));
        let issuer=BootstrapIssuerClient::new(client,issuer_clock.clone(),credentials,reader,crate::scope::ProofBudgets::default()).unwrap();

            for mode in [BootstrapProofMode::Liveness, BootstrapProofMode::Candidate] {
                let (result, peer) = tokio::join!(issuer.probe(&enrollment, mode), async {
                    let (socket, _) = listener.accept().await.unwrap();
                    let handshake = server.begin_handshake().unwrap();
                    let mut config = (*handshake.rustls_config()).clone();
                    config.alpn_protocols = vec![b"opc-scope/1".to_vec()];
                    tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(socket).await
                });
                assert!(peer.is_err());
                assert_eq!(result.err(), Some(StartupError::TransportRevisionMismatch), "ALPN refusal for {mode:?}");
                let alerts = if mode == BootstrapProofMode::Liveness { 1 } else { 2 };
                assert_eq!(signal(Role::Issuer, Purpose::Handshake, Direction::Outbound), (alerts, 0, true));
                let purpose = match mode { BootstrapProofMode::Liveness => StartupMode::Liveness, BootstrapProofMode::Candidate => StartupMode::Candidate };
                let (result, peer) = tokio::join!(issuer.probe(&enrollment, mode), async {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut stream = server.begin_handshake().unwrap().accept_scope(socket, scope().tls_domain().unwrap()).await.unwrap();
                    let mut fixed = [0; HEADER_BYTES];
                    stream.read_exact(&mut fixed).await.unwrap();
                    let call = Header::decode(&fixed).unwrap();
                    assert_eq!(call.method, purpose.method());
                    let mut body = vec![0; call.payload_len];
                    stream.read_exact(&mut body).await.unwrap();
                    let mut old = call.response(FrameKind::Proof, 128).unwrap().encode().unwrap();
                    old[4..6].copy_from_slice(&1u16.to_be_bytes());
                    stream.write_all(&old).await.unwrap();
                    stream.flush().await.unwrap();
                    stream
                });
                assert_eq!(result.err(), Some(StartupError::TransportRevisionMismatch), "old authenticated proof header for {mode:?} before body allocation");
                let diagnostic_purpose = match mode { BootstrapProofMode::Liveness => Purpose::BootLiveness, BootstrapProofMode::Candidate => Purpose::BootCandidate };
                assert_eq!(signal(Role::Issuer, diagnostic_purpose, Direction::Outbound), (1, 1, true));
                assert_eq!(signal(Role::Issuer, Purpose::Handshake, Direction::Outbound), (alerts, 0, false));
                drop(peer);
                assert!(process.enter_peer_control().await.is_err());
                let (result, worker) = tokio::join!(issuer.probe(&enrollment, mode), async {
                    let (socket, _) = listener.accept().await.unwrap();
                    responder.respond_once(socket).await
                });
                let result = result.expect("a later authenticated revision-two probe must recover without restart");
                assert_eq!(result.proof().is_candidate(), mode == BootstrapProofMode::Candidate);
                worker.unwrap();
                assert_eq!(signal(Role::Issuer, diagnostic_purpose, Direction::Outbound), (1, 1, false));
            }
        }).await.expect("bounded issuer revision fixture");
    });
}
