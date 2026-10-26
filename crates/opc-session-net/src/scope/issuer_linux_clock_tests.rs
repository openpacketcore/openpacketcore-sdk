use super::*;
use crate::scope::{linux_clock_test_support::ClockFixture, AuthenticationTimeSource};
use std::time::Duration;

#[test]
fn linux_time_startup_and_retained_proof_recover_without_admitting_a_candidate() {
    const NAME: &str = "scope::issuer_tests::linux_clock::linux_time_startup_and_retained_proof_recover_without_admitting_a_candidate";
    const CHILD: &str = "OPC_SCOPE_LINUX_CLOCK_ISSUER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap()).unwrap();
        let (_client_tx, client_rx) = watch::channel(Some(material(ISSUER, &ca)));
        let (_server_tx, server_rx) = watch::channel(Some(material(WORKER, &ca)));
        let client = TlsConfigBuilder::new(client_rx).with_policy(PeerPolicy { allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])), ..Default::default() }).build_authenticated_client_config().unwrap();
        let server = TlsConfigBuilder::new(server_rx).with_policy(PeerPolicy { allowed_instances: Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])), ..Default::default() }).build_authenticated_server_config().unwrap();
        let key = SigningKey::from_slice(&[1; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let jwks = serde_json::to_vec(&json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"one","x":URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),"y":URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..])}]})).unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = json!({"iss":"https://cluster.test","aud":["openpacketcore-scope-bootstrap"],"sub":"system:serviceaccount:test:worker","iat":now-60,"nbf":now-60,"exp":now+60,"kubernetes.io":{"namespace":"test","pod":{"name":"worker-0","uid":uuid::Uuid::from_bytes([3;16]).to_string()},"serviceaccount":{"name":"worker","uid":uuid::Uuid::from_bytes([6;16]).to_string()}}});
        let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"one"}"#), URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()));
        let signature: Signature = key.sign(input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())).into_bytes();
        let credentials = Arc::new(BootstrapCredentialVerifier::activate("https://cluster.test".into(), "https://cluster.test/openid/v1/jwks".into(), Arc::new(Keys(jwks))).await.unwrap());
        let root = tempfile::tempdir().unwrap();
        let process = Arc::new(ScopeProcess::new(scope(), [3;16], crate::scope::BootIdentity::generate().unwrap(), std::fs::File::open(root.path()).unwrap()).unwrap());
        let policy = crate::scope::ScopePolicy::new(vec![crate::scope::PrincipalGrant::new(SpiffeId::new(ISSUER).unwrap(), crate::scope::ScopeRole::Controller, vec![scope()]).unwrap()]).unwrap();
        let worker_time = ClockFixture::new();
        let issuer_time = ClockFixture::new();
        let responder = BootProofResponder::new(process.clone(), SpiffeId::new(ISSUER).unwrap(), policy, worker_time.clock.clone(), Arc::new(Token(token)), server, crate::scope::ProofBudgets::default()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let enrollment = PodEnrollment::new(scope(), "test".into(), "worker-0".into(), "worker".into(), [6;16], "worker".into(), [4;16], SpiffeId::new(WORKER).unwrap(), address.port()).unwrap();
        let reader = Arc::new(KubernetesBootReader::new(Arc::new(Api { address: Mutex::new(Some(address)), clock: Arc::new(IssuerClock(AtomicI64::new(0))), expire_on_recheck: false, reads: AtomicUsize::new(0), observe_error: None, revalidate_error: Mutex::new(None), revalidate_container_id: Mutex::new(None), revalidate_revision: Mutex::new(None) })));
        let issuer = BootstrapIssuerClient::new(client, issuer_time.clock.clone(), credentials, reader, crate::scope::ProofBudgets::default()).unwrap();
        for issuer_failed in [true, false] {
            issuer_time.failed.store(issuer_failed, Ordering::Release);
            worker_time.failed.store(!issuer_failed, Ordering::Release);
            let (verified, worker) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(issuer.probe(&enrollment, BootstrapProofMode::Candidate), async {
                    let (stream, _) = listener.accept().await.unwrap();
                    responder.respond_once(stream).await
                })
            }).await.unwrap();
            if issuer_failed {
                assert_eq!(verified.err(), Some(StartupError::AuthTimeUnavailable));
                assert!(worker.is_err());
            } else {
                assert_eq!(worker.err(), Some(StartupError::AuthTimeUnavailable));
                assert!(verified.is_err());
            }
            assert!(process.enter_peer_control().await.is_err());
        }
        issuer_time.failed.store(false, Ordering::Release);
        worker_time.failed.store(false, Ordering::Release);
        let (verified, worker) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(issuer.probe(&enrollment, BootstrapProofMode::Candidate), async {
                let (stream, _) = listener.accept().await.unwrap();
                responder.respond_once(stream).await
            })
        }).await.unwrap();
        let verified = verified.unwrap();
        let _worker = worker.unwrap();
        assert!(verified.proof().is_candidate());
        assert_eq!(verified.proof().process_nonce(), process.boot().process_nonce());
        verified.revalidate().await.unwrap();
        let generation = issuer_time.source.read().unwrap().synchronization_generation;
        issuer_time.failed.store(true, Ordering::Release);
        assert_eq!(verified.revalidate().await, Err(StartupError::AuthTimeUnavailable));
        assert!(process.enter_peer_control().await.is_err());
        issuer_time.failed.store(false, Ordering::Release);
        verified.revalidate().await.unwrap();
        assert_eq!(issuer_time.source.read().unwrap().synchronization_generation, generation + 1);
        assert!(process.enter_peer_control().await.is_err(), "time recovery and a proof never deliver authority");
    });
}
