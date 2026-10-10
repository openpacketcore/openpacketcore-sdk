use super::{
    credential::*,
    issuer::*,
    platform::*,
    startup::*,
    startup_tests::{material, scope, Clock, ISSUER, WORKER},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opc_tls::{PeerPolicy, TlsConfigBuilder};
use opc_types::{InstanceId, SpiffeId};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::json;
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicI64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::watch;
struct IssuerClock(AtomicI64);
impl super::AuthenticationClock for IssuerClock {
    fn interval(
        &self,
    ) -> Result<opc_tls::AuthenticationTimeInterval, super::AuthenticationTimeError> {
        let now = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::now_utc()
                + time::Duration::seconds(self.0.load(Ordering::Acquire)),
        );
        opc_tls::AuthenticationTimeInterval::new(now, now)
            .map_err(|_| super::AuthenticationTimeError)
    }
}
struct Api {
    address: Mutex<Option<std::net::SocketAddr>>,
    clock: Arc<IssuerClock>,
    expire_on_recheck: bool,
    reads: AtomicUsize,
}
#[async_trait::async_trait]
impl KubernetesPodSource for Api {
    async fn get_pod_consistent(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<u8>, PlatformError> {
        assert_eq!((namespace, name), ("test", "worker-0"));
        if self.reads.fetch_add(1, Ordering::AcqRel) == 1 && self.expire_on_recheck {
            tokio::task::yield_now().await;
            self.clock.0.store(120, Ordering::Release);
        }
        Ok(serde_json::to_vec(&json!({"metadata":{"name":name,"namespace":namespace,"uid":uuid::Uuid::from_bytes([3;16]).to_string(),"resourceVersion":"42","ownerReferences":[{"uid":uuid::Uuid::from_bytes([4;16]).to_string(),"controller":true}]},"spec":{"serviceAccountName":"worker"},"status":{"podIP":self.address.lock().unwrap().unwrap().ip().to_string(),"containerStatuses":[{"name":"worker","containerID":"cri-o://exact","state":{"running":{"startedAt":"2026-10-01T00:00:00Z"}}}]}})).unwrap())
    }
}
struct Keys(Vec<u8>);
#[async_trait::async_trait]
impl IssuerKeySource for Keys {
    async fn discovery(&self) -> Result<Vec<u8>, BootstrapCredentialError> {
        Ok(br#"{"issuer":"https://cluster.test","jwks_uri":"https://cluster.test/openid/v1/jwks"}"#.to_vec())
    }
    async fn jwks(&self) -> Result<Vec<u8>, BootstrapCredentialError> {
        Ok(self.0.clone())
    }
}
struct Token(Vec<u8>);
#[async_trait::async_trait]
impl BootstrapCredentialSource for Token {
    async fn read(&self) -> Result<BootstrapCredential, StartupError> {
        BootstrapCredential::new(self.0.clone())
    }
}
#[test]
fn issuer_reconstructs_the_proof_from_live_tls_token_and_exact_current_pod() {
    run_issuer(Scenario::Verify,"scope::issuer_tests::issuer_reconstructs_the_proof_from_live_tls_token_and_exact_current_pod");
}
#[test]
fn verified_issuer_delivers_an_exact_ticket_on_the_retained_startup_connection() {
    run_issuer(Scenario::Deliver,"scope::issuer_tests::verified_issuer_delivers_an_exact_ticket_on_the_retained_startup_connection");
}
#[test]
fn issuer_refreshes_the_same_ticket_when_a_predecessor_becomes_visible() {
    run_issuer(
        Scenario::Refresh,
        "scope::issuer_tests::issuer_refreshes_the_same_ticket_when_a_predecessor_becomes_visible",
    );
}
#[test]
fn issuer_rechecks_bootstrap_validity_before_durable_issuance() {
    run_issuer(
        Scenario::ExpiredBeforeIssuance,
        "scope::issuer_tests::issuer_rechecks_bootstrap_validity_before_durable_issuance",
    );
}
#[test]
fn bootstrap_expiry_during_independent_pod_read_is_retryable() {
    run_issuer(
        Scenario::ExpiresWhileReading,
        "scope::issuer_tests::bootstrap_expiry_during_independent_pod_read_is_retryable",
    );
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Verify,
    Deliver,
    Refresh,
    ExpiredBeforeIssuance,
    ExpiresWhileReading,
}
struct NoPredecessors;
#[async_trait::async_trait]
impl super::TicketNoticeSource for NoPredecessors {
    async fn page(
        &self,
        first: u32,
        count: u8,
    ) -> Result<Vec<super::TicketNoticeEntry>, StartupError> {
        assert_eq!((first, count), (0, 0));
        Ok(Vec::new())
    }
}
struct Snapshot {
    entry: super::notice::ClosureHint,
    change_between_passes: bool,
    reads: AtomicUsize,
}
#[async_trait::async_trait]
impl super::TicketNoticeSource for Snapshot {
    async fn page(
        &self,
        first: u32,
        count: u8,
    ) -> Result<Vec<super::TicketNoticeEntry>, StartupError> {
        assert_eq!((first, count), (0, 1));
        let mut hint = self.entry.clone();
        if self.reads.fetch_add(1, Ordering::AcqRel) > 0 && self.change_between_passes {
            hint.digest[0] ^= 1;
        }
        Ok(vec![super::TicketNoticeEntry { hint }])
    }
}
fn predecessor_snapshot(change_between_passes: bool) -> Snapshot {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/rfc/026-scope-authenticated-transport-vectors.json"
    ))
    .unwrap();
    let encoded: Vec<_> = v["ticket_notice"]["page_hex"]
        .as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut page = super::notice::NoticePage::decode(&encoded).unwrap();
    Snapshot {
        entry: page.entries.remove(0),
        change_between_passes,
        reads: AtomicUsize::new(0),
    }
}
fn run_issuer(scenario: Scenario, test_name: &str) {
    const CHILD: &str = "OPC_SCOPE_ISSUER_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
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
        let root=tempfile::tempdir().unwrap();let process=Arc::new(ScopeProcess::new(scope(),[3;16],super::BootIdentity::generate().unwrap(),std::fs::File::open(root.path()).unwrap()).unwrap());
        let policy=super::ScopePolicy::new(vec![super::PrincipalGrant::new(SpiffeId::new(ISSUER).unwrap(),super::ScopeRole::Controller,vec![scope()]).unwrap()]).unwrap();
        let responder=BootProofResponder::new(process.clone(),SpiffeId::new(ISSUER).unwrap(),policy,Arc::new(Clock),Arc::new(Token(token)),server,super::ProofBudgets::default()).unwrap();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let enrollment=PodEnrollment::new(scope(),"test".into(),"worker-0".into(),"worker".into(),[6;16],"worker".into(),[4;16],SpiffeId::new(WORKER).unwrap(),address.port()).unwrap();
        let issuer_clock=Arc::new(IssuerClock(AtomicI64::new(0)));
        let reader=Arc::new(KubernetesBootReader::new(Arc::new(Api{address:Mutex::new(Some(address)),clock:issuer_clock.clone(),expire_on_recheck:scenario==Scenario::ExpiresWhileReading,reads:AtomicUsize::new(0)})));
        let issuer=BootstrapIssuerClient::new(client,issuer_clock.clone(),credentials,reader,super::ProofBudgets::default()).unwrap();
        let (verified,worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
        let worker=worker.unwrap();
        if scenario==Scenario::ExpiresWhileReading {
            assert!(matches!(verified,Err(StartupError::AuthTimeUnavailable)),"JWT expiry after independent Pod read must refuse startup with a retryable authentication-time result");
            assert!(process.enter_peer_control().await.is_err());
            return;
        }
        let verified=verified.unwrap();assert_eq!(verified.proof().workload(),&[3;16]);assert_eq!(verified.proof().process_nonce(),process.boot().process_nonce());assert_eq!(verified.proof().boot_key_digest(),process.boot().key_digest());
        assert!(verified.proof().is_candidate());
        if scenario==Scenario::ExpiredBeforeIssuance {
            verified.revalidate().await.unwrap();
            issuer_clock.0.store(120,Ordering::Release);
            assert!(matches!(verified.revalidate().await,Err(StartupError::AuthTimeUnavailable)),"a retained proof must not outlive its bootstrap credential before issuance");
            issuer_clock.0.store(0,Ordering::Release);
            verified.revalidate().await.unwrap();
            assert!(process.enter_peer_control().await.is_err());
        }
        if matches!(scenario, Scenario::Deliver | Scenario::Refresh) {
            let notice=super::IssuedTicketNotice::new(128,b"issuer-record-uid".to_vec(),b"opaque:0042".to_vec(),0).unwrap();
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let (sent,received)=tokio::join!(verified.deliver_ticket_notice(notice,&NoPredecessors,deadline),worker.receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)));
            sent.unwrap();let ticket=received.unwrap();assert_eq!(ticket.generation(),128);assert_eq!(ticket.authority_record_uid(),b"issuer-record-uid");assert_eq!(ticket.authority_revision(),b"opaque:0042");
            let (verified,worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
            let notice=super::IssuedTicketNotice::new(128,b"issuer-record-uid".to_vec(),b"opaque:0042".to_vec(),0).unwrap();
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let (sent,received)=tokio::join!(verified.unwrap().deliver_ticket_notice(notice,&NoPredecessors,deadline),worker.unwrap().receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)));
            sent.unwrap();
            assert_eq!(received.unwrap().notice_id(),ticket.notice_id(),"redelivery of unchanged contents keeps its notice ID across startup connections");
            if scenario == Scenario::Refresh {
                // The reader's committed predecessor appears only after the
                // original issuance and its empty notice have completed.
                for change_between_passes in [false, true] {
                    let snapshot = predecessor_snapshot(change_between_passes);
                    let (verified, worker) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        tokio::join!(issuer.probe(&enrollment, BootstrapProofMode::Candidate), async {
                            let (stream, _) = listener.accept().await.unwrap();
                            responder.respond_once(stream).await
                        })
                    }).await.unwrap();
                    let notice = super::IssuedTicketNotice::new(128, b"issuer-record-uid".to_vec(), b"opaque:0042".to_vec(), 1).unwrap();
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                    let mut staged = Vec::new();
                    let (sent, received) = tokio::join!(
                        verified.unwrap().deliver_ticket_notice(notice, &snapshot, deadline),
                        worker.unwrap().receive_ticket_notice(deadline, |hint| { staged.push(hint); Ok(()) }),
                    );
                    if change_between_passes {
                        assert_eq!(sent.err(), Some(StartupError::Invalid), "a source that changes within one delivery cannot complete");
                        assert!(received.is_err());
                    } else {
                        sent.unwrap();
                        let refreshed = received.expect("a later complete evidence snapshot must be accepted");
                        assert_eq!(refreshed.generation(), ticket.generation());
                        assert_eq!(refreshed.authority_record_uid(), ticket.authority_record_uid());
                        assert_eq!(refreshed.authority_revision(), ticket.authority_revision());
                        assert_ne!(refreshed.notice_id(), ticket.notice_id());
                        assert_eq!(staged.len(), 1);
                        assert_eq!(staged[0].predecessor_bytes(), snapshot.entry.predecessor);
                        assert_eq!(staged[0].evidence_digest(), &snapshot.entry.digest);
                        assert!(process.enter_peer_control().await.is_err(), "a refreshed notice still confers no admission");
                    }
                    assert_eq!(snapshot.reads.load(Ordering::Acquire), 2);
                }
            }
        }
    });
}
