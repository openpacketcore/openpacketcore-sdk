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
#[path = "issuer_revision_tests.rs"]
mod revision;
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
    observe_error: Option<PlatformError>,
    revalidate_error: Mutex<Option<PlatformError>>,
    revalidate_container_id: Mutex<Option<String>>,
    revalidate_revision: Mutex<Option<String>>,
}
#[async_trait::async_trait]
impl KubernetesPodSource for Api {
    async fn get_pod_consistent(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<u8>, PlatformError> {
        assert_eq!((namespace, name), ("test", "worker-0"));
        if let Some(error) = self.observe_error {
            return Err(error);
        }
        let read = self.reads.fetch_add(1, Ordering::AcqRel);
        if read > 0 {
            if let Some(error) = *self.revalidate_error.lock().unwrap() {
                return Err(error);
            }
        }
        if read == 1 && self.expire_on_recheck {
            tokio::task::yield_now().await;
            self.clock.0.store(120, Ordering::Release);
        }
        let container_id = if read > 0 {
            self.revalidate_container_id.lock().unwrap().clone()
        } else {
            None
        }
        .unwrap_or_else(|| "cri-o://exact".to_string());
        let revision = self
            .revalidate_revision
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "42".into());
        Ok(serde_json::to_vec(&json!({"metadata":{"name":name,"namespace":namespace,"uid":uuid::Uuid::from_bytes([3;16]).to_string(),"resourceVersion":revision,"ownerReferences":[{"uid":uuid::Uuid::from_bytes([4;16]).to_string(),"controller":true}]},"spec":{"serviceAccountName":"worker"},"status":{"podIP":self.address.lock().unwrap().unwrap().ip().to_string(),"containerStatuses":[{"name":"worker","containerID":container_id,"state":{"running":{"startedAt":"2026-10-01T00:00:00Z"}}}]}})).unwrap())
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
struct RotatingKeys {
    response: Mutex<Result<Vec<u8>, BootstrapCredentialError>>,
    reads: AtomicUsize,
}
#[async_trait::async_trait]
impl IssuerKeySource for RotatingKeys {
    async fn discovery(&self) -> Result<Vec<u8>, BootstrapCredentialError> {
        Keys(Vec::new()).discovery().await
    }
    async fn jwks(&self) -> Result<Vec<u8>, BootstrapCredentialError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.response.lock().unwrap().clone()
    }
}
struct RotatingToken(Mutex<Vec<u8>>);
#[async_trait::async_trait]
impl BootstrapCredentialSource for RotatingToken {
    async fn read(&self) -> Result<BootstrapCredential, StartupError> {
        BootstrapCredential::new(self.0.lock().unwrap().clone())
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
#[test]
fn probe_preserves_definitive_platform_refusal() {
    run_issuer(
        Scenario::ProbePlatformInvalid,
        "scope::issuer_tests::probe_preserves_definitive_platform_refusal",
    );
}

#[test]
fn probe_keeps_transient_platform_failure_retryable() {
    run_issuer(
        Scenario::ProbePlatformUnavailable,
        "scope::issuer_tests::probe_keeps_transient_platform_failure_retryable",
    );
}

#[test]
fn retained_session_revalidation_preserves_changed_platform_observation() {
    run_issuer(
        Scenario::RevalidatePlatformChanged,
        "scope::issuer_tests::retained_session_revalidation_preserves_changed_platform_observation",
    );
}

#[test]
fn authenticated_refusal_after_updated_container_facts_is_typed_for_the_worker() {
    run_issuer(
        Scenario::RefuseAfterChangedFacts,
        "scope::issuer_tests::authenticated_refusal_after_updated_container_facts_is_typed_for_the_worker",
    );
}

#[test]
fn a_refused_boot_does_not_block_the_next_fresh_boot_ticket() {
    run_issuer(
        Scenario::RefuseThenFreshBootTickets,
        "scope::issuer_tests::a_refused_boot_does_not_block_the_next_fresh_boot_ticket",
    );
}

#[test]
fn a_lost_refusal_stays_unavailable_and_never_refuses_the_boot() {
    run_issuer(
        Scenario::LostRefusalStaysUnavailable,
        "scope::issuer_tests::a_lost_refusal_stays_unavailable_and_never_refuses_the_boot",
    );
}

#[test]
fn a_liveness_startup_session_cannot_carry_a_boot_refusal() {
    run_issuer(
        Scenario::RefuseOnLiveness,
        "scope::issuer_tests::a_liveness_startup_session_cannot_carry_a_boot_refusal",
    );
}

#[test]
fn a_boot_refusal_cannot_follow_a_partial_ticket_notice() {
    run_issuer(
        Scenario::RefuseAfterNotice,
        "scope::issuer_tests::a_boot_refusal_cannot_follow_a_partial_ticket_notice",
    );
}

#[test]
fn probe_preserves_changed_platform_observation() {
    run_issuer(
        Scenario::ProbePlatformChanged,
        "scope::issuer_tests::probe_preserves_changed_platform_observation",
    );
}

#[test]
fn ticket_delivery_preserves_each_platform_failure_class() {
    run_issuer(
        Scenario::DeliverPlatformFailures,
        "scope::issuer_tests::ticket_delivery_preserves_each_platform_failure_class",
    );
}

#[test]
fn a_revision_only_change_allows_the_same_boot_to_reprobe_and_receive_a_ticket() {
    run_issuer(Scenario::RevisionOnlyChange, "scope::issuer_tests::a_revision_only_change_allows_the_same_boot_to_reprobe_and_receive_a_ticket");
}

#[test]
fn authenticated_invalid_platform_refusal_is_typed_for_the_worker() {
    run_issuer(
        Scenario::RefusePlatformInvalid,
        "scope::issuer_tests::authenticated_invalid_platform_refusal_is_typed_for_the_worker",
    );
}

#[test]
fn authenticated_prerequisite_refusal_is_typed_for_the_worker() {
    run_issuer(
        Scenario::RefusePrerequisite,
        "scope::issuer_tests::authenticated_prerequisite_refusal_is_typed_for_the_worker",
    );
}

#[test]
fn activated_issuer_preserves_failed_key_refresh_classes_then_recovers() {
    run_issuer(
        Scenario::RefreshCredentialFailures,
        "scope::issuer_tests::activated_issuer_preserves_failed_key_refresh_classes_then_recovers",
    );
}

#[test]
fn probe_internal_revalidation_preserves_each_platform_class_and_recovers() {
    run_issuer(
        Scenario::ProbeRevalidationFailures,
        "scope::issuer_tests::probe_internal_revalidation_preserves_each_platform_class_and_recovers",
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Verify,
    Deliver,
    Refresh,
    ExpiredBeforeIssuance,
    ExpiresWhileReading,
    ProbePlatformInvalid,
    ProbePlatformUnavailable,
    RevalidatePlatformChanged,
    RefuseAfterChangedFacts,
    RefuseThenFreshBootTickets,
    LostRefusalStaysUnavailable,
    RefuseOnLiveness,
    RefuseAfterNotice,
    ProbePlatformChanged,
    DeliverPlatformFailures,
    RevisionOnlyChange,
    RefusePlatformInvalid,
    RefusePrerequisite,
    RefreshCredentialFailures,
    ProbeRevalidationFailures,
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
    let v: serde_json::Value = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../../docs/rfc/026-scope-transport-revision2-vectors.json"
    ))
    .unwrap()["authority_startup"]
        .clone();
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
        let client_rx_next=client_rx.clone();let server_rx_next=server_rx.clone();
        let client=TlsConfigBuilder::new(client_rx).with_policy(PeerPolicy{allowed_instances:Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),..Default::default()}).build_authenticated_client_config().unwrap();
        let server=TlsConfigBuilder::new(server_rx).with_policy(PeerPolicy{allowed_instances:Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])),..Default::default()}).build_authenticated_server_config().unwrap();
        let key=SigningKey::from_slice(&[1;32]).unwrap();let point=key.verifying_key().to_sec1_point(false);
        let jwks=serde_json::to_vec(&json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"one","x":URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),"y":URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..])}]})).unwrap();
        let now=time::OffsetDateTime::now_utc().unix_timestamp();
        let claims=json!({"iss":"https://cluster.test","aud":["openpacketcore-scope-bootstrap"],"sub":"system:serviceaccount:test:worker","iat":now-60,"nbf":now-60,"exp":now+60,"kubernetes.io":{"namespace":"test","pod":{"name":"worker-0","uid":uuid::Uuid::from_bytes([3;16]).to_string()},"serviceaccount":{"name":"worker","uid":uuid::Uuid::from_bytes([6;16]).to_string()}}});
        let input=format!("{}.{}",URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"one"}"#),URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()));
        let signature:Signature=key.sign(input.as_bytes());let token=format!("{input}.{}",URL_SAFE_NO_PAD.encode(signature.to_bytes())).into_bytes();
        let key_source=Arc::new(RotatingKeys { response:Mutex::new(Ok(jwks)), reads:AtomicUsize::new(0) });
        let credentials=Arc::new(BootstrapCredentialVerifier::activate("https://cluster.test".into(),"https://cluster.test/openid/v1/jwks".into(),key_source.clone()).await.unwrap());
        let token_source=Arc::new(RotatingToken(Mutex::new(token.clone())));
        let root=tempfile::tempdir().unwrap();let process=Arc::new(ScopeProcess::new(scope(),[3;16],super::BootIdentity::generate().unwrap(),std::fs::File::open(root.path()).unwrap()).unwrap());
        let policy=super::ScopePolicy::new(vec![super::PrincipalGrant::new(SpiffeId::new(ISSUER).unwrap(),super::ScopeRole::Controller,vec![scope()]).unwrap()]).unwrap();
        let responder=BootProofResponder::new(process.clone(),SpiffeId::new(ISSUER).unwrap(),policy.clone(),Arc::new(Clock),token_source.clone(),server,super::ProofBudgets::default()).unwrap();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let enrollment=PodEnrollment::new(scope(),"test".into(),"worker-0".into(),"worker".into(),[6;16],"worker".into(),[4;16],SpiffeId::new(WORKER).unwrap(),address.port()).unwrap();
        let issuer_clock=Arc::new(IssuerClock(AtomicI64::new(0)));
        let api=Arc::new(Api{address:Mutex::new(Some(address)),clock:issuer_clock.clone(),expire_on_recheck:scenario==Scenario::ExpiresWhileReading,reads:AtomicUsize::new(0),observe_error:match scenario { Scenario::ProbePlatformInvalid=>Some(PlatformError::Invalid), Scenario::ProbePlatformChanged=>Some(PlatformError::Changed), Scenario::ProbePlatformUnavailable=>Some(PlatformError::Unavailable), _=>None }, revalidate_error:Mutex::new(None), revalidate_container_id:Mutex::new(None),revalidate_revision:Mutex::new(None)});
        let reader=Arc::new(KubernetesBootReader::new(api.clone()));
        let issuer=BootstrapIssuerClient::new(client,issuer_clock.clone(),credentials.clone(),reader.clone(),super::ProofBudgets::default()).unwrap();
        if matches!(scenario, Scenario::ProbePlatformInvalid | Scenario::ProbePlatformUnavailable | Scenario::ProbePlatformChanged) {
            let error = issuer.probe(&enrollment, BootstrapProofMode::Candidate).await.err().expect("probe must refuse the platform observation");
            let expected = match scenario { Scenario::ProbePlatformInvalid => StartupError::PlatformInvalid, Scenario::ProbePlatformChanged => StartupError::PlatformChanged, _ => StartupError::Unavailable };
            assert_eq!(error, expected, "probe must preserve the platform failure class");
            return;
        }
        if scenario==Scenario::ProbeRevalidationFailures {
            for (platform, expected) in [
                (PlatformError::Invalid, StartupError::PlatformInvalid),
                (PlatformError::Changed, StartupError::PlatformChanged),
                (PlatformError::Unavailable, StartupError::Unavailable),
            ] {
                api.reads.store(0, Ordering::Release);
                *api.revalidate_error.lock().unwrap()=Some(platform);
                let (verified, worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
                assert_eq!(verified.err(),Some(expected),"the second platform read inside probe preserves its class");
                assert_eq!(api.reads.load(Ordering::Acquire),2,"the initial observation and authenticated proof precede revalidation");
                drop(worker.unwrap());
                assert!(process.enter_peer_control().await.is_err());
                *api.revalidate_error.lock().unwrap()=None;
                api.reads.store(0, Ordering::Release);
                let (verified, worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
                let verified=verified.expect("reconciliation permits a fresh probe of the same boot");
                assert_eq!(verified.proof().process_nonce(),process.boot().process_nonce());
                assert_eq!(api.reads.load(Ordering::Acquire),2);
                assert!(process.enter_peer_control().await.is_err(),"proof recovery confers no admission");
                drop(worker.unwrap());
            }
            return;
        }
        let probe_mode=if scenario==Scenario::RefuseOnLiveness {BootstrapProofMode::Liveness} else {BootstrapProofMode::Candidate};
        let (verified,worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,probe_mode),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
        let worker=worker.unwrap();
        if scenario==Scenario::RefuseOnLiveness {
            let verified=verified.expect("liveness proof");
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            assert_eq!(verified.deliver_boot_refusal(super::BootRefusalReason::PrerequisiteRefused,deadline).await.err(),Some(StartupError::Invalid),"a liveness startup session cannot carry a candidate boot refusal");
            assert!(process.enter_peer_control().await.is_err());
            return;
        }
        if scenario==Scenario::ExpiresWhileReading {
            assert!(matches!(verified,Err(StartupError::AuthTimeUnavailable)),"JWT expiry after independent Pod read must refuse startup with a retryable authentication-time result");
            assert!(process.enter_peer_control().await.is_err());
            return;
        }
        let verified=verified.unwrap();assert_eq!(verified.proof().workload(),&[3;16]);assert_eq!(verified.proof().process_nonce(),process.boot().process_nonce());assert_eq!(verified.proof().boot_key_digest(),process.boot().key_digest());
        assert!(verified.proof().is_candidate());
        if scenario==Scenario::RefreshCredentialFailures {
            drop(verified);
            drop(worker);
            for (key_byte, failure, expected) in [
                (2, BootstrapCredentialError::UnsupportedPrerequisite, StartupError::PrerequisiteRefused),
                (3, BootstrapCredentialError::Unavailable, StartupError::Unavailable),
                (4, BootstrapCredentialError::Rejected, StartupError::Unauthorized),
            ] {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let rotated = SigningKey::from_slice(&[key_byte;32]).unwrap();
                let signature: Signature = rotated.sign(input.as_bytes());
                *token_source.0.lock().unwrap() = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())).into_bytes();
                *key_source.response.lock().unwrap() = Err(failure);
                let before = key_source.reads.load(Ordering::SeqCst);
                for _ in 0..2 {
                    let (verified, worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
                    assert_eq!(verified.err(),Some(expected),"live issuer preserves the failed refresh classification");
                    drop(worker.unwrap());
                    assert!(process.enter_peer_control().await.is_err());
                }
                assert_eq!(key_source.reads.load(Ordering::SeqCst), before+1, "one shared refresh attempt per interval");
                let point=rotated.verifying_key().to_sec1_point(false);
                *key_source.response.lock().unwrap() = Ok(serde_json::to_vec(&json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"one","x":URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),"y":URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..])}]})).unwrap());
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let (verified,worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
                let verified=verified.expect("a later rotated-key refresh recovers without changing the boot");
                assert_eq!(verified.proof().process_nonce(),process.boot().process_nonce());
                assert_eq!(key_source.reads.load(Ordering::SeqCst), before+2);
                drop(worker.unwrap());
            }
            return;
        }
        if scenario==Scenario::RefuseAfterNotice {
            use tokio::io::AsyncWriteExt;
            let mut verified = verified;
            let entries = (1..=8).map(|ordinal| {
                let mut hint = predecessor_snapshot(false).entry;
                // These are opaque staging hints; no authority is inferred.
                hint.predecessor = vec![ordinal];
                hint
            }).collect();
            let page = super::notice::NoticePage {
                notice_id: [0x72; 16],
                boot: super::notice::NoticeBoot { scope: scope(), workload: [3;16], process: *process.boot().process_nonce(), key: process.boot().key_digest() },
                generation: 128,
                authority: super::wire::AuthorityReference { record_uid: b"issuer-record-uid".to_vec(), revision: b"opaque:0042".to_vec() },
                total: 9,
                first: 0,
                entries,
            };
            let mut body = verified.nonce.to_vec();
            body.extend_from_slice(&page.encode().unwrap());
            let header = verified.header.response(super::wire::FrameKind::TicketNotice, body.len()).unwrap();
            let refusal = super::refusal::encode_payload(&verified.nonce, process.boot().process_nonce(), &process.boot().key_digest(), super::BootRefusalReason::PlatformChanged);
            let refusal_header = super::refusal::refusal_header(&verified.header, refusal.len()).unwrap();
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let mut staged = 0;
            let (sent, received) = tokio::join!(async {
                verified.connection.write_all(&header.encode().unwrap()).await.unwrap();
                verified.connection.write_all(&body).await.unwrap();
                verified.connection.write_all(&refusal_header.encode().unwrap()).await.unwrap();
                verified.connection.write_all(&refusal).await.unwrap();
                verified.connection.flush().await.unwrap();
            }, worker.receive_ticket_notice(deadline, |_| { staged += 1; Ok(()) }));
            let () = sent;
            assert_eq!(staged, 8, "the first valid partial page reached the staging callback");
            assert_eq!(received.err(), Some(StartupError::Invalid), "a refusal is legal only as the first and sole response");
            assert!(process.enter_peer_control().await.is_err());
            return;
        }
        if scenario==Scenario::RevalidatePlatformChanged {
            *api.revalidate_error.lock().unwrap()=Some(PlatformError::Changed);
            assert_eq!(verified.revalidate().await.unwrap_err(),StartupError::PlatformChanged,"retained-session revalidation must preserve the changed-observation class");
            for (platform, expected) in [(PlatformError::Invalid, StartupError::PlatformInvalid), (PlatformError::Unavailable, StartupError::Unavailable)] {
                *api.revalidate_error.lock().unwrap()=Some(platform);
                assert_eq!(verified.revalidate().await.err(),Some(expected));
            }
            *api.revalidate_error.lock().unwrap()=None;
            verified.revalidate().await.expect("a reconciled observation is accepted on a later attempt");
            return;
        }
        if matches!(scenario, Scenario::RefusePlatformInvalid | Scenario::RefusePrerequisite) {
            let reason = if scenario == Scenario::RefusePlatformInvalid { super::BootRefusalReason::PlatformInvalid } else { super::BootRefusalReason::PrerequisiteRefused };
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let (sent, received)=tokio::join!(verified.deliver_boot_refusal(reason, deadline),worker.receive_ticket_notice(deadline, |_|Err(StartupError::Invalid)));
            sent.unwrap();
            assert_eq!(received.err(),Some(StartupError::BootRefused(reason)));
            assert!(process.enter_peer_control().await.is_err());
            return;
        }
        if scenario==Scenario::RevisionOnlyChange {
            *api.revalidate_revision.lock().unwrap()=Some("43".into());
            assert_eq!(verified.revalidate().await.err(),Some(StartupError::PlatformChanged));
            drop(verified);
            drop(worker);
            let (verified,worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
            let verified=verified.expect("re-probe the unchanged boot at the newer platform revision");
            assert_eq!(verified.proof().process_nonce(),process.boot().process_nonce());
            assert_eq!(verified.proof().boot_key_digest(),process.boot().key_digest());
            let notice=super::IssuedTicketNotice::new(128,b"issuer-record-uid".to_vec(),b"opaque:0043".to_vec(),0).unwrap();
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let (sent,received)=tokio::join!(verified.deliver_ticket_notice(notice,&NoPredecessors,deadline),worker.unwrap().receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)));
            sent.unwrap();
            assert_eq!(received.unwrap().generation(),128);
            assert!(process.enter_peer_control().await.is_err());
            return;
        }
        if scenario==Scenario::DeliverPlatformFailures {
            drop(verified);
            drop(worker);
            for (platform,expected) in [(PlatformError::Invalid,StartupError::PlatformInvalid),(PlatformError::Changed,StartupError::PlatformChanged),(PlatformError::Unavailable,StartupError::Unavailable)] {
                *api.revalidate_error.lock().unwrap()=None;
                let (verified,worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder.respond_once(stream).await})}).await.unwrap();
                let verified=verified.unwrap();
                *api.revalidate_error.lock().unwrap()=Some(platform);
                let notice=super::IssuedTicketNotice::new(128,b"issuer-record-uid".to_vec(),b"opaque:0042".to_vec(),0).unwrap();
                let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
                let (sent,received)=tokio::join!(verified.deliver_ticket_notice(notice,&NoPredecessors,deadline),worker.unwrap().receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)));
                assert_eq!(sent.err(),Some(expected));
                assert_eq!(received.err(),Some(StartupError::Unavailable),"an absent notice does not turn the issuer's local failure into a boot refusal");
                assert!(process.enter_peer_control().await.is_err());
            }
            return;
        }
        if scenario==Scenario::RefuseAfterChangedFacts {
            // The proof observed the preceding container; the platform record
            // catches up on the retained-session revalidation.
            *api.revalidate_container_id.lock().unwrap()=Some("cri-o://restarted".to_string());
            assert_eq!(verified.revalidate().await.unwrap_err(),StartupError::PlatformChanged,"updated container facts after the proof are definitive");
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let (sent,received)=tokio::join!(verified.deliver_boot_refusal(super::BootRefusalReason::PlatformChanged,deadline),worker.receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)));
            sent.expect("authenticated refusal delivery");
            assert_eq!(received.err(),Some(StartupError::BootRefused(super::BootRefusalReason::PlatformChanged)),"the worker receives the closed typed reason");
            assert!(process.enter_peer_control().await.is_err(),"a refusal grants no authority");
            return;
        }
        if scenario==Scenario::LostRefusalStaysUnavailable {
            // The issuer connection disappears without a complete refusal.
            drop(verified);
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            assert_eq!(worker.receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)).await.err(),Some(StartupError::Unavailable),"a lost refusal stays unavailable");
            assert!(process.enter_peer_control().await.is_err());
            return;
        }
        if scenario==Scenario::RefuseThenFreshBootTickets {
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let (sent,received)=tokio::join!(verified.deliver_boot_refusal(super::BootRefusalReason::PlatformChanged,deadline),worker.receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)));
            sent.expect("first boot refusal");
            assert_eq!(received.err(),Some(StartupError::BootRefused(super::BootRefusalReason::PlatformChanged)));
            assert!(process.enter_peer_control().await.is_err());
            // A fresh boot (new process nonce and boot key) completes normally.
            let previous_process_nonce = *process.boot().process_nonce();
            let previous_key_digest = process.boot().key_digest();
            drop(responder);
            drop(process);
            let client_next=TlsConfigBuilder::new(client_rx_next).with_policy(PeerPolicy{allowed_instances:Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),..Default::default()}).build_authenticated_client_config().unwrap();
            let server_next=TlsConfigBuilder::new(server_rx_next).with_policy(PeerPolicy{allowed_instances:Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])),..Default::default()}).build_authenticated_server_config().unwrap();
            let process_next=Arc::new(ScopeProcess::new(scope(),[3;16],super::BootIdentity::generate().unwrap(),std::fs::File::open(root.path()).unwrap()).unwrap());
            let responder_next=BootProofResponder::new(process_next.clone(),SpiffeId::new(ISSUER).unwrap(),policy.clone(),Arc::new(Clock),Arc::new(Token(token.clone())),server_next,super::ProofBudgets::default()).unwrap();
            let issuer_next=BootstrapIssuerClient::new(client_next,issuer_clock.clone(),credentials.clone(),reader.clone(),super::ProofBudgets::default()).unwrap();
            let (verified,worker)=tokio::time::timeout(std::time::Duration::from_secs(5),async{tokio::join!(issuer_next.probe(&enrollment,BootstrapProofMode::Candidate),async {let (stream,_)=listener.accept().await.unwrap();responder_next.respond_once(stream).await})}).await.unwrap();
            let verified=verified.expect("fresh boot candidate proof");let worker=worker.expect("fresh boot responder");
            assert_ne!(verified.proof().process_nonce(),&previous_process_nonce,"a fresh boot has a fresh process nonce");
            assert_ne!(verified.proof().boot_key_digest(),previous_key_digest,"a fresh boot has a fresh key");
            let notice=super::IssuedTicketNotice::new(128,b"issuer-record-uid".to_vec(),b"opaque:0042".to_vec(),0).unwrap();
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let (sent,received)=tokio::join!(verified.deliver_ticket_notice(notice,&NoPredecessors,deadline),worker.receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)));
            sent.expect("fresh boot ticket");
            let ticket=received.expect("the fresh boot receives a ticket");
            assert_eq!(ticket.generation(),128);
            assert!(process_next.enter_peer_control().await.is_err(),"the notice is a hint, not admission");
            return;
        }
        if scenario==Scenario::ExpiredBeforeIssuance {
            verified.revalidate().await.unwrap();
            issuer_clock.0.store(120,Ordering::Release);
            assert!(matches!(verified.revalidate().await,Err(StartupError::AuthTimeUnavailable)),"a retained proof must not outlive its bootstrap credential before issuance");
            issuer_clock.0.store(0,Ordering::Release);
            verified.revalidate().await.unwrap();
            assert!(process.enter_peer_control().await.is_err());
            issuer_clock.0.store(120,Ordering::Release);
            let notice=super::IssuedTicketNotice::new(128,b"issuer-record-uid".to_vec(),b"opaque:0042".to_vec(),0).unwrap();
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
            let (sent,received)=tokio::join!(verified.deliver_ticket_notice(notice,&NoPredecessors,deadline),worker.receive_ticket_notice(deadline,|_|Err(StartupError::Invalid)));
            assert_eq!(sent.err(),Some(StartupError::AuthTimeUnavailable));
            assert_eq!(received.err(),Some(StartupError::Unavailable));
            return;
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

#[cfg(target_os = "linux")]
#[path = "issuer_linux_clock_tests.rs"]
mod linux_clock;

// Exercise the actual startup boundary for a process admitted by the native
// authority fixture, retaining its caller-owned effect throughout this call.
#[cfg(all(feature = "test-control", target_os = "linux"))]
pub(crate) async fn assert_admitted_liveness_refusal(
    process: Arc<ScopeProcess>,
    worker_identity: SpiffeId,
    issuer_identity: SpiffeId,
    client: opc_tls::AuthenticatedClientConfig,
    server: opc_tls::AuthenticatedServerConfig,
) {
    drop(
        process
            .enter_peer_control()
            .await
            .expect("native worker is admitted"),
    );
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let jwks = serde_json::to_vec(&json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"one","x":URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),"y":URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..])}]})).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({"iss":"https://cluster.test","aud":["openpacketcore-scope-bootstrap"],"sub":"system:serviceaccount:test:worker","iat":now-60,"nbf":now-60,"exp":now+60,"kubernetes.io":{"namespace":"test","pod":{"name":"worker-0","uid":uuid::Uuid::from_bytes([3;16]).to_string()},"serviceaccount":{"name":"worker","uid":uuid::Uuid::from_bytes([6;16]).to_string()}}});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"one"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = key.sign(input.as_bytes());
    let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())).into_bytes();
    let credentials = Arc::new(
        BootstrapCredentialVerifier::activate(
            "https://cluster.test".into(),
            "https://cluster.test/openid/v1/jwks".into(),
            Arc::new(Keys(jwks)),
        )
        .await
        .unwrap(),
    );
    let policy = crate::scope::ScopePolicy::new(vec![crate::scope::PrincipalGrant::new(
        issuer_identity.clone(),
        crate::scope::ScopeRole::Controller,
        vec![process.scope().clone()],
    )
    .unwrap()])
    .unwrap();
    let responder = BootProofResponder::new(
        process.clone(),
        issuer_identity.clone(),
        policy,
        Arc::new(Clock),
        Arc::new(Token(token)),
        server,
        crate::scope::ProofBudgets::default(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let enrollment = PodEnrollment::new(
        process.scope().clone(),
        "test".into(),
        "worker-0".into(),
        "worker".into(),
        [6; 16],
        "worker".into(),
        [4; 16],
        worker_identity,
        address.port(),
    )
    .unwrap();
    let reader = Arc::new(KubernetesBootReader::new(Arc::new(Api {
        address: Mutex::new(Some(address)),
        clock: Arc::new(IssuerClock(AtomicI64::new(0))),
        expire_on_recheck: false,
        reads: AtomicUsize::new(0),
        observe_error: None,
        revalidate_error: Mutex::new(None),
        revalidate_container_id: Mutex::new(None),
        revalidate_revision: Mutex::new(None),
    })));
    let issuer = BootstrapIssuerClient::new(
        client,
        Arc::new(Clock),
        credentials,
        reader,
        crate::scope::ProofBudgets::default(),
    )
    .unwrap();
    let (verified, worker) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            issuer.probe(&enrollment, BootstrapProofMode::Liveness),
            async {
                let (stream, _) = listener.accept().await.unwrap();
                responder.respond_once(stream).await
            }
        )
    })
    .await
    .unwrap();
    let verified = verified.expect("admitted worker proves its live boot");
    let _worker = worker.unwrap();
    assert!(!verified.proof().is_candidate());
    assert_eq!(
        verified.proof().process_nonce(),
        process.boot().process_nonce()
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    assert_eq!(
        verified
            .deliver_boot_refusal(super::BootRefusalReason::PrerequisiteRefused, deadline)
            .await
            .err(),
        Some(StartupError::Invalid),
        "candidate refusal cannot cross an admitted worker's liveness boundary",
    );
    drop(
        process
            .enter_peer_control()
            .await
            .expect("refusal cannot revoke admission"),
    );
}
