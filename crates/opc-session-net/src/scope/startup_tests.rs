use super::{boot::BootIdentity, clock::*, policy::*, proof::*, startup::*, wire::*};
use opc_identity::{build_identity_state, IdentityState, TrustBundle, TrustBundleSet, TrustDomain};
use opc_tls::{AuthenticationTimeInterval, PeerPolicy, TlsConfigBuilder};
use opc_types::{InstanceId, NetworkFunctionKind, SpiffeId, TenantId, Timestamp};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashSet;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};
pub(super) const ISSUER: &str =
    "spiffe://example.test/tenant/test/ns/test/sa/issuer/nf/smf/instance/issuer-0";
pub(super) const WORKER: &str =
    "spiffe://example.test/tenant/test/ns/test/sa/worker/nf/smf/instance/worker-0";
pub(super) fn scope() -> ScopeBinding {
    ScopeBinding::new(
        [1; 32],
        TenantId::new("test").unwrap(),
        NetworkFunctionKind::new("smf").unwrap(),
        [2; 32],
    )
    .unwrap()
}
pub(super) fn material(
    id: &str,
    ca: &rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
) -> IdentityState {
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(id).unwrap(),
    )];
    let key = rcgen::KeyPair::generate().unwrap();
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
pub(super) struct Clock;
impl AuthenticationClock for Clock {
    fn interval(&self) -> Result<AuthenticationTimeInterval, AuthenticationTimeError> {
        let now = Timestamp::from_offset_datetime(time::OffsetDateTime::now_utc());
        AuthenticationTimeInterval::new(now, now).map_err(|_| AuthenticationTimeError)
    }
}
struct Token(AtomicUsize);
#[async_trait::async_trait]
impl BootstrapCredentialSource for Token {
    async fn read(&self) -> Result<BootstrapCredential, StartupError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BootstrapCredential::new(b"synthetic.bootstrap.test-token".to_vec())
    }
}
fn call(mode: StartupMode) -> (Header, CallPayload, StartupRequest) {
    let request = StartupRequest {
        scope: scope(),
        workload: [3; 16],
        observation: [4; 32],
        challenge: [5; 32],
    };
    let body = request.encode().unwrap();
    let payload = CallPayload {
        nonce: [6; 32],
        canonical: body.clone(),
    };
    let header = Header {
        kind: FrameKind::Call,
        class: Class::SafetyControl,
        method: mode.method(),
        installation: [1; 32],
        scope: scope().commitment(),
        request_id: [7; 16],
        digest: transport_request_digest(mode.method(), &[7; 16], &body).unwrap(),
        payload_len: payload.encode(mode.method()).unwrap().len(),
    };
    (header, payload, request)
}
#[test]
fn startup_responder_real_tls_guards_issuer_token_key_and_candidate_exclusion() {
    const CHILD: &str = "OPC_SCOPE_STARTUP_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let out=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","scope::startup_tests::startup_responder_real_tls_guards_issuer_token_key_and_candidate_exclusion","--nocapture"])
            .env(CHILD,"1").output().unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
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
            assert!(matches!(
                ScopeProcess::new(
                    scope(),
                    [3; 16],
                    BootIdentity::generate().unwrap(),
                    std::fs::File::open(root.path()).unwrap()
                ),
                Err(StartupError::ExclusionBusy)
            ));
            let mut ca_params = rcgen::CertificateParams::default();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca =
                rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap())
                    .unwrap();
            let (_client_source, client_rx) = watch::channel(Some(material(ISSUER, &ca)));
            let (_server_source, server_rx) = watch::channel(Some(material(WORKER, &ca)));
            let client = TlsConfigBuilder::new(client_rx)
                .with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),
                    ..Default::default()
                })
                .build_authenticated_client_config()
                .unwrap();
            let server = TlsConfigBuilder::new(server_rx)
                .with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])),
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
                super::pool::ProofBudgets::default(),
            )
            .unwrap();
            for mode in [StartupMode::Liveness, StartupMode::Candidate] {
                let (header, payload, request) = call(mode);
                let (client_io, server_io) = tokio::io::duplex(16384);
                let (proof, responder_result) =
                    tokio::time::timeout(Duration::from_secs(5), async {
                        tokio::join!(
                            async {
                                let mut stream = client
                                    .begin_handshake()
                                    .unwrap()
                                    .connect_scope(client_io, scope().tls_domain().unwrap())
                                    .await
                                    .unwrap();
                                stream.write_all(&header.encode().unwrap()).await.unwrap();
                                stream
                                    .write_all(&payload.encode(mode.method()).unwrap())
                                    .await
                                    .unwrap();
                                stream.flush().await.unwrap();
                                let mut bytes = [0; 128];
                                stream.read_exact(&mut bytes).await.unwrap();
                                let reply = Header::decode(&bytes).unwrap();
                                assert!(header.matches_attempt(&reply));
                                assert_eq!(reply.kind, FrameKind::Proof);
                                let mut body = vec![0; reply.payload_len];
                                stream.read_exact(&mut body).await.unwrap();
                                let proof = StartupProof::decode(&body).unwrap();
                                assert_eq!(proof.claims.scope, scope());
                                assert_eq!(proof.claims.workload, [3; 16]);
                                assert_eq!(proof.claims.process, *process.boot().process_nonce());
                                assert_eq!(proof.claims.public_key, *process.boot().public_key());
                                assert_eq!(proof.claims.mode, mode);
                                assert_eq!(proof.claims.challenge, request.challenge);
                                assert_eq!(
                                    &proof.claims.binding,
                                    stream
                                        .channel_binding(mode.purpose(), Clock.interval().unwrap())
                                        .unwrap()
                                        .as_bytes()
                                );
                                verify_signature(
                                    &proof.claims.public_key,
                                    &proof.claims.encode().unwrap(),
                                    &proof.signature,
                                )
                                .unwrap();
                                if mode == StartupMode::Candidate {
                                    let mut page = super::notice::NoticePage {
                                        notice_id: [8; 16],
                                        boot: super::notice::NoticeBoot {
                                            scope: scope(),
                                            workload: [3; 16],
                                            process: *process.boot().process_nonce(),
                                            key: process.boot().key_digest(),
                                        },
                                        generation: 1,
                                        authority: AuthorityReference::new(
                                            b"record-1".to_vec(),
                                            b"rv-9".to_vec(),
                                        )
                                        .unwrap(),
                                        total: 0,
                                        first: 0,
                                        entries: vec![],
                                    };
                                    page.notice_id = super::notice::NoticeCommitment::new(
                                        &page.boot,
                                        page.generation,
                                        &page.authority,
                                        0,
                                    )
                                    .unwrap()
                                    .finish()
                                    .unwrap();
                                    let mut bytes = payload.nonce.to_vec();
                                    bytes.extend_from_slice(&page.encode().unwrap());
                                    let notice = header
                                        .response(FrameKind::TicketNotice, bytes.len())
                                        .unwrap();
                                    stream.write_all(&notice.encode().unwrap()).await.unwrap();
                                    stream.write_all(&bytes).await.unwrap();
                                    stream.flush().await.unwrap();
                                }
                                proof
                            },
                            async {
                                let session = responder.respond_once(server_io).await?;
                                if mode == StartupMode::Candidate {
                                    let ticket = session
                                        .receive_ticket_notice(
                                            tokio::time::Instant::now() + Duration::from_secs(5),
                                            |_| Ok(()),
                                        )
                                        .await?;
                                    assert_eq!(ticket.generation(), 1);
                                    assert_eq!(ticket.authority_record_uid(), b"record-1");
                                }
                                Ok::<_, StartupError>(())
                            }
                        )
                    })
                    .await
                    .unwrap();
                responder_result.unwrap();
                assert_eq!(
                    proof.credential.as_slice(),
                    b"synthetic.bootstrap.test-token"
                );
            }
            assert_eq!(token.0.load(Ordering::SeqCst), 2);
            // Revoked issuers get no credential and no challenge/body allocation.
            policy.replace(vec![]).unwrap();
            let (header, _, _) = call(StartupMode::Candidate);
            let (client_io, server_io) = tokio::io::duplex(4096);
            let (_, result) = tokio::join!(
                async {
                    let mut stream = client
                        .begin_handshake()
                        .unwrap()
                        .connect_scope(client_io, scope().tls_domain().unwrap())
                        .await
                        .unwrap();
                    stream.write_all(&header.encode().unwrap()).await.unwrap();
                    stream.flush().await.unwrap();
                },
                responder.respond_once(server_io)
            );
            assert!(matches!(result, Err(StartupError::Unauthorized)));
            assert_eq!(token.0.load(Ordering::SeqCst), 2);
            assert!(process.enter_peer_control().await.is_err());
        });
}
