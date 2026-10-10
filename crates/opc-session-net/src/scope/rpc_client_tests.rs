use super::{
    startup_tests::{material, Clock, ISSUER, WORKER},
    wire::{CallPayload, FrameKind, Header, HEADER_BYTES},
    *,
};
use futures_util::FutureExt;
use opc_session_store::{
    consensus::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity,
    },
    scope_authority::{ScopeExecution, ScopeId},
    scope_scheduler::{ScopeSchedulerOwner, ScopeWorkClass},
    SessionConsumerIdentity,
};
use opc_tls::{PeerPolicy, TlsConfigBuilder};
use opc_types::{InstanceId, NetworkFunctionKind, SpiffeId, TenantId};
use std::{collections::HashSet, fs::File, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn receive_call(
    connection: &mut opc_tls::ScopeTlsConnection<TcpStream>,
) -> (Header, CallPayload) {
    let mut bytes = [0; HEADER_BYTES];
    connection.read_exact(&mut bytes).await.unwrap();
    let header = Header::decode(&bytes).unwrap();
    assert_eq!(header.kind, FrameKind::Call);
    let mut body = vec![0; header.payload_len];
    connection.read_exact(&mut body).await.unwrap();
    let payload = CallPayload::decode(header.method, &body).unwrap();
    (header, payload)
}

struct NoPublication;
#[async_trait::async_trait]
impl ScopeLocalClosurePublisher for NoPublication {
    async fn publish(&self, _: &LocalClosurePublication) -> Result<(), ScopeEvidenceError> {
        Err(ScopeEvidenceError::Unavailable)
    }
}

#[test]
fn preproof_and_start_refusals_retain_the_same_resident_request() {
    const CHILD: &str = "OPC_SCOPE_START_REFUSAL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scope::rpc_client_tests::preproof_and_start_refusals_retain_the_same_resident_request",
                "--nocapture",
            ])
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
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let identity = SessionConsensusIdentity::new(
                SessionConsensusClusterId::from_bytes([1; 32]),
                SessionConsensusConfigurationId::from_bytes([2; 32]),
                SessionConsensusConfigurationEpoch::new(1).unwrap(),
            );
            let scope = ScopeId::new(
                identity,
                TenantId::new("test").unwrap(),
                NetworkFunctionKind::new("smf").unwrap(),
                [3; 32],
            )
            .unwrap();
            let binding = ScopeBinding::from_scope(&scope).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let process = Arc::new(
                ScopeProcess::new(
                    binding.clone(),
                    [4; 16],
                    BootIdentity::generate().unwrap(),
                    File::open(directory.path()).unwrap(),
                )
                .unwrap(),
            );
            let execution = ScopeExecution::new(
                SessionConsumerIdentity::new(WORKER).unwrap(),
                1,
                [4; 16],
                *process.boot().process_nonce(),
                process.boot().key_digest(),
            )
            .unwrap();
            let record = BootAuthorityRecord::new(
                binding.clone(),
                execution,
                *process.boot().public_key(),
                b"record".to_vec(),
                b"revision".to_vec(),
            )
            .unwrap();
            let mut parameters = rcgen::CertificateParams::default();
            parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = rcgen::CertifiedIssuer::self_signed(
                parameters,
                rcgen::KeyPair::generate().unwrap(),
            )
            .unwrap();
            let (_source, receive) = tokio::sync::watch::channel(Some(material(WORKER, &ca)));
            let tls = TlsConfigBuilder::new(receive)
                .with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])),
                    ..Default::default()
                })
                .build_authenticated_client_config()
                .unwrap();
            let (_server_source, receive) =
                tokio::sync::watch::channel(Some(material(ISSUER, &ca)));
            let server_tls = TlsConfigBuilder::new(receive)
                .with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),
                    ..Default::default()
                })
                .build_authenticated_server_config()
                .unwrap();
            let listener = Arc::new(
                TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap(),
            );
            let owner = ScopeSchedulerOwner::default();
            let scheduler = owner.scheduler();
            let client = ScopeClient::new(ScopeClientConfig {
                ticket: BootTicket::from_authority_record(&process, &record).unwrap(),
                process: process.clone(),
                scope,
                tls,
                server: SpiffeId::new(ISSUER).unwrap(),
                addresses: [listener.local_addr().unwrap(); 5],
                clock: Arc::new(Clock),
                scheduler: scheduler.clone(),
                local_closure: Arc::new(NoPublication),
            })
            .unwrap();
            let request = Arc::new(client.prepare_initial().await.unwrap());
            let canonical = request.request().encode_canonical().unwrap();
            let peer = listener.clone();
            let peer_tls = server_tls.clone();
            let domain = binding.tls_domain().unwrap();
            let closed = tokio::spawn(async move {
                let mut calls = Vec::new();
                // Neither connection receives a challenge, so no proof can leave.
                for _ in 0..2 {
                    let (socket, _) = peer.accept().await.unwrap();
                    let mut connection = peer_tls
                        .begin_handshake()
                        .unwrap()
                        .accept_scope(socket, domain.clone())
                        .await
                        .unwrap();
                    calls.push(receive_call(&mut connection).await);
                }
                calls
            });
            assert!(
                matches!(
                    tokio::time::timeout(
                        Duration::from_secs(10),
                        client.submit(&request, Duration::from_secs(5))
                    )
                    .await
                    .unwrap(),
                    Err(ScopeRpcError::Retry)
                ),
                "two pre-proof EOFs cannot imply submission"
            );
            let calls = tokio::time::timeout(Duration::from_secs(10), closed)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(calls.len(), 2, "one transparent reconnect only");
            assert!(
                listener.accept().now_or_never().is_none(),
                "no third connection is attempted"
            );
            assert!(calls[0].0.matches_attempt(&calls[1].0));
            assert_ne!(
                calls[0].1.nonce, calls[1].1.nonce,
                "reconnect has a fresh channel attempt"
            );
            for (_, payload) in calls {
                assert_eq!(payload.canonical, canonical);
            }

            let submitted = client.clone();
            let pending = request.clone();
            let timed =
                tokio::spawn(
                    async move { submitted.submit(&pending, Duration::from_secs(5)).await },
                );
            let (socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut stalled = server_tls
                .begin_handshake()
                .unwrap()
                .accept_scope(socket, binding.tls_domain().unwrap())
                .await
                .unwrap();
            let (_, payload) = receive_call(&mut stalled).await;
            assert_eq!(payload.canonical, canonical);
            // Handshake and call delivery are complete before virtual time moves.
            // The server withholds the challenge throughout the client's deadline.
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(6)).await;
            let result = timed.await.unwrap();
            tokio::time::resume();
            assert!(
                matches!(result, Err(ScopeRpcError::Retry)),
                "a pre-proof deadline is proven no submission"
            );
            drop(stalled);
            owner.close();
            for _ in 0..2 {
                assert!(matches!(
                    client.submit(&request, Duration::from_secs(1)).await,
                    Err(ScopeRpcError::Retry)
                ));
                let retained = scheduler.snapshot().class(ScopeWorkClass::SafetyControl);
                assert_eq!(
                    (retained.resident, retained.running),
                    (1, 0),
                    "a refused start must return the original resident entitlement"
                );
                assert_eq!(request.request().encode_canonical().unwrap(), canonical);
                assert!(process.enter_peer_control().await.is_err());
            }
            drop(request);
            assert_eq!(
                scheduler
                    .snapshot()
                    .class(ScopeWorkClass::SafetyControl)
                    .resident,
                0,
                "dropping the retained request releases its one entitlement"
            );
        });
}

#[test]
fn deadline_after_proof_transmission_stays_outcome_unknown() {
    const CHILD: &str = "OPC_SCOPE_PROOF_DEADLINE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scope::rpc_client_tests::deadline_after_proof_transmission_stays_outcome_unknown",
                "--nocapture",
            ])
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
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let identity = SessionConsensusIdentity::new(
                SessionConsensusClusterId::from_bytes([1; 32]),
                SessionConsensusConfigurationId::from_bytes([2; 32]),
                SessionConsensusConfigurationEpoch::new(1).unwrap(),
            );
            let scope = ScopeId::new(
                identity,
                TenantId::new("test").unwrap(),
                NetworkFunctionKind::new("smf").unwrap(),
                [3; 32],
            )
            .unwrap();
            let binding = ScopeBinding::from_scope(&scope).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let process = Arc::new(
                ScopeProcess::new(
                    binding.clone(),
                    [4; 16],
                    BootIdentity::generate().unwrap(),
                    File::open(directory.path()).unwrap(),
                )
                .unwrap(),
            );
            let execution = ScopeExecution::new(
                SessionConsumerIdentity::new(WORKER).unwrap(),
                1,
                [4; 16],
                *process.boot().process_nonce(),
                process.boot().key_digest(),
            )
            .unwrap();
            let record = BootAuthorityRecord::new(
                binding.clone(),
                execution,
                *process.boot().public_key(),
                b"record".to_vec(),
                b"revision".to_vec(),
            )
            .unwrap();
            let mut parameters = rcgen::CertificateParams::default();
            parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = rcgen::CertifiedIssuer::self_signed(
                parameters,
                rcgen::KeyPair::generate().unwrap(),
            )
            .unwrap();
            let (_source, receive) = tokio::sync::watch::channel(Some(material(WORKER, &ca)));
            let tls = TlsConfigBuilder::new(receive)
                .with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])),
                    ..Default::default()
                })
                .build_authenticated_client_config()
                .unwrap();
            let (_server_source, receive) =
                tokio::sync::watch::channel(Some(material(ISSUER, &ca)));
            let server_tls = TlsConfigBuilder::new(receive)
                .with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),
                    ..Default::default()
                })
                .build_authenticated_server_config()
                .unwrap();
            let listener = Arc::new(
                TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap(),
            );
            let owner = ScopeSchedulerOwner::default();
            let scheduler = owner.scheduler();
            let client = ScopeClient::new(ScopeClientConfig {
                ticket: BootTicket::from_authority_record(&process, &record).unwrap(),
                process: process.clone(),
                scope,
                tls,
                server: SpiffeId::new(ISSUER).unwrap(),
                addresses: [listener.local_addr().unwrap(); 5],
                clock: Arc::new(Clock),
                scheduler: scheduler.clone(),
                local_closure: Arc::new(NoPublication),
            })
            .unwrap();
            let request = Arc::new(client.prepare_initial().await.unwrap());
            let canonical = request.request().encode_canonical().unwrap();
            let submitted = client.clone();
            let pending = request.clone();
            let timed =
                tokio::spawn(
                    async move { submitted.submit(&pending, Duration::from_secs(30)).await },
                );
            let peer = tokio::time::timeout(Duration::from_secs(10), async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut peer = server_tls
                    .begin_handshake()
                    .unwrap()
                    .accept_scope(socket, binding.tls_domain().unwrap())
                    .await
                    .unwrap();
                let (call, payload) = receive_call(&mut peer).await;
                assert_eq!(payload.canonical, canonical);
                let challenge = call.response(FrameKind::Challenge, 32).unwrap();
                peer.write_all(&challenge.encode().unwrap()).await.unwrap();
                peer.write_all(&[71; 32]).await.unwrap();
                peer.flush().await.unwrap();
                let mut fixed = [0; HEADER_BYTES];
                peer.read_exact(&mut fixed).await.unwrap();
                let proof = Header::decode(&fixed).unwrap();
                assert_eq!(proof.kind, FrameKind::Proof);
                assert!(proof.matches_attempt(&call));
                let mut bytes = vec![0; proof.payload_len];
                peer.read_exact(&mut bytes).await.unwrap();
                super::proof::PossessionProof::decode(&bytes).unwrap();
                peer
            })
            .await
            .expect("the peer receives the complete possession proof");
            assert!(!timed.is_finished(), "the peer has withheld the result");
            // Only advance time after actual TLS delivery. Keep the peer open:
            // EOF would report uncertainty without exercising the deadline flag.
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(31)).await;
            let result = timed.await.unwrap();
            tokio::time::resume();
            assert!(
                matches!(result, Err(ScopeRpcError::OutcomeUnknown)),
                "a deadline after the proof left must retain uncertainty"
            );
            assert!(
                listener.accept().now_or_never().is_none(),
                "no reconnect after proof transmission"
            );
            assert_eq!(request.request().encode_canonical().unwrap(), canonical);
            drop(peer);
            owner.close();
        });
}
