use super::*;
use crate::scope::{
    proof::PossessionClaims,
    rpc_server::NativeCall,
    startup_tests::{material, Clock, ISSUER, WORKER},
    BootAuthorityRecord, BootIdentity, BootTicket, ScopeProcess,
};
use futures_util::FutureExt;
use opc_session_store::{
    consensus::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity,
    },
    scope_batch::*,
    scope_scheduler::{ScopeSchedulerOwner, ScopeWorkClass},
};
use opc_tls::{PeerPolicy, TlsConfigBuilder};
use opc_types::{InstanceId, NetworkFunctionKind, SpiffeId, TenantId};
use serde_json::json;
use std::{
    collections::HashSet,
    fs::File,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

struct NoPublication;
#[async_trait::async_trait]
impl crate::scope::ScopeLocalClosurePublisher for NoPublication {
    async fn publish(
        &self,
        _: &LocalClosurePublication,
    ) -> Result<(), crate::scope::ScopeEvidenceError> {
        Err(crate::scope::ScopeEvidenceError::Unavailable)
    }
}

// A scripted authenticated peer, not a consensus or batch-state implementation.
// Its fixed before/after observations isolate the client ownership boundary.
struct Peer {
    mode: usize,
    scope: ScopeId,
    stamp: Mutex<Option<ScopeAuthorityStamp>>,
    receipt: Mutex<Option<ScopeBatchReceipt>>,
    applied: AtomicUsize,
    emergency_reopens: AtomicUsize,
    hold_reopen: AtomicBool,
    corrupt_lookup: AtomicBool,
    malformed_challenge: AtomicBool,
    preproof_refused: Notify,
    reopen_entered: Notify,
    reopen_release: Notify,
    entered: Notify,
    release: Notify,
}
impl Peer {
    async fn reopen(&self) -> ScopeBatchReopen {
        let stamp = self.stamp.lock().await.clone().unwrap();
        let receipt = self.receipt.lock().await.clone();
        let mut counters = [0_u64; 16];
        counters[0] = u64::from(receipt.is_some());
        let lanes = (0..8).map(|lane| {
            let own = receipt.as_ref().filter(|receipt| usize::from(receipt.attempt().lane()) == lane);
            json!({"sequence": u64::from(own.is_some()), "discarded_through": 0, "receipt": own})
        }).collect::<Vec<_>>();
        serde_json::from_value(json!({"Initialized": {
            "authority": {"scope": self.scope, "revision": 1, "retired_through": 0,
                "admission_generation_floor": 1, "stamp": stamp, "active": true, "closed_digest": null},
            "revision": u64::from(receipt.is_some()), "birth_floor": 0,
            "counters": counters, "lanes": lanes
        }})).unwrap()
    }

    async fn serve(self: Arc<Self>, mut connection: ScopeTlsConnection<TcpStream>, class: Class) {
        loop {
            let mut fixed = [0; HEADER_BYTES];
            if connection.read_exact(&mut fixed).await.is_err() {
                return;
            }
            let call = Header::decode(&fixed).unwrap();
            assert_eq!(
                call.class, class,
                "the physical listener carries the declared class"
            );
            let mut bytes = vec![0; call.payload_len];
            connection.read_exact(&mut bytes).await.unwrap();
            let payload = CallPayload::decode(call.method, &bytes).unwrap();
            let native = NativeCall::decode(&call, &payload.canonical, &self.scope).unwrap();
            let challenge = [71; 32];
            let malformed = self.malformed_challenge.swap(false, Ordering::AcqRel);
            let mut response = call.response(FrameKind::Challenge, 32).unwrap();
            if malformed {
                response.request_id[0] ^= 1;
            }
            connection
                .write_all(&response.encode().unwrap())
                .await
                .unwrap();
            connection.write_all(&challenge).await.unwrap();
            connection.flush().await.unwrap();
            if malformed {
                assert!(
                    connection.read_exact(&mut fixed).await.is_err(),
                    "a mismatched challenge must never receive a possession proof"
                );
                self.preproof_refused.notify_one();
                return;
            }
            connection.read_exact(&mut fixed).await.unwrap();
            let header = Header::decode(&fixed).unwrap();
            assert!(header.matches_attempt(&call));
            assert_eq!(header.kind, FrameKind::Proof);
            let mut bytes = vec![0; header.payload_len];
            connection.read_exact(&mut bytes).await.unwrap();
            let proof = PossessionProof::decode(&bytes).unwrap();
            let execution = native.execution().cloned().unwrap_or_else(|| {
                self.stamp
                    .try_lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .execution()
                    .clone()
            });
            let claims = PossessionClaims {
                call: call.clone(),
                caller_nonce: payload.nonce,
                execution: execution.transport_digest().unwrap(),
                public_key: proof.claims.public_key,
                authority: proof.claims.authority.clone(),
                challenge,
                binding: *connection
                    .channel_binding(
                        ChannelBindingPurpose::ScopeRequest,
                        crate::scope::AuthenticationClock::interval(&Clock).unwrap(),
                    )
                    .unwrap()
                    .as_bytes(),
            };
            assert_eq!(execution.boot_key(), &hash(&claims.public_key));
            proof.verify_against(&claims).unwrap();
            let (status, own, body) = match native {
                NativeCall::Authority(request) => {
                    let stamp: ScopeAuthorityStamp = serde_json::from_value(json!({
                        "namespace": ScopeNamespace::new(self.scope.clone(), ScopeIncarnation::new(1).unwrap()).unwrap(),
                        "revision": 1, "execution": request.operation().execution()
                    })).unwrap();
                    *self.stamp.lock().await = Some(stamp.clone());
                    let mut body = stamp.encode_canonical().unwrap();
                    body.push(1);
                    (
                        ResultStatus::Committed,
                        execution.transport_digest().unwrap(),
                        body,
                    )
                }
                NativeCall::BatchReopen(_) => {
                    let committed = self.receipt.lock().await.is_some();
                    if committed && self.hold_reopen.swap(false, Ordering::AcqRel) {
                        self.reopen_entered.notify_one();
                        self.reopen_release.notified().await;
                    }
                    if class == Class::Emergency {
                        self.emergency_reopens.fetch_add(1, Ordering::SeqCst);
                    }
                    (
                        ResultStatus::CurrentView,
                        [0; 32],
                        self.reopen().await.encode_canonical().unwrap(),
                    )
                }
                NativeCall::Batch(request) => {
                    assert_eq!(
                        self.applied.fetch_add(1, Ordering::SeqCst),
                        0,
                        "lost reply resolves without duplicate application"
                    );
                    let mut counters = [0_u64; 16];
                    counters[0] = 1;
                    let outcome: ScopeBatchOutcome = serde_json::from_value(json!({
                        "request_digest": request.digest().unwrap(), "lane": request.lane(),
                        "sequence": request.sequence(), "revision": 1, "rows": [], "counters": counters
                    })).unwrap();
                    assert!(outcome.matches_request(&request));
                    let receipt =
                        serde_json::from_value(json!({"attempt": request.attempt().unwrap(),
                        "revision": 1, "terminal": {"Applied": outcome}}))
                        .unwrap();
                    *self.receipt.lock().await = Some(receipt);
                    self.entered.notify_one();
                    self.release.notified().await;
                    if self.mode == 0 {
                        return; // Commit is observed by reopen, but its direct reply is lost.
                    }
                    let mut own = execution.transport_digest().unwrap();
                    let body = match self.mode {
                        1 => {
                            own[0] ^= 1;
                            outcome.encode_canonical().unwrap()
                        }
                        2 => vec![0],
                        3 => {
                            let mut value = serde_json::to_value(outcome).unwrap();
                            value["request_digest"] = serde_json::to_value([42_u8; 32]).unwrap();
                            serde_json::from_value::<ScopeBatchOutcome>(value)
                                .unwrap()
                                .encode_canonical()
                                .unwrap()
                        }
                        _ => unreachable!(),
                    };
                    (ResultStatus::Committed, own, body)
                }
                NativeCall::BatchLookup(target) => {
                    let mut lookup = self.reopen().await.lookup(&target).unwrap();
                    if self.corrupt_lookup.swap(false, Ordering::AcqRel) {
                        let mut value = serde_json::to_value(lookup).unwrap();
                        value["Applied"]["request_digest"] =
                            serde_json::to_value([42_u8; 32]).unwrap();
                        lookup = serde_json::from_value(value).unwrap();
                    }
                    (
                        ResultStatus::CurrentView,
                        [0; 32],
                        lookup.encode_canonical().unwrap(),
                    )
                }
                _ => panic!("unexpected scripted call"),
            };
            let body = ResultPayload::new(payload.nonce, status, own, body)
                .unwrap()
                .encode()
                .unwrap();
            connection
                .write_all(
                    &call
                        .response(FrameKind::Result, body.len())
                        .unwrap()
                        .encode()
                        .unwrap(),
                )
                .await
                .unwrap();
            connection.write_all(&body).await.unwrap();
            connection.flush().await.unwrap();
        }
    }
}

async fn assert_batch_signing_boundary(client: &ScopeClient, own: &ScopeAuthorityStamp) {
    let foreign_boot = BootIdentity::generate().unwrap();
    let foreign_execution = ScopeExecution::new(
        own.execution().identity().clone(),
        own.execution().admission_generation() + 1,
        [88; 16],
        *foreign_boot.process_nonce(),
        foreign_boot.key_digest(),
    )
    .unwrap();
    let mut value = serde_json::to_value(own).unwrap();
    value["execution"] = serde_json::to_value(foreign_execution).unwrap();
    let foreign: ScopeAuthorityStamp = serde_json::from_value(value).unwrap();
    let request = ScopeBatchRequest::in_lane(
        &foreign,
        [89; 16],
        0,
        1,
        Vec::new(),
        vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
    )
    .unwrap();
    let target = request.attempt().unwrap();
    let slot = client.0.connections[Class::Normal.index()].lock().await;
    let connection = &slot.as_ref().unwrap().stream;
    for (method, canonical, digest) in [
        (
            Method::ApplyBatch,
            request.encode_canonical().unwrap(),
            request.digest().unwrap(),
        ),
        (
            Method::BatchCancel,
            target.encode_canonical().unwrap(),
            target.cancellation_digest().unwrap(),
        ),
        (
            Method::BatchReopen,
            foreign.encode_canonical().unwrap(),
            [0; 32],
        ),
        (
            Method::BatchLookup,
            target.encode_canonical().unwrap(),
            [0; 32],
        ),
    ] {
        let id = *target.request_id();
        let read = matches!(method, Method::BatchReopen | Method::BatchLookup);
        let header = Header {
            kind: FrameKind::Call,
            class: Class::Normal,
            method,
            installation: *client.0.config.process.scope().installation(),
            scope: client.0.config.process.scope().commitment(),
            request_id: id,
            digest: if read {
                transport_request_digest(method, &id, &canonical).unwrap()
            } else {
                digest
            },
            payload_len: canonical.len() + 36,
        };
        let proof = client.0.config.process.boot().scope_proof(
            connection,
            crate::scope::AuthenticationClock::interval(&Clock).unwrap(),
            &client.0.config.scope,
            &client.0.execution,
            &header,
            [90; 32],
            &canonical,
            None,
            [91; 32],
            None,
        );
        if read {
            assert_eq!(
                proof.unwrap().claims.execution,
                own.execution().transport_digest().unwrap(),
                "a historical target is signed by the current caller, never its former boot"
            );
        } else {
            assert!(
                matches!(proof, Err(ScopeRpcError::Unauthorized)),
                "the typed boot signer cannot authorize another execution's apply or cancel"
            );
        }
    }
}

#[test]
fn authenticated_batch_reuses_one_reservation_and_resolves_a_lost_reply() {
    const CHILD: &str = "OPC_SCOPE_BATCH_CLIENT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        for mode in 0..4 {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "scope::rpc_client::batch_tests::authenticated_batch_reuses_one_reservation_and_resolves_a_lost_reply", "--nocapture"])
            .env(CHILD, mode.to_string()).output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            timeout(Duration::from_secs(10), async {
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
                        allowed_instances: Some(HashSet::from([
                            InstanceId::new("issuer-0").unwrap()
                        ])),
                        ..Default::default()
                    })
                    .build_authenticated_client_config()
                    .unwrap();
                let (_server_source, receive) =
                    tokio::sync::watch::channel(Some(material(ISSUER, &ca)));
                let server_tls = TlsConfigBuilder::new(receive)
                    .with_policy(PeerPolicy {
                        allowed_instances: Some(HashSet::from([
                            InstanceId::new("worker-0").unwrap()
                        ])),
                        ..Default::default()
                    })
                    .build_authenticated_server_config()
                    .unwrap();
                let peer = Arc::new(Peer {
                    mode: std::env::var(CHILD).unwrap().parse().unwrap(),
                    scope: scope.clone(),
                    stamp: Mutex::new(None),
                    receipt: Mutex::new(None),
                    applied: AtomicUsize::new(0),
                    emergency_reopens: AtomicUsize::new(0),
                    hold_reopen: AtomicBool::new(true),
                    corrupt_lookup: AtomicBool::new(false),
                    malformed_challenge: AtomicBool::new(false),
                    preproof_refused: Notify::new(),
                    reopen_entered: Notify::new(),
                    reopen_release: Notify::new(),
                    entered: Notify::new(),
                    release: Notify::new(),
                });
                let mut addresses = [std::net::SocketAddr::from(([127, 0, 0, 1], 9)); 5];
                let mut tasks = Vec::new();
                for class in [Class::SafetyControl, Class::Emergency, Class::Normal] {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    addresses[class.index()] = listener.local_addr().unwrap();
                    let tls = server_tls.clone();
                    let peer = peer.clone();
                    let domain = binding.tls_domain().unwrap();
                    tasks.push(tokio::spawn(async move {
                        loop {
                            let (socket, _) = listener.accept().await.unwrap();
                            let handshake = tls.begin_handshake().unwrap();
                            let peer = peer.clone();
                            let domain = domain.clone();
                            tokio::spawn(async move {
                                peer.serve(
                                    handshake.accept_scope(socket, domain).await.unwrap(),
                                    class,
                                )
                                .await;
                            });
                        }
                    }));
                }
                let owner = ScopeSchedulerOwner::default();
                let scheduler = owner.scheduler();
                let client = ScopeClient::new(ScopeClientConfig {
                    ticket: BootTicket::from_authority_record(&process, &record).unwrap(),
                    process,
                    scope,
                    tls,
                    server: SpiffeId::new(ISSUER).unwrap(),
                    addresses,
                    clock: Arc::new(Clock),
                    scheduler: scheduler.clone(),
                    local_closure: Arc::new(NoPublication),
                })
                .unwrap();
                let initial = client.prepare_initial().await.unwrap();
                let ScopeAuthorityReply::Admitted(authority) = client
                    .submit(&initial, Duration::from_secs(2))
                    .await
                    .unwrap()
                else {
                    panic!("admitted");
                };
                peer.malformed_challenge.store(true, Ordering::Release);
                assert_eq!(
                    client
                        .batches(&authority, ScopeWorkClass::Emergency, Duration::from_secs(2))
                        .await
                        .err(),
                    Some(ScopeBatchError::InvalidRequest),
                    "a malformed challenge before proof transmission cannot make an Emergency batch uncertain"
                );
                peer.preproof_refused.notified().await;
                let coordinator = client
                    .batches(&authority, ScopeWorkClass::Normal, Duration::from_secs(2))
                    .await
                    .expect("the authenticated client opens the shared batch coordinator");
                assert_batch_signing_boundary(&client, authority.stamp()).await;
                let handle = coordinator
                    .reserve_lane(0, ScopeWorkClass::Normal)
                    .await
                    .unwrap()
                    .submit(|context| async move {
                        context.request(
                            [72; 16],
                            Vec::new(),
                            vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
                        )
                    })
                    .await
                    .unwrap();
                peer.entered.notified().await;
                let snapshot = scheduler.snapshot().class(ScopeWorkClass::Normal);
                assert_eq!(
                    (snapshot.resident, snapshot.running),
                    (1, 1),
                    "transport must reuse the coordinator's sole reservation"
                );
                let waiting = coordinator.reserve_lane(0, ScopeWorkClass::Emergency);
                tokio::pin!(waiting);
                assert!(waiting.as_mut().now_or_never().is_none(), "the accepted Normal request still owns the lane");
                drop(handle);
                peer.release.notify_one();
                let mut completions = coordinator.completions();
                tokio::select! {
                    _ = peer.reopen_entered.notified() => {},
                    completion = completions.next() => panic!(
                        "an unverified committed reply cannot publish a terminal result: {:?}",
                        completion.outcome()
                    ),
                }
                assert_eq!(coordinator.lane_status()[0].last_error, Some(ScopeBatchError::OutcomeUnknown),
                    "lost and malformed committed replies remain uncertain until a fresh exact observation");
                assert!(coordinator.lane_status()[0].oldest_unacknowledged.is_none());
                let normal = scheduler.snapshot().class(ScopeWorkClass::Normal);
                let emergency = scheduler.snapshot().class(ScopeWorkClass::Emergency);
                // The Emergency waiter holds a resident credit while queued on shared lane 0.
                // The inherited retry still reuses the Normal resident descriptor.
                assert_eq!((normal.resident, normal.running, emergency.resident, emergency.running), (1, 0, 1, 1),
                    "inherited retry charges Emergency running capacity without allocating another resident descriptor");
                peer.reopen_release.notify_one();
                let completion = completions.next().await;
                assert!(matches!(
                    completion.outcome(),
                    ScopeBatchCompletionOutcome::Applied(_)
                ));
                assert_eq!(peer.applied.load(Ordering::SeqCst), 1);
                assert!(peer.emergency_reopens.load(Ordering::SeqCst) > 0,
                    "an Emergency waiter promotes the exact resolution retry onto its own TLS listener");
                let reopened = client
                    .batches(&authority, ScopeWorkClass::Normal, Duration::from_secs(2))
                    .await
                    .unwrap();
                let replayed = reopened.completions().next().await;
                assert_eq!(
                    completion.attempt(),
                    replayed.attempt(),
                    "factories share retained delivery state"
                );
                assert!(matches!(
                    client
                        .batch_outcome(
                            completion.attempt(),
                            ScopeWorkClass::Normal,
                            Duration::from_secs(2)
                        )
                        .await
                        .unwrap(),
                    ScopeBatchLookup::Applied(_)
                ));
                peer.corrupt_lookup.store(true, Ordering::Release);
                assert_eq!(client.batch_outcome(completion.attempt(), ScopeWorkClass::Normal, Duration::from_secs(2)).await,
                    Err(ScopeBatchError::OutcomeUnknown),
                    "a canonical Applied reply for a different digest cannot resolve this exact attempt");
                assert!(reopened.ack(completion.attempt()));
                drop(waiting.await.unwrap());
                for task in tasks {
                    task.abort();
                }
            })
            .await
            .expect("bounded authenticated batch fixture");
        });
}
