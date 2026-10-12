//! Public callers distinguish revision failures and retain the ability to recover.
use super::*;
use crate::scope::{
    revision_tests::signal, ScopeTransportDirection as Direction, ScopeTransportPurpose as Purpose,
    ScopeTransportRole as Role,
};

pub(super) struct ChildReadRevisionFixture {
    pub(super) client: ScopeClient,
    pub(super) authority: Box<CommittedScopeAuthority>,
    pub(super) peer: Arc<Peer>,
    legacy: Arc<AtomicBool>,
    pub(super) handshakes: Arc<AtomicUsize>,
    owner: ScopeSchedulerOwner,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _directory: tempfile::TempDir,
}

impl ChildReadRevisionFixture {
    pub(super) async fn new() -> Self {
        let identity = SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([2; 32]),
            SessionConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let scope = ScopeId::new(
            identity,
            TenantId::new("test").unwrap(),
            NetworkFunctionKind::new("smf").unwrap(),
            [73; 32],
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
        let ca =
            rcgen::CertifiedIssuer::self_signed(parameters, rcgen::KeyPair::generate().unwrap())
                .unwrap();
        let (_source, receive) = tokio::sync::watch::channel(Some(material(WORKER, &ca)));
        let tls = TlsConfigBuilder::new(receive)
            .with_policy(PeerPolicy {
                allowed_instances: Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])),
                ..Default::default()
            })
            .build_authenticated_client_config()
            .unwrap();
        let (_source, receive) = tokio::sync::watch::channel(Some(material(ISSUER, &ca)));
        let server_tls = TlsConfigBuilder::new(receive)
            .with_policy(PeerPolicy {
                allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),
                ..Default::default()
            })
            .build_authenticated_server_config()
            .unwrap();
        let peer = Arc::new(Peer {
            mode: 0,
            scope: scope.clone(),
            stamp: Mutex::new(None),
            receipt: Mutex::new(None),
            applied: AtomicUsize::new(0),
            emergency_reopens: AtomicUsize::new(0),
            hold_reopen: AtomicBool::new(false),
            corrupt_lookup: AtomicBool::new(false),
            malformed_challenge: AtomicBool::new(false),
            preproof_refused: Notify::new(),
            reopen_entered: Notify::new(),
            reopen_release: Notify::new(),
            entered: Notify::new(),
            release: Notify::new(),
            child_replies: Mutex::new(Default::default()),
            child_calls: AtomicUsize::new(0),
            child_proofs: AtomicUsize::new(0),
        });
        let legacy = Arc::new(AtomicBool::new(false));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let mut addresses = [std::net::SocketAddr::from(([127, 0, 0, 1], 9)); 5];
        let mut tasks = Vec::new();
        for class in [Class::SafetyControl, Class::Normal] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addresses[class.index()] = listener.local_addr().unwrap();
            let tls = server_tls.clone();
            let peer = peer.clone();
            let domain = binding.tls_domain().unwrap();
            let legacy = legacy.clone();
            let handshakes = handshakes.clone();
            tasks.push(tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    // Match the real voter socket, including TCP_NODELAY for
                    // the separately framed challenge and Result payloads.
                    crate::scope::socket::configure(&socket).unwrap();
                    let handshake = tls.begin_handshake().unwrap();
                    let use_legacy = class == Class::Normal && legacy.load(Ordering::SeqCst);
                    if class == Class::Normal {
                        handshakes.fetch_add(1, Ordering::SeqCst);
                    }
                    let peer = peer.clone();
                    let domain = domain.clone();
                    connections.spawn(async move {
                        if use_legacy {
                            let mut config = (*handshake.rustls_config()).clone();
                            config.alpn_protocols = vec![b"opc-scope/1".to_vec()];
                            assert!(tokio_rustls::TlsAcceptor::from(Arc::new(config))
                                .accept(socket)
                                .await
                                .is_err());
                            return;
                        }
                        peer.serve(handshake.accept_scope(socket, domain).await.unwrap(), class)
                            .await;
                    });
                }
            }));
        }
        let owner = ScopeSchedulerOwner::default();
        let client = ScopeClient::new(ScopeClientConfig {
            ticket: BootTicket::from_authority_record(&process, &record).unwrap(),
            process,
            scope,
            tls,
            server: SpiffeId::new(ISSUER).unwrap(),
            addresses,
            clock: Arc::new(Clock),
            scheduler: owner.scheduler(),
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
        Self {
            client,
            authority,
            peer,
            legacy,
            handshakes,
            owner,
            tasks,
            _directory: directory,
        }
    }

    pub(super) async fn stop(self) {
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

#[derive(Clone, Copy)]
enum Scenario {
    ReopenAlpn,
    ChildAlpn,
    ChildFrame,
}

#[test]
fn scope_client_revision_mismatch_does_not_transparently_reconnect() {
    run(
        Scenario::ReopenAlpn,
        "scope_client_revision_mismatch_does_not_transparently_reconnect",
    );
}

#[test]
fn child_read_revision_mismatch_has_a_typed_alpn_error_and_recovers() {
    run(
        Scenario::ChildAlpn,
        "child_read_revision_mismatch_has_a_typed_alpn_error_and_recovers",
    );
}

#[test]
fn child_read_revision_one_header_is_typed_before_reading_its_body() {
    run(
        Scenario::ChildFrame,
        "child_read_revision_one_header_is_typed_before_reading_its_body",
    );
}

fn run(scenario: Scenario, name: &str) {
    const CHILD: &str = "OPC_SCOPE_REVISION_MISMATCH_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = format!("scope::rpc_client::batch_tests::child_reads::revision::{name}");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
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
        timeout(Duration::from_secs(15), async {
            let fixture = ChildReadRevisionFixture::new().await;
            let key = ScopeChildKey::new([8; 32]).unwrap();
            let request = ScopeChildReadRequest::new(fixture.authority.stamp(), vec![key]).unwrap();
            let missing = crate::scope::child_read_wire::encode_observation(&request, &[None]).unwrap();
            match scenario {
                Scenario::ReopenAlpn | Scenario::ChildAlpn => {
                    fixture.legacy.store(true, Ordering::SeqCst);
                    match scenario {
                        Scenario::ReopenAlpn => {
                            assert_eq!(fixture.client.batches(&fixture.authority, ScopeWorkClass::Normal, Duration::from_secs(2)).await.err(),
                                Some(ScopeBatchError::TransportRevisionMismatch));
                        }
                        Scenario::ChildAlpn => {
                            assert_eq!(fixture.client.read_child(&fixture.authority, key, ScopeWorkClass::Normal, Instant::now() + Duration::from_secs(2)).await,
                                Err(ScopeChildReadError::TransportRevisionMismatch));
                        }
                        Scenario::ChildFrame => unreachable!(),
                    }
                    assert_eq!(fixture.handshakes.load(Ordering::SeqCst), 1, "a typed mismatch must not enter the transparent reconnect arm");
                    assert_eq!(fixture.peer.child_calls.load(Ordering::SeqCst), 0);
                    assert_eq!(fixture.peer.child_proofs.load(Ordering::SeqCst), 0);
                    assert_eq!(signal(Role::Worker, Purpose::Handshake, Direction::Outbound), (1, 0, true));
                    assert_eq!(signal(Role::Worker, Purpose::ScopeResponse, Direction::Outbound), (0, 0, false));
                    fixture.legacy.store(false, Ordering::SeqCst);
                }
                Scenario::ChildFrame => {
                    for preproof in [true, false] {
                        let mut reply = Reply::new(ResultStatus::ChildObservation, missing.clone());
                        reply.corruption = 6;
                        reply.preproof = preproof;
                        let calls = fixture.peer.child_calls.load(Ordering::SeqCst);
                        let proofs = fixture.peer.child_proofs.load(Ordering::SeqCst);
                        let handshakes = fixture.handshakes.load(Ordering::SeqCst);
                        fixture.peer.child_replies.lock().await.push_back(reply);
                        assert_eq!(fixture.client.read_child(&fixture.authority, key, ScopeWorkClass::Normal, Instant::now() + Duration::from_secs(2)).await,
                            Err(ScopeChildReadError::TransportRevisionMismatch), "authenticated revision-one header, before proof {preproof}");
                        assert_eq!(fixture.peer.child_calls.load(Ordering::SeqCst), calls + 1);
                        assert_eq!(fixture.peer.child_proofs.load(Ordering::SeqCst), proofs + usize::from(!preproof));
                        assert_eq!(fixture.handshakes.load(Ordering::SeqCst), handshakes + 1, "no immediate reconnect on an authenticated old frame");
                        let events = if preproof { 1 } else { 2 };
                        assert_eq!(signal(Role::Worker, Purpose::ScopeResponse, Direction::Outbound), (events, events, true));
                        assert_eq!(signal(Role::Worker, Purpose::Handshake, Direction::Outbound), (0, 0, false));
                    }
                }
            }
            assert_eq!(fixture.owner.scheduler().snapshot().class(ScopeWorkClass::Normal).resident, 0);
            fixture.peer.child_replies.lock().await.push_back(Reply::new(ResultStatus::ChildObservation, missing));
            assert_eq!(fixture.client.read_child(&fixture.authority, key, ScopeWorkClass::Normal, Instant::now() + Duration::from_secs(2)).await, Ok(None),
                "a later authenticated revision-two connection recovers without a process restart");
            let (alerts, frames) = match scenario { Scenario::ChildFrame => (0, 2), _ => (1, 0) };
            assert_eq!(signal(Role::Worker, Purpose::Handshake, Direction::Outbound), (alerts, 0, false));
            assert_eq!(signal(Role::Worker, Purpose::ScopeResponse, Direction::Outbound), (frames, frames, false));
            assert_eq!(fixture.owner.scheduler().snapshot().class(ScopeWorkClass::Normal).resident, 0);
            assert_eq!(fixture.peer.applied.load(Ordering::SeqCst), 0, "no revision refusal submits an application batch");
            fixture.stop().await;
        }).await.expect("bounded revision mismatch fixture");
    });
}
