//! An authenticated scripted peer exercises the public read's complete error table.
use super::*;

pub(super) struct Reply {
    status: ResultStatus,
    body: Vec<u8>,
    pub(super) preproof: bool,
    pub(super) drop_reply: bool,
    corruption: u8,
}

impl Reply {
    fn new(status: ResultStatus, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            preproof: false,
            drop_reply: false,
            corruption: 0,
        }
    }

    pub(super) async fn send(
        self,
        connection: &mut ScopeTlsConnection<TcpStream>,
        call: &Header,
        nonce: [u8; 32],
    ) {
        let mut body = ResultPayload::new(nonce, self.status, [0; 32], self.body)
            .unwrap()
            .encode()
            .unwrap();
        let mut header = call.response(FrameKind::Result, body.len()).unwrap();
        match self.corruption {
            1 => body[0] ^= 1,
            2 => header.request_id[0] ^= 1,
            3 => body[33] ^= 1,
            4 => body[32] = 255,
            5 => {
                body.push(0);
                header.payload_len += 1;
            }
            _ => {}
        }
        connection
            .write_all(&header.encode().unwrap())
            .await
            .unwrap();
        connection.write_all(&body).await.unwrap();
        connection.flush().await.unwrap();
    }
}

#[test]
fn child_read_client_preserves_the_complete_error_table_and_rejects_other_statuses() {
    const CHILD: &str = "OPC_CHILD_READ_ERROR_TABLE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "scope::rpc_client::batch_tests::child_reads::child_read_client_preserves_the_complete_error_table_and_rejects_other_statuses", "--nocapture"])
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
            timeout(Duration::from_secs(15), async {
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
                let (_source, receive) = tokio::sync::watch::channel(Some(material(ISSUER, &ca)));
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
                let mut addresses = [std::net::SocketAddr::from(([127, 0, 0, 1], 9)); 5];
                let mut tasks = Vec::new();
                for class in [Class::SafetyControl, Class::Normal] {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    addresses[class.index()] = listener.local_addr().unwrap();
                    let tls = server_tls.clone();
                    let peer = peer.clone();
                    let domain = binding.tls_domain().unwrap();
                    tasks.push(tokio::spawn(async move {
                        let mut connections = tokio::task::JoinSet::new();
                        loop {
                            let (socket, _) = listener.accept().await.unwrap();
                            let handshake = tls.begin_handshake().unwrap();
                            let peer = peer.clone();
                            let domain = domain.clone();
                            connections.spawn(async move {
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
                let key = ScopeChildKey::new([8; 32]).unwrap();
                let request = ScopeChildReadRequest::new(authority.stamp(), vec![key]).unwrap();
                let unavailable = ScopeChildReadError::Batch(ScopeBatchError::Unavailable);
                let mut cases = Vec::new();
                for (reason, expected) in [
                    (1, ScopeBatchError::InvalidRequest),
                    (2, ScopeAuthorityError::Unauthorized.into()),
                    (3, ScopeBatchError::Unavailable),
                    (4, ScopeBatchError::Unavailable),
                    (5, ScopeAuthorityError::ProfileNotActivated.into()),
                ] {
                    for preproof in [false, true] {
                        let mut reply = Reply::new(ResultStatus::ProvenNoEffect, vec![0, reason]);
                        reply.preproof = preproof;
                        cases.push((
                            format!("refusal {reason} before proof {preproof}"),
                            reply,
                            ScopeChildReadError::from(expected.clone()),
                        ));
                    }
                }
                let mut errors = vec![
                    ScopeBatchError::InvalidRequest,
                    ScopeBatchError::Conflict(ScopeBatchConflicts {
                        children: vec![key],
                        claims: vec![],
                        counters: vec![0],
                    }),
                    ScopeBatchError::RevisionConflict,
                    ScopeBatchError::IdempotencyConflict,
                    ScopeBatchError::FormatMismatch,
                    ScopeBatchError::OutcomeUnknown,
                    ScopeBatchError::Unavailable,
                    ScopeBatchError::SequenceConflict,
                    ScopeBatchError::Cancelled,
                    ScopeBatchError::ScopeGuardStalled,
                ];
                errors.extend(
                    [
                        ScopeAuthorityError::InvalidRequest,
                        ScopeAuthorityError::Unauthorized,
                        ScopeAuthorityError::Conflict,
                        ScopeAuthorityError::IdempotencyConflict,
                        ScopeAuthorityError::StaleAuthority,
                        ScopeAuthorityError::Retired,
                        ScopeAuthorityError::Superseded,
                        ScopeAuthorityError::ClosureRequired,
                        ScopeAuthorityError::FormatMismatch,
                        ScopeAuthorityError::FreshInstallationRequired,
                        ScopeAuthorityError::DurableConsensusRequired,
                        ScopeAuthorityError::OutcomeUnknown,
                        ScopeAuthorityError::Unavailable,
                        ScopeAuthorityError::ProfileNotActivated,
                    ]
                    .into_iter()
                    .map(ScopeBatchError::Scope),
                );
                for error in errors {
                    cases.push((
                        format!("canonical {error:?}"),
                        Reply::new(ResultStatus::BatchError, error.encode_canonical().unwrap()),
                        error.into(),
                    ));
                }
                cases.push((
                    "unknown outcome".into(),
                    Reply::new(ResultStatus::OutcomeUnknown, vec![]),
                    ScopeBatchError::OutcomeUnknown.into(),
                ));
                cases.push((
                    "oversize observation".into(),
                    Reply::new(ResultStatus::ChildObservation, vec![1]),
                    ScopeChildReadError::ObservationTooLarge,
                ));
                for status in [
                    ResultStatus::Committed,
                    ResultStatus::CurrentView,
                    ResultStatus::ScanObservation,
                ] {
                    cases.push((
                        format!("unsupported {status:?}"),
                        Reply::new(status, vec![1]),
                        unavailable.clone(),
                    ));
                }
                for reason in 1..=4 {
                    cases.push((
                        format!("unsupported obsolete {reason}"),
                        Reply::new(ResultStatus::Obsolete, vec![reason]),
                        unavailable.clone(),
                    ));
                }
                cases.push((
                    "noncanonical batch error".into(),
                    Reply::new(ResultStatus::BatchError, vec![255]),
                    unavailable.clone(),
                ));
                let missing =
                    crate::scope::child_read_wire::encode_observation(&request, &[None]).unwrap();
                for corruption in 1..=5 {
                    let mut reply = Reply::new(ResultStatus::ChildObservation, missing.clone());
                    reply.corruption = corruption;
                    cases.push((
                        format!("corrupt correlation or envelope {corruption}"),
                        reply,
                        unavailable.clone(),
                    ));
                }
                let mut lost = Reply::new(ResultStatus::ChildObservation, missing.clone());
                lost.drop_reply = true;
                cases.push((
                    "reply lost after proof".into(),
                    lost,
                    ScopeBatchError::OutcomeUnknown.into(),
                ));
                for (label, reply, expected) in cases {
                    let before = peer.child_calls.load(Ordering::SeqCst);
                    let proofs = peer.child_proofs.load(Ordering::SeqCst);
                    let preproof = reply.preproof;
                    peer.child_replies.lock().await.push_back(reply);
                    assert_eq!(
                        client
                            .read_child(
                                &authority,
                                key,
                                ScopeWorkClass::Normal,
                                Instant::now() + Duration::from_secs(2)
                            )
                            .await,
                        Err(expected),
                        "{label}"
                    );
                    assert_eq!(
                        peer.child_calls.load(Ordering::SeqCst),
                        before + 1,
                        "one attempted exchange: {label}"
                    );
                    assert_eq!(
                        peer.child_proofs.load(Ordering::SeqCst),
                        proofs + usize::from(!preproof),
                        "proof boundary: {label}"
                    );
                    assert_eq!(
                        owner
                            .scheduler()
                            .snapshot()
                            .class(ScopeWorkClass::Normal)
                            .resident,
                        0
                    );
                }
                peer.child_replies
                    .lock()
                    .await
                    .push_back(Reply::new(ResultStatus::ChildObservation, missing));
                assert_eq!(
                    client
                        .read_child(
                            &authority,
                            key,
                            ScopeWorkClass::Normal,
                            Instant::now() + Duration::from_secs(2)
                        )
                        .await,
                    Ok(None)
                );
                assert_eq!(
                    peer.applied.load(Ordering::SeqCst),
                    0,
                    "observations never apply an application batch"
                );
                for task in tasks {
                    task.abort();
                    let _ = task.await;
                }
            })
            .await
            .expect("bounded child-read error-table fixture");
        });
}
