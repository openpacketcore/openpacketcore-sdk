//! An authenticated scripted peer exercises the public read's complete error table.
use super::*;

#[path = "child_read_revision_tests.rs"]
mod revision;

pub(super) struct Reply {
    status: ResultStatus,
    body: Vec<u8>,
    pub(super) preproof: bool,
    pub(super) drop_reply: bool,
    corruption: u8,
    hold_result: Option<Arc<HeldChildResult>>,
}

#[derive(Default)]
struct HeldChildResult {
    entered: Notify,
    release: Notify,
    peer_closed: Notify,
}

impl Reply {
    fn new(status: ResultStatus, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            preproof: false,
            drop_reply: false,
            corruption: 0,
            hold_result: None,
        }
    }

    pub(super) async fn send(
        self,
        connection: &mut ScopeTlsConnection<TcpStream>,
        call: &Header,
        nonce: [u8; 32],
    ) {
        if let Some(hold) = &self.hold_result {
            hold.entered.notify_one();
            let mut unexpected = [0; 1];
            tokio::select! {
                () = hold.release.notified() => {},
                result = connection.read(&mut unexpected) => {
                    match result {
                        Ok(0) => {},
                        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {},
                        other => panic!("the timed-out exchange must close its connection: {other:?}"),
                    }
                    hold.peer_closed.notify_one();
                    return;
                }
            }
        }
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
            6 => {
                let mut fixed = header.encode().unwrap();
                fixed[4..6].copy_from_slice(&1_u16.to_be_bytes());
                connection.write_all(&fixed).await.unwrap();
                connection.flush().await.unwrap();
                return;
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

#[derive(Clone, Copy)]
enum ChildDeadlineCase {
    Result,
    Connection,
    ExistingBatch,
}

#[test]
fn child_read_result_deadline_is_unavailable_and_discards_the_connection() {
    run_child_deadline_case(
        ChildDeadlineCase::Result,
        "child_read_result_deadline_is_unavailable_and_discards_the_connection",
    );
}

#[test]
fn child_read_deadline_includes_waiting_for_the_pooled_connection() {
    run_child_deadline_case(
        ChildDeadlineCase::Connection,
        "child_read_deadline_includes_waiting_for_the_pooled_connection",
    );
}

#[test]
fn batch_attempt_starts_after_pooled_connection_acquisition() {
    run_child_deadline_case(
        ChildDeadlineCase::ExistingBatch,
        "batch_attempt_starts_after_pooled_connection_acquisition",
    );
}

fn run_child_deadline_case(case: ChildDeadlineCase, name: &str) {
    const CHILD: &str = "OPC_CHILD_READ_DEADLINE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = format!("scope::rpc_client::batch_tests::child_reads::{name}");
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
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the child must execute the exact named case"
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        timeout(Duration::from_secs(20), async {
            let fixture = revision::Fixture::new().await;
            let key = ScopeChildKey::new([8; 32]).unwrap();
            let request = ScopeChildReadRequest::new(fixture.authority.stamp(), vec![key]).unwrap();
            let missing = crate::scope::child_read_wire::encode_observation(&request, &[None]).unwrap();
            let hold = Arc::new(HeldChildResult::default());
            let mut reply = Reply::new(ResultStatus::ChildObservation, missing.clone());
            reply.hold_result = Some(hold.clone());
            fixture.peer.child_replies.lock().await.push_back(reply);
            let mut first = Box::pin(fixture.client.read_child(
                &fixture.authority, key, ScopeWorkClass::Normal,
                Instant::now() + Duration::from_secs(10),
            ));
            timeout(Duration::from_secs(10), async {
                tokio::select! {
                    () = hold.entered.notified() => {},
                    result = first.as_mut() => panic!("read ended before its Result was held: {result:?}"),
                }
            }).await.unwrap();
            assert_eq!(fixture.peer.child_calls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.peer.child_proofs.load(Ordering::SeqCst), 1);
            // Advance only after the real authenticated exchange reaches Result.
            // TLS/network setup is outside the controlled deadline experiment.
            tokio::time::pause();
            match case {
                ChildDeadlineCase::Result => {
                    tokio::time::advance(Duration::from_secs(10)).await;
                    let result = first.as_mut().await;
                    assert_eq!(result,
                        Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)),
                        "a withheld child Result must remain Unavailable, not an unknown mutation outcome: {}",
                        result.as_ref().err().unwrap());
                    drop(first);
                    tokio::time::resume();
                    timeout(Duration::from_secs(10), hold.peer_closed.notified()).await.unwrap();
                    assert_eq!(fixture.peer.child_calls.load(Ordering::SeqCst), 1,
                        "a withheld Result causes no replay or recovery exchange");
                    fixture.peer.child_replies.lock().await.push_back(
                        Reply::new(ResultStatus::ChildObservation, missing));
                    assert_eq!(fixture.client.read_child(&fixture.authority, key,
                        ScopeWorkClass::Normal, Instant::now() + Duration::from_secs(2)).await, Ok(None));
                    assert_eq!(fixture.handshakes.load(Ordering::SeqCst), 2,
                        "the expired exchange cannot return its connection to the pool");
                    assert_eq!(fixture.peer.child_calls.load(Ordering::SeqCst), 2);
                }
                ChildDeadlineCase::Connection => {
                    let mut second = Box::pin(fixture.client.read_child(&fixture.authority, key,
                        ScopeWorkClass::Normal, Instant::now() + Duration::from_millis(40)));
                    assert!(futures_util::poll!(second.as_mut()).is_pending());
                    tokio::time::advance(Duration::from_millis(40)).await;
                    assert_eq!(timeout(Duration::from_secs(1), second.as_mut()).await.unwrap(),
                        Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)));
                    drop(second);
                    assert_eq!(fixture.peer.child_calls.load(Ordering::SeqCst), 1,
                        "an expired connection waiter must start no second exchange");
                    assert_eq!(fixture.peer.child_proofs.load(Ordering::SeqCst), 1);
                    // A batch builder already owns its running entitlement.
                    // Exercise that entry point too, without the public read's
                    // outer admission timeout masking the pooled-wait bound.
                    let mut admitted = Box::pin(fixture.client.read_children_admitted(
                        &request, ScopeWorkClass::Normal,
                        Instant::now() + Duration::from_millis(40)));
                    assert!(futures_util::poll!(admitted.as_mut()).is_pending());
                    tokio::time::advance(Duration::from_millis(40)).await;
                    assert_eq!(timeout(Duration::from_secs(1), admitted.as_mut()).await
                        .expect("the admitted pooled waiter must finish at its own deadline"),
                        Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)));
                    drop(admitted);
                    assert_eq!(fixture.peer.child_calls.load(Ordering::SeqCst), 1,
                        "the admitted expired waiter must start no second exchange");
                    assert_eq!(fixture.peer.child_proofs.load(Ordering::SeqCst), 1);
                    hold.release.notify_one();
                    tokio::time::resume();
                    assert_eq!(first.as_mut().await, Ok(None), "the owner of the connection is unaffected");
                    drop(first);
                    assert_eq!(fixture.handshakes.load(Ordering::SeqCst), 1);
                }
                ChildDeadlineCase::ExistingBatch => {
                    let mut batches = Box::pin(fixture.client.batches(&fixture.authority,
                        ScopeWorkClass::Normal, Duration::from_millis(40)));
                    assert!(futures_util::poll!(batches.as_mut()).is_pending());
                    tokio::time::advance(Duration::from_millis(50)).await;
                    assert!(futures_util::poll!(batches.as_mut()).is_pending(),
                        "existing methods keep waiting for the pooled connection before starting their attempt");
                    hold.release.notify_one();
                    tokio::time::resume();
                    assert_eq!(first.as_mut().await, Ok(None));
                    drop(first);
                    let outcome = batches.await;
                    assert!(outcome.is_ok(),
                        "the original full attempt starts after acquisition: {:?}",
                        outcome.err().map(|error| error.encode_canonical()));
                    assert_eq!(fixture.handshakes.load(Ordering::SeqCst), 1);
                }
            }
            fixture.stop().await;
        }).await.unwrap();
    });
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
