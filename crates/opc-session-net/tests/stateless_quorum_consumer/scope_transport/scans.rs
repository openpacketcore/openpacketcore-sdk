//! Authenticated scan calls through a real TLS follower and durable three-voter store.
use super::*;
use opc_session_store::{scope_batch::*, scope_scan::*, scope_scheduler::ScopeWorkClass};

#[derive(Clone, Copy)]
enum Case {
    Cut,
    Capacity,
    Stale,
}

#[test]
fn native_scope_scan_tls_keeps_one_cut_and_locally_revalidates_fresh_proofs() {
    run(
        Case::Cut,
        concat!(
            "stateless_quorum_consumer::scope_transport::scans::",
            "native_scope_scan_tls_keeps_one_cut_and_locally_revalidates_fresh_proofs"
        ),
    );
}
#[test]
fn native_scope_scan_tls_queued_open_releases_running_and_shutdown_drains() {
    run(
        Case::Capacity,
        concat!(
            "stateless_quorum_consumer::scope_transport::scans::",
            "native_scope_scan_tls_queued_open_releases_running_and_shutdown_drains"
        ),
    );
}
#[test]
fn native_scope_scan_tls_rejects_a_superseded_boot_on_existing_and_new_channels() {
    run(
        Case::Stale,
        concat!(
            "stateless_quorum_consumer::scope_transport::scans::",
            "native_scope_scan_tls_rejects_a_superseded_boot_on_existing_and_new_channels"
        ),
    );
}

fn child(n: u8) -> ScopeChildKey {
    ScopeChildKey::new([n; 32]).unwrap()
}
fn claim(n: u8) -> ScopeClaimKey {
    ScopeClaimKey::new([n; 32]).unwrap()
}
fn create(n: u8, claims: &[u8]) -> ScopeChildMutation {
    let envelope = opc_crypto::CryptoEnvelopeV1 {
        algorithm: opc_key::AeadAlgorithm::Aes256GcmSiv,
        key_id: opc_key::KeyId::new("scan-tls-fixture").unwrap(),
        nonce: vec![n; 12],
        aad: vec![n; 32],
        ciphertext_and_tag: vec![n; 32],
    }
    .encode()
    .unwrap();
    ScopeChildMutation::Create {
        key: child(n),
        value: ScopeSealedValue::new(envelope).unwrap(),
        claims: claims.iter().map(|n| claim(*n)).collect(),
    }
}

struct MetricsOnly;
#[async_trait]
impl ScopeAuthorityAdmission for MetricsOnly {
    async fn authorize(
        &self,
        _: &SessionConsumerIdentity,
        _: &ScopeId,
        _: Option<&ScopeExecution>,
        _: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        Err(ScopeAuthorityError::Unauthorized)
    }
}

fn run(case: Case, name: &str) {
    const CHILD: &str = "OPC_SCOPE_SCAN_TLS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
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
    tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap().block_on(async {
        let pki = Arc::new(TestPki::new());
        let mut fleet = ThreeVoterConsumerFleet::start_fixed_durable_classified(pki.clone()).await;
        let result = std::panic::AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(90), async {
            let (leader,_,_) = fleet.wait_for_observed_leader().await;
            fleet.stores[leader].activate_scope_profile().await.unwrap();
            let follower = (leader + 1) % 3;
            let scope = ScopeId::new(fleet.manifest.fixed_durable_quorum_consensus_identity(),
                TenantId::new("test").unwrap(), NetworkFunctionKind::new("scope").unwrap(), [0x57;32]).unwrap();
            let binding = ScopeBinding::from_scope(&scope).unwrap();
            let local = tempfile::tempdir().unwrap();
            let process = Arc::new(ScopeProcess::new(binding.clone(),[3;16],BootIdentity::generate().unwrap(),
                std::fs::File::open(local.path()).unwrap()).unwrap());
            let worker = spiffe("scope-worker");
            let execution = ScopeExecution::new(SessionConsumerIdentity::new(worker.clone()).unwrap(),127,[3;16],
                *process.boot().process_nonce(),process.boot().key_digest()).unwrap();
            let record = BootAuthorityRecord::new(binding.clone(),execution.clone(),*process.boot().public_key(),
                b"authority-uid".to_vec(),b"rv:127".to_vec()).unwrap();
            let ticket = BootTicket::from_authority_record(&process,&record).unwrap();
            let boots = Arc::new(Boots(std::sync::Mutex::new(record),std::sync::Mutex::new(None)));
            let closures = Arc::new(Closures::default());
            let server_scheduler = ScopeSchedulerOwner::default();
            let client_scheduler = ScopeSchedulerOwner::default();
            let policy = ScopePolicy::new(vec![PrincipalGrant::new(opc_types::SpiffeId::new(worker.clone()).unwrap(),
                ScopeRole::Worker,vec![binding.clone()]).unwrap()]).unwrap();
            let server = Arc::new(ScopeServer::new(ScopeServerConfig {
                tls: server_tls(&pki,&three_voter_spiffe(follower),"scope-worker"),clock:Arc::new(ScopeClock),
                policy,store:Arc::new(fleet.stores[follower].clone()),scopes:vec![scope.clone()],
                boots:boots.clone(),closures:closures.clone(),scheduler:server_scheduler.scheduler(),proofs:ProofBudgets::default(),
            }).unwrap());
            let handle = server.clone().serve([SocketAddr::from(([127,0,0,1],0));5]).await.unwrap();
            let tls = client_tls(&pki,&worker,&follower.to_string());
            let server_id = opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap();
            let client = ScopeClient::new(ScopeClientConfig {process:process.clone(),scope:scope.clone(),ticket,
                tls:tls.clone(),server:server_id.clone(),addresses:handle.addresses(),clock:Arc::new(ScopeClock),
                scheduler:client_scheduler.scheduler(),local_closure:closures.clone()}).unwrap();
            let initial = client.prepare_initial().await.unwrap();
            let ScopeAuthorityReply::Admitted(authority) = client.submit(&initial,Duration::from_secs(5)).await.unwrap()
                else {panic!("initial own authority")};
            let batches = client.batches(&authority,ScopeWorkClass::Normal,Duration::from_secs(5)).await.unwrap();
            let write = batches.reserve_lane(0,ScopeWorkClass::Normal).await.unwrap().submit(|context| async move {
                context.request([61;16],vec![create(1,&[7])],vec![ScopeCounterMutation::new(0,0,7).unwrap()])
            }).await.unwrap();
            let written = write.completion().await;
            assert!(matches!(written.outcome(),ScopeBatchCompletionOutcome::Applied(_)));
            assert!(batches.ack(written.attempt()));
            let close = client.prepare_close(&authority).await.unwrap();
            let ScopeAuthorityReply::Closed(closed) = client.submit(&close,Duration::from_secs(5)).await.unwrap()
                else {panic!("closed predecessor")};
            let evidence = client.current(Duration::from_secs(5)).await.unwrap().closed_evidence().unwrap();
            drop(written);drop(write);drop(batches);drop(initial);drop(close);drop(client);drop(process);

            let process = Arc::new(ScopeProcess::new(binding.clone(),[3;16],BootIdentity::generate().unwrap(),
                std::fs::File::open(local.path()).unwrap()).unwrap());
            let next = ScopeExecution::new(execution.identity().clone(),129,[3;16],*process.boot().process_nonce(),process.boot().key_digest()).unwrap();
            let record = BootAuthorityRecord::new(binding.clone(),next,*process.boot().public_key(),b"authority-uid".to_vec(),b"rv:129".to_vec()).unwrap();
            let ticket = BootTicket::from_authority_record(&process,&record).unwrap();
            *boots.0.lock().unwrap()=record;
            let client = ScopeClient::new(ScopeClientConfig {process:process.clone(),scope:scope.clone(),ticket,
                tls:tls.clone(),server:server_id.clone(),addresses:handle.addresses(),clock:Arc::new(ScopeClock),
                scheduler:client_scheduler.scheduler(),local_closure:closures.clone()}).unwrap();
            let pending = client.prepare_successor(&closed,evidence).await.unwrap();
            let ScopeAuthorityReply::Admitted(authority) = client.submit(&pending,Duration::from_secs(5)).await.unwrap()
                else {panic!("successor own authority")};
            let port = client.scans(&authority,&pending).expect("an exact committed succession creates an authenticated scan port");
            let metrics = ScopeScanStore::new(Arc::new(fleet.stores[follower].clone()),
                authority.stamp().namespace().clone(),Arc::new(MetricsOnly)).unwrap();
            let limits = ScopeScanPageLimits::new(1,opc_session_store::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES).unwrap();
            let barriers = fleet.stores[follower].scope_read_barrier_count_for_test();
            let view = port.open(None,limits).await.expect("actual TLS opens a positively handed-over coherent cut");
            assert!(fleet.stores[follower].scope_read_barrier_count_for_test() > barriers);
            assert_eq!(view.authority().stamp(),Some(authority.stamp()));
            assert_eq!(view.checkpoint().counters()[0],7);
            assert_eq!(metrics.metrics().active_views,1);
            let first = port.page(&view,view.initial_cursor()).await.unwrap();
            assert_eq!(first.items().len(),1);
            assert_eq!(first.items().next().unwrap().child().unwrap().key(),child(1));

            match case {
                Case::Cut => {
                    let batches = client.batches(&authority,ScopeWorkClass::Normal,Duration::from_secs(5)).await.unwrap();
                    let old = batches.completions().next().await;
                    assert!(batches.ack(old.attempt()));
                    let write = batches.reserve_lane(1,ScopeWorkClass::Normal).await.unwrap().submit(|context| async move {
                        context.request([62;16],vec![ScopeChildMutation::Delete{key:child(1),expected:ScopeChildRevision::new(1,1).unwrap()},
                            create(2,&[8])],vec![])
                    }).await.unwrap();
                    let written = write.completion().await;
                    assert!(matches!(written.outcome(),ScopeBatchCompletionOutcome::Applied(_)));
                    assert!(batches.ack(written.attempt()));
                    let barriers = fleet.stores[follower].scope_read_barrier_count_for_test();
                    server.lose_next_scan_reply_for_test();
                    assert!(matches!(port.page(&view,view.initial_cursor()).await,Err(ScopeScanRequestFailure::Retryable(_))));
                    let replay = port.page(&view,view.initial_cursor()).await.unwrap();
                    assert_eq!(ScopeScanResponse::Page(first.clone()).encode_canonical().unwrap(),
                        ScopeScanResponse::Page(replay).encode_canonical().unwrap(),"lost replies reuse the exact old cut and cursor window");
                    let found = port.lookup(&view,ScopeScanLookupKey::Child(child(1))).await.unwrap();
                    assert_eq!(found.item().disposition(),ScopeScanDisposition::LiveChild);
                    assert_eq!(found.cut(),view.cut());
                    let absent = port.lookup(&view,ScopeScanLookupKey::Child(child(2))).await.unwrap();
                    assert_eq!(absent.item().disposition(),ScopeScanDisposition::MissingAtCut);
                    let classified = port.classify(&view,ScopeScanLookupKey::Claim(claim(7))).await.unwrap();
                    assert!(matches!(classified.item().disposition(),ScopeScanDisposition::ClaimHeld(_)));
                    assert_eq!(classified.cut(),view.cut());
                    let second = port.page(&view,first.continuation().unwrap()).await.unwrap();
                    assert_eq!(second.items().next().unwrap().claim().unwrap().key(),claim(7));
                    let complete = port.page(&view,second.continuation().unwrap()).await.unwrap();
                    assert_eq!(complete.status(),ScopeScanPageStatus::Complete);
                    assert_eq!(complete.summary().unwrap().examined_items(),2);
                    assert_eq!(fleet.stores[follower].scope_read_barrier_count_for_test(),barriers,
                        "promoted channels and a fresh reconnected proof perform only local page guards");
                    port.close(view).await;
                    assert_eq!(metrics.metrics().active_views,0);
                    let mut sink = Sink{cut:None,items:0,discarded:false};
                    assert_eq!(ScopeScanClient::new(port).restore(&mut sink, tokio::time::Instant::now() + Duration::from_secs(60)).await.unwrap(),4);
                    assert!(!sink.discarded);
                    assert_eq!(metrics.metrics().active_views,0);
                    handle.shutdown().await;
                }
                Case::Capacity => {
                    let mut views=vec![view];
                    for _ in 1..ScopeScanLimits::default().max_views() {
                        views.push(port.open(None,limits).await.unwrap());
                    }
                    let queued=tokio::spawn({let port=port.clone();async move {port.open(None,limits).await}});
                    tokio::time::timeout(Duration::from_secs(10),async {
                        while metrics.metrics().waiting_views!=1 {tokio::task::yield_now().await;}
                    }).await.expect("the fifth actual TLS open queues at the store's retention cap");
                    assert_eq!(server_scheduler.scheduler().snapshot().class(ScopeWorkClass::Normal).running,0,
                        "retention queueing holds no additional transport execution credit");
                    assert!(matches!(port.classify(&views[0],ScopeScanLookupKey::Claim(claim(7))).await.unwrap().item().disposition(),
                        ScopeScanDisposition::ClaimHeld(_)),"classification keeps its independent channel and budget");
                    tokio::time::sleep(Duration::from_secs(12)).await;
                    assert!(!queued.is_finished(), "queued open lost its place to a request timeout");
                    assert_eq!(metrics.metrics().waiting_views,1);
                    queued.abort();
                    assert!(queued.await.unwrap_err().is_cancelled());
                    tokio::time::timeout(Duration::from_secs(5),async {
                        while metrics.metrics().waiting_views!=0 {tokio::time::sleep(Duration::from_millis(10)).await;}
                    }).await.expect("disconnect cancels only the queued admission");
                    assert_eq!(metrics.metrics().active_views,views.len());
                    let queued=tokio::spawn({let port=port.clone();async move {port.open(None,limits).await}});
                    tokio::time::timeout(Duration::from_secs(5),async {
                        while metrics.metrics().waiting_views!=1 {tokio::time::sleep(Duration::from_millis(10)).await;}
                    }).await.expect("a subsequent open can queue after cancellation");
                    let close=tokio::time::timeout(Duration::from_secs(5),client.prepare_close(&authority))
                        .await.expect("a queued read must not hold the process gate against graceful Close")
                        .unwrap();
                    assert!(matches!(queued.await.unwrap(),
                        Err(ScopeScanRequestFailure::Final(ScopeScanError::StaleAuthority))),
                        "quiescence cancels a waiting observation instead of accepting a late response");
                    tokio::time::timeout(Duration::from_secs(5),async {
                        while metrics.metrics().waiting_views!=0 {tokio::task::yield_now().await;}
                    }).await.expect("quiescence disconnect releases the queued store admission");
                    drop(close);
                    handle.shutdown().await;
                    assert_eq!(metrics.metrics().active_views,0);
                    assert_eq!(metrics.metrics().waiting_views,0);
                    drop(views);
                }
                Case::Stale => {
                    port.classify(&view,ScopeScanLookupKey::Claim(claim(7))).await.unwrap();
                    // The test's independent closure source records the old Pod's
                    // final termination. Its still-live local gate deliberately
                    // exercises the serving store's fence instead of a client check.
                    let terminated=FinalTerminationRecord::new(authority.stamp().clone(),"test".into(),"worker".into(),[3;16],
                        "worker".into(),"containerd://scan-129".into(),0,0,"Completed".into(),"".into(),
                        "2026-01-01T00:00:00Z".into(),"2026-01-01T00:01:00Z".into(),b"terminated-129".to_vec(),b"rv:129-closed".to_vec()).unwrap();
                    let digest=terminated.digest().unwrap();
                    closures.final_records.lock().unwrap().insert(digest,terminated);
                    let other_local=tempfile::tempdir().unwrap();
                    let other_process=Arc::new(ScopeProcess::new(binding.clone(),[4;16],BootIdentity::generate().unwrap(),
                        std::fs::File::open(other_local.path()).unwrap()).unwrap());
                    let other_execution=ScopeExecution::new(execution.identity().clone(),130,[4;16],
                        *other_process.boot().process_nonce(),other_process.boot().key_digest()).unwrap();
                    let record=BootAuthorityRecord::new(binding,other_execution,*other_process.boot().public_key(),b"next-pod-uid".to_vec(),b"rv:130".to_vec()).unwrap();
                    let ticket=BootTicket::from_authority_record(&other_process,&record).unwrap();
                    *boots.0.lock().unwrap()=record;
                    let next_client=ScopeClient::new(ScopeClientConfig{process:other_process,scope,ticket,tls,server:server_id,
                        addresses:handle.addresses(),clock:Arc::new(ScopeClock),scheduler:client_scheduler.scheduler(),local_closure:closures}).unwrap();
                    let next_pending=next_client.prepare_successor(authority.stamp(),
                        ScopeClosureEvidence::new(ScopeClosureKind::FinalTermination,digest).unwrap()).await.unwrap();
                    assert!(matches!(next_client.submit(&next_pending,Duration::from_secs(5)).await.unwrap(),ScopeAuthorityReply::Admitted(_)));
                    drop(process.enter_peer_control().await.unwrap());
                    let barriers=fleet.stores[follower].scope_read_barrier_count_for_test();
                    assert!(matches!(port.page(&view,view.initial_cursor()).await,
                        Err(ScopeScanRequestFailure::Final(ScopeScanError::StaleAuthority))));
                    assert!(matches!(port.lookup(&view,ScopeScanLookupKey::Child(child(1))).await,
                        Err(ScopeScanRequestFailure::Final(ScopeScanError::StaleAuthority))));
                    assert!(matches!(port.classify(&view,ScopeScanLookupKey::Claim(claim(7))).await,
                        Err(ScopeScanRequestFailure::Final(ScopeScanError::StaleAuthority))));
                    server.lose_next_scan_reply_for_test();
                    assert!(matches!(port.page(&view,view.initial_cursor()).await,Err(ScopeScanRequestFailure::Retryable(_))));
                    assert!(matches!(port.page(&view,view.initial_cursor()).await,
                        Err(ScopeScanRequestFailure::Final(ScopeScanError::StaleAuthority))),"reconnection cannot inherit promotion or ignore the exact boot fence");
                    assert_eq!(fleet.stores[follower].scope_read_barrier_count_for_test(),barriers);
                    handle.shutdown().await;
                    assert_eq!(metrics.metrics().active_views,0);
                }
            }
        })).catch_unwind().await;
        fleet.quiesce().await;
        match result { Ok(Ok(()))=>{},Ok(Err(error))=>panic!("bounded native scan TLS scenario: {error}"),
            Err(error)=>std::panic::resume_unwind(error) }
    });
}

struct Sink {
    cut: Option<ScopeCut>,
    items: usize,
    discarded: bool,
}
#[async_trait]
impl ScopeScanSink for Sink {
    type Error = std::convert::Infallible;
    type Output = usize;
    async fn begin(
        &mut self,
        cut: &ScopeCut,
        _: &ScopeAuthorityView,
        _: &ScopeScanCheckpoint,
    ) -> Result<(), Self::Error> {
        assert!(self.cut.replace(cut.clone()).is_none());
        self.items = 0;
        Ok(())
    }
    async fn stage(&mut self, reply: &ScopeScanReply) -> Result<(), Self::Error> {
        assert_eq!(self.cut.as_ref(), Some(reply.cut()));
        self.items += reply.items().len();
        Ok(())
    }
    async fn finish(&mut self, reply: &ScopeScanReply) -> Result<Self::Output, Self::Error> {
        assert_eq!(reply.status(), ScopeScanPageStatus::Complete);
        assert_eq!(reply.summary().unwrap().examined_items(), self.items as u64);
        self.cut = None;
        Ok(self.items)
    }
    fn discard(&mut self, _: &ScopeCut) {
        self.cut = None;
        self.items = 0;
        self.discarded = true;
    }
}
