//! Linux clock refusal cannot mutate native authority or discharge held effects.
use super::*;
use crate::scope::linux_clock_test_support::ClockFixture;

#[test]
fn linux_time_native_authority_and_quiescence_survive_synchronization_loss() {
    const NAME: &str = "stateless_quorum_consumer::scope_transport::linux_clock::linux_time_native_authority_and_quiescence_survive_synchronization_loss";
    const CHILD: &str = "OPC_SCOPE_LINUX_CLOCK_NATIVE_CHILD";
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
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let pki = Arc::new(TestPki::new());
            let mut fleet =
                ThreeVoterConsumerFleet::start_fixed_durable_classified(pki.clone()).await;
            let result = std::panic::AssertUnwindSafe(tokio::time::timeout(
                Duration::from_secs(30),
                async {
                    let (leader, _, _) = fleet.wait_for_observed_leader().await;
                    fleet.stores[leader].activate_scope_profile().await.unwrap();
                    let follower = (leader + 1) % 3;
                    let scope = ScopeId::new(
                        fleet.manifest.fixed_durable_quorum_consensus_identity(),
                        TenantId::new("test").unwrap(),
                        NetworkFunctionKind::new("scope").unwrap(),
                        [0x58; 32],
                    )
                    .unwrap();
                    let binding = ScopeBinding::from_scope(&scope).unwrap();
                    let local = tempfile::tempdir().unwrap();
                    let process = Arc::new(
                        ScopeProcess::new(
                            binding.clone(),
                            [3; 16],
                            BootIdentity::generate().unwrap(),
                            std::fs::File::open(local.path()).unwrap(),
                        )
                        .unwrap(),
                    );
                    let worker = spiffe("scope-worker");
                    let execution = ScopeExecution::new(
                        SessionConsumerIdentity::new(worker.clone()).unwrap(),
                        127,
                        [3; 16],
                        *process.boot().process_nonce(),
                        process.boot().key_digest(),
                    )
                    .unwrap();
                    let record = BootAuthorityRecord::new(
                        binding.clone(),
                        execution.clone(),
                        *process.boot().public_key(),
                        b"authority-uid".to_vec(),
                        b"rv:127".to_vec(),
                    )
                    .unwrap();
                    let ticket = BootTicket::from_authority_record(&process, &record).unwrap();
                    let boots = Arc::new(Boots(
                        std::sync::Mutex::new(record),
                        std::sync::Mutex::new(None),
                    ));
                    let closures = Arc::new(Closures::default());
                    let server_scheduler = ScopeSchedulerOwner::default();
                    let client_scheduler = ScopeSchedulerOwner::default();
                    let policy = ScopePolicy::new(vec![PrincipalGrant::new(
                        opc_types::SpiffeId::new(worker.clone()).unwrap(),
                        ScopeRole::Worker,
                        vec![binding.clone()],
                    )
                    .unwrap()])
                    .unwrap();
                    let server = Arc::new(
                        ScopeServer::new(ScopeServerConfig {
                            tls: server_tls(&pki, &three_voter_spiffe(follower), "scope-worker"),
                            clock: Arc::new(ScopeClock),
                            policy,
                            store: Arc::new(fleet.stores[follower].clone()),
                            scopes: vec![scope.clone()],
                            boots,
                            closures: closures.clone(),
                            scheduler: server_scheduler.scheduler(),
                            proofs: ProofBudgets::default(),
                        })
                        .unwrap(),
                    );
                    let handle = server
                        .serve([SocketAddr::from(([127, 0, 0, 1], 0)); 5])
                        .await
                        .unwrap();
                    let time = ClockFixture::new();
                    let client = ScopeClient::new(ScopeClientConfig {
                        process: process.clone(),
                        scope,
                        ticket,
                        tls: client_tls(&pki, &worker, &follower.to_string()),
                        server: opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap(),
                        addresses: handle.addresses(),
                        clock: time.clock.clone(),
                        scheduler: client_scheduler.scheduler(),
                        local_closure: closures.clone(),
                    })
                    .unwrap();
                    let initial = client.prepare_initial().await.unwrap();
                    let original = initial.request().encode_canonical().unwrap();
                    let ScopeAuthorityReply::Admitted(authority) = client
                        .submit(&initial, Duration::from_secs(5))
                        .await
                        .unwrap()
                    else {
                        panic!("initial admission");
                    };
                    let before = client.current(Duration::from_secs(5)).await.unwrap();
                    let receipt = client
                        .outcome(&initial, Duration::from_secs(5))
                        .await
                        .unwrap();
                    assert!(before.is_active());
                    assert_eq!(before.stamp(), Some(authority.stamp()));
                    let effect = process.enter_peer_control().await.unwrap();
                    crate::scope::assert_admitted_liveness_refusal(
                        process.clone(),
                        opc_types::SpiffeId::new(worker.clone()).unwrap(),
                        opc_types::SpiffeId::new(spiffe("scope-issuer")).unwrap(),
                        client_tls(&pki, &spiffe("scope-issuer"), "scope-worker"),
                        server_tls(&pki, &worker, "scope-issuer"),
                    )
                    .await;
                    assert_eq!(
                        client.current(Duration::from_secs(5)).await.unwrap(),
                        before,
                        "rejected liveness refusal preserves committed authority"
                    );
                    assert_eq!(
                        client
                            .outcome(&initial, Duration::from_secs(5))
                            .await
                            .unwrap(),
                        receipt,
                        "rejected liveness refusal preserves the exact admission receipt"
                    );
                    assert_eq!(initial.request().encode_canonical().unwrap(), original);
                    assert!(closures.local.lock().unwrap().is_empty());
                    assert!(closures.final_records.lock().unwrap().is_empty());
                    let first_generation = time.source.read().unwrap().synchronization_generation;
                    time.failed.store(true, Ordering::Release);
                    assert_eq!(
                        client.current(Duration::from_secs(1)).await.err(),
                        Some(ScopeRpcError::AuthTimeUnavailable)
                    );
                    assert_eq!(
                        client.outcome(&initial, Duration::from_secs(1)).await.err(),
                        Some(ScopeRpcError::AuthTimeUnavailable)
                    );
                    drop(process.enter_peer_control().await.unwrap());
                    assert!(closures.local.lock().unwrap().is_empty());
                    assert!(closures.final_records.lock().unwrap().is_empty());
                    time.failed.store(false, Ordering::Release);
                    assert_eq!(client.current(Duration::from_secs(5)).await.unwrap(), before,
                "clock recovery preserves the complete revision, stamp and generation floors");
                    assert_eq!(
                        client
                            .outcome(&initial, Duration::from_secs(5))
                            .await
                            .unwrap(),
                        receipt
                    );
                    assert_eq!(initial.request().encode_canonical().unwrap(), original);
                    assert_eq!(
                        time.source.read().unwrap().synchronization_generation,
                        first_generation + 1
                    );
                    assert!(closures.local.lock().unwrap().is_empty());
                    assert!(closures.final_records.lock().unwrap().is_empty());

                    let mut close = Box::pin(client.prepare_close(&authority));
                    assert!(futures_util::poll!(&mut close).is_pending());
                    time.failed.store(true, Ordering::Release);
                    assert!(time.clock.interval().is_err());
                    assert!(futures_util::poll!(&mut close).is_pending());
                    time.failed.store(false, Ordering::Release);
                    assert!(time.clock.interval().is_ok());
                    assert!(
                        futures_util::poll!(&mut close).is_pending(),
                        "recovery cannot drain a held effect"
                    );
                    assert!(closures.local.lock().unwrap().is_empty());
                    assert!(process.enter_peer_control().await.is_err());
                    assert_eq!(
                        client.current(Duration::from_secs(5)).await.unwrap(),
                        before
                    );
                    drop(effect);
                    let close = close.await.unwrap();
                    assert_eq!(closures.local.lock().unwrap().len(), 1);
                    assert!(closures.final_records.lock().unwrap().is_empty());
                    let ScopeAuthorityReply::Closed(closed) =
                        client.submit(&close, Duration::from_secs(5)).await.unwrap()
                    else {
                        panic!("explicit positive closure");
                    };
                    assert_eq!(closed.revision(), authority.stamp().revision() + 1);
                    assert!(!client
                        .current(Duration::from_secs(5))
                        .await
                        .unwrap()
                        .is_active());
                    handle.shutdown().await;
                },
            ))
            .catch_unwind()
            .await;
            fleet.quiesce().await;
            result
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                .unwrap();
        });
}
