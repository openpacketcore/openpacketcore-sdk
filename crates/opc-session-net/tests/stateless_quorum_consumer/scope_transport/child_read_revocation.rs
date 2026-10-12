//! A policy revoked during real dispatch admission cannot expose a held cut.
use super::*;
use opc_session_store::{
    scope_batch::*,
    scope_scheduler::{ClassBudget, ScopeSchedulerBudgets, ScopeWorkClass},
};
use tokio::time::Instant;

#[test]
fn native_scope_child_read_held_policy_revocation_returns_unauthorized_without_observation() {
    const CHILD: &str = "OPC_CHILD_READ_REVOKED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "stateless_quorum_consumer::scope_transport::child_read_revocation::native_scope_child_read_held_policy_revocation_returns_unauthorized_without_observation", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
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
                        [0x63; 32],
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
                        execution,
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
                    let server_scheduler =
                        ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
                            ScopeWorkClass::Normal,
                            ClassBudget {
                                queued: 4,
                                running: 1,
                            },
                        ))
                        .unwrap();
                    let client_scheduler =
                        ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
                            ScopeWorkClass::Normal,
                            ClassBudget {
                                queued: 4,
                                running: 1,
                            },
                        ))
                        .unwrap();
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
                            policy: policy.clone(),
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
                        .clone()
                        .serve([SocketAddr::from(([127, 0, 0, 1], 0)); 5])
                        .await
                        .unwrap();
                    let client = ScopeClient::new(ScopeClientConfig {
                        process: process.clone(),
                        scope: scope.clone(),
                        ticket,
                        tls: client_tls(&pki, &worker, &follower.to_string()),
                        server: opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap(),
                        addresses: handle.addresses(),
                        clock: Arc::new(ScopeClock),
                        scheduler: client_scheduler.scheduler(),
                        local_closure: closures,
                    })
                    .unwrap();
                    let initial = client.prepare_initial().await.unwrap();
                    let ScopeAuthorityReply::Admitted(authority) = client
                        .submit(&initial, Duration::from_secs(5))
                        .await
                        .unwrap()
                    else {
                        panic!("own initial authority");
                    };

                    let authority = Arc::new(authority);
                    let key = ScopeChildKey::new([1; 32]).unwrap();
                    let held = server_scheduler
                        .scheduler()
                        .reserve(
                            opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                                &scope,
                            ),
                            ScopeWorkClass::Normal,
                        )
                        .await
                        .unwrap()
                        .start()
                        .await
                        .unwrap();
                    let log = fleet.stores[leader].status().last_log_index;
                    let barriers = fleet.read_barrier_calls();
                    let read_client = client.clone();
                    let read_authority = authority.clone();
                    let reading = tokio::spawn(async move {
                        read_client
                            .read_child(
                                &read_authority,
                                key,
                                ScopeWorkClass::Normal,
                                Instant::now() + Duration::from_secs(5),
                            )
                            .await
                    });
                    tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
                        while fleet.stores[follower].scope_child_read_cuts_for_test() != 1
                            || server_scheduler
                                .scheduler()
                                .snapshot()
                                .class(ScopeWorkClass::Normal)
                                .resident
                                != 2
                        {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .expect("the real current cut waits for Normal dispatch admission");
                    assert_eq!(
                        server.child_read_proof_usage_for_test(Class::Normal),
                        (1, 0)
                    );
                    policy.replace(vec![]).unwrap();
                    drop(held);
                    assert_eq!(
                        reading.await.unwrap(),
                        Err(ScopeChildReadError::Batch(ScopeBatchError::Scope(
                            ScopeAuthorityError::Unauthorized
                        ))),
                        "a revoked admitted read reports Unauthorized and returns no observation"
                    );
                    assert_eq!(fleet.stores[follower].scope_child_read_cuts_for_test(), 0);
                    tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
                        while server.child_read_proof_usage_for_test(Class::Normal) != (0, 0) {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .unwrap();
                    assert_eq!(
                        server_scheduler
                            .scheduler()
                            .snapshot()
                            .class(ScopeWorkClass::Normal)
                            .resident,
                        0
                    );
                    assert_eq!(
                        client_scheduler
                            .scheduler()
                            .snapshot()
                            .class(ScopeWorkClass::Normal)
                            .resident,
                        0
                    );
                    assert_eq!(fleet.read_barrier_calls(), barriers + 1);
                    assert_eq!(fleet.stores[leader].status().last_log_index, log);
                    policy
                        .replace(vec![PrincipalGrant::new(
                            opc_types::SpiffeId::new(worker).unwrap(),
                            ScopeRole::Worker,
                            vec![binding],
                        )
                        .unwrap()])
                        .unwrap();
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
                    assert_eq!(fleet.stores[leader].status().last_log_index, log);
                    handle.shutdown().await;
                },
            ))
            .catch_unwind()
            .await;
            fleet.quiesce().await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => panic!("bounded held revocation: {error}"),
                Err(error) => std::panic::resume_unwind(error),
            }
        });
}
