//! Public worker point reads and borrowed predicate reads reach the real follower RPC.
use super::*;
use opc_session_store::{
    scope_batch::*,
    scope_scheduler::{ClassBudget, ScopeSchedulerBudgets, ScopeWorkClass},
};
use tokio::time::Instant;

fn key(tag: u8) -> ScopeChildKey {
    ScopeChildKey::new([tag; 32]).unwrap()
}

fn value(tag: u8) -> ScopeSealedValue {
    ScopeSealedValue::new(
        opc_crypto::CryptoEnvelopeV1 {
            algorithm: opc_key::AeadAlgorithm::Aes256GcmSiv,
            key_id: opc_key::KeyId::new("child-read-tls-fixture").unwrap(),
            nonce: vec![tag; 12],
            aad: vec![tag; 32],
            ciphertext_and_tag: vec![tag; 32],
        }
        .encode()
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn native_scope_child_read_client_keeps_one_barrier_on_fresh_and_reused_connections() {
    run(
        false,
        concat!(
            "stateless_quorum_consumer::scope_transport::child_reads::",
            "native_scope_child_read_client_keeps_one_barrier_on_fresh_and_reused_connections"
        ),
    );
}

#[test]
fn native_scope_child_read_builder_reuses_running_credit_and_bounds_all_exchanges() {
    run(
        true,
        concat!(
            "stateless_quorum_consumer::scope_transport::child_reads::",
            "native_scope_child_read_builder_reuses_running_credit_and_bounds_all_exchanges"
        ),
    );
}

fn run(builder: bool, name: &str) {
    const CHILD: &str = "OPC_SCOPE_CHILD_READ_TLS_CHILD";
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
        let result = std::panic::AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(30), async {
            let (leader, _, _) = fleet.wait_for_observed_leader().await;
            fleet.stores[leader].activate_scope_profile().await.unwrap();
            let follower = (leader + 1) % 3;
            let scope = ScopeId::new(fleet.manifest.fixed_durable_quorum_consensus_identity(),
                TenantId::new("test").unwrap(), NetworkFunctionKind::new("scope").unwrap(), [0x63; 32]).unwrap();
            let binding = ScopeBinding::from_scope(&scope).unwrap();
            let local = tempfile::tempdir().unwrap();
            let process = Arc::new(ScopeProcess::new(binding.clone(), [3; 16], BootIdentity::generate().unwrap(),
                std::fs::File::open(local.path()).unwrap()).unwrap());
            let worker = spiffe("scope-worker");
            let execution = ScopeExecution::new(SessionConsumerIdentity::new(worker.clone()).unwrap(), 127, [3; 16],
                *process.boot().process_nonce(), process.boot().key_digest()).unwrap();
            let record = BootAuthorityRecord::new(binding.clone(), execution, *process.boot().public_key(),
                b"authority-uid".to_vec(), b"rv:127".to_vec()).unwrap();
            let ticket = BootTicket::from_authority_record(&process, &record).unwrap();
            let boots = Arc::new(Boots(std::sync::Mutex::new(record), std::sync::Mutex::new(None)));
            let closures = Arc::new(Closures::default());
            let server_scheduler = ScopeSchedulerOwner::default();
            let client_scheduler = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
                ScopeWorkClass::Normal, ClassBudget { queued: 4, running: 1 })).unwrap();
            let policy = ScopePolicy::new(vec![PrincipalGrant::new(opc_types::SpiffeId::new(worker.clone()).unwrap(),
                ScopeRole::Worker, vec![binding.clone()]).unwrap()]).unwrap();
            let server = Arc::new(ScopeServer::new(ScopeServerConfig {
                tls: server_tls(&pki, &three_voter_spiffe(follower), "scope-worker"), clock: Arc::new(ScopeClock),
                policy, store: Arc::new(fleet.stores[follower].clone()), scopes: vec![scope.clone()],
                boots, closures: closures.clone(), scheduler: server_scheduler.scheduler(), proofs: ProofBudgets::default(),
            }).unwrap());
            let handle = server.clone().serve([SocketAddr::from(([127, 0, 0, 1], 0)); 5]).await.unwrap();
            let client = ScopeClient::new(ScopeClientConfig { process: process.clone(), scope: scope.clone(), ticket,
                tls: client_tls(&pki, &worker, &follower.to_string()),
                server: opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap(), addresses: handle.addresses(),
                clock: Arc::new(ScopeClock), scheduler: client_scheduler.scheduler(), local_closure: closures }).unwrap();
            let initial = client.prepare_initial().await.unwrap();
            let ScopeAuthorityReply::Admitted(authority) = client.submit(&initial, Duration::from_secs(5)).await.unwrap()
                else { panic!("own initial authority"); };
            let batches = client.batches(&authority, ScopeWorkClass::Normal, Duration::from_secs(2)).await.unwrap();
            let write = batches.reserve_lane(0, ScopeWorkClass::Normal).await.unwrap().submit(|context| async move {
                context.request([61; 16], vec![1, 2].into_iter().map(|tag| ScopeChildMutation::Create {
                    key: key(tag), value: value(tag), claims: vec![ScopeClaimKey::new([tag + 10; 32]).unwrap()],
                }).collect(), vec![])
            }).await.unwrap();
            let written = write.completion().await;
            let ScopeBatchCompletionOutcome::Applied(outcome) = written.outcome() else { panic!("children committed"); };
            assert!(batches.ack(written.attempt()));
            let requested = [key(2), key(9), key(1)];
            if !builder {
                for class in [ScopeWorkClass::Normal, ScopeWorkClass::Emergency,
                    ScopeWorkClass::EmergencyClassification, ScopeWorkClass::Maintenance] {
                    for _ in 0..2 {
                        let barriers = fleet.read_barrier_calls();
                        let log = fleet.stores[leader].status().last_log_index;
                        let rows = client.read_children(&authority, &requested, class, Instant::now() + Duration::from_secs(2)).await.unwrap();
                        assert_eq!(fleet.read_barrier_calls(), barriers + 1, "fresh and pooled RPCs each use one barrier");
                        assert_eq!(fleet.stores[leader].status().last_log_index, log);
                        assert_eq!(rows.len(), 3);
                        assert_eq!(rows[1], None);
                        for (index, tag, revision) in [(0, 2, outcome.rows()[1]), (2, 1, outcome.rows()[0])] {
                            let row = rows[index].as_ref().unwrap();
                            assert_eq!(row.namespace(), authority.stamp().namespace());
                            assert_eq!(row.key(), key(tag));
                            assert_eq!(row.revision(), revision);
                            assert_eq!(row.batch_revision(), outcome.revision());
                            assert_eq!(row.value(), Some(&value(tag)));
                            assert_eq!(row.claims(), &[ScopeClaimKey::new([tag + 10; 32]).unwrap()]);
                        }
                        assert!(batches.lane_status().iter().all(|lane| !lane.occupied), "standalone reads own no replay lane");
                    }
                }
                let barriers = fleet.read_barrier_calls();
                for keys in [vec![], vec![key(1), key(1)], (1..=33).map(key).collect()] {
                    assert_eq!(client.read_children(&authority, &keys, ScopeWorkClass::Normal, Instant::now() + Duration::from_secs(2)).await,
                        Err(ScopeChildReadError::Batch(ScopeBatchError::InvalidRequest)));
                }
                assert_eq!(client.read_child(&authority, key(1), ScopeWorkClass::SafetyControl, Instant::now() + Duration::from_secs(2)).await,
                    Err(ScopeChildReadError::Batch(ScopeBatchError::Scope(ScopeAuthorityError::Unauthorized))));
                assert_eq!(client.read_child(&authority, key(1), ScopeWorkClass::Normal, Instant::now()).await,
                    Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)));
                assert_eq!(fleet.read_barrier_calls(), barriers, "invalid inputs never reach native read admission");
                let held = client_scheduler.scheduler().reserve(
                    opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(&scope), ScopeWorkClass::Normal)
                    .await.unwrap().start().await.unwrap();
                assert_eq!(client.read_child(&authority, key(1), ScopeWorkClass::Normal, Instant::now() + Duration::from_millis(40)).await,
                    Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)), "absolute deadline includes native admission");
                assert_eq!(fleet.read_barrier_calls(), barriers);
                drop(held);
            } else {
                let scheduler = client_scheduler.scheduler();
                let read = batches.reserve_lane(0, ScopeWorkClass::Normal).await.unwrap()
                    .submit_with_reads(ScopeBatchReadBudget::new(Instant::now() + Duration::from_secs(2), 1).unwrap(),
                        |mut reads| Box::pin(async move {
                            assert_eq!(reads.class(), ScopeWorkClass::Normal);
                            let rows = reads.read_children(&requested, Instant::now() + Duration::from_secs(20)).await?;
                            assert_eq!(rows.len(), 3);
                            assert_eq!(rows[1], None);
                            let snapshot = scheduler.snapshot().class(ScopeWorkClass::Normal);
                            assert_eq!((snapshot.resident, snapshot.running), (1, 1), "builder reuses its only running credit");
                            reads.build().request([62; 16], vec![], vec![ScopeCounterMutation::new(0, 0, 1).unwrap()]).map_err(Into::into)
                        })).await.unwrap();
                let done = read.completion().await;
                assert!(matches!(done.outcome(), ScopeBatchCompletionOutcome::Applied(_)));
                assert!(batches.ack(done.attempt()));
                let log = fleet.stores[leader].status().last_log_index;
                let scheduler = client_scheduler.scheduler();
                let exhausted = batches.reserve_lane(0, ScopeWorkClass::Normal).await.unwrap()
                    .submit_with_reads(ScopeBatchReadBudget::new(Instant::now() + Duration::from_secs(2), 1).unwrap(),
                        |mut reads| Box::pin(async move {
                            reads.read_children(&[key(1)], Instant::now() + Duration::from_secs(20)).await?;
                            assert_eq!(scheduler.snapshot().class(ScopeWorkClass::Normal).running, 1);
                            reads.read_children(&[key(2)], Instant::now() + Duration::from_secs(20)).await?;
                            panic!("exhausted read budget cannot reach request construction")
                        })).await.err();
                assert_eq!(exhausted, Some(ScopeChildReadError::ReadBudgetExceeded));
                assert_eq!(fleet.stores[leader].status().last_log_index, log, "failed builder neither submits nor cancels an application batch");
                assert_eq!(client_scheduler.scheduler().snapshot().class(ScopeWorkClass::Normal).resident, 0);
                let expired = batches.reserve_lane(0, ScopeWorkClass::Normal).await.unwrap()
                    .submit_with_reads(ScopeBatchReadBudget::new(Instant::now() + Duration::from_millis(40), 2).unwrap(),
                        |mut reads| Box::pin(async move {
                            reads.read_children(&[key(1)], Instant::now() + Duration::from_secs(20)).await?;
                            std::future::pending::<Result<ScopeBatchRequest, ScopeChildReadError>>().await
                        })).await.err();
                assert_eq!(expired, Some(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)), "whole-builder deadline cannot restart after a read");
                assert_eq!(fleet.stores[leader].status().last_log_index, log);
                assert_eq!(client_scheduler.scheduler().snapshot().class(ScopeWorkClass::Normal).resident, 0);
                assert!(batches.lane_status().iter().all(|lane| !lane.occupied));
            }
            let close = client.prepare_close(&authority).await.unwrap();
            assert!(matches!(client.submit(&close, Duration::from_secs(2)).await.unwrap(), ScopeAuthorityReply::Closed(_)));
            assert_eq!(client.read_child(&authority, key(1), ScopeWorkClass::Normal, Instant::now() + Duration::from_secs(2)).await,
                Err(ScopeChildReadError::Batch(ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority))));
            handle.shutdown().await;
        })).catch_unwind().await;
        fleet.quiesce().await;
        match result {
            Ok(Ok(())) => {},
            Ok(Err(error)) => panic!("bounded child-read TLS scenario: {error}"),
            Err(error) => std::panic::resume_unwind(error),
        }
    });
}
