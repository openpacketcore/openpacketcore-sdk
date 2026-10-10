//! Actual worker TLS plus follower-to-leader class routing and exact batch reads.
use super::*;
use opc_session_store::{
    scope_batch::*,
    scope_scheduler::{ScopeSchedulerKey, ScopeWorkClass},
};

#[test]
fn native_scope_batch_emergency_survives_normal_and_unproven_pressure() {
    const NAME: &str = "stateless_quorum_consumer::scope_transport::batch::native_scope_batch_emergency_survives_normal_and_unproven_pressure";
    const CHILD: &str = "OPC_SCOPE_NATIVE_BATCH_CHILD";
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
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let pki = Arc::new(TestPki::new());
        let mut fleet = ThreeVoterConsumerFleet::start_fixed_durable_classified(pki.clone()).await;
        let result = std::panic::AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(30), async {
            let (leader, _, _) = fleet.wait_for_observed_leader().await;
            fleet.stores[leader].activate_scope_profile().await.unwrap();
            let follower = (leader + 1) % 3;
            let scope = ScopeId::new(fleet.manifest.fixed_durable_quorum_consensus_identity(),
                TenantId::new("test").unwrap(), NetworkFunctionKind::new("scope").unwrap(), [0x56; 32]).unwrap();
            let binding = ScopeBinding::from_scope(&scope).unwrap();
            let local = tempfile::tempdir().unwrap();
            let process = Arc::new(ScopeProcess::new(binding.clone(), [3; 16], BootIdentity::generate().unwrap(),
                std::fs::File::open(local.path()).unwrap()).unwrap());
            let worker = spiffe("scope-worker");
            let execution = ScopeExecution::new(SessionConsumerIdentity::new(worker.clone()).unwrap(), 127, [3; 16],
                *process.boot().process_nonce(), process.boot().key_digest()).unwrap();
            let record = BootAuthorityRecord::new(binding.clone(), execution.clone(), *process.boot().public_key(),
                b"authority-uid".to_vec(), b"rv:127".to_vec()).unwrap();
            let ticket = BootTicket::from_authority_record(&process, &record).unwrap();
            let boots = Arc::new(Boots(std::sync::Mutex::new(record), std::sync::Mutex::new(None)));
            let closures = Arc::new(Closures::default());
            let server_scheduler = ScopeSchedulerOwner::default();
            let client_scheduler = ScopeSchedulerOwner::default();
            let policy = ScopePolicy::new(vec![
                PrincipalGrant::new(opc_types::SpiffeId::new(worker.clone()).unwrap(), ScopeRole::Worker, vec![binding.clone()]).unwrap(),
                PrincipalGrant::new(opc_types::SpiffeId::new(spiffe("scope-controller")).unwrap(), ScopeRole::Controller, vec![binding.clone()]).unwrap(),
                PrincipalGrant::new(opc_types::SpiffeId::new(spiffe("scope-observer")).unwrap(), ScopeRole::Observer, vec![binding.clone()]).unwrap(),
            ]).unwrap();
            let (server_material,server_updates) = rotating_server_tls(&pki,&three_voter_spiffe(follower),"scope-worker");
            let server = Arc::new(ScopeServer::new(ScopeServerConfig {
                tls: server_material, clock: Arc::new(ScopeClock),
                policy, store: Arc::new(fleet.stores[follower].clone()), scopes: vec![scope.clone()],
                boots: boots.clone(), closures: closures.clone(), scheduler: server_scheduler.scheduler(), proofs: ProofBudgets::default(),
            }).unwrap());
            let handle = server.clone().serve([SocketAddr::from(([127, 0, 0, 1], 0)); 5]).await.unwrap();
            let tls = client_tls(&pki, &worker, &follower.to_string());
            let server_id = opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap();
            let client = ScopeClient::new(ScopeClientConfig { process: process.clone(), scope: scope.clone(), ticket,
                tls: tls.clone(), server: server_id.clone(), addresses: handle.addresses(), clock: Arc::new(ScopeClock),
                scheduler: client_scheduler.scheduler(), local_closure: closures.clone() }).unwrap();
            let initial = client.prepare_initial().await.unwrap();
            let ScopeAuthorityReply::Admitted(authority) = client.submit(&initial, Duration::from_secs(5)).await.unwrap()
                else { panic!("own initial authority"); };
            // Establish the current boot on its physical Emergency connection.
            let coordinator = client.batches(&authority, ScopeWorkClass::Emergency, Duration::from_secs(2)).await.unwrap();
            tokio::time::sleep(Duration::from_secs(6)).await;
            let idle = client.batches(&authority, ScopeWorkClass::Emergency, Duration::from_secs(2)).await.map(|_| ());
            client.batches(&authority, ScopeWorkClass::Emergency, Duration::from_secs(2)).await.unwrap();
            server_updates.send_replace(Some(pki.identity_state(&three_voter_spiffe(follower))));
            let rotated = client.batches(&authority, ScopeWorkClass::Emergency, Duration::from_secs(2)).await.map(|_| ());
            client.batches(&authority, ScopeWorkClass::Emergency, Duration::from_secs(2)).await.unwrap();
            assert_eq!((idle,rotated),(Ok(()),Ok(())), "Emergency reconnects before proof after idle close or server rotation");
            let mut siblings = Vec::new();
            for tag in 80..82 {
                siblings.push(crate::scope::protocol_test_support::pending_batch_proof_in_class(tls.clone(), handle.addresses()[2], authority.stamp(), Class::EmergencyClassification, tag).await);
            }
            let pending_tls=tls.clone(); let pending_stamp=authority.stamp().clone(); let pending_address=handle.addresses()[1];
            let queued=tokio::spawn(async move {
                crate::scope::protocol_test_support::pending_batch_proof(pending_tls,pending_address,&pending_stamp,82).await
            });
            tokio::time::timeout(Duration::from_secs(10),async {
                while server.unproven_proof_waiters_for_test(Class::EmergencyClassification)==0 && !queued.is_finished() {
                    tokio::task::yield_now().await;
                }
            }).await.expect("an unproven Emergency call reaches proof admission");
            assert!(!queued.is_finished(),"unproven Emergency must wait in the saturated classification bucket before receiving a challenge");

            // These are real native requests, held after durable handling while
            // both Normal follower-to-leader transport lanes still own replies.
            fleet.normal_reply_hold.armed.store(true, Ordering::Release);
            let mut ordinary = Vec::new();
            for tag in 0..2 {
                let store = fleet.stores[follower].clone();
                ordinary.push(tokio::spawn(async move {
                    store.acquire(&tenant_test_key(TenantId::new(format!("normal-{tag}")).unwrap()),
                        OwnerId::new(format!("normal-{tag}")).unwrap(), Duration::from_secs(30)).await
                }));
            }
            tokio::time::timeout(Duration::from_secs(2), fleet.normal_reply_hold.entered.acquire_many(2)).await.unwrap().unwrap().forget();
            let emergency = coordinator.reserve(ScopeWorkClass::Emergency).await.unwrap().submit(|context| async move {
                context.request([83; 16], Vec::new(), vec![ScopeCounterMutation::new(0, 0, 1).unwrap()])
            }).await.unwrap();
            let completed = tokio::time::timeout(Duration::from_secs(2), emergency.completion()).await
                .expect("established Emergency crosses actual TLS forwarding while Normal replies and unproven proofs remain held");
            assert!(matches!(completed.outcome(), ScopeBatchCompletionOutcome::Applied(_)));
            assert_eq!(completed.attempt().lane(), 7);
            assert!(coordinator.ack(completed.attempt()));
            assert!(ordinary.iter().all(|task| !task.is_finished()), "both Normal replies are still held at Emergency completion");
            drop(siblings);
            drop(tokio::time::timeout(Duration::from_secs(10),queued).await.unwrap().unwrap());

            // A new socket must prove this boot again; promotion is never copied
            // from the lost connection. Keep both Normal reply lanes blocked
            // while a lost Emergency reply reconnects and resolves exactly.
            server.lose_next_committed_reply_for_test();
            let unknown = coordinator.reserve_lane(7, ScopeWorkClass::Emergency).await.unwrap().submit(|context| async move {
                context.request([87; 16], Vec::new(), vec![ScopeCounterMutation::new(0, 1, 2).unwrap()])
            }).await.unwrap();
            let resolved = tokio::time::timeout(Duration::from_secs(2), unknown.completion()).await
                .expect("Emergency reconnect and exact lookup progress while both Normal reply lanes remain held");
            assert!(matches!(resolved.outcome(), ScopeBatchCompletionOutcome::Applied(_)));
            let predecessor_attempt = resolved.attempt().clone();
            assert_eq!(predecessor_attempt.sequence(), 2);
            assert!(coordinator.ack(&predecessor_attempt));
            assert!(ordinary.iter().all(|task| !task.is_finished()));
            fleet.normal_reply_hold.armed.store(false, Ordering::Release);
            fleet.normal_reply_hold.release.add_permits(2);
            for task in ordinary { task.await.unwrap().unwrap(); }

            // A separately known boot sharing the SVID may resolve history, but
            // must queue on classification even if it declares Emergency.
            let candidate_directory = tempfile::tempdir().unwrap();
            let candidate_process = Arc::new(ScopeProcess::new(binding.clone(), [4; 16], BootIdentity::generate().unwrap(),
                std::fs::File::open(candidate_directory.path()).unwrap()).unwrap());
            let candidate_execution = ScopeExecution::new(execution.identity().clone(), 128, [4; 16],
                *candidate_process.boot().process_nonce(), candidate_process.boot().key_digest()).unwrap();
            let record = BootAuthorityRecord::new(binding.clone(), candidate_execution.clone(), *candidate_process.boot().public_key(),
                b"authority-uid".to_vec(), b"rv:128".to_vec()).unwrap();
            let ticket = BootTicket::from_authority_record(&candidate_process, &record).unwrap();
            *boots.0.lock().unwrap() = record;
            // This sibling Pod has its own process-local producer budget; both
            // clients still contend on the same server scheduler and proofs.
            let candidate_scheduler = ScopeSchedulerOwner::default();
            let candidate = ScopeClient::new(ScopeClientConfig { process: candidate_process.clone(), scope: scope.clone(), ticket,
                tls: tls.clone(), server: server_id.clone(), addresses: handle.addresses(), clock: Arc::new(ScopeClock),
                scheduler: candidate_scheduler.scheduler(), local_closure: closures.clone() }).unwrap();
            assert_eq!(candidate.batches(&authority, ScopeWorkClass::Emergency, Duration::from_secs(2)).await.err(),
                Some(ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority)),
                "a copied committed capability belongs to a different boot");
            // Bypass the typed client's capability gate with a real channel proof
            // for a non-current boot, and require the server's own refusal.
            let mut advertised=serde_json::to_value(authority.stamp()).unwrap();
            advertised["execution"]=serde_json::to_value(&candidate_execution).unwrap();
            let advertised:ScopeAuthorityStamp=serde_json::from_value(advertised).unwrap();
            // Use an ordinary data lane so classification reaches the explicit
            // currentness guard, rather than the independent lane-7 class guard.
            let forged=ScopeBatchRequest::in_lane(&advertised,[88;16],0,1,Vec::new(),
                vec![ScopeCounterMutation::new(0,2,3).unwrap()]).unwrap();
            let emergency_held=server_scheduler.scheduler().reserve(ScopeSchedulerKey::from_bytes([97;32]),
                ScopeWorkClass::Emergency).await.unwrap().start().await.unwrap();
            let refused=tokio::time::timeout(Duration::from_secs(10),
                crate::scope::attack_test_support::noncurrent_emergency_batch(&tls,handle.addresses()[1],&forged,&candidate_process,&ScopeClock)).await
                .expect("a non-current mutation never needs established Emergency dispatch capacity");
            assert_eq!(refused,ScopeBatchError::Scope(ScopeAuthorityError::Unauthorized),
                "the server refuses a valid non-current proof before a store stale-authority result");
            assert_eq!(server_scheduler.scheduler().snapshot().class(ScopeWorkClass::Emergency).running,1);
            drop(emergency_held);
            let classification = server_scheduler.scheduler().reserve(ScopeSchedulerKey::from_bytes([98; 32]),
                ScopeWorkClass::EmergencyClassification).await.unwrap().start().await.unwrap();
            let query = predecessor_attempt.clone();
            let sibling = candidate.clone();
            let observed = tokio::spawn(async move { sibling.batch_outcome(&query, ScopeWorkClass::Emergency, Duration::from_secs(2)).await });
            tokio::time::timeout(Duration::from_secs(2), async {
                while server_scheduler.scheduler().snapshot().class(ScopeWorkClass::EmergencyClassification).start_waiting == 0 {
                    tokio::task::yield_now().await;
                }
            }).await.expect("a verified non-current boot must wait on classification dispatch, not established Emergency");
            assert_eq!(server_scheduler.scheduler().snapshot().class(ScopeWorkClass::Emergency).running, 0);
            assert_eq!(client_scheduler.scheduler().snapshot().class(ScopeWorkClass::Emergency).running, 0);
            assert_eq!(candidate_scheduler.scheduler().snapshot().class(ScopeWorkClass::Emergency).running, 1);
            let second_result = tokio::time::timeout(Duration::from_secs(1), async {
                let second = coordinator.reserve_lane(6, ScopeWorkClass::Emergency).await.unwrap().submit(|context| async move {
                    context.request([84; 16], Vec::new(), vec![ScopeCounterMutation::new(1, 0, 1).unwrap()])
                }).await.unwrap();
                second.completion().await
            }).await.expect("current worker completes while the candidate remains queued on classification");
            assert!(matches!(second_result.outcome(), ScopeBatchCompletionOutcome::Applied(_)));
            assert!(coordinator.ack(second_result.attempt()));
            assert!(!observed.is_finished(), "candidate read remains held until classification releases");
            drop(classification);
            let observed = observed.await.unwrap().unwrap_or_else(|error| {
                panic!("candidate read after classification release failed: {error}")
            });
            assert!(matches!(observed, ScopeBatchLookup::Applied(_)));
            assert!(candidate_process.enter_peer_control().await.is_err(), "historical reads cannot activate a candidate");
            drop(candidate); drop(candidate_process);

            let read_scheduler = ScopeSchedulerOwner::default();
            for role in ["scope-controller", "scope-observer"] {
                let tls = client_tls(&pki, &spiffe(role), &follower.to_string());
                crate::scope::attack_test_support::controller_cannot_submit_batch_mutation(
                    &tls, handle.addresses()[3], &predecessor_attempt).await;
                let reader = ScopeReadClient::new(ScopeReadClientConfig { scope: scope.clone(),
                    tls, server: server_id.clone(), addresses: handle.addresses(),
                    clock: Arc::new(ScopeClock), scheduler: read_scheduler.scheduler() }).unwrap();
                assert!(matches!(reader.batch_outcome(&predecessor_attempt, ScopeWorkClass::Normal, Duration::from_secs(2)).await.unwrap(), ScopeBatchLookup::Applied(_)));
                assert!(reader.batch_outcome(&predecessor_attempt, ScopeWorkClass::Emergency, Duration::from_secs(2)).await.is_err());
            }
            server.lose_next_committed_reply_for_test();
            let cancelled = coordinator.reserve_lane(0, ScopeWorkClass::Normal).await.unwrap().submit(|context| async move {
                context.request([85; 16], Vec::new(), vec![ScopeCounterMutation::new(2, 0, 1).unwrap()])
            }).await.unwrap();
            assert!(cancelled.cancel());
            let cancellation = cancelled.completion().await;
            assert!(matches!(cancellation.outcome(), ScopeBatchCompletionOutcome::Cancelled));
            assert!(matches!(client.batch_outcome(cancellation.attempt(), ScopeWorkClass::Normal, Duration::from_secs(2)).await.unwrap(), ScopeBatchLookup::Cancelled));
            assert!(coordinator.ack(cancellation.attempt()));

            let close = client.prepare_close(&authority).await.unwrap();
            let ScopeAuthorityReply::Closed(closed) = client.submit(&close, Duration::from_secs(5)).await.unwrap()
                else { panic!("closed predecessor"); };
            let evidence = client.current(Duration::from_secs(2)).await.unwrap().closed_evidence().unwrap();
            drop(coordinator); drop(initial); drop(close); drop(client); drop(process);
            let successor_process = Arc::new(ScopeProcess::new(binding.clone(), [3; 16], BootIdentity::generate().unwrap(),
                std::fs::File::open(local.path()).unwrap()).unwrap());
            let successor_execution = ScopeExecution::new(execution.identity().clone(), 129, [3; 16],
                *successor_process.boot().process_nonce(), successor_process.boot().key_digest()).unwrap();
            let record = BootAuthorityRecord::new(binding, successor_execution, *successor_process.boot().public_key(),
                b"authority-uid".to_vec(), b"rv:129".to_vec()).unwrap();
            let ticket = BootTicket::from_authority_record(&successor_process, &record).unwrap();
            *boots.0.lock().unwrap() = record;
            let successor = ScopeClient::new(ScopeClientConfig { process: successor_process.clone(), scope: scope.clone(), ticket,
                tls, server: server_id, addresses: handle.addresses(), clock: Arc::new(ScopeClock),
                scheduler: client_scheduler.scheduler(), local_closure: closures.clone() }).unwrap();
            assert!(matches!(successor.batch_outcome(&predecessor_attempt, ScopeWorkClass::Normal, Duration::from_secs(2)).await.unwrap(), ScopeBatchLookup::Applied(_)),
                "a successor resolves the predecessor's lost batch reply without its key or resubmission");
            assert!(successor_process.enter_peer_control().await.is_err());
            let pending = successor.prepare_successor(&closed, evidence).await.unwrap();
            let ScopeAuthorityReply::Admitted(next_authority) = successor.submit(&pending, Duration::from_secs(5)).await.unwrap()
                else { panic!("own successor authority"); };
            let recovered = successor.batches(&next_authority, ScopeWorkClass::Normal, Duration::from_secs(2)).await.unwrap();
            let mut completions = recovered.completions();
            for expected_lane in [0, 6, 7] {
                let receipt = completions.next().await;
                assert_eq!(receipt.attempt().lane(), expected_lane);
                assert_eq!(receipt.attempt().stamp().execution(), &execution);
                assert!(recovered.ack(receipt.attempt()));
            }
            let check = recovered.reserve(ScopeWorkClass::Emergency).await.unwrap().submit(|context| async move {
                assert_eq!(&context.view().counters()[..3], &[2, 1, 0], "cancelled writes have no effect and succession retains floors");
                context.request([86; 16], Vec::new(), vec![ScopeCounterMutation::new(0, 2, 3).unwrap()])
            }).await.unwrap();
            let next = check.completion().await;
            assert!(matches!(next.outcome(), ScopeBatchCompletionOutcome::Applied(_)));
            assert!(recovered.ack(next.attempt()));
            handle.shutdown().await;
        })).catch_unwind().await;
        fleet.normal_reply_hold.armed.store(false, Ordering::Release);
        fleet.normal_reply_hold.release.add_permits(16);
        fleet.quiesce().await;
        match result {
            Ok(Ok(())) => {},
            Ok(Err(error)) => panic!("bounded native batch scenario: {error}"),
            Err(error) => std::panic::resume_unwind(error),
        }
    });
}
