//! Hold real server cuts and inspect the reserved proof and execution budgets.
use super::*;
use crate::scope::attack_test_support::cross_slot::{RawCall, RawPeer};
use opc_session_store::{
    scope_batch::*,
    scope_scheduler::{ClassBudget, ScopeSchedulerBudgets, ScopeWorkClass},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    PeerClose,
    CutExpiry,
    Promotion,
}

#[test]
fn native_scope_child_read_peer_close_releases_cut_and_proof_while_admission_is_held() {
    run(
        Scenario::PeerClose,
        concat!(
            "stateless_quorum_consumer::scope_transport::child_read_guards::",
            "native_scope_child_read_peer_close_releases_cut_and_proof_while_admission_is_held"
        ),
    );
}

#[test]
fn native_scope_child_read_ten_second_cut_bound_returns_retry_and_releases_ownership() {
    run(
        Scenario::CutExpiry,
        concat!(
            "stateless_quorum_consumer::scope_transport::child_read_guards::",
            "native_scope_child_read_ten_second_cut_bound_returns_retry_and_releases_ownership"
        ),
    );
}

#[test]
fn native_scope_child_read_promotes_only_after_current_cut_and_clears_stale_hint() {
    run(
        Scenario::Promotion,
        concat!(
            "stateless_quorum_consumer::scope_transport::child_read_guards::",
            "native_scope_child_read_promotes_only_after_current_cut_and_clears_stale_hint"
        ),
    );
}

async fn eventually(check: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !check() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("held child read reaches or releases its exact resource boundary");
}

fn run(scenario: Scenario, name: &str) {
    const CHILD: &str = "OPC_SCOPE_CHILD_READ_GUARDS_CHILD";
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
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let pki = Arc::new(TestPki::new());
        let mut fleet = ThreeVoterConsumerFleet::start_fixed_durable_classified(pki.clone()).await;
        let result = std::panic::AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(30), async {
            let (leader, _, _) = fleet.wait_for_observed_leader().await;
            fleet.stores[leader].activate_scope_profile().await.unwrap();
            let follower = (leader + 1) % 3;
            let scope = ScopeId::new(fleet.manifest.fixed_durable_quorum_consensus_identity(), TenantId::new("test").unwrap(),
                NetworkFunctionKind::new("scope").unwrap(), [0x64; 32]).unwrap();
            let binding = ScopeBinding::from_scope(&scope).unwrap();
            let worker = spiffe("scope-worker");
            let peer = Arc::new(RawPeer::new(&scope, SessionConsumerIdentity::new(worker.clone()).unwrap(), 23));
            let boots = Arc::new(Boots(std::sync::Mutex::new(peer.record.clone()), std::sync::Mutex::new(None)));
            let closures = Arc::new(Closures::default());
            let scheduler = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
                ScopeWorkClass::Normal, ClassBudget { queued: 4, running: 1 })).unwrap();
            let server = Arc::new(ScopeServer::new(ScopeServerConfig {
                tls: server_tls(&pki, &three_voter_spiffe(follower), "scope-worker"), clock: Arc::new(ScopeClock),
                policy: ScopePolicy::new(vec![PrincipalGrant::new(opc_types::SpiffeId::new(worker.clone()).unwrap(), ScopeRole::Worker, vec![binding.clone()]).unwrap()]).unwrap(),
                store: Arc::new(fleet.stores[follower].clone()), scopes: vec![scope.clone()], boots, closures: closures.clone(),
                scheduler: scheduler.scheduler(), proofs: ProofBudgets::default(),
            }).unwrap());
            let handle = server.clone().serve([SocketAddr::from(([127, 0, 0, 1], 0)); 5]).await.unwrap();
            let tls = client_tls(&pki, &worker, &follower.to_string());
            let initial = ScopeAuthorityRequest::new(scope.clone(), [81; 16], 0,
                ScopeAuthorityOperation::AdmitInitial { execution: peer.record.execution().clone() }).unwrap();
            let mut admitted = peer.send(&tls, handle.addresses(), &scope, peer.record.execution(), RawCall::Authority(&initial), &ScopeClock).await.unwrap();
            assert_eq!(admitted.pop(), Some(1));
            let stamp = ScopeAuthorityStamp::decode_canonical(&admitted).unwrap();
            let request = ScopeChildReadRequest::new(&stamp, vec![ScopeChildKey::new([3; 32]).unwrap()]).unwrap();
            let class = if scenario == Scenario::Promotion { Class::Emergency } else { Class::Normal };
            let socket = tokio::net::TcpStream::connect(handle.addresses()[if class == Class::Emergency { 1 } else { 3 }]).await.unwrap();
            socket.set_nodelay(true).unwrap();
            let mut stream = tls.begin_handshake().unwrap().connect_scope(socket, binding.tls_domain().unwrap()).await.unwrap();
            let log = fleet.stores[leader].status().last_log_index;
            if scenario != Scenario::Promotion {
                let held = scheduler.scheduler().reserve(opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(&scope), ScopeWorkClass::Normal)
                    .await.unwrap().start().await.unwrap();
                let p = peer.clone();
                let r = request.clone();
                let reading = tokio::spawn(async move { p.child_read_on(stream, &r, class, 82, &ScopeClock).await });
                eventually(|| fleet.stores[follower].scope_child_read_cuts_for_test() == 1
                    && scheduler.scheduler().snapshot().class(ScopeWorkClass::Normal).resident == 2).await;
                assert_eq!(server.child_read_proof_usage_for_test(Class::Normal), (1, 0));
                assert_eq!(scheduler.scheduler().snapshot().class(ScopeWorkClass::Normal).running, 1,
                    "only the held dispatch credit runs before the child receives admission");
                if scenario == Scenario::PeerClose {
                    reading.abort();
                    assert!(matches!(reading.await, Err(error) if error.is_cancelled()));
                    eventually(|| fleet.stores[follower].scope_child_read_cuts_for_test() == 0
                        && server.child_read_proof_usage_for_test(Class::Normal) == (0, 0)
                        && scheduler.scheduler().snapshot().class(ScopeWorkClass::Normal).resident == 1).await;
                    drop(held);
                } else {
                    tokio::time::pause();
                    tokio::time::advance(Duration::from_secs(9)).await;
                    let finished_early = reading.is_finished();
                    tokio::time::advance(Duration::from_secs(1)).await;
                    tokio::time::resume();
                    assert!(!finished_early, "the held cut survives before its fixed maximum");
                    let (next, reply) = tokio::time::timeout(Duration::from_secs(1), reading).await
                        .expect("the fixed ten-second maximum ends class admission without a peer deadline").unwrap();
                    assert_eq!((reply.status, reply.body), (0, vec![0, 3]), "an expired cut returns Retry, never a late observation");
                    assert_eq!(fleet.stores[follower].scope_child_read_cuts_for_test(), 0);
                    eventually(|| server.child_read_proof_usage_for_test(Class::Normal) == (0, 0)).await;
                    assert_eq!(scheduler.scheduler().snapshot().class(ScopeWorkClass::Normal).resident, 1);
                    drop(held);
                    let (_, reply) = peer.child_read_on(next, &request, class, 83, &ScopeClock).await;
                    assert_eq!(reply.status, 7, "the same peer can read again after the expired cut is released");
                }
                assert_eq!(fleet.stores[leader].status().last_log_index, log);
            } else {
                for round in 0..4 {
                    if round == 2 {
                        let local = LocalClosureRecord::new(stamp.clone(), [84; 32]).unwrap();
                        let digest = local.digest().unwrap();
                        closures.local.lock().unwrap().insert(digest, local);
                        let close = ScopeAuthorityRequest::new(scope.clone(), [84; 16], stamp.revision(),
                            ScopeAuthorityOperation::Close { current: stamp.clone(), evidence: ScopeClosureEvidence::new(ScopeClosureKind::LocalQuiescence, digest).unwrap() }).unwrap();
                        let mut closed = peer.send(&tls, handle.addresses(), &scope, peer.record.execution(), RawCall::Authority(&close), &ScopeClock).await.unwrap();
                        assert_eq!(closed.pop(), Some(0));
                    }
                    let pause = fleet.stores[follower].pause_next_scope_child_read_for_test(ScopeChildReadStage::BeforeCapture);
                    let p = peer.clone();
                    let r = request.clone();
                    let reading = tokio::spawn(async move { p.child_read_on(stream, &r, class, 90 + round, &ScopeClock).await });
                    pause.reached().await;
                    let promoted = round == 1 || round == 2;
                    assert_eq!(server.child_read_proof_usage_for_test(Class::Emergency), (0, usize::from(promoted)),
                        "only a previously verified current cut selects WorkerCurrent: round {round}");
                    assert_eq!(server.child_read_proof_usage_for_test(Class::EmergencyClassification), (usize::from(!promoted), 0),
                        "unpromoted Emergency uses only classification WorkerUnproven: round {round}");
                    assert_eq!(scheduler.scheduler().snapshot().class(ScopeWorkClass::Emergency).running, 0,
                        "no Emergency dispatch credit before the current cut, including a stale boot");
                    pause.release();
                    let (next, reply) = reading.await.unwrap();
                    stream = next;
                    if round < 2 {
                        assert_eq!(reply.status, 7);
                        assert_eq!(crate::scope::child_read_wire::decode_observation(&request, &reply.body).unwrap(), vec![None]);
                    } else {
                        assert_eq!(reply.status, 5);
                        assert_eq!(ScopeBatchError::decode_canonical(&reply.body).unwrap(), ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority));
                    }
                    assert_eq!(fleet.stores[follower].scope_child_read_cuts_for_test(), 0);
                }
                // The next stale read also has no retained current promotion.
                drop(stream);
            }
            handle.shutdown().await;
        })).catch_unwind().await;
        fleet.quiesce().await;
        match result { Ok(Ok(())) => {}, Ok(Err(error)) => panic!("bounded child-read guard scenario: {error}"), Err(error) => std::panic::resume_unwind(error) }
    });
}
