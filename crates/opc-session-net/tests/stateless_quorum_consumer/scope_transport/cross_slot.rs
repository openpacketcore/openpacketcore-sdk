//! One worker SVID grants routing to two slots, never possession of both keys.
use super::*;
use crate::scope::attack_test_support::cross_slot::{RawCall, RawPeer};
use opc_session_store::scope_batch::*;

struct SlotBoots {
    records: HashMap<[u8; 32], BootAuthorityRecord>,
    inconsistent: std::sync::Mutex<Option<BootAuthorityRecord>>,
}
#[async_trait]
impl ScopeBootAuthority for SlotBoots {
    async fn read_current(
        &self,
        scope: &ScopeBinding,
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
        self.records
            .get(&scope.commitment())
            .cloned()
            .ok_or(ScopeEvidenceError::Mismatch)
    }
    async fn read_known(
        &self,
        scope: &ScopeBinding,
        key: [u8; 32],
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
        if let Some(record) = self.inconsistent.lock().unwrap().clone() {
            return Ok(record);
        }
        self.records
            .get(&scope.commitment())
            .filter(|record| record.execution().boot_key() == &key)
            .cloned()
            .ok_or(ScopeEvidenceError::Mismatch)
    }
}

#[test]
fn native_scope_shared_identity_cannot_sign_for_another_slots_boot() {
    const NAME: &str = "stateless_quorum_consumer::scope_transport::cross_slot::native_scope_shared_identity_cannot_sign_for_another_slots_boot";
    const CHILD: &str = "OPC_SCOPE_NATIVE_CROSS_SLOT_CHILD";
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
    tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap().block_on(async {
        let pki = Arc::new(TestPki::new());
        let mut fleet = ThreeVoterConsumerFleet::start_fixed_durable_classified(pki.clone()).await;
        let result = std::panic::AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(60), async {
            let (leader, _, _) = fleet.wait_for_observed_leader().await;
            fleet.stores[leader].activate_scope_profile().await.unwrap();
            let follower = (leader + 1) % 3;
            let scopes = [0x57, 0x58].map(|tag| ScopeId::new(
                fleet.manifest.fixed_durable_quorum_consensus_identity(),
                TenantId::new("test").unwrap(), NetworkFunctionKind::new("scope").unwrap(), [tag; 32]).unwrap());
            let bindings = scopes.each_ref().map(|scope| ScopeBinding::from_scope(scope).unwrap());
            let worker = spiffe("scope-worker");
            let identity = SessionConsumerIdentity::new(worker.clone()).unwrap();
            let peers = [RawPeer::new(&scopes[0], identity.clone(), 21), RawPeer::new(&scopes[1], identity, 22)];
            assert_ne!(peers[0].record.execution().boot_key(), peers[1].record.execution().boot_key());
            let boots = Arc::new(SlotBoots {
                records: bindings.iter().zip(&peers).map(|(scope, peer)| (scope.commitment(), peer.record.clone())).collect(),
                inconsistent: std::sync::Mutex::new(None),
            });
            let closures = Arc::new(Closures::default());
            let scheduler = ScopeSchedulerOwner::default();
            let server = Arc::new(ScopeServer::new(ScopeServerConfig {
                tls: server_tls(&pki, &three_voter_spiffe(follower), "scope-worker"),
                clock: Arc::new(ScopeClock),
                policy: ScopePolicy::new(vec![PrincipalGrant::new(
                    opc_types::SpiffeId::new(worker.clone()).unwrap(), ScopeRole::Worker, bindings.to_vec()).unwrap()]).unwrap(),
                store: Arc::new(fleet.stores[follower].clone()), scopes: scopes.to_vec(),
                boots: boots.clone(), closures: closures.clone(), scheduler: scheduler.scheduler(), proofs: ProofBudgets::default(),
            }).unwrap());
            let handle = server.serve([SocketAddr::from(([127, 0, 0, 1], 0)); 5]).await.unwrap();
            // Both raw peers use exactly the same transport identity and grants.
            let tls = client_tls(&pki, &worker, &follower.to_string());
            let addresses = handle.addresses();
            let admissions = std::array::from_fn::<_, 2, _>(|index| ScopeAuthorityRequest::new(
                scopes[index].clone(), [61 + index as u8; 16], 0,
                ScopeAuthorityOperation::AdmitInitial { execution: peers[index].record.execution().clone() }).unwrap());
            let mut stamps = Vec::new();
            for index in 0..2 {
                let mut committed = peers[index].send(&tls, addresses, &scopes[index], peers[index].record.execution(),
                    RawCall::Authority(&admissions[index]), &ScopeClock).await.unwrap();
                assert_eq!(committed.pop(), Some(1));
                let stamp = ScopeAuthorityStamp::decode_canonical(&committed).unwrap();
                assert_eq!(stamp.scope(), &scopes[index]);
                assert_eq!(stamp.execution(), peers[index].record.execution());
                stamps.push(stamp);
            }
            let scope_b = &scopes[1];
            let stamp_b = &stamps[1];
            let execution_b = peers[1].record.execution();
            let apply = ScopeBatchRequest::in_lane(stamp_b, [63; 16], 0, 1, Vec::new(),
                vec![ScopeCounterMutation::new(0, 0, 1).unwrap()]).unwrap();
            let cancel = ScopeBatchRequest::in_lane(stamp_b, [64; 16], 1, 1, Vec::new(),
                vec![ScopeCounterMutation::new(1, 0, 1).unwrap()]).unwrap().attempt().unwrap();
            // Supply otherwise valid independent closure evidence so a missing
            // boot-key check cannot be hidden by an unrelated evidence refusal.
            let local = LocalClosureRecord::new(stamp_b.clone(), [65; 32]).unwrap();
            let digest = local.digest().unwrap();
            closures.local.lock().unwrap().insert(digest, local);
            let close = ScopeAuthorityRequest::new(scope_b.clone(), [66; 16], stamp_b.revision(),
                ScopeAuthorityOperation::Close { current: stamp_b.clone(),
                    evidence: ScopeClosureEvidence::new(ScopeClosureKind::LocalQuiescence, digest).unwrap() }).unwrap();
            let attacks = [RawCall::ApplyBatch(&apply), RawCall::BatchCancel(&cancel), RawCall::Authority(&close),
                RawCall::Current, RawCall::Outcome(&admissions[1]), RawCall::BatchReopen(stamp_b), RawCall::BatchLookup(&cancel)];
            let before = peers[1].send(&tls, addresses, scope_b, execution_b, RawCall::BatchReopen(stamp_b), &ScopeClock).await.unwrap();
            let cut = ScopeBatchReopen::decode_canonical(&before).unwrap();
            assert!(matches!(cut, ScopeBatchReopen::Initialized(ref state) if state.authority().is_active()));
            for call in attacks {
                let reads = fleet.read_barrier_calls();
                let log = fleet.stores[leader].status().last_log_index;
                let answer = peers[0].send(&tls, addresses, scope_b, execution_b, call, &ScopeClock).await;
                assert_eq!(answer.err(), Some(ScopeRpcError::Unauthorized),
                    "{} signed by slot A must not claim slot B's execution", call.label());
                if call.carries_execution() {
                    assert_eq!(fleet.read_barrier_calls(), reads,
                        "{} with the wrong boot key must be rejected before any native store read", call.label());
                }
                assert_eq!(fleet.stores[leader].status().last_log_index, log,
                    "{} must not append a native store command", call.label());
                let after = peers[1].send(&tls, addresses, scope_b, execution_b, RawCall::BatchReopen(stamp_b), &ScopeClock).await.unwrap();
                assert_eq!(after, before, "{} must leave authority, counters, floors and all lane receipts unchanged", call.label());
            }
            // Read calls carry no execution in their native payload. Inject an
            // inconsistent retained record to reach the second boot-key check
            // independently of the first mutation check and the record lookup.
            *boots.inconsistent.lock().unwrap() = Some(peers[0].inconsistent_retained_record(&peers[1]));
            for call in attacks.into_iter().filter(|call| !call.carries_execution()) {
                let log = fleet.stores[leader].status().last_log_index;
                let answer = peers[0].send(&tls, addresses, scope_b, execution_b, call, &ScopeClock).await;
                assert_eq!(answer.err(), Some(ScopeRpcError::Unauthorized),
                    "{} must bind the retained execution to the signing boot key", call.label());
                assert_eq!(fleet.stores[leader].status().last_log_index, log);
            }
            *boots.inconsistent.lock().unwrap() = None;
            assert_eq!(peers[1].send(&tls, addresses, scope_b, execution_b, RawCall::BatchReopen(stamp_b), &ScopeClock).await.unwrap(), before);

            // Positive controls use the identical wire payloads with B's key.
            // A still observes its own slot, and all four B reads succeed.
            peers[0].send(&tls, addresses, &scopes[0], peers[0].record.execution(), RawCall::Current, &ScopeClock).await.unwrap();
            for call in attacks.into_iter().filter(|call| !call.carries_execution()) {
                peers[1].send(&tls, addresses, scope_b, execution_b, call, &ScopeClock).await.unwrap();
            }
            let applied = peers[1].send(&tls, addresses, scope_b, execution_b, RawCall::ApplyBatch(&apply), &ScopeClock).await.unwrap();
            let applied = ScopeBatchOutcome::decode_canonical(&applied).unwrap();
            assert_eq!((applied.lane(), applied.sequence(), applied.counters()[0]), (0, 1, 1));
            let cancelled = peers[1].send(&tls, addresses, scope_b, execution_b, RawCall::BatchCancel(&cancel), &ScopeClock).await.unwrap();
            let cancelled = ScopeBatchReceipt::decode_canonical(&cancelled).unwrap();
            assert_eq!(cancelled.attempt(), &cancel);
            assert!(matches!(cancelled.terminal(), ScopeBatchTerminal::Cancelled));
            let mut closed = peers[1].send(&tls, addresses, scope_b, execution_b, RawCall::Authority(&close), &ScopeClock).await.unwrap();
            assert_eq!(closed.pop(), Some(0));
            let closed = ScopeAuthorityStamp::decode_canonical(&closed).unwrap();
            assert_eq!(closed.execution(), execution_b);
            handle.shutdown().await;
        })).catch_unwind().await;
        fleet.quiesce().await;
        match result {
            Ok(Ok(())) => {},
            Ok(Err(error)) => panic!("bounded native cross-slot scenario: {error}"),
            Err(error) => std::panic::resume_unwind(error),
        }
    });
}
