use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::voter_slots::*;
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusNodeId, ConsensusRequestId,
};
use tokio::sync::{oneshot, Notify};
use tokio::time::Instant;

fn member(slot: u16, incarnation: u64) -> VoterSlotMember {
    VoterSlotMember {
        identity: VoterSlotIdentity::new(
            SlotId::new(slot).unwrap(),
            VoterIncarnation::new(incarnation).unwrap(),
        ),
        key_digest: [incarnation as u8; 32],
        descriptor_digest: [slot as u8; 32],
        admission_generation: incarnation,
    }
}
fn node(slot: u16) -> ConsensusNodeId {
    member(slot, 1).identity.node_id()
}
fn genesis() -> VoterSlotTable {
    VoterSlotTable {
        cluster_instance: ConsensusClusterId::from_bytes([3; 32]),
        manifest_digest: [4; 32],
        revision: 1,
        configuration_epoch: ConsensusConfigurationEpoch::new(1).unwrap(),
        slots: (1..=3)
            .map(|slot| VoterSlotRecord {
                member: member(slot, 1),
                retired_through: 0,
                phase: VoterSlotPhase::Voting,
                last_result: None,
            })
            .collect(),
        replacement: None,
    }
}
fn request(slot: u16, seed: u8) -> VoterReplacementRequest {
    let table = genesis();
    let candidate = member(slot, 2);
    let configuration = table
        .current_configuration()
        .identity(table.cluster_instance, table.manifest_digest)
        .unwrap();
    let mut claims = LostVoterAttestationV1 {
        request_id: ConsensusRequestId::from_bytes([seed; 16]),
        request_digest: [0; 32],
        cluster_instance: table.cluster_instance,
        slot: SlotId::new(slot).unwrap(),
        expected_incarnation: VoterIncarnation::new(1).unwrap(),
        old_descriptor_digest: [slot as u8; 32],
        candidate_key_digest: candidate.key_digest,
        admission_generation: 2,
        candidate_spiffe_id: format!("spiffe://example.test/voter/{slot}"),
        controller_spiffe_id: "spiffe://example.test/controller".into(),
        signing_key_digest: [7; 32],
        reason: VoterLossReason::TimeBoundLoss,
        policy_digest: [8; 32],
        observation_start_ms: 100,
        decision_ms: 200,
        issued_ms: 200,
        expires_ms: 300,
        signature: [9; 64],
    };
    claims.request_digest =
        voter_replacement_request_digest(1, configuration, &candidate, &claims).unwrap();
    VoterReplacementRequest {
        expected_revision: 1,
        expected_configuration: configuration,
        candidate,
        attestation: claims,
    }
}

#[derive(Debug)]
struct Reader(Mutex<VoterSlotDurableState>);
#[async_trait]
impl VoterSlotStateReader for Reader {
    async fn read_voter_slot_state(&self) -> Result<VoterSlotDurableState, VoterReplacementError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Default, Debug)]
struct FenceEngine {
    events: Mutex<Vec<String>>,
    closed: Mutex<BTreeSet<ConsensusNodeId>>,
}
#[async_trait]
impl VoterResponseFenceEngine for FenceEngine {
    type Receipt = ConsensusNodeId;
    fn disable_application_leases(&self) {
        self.events.lock().unwrap().push("leases-disabled".into());
    }
    async fn effective_members(&self) -> Result<BTreeSet<ConsensusNodeId>, VoterReplacementError> {
        Ok((1..=3).map(node).collect())
    }
    async fn fence(&self, peer: ConsensusNodeId) -> Result<Self::Receipt, VoterReplacementError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("fence-{}", peer.get()));
        self.closed.lock().unwrap().insert(peer);
        Ok(peer)
    }
    async fn release(&self, receipt: Self::Receipt) -> Result<(), VoterReplacementError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("release-{}", receipt.get()));
        self.closed.lock().unwrap().remove(&receipt);
        Ok(())
    }
    async fn ensure_surviving_quorum(&self, _: Instant) -> Result<(), VoterReplacementError> {
        self.events.lock().unwrap().push("quorum".into());
        Ok(())
    }
    fn enable_voting(&self, enabled: bool) {
        self.events
            .lock()
            .unwrap()
            .push(format!("voting-{enabled}"));
    }
}

async fn runtime(
    state: VoterSlotDurableState,
) -> (
    Arc<VoterAdmission<FenceEngine>>,
    Arc<Reader>,
    Arc<FenceEngine>,
) {
    let reader = Arc::new(Reader(Mutex::new(state)));
    let engine = Arc::new(FenceEngine::default());
    let admission = VoterAdmission::new(node(1), reader.clone()).await.unwrap();
    assert_eq!(
        admission
            .run_peer(node(2), Instant::now() + Duration::from_secs(1), || async {
                Ok(())
            })
            .await,
        Err(VoterReplacementError::Unavailable)
    );
    admission.attach_engine(engine.clone()).await.unwrap();
    (admission, reader, engine)
}

#[tokio::test(start_paused = true)]
async fn snapshot_fences_before_install_and_cancellation_keeps_the_barrier_owned() {
    let (admission, reader, engine) = runtime(VoterSlotDurableState::new(genesis()).unwrap()).await;
    let mut incoming = genesis();
    let cut = VoterSlotLogId { term: 2, index: 10 };
    incoming
        .apply_control(&VoterSlotControl::Begin(Box::new(request(3, 1))), cut)
        .unwrap();
    let (entered, start) = oneshot::channel();
    let (complete, finish) = oneshot::channel();
    let runtime = admission.clone();
    let installing_engine = engine.clone();
    let installing = tokio::spawn(async move {
        runtime
            .run_snapshot(
                incoming.clone(),
                (1..=3).map(node).collect(),
                Instant::now() + Duration::from_secs(30),
                move || async move {
                    assert!(installing_engine.closed.lock().unwrap().contains(&node(3)));
                    entered.send(()).unwrap();
                    finish.await.unwrap();
                    reader
                        .0
                        .lock()
                        .unwrap()
                        .publish_snapshot(incoming, cut)
                        .unwrap();
                    Ok(())
                },
            )
            .await
    });
    start.await.unwrap();
    installing.abort();
    assert_eq!(
        admission
            .run_peer(node(3), Instant::now() + Duration::from_secs(1), || async {
                Ok(())
            })
            .await,
        Err(VoterReplacementError::UnauthorizedReplacement)
    );
    complete.send(()).unwrap();
    admission.reconcile().await.unwrap();
    assert!(engine.closed.lock().unwrap().contains(&node(3)));
    assert!(admission
        .durable_view()
        .unwrap()
        .table()
        .is_retired(node(3)));
}

#[tokio::test(start_paused = true)]
async fn restart_installs_durable_fences_before_admitting_rpc_or_voting() {
    let mut state = VoterSlotDurableState::new(genesis()).unwrap();
    state
        .append_intent(VoterSlotIntent {
            log_id: VoterSlotLogId { term: 1, index: 10 },
            request: request(3, 1),
        })
        .unwrap();
    let (admission, _, engine) = runtime(state).await;
    assert_eq!(
        admission
            .run_peer(node(3), Instant::now() + Duration::from_secs(1), || async {
                panic!("retired peer reached engine");
                #[allow(unreachable_code)]
                Ok(())
            })
            .await,
        Err(VoterReplacementError::UnauthorizedReplacement)
    );
    assert_eq!(
        admission
            .run_peer(node(2), Instant::now() + Duration::from_secs(1), || async {
                Ok(17)
            })
            .await,
        Ok(17)
    );
    let events = engine.events.lock().unwrap();
    let lease = events
        .iter()
        .position(|event| event == "leases-disabled")
        .unwrap();
    let fence = events.iter().position(|event| event == "fence-3").unwrap();
    let voting = events
        .iter()
        .position(|event| event == "voting-true")
        .unwrap();
    assert!(lease < fence && fence < voting, "{events:?}");
}

#[tokio::test(start_paused = true)]
async fn cancellation_keeps_a_peer_call_owned_until_definitive_engine_completion() {
    let (admission, _, engine) = runtime(VoterSlotDurableState::new(genesis()).unwrap()).await;
    tokio::time::advance(VOTER_RECENT_TRAFFIC_WINDOW).await;
    let (entered, start) = oneshot::channel();
    let (complete, finish) = oneshot::channel();
    let peer = admission.clone();
    let call = tokio::spawn(async move {
        peer.run_peer(
            node(3),
            Instant::now() + Duration::from_secs(30),
            || async move {
                entered.send(()).unwrap();
                finish.await.unwrap();
                Ok(())
            },
        )
        .await
    });
    start.await.unwrap();
    call.abort();
    let replacement = admission.clone();
    let dispatched = Arc::new(Notify::new());
    let notify = dispatched.clone();
    let replace = tokio::spawn(async move {
        replacement
            .run_intent(
                request(3, 1),
                VoterIntentOrigin::Leader,
                Instant::now() + Duration::from_secs(20),
                move || async move {
                    notify.notify_one();
                    Ok(())
                },
            )
            .await
    });
    tokio::task::yield_now().await;
    assert!(
        !engine
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "fence-3"),
        "fence must drain the already accepted engine effect first"
    );
    complete.send(()).unwrap();
    dispatched.notified().await;
    replace.await.unwrap().unwrap();
    assert!(
        engine.closed.lock().unwrap().is_empty(),
        "definitive completion plus durable absence releases only this attempt"
    );
}

#[tokio::test(start_paused = true)]
async fn timed_out_prepare_keeps_its_fence_until_durable_truncation() {
    let (admission, reader, engine) = runtime(VoterSlotDurableState::new(genesis()).unwrap()).await;
    tokio::time::advance(VOTER_RECENT_TRAFFIC_WINDOW).await;
    let wanted = request(3, 1);
    let persisted = wanted.clone();
    let (entered, start) = oneshot::channel();
    let (complete, finish) = oneshot::channel();
    let replacement = admission.clone();
    let database = reader.clone();
    let call = tokio::spawn(async move {
        replacement
            .run_intent(
                wanted,
                VoterIntentOrigin::Leader,
                Instant::now() + Duration::from_secs(1),
                || async move {
                    database
                        .0
                        .lock()
                        .unwrap()
                        .append_intent(VoterSlotIntent {
                            log_id: VoterSlotLogId { term: 1, index: 10 },
                            request: persisted,
                        })
                        .unwrap();
                    entered.send(()).unwrap();
                    finish.await.unwrap();
                    Ok(())
                },
            )
            .await
    });
    start.await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        call.await.unwrap(),
        Err(VoterReplacementError::OutcomeUnknown)
    );
    assert!(engine.closed.lock().unwrap().contains(&node(3)));
    assert_eq!(
        admission
            .run_intent(
                request(2, 2),
                VoterIntentOrigin::Leader,
                Instant::now() + Duration::from_secs(1),
                || async {
                    panic!("second slot must not dispatch");
                    #[allow(unreachable_code)]
                    Ok(())
                }
            )
            .await,
        Err(VoterReplacementError::ReplacementInProgress)
    );
    assert!(!engine.closed.lock().unwrap().contains(&node(2)));
    complete.send(()).unwrap();
    tokio::task::yield_now().await;
    admission.reconcile().await.unwrap();
    assert!(engine.closed.lock().unwrap().contains(&node(3)));
    reader.0.lock().unwrap().truncate_from(10);
    admission.reconcile().await.unwrap();
    assert!(engine.closed.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn provisional_to_permanent_publication_never_reopens_the_retired_peer() {
    let (admission, reader, engine) = runtime(VoterSlotDurableState::new(genesis()).unwrap()).await;
    tokio::time::advance(VOTER_RECENT_TRAFFIC_WINDOW).await;
    let wanted = request(3, 1);
    let committed = wanted.clone();
    let database = reader.clone();
    admission
        .run_intent(
            wanted,
            VoterIntentOrigin::ReplicatedAppend,
            Instant::now() + Duration::from_secs(1),
            || async move {
                let cut = VoterSlotLogId { term: 1, index: 10 };
                let mut database = database.0.lock().unwrap();
                database
                    .append_intent(VoterSlotIntent {
                        log_id: cut,
                        request: committed.clone(),
                    })
                    .unwrap();
                let mut table = database.table().clone();
                table
                    .apply_control(&VoterSlotControl::Begin(Box::new(committed)), cut)
                    .unwrap();
                database.publish_applied(table, cut).unwrap();
                Ok(())
            },
        )
        .await
        .unwrap();
    assert!(engine.closed.lock().unwrap().contains(&node(3)));
    assert!(!engine
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event == "release-3"));
}

#[tokio::test(start_paused = true)]
async fn a_provisionally_closed_local_incarnation_never_opens_rpc_admission() {
    let mut state = VoterSlotDurableState::new(genesis()).unwrap();
    state
        .append_intent(VoterSlotIntent {
            log_id: VoterSlotLogId { term: 1, index: 10 },
            request: request(3, 1),
        })
        .unwrap();
    let reader = Arc::new(Reader(Mutex::new(state)));
    let engine = Arc::new(FenceEngine::default());
    let admission = VoterAdmission::new(node(3), reader).await.unwrap();
    admission.attach_engine(engine.clone()).await.unwrap();
    assert!(!admission.local_voting_admitted());
    assert_eq!(
        admission
            .run_peer(node(2), Instant::now() + Duration::from_secs(1), || async {
                Ok(())
            })
            .await,
        Err(VoterReplacementError::UnauthorizedReplacement)
    );
    assert!(
        !engine
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "fence-3"),
        "the core must not fence local storage acknowledgements"
    );
}

#[tokio::test(start_paused = true)]
async fn provisional_fence_only_admits_higher_term_leader_requests() {
    let mut durable = VoterSlotDurableState::new(genesis()).unwrap();
    let wanted = request(3, 1);
    let cut = VoterSlotLogId { term: 2, index: 10 };
    durable
        .append_intent(VoterSlotIntent {
            log_id: cut,
            request: wanted.clone(),
        })
        .unwrap();
    let (admission, reader, engine) = runtime(durable).await;
    for request in [
        VoterPeerRequest::Other,
        VoterPeerRequest::AppendEntries { term: 1 },
        VoterPeerRequest::AppendEntries { term: 2 },
        VoterPeerRequest::InstallSnapshot { term: 2 },
    ] {
        assert_eq!(
            admission
                .run_peer_request(
                    node(3),
                    request,
                    Instant::now() + Duration::from_secs(1),
                    || async { Ok(()) }
                )
                .await,
            Err(VoterReplacementError::UnauthorizedReplacement)
        );
    }
    for request in [
        VoterPeerRequest::AppendEntries { term: 3 },
        VoterPeerRequest::InstallSnapshot { term: 3 },
    ] {
        admission
            .run_peer_request(
                node(3),
                request,
                Instant::now() + Duration::from_secs(1),
                || async { Ok(()) },
            )
            .await
            .unwrap();
        assert!(
            engine.closed.lock().unwrap().contains(&node(3)),
            "admitting a request must not release the response fence"
        );
    }
    let mut table = genesis();
    table
        .apply_control(&VoterSlotControl::Begin(Box::new(wanted)), cut)
        .unwrap();
    reader
        .0
        .lock()
        .unwrap()
        .publish_applied(table, cut)
        .unwrap();
    admission.reconcile().await.unwrap();
    for request in [
        VoterPeerRequest::AppendEntries { term: 100 },
        VoterPeerRequest::InstallSnapshot { term: 100 },
    ] {
        assert_eq!(
            admission
                .run_peer_request(
                    node(3),
                    request,
                    Instant::now() + Duration::from_secs(1),
                    || async { Ok(()) }
                )
                .await,
            Err(VoterReplacementError::UnauthorizedReplacement)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn resolving_leader_snapshot_does_not_wait_for_the_prepare_it_must_resolve() {
    let (admission, reader, engine) = runtime(VoterSlotDurableState::new(genesis()).unwrap()).await;
    tokio::time::advance(VOTER_RECENT_TRAFFIC_WINDOW).await;
    let wanted = request(3, 1);
    let persisted = wanted.clone();
    let (entered, started) = oneshot::channel();
    let (complete, completion) = oneshot::channel();
    let proposer = admission.clone();
    let database = reader.clone();
    let pending = tokio::spawn(async move {
        proposer
            .run_intent(
                wanted,
                VoterIntentOrigin::Leader,
                Instant::now() + Duration::from_secs(30),
                || async move {
                    database
                        .0
                        .lock()
                        .unwrap()
                        .append_intent(VoterSlotIntent {
                            log_id: VoterSlotLogId { term: 2, index: 10 },
                            request: persisted,
                        })
                        .unwrap();
                    entered.send(()).unwrap();
                    completion.await.unwrap();
                    Ok(())
                },
            )
            .await
    });
    started.await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), admission.reconcile())
        .await
        .expect("durable publication must not wait for client_write completion")
        .unwrap();
    let installer = admission.clone();
    let database = reader.clone();
    let deadline = Instant::now() + Duration::from_secs(1);
    admission
        .run_peer_request(
            node(3),
            VoterPeerRequest::InstallSnapshot { term: 3 },
            deadline,
            move || async move {
                installer
                    .run_snapshot(
                        genesis(),
                        (1..=3).map(node).collect(),
                        deadline,
                        || async move {
                            database.0.lock().unwrap().truncate_from(10);
                            Ok(())
                        },
                    )
                    .await
            },
        )
        .await
        .expect("snapshot must reach the engine while Prepare is pending");
    assert!(
        engine.closed.lock().unwrap().contains(&node(3)),
        "the pending attempt still owns its fence"
    );
    complete.send(()).unwrap();
    pending.await.unwrap().unwrap();
    assert!(engine.closed.lock().unwrap().is_empty());
}
