//! Real replicated admissions and completions behind classified follower lanes.
use super::*;
use crate::consensus::store::{
    decode_roster_bounded, session_consensus_work_class, ForwardConsumerScope,
    ForwardMutationRequest, ForwardRequest, ForwardWorkClass,
};
use crate::consensus::types::{
    roster_v2_persistence_fixture_for_class, roster_v2_persistence_fixture_for_store_request,
    ConsensusRosterAdmissionCommand, ConsensusRosterAdmissionOutcome,
    ConsensusRosterTerminalCommandV2, ConsensusRosterTerminalOutcome, SessionConsensusRequestId,
    SessionMutationIntent, SessionMutationOutcome,
};
use crate::consensus::SessionConsensusRpcFamily;
use crate::consumer::{session_consumer_roster_scope_commitment, SessionConsumerScope};
use crate::fenced_mutation_roster::{AdmissionClass, Phase, Scope};
use crate::scope_scheduler::ScopeWorkClass;

pub(super) struct CompletionGate {
    sender: SessionConsensusNodeId,
    ordinary: SessionConsensusRequestId,
    lanes: [Arc<tokio::sync::Semaphore>; 5],
    held: AtomicUsize,
    release: tokio::sync::Semaphore,
}

impl CompletionGate {
    pub(super) async fn enter(
        &self,
        request: &SessionConsensusWireRequest,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, SessionConsensusPeerError> {
        if request.sender != self.sender {
            return Ok(None);
        }
        let class = session_consensus_work_class(request)?;
        // The production transport has two FIFO lanes per peer and class.
        // Hold only this ordinary completion, after it owns a real class lane.
        let lane = Arc::clone(&self.lanes[class.index()])
            .acquire_owned()
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
        if request.family == SessionConsensusRpcFamily::ForwardRosterMutation {
            let forwarded: ForwardRequest = decode_roster_bounded(&request.payload)
                .map_err(|_| SessionConsensusPeerError::Protocol)?;
            if matches!(forwarded, ForwardRequest::Mutation(ref value) if value.request_id == self.ordinary)
            {
                self.held.fetch_add(1, Ordering::SeqCst);
                self.release
                    .acquire()
                    .await
                    .map_err(|_| SessionConsensusPeerError::Unavailable)?
                    .forget();
            }
        }
        Ok(Some(lane))
    }
}

async fn admit(store: &ConsensusSessionStore, command: ConsensusRosterAdmissionCommand) -> u64 {
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    store
        .require_protected_roster_profile_v2_activation_before(deadline)
        .await
        .expect("emergency admission's real profile barrier is not behind ordinary completions");
    let response = store
        .submit_request_before(
            command.request_id().unwrap(),
            SessionMutationIntent::RosterAdmissionV2(Box::new(command)),
            Some(store.current_scope().unwrap().0),
            deadline,
        )
        .await
        .expect("signed admission reaches the leader");
    match response.result {
        Ok(SessionMutationOutcome::RosterAdmissionV2(
            ConsensusRosterAdmissionOutcome::Admitted {
                registration_request_id,
                ..
            },
        )) => registration_request_id.history_epoch(),
        other => panic!("signed admission recorded: {other:?}"),
    }
}

async fn complete(store: &ConsensusSessionStore, terminal: ConsensusRosterTerminalCommandV2) {
    let response = store
        .submit_request_before(
            terminal.request_id().unwrap(),
            SessionMutationIntent::RosterTerminalV2(Box::new(terminal)),
            Some(store.current_scope().unwrap().0),
            tokio::time::Instant::now() + store.inner.operation_timeout,
        )
        .await
        .expect("emergency completion is not behind ordinary completions");
    assert!(
        matches!(
            response.result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed { .. }
            ))
        ),
        "signed terminal recorded: {:?}",
        response.result
    );
}

async fn reject_reclassified_terminal(
    store: &ConsensusSessionStore,
    original: &ConsensusRosterTerminalCommandV2,
) {
    use crate::consensus::types::{ConsensusRosterRejection, ConsensusRosterTerminalCommandInput};
    use sha2::{Digest, Sha256};
    // Rebuild both public checksums. Only the unchanged admission and signed
    // evidence can refuse this forgery; malformed framing is not the test.
    let mut record = original.record_bytes().to_vec();
    let body_end = record.len() - 32;
    let mut terminal_hash = Sha256::new();
    terminal_hash.update(b"opc/session-store/protected-roster/emergency-terminal/v1\0");
    terminal_hash.update(&record[body_end - 32..body_end]);
    record[body_end - 32..body_end].copy_from_slice(&terminal_hash.finalize());
    record[..8].copy_from_slice(b"OPCRTE1\0");
    let mut frame_hash = Sha256::new();
    frame_hash.update(b"opc/session-store/protected-roster/emergency-terminal-frame/v1\0");
    frame_hash.update(&record[..body_end]);
    record[body_end..].copy_from_slice(&frame_hash.finalize());
    let (registration_handle, registration_request_id, registration_terminal_slot) =
        original.registration_parts();
    let forged =
        ConsensusRosterTerminalCommandV2::new_with_proof_bundle_evidence_and_ingress_request_id(
            ConsensusRosterTerminalCommandInput {
                binding: original.binding(),
                registration_handle,
                registration_request_id,
                registration_terminal_slot,
                authority: original.authority().clone(),
                record,
            },
            original.proof_bundle().unwrap(),
            original.terminal_evidence().unwrap(),
            original.ingress_request_id(),
            original.ingress_attestation().unwrap(),
        )
        .unwrap();
    assert_eq!(forged.admission_class(), AdmissionClass::Emergency);
    let response = store
        .submit_request_before(
            forged.request_id().unwrap(),
            SessionMutationIntent::RosterTerminalV2(Box::new(forged)),
            Some(store.current_scope().unwrap().0),
            tokio::time::Instant::now() + store.inner.operation_timeout,
        )
        .await
        .unwrap();
    assert!(
        matches!(
            response.result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Rejected {
                    rejection: ConsensusRosterRejection::TerminalConflict,
                    ..
                }
            ))
        ),
        "apply rejects the signed admission/terminal class mismatch: {:?}",
        response.result
    );
}

#[derive(Clone, Copy)]
enum Check {
    Admission,
    Completion,
    NormalQuota,
    ClassMismatch,
}

async fn ordinary_completion_congestion(native: bool, check: Check) {
    use crate::consensus::store::membership_tests::MutableClock;
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let seed = roster_v2_persistence_fixture_for_class(Phase::Aborted, AdmissionClass::Ordinary);
    let clock = Arc::new(MutableClock::new(
        opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        ),
    ));
    let mut fleet = Fleet::new_roster_production("roster-completion-congestion", native, seed.root);
    fleet.clock = Some(clock.clone());
    fleet.open().await;
    let mut tasks = tokio::task::JoinSet::new();
    let mut gate_for_cleanup = None;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let follower = (leader + 1) % 3;
        let ingress = &fleet.stores[follower];
        let identity = ingress.current_scope().unwrap().0;
        let scope = Scope::from_digest(session_consumer_roster_scope_commitment(
            SessionConsumerScope::new(identity),
        ));
        let fixture = |epoch, class| {
            roster_v2_persistence_fixture_for_store_request(
                identity,
                scope,
                epoch,
                class,
                Phase::Aborted,
                if class == AdmissionClass::Ordinary {
                    [0xb1; 16]
                } else {
                    [0xb2; 16]
                },
            )
        };
        let ordinary = fixture(1, AdmissionClass::Ordinary);
        let lease = ingress
            .acquire(
                ordinary.authority.key(),
                ordinary.authority.owner().clone(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert_eq!(lease.fence(), ordinary.authority.fence());
        assert_eq!(lease.credential_id(), ordinary.authority.credential_id());
        clock.set(opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(2),
        ));
        ingress
            .activate_protected_roster_profile_v2()
            .await
            .unwrap();
        let admission = |signed: crate::consensus::types::RosterV2PersistenceFixture| {
            ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(
                signed.admission,
                signed.authority,
                signed.admission_ingress.request_id(),
                signed.admission_ingress,
                signed.admission_provenance,
            )
            .unwrap()
        };
        let ordinary_admission = admission(ordinary);
        let ordinary_epoch = admit(ingress, ordinary_admission.clone()).await;
        let ordinary_terminal = fixture(ordinary_epoch, AdmissionClass::Ordinary).terminal_command;
        if matches!(check, Check::ClassMismatch) {
            reject_reclassified_terminal(ingress, &ordinary_terminal).await;
            complete(ingress, ordinary_terminal.clone()).await;
            reject_reclassified_terminal(ingress, &ordinary_terminal).await;
            let snapshot = fleet.stores[leader].protected_roster_diagnostic_snapshot();
            assert_eq!(snapshot.live_reservations, 0);
            assert_eq!(snapshot.retained_reservations, 1);
            return;
        }
        complete(ingress, ordinary_terminal.clone()).await;
        let emergency_admission = admission(fixture(1, AdmissionClass::Emergency));
        let emergency_epoch = if matches!(check, Check::Completion) {
            Some(admit(ingress, emergency_admission.clone()).await)
        } else {
            None
        };
        let gate = Arc::new(CompletionGate {
            sender: ingress.inner.local_node_id,
            ordinary: ordinary_terminal.request_id().unwrap(),
            lanes: std::array::from_fn(|_| Arc::new(tokio::sync::Semaphore::new(2))),
            held: AtomicUsize::new(0),
            release: tokio::sync::Semaphore::new(0),
        });
        *fleet.peers[leader].roster_completion_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate_for_cleanup = Some(Arc::clone(&gate));
        for _ in 0..16 {
            let store = ingress.clone();
            let terminal = ordinary_terminal.clone();
            tasks.spawn(async move { complete(&store, terminal).await });
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while gate.held.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("two ordinary completions hold their decoded transport lanes");
        match check {
            Check::ClassMismatch => unreachable!("checked before congestion"),
            Check::Admission => {
                let epoch = admit(ingress, emergency_admission).await;
                complete(
                    ingress,
                    fixture(epoch, AdmissionClass::Emergency).terminal_command,
                )
                .await;
            }
            Check::Completion => {
                complete(
                    ingress,
                    fixture(emergency_epoch.unwrap(), AdmissionClass::Emergency).terminal_command,
                )
                .await;
            }
            Check::NormalQuota => {
                let observed = tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        let normal = ingress
                            .inner
                            .forward_admission
                            .snapshot()
                            .class(ScopeWorkClass::Normal);
                        if normal.running == 8 && normal.start_waiting >= 8 {
                            return normal;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await;
                assert!(
                    observed.is_ok(),
                    "ordinary completions consume Normal quotas: {:?}",
                    ingress.inner.forward_admission.snapshot()
                );
                assert_eq!(observed.unwrap().resident, 16);
                let request = ForwardMutationRequest {
                    request_id: ordinary_admission.request_id().unwrap(),
                    intent: SessionMutationIntent::RosterAdmissionV2(Box::new(ordinary_admission)),
                    required_consumer_scope: ForwardConsumerScope::Consumer(Box::new(identity)),
                    work_class: ForwardWorkClass::Inferred,
                };
                assert!(
                    matches!(
                        ingress
                            .forward_mutation_before(
                                fleet.stores[leader].inner.local_node_id,
                                &request,
                                tokio::time::Instant::now() + Duration::from_millis(20),
                            )
                            .await,
                        Err(crate::consensus::store::ConsensusPeerCallFailure::BeforeTransmission)
                    ),
                    "an ordinary signed admission still waits for Normal quota"
                );
            }
        }
        assert!(
            tasks.try_join_next().is_none(),
            "ordinary completions remain held during emergency work"
        );
    })
    .catch_unwind()
    .await;
    if let Some(gate) = gate_for_cleanup {
        gate.release.add_permits(16);
    }
    // Test failures still drain tasks and shut down the real store fleet.
    let drained = tokio::time::timeout(Duration::from_secs(15), async {
        let mut failed = false;
        while let Some(outcome) = tasks.join_next().await {
            failed |= outcome.is_err();
        }
        failed
    })
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(
        !drained.expect("ordinary requests drain after the transport hold is released"),
        "ordinary completions succeed when their lanes resume"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_completion_sqlite_ordinary_wave_does_not_delay_emergency_admission() {
    ordinary_completion_congestion(false, Check::Admission).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_completion_native_ordinary_wave_does_not_delay_emergency_admission() {
    ordinary_completion_congestion(true, Check::Admission).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_completion_sqlite_ordinary_wave_does_not_delay_emergency_completion() {
    ordinary_completion_congestion(false, Check::Completion).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_completion_native_ordinary_wave_does_not_delay_emergency_completion() {
    ordinary_completion_congestion(true, Check::Completion).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_completion_sqlite_ordinary_wave_consumes_normal_quota() {
    ordinary_completion_congestion(false, Check::NormalQuota).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_completion_native_ordinary_wave_consumes_normal_quota() {
    ordinary_completion_congestion(true, Check::NormalQuota).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_completion_sqlite_apply_rejects_reclassified_terminal() {
    ordinary_completion_congestion(false, Check::ClassMismatch).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_completion_native_apply_rejects_reclassified_terminal() {
    ordinary_completion_congestion(true, Check::ClassMismatch).await;
}
