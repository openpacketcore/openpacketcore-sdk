use super::*;
use opc_session_store::scope_authority::*;
use opc_session_store::SessionConsumerIdentity;

fn principal(name: &str) -> SessionConsumerIdentity {
    SessionConsumerIdentity::new(format!("spiffe://scope.test/{name}")).unwrap()
}
fn execution(n: u8) -> ScopeExecution {
    ScopeExecution::new(
        principal(&format!("worker-{n}")),
        u64::from(n),
        [n; 16],
        [n; 16],
        [n; 32],
    )
    .unwrap()
}
struct Admission;
#[async_trait]
impl ScopeAuthorityAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        _: &ScopeId,
        claim: Option<&ScopeExecution>,
        _: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        if claim.is_some_and(|value| value != &execution(1) && value != &execution(2)) {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        if authenticated == &principal("controller") {
            return Ok(ScopeAuthorityRole::ScopeController);
        }
        if (authenticated == &principal("worker-1") || authenticated == &principal("worker-2"))
            && claim.is_none_or(|value| value.identity() == authenticated)
        {
            return Ok(ScopeAuthorityRole::Worker);
        }
        Err(ScopeAuthorityError::Unauthorized)
    }
    async fn verify_closure(
        &self,
        _: &SessionConsumerIdentity,
        _: &ScopeAuthorityStamp,
        _: &ScopeClosureEvidence,
        _: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_profile_membership_carries_activation_without_unanimous_reactivation() {
    let mut fleet = DynamicFleet::start_three().await;
    fleet.stores[0].activate_scope_profile().await.unwrap();

    for (epoch, desired, seed) in [(1, vec![0, 1, 2, 3, 4], 0xA3), (2, vec![0, 1, 2], 0xA4)] {
        let transition = fleet.transition_request(epoch, &desired, seed);
        if epoch == 1 {
            fleet.provision_expansion(&transition).await;
        } else {
            fleet.stage_on_all(&transition);
        }
        let proof = fleet.prepare(&transition, &desired).await;
        fleet.commit(&transition, &proof, &desired).await;
        let removed = if epoch == 1 { &[][..] } else { &[3, 4][..] };
        wait_completed_and_admitted(&fleet.stores, &transition, &desired, removed).await;
        let leader = fleet.wait_transition_caller(&desired).await;
        let unavailable = desired
            .iter()
            .copied()
            .filter(|index| *index != leader)
            .take(desired.len() / 2)
            .collect::<Vec<_>>();
        for index in &unavailable {
            fleet.network.isolate(*index);
        }
        // This is the first scope operation under the successor identity. A
        // live quorum must suffice: re-probing every voter would make exact recovery
        // depend on unavailable members after an otherwise successful cutover.
        let activation = fleet.stores[leader].activate_scope_profile().await;
        for index in unavailable {
            fleet.network.heal(index);
        }
        if let Err(error) = activation {
            for store in &fleet.stores {
                store.shutdown().await.unwrap();
            }
            panic!(
                "activated scope profile must survive epoch {epoch} with only a quorum: {error:?}"
            );
        }
    }
    for store in &fleet.stores {
        store.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_authority_recovers_during_abort_cleanup_with_unreachable_learner() {
    use opc_session_store::scope_batch::{
        ScopeBatchRequest, ScopeBatchStore, ScopeCounterMutation,
    };

    let mut fleet = DynamicFleet::start_three().await;
    let before = fleet.stores[0]
        .consumer_scope()
        .unwrap()
        .consensus_identity();
    let scope = ScopeId::new(
        before,
        TenantId::from_static("scope-abort-cleanup"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();

    let authority = ScopeAuthorityStore::new(
        Arc::new(fleet.stores[0].clone()),
        scope.clone(),
        Arc::new(Admission),
    )
    .unwrap();
    let request = |revision, id, operation| {
        ScopeAuthorityRequest::new(scope.clone(), [id; 16], revision, operation).unwrap()
    };
    let initial_request = request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let view = authority
        .execute(&principal("worker-1"), &initial_request)
        .await
        .unwrap();

    let expanded = [0, 1, 2, 3, 4];
    let transition = fleet.transition_request(1, &expanded, 0xC9);
    fleet.provision_expansion(&transition).await;
    fleet.prepare(&transition, &expanded).await;

    let prepared_view = authority
        .execute(&principal("worker-1"), &initial_request)
        .await
        .expect("an active scope recovers while prepared, before Fence");
    assert_eq!(prepared_view, view);
    let prepared_grant = view.admission_generation_floor();

    // The durable abort restores the predecessor authority, but this learner
    // prevents cleanup from reopening ordinary application admission.
    fleet.network.isolate(3);
    let leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
    let store = fleet.stores[leader].clone();
    let aborting = transition.clone();
    let abort = tokio::spawn(async move { store.abort_topology_transition(&aborting).await });
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(Some(status)) = fleet.stores[leader]
                .topology_transition_status(&transition)
                .await
            {
                if status.phase() == SessionTopologyTransitionPhase::Aborting {
                    return;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("the abort decision becomes durable while its learner is unreachable");

    let decided = Instant::now();
    let mut refusals = 0;

    // The isolated learner keeps cleanup pending until we explicitly heal it.
    // Recovery must precede that event; elapsed time is diagnostic only, with
    // the shared test deadline serving solely as a generous hang guard.
    let recovered_after = tokio::time::timeout(TEST_DEADLINE, async {
        loop {
            match authority
                .execute(&principal("worker-1"), &initial_request)
                .await
            {
                Ok(recovered) => {
                    assert_eq!(recovered, view);
                    break decided.elapsed();
                }
                Err(ScopeAuthorityError::Unavailable | ScopeAuthorityError::OutcomeUnknown) => {
                    refusals += 1;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(error) => {
                    panic!("unexpected exact recovery error during abort cleanup: {error:?}")
                }
            }
        }
    })
    .await;
    let read_during_cleanup = authority.current(&principal("worker-1")).await;
    let batch_during_cleanup = if recovered_after.is_ok() {
        let follower = (leader + 1) % 3;
        let batches = ScopeBatchStore::new(
            Arc::new(fleet.stores[follower].clone()),
            ScopeNamespace::new(scope.clone(), ScopeIncarnation::new(1).unwrap()).unwrap(),
            Arc::new(Admission),
        )
        .unwrap();
        let batch = ScopeBatchRequest::new(
            view.stamp().unwrap(),
            [0x12; 16],
            0,
            vec![],
            vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
        )
        .unwrap();
        Some(batches.execute(&principal("worker-1"), &batch).await)
    } else {
        None
    };
    let admitted_during_cleanup = fleet.stores[leader].status().admitted;
    let abort_finished_during_cleanup = abort.is_finished();
    eprintln!("scope_abort_cleanup refusals={refusals} recovered_after={recovered_after:?} leader_admitted={admitted_during_cleanup} abort_finished={abort_finished_during_cleanup}");

    // Heal and shut down before asserting the regression, including its RED.
    fleet.network.heal(3);
    let first_abort = abort.await.unwrap();
    eprintln!("scope_abort_cleanup first_abort_result={first_abort:?}");
    fleet.abort(&transition, &[0, 1, 2]).await;

    let healed = Instant::now();
    // Individual replicas can still be reconciling admission after the
    // caller observes Aborted. Resolve uncertainty with this exact request.
    let mut recovery_retries = 0;
    let recovery_request = initial_request.clone();
    let after_cleanup = loop {
        match authority
            .execute(&principal("worker-1"), &recovery_request)
            .await
        {
            Err(ScopeAuthorityError::Unavailable | ScopeAuthorityError::OutcomeUnknown)
                if healed.elapsed() < Duration::from_secs(30) =>
            {
                recovery_retries += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            result => break result,
        }
    };
    eprintln!(
        "scope_abort_cleanup recovery_retries={recovery_retries} recovered_after={:?}",
        healed.elapsed()
    );
    for store in &fleet.stores {
        store.shutdown().await.unwrap();
    }

    assert!(
        !admitted_during_cleanup,
        "ordinary admission remains closed"
    );
    assert!(
        !abort_finished_during_cleanup,
        "the isolated learner still blocks cleanup"
    );
    assert!(
        recovered_after.is_ok(),
        "active scope exact recovery exceeded the test hang guard while cleanup was blocked; refusals={refusals}"
    );
    assert_eq!(view.admission_generation_floor(), prepared_grant);
    assert_eq!(read_during_cleanup.unwrap(), view);
    let batch = batch_during_cleanup
        .unwrap()
        .expect("active scope batches cross abort cleanup");
    assert_eq!(batch.revision(), 1);
    assert_eq!(batch.counters()[0], 1);
    assert_eq!(
        after_cleanup.unwrap().admission_generation_floor(),
        prepared_grant
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_authority_recovers_closes_and_succeeds_after_live_membership_transition() {
    let mut fleet = DynamicFleet::start_three().await;
    let before = fleet.stores[0]
        .consumer_scope()
        .unwrap()
        .consensus_identity();
    let scope = ScopeId::new(
        before,
        TenantId::from_static("scope-membership"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();

    // Keep this exact service alive across reconfiguration.
    let authority = ScopeAuthorityStore::new(
        Arc::new(fleet.stores[0].clone()),
        scope.clone(),
        Arc::new(Admission),
    )
    .unwrap();
    let request = |revision, id, operation| {
        ScopeAuthorityRequest::new(scope.clone(), [id; 16], revision, operation).unwrap()
    };
    let initial_request = request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let initial = authority
        .execute(&principal("worker-1"), &initial_request)
        .await
        .unwrap();

    let expanded = [0, 1, 2, 3, 4];
    let transition = fleet.transition_request(1, &expanded, 0xC7);
    fleet.provision_expansion(&transition).await;
    // Hold the actual coordinator's exclusive operation gate during Prepare.
    // An active scope must recover and commit batches while learner catch-up or
    // a distributed barrier is delayed, before any authority Fence exists.
    #[cfg(feature = "test-control")]
    let (proof, initial) = {
        use opc_session_store::scope_batch::{
            ScopeBatchRequest, ScopeBatchStore, ScopeCounterMutation,
        };
        let leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
        let (entered, release) =
            pause_next_outbound_learner_barrier_for_test(&fleet.stores[leader]).unwrap();
        let store = fleet.stores[leader].clone();
        let peers = fleet.network.peers_for_request(leader, &transition);
        let request = transition.clone();
        let prepare =
            tokio::spawn(async move { store.prepare_topology_transition(&request, peers).await });
        let deadline = entered
            .await
            .expect("Prepare reached its real barrier with the gate held");
        assert!(!fleet.stores[leader].status().admitted);

        let recovered = tokio::time::timeout_at(
            deadline,
            authority.execute(&principal("worker-1"), &initial_request),
        )
        .await
        .unwrap()
        .expect("an active scope recovers before Fence while Prepare holds its gate");
        assert_eq!(
            recovered.admission_generation_floor(),
            initial.admission_generation_floor()
        );
        let follower = (leader + 1) % 3;
        let batches = ScopeBatchStore::new(
            Arc::new(fleet.stores[follower].clone()),
            ScopeNamespace::new(scope.clone(), ScopeIncarnation::new(1).unwrap()).unwrap(),
            Arc::new(Admission),
        )
        .unwrap();
        let batch = ScopeBatchRequest::new(
            recovered.stamp().unwrap(),
            [0x32; 16],
            0,
            vec![],
            vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
        )
        .unwrap();
        let outcome = batches
            .execute(&principal("worker-1"), &batch)
            .await
            .expect("an active batch crosses follower and leader admission before Fence");
        assert_eq!(outcome.revision(), 1);
        assert_eq!(outcome.counters()[0], 1);
        release.send(()).unwrap();
        (prepare.await.unwrap().unwrap(), recovered)
    };
    #[cfg(not(feature = "test-control"))]
    let proof = fleet.prepare(&transition, &expanded).await;
    fleet.commit(&transition, &proof, &expanded).await;
    wait_completed_and_admitted(&fleet.stores, &transition, &expanded, &[]).await;
    let after = fleet.stores[0]
        .consumer_scope()
        .unwrap()
        .consensus_identity();
    assert_ne!(before, after);
    assert_eq!(before.cluster_id(), after.cluster_id());
    let successor_scope = ScopeId::new(
        after,
        scope.tenant().clone(),
        scope.nf_kind().clone(),
        *scope.slot(),
    )
    .unwrap();
    assert_eq!(successor_scope, scope);

    let recovered = authority
        .execute(&principal("worker-1"), &initial_request)
        .await
        .unwrap();
    assert_eq!(
        recovered.admission_generation_floor(),
        initial.admission_generation_floor()
    );
    let released = authority
        .execute(
            &principal("worker-1"),
            &request(
                recovered.revision(),
                4,
                ScopeAuthorityOperation::Close {
                    current: recovered.stamp().unwrap().clone(),
                    evidence: ScopeClosureEvidence::new(ScopeClosureKind::LocalQuiescence, [4; 32])
                        .unwrap(),
                },
            ),
        )
        .await
        .unwrap();
    let new_service = ScopeAuthorityStore::new(
        Arc::new(fleet.stores[4].clone()),
        successor_scope,
        Arc::new(Admission),
    )
    .unwrap();
    let succeeding = request(
        released.revision(),
        5,
        ScopeAuthorityOperation::SucceedClosed {
            predecessor: released.stamp().unwrap().clone(),
            execution: execution(2),
            evidence: released.closed_evidence().unwrap(),
        },
    );
    let acquired = new_service
        .execute(&principal("controller"), &succeeding)
        .await
        .unwrap();
    let capability = new_service
        .admit(&principal("worker-2"), &succeeding)
        .await
        .unwrap();
    assert_eq!(capability.stamp(), acquired.stamp().unwrap());
    assert_eq!(acquired.admission_generation_floor(), 2);
    assert_eq!(
        authority.current(&principal("worker-1")).await.unwrap(),
        acquired
    );
    for store in &fleet.stores {
        store.shutdown().await.unwrap();
    }
}
