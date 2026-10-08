use super::*;
use opc_session_store::scope_lease::*;
use opc_session_store::SessionConsumerIdentity;
use std::sync::atomic::AtomicU64;

fn principal(name: &str) -> SessionConsumerIdentity {
    SessionConsumerIdentity::new(format!("spiffe://scope.test/{name}")).unwrap()
}
fn execution(n: u8) -> ScopeExecution {
    ScopeExecution::new(
        principal(&format!("worker-{n}")),
        u64::from(n),
        [n; 16],
        [n; 16],
        [n; 16],
    )
    .unwrap()
}
struct Clock(AtomicU64);
impl ScopeLeaseClock for Clock {
    fn bounds(&self) -> Result<ScopeClockBounds, ScopeLeaseError> {
        let now = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(
                1_800_000_000 + self.0.load(Ordering::SeqCst) as i64,
            )
            .unwrap(),
        );
        ScopeClockBounds::new(now, now)
    }
}
struct Admission;
#[async_trait]
impl ScopeLeaseAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        _: &ScopeLeaseId,
        claim: Option<&ScopeExecution>,
        action: ScopeLeaseAction,
    ) -> Result<(), ScopeLeaseError> {
        let admitted = claim.is_none_or(|claim| claim == &execution(1) || claim == &execution(2))
            && match action {
                ScopeLeaseAction::Select => authenticated == &principal("controller"),
                _ => {
                    authenticated == &principal("worker-1")
                        || authenticated == &principal("worker-2")
                }
            };
        admitted.then_some(()).ok_or(ScopeLeaseError::Unauthorized)
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
        // live quorum must suffice: re-probing every voter would make renewal
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
async fn scope_lease_renews_during_abort_cleanup_with_unreachable_learner() {
    use opc_session_store::scope_batch::{
        ScopeBatchRequest, ScopeBatchStore, ScopeCounterMutation,
    };

    let mut fleet = DynamicFleet::start_three().await;
    let before = fleet.stores[0]
        .consumer_scope()
        .unwrap()
        .consensus_identity();
    let scope = ScopeLeaseId::new(
        before,
        TenantId::from_static("scope-abort-cleanup"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let authority = ScopeLeaseStore::new(
        Arc::new(fleet.stores[0].clone()),
        scope.clone(),
        clock.clone(),
        Arc::new(Admission),
    )
    .unwrap();
    let request = |revision, id, operation| {
        ScopeLeaseRequest::new(scope.clone(), [id; 16], revision, operation).unwrap()
    };
    authority
        .execute(
            &principal("controller"),
            &request(
                0,
                1,
                ScopeLeaseOperation::Select {
                    execution: execution(1),
                },
            ),
        )
        .await
        .unwrap();
    let mut view = authority
        .execute(
            &principal("worker-1"),
            &request(
                1,
                2,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1,
                },
            ),
        )
        .await
        .unwrap();
    let expanded = [0, 1, 2, 3, 4];
    let transition = fleet.transition_request(1, &expanded, 0xC9);
    fleet.provision_expansion(&transition).await;
    fleet.prepare(&transition, &expanded).await;
    clock.0.store(1, Ordering::SeqCst);
    view = authority
        .execute(
            &principal("worker-1"),
            &request(
                view.revision(),
                0x10,
                ScopeLeaseOperation::Renew {
                    permit: view.permit().unwrap().clone(),
                },
            ),
        )
        .await
        .expect("an active scope renews while prepared, before Fence");
    let prepared_grant = view.grant_floor();

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
    let mut renewed_after = None;
    clock.0.store(2, Ordering::SeqCst);
    while decided.elapsed() < Duration::from_secs(12) {
        match authority
            .execute(
                &principal("worker-1"),
                &request(
                    view.revision(),
                    0x11,
                    ScopeLeaseOperation::Renew {
                        permit: view.permit().unwrap().clone(),
                    },
                ),
            )
            .await
        {
            Ok(renewed) => {
                renewed_after = Some(decided.elapsed());
                view = renewed;
                break;
            }
            Err(ScopeLeaseError::Unavailable) => {
                refusals += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => panic!("unexpected renewal error during abort cleanup: {error:?}"),
        }
    }
    let read_during_cleanup = authority.current(&principal("worker-1")).await;
    let batch_during_cleanup = if renewed_after.is_some() {
        let follower = (leader + 1) % 3;
        let batches = ScopeBatchStore::new(
            Arc::new(fleet.stores[follower].clone()),
            scope.clone(),
            clock.clone(),
            Arc::new(Admission),
        )
        .unwrap();
        let batch = ScopeBatchRequest::new(
            view.permit().unwrap(),
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
    eprintln!("scope_abort_cleanup refusals={refusals} renewed_after={renewed_after:?} leader_admitted={admitted_during_cleanup} abort_finished={abort_finished_during_cleanup}");

    // Heal and shut down before asserting the regression, including its RED.
    fleet.network.heal(3);
    let first_abort = abort.await.unwrap();
    eprintln!("scope_abort_cleanup first_abort_result={first_abort:?}");
    fleet.abort(&transition, &[0, 1, 2]).await;
    clock.0.store(3, Ordering::SeqCst);
    let healed = Instant::now();
    // Individual replicas can still be reconciling admission after the
    // caller observes Aborted. Resolve uncertainty with this exact request.
    let mut recovery_retries = 0;
    let recovery_request = request(
        view.revision(),
        0x13,
        ScopeLeaseOperation::Renew {
            permit: view.permit().unwrap().clone(),
        },
    );
    let after_cleanup = loop {
        match authority
            .execute(&principal("worker-1"), &recovery_request)
            .await
        {
            Err(ScopeLeaseError::Unavailable | ScopeLeaseError::OutcomeUnknown)
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
        renewed_after.is_some(),
        "active scope renewal must not wait for abort cleanup; refusals={refusals}"
    );
    assert_eq!(view.grant_floor(), prepared_grant);
    assert_eq!(read_during_cleanup.unwrap(), view);
    let batch = batch_during_cleanup
        .unwrap()
        .expect("active scope batches cross abort cleanup");
    assert_eq!(batch.revision(), 1);
    assert_eq!(batch.counters()[0], 1);
    assert_eq!(after_cleanup.unwrap().grant_floor(), prepared_grant);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_lease_renews_releases_and_reselects_after_live_membership_transition() {
    let mut fleet = DynamicFleet::start_three().await;
    let before = fleet.stores[0]
        .consumer_scope()
        .unwrap()
        .consensus_identity();
    let scope = ScopeLeaseId::new(
        before,
        TenantId::from_static("scope-membership"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    // Keep this exact service alive across reconfiguration.
    let authority = ScopeLeaseStore::new(
        Arc::new(fleet.stores[0].clone()),
        scope.clone(),
        clock.clone(),
        Arc::new(Admission),
    )
    .unwrap();
    let request = |revision, id, operation| {
        ScopeLeaseRequest::new(scope.clone(), [id; 16], revision, operation).unwrap()
    };
    authority
        .execute(
            &principal("controller"),
            &request(
                0,
                1,
                ScopeLeaseOperation::Select {
                    execution: execution(1),
                },
            ),
        )
        .await
        .unwrap();
    let initial = authority
        .execute(
            &principal("worker-1"),
            &request(
                1,
                2,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1,
                },
            ),
        )
        .await
        .unwrap();

    let expanded = [0, 1, 2, 3, 4];
    let transition = fleet.transition_request(1, &expanded, 0xC7);
    fleet.provision_expansion(&transition).await;
    // Hold the actual coordinator's exclusive operation gate during Prepare.
    // An active scope must renew and commit batches while learner catch-up or
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
        clock.0.store(1, Ordering::SeqCst);
        let renewed = tokio::time::timeout_at(
            deadline,
            authority.execute(
                &principal("worker-1"),
                &ScopeLeaseRequest::new(
                    scope.clone(),
                    [0x31; 16],
                    initial.revision(),
                    ScopeLeaseOperation::Renew {
                        permit: initial.permit().unwrap().clone(),
                    },
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap()
        .expect("an active scope renews before Fence while Prepare holds its gate");
        assert_eq!(renewed.grant_floor(), initial.grant_floor());
        let follower = (leader + 1) % 3;
        let batches = ScopeBatchStore::new(
            Arc::new(fleet.stores[follower].clone()),
            scope.clone(),
            clock.clone(),
            Arc::new(Admission),
        )
        .unwrap();
        let batch = ScopeBatchRequest::new(
            renewed.permit().unwrap(),
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
        (prepare.await.unwrap().unwrap(), renewed)
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
    let successor_scope = ScopeLeaseId::new(
        after,
        scope.tenant().clone(),
        scope.nf_kind().clone(),
        *scope.slot(),
    )
    .unwrap();
    assert_eq!(successor_scope, scope);

    clock.0.store(2, Ordering::SeqCst);
    let renewed = authority
        .execute(
            &principal("worker-1"),
            &request(
                initial.revision(),
                3,
                ScopeLeaseOperation::Renew {
                    permit: initial.permit().unwrap().clone(),
                },
            ),
        )
        .await
        .unwrap();
    assert_eq!(renewed.grant_floor(), initial.grant_floor());
    let released = authority
        .execute(
            &principal("worker-1"),
            &request(
                renewed.revision(),
                4,
                ScopeLeaseOperation::Release {
                    closed: ScopeGateClosed::after_gate_closed(renewed.permit().unwrap().clone()),
                },
            ),
        )
        .await
        .unwrap();
    let new_service = ScopeLeaseStore::new(
        Arc::new(fleet.stores[4].clone()),
        successor_scope,
        clock,
        Arc::new(Admission),
    )
    .unwrap();
    let selected = new_service
        .execute(
            &principal("controller"),
            &request(
                released.revision(),
                5,
                ScopeLeaseOperation::Select {
                    execution: execution(2),
                },
            ),
        )
        .await
        .unwrap();
    let acquired = new_service
        .execute(
            &principal("worker-2"),
            &request(
                selected.revision(),
                6,
                ScopeLeaseOperation::Acquire {
                    execution: execution(2),
                    selection: 2,
                },
            ),
        )
        .await
        .unwrap();
    assert_eq!(acquired.grant_floor(), 2);
    assert_eq!(
        authority.current(&principal("worker-1")).await.unwrap(),
        acquired
    );
    for store in &fleet.stores {
        store.shutdown().await.unwrap();
    }
}
