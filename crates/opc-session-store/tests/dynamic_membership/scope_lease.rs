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

    clock.0.store(1, Ordering::SeqCst);
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
