//! Protected coordinator + real adapter regressions; kernel IO is simulated.

use super::*;
use opc_session_store::{
    EncryptingSessionBackend, OwnerId, SelectorLedgerStorageScope, SessionStore,
    SqliteSessionBackend,
};
use opc_types::{NetworkFunctionKind, TenantId};

type Store = EncryptingSessionBackend<SqliteSessionBackend, opc_key::MemoryKeyProvider>;

struct Fixture {
    runtime: Arc<FakeRuntime>,
    backend: Arc<EbpfGtpuDataplaneBackend>,
    authority: crate::GtpuSessionSelectorNamespaceAuthority<Store>,
    parent: GtpuSessionGroup,
    sibling: GtpuSessionGroup,
    store: SessionStore<Store>,
    scope: SelectorLedgerStorageScope,
}

#[derive(Clone, Copy)]
enum MarkHistory {
    Active,
    Retired,
    AmbiguousRetirement,
}

async fn assert_cross_profile_mark_history_stays_reserved(child_first: bool, history: MarkHistory) {
    let fixture = Fixture::new().await;
    let child = fixture.child(0xb4, 0x1110, 6);
    let mut legacy_context = child.entries()[0].context().clone();
    legacy_context.ms_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 223));
    legacy_context.local_teid = teid(0x1111);
    legacy_context.peer_teid = teid(0x2111);
    let legacy = grouped_group(
        0xb5,
        fixture.parent.device_id(),
        vec![
            GtpuSessionEntry::new(legacy_context, child.entries()[0].local_outer_address())
                .unwrap(),
        ],
    );
    let (source, active) = if child_first {
        (child.clone(), fixture.add(child.clone()).await.unwrap())
    } else {
        (
            legacy.clone(),
            fixture
                .authority
                .reconcile_fresh(fixture.backend.clone(), legacy.clone())
                .await
                .unwrap(),
        )
    };
    let parent = fixture.parent_claim().await;
    match history {
        MarkHistory::Active => drop(active),
        MarkHistory::Retired => drop(
            fixture
                .authority
                .retire(fixture.backend.clone(), active, source)
                .await
                .unwrap(),
        ),
        MarkHistory::AmbiguousRetirement => {
            fixture.runtime.fail_in_order(["session_uplink_remove"]);
            assert!(fixture
                .authority
                .retire(fixture.backend.clone(), active, source.clone())
                .await
                .is_err());
            assert!(fixture.runtime.state().failures.is_empty());
            assert!(fixture
                .authority
                .recover_retired(fixture.backend.clone(), source)
                .await
                .is_err());
        }
    }
    let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    let stamps = fixture.runtime.state().selector_operation_stamps.clone();
    let result = if child_first {
        fixture
            .authority
            .reconcile_fresh(fixture.backend.clone(), legacy)
            .await
    } else {
        fixture
            .authority
            .reconcile_bearer(
                fixture.backend.clone(),
                parent,
                fixture.parent.clone(),
                child,
            )
            .await
    };
    assert!(
        result.is_err(),
        "legacy global marks must conflict with the child profile in both orders"
    );
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
    assert_eq!(fixture.runtime.state().selector_operation_stamps, stamps);
}

#[tokio::test]
async fn protected_grouped_bearer_cross_profile_legacy_active_mark_blocks_child() {
    assert_cross_profile_mark_history_stays_reserved(false, MarkHistory::Active).await;
}

#[tokio::test]
async fn protected_grouped_bearer_cross_profile_legacy_retired_mark_blocks_child() {
    assert_cross_profile_mark_history_stays_reserved(false, MarkHistory::Retired).await;
}

#[tokio::test]
async fn protected_grouped_bearer_cross_profile_legacy_ambiguous_mark_blocks_child() {
    assert_cross_profile_mark_history_stays_reserved(false, MarkHistory::AmbiguousRetirement).await;
}

#[tokio::test]
async fn protected_grouped_bearer_cross_profile_child_active_mark_blocks_legacy() {
    assert_cross_profile_mark_history_stays_reserved(true, MarkHistory::Active).await;
}

#[tokio::test]
async fn protected_grouped_bearer_cross_profile_child_retired_mark_blocks_legacy() {
    assert_cross_profile_mark_history_stays_reserved(true, MarkHistory::Retired).await;
}

#[tokio::test]
async fn protected_grouped_bearer_cross_profile_child_ambiguous_mark_blocks_legacy() {
    assert_cross_profile_mark_history_stays_reserved(true, MarkHistory::AmbiguousRetirement).await;
}

impl Fixture {
    async fn parent_claim(&self) -> crate::GtpuSessionSelectorActiveClaim {
        self.authority
            .recover_active(self.backend.clone(), self.parent.clone())
            .await
            .unwrap()
    }

    async fn add(
        &self,
        child: GtpuSessionGroup,
    ) -> Result<crate::GtpuSessionSelectorActiveClaim, crate::GtpuSessionSelectorCoordinatorError>
    {
        self.authority
            .reconcile_bearer(
                self.backend.clone(),
                self.parent_claim().await,
                self.parent.clone(),
                child,
            )
            .await
    }
    async fn new() -> Self {
        let runtime = Arc::new(FakeRuntime::new());
        let device = grouped_device_id(0xb1);
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let backend = Arc::new(
            attach_grouped_fake(
                runtime.clone(),
                device,
                GtpuLocalEndpointSet::new(local, None).unwrap(),
            )
            .await,
        );
        let tenant = TenantId::from_static("grouped-bearer-fixture");
        let keys = Arc::new(opc_key::MemoryKeyProvider::new());
        keys.insert_active_key(
            opc_key::KeyId::new("selector-fixture-key").unwrap(),
            opc_key::KeyPurpose::Session,
            tenant.clone(),
            opc_key::Zeroizing::new([0x53; 32]),
        )
        .unwrap();
        let store = SessionStore::new(EncryptingSessionBackend::new(
            Arc::new(SqliteSessionBackend::in_memory().unwrap()),
            keys,
            "selector-fixture",
        ));
        let scope =
            SelectorLedgerStorageScope::new(tenant, NetworkFunctionKind::from_static("epdg"));
        let authority = crate::GtpuSessionSelectorNamespaceAuthority::provision_protected(
            store.clone(),
            scope.clone(),
            backend.selector_namespace_bootstrap(device).await.unwrap(),
            backend.clone(),
            OwnerId::new("grouped-bearer-worker").unwrap(),
            crate::selector_namespace::SELECTOR_NAMESPACE_MAX_LEASE_TTL,
            32,
        )
        .await
        .unwrap();
        let parent = grouped_group(0xb2, device, vec![grouped_v4_entry(0x1101, 0x2101)]);
        let sibling = grouped_group(
            0xb3,
            device,
            vec![grouped_entry_for_addresses(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 222)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                local,
                0x1102,
                0x2102,
                None,
            )],
        );
        for group in [&parent, &sibling] {
            drop(
                authority
                    .reconcile_fresh(backend.clone(), group.clone())
                    .await
                    .unwrap(),
            );
        }
        Self {
            runtime,
            backend,
            authority,
            parent,
            sibling,
            store,
            scope,
        }
    }

    fn child(&self, id: u8, teid: u32, mark: u32) -> GtpuSessionGroup {
        let mut context = self.parent.entries()[0].context().clone();
        context.local_teid = super::teid(teid);
        context.peer_teid = super::teid(teid + 0x1000);
        context.bearer_mark = GtpBearerMark::new(mark);
        context.downlink_source_port_policy = crate::GtpuSourcePortPolicy::Exact(3000 + id as u16);
        grouped_group(
            id,
            self.parent.device_id(),
            vec![
                GtpuSessionEntry::new(context, self.parent.entries()[0].local_outer_address())
                    .unwrap(),
            ],
        )
    }
}

#[tokio::test]
async fn protected_grouped_bearer_preflight_rejects_foreign_duplicate_and_reversed_owners() {
    let fixture = Fixture::new().await;
    let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    let stamps = fixture.runtime.state().selector_operation_stamps.clone();
    let child = fixture.child(0xb4, 0x1110, 0x41);
    let sibling_claim = fixture
        .authority
        .recover_active(fixture.backend.clone(), fixture.sibling.clone())
        .await
        .unwrap();
    assert!(fixture
        .authority
        .reconcile_bearer(
            fixture.backend.clone(),
            sibling_claim,
            fixture.parent.clone(),
            child.clone()
        )
        .await
        .is_err());
    assert!(fixture
        .authority
        .reconcile_bearer(
            fixture.backend.clone(),
            fixture.parent_claim().await,
            child.clone(),
            fixture.parent.clone()
        )
        .await
        .is_err());
    let duplicate_teid = fixture.child(0xb4, 0x1102, 0x41);
    assert!(fixture.add(duplicate_teid).await.is_err());
    let mut wrong_peer = child.entries()[0].context().clone();
    wrong_peer.peer_address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    let wrong_peer = grouped_group(
        0xb4,
        fixture.parent.device_id(),
        vec![GtpuSessionEntry::new(wrong_peer, child.entries()[0].local_outer_address()).unwrap()],
    );
    assert!(fixture.add(wrong_peer).await.is_err());
    assert!(fixture
        .authority
        .reconcile_fresh(fixture.backend.clone(), child.clone())
        .await
        .is_err());
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
    assert_eq!(fixture.runtime.state().selector_operation_stamps, stamps);
    let active = fixture.add(child.clone()).await.unwrap();
    let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    assert!(fixture.add(child.clone()).await.is_err());
    assert!(fixture
        .add(fixture.child(0xb5, 0x1111, 0x42))
        .await
        .is_err());
    assert!(fixture
        .authority
        .retire(
            fixture.backend.clone(),
            fixture.parent_claim().await,
            fixture.parent.clone()
        )
        .await
        .is_err());
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), active, child.clone())
            .await
            .unwrap(),
    );
    assert!(
        fixture.add(child).await.is_err(),
        "retired group IDs never resurrect"
    );
}

#[tokio::test]
async fn protected_grouped_bearer_exact_reopen_and_stale_parent_generation() {
    let mut fixture = Fixture::new().await;
    let child = fixture.child(0xb4, 0x1110, 0x41);
    drop(fixture.add(child.clone()).await.unwrap());
    fixture.authority = crate::GtpuSessionSelectorNamespaceAuthority::open_protected(
        fixture.store.clone(),
        fixture.scope.clone(),
        fixture
            .backend
            .selector_namespace_bootstrap(fixture.parent.device_id())
            .await
            .unwrap(),
        fixture.backend.clone(),
        OwnerId::new("reopened-bearer-worker").unwrap(),
        crate::selector_namespace::SELECTOR_NAMESPACE_MAX_LEASE_TTL,
        32,
    )
    .await
    .unwrap();
    let active = fixture
        .authority
        .recover_active(fixture.backend.clone(), child.clone())
        .await
        .unwrap();
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), active, child)
            .await
            .unwrap(),
    );
    let stale = fixture.parent_claim().await;
    drop(
        fixture
            .authority
            .retire(
                fixture.backend.clone(),
                fixture.parent_claim().await,
                fixture.parent.clone(),
            )
            .await
            .unwrap(),
    );
    let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    assert!(fixture
        .authority
        .reconcile_bearer(
            fixture.backend.clone(),
            stale,
            fixture.parent.clone(),
            fixture.child(0xb5, 0x1111, 0x42)
        )
        .await
        .is_err());
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
    drop(
        fixture
            .authority
            .recover_active(fixture.backend, fixture.sibling)
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn protected_grouped_bearer_parent_proofs_are_revoked_at_both_effect_boundaries() {
    let fixture = Fixture::new().await;
    let policy = opc_dataplane_observation::TrafficContinuityPolicy::new(
        2,
        std::time::Duration::from_millis(1),
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(2),
        8,
    )
    .unwrap();
    let authority =
        GtpuTrafficProofAuthority::new(fixture.parent.clone(), 1, 2, 3, policy).unwrap();
    let store = fixture
        .backend
        .register_gtpu_traffic_proof_authority(authority.clone())
        .await
        .unwrap();
    let sibling_authority =
        GtpuTrafficProofAuthority::new(fixture.sibling.clone(), 1, 2, 3, policy).unwrap();
    let sibling_store = fixture
        .backend
        .register_gtpu_traffic_proof_authority(sibling_authority)
        .await
        .unwrap();
    let mut sibling_session = fixture
        .backend
        .begin_gtpu_traffic_proof(sibling_store.lease().await)
        .await
        .unwrap();
    let sibling_events =
        enqueue_public_request_and_private_return_traffic(&fixture.runtime, &fixture.sibling);
    fixture
        .runtime
        .state()
        .traffic_observation_events
        .insert(S2BU_IFINDEX, sibling_events);
    let sibling_proof = match fixture
        .backend
        .poll_gtpu_traffic_proof(&mut sibling_session)
        .await
        .unwrap()
    {
        GtpuTrafficProofPoll::Proven(proof) => proof,
        _ => panic!("paired sibling observations must issue the private proof"),
    };
    let mut child_active = None;
    let child = fixture.child(0xb4, 0x1110, 0x41);
    for adding in [true, false] {
        let mut session = fixture
            .backend
            .begin_gtpu_traffic_proof(store.lease().await)
            .await
            .unwrap();
        let events =
            enqueue_public_request_and_private_return_traffic(&fixture.runtime, &fixture.parent);
        fixture
            .runtime
            .state()
            .traffic_observation_events
            .insert(S2BU_IFINDEX, events);
        let proof = match fixture
            .backend
            .poll_gtpu_traffic_proof(&mut session)
            .await
            .unwrap()
        {
            GtpuTrafficProofPoll::Proven(proof) => proof,
            _ => panic!("paired test observations must issue the private proof"),
        };
        assert_eq!(
            fixture
                .backend
                .validate_gtpu_traffic_proof(&proof, &store.lease().await)
                .await
                .unwrap(),
            GtpuTrafficProofValidation::Current
        );
        if adding {
            child_active = Some(fixture.add(child.clone()).await.unwrap());
        } else {
            drop(
                fixture
                    .authority
                    .retire(
                        fixture.backend.clone(),
                        child_active.take().unwrap(),
                        child.clone(),
                    )
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            fixture
                .backend
                .validate_gtpu_traffic_proof(&proof, &store.lease().await)
                .await
                .unwrap(),
            GtpuTrafficProofValidation::Invalidated(GtpuTrafficProofInvalidation::AuthorityRevoked)
        );
        assert_eq!(
            fixture
                .backend
                .validate_gtpu_traffic_proof(&sibling_proof, &sibling_store.lease().await)
                .await
                .unwrap(),
            GtpuTrafficProofValidation::Current
        );
        fixture
            .backend
            .close_gtpu_traffic_proof(session)
            .await
            .unwrap();
    }
    fixture
        .backend
        .close_gtpu_traffic_proof(sibling_session)
        .await
        .unwrap();
}

#[tokio::test]
async fn protected_grouped_bearer_partial_install_and_retirement_debt_never_replays() {
    for removing in [false, true] {
        for cut in [
            "selector_operation_stamp_put",
            "session_transaction_put",
            "session_group_put",
            "session_uplink_put",
            "session_downlink_put",
        ] {
            let fixture = Fixture::new().await;
            let child = fixture.child(0xb4, 0x1110, 0x41);
            let parent_bytes = fixture.runtime.state().session_groups
                [&(S2BU_IFINDEX, fixture.parent.id().to_bytes())];
            let sibling_bytes = fixture.runtime.state().session_groups
                [&(S2BU_IFINDEX, fixture.sibling.id().to_bytes())];
            let active = if removing {
                Some(fixture.add(child.clone()).await.unwrap())
            } else {
                None
            };
            let cut = if removing {
                match cut {
                    "session_uplink_put" => "session_uplink_remove",
                    "session_downlink_put" => "session_downlink_remove",
                    other => other,
                }
            } else {
                cut
            };
            let parent_for_add = fixture.parent_claim().await;
            let parent_for_retire = fixture.parent_claim().await;
            fixture.runtime.fail_in_order([cut]);
            let result = if let Some(active) = active {
                fixture
                    .authority
                    .retire(fixture.backend.clone(), active, child.clone())
                    .await
                    .map(|_| ())
            } else {
                fixture.add(child.clone()).await.map(|_| ())
            };
            assert!(result.is_err(), "fault at {cut} must retain exact debt");
            assert!(
                fixture.runtime.state().failures.is_empty(),
                "injected boundary must run"
            );
            let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
            assert!(fixture
                .authority
                .recover_active(fixture.backend.clone(), child.clone())
                .await
                .is_err());
            if removing {
                assert!(fixture
                    .authority
                    .recover_retiring(fixture.backend.clone(), child.clone())
                    .await
                    .is_err());
            } else {
                assert!(fixture
                    .authority
                    .recover_install(fixture.backend.clone(), child.clone())
                    .await
                    .is_err());
            }
            assert!(fixture
                .authority
                .reconcile_bearer(
                    fixture.backend.clone(),
                    parent_for_add,
                    fixture.parent.clone(),
                    fixture.child(0xb5, 0x1111, 0x42)
                )
                .await
                .is_err());
            assert!(fixture
                .authority
                .retire(
                    fixture.backend.clone(),
                    parent_for_retire,
                    fixture.parent.clone()
                )
                .await
                .is_err());
            assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
            assert_eq!(
                fixture.runtime.state().session_groups
                    [&(S2BU_IFINDEX, fixture.parent.id().to_bytes())],
                parent_bytes
            );
            assert_eq!(
                fixture.runtime.state().session_groups
                    [&(S2BU_IFINDEX, fixture.sibling.id().to_bytes())],
                sibling_bytes
            );
        }
    }
}

#[tokio::test]
async fn protected_grouped_live_bearer_create_delete_create_preserves_parent_and_sibling() {
    let fixture = Fixture::new().await;
    let parent_key = (S2BU_IFINDEX, fixture.parent.id().to_bytes());
    let sibling_key = (S2BU_IFINDEX, fixture.sibling.id().to_bytes());
    let parent_bytes = fixture.runtime.state().session_groups[&parent_key];
    let sibling_bytes = fixture.runtime.state().session_groups[&sibling_key];
    fixture.runtime.state().grouped_reader_grace_enabled = true;
    for cycle in 0..2 {
        let child = fixture.child(0xb4 + cycle, 0x1110 + u32::from(cycle), 0x41);
        let active = fixture.add(child.clone()).await;
        assert!(active.is_ok(), "exact default owner must admit a marked child without retiring its default: {active:?}");
        drop(
            fixture
                .authority
                .retire(fixture.backend.clone(), active.unwrap(), child.clone())
                .await
                .unwrap(),
        );
        assert_eq!(
            fixture.runtime.state().session_groups[&parent_key],
            parent_bytes
        );
        assert_eq!(
            fixture.runtime.state().session_groups[&sibling_key],
            sibling_bytes
        );
        assert!(!fixture
            .runtime
            .state()
            .session_groups
            .contains_key(&(S2BU_IFINDEX, child.id().to_bytes())));
        drop(
            fixture
                .authority
                .recover_active(fixture.backend.clone(), fixture.parent.clone())
                .await
                .unwrap(),
        );
        drop(
            fixture
                .authority
                .recover_active(fixture.backend.clone(), fixture.sibling.clone())
                .await
                .unwrap(),
        );
    }
}

// Gate the real adapter after a map effect but before its acknowledgement.
// This four-second test containment bound does not change any SDK deadline.
pub(super) struct EffectGate {
    group: [u8; GTPU_SESSION_GROUP_ID_LEN],
    operation: &'static str,
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
}

impl EffectGate {
    fn new(group: &GtpuSessionGroup, operation: &'static str) -> Arc<Self> {
        Arc::new(Self {
            group: group.id().to_bytes(),
            operation,
            entered: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            wake: std::sync::Condvar::new(),
        })
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

pub(super) fn pause_effect(
    runtime: &FakeRuntime,
    group: [u8; GTPU_SESSION_GROUP_ID_LEN],
    operation: &'static str,
) -> Result<(), GtpuError> {
    let gate = {
        let mut slot = runtime.bearer_effect_gate.lock().unwrap();
        if slot
            .as_ref()
            .is_some_and(|gate| gate.group == group && gate.operation == operation)
        {
            slot.take()
        } else {
            None
        }
    };
    if let Some(gate) = gate {
        gate.entered.notify_one();
        let (released, _) = gate
            .wake
            .wait_timeout_while(
                gate.released.lock().unwrap(),
                std::time::Duration::from_secs(4),
                |released| !*released,
            )
            .unwrap();
        if !*released {
            return Err(state_indeterminate("bearer_effect_fixture_gate"));
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_grouped_bearer_cancelled_observation_waits_for_late_terminal_effect() {
    for removing in [false, true] {
        let fixture = Fixture::new().await;
        let child = fixture.child(0xb4, 0x1110, 0x41);
        let active = if removing {
            Some(fixture.add(child.clone()).await.unwrap())
        } else {
            None
        };
        let operation = if removing {
            "session_group_remove"
        } else {
            "session_group_put_active"
        };
        let gate = EffectGate::new(&child, operation);
        *fixture.runtime.bearer_effect_gate.lock().unwrap() = Some(gate.clone());
        if let Some(active) = active {
            let observation =
                fixture
                    .authority
                    .retire(fixture.backend.clone(), active, child.clone());
            tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.notified())
                .await
                .unwrap();
            drop(observation);
        } else {
            let observation = fixture.authority.reconcile_bearer(
                fixture.backend.clone(),
                fixture.parent_claim().await,
                fixture.parent.clone(),
                child.clone(),
            );
            tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.notified())
                .await
                .unwrap();
            drop(observation);
        }
        // Drop has no authority to stop or replay an in-progress map effect.
        gate.release();
        if removing {
            drop(
                fixture
                    .authority
                    .recover_retired(fixture.backend.clone(), child.clone())
                    .await
                    .unwrap(),
            );
            assert!(!fixture
                .runtime
                .state()
                .session_groups
                .contains_key(&(S2BU_IFINDEX, child.id().to_bytes())));
        } else {
            drop(
                fixture
                    .authority
                    .recover_active(fixture.backend.clone(), child.clone())
                    .await
                    .unwrap(),
            );
        }
        let effect_count = fixture
            .runtime
            .state()
            .operations
            .iter()
            .filter(|call| **call == operation)
            .count();
        assert_eq!(
            effect_count,
            if removing { 1 } else { 3 },
            "late completion is observed without replay"
        );
        drop(fixture.parent_claim().await);
        drop(
            fixture
                .authority
                .recover_active(fixture.backend.clone(), fixture.sibling.clone())
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn protected_grouped_bearer_reuse_requires_quiescence_before_any_new_effect() {
    let fixture = Fixture::new().await;
    let child = fixture.child(0xb4, 0x1110, 0x41);
    let active = fixture.add(child.clone()).await.unwrap();
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), active, child)
            .await
            .unwrap(),
    );
    let next = fixture.child(0xb5, 0x1111, 0x41);
    let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    let stamps = fixture.runtime.state().selector_operation_stamps.clone();
    assert!(fixture.add(next.clone()).await.is_err());
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
    assert_eq!(fixture.runtime.state().selector_operation_stamps, stamps);
    fixture.runtime.state().grouped_reader_grace_enabled = true;
    let active = fixture.add(next.clone()).await.unwrap();
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), active, next)
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn consumer_simulation_runs_protected_bearer_and_tft_lifecycle_without_traffic_proof() {
    use crate::testkit::GroupedGtpuDataplaneSimulation;
    let fixture = Fixture::new().await;
    let backend = Arc::new(GroupedGtpuDataplaneSimulation::new().unwrap());
    let endpoints =
        GtpuLocalEndpointSet::new(fixture.parent.entries()[0].local_outer_address(), None).unwrap();
    let device = backend
        .create_device_with_endpoints(grouped_device_request(
            "simulated",
            fixture.parent.device_id(),
            endpoints,
        ))
        .await
        .unwrap();
    let scope = SelectorLedgerStorageScope::new(
        TenantId::from_static("grouped-bearer-fixture"),
        NetworkFunctionKind::from_static("grouped-simulation"),
    );
    let authority = crate::GtpuSessionSelectorNamespaceAuthority::provision_protected(
        fixture.store.clone(),
        scope.clone(),
        backend
            .selector_namespace_bootstrap(fixture.parent.device_id())
            .await
            .unwrap(),
        backend.clone(),
        OwnerId::new("consumer-simulation-worker").unwrap(),
        crate::selector_namespace::SELECTOR_NAMESPACE_MAX_LEASE_TTL,
        32,
    )
    .await
    .unwrap();
    let rebind = |group: &GtpuSessionGroup| {
        let mut context = group.entries()[0].context().clone();
        context.link_ifindex = device.ifindex;
        grouped_group(
            group.id().to_bytes()[0],
            group.device_id(),
            vec![GtpuSessionEntry::new(context, group.entries()[0].local_outer_address()).unwrap()],
        )
    };
    let parent = rebind(&fixture.parent);
    let sibling = rebind(&fixture.sibling);
    for group in [&parent, &sibling] {
        drop(
            authority
                .reconcile_fresh(backend.clone(), group.clone())
                .await
                .unwrap(),
        );
    }
    assert!(
        authority
            .reconcile_bearer(
                backend.clone(),
                fixture.parent_claim().await,
                parent.clone(),
                rebind(&fixture.child(0xb4, 0x1110, 0x41))
            )
            .await
            .is_err(),
        "real-adapter namespace receipts cannot control simulation state"
    );
    assert!(
        fixture
            .authority
            .recover_active(backend.clone(), fixture.parent.clone())
            .await
            .is_err(),
        "simulation cannot acquire a real-adapter namespace"
    );
    assert_eq!(backend.probe().await.unwrap().kind, GtpuBackendKind::Mock);
    assert!(!backend.probe().await.unwrap().mutation_ready);
    assert_eq!(
        backend.gtpu_traffic_proof_capability(),
        GtpuCapability::Missing
    );
    let policy = opc_dataplane_observation::TrafficContinuityPolicy::new(
        2,
        std::time::Duration::from_millis(1),
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(2),
        8,
    )
    .unwrap();
    assert!(backend
        .register_gtpu_traffic_proof_authority(
            GtpuTrafficProofAuthority::new(parent.clone(), 1, 2, 3, policy).unwrap()
        )
        .await
        .is_err());
    let default_tft = TftUplinkClassifier::new(
        device.ifindex,
        parent.entries()[0].context().ms_address,
        vec![TftUplinkBearer::default_bearer()],
    )
    .unwrap();
    assert_eq!(
        backend
            .reconcile_tft_uplink_classifier(default_tft.clone())
            .await
            .unwrap(),
        TftUplinkClassifierReconcileOutcome::Installed
    );
    for cycle in 0..2 {
        let child = rebind(&fixture.child(0xb4 + cycle, 0x1110 + u32::from(cycle), 0x41));
        let parent_claim = authority
            .recover_active(backend.clone(), parent.clone())
            .await
            .unwrap();
        let active = authority
            .reconcile_bearer(backend.clone(), parent_claim, parent.clone(), child.clone())
            .await
            .unwrap();
        let filter = PacketFilter::new(
            PacketFilterIdentifier::new(1).unwrap(),
            PacketFilterDirection::UplinkOnly,
            1,
            vec![
                PacketFilterComponent::ProtocolIdentifierNextHeader(17),
                PacketFilterComponent::SingleLocalPort(10000 + u16::from(cycle)),
            ],
        )
        .unwrap();
        let tft = TftUplinkClassifier::new(
            device.ifindex,
            parent.entries()[0].context().ms_address,
            vec![
                TftUplinkBearer::default_bearer(),
                TftUplinkBearer::dedicated(
                    GtpBearerMark::new(0x41).unwrap(),
                    TrafficFlowTemplate::create_new(vec![filter], Vec::new()).unwrap(),
                ),
            ],
        )
        .unwrap();
        backend.validate_tft_uplink_classifier(&tft).unwrap();
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(tft.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::Replaced
        );
        assert_eq!(
            backend
                .read_tft_uplink_classifier(device.ifindex, tft.paa())
                .await
                .unwrap(),
            TftUplinkClassifierReadback::Present(tft.clone())
        );
        for group in [&parent, &sibling, &child] {
            let context = group.entries()[0].context();
            for selector in [
                PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(context).unwrap(),
                ),
                PdpContextSelector::Uplink(
                    PdpContextUplinkSelector::from_context(context).unwrap(),
                ),
            ] {
                assert_eq!(
                    backend.read_pdp_context(selector).await.unwrap(),
                    PdpContextReadback::Present(context.clone())
                );
            }
        }
        assert!(backend
            .install_pdp_context(child.entries()[0].context().clone())
            .await
            .is_err());
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(default_tft.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::Replaced
        );
        drop(
            authority
                .retire(backend.clone(), active, child.clone())
                .await
                .unwrap(),
        );
        let context = child.entries()[0].context();
        for selector in [
            PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(context).unwrap(),
            ),
            PdpContextSelector::Uplink(PdpContextUplinkSelector::from_context(context).unwrap()),
        ] {
            assert_eq!(
                backend.read_pdp_context(selector).await.unwrap(),
                PdpContextReadback::Absent
            );
        }
        drop(
            authority
                .recover_retired(backend.clone(), child)
                .await
                .unwrap(),
        );
        drop(
            authority
                .recover_active(backend.clone(), parent.clone())
                .await
                .unwrap(),
        );
        drop(
            authority
                .recover_active(backend.clone(), sibling.clone())
                .await
                .unwrap(),
        );
    }
    assert_eq!(
        backend
            .remove_tft_uplink_classifier_exact(default_tft)
            .await
            .unwrap(),
        TftUplinkClassifierRemovalOutcome::Removed
    );
    let reopened = crate::GtpuSessionSelectorNamespaceAuthority::open_protected(
        fixture.store.clone(),
        scope,
        backend
            .selector_namespace_bootstrap(parent.device_id())
            .await
            .unwrap(),
        backend.clone(),
        OwnerId::new("consumer-simulation-reopened").unwrap(),
        crate::selector_namespace::SELECTOR_NAMESPACE_MAX_LEASE_TTL,
        32,
    )
    .await
    .unwrap();
    drop(
        reopened
            .recover_active(backend.clone(), parent)
            .await
            .unwrap(),
    );
    drop(reopened.recover_active(backend, sibling).await.unwrap());
}

#[tokio::test]
async fn protected_grouped_bearer_profile_same_mark_is_scoped_to_exact_parent_paa() {
    let fixture = Fixture::new().await;
    let child = fixture.child(0xb4, 0x1110, 6);
    let active = fixture.add(child.clone()).await.unwrap();
    let mut other_context = fixture.sibling.entries()[0].context().clone();
    other_context.local_teid = teid(0x1111);
    other_context.peer_teid = teid(0x2111);
    other_context.bearer_mark = GtpBearerMark::new(6);
    let other = grouped_group(
        0xb5,
        fixture.parent.device_id(),
        vec![GtpuSessionEntry::new(
            other_context,
            fixture.sibling.entries()[0].local_outer_address(),
        )
        .unwrap()],
    );
    let parent_before =
        fixture.runtime.state().session_groups[&(S2BU_IFINDEX, fixture.parent.id().to_bytes())];
    let sibling_before =
        fixture.runtime.state().session_groups[&(S2BU_IFINDEX, fixture.sibling.id().to_bytes())];
    let other_parent = fixture
        .authority
        .recover_active(fixture.backend.clone(), fixture.sibling.clone())
        .await
        .unwrap();
    let other_active = fixture
        .authority
        .reconcile_bearer(
            fixture.backend.clone(),
            other_parent,
            fixture.sibling.clone(),
            other.clone(),
        )
        .await;
    assert!(
        other_active.is_ok(),
        "two exact defaults must independently own PAA+mark 6: {other_active:?}"
    );
    assert_eq!(
        fixture.runtime.state().session_groups[&(S2BU_IFINDEX, fixture.parent.id().to_bytes())],
        parent_before
    );
    assert_eq!(
        fixture.runtime.state().session_groups[&(S2BU_IFINDEX, fixture.sibling.id().to_bytes())],
        sibling_before
    );
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), active, child)
            .await
            .unwrap(),
    );
    drop(
        fixture
            .authority
            .recover_active(fixture.backend.clone(), other.clone())
            .await
            .unwrap(),
    );
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), other_active.unwrap(), other)
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn protected_grouped_bearer_profile_default_reattach_preserves_exact_child_lineage() {
    let fixture = Fixture::new().await;
    fixture.runtime.state().grouped_reader_grace_enabled = true;
    let child = fixture.child(0xb4, 0x1110, 6);
    let active = fixture.add(child.clone()).await.unwrap();
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), active, child)
            .await
            .unwrap(),
    );
    let stale = fixture.parent_claim().await;
    drop(
        fixture
            .authority
            .retire(
                fixture.backend.clone(),
                fixture.parent_claim().await,
                fixture.parent.clone(),
            )
            .await
            .unwrap(),
    );
    let mut next_context = fixture.parent.entries()[0].context().clone();
    next_context.local_teid = teid(0x1115);
    next_context.peer_teid = teid(0x2115);
    let parent = grouped_group(
        0xb6,
        fixture.parent.device_id(),
        vec![GtpuSessionEntry::new(
            next_context,
            fixture.parent.entries()[0].local_outer_address(),
        )
        .unwrap()],
    );
    let new_parent = fixture
        .authority
        .reconcile_reattached(fixture.backend.clone(), parent.clone())
        .await
        .unwrap();
    let child = fixture.child(0xb7, 0x1116, 6);
    assert!(fixture
        .authority
        .reconcile_bearer(
            fixture.backend.clone(),
            stale,
            fixture.parent.clone(),
            child.clone()
        )
        .await
        .is_err());
    fixture.runtime.state().grouped_reader_grace_enabled = false;
    let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    assert!(
        fixture
            .authority
            .reconcile_bearer(
                fixture.backend.clone(),
                new_parent,
                parent.clone(),
                child.clone()
            )
            .await
            .is_err(),
        "default reuse cannot replace child-source quiescence"
    );
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
    fixture.runtime.state().grouped_reader_grace_enabled = true;
    let new_parent = fixture
        .authority
        .recover_active(fixture.backend.clone(), parent.clone())
        .await
        .unwrap();
    let active = fixture
        .authority
        .reconcile_bearer(
            fixture.backend.clone(),
            new_parent,
            parent.clone(),
            child.clone(),
        )
        .await;
    assert!(active.is_ok(), "exact retired default lineage plus fresh current default must support child mark reuse: {active:?}");
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), active.unwrap(), child)
            .await
            .unwrap(),
    );
    drop(
        fixture
            .authority
            .recover_active(fixture.backend.clone(), parent)
            .await
            .unwrap(),
    );
    drop(
        fixture
            .authority
            .recover_active(fixture.backend.clone(), fixture.sibling.clone())
            .await
            .unwrap(),
    );
}
