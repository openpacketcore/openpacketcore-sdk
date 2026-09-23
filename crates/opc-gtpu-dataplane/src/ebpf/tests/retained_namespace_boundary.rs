//! Characterize intact reopening versus lost namespace authority. These use
//! the protected coordinator and production adapter with synthetic kernel IO.
//! A refused open is not a successful restore or proof of kernel-object loss.

use super::*;
use crate::{GtpuSessionSelectorNamespaceAuthority, GtpuSessionSelectorNamespaceError};
use opc_session_store::{
    EncryptingSessionBackend, OwnerId, SelectorLedgerStorageScope, SessionStore,
    SqliteSessionBackend,
};
use opc_types::{NetworkFunctionKind, TenantId};

type Store = EncryptingSessionBackend<SqliteSessionBackend, opc_key::MemoryKeyProvider>;
type Authority = GtpuSessionSelectorNamespaceAuthority<Store>;

struct Fixture {
    runtime: Arc<FakeRuntime>,
    backend: Arc<EbpfGtpuDataplaneBackend>,
    authority: Authority,
    store: SessionStore<Store>,
    scope: SelectorLedgerStorageScope,
    device: GtpuSessionDeviceId,
    endpoints: GtpuLocalEndpointSet,
    groups: Vec<GtpuSessionGroup>,
}

impl Fixture {
    async fn new(with_groups: bool) -> Self {
        let runtime = Arc::new(FakeRuntime::new());
        let device = grouped_device_id(0xd1);
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let endpoints = GtpuLocalEndpointSet::new(local, None).unwrap();
        let backend = Arc::new(attach_grouped_fake(runtime.clone(), device, endpoints).await);
        let tenant = TenantId::from_static("retained-namespace-fixture");
        let keys = Arc::new(opc_key::MemoryKeyProvider::new());
        keys.insert_active_key(
            opc_key::KeyId::new("retained-namespace-key").unwrap(),
            opc_key::KeyPurpose::Session,
            tenant.clone(),
            opc_key::Zeroizing::new([0x63; 32]),
        )
        .unwrap();
        let store = SessionStore::new(EncryptingSessionBackend::new(
            Arc::new(SqliteSessionBackend::in_memory().unwrap()),
            keys,
            "retained-namespace",
        ));
        let scope =
            SelectorLedgerStorageScope::new(tenant, NetworkFunctionKind::from_static("epdg"));
        let authority = Authority::provision_protected(
            store.clone(),
            scope.clone(),
            backend.selector_namespace_bootstrap(device).await.unwrap(),
            backend.clone(),
            OwnerId::new("retained-namespace-first-owner").unwrap(),
            crate::selector_namespace::SELECTOR_NAMESPACE_MAX_LEASE_TTL,
            32,
        )
        .await
        .unwrap();
        let mut groups = Vec::new();
        if with_groups {
            groups.push(grouped_group(
                0xd2,
                device,
                vec![grouped_v4_entry(0x1201, 0x2201)],
            ));
            groups.push(grouped_group(
                0xd3,
                device,
                vec![grouped_entry_for_addresses(
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 222)),
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                    local,
                    0x1202,
                    0x2202,
                    None,
                )],
            ));
            for group in &groups {
                drop(
                    authority
                        .reconcile_fresh(backend.clone(), group.clone())
                        .await
                        .unwrap(),
                );
            }
        }
        Self {
            runtime,
            backend,
            authority,
            store,
            scope,
            device,
            endpoints,
            groups,
        }
    }

    async fn open(
        &self,
        backend: Arc<EbpfGtpuDataplaneBackend>,
        provision: bool,
    ) -> Result<Authority, GtpuSessionSelectorNamespaceError> {
        let bootstrap = backend
            .selector_namespace_bootstrap(self.device)
            .await
            .unwrap();
        let owner = OwnerId::new("retained-namespace-next-owner").unwrap();
        let ttl = crate::selector_namespace::SELECTOR_NAMESPACE_MAX_LEASE_TTL;
        if provision {
            Authority::provision_protected(
                self.store.clone(),
                self.scope.clone(),
                bootstrap,
                backend,
                owner,
                ttl,
                32,
            )
            .await
        } else {
            Authority::open_protected(
                self.store.clone(),
                self.scope.clone(),
                bootstrap,
                backend,
                owner,
                ttl,
                32,
            )
            .await
        }
    }

    async fn assert_original_owners_remain_exact(&self) {
        let reopened = self.open(self.backend.clone(), false).await.unwrap();
        for group in &self.groups {
            drop(
                reopened
                    .recover_active(self.backend.clone(), group.clone())
                    .await
                    .unwrap(),
            );
            assert!(
                self.authority
                    .reconcile_fresh(self.backend.clone(), group.clone())
                    .await
                    .is_err(),
                "retained selector history must not become fresh admission"
            );
        }
    }

    async fn replacement(
        &self,
        pin: [u8; 32],
    ) -> (Arc<FakeRuntime>, Arc<EbpfGtpuDataplaneBackend>) {
        let runtime = Arc::new(FakeRuntime::new());
        runtime
            .state()
            .selector_namespace_pin_commitments
            .insert(S2BU_IFINDEX, pin);
        let backend =
            Arc::new(attach_grouped_fake(runtime.clone(), self.device, self.endpoints).await);
        (runtime, backend)
    }

    async fn start_relocation(
        &self,
        backend: Arc<EbpfGtpuDataplaneBackend>,
    ) -> crate::GtpuSessionSelectorOperation<Authority, GtpuSessionSelectorNamespaceError> {
        Authority::relocate_never_admitted_protected(
            self.store.clone(),
            self.scope.clone(),
            backend
                .selector_namespace_bootstrap(self.device)
                .await
                .unwrap(),
            backend,
            OwnerId::new("synthetic-explicit-relocation").unwrap(),
            crate::selector_namespace::SELECTOR_NAMESPACE_MAX_LEASE_TTL,
            32,
        )
    }
}

#[tokio::test]
async fn retained_namespace_boundary_exact_empty_and_active_open_without_publication() {
    for with_groups in [false, true] {
        let fixture = Fixture::new(with_groups).await;
        let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
        let stamps = fixture.runtime.state().selector_operation_stamps.clone();
        let bindings = fixture.runtime.state().selector_namespace_bindings.clone();
        fixture.runtime.state().operations.clear();
        fixture.assert_original_owners_remain_exact().await;
        assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
        assert!(fixture.runtime.state().selector_operation_stamps == stamps);
        assert!(fixture.runtime.state().selector_namespace_bindings == bindings);
        assert!(!fixture
            .runtime
            .state()
            .operations
            .contains(&"selector_namespace_provision"));
    }
}

#[tokio::test]
async fn retained_namespace_boundary_new_control_root_is_not_the_same_empty_namespace() {
    assert_replacement_root_stays_closed(false).await;
}

#[tokio::test]
async fn pristine_namespace_relocation_retains_ledger_and_excludes_original_owner() {
    let fixture = Fixture::new(false).await;
    let old_binding = fixture.runtime.state().selector_namespace_bindings[&S2BU_IFINDEX];
    let old_publication = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    let replacement_runtime = Arc::new(FakeRuntime::new());
    replacement_runtime
        .state()
        .selector_namespace_pin_commitments
        .insert(S2BU_IFINDEX, [0xb7; 32]);
    let replacement = Arc::new(
        attach_grouped_fake(
            replacement_runtime.clone(),
            fixture.device,
            fixture.endpoints,
        )
        .await,
    );
    let relocated = Authority::relocate_never_admitted_protected(
        fixture.store.clone(),
        fixture.scope.clone(),
        replacement
            .selector_namespace_bootstrap(fixture.device)
            .await
            .unwrap(),
        replacement.clone(),
        OwnerId::new("synthetic-relocation-owner").unwrap(),
        crate::selector_namespace::SELECTOR_NAMESPACE_MAX_LEASE_TTL,
        32,
    )
    .await
    .expect("an exact never-admitted ledger must support explicit relocation");
    let new_binding = replacement_runtime.state().selector_namespace_bindings[&S2BU_IFINDEX];
    assert_eq!(old_binding.ledger_id(), new_binding.ledger_id());
    assert_eq!(old_binding.stable_device(), new_binding.stable_device());
    assert_eq!(
        old_binding.storage_scope_commitment(),
        new_binding.storage_scope_commitment()
    );
    assert_ne!(old_binding.backend_epoch(), new_binding.backend_epoch());
    assert_ne!(old_binding.pin_commitment(), new_binding.pin_commitment());
    let group = grouped_group(0xe1, fixture.device, vec![grouped_v4_entry(0x1301, 0x2301)]);
    assert!(fixture
        .authority
        .reconcile_fresh(fixture.backend.clone(), group.clone())
        .await
        .is_err());
    assert!(fixture.open(fixture.backend.clone(), false).await.is_err());
    assert!(fixture.open(fixture.backend.clone(), true).await.is_err());
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == old_publication);
    drop(
        relocated
            .reconcile_fresh(replacement.clone(), group.clone())
            .await
            .unwrap(),
    );
    let reopened = fixture.open(replacement.clone(), false).await.unwrap();
    drop(reopened.recover_active(replacement, group).await.unwrap());
    assert!(fixture.runtime.state().selector_namespace_bindings[&S2BU_IFINDEX] == old_binding);
}

#[tokio::test]
async fn pristine_namespace_relocation_refuses_active_retired_unadmitted_and_terminal_history() {
    for history in ["active", "retired", "unadmitted", "decommissioned"] {
        let fixture = Fixture::new(history == "active" || history == "retired").await;
        if history == "retired" {
            for group in &fixture.groups {
                let active = fixture
                    .authority
                    .recover_active(fixture.backend.clone(), group.clone())
                    .await
                    .unwrap();
                drop(
                    fixture
                        .authority
                        .retire(fixture.backend.clone(), active, group.clone())
                        .await
                        .unwrap(),
                );
            }
        } else if history == "unadmitted" {
            let group = grouped_group(0xe2, fixture.device, vec![grouped_v4_entry(0x1401, 0x2401)]);
            drop(
                fixture
                    .authority
                    .seal_unadmitted(fixture.backend.clone(), group)
                    .await
                    .unwrap(),
            );
        } else if history == "decommissioned" {
            fixture
                .authority
                .decommission(fixture.backend.clone())
                .await
                .unwrap();
        }
        let (runtime, replacement) = fixture.replacement([0xb8; 32]).await;
        let original = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
        let before = FakeGroupedPublicationSnapshot::capture(&runtime.state());
        runtime.state().operations.clear();
        assert!(
            matches!(
                fixture.start_relocation(replacement).await.await,
                Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
            ),
            "{history}"
        );
        assert!(runtime.state().selector_namespace_bindings.is_empty());
        assert!(!runtime
            .state()
            .operations
            .contains(&"selector_namespace_provision"));
        assert!(FakeGroupedPublicationSnapshot::capture(&runtime.state()) == before);
        assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == original);
        if history == "active" {
            fixture.assert_original_owners_remain_exact().await;
        }
    }
}

#[tokio::test]
async fn pristine_namespace_relocation_cancelled_precommit_resumes_only_exact_successor() {
    let fixture = Fixture::new(false).await;
    let old_publication = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    let (runtime, replacement) = fixture.replacement([0xb9; 32]).await;
    let (entered, release, finished) = replacement
        .pause_next_blocking_worker_start("ebpf_selector_namespace_authorized_provision");
    let operation = fixture.start_relocation(replacement.clone()).await;
    rendezvous_test_barrier(entered).await;
    // The production coordinator has already committed its exact successor,
    // but this effect has not started. Abandon the observer and force a
    // definite backend refusal after releasing the deterministic barrier.
    drop(operation);
    assert!(runtime.state().selector_namespace_bindings.is_empty());
    runtime.state().grouped_map_ready.remove(&S2BU_IFINDEX);
    let (third_runtime, third) = fixture.replacement([0xba; 32]).await;
    let redirected = fixture.start_relocation(third).await;
    let old_group = grouped_group(0xe3, fixture.device, vec![grouped_v4_entry(0x1501, 0x2501)]);
    let stale = fixture
        .authority
        .reconcile_fresh(fixture.backend.clone(), old_group);
    rendezvous_test_barrier(release).await;
    rendezvous_test_barrier(finished).await;
    assert!(matches!(
        redirected.await,
        Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
    ));
    assert!(stale.await.is_err());
    assert!(third_runtime.state().selector_namespace_bindings.is_empty());
    assert!(runtime.state().selector_namespace_bindings.is_empty());
    // A generic provision command must not resume the additional authority.
    runtime.state().grouped_map_ready.insert(S2BU_IFINDEX);
    assert!(matches!(
        fixture.open(replacement.clone(), true).await,
        Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
    ));
    let relocated = fixture
        .start_relocation(replacement.clone())
        .await
        .await
        .unwrap();
    let current = runtime.state().selector_namespace_bindings[&S2BU_IFINDEX];
    drop(
        fixture
            .start_relocation(replacement.clone())
            .await
            .await
            .unwrap(),
    );
    assert!(runtime.state().selector_namespace_bindings[&S2BU_IFINDEX] == current);
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == old_publication);
    let group = grouped_group(0xe4, fixture.device, vec![grouped_v4_entry(0x1601, 0x2601)]);
    drop(
        relocated
            .reconcile_fresh(replacement.clone(), group)
            .await
            .unwrap(),
    );
    assert!(matches!(
        fixture.start_relocation(replacement).await.await,
        Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
    ));
}

#[tokio::test]
async fn pristine_namespace_relocation_lost_provision_ack_retains_exact_binding() {
    let fixture = Fixture::new(false).await;
    let old_binding = fixture.runtime.state().selector_namespace_bindings[&S2BU_IFINDEX];
    let (runtime, replacement) = fixture.replacement([0xbb; 32]).await;
    runtime
        .state()
        .failures_after
        .push_back("selector_namespace_provision");
    assert!(matches!(
        fixture.start_relocation(replacement.clone()).await.await,
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    ));
    let installed = runtime.state().selector_namespace_bindings[&S2BU_IFINDEX];
    assert_eq!(installed.ledger_id(), old_binding.ledger_id());
    assert_ne!(installed.backend_epoch(), old_binding.backend_epoch());
    assert!(matches!(
        fixture.open(replacement.clone(), false).await,
        Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
    ));
    let (third_runtime, third) = fixture.replacement([0xbc; 32]).await;
    assert!(matches!(
        fixture.start_relocation(third).await.await,
        Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
    ));
    assert!(third_runtime.state().selector_namespace_bindings.is_empty());
    drop(
        fixture
            .start_relocation(replacement.clone())
            .await
            .await
            .unwrap(),
    );
    assert!(runtime.state().selector_namespace_bindings[&S2BU_IFINDEX] == installed);
    drop(fixture.open(replacement, false).await.unwrap());
    assert!(fixture.runtime.state().selector_namespace_bindings[&S2BU_IFINDEX] == old_binding);
}

#[tokio::test]
async fn pristine_namespace_relocation_readback_refuses_unowned_or_incomplete_inventory() {
    for fault in [
        "group",
        "uplink",
        "downlink",
        "transaction",
        "stamp",
        "forwarding",
        "classifier",
        "observation",
        "terminal",
        "missing_marker",
        "foreign_marker",
        "wrong_pin",
        "missing_maps",
        "missing_hook",
        "replaced_graph",
    ] {
        let fixture = Fixture::new(false).await;
        let original = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
        let (runtime, replacement) = fixture.replacement([0xbd; 32]).await;
        runtime
            .state()
            .failures_after
            .push_back("selector_namespace_provision");
        assert!(matches!(
            fixture.start_relocation(replacement.clone()).await.await,
            Err(GtpuSessionSelectorNamespaceError::Indeterminate)
        ));
        let (entered, release, finished) =
            replacement.pause_next_blocking_worker_start("ebpf_selector_pristine_readback");
        let retry = fixture.start_relocation(replacement.clone()).await;
        rendezvous_test_barrier(entered).await;
        {
            let mut state = runtime.state();
            match fault {
                "group" => {
                    state.session_groups.insert(
                        (S2BU_IFINDEX, [1; GTPU_SESSION_GROUP_ID_LEN]),
                        [0; GTPU_SESSION_GROUP_VALUE_LEN],
                    );
                }
                "uplink" => {
                    state.session_uplink_index.insert(
                        (S2BU_IFINDEX, [1; GTPU_SESSION_UPLINK_KEY_LEN]),
                        [0; GTPU_SESSION_GROUP_REF_LEN],
                    );
                }
                "downlink" => {
                    state.session_downlink_index.insert(
                        (S2BU_IFINDEX, [1; GTPU_SESSION_DOWNLINK_KEY_LEN]),
                        [0; GTPU_SESSION_GROUP_REF_LEN],
                    );
                }
                "transaction" => {
                    state.session_transactions.insert(
                        (S2BU_IFINDEX, [1; GTPU_SESSION_GROUP_ID_LEN]),
                        [0; GTPU_SESSION_TRANSACTION_VALUE_LEN],
                    );
                }
                "stamp" => {
                    state.selector_operation_stamps.insert(
                        (S2BU_IFINDEX, [1; GTPU_SESSION_GROUP_ID_LEN]),
                        [0; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
                    );
                }
                "forwarding" => {
                    state
                        .far
                        .insert((S2BU_IFINDEX, [192, 0, 2, 20]), [0; UPLINK_FAR_VALUE_LEN]);
                }
                "classifier" => {
                    state.tft_meta.insert(
                        (S2BU_IFINDEX, [1; TFT_CLASSIFIER_KEY_LEN]),
                        [0; TFT_CLASSIFIER_META_VALUE_LEN],
                    );
                }
                "observation" => {
                    state.traffic_observation_registrations.insert(
                        (S2BU_IFINDEX, [1; GTPU_SESSION_GROUP_ID_LEN]),
                        [0; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
                    );
                }
                "terminal" => {
                    state.selector_namespace_terminal_fences.insert(
                        S2BU_IFINDEX,
                        [1; crate::selector_namespace::DECOMMISSION_CAPSULE_LEN],
                    );
                }
                "missing_marker" => {
                    state.selector_namespace_bindings.remove(&S2BU_IFINDEX);
                }
                "foreign_marker" => {
                    state.selector_namespace_bindings.insert(
                        S2BU_IFINDEX,
                        fixture.runtime.state().selector_namespace_bindings[&S2BU_IFINDEX],
                    );
                }
                "wrong_pin" => {
                    state
                        .selector_namespace_pin_commitments
                        .insert(S2BU_IFINDEX, [0xbe; 32]);
                }
                "missing_maps" => {
                    state.grouped_map_ready.remove(&S2BU_IFINDEX);
                }
                "missing_hook" => {
                    state.uplink_filter_ready.remove(&S2BU_IFINDEX);
                }
                "replaced_graph" => {
                    state.pin_identity_invalid.insert(S2BU_IFINDEX);
                }
                _ => unreachable!(),
            }
        }
        let before = FakeGroupedPublicationSnapshot::capture(&runtime.state());
        let bindings = runtime.state().selector_namespace_bindings.clone();
        let stamps = runtime.state().selector_operation_stamps.clone();
        let terminals = runtime.state().selector_namespace_terminal_fences.clone();
        let observations = runtime.state().traffic_observation_registrations.clone();
        rendezvous_test_barrier(release).await;
        rendezvous_test_barrier(finished).await;
        assert!(
            matches!(
                retry.await,
                Err(GtpuSessionSelectorNamespaceError::Indeterminate)
            ),
            "{fault}"
        );
        assert!(
            FakeGroupedPublicationSnapshot::capture(&runtime.state()) == before,
            "{fault}"
        );
        assert!(
            runtime.state().selector_namespace_bindings == bindings,
            "{fault}"
        );
        assert!(
            runtime.state().selector_operation_stamps == stamps,
            "{fault}"
        );
        assert!(
            runtime.state().selector_namespace_terminal_fences == terminals,
            "{fault}"
        );
        assert!(
            runtime.state().traffic_observation_registrations == observations,
            "{fault}"
        );
        assert!(
            FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == original,
            "{fault}"
        );
    }
}

#[tokio::test]
async fn retained_namespace_boundary_new_control_root_preserves_both_original_owners() {
    assert_replacement_root_stays_closed(true).await;
}

async fn assert_replacement_root_stays_closed(with_groups: bool) {
    let fixture = Fixture::new(with_groups).await;
    let original = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    let original_stamps = fixture.runtime.state().selector_operation_stamps.clone();
    let original_bindings = fixture.runtime.state().selector_namespace_bindings.clone();

    // Same convenient device, interface, endpoints and protected store; a
    // different control-root incarnation must not become loss qualification.
    // The old backend deliberately stays live to detect unsafe adoption.
    let replacement_runtime = Arc::new(FakeRuntime::new());
    replacement_runtime
        .state()
        .selector_namespace_pin_commitments
        .insert(S2BU_IFINDEX, [0xa7; 32]);
    let replacement = Arc::new(
        attach_grouped_fake(
            replacement_runtime.clone(),
            fixture.device,
            fixture.endpoints,
        )
        .await,
    );
    let replacement_before = FakeGroupedPublicationSnapshot::capture(&replacement_runtime.state());
    replacement_runtime.state().operations.clear();
    for provision in [false, true] {
        let result = fixture.open(replacement.clone(), provision).await;
        assert!(matches!(
            result,
            Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
        ));
    }
    assert!(replacement_runtime
        .state()
        .selector_namespace_bindings
        .is_empty());
    assert!(replacement_runtime
        .state()
        .selector_operation_stamps
        .is_empty());
    assert!(!replacement_runtime
        .state()
        .operations
        .contains(&"selector_namespace_provision"));
    assert!(
        FakeGroupedPublicationSnapshot::capture(&replacement_runtime.state()) == replacement_before
    );
    fixture.assert_original_owners_remain_exact().await;
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == original);
    assert!(fixture.runtime.state().selector_operation_stamps == original_stamps);
    assert!(fixture.runtime.state().selector_namespace_bindings == original_bindings);
}

#[tokio::test]
async fn retained_namespace_boundary_missing_marker_does_not_authorize_reprovision() {
    for with_groups in [false, true] {
        let fixture = Fixture::new(with_groups).await;
        let binding = fixture
            .runtime
            .state()
            .selector_namespace_bindings
            .remove(&S2BU_IFINDEX)
            .unwrap();
        let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
        let stamps = fixture.runtime.state().selector_operation_stamps.clone();
        fixture.runtime.state().operations.clear();
        for provision in [false, true] {
            assert!(matches!(
                fixture.open(fixture.backend.clone(), provision).await,
                Err(GtpuSessionSelectorNamespaceError::Indeterminate)
            ));
        }
        assert!(fixture
            .runtime
            .state()
            .selector_namespace_bindings
            .is_empty());
        assert!(fixture.runtime.state().selector_operation_stamps == stamps);
        assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
        assert!(!fixture
            .runtime
            .state()
            .operations
            .contains(&"selector_namespace_provision"));

        // Undo only the synthetic fault to check that failed opening did not
        // rewrite the protected ledger. This is not a recovery procedure.
        fixture
            .runtime
            .state()
            .selector_namespace_bindings
            .insert(S2BU_IFINDEX, binding);
        fixture.assert_original_owners_remain_exact().await;
    }
}

fn restart_attachment() -> GtpDevice {
    GtpDevice {
        name: "s2bu".to_owned(),
        ifindex: S2BU_IFINDEX,
    }
}

fn detached_publication(runtime: &FakeRuntime) -> FakeGroupedPublicationSnapshot {
    let mut expected = FakeGroupedPublicationSnapshot::capture(&runtime.state());
    expected.attached.remove(&S2BU_IFINDEX);
    expected.uplink_filter_ready.remove(&S2BU_IFINDEX);
    expected.downlink_filter_ready.remove(&S2BU_IFINDEX);
    expected.uplink_filter_pin_dir.remove(&S2BU_IFINDEX);
    expected.downlink_filter_pin_dir.remove(&S2BU_IFINDEX);
    expected
}

#[tokio::test]
async fn grouped_restart_detach_reopens_active_and_retired_history_without_touching_neighbor() {
    let fixture = Fixture::new(true).await;
    let retired = fixture.groups[0].clone();
    let active = fixture
        .authority
        .recover_active(fixture.backend.clone(), retired.clone())
        .await
        .unwrap();
    drop(
        fixture
            .authority
            .retire(fixture.backend.clone(), active, retired.clone())
            .await
            .unwrap(),
    );
    let neighbor = fixture
        .backend
        .create_device_with_endpoints(grouped_device_request(
            "s2bu-new",
            grouped_device_id(0xe1),
            fixture.endpoints,
        ))
        .await
        .unwrap();
    assert_ne!(neighbor.ifindex, S2BU_IFINDEX);
    let expected = detached_publication(&fixture.runtime);
    let bindings = fixture.runtime.state().selector_namespace_bindings.clone();
    let stamps = fixture.runtime.state().selector_operation_stamps.clone();
    assert!(!stamps.is_empty());
    fixture
        .backend
        .suspend_grouped_device(&restart_attachment())
        .await
        .unwrap();
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == expected);
    assert!(fixture.runtime.state().selector_namespace_bindings == bindings);
    assert!(fixture.runtime.state().selector_operation_stamps == stamps);
    assert!(!fixture
        .backend
        .devices()
        .unwrap()
        .contains_key(&S2BU_IFINDEX));
    assert!(fixture
        .backend
        .devices()
        .unwrap()
        .contains_key(&neighbor.ifindex));
    assert!(matches!(
        fixture
            .backend
            .suspend_grouped_device(&restart_attachment())
            .await,
        Err(GtpuError::NotFound)
    ));
    assert!(fixture
        .authority
        .recover_active(fixture.backend.clone(), fixture.groups[1].clone())
        .await
        .is_err());

    let next = Arc::new(
        attach_grouped_fake(fixture.runtime.clone(), fixture.device, fixture.endpoints).await,
    );
    let reopened = fixture.open(next.clone(), false).await.unwrap();
    assert!(reopened
        .reconcile_fresh(next.clone(), retired)
        .await
        .is_err());
    drop(
        reopened
            .recover_active(next.clone(), fixture.groups[1].clone())
            .await
            .unwrap(),
    );
    // Changing only group/tunnel IDs must not reuse a retired selector. An
    // independent session uses a different address as well as fresh IDs.
    let reused_selector =
        grouped_group(0xe2, fixture.device, vec![grouped_v4_entry(0x1203, 0x2203)]);
    assert!(reopened
        .reconcile_fresh(next.clone(), reused_selector)
        .await
        .is_err());
    let new_group = grouped_group(
        0xe3,
        fixture.device,
        vec![grouped_entry_for_addresses(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 223)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            0x1204,
            0x2204,
            None,
        )],
    );
    let active = reopened
        .reconcile_fresh(next.clone(), new_group.clone())
        .await
        .unwrap();
    drop(reopened.retire(next, active, new_group).await.unwrap());
    assert!(fixture
        .runtime
        .state()
        .attached
        .contains_key(&neighbor.ifindex));
    assert!(fixture
        .runtime
        .state()
        .uplink_filter_ready
        .contains(&neighbor.ifindex));
    assert!(fixture
        .runtime
        .state()
        .downlink_filter_ready
        .contains(&neighbor.ifindex));
}

#[tokio::test]
async fn grouped_restart_detach_refuses_foreign_or_incomplete_graph_without_effects() {
    for fault in [
        "pin",
        "uplink",
        "downlink",
        "off_slot",
        "missing_maps",
        "missing_hook",
    ] {
        let fixture = Fixture::new(true).await;
        {
            let mut state = fixture.runtime.state();
            match fault {
                "pin" => {
                    state.pin_identity_invalid.insert(S2BU_IFINDEX);
                }
                "uplink" => {
                    state.uplink_filter_foreign.insert(S2BU_IFINDEX);
                }
                "downlink" => {
                    state.downlink_filter_foreign.insert(S2BU_IFINDEX);
                }
                "off_slot" => {
                    state.off_slot_sdk_hooks.insert(S2BU_IFINDEX);
                }
                "missing_maps" => {
                    state.grouped_map_ready.remove(&S2BU_IFINDEX);
                }
                "missing_hook" => {
                    state.downlink_filter_ready.remove(&S2BU_IFINDEX);
                }
                _ => unreachable!(),
            }
        }
        let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
        let bindings = fixture.runtime.state().selector_namespace_bindings.clone();
        let stamps = fixture.runtime.state().selector_operation_stamps.clone();
        assert!(
            fixture
                .backend
                .suspend_grouped_device(&restart_attachment())
                .await
                .is_err(),
            "{fault}"
        );
        assert!(
            FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before,
            "{fault}"
        );
        assert!(
            fixture.runtime.state().selector_namespace_bindings == bindings,
            "{fault}"
        );
        assert!(
            fixture.runtime.state().selector_operation_stamps == stamps,
            "{fault}"
        );
    }
}

#[tokio::test]
async fn grouped_restart_detach_refuses_ordinary_stale_and_unadmitted_handles() {
    let (ordinary, runtime) = backend_with_fake();
    let ordinary_device = ordinary.create_device(create_request()).await.unwrap();
    let before = FakeGroupedPublicationSnapshot::capture(&runtime.state());
    assert!(matches!(
        ordinary.suspend_grouped_device(&ordinary_device).await,
        Err(GtpuError::UnsupportedFeature {
            feature: "grouped_restart_detach"
        })
    ));
    assert!(FakeGroupedPublicationSnapshot::capture(&runtime.state()) == before);
    // The existing ordinary lifecycle still removes its graph.
    ordinary.remove_device(&ordinary_device).await.unwrap();
    assert!(runtime.state().attached.is_empty());
    assert!(runtime.state().pinned_config.is_empty());

    for mode in ["stale", "cleanup_only", "successor_pending"] {
        let fixture = Fixture::new(false).await;
        let mut attachment = restart_attachment();
        match mode {
            "stale" => {
                attachment.name = "s2bu-new".to_owned();
            }
            "cleanup_only" => {
                fixture
                    .backend
                    .devices()
                    .unwrap()
                    .get_mut(&S2BU_IFINDEX)
                    .unwrap()
                    .cleanup_only = true;
            }
            "successor_pending" => {
                fixture
                    .backend
                    .devices()
                    .unwrap()
                    .get_mut(&S2BU_IFINDEX)
                    .unwrap()
                    .successor_pending = true;
            }
            _ => unreachable!(),
        }
        let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
        assert!(
            fixture
                .backend
                .suspend_grouped_device(&attachment)
                .await
                .is_err(),
            "{mode}"
        );
        assert!(
            FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before,
            "{mode}"
        );
        assert!(!fixture
            .runtime
            .state()
            .operations
            .contains(&"suspend_grouped"));
    }
}

#[tokio::test]
async fn grouped_restart_detach_cancel_before_dispatch_has_no_effect() {
    let fixture = Fixture::new(true).await;
    let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    let (entered, release, finished) = fixture
        .backend
        .pause_next_blocking_worker_start("ebpf_suspend_grouped_device");
    let backend = fixture.backend.clone();
    let task =
        tokio::spawn(async move { backend.suspend_grouped_device(&restart_attachment()).await });
    rendezvous_test_barrier(entered).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    rendezvous_test_barrier(release).await;
    rendezvous_test_barrier(finished).await;
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before);
    fixture.assert_original_owners_remain_exact().await;
}

#[tokio::test]
async fn grouped_restart_detach_cancel_after_dispatch_finishes_under_owned_guard() {
    let fixture = Fixture::new(true).await;
    let expected = detached_publication(&fixture.runtime);
    let (entered, release) = fixture
        .runtime
        .pause_next_historical_recovery_effect("restart_before_detach");
    let backend = fixture.backend.clone();
    let task =
        tokio::spawn(async move { backend.suspend_grouped_device(&restart_attachment()).await });
    rendezvous_test_barrier(entered).await;
    assert!(fixture
        .runtime
        .selector_namespace_effect_held
        .load(Ordering::Acquire));
    assert!(fixture.backend.inner.operation_lock.try_lock().is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(fixture
        .runtime
        .selector_namespace_effect_held
        .load(Ordering::Acquire));
    rendezvous_test_barrier(release).await;
    // Acquiring the same operation guard waits for the dispatched worker to
    // settle. No sleep or abandoned observer is used as completion evidence.
    assert!(matches!(
        fixture.backend.remove_device(&restart_attachment()).await,
        Err(GtpuError::NotFound)
    ));
    assert!(!fixture
        .runtime
        .selector_namespace_effect_held
        .load(Ordering::Acquire));
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == expected);
    let next = Arc::new(
        attach_grouped_fake(fixture.runtime.clone(), fixture.device, fixture.endpoints).await,
    );
    let reopened = fixture.open(next.clone(), false).await.unwrap();
    for group in &fixture.groups {
        drop(
            reopened
                .recover_active(next.clone(), group.clone())
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn grouped_restart_detach_partial_failure_retains_exact_history_and_refuses_success() {
    let fixture = Fixture::new(true).await;
    let before = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
    let bindings = fixture.runtime.state().selector_namespace_bindings.clone();
    let stamps = fixture.runtime.state().selector_operation_stamps.clone();
    fixture.runtime.fail_in_order(["restart_after_uplink"]);
    assert!(matches!(
        fixture
            .backend
            .suspend_grouped_device(&restart_attachment())
            .await,
        Err(GtpuError::StateIndeterminate { .. })
    ));
    let mut expected = before;
    expected.attached.remove(&S2BU_IFINDEX);
    expected.uplink_filter_ready.remove(&S2BU_IFINDEX);
    expected.uplink_filter_pin_dir.remove(&S2BU_IFINDEX);
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == expected);
    assert!(fixture.runtime.state().selector_namespace_bindings == bindings);
    assert!(fixture.runtime.state().selector_operation_stamps == stamps);
    assert!(fixture
        .backend
        .suspend_grouped_device(&restart_attachment())
        .await
        .is_err());
    assert!(FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == expected);
    assert!(fixture
        .authority
        .recover_active(fixture.backend.clone(), fixture.groups[0].clone())
        .await
        .is_err());
}

#[tokio::test]
async fn grouped_restart_detach_rejects_identity_change_before_final_receipt() {
    for boundary in ["restart_before_detach", "restart_after_detach"] {
        let fixture = Fixture::new(true).await;
        let pins = fixture.runtime.state().pinned_grouped_config.clone();
        let stamps = fixture.runtime.state().selector_operation_stamps.clone();
        let (entered, release) = fixture
            .runtime
            .pause_next_historical_recovery_effect(boundary);
        let backend = fixture.backend.clone();
        let task =
            tokio::spawn(
                async move { backend.suspend_grouped_device(&restart_attachment()).await },
            );
        rendezvous_test_barrier(entered).await;
        fixture
            .runtime
            .state()
            .pin_identity_invalid
            .insert(S2BU_IFINDEX);
        let before_resume = FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state());
        rendezvous_test_barrier(release).await;
        assert!(
            matches!(
                task.await.unwrap(),
                Err(GtpuError::StateIndeterminate { .. })
            ),
            "{boundary}"
        );
        assert!(
            FakeGroupedPublicationSnapshot::capture(&fixture.runtime.state()) == before_resume,
            "{boundary}"
        );
        assert!(
            fixture.runtime.state().pinned_grouped_config == pins,
            "{boundary}"
        );
        assert!(
            fixture.runtime.state().selector_operation_stamps == stamps,
            "{boundary}"
        );
        assert!(!fixture
            .runtime
            .selector_namespace_effect_held
            .load(Ordering::Acquire));
    }
}
