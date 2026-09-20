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
