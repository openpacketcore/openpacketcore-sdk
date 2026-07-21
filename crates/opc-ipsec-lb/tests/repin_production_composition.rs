//! Public composition proof for destination-scoped Host-XDP session re-pin.

use opc_ipsec_lb::{
    ClusterNode, HostXdpSteeringBackend, HostXdpSteeringBackendConfig, MockRePinAuditSink,
    OwnershipFence, OwnershipTransitionId, RePinCoordinator, RePinRequest, SameSpiResume,
    SessionOwnershipKey, SessionOwnershipKeyspace, SessionRePinCoordinator,
    SessionStoreOwnershipFencer, SessionStoreOwnershipSource, SessionStoreRePinJournal,
    SteeringRule,
};
use opc_ipsec_xfrm::{AppliedEspCounterReceipt, InstalledOutboundSaBinding};
use opc_session_store::FakeSessionBackend;
use opc_types::{NetworkFunctionKind, TenantId};

// This helper is deliberately type-checked but not executed: production is
// the only path that can mint the opaque XFRM binding and applied receipt. It
// proves that downstream code can carry the binding's durable ID into the
// request while independently carrying its live actor target and receipt into
// the coordinator, without a raw-SPI or fabricated-authority adapter.
#[allow(dead_code, clippy::too_many_arguments)]
fn public_applied_counter_authority_composes_with_host_repin(
    installed: &InstalledOutboundSaBinding,
    receipt: AppliedEspCounterReceipt,
    inbound_spi: u32,
    transition_id: OwnershipTransitionId,
    previous_fence: OwnershipFence,
    previous_owner: ClusterNode,
    new_owner: ClusterNode,
    rule: SteeringRule,
    ownership_key: SessionOwnershipKey,
    resume: SameSpiResume,
) -> Result<(), opc_ipsec_lb::IpsecLbError> {
    let request = RePinRequest::new_esp(
        inbound_spi,
        installed.id(),
        transition_id,
        previous_fence,
        previous_owner,
        new_owner,
        rule,
        ownership_key,
        resume,
    )?;
    let live_target = installed.outbound_esp_counter_target();

    let tenant = TenantId::new("tenant-a").expect("valid test tenant");
    let nf_kind = NetworkFunctionKind::new("epdg").expect("valid NF kind");
    let store = FakeSessionBackend::new();
    let ownership_keys = SessionOwnershipKeyspace::new(tenant, nf_kind);
    let steering = HostXdpSteeringBackend::unsupported(
        "swu0",
        HostXdpSteeringBackendConfig::default().for_destination_scoped_repin(),
    );
    let ownership = SessionStoreOwnershipSource::new(store.clone(), ownership_keys.clone());
    let fencer = SessionStoreOwnershipFencer::new(store, ownership_keys);
    let _coordinator =
        RePinCoordinator::new(steering, fencer, ownership, MockRePinAuditSink::new())
            .with_esp_counter_resume_receipt(receipt, live_target);

    assert_eq!(request.outbound_sa_binding_id, Some(installed.id()));
    Ok(())
}

#[test]
fn public_host_store_repin_composition_supports_safe_session_retirement() {
    let tenant = TenantId::new("tenant-a").expect("valid test tenant");
    let nf_kind = NetworkFunctionKind::new("epdg").expect("valid NF kind");
    let store = FakeSessionBackend::new();
    let ownership_keys = SessionOwnershipKeyspace::new(tenant.clone(), nf_kind.clone());

    let steering = HostXdpSteeringBackend::unsupported(
        "swu0",
        HostXdpSteeringBackendConfig::default().for_destination_scoped_repin(),
    );
    let ownership = SessionStoreOwnershipSource::new(store.clone(), ownership_keys.clone());
    let fencer = SessionStoreOwnershipFencer::new(store.clone(), ownership_keys);
    let journal = SessionStoreRePinJournal::new(store, tenant, nf_kind);
    let repin = RePinCoordinator::new(steering, fencer, ownership, MockRePinAuditSink::new());

    // This construction is intentionally outside the crate. It proves the
    // public Host-XDP/store types satisfy both activation and coordinated
    // retirement bounds without a downstream adapter or raw steering escape.
    let _session_repin = SessionRePinCoordinator::new(repin, journal);
}
