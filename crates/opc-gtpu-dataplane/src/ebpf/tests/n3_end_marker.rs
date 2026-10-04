//! Real protected coordinator and eBPF adapter, synthetic kernel IO. These
//! tests qualify refusal boundaries; the native test qualifies packet effects.

use super::*;
use crate::{GtpuN3EndMarkerError, GtpuSessionSelectorNamespaceAuthority};
use opc_session_store::{
    EncryptingSessionBackend, OwnerId, SelectorLedgerStorageScope, SessionStore,
    SqliteSessionBackend,
};
use opc_types::{NetworkFunctionKind, TenantId};
use std::time::Duration;

type Authority = GtpuSessionSelectorNamespaceAuthority<
    EncryptingSessionBackend<SqliteSessionBackend, opc_key::MemoryKeyProvider>,
>;

async fn fixture(
    second: Option<GtpuSessionEntry>,
) -> (
    Arc<FakeRuntime>,
    Arc<EbpfGtpuDataplaneBackend>,
    Authority,
    GtpuSessionGroup,
    crate::GtpuSessionSelectorRetiredClaim,
) {
    let runtime = Arc::new(FakeRuntime::new());
    let device_id = grouped_device_id(0x72);
    let endpoints = GtpuLocalEndpointSet::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        Some(IpAddr::V6(ipv6_local())),
    )
    .unwrap();
    let backend = Arc::new(attach_grouped_fake(runtime.clone(), device_id, endpoints).await);
    let tenant = TenantId::from_static("n3-end-marker-fixture");
    let keys = Arc::new(opc_key::MemoryKeyProvider::new());
    keys.insert_active_key(
        opc_key::KeyId::new("fixture-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x53; 32]),
    )
    .unwrap();
    let store = SessionStore::new(EncryptingSessionBackend::new(
        Arc::new(SqliteSessionBackend::in_memory().unwrap()),
        keys,
        "n3-end-marker-fixture",
    ));
    let authority = Authority::provision_protected(
        store,
        SelectorLedgerStorageScope::new(tenant, NetworkFunctionKind::from_static("n3iwf")),
        backend
            .selector_namespace_bootstrap(device_id)
            .await
            .unwrap(),
        backend.clone(),
        OwnerId::new("fixture-worker").unwrap(),
        Duration::from_secs(30),
        32,
    )
    .await
    .unwrap();
    let mut entries = vec![grouped_v4_entry(0x1100_0001, 0x2100_0001)
        .restore_n3_qfi(0)
        .unwrap()];
    entries.extend(second);
    let desired = grouped_group(0x73, device_id, entries);
    let active = authority
        .reconcile_fresh(backend.clone(), desired.clone())
        .await
        .unwrap();
    let retired = authority
        .retire(backend.clone(), active, desired.clone())
        .await
        .unwrap();
    (runtime, backend, authority, desired, retired)
}

fn control_socket_is_unopened(backend: &EbpfGtpuDataplaneBackend) -> bool {
    backend.devices().unwrap()[&S2BU_IFINDEX]
        .control_socket
        .lock()
        .unwrap()
        .is_unopened()
}

#[tokio::test]
async fn mixed_end_marker_profiles_are_unsupported_before_grace_or_socket_effects() {
    for outer_ipv6 in [true, false] {
        let second = grouped_v6_entry(0x1100_0002, 0x2100_0002, ipv6_peer());
        let second = if outer_ipv6 {
            second
        } else {
            let first = grouped_v4_entry(0x1100_0001, 0x2100_0001);
            let mut context = second.context().clone();
            context.peer_address = first.context().peer_address;
            context.uplink_source_port_policy = crate::GtpuUplinkSourcePortPolicy::Selected(40000);
            GtpuSessionEntry::new(context, first.local_outer_address()).unwrap()
        }
        .restore_n3_qfi(63)
        .unwrap();
        let (runtime, backend, authority, desired, retired) = fixture(Some(second)).await;
        runtime.state().grouped_reader_grace_enabled = true;
        assert!(matches!(
            authority
                .send_n3_end_markers(backend.clone(), retired)
                .await,
            Err(GtpuN3EndMarkerError::Unsupported)
        ));
        assert_eq!(runtime.state().grouped_reader_grace_calls, 0);
        assert!(control_socket_is_unopened(&backend));
        drop(authority.recover_retired(backend, desired).await.unwrap());
    }
}

#[tokio::test]
async fn end_marker_requires_available_successful_grace_and_exact_post_grace_retirement() {
    let (runtime, backend, authority, desired, retired) = fixture(None).await;
    assert!(matches!(
        authority
            .send_n3_end_markers(backend.clone(), retired)
            .await,
        Err(GtpuN3EndMarkerError::Unsupported)
    ));
    assert_eq!(runtime.state().grouped_reader_grace_calls, 0);
    assert!(control_socket_is_unopened(&backend));

    let key = (S2BU_IFINDEX, desired.id().to_bytes());
    let stamp = runtime.state().selector_operation_stamps[&key];
    for corrupt_after_grace in [false, true] {
        let retired = authority
            .recover_retired(backend.clone(), desired.clone())
            .await
            .unwrap();
        {
            let mut state = runtime.state();
            state.grouped_reader_grace_enabled = true;
            state.grouped_reader_grace_fault = !corrupt_after_grace;
            state.grouped_reader_grace_corrupt_group =
                corrupt_after_grace.then_some(desired.id().to_bytes());
        }
        assert!(matches!(
            authority
                .send_n3_end_markers(backend.clone(), retired)
                .await,
            Err(GtpuN3EndMarkerError::Backend)
        ));
        assert!(control_socket_is_unopened(&backend));
        runtime.state().selector_operation_stamps.insert(key, stamp);
    }
    assert_eq!(runtime.state().grouped_reader_grace_calls, 2);
    drop(authority.recover_retired(backend, desired).await.unwrap());
}
