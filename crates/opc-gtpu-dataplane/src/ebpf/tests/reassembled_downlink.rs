//! Backend-authoritative downlink consumer over the fake runtime. These tests
//! pin every tc-parity decision against the backend's own map state; the
//! privileged native test proves kernel reassembly and socket delivery.

use super::*;
use crate::control_port::GtpuControlDatagram;
use crate::ebpf::reassembled_downlink::{process_downlink_datagram, DownlinkAuthorityScope};
use crate::{
    GtpuDownlinkCounters, GtpuDownlinkDrop, GtpuDownlinkEvent,
    GtpuSessionSelectorNamespaceAuthority,
};
use opc_gtpu_ebpf_common::DownlinkBindingMismatch;
use opc_session_store::{
    EncryptingSessionBackend, OwnerId, SelectorLedgerStorageScope, SessionStore,
    SqliteSessionBackend,
};
use opc_types::{NetworkFunctionKind, TenantId};
use std::time::Duration;

const UE: [u8; 4] = [10, 45, 0, 2];
const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LOCAL_TEID: u32 = 0x1000_0001;

fn inner_ipv4(destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(28 + payload.len()).unwrap();
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[8, 8, 8, 8]);
    packet.extend_from_slice(&destination);
    packet.extend_from_slice(&53_u16.to_be_bytes());
    packet.extend_from_slice(&5060_u16.to_be_bytes());
    packet.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);
    packet
}

fn inner_ipv6(destination: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(&[17, 64]);
    packet.extend_from_slice(&"2001:db8:ffff::8".parse::<Ipv6Addr>().unwrap().octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    packet
}

fn gpdu(teid: u32, inner: &[u8]) -> Vec<u8> {
    let mut message = vec![0x30, 0xff];
    message.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    message.extend_from_slice(&teid.to_be_bytes());
    message.extend_from_slice(inner);
    message
}

fn datagram_from(message: Vec<u8>, peer: Ipv4Addr, source_port: u16) -> GtpuControlDatagram {
    GtpuControlDatagram::received(
        message.into(),
        crate::DownlinkOuterProvenance::new(peer, LOCAL, S2BU_IFINDEX, source_port).unwrap(),
        Arc::new(()),
    )
}

fn ordinary_scope() -> DownlinkAuthorityScope {
    DownlinkAuthorityScope {
        ifindex: S2BU_IFINDEX,
        grouped_config: None,
        ordinary_local_ipv4: Some(LOCAL),
    }
}

fn process(
    runtime: &FakeRuntime,
    scope: DownlinkAuthorityScope,
    message: Vec<u8>,
    counters: &mut GtpuDownlinkCounters,
) -> GtpuDownlinkEvent {
    process_downlink_datagram(runtime, scope, datagram_from(message, PEER, 2152), counters)
}

async fn ordinary_fixture(context: GtpPdpContext) -> (EbpfGtpuDataplaneBackend, Arc<FakeRuntime>) {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    backend.install_pdp_context(context).await.unwrap();
    open_fake_traffic_gate(&runtime);
    // The single current object loads the grouped index for every attachment;
    // an ordinary attachment's index is empty, so tc takes the v5 path.
    runtime.state().grouped_map_ready.insert(S2BU_IFINDEX);
    (backend, runtime)
}

fn open_fake_traffic_gate(runtime: &FakeRuntime) {
    runtime
        .state()
        .traffic_observation_gate
        .insert(S2BU_IFINDEX, 3);
}

fn expect_drop(event: GtpuDownlinkEvent) -> GtpuDownlinkDrop {
    match event {
        GtpuDownlinkEvent::Dropped(reason) => reason,
        other => panic!("expected a fail-closed drop, got {other:?}"),
    }
}

#[tokio::test]
async fn ordinary_default_bearer_decapsulates_exact_inner_packet_once() {
    let (_backend, runtime) = ordinary_fixture(context()).await;
    let inner = inner_ipv4(UE, b"INVITE sip:ue SIP/2.0");
    let mut counters = GtpuDownlinkCounters::default();
    let GtpuDownlinkEvent::Decapsulated(decapsulated) = process(
        &runtime,
        ordinary_scope(),
        gpdu(LOCAL_TEID, &inner),
        &mut counters,
    ) else {
        panic!("authorized default-bearer G-PDU must decapsulate");
    };
    assert_eq!(decapsulated.inner_packet(), inner.as_slice());
    assert_eq!(decapsulated.bearer_mark(), None);
    assert_eq!(decapsulated.family(), crate::GtpAddressFamily::Ipv4);
    let debug = format!("{decapsulated:?}");
    assert!(!debug.contains("10, 45") && !debug.contains("INVITE"));
    assert_eq!(counters.decapsulated, 1);
    assert_eq!(
        counters,
        GtpuDownlinkCounters {
            decapsulated: 1,
            ..GtpuDownlinkCounters::default()
        }
    );
}

#[tokio::test]
async fn ordinary_marked_bearer_returns_its_exact_output_mark() {
    let (_backend, runtime) =
        ordinary_fixture(marked_context(0x0001_0001, 0x1000_0002, 0x2000_0002)).await;
    let mut counters = GtpuDownlinkCounters::default();
    let GtpuDownlinkEvent::Decapsulated(decapsulated) = process(
        &runtime,
        ordinary_scope(),
        gpdu(0x1000_0002, &inner_ipv4(UE, b"marked")),
        &mut counters,
    ) else {
        panic!("authorized marked G-PDU must decapsulate");
    };
    assert_eq!(decapsulated.bearer_mark(), GtpBearerMark::new(0x0001_0001));
    assert!(!format!("{decapsulated:?}").contains("65537"));
}

#[tokio::test]
async fn commit_phase_other_than_active_is_the_publication_fence() {
    for phase in [
        MarkedBearerOwnerPhase::Pending,
        MarkedBearerOwnerPhase::Removing,
    ] {
        let (_backend, runtime) = ordinary_fixture(context()).await;
        {
            let mut state = runtime.state();
            let key = (S2BU_IFINDEX, UE);
            let commit = PdpContextCommit::decode(&state.sport[&key]);
            state.sport.insert(key, commit.with_phase(phase).encode());
        }
        let mut counters = GtpuDownlinkCounters::default();
        assert_eq!(
            expect_drop(process(
                &runtime,
                ordinary_scope(),
                gpdu(LOCAL_TEID, &inner_ipv4(UE, b"fenced")),
                &mut counters,
            )),
            GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
        );
        assert_eq!(counters.binding_drops, 1);
        assert_eq!(counters.decapsulated, 0);
    }
}

#[tokio::test]
async fn every_missing_graph_component_fails_closed() {
    for component in ["far", "commit", "binding"] {
        let (_backend, runtime) = ordinary_fixture(context()).await;
        {
            let mut state = runtime.state();
            match component {
                "far" => drop(state.far.remove(&(S2BU_IFINDEX, UE))),
                "commit" => drop(state.sport.remove(&(S2BU_IFINDEX, UE))),
                _ => drop(
                    state
                        .downlink_binding
                        .remove(&(S2BU_IFINDEX, LOCAL_TEID.to_be_bytes())),
                ),
            }
        }
        let mut counters = GtpuDownlinkCounters::default();
        assert_eq!(
            expect_drop(process(
                &runtime,
                ordinary_scope(),
                gpdu(LOCAL_TEID, &inner_ipv4(UE, b"partial")),
                &mut counters,
            )),
            GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid),
            "{component}"
        );
    }
}

#[tokio::test]
async fn corrupt_dscp_and_mismatched_commit_graph_fail_closed() {
    let (_backend, runtime) = ordinary_fixture(context()).await;
    runtime.state().dscp.insert((S2BU_IFINDEX, UE), [64]);
    let mut counters = GtpuDownlinkCounters::default();
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"dscp")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
    // A FAR replaced without its commit is a mixed graph.
    runtime.state().dscp.remove(&(S2BU_IFINDEX, UE));
    {
        let mut state = runtime.state();
        let mut far = UplinkFar::decode(&state.far[&(S2BU_IFINDEX, UE)]);
        far.o_teid = 0x2999_0001_u32.to_be_bytes();
        state.far.insert((S2BU_IFINDEX, UE), far.encode());
    }
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"mixed")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
    assert_eq!(counters.binding_drops, 2);
}

#[tokio::test]
async fn admitting_binding_that_differs_from_the_active_commit_fails_closed() {
    let (_backend, runtime) = ordinary_fixture(context()).await;
    let narrowed = DownlinkEndpointBinding::new(
        GtpuEndpointAddress::Ipv4(PEER.octets()),
        GtpuEndpointAddress::Ipv4(LOCAL.octets()),
        S2BU_IFINDEX,
        crate::GtpuSourcePortPolicy::Exact(2152),
    )
    .unwrap();
    runtime
        .state()
        .downlink_binding
        .insert((S2BU_IFINDEX, LOCAL_TEID.to_be_bytes()), narrowed.encode());
    let mut counters = GtpuDownlinkCounters::default();
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"mixed binding")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
}

#[tokio::test]
async fn marked_owner_journal_is_mandatory() {
    let (_backend, runtime) =
        ordinary_fixture(marked_context(0x0001_0001, 0x1000_0002, 0x2000_0002)).await;
    let selector = UplinkFarKey {
        ue_ip: UE,
        bearer_mark: 0x0001_0001_u32.to_be_bytes(),
    }
    .encode();
    let owner = runtime
        .state()
        .marked_owner
        .remove(&(S2BU_IFINDEX, selector))
        .unwrap();
    let mut counters = GtpuDownlinkCounters::default();
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(0x1000_0002, &inner_ipv4(UE, b"owner")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
    let mut pending = MarkedBearerOwner::decode(&owner);
    pending.phase = MarkedBearerOwnerPhase::Pending;
    runtime
        .state()
        .marked_owner
        .insert((S2BU_IFINDEX, selector), pending.encode());
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(0x1000_0002, &inner_ipv4(UE, b"owner")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
}

#[tokio::test]
async fn outer_binding_and_inner_destination_are_enforced() {
    let (_backend, runtime) = ordinary_fixture(context()).await;
    let mut counters = GtpuDownlinkCounters::default();
    let wrong_peer = process_downlink_datagram(
        runtime.as_ref(),
        ordinary_scope(),
        datagram_from(
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"peer")),
            Ipv4Addr::new(192, 0, 2, 11),
            2152,
        ),
        &mut counters,
    );
    assert_eq!(
        expect_drop(wrong_peer),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::PeerAddress)
    );
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4([10, 45, 0, 3], b"dst")),
            &mut counters,
        )),
        GtpuDownlinkDrop::DestinationMismatch
    );
    let foreign_attachment = DownlinkAuthorityScope {
        ifindex: S2BU_IFINDEX + 1,
        grouped_config: None,
        ordinary_local_ipv4: Some(LOCAL),
    };
    assert_eq!(
        expect_drop(process(
            &runtime,
            foreign_attachment,
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"ifindex")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::IngressAttachment)
    );
    assert_eq!(counters.binding_drops, 2);
    assert_eq!(counters.destination_mismatches, 1);
}

#[tokio::test]
async fn unknown_teid_is_returned_undecapsulated_and_retained_binding_is_not_unknown() {
    let (_backend, runtime) = ordinary_fixture(context()).await;
    let message = gpdu(0x1000_0999, &inner_ipv4(UE, b"foreign"));
    let mut counters = GtpuDownlinkCounters::default();
    let GtpuDownlinkEvent::UnknownTunnel(datagram) =
        process(&runtime, ordinary_scope(), message.clone(), &mut counters)
    else {
        panic!("a foreign TEID must be an unknown-tunnel observation");
    };
    assert_eq!(datagram.bytes(), message.as_slice());
    assert_eq!(counters.unknown_tunnel, 1);

    // A partially removed graph whose binding survives is not an unowned tunnel.
    runtime
        .state()
        .pdr
        .remove(&(S2BU_IFINDEX, LOCAL_TEID.to_be_bytes()));
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"retained")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
}

#[tokio::test]
async fn corrupt_pdr_ownership_is_malformed() {
    let (_backend, runtime) = ordinary_fixture(context()).await;
    runtime.state().marked_pdr.insert(
        (S2BU_IFINDEX, LOCAL_TEID.to_be_bytes()),
        MarkedDownlinkPdr {
            ue_ip: UE,
            bearer_mark: [0, 1, 0, 1],
        }
        .encode(),
    );
    let mut counters = GtpuDownlinkCounters::default();
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"dual")),
            &mut counters,
        )),
        GtpuDownlinkDrop::Malformed
    );
    let (_backend, runtime) = ordinary_fixture(context()).await;
    {
        let mut state = runtime.state();
        state.pdr.remove(&(S2BU_IFINDEX, LOCAL_TEID.to_be_bytes()));
        state.marked_pdr.insert(
            (S2BU_IFINDEX, LOCAL_TEID.to_be_bytes()),
            MarkedDownlinkPdr {
                ue_ip: UE,
                bearer_mark: [0; 4],
            }
            .encode(),
        );
    }
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"zero")),
            &mut counters,
        )),
        GtpuDownlinkDrop::Malformed
    );
    assert_eq!(counters.malformed, 2);
}

#[tokio::test]
async fn closed_traffic_gate_and_foreign_grouped_index_fail_closed() {
    let (_backend, runtime) = ordinary_fixture(context()).await;
    runtime
        .state()
        .traffic_observation_gate
        .insert(S2BU_IFINDEX, 2);
    let mut counters = GtpuDownlinkCounters::default();
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"gate")),
            &mut counters,
        )),
        GtpuDownlinkDrop::StateUnavailable
    );
    assert_eq!(counters.state_unavailable, 1);
    open_fake_traffic_gate(&runtime);

    // A retained grouped index on an ordinary attachment is never a v5
    // fallback, matching the tc lookup order.
    let mut key = [0_u8; GTPU_SESSION_DOWNLINK_KEY_LEN];
    key[0] = 4;
    key[1] = 4;
    key[4..8].copy_from_slice(&LOCAL_TEID.to_be_bytes());
    runtime
        .state()
        .session_downlink_index
        .insert((S2BU_IFINDEX, key), [0x44; GTPU_SESSION_GROUP_REF_LEN]);
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"grouped")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
}

#[tokio::test]
async fn controls_and_malformed_framing_are_never_decapsulated() {
    let (_backend, runtime) = ordinary_fixture(context()).await;
    let mut counters = GtpuDownlinkCounters::default();
    // Echo Request with the mandatory sequence block.
    let echo = vec![0x32, 1, 0, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0];
    assert!(matches!(
        process(&runtime, ordinary_scope(), echo, &mut counters),
        GtpuDownlinkEvent::Control(_)
    ));
    let mut truncated = gpdu(LOCAL_TEID, &inner_ipv4(UE, b"short"));
    truncated.truncate(20);
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            truncated,
            &mut counters
        )),
        GtpuDownlinkDrop::Malformed
    );
    // Inner IPv6 on the ordinary IPv4 path is malformed, as in tc.
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv6(ipv6_inner(), b"v6")),
            &mut counters,
        )),
        GtpuDownlinkDrop::Malformed
    );
    assert_eq!(counters.control_plane, 1);
    assert_eq!(counters.malformed, 2);
    assert_eq!(counters.decapsulated, 0);
}

type Authority = GtpuSessionSelectorNamespaceAuthority<
    EncryptingSessionBackend<SqliteSessionBackend, opc_key::MemoryKeyProvider>,
>;

async fn grouped_fixture(
    entries: Vec<GtpuSessionEntry>,
) -> (
    Arc<FakeRuntime>,
    Arc<EbpfGtpuDataplaneBackend>,
    Authority,
    GtpuSessionGroup,
    DownlinkAuthorityScope,
) {
    let runtime = Arc::new(FakeRuntime::new());
    let device_id = grouped_device_id(0x72);
    let endpoints =
        GtpuLocalEndpointSet::new(IpAddr::V4(LOCAL), Some(IpAddr::V6(ipv6_local()))).unwrap();
    let backend = Arc::new(attach_grouped_fake(runtime.clone(), device_id, endpoints).await);
    let tenant = TenantId::from_static("reassembled-downlink-fixture");
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
        "reassembled-downlink-fixture",
    ));
    let authority = Authority::provision_protected(
        store,
        SelectorLedgerStorageScope::new(tenant, NetworkFunctionKind::from_static("epdg")),
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
    let desired = grouped_group(0x73, device_id, entries);
    drop(
        authority
            .reconcile_fresh(backend.clone(), desired.clone())
            .await
            .unwrap(),
    );
    open_fake_traffic_gate(&runtime);
    let scope = DownlinkAuthorityScope {
        ifindex: S2BU_IFINDEX,
        grouped_config: grouped_device_config(device_id, S2BU_IFINDEX, endpoints),
        ordinary_local_ipv4: None,
    };
    assert!(scope.grouped_config.is_some());
    (runtime, backend, authority, desired, scope)
}

fn grouped_v6_inner_over_v4_entry(local_teid: u32, peer_teid: u32) -> GtpuSessionEntry {
    let mut context = grouped_v4_entry(local_teid, peer_teid).context().clone();
    context.ms_address = IpAddr::V6(ipv6_inner());
    GtpuSessionEntry::new(context, IpAddr::V4(LOCAL)).unwrap()
}

#[tokio::test]
async fn grouped_dual_family_generation_authorizes_both_inner_families() {
    let (runtime, _backend, _authority, _desired, scope) = grouped_fixture(vec![
        grouped_v4_entry(0x1100_0001, 0x2100_0001),
        grouped_v6_inner_over_v4_entry(0x1100_0002, 0x2100_0002),
    ])
    .await;
    let mut counters = GtpuDownlinkCounters::default();
    let v4 = inner_ipv4(UE, b"grouped v4");
    let GtpuDownlinkEvent::Decapsulated(decapsulated) =
        process(&runtime, scope, gpdu(0x1100_0001, &v4), &mut counters)
    else {
        panic!("grouped IPv4 inner must decapsulate");
    };
    assert_eq!(decapsulated.inner_packet(), v4.as_slice());
    let v6 = inner_ipv6(ipv6_inner(), b"grouped v6");
    let GtpuDownlinkEvent::Decapsulated(decapsulated) =
        process(&runtime, scope, gpdu(0x1100_0002, &v6), &mut counters)
    else {
        panic!("grouped IPv6 inner over IPv4 outer must decapsulate");
    };
    assert_eq!(decapsulated.inner_packet(), v6.as_slice());
    assert_eq!(decapsulated.family(), crate::GtpAddressFamily::Ipv6);
    // A TEID indexed for IPv4 never authorizes an IPv6 T-PDU.
    assert!(matches!(
        process(&runtime, scope, gpdu(0x1100_0001, &v6), &mut counters),
        GtpuDownlinkEvent::UnknownTunnel(_)
    ));
    // Wrong destination and non-exact inner length fail closed.
    assert_eq!(
        expect_drop(process(
            &runtime,
            scope,
            gpdu(0x1100_0001, &inner_ipv4([10, 45, 0, 9], b"x")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
    let mut padded = inner_ipv4(UE, b"pad");
    padded.extend_from_slice(&[0; 4]);
    assert_eq!(
        expect_drop(process(
            &runtime,
            scope,
            gpdu(0x1100_0001, &padded),
            &mut counters
        )),
        GtpuDownlinkDrop::Malformed
    );
    assert_eq!(counters.decapsulated, 2);
}

#[tokio::test]
async fn grouped_stale_generation_and_unusable_datapath_fail_closed() {
    let (runtime, _backend, _authority, desired, scope) =
        grouped_fixture(vec![grouped_v4_entry(0x1100_0001, 0x2100_0001)]).await;
    let mut counters = GtpuDownlinkCounters::default();
    // Advance the retained authority generation without its index: the old
    // index reference is now stale and must not authorize.
    {
        let mut state = runtime.state();
        let key = (S2BU_IFINDEX, desired.id().to_bytes());
        let mut authority = state.session_groups[&key];
        authority[11] = authority[11].wrapping_add(1);
        state.session_groups.insert(key, authority);
    }
    assert_eq!(
        expect_drop(process(
            &runtime,
            scope,
            gpdu(0x1100_0001, &inner_ipv4(UE, b"stale")),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
    runtime.state().pin_identity_invalid.insert(S2BU_IFINDEX);
    assert_eq!(
        expect_drop(process(
            &runtime,
            scope,
            gpdu(0x1100_0001, &inner_ipv4(UE, b"fenced")),
            &mut counters,
        )),
        GtpuDownlinkDrop::StateUnavailable
    );
}

fn ordinary_ipv6_context() -> GtpPdpContext {
    GtpPdpContext {
        ms_address: IpAddr::V6("2001:db8:45:1::".parse().unwrap()),
        ..context()
    }
}

/// An ordinary attachment carries an inner-IPv6 context in the family-tagged
/// authority with its own published configuration (#998). A reassembled
/// G-PDU for it must decapsulate exactly as tc does, and nothing outside its
/// /64 or without that authority may.
#[tokio::test]
async fn ordinary_inner_ipv6_context_decapsulates_through_its_family_authority() {
    let (backend, runtime) = ordinary_fixture(context()).await;
    backend
        .install_pdp_context(ordinary_ipv6_context())
        .await
        .unwrap();
    let mut counters = GtpuDownlinkCounters::default();
    let inside = inner_ipv6("2001:db8:45:1::abcd".parse().unwrap(), b"ordinary v6");
    let GtpuDownlinkEvent::Decapsulated(decapsulated) = process(
        &runtime,
        ordinary_scope(),
        gpdu(LOCAL_TEID, &inside),
        &mut counters,
    ) else {
        panic!("an ordinary inner-IPv6 G-PDU must decapsulate");
    };
    assert_eq!(decapsulated.inner_packet(), inside.as_slice());
    assert_eq!(decapsulated.family(), crate::GtpAddressFamily::Ipv6);
    assert_eq!(decapsulated.bearer_mark(), None);
    // The IPv4 context on the same TEID is unaffected.
    assert!(matches!(
        process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"v4")),
            &mut counters
        ),
        GtpuDownlinkEvent::Decapsulated(_)
    ));
    // Outside the /64 fails the family authority.
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(
                LOCAL_TEID,
                &inner_ipv6("2001:db8:45:2::1".parse().unwrap(), b"outside")
            ),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
    // After family-scoped removal the IPv6 T-PDU reaches the IPv4-only v5
    // path, which (like tc) treats it as malformed.
    backend
        .remove_pdp_context(RemovePdpContextRequest {
            local_teid: teid(LOCAL_TEID),
            link_ifindex: S2BU_IFINDEX,
            gtp_version: GtpVersion::V1,
            address_family: GtpAddressFamily::Ipv6,
        })
        .await
        .unwrap();
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &inside),
            &mut counters,
        )),
        GtpuDownlinkDrop::Malformed
    );
    assert_eq!(counters.decapsulated, 2);
}
