//! Backend-authoritative downlink consumer over the fake runtime. These tests
//! pin every tc-parity decision against the backend's own map state; the
//! privileged native test proves kernel reassembly and socket delivery.

use super::*;
use crate::control_port::GtpuControlDatagram;
use crate::ebpf::reassembled_downlink::{
    process_downlink_datagram, DownlinkAuthorityScope, ProcessedDownlink,
};
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

/// An inner IPv4/UDP datagram with Don't Fragment set and a valid header
/// checksum: the consumer validates the header like the kernel's IPv4 input.
fn inner_ipv4(destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(28 + payload.len()).unwrap();
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[8, 8, 8, 8]);
    packet.extend_from_slice(&destination);
    let checksum = opc_gtpu_ebpf_common::internet_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
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
    event(process_downlink_datagram(
        runtime,
        scope,
        datagram_from(message, PEER, 2152),
        counters,
    ))
}

fn event(processed: ProcessedDownlink) -> GtpuDownlinkEvent {
    match processed {
        ProcessedDownlink::Event(event) => event,
        ProcessedDownlink::PacketTooBig(_) => panic!("unexpected over-MTU plan"),
        ProcessedDownlink::FragmentInner(_) => panic!("unexpected inner fragmentation plan"),
    }
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
    let wrong_peer = event(process_downlink_datagram(
        runtime.as_ref(),
        ordinary_scope(),
        datagram_from(
            gpdu(LOCAL_TEID, &inner_ipv4(UE, b"peer")),
            Ipv4Addr::new(192, 0, 2, 11),
            2152,
        ),
        &mut counters,
    ));
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

fn mtu_context(mtu: u16) -> GtpPdpContext {
    let mut context = context();
    context.downlink_inner_mtu =
        Some(crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(mtu).unwrap());
    context
}

fn dont_fragment(mut packet: Vec<u8>) -> Vec<u8> {
    packet[6] |= 0x40;
    checksummed(packet)
}

/// A context with the default inner fragmentation policy at `mtu`.
fn fragment_context(mtu: u16) -> GtpPdpContext {
    let mut context = context();
    context.downlink_inner_mtu = Some(crate::GtpuDownlinkInnerMtu::new(mtu).unwrap());
    context
}

/// Recompute the IPv4 header checksum after a header field was changed. The
/// consumer and the inner fragmenter both validate it (RFC 1812 section
/// 5.2.2).
fn checksummed(mut packet: Vec<u8>) -> Vec<u8> {
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    packet[10..12].fill(0);
    let checksum = opc_gtpu_ebpf_common::internet_checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn fragment_plan(
    processed: ProcessedDownlink,
) -> crate::ebpf::reassembled_downlink::InnerFragmentPlan {
    match processed {
        ProcessedDownlink::FragmentInner(plan) => plan,
        ProcessedDownlink::Event(event) => panic!("expected a fragmentation plan, got {event:?}"),
        ProcessedDownlink::PacketTooBig(_) => panic!("expected a fragmentation plan"),
    }
}

/// A fragmentable (DF clear) inner packet of exactly `total` octets.
fn sized_inner(total: usize) -> Vec<u8> {
    let mut packet = inner_ipv4(UE, &vec![0x5a; total - 28]);
    packet[6] &= !0x40;
    checksummed(packet)
}

fn plan(processed: ProcessedDownlink) -> crate::ebpf::reassembled_downlink::PacketTooBigPlan {
    match processed {
        ProcessedDownlink::PacketTooBig(plan) => plan,
        ProcessedDownlink::Event(event) => panic!("expected an over-MTU plan, got {event:?}"),
        ProcessedDownlink::FragmentInner(_) => panic!("expected an in-tunnel error plan"),
    }
}

#[tokio::test]
async fn downlink_inner_mtu_is_committed_read_back_replaced_and_cleared() {
    let (backend, runtime) = ordinary_fixture(mtu_context(1_300)).await;
    let key = (S2BU_IFINDEX, UE);
    // The explicit in-tunnel Packet Too Big opt-in sets bit 15 of the field.
    assert_eq!(
        &runtime.state().sport[&key][66..],
        &(0x8000 | 1_300_u16).to_be_bytes()
    );
    let selector = crate::PdpContextSelector::LocalTeid(
        crate::PdpContextLocalTeidSelector::from_context(&mtu_context(1_300)).unwrap(),
    );
    assert_eq!(
        backend.read_pdp_context(selector.clone()).await.unwrap(),
        crate::PdpContextReadback::Present(mtu_context(1_300))
    );
    // Idempotent reinstall, then commit-last replacement of the MTU alone.
    backend
        .install_pdp_context(mtu_context(1_300))
        .await
        .unwrap();
    backend
        .install_pdp_context(mtu_context(1_400))
        .await
        .unwrap();
    assert_eq!(
        &runtime.state().sport[&key][66..],
        &(0x8000 | 1_400_u16).to_be_bytes()
    );
    assert_eq!(
        backend.read_pdp_context(selector.clone()).await.unwrap(),
        crate::PdpContextReadback::Present(mtu_context(1_400))
    );
    // Clearing restores the original reserved-zero bytes exactly.
    backend.install_pdp_context(context()).await.unwrap();
    assert_eq!(&runtime.state().sport[&key][66..], &[0, 0]);
    assert_eq!(
        crate::model::pdp_context_mismatches(&mtu_context(1_300), &context()),
        vec![crate::PdpContextMismatchField::DownlinkInnerMtu]
    );
}

#[tokio::test]
async fn downlink_inner_mtu_requires_the_service_port_uplink_policy() {
    let (backend, _runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let mut selected = mtu_context(1_300);
    selected.uplink_source_port_policy =
        crate::GtpuUplinkSourcePortPolicy::selected(40_000).unwrap();
    assert!(matches!(
        backend.install_pdp_context(selected).await,
        Err(GtpuError::UnsupportedFeature {
            feature: "downlink_inner_mtu_with_selected_uplink_source_port"
        })
    ));
    // The default inner fragmentation sends nothing uplink, so it accepts a
    // selected uplink source port.
    let mut selected = fragment_context(1_300);
    selected.uplink_source_port_policy =
        crate::GtpuUplinkSourcePortPolicy::selected(40_000).unwrap();
    backend.install_pdp_context(selected).await.unwrap();
    for constructor in [
        crate::GtpuDownlinkInnerMtu::new,
        crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big,
    ] {
        assert!(constructor(575).is_none());
        assert_eq!(constructor(576).unwrap().get(), 576);
        assert_eq!(constructor(32_767).unwrap().get(), 32_767);
        assert!(constructor(32_768).is_none(), "the MTU field has 15 bits");
        // The grouped entry ABI carries no MTU, so grouped contexts refuse it.
        let mut grouped = grouped_v4_entry(0x1100_0001, 0x2100_0001).context().clone();
        grouped.downlink_inner_mtu = constructor(1_300);
        assert!(GtpuSessionEntry::new(grouped, IpAddr::V4(LOCAL)).is_err());
    }
    assert_eq!(
        crate::GtpuDownlinkInnerMtu::new(1_300).unwrap().policy(),
        crate::GtpuDownlinkOversizePolicy::FragmentInner
    );
    assert_eq!(
        crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(1_300)
            .unwrap()
            .policy(),
        crate::GtpuDownlinkOversizePolicy::InTunnelPacketTooBig
    );
}

#[tokio::test]
async fn only_an_authorized_oversized_dont_fragment_packet_becomes_a_plan() {
    let (_backend, runtime) = ordinary_fixture(mtu_context(1_300)).await;
    let mut counters = GtpuDownlinkCounters::default();
    // Exactly the MTU, and an oversized fragmentable packet, are forwarded.
    for packet in [dont_fragment(sized_inner(1_300)), sized_inner(1_400)] {
        assert!(matches!(
            process(
                &runtime,
                ordinary_scope(),
                gpdu(LOCAL_TEID, &packet),
                &mut counters
            ),
            GtpuDownlinkEvent::Decapsulated(_)
        ));
    }
    let oversized = checksummed(dont_fragment(sized_inner(1_301)));
    let plan = plan(process_downlink_datagram(
        runtime.as_ref(),
        ordinary_scope(),
        datagram_from(gpdu(LOCAL_TEID, &oversized), PEER, 2152),
        &mut counters,
    ));
    assert_eq!(plan.mtu(), 1_300);
    assert_eq!(plan.session(), LOCAL_TEID.to_be_bytes());
    let (_, local, peer) = plan.build_uplink_gpdu().unwrap();
    assert_eq!((local, peer), (LOCAL, PEER));
    assert_eq!(counters.packet_too_big, 1);
    assert_eq!(counters.decapsulated, 2);
    // An unauthorized oversized packet is never a plan.
    assert!(matches!(
        event(process_downlink_datagram(
            runtime.as_ref(),
            ordinary_scope(),
            datagram_from(
                gpdu(LOCAL_TEID, &oversized),
                Ipv4Addr::new(192, 0, 2, 11),
                2152
            ),
            &mut counters,
        )),
        GtpuDownlinkEvent::Dropped(GtpuDownlinkDrop::BindingMismatch(_))
    ));
    // A session without an MTU forwards the same packet.
    let (_backend, runtime) = ordinary_fixture(context()).await;
    assert!(matches!(
        process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &oversized),
            &mut counters
        ),
        GtpuDownlinkEvent::Decapsulated(_)
    ));
}

#[tokio::test]
async fn in_tunnel_error_matches_an_independent_rfc_1191_literal() {
    let (_backend, runtime) = ordinary_fixture(mtu_context(1_300)).await;
    let oversized = checksummed(dont_fragment(sized_inner(1_400)));
    let mut counters = GtpuDownlinkCounters::default();
    let gpdu_bytes = plan(process_downlink_datagram(
        runtime.as_ref(),
        ordinary_scope(),
        datagram_from(gpdu(LOCAL_TEID, &oversized), PEER, 2152),
        &mut counters,
    ))
    .build_uplink_gpdu()
    .unwrap()
    .0;
    // G-PDU header: v1/PT, T-PDU, length 56, the default bearer's peer TEID.
    let mut expected = vec![0x30, 0xff, 0x00, 0x38, 0x20, 0x00, 0x00, 0x01];
    // IPv4: 56 octets, TTL 64, ICMP, from the UE PAA to the originator.
    let mut ip = vec![
        0x45, 0x00, 0x00, 0x38, 0, 0, 0, 0, 64, 1, 0, 0, 10, 45, 0, 2, 8, 8, 8, 8,
    ];
    let checksum = opc_gtpu_ebpf_common::internet_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    // ICMP type 3 code 4, next-hop MTU 1300, then exactly 28 quoted octets.
    let mut icmp = vec![3, 4, 0, 0, 0, 0, 0x05, 0x14];
    icmp.extend_from_slice(&oversized[..28]);
    let checksum = opc_gtpu_ebpf_common::internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    expected.extend_from_slice(&ip);
    expected.extend_from_slice(&icmp);
    assert_eq!(gpdu_bytes, expected);
    assert!(
        !gpdu_bytes.windows(8).any(|window| window == [0x5a; 8]),
        "no application payload beyond the RFC 792 64 bits is quoted"
    );
}

fn oversized_plan(
    runtime: &FakeRuntime,
    teid: u32,
    packet: &[u8],
) -> crate::ebpf::reassembled_downlink::PacketTooBigPlan {
    let mut counters = GtpuDownlinkCounters::default();
    plan(process_downlink_datagram(
        runtime,
        ordinary_scope(),
        datagram_from(gpdu(teid, packet), PEER, 2152),
        &mut counters,
    ))
}

/// Replace the invoking packet's originator (its source) and protocol,
/// keeping its header checksum valid.
fn from_originator(originator: [u8; 4], protocol: u8, icmp_type: u8) -> Vec<u8> {
    let mut packet = dont_fragment(sized_inner(1_400));
    packet[12..16].copy_from_slice(&originator);
    packet[9] = protocol;
    packet[20] = icmp_type;
    checksummed(packet)
}

#[tokio::test]
async fn rfc_1122_never_answer_rules_apply_to_each_class() {
    let (_backend, runtime) = ordinary_fixture(mtu_context(1_300)).await;
    // Originators that do not identify one host.
    for originator in [
        [0, 0, 0, 0],
        [0, 1, 2, 3],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        [239, 255, 255, 255],
        [240, 0, 0, 1],
        [255, 255, 255, 255],
    ] {
        let plan = oversized_plan(&runtime, LOCAL_TEID, &from_originator(originator, 17, 0));
        assert!(
            plan.build_uplink_gpdu().is_none(),
            "originator {originator:?} must not be answered"
        );
    }
    // Every ICMP error type is never answered (RFC 1122 3.2.2 / RFC 792).
    for icmp_type in [3, 4, 5, 11, 12] {
        let plan = oversized_plan(
            &runtime,
            LOCAL_TEID,
            &from_originator([8, 8, 8, 8], 1, icmp_type),
        );
        assert!(plan.build_uplink_gpdu().is_none(), "ICMP type {icmp_type}");
    }
    // Informational ICMP (an oversized DF Echo Request) is answered.
    for icmp_type in [0, 8, 13] {
        let plan = oversized_plan(
            &runtime,
            LOCAL_TEID,
            &from_originator([8, 8, 8, 8], 1, icmp_type),
        );
        assert!(plan.build_uplink_gpdu().is_some(), "ICMP type {icmp_type}");
    }
    // A non-initial fragment is never answered.
    let mut non_initial = dont_fragment(sized_inner(1_400));
    non_initial[7] = 1;
    let non_initial = checksummed(non_initial);
    assert!(oversized_plan(&runtime, LOCAL_TEID, &non_initial)
        .build_uplink_gpdu()
        .is_none());
    // An ordinary unicast originator is answered.
    assert!(
        oversized_plan(&runtime, LOCAL_TEID, &from_originator([8, 8, 8, 8], 17, 0))
            .build_uplink_gpdu()
            .is_some()
    );
}

/// RFC 1812 section 5.2.2 and RFC 1122 section 3.2.1.2: an invoking packet
/// whose header fails validation is silently discarded, never answered.
#[tokio::test]
async fn in_tunnel_error_requires_a_valid_invoking_header() {
    let (_backend, runtime) = ordinary_fixture(mtu_context(1_300)).await;
    let valid = checksummed(dont_fragment(sized_inner(1_400)));
    assert!(oversized_plan(&runtime, LOCAL_TEID, &valid)
        .build_uplink_gpdu()
        .is_some());
    let mut corrupt = valid.clone();
    corrupt[10] ^= 0xff;
    // The header still claims 1,400 octets; only 1,000 arrived.
    let truncated = valid[..1_000].to_vec();
    for (case, packet) in [("header checksum", corrupt), ("truncated", truncated)] {
        assert!(
            oversized_plan(&runtime, LOCAL_TEID, &packet)
                .build_uplink_gpdu()
                .is_none(),
            "{case}: the invoking packet must be discarded, not answered"
        );
    }
}

#[tokio::test]
async fn dedicated_bearer_errors_use_the_default_bearer_uplink() {
    let mut dedicated = marked_context(0x0001_0001, 0x1000_0002, 0x2000_0002);
    dedicated.downlink_inner_mtu = crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(1_300);
    let (backend, runtime) = ordinary_fixture(dedicated).await;
    let packet = checksummed(dont_fragment(sized_inner(1_400)));
    // Only a dedicated bearer: there is no default-bearer uplink to use.
    let plan = oversized_plan(&runtime, 0x1000_0002, &packet);
    assert_eq!(plan.session(), 0x1000_0002_u32.to_be_bytes());
    assert!(plan.build_uplink_gpdu().is_none());
    // With the default bearer installed, the error rides its uplink TEID.
    backend.install_pdp_context(context()).await.unwrap();
    let (gpdu, local, peer) = oversized_plan(&runtime, 0x1000_0002, &packet)
        .build_uplink_gpdu()
        .unwrap();
    assert_eq!((local, peer), (LOCAL, PEER));
    assert_eq!(&gpdu[4..8], &0x2000_0001_u32.to_be_bytes());
    // A transitional default commit is not a usable route.
    {
        let mut state = runtime.state();
        let key = (S2BU_IFINDEX, UE);
        let commit = PdpContextCommit::decode(&state.sport[&key]);
        state.sport.insert(
            key,
            commit.with_phase(MarkedBearerOwnerPhase::Pending).encode(),
        );
    }
    assert!(oversized_plan(&runtime, 0x1000_0002, &packet)
        .build_uplink_gpdu()
        .is_none());
}

#[test]
fn packet_too_big_limiter_is_an_exact_per_session_token_bucket() {
    use crate::reassembly::PacketTooBigLimiter;
    use std::time::Instant;
    assert!(crate::GtpuPacketTooBigRateLimit::new(0, Duration::from_secs(1)).is_none());
    assert!(crate::GtpuPacketTooBigRateLimit::new(1, Duration::ZERO).is_none());
    let limit = crate::GtpuPacketTooBigRateLimit::new(2, Duration::from_millis(100)).unwrap();
    let mut limiter = PacketTooBigLimiter::new(limit);
    let (a, b) = ([0, 0, 0, 1], [0, 0, 0, 2]);
    let start = Instant::now();
    assert!(limiter.admit(a, start));
    assert!(limiter.admit(a, start));
    assert!(!limiter.admit(a, start));
    // Exhausting one session never limits another.
    assert!(limiter.admit(b, start));
    assert!(limiter.admit(b, start));
    assert!(!limiter.admit(b, start));
    assert!(!limiter.admit(a, start + Duration::from_millis(99)));
    assert!(limiter.admit(a, start + Duration::from_millis(100)));
    assert!(!limiter.admit(a, start + Duration::from_millis(150)));
    // A long idle period refills to the burst, never beyond it.
    let later = start + Duration::from_secs(60);
    assert!(limiter.admit(a, later));
    assert!(limiter.admit(a, later));
    assert!(!limiter.admit(a, later));
    // The table is bounded; the least recently used session is evicted.
    let mut limiter = PacketTooBigLimiter::new(limit);
    for index in 0..4_097_u32 {
        let now = start + Duration::from_micros(u64::from(index));
        assert!(limiter.admit(index.to_be_bytes(), now));
    }
    let default = crate::GtpuPacketTooBigRateLimit::default();
    assert_eq!(
        (default.burst(), default.refill_interval()),
        (16, Duration::from_millis(10))
    );
}

#[tokio::test]
async fn backends_without_enforcement_refuse_a_downlink_inner_mtu() {
    let mock = crate::MockGtpuDataplaneBackend::new();
    assert_eq!(
        crate::GtpuDataplaneBackend::probe(&mock)
            .await
            .unwrap()
            .downlink_inner_mtu_enforcement,
        crate::GtpuCapability::Missing
    );
    for context in [mtu_context(1_300), fragment_context(1_300)] {
        assert!(matches!(
            crate::GtpuDataplaneBackend::install_pdp_context(&mock, context).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "downlink_inner_mtu"
            })
        ));
    }
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

/// The family-tagged entry that carries an ordinary inner-IPv6 context has
/// no downlink inner MTU field, so an opted-in IPv6 context must be refused
/// explicitly rather than installed without enforcement.
#[tokio::test]
async fn ordinary_inner_ipv6_context_refuses_the_in_tunnel_packet_too_big_opt_in() {
    let (backend, runtime) = ordinary_fixture(context()).await;
    // IPv6 has no in-network fragmentation (RFC 8200 section 4.5), and the
    // family-tagged entry has no MTU field: both policies are refused.
    for mtu in [
        crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(1_300),
        crate::GtpuDownlinkInnerMtu::new(1_300),
    ] {
        let mut ipv6 = ordinary_ipv6_context();
        ipv6.downlink_inner_mtu = mtu;
        assert!(matches!(
            backend.install_pdp_context(ipv6).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "downlink_inner_mtu_inner_ipv6"
            })
        ));
    }
    assert!(runtime.state().session_downlink_index.is_empty());
}

#[tokio::test]
async fn default_fragmentation_policy_is_committed_read_back_and_replaced() {
    let (backend, runtime) = ordinary_fixture(fragment_context(1_300)).await;
    let key = (S2BU_IFINDEX, UE);
    // The default policy is the bare MTU; the explicit opt-in sets bit 15.
    assert_eq!(&runtime.state().sport[&key][66..], &1_300_u16.to_be_bytes());
    let selector = crate::PdpContextSelector::LocalTeid(
        crate::PdpContextLocalTeidSelector::from_context(&fragment_context(1_300)).unwrap(),
    );
    assert_eq!(
        backend.read_pdp_context(selector.clone()).await.unwrap(),
        crate::PdpContextReadback::Present(fragment_context(1_300))
    );
    assert_eq!(
        crate::model::pdp_context_mismatches(&fragment_context(1_300), &mtu_context(1_300)),
        vec![crate::PdpContextMismatchField::DownlinkInnerMtu],
        "the policy is part of the exact context"
    );
    backend
        .install_pdp_context(mtu_context(1_300))
        .await
        .unwrap();
    assert_eq!(&runtime.state().sport[&key][66..], &[0x85, 0x14]);
    assert_eq!(
        backend.read_pdp_context(selector.clone()).await.unwrap(),
        crate::PdpContextReadback::Present(mtu_context(1_300))
    );
    backend
        .install_pdp_context(fragment_context(1_300))
        .await
        .unwrap();
    assert_eq!(&runtime.state().sport[&key][66..], &1_300_u16.to_be_bytes());
    backend.install_pdp_context(context()).await.unwrap();
    assert_eq!(&runtime.state().sport[&key][66..], &[0, 0]);
}

#[tokio::test]
async fn default_policy_hands_only_an_authorized_oversized_df_packet_to_the_fragmenter() {
    let (_backend, runtime) = ordinary_fixture(fragment_context(1_300)).await;
    let mut counters = GtpuDownlinkCounters::default();
    // Exactly the MTU, and an oversized fragmentable packet, are forwarded.
    for packet in [dont_fragment(sized_inner(1_300)), sized_inner(1_400)] {
        assert!(matches!(
            process(
                &runtime,
                ordinary_scope(),
                gpdu(LOCAL_TEID, &packet),
                &mut counters
            ),
            GtpuDownlinkEvent::Decapsulated(_)
        ));
    }
    let oversized = dont_fragment(sized_inner(1_301));
    let plan = fragment_plan(process_downlink_datagram(
        runtime.as_ref(),
        ordinary_scope(),
        datagram_from(gpdu(LOCAL_TEID, &oversized), PEER, 2152),
        &mut counters,
    ));
    assert_eq!(plan.mtu(), 1_300);
    assert_eq!(plan.destination(), UE);
    assert_eq!(plan.bearer_mark(), None);
    assert_eq!(plan.inner_packet(), oversized.as_slice());
    assert_eq!(counters.packet_too_big, 0, "no in-tunnel error is planned");
    assert_eq!(counters.decapsulated, 2);
    // An unauthorized oversized packet is never a plan.
    assert!(matches!(
        event(process_downlink_datagram(
            runtime.as_ref(),
            ordinary_scope(),
            datagram_from(
                gpdu(LOCAL_TEID, &oversized),
                Ipv4Addr::new(192, 0, 2, 11),
                2152
            ),
            &mut counters,
        )),
        GtpuDownlinkEvent::Dropped(GtpuDownlinkDrop::BindingMismatch(_))
    ));
    // A dedicated bearer's plan carries its exact output mark.
    let mut dedicated = marked_context(0x0001_0001, 0x1000_0002, 0x2000_0002);
    dedicated.downlink_inner_mtu = crate::GtpuDownlinkInnerMtu::new(1_300);
    let (_backend, runtime) = ordinary_fixture(dedicated).await;
    let plan = fragment_plan(process_downlink_datagram(
        runtime.as_ref(),
        ordinary_scope(),
        datagram_from(gpdu(0x1000_0002, &oversized), PEER, 2152),
        &mut counters,
    ));
    assert_eq!(plan.bearer_mark(), GtpBearerMark::new(0x0001_0001));
    assert_eq!(plan.destination(), UE);
}

/// Split one over-MTU packet through the control port's fragmentation step.
async fn fragment_through_port(
    teid: u32,
    packets: &[Vec<u8>],
    state: &mut crate::ebpf::control_port::ControlSocketState,
) -> Vec<GtpuDownlinkEvent> {
    let mut dedicated = marked_context(0x0001_0001, 0x1000_0002, 0x2000_0002);
    dedicated.downlink_inner_mtu = crate::GtpuDownlinkInnerMtu::new(1_300);
    let (backend, runtime) = ordinary_fixture(fragment_context(1_300)).await;
    backend.install_pdp_context(dedicated).await.unwrap();
    let mut counters = GtpuDownlinkCounters::default();
    packets
        .iter()
        .map(|packet| {
            let plan = fragment_plan(process_downlink_datagram(
                runtime.as_ref(),
                ordinary_scope(),
                datagram_from(gpdu(teid, packet), PEER, 2152),
                &mut counters,
            ));
            crate::ebpf::control_port::fragment_inner(state, &plan)
        })
        .collect()
}

fn fragments(event: GtpuDownlinkEvent) -> crate::GtpuFragmentedDownlink {
    match event {
        GtpuDownlinkEvent::Fragmented(fragmented) => fragmented,
        other => panic!("expected fragments, got {other:?}"),
    }
}

#[tokio::test]
async fn default_policy_returns_exact_rfc_791_fragments_with_the_bearer_mark() {
    let mut state = crate::ebpf::control_port::ControlSocketState::default();
    // Atomic datagrams (DF, not a fragment) with Identification zero, then a
    // DF fragment that owns Identification 0x4242, then another atomic one.
    let atomic = checksummed(dont_fragment(sized_inner(1_450)));
    let mut non_atomic = dont_fragment(sized_inner(1_450));
    non_atomic[4..6].copy_from_slice(&0x4242_u16.to_be_bytes());
    non_atomic[6] |= 0x20;
    let non_atomic = checksummed(non_atomic);
    let events = fragment_through_port(
        0x1000_0002,
        &[atomic.clone(), non_atomic.clone(), atomic.clone()],
        &mut state,
    )
    .await;
    let mut events = events.into_iter();
    let first = fragments(events.next().unwrap());
    assert_eq!(first.bearer_mark(), GtpBearerMark::new(0x0001_0001));
    assert_eq!(first.mtu(), 1_300);
    assert_eq!(first.family(), crate::GtpAddressFamily::Ipv4);
    assert_eq!(
        format!("{first:?}"),
        "GtpuFragmentedDownlink { fragments: 2, mtu: 1300, bearer_mark: \"<redacted>\" }",
        "Debug exposes no packet bytes, addresses or mark"
    );
    let pieces = first.fragments();
    assert_eq!(pieces.len(), 2);
    let identification = u16::from_be_bytes([pieces[0][4], pieces[0][5]]);
    assert_ne!(
        identification, 0,
        "an atomic datagram gets a fresh non-zero ID"
    );
    // Independent literal: 1,300 then 170 octets, MF then offset 160, DF clear.
    for (piece, total, flags) in [(&pieces[0], 1_300_u16, 0x2000_u16), (&pieces[1], 170, 160)] {
        let mut expected = atomic[..20].to_vec();
        expected[2..4].copy_from_slice(&total.to_be_bytes());
        expected[4..6].copy_from_slice(&identification.to_be_bytes());
        expected[6..8].copy_from_slice(&flags.to_be_bytes());
        let expected = checksummed(expected);
        assert_eq!(&piece[..20], expected.as_slice());
        assert_eq!(piece.len(), usize::from(total));
    }
    let mut data = pieces[0][20..].to_vec();
    data.extend_from_slice(&pieces[1][20..]);
    assert_eq!(data, &atomic[20..]);

    // A DF fragment keeps its own Identification and MF on its last piece,
    // and does not advance the destination's sequence.
    let second = fragments(events.next().unwrap());
    for piece in second.fragments() {
        assert_eq!(&piece[4..6], &0x4242_u16.to_be_bytes());
        assert_eq!(piece[6] & 0x60, 0x20, "DF clear, MF kept");
    }
    let third = fragments(events.next().unwrap());
    let next = identification.checked_add(1).unwrap_or(1);
    assert_eq!(&third.fragments()[0][4..6], &next.to_be_bytes());
    let counters = state.downlink_counters();
    assert_eq!(counters.inner_fragmented, 3);
    assert_eq!(counters.inner_fragments, 6);
    assert_eq!(counters.packet_too_big, 0);
}

#[tokio::test]
async fn default_policy_refuses_options_and_malformed_headers_before_taking_a_token() {
    let limit = crate::GtpuInnerFragmentRateLimit::new(1, Duration::from_secs(3_600)).unwrap();
    let mut state = crate::ebpf::control_port::ControlSocketState::with_inner_fragment_limit(limit);
    let valid = checksummed(dont_fragment(sized_inner(1_450)));
    let mut options = valid[..20].to_vec();
    options[0] = 0x46;
    options.extend_from_slice(&[1, 1, 1, 0]);
    options.extend_from_slice(&valid[20..]);
    let total = u16::try_from(options.len()).unwrap();
    options[2..4].copy_from_slice(&total.to_be_bytes());
    let options = checksummed(options);
    let mut corrupt = valid.clone();
    corrupt[10] ^= 0xff;
    let events = fragment_through_port(
        LOCAL_TEID,
        &[options, corrupt, valid.clone(), valid],
        &mut state,
    )
    .await;
    let reasons: Vec<_> = events
        .into_iter()
        .map(|event| match event {
            GtpuDownlinkEvent::Dropped(reason) => Some(reason),
            GtpuDownlinkEvent::Fragmented(_) => None,
            other => panic!("unexpected event {other:?}"),
        })
        .collect();
    assert_eq!(
        reasons,
        [
            Some(GtpuDownlinkDrop::InnerUnfragmentable),
            Some(GtpuDownlinkDrop::Malformed),
            None,
            Some(GtpuDownlinkDrop::InnerFragmentRateLimited),
        ]
    );
    let counters = state.downlink_counters();
    assert_eq!(counters.inner_unfragmentable, 1);
    assert_eq!(counters.malformed, 1);
    assert_eq!(counters.inner_fragmented, 1);
    assert_eq!(counters.inner_fragment_rate_limited, 1);
}

#[test]
fn inner_fragment_budget_is_per_destination_with_non_repeating_identifications() {
    use crate::reassembly::InnerFragmentBudget;
    use crate::GtpuInnerFragmentRateLimit as Limit;
    use std::time::Instant;
    assert!(Limit::new(0, Duration::from_secs(1)).is_none());
    assert!(Limit::new(1, Duration::ZERO).is_none());
    let default = Limit::default();
    assert_eq!(
        (default.burst(), default.refill_interval()),
        (64, Duration::from_millis(4))
    );
    assert_eq!(Limit::new(64, Duration::from_millis(4)), Some(default));
    // RFC 6864: no more than 65,535 admissions in the 255-second lifetime,
    // counting the one refill a 255-second window can hold.
    assert!(Limit::new(65_534, Duration::from_secs(3_600)).is_some());
    assert!(Limit::new(65_535, Duration::from_secs(3_600)).is_none());
    assert!(Limit::new(65_535, Duration::from_secs(255)).is_none());
    assert!(Limit::new(1, Duration::from_nanos(3_891_000)).is_none());
    assert!(Limit::new(1, Duration::from_nanos(3_892_000)).is_some());

    let limit = Limit::new(2, Duration::from_millis(100)).unwrap();
    let mut budget = InnerFragmentBudget::new(limit);
    let (a, b) = ([10, 45, 0, 2], [10, 45, 0, 3]);
    let start = Instant::now();
    let first = budget.admit(a, start, true).unwrap().unwrap();
    assert_ne!(first, 0);
    assert_eq!(
        budget.admit(a, start, false),
        Some(None),
        "a non-atomic datagram keeps its own Identification but takes a token"
    );
    assert_eq!(budget.admit(a, start, true), None);
    assert!(
        budget.admit(b, start, true).unwrap().is_some(),
        "per destination"
    );
    let refilled = start + Duration::from_millis(100);
    let second = budget.admit(a, refilled, true).unwrap().unwrap();
    assert_eq!(second, first.checked_add(1).unwrap_or(1));
    // A replacement keeps the sequence and never grants an extra burst.
    budget.set_limit(Limit::new(64, Duration::from_secs(3_600)).unwrap());
    assert_eq!(budget.admit(a, refilled, true), None);

    // One destination's sequence assigns every non-zero Identification
    // exactly once before its budget is exhausted: the largest burst, then
    // the one refill an hour later.
    let mut budget =
        InnerFragmentBudget::new(Limit::new(65_534, Duration::from_secs(3_600)).unwrap());
    let mut seen = vec![false; 65_536];
    let hour_later = start + Duration::from_secs(3_600);
    for index in 0..65_535 {
        let now = if index < 65_534 { start } else { hour_later };
        let identification = budget.admit(a, now, true).unwrap().unwrap();
        assert_ne!(identification, 0);
        assert!(!seen[usize::from(identification)]);
        seen[usize::from(identification)] = true;
    }
    assert_eq!(budget.admit(a, hour_later, true), None);
    assert!(format!("{budget:?}").contains("tracked: 1"));

    // The table is bounded; the least recently used destination is evicted.
    let mut budget = InnerFragmentBudget::new(limit);
    for index in 0..4_097_u32 {
        let now = start + Duration::from_micros(u64::from(index));
        assert!(budget.admit(index.to_be_bytes(), now, true).is_some());
    }
    assert!(format!("{budget:?}").contains("tracked: 4096"));
}

/// One inner IPv4 fragment of exactly `total` octets with the given flags
/// and fragment offset word, Identification 0x2600 and a valid header
/// checksum.
fn inner_fragment(total: usize, flags_fragment: u16) -> Vec<u8> {
    let mut packet = sized_inner(total);
    packet[4..6].copy_from_slice(&0x2600_u16.to_be_bytes());
    packet[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
    checksummed(packet)
}

/// #1023: tc hands every inner fragment of a context with a downlink inner
/// MTU to the consumer. Each is authorized on its own and returned exactly as
/// it arrived, with its own tunnel's bearer mark, under either oversize
/// policy. None becomes a fragmentation or Packet Too Big plan, so none takes
/// a token from either rate limit.
#[tokio::test]
async fn every_authorized_inner_fragment_is_decapsulated_with_its_bearer_mark() {
    for constructor in [
        crate::GtpuDownlinkInnerMtu::new,
        crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big,
    ] {
        let mut default_bearer = context();
        default_bearer.downlink_inner_mtu = constructor(1_300);
        let mut dedicated = marked_context(0x0001_0001, 0x1000_0002, 0x2000_0002);
        dedicated.downlink_inner_mtu = constructor(1_300);
        let (backend, runtime) = ordinary_fixture(default_bearer).await;
        backend.install_pdp_context(dedicated).await.unwrap();
        let mut counters = GtpuDownlinkCounters::default();
        let mut returned = 0;
        for (teid, mark) in [
            (LOCAL_TEID, None),
            (0x1000_0002, GtpBearerMark::new(0x0001_0001)),
        ] {
            // A first (More Fragments), a middle (More Fragments and an
            // offset) and a last (offset only) fragment, without and with
            // Don't Fragment, from the smallest up to exactly the MTU.
            for flags_fragment in [0x2000, 0x20a0, 0x00a0, 0x6000, 0x60a0, 0x40a0] {
                for total in [28, 1_300] {
                    let fragment = inner_fragment(total, flags_fragment);
                    let GtpuDownlinkEvent::Decapsulated(decapsulated) = process(
                        &runtime,
                        ordinary_scope(),
                        gpdu(teid, &fragment),
                        &mut counters,
                    ) else {
                        panic!("fragment {flags_fragment:#06x} of {total} octets must decapsulate");
                    };
                    assert_eq!(decapsulated.inner_packet(), fragment.as_slice());
                    assert_eq!(decapsulated.bearer_mark(), mark);
                    assert_eq!(decapsulated.family(), crate::GtpAddressFamily::Ipv4);
                    returned += 1;
                }
            }
        }
        assert_eq!(returned, 24);
        assert_eq!(
            counters,
            GtpuDownlinkCounters {
                decapsulated: returned,
                decapsulated_inner_fragments: returned,
                ..GtpuDownlinkCounters::default()
            }
        );
        // Don't Fragment and the reserved flag alone do not make a fragment.
        for flags_fragment in [0x0000, 0x4000, 0x8000] {
            assert!(matches!(
                process(
                    &runtime,
                    ordinary_scope(),
                    gpdu(LOCAL_TEID, &inner_fragment(1_300, flags_fragment)),
                    &mut counters,
                ),
                GtpuDownlinkEvent::Decapsulated(_)
            ));
        }
        assert_eq!(counters.decapsulated, returned + 3);
        assert_eq!(counters.decapsulated_inner_fragments, returned);
    }
}

/// A fragment that exceeds the downlink inner MTU follows the oversize policy
/// only when it has Don't Fragment set, exactly like any other packet.
/// Without it, the fragment is returned as it arrived: fragmenting a packet
/// without Don't Fragment to the MTU is part (ii) of #1023.
#[tokio::test]
async fn an_over_mtu_fragment_follows_the_oversize_policy_only_with_dont_fragment() {
    let without_dont_fragment = [0x2000_u16, 0x20a0, 0x00a0];
    for context in [fragment_context(1_300), mtu_context(1_300)] {
        let (_backend, runtime) = ordinary_fixture(context).await;
        let mut counters = GtpuDownlinkCounters::default();
        for flags_fragment in without_dont_fragment {
            let fragment = inner_fragment(1_500, flags_fragment);
            let GtpuDownlinkEvent::Decapsulated(decapsulated) = process(
                &runtime,
                ordinary_scope(),
                gpdu(LOCAL_TEID, &fragment),
                &mut counters,
            ) else {
                panic!("an over-MTU fragment without Don't Fragment is returned as it arrived");
            };
            assert_eq!(decapsulated.inner_packet(), fragment.as_slice());
        }
        assert_eq!(
            counters,
            GtpuDownlinkCounters {
                decapsulated: 3,
                decapsulated_inner_fragments: 3,
                ..GtpuDownlinkCounters::default()
            }
        );
    }

    // Default policy: a Don't Fragment fragment over the MTU is fragmented
    // within its own range. It keeps its Identification, and More Fragments
    // stays on its last piece unless it was the datagram's last fragment.
    let (_backend, runtime) = ordinary_fixture(fragment_context(1_300)).await;
    let mut state = crate::ebpf::control_port::ControlSocketState::default();
    let mut counters = GtpuDownlinkCounters::default();
    for (flags_fragment, pieces) in [
        (0x6000_u16, [0x2000_u16, 0x2000 | 160]),
        (0x60a0, [0x2000 | 160, 0x2000 | 320]),
        (0x40a0, [0x2000 | 160, 320]),
    ] {
        let fragment = inner_fragment(1_500, flags_fragment);
        let plan = fragment_plan(process_downlink_datagram(
            runtime.as_ref(),
            ordinary_scope(),
            datagram_from(gpdu(LOCAL_TEID, &fragment), PEER, 2152),
            &mut counters,
        ));
        let fragmented = fragments(crate::ebpf::control_port::fragment_inner(&mut state, &plan));
        let flags: Vec<u16> = fragmented
            .fragments()
            .iter()
            .map(|piece| {
                assert_eq!(
                    &piece[4..6],
                    &0x2600_u16.to_be_bytes(),
                    "own Identification"
                );
                u16::from_be_bytes([piece[6], piece[7]])
            })
            .collect();
        assert_eq!(flags, pieces, "fragment {flags_fragment:#06x}");
        let mut data = fragmented.fragments()[0][20..].to_vec();
        data.extend_from_slice(&fragmented.fragments()[1][20..]);
        assert_eq!(data, &fragment[20..]);
    }
    assert_eq!(counters.decapsulated, 0);
    assert_eq!(state.downlink_counters().inner_fragmented, 3);

    // Opt-in policy: a Don't Fragment fragment over the MTU is a Packet Too
    // Big plan. Only a first fragment is answered (RFC 1122 section 3.2.2).
    let (_backend, runtime) = ordinary_fixture(mtu_context(1_300)).await;
    for (flags_fragment, answered) in [(0x6000_u16, true), (0x60a0, false), (0x40a0, false)] {
        let plan = oversized_plan(&runtime, LOCAL_TEID, &inner_fragment(1_500, flags_fragment));
        assert_eq!(
            plan.build_uplink_gpdu().is_some(),
            answered,
            "fragment {flags_fragment:#06x}"
        );
    }
}

/// A non-first fragment carries no transport header, and its authorization
/// needs none: a downlink G-PDU is authorized by its tunnel, its outer
/// endpoints, the complete Active graph and its inner destination. A last
/// fragment is therefore refused for exactly the reasons any G-PDU is, and
/// the consumer keeps no per-datagram state to authorize it by its first
/// fragment.
#[tokio::test]
async fn a_non_first_fragment_needs_the_complete_authorization_of_its_own_g_pdu() {
    let (_backend, runtime) = ordinary_fixture(fragment_context(1_300)).await;
    let last = inner_fragment(600, 0x00a0);
    let mut counters = GtpuDownlinkCounters::default();
    // Never preceded by a first fragment: authorized on its own.
    let GtpuDownlinkEvent::Decapsulated(decapsulated) = process(
        &runtime,
        ordinary_scope(),
        gpdu(LOCAL_TEID, &last),
        &mut counters,
    ) else {
        panic!("an authorized last fragment must decapsulate");
    };
    assert_eq!(decapsulated.inner_packet(), last.as_slice());

    // Another peer's G-PDU for this tunnel.
    assert!(matches!(
        event(process_downlink_datagram(
            runtime.as_ref(),
            ordinary_scope(),
            datagram_from(gpdu(LOCAL_TEID, &last), Ipv4Addr::new(192, 0, 2, 11), 2152),
            &mut counters,
        )),
        GtpuDownlinkEvent::Dropped(GtpuDownlinkDrop::BindingMismatch(_))
    ));
    // Another subscriber's address inside this tunnel.
    let mut foreign = last.clone();
    foreign[16..20].copy_from_slice(&[10, 45, 0, 3]);
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &checksummed(foreign)),
            &mut counters,
        )),
        GtpuDownlinkDrop::DestinationMismatch
    );
    // A tunnel that is not installed.
    assert!(matches!(
        process(
            &runtime,
            ordinary_scope(),
            gpdu(0x1000_0fff, &last),
            &mut counters,
        ),
        GtpuDownlinkEvent::UnknownTunnel(_)
    ));
    // A commit that is not Active: the publication fence.
    let key = (S2BU_IFINDEX, UE);
    let active = runtime.state().sport[&key];
    let pending = PdpContextCommit::decode(&active)
        .with_phase(MarkedBearerOwnerPhase::Pending)
        .encode();
    runtime.state().sport.insert(key, pending);
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &last),
            &mut counters,
        )),
        GtpuDownlinkDrop::BindingMismatch(DownlinkBindingMismatch::Invalid)
    );
    runtime.state().sport.insert(key, active);
    // A closed traffic gate.
    runtime
        .state()
        .traffic_observation_gate
        .insert(S2BU_IFINDEX, 2);
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &last),
            &mut counters,
        )),
        GtpuDownlinkDrop::StateUnavailable
    );
    assert_eq!(
        counters,
        GtpuDownlinkCounters {
            decapsulated: 1,
            decapsulated_inner_fragments: 1,
            binding_drops: 2,
            destination_mismatches: 1,
            unknown_tunnel: 1,
            state_unavailable: 1,
            ..GtpuDownlinkCounters::default()
        }
    );
}

/// Every way the kernel's IPv4 input (`ip_rcv_core`) refuses an inner header,
/// applied to a valid 28-octet packet with the given flags: a name and the
/// refused packet.
fn refused_inner_headers(flags_fragment: u16) -> Vec<(&'static str, Vec<u8>)> {
    let valid = inner_fragment(28, flags_fragment);
    let with = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut packet = valid.clone();
        change(&mut packet);
        packet
    };
    // A total length that the header checksum covers, so only the length is
    // wrong.
    let with_total_length = |total: u16| {
        checksummed(with(&|packet| {
            packet[2..4].copy_from_slice(&total.to_be_bytes());
        }))
    };
    vec![
        ("header checksum", with(&|packet| packet[10] ^= 0x01)),
        (
            "header checksum low octet",
            with(&|packet| packet[11] ^= 0x80),
        ),
        ("IHL below 5", with(&|packet| packet[0] = 0x44)),
        ("IHL beyond the datagram", with(&|packet| packet[0] = 0x4f)),
        ("total length below the header", with_total_length(19)),
        (
            "total length above the received length",
            with_total_length(29),
        ),
    ]
}

/// On main, tc decapsulated an inner fragment whose G-PDU was not fragmented
/// on the outer path, and the kernel's IPv4 input then validated its header:
/// version 4, a header length of at least five words within the packet, the
/// header checksum, and a total length that covers the header and is not
/// truncated (`ip_rcv_core`). The consumer returns such a fragment for an
/// `IP_HDRINCL` injection, which rewrites the checksum and the total length,
/// so it must refuse what the kernel refused. The first case is the smallest
/// one: an MTU of 576 and a 28-octet first fragment with one flipped
/// checksum octet.
#[tokio::test]
async fn a_handed_off_packet_with_an_invalid_inner_header_is_never_decapsulated() {
    // (context, flags and fragment offset): a first fragment and a last
    // fragment that tc hands off, and a packet that is not a fragment, which
    // reaches the consumer after outer reassembly with or without an MTU.
    for (context, flags_fragment) in [
        (fragment_context(576), 0x2000_u16),
        (fragment_context(576), 0x0003),
        (mtu_context(576), 0x2000),
        (fragment_context(576), 0x0000),
        (context(), 0x0000),
        (context(), 0x2000),
    ] {
        let (_backend, runtime) = ordinary_fixture(context).await;
        let mut counters = GtpuDownlinkCounters::default();
        let valid = inner_fragment(28, flags_fragment);
        assert!(matches!(
            process(
                &runtime,
                ordinary_scope(),
                gpdu(LOCAL_TEID, &valid),
                &mut counters
            ),
            GtpuDownlinkEvent::Decapsulated(_)
        ));
        let refused = refused_inner_headers(flags_fragment);
        for (case, packet) in &refused {
            assert_eq!(
                expect_drop(process(
                    &runtime,
                    ordinary_scope(),
                    gpdu(LOCAL_TEID, packet),
                    &mut counters,
                )),
                GtpuDownlinkDrop::Malformed,
                "{case}, flags {flags_fragment:#06x}"
            );
        }
        assert_eq!(
            counters,
            GtpuDownlinkCounters {
                decapsulated: 1,
                decapsulated_inner_fragments: u64::from(flags_fragment != 0),
                malformed: u64::try_from(refused.len()).unwrap(),
                ..GtpuDownlinkCounters::default()
            },
            "flags {flags_fragment:#06x}"
        );
    }
}

/// Octets after the IPv4 total length are not part of the datagram. The
/// kernel's IPv4 input trims them; an `IP_HDRINCL` injection would instead
/// extend the total length over them. The consumer returns the datagram
/// alone.
#[tokio::test]
async fn octets_after_the_inner_total_length_are_trimmed() {
    let (_backend, runtime) = ordinary_fixture(fragment_context(576)).await;
    let mut counters = GtpuDownlinkCounters::default();
    for flags_fragment in [0x2000_u16, 0x0003, 0x0000] {
        for trailing in [1_usize, 7, 18] {
            let datagram = inner_fragment(60, flags_fragment);
            let mut carried = datagram.clone();
            carried.extend(std::iter::repeat_n(0xee, trailing));
            let GtpuDownlinkEvent::Decapsulated(decapsulated) = process(
                &runtime,
                ordinary_scope(),
                gpdu(LOCAL_TEID, &carried),
                &mut counters,
            ) else {
                panic!("a valid datagram followed by {trailing} octets must decapsulate");
            };
            assert_eq!(
                decapsulated.inner_packet(),
                datagram.as_slice(),
                "flags {flags_fragment:#06x}, {trailing} trailing octets"
            );
        }
    }
    assert_eq!(counters.decapsulated, 9);
    assert_eq!(counters.malformed, 0);
}

/// A header with IPv4 options is valid when its checksum covers the options.
/// The consumer returns it unchanged: it validates the header as the kernel's
/// input does, and does not process options.
#[tokio::test]
async fn an_inner_header_with_options_is_validated_over_its_whole_length() {
    let (_backend, runtime) = ordinary_fixture(fragment_context(576)).await;
    let mut counters = GtpuDownlinkCounters::default();
    let plain = inner_fragment(60, 0x2000);
    // IHL 6: one NOP, one NOP, one NOP and End of Options List.
    let mut options = plain[..20].to_vec();
    options[0] = 0x46;
    options.extend_from_slice(&[1, 1, 1, 0]);
    options.extend_from_slice(&plain[20..]);
    let total = u16::try_from(options.len()).unwrap();
    options[2..4].copy_from_slice(&total.to_be_bytes());
    let options = checksummed(options);
    let GtpuDownlinkEvent::Decapsulated(decapsulated) = process(
        &runtime,
        ordinary_scope(),
        gpdu(LOCAL_TEID, &options),
        &mut counters,
    ) else {
        panic!("a valid header with options must decapsulate");
    };
    assert_eq!(decapsulated.inner_packet(), options.as_slice());
    // The checksum covers the options: one flipped option octet is refused.
    let mut corrupt = options.clone();
    corrupt[21] ^= 0x01;
    assert_eq!(
        expect_drop(process(
            &runtime,
            ordinary_scope(),
            gpdu(LOCAL_TEID, &corrupt),
            &mut counters,
        )),
        GtpuDownlinkDrop::Malformed
    );
}

/// The grouped path returns an inner IPv4 packet for the same injection, so
/// its header checksum is validated too. Its exact-length rule is unchanged.
#[tokio::test]
async fn grouped_inner_ipv4_header_checksum_is_validated() {
    let (runtime, _backend, _authority, _desired, scope) =
        grouped_fixture(vec![grouped_v4_entry(0x1100_0001, 0x2100_0001)]).await;
    let mut counters = GtpuDownlinkCounters::default();
    let valid = inner_ipv4(UE, b"grouped");
    assert!(matches!(
        process(&runtime, scope, gpdu(0x1100_0001, &valid), &mut counters),
        GtpuDownlinkEvent::Decapsulated(_)
    ));
    let mut corrupt = valid.clone();
    corrupt[10] ^= 0x01;
    assert_eq!(
        expect_drop(process(
            &runtime,
            scope,
            gpdu(0x1100_0001, &corrupt),
            &mut counters
        )),
        GtpuDownlinkDrop::Malformed
    );
    assert_eq!(counters.decapsulated, 1);
    assert_eq!(counters.malformed, 1);
}
