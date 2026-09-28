//! Backend-authoritative post-reassembly downlink consumer on a real kernel.
//!
//! The committed tc object hands outer IPv4 fragments to the stack. The kernel
//! reassembles them and delivers one UDP/2152 datagram to the backend-owned
//! queue, where `try_receive_downlink` must authorize it with the backend's
//! own maps and return the exact inner packet and bearer mark once.

use super::*;
use opc_gtpu_dataplane::control_port::{GtpuControlPort, GtpuControlPortError};
use opc_gtpu_dataplane::{GtpAddressFamily, GtpuDownlinkDrop, GtpuDownlinkEvent};

const FOREIGN_TEID: u32 = 0x1000_0fff;
const INVITE_LEN: usize = 1_300;

fn sip_invite_payload(tag: &[u8; 8]) -> Vec<u8> {
    let mut payload = b"INVITE sip:ue@ims.example SIP/2.0\r\n".to_vec();
    payload.extend_from_slice(tag);
    payload.resize(INVITE_LEN, b's');
    payload
}

fn receive_event(port: &dyn GtpuControlPort) -> GtpuDownlinkEvent {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match port.try_receive_downlink(4096) {
            Ok(Some(event)) => return event,
            Ok(None) | Err(GtpuControlPortError::Busy) => {}
            Err(error) => panic!("downlink consumer receive failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "reassembled G-PDU must reach the backend consumer"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn expect_no_event(port: &dyn GtpuControlPort, window: Duration) {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        if let Some(event) = port.try_receive_downlink(4096).expect("quiet receive") {
            panic!("unexpected downlink event {event:?}");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn expect_decapsulated(
    port: &dyn GtpuControlPort,
    expected_inner: &[u8],
    expected_mark: Option<GtpBearerMark>,
) {
    match receive_event(port) {
        GtpuDownlinkEvent::Decapsulated(decapsulated) => {
            assert_eq!(
                decapsulated.inner_packet(),
                expected_inner,
                "decapsulated inner packet must equal the fragmented original"
            );
            assert_eq!(decapsulated.bearer_mark(), expected_mark);
            assert_eq!(decapsulated.family(), GtpAddressFamily::Ipv4);
            let debug = format!("{decapsulated:?}");
            assert!(!debug.contains("INVITE") && !debug.contains("10.45"));
        }
        other => panic!("authorized fragmented G-PDU must decapsulate, got {other:?}"),
    }
}

fn expect_drop(port: &dyn GtpuControlPort, expected: GtpuDownlinkDrop) {
    match receive_event(port) {
        GtpuDownlinkEvent::Dropped(reason) => assert_eq!(reason, expected),
        other => panic!("expected fail-closed drop {expected:?}, got {other:?}"),
    }
}

struct FragmentSender<'a> {
    net: &'a TestNet,
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
}

impl FragmentSender<'_> {
    fn frame(&self, teid: u32, inner: &[u8], peer: Ipv4Addr) -> Vec<u8> {
        let gpdu = build_gpdu(teid, None, inner);
        let mut frame =
            build_outer_gtpu_frame(self.destination_mac, self.source_mac, &[], &gpdu, true, 0);
        if peer != PGW_IP {
            let ip = ETH_HDR_LEN;
            frame[ip + 12..ip + 16].copy_from_slice(&peer.octets());
            refresh_outer_ipv4_checksum(&mut frame);
            refresh_outer_udp_checksum(&mut frame);
        }
        frame
    }

    fn send(&self, frames: &[&[u8]]) {
        for frame in frames {
            send_raw_gtpu_frame(
                &self.net.pgw_ns,
                "s2bup",
                frame,
                RawChecksumMetadata::Unverified,
            );
        }
    }

    /// Send one complete two-fragment set; returns the exact G-PDU payload.
    fn send_set(&self, teid: u32, inner: &[u8], id: u16, order: SetOrder) -> Vec<u8> {
        self.send_set_from(teid, inner, id, order, PGW_IP)
    }

    fn send_set_from(
        &self,
        teid: u32,
        inner: &[u8],
        id: u16,
        order: SetOrder,
        peer: Ipv4Addr,
    ) -> Vec<u8> {
        let frame = self.frame(teid, inner, peer);
        let (first, second) = build_outer_fragments(&frame, 1_000, id);
        match order {
            SetOrder::InOrder => self.send(&[&first, &second]),
            SetOrder::Reordered => self.send(&[&second, &first]),
            SetOrder::DuplicatedFirst => self.send(&[&first, &first, &second]),
            SetOrder::DuplicatedLast => self.send(&[&first, &second, &second]),
        }
        build_gpdu(teid, None, inner)
    }
}

fn marked_owner_map(
    pin_dir: &std::path::Path,
) -> BpfHashMap<MapData, [u8; UPLINK_MARK_KEY_LEN], [u8; MARKED_BEARER_OWNER_VALUE_LEN]> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_MARKED_BEARER_OWNER)).expect("open owner journal"),
    )
    .expect("identify owner journal");
    BpfHashMap::try_from(map).expect("typed owner journal")
}

fn marked_selector(mark: u32) -> [u8; UPLINK_MARK_KEY_LEN] {
    UplinkFarKey {
        ue_ip: UE_PAA.octets(),
        bearer_mark: mark.to_be_bytes(),
    }
    .encode()
}

/// Change only the owner journal's phase, leaving the Active commit intact.
fn replace_marked_owner_phase_only(
    pin_dir: &std::path::Path,
    mark: u32,
    phase: MarkedBearerOwnerPhase,
) -> [u8; MARKED_BEARER_OWNER_VALUE_LEN] {
    let mut owners = marked_owner_map(pin_dir);
    let selector = marked_selector(mark);
    let exact = owners.get(&selector, 0).expect("read owner journal");
    let mut changed = MarkedBearerOwner::decode(&exact);
    changed.phase = phase;
    owners
        .insert(selector, changed.encode(), 0)
        .expect("replace owner phase only");
    exact
}

fn restore_marked_owner(
    pin_dir: &std::path::Path,
    mark: u32,
    exact: [u8; MARKED_BEARER_OWNER_VALUE_LEN],
) {
    marked_owner_map(pin_dir)
        .insert(marked_selector(mark), exact, 0)
        .expect("restore owner journal");
}

/// Read, and optionally replace, the loader traffic gate word.
fn replace_traffic_gate(pin_dir: &std::path::Path, value: Option<u64>) -> u64 {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(GTPU_TRAFFIC_OBSERVATION_GATE_MAP_NAME))
            .expect("open traffic gate"),
    )
    .expect("identify traffic gate");
    let mut gate = Array::<_, u64>::try_from(map).expect("typed traffic gate");
    let previous = gate
        .get(&GTPU_TRAFFIC_OBSERVATION_GATE_INDEX, 0)
        .expect("read traffic gate");
    if let Some(value) = value {
        gate.set(GTPU_TRAFFIC_OBSERVATION_GATE_INDEX, value, 0)
            .expect("replace traffic gate");
    }
    previous
}

#[derive(Clone, Copy)]
enum SetOrder {
    InOrder,
    Reordered,
    DuplicatedFirst,
    DuplicatedLast,
}

/// Ordinary (single-context) attachment: default and dedicated bearers.
// The serial guard is deliberately held for the entire body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_ordinary() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // One-second reassembly timeout makes the missing-fragment case
    // observable; restored on unwind.
    let _fragment_limits = FragmentSysctlGuard::configure(1, 4 * 1024 * 1024)?;
    let net = TestNet::provision();
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    let pin_dir = net.pin_root.join("s2bu");
    assert!(matches!(
        backend.probe().await?.downlink_outer_fragment_handling,
        GtpuDownlinkFragmentContract::KernelReassemblyHandoff { .. }
    ));
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;
    backend
        .install_pdp_context(dedicated_session_context(
            device.ifindex,
            MARK_A,
            LOCAL_TEID_A,
            PEER_TEID_A,
        ))
        .await?;

    let port = backend.open_gtpu_control_port(&device).await?;
    assert_eq!(port.downlink_counters()?, Default::default());
    let sender = FragmentSender {
        net: &net,
        destination_mac: main_link_address("s2bu"),
        source_mac: net.pgw_link_address("s2bup"),
    };
    let inner =
        |tag: &[u8; 8]| build_inner_udp(REMOTE_HOST, UE_PAA, 5060, 5060, &sip_invite_payload(tag));

    // In-order, reordered, and duplicated-head fragments each yield exactly
    // one decapsulated default-bearer packet and leave no partial queue.
    for (id, (tag, order)) in [
        (b"in-order", SetOrder::InOrder),
        (b"reorder!", SetOrder::Reordered),
        (b"dup-head", SetOrder::DuplicatedFirst),
    ]
    .into_iter()
    .enumerate()
    {
        let packet = inner(tag);
        sender.send_set(LOCAL_TEID, &packet, 0x4100 + id as u16, order);
        expect_decapsulated(port.as_ref(), &packet, None);
        expect_no_event(port.as_ref(), Duration::from_millis(150));
    }

    // A missing fragment never produces an event, and its late tail cannot
    // resurrect the evicted set. No other partial queue exists here, so the
    // timeout increment is this set's eviction.
    let timeout_before = ipv4_reassembly_stat("ReasmTimeout");
    let frame = sender.frame(LOCAL_TEID, &inner(b"missing!"), PGW_IP);
    let (head, tail) = build_outer_fragments(&frame, 1_000, 0x4120);
    sender.send(&[&head]);
    wait_for_ipv4_reassembly_stat_increment("ReasmTimeout", timeout_before, Duration::from_secs(4));
    sender.send(&[&tail]);
    expect_no_event(port.as_ref(), Duration::from_millis(500));

    // A duplicated tail after completion is delivered once; the duplicate
    // opens only an incomplete queue that the kernel later evicts.
    let packet = inner(b"dup-tail");
    sender.send_set(LOCAL_TEID, &packet, 0x4103, SetOrder::DuplicatedLast);
    expect_decapsulated(port.as_ref(), &packet, None);
    expect_no_event(port.as_ref(), Duration::from_millis(150));

    // The dedicated bearer returns its exact output mark.
    let packet = inner(b"dedicate");
    sender.send_set(LOCAL_TEID_A, &packet, 0x4110, SetOrder::InOrder);
    expect_decapsulated(port.as_ref(), &packet, GtpBearerMark::new(MARK_A));

    // A foreign TEID is handed back undecapsulated, bytes intact.
    let foreign = sender.send_set(FOREIGN_TEID, &inner(b"foreign!"), 0x4130, SetOrder::InOrder);
    match receive_event(port.as_ref()) {
        GtpuDownlinkEvent::UnknownTunnel(datagram) => assert_eq!(datagram.bytes(), foreign),
        other => panic!("foreign TEID must be an unknown-tunnel observation, got {other:?}"),
    }

    // A fragment set from an unauthorized peer fails the canonical binding.
    sender.send_set_from(
        LOCAL_TEID,
        &inner(b"wrongpgw"),
        0x4140,
        SetOrder::InOrder,
        PGW_ALT_IP,
    );
    expect_drop(
        port.as_ref(),
        GtpuDownlinkDrop::BindingMismatch(
            opc_gtpu_ebpf_common::DownlinkBindingMismatch::PeerAddress,
        ),
    );

    // Stale generation: a non-Active commit (install/replace/remove window or
    // crash residue) is the publication fence, for the default bearer...
    let active_commit = read_pinned_default_commit(&pin_dir);
    for phase in [
        MarkedBearerOwnerPhase::Pending,
        MarkedBearerOwnerPhase::Removing,
    ] {
        replace_pinned_source_port(&pin_dir, active_commit.with_phase(phase).encode());
        sender.send_set(LOCAL_TEID, &inner(b"fenced!!"), 0x4150, SetOrder::InOrder);
        expect_drop(
            port.as_ref(),
            GtpuDownlinkDrop::BindingMismatch(
                opc_gtpu_ebpf_common::DownlinkBindingMismatch::Invalid,
            ),
        );
    }
    replace_pinned_source_port(&pin_dir, active_commit.encode());
    // ...and for the dedicated bearer's owner journal.
    set_marked_owner_phase(&pin_dir, MARK_A, MarkedBearerOwnerPhase::Pending);
    sender.send_set(LOCAL_TEID_A, &inner(b"ownerpnd"), 0x4160, SetOrder::InOrder);
    expect_drop(
        port.as_ref(),
        GtpuDownlinkDrop::BindingMismatch(opc_gtpu_ebpf_common::DownlinkBindingMismatch::Invalid),
    );
    set_marked_owner_phase(&pin_dir, MARK_A, MarkedBearerOwnerPhase::Active);

    // The owner journal alone fences a dedicated bearer, even while its
    // complete commit is still Active.
    let exact_owner =
        replace_marked_owner_phase_only(&pin_dir, MARK_A, MarkedBearerOwnerPhase::Pending);
    sender.send_set(LOCAL_TEID_A, &inner(b"owneronl"), 0x4161, SetOrder::InOrder);
    expect_drop(
        port.as_ref(),
        GtpuDownlinkDrop::BindingMismatch(opc_gtpu_ebpf_common::DownlinkBindingMismatch::Invalid),
    );
    restore_marked_owner(&pin_dir, MARK_A, exact_owner);

    // A canonical binding that admits the packet but differs from the Active
    // commit is a mixed graph, not authority.
    let widened = DownlinkEndpointBinding::new(
        GtpuEndpointAddress::Ipv4(PGW_IP.octets()),
        GtpuEndpointAddress::Ipv4(EPDG_S2BU_IP.octets()),
        device.ifindex,
        GtpuSourcePortPolicy::Any,
    )
    .expect("canonical widened binding")
    .encode();
    let exact_binding = replace_pinned_binding(&pin_dir, LOCAL_TEID, Some(widened))
        .expect("installed default binding");
    sender.send_set(LOCAL_TEID, &inner(b"mixedbnd"), 0x4162, SetOrder::InOrder);
    expect_drop(
        port.as_ref(),
        GtpuDownlinkDrop::BindingMismatch(opc_gtpu_ebpf_common::DownlinkBindingMismatch::Invalid),
    );
    replace_pinned_binding(&pin_dir, LOCAL_TEID, Some(exact_binding));

    // The inner destination must be the session PAA.
    sender.send_set(
        LOCAL_TEID,
        &build_inner_udp(
            REMOTE_HOST,
            Ipv4Addr::new(10, 45, 0, 99),
            5060,
            5060,
            &sip_invite_payload(b"not-ue!!"),
        ),
        0x4163,
        SetOrder::InOrder,
    );
    expect_drop(port.as_ref(), GtpuDownlinkDrop::DestinationMismatch);

    // While the loader traffic gate is closed tc passes packets untouched,
    // so the consumer must not decapsulate on the attachment's behalf.
    let open_gate = replace_traffic_gate(&pin_dir, None);
    assert!(open_gate != 0 && open_gate & 1 == 1, "gate must be open");
    replace_traffic_gate(&pin_dir, Some(open_gate + 1));
    sender.send_set(LOCAL_TEID, &inner(b"gateshut"), 0x4164, SetOrder::InOrder);
    expect_drop(port.as_ref(), GtpuDownlinkDrop::StateUnavailable);
    replace_traffic_gate(&pin_dir, Some(open_gate));

    let packet = inner(b"restored");
    sender.send_set(LOCAL_TEID, &packet, 0x4170, SetOrder::InOrder);
    expect_decapsulated(port.as_ref(), &packet, None);

    // Removal of the exact context: its TEID no longer selects a tunnel.
    backend
        .remove_pdp_context(RemovePdpContextRequest {
            local_teid: Teid::new(LOCAL_TEID_A).expect("nonzero"),
            link_ifindex: device.ifindex,
            gtp_version: GtpVersion::V1,
            address_family: opc_gtpu_dataplane::GtpAddressFamily::Ipv4,
        })
        .await?;
    sender.send_set(LOCAL_TEID_A, &inner(b"removed!"), 0x4180, SetOrder::InOrder);
    assert!(matches!(
        receive_event(port.as_ref()),
        GtpuDownlinkEvent::UnknownTunnel(_)
    ));

    let counters = port.downlink_counters()?;
    assert_eq!(counters.decapsulated, 6);
    assert_eq!(counters.unknown_tunnel, 2);
    assert_eq!(counters.binding_drops, 6);
    assert_eq!(counters.destination_mismatches, 1);
    assert_eq!(counters.malformed, 0);
    assert_eq!(counters.state_unavailable, 1);
    assert!(!format!("{counters:?}").contains("10.45"));

    // Device removal retires the queue: nothing further is decapsulated.
    backend.remove_device(&device).await?;
    assert_eq!(
        port.try_receive_downlink(4096).unwrap_err(),
        GtpuControlPortError::Unavailable
    );
    drop(net);
    eprintln!(
        "OPC_GTPU_BACKEND_REASSEMBLY_CONSUMER_PROVEN: ordinary default/dedicated bearers, in-order/reordered/duplicated/missing/foreign/stale fragments"
    );
    Ok(())
}

const GROUP_LOCAL_TEID_V6_OVER_V4: u32 = 0x6100_0003;
const GROUP_PEER_TEID_V6_OVER_V4: u32 = 0x6200_0003;

fn pinned_group_authority(
    pin_dir: &std::path::Path,
) -> BpfHashMap<MapData, [u8; GTPU_SESSION_GROUP_ID_LEN], [u8; GTPU_SESSION_GROUP_VALUE_LEN]> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_SESSION_GROUPS)).expect("open grouped authority pin"),
    )
    .expect("identify grouped authority map");
    BpfHashMap::try_from(map).expect("typed grouped authority map")
}

/// Grouped attachment: IPv4 and IPv6 inner families over the IPv4 outer
/// endpoint, exact generation authority, and retirement.
// The serial guard is deliberately held for the entire body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_grouped() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fragment_limits = FragmentSysctlGuard::configure(1, 4 * 1024 * 1024)?;
    let net = TestNet::provision();
    let backend = Arc::new(EbpfGtpuDataplaneBackend::with_config(
        EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..EbpfGtpuDataplaneBackendConfig::default()
        },
    ));
    let device = backend
        .create_device_with_endpoints(grouped_device_request(grouped_mtu_policy()))
        .await?;
    let capabilities = backend
        .gtpu_ip_family_capabilities(grouped_attachment(&device))
        .await?;
    assert!(
        matches!(
            capabilities.downlink_outer_ipv4_fragment_handling,
            GtpuDownlinkFragmentContract::KernelReassemblyHandoff { .. }
        ),
        "a grouped IPv4-outer attachment has a backend-authoritative consumer"
    );
    assert_eq!(
        capabilities.downlink_outer_ipv6_fragment_handling,
        GtpuDownlinkFragmentContract::Unsupported
    );
    let group = GtpuSessionGroup::new(
        grouped_group_id(),
        grouped_device_id(),
        vec![
            grouped_entry(
                device.ifindex,
                IpAddr::V4(UE_PAA),
                IpAddr::V4(EPDG_S2BU_IP),
                IpAddr::V4(PGW_IP),
                GROUP_LOCAL_TEID_V4_INITIAL,
                GROUP_PEER_TEID_V4_INITIAL,
            ),
            grouped_entry(
                device.ifindex,
                IpAddr::V6(UE_PAA_IPV6),
                IpAddr::V4(EPDG_S2BU_IP),
                IpAddr::V4(PGW_IP),
                GROUP_LOCAL_TEID_V6_OVER_V4,
                GROUP_PEER_TEID_V6_OVER_V4,
            ),
        ],
    )?;
    let (namespace, active) = reconcile_fresh_grouped(backend.clone(), group.clone()).await?;
    let pin_dir = grouped_pin_directory(&net.pin_root, grouped_device_id());

    let port = backend.open_gtpu_control_port(&device).await?;
    let sender = FragmentSender {
        net: &net,
        destination_mac: main_link_address("s2bu"),
        source_mac: net.pgw_link_address("s2bup"),
    };
    let v4 = build_inner_udp(
        REMOTE_HOST,
        UE_PAA,
        5060,
        5060,
        &sip_invite_payload(b"groupv4!"),
    );
    sender.send_set(
        GROUP_LOCAL_TEID_V4_INITIAL,
        &v4,
        0x4200,
        SetOrder::Reordered,
    );
    expect_decapsulated(port.as_ref(), &v4, None);

    let v6 = build_inner_udp_v6(
        REMOTE_HOST_IPV6,
        UE_PAA_IPV6,
        5060,
        5060,
        &sip_invite_payload(b"groupv6!"),
    );
    sender.send_set(GROUP_LOCAL_TEID_V6_OVER_V4, &v6, 0x4201, SetOrder::InOrder);
    match receive_event(port.as_ref()) {
        GtpuDownlinkEvent::Decapsulated(decapsulated) => {
            assert_eq!(decapsulated.inner_packet(), v6.as_slice());
            assert_eq!(decapsulated.family(), GtpAddressFamily::Ipv6);
            assert_eq!(decapsulated.bearer_mark(), None);
        }
        other => panic!("grouped IPv6-over-IPv4 fragments must decapsulate, got {other:?}"),
    }

    // A TEID never authorizes the other inner family's T-PDU.
    sender.send_set(GROUP_LOCAL_TEID_V4_INITIAL, &v6, 0x4202, SetOrder::InOrder);
    assert!(matches!(
        receive_event(port.as_ref()),
        GtpuDownlinkEvent::UnknownTunnel(_)
    ));

    // Stale generation: the retained index names the old generation.
    let mut groups = pinned_group_authority(&pin_dir);
    let key = grouped_group_id().to_bytes();
    let exact = groups.get(&key, 0)?;
    let mut advanced = exact;
    advanced[11] = advanced[11].wrapping_add(1);
    groups.insert(key, advanced, 0)?;
    sender.send_set(GROUP_LOCAL_TEID_V4_INITIAL, &v4, 0x4203, SetOrder::InOrder);
    expect_drop(
        port.as_ref(),
        GtpuDownlinkDrop::BindingMismatch(opc_gtpu_ebpf_common::DownlinkBindingMismatch::Invalid),
    );
    groups.insert(key, exact, 0)?;
    drop(groups);
    sender.send_set(
        GROUP_LOCAL_TEID_V4_INITIAL,
        &v4,
        0x4204,
        SetOrder::DuplicatedFirst,
    );
    expect_decapsulated(port.as_ref(), &v4, None);

    // A foreign peer fails the grouped endpoint authority.
    sender.send_set_from(
        GROUP_LOCAL_TEID_V4_INITIAL,
        &v4,
        0x4205,
        SetOrder::InOrder,
        PGW_ALT_IP,
    );
    expect_drop(
        port.as_ref(),
        GtpuDownlinkDrop::BindingMismatch(opc_gtpu_ebpf_common::DownlinkBindingMismatch::Invalid),
    );

    // Retirement removes the exact selectors; nothing is decapsulated.
    let _retired = namespace
        .retire(backend.clone(), active, group)
        .await
        .map_err(|_| "grouped retirement")?;
    sender.send_set(GROUP_LOCAL_TEID_V4_INITIAL, &v4, 0x4206, SetOrder::InOrder);
    assert!(matches!(
        receive_event(port.as_ref()),
        GtpuDownlinkEvent::UnknownTunnel(_)
    ));
    let counters = port.downlink_counters()?;
    assert_eq!(counters.decapsulated, 3);
    assert_eq!(counters.unknown_tunnel, 2);
    assert_eq!(counters.binding_drops, 2);
    assert_eq!(counters.malformed + counters.state_unavailable, 0);
    drop(port);
    drop(net);
    eprintln!(
        "OPC_GTPU_BACKEND_GROUPED_REASSEMBLY_CONSUMER_PROVEN: grouped IPv4/IPv6 inner over IPv4 outer, stale generation, retirement"
    );
    Ok(())
}

/// Sustained PDP churn on the same attachment (the mass re-attach pattern
/// after failover) must not starve the shared UDP/2152 queue: every Echo is
/// answered and every reassembled G-PDU is decapsulated, and the consumer is
/// never told to back off.
// The serial guard is deliberately held for the entire body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_churn() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fragment_limits = FragmentSysctlGuard::configure(2, 4 * 1024 * 1024)?;
    let net = TestNet::provision();
    let backend = Arc::new(EbpfGtpuDataplaneBackend::with_config(
        EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..EbpfGtpuDataplaneBackendConfig::default()
        },
    ));
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;
    let port = backend.open_gtpu_control_port(&device).await?;

    // Churn: install and remove a dedicated bearer back to back, each
    // holding the backend-wide mutation lock for its whole duration.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let churn = {
        let backend = Arc::clone(&backend);
        let stop = Arc::clone(&stop);
        let ifindex = device.ifindex;
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("churn runtime");
            let mut cycles = 0_u64;
            while !stop.load(Ordering::Relaxed) {
                runtime.block_on(async {
                    backend
                        .install_pdp_context(dedicated_session_context(
                            ifindex,
                            MARK_B,
                            LOCAL_TEID_B,
                            PEER_TEID_B,
                        ))
                        .await
                        .expect("churn install");
                    backend
                        .remove_pdp_context(RemovePdpContextRequest {
                            local_teid: Teid::new(LOCAL_TEID_B).expect("nonzero"),
                            link_ifindex: ifindex,
                            gtp_version: GtpVersion::V1,
                            address_family: opc_gtpu_dataplane::GtpAddressFamily::Ipv4,
                        })
                        .await
                        .expect("churn removal");
                });
                cycles += 1;
            }
            cycles
        })
    };
    std::thread::sleep(Duration::from_millis(200));

    let pgw = in_netns(&net.pgw_ns, || {
        let socket = UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .expect("PGW receive timeout");
        socket
    });
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    let sender = FragmentSender {
        net: &net,
        destination_mac: main_link_address("s2bu"),
        source_mac: net.pgw_link_address("s2bup"),
    };
    const ROUNDS: u16 = 20;
    let mut busy = 0_u32;
    let mut echo_responses = 0_u16;
    let mut decapsulated = 0_u16;
    let deadline = Instant::now() + Duration::from_secs(20);
    for round in 0..ROUNDS {
        let sequence = 0x7000 + round;
        let mut echo = vec![0x32, 1, 0, 4, 0, 0, 0, 0];
        echo.extend_from_slice(&sequence.to_be_bytes());
        echo.extend_from_slice(&[0, 0]);
        pgw.send_to(&echo, (EPDG_S2BU_IP, GTPU_PORT))?;
        let packet = build_inner_udp(
            REMOTE_HOST,
            UE_PAA,
            5060,
            5060,
            &sip_invite_payload(&[
                b'c',
                b'h',
                b'u',
                b'r',
                b'n',
                b'-',
                b'0' + (round / 10) as u8,
                b'0' + (round % 10) as u8,
            ]),
        );
        sender.send_set(LOCAL_TEID, &packet, 0x4300 + round, SetOrder::InOrder);
        let mut round_echo = false;
        let mut round_decap = false;
        while !(round_echo && round_decap) {
            assert!(
                Instant::now() < deadline,
                "shared queue starved under churn (round {round}, busy {busy})"
            );
            match port.try_receive_downlink(4096) {
                Ok(Some(GtpuDownlinkEvent::Control(event))) => {
                    let plan = event.echo_response(
                        opc_gtpu_dataplane::control_port::GtpuControlResponseBudget::new(14, 2)?,
                    )?;
                    port.send_control_response(plan)?;
                    round_echo = true;
                }
                Ok(Some(GtpuDownlinkEvent::Decapsulated(decap))) => {
                    assert_eq!(decap.inner_packet(), packet.as_slice());
                    round_decap = true;
                }
                Ok(Some(other)) => panic!("unexpected event under churn: {other:?}"),
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(GtpuControlPortError::Busy) => busy += 1,
                Err(error) => panic!("consumer failed under churn: {error}"),
            }
        }
        let mut response = [0_u8; 64];
        let response_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok((length, _)) = pgw.recv_from(&mut response) {
                assert_eq!(&response[8..10], &sequence.to_be_bytes());
                assert_eq!(length, 14);
                echo_responses += 1;
                break;
            }
            assert!(Instant::now() < response_deadline, "Echo response lost");
        }
        decapsulated += 1;
    }
    stop.store(true, Ordering::Relaxed);
    let cycles = churn.join().expect("churn thread");
    assert!(cycles > 0, "the churn must actually overlap the traffic");
    assert_eq!((echo_responses, decapsulated), (ROUNDS, ROUNDS));
    assert_eq!(
        busy, 0,
        "the consumer must never yield to unrelated mutation"
    );
    drop(port);
    backend.remove_device(&device).await?;
    drop(net);
    eprintln!(
        "OPC_GTPU_BACKEND_CONSUMER_CHURN_PROVEN: {ROUNDS} Echo and reassembled rounds drained during {cycles} install/remove cycles"
    );
    Ok(())
}
