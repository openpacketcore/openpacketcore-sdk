//! Default downlink handling of an oversized inner IPv4 packet with Don't
//! Fragment set, on a real kernel (#1002).
//!
//! The access link `ue0` (MTU 1,400) is narrower than the 1,450-octet DF
//! datagram, as the CRC SWu path is. The test plays the ePDG: it drains
//! `try_receive_downlink` and injects every returned inner packet toward
//! XFRM with its bearer mark, through an `IP_HDRINCL` raw socket whose
//! `IP_PKTINFO` source is the inner source (so a source-specific XFRM OUT
//! selector matches). The contract: the datagram reaches the UE's socket as
//! inner fragments that the UE reassembles exactly, on the default bearer,
//! after outer reassembly, and on a dedicated bearer through its real ESP
//! Child SA, and the host generates no ICMP anywhere.

use super::*;
use opc_gtpu_dataplane::control_port::{GtpuControlPort, GtpuControlPortError};
use opc_gtpu_dataplane::GtpuDownlinkEvent;

/// The access-side (SWu) link MTU.
const ACCESS_MTU: u16 = 1_400;
/// The session's downlink inner MTU: the access MTU minus the largest ESP
/// tunnel-mode overhead of the test Child SAs (outer IPv4 20, UDP 8, ESP 8,
/// IV 16, padding 15, trailer 2, ICV 12 = 81 octets), rounded down.
const SESSION_MTU: u16 = 1_300;
/// 20 + 8 + 1,422 = a 1,450-octet inner datagram, the CRC case.
const OVERSIZED_PAYLOAD: usize = 1_422;
const FITTING_PAYLOAD: usize = 1_200;
const SIP_PORT: u16 = 5060;

fn with_dont_fragment(mut packet: Vec<u8>) -> Vec<u8> {
    packet[6] |= 0x40;
    packet[10..12].fill(0);
    let mut header = [0_u8; 20];
    header.copy_from_slice(&packet[..20]);
    packet[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
    packet
}

fn application_payload(tag: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| tag ^ u8::try_from(index % 251).unwrap())
        .collect()
}

/// An inner UDP datagram from the remote host to the UE's SIP port. Like a
/// Linux sender on an unconnected UDP socket, its Identification is zero.
fn datagram(tag: u8, payload_len: usize, dont_fragment: bool) -> Vec<u8> {
    let packet = build_inner_udp(
        REMOTE_HOST,
        UE_PAA,
        SIP_PORT,
        SIP_PORT,
        &application_payload(tag, payload_len),
    );
    if dont_fragment {
        with_dont_fragment(packet)
    } else {
        packet
    }
}

/// Host-generated ICMP Destination Unreachable messages in this netns.
fn host_icmp_destination_unreachable() -> u64 {
    let snmp = std::fs::read_to_string("/proc/net/snmp").expect("read /proc/net/snmp");
    let mut lines = snmp.lines().filter(|line| line.starts_with("Icmp:"));
    let header = lines.next().expect("Icmp header row");
    let values = lines.next().expect("Icmp value row");
    header
        .split_whitespace()
        .zip(values.split_whitespace())
        .find(|(name, _)| *name == "OutDestUnreachs")
        .and_then(|(_, value)| value.parse().ok())
        .expect("OutDestUnreachs counter")
}

/// Drain every captured frame; return its IPv4 packets without Ethernet.
fn captured_ipv4(capture: &OwnedFd) -> Vec<Vec<u8>> {
    use nix::sys::socket::{recv, MsgFlags};
    let mut frame = vec![0_u8; 65_536];
    let mut packets = Vec::new();
    while let Ok(length) = recv(capture.as_raw_fd(), &mut frame, MsgFlags::MSG_DONTWAIT) {
        if length >= 14 + 20 && frame[12..14] == [0x08, 0x00] {
            packets.push(frame[14..length].to_vec());
        }
    }
    packets
}

fn plaintext_icmp(packets: &[Vec<u8>]) -> usize {
    packets
        .iter()
        .filter(|packet| packet[9] == IPPROTO_ICMP)
        .count()
}

/// Require the captured packets toward the UE to carry `datagram` as RFC
/// 791 inner fragments of at most the session MTU that reassemble exactly:
/// one non-zero Identification, Don't Fragment clear, valid header
/// checksums, More Fragments on all but the last, contiguous offsets.
/// Returns the fragment count.
fn assert_inner_fragments(packets: &[Vec<u8>], datagram: &[u8]) -> usize {
    let fragments: Vec<&Vec<u8>> = packets
        .iter()
        .filter(|packet| {
            packet[9] == IPPROTO_UDP
                && packet[12..16] == REMOTE_HOST.octets()
                && packet[16..20] == UE_PAA.octets()
        })
        .collect();
    assert!(
        fragments.len() >= 2,
        "the datagram must arrive as inner fragments, got {} packets",
        fragments.len()
    );
    let identification = [fragments[0][4], fragments[0][5]];
    assert_ne!(
        identification,
        [0, 0],
        "fragments need a real Identification"
    );
    let mut pieces = Vec::new();
    for fragment in &fragments {
        assert!(fragment.len() <= usize::from(SESSION_MTU));
        assert_eq!(
            usize::from(u16::from_be_bytes([fragment[2], fragment[3]])),
            fragment.len()
        );
        assert_eq!(&fragment[4..6], &identification, "one Identification");
        assert_eq!(fragment[6] & 0x40, 0, "Don't Fragment cleared");
        assert_eq!(internet_checksum(&fragment[..20]), 0, "header checksum");
        assert_eq!(
            &fragment[8..10],
            &datagram[8..10],
            "TTL and protocol copied"
        );
        let flags = u16::from_be_bytes([fragment[6], fragment[7]]);
        pieces.push((
            usize::from(flags & 0x1fff) * 8,
            flags & 0x2000 != 0,
            &fragment[20..],
        ));
    }
    pieces.sort_by_key(|piece| piece.0);
    let mut data = Vec::new();
    for (index, (offset, more_fragments, piece)) in pieces.iter().enumerate() {
        assert_eq!(*offset, data.len(), "contiguous fragment offsets");
        assert_eq!(*more_fragments, index + 1 < pieces.len(), "More Fragments");
        data.extend_from_slice(piece);
    }
    assert_eq!(data, &datagram[20..], "fragments reassemble exactly");
    fragments.len()
}

/// SPIs of the ESP-in-UDP frames from the ePDG to the UE, in order.
fn esp_spis(packets: &[Vec<u8>]) -> Vec<u32> {
    packets
        .iter()
        .filter(|packet| {
            packet[9] == IPPROTO_UDP
                && packet[12..16] == EPDG_SWU_IP.octets()
                && packet[16..20] == UE_SWU_IP.octets()
                && packet.len() >= 20 + 8 + 4
                && packet[20..24] == [0x11, 0x94, 0x11, 0x94]
        })
        .map(|packet| {
            assert!(packet.len() <= usize::from(ACCESS_MTU), "ESP fits the link");
            u32::from_be_bytes([packet[28], packet[29], packet[30], packet[31]])
        })
        .collect()
}

/// Inject one inner IPv4 packet toward XFRM as the ePDG does: an
/// `IPPROTO_RAW` (`IP_HDRINCL`) socket, the bearer mark as `SO_MARK` (zero
/// for the default bearer), and the inner source as the `IP_PKTINFO`
/// source. Linux builds the XFRM flow from the socket, not from the packet:
/// without that source a source-specific OUT selector would not match.
fn inject_toward_xfrm(packet: &[u8], mark: Option<GtpBearerMark>) {
    use nix::sys::socket::{
        sendmsg, setsockopt, socket, sockopt, AddressFamily, ControlMessage, MsgFlags, SockFlag,
        SockProtocol, SockType, SockaddrIn,
    };
    let raw = socket(
        AddressFamily::Inet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::Raw,
    )
    .expect("open IP_HDRINCL raw socket");
    setsockopt(&raw, sockopt::Mark, &mark.map_or(0, GtpBearerMark::get)).expect("set SO_MARK");
    let source = [packet[12], packet[13], packet[14], packet[15]];
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let info = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: u32::from_ne_bytes(source),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };
    let sent = sendmsg(
        raw.as_raw_fd(),
        &[std::io::IoSlice::new(packet)],
        &[ControlMessage::Ipv4PacketInfo(&info)],
        MsgFlags::empty(),
        Some(&SockaddrIn::from(std::net::SocketAddrV4::new(
            destination,
            0,
        ))),
    )
    .expect("inject one inner packet toward XFRM");
    assert_eq!(sent, packet.len());
}

/// Serve the backend-owned consumer for `window` as the ePDG's loop does,
/// injecting every returned inner packet toward XFRM with its bearer mark.
/// Returns every event, in order.
fn serve_consumer(port: &dyn GtpuControlPort, window: Duration) -> Vec<GtpuDownlinkEvent> {
    let deadline = Instant::now() + window;
    let mut events = Vec::new();
    while Instant::now() < deadline {
        match port.try_receive_downlink(4096) {
            Ok(Some(event)) => {
                if let GtpuDownlinkEvent::Decapsulated(packet) = &event {
                    inject_toward_xfrm(packet.inner_packet(), packet.bearer_mark());
                }
                events.push(event);
            }
            Ok(None) | Err(GtpuControlPortError::Busy) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("downlink consumer receive failed: {error}"),
        }
    }
    events
}

/// Require the UE's socket to receive exactly `payload` from the remote host.
fn expect_ue_delivery(ue: &UdpSocket, payload: &[u8], context: &str) {
    let mut buffer = [0_u8; 2_048];
    let (length, source) = ue
        .recv_from(&mut buffer)
        .unwrap_or_else(|_| panic!("{context}: the datagram must reach the UE"));
    assert_eq!(
        source,
        SocketAddr::from((REMOTE_HOST, SIP_PORT)),
        "{context}"
    );
    assert_eq!(&buffer[..length], payload, "{context}: exact payload");
}

// The serial guard is deliberately held for the entire body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fragment_limits = FragmentSysctlGuard::configure(2, 4 * 1024 * 1024)?;
    let net = TestNet::provision();
    run(
        "ip",
        &["link", "set", "ue0", "mtu", &ACCESS_MTU.to_string()],
    );
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    assert_eq!(
        backend.probe().await?.downlink_inner_mtu_enforcement,
        GtpuCapability::Available
    );
    let default_bearer = session_context(device.ifindex);
    backend.install_pdp_context(default_bearer).await?;
    let dedicated = dedicated_session_context(device.ifindex, MARK_A, LOCAL_TEID_A, PEER_TEID_A);
    backend.install_pdp_context(dedicated).await?;

    let port = backend.open_gtpu_control_port(&device).await?;
    let pgw_capture = packet_capture_socket(&net.pgw_ns);
    let ue_capture = packet_capture_socket(&net.ue_ns);
    let ue = in_netns(&net.ue_ns, || {
        let socket = UdpSocket::bind((UE_PAA, SIP_PORT)).expect("bind UE receiver");
        socket
            .set_read_timeout(Some(Duration::from_millis(1_000)))
            .expect("UE receive timeout");
        socket
    });
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    run("ping", &["-c", "1", "-W", "1", "10.45.0.2"]);
    let mut core_packets = captured_ipv4(&pgw_capture);
    core_packets.clear();
    let _ = captured_ipv4(&ue_capture);
    let host_icmp_before = host_icmp_destination_unreachable();
    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");
    let frame = |teid: u32, packet: &[u8]| {
        build_outer_gtpu_frame(
            destination_mac,
            source_mac,
            &[],
            &build_gpdu(teid, None, packet),
            true,
            0,
        )
    };
    let send = |frames: &[&[u8]]| {
        for frame in frames {
            send_raw_gtpu_frame(&net.pgw_ns, "s2bup", frame, RawChecksumMetadata::Unverified);
        }
    };
    let window = Duration::from_millis(300);

    // 1. The CRC case on the default bearer: a 1,450-octet DF datagram over
    //    a 1,400-octet access link.
    let crc_case = datagram(0x51, OVERSIZED_PAYLOAD, true);
    send(&[&frame(LOCAL_TEID, &crc_case)]);
    let events = serve_consumer(port.as_ref(), window);
    let mut buffer = [0_u8; 2_048];
    let delivered = ue.recv_from(&mut buffer);
    core_packets.extend(captured_ipv4(&pgw_capture));
    eprintln!(
        "inner fragmentation: consumer events={events:?}, delivered to the UE={}, host OutDestUnreachs delta={}, plaintext ICMP toward the core={}",
        delivered.is_ok(),
        host_icmp_destination_unreachable() - host_icmp_before,
        plaintext_icmp(&core_packets)
    );
    let (length, source) =
        delivered.map_err(|_| "the oversized DF datagram must reach the UE, not be black-holed")?;
    assert_eq!(source, SocketAddr::from((REMOTE_HOST, SIP_PORT)));
    assert_eq!(
        &buffer[..length],
        application_payload(0x51, OVERSIZED_PAYLOAD).as_slice()
    );
    assert_eq!(
        assert_inner_fragments(&captured_ipv4(&ue_capture), &crc_case),
        2
    );

    // 2. The same datagram fragmented on the outer path: the kernel
    //    reassembles the G-PDU into the shared queue, and the consumer
    //    fragments the inner packet exactly the same way.
    let reassembled = datagram(0x52, OVERSIZED_PAYLOAD, true);
    let (head, tail) = build_outer_fragments(&frame(LOCAL_TEID, &reassembled), 1_000, 0x5200);
    send(&[&head, &tail]);
    serve_consumer(port.as_ref(), window);
    expect_ue_delivery(
        &ue,
        &application_payload(0x52, OVERSIZED_PAYLOAD),
        "outer-reassembled",
    );
    assert_eq!(
        assert_inner_fragments(&captured_ipv4(&ue_capture), &reassembled),
        2
    );

    // 3. A fitting DF datagram and an oversized fragmentable one stay on the
    //    tc fast path: no consumer event.
    send(&[&frame(LOCAL_TEID, &datagram(0x53, FITTING_PAYLOAD, true))]);
    send(&[&frame(
        LOCAL_TEID,
        &datagram(0x54, OVERSIZED_PAYLOAD, false),
    )]);
    let events = serve_consumer(port.as_ref(), window);
    assert!(events.is_empty(), "fast-path packets: {events:?}");
    expect_ue_delivery(&ue, &application_payload(0x53, FITTING_PAYLOAD), "fitting");
    expect_ue_delivery(
        &ue,
        &application_payload(0x54, OVERSIZED_PAYLOAD),
        "fragmentable",
    );

    // 4. A dedicated bearer through its real ESP Child SA: every fragment is
    //    injected with the bearer mark, leaves under the dedicated SPI, is
    //    decrypted by the UE and reassembled.
    let _epdg_nat_t_socket = nat_t_socket(EPDG_SWU_IP);
    let _ue_nat_t_socket = in_netns(&net.ue_ns, || nat_t_socket(UE_SWU_IP));
    install_real_marked_outbound_xfrm_for_ue_application(&net.ue_ns).await?;
    let _ = captured_ipv4(&ue_capture);
    let dedicated_case = datagram(0x55, OVERSIZED_PAYLOAD, true);
    send(&[&frame(LOCAL_TEID_A, &dedicated_case)]);
    serve_consumer(port.as_ref(), window);
    expect_ue_delivery(
        &ue,
        &application_payload(0x55, OVERSIZED_PAYLOAD),
        "dedicated bearer",
    );
    assert_eq!(
        esp_spis(&captured_ipv4(&ue_capture)),
        [OUTBOUND_SPI_A, OUTBOUND_SPI_A],
        "one dedicated-SA ESP packet per inner fragment"
    );

    // No plaintext ICMP crossed the core, and the host generated no
    // Destination Unreachable.
    core_packets.extend(captured_ipv4(&pgw_capture));
    assert_eq!(plaintext_icmp(&core_packets), 0, "no ICMP toward the core");
    assert_eq!(
        host_icmp_destination_unreachable(),
        host_icmp_before,
        "the host must not generate its own Fragmentation Needed"
    );
    let counters = port.downlink_counters()?;
    assert_eq!(counters.decapsulated, 0);
    assert_eq!(counters.shared_queue_drops, 0);
    assert_eq!(counters.packet_too_big_queue_drops, 0);

    drop(port);
    backend.remove_device(&device).await?;
    drop(net);
    eprintln!(
        "OPC_GTPU_DOWNLINK_INNER_FRAGMENTATION_PROVEN: IPv4 DF datagram over the session MTU delivered as exact inner fragments (default, outer-reassembled, dedicated via ESP), no host ICMP"
    );
    Ok(())
}
