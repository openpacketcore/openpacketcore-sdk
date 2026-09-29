//! Downlink tunnel-MTU enforcement with an in-tunnel RFC 1191 error on a real
//! kernel.
//!
//! The UE-facing link is deliberately narrower than the oversized packets, so
//! any decapsulation would make the host emit its own Fragmentation Needed
//! toward the originator, unencapsulated. The contract is exactly one
//! well-formed error per offending packet inside the session's uplink G-PDU,
//! and no host-generated ICMP anywhere.

use super::*;
use opc_gtpu_dataplane::control_port::{GtpuControlPort, GtpuControlPortError};
use opc_gtpu_dataplane::{
    GtpuDownlinkEvent, GtpuDownlinkInnerMtu, GtpuPacketTooBigRateLimit, GtpuPacketTooBigSignal,
};

const SESSION_MTU: u16 = 1_300;
const OVERSIZED_PAYLOAD: usize = 1_372; // 20 + 8 + 1372 = 1400-octet inner packet
const FITTING_PAYLOAD: usize = 1_200;

fn with_dont_fragment(mut packet: Vec<u8>) -> Vec<u8> {
    packet[6] |= 0x40;
    packet[10..12].fill(0);
    let mut header = [0_u8; 20];
    header.copy_from_slice(&packet[..20]);
    packet[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
    packet
}

fn inner(tag: u8, payload_len: usize, dont_fragment: bool) -> Vec<u8> {
    let packet = build_inner_udp(REMOTE_HOST, UE_PAA, 5060, 5060, &vec![tag; payload_len]);
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
            "over-MTU G-PDU must reach the consumer"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn expect_no_event(port: &dyn GtpuControlPort) {
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        if let Some(event) = port.try_receive_downlink(4096).expect("quiet receive") {
            panic!("unexpected downlink event {event:?}");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn expect_too_big(port: &dyn GtpuControlPort, expected: GtpuPacketTooBigSignal) {
    match receive_event(port) {
        GtpuDownlinkEvent::PacketTooBig(too_big) => {
            assert_eq!(too_big.mtu(), SESSION_MTU);
            assert_eq!(too_big.family(), opc_gtpu_dataplane::GtpAddressFamily::Ipv4);
            assert_eq!(too_big.signal(), expected);
        }
        other => panic!("over-MTU DF packet must be refused, got {other:?}"),
    }
}

/// Validate one in-tunnel error G-PDU and return its inner ICMP packet.
fn assert_in_tunnel_error(gpdu: &[u8], expected_teid: u32, invoking: &[u8]) {
    assert_eq!(&gpdu[..2], &[0x30, 0xff], "plain G-PDU header");
    assert_eq!(
        usize::from(u16::from_be_bytes([gpdu[2], gpdu[3]])),
        gpdu.len() - 8
    );
    assert_eq!(
        u32::from_be_bytes(gpdu[4..8].try_into().unwrap()),
        expected_teid
    );
    let ip = &gpdu[8..];
    // RFC 792/1191: IP header + ICMP header + invoking IP header + 64 bits.
    assert_eq!(ip.len(), 20 + 8 + 20 + 8, "exact RFC 1191 quote length");
    assert_eq!(ip[0], 0x45);
    assert_eq!(usize::from(u16::from_be_bytes([ip[2], ip[3]])), ip.len());
    assert_eq!(ip[9], IPPROTO_ICMP);
    assert_eq!(
        &ip[12..16],
        &UE_PAA.octets(),
        "source is the session PAA (the invoking destination)"
    );
    assert_eq!(&ip[16..20], &REMOTE_HOST.octets(), "sent to the originator");
    assert_eq!(
        internet_checksum(&ip[..20]),
        0,
        "valid IPv4 header checksum"
    );
    let icmp = &ip[20..];
    assert_eq!(icmp[0], 3, "Destination Unreachable");
    assert_eq!(icmp[1], 4, "Fragmentation Needed and DF set");
    assert_eq!(&icmp[4..6], &[0, 0], "unused");
    assert_eq!(
        u16::from_be_bytes([icmp[6], icmp[7]]),
        SESSION_MTU,
        "next-hop MTU"
    );
    assert_eq!(internet_checksum(icmp), 0, "valid ICMP checksum");
    assert_eq!(
        &icmp[8..],
        &invoking[..28],
        "exact invoking header and 64 bits"
    );
}

/// Collect every plaintext ICMP frame seen by one namespace's capture.
fn plaintext_icmp_frames(capture: &OwnedFd) -> usize {
    use nix::sys::socket::{recv, MsgFlags};
    let mut frame = vec![0_u8; 65_536];
    let mut seen = 0;
    while let Ok(length) = recv(capture.as_raw_fd(), &mut frame, MsgFlags::MSG_DONTWAIT) {
        if length >= 14 + 20 && frame[12..14] == [0x08, 0x00] && frame[14 + 9] == IPPROTO_ICMP {
            seen += 1;
        }
    }
    seen
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
    // The access-side link is narrower than the oversized packets, exactly
    // like an ESP-in-UDP SWu path after encapsulation overhead.
    run(
        "ip",
        &["link", "set", "ue0", "mtu", &SESSION_MTU.to_string()],
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
    let mtu =
        GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(SESSION_MTU).expect("canonical session MTU");
    let mut default_bearer = session_context(device.ifindex);
    default_bearer.downlink_inner_mtu = Some(mtu);
    backend.install_pdp_context(default_bearer.clone()).await?;
    let mut dedicated =
        dedicated_session_context(device.ifindex, MARK_A, LOCAL_TEID_A, PEER_TEID_A);
    dedicated.downlink_inner_mtu = Some(mtu);
    backend.install_pdp_context(dedicated).await?;
    // Exact readback and idempotent reinstall include the MTU.
    backend.install_pdp_context(default_bearer.clone()).await?;
    assert!(matches!(
        backend
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&default_bearer).expect("selector")
            ))
            .await?,
        PdpContextReadback::Present(context) if context.downlink_inner_mtu == Some(mtu)
    ));

    let port = backend.open_gtpu_control_port(&device).await?;
    let pgw = in_netns(&net.pgw_ns, || {
        let socket = UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("PGW receive timeout");
        socket
    });
    let pgw_capture = packet_capture_socket(&net.pgw_ns);
    let ue_capture = packet_capture_socket(&net.ue_ns);
    let ue = in_netns(&net.ue_ns, || {
        let socket = UdpSocket::bind((UE_PAA, 5060)).expect("bind UE receiver");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("UE receive timeout");
        socket
    });
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    let _ = plaintext_icmp_frames(&pgw_capture);
    let _ = plaintext_icmp_frames(&ue_capture);
    let host_icmp_before = host_icmp_destination_unreachable();
    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");
    let send_gpdu = |teid: u32, packet: &[u8]| {
        let frame = build_outer_gtpu_frame(
            destination_mac,
            source_mac,
            &[],
            &build_gpdu(teid, None, packet),
            true,
            0,
        );
        send_raw_gtpu_frame(
            &net.pgw_ns,
            "s2bup",
            &frame,
            RawChecksumMetadata::Unverified,
        );
    };
    let receive_pgw = || {
        let mut buffer = [0_u8; 2048];
        pgw.recv_from(&mut buffer).map(|(length, source)| {
            assert_eq!(source, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
            buffer[..length].to_vec()
        })
    };
    let expect_pgw_silent = || {
        assert!(
            receive_pgw().is_err(),
            "no further in-tunnel error may reach the peer"
        );
    };

    // 1. An oversized DF packet on the default bearer: exactly one error in
    //    the session's uplink tunnel, the packet itself never reaches the UE.
    let oversized = inner(0x51, OVERSIZED_PAYLOAD, true);
    send_gpdu(LOCAL_TEID, &oversized);
    expect_too_big(port.as_ref(), GtpuPacketTooBigSignal::Sent);
    assert_in_tunnel_error(&receive_pgw()?, PEER_TEID, &oversized);
    expect_pgw_silent();

    // 2. An offending packet on the dedicated bearer is signalled on the
    //    UE's default-bearer uplink (TS 23.401 uplink bearer binding: the
    //    dedicated TFT may admit only its media flows).
    let dedicated_oversized = inner(0x52, OVERSIZED_PAYLOAD, true);
    send_gpdu(LOCAL_TEID_A, &dedicated_oversized);
    expect_too_big(port.as_ref(), GtpuPacketTooBigSignal::Sent);
    assert_in_tunnel_error(&receive_pgw()?, PEER_TEID, &dedicated_oversized);
    expect_pgw_silent();

    // 3. An outer-fragmented oversized DF packet is reassembled by the kernel
    //    and signalled exactly once by the same consumer.
    let reassembled = inner(0x53, OVERSIZED_PAYLOAD, true);
    let frame = build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &build_gpdu(LOCAL_TEID, None, &reassembled),
        true,
        0,
    );
    let (head, tail) = build_outer_fragments(&frame, 1_000, 0x5100);
    for fragment in [&head, &tail] {
        send_raw_gtpu_frame(
            &net.pgw_ns,
            "s2bup",
            fragment,
            RawChecksumMetadata::Unverified,
        );
    }
    expect_too_big(port.as_ref(), GtpuPacketTooBigSignal::Sent);
    assert_in_tunnel_error(&receive_pgw()?, PEER_TEID, &reassembled);
    expect_pgw_silent();

    // 4. A fitting DF packet and an oversized non-DF packet are forwarded
    //    through tc, not signalled; the host fragments the latter itself.
    let fitting = inner(0x54, FITTING_PAYLOAD, true);
    send_gpdu(LOCAL_TEID, &fitting);
    let mut buffer = [0_u8; 2048];
    let (length, _) = ue.recv_from(&mut buffer)?;
    assert_eq!(&buffer[..length], &vec![0x54; FITTING_PAYLOAD][..]);
    let fragmentable = inner(0x55, OVERSIZED_PAYLOAD, false);
    send_gpdu(LOCAL_TEID, &fragmentable);
    let (length, _) = ue.recv_from(&mut buffer)?;
    assert_eq!(&buffer[..length], &vec![0x55; OVERSIZED_PAYLOAD][..]);
    expect_no_event(port.as_ref());
    expect_pgw_silent();

    // 5. The rate limit holds: burst 2, no refill during the test.
    port.set_packet_too_big_rate_limit(
        GtpuPacketTooBigRateLimit::new(2, Duration::from_secs(3_600)).expect("canonical limit"),
    )?;
    for (index, expected) in [
        GtpuPacketTooBigSignal::Sent,
        GtpuPacketTooBigSignal::Sent,
        GtpuPacketTooBigSignal::RateLimited,
        GtpuPacketTooBigSignal::RateLimited,
    ]
    .into_iter()
    .enumerate()
    {
        let packet = inner(0x60 + index as u8, OVERSIZED_PAYLOAD, true);
        send_gpdu(LOCAL_TEID, &packet);
        expect_too_big(port.as_ref(), expected);
        if expected == GtpuPacketTooBigSignal::Sent {
            assert_in_tunnel_error(&receive_pgw()?, PEER_TEID, &packet);
        }
    }
    expect_pgw_silent();
    // The limit is per session: the exhausted default bearer does not
    // silence the dedicated bearer's first error.
    let other_session = inner(0x66, OVERSIZED_PAYLOAD, true);
    send_gpdu(LOCAL_TEID_A, &other_session);
    expect_too_big(port.as_ref(), GtpuPacketTooBigSignal::Sent);
    assert_in_tunnel_error(&receive_pgw()?, PEER_TEID, &other_session);
    expect_pgw_silent();

    // 6. A backlog of over-MTU hand-offs never delays the shared queue: with
    //    40 steered packets waiting, a later Echo Request is served first.
    for index in 0..40_u8 {
        send_gpdu(LOCAL_TEID, &inner(0x70 + index, OVERSIZED_PAYLOAD, true));
    }
    let echo = [0x32, 1, 0, 4, 0, 0, 0, 0, 0x5e, 0x11, 0, 0];
    pgw.send_to(&echo, (EPDG_S2BU_IP, GTPU_PORT))?;
    std::thread::sleep(Duration::from_millis(200));
    match receive_event(port.as_ref()) {
        GtpuDownlinkEvent::Control(event) => assert_eq!(event.bytes(), echo),
        other => panic!("Echo must be served ahead of the hand-off backlog, got {other:?}"),
    }
    for _ in 0..40 {
        expect_too_big(port.as_ref(), GtpuPacketTooBigSignal::RateLimited);
    }
    expect_no_event(port.as_ref());
    expect_pgw_silent();

    // 7. Never-answer packets (RFC 1122 3.2.2: a 0/8 originator) are refused
    //    before any token is taken, so they cannot drain a session's budget.
    port.set_packet_too_big_rate_limit(
        GtpuPacketTooBigRateLimit::new(1, Duration::from_secs(3_600)).expect("canonical limit"),
    )?;
    for index in 0..3_u8 {
        let unanswerable = with_dont_fragment(build_inner_udp(
            Ipv4Addr::new(0, 1, 2, 3),
            UE_PAA,
            5060,
            5060,
            &vec![0x90 + index; OVERSIZED_PAYLOAD],
        ));
        send_gpdu(LOCAL_TEID, &unanswerable);
        expect_too_big(port.as_ref(), GtpuPacketTooBigSignal::Unsendable);
    }
    let answerable = inner(0x93, OVERSIZED_PAYLOAD, true);
    send_gpdu(LOCAL_TEID, &answerable);
    expect_too_big(port.as_ref(), GtpuPacketTooBigSignal::Sent);
    assert_in_tunnel_error(&receive_pgw()?, PEER_TEID, &answerable);
    expect_pgw_silent();

    // Nothing oversized reached the UE, no plaintext ICMP crossed either
    // neighbour namespace, and the host generated no Destination Unreachable.
    assert!(
        ue.recv_from(&mut buffer).is_err(),
        "no oversized DF packet may reach the UE"
    );
    assert_eq!(
        plaintext_icmp_frames(&pgw_capture),
        0,
        "no plaintext ICMP toward the core"
    );
    assert_eq!(
        plaintext_icmp_frames(&ue_capture),
        0,
        "no plaintext ICMP toward the UE"
    );
    assert_eq!(
        host_icmp_destination_unreachable(),
        host_icmp_before,
        "the host must not generate its own Fragmentation Needed"
    );
    let counters = port.downlink_counters()?;
    assert_eq!(counters.packet_too_big, 52);
    assert_eq!(counters.packet_too_big_signalled, 7);
    assert_eq!(counters.packet_too_big_rate_limited, 42);
    assert_eq!(counters.packet_too_big_unsendable, 3);
    assert_eq!(counters.decapsulated, 0);
    assert_eq!(counters.control_plane, 1);
    assert_eq!(counters.shared_queue_drops, 0);
    assert_eq!(counters.packet_too_big_queue_drops, 0);

    drop(port);
    backend.remove_device(&device).await?;
    drop(net);
    eprintln!(
        "OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_PROVEN: IPv4 default/dedicated(default-bearer uplink)/reassembled in-tunnel RFC 1191, exact quote, per-session rate limit, Echo ahead of hand-off backlog, no host ICMP"
    );
    Ok(())
}
