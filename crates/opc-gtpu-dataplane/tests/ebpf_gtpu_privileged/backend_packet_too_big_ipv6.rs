//! In-tunnel RFC 4443 Packet Too Big for an ordinary inner-IPv6 context on a
//! real kernel.
//!
//! The UE-facing link is narrower than the oversized packet, so a
//! decapsulation would make the host emit its own ICMPv6 Packet Too Big
//! toward the originator, unencapsulated. The contract is exactly one
//! well-formed error inside the session's in-tunnel G-PDU and no
//! host-generated ICMPv6 anywhere.

use super::*;
use opc_gtpu_dataplane::control_port::{GtpuControlPort, GtpuControlPortError};
use opc_gtpu_dataplane::{
    GtpAddressFamily, GtpuDownlinkEvent, GtpuDownlinkInnerMtu, GtpuPacketTooBigRateLimit,
    GtpuPacketTooBigSignal,
};

const SESSION_MTU: u16 = 1_300;
const OVERSIZED_PAYLOAD: usize = 1_352; // 40 + 8 + 1352 = 1400-octet inner packet
const FITTING_PAYLOAD: usize = 1_252;
const ICMPV6_QUOTE: usize = 1_280 - 40 - 8;

const ICMPV6_TYPE_PACKET_TOO_BIG: u8 = 2;

fn inner(total_payload: usize, source: Ipv6Addr) -> Vec<u8> {
    build_inner_udp_v6(source, UE_PAA_IPV6, 5060, 5060, &vec![0x5a; total_payload])
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

fn expect_too_big(port: &dyn GtpuControlPort) {
    match receive_event(port) {
        GtpuDownlinkEvent::PacketTooBig(too_big) => {
            assert_eq!(too_big.mtu(), SESSION_MTU);
            assert_eq!(too_big.family(), GtpAddressFamily::Ipv6);
            assert_eq!(too_big.signal(), GtpuPacketTooBigSignal::Sent);
        }
        other => panic!("over-MTU IPv6 packet must be signalled, got {other:?}"),
    }
}

/// Validate one in-tunnel RFC 4443 error G-PDU and return its ICMPv6 message.
fn assert_in_tunnel_icmpv6_error(gpdu: &[u8], expected_teid: u32, invoking: &[u8]) {
    assert_eq!(&gpdu[..2], &[0x30, 0xff], "plain G-PDU header");
    assert_eq!(
        usize::from(u16::from_be_bytes([gpdu[2], gpdu[3]])),
        gpdu.len() - 8
    );
    assert_eq!(
        u32::from_be_bytes(gpdu[4..8].try_into().unwrap()),
        expected_teid
    );
    let outer = &gpdu[8..];
    assert_eq!(outer[0] >> 4, 6, "inner error is IPv6");
    let quote = invoking.len().min(ICMPV6_QUOTE);
    assert_eq!(outer.len(), 40 + 8 + quote);
    assert_eq!(
        usize::from(u16::from_be_bytes([outer[4], outer[5]])),
        8 + quote
    );
    assert_eq!(outer[6], IPPROTO_ICMPV6);
    assert_eq!(
        &outer[8..24],
        &UE_PAA_IPV6.octets(),
        "source is the invoking destination (the subscriber address)"
    );
    assert_eq!(
        &outer[24..40],
        &REMOTE_HOST_IPV6.octets(),
        "sent to the originator"
    );
    let icmp = &outer[40..];
    assert_eq!(icmp[0], ICMPV6_TYPE_PACKET_TOO_BIG);
    assert_eq!(icmp[1], 0, "code zero");
    assert_eq!(
        u32::from_be_bytes(icmp[4..8].try_into().unwrap()),
        u32::from(SESSION_MTU),
        "advertised MTU"
    );
    assert_eq!(&icmp[8..], &invoking[..quote], "bounded invoking quote");
    assert_eq!(
        icmpv6_checksum(UE_PAA_IPV6, REMOTE_HOST_IPV6, icmp),
        0,
        "valid ICMPv6 checksum over the outer pseudo-header"
    );
}

/// Count plaintext ICMPv6 Packet Too Big frames seen by one namespace's
/// capture.
fn plaintext_icmpv6_ptb_frames(capture: &OwnedFd) -> usize {
    use nix::sys::socket::{recv, MsgFlags};
    let mut frame = vec![0_u8; 65_536];
    let mut seen = 0;
    while let Ok(length) = recv(capture.as_raw_fd(), &mut frame, MsgFlags::MSG_DONTWAIT) {
        if length >= 14 + 40 + 8
            && frame[12..14] == [0x86, 0xdd]
            && frame[14 + 6] == IPPROTO_ICMPV6
            && frame[14 + 40] == ICMPV6_TYPE_PACKET_TOO_BIG
        {
            seen += 1;
        }
    }
    seen
}

fn host_icmpv6_packet_too_big() -> u64 {
    fs::read_to_string("/proc/net/snmp6")
        .expect("read IPv6 counters")
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "Icmp6OutPktTooBigs").then(|| {
                fields
                    .next()
                    .expect("counter value")
                    .parse()
                    .expect("integer counter")
            })
        })
        .expect("Icmp6OutPktTooBigs counter")
}

/// Before installing tc, prove the same oversized IPv6 packet triggers a
/// host PTB when it reaches ordinary forwarding toward the access link.
fn assert_host_packet_too_big_control(net: &TestNet) {
    let capture = packet_capture_socket(&net.pgw_ns);
    let before = host_icmpv6_packet_too_big();
    let mut frame = Vec::new();
    frame.extend_from_slice(&main_link_address("s2bu"));
    frame.extend_from_slice(&net.pgw_link_address("s2bup"));
    frame.extend_from_slice(&[0x86, 0xdd]);
    frame.extend_from_slice(&inner(OVERSIZED_PAYLOAD, REMOTE_HOST_IPV6));
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &frame,
        RawChecksumMetadata::Unverified,
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut captured = 0;
    loop {
        captured += plaintext_icmpv6_ptb_frames(&capture);
        if host_icmpv6_packet_too_big() > before && captured > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ordinary forwarding must generate and deliver a host PTB: counter {}, before {before}, captured {captured}",
            host_icmpv6_packet_too_big()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(host_icmpv6_packet_too_big(), before + 1);
    assert_eq!(captured, 1);
    let output = Command::new("ip")
        .args(["-j", "link", "show", "dev", "ue0"])
        .output()
        .expect("read gateway access MTU");
    assert!(output.status.success());
    let link: serde_json::Value = serde_json::from_slice(&output.stdout).expect("link JSON");
    assert_eq!(link[0]["mtu"].as_u64(), Some(u64::from(SESSION_MTU)));
    eprintln!("OPC_GTPU_HOST_IPV6_PTB_CONTROL_PROVEN: one counter increment and plaintext frame");
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
    // The access-side link is narrower than the oversized packet, so a
    // decapsulation would make the host emit its own ICMPv6 PTB.
    run(
        "ip",
        &["-n", &net.ue_ns, "link", "set", "ue1", "mtu", "1300"],
    );
    assert_host_packet_too_big_control(&net);
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
    let ipv4 = session_context(device.ifindex);
    let ipv6 = GtpPdpContext {
        ms_address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 0)),
        downlink_inner_mtu: Some(
            GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(SESSION_MTU)
                .expect("canonical session MTU"),
        ),
        ..ipv4.clone()
    };
    backend.install_pdp_context(ipv4).await?;
    backend.install_pdp_context(ipv6.clone()).await?;
    assert!(matches!(
        backend
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&ipv6).expect("selector")
            ))
            .await?,
        PdpContextReadback::Present(readback)
            if readback.downlink_inner_mtu == ipv6.downlink_inner_mtu
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
        let socket = UdpSocket::bind((UE_PAA_IPV6, 5060)).expect("bind UE IPv6 receiver");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("UE receive timeout");
        socket
    });
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    let _ = plaintext_icmpv6_ptb_frames(&pgw_capture);
    let _ = plaintext_icmpv6_ptb_frames(&ue_capture);
    let host_ptb_before = host_icmpv6_packet_too_big();
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

    // 1. An oversized inner IPv6 packet: exactly one well-formed RFC 4443
    //    error in the session's uplink tunnel, and the packet itself never
    //    reaches the UE.
    let oversized = inner(OVERSIZED_PAYLOAD, REMOTE_HOST_IPV6);
    send_gpdu(LOCAL_TEID, &oversized);
    expect_too_big(port.as_ref());
    assert_in_tunnel_icmpv6_error(&receive_pgw()?, PEER_TEID, &oversized);
    expect_pgw_silent();
    assert_eq!(
        plaintext_icmpv6_ptb_frames(&pgw_capture),
        0,
        "no host-generated ICMPv6 toward the core"
    );
    assert_eq!(
        plaintext_icmpv6_ptb_frames(&ue_capture),
        0,
        "no host-generated ICMPv6 toward the UE"
    );
    assert_eq!(host_icmpv6_packet_too_big(), host_ptb_before);

    // 2. A fitting packet is decapsulated and forwarded, never signalled.
    let fitting = inner(FITTING_PAYLOAD, REMOTE_HOST_IPV6);
    send_gpdu(LOCAL_TEID, &fitting);
    let mut buffer = [0_u8; 2048];
    let (length, _) = ue.recv_from(&mut buffer)?;
    assert_eq!(&buffer[..length], &vec![0x5a; FITTING_PAYLOAD][..]);
    expect_no_event(port.as_ref());
    expect_pgw_silent();

    // 3. An unanswerable source consumes no token (RFC 4443 section 2.4):
    //    with a burst of one, the following answerable packet is still sent.
    port.set_packet_too_big_rate_limit(
        GtpuPacketTooBigRateLimit::new(1, Duration::from_secs(3_600)).expect("canonical limit"),
    )?;
    let unanswerable = inner(OVERSIZED_PAYLOAD, Ipv6Addr::UNSPECIFIED);
    send_gpdu(LOCAL_TEID, &unanswerable);
    match receive_event(port.as_ref()) {
        GtpuDownlinkEvent::PacketTooBig(too_big) => {
            assert_eq!(too_big.signal(), GtpuPacketTooBigSignal::Unsendable);
        }
        other => panic!("an unanswerable source must be unsendable, got {other:?}"),
    }
    expect_pgw_silent();
    let answerable = inner(OVERSIZED_PAYLOAD, REMOTE_HOST_IPV6);
    send_gpdu(LOCAL_TEID, &answerable);
    expect_too_big(port.as_ref());
    assert_in_tunnel_icmpv6_error(&receive_pgw()?, PEER_TEID, &answerable);
    expect_pgw_silent();
    let limited = inner(OVERSIZED_PAYLOAD, REMOTE_HOST_IPV6);
    send_gpdu(LOCAL_TEID, &limited);
    match receive_event(port.as_ref()) {
        GtpuDownlinkEvent::PacketTooBig(too_big) => {
            assert_eq!(too_big.signal(), GtpuPacketTooBigSignal::RateLimited);
        }
        other => panic!("the second error must be rate limited, got {other:?}"),
    }
    expect_pgw_silent();
    assert_eq!(
        plaintext_icmpv6_ptb_frames(&pgw_capture),
        0,
        "still no host-generated ICMPv6 toward the core"
    );
    assert_eq!(
        plaintext_icmpv6_ptb_frames(&ue_capture),
        0,
        "still no host-generated ICMPv6 toward the UE"
    );
    assert_eq!(
        host_icmpv6_packet_too_big(),
        host_ptb_before,
        "in-tunnel handling must not generate a host PTB"
    );

    drop(port);
    backend.remove_device(&device).await?;
    drop(net);
    eprintln!("OPC_GTPU_BACKEND_INNER_IPV6_PTB_PROVEN: one RFC 4443 error, no host ICMPv6");
    Ok(())
}
