//! Baseline (and reproducible RED) for downlink tunnel-MTU handling.
//!
//! An oversized DF downlink packet reaches an installed session whose access
//! path (here `ue0`, MTU 1300) is narrower than the packet. Without the
//! per-context opt-in (`GtpPdpContext::downlink_inner_mtu`), tc decapsulates
//! and the host emits its own Fragmentation Needed: from a host address,
//! unencapsulated, toward the core, quoting 548 octets of the subscriber
//! packet, while nothing reaches the tunnel. This test pins that unchanged
//! default. Copied unmodified onto `origin/main` (0bf44952) it passes with
//! the same observations, which is the RED for #1002: the opted-in test
//! `ebpf_gtpu_downlink_packet_too_big_is_signalled_in_tunnel` fails there.

use super::*;

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

fn plaintext_icmp_frames(capture: &OwnedFd) -> Vec<Vec<u8>> {
    use nix::sys::socket::{recv, MsgFlags};
    let mut frame = vec![0_u8; 65_536];
    let mut seen = Vec::new();
    while let Ok(length) = recv(capture.as_raw_fd(), &mut frame, MsgFlags::MSG_DONTWAIT) {
        if length >= 14 + 20 && frame[12..14] == [0x08, 0x00] && frame[14 + 9] == IPPROTO_ICMP {
            seen.push(frame[14..length].to_vec());
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
    let net = TestNet::provision();
    run("ip", &["link", "set", "ue0", "mtu", "1300"]);
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;
    let pgw = in_netns(&net.pgw_ns, || {
        let socket = UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(800)))
            .expect("PGW receive timeout");
        socket
    });
    let pgw_capture = packet_capture_socket(&net.pgw_ns);
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    let _ = plaintext_icmp_frames(&pgw_capture);
    let host_icmp_before = host_icmp_destination_unreachable();

    let mut inner = build_inner_udp(REMOTE_HOST, UE_PAA, 5060, 5060, &[0x51; 1_372]);
    inner[6] |= 0x40; // DF
    inner[10..12].fill(0);
    let checksum = internet_checksum(&inner[..20]);
    inner[10..12].copy_from_slice(&checksum.to_be_bytes());
    let frame = build_outer_gtpu_frame(
        main_link_address("s2bu"),
        net.pgw_link_address("s2bup"),
        &[],
        &build_gpdu(LOCAL_TEID, None, &inner),
        true,
        0,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &frame,
        RawChecksumMetadata::Unverified,
    );

    let mut buffer = [0_u8; 2048];
    let in_tunnel = pgw.recv_from(&mut buffer).is_ok();
    std::thread::sleep(Duration::from_millis(300));
    let leaked = plaintext_icmp_frames(&pgw_capture);
    let host_generated = host_icmp_destination_unreachable() - host_icmp_before;
    for icmp in &leaked {
        let ihl = usize::from(icmp[0] & 0x0f) * 4;
        eprintln!(
            "baseline: plaintext ICMP type {} code {} quoting {} octets toward the core",
            icmp[ihl],
            icmp[ihl + 1],
            icmp.len() - ihl - 8
        );
    }
    eprintln!(
        "baseline: in-tunnel error={in_tunnel}, plaintext ICMP frames on S2b-U={}, host OutDestUnreachs delta={host_generated}",
        leaked.len()
    );
    assert!(
        !in_tunnel,
        "without the opt-in nothing is sent in the tunnel"
    );
    assert_eq!(
        leaked.len(),
        1,
        "the host emits its own error toward the core"
    );
    let ihl = usize::from(leaked[0][0] & 0x0f) * 4;
    assert_eq!((leaked[0][ihl], leaked[0][ihl + 1]), (3, 4));
    assert_eq!(host_generated, 1);
    backend.remove_device(&device).await?;
    drop(net);
    eprintln!("OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_BASELINE_PROVEN: default unchanged without opt-in");
    Ok(())
}
