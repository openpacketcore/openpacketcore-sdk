//! Downlink inner IPv4 fragments through the backend-owned queue, on a real
//! kernel (#1023).
//!
//! A core gateway that fragments a large inner datagram sends each fragment
//! in its own G-PDU. A G-PDU that outgrows the S2b-U link arrives as outer
//! fragments, which the kernel reassembles for the backend-owned queue. If tc
//! decapsulated the fragments whose G-PDUs fit, one datagram would be split
//! between the consumer and the host stack. Where connection tracking is
//! active, netfilter then holds the two halves in separate reassembly queues
//! (PRE_ROUTING for the forwarded half, LOCAL_OUT for the injected half)
//! until both expire, and the datagram is lost without any error.
//!
//! The contract: for a context with a downlink inner MTU, tc hands every
//! authorized inner IPv4 fragment (More Fragments set, or a non-zero fragment
//! offset) to the backend-owned queue undecapsulated. The consumer returns it
//! as `Decapsulated` with its bearer mark, so every fragment of a datagram
//! takes one path. The test plays the gateway application: it drains
//! `try_receive_downlink` and injects each returned packet toward XFRM
//! through the production `GtpuDownlinkInjector::raw_ipv4`, including its
//! exact mark/source selection and `IP_NODEFRAG`. One connection-tracking
//! rule is active in the gateway namespace throughout.
//!
//! The consumer also stands in for the kernel's IPv4 input, which validated
//! the header of every packet that tc decapsulated. The consumer must refuse
//! malformed headers and trim octets after the total length; the production
//! injector separately validates the returned bytes before raw output.
//!
//! The fragments wait in their own backend-owned queue. A flood of them must
//! overflow only that queue: the kernel drops and counts the excess, and
//! over-MTU Don't Fragment packets and Echo are still served. The shared
//! queue keeps its priority only for a bounded run, so that sustained Echo
//! cannot keep the consumer from the fragments either.

use super::*;
use opc_gtpu_dataplane::control_port::{GtpuControlPort, GtpuControlPortError};
use opc_gtpu_dataplane::{
    GtpuDownlinkDrop, GtpuDownlinkEvent, GtpuDownlinkInjectionError, GtpuDownlinkInjector,
    GtpuDownlinkInnerMtu,
};

/// The access-side link MTU (`ue0`), left at the Ethernet default.
const ACCESS_MTU: u16 = 1_500;
/// The largest ESP tunnel-mode overhead of the test Child SAs: outer IPv4
/// 20, UDP 8, ESP 8, AES-CBC IV 16, padding 15, trailer 2, ICV 12.
const ESP_OVERHEAD: u16 = 81;
/// The session's downlink inner MTU: the access MTU minus that overhead.
const SESSION_MTU: u16 = ACCESS_MTU - ESP_OVERHEAD;
/// The MTU at which the core gateway fragments the reproduction's datagram.
const CORE_MTU: usize = 1_500;
/// 20 + 8 + 2,572 = the 2,600-octet inner datagram of the reproduction.
const LARGE_PAYLOAD: usize = 2_572;
const SIP_PORT: u16 = 5060;
/// Datagrams the consumer takes from the shared queue in a row before the
/// hand-off queues get one turn.
const SHARED_QUEUE_RUN: usize = 8;
/// Echo Requests waiting in the shared queue in the flood leg: more than two
/// full runs.
const ECHO_REQUESTS: usize = 20;
/// `ipfrag_time` in the gateway namespace while this test runs: should a
/// fragment be stranded in a host reassembly queue, it expires this soon and
/// is not left behind for the tests that follow.
const REASSEMBLY_TIMEOUT_SECONDS: u32 = 1;

fn application_payload(tag: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| tag ^ u8::try_from(index % 251).unwrap())
        .collect()
}

/// An inner UDP datagram from the remote host to the UE's SIP port.
fn datagram(tag: u8, payload_len: usize) -> Vec<u8> {
    build_inner_udp(
        REMOTE_HOST,
        UE_PAA,
        SIP_PORT,
        SIP_PORT,
        &application_payload(tag, payload_len),
    )
}

/// Fragment `datagram` as a core gateway with a `mtu`-octet link does (RFC
/// 791 section 3.2), independently of the SDK's fragmenter: every fragment
/// but the last carries the largest multiple of 8 data octets that fits.
fn core_fragments(datagram: &[u8], mtu: usize, identification: u16) -> Vec<Vec<u8>> {
    let data = &datagram[20..];
    let per_fragment = (mtu - 20) / 8 * 8;
    let count = data.len().div_ceil(per_fragment);
    assert!(count >= 2, "the datagram must need fragmentation");
    data.chunks(per_fragment)
        .enumerate()
        .map(|(index, chunk)| {
            let mut fragment = datagram[..20].to_vec();
            let total = u16::try_from(20 + chunk.len()).unwrap();
            fragment[2..4].copy_from_slice(&total.to_be_bytes());
            fragment[4..6].copy_from_slice(&identification.to_be_bytes());
            let more_fragments = if index + 1 < count { 0x2000 } else { 0 };
            let offset = u16::try_from(index * per_fragment / 8).unwrap();
            fragment[6..8].copy_from_slice(&(more_fragments | offset).to_be_bytes());
            fragment[10..12].fill(0);
            let mut header = [0_u8; 20];
            header.copy_from_slice(&fragment);
            fragment[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
            fragment.extend_from_slice(chunk);
            fragment
        })
        .collect()
}

/// The gateway namespace's IPv4 reassembly counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reassembly {
    requested: u64,
    succeeded: u64,
    failed: u64,
}

impl Reassembly {
    fn read() -> Self {
        Self {
            requested: ipv4_reassembly_stat("ReasmReqds"),
            succeeded: ipv4_reassembly_stat("ReasmOKs"),
            failed: ipv4_reassembly_stat("ReasmFails"),
        }
    }

    /// Fragments queued, datagrams reassembled and reassemblies failed since
    /// `earlier`.
    fn since(self, earlier: Self) -> (u64, u64, u64) {
        (
            self.requested - earlier.requested,
            self.succeeded - earlier.succeeded,
            self.failed - earlier.failed,
        )
    }
}

/// IPv4 reassembly queues currently held in this namespace, by local
/// reassembly or by netfilter defragmentation (`/proc/net/sockstat`).
fn ipv4_reassembly_queues() -> u64 {
    let sockstat = std::fs::read_to_string("/proc/net/sockstat").expect("read /proc/net/sockstat");
    let mut fields = sockstat
        .lines()
        .find(|line| line.starts_with("FRAG:"))
        .expect("FRAG row")
        .split_whitespace()
        .skip_while(|field| *field != "inuse");
    fields
        .nth(1)
        .and_then(|value| value.parse().ok())
        .expect("FRAG inuse counter")
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

/// The captured inner packets from the remote host to the UE, in capture
/// order.
fn wire_inner_packets(packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
    packets
        .iter()
        .filter(|packet| {
            packet[9] == IPPROTO_UDP
                && packet[12..16] == REMOTE_HOST.octets()
                && packet[16..20] == UE_PAA.octets()
        })
        .cloned()
        .collect()
}

/// SPIs of the ESP-in-UDP frames from the gateway to the UE, in order.
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
            assert_eq!(
                u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff,
                0,
                "no ESP packet is fragmented on the outer header"
            );
            assert!(packet.len() <= usize::from(ACCESS_MTU), "ESP fits the link");
            u32::from_be_bytes([packet[28], packet[29], packet[30], packet[31]])
        })
        .collect()
}

/// Serve the backend-owned consumer for `window` as the gateway
/// application's loop does, injecting every returned inner packet toward XFRM
/// with its bearer mark. Returns every event, in order.
fn serve_consumer(
    port: &dyn GtpuControlPort,
    injector: &mut GtpuDownlinkInjector,
    window: Duration,
) -> Vec<GtpuDownlinkEvent> {
    let deadline = Instant::now() + window;
    let mut events = Vec::new();
    while Instant::now() < deadline {
        match port.try_receive_downlink(4096) {
            Ok(Some(event)) => {
                match &event {
                    GtpuDownlinkEvent::Decapsulated(packet) => {
                        assert_eq!(injector.inject(packet.into()), Ok(1));
                    }
                    GtpuDownlinkEvent::Fragmented(fragmented) => {
                        assert_eq!(
                            injector.inject(fragmented.into()),
                            Ok(fragmented.fragments().len())
                        );
                    }
                    _ => {}
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

/// Drain the backend-owned consumer without injecting anything, until it has
/// stayed empty for `idle`. Returns every event, in order.
fn drain_consumer(port: &dyn GtpuControlPort, idle: Duration) -> Vec<GtpuDownlinkEvent> {
    let mut events = Vec::new();
    let mut empty_since = Instant::now();
    while empty_since.elapsed() < idle {
        match port.try_receive_downlink(4096) {
            Ok(Some(event)) => {
                events.push(event);
                empty_since = Instant::now();
            }
            Ok(None) | Err(GtpuControlPortError::Busy) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("downlink consumer receive failed: {error}"),
        }
    }
    events
}

fn with_dont_fragment(mut packet: Vec<u8>) -> Vec<u8> {
    packet[6] |= 0x40;
    packet[10..12].fill(0);
    let mut header = [0_u8; 20];
    header.copy_from_slice(&packet[..20]);
    packet[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
    packet
}

/// The receive buffer the kernel gives a new UDP socket in this namespace:
/// the budget of each backend-owned queue.
fn default_udp_receive_buffer() -> usize {
    use nix::sys::socket::{getsockopt, sockopt};
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a probe socket");
    getsockopt(&socket, sockopt::RcvBuf).expect("read the default SO_RCVBUF")
}

/// Require exactly the `expected` inner packets, in order, each returned as
/// `Decapsulated` exactly as it arrived, with the bearer mark.
fn expect_decapsulated(
    events: &[GtpuDownlinkEvent],
    expected: &[&[u8]],
    mark: Option<GtpBearerMark>,
    context: &str,
) {
    let returned: Vec<&[u8]> = events
        .iter()
        .map(|event| match event {
            GtpuDownlinkEvent::Decapsulated(packet) => {
                assert_eq!(packet.bearer_mark(), mark, "{context}: bearer mark");
                assert_eq!(packet.family(), opc_gtpu_dataplane::GtpAddressFamily::Ipv4);
                packet.inner_packet()
            }
            other => panic!("{context}: expected a Decapsulated fragment, got {other:?}"),
        })
        .collect();
    assert_eq!(
        returned.len(),
        expected.len(),
        "{context}: every inner fragment must come through the consumer"
    );
    assert_eq!(
        returned, expected,
        "{context}: exact fragments in queue order"
    );
}

/// Require the UE's socket to receive exactly `payload` from the remote host.
fn expect_ue_delivery(ue: &UdpSocket, payload: &[u8], context: &str) {
    let mut buffer = vec![0_u8; 4_096];
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
    let _fragment_limits =
        FragmentSysctlGuard::configure(REASSEMBLY_TIMEOUT_SECONDS, 4 * 1024 * 1024)?;
    // The exact reassembly counts below must be this test's own. Every test
    // of this binary shares the gateway namespace, and an earlier one may
    // have left incomplete reassembly queues behind: wait until they expire.
    let leftovers_deadline = Instant::now() + Duration::from_secs(35);
    while ipv4_reassembly_queues() != 0 {
        assert!(
            Instant::now() < leftovers_deadline,
            "reassembly queues left by an earlier test did not expire"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let net = TestNet::provision();
    // One connection-tracking rule activates netfilter's IPv4 defragmentation
    // at PRE_ROUTING and LOCAL_OUT for the whole gateway namespace, as some
    // container platforms do in every workload namespace.
    run(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            &net.nft_table,
            "forward",
            "ct",
            "state",
            "invalid",
            "counter",
        ],
    );
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    let pin_dir = net.pin_root.join("s2bu");
    let port = backend.open_gtpu_control_port(&device).await?;
    let mut injector = GtpuDownlinkInjector::raw_ipv4()?;
    // A context without a downlink inner MTU first: today's behaviour.
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;

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

    // 1. Without a downlink inner MTU nothing changes: tc decapsulates both
    //    fragments, and the consumer sees neither. This leg also proves that
    //    connection tracking is active here: a plain router never reassembles
    //    what it forwards, but netfilter's defragmentation reassembles the two
    //    fast-path fragments at PRE_ROUTING before the host forwards them.
    let baseline = datagram(0x61, 2_000);
    let fragments = core_fragments(&baseline, 1_400, 0x6100);
    assert_eq!(fragments.len(), 2);
    let reassembly_before = Reassembly::read();
    let decapsulated_before = pinned_counter(&pin_dir, COUNTER_DL_DECAP);
    send(&[
        &frame(LOCAL_TEID, &fragments[0]),
        &frame(LOCAL_TEID, &fragments[1]),
    ]);
    let events = serve_consumer(port.as_ref(), &mut injector, window);
    assert!(
        events.is_empty(),
        "no downlink inner MTU: fast path, got {events:?}"
    );
    expect_ue_delivery(
        &ue,
        &application_payload(0x61, 2_000),
        "no downlink inner MTU",
    );
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_DL_DECAP) - decapsulated_before,
        2,
        "tc decapsulates both fragments of a context without a downlink inner MTU"
    );
    assert_eq!(
        Reassembly::read().since(reassembly_before),
        (2, 1, 0),
        "connection tracking must be active: netfilter reassembles the fast-path fragments"
    );
    assert_eq!(ipv4_reassembly_queues(), 0);

    // Still without a downlink inner MTU: the smallest first fragment (28
    // octets, More Fragments set) with one flipped header checksum octet. tc
    // decapsulates it, and the kernel's IPv4 input discards it. This is the
    // behaviour the consumer must keep for the fragments it is handed.
    let mut corrupt = core_fragments(&datagram(0x69, 9), 28, 0x6900).swap_remove(0);
    assert_eq!(
        (corrupt.len(), &corrupt[6..8]),
        (28, &[0x20_u8, 0x00][..]),
        "a 28-octet first fragment"
    );
    corrupt[10] ^= 0x01;
    let _ = captured_ipv4(&ue_capture);
    let header_errors_before = ipv4_reassembly_stat("InHdrErrors");
    send(&[&frame(LOCAL_TEID, &corrupt)]);
    let events = serve_consumer(port.as_ref(), &mut injector, window);
    assert!(events.is_empty(), "fast path, got {events:?}");
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_DL_DECAP) - decapsulated_before,
        3,
        "tc decapsulates the corrupt fragment of a context without a downlink inner MTU"
    );
    assert_eq!(
        ipv4_reassembly_stat("InHdrErrors") - header_errors_before,
        1,
        "the kernel's IPv4 input discards a fragment with a wrong header checksum"
    );
    assert!(
        wire_inner_packets(&captured_ipv4(&ue_capture)).is_empty(),
        "the kernel does not forward a fragment with a wrong header checksum"
    );

    // The same session now carries a downlink inner MTU, as does a dedicated
    // bearer of the same UE.
    let mtu = GtpuDownlinkInnerMtu::new(SESSION_MTU).expect("canonical session MTU");
    let mut default_bearer = session_context(device.ifindex);
    default_bearer.downlink_inner_mtu = Some(mtu);
    backend.install_pdp_context(default_bearer).await?;
    let mut dedicated =
        dedicated_session_context(device.ifindex, MARK_A, LOCAL_TEID_A, PEER_TEID_A);
    dedicated.downlink_inner_mtu = Some(mtu);
    backend.install_pdp_context(dedicated).await?;
    let _ = captured_ipv4(&ue_capture);

    // 2. The reproduction: a 2,600-octet datagram that the core fragments at
    //    1,500. The first fragment's G-PDU (1,536 octets) outgrows the S2b-U
    //    link and arrives as two outer fragments; the last fragment's G-PDU
    //    fits. Both inner fragments must come through the consumer.
    let large = datagram(0x62, LARGE_PAYLOAD);
    assert_eq!(large.len(), 2_600);
    let fragments = core_fragments(&large, CORE_MTU, 0x6200);
    assert_eq!(
        fragments.iter().map(Vec::len).collect::<Vec<_>>(),
        [1_500, 1_120]
    );
    let hand_off_start = Reassembly::read();
    let decapsulated_before = pinned_counter(&pin_dir, COUNTER_DL_DECAP);
    let (head, tail) = build_outer_fragments(&frame(LOCAL_TEID, &fragments[0]), 1_000, 0x6201);
    send(&[&head, &tail, &frame(LOCAL_TEID, &fragments[1])]);
    let events = serve_consumer(port.as_ref(), &mut injector, window);
    let mut buffer = vec![0_u8; 4_096];
    let delivered = ue.recv_from(&mut buffer);
    eprintln!(
        "inner fragment hand-off: consumer events={events:?}, delivered to the UE={}, tc decapsulations={}, gateway reassembly (fragments, datagrams, failures)={:?}",
        delivered.is_ok(),
        pinned_counter(&pin_dir, COUNTER_DL_DECAP) - decapsulated_before,
        Reassembly::read().since(hand_off_start)
    );
    // The first fragment exceeds the session MTU without Don't Fragment set.
    // It is returned as it arrived; fragmenting it to the session MTU is
    // part (ii) of #1023.
    expect_decapsulated(
        &events,
        &[&fragments[0], &fragments[1]],
        None,
        "outer-fragmented first fragment",
    );
    let (length, source) = delivered
        .map_err(|_| "the 2,600-octet datagram must reach the UE, not be stranded in the host")?;
    assert_eq!(source, SocketAddr::from((REMOTE_HOST, SIP_PORT)));
    assert_eq!(
        &buffer[..length],
        application_payload(0x62, LARGE_PAYLOAD).as_slice()
    );
    assert_eq!(
        wire_inner_packets(&captured_ipv4(&ue_capture)),
        fragments,
        "every inner fragment leaves as its own packet, exactly as returned"
    );
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_DL_DECAP),
        decapsulated_before,
        "tc decapsulates no inner fragment of a context with a downlink inner MTU"
    );
    assert_eq!(
        Reassembly::read().since(hand_off_start),
        (2, 1, 0),
        "the host reassembles the two outer fragments and no inner fragment"
    );
    assert_eq!(
        ipv4_reassembly_queues(),
        0,
        "no fragment may be held in a host reassembly queue"
    );

    // 3. Three fragments whose G-PDUs all fit the S2b-U link, sent in reverse
    //    order: offset only, More Fragments with an offset, More Fragments
    //    only. Each is handed off on its own; none reaches a host reassembly
    //    queue.
    let reordered = datagram(0x63, 3_300);
    let fragments = core_fragments(&reordered, 1_300, 0x6300);
    assert_eq!(
        fragments.iter().map(Vec::len).collect::<Vec<_>>(),
        [1_300, 1_300, 768]
    );
    let reassembly_before = Reassembly::read();
    send(&[
        &frame(LOCAL_TEID, &fragments[2]),
        &frame(LOCAL_TEID, &fragments[1]),
        &frame(LOCAL_TEID, &fragments[0]),
    ]);
    expect_decapsulated(
        &serve_consumer(port.as_ref(), &mut injector, window),
        &[&fragments[2], &fragments[1], &fragments[0]],
        None,
        "reordered fragments",
    );
    expect_ue_delivery(
        &ue,
        &application_payload(0x63, 3_300),
        "reordered fragments",
    );
    assert_eq!(
        Reassembly::read().since(reassembly_before),
        (0, 0, 0),
        "no inner fragment enters a host reassembly queue"
    );
    assert_eq!(ipv4_reassembly_queues(), 0);
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_DL_DECAP),
        decapsulated_before
    );

    // 3b. The same corrupt first fragment, now handed to the consumer. It
    //     must be dropped as the kernel dropped it above. Returned as
    //     `Decapsulated`, a bare IP_HDRINCL send would repair and forward it.
    //     The production injector validates too, but the receive contract
    //     must independently refuse invalid checksums and truncated lengths.
    let mut truncated = core_fragments(&datagram(0x6b, 9), 28, 0x6b00).swap_remove(0);
    truncated[2..4].copy_from_slice(&29_u16.to_be_bytes());
    truncated[10..12].fill(0);
    let mut header = [0_u8; 20];
    header.copy_from_slice(&truncated[..20]);
    truncated[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
    assert_eq!(truncated.len(), 28);
    let _ = captured_ipv4(&ue_capture);
    send(&[&frame(LOCAL_TEID, &corrupt), &frame(LOCAL_TEID, &truncated)]);
    let events = serve_consumer(port.as_ref(), &mut injector, window);
    assert!(
        matches!(
            &events[..],
            [
                GtpuDownlinkEvent::Dropped(GtpuDownlinkDrop::Malformed),
                GtpuDownlinkEvent::Dropped(GtpuDownlinkDrop::Malformed)
            ]
        ),
        "fragments with a wrong header checksum and an inconsistent total length: {events:?}"
    );
    assert!(
        wire_inner_packets(&captured_ipv4(&ue_capture)).is_empty(),
        "a fragment with an invalid inner header must not be repaired and sent"
    );

    // 3c. Octets after the inner total length are not part of the datagram.
    //     The kernel's IPv4 input trims them; a bare IP_HDRINCL send would
    //     extend the total length over them. Both fragments come back trimmed,
    //     and the UE reassembles the exact datagram.
    let padded = datagram(0x6a, 2_000);
    let fragments = core_fragments(&padded, 1_300, 0x6a00);
    assert_eq!(fragments.len(), 2);
    let carried: Vec<Vec<u8>> = fragments
        .iter()
        .map(|fragment| {
            let mut carried = fragment.clone();
            carried.extend_from_slice(&[0xee; 6]);
            carried
        })
        .collect();
    send(&[
        &frame(LOCAL_TEID, &carried[0]),
        &frame(LOCAL_TEID, &carried[1]),
    ]);
    expect_decapsulated(
        &serve_consumer(port.as_ref(), &mut injector, window),
        &[&fragments[0], &fragments[1]],
        None,
        "octets after the total length",
    );
    expect_ue_delivery(
        &ue,
        &application_payload(0x6a, 2_000),
        "octets after the total length",
    );
    assert_eq!(
        wire_inner_packets(&captured_ipv4(&ue_capture)),
        fragments,
        "the fragments leave without the trailing octets"
    );
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_DL_DECAP),
        decapsulated_before
    );

    // 4. A datagram that is not a fragment stays on the tc fast path.
    send(&[&frame(LOCAL_TEID, &datagram(0x64, 1_200))]);
    let events = serve_consumer(port.as_ref(), &mut injector, window);
    assert!(events.is_empty(), "fast-path packet: {events:?}");
    expect_ue_delivery(&ue, &application_payload(0x64, 1_200), "not a fragment");
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_DL_DECAP) - decapsulated_before,
        1
    );

    // Nothing was left behind in a host reassembly queue: past the
    // reassembly timeout, none is held and no reassembly has failed.
    std::thread::sleep(Duration::from_millis(
        u64::from(REASSEMBLY_TIMEOUT_SECONDS) * 1_000 + 500,
    ));
    assert_eq!(ipv4_reassembly_queues(), 0);
    assert_eq!(
        ipv4_reassembly_stat("ReasmFails"),
        hand_off_start.failed,
        "no fragment may be stranded in a host reassembly queue"
    );

    // 5. A dedicated bearer through its real ESP Child SA: each fragment is
    //    returned with the bearer mark, leaves as its own ESP packet under
    //    the dedicated SPI, and the UE decrypts and reassembles the datagram.
    let _epdg_nat_t_socket = nat_t_socket(EPDG_SWU_IP);
    let _ue_nat_t_socket = in_netns(&net.ue_ns, || nat_t_socket(UE_SWU_IP));
    install_real_marked_outbound_xfrm_for_ue_application(&net.ue_ns).await?;
    let _ = captured_ipv4(&ue_capture);
    let dedicated_case = datagram(0x65, 2_000);
    let fragments = core_fragments(&dedicated_case, 1_300, 0x6500);
    assert_eq!(fragments.len(), 2);
    send(&[
        &frame(LOCAL_TEID_A, &fragments[0]),
        &frame(LOCAL_TEID_A, &fragments[1]),
    ]);
    expect_decapsulated(
        &serve_consumer(port.as_ref(), &mut injector, window),
        &[&fragments[0], &fragments[1]],
        GtpBearerMark::new(MARK_A),
        "dedicated bearer",
    );
    expect_ue_delivery(&ue, &application_payload(0x65, 2_000), "dedicated bearer");
    assert_eq!(
        esp_spis(&captured_ipv4(&ue_capture)),
        [OUTBOUND_SPI_A, OUTBOUND_SPI_A],
        "one dedicated-SA ESP packet per inner fragment"
    );

    // 6. A datagram sent straight to the inner-fragment queue is never
    //    exposed as a control or unknown-tunnel event bound to that queue: an
    //    Echo Request and a G-PDU for no tunnel are both dropped.
    let peer = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, 0)).expect("bind PGW sender")
    });
    let queue = (
        EPDG_S2BU_IP,
        opc_gtpu_ebpf_common::GTPU_INNER_FRAGMENT_QUEUE_PORT,
    );
    let echo = [0x32, 1, 0, 4, 0, 0, 0, 0, 0x5e, 0x11, 0, 0];
    peer.send_to(&echo, queue)?;
    peer.send_to(&build_gpdu(0x7777_0001, None, &datagram(0x66, 64)), queue)?;
    let events = drain_consumer(port.as_ref(), window);
    assert!(
        matches!(
            &events[..],
            [
                GtpuDownlinkEvent::Dropped(GtpuDownlinkDrop::StateUnavailable),
                GtpuDownlinkEvent::Dropped(GtpuDownlinkDrop::StateUnavailable)
            ]
        ),
        "datagrams sent to the inner-fragment queue: {events:?}"
    );

    // So far no hand-off has met an unbound queue: no plaintext ICMP crossed
    // the core. The capture cannot hold the flood below, so from here on the
    // host's own Destination Unreachable counter is the evidence.
    core_packets.extend(captured_ipv4(&pgw_capture));
    assert_eq!(plaintext_icmp(&core_packets), 0, "no ICMP toward the core");

    // 7. The queue budget and the service order. With nobody draining, a
    //    flood of inner fragments larger than the queue's receive buffer
    //    arrives, then three over-MTU Don't Fragment datagrams and twenty
    //    Echo Requests. The flood overflows only its own queue: the kernel
    //    keeps at most one receive buffer of fragments and counts the rest
    //    as dropped. Echo is served first, but only for a run of eight: then
    //    one hand-off datagram is served, although Echo is still waiting.
    //    The hand-off turns alternate between over-MTU packets and
    //    fragments. No Echo and no over-MTU packet is lost.
    let receive_buffer = default_udp_receive_buffer();
    let flood_fragment = core_fragments(&datagram(0x67, 2_600), 1_400, 0x6700).swap_remove(0);
    assert_eq!(flood_fragment.len(), 1_396);
    // Every datagram is charged at least its own length, so this many cannot
    // fit one receive buffer.
    let flood = receive_buffer / 1_024 + 64;
    send_raw_gtpu_frames(
        &net.pgw_ns,
        "s2bup",
        &vec![frame(LOCAL_TEID, &flood_fragment); flood],
    );
    let oversized: Vec<Vec<u8>> = (0..3_u8)
        .map(|index| with_dont_fragment(datagram(0x68 + index, 1_422)))
        .collect();
    for packet in &oversized {
        assert!(packet.len() > usize::from(SESSION_MTU));
        send(&[&frame(LOCAL_TEID, packet)]);
    }
    for _ in 0..ECHO_REQUESTS {
        peer.send_to(&echo, (EPDG_S2BU_IP, GTPU_PORT))?;
    }
    std::thread::sleep(Duration::from_millis(200));
    let events = drain_consumer(port.as_ref(), window);
    // The shared queue is served first, for one run. Then the hand-off
    // queues get one turn while Echo Requests are still waiting, and so on:
    // sustained input on the shared queue cannot starve the hand-offs.
    let control: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, event)| match event {
            GtpuDownlinkEvent::Control(event) => {
                assert_eq!(event.bytes(), echo);
                true
            }
            _ => false,
        })
        .map(|(index, _)| index)
        .collect();
    let expected_control: Vec<usize> = (0..ECHO_REQUESTS)
        .map(|echo| echo + echo / SHARED_QUEUE_RUN)
        .collect();
    assert_eq!(
        control, expected_control,
        "a run of {SHARED_QUEUE_RUN} from the shared queue, then one hand-off turn; no Echo lost"
    );
    let fragmented: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, event)| matches!(event, GtpuDownlinkEvent::Fragmented(_)))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        fragmented.len(),
        oversized.len(),
        "the fragment flood must not cost the over-MTU path a packet"
    );
    // Both hand-off queues hold a backlog, so their turns alternate: three
    // over-MTU packets and three fragments, whichever queue has the first
    // turn. Neither class waits for the other's backlog.
    let turns: Vec<bool> = events
        .iter()
        .filter(|event| !matches!(event, GtpuDownlinkEvent::Control(_)))
        .take(6)
        .map(|event| matches!(event, GtpuDownlinkEvent::Fragmented(_)))
        .collect();
    assert!(
        turns == [true, false, true, false, true, false]
            || turns == [false, true, false, true, false, true],
        "the hand-off queues must be served in turn, over-MTU packets at {fragmented:?}"
    );
    let accepted = events
        .iter()
        .filter(|event| match event {
            GtpuDownlinkEvent::Decapsulated(packet) => {
                assert_eq!(packet.inner_packet(), flood_fragment.as_slice());
                true
            }
            _ => false,
        })
        .count();
    assert_eq!(events.len(), ECHO_REQUESTS + oversized.len() + accepted);
    assert!(
        (1..flood).contains(&accepted),
        "the flood must overflow the inner-fragment queue: {accepted} of {flood} accepted"
    );
    assert!(
        accepted <= receive_buffer / flood_fragment.len() + 1,
        "the queue holds at most its receive buffer: {accepted} datagrams in {receive_buffer} octets"
    );
    // The kernel reports its cumulative drop count with a received datagram:
    // receive one more fragment to read the flood's.
    send(&[&frame(LOCAL_TEID, &flood_fragment)]);
    assert!(matches!(
        &drain_consumer(port.as_ref(), window)[..],
        [GtpuDownlinkEvent::Decapsulated(_)]
    ));
    let counters = port.downlink_counters()?;
    eprintln!(
        "inner fragment queue budget: receive buffer={receive_buffer} octets, flood={flood} fragments, accepted={accepted}, kernel drops={}",
        counters.inner_fragment_queue_drops
    );
    assert_eq!(
        counters.inner_fragment_queue_drops,
        u64::try_from(flood - accepted)?,
        "every fragment beyond the queue's budget is dropped by the kernel and counted"
    );
    assert_eq!(counters.packet_too_big_queue_drops, 0);
    assert_eq!(counters.shared_queue_drops, 0);

    // No hand-off met an unbound queue, and an overflowing queue is silent:
    // over the whole test the host generated no Destination Unreachable.
    assert_eq!(
        host_icmp_destination_unreachable(),
        host_icmp_before,
        "the host must not answer a hand-off with Port Unreachable"
    );
    let returned = u64::try_from(9 + accepted + 1)?;
    assert_eq!(counters.decapsulated, returned);
    assert_eq!(
        counters.decapsulated_inner_fragments, returned,
        "every decapsulated packet of this test was an inner fragment"
    );
    assert_eq!(counters.inner_fragmented, 3);
    assert_eq!(counters.inner_fragments, 6);
    assert_eq!(counters.inner_fragment_rate_limited, 0);
    assert_eq!(counters.state_unavailable, 2);
    assert_eq!(counters.packet_too_big, 0);
    assert_eq!(
        counters.malformed, 2,
        "the fragments with a wrong header checksum and an inconsistent total length"
    );
    assert_eq!(counters.binding_drops, 0);

    // 8. An origin-fragmented zero-ID datagram with DF on its pieces. The
    // over-MTU first piece becomes a real Fragmented outcome with DF clear;
    // its fitting sibling remains a separate Decapsulated outcome with DF.
    // Rewriting only the batch could never repair this datagram. Refuse it
    // before sending and preserve zero on the separately accepted DF sibling.
    let origin = datagram(0x6c, LARGE_PAYLOAD);
    let zero_fragments: Vec<_> = core_fragments(&origin, CORE_MTU, 0)
        .into_iter()
        .map(with_dont_fragment)
        .collect();
    assert_eq!(zero_fragments.len(), 2);
    let (head, tail) =
        build_outer_fragments(&frame(LOCAL_TEID_A, &zero_fragments[0]), 1_000, 0x6c01);
    let _ = captured_ipv4(&ue_capture);
    send(&[&head, &tail, &frame(LOCAL_TEID_A, &zero_fragments[1])]);
    let outcomes = drain_consumer(port.as_ref(), window);
    assert_eq!(outcomes.len(), 2);
    let batch = outcomes
        .iter()
        .find_map(|event| match event {
            GtpuDownlinkEvent::Fragmented(batch) => Some(batch),
            _ => None,
        })
        .expect("over-MTU DF origin fragment must be re-fragmented");
    let sibling = outcomes
        .iter()
        .find_map(|event| match event {
            GtpuDownlinkEvent::Decapsulated(packet) => Some(packet),
            _ => None,
        })
        .expect("fitting DF sibling must remain independent");
    assert_eq!(batch.fragments().len(), 2);
    for fragment in batch.fragments() {
        assert_eq!(&fragment[4..6], &[0, 0]);
        assert_eq!(fragment[6] & 0x60, 0x20, "DF cleared, MF retained");
    }
    let refusals = injector.counters().zero_identification_refusals;
    assert_eq!(
        injector.inject(batch.into()),
        Err(GtpuDownlinkInjectionError::ZeroIdentificationFragment)
    );
    assert_eq!(
        injector.counters().zero_identification_refusals,
        refusals + 1
    );
    assert!(
        captured_ipv4(&ue_capture).is_empty(),
        "refused batch emitted no packet"
    );
    assert_eq!(sibling.inner_packet(), zero_fragments[1]);
    assert_eq!(injector.inject(sibling.into()), Ok(1));
    let mut missing = [0_u8; 4_096];
    assert!(
        ue.recv_from(&mut missing).is_err(),
        "the refused datagram is lost"
    );
    let wire = captured_ipv4(&ue_capture);
    assert_eq!(esp_spis(&wire), [OUTBOUND_SPI_A]);
    assert_eq!(wire_inner_packets(&wire), [zero_fragments[1].clone()]);

    drop(port);
    backend.remove_device(&device).await?;
    drop(net);
    eprintln!(
        "OPC_GTPU_DOWNLINK_INNER_FRAGMENT_HAND_OFF_PROVEN: real receive outcomes use the production injector with exact marks and bytes; outer-fragmented, reordered and dedicated fragments reassemble with conntrack; malformed headers are refused and trailing bytes trimmed; queue flood is isolated; zero-ID origin-fragment batch is refused before sending"
    );
    Ok(())
}
