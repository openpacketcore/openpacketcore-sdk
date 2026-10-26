//! A hand-off from tc needs a bound consumer, on a real kernel (#1019).
//!
//! tc leaves some downlink datagrams to a UDP socket on the gateway instead
//! of decapsulating them:
//!
//! - an over-MTU Don't Fragment packet and an inner fragment of a context
//!   with a downlink inner MTU, steered to UDP/2153 and UDP/2154;
//! - a G-PDU for no tunnel, or with a required unknown extension, left on
//!   UDP/2152;
//! - a G-PDU that is fragmented on the outer path, reassembled by the kernel
//!   for UDP/2152.
//!
//! The backend binds those sockets when the application first opens the
//! control port, and they close with the process. While none is bound the
//! kernel would answer each such datagram with ICMP Port Unreachable toward
//! the core, quoting up to 548 octets of it: the outer headers and the start
//! of the subscriber's inner packet, in plaintext.
//!
//! The contract: tc passes such a datagram on only while a socket is bound
//! for it. Otherwise it drops the datagram and counts the drop, and the host
//! sends nothing toward the core. That holds for a fresh attachment whose
//! port was never opened, while the process is down, and after a restart
//! until the port is open again.
//!
//! An outer-fragmented datagram is judged by its first fragment, the only
//! one that carries the UDP header. tc does not drop that fragment, which
//! would strand the others in the host's reassembly queue: it counts the
//! datagram and marks it, so that the host reassembles it and UDP input
//! discards it unanswered.

use super::*;
use opc_gtpu_dataplane::control_port::{GtpuControlPort, GtpuControlPortError};
use opc_gtpu_dataplane::{GtpuDownlinkEvent, GtpuDownlinkInnerMtu};

pub(super) const SESSION_MTU: u16 = 1_300;
/// 20 + 8 + 1,372 = a 1,400-octet inner packet, above the session MTU.
const OVERSIZED_PAYLOAD: usize = 1_372;
const FITTING_PAYLOAD: usize = 1_200;
const UNKNOWN_TEID: u32 = 0xdead_beef;
/// An extension type that this endpoint must understand and does not.
pub(super) const REQUIRED_UNKNOWN_EXTENSION: u8 = 0xc1;
/// How long a datagram may take from the sender to tc's verdict.
const VERDICT_DEADLINE: Duration = Duration::from_secs(5);
/// How long an ICMP error that the host has generated may take to reach the
/// capture.
const SETTLE: Duration = Duration::from_millis(100);

fn refresh_inner_checksum(mut packet: Vec<u8>) -> Vec<u8> {
    packet[10..12].fill(0);
    let mut header = [0_u8; 20];
    header.copy_from_slice(&packet[..20]);
    packet[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
    packet
}

fn inner(tag: u8, payload_len: usize) -> Vec<u8> {
    build_inner_udp(REMOTE_HOST, UE_PAA, 5060, 5060, &vec![tag; payload_len])
}

/// An inner packet above the session MTU with Don't Fragment set.
pub(super) fn oversized(tag: u8) -> Vec<u8> {
    let mut packet = inner(tag, OVERSIZED_PAYLOAD);
    packet[6] |= 0x40;
    refresh_inner_checksum(packet)
}

/// A first inner fragment: More Fragments set, offset zero.
pub(super) fn inner_fragment(tag: u8) -> Vec<u8> {
    let mut packet = inner(tag, 64);
    packet[6] |= 0x20;
    refresh_inner_checksum(packet)
}

pub(super) fn host_counter(path: &str, row: &str, name: &str) -> u64 {
    let table =
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    let mut rows = table.lines().filter(|line| line.starts_with(row));
    let header = rows.next().expect("counter header row");
    let values = rows.next().expect("counter value row");
    header
        .split_whitespace()
        .zip(values.split_whitespace())
        .find(|(column, _)| *column == name)
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or_else(|| panic!("{name} counter"))
}

/// Host-generated ICMP Destination Unreachable messages in this netns.
pub(super) fn host_icmp_destination_unreachable() -> u64 {
    host_counter("/proc/net/snmp", "Icmp:", "OutDestUnreachs")
}

/// Host-generated ICMP Time Exceeded messages in this netns.
pub(super) fn host_icmp_time_exceeded() -> u64 {
    host_counter("/proc/net/snmp", "Icmp:", "OutTimeExcds")
}

/// UDP datagrams that UDP input discarded in this netns.
pub(super) fn host_udp_input_errors() -> u64 {
    host_counter("/proc/net/snmp", "Udp:", "InErrors")
}

/// IPv4 datagrams that this netns reassembled.
pub(super) fn host_reassembled() -> u64 {
    host_counter("/proc/net/snmp", "Ip:", "ReasmOKs")
}

/// Host-generated ICMPv6 Destination Unreachable messages in this netns.
pub(super) fn host_icmpv6_destination_unreachable() -> u64 {
    std::fs::read_to_string("/proc/net/snmp6")
        .expect("read /proc/net/snmp6")
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("Icmp6OutDestUnreachs"))
                .then(|| fields.next().and_then(|value| value.parse().ok()))
                .flatten()
        })
        .expect("Icmp6OutDestUnreachs counter")
}

/// IPv4 reassembly queues currently held in this namespace.
pub(super) fn ipv4_reassembly_queues() -> u64 {
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

/// Drain the core-side capture; count the ICMP errors the gateway sent
/// toward the core: every IPv4 ICMP message, and ICMPv6 Destination
/// Unreachable (Neighbor Discovery is ICMPv6 too and is not an error).
pub(super) fn icmp_errors_toward_core(capture: &OwnedFd) -> usize {
    use nix::sys::socket::{recv, MsgFlags};
    let mut frame = vec![0_u8; 65_536];
    let mut errors = 0;
    while let Ok(length) = recv(capture.as_raw_fd(), &mut frame, MsgFlags::MSG_DONTWAIT) {
        let ipv4_icmp = length >= ETH_HDR_LEN + 20
            && frame[12..14] == [0x08, 0x00]
            && frame[ETH_HDR_LEN + 9] == IPPROTO_ICMP;
        let ipv6_unreachable = length > ETH_HDR_LEN + 40
            && frame[12..14] == [0x86, 0xdd]
            && frame[ETH_HDR_LEN + 6] == IPPROTO_ICMPV6
            && frame[ETH_HDR_LEN + 40] == 1;
        if ipv4_icmp || ipv6_unreachable {
            errors += 1;
        }
    }
    errors
}

/// Drain the backend-owned consumer until it has stayed empty for `idle`.
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

/// What the host must not have done, and what tc must have counted.
struct Silence<'a> {
    capture: &'a OwnedFd,
    pin_dir: &'a Path,
    destination_unreachable: u64,
    destination_unreachable_v6: u64,
    time_exceeded: u64,
    udp_input_errors: u64,
    reassembled: u64,
    drops: u64,
}

impl<'a> Silence<'a> {
    fn begin(capture: &'a OwnedFd, pin_dir: &'a Path, drops: u64) -> Self {
        let _ = icmp_errors_toward_core(capture);
        Self {
            capture,
            pin_dir,
            destination_unreachable: host_icmp_destination_unreachable(),
            destination_unreachable_v6: host_icmpv6_destination_unreachable(),
            time_exceeded: host_icmp_time_exceeded(),
            udp_input_errors: host_udp_input_errors(),
            reassembled: host_reassembled(),
            drops,
        }
    }

    /// Wait until tc has counted exactly `dropped` further datagrams as
    /// dropped for a missing consumer, then require that the gateway sent no
    /// ICMP error toward the core since `begin`.
    ///
    /// `fragmented` of those datagrams arrived as outer fragments. The host
    /// must have reassembled each of them, UDP input must have discarded it,
    /// and no fragment may be left in a reassembly queue. `delivered` further
    /// outer-fragmented datagrams were reassembled for a bound socket.
    ///
    /// The count is tc's verdict on each datagram. Once it is reached, none
    /// of them is still on its way to the host, and the short wait after it
    /// only covers the transmission of an error the host had generated.
    fn expect_fragmented(&mut self, dropped: u64, fragmented: u64, delivered: u64, context: &str) {
        self.drops += dropped;
        self.udp_input_errors += fragmented;
        self.reassembled += fragmented + delivered;
        let deadline = Instant::now() + VERDICT_DEADLINE;
        loop {
            let counted = pinned_counter(self.pin_dir, COUNTER_DL_MISSING_CONSUMER);
            let discarded = host_udp_input_errors();
            assert!(
                counted <= self.drops,
                "{context}: tc counted {counted} missing-consumer drops, expected {}",
                self.drops
            );
            assert!(
                discarded <= self.udp_input_errors,
                "{context}: UDP input discarded {discarded} datagrams, expected {}",
                self.udp_input_errors
            );
            if counted == self.drops && discarded == self.udp_input_errors {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{context}: tc counted {counted} missing-consumer drops, expected {}; UDP input discarded {discarded} datagrams, expected {}",
                self.drops,
                self.udp_input_errors
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(SETTLE);
        assert_eq!(
            icmp_errors_toward_core(self.capture),
            0,
            "{context}: the gateway sent an ICMP error toward the core"
        );
        assert_eq!(
            host_icmp_destination_unreachable(),
            self.destination_unreachable,
            "{context}: the host generated a Destination Unreachable"
        );
        assert_eq!(
            host_icmpv6_destination_unreachable(),
            self.destination_unreachable_v6,
            "{context}: the host generated an ICMPv6 Destination Unreachable"
        );
        assert_eq!(
            host_icmp_time_exceeded(),
            self.time_exceeded,
            "{context}: the host generated a Time Exceeded"
        );
        assert_eq!(
            pinned_counter(self.pin_dir, COUNTER_DL_MISSING_CONSUMER),
            self.drops,
            "{context}: missing-consumer drops"
        );
        assert_eq!(
            host_udp_input_errors(),
            self.udp_input_errors,
            "{context}: datagrams discarded by UDP input"
        );
        assert_eq!(
            host_reassembled(),
            self.reassembled,
            "{context}: datagrams reassembled by the host"
        );
        assert_eq!(
            ipv4_reassembly_queues(),
            0,
            "{context}: a fragment is stranded in a reassembly queue"
        );
    }

    /// As [`Self::expect_fragmented`], for datagrams that are not fragmented
    /// on the outer path.
    fn expect(&mut self, dropped: u64, context: &str) {
        self.expect_fragmented(dropped, 0, 0, context);
    }
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
    // The reassembly counts below must be this test's own. Every test of
    // this binary shares the gateway namespace, and an earlier one may have
    // left incomplete reassembly queues behind: wait until they expire.
    let leftovers_deadline = Instant::now() + Duration::from_secs(35);
    while ipv4_reassembly_queues() != 0 {
        assert!(
            Instant::now() < leftovers_deadline,
            "reassembly queues left by an earlier test did not expire"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let ordinary_drops = ordinary_attachment().await?;
    let grouped_drops = grouped_attachment_over_ipv6().await?;
    eprintln!(
        "OPC_GTPU_DOWNLINK_HAND_OFF_CONSUMER_PROVEN: no ICMP toward the core and {ordinary_drops} + {grouped_drops} counted drops while no consumer is bound (never opened, another port bound, process down, adopted and not yet reopened; IPv4 and IPv6 outer); every hand-off delivered once one is, to a SO_REUSEPORT socket too"
    );
    Ok(())
}

/// An ordinary IPv4 attachment with one context that carries a downlink
/// inner MTU. Returns the missing-consumer drops it counted.
async fn ordinary_attachment() -> Result<u64, Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };
    let backend = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    let pin_dir = net.pin_root.join("s2bu");
    let mtu = GtpuDownlinkInnerMtu::new(SESSION_MTU).expect("canonical session MTU");
    let mut context = session_context(device.ifindex);
    context.downlink_inner_mtu = Some(mtu);
    backend.install_pdp_context(context.clone()).await?;

    let pgw_capture = packet_capture_socket(&net.pgw_ns);
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");
    let frame =
        |gpdu: &[u8]| build_outer_gtpu_frame(destination_mac, source_mac, &[], gpdu, true, 0);
    let send = |frame: &[u8]| {
        send_raw_gtpu_frame(&net.pgw_ns, "s2bup", frame, RawChecksumMetadata::Unverified);
    };
    // The five hand-offs, one datagram each. `tag` keeps their payloads
    // apart.
    let over_mtu = |tag: u8| frame(&build_gpdu(LOCAL_TEID, None, &oversized(tag)));
    let fragment = |tag: u8| frame(&build_gpdu(LOCAL_TEID, None, &inner_fragment(tag)));
    let unknown_tunnel = |tag: u8| frame(&build_gpdu(UNKNOWN_TEID, None, &inner(tag, 64)));
    let required_extension = |tag: u8| {
        let mut gpdu = build_extension_gpdu(LOCAL_TEID, &inner(tag, 64));
        gpdu[11] = REQUIRED_UNKNOWN_EXTENSION;
        frame(&gpdu)
    };
    let outer_fragments = |tag: u8, identification: u16| {
        build_outer_fragments(
            &frame(&build_gpdu(LOCAL_TEID, None, &inner(tag, FITTING_PAYLOAD))),
            1_000,
            identification,
        )
    };
    // Both fragments of a datagram leave in one burst, in the given order.
    let send_fragments = |first: Vec<u8>, second: Vec<u8>| {
        send_raw_gtpu_frames(&net.pgw_ns, "s2bup", &[first, second]);
    };
    let send_all = |tag: u8, identification: u16| {
        send(&over_mtu(tag));
        send(&fragment(tag + 1));
        send(&unknown_tunnel(tag + 2));
        send(&required_extension(tag + 3));
        let (head, tail) = outer_fragments(tag + 4, identification);
        send_fragments(head, tail);
    };
    let mut silence = Silence::begin(&pgw_capture, &pin_dir, 0);

    // 1. A fresh attachment whose control port was never opened: nothing is
    //    bound on UDP/2152, UDP/2153 or UDP/2154. Every hand-off is dropped
    //    and counted, and the host answers none of them.
    send(&over_mtu(0x10));
    silence.expect(1, "over-MTU Don't Fragment packet, port never opened");
    send(&fragment(0x11));
    silence.expect(1, "inner fragment, port never opened");
    send(&unknown_tunnel(0x12));
    silence.expect(1, "G-PDU for no tunnel, port never opened");
    send(&required_extension(0x13));
    silence.expect(1, "required unknown extension, port never opened");
    //    An outer-fragmented G-PDU: tc counts it at its first fragment, the
    //    only one that carries the UDP header, and marks that fragment. The
    //    host reassembles the datagram, and UDP input discards it without
    //    looking for a socket. No fragment is left in a reassembly queue.
    let (head, tail) = outer_fragments(0x14, 0x1900);
    send_fragments(head, tail);
    silence.expect_fragmented(1, 1, 0, "outer-fragmented G-PDU, port never opened");
    //    The same when the first fragment arrives last.
    let (head, tail) = outer_fragments(0x15, 0x1901);
    send_fragments(tail, head);
    silence.expect_fragmented(
        1,
        1,
        0,
        "outer-fragmented G-PDU in reverse order, port never opened",
    );
    // The backend reports the same counter, and counts the G-PDU for no
    // tunnel as a lookup miss as well.
    let counters = backend.datapath_snapshot(&device).await?.counters;
    assert_eq!(counters.downlink_missing_consumer, silence.drops);
    assert_eq!(counters.downlink_unknown_teid, 1);
    assert_eq!(counters.downlink_decapsulated, 0);

    // 2. The check is per datagram: an application's own socket on UDP/2152
    //    receives the G-PDU for no tunnel, while the over-MTU packet still
    //    has no socket on UDP/2153.
    {
        let application = UdpSocket::bind((EPDG_S2BU_IP, GTPU_PORT))?;
        application.set_read_timeout(Some(Duration::from_secs(2)))?;
        let unknown = build_gpdu(UNKNOWN_TEID, None, &inner(0x20, 64));
        send(&frame(&unknown));
        let mut buffer = [0_u8; 2048];
        let (length, source) = application.recv_from(&mut buffer)?;
        assert_eq!(&buffer[..length], unknown);
        assert_eq!(source, SocketAddr::from((PGW_IP, GTPU_PORT)));
        send(&over_mtu(0x21));
        silence.expect(1, "over-MTU packet while only UDP/2152 is bound");
        //    The same socket receives an outer-fragmented G-PDU. It is bound
        //    to no device: a kernel before Linux 6.5 cannot tell tc whether
        //    the interface belongs to a VRF, where such a socket would not
        //    be eligible, so tc leaves the datagram to the stack's own
        //    lookup. Outside a VRF that lookup delivers it.
        let fragmented = build_gpdu(UNKNOWN_TEID, None, &inner(0x23, FITTING_PAYLOAD));
        let (head, tail) = build_outer_fragments(&frame(&fragmented), 1_000, 0x1906);
        send_fragments(head, tail);
        let (length, source) = application.recv_from(&mut buffer)?;
        assert_eq!(&buffer[..length], fragmented);
        assert_eq!(source, SocketAddr::from((PGW_IP, GTPU_PORT)));
        silence.expect_fragmented(
            0,
            0,
            1,
            "outer-fragmented G-PDU while an application socket is bound",
        );
    }
    //    An application socket with SO_REUSEPORT is bound all the same. A
    //    kernel before Linux 6.6 cannot assign such a socket to a packet;
    //    tc then leaves the delivery to the stack, which finds it.
    {
        use nix::sys::socket::{
            bind, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, SockaddrIn,
        };
        let descriptor = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )?;
        setsockopt(&descriptor, sockopt::ReusePort, &true)?;
        bind(
            descriptor.as_raw_fd(),
            &SockaddrIn::from(std::net::SocketAddrV4::new(EPDG_S2BU_IP, GTPU_PORT)),
        )?;
        let application = UdpSocket::from(descriptor);
        application.set_read_timeout(Some(Duration::from_secs(2)))?;
        let unknown = build_gpdu(UNKNOWN_TEID, None, &inner(0x22, 64));
        send(&frame(&unknown));
        let mut buffer = [0_u8; 2048];
        let (length, source) = application.recv_from(&mut buffer)?;
        assert_eq!(&buffer[..length], unknown);
        assert_eq!(source, SocketAddr::from((PGW_IP, GTPU_PORT)));
        silence.expect(0, "G-PDU for no tunnel with a SO_REUSEPORT socket bound");
    }
    //    Two application sockets share the port with SO_REUSEADDR: one on
    //    the endpoint's address and bound to no device, one on every address
    //    and bound to the attachment's interface. UDP input chooses the
    //    socket on the exact address. tc must not assign the other one: on a
    //    kernel before Linux 6.5 its lookup with the VRF scope engaged does
    //    not see the first socket, and finds the second.
    {
        use nix::sys::socket::{
            bind, recv, setsockopt, socket, sockopt, AddressFamily, MsgFlags, SockFlag, SockType,
            SockaddrIn,
        };
        let application = |address: Ipv4Addr, device: Option<&str>| {
            let descriptor = socket(
                AddressFamily::Inet,
                SockType::Datagram,
                SockFlag::SOCK_CLOEXEC,
                None,
            )?;
            setsockopt(&descriptor, sockopt::ReuseAddr, &true)?;
            if let Some(device) = device {
                setsockopt(
                    &descriptor,
                    sockopt::BindToDevice,
                    &std::ffi::OsString::from(device),
                )?;
            }
            bind(
                descriptor.as_raw_fd(),
                &SockaddrIn::from(std::net::SocketAddrV4::new(address, GTPU_PORT)),
            )?;
            let socket = UdpSocket::from(descriptor);
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            Ok::<_, Box<dyn std::error::Error>>(socket)
        };
        let on_exact_address = application(EPDG_S2BU_IP, None)?;
        let on_interface = application(Ipv4Addr::UNSPECIFIED, Some("s2bu"))?;
        let unknown = build_gpdu(UNKNOWN_TEID, None, &inner(0x24, 64));
        send(&frame(&unknown));
        let mut buffer = [0_u8; 2048];
        let received = on_exact_address.recv_from(&mut buffer);
        assert!(
            recv(
                on_interface.as_raw_fd(),
                &mut [0_u8; 2048],
                MsgFlags::MSG_DONTWAIT
            )
            .is_err(),
            "the hand-off was delivered to a socket that UDP input does not choose"
        );
        let (length, source) = received?;
        assert_eq!(&buffer[..length], unknown);
        assert_eq!(source, SocketAddr::from((PGW_IP, GTPU_PORT)));
        silence.expect(0, "G-PDU for no tunnel with two application sockets bound");
    }

    // 3. With the control port open, the same five hand-offs reach the
    //    consumer and none is counted as dropped.
    let port = backend.open_gtpu_control_port(&device).await?;
    send_all(0x30, 0x1902);
    let events = drain_consumer(port.as_ref(), Duration::from_millis(500));
    let count = |matches: fn(&GtpuDownlinkEvent) -> bool| {
        events.iter().filter(|event| matches(event)).count()
    };
    assert_eq!(
        (
            count(|event| matches!(event, GtpuDownlinkEvent::Fragmented(_))),
            count(|event| matches!(event, GtpuDownlinkEvent::Decapsulated(_))),
            count(|event| matches!(event, GtpuDownlinkEvent::UnknownTunnel(_))),
            count(|event| matches!(event, GtpuDownlinkEvent::Control(_))),
            events.len(),
        ),
        (1, 2, 1, 1, 5),
        "with a bound consumer every hand-off must be delivered: {events:?}"
    );
    silence.expect_fragmented(0, 0, 1, "hand-offs with the control port open");

    // 4. The process is down: its sockets are closed, and tc keeps steering
    //    from the pinned graph.
    drop(port);
    drop(backend);
    send_all(0x40, 0x1903);
    silence.expect_fragmented(5, 1, 0, "hand-offs while the process is down");

    // 5. After a restart: the retained graph is adopted with its MTU
    //    context, and the control port is not open yet.
    let restored = EbpfGtpuDataplaneBackend::with_config(config);
    let adopted = restored.resolve_device("s2bu").await?;
    assert_eq!(adopted.ifindex, device.ifindex);
    assert!(
        matches!(
            restored
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context).expect("selector")
                ))
                .await?,
            PdpContextReadback::Present(retained) if retained.downlink_inner_mtu == Some(mtu)
        ),
        "the adopted graph must hold the MTU context"
    );
    send_all(0x50, 0x1904);
    silence.expect_fragmented(
        5,
        1,
        0,
        "hand-offs after adoption, before the port is reopened",
    );

    // 6. Once the port is open again, the hand-offs are delivered.
    let port = restored.open_gtpu_control_port(&adopted).await?;
    send_all(0x60, 0x1905);
    let events = drain_consumer(port.as_ref(), Duration::from_millis(500));
    assert_eq!(
        events.len(),
        5,
        "after the port is reopened every hand-off must be delivered: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, GtpuDownlinkEvent::Dropped(_))),
        "no hand-off may be refused by the consumer: {events:?}"
    );
    silence.expect_fragmented(0, 0, 1, "hand-offs after the port is reopened");
    let drops = silence.drops;
    drop(port);
    restored.remove_device(&adopted).await?;
    Ok(drops)
}

/// A grouped attachment with an IPv6 outer endpoint. The backend has no
/// IPv6 control port, so the only consumer is an application's own socket.
/// Returns the missing-consumer drops it counted.
async fn grouped_attachment_over_ipv6() -> Result<u64, Box<dyn std::error::Error>> {
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
    let authority =
        reconcile_fresh_grouped(backend.clone(), initial_grouped_session(device.ifindex)).await?;
    let pin_dir = grouped_pin_directory(&net.pin_root, grouped_device_id());
    let pgw_capture = packet_capture_socket(&net.pgw_ns);
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    resolve_s2bu_ipv6_gateway_neighbour();
    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");
    let frame_v6 = |gpdu: &[u8]| {
        build_outer_ipv6_gtpu_frame(
            destination_mac,
            source_mac,
            PGW_IPV6,
            EPDG_S2BU_IPV6,
            gpdu,
            OuterIpv6Extension::None,
        )
    };
    let send = |frame: &[u8]| {
        send_raw_gtpu_frame(&net.pgw_ns, "s2bup", frame, RawChecksumMetadata::Unverified);
    };
    let unknown = build_gpdu(UNKNOWN_TEID, None, &inner(0x70, 64));
    let mut required = build_extension_gpdu(UNKNOWN_TEID, &inner(0x71, 64));
    required[11] = REQUIRED_UNKNOWN_EXTENSION;
    let mut silence = Silence::begin(&pgw_capture, &pin_dir, 0);

    // 1. No socket on UDP/2152 for either family.
    send(&frame_v6(&unknown));
    silence.expect(1, "G-PDU for no tunnel over IPv6, nothing bound");
    send(&frame_v6(&required));
    silence.expect(1, "required unknown extension over IPv6, nothing bound");
    send(&build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &unknown,
        true,
        0,
    ));
    silence.expect(1, "G-PDU for no tunnel over IPv4 on a grouped attachment");
    //    An outer-fragmented datagram for the grouped attachment's IPv4
    //    endpoint is judged by its first fragment as well.
    let (head, tail) = build_outer_fragments(
        &build_outer_gtpu_frame(
            destination_mac,
            source_mac,
            &[],
            &build_gpdu(UNKNOWN_TEID, None, &inner(0x72, FITTING_PAYLOAD)),
            true,
            0,
        ),
        1_000,
        0x1910,
    );
    send_raw_gtpu_frames(&net.pgw_ns, "s2bup", &[head, tail]);
    silence.expect_fragmented(
        1,
        1,
        0,
        "outer-fragmented G-PDU on a grouped attachment, nothing bound",
    );

    // 2. An application's IPv6 socket receives both.
    let application = UdpSocket::bind((EPDG_S2BU_IPV6, GTPU_PORT))?;
    application.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buffer = [0_u8; 2048];
    for gpdu in [&unknown, &required] {
        send(&frame_v6(gpdu));
        let (length, source) = application.recv_from(&mut buffer)?;
        assert_eq!(&buffer[..length], gpdu.as_slice());
        assert_eq!(source, SocketAddr::from((PGW_IPV6, GTPU_PORT)));
    }
    silence.expect(0, "hand-offs over IPv6 with an application socket bound");
    let drops = silence.drops;
    drop(application);
    drop(authority);
    backend.remove_device(&device).await?;
    Ok(drops)
}
