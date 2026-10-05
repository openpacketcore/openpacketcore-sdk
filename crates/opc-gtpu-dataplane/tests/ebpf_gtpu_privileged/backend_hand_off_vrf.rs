//! A hand-off from tc respects the VRF of the attachment, on a real kernel
//! (#1019).
//!
//! The attachment's interface can be enslaved to a VRF. UDP input then
//! delivers a datagram that arrives on it only to a socket that is eligible
//! in that VRF: one bound to the interface or to the VRF device, or one bound
//! to no device while `udp_l3mdev_accept` is set. A socket that is bound to
//! no device belongs to the default VRF otherwise, and is not eligible.
//!
//! tc looks for the consumer of a hand-off before the stack does. If it took
//! such a socket for the consumer, it would
//!
//! - pass the first fragment of an outer-fragmented datagram unmarked, and
//!   the host would answer the reassembled datagram with ICMP Port
//!   Unreachable, quoting the start of the subscriber's packet;
//! - pass a datagram that it cannot assign (a `SO_REUSEPORT` socket, before
//!   Linux 6.6) to the same answer;
//! - assign every other datagram to that socket, and so deliver it across the
//!   VRF boundary.
//!
//! Before Linux 6.5 the socket lookup that tc can use does not know the VRF
//! of the device, so tc has to establish the eligibility itself. The
//! contract, on every kernel: with no eligible consumer in the VRF, a socket
//! in the default VRF receives nothing, the host sends no ICMP error toward
//! the core, and each datagram is either dropped and counted by tc or
//! discarded by the host's own socket lookup. A consumer that is eligible in
//! the VRF receives every hand-off.

use super::backend_hand_off_consumer::{
    host_counter, host_icmp_destination_unreachable, host_icmp_time_exceeded,
    host_icmpv6_destination_unreachable, host_reassembled, host_udp_input_errors,
    icmp_errors_toward_core, ipv4_reassembly_queues,
};
use super::*;
use opc_gtpu_dataplane::control_port::GtpuControlPortError;
use opc_gtpu_dataplane::GtpuDownlinkEvent;

pub(super) const VRF_DEVICE: &str = "opcvrf0";
const VRF_TABLE: &str = "4219";
const L3MDEV_ACCEPT: &str = "/proc/sys/net/ipv4/udp_l3mdev_accept";
pub(super) const UNKNOWN_TEID: u32 = 0xdead_beef;
/// An inner payload that makes the outer datagram span two fragments.
pub(super) const FRAGMENTED_PAYLOAD: usize = 1_200;
/// How long a datagram may take from the sender to its disposal.
const DISPOSAL_DEADLINE: Duration = Duration::from_secs(2);
/// How long an ICMP error that the host has generated may take to reach the
/// capture.
const SETTLE: Duration = Duration::from_millis(100);

/// A device that holds the endpoint addresses, enslaved to a VRF for the life
/// of this value.
pub(super) struct VrfSlave {
    l3mdev_accept: String,
}

impl VrfSlave {
    /// The attachment's interface itself.
    fn enslave() -> Self {
        Self::enslave_device("s2bu")
    }

    pub(super) fn enslave_device(device: &str) -> Self {
        let l3mdev_accept = std::fs::read_to_string(L3MDEV_ACCEPT).expect("read udp_l3mdev_accept");
        run(
            "ip",
            &["link", "add", VRF_DEVICE, "type", "vrf", "table", VRF_TABLE],
        );
        let slave = Self { l3mdev_accept };
        run("ip", &["link", "set", VRF_DEVICE, "up"]);
        run("ip", &["link", "set", device, "master", VRF_DEVICE]);
        // Enslaving cycles the interface, which removes its IPv6 address.
        run(
            "ip",
            &[
                "-6",
                "addr",
                "replace",
                "2001:db8:2::1/64",
                "dev",
                device,
                "nodad",
            ],
        );
        slave
    }

    /// Whether a socket that is bound to no device is eligible in every VRF.
    pub(super) fn accept_unbound_sockets(&self, accept: bool) {
        std::fs::write(L3MDEV_ACCEPT, if accept { "1" } else { "0" })
            .expect("write udp_l3mdev_accept");
    }
}

impl Drop for VrfSlave {
    fn drop(&mut self) {
        let _ = std::fs::write(L3MDEV_ACCEPT, self.l3mdev_accept.trim());
        // The l3mdev policy rules that the first VRF of a namespace installs
        // (for IPv4, IPv6 and their multicast routing) stay behind. They
        // select a table only for a device that belongs to a VRF, and the
        // kernel would not install them again for a later VRF.
        let _ = Command::new("ip")
            .args(["link", "del", VRF_DEVICE])
            .output();
    }
}

/// A UDP socket on every local address of `family` and on `port`, bound to
/// `device` when one is given.
pub(super) fn udp_socket(
    family: nix::sys::socket::AddressFamily,
    port: u16,
    reuse_port: bool,
    device: Option<&str>,
) -> Result<UdpSocket, Box<dyn std::error::Error>> {
    use nix::sys::socket::{
        bind, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, SockaddrIn,
        SockaddrIn6,
    };
    let descriptor = socket(family, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None)?;
    if reuse_port {
        setsockopt(&descriptor, sockopt::ReusePort, &true)?;
    }
    if let Some(device) = device {
        setsockopt(
            &descriptor,
            sockopt::BindToDevice,
            &std::ffi::OsString::from(device),
        )?;
    }
    if family == AddressFamily::Inet6 {
        setsockopt(&descriptor, sockopt::Ipv6V6Only, &true)?;
        bind(
            descriptor.as_raw_fd(),
            &SockaddrIn6::from(std::net::SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                port,
                0,
                0,
            )),
        )?;
    } else {
        bind(
            descriptor.as_raw_fd(),
            &SockaddrIn::from(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
        )?;
    }
    let socket = UdpSocket::from(descriptor);
    socket.set_read_timeout(Some(DISPOSAL_DEADLINE))?;
    Ok(socket)
}

/// The datagrams that are waiting on `socket` now.
pub(super) fn waiting(socket: &UdpSocket) -> usize {
    use nix::sys::socket::{recv, MsgFlags};
    let mut buffer = [0_u8; 2048];
    let mut datagrams = 0;
    while recv(socket.as_raw_fd(), &mut buffer, MsgFlags::MSG_DONTWAIT).is_ok() {
        datagrams += 1;
    }
    datagrams
}

/// UDP datagrams for which the host's socket lookup found no socket in this
/// netns, either family.
fn host_udp_no_ports() -> u64 {
    let ipv6 = std::fs::read_to_string("/proc/net/snmp6")
        .expect("read /proc/net/snmp6")
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("Udp6NoPorts"))
                .then(|| fields.next().and_then(|value| value.parse::<u64>().ok()))
                .flatten()
        })
        .expect("Udp6NoPorts counter");
    host_counter("/proc/net/snmp", "Udp:", "NoPorts") + ipv6
}

/// Whether the socket lookup that tc uses is known to apply the VRF scope of
/// the device itself, as upstream does from Linux 6.5. An older release line
/// can carry that change as a backport, so `false` only means that it is not
/// known here.
fn lookup_knows_the_device_scope() -> bool {
    let release =
        std::fs::read_to_string("/proc/sys/kernel/osrelease").expect("read the kernel release");
    let mut numbers = release
        .split(|character: char| !character.is_ascii_digit())
        .map(str::parse::<u32>);
    matches!(
        (numbers.next(), numbers.next()),
        (Some(Ok(major)), Some(Ok(minor))) if (major, minor) >= (6, 5)
    )
}

#[derive(Clone, Copy)]
pub(super) struct Counters {
    missing_consumer: u64,
    no_ports: u64,
    input_errors: u64,
    reassembled: u64,
    destination_unreachable: u64,
    destination_unreachable_v6: u64,
    time_exceeded: u64,
}

impl Counters {
    fn read(pin_dir: &Path) -> Self {
        Self {
            missing_consumer: pinned_counter(pin_dir, COUNTER_DL_MISSING_CONSUMER),
            no_ports: host_udp_no_ports(),
            input_errors: host_udp_input_errors(),
            reassembled: host_reassembled(),
            destination_unreachable: host_icmp_destination_unreachable(),
            destination_unreachable_v6: host_icmpv6_destination_unreachable(),
            time_exceeded: host_icmp_time_exceeded(),
        }
    }
}

/// What the gateway did with the datagrams of each leg. A leg that breaks the
/// contract is recorded and the next one still runs, so that one run shows
/// every broken leg.
pub(super) struct Legs<'a> {
    pub(super) capture: &'a OwnedFd,
    pub(super) pin_dir: &'a Path,
    /// Datagrams that tc dropped and counted for a missing consumer.
    pub(super) counted: u64,
    /// Datagrams that the host's own socket lookup discarded.
    pub(super) unanswered: u64,
    pub(super) violations: Vec<String>,
}

impl Legs<'_> {
    pub(super) fn begin(&self) -> Counters {
        let _ = icmp_errors_toward_core(self.capture);
        Counters::read(self.pin_dir)
    }

    /// What holds for every leg: the gateway sent no ICMP error toward the
    /// core, and no socket of the default VRF received a datagram.
    fn silence(&mut self, leg: &str, before: Counters, after: Counters, bystanders: &[&UdpSocket]) {
        let errors = icmp_errors_toward_core(self.capture);
        if errors != 0 {
            self.violations.push(format!(
                "{leg}: the gateway sent {errors} ICMP error(s) toward the core"
            ));
        }
        for (name, before, after) in [
            (
                "Destination Unreachable",
                before.destination_unreachable,
                after.destination_unreachable,
            ),
            (
                "ICMPv6 Destination Unreachable",
                before.destination_unreachable_v6,
                after.destination_unreachable_v6,
            ),
            ("Time Exceeded", before.time_exceeded, after.time_exceeded),
        ] {
            if after != before {
                self.violations.push(format!(
                    "{leg}: the host generated {} {name}",
                    after - before
                ));
            }
        }
        let crossed: usize = bystanders.iter().map(|socket| waiting(socket)).sum();
        if crossed != 0 {
            self.violations.push(format!(
                "{leg}: {crossed} datagram(s) were delivered to a socket in the default VRF"
            ));
        }
        let stranded = ipv4_reassembly_queues();
        if stranded != 0 {
            self.violations
                .push(format!("{leg}: {stranded} reassembly queue(s) left behind"));
        }
    }

    /// `datagrams` hand-offs were sent while no consumer is eligible in the
    /// VRF. Each must end in one of two ways: tc dropped and counted it, or
    /// the host's own socket lookup discarded it. With `fragmented`, each
    /// arrived as outer fragments, which the host must have reassembled; UDP
    /// input discards the ones that tc counted and marked.
    pub(super) fn refused(
        &mut self,
        leg: &str,
        before: Counters,
        datagrams: u64,
        fragmented: bool,
        bystanders: &[&UdpSocket],
    ) {
        let deadline = Instant::now() + DISPOSAL_DEADLINE;
        let after = loop {
            let now = Counters::read(self.pin_dir);
            let disposed =
                now.missing_consumer - before.missing_consumer + now.no_ports - before.no_ports;
            if disposed >= datagrams || Instant::now() >= deadline {
                break now;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        std::thread::sleep(SETTLE);
        let after = Counters {
            missing_consumer: pinned_counter(self.pin_dir, COUNTER_DL_MISSING_CONSUMER),
            ..after
        };
        let counted = after.missing_consumer - before.missing_consumer;
        let unanswered = after.no_ports - before.no_ports;
        if counted + unanswered != datagrams {
            self.violations.push(format!(
                "{leg}: of {datagrams} datagram(s), tc dropped and counted {counted} and the host's socket lookup discarded {unanswered}"
            ));
        }
        let after = Counters {
            input_errors: host_udp_input_errors(),
            reassembled: host_reassembled(),
            destination_unreachable: host_icmp_destination_unreachable(),
            destination_unreachable_v6: host_icmpv6_destination_unreachable(),
            time_exceeded: host_icmp_time_exceeded(),
            ..after
        };
        let reassembled = after.reassembled - before.reassembled;
        let discarded = after.input_errors - before.input_errors;
        let (expected_reassembled, expected_discarded) = if fragmented {
            (datagrams, counted)
        } else {
            (0, 0)
        };
        if reassembled != expected_reassembled {
            self.violations.push(format!(
                "{leg}: the host reassembled {reassembled} datagram(s), expected {expected_reassembled}"
            ));
        }
        if discarded != expected_discarded {
            self.violations.push(format!(
                "{leg}: UDP input discarded {discarded} datagram(s) as malformed, expected {expected_discarded}"
            ));
        }
        self.counted += counted;
        self.unanswered += unanswered;
        self.silence(leg, before, after, bystanders);
    }

    /// One hand-off was sent while `consumer` is eligible in the VRF. It must
    /// receive exactly `expected`, from `source`, and nothing may be dropped,
    /// discarded or answered.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn delivered(
        &mut self,
        leg: &str,
        before: Counters,
        consumer: &UdpSocket,
        expected: &[u8],
        source: SocketAddr,
        fragmented: bool,
        bystanders: &[&UdpSocket],
    ) {
        let mut buffer = [0_u8; 2048];
        match consumer.recv_from(&mut buffer) {
            Ok((length, from)) if &buffer[..length] == expected && from == source => {}
            Ok((length, from)) => self.violations.push(format!(
                "{leg}: the consumer received {length} octets from {from}, expected {} from {source}",
                expected.len()
            )),
            Err(error) => self
                .violations
                .push(format!("{leg}: the consumer received nothing: {error}")),
        }
        std::thread::sleep(SETTLE);
        let after = Counters::read(self.pin_dir);
        let counted = after.missing_consumer - before.missing_consumer;
        let unanswered = after.no_ports - before.no_ports;
        let discarded = after.input_errors - before.input_errors;
        if (counted, unanswered, discarded) != (0, 0, 0) {
            self.violations.push(format!(
                "{leg}: tc dropped and counted {counted}, the host's socket lookup discarded {unanswered} and UDP input discarded {discarded} although a consumer is eligible"
            ));
        }
        let reassembled = after.reassembled - before.reassembled;
        if reassembled != u64::from(fragmented) {
            self.violations.push(format!(
                "{leg}: the host reassembled {reassembled} datagram(s), expected {}",
                u64::from(fragmented)
            ));
        }
        let extra = waiting(consumer);
        if extra != 0 {
            self.violations.push(format!(
                "{leg}: the consumer received {extra} further datagram(s)"
            ));
        }
        self.silence(leg, before, after, bystanders);
    }
}

// The serial guard is deliberately held for the entire body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify() -> Result<(), Box<dyn std::error::Error>> {
    use nix::sys::socket::AddressFamily;

    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The reassembly counts below must be this test's own; see the hand-off
    // consumer test.
    let leftovers_deadline = Instant::now() + Duration::from_secs(35);
    while ipv4_reassembly_queues() != 0 {
        assert!(
            Instant::now() < leftovers_deadline,
            "reassembly queues left by an earlier test did not expire"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let net = TestNet::provision();
    let vrf = VrfSlave::enslave();
    vrf.accept_unbound_sockets(false);
    // A grouped attachment has an IPv4 and an IPv6 endpoint on the enslaved
    // interface.
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
    run(
        "ping",
        &["-c", "1", "-W", "1", "-I", VRF_DEVICE, "192.0.2.10"],
    );
    run(
        "ping",
        &[
            "-6",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            VRF_DEVICE,
            "2001:db8:2::10",
        ],
    );
    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");
    let gpdu = |tag: u8, payload: usize| {
        build_gpdu(
            UNKNOWN_TEID,
            None,
            &build_inner_udp(REMOTE_HOST, UE_PAA, 5060, 5060, &vec![tag; payload]),
        )
    };
    let frame_v4 =
        |gpdu: &[u8]| build_outer_gtpu_frame(destination_mac, source_mac, &[], gpdu, true, 0);
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
    // Both fragments of a datagram leave in one burst, in the given order.
    let send_fragments = |gpdu: &[u8], identification: u16, reverse: bool| {
        let (head, tail) = build_outer_fragments(&frame_v4(gpdu), 1_000, identification);
        let burst = if reverse { [tail, head] } else { [head, tail] };
        send_raw_gtpu_frames(&net.pgw_ns, "s2bup", &burst);
    };
    let core_v4 = SocketAddr::from((PGW_IP, GTPU_PORT));
    let core_v6 = SocketAddr::from((PGW_IPV6, GTPU_PORT));
    let mut legs = Legs {
        capture: &pgw_capture,
        pin_dir: &pin_dir,
        counted: 0,
        unanswered: 0,
        violations: Vec::new(),
    };

    // 1. Nothing in the VRF consumes UDP/2152. An unrelated socket in the
    //    default VRF listens on that port on every address, bound to no
    //    device. It is not eligible for a datagram that arrives in the VRF.
    {
        let bystander_v4 = udp_socket(AddressFamily::Inet, GTPU_PORT, false, None)?;
        let bystander_v6 = udp_socket(AddressFamily::Inet6, GTPU_PORT, false, None)?;
        let bystanders = [&bystander_v4, &bystander_v6];

        //  A G-PDU for no tunnel must not be assigned to that socket.
        let before = legs.begin();
        send(&frame_v4(&gpdu(0x10, 64)));
        legs.refused(
            "G-PDU for no tunnel, listener in the default VRF",
            before,
            1,
            false,
            &bystanders,
        );
        let before = legs.begin();
        send(&frame_v6(&gpdu(0x11, 64)));
        legs.refused(
            "G-PDU for no tunnel over IPv6, listener in the default VRF",
            before,
            1,
            false,
            &bystanders,
        );
        //  An outer-fragmented G-PDU must not pass its first-fragment check
        //  because of that socket, in either fragment order.
        let before = legs.begin();
        send_fragments(&gpdu(0x12, FRAGMENTED_PAYLOAD), 0x1a00, false);
        legs.refused(
            "outer-fragmented G-PDU, listener in the default VRF",
            before,
            1,
            true,
            &bystanders,
        );
        let before = legs.begin();
        send_fragments(&gpdu(0x13, FRAGMENTED_PAYLOAD), 0x1a01, true);
        legs.refused(
            "outer-fragmented G-PDU in reverse order, listener in the default VRF",
            before,
            1,
            true,
            &bystanders,
        );

        // 2. With `udp_l3mdev_accept`, a socket that is bound to no device is
        //    eligible in every VRF: the same sockets are the consumers now.
        vrf.accept_unbound_sockets(true);
        let unknown = gpdu(0x20, 64);
        let before = legs.begin();
        send(&frame_v4(&unknown));
        legs.delivered(
            "G-PDU for no tunnel with udp_l3mdev_accept",
            before,
            &bystander_v4,
            &unknown,
            core_v4,
            false,
            &[&bystander_v6],
        );
        let before = legs.begin();
        send(&frame_v6(&unknown));
        legs.delivered(
            "G-PDU for no tunnel over IPv6 with udp_l3mdev_accept",
            before,
            &bystander_v6,
            &unknown,
            core_v6,
            false,
            &[&bystander_v4],
        );
        let fragmented = gpdu(0x21, FRAGMENTED_PAYLOAD);
        let before = legs.begin();
        send_fragments(&fragmented, 0x1a02, false);
        legs.delivered(
            "outer-fragmented G-PDU with udp_l3mdev_accept",
            before,
            &bystander_v4,
            &fragmented,
            core_v4,
            true,
            &[&bystander_v6],
        );
        vrf.accept_unbound_sockets(false);
    }

    // 3. The unrelated sockets set SO_REUSEPORT. A kernel before Linux 6.6
    //    cannot assign such a socket; tc must not pass the datagram on to the
    //    stack because of a socket that the stack will not accept.
    {
        let bystander_v4 = udp_socket(AddressFamily::Inet, GTPU_PORT, true, None)?;
        let bystander_v6 = udp_socket(AddressFamily::Inet6, GTPU_PORT, true, None)?;
        let bystanders = [&bystander_v4, &bystander_v6];
        let before = legs.begin();
        send(&frame_v4(&gpdu(0x30, 64)));
        legs.refused(
            "G-PDU for no tunnel, SO_REUSEPORT listener in the default VRF",
            before,
            1,
            false,
            &bystanders,
        );
        let before = legs.begin();
        send(&frame_v6(&gpdu(0x31, 64)));
        legs.refused(
            "G-PDU for no tunnel over IPv6, SO_REUSEPORT listener in the default VRF",
            before,
            1,
            false,
            &bystanders,
        );

        // 4. A consumer on the attachment's interface is eligible in the VRF
        //    and receives every hand-off, next to the unrelated sockets. It
        //    sets SO_REUSEPORT as they do, so that all of them can be bound;
        //    on a kernel that cannot assign such a socket, this is the path
        //    on which tc leaves the delivery to the stack.
        let consumer_v4 = udp_socket(AddressFamily::Inet, GTPU_PORT, true, Some("s2bu"))?;
        let consumer_v6 = udp_socket(AddressFamily::Inet6, GTPU_PORT, true, Some("s2bu"))?;
        let unknown = gpdu(0x40, 64);
        let before = legs.begin();
        send(&frame_v4(&unknown));
        legs.delivered(
            "G-PDU for no tunnel, consumer on the attachment's interface",
            before,
            &consumer_v4,
            &unknown,
            core_v4,
            false,
            &bystanders,
        );
        let before = legs.begin();
        send(&frame_v6(&unknown));
        legs.delivered(
            "G-PDU for no tunnel over IPv6, consumer on the attachment's interface",
            before,
            &consumer_v6,
            &unknown,
            core_v6,
            false,
            &bystanders,
        );
        let fragmented = gpdu(0x41, FRAGMENTED_PAYLOAD);
        let before = legs.begin();
        send_fragments(&fragmented, 0x1a03, false);
        legs.delivered(
            "outer-fragmented G-PDU, consumer on the attachment's interface",
            before,
            &consumer_v4,
            &fragmented,
            core_v4,
            true,
            &bystanders,
        );
    }

    // 5. The backend binds its own sockets to the attachment's interface, so
    //    its control port is the consumer inside the VRF as well.
    {
        let port = backend.open_gtpu_control_port(&device).await?;
        let unknown = gpdu(0x50, 64);
        let before = legs.begin();
        send(&frame_v4(&unknown));
        let deadline = Instant::now() + DISPOSAL_DEADLINE;
        let event = loop {
            match port.try_receive_downlink(4096) {
                Ok(Some(event)) => break Some(event),
                Ok(None) | Err(GtpuControlPortError::Busy) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(None) | Err(GtpuControlPortError::Busy) => break None,
                Err(error) => panic!("downlink consumer receive failed: {error}"),
            }
        };
        if !matches!(event, Some(GtpuDownlinkEvent::UnknownTunnel(_))) {
            legs.violations.push(format!(
                "G-PDU for no tunnel, control port open: the backend's consumer received {event:?}"
            ));
        }
        std::thread::sleep(SETTLE);
        let after = Counters::read(&pin_dir);
        if (after.missing_consumer, after.no_ports) != (before.missing_consumer, before.no_ports) {
            legs.violations.push(
                "G-PDU for no tunnel, control port open: dropped or discarded although the backend's consumer is bound"
                    .to_owned(),
            );
        }
        legs.silence("G-PDU for no tunnel, control port open", before, after, &[]);
    }

    let (counted, unanswered) = (legs.counted, legs.unanswered);
    // Where the lookup knows the VRF of the device, tc has established for
    // every refused datagram that no consumer is eligible, and must have
    // dropped and counted it itself.
    if lookup_knows_the_device_scope() && unanswered != 0 {
        legs.violations.push(format!(
            "tc left {unanswered} datagram(s) to the host's socket lookup although this kernel's lookup knows the VRF of the device"
        ));
    }
    let violations = std::mem::take(&mut legs.violations);
    drop(authority);
    backend.remove_device(&device).await?;
    assert!(
        violations.is_empty(),
        "hand-offs on a VRF slave broke the contract:\n{}",
        violations.join("\n")
    );
    eprintln!(
        "OPC_GTPU_DOWNLINK_HAND_OFF_VRF_PROVEN: on a VRF slave, a socket in the default VRF received none of {} hand-offs and the core no ICMP error (tc dropped and counted {counted}, the host's own socket lookup discarded {unanswered}; a G-PDU for no tunnel over IPv4 and IPv6, with and without SO_REUSEPORT on that socket, and an outer-fragmented G-PDU over IPv4 in either fragment order); with udp_l3mdev_accept, with a consumer on the attachment's interface and with the control port open every hand-off was delivered",
        counted + unanswered
    );
    Ok(())
}
