//! A hand-off that arrives in a VLAN has no consumer on the interface below,
//! on a real kernel (#1019).
//!
//! The kernel takes the outermost VLAN tag out of a frame before tc runs at
//! the ingress of the device that received it, and keeps the tag beside the
//! frame. It does so whether or not the adapter stripped the tag itself, so
//! the frame looks untagged to a tc program in either case. After tc, a frame
//! whose tag has a VLAN ID other than 0 goes to the VLAN device of that ID
//! above the receiving device, or is marked as a frame for another host when
//! there is none. IP input never receives it on the device that tc is
//! attached to.
//!
//! tc looks for the consumer of a hand-off on the device it is attached to.
//! For such a frame that lookup describes the wrong device. It finds a
//! consumer on the interface below, which UDP input would never give the
//! datagram to, and assigns the datagram to it across the device boundary.
//! Or it lets a first fragment pass because of that consumer. The VLAN device
//! then reassembles the datagram, and the host delivers it to a socket there
//! or answers it with ICMP Port Unreachable.
//!
//! The contract: a hand-off in a frame with a VLAN ID other than 0 has no
//! consumer, whichever hand-off it is: a G-PDU for no tunnel over IPv4 or
//! IPv6, one with a required unknown extension, an over-MTU packet or an
//! inner fragment that tc has already steered to its queue, and an
//! outer-fragmented G-PDU. tc makes no lookup for it. It drops and counts the
//! datagram, and counts and marks a first fragment, so that no socket
//! receives it, whether it is bound to the interface, to the VLAN device or
//! to no device, and the host generates no ICMP error. Everything else in
//! such a frame is handled as in any other: a G-PDU of a provisioned tunnel
//! is decapsulated. A frame with a priority tag (VLAN ID 0) is the
//! interface's own, as the kernel treats it. An interface with a VLAN device
//! above it is accepted, and the VLAN device can carry the attachment itself.

use super::attachment_stacked_device::wait_for_reassembly_leftovers;
use super::backend_hand_off_consumer::{
    host_icmp_destination_unreachable, host_icmp_time_exceeded,
    host_icmpv6_destination_unreachable, host_reassembled, host_udp_input_errors, inner_fragment,
    ipv4_reassembly_queues, oversized, REQUIRED_UNKNOWN_EXTENSION, SESSION_MTU,
};
use super::backend_hand_off_vrf::{udp_socket, waiting, FRAGMENTED_PAYLOAD, UNKNOWN_TEID};
use super::*;
use opc_gtpu_dataplane::GtpuDownlinkInnerMtu;

/// The VLAN device above the attachment's interface, and its peer above the
/// core's interface. An attachment is pinned under its interface's name, and
/// bpffs accepts no dot in a name.
const VLAN: &str = "s2buv100";
const VLAN_PEER: &str = "s2bupv100";
const VLAN_ID: u16 = 100;
/// The address of the VLAN device, and the core's address in the VLAN.
const VLAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const VLAN_PEER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
/// A VLAN device with the ID 0 above the core's interface: what it sends
/// carries a priority tag beside the frame.
const PRIORITY_PEER: &str = "s2bupv0";
/// Priority 5 and the VLAN ID 0.
const PRIORITY_TAG: u16 = 5 << 13;
/// How long a datagram may take from the sender to a socket.
const DELIVERY_DEADLINE: Duration = Duration::from_secs(2);
/// How long a datagram that tc passed on, or an ICMP error about it, may
/// take to show.
const SETTLE: Duration = Duration::from_millis(150);

/// The VLAN devices on both sides, for the life of this value.
struct VlanDevices<'a> {
    net: &'a TestNet,
}

impl<'a> VlanDevices<'a> {
    fn add(net: &'a TestNet) -> Self {
        let id = VLAN_ID.to_string();
        run(
            "ip",
            &[
                "link", "add", "link", "s2bu", "name", VLAN, "type", "vlan", "id", &id,
            ],
        );
        let devices = Self { net };
        run("ip", &["link", "set", VLAN, "up"]);
        run("ip", &["addr", "add", "203.0.113.1/24", "dev", VLAN]);
        let pgw = |arguments: &[&str]| {
            let mut all = vec!["-n", net.pgw_ns.as_str()];
            all.extend_from_slice(arguments);
            run("ip", &all);
        };
        pgw(&[
            "link", "add", "link", "s2bup", "name", VLAN_PEER, "type", "vlan", "id", &id,
        ]);
        pgw(&["link", "set", VLAN_PEER, "up"]);
        pgw(&["addr", "add", "203.0.113.10/24", "dev", VLAN_PEER]);
        pgw(&[
            "link",
            "add",
            "link",
            "s2bup",
            "name",
            PRIORITY_PEER,
            "type",
            "vlan",
            "id",
            "0",
        ]);
        pgw(&["link", "set", PRIORITY_PEER, "up"]);
        devices
    }
}

impl Drop for VlanDevices<'_> {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", VLAN]).output();
        for peer in [VLAN_PEER, PRIORITY_PEER] {
            let _ = Command::new("ip")
                .args(["-n", self.net.pgw_ns.as_str(), "link", "del", peer])
                .output();
        }
    }
}

/// Where the sender puts the tag.
#[derive(Clone, Copy)]
enum Tag {
    /// In the frame, as an adapter without tag offload delivers it.
    InTheFrame,
    /// Beside the frame, as an adapter that strips the tag delivers it.
    BesideTheFrame,
}

impl Tag {
    const BOTH: [Self; 2] = [Self::InTheFrame, Self::BesideTheFrame];

    fn name(self) -> &'static str {
        match self {
            Self::InTheFrame => "tag in the frame",
            Self::BesideTheFrame => "tag beside the frame",
        }
    }
}

/// `frame` with an 802.1Q tag of `control` after its link addresses.
fn tagged(frame: &[u8], control: u16) -> Vec<u8> {
    let mut tagged = Vec::with_capacity(frame.len() + 4);
    tagged.extend_from_slice(&frame[..12]);
    tagged.extend_from_slice(&0x8100_u16.to_be_bytes());
    tagged.extend_from_slice(&control.to_be_bytes());
    tagged.extend_from_slice(&frame[12..]);
    tagged
}

/// `frame` from `source` to `destination` instead of the addresses outside
/// the VLAN.
fn readdressed(mut frame: Vec<u8>, source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let ip = ETH_HDR_LEN;
    let udp = ip + IPV4_MIN_HDR_LEN;
    frame[ip + 12..ip + 16].copy_from_slice(&source.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&destination.octets());
    frame[ip + 10..ip + 12].fill(0);
    let checksum = internet_checksum(&frame[ip..udp]);
    frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    frame[udp + 6..udp + 8].fill(0);
    let checksum = udp_ipv4_checksum(source.octets(), destination.octets(), &frame[udp..])
        .expect("bounded outer UDP checksum input");
    frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// `frame` from the core's address in the VLAN to the endpoint of the
/// attachment below the VLAN device.
fn from_source(frame: Vec<u8>, source: Ipv4Addr) -> Vec<u8> {
    readdressed(frame, source, EPDG_S2BU_IP)
}

struct Sender<'a> {
    net: &'a TestNet,
}

impl Sender<'_> {
    fn raw(&self, interface: &str, frame: &[u8]) {
        send_raw_gtpu_frame(
            &self.net.pgw_ns,
            interface,
            frame,
            RawChecksumMetadata::Unverified,
        );
    }

    /// `frame` in the VLAN.
    fn in_the_vlan(&self, frame: &[u8], tag: Tag) {
        match tag {
            Tag::InTheFrame => self.raw("s2bup", &tagged(frame, VLAN_ID)),
            Tag::BesideTheFrame => self.raw(VLAN_PEER, frame),
        }
    }

    /// `frame` with a priority tag.
    fn with_a_priority_tag(&self, frame: &[u8], tag: Tag) {
        match tag {
            Tag::InTheFrame => self.raw("s2bup", &tagged(frame, PRIORITY_TAG)),
            Tag::BesideTheFrame => self.raw(PRIORITY_PEER, frame),
        }
    }

    fn untagged(&self, frame: &[u8]) {
        self.raw("s2bup", frame);
    }

    /// Both fragments of a datagram in the VLAN, in one burst.
    fn fragments_in_the_vlan(&self, frame: &[u8], identification: u16, tag: Tag) {
        let (first, second) = build_outer_fragments(frame, 1_000, identification);
        match tag {
            Tag::InTheFrame => send_raw_gtpu_frames(
                &self.net.pgw_ns,
                "s2bup",
                &[tagged(&first, VLAN_ID), tagged(&second, VLAN_ID)],
            ),
            Tag::BesideTheFrame => {
                send_raw_gtpu_frames(&self.net.pgw_ns, VLAN_PEER, &[first, second]);
            }
        }
    }
}

/// tc's counters that a frame of the interface's own moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Judged {
    decapsulated: u64,
    unknown_tunnel: u64,
    missing_consumer: u64,
}

impl Judged {
    fn read(pin_dir: &Path) -> Self {
        Self {
            decapsulated: pinned_counter(pin_dir, COUNTER_DL_DECAP),
            unknown_tunnel: pinned_counter(pin_dir, COUNTER_DL_UNKNOWN_TEID),
            missing_consumer: pinned_counter(pin_dir, COUNTER_DL_MISSING_CONSUMER),
        }
    }

    /// The counters once they show `expected`, or what they show when the
    /// time for that is over.
    fn settled(pin_dir: &Path, expected: Self) -> Self {
        let deadline = Instant::now() + DELIVERY_DEADLINE;
        loop {
            let found = Self::read(pin_dir);
            if found == expected || Instant::now() >= deadline {
                return found;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// What the host did on its own account: the ICMP errors it generated, the
/// datagrams it reassembled, and the ones UDP input discarded as malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Host {
    destination_unreachable: u64,
    destination_unreachable_v6: u64,
    time_exceeded: u64,
    reassembled: u64,
    input_errors: u64,
}

impl Host {
    fn read() -> Self {
        Self {
            destination_unreachable: host_icmp_destination_unreachable(),
            destination_unreachable_v6: host_icmpv6_destination_unreachable(),
            time_exceeded: host_icmp_time_exceeded(),
            reassembled: host_reassembled(),
            input_errors: host_udp_input_errors(),
        }
    }

    /// The counters once they show `expected`, or what they show when the
    /// time for that is over.
    fn settled(expected: Self) -> Self {
        let deadline = Instant::now() + DELIVERY_DEADLINE;
        loop {
            let found = Self::read();
            if found == expected || Instant::now() >= deadline {
                return found;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The datagram that `socket` received within the deadline, if any.
fn received(socket: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buffer = [0_u8; 2048];
    socket
        .recv_from(&mut buffer)
        .ok()
        .map(|(length, from)| (buffer[..length].to_vec(), from))
}

/// What holds for every hand-off in the VLAN: tc counted it as one without a
/// consumer, no socket received it, and the host generated no ICMP error and
/// did nothing else on its account than `host` says.
fn given_to_no_socket(
    pin_dir: &Path,
    violations: &mut Vec<String>,
    leg: &str,
    before: Judged,
    expected: Judged,
    host: Host,
    sockets: &[&UdpSocket],
) {
    let found = Judged::settled(pin_dir, expected);
    if found != expected {
        violations.push(format!(
            "{leg}: tc did not count the hand-off as one without a consumer: {before:?} became {found:?}, expected {expected:?}"
        ));
    }
    let found = Host::settled(host);
    std::thread::sleep(SETTLE);
    let after = Host::read();
    if after != host {
        violations.push(format!(
            "{leg}: the host answered or mishandled the hand-off: {found:?} then {after:?}, expected {host:?}"
        ));
    }
    let delivered: usize = sockets.iter().map(|socket| waiting(socket)).sum();
    if delivered != 0 {
        violations.push(format!(
            "{leg}: {delivered} datagram(s) of the VLAN were delivered to a socket"
        ));
    }
    let stranded = ipv4_reassembly_queues();
    if stranded != 0 {
        violations.push(format!("{leg}: {stranded} reassembly queue(s) left behind"));
    }
}

/// The same hand-off without the tag reaches `consumer` as `datagram` from
/// `source`, and tc counts `expected`.
#[allow(clippy::too_many_arguments)]
fn consumed_without_the_tag(
    pin_dir: &Path,
    violations: &mut Vec<String>,
    leg: &str,
    consumer: &UdpSocket,
    datagram: &[u8],
    source: SocketAddr,
    before: Judged,
    expected: Judged,
) {
    match received(consumer) {
        Some((found, from)) if found == datagram && from == source => {}
        other => violations.push(format!(
            "{leg}: the same hand-off without the tag did not reach the consumer: {:?}",
            other.map(|(datagram, from)| (datagram.len(), from))
        )),
    }
    let found = Judged::settled(pin_dir, expected);
    if found != expected {
        violations.push(format!(
            "{leg}: the same hand-off without the tag was not passed on: {before:?} became {found:?}"
        ));
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
    wait_for_reassembly_leftovers();
    let net = TestNet::provision();
    let _vlan = VlanDevices::add(&net);
    // An interface with a VLAN device above it is accepted.
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

    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");
    let frame =
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
    let inner = |tag: u8, payload: usize| {
        build_inner_udp(REMOTE_HOST, UE_PAA, 5060, 5060, &vec![tag; payload])
    };
    let unknown = |tag: u8, payload: usize| build_gpdu(UNKNOWN_TEID, None, &inner(tag, payload));
    let provisioned = |tag: u8| build_gpdu(GROUP_LOCAL_TEID_V4_INITIAL, None, &inner(tag, 64));
    let sender = Sender { net: &net };
    let core = SocketAddr::from((PGW_IP, GTPU_PORT));
    let core_v6 = SocketAddr::from((PGW_IPV6, GTPU_PORT));
    let vlan_peer = SocketAddr::from((VLAN_PEER_IP, GTPU_PORT));
    let mut violations = Vec::new();
    // Hand-offs in the VLAN that tc dropped, and first fragments it marked.
    let (mut dropped, mut marked) = (0_u64, 0_u64);

    // 1. Only a socket bound to no device listens on UDP/2152. Outside a
    //    VRF, UDP input accepts such a socket on every device, the VLAN
    //    device included, and tc's lookup on the interface finds it. tc
    //    gives the hand-off in the VLAN to no socket all the same: it is
    //    dropped and counted, and the socket receives nothing. The same
    //    G-PDU without the tag reaches it.
    {
        let on_no_device = udp_socket(AddressFamily::Inet, GTPU_PORT, false, None)?;
        on_no_device.set_read_timeout(Some(DELIVERY_DEADLINE))?;
        for (index, tag) in Tag::BOTH.into_iter().enumerate() {
            let leg = format!(
                "G-PDU for no tunnel in the VLAN, {}, a socket bound to no device",
                tag.name()
            );
            let (before, host) = (Judged::read(&pin_dir), Host::read());
            let expected = Judged {
                unknown_tunnel: before.unknown_tunnel + 1,
                missing_consumer: before.missing_consumer + 1,
                ..before
            };
            let gpdu = unknown(0x08 + index as u8, 64);
            sender.in_the_vlan(&from_source(frame(&gpdu), VLAN_PEER_IP), tag);
            given_to_no_socket(
                &pin_dir,
                &mut violations,
                &leg,
                before,
                expected,
                host,
                &[&on_no_device],
            );
            dropped += 1;

            let before = Judged::read(&pin_dir);
            let expected = Judged {
                unknown_tunnel: before.unknown_tunnel + 1,
                ..before
            };
            sender.untagged(&frame(&gpdu));
            consumed_without_the_tag(
                &pin_dir,
                &mut violations,
                &leg,
                &on_no_device,
                &gpdu,
                core,
                before,
                expected,
            );
        }
    }

    {
        // A socket on the VLAN device listens on UDP/2152 from here on. It
        // is where UDP input would deliver a datagram that arrives in the
        // VLAN.
        let on_the_vlan = udp_socket(AddressFamily::Inet, GTPU_PORT, false, Some(VLAN))?;
        let on_the_vlan_v6 = udp_socket(AddressFamily::Inet6, GTPU_PORT, false, Some(VLAN))?;

        // 2. Nothing is bound on the attachment's interface. A G-PDU for no
        //    tunnel for the endpoint, in the VLAN, is dropped and counted.
        for (index, tag) in Tag::BOTH.into_iter().enumerate() {
            let leg = format!("G-PDU for no tunnel in the VLAN, {}", tag.name());
            let (before, host) = (Judged::read(&pin_dir), Host::read());
            let expected = Judged {
                unknown_tunnel: before.unknown_tunnel + 1,
                missing_consumer: before.missing_consumer + 1,
                ..before
            };
            let gpdu = unknown(0x10 + index as u8, 64);
            sender.in_the_vlan(&from_source(frame(&gpdu), VLAN_PEER_IP), tag);
            given_to_no_socket(
                &pin_dir,
                &mut violations,
                &leg,
                before,
                expected,
                host,
                &[&on_the_vlan],
            );
            dropped += 1;
        }

        // 3. A consumer is bound on the attachment's interface. tc makes no
        //    lookup for a hand-off in the VLAN, so it does not take that
        //    consumer for the datagram's: the hand-off is dropped and counted
        //    all the same, and the consumer receives nothing. The same G-PDU
        //    without the tag is the consumer's. Over IPv4 and over IPv6.
        let on_the_interface = udp_socket(AddressFamily::Inet, GTPU_PORT, false, Some("s2bu"))?;
        let on_the_interface_v6 = udp_socket(AddressFamily::Inet6, GTPU_PORT, false, Some("s2bu"))?;
        for socket in [&on_the_interface, &on_the_interface_v6] {
            socket.set_read_timeout(Some(DELIVERY_DEADLINE))?;
        }
        let sockets = [
            &on_the_vlan,
            &on_the_vlan_v6,
            &on_the_interface,
            &on_the_interface_v6,
        ];
        for (index, tag) in Tag::BOTH.into_iter().enumerate() {
            for (family, ipv6) in [("", false), (" over IPv6", true)] {
                let leg = format!(
                    "G-PDU for no tunnel{family} in the VLAN, {}, consumer on the attachment's interface",
                    tag.name()
                );
                let (before, host) = (Judged::read(&pin_dir), Host::read());
                let expected = Judged {
                    unknown_tunnel: before.unknown_tunnel + 1,
                    missing_consumer: before.missing_consumer + 1,
                    ..before
                };
                let gpdu = unknown(0x20 + 2 * index as u8 + u8::from(ipv6), 64);
                let (in_the_vlan, without_the_tag, consumer, source) = if ipv6 {
                    let frame = frame_v6(&gpdu);
                    (frame.clone(), frame, &on_the_interface_v6, core_v6)
                } else {
                    (
                        from_source(frame(&gpdu), VLAN_PEER_IP),
                        frame(&gpdu),
                        &on_the_interface,
                        core,
                    )
                };
                sender.in_the_vlan(&in_the_vlan, tag);
                given_to_no_socket(
                    &pin_dir,
                    &mut violations,
                    &leg,
                    before,
                    expected,
                    host,
                    &sockets,
                );
                dropped += 1;

                let before = Judged::read(&pin_dir);
                let expected = Judged {
                    unknown_tunnel: before.unknown_tunnel + 1,
                    ..before
                };
                sender.untagged(&without_the_tag);
                consumed_without_the_tag(
                    &pin_dir,
                    &mut violations,
                    &leg,
                    consumer,
                    &gpdu,
                    source,
                    before,
                    expected,
                );
            }
        }
        drop(on_the_vlan_v6);
        drop(on_the_interface_v6);

        // 4. An outer-fragmented G-PDU in the VLAN, with that consumer still
        //    bound. tc counts the datagram at its first fragment and marks
        //    that fragment. The host reassembles the datagram on the VLAN
        //    device and UDP input discards it: it reaches no socket there,
        //    and without a socket there the host generates no ICMP error.
        let mut on_the_vlan = Some(on_the_vlan);
        for (round, listener) in ["a socket on the VLAN device", "nothing on the VLAN device"]
            .into_iter()
            .enumerate()
        {
            if round == 1 {
                on_the_vlan = None;
            }
            for (index, tag) in Tag::BOTH.into_iter().enumerate() {
                let leg = format!(
                    "outer-fragmented G-PDU in the VLAN, {}, {listener}",
                    tag.name()
                );
                let (before, host) = (Judged::read(&pin_dir), Host::read());
                let expected = Judged {
                    missing_consumer: before.missing_consumer + 1,
                    ..before
                };
                let reassembled = Host {
                    reassembled: host.reassembled + 1,
                    input_errors: host.input_errors + 1,
                    ..host
                };
                let number = (2 * round + index) as u8;
                let gpdu = unknown(0x30 + number, FRAGMENTED_PAYLOAD);
                sender.fragments_in_the_vlan(
                    &from_source(frame(&gpdu), VLAN_PEER_IP),
                    0x1c00 + u16::from(number),
                    tag,
                );
                let sockets: Vec<&UdpSocket> =
                    on_the_vlan.iter().chain([&on_the_interface]).collect();
                given_to_no_socket(
                    &pin_dir,
                    &mut violations,
                    &leg,
                    before,
                    expected,
                    reassembled,
                    &sockets,
                );
                marked += 1;
            }
        }

        // 5. A priority tag has the VLAN ID 0. The kernel receives such a
        //    frame on the interface itself, so it is the attachment's own:
        //    the consumer on the interface receives a G-PDU for no tunnel.
        for (index, tag) in Tag::BOTH.into_iter().enumerate() {
            let leg = format!("G-PDU for no tunnel with a priority tag, {}", tag.name());
            let before = Judged::read(&pin_dir);
            let gpdu = unknown(0x40 + index as u8, 64);
            sender.with_a_priority_tag(&frame(&gpdu), tag);
            match received(&on_the_interface) {
                Some((datagram, from)) if datagram == gpdu && from == core => {}
                other => violations.push(format!(
                    "{leg}: the consumer on the interface did not receive it: {:?}",
                    other.map(|(datagram, from)| (datagram.len(), from))
                )),
            }
            let expected = Judged {
                unknown_tunnel: before.unknown_tunnel + 1,
                ..before
            };
            let found = Judged::settled(&pin_dir, expected);
            if found != expected {
                violations.push(format!(
                    "{leg}: the hand-off was not counted as one for no tunnel alone: {before:?} became {found:?}"
                ));
            }
        }
    }

    // 6. What is no hand-off is handled as in any other frame: a G-PDU of a
    //    provisioned tunnel is decapsulated, in the VLAN and with a priority
    //    tag.
    let mut decapsulated = 0_u64;
    for (index, tag) in Tag::BOTH.into_iter().enumerate() {
        for (name, priority) in [("in the VLAN", false), ("with a priority tag", true)] {
            let leg = format!("G-PDU of a provisioned tunnel {name}, {}", tag.name());
            let before = Judged::read(&pin_dir);
            let expected = Judged {
                decapsulated: before.decapsulated + 1,
                ..before
            };
            let gpdu = frame(&provisioned(0x50 + index as u8));
            if priority {
                sender.with_a_priority_tag(&gpdu, tag);
            } else {
                sender.in_the_vlan(&gpdu, tag);
            }
            let found = Judged::settled(&pin_dir, expected);
            if found != expected {
                violations.push(format!(
                    "{leg}: not decapsulated: {before:?} became {found:?}"
                ));
            }
            decapsulated += 1;
        }
    }
    drop(authority);
    backend.remove_device(&device).await?;

    // 7. The hand-offs of a context that carries a downlink inner MTU, and
    //    the one for a required unknown extension, on an ordinary attachment.
    //    tc steers the first two to UDP/2153 and UDP/2154 before it decides
    //    the consumer. A consumer is bound on the interface for each queue,
    //    and a socket listens on each port on the VLAN device: in the VLAN
    //    each hand-off is dropped and counted, also the two that were
    //    already steered, and none of those sockets receives anything.
    {
        let mut request = CreateGtpDeviceRequest::new("s2bu");
        request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
        let ordinary = backend.create_device(request).await?;
        let pin_dir = net.pin_root.join("s2bu");
        let mut context = session_context(ordinary.ifindex);
        context.downlink_inner_mtu =
            Some(GtpuDownlinkInnerMtu::new(SESSION_MTU).expect("canonical session MTU"));
        backend.install_pdp_context(context).await?;

        let ports = [GTPU_PORT, 2153, 2154];
        let mut on_the_interface = Vec::new();
        let mut on_the_vlan = Vec::new();
        for port in ports {
            let socket = udp_socket(AddressFamily::Inet, port, false, Some("s2bu"))?;
            socket.set_read_timeout(Some(DELIVERY_DEADLINE))?;
            on_the_interface.push(socket);
            on_the_vlan.push(udp_socket(AddressFamily::Inet, port, false, Some(VLAN))?);
        }
        let sockets: Vec<&UdpSocket> = on_the_interface.iter().chain(&on_the_vlan).collect();
        let required_extension = |tag: u8| {
            let mut gpdu = build_extension_gpdu(LOCAL_TEID, &inner(tag, 64));
            gpdu[11] = REQUIRED_UNKNOWN_EXTENSION;
            gpdu
        };
        for (index, tag) in Tag::BOTH.into_iter().enumerate() {
            let number = 0x60 + 3 * index as u8;
            for (name, gpdu, queue) in [
                (
                    "over-MTU Don't Fragment packet",
                    build_gpdu(LOCAL_TEID, None, &oversized(number)),
                    1,
                ),
                (
                    "inner fragment",
                    build_gpdu(LOCAL_TEID, None, &inner_fragment(number + 1)),
                    2,
                ),
                (
                    "G-PDU with a required unknown extension",
                    required_extension(number + 2),
                    0,
                ),
            ] {
                let leg = format!("{name} in the VLAN, {}", tag.name());
                let (before, host) = (Judged::read(&pin_dir), Host::read());
                let expected = Judged {
                    missing_consumer: before.missing_consumer + 1,
                    ..before
                };
                sender.in_the_vlan(&frame(&gpdu), tag);
                given_to_no_socket(
                    &pin_dir,
                    &mut violations,
                    &leg,
                    before,
                    expected,
                    host,
                    &sockets,
                );
                dropped += 1;

                let before = Judged::read(&pin_dir);
                sender.untagged(&frame(&gpdu));
                consumed_without_the_tag(
                    &pin_dir,
                    &mut violations,
                    &leg,
                    &on_the_interface[queue],
                    &gpdu,
                    core,
                    before,
                    before,
                );
            }
        }
        drop(on_the_interface);
        drop(on_the_vlan);
        backend.remove_device(&ordinary).await?;
    }

    // 8. The VLAN device carries the attachment itself. The frames of its
    //    VLAN reach it without their tag, and its program judges them as its
    //    own: a G-PDU for no tunnel for its endpoint is dropped and counted
    //    while no consumer is bound, and delivered to a consumer on the VLAN
    //    device. An older kernel leaves the control word of the consumed tag
    //    beside the frame, which the program must not take for a tag.
    let mut on_the_vlan_device = 0_u64;
    {
        let mut request = CreateGtpDeviceRequest::new(VLAN);
        request.bind_address = IpAddr::V4(VLAN_IP);
        let vlan_attachment = backend.create_device(request).await?;
        let vlan_pin_dir = net.pin_root.join(VLAN);
        for (index, tag) in Tag::BOTH.into_iter().enumerate() {
            let leg = format!("attachment on the VLAN device, {}", tag.name());
            let before = Judged::read(&vlan_pin_dir);
            let expected = Judged {
                unknown_tunnel: before.unknown_tunnel + 1,
                missing_consumer: before.missing_consumer + 1,
                ..before
            };
            let gpdu = unknown(0x70 + index as u8, 64);
            sender.in_the_vlan(&readdressed(frame(&gpdu), VLAN_PEER_IP, VLAN_IP), tag);
            let found = Judged::settled(&vlan_pin_dir, expected);
            if found != expected {
                violations.push(format!(
                    "{leg}: a G-PDU for no tunnel without a consumer was not dropped and counted: {before:?} became {found:?}"
                ));
            }
            on_the_vlan_device += 1;
        }
        let consumer = udp_socket(AddressFamily::Inet, GTPU_PORT, false, Some(VLAN))?;
        consumer.set_read_timeout(Some(DELIVERY_DEADLINE))?;
        for (index, tag) in Tag::BOTH.into_iter().enumerate() {
            let leg = format!(
                "attachment on the VLAN device, {}, consumer on the VLAN device",
                tag.name()
            );
            let before = Judged::read(&vlan_pin_dir);
            let gpdu = unknown(0x72 + index as u8, 64);
            sender.in_the_vlan(&readdressed(frame(&gpdu), VLAN_PEER_IP, VLAN_IP), tag);
            match received(&consumer) {
                Some((datagram, from)) if datagram == gpdu && from == vlan_peer => {}
                Some((datagram, from)) => violations.push(format!(
                    "{leg}: the consumer received {} octets from {from}",
                    datagram.len()
                )),
                None => violations.push(format!("{leg}: the consumer received nothing")),
            }
            let expected = Judged {
                unknown_tunnel: before.unknown_tunnel + 1,
                ..before
            };
            let found = Judged::settled(&vlan_pin_dir, expected);
            if found != expected {
                violations.push(format!(
                    "{leg}: the hand-off was not counted as one for no tunnel alone: {before:?} became {found:?}"
                ));
            }
            on_the_vlan_device += 1;
        }
        drop(consumer);
        backend.remove_device(&vlan_attachment).await?;
    }

    assert!(
        violations.is_empty(),
        "hand-offs in a VLAN broke the contract:\n{}",
        violations.join("\n")
    );
    eprintln!(
        "OPC_GTPU_DOWNLINK_VLAN_FRAMES_PROVEN: with a VLAN device above the attachment's interface, tc gave {} hand-offs that arrived in that VLAN to no socket, with the tag in the frame and beside it: it dropped and counted {dropped} (a G-PDU for no tunnel while only a socket bound to no device listened, while nothing was bound on the interface, and while a consumer was bound there, then also over IPv6; an over-MTU packet and an inner fragment that were already steered; and a G-PDU with a required unknown extension) and counted and marked the first fragment of {marked} outer-fragmented ones, which the host reassembled and discarded; no socket received one and the host generated no ICMP error; a consumer on the interface received 2 hand-offs with a priority tag; tc decapsulated {decapsulated} G-PDUs of a provisioned tunnel in the VLAN and with a priority tag; an attachment on the VLAN device judged {on_the_vlan_device} frames of its VLAN",
        dropped + marked
    );
    Ok(())
}
