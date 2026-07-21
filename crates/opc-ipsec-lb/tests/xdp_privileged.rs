//! Privileged end-to-end proof of the XDP keyless-classification datapath.
//!
//! Topology (the main netns is the fresh namespace the CI harness provides;
//! the peer and redirector netns are provisioned per test process with unique
//! names so concurrently provisioned binaries never collide):
//!
//! ```text
//!   [peer netns]                 [main netns = ePDG]              [redirector netns]
//!   xpNb 203.0.113.9 ──veth── xpNa 203.0.113.7 (XDP attached)
//!                                                      xhNa ──veth── xhNb (AF_PACKET capture)
//! ```
//!
//! The test proves, with documentation addresses only (RFC 5737):
//!
//! - classification of all three classes: UDP/500 IKE, UDP/4500 non-ESP-marker
//!   discrimination (marker IKE vs ESP-in-UDP), and native ESP;
//! - local pass for self-owned keys (packets reach local sockets);
//! - explicit userspace-redirector hand-off for remote-owned keys (frames
//!   arrive on the hand-off interface, never on the local stack);
//! - fail-closed slow-path hand-off with distinct counters for map miss,
//!   stale generation, and unclassifiable candidates (never a silent drop);
//! - old-or-new hash-map publication for both owner/generation records and the
//!   ownership fence under concurrent raw map reads and writes;
//! - graceful process handoff under continuous traffic: fresh map namespaces
//!   take over atomically and no verdict gap appears;
//! - killed-process restart: closing the owning process's `bpf_link` detaches
//!   the hook, while pinned maps remain adoptable, owners are flushed, and the
//!   persisted fence remains authoritative.
//!
//! Run inside a privileged fresh netns with:
//!
//! ```sh
//! OPC_IPSEC_LB_RUN_PRIVILEGED=1 cargo test -p opc-ipsec-lb \
//!   --test xdp_privileged -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use aya::maps::{Array, HashMap as BpfHashMap, Map, MapData};
use aya::programs::links::FdLink;
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use nix::sys::socket::{recv, recvfrom, sendto, LinkAddr, MsgFlags, SockaddrIn};
use nix::sys::time::TimeVal;
use opc_ipsec_lb::model::{IpAddress, ShardId};
use opc_ipsec_lb::ownership::{
    DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi, EstablishedIkeOwnershipKey,
    IkeSpi, RoutingDomainTag, SessionOwnershipKey,
};
use opc_ipsec_lb::{
    HostXdpAttachMode, HostXdpFenceDomain, HostXdpRedirectHandoff, HostXdpSteeringBackend,
    HostXdpSteeringBackendConfig, HostXdpUpgradeOutcome,
};
use opc_ipsec_lb_ebpf_common::{
    XdpDatapathConfig, XdpFenceMode, XdpOwnerValue, CONFIG_KEY, CONFIG_VALUE_LEN, FENCE_KEY,
    MAP_CONFIG, MAP_COUNTERS, MAP_FENCE, MAP_KEY_FENCES, MAP_OWNERS, OWNER_KEY_LEN,
    OWNER_VALUE_LEN, PROG_SWU_XDP, XDP_CONFIG_ABI_VERSION,
};

const VIP4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const PEER4: [u8; 4] = [203, 0, 113, 9];
const VIP6: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
const PEER6: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
const DOMAIN: u64 = 7;
const SELF_SHARD: u16 = 1;
const REMOTE_SHARD: u16 = 2;
const IKE_INIT_SPI: u64 = 0x0102_0304_0506_0708;
const IKE_RESP_SPI: u64 = 0x1112_1314_1516_1718;
const SPI_REMOTE_ESP_UDP: u32 = 0x00ca_fe00;
const SPI_LOCAL_ESP_UDP: u32 = 0x00ca_fe01;
const SPI_LOCAL_NATIVE_ESP: u32 = 0x00ca_fe02;
const SPI_STALE_ESP_UDP: u32 = 0x00ca_fe03;
const SPI_UNKNOWN_NATIVE_ESP: u32 = 0x00ca_fe09;
const SPI_ATOMIC_ESP_UDP: u32 = 0x00ca_fe05;
const SPI_REPLACE_ESP_UDP: u32 = 0x00ca_fe06;
const SPI_CRASH_ESP_UDP: u32 = 0x00ca_fe07;

const CRASH_CHILD_ENV: &str = "OPC_IPSEC_LB_XDP_CRASH_CHILD";
const CRASH_INTERFACE_ENV: &str = "OPC_IPSEC_LB_XDP_CRASH_INTERFACE";
const CRASH_PIN_ROOT_ENV: &str = "OPC_IPSEC_LB_XDP_CRASH_PIN_ROOT";
const CRASH_HANDOFF_ENV: &str = "OPC_IPSEC_LB_XDP_CRASH_HANDOFF";
const CRASH_READY_ENV: &str = "OPC_IPSEC_LB_XDP_CRASH_READY";

const MAP_SLOT_A: &str = "maps-v4-a";
const MAP_SLOT_B: &str = "maps-v4-b";
const HANDOFF_LINK: &str = "upgrade-link";
const CONTROL_DIRECTORY: &str = "control";
const FROZEN_XDP_V3: &[u8] = include_bytes!("fixtures/xdp-upgrade/opc-ipsec-lb-xdp-v3.bpf.o");
const CURRENT_XDP: &[u8] = include_bytes!("../bpf/opc-ipsec-lb-xdp.bpf.o");

static PROVISION_SEQ: AtomicU32 = AtomicU32::new(0);
static PRIVILEGED_PORT_GUARD: Mutex<()> = Mutex::new(());

fn lock_privileged_test_ports() -> MutexGuard<'static, ()> {
    match PRIVILEGED_PORT_GUARD.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn run(program: &str, args: &[&str]) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Run `f` on a thread joined to the named netns; sockets it creates keep
/// that namespace for their lifetime.
fn in_netns<T: Send + 'static>(namespace: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let path = format!("/run/netns/{namespace}");
    std::thread::spawn(move || {
        let file = fs::File::open(&path).expect("open netns handle");
        nix::sched::setns(file, nix::sched::CloneFlags::CLONE_NEWNET).expect("setns");
        f()
    })
    .join()
    .expect("netns thread")
}

struct Provision {
    peer_ns: String,
    redir_ns: String,
    pub_main: String,
    pub_peer: String,
    hand_main: String,
    hand_peer: String,
    down_main: String,
    pin_root: PathBuf,
}

impl Provision {
    fn new() -> Self {
        let seq = PROVISION_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let provision = Self {
            peer_ns: format!("opx{pid}s{seq}p"),
            redir_ns: format!("opx{pid}s{seq}r"),
            pub_main: format!("xp{seq}a"),
            pub_peer: format!("xp{seq}b"),
            hand_main: format!("xh{seq}a"),
            hand_peer: format!("xh{seq}b"),
            down_main: format!("xd{seq}a"),
            pin_root: PathBuf::from(format!("/sys/fs/bpf/opc-xdp308-{pid}-{seq}")),
        };

        run("ip", &["netns", "add", &provision.peer_ns]);
        run("ip", &["netns", "add", &provision.redir_ns]);
        run(
            "ip",
            [
                "link",
                "add",
                &provision.pub_main,
                "type",
                "veth",
                "peer",
                "name",
                &provision.pub_peer,
            ]
            .as_ref(),
        );
        run(
            "ip",
            [
                "link",
                "set",
                &provision.pub_peer,
                "netns",
                &provision.peer_ns,
            ]
            .as_ref(),
        );
        run(
            "ip",
            [
                "link",
                "add",
                &provision.hand_main,
                "type",
                "veth",
                "peer",
                "name",
                &provision.hand_peer,
            ]
            .as_ref(),
        );
        run(
            "ip",
            [
                "link",
                "set",
                &provision.hand_peer,
                "netns",
                &provision.redir_ns,
            ]
            .as_ref(),
        );
        run(
            "ip",
            ["addr", "add", "203.0.113.7/24", "dev", &provision.pub_main].as_ref(),
        );
        run("ip", ["link", "set", &provision.pub_main, "up"].as_ref());
        run(
            "ip",
            [
                "-n",
                &provision.peer_ns,
                "addr",
                "add",
                "203.0.113.9/24",
                "dev",
                &provision.pub_peer,
            ]
            .as_ref(),
        );
        run(
            "ip",
            [
                "-n",
                &provision.peer_ns,
                "link",
                "set",
                &provision.pub_peer,
                "up",
            ]
            .as_ref(),
        );
        run("ip", ["link", "set", &provision.hand_main, "up"].as_ref());
        run(
            "ip",
            [
                "-n",
                &provision.redir_ns,
                "link",
                "set",
                &provision.hand_peer,
                "up",
            ]
            .as_ref(),
        );
        // A deliberately DOWN veth pair used to prove attach-time hand-off
        // validation rejects unusable redirect channels.
        run(
            "ip",
            [
                "link",
                "add",
                &provision.down_main,
                "type",
                "veth",
                "peer",
                "name",
                &format!("xd{seq}b"),
            ]
            .as_ref(),
        );
        provision
    }
}

impl Drop for Provision {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", &self.down_main])
            .output();
        for namespace in [&self.peer_ns, &self.redir_ns] {
            let _ = Command::new("ip")
                .args(["netns", "del", namespace])
                .output();
        }
        let _ = fs::remove_dir_all(&self.pin_root);
    }
}

fn packet_capture_socket(namespace: &str) -> OwnedFd {
    use nix::sys::socket::{
        setsockopt, socket, sockopt, AddressFamily, SockFlag, SockProtocol, SockType,
    };

    let namespace = namespace.to_owned();
    in_netns(&namespace, || {
        let socket = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::EthAll,
        )
        .expect("open AF_PACKET capture socket");
        setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::new(0, 200_000))
            .expect("set capture timeout");
        socket
    })
}

fn udp_send_socket(namespace: &str) -> UdpSocket {
    in_netns(namespace, || {
        UdpSocket::bind("0.0.0.0:0").expect("bind peer UDP socket")
    })
}

/// IPPROTO_RAW send socket (implies IP_HDRINCL), used to emit hand-built
/// native ESP packets without link-layer access.
fn raw_ip_send_socket(namespace: &str) -> OwnedFd {
    use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};

    let namespace = namespace.to_owned();
    in_netns(&namespace, || {
        socket(
            AddressFamily::Inet,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::Raw,
        )
        .expect("open raw IP send socket")
    })
}

fn main_capture_socket() -> OwnedFd {
    use nix::sys::socket::{
        setsockopt, socket, sockopt, AddressFamily, SockFlag, SockProtocol, SockType,
    };

    let socket = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthAll,
    )
    .expect("open main AF_PACKET capture socket");
    setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::new(0, 200_000))
        .expect("set main capture timeout");
    socket
}

fn send_udp(socket: &UdpSocket, destination_port: u16, payload: &[u8]) {
    let sent = socket
        .send_to(payload, SocketAddr::new(VIP4.into(), destination_port))
        .expect("send UDP datagram");
    assert_eq!(sent, payload.len(), "short UDP send");
}

fn send_esp(socket: &OwnedFd, payload: &[u8]) {
    let packet = ipv4_packet(50, PEER4, VIP4.octets(), payload);
    let destination = SockaddrIn::new(203, 0, 113, 7, 0);
    let sent = sendto(socket.as_raw_fd(), &packet, &destination, MsgFlags::empty())
        .expect("send native ESP packet");
    assert_eq!(sent, packet.len(), "short ESP send");
}

/// Capture one peer-originated IPv4 UDP frame and its AF_PACKET address so a
/// synthetic Ethernet fixture can be injected through the same veth.
fn capture_peer_udp_frame(socket: &OwnedFd, destination_port: u16) -> (Vec<u8>, LinkAddr) {
    let mut buffer = vec![0_u8; 65_536];
    for _ in 0..64 {
        let (length, address) = recvfrom::<LinkAddr>(socket.as_raw_fd(), &mut buffer)
            .expect("capture peer UDP template frame");
        let frame = &buffer[..length];
        if frame.len() < 14 + 20 + 8 || frame[12..14] != [0x08, 0x00] {
            continue;
        }
        let ip = &frame[14..];
        let header_len = usize::from(ip[0] & 0x0f) * 4;
        if header_len < 20 || ip.len() < header_len + 8 || ip[9] != 17 {
            continue;
        }
        if u16::from_be_bytes([ip[header_len + 2], ip[header_len + 3]]) != destination_port {
            continue;
        }
        return (
            frame.to_vec(),
            address.expect("captured peer frame address"),
        );
    }
    panic!("did not capture peer UDP/{destination_port} template frame")
}

/// Inject an IPv6 extension-shaped + UDP/500 packet. Its zero UDP checksum is
/// intentionally irrelevant: XDP must hand the packet to the userspace slow
/// path based on the base header's extension kind before transport
/// interpretation.
fn send_ipv6_extension_frame(
    socket: &OwnedFd,
    address: &LinkAddr,
    ethernet_template: &[u8],
    extension_kind: u8,
    ike_payload: &[u8],
) {
    let udp_len = 8 + ike_payload.len();
    let ipv6_payload_len = 8 + udp_len;
    let mut frame = Vec::with_capacity(14 + 40 + ipv6_payload_len);
    frame.extend_from_slice(&ethernet_template[..12]);
    frame.extend_from_slice(&[0x86, 0xdd]);
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&(ipv6_payload_len as u16).to_be_bytes());
    frame.push(extension_kind);
    frame.push(64);
    frame.extend_from_slice(&PEER6);
    frame.extend_from_slice(&VIP6);
    frame.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]); // UDP + six Pad1 octets
    frame.extend_from_slice(&45_000_u16.to_be_bytes());
    frame.extend_from_slice(&500_u16.to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(ike_payload);

    let sent = sendto(socket.as_raw_fd(), &frame, address, MsgFlags::empty())
        .expect("inject IPv6 extension-bearing frame");
    assert_eq!(sent, frame.len(), "short AF_PACKET frame send");
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..].copy_from_slice(payload);
    packet
}

/// Drain a UDP socket until the read timeout expires, returning payloads.
fn drain_udp(socket: &UdpSocket) -> Vec<Vec<u8>> {
    let mut received = Vec::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        match socket.recv(&mut buffer) {
            Ok(length) => received.push(buffer[..length].to_vec()),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                return received;
            }
            Err(error) => panic!("UDP drain failed: {error}"),
        }
    }
}

/// Drain a raw/packet fd until the timeout expires, returning frames.
fn drain_fd(fd: &OwnedFd) -> Vec<Vec<u8>> {
    let mut received = Vec::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        match recv(fd.as_raw_fd(), &mut buffer, MsgFlags::empty()) {
            Ok(length) => received.push(buffer[..length].to_vec()),
            Err(_) => return received,
        }
    }
}

/// Extract the ESP SPI from an AF_PACKET-captured frame carrying native ESP.
fn capture_esp_spi(frame: &[u8]) -> Option<u32> {
    let ip = frame.get(14..)?;
    if ip.len() < 20 || ip[9] != 50 {
        return None;
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    let bytes: [u8; 4] = ip.get(ihl..ihl + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn ike_header(initiator: u64, responder: u64, exchange: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(28 + payload.len());
    header.extend_from_slice(&initiator.to_be_bytes());
    header.extend_from_slice(&responder.to_be_bytes());
    header.push(0x20); // next payload: SA
    header.push(0x20); // IKEv2
    header.push(exchange);
    header.push(0x08); // initiator flag
    header.extend_from_slice(&[0, 0, 0, 0]);
    header.extend_from_slice(&((28 + payload.len()) as u32).to_be_bytes());
    header.extend_from_slice(payload);
    header
}

fn esp_packet(spi: u32, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.extend_from_slice(&spi.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn destination_context() -> DestinationContext {
    DestinationContext::new(IpAddress::V4(VIP4.octets()), RoutingDomainTag::new(DOMAIN))
}

fn esp_udp_key(spi: u32) -> SessionOwnershipKey {
    SessionOwnershipKey::Esp(EspOwnershipKey::new(
        destination_context(),
        EspEncapsulationKind::UdpEncapsulated,
        EspSpi::new(spi).expect("allocatable SPI"),
    ))
}

fn native_esp_key(spi: u32) -> SessionOwnershipKey {
    SessionOwnershipKey::Esp(EspOwnershipKey::new(
        destination_context(),
        EspEncapsulationKind::Native,
        EspSpi::new(spi).expect("allocatable SPI"),
    ))
}

fn established_ike_key() -> SessionOwnershipKey {
    SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
        destination_context(),
        IkeSpi::new(IKE_INIT_SPI).expect("nonzero"),
        IkeSpi::new(IKE_RESP_SPI).expect("nonzero"),
    ))
}

fn fixed_owner_map_key(key: &SessionOwnershipKey) -> [u8; OWNER_KEY_LEN] {
    let canonical = key.to_canonical_bytes();
    assert!(
        canonical.len() < OWNER_KEY_LEN,
        "canonical key fits map key"
    );
    let mut map_key = [0_u8; OWNER_KEY_LEN];
    map_key[0] = u8::try_from(canonical.len()).expect("canonical key length fits u8");
    map_key[1..1 + canonical.len()].copy_from_slice(&canonical);
    map_key
}

fn pinned_owner_map(
    pin_dir: &Path,
) -> BpfHashMap<MapData, [u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_OWNERS)).expect("open pinned owner map"),
    )
    .expect("identify pinned owner map");
    BpfHashMap::try_from(map).expect("typed pinned owner map")
}

fn pinned_fence_map(pin_dir: &Path) -> BpfHashMap<MapData, u32, u64> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_FENCE)).expect("open pinned fence map"),
    )
    .expect("identify pinned fence map");
    BpfHashMap::try_from(map).expect("typed pinned fence map")
}

fn pinned_key_fence_map(pin_dir: &Path) -> BpfHashMap<MapData, [u8; OWNER_KEY_LEN], u64> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_KEY_FENCES)).expect("open pinned key-fence map"),
    )
    .expect("identify pinned key-fence map");
    BpfHashMap::try_from(map).expect("typed pinned key-fence map")
}

fn backend_config(provision: &Provision, handoff_ifindex: u32) -> HostXdpSteeringBackendConfig {
    HostXdpSteeringBackendConfig {
        bpffs_pin_root: provision.pin_root.clone(),
        self_shard: ShardId::new(SELF_SHARD),
        routing_domain: RoutingDomainTag::new(DOMAIN),
        fence_domain: HostXdpFenceDomain::Global,
        redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
            ifindex: NonZeroU32::new(handoff_ifindex).expect("nonzero hand-off ifindex"),
        },
        attach_mode: HostXdpAttachMode::Generic,
    }
}

fn destination_scoped_backend_config(
    provision: &Provision,
    handoff_ifindex: u32,
) -> HostXdpSteeringBackendConfig {
    HostXdpSteeringBackendConfig {
        fence_domain: HostXdpFenceDomain::PerOwnershipKey,
        ..backend_config(provision, handoff_ifindex)
    }
}

fn legacy_config_bytes(version: u8, fence: u64, handoff_ifindex: u32) -> [u8; CONFIG_VALUE_LEN] {
    let mut config = XdpDatapathConfig {
        fence_mode: XdpFenceMode::Global,
        self_shard: SELF_SHARD,
        routing_domain: DOMAIN,
        handoff_ifindex,
    }
    .encode();
    config[0] = version;
    if version == 1 {
        config[12..20].copy_from_slice(&fence.to_be_bytes());
    }
    config
}

fn load_v3_namespace(pin_dir: &Path, version: u8, fence: u64, handoff_ifindex: u32) -> Ebpf {
    fs::create_dir_all(pin_dir).expect("create frozen-v3 map namespace");
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_dir)
        .load(FROZEN_XDP_V3)
        .expect("load frozen-v3 XDP object");
    let mut config = Array::<_, [u8; CONFIG_VALUE_LEN]>::try_from(
        ebpf.map_mut(MAP_CONFIG).expect("frozen-v3 config map"),
    )
    .expect("frozen-v3 config array");
    config
        .set(
            CONFIG_KEY,
            legacy_config_bytes(version, fence, handoff_ifindex),
            0,
        )
        .expect("initialize frozen-v3 config");
    let mut fence_map =
        BpfHashMap::<_, u32, u64>::try_from(ebpf.map_mut(MAP_FENCE).expect("frozen-v3 fence map"))
            .expect("frozen-v3 fence hash");
    fence_map
        .insert(FENCE_KEY, fence, 0)
        .expect("initialize frozen-v3 fence");
    ebpf
}

fn create_v1_namespace(interface_dir: &Path, fence: u64, handoff_ifindex: u32) {
    let ebpf = load_v3_namespace(interface_dir, 1, fence, handoff_ifindex);
    drop(ebpf);
    fs::remove_file(interface_dir.join(MAP_FENCE)).expect("v1 has no separate fence pin");
}

fn create_current_namespace(pin_dir: &Path, fence: u64, handoff_ifindex: u32) {
    fs::create_dir_all(pin_dir).expect("create current map namespace");
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_dir)
        .load(CURRENT_XDP)
        .expect("load current XDP object");
    let mut config = BpfHashMap::<_, u32, [u8; CONFIG_VALUE_LEN]>::try_from(
        ebpf.map_mut(MAP_CONFIG).expect("current config map"),
    )
    .expect("current config hash");
    config
        .insert(
            CONFIG_KEY,
            legacy_config_bytes(XDP_CONFIG_ABI_VERSION, fence, handoff_ifindex),
            0,
        )
        .expect("initialize current config");
    let mut fence_map =
        BpfHashMap::<_, u32, u64>::try_from(ebpf.map_mut(MAP_FENCE).expect("current fence map"))
            .expect("current fence hash");
    fence_map
        .insert(FENCE_KEY, fence, 0)
        .expect("initialize current fence");
    drop(ebpf);
}

fn install_frozen_v3_handoff(provision: &Provision, fence: u64, handoff_ifindex: u32) {
    let interface_dir = provision.pin_root.join(&provision.pub_main);
    let mut ebpf = load_v3_namespace(&interface_dir, 3, fence, handoff_ifindex);
    let program: &mut Xdp = ebpf
        .program_mut(PROG_SWU_XDP)
        .expect("frozen-v3 XDP program")
        .try_into()
        .expect("frozen-v3 program type");
    program.load().expect("load frozen-v3 program");
    let aya_link_id = program
        .attach(&provision.pub_main, XdpMode::Skb)
        .expect("attach frozen-v3 program");
    let aya_link = program
        .take_link(aya_link_id)
        .expect("take frozen-v3 XDP link");
    let fd_link = FdLink::try_from(aya_link).expect("kernel must provide an XDP bpf_link");
    let pinned = fd_link
        .pin(interface_dir.join(HANDOFF_LINK))
        .expect("pin frozen-v3 handoff link");
    drop(pinned);
    drop(ebpf);
}

fn assert_preserved_fence(backend: &HostXdpSteeringBackend, fence: u64) {
    assert!(
        matches!(
            block_on(backend.advance_fence(fence)),
            Err(opc_ipsec_lb::IpsecLbError::OwnershipConflict { .. })
        ),
        "restart must reject regression to the recovered fence"
    );
    block_on(backend.advance_fence(fence + 1)).expect("advance beyond recovered fence");
}

fn run_crash_owner_child() {
    let interface = env::var(CRASH_INTERFACE_ENV).expect("crash child interface");
    let pin_root = PathBuf::from(env::var_os(CRASH_PIN_ROOT_ENV).expect("crash child pin root"));
    let handoff_ifindex = env::var(CRASH_HANDOFF_ENV)
        .expect("crash child hand-off")
        .parse::<u32>()
        .expect("numeric crash child hand-off");
    let ready = PathBuf::from(env::var_os(CRASH_READY_ENV).expect("crash child ready path"));
    let backend = HostXdpSteeringBackend::new(
        interface,
        HostXdpSteeringBackendConfig {
            bpffs_pin_root: pin_root,
            self_shard: ShardId::new(SELF_SHARD),
            routing_domain: RoutingDomainTag::new(DOMAIN),
            fence_domain: HostXdpFenceDomain::Global,
            redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
                ifindex: NonZeroU32::new(handoff_ifindex).expect("nonzero crash hand-off"),
            },
            attach_mode: HostXdpAttachMode::Generic,
        },
    );
    block_on(backend.attach()).expect("crash child attach");
    block_on(backend.install_owner(
        &esp_udp_key(SPI_CRASH_ESP_UDP),
        ShardId::new(REMOTE_SHARD),
        7,
    ))
    .expect("crash child owner install");
    block_on(backend.advance_fence(6)).expect("crash child fence");
    fs::write(ready, b"ready").expect("publish crash child readiness");

    // The parent must terminate this process with SIGKILL. Keep a bound so a
    // failed parent cannot leave an orphaned privileged test indefinitely.
    std::thread::sleep(Duration::from_secs(30));
    panic!("crash child was not killed by its parent");
}

/// Drive the async backend API from plain threads.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("ad-hoc runtime")
        .block_on(future)
}

#[test]
#[ignore = "requires root (CAP_SYS_ADMIN/CAP_NET_ADMIN), a fresh netns, and bpffs"]
fn xdp_upgrade_crash_recovery_and_v3_handoff() {
    if env::var("OPC_IPSEC_LB_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_IPSEC_LB_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return;
    }
    let _port_guard = lock_privileged_test_ports();

    // Every SDK-produced current-schema/global cleanup cut must retain a
    // readable scalar-fence witness.
    // A second complete namespace at the same maximum proves recovery never
    // regresses even when the interrupted namespace is selected for staging.
    const CURRENT_GLOBAL_FENCE: u64 = 41;
    for cut_after in 1..=5 {
        let provision = Provision::new();
        let handoff_ifindex = nix::net::if_::if_nametoindex(provision.hand_main.as_str())
            .expect("resolve hand-off ifindex");
        let config = backend_config(&provision, handoff_ifindex);
        let first = HostXdpSteeringBackend::new(provision.pub_main.clone(), config.clone());
        block_on(first.attach()).expect("attach first current namespace");
        block_on(first.advance_fence(CURRENT_GLOBAL_FENCE)).expect("seed first current fence");
        drop(first);

        let second = HostXdpSteeringBackend::new(provision.pub_main.clone(), config.clone());
        block_on(second.attach()).expect("stage second complete current namespace");
        drop(second);

        let slot_a = provision
            .pin_root
            .join(&provision.pub_main)
            .join(MAP_SLOT_A);
        for map_name in [
            MAP_OWNERS,
            MAP_COUNTERS,
            MAP_KEY_FENCES,
            MAP_CONFIG,
            MAP_FENCE,
        ]
        .into_iter()
        .take(cut_after)
        {
            fs::remove_file(slot_a.join(map_name)).expect("inject current cleanup crash cut");
        }

        let recovered = HostXdpSteeringBackend::new(provision.pub_main.clone(), config);
        block_on(recovered.attach()).expect("recover interrupted current cleanup");
        assert_preserved_fence(&recovered, CURRENT_GLOBAL_FENCE);
        block_on(recovered.detach()).expect("detach current recovery proof");
    }

    // Destination-scoped v5 cleanup removes the owner before its keyed fence,
    // then retains CONFIG and the nonzero carried scalar floor until the final
    // two cuts. Restart after every cut must preserve all remaining evidence
    // without rearming a stale owner.
    const V5_OWNER_GENERATION: u64 = 47;
    const V5_CARRIED_GLOBAL_FLOOR: u64 = 59;
    // The fifth removal is the completed cleanup, not an interruptible cut:
    // after deleting the final scalar FENCE there is no remaining namespace
    // evidence from which a crash recovery could reconstruct its value.
    for cut_after in 0..=4 {
        let provision = Provision::new();
        let handoff_ifindex = nix::net::if_::if_nametoindex(provision.hand_main.as_str())
            .expect("resolve hand-off ifindex");
        let config = destination_scoped_backend_config(&provision, handoff_ifindex);
        let first = HostXdpSteeringBackend::new(provision.pub_main.clone(), config.clone());
        block_on(first.attach()).expect("attach destination-scoped v5 namespace");

        let interface_dir = provision.pin_root.join(&provision.pub_main);
        let slot_a = interface_dir.join(MAP_SLOT_A);
        let slot_b = interface_dir.join(MAP_SLOT_B);
        let key = esp_udp_key(SPI_CRASH_ESP_UDP);
        let map_key = fixed_owner_map_key(&key);
        let raw_owner = XdpOwnerValue {
            owner_shard: REMOTE_SHARD,
            generation: V5_OWNER_GENERATION,
        }
        .encode();
        pinned_owner_map(&slot_a)
            .insert(map_key, raw_owner, 0)
            .expect("seed v5 owner witness");
        pinned_key_fence_map(&slot_a)
            .insert(map_key, V5_OWNER_GENERATION, 0)
            .expect("seed v5 keyed-fence witness");
        pinned_fence_map(&slot_a)
            .insert(FENCE_KEY, V5_CARRIED_GLOBAL_FLOOR, 0)
            .expect("seed v5 carried scalar floor");

        let packet_io = (cut_after <= 1).then(|| {
            let sender = udp_send_socket(&provision.peer_ns);
            let capture = packet_capture_socket(&provision.redir_ns);
            let local = UdpSocket::bind("0.0.0.0:4500").expect("bind keyed-v5 UDP/4500");
            local
                .set_read_timeout(Some(Duration::from_millis(200)))
                .expect("set keyed-v5 local timeout");
            (sender, capture, local)
        });
        if let Some((sender, capture, local)) = packet_io.as_ref() {
            send_udp(sender, 4500, &esp_packet(SPI_CRASH_ESP_UDP, 1, &[0x6a; 24]));
            std::thread::sleep(Duration::from_millis(100));
            assert!(drain_udp(local).is_empty());
            assert!(drain_fd(capture).iter().any(|frame| {
                frame
                    .windows(4)
                    .any(|window| window == SPI_CRASH_ESP_UDP.to_be_bytes())
            }));
        }

        // Keep the unpinned bpf_link owner alive through the live-packet
        // assertion. Dropping it is the simulated process crash that detaches
        // XDP while leaving the pinned map namespace for recovery.
        drop(first);

        for map_name in [
            MAP_OWNERS,
            MAP_COUNTERS,
            MAP_KEY_FENCES,
            MAP_CONFIG,
            MAP_FENCE,
        ]
        .into_iter()
        .take(cut_after)
        {
            fs::remove_file(slot_a.join(map_name)).expect("inject keyed-v5 cleanup crash cut");
        }

        let recovered = HostXdpSteeringBackend::new(provision.pub_main.clone(), config);
        block_on(recovered.attach()).expect("recover interrupted keyed-v5 cleanup");
        let active_slot = &slot_b;
        assert_eq!(
            pinned_fence_map(active_slot)
                .get(&FENCE_KEY, 0)
                .expect("read recovered carried scalar floor"),
            V5_CARRIED_GLOBAL_FLOOR
        );
        let recovered_owner = pinned_owner_map(active_slot).get(&map_key, 0);
        let recovered_key_fence = pinned_key_fence_map(active_slot).get(&map_key, 0);
        match cut_after {
            0 => {
                assert_eq!(recovered_owner.expect("read recovered owner"), raw_owner);
                assert!(recovered_key_fence.is_err());
            }
            1 | 2 => {
                assert!(recovered_owner.is_err());
                assert_eq!(
                    recovered_key_fence.expect("read recovered keyed fence"),
                    V5_OWNER_GENERATION
                );
            }
            3..=4 => {
                assert!(recovered_owner.is_err());
                assert!(recovered_key_fence.is_err());
            }
            _ => unreachable!("bounded cleanup cut"),
        }
        if let Some((sender, capture, local)) = packet_io.as_ref() {
            send_udp(sender, 4500, &esp_packet(SPI_CRASH_ESP_UDP, 2, &[0x6b; 24]));
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                drain_udp(local)
                    .iter()
                    .any(|payload| payload.starts_with(&SPI_CRASH_ESP_UDP.to_be_bytes())),
                "owner-only and fence-only recovery states must use the local slow path"
            );
            assert!(
                !drain_fd(capture).iter().any(|frame| {
                    frame
                        .windows(4)
                        .any(|window| window == SPI_CRASH_ESP_UDP.to_be_bytes())
                }),
                "recovered partial keyed state must never redirect"
            );
        }
        block_on(recovered.detach()).expect("detach keyed-v5 recovery proof");
    }

    // V1 stores the fence in config, so config must be the final deleted pin.
    // Exercise a restart after every possible v1 cleanup cut against another
    // complete namespace carrying the same maximum generation.
    const V1_FENCE: u64 = 53;
    for cut_after in 1..=3 {
        let provision = Provision::new();
        let handoff_ifindex = nix::net::if_::if_nametoindex(provision.hand_main.as_str())
            .expect("resolve hand-off ifindex");
        let interface_dir = provision.pin_root.join(&provision.pub_main);
        create_v1_namespace(&interface_dir, V1_FENCE, handoff_ifindex);

        let config = backend_config(&provision, handoff_ifindex);
        let staged = HostXdpSteeringBackend::new(provision.pub_main.clone(), config.clone());
        block_on(staged.attach()).expect("stage complete v5 namespace beside v1");
        drop(staged);

        for map_name in [MAP_OWNERS, MAP_COUNTERS, MAP_CONFIG]
            .into_iter()
            .take(cut_after)
        {
            fs::remove_file(interface_dir.join(map_name)).expect("inject v1 cleanup crash cut");
        }

        let recovered = HostXdpSteeringBackend::new(provision.pub_main.clone(), config);
        block_on(recovered.attach()).expect("recover interrupted v1 cleanup");
        assert_preserved_fence(&recovered, V1_FENCE);
        block_on(recovered.detach()).expect("detach v1 recovery proof");
    }

    // A unique maximum that exists only in a partial namespace must never be
    // erased as the staging target. The replacement namespace receives the
    // recovered generation before the old witness can be retired.
    const UNIQUE_MAX_FENCE: u64 = 67;
    {
        let provision = Provision::new();
        let handoff_ifindex = nix::net::if_::if_nametoindex(provision.hand_main.as_str())
            .expect("resolve hand-off ifindex");
        let interface_dir = provision.pin_root.join(&provision.pub_main);
        let slot_a = interface_dir.join(MAP_SLOT_A);
        let slot_b = interface_dir.join(MAP_SLOT_B);
        create_current_namespace(&slot_a, UNIQUE_MAX_FENCE, handoff_ifindex);
        for map_name in [MAP_OWNERS, MAP_COUNTERS, MAP_KEY_FENCES, MAP_CONFIG] {
            fs::remove_file(slot_a.join(map_name)).expect("create unique-max partial residue");
        }
        create_current_namespace(&slot_b, UNIQUE_MAX_FENCE - 1, handoff_ifindex);

        let recovered = HostXdpSteeringBackend::new(
            provision.pub_main.clone(),
            backend_config(&provision, handoff_ifindex),
        );
        block_on(recovered.attach()).expect("stage away from unique-max partial namespace");
        assert!(
            slot_a.join(MAP_FENCE).exists(),
            "the unique maximum witness must survive staging"
        );
        assert_eq!(
            pinned_fence_map(&slot_b)
                .get(&FENCE_KEY, 0)
                .expect("read replacement fence"),
            UNIQUE_MAX_FENCE,
            "the replacement must persist the maximum before old cleanup"
        );
        fs::remove_file(slot_a.join(MAP_FENCE)).expect("retire old maximum witness");
        assert_preserved_fence(&recovered, UNIQUE_MAX_FENCE);
        block_on(recovered.detach()).expect("detach unique-max proof");
    }

    // A partial namespace containing an alias of an active program map is not
    // disjoint crash residue. Adoption must fail before the exact link changes.
    {
        let provision = Provision::new();
        let handoff_ifindex = nix::net::if_::if_nametoindex(provision.hand_main.as_str())
            .expect("resolve hand-off ifindex");
        let config = backend_config(&provision, handoff_ifindex);
        let backend = HostXdpSteeringBackend::new(provision.pub_main.clone(), config.clone());
        block_on(backend.attach()).expect("attach active intersection proof");
        block_on(backend.advance_fence(79)).expect("seed active fence");
        block_on(backend.prepare_upgrade_handoff()).expect("prepare active handoff");

        let interface_dir = provision.pin_root.join(&provision.pub_main);
        let slot_a = interface_dir.join(MAP_SLOT_A);
        let slot_b = interface_dir.join(MAP_SLOT_B);
        fs::create_dir_all(&slot_b).expect("create intersecting partial namespace");
        MapData::from_pin(slot_a.join(MAP_OWNERS))
            .expect("open active owners map")
            .pin(slot_b.join(MAP_OWNERS))
            .expect("alias active owners map");
        MapData::from_pin(slot_a.join(MAP_FENCE))
            .expect("open active fence map")
            .pin(slot_b.join(MAP_FENCE))
            .expect("alias active fence map");

        let handoff_path = interface_dir.join(HANDOFF_LINK);
        let before = opc_linux_gtpu_sys::open_xdp_link_from_pin(&handoff_path)
            .expect("open handoff link before rejected adoption")
            .info()
            .expect("read handoff identity before rejected adoption");
        let successor = HostXdpSteeringBackend::new(provision.pub_main.clone(), config);
        assert!(
            matches!(
                block_on(successor.adopt_upgrade_handoff()),
                Err(opc_ipsec_lb::IpsecLbError::XdpUpgradeIndeterminate)
            ),
            "an active-map alias in partial residue must fail closed"
        );
        let after = opc_linux_gtpu_sys::open_xdp_link_from_pin(&handoff_path)
            .expect("open handoff link after rejected adoption")
            .info()
            .expect("read handoff identity after rejected adoption");
        assert_eq!(before, after, "rejected adoption must not mutate the link");
        drop(successor);
        drop(backend);
        fs::remove_file(handoff_path).expect("detach rejected handoff proof");
    }

    // The frozen v3 object is a genuinely distinct artifact (array config)
    // whose pinned link and maps must migrate to the current v5 hash schema.
    // A higher disjoint partial generation in the fixed target additionally
    // proves adoption persists the maximum into the active legacy namespace
    // before it erases and reconstructs that target.
    const V3_FENCE: u64 = 83;
    {
        let provision = Provision::new();
        let handoff_ifindex = nix::net::if_::if_nametoindex(provision.hand_main.as_str())
            .expect("resolve hand-off ifindex");
        install_frozen_v3_handoff(&provision, V3_FENCE, handoff_ifindex);
        let legacy_dir = provision.pin_root.join(&provision.pub_main);
        let retained_active_fence = pinned_fence_map(&legacy_dir);
        let target = provision
            .pin_root
            .join(&provision.pub_main)
            .join(MAP_SLOT_A);
        create_current_namespace(&target, V3_FENCE + 1, handoff_ifindex);
        for map_name in [MAP_OWNERS, MAP_COUNTERS, MAP_KEY_FENCES, MAP_CONFIG] {
            fs::remove_file(target.join(map_name)).expect("create higher target residue");
        }
        let successor = HostXdpSteeringBackend::new(
            provision.pub_main.clone(),
            backend_config(&provision, handoff_ifindex),
        );
        let outcome =
            block_on(successor.adopt_upgrade_handoff()).expect("adopt frozen-v3 handoff into v5");
        assert!(matches!(
            outcome,
            HostXdpUpgradeOutcome::Applied | HostXdpUpgradeOutcome::AppliedCleanupPending { .. }
        ));
        assert_eq!(
            retained_active_fence
                .get(&FENCE_KEY, 0)
                .expect("read retained legacy fence after migration"),
            V3_FENCE + 1,
            "adoption must persist the maximum into the active map before target erasure"
        );
        assert_preserved_fence(&successor, V3_FENCE + 1);
        block_on(successor.detach()).expect("detach v3-to-v5 proof");
    }
}

#[test]
#[ignore = "requires root (CAP_SYS_ADMIN/CAP_NET_ADMIN), a fresh netns, and bpffs"]
fn xdp_keyless_classification_and_owner_steering() {
    if env::var(CRASH_CHILD_ENV).as_deref() == Ok("1") {
        run_crash_owner_child();
        return;
    }
    if env::var("OPC_IPSEC_LB_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_IPSEC_LB_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return;
    }
    let _port_guard = lock_privileged_test_ports();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let provision = Provision::new();

    let sender = udp_send_socket(&provision.peer_ns);
    let esp_sender = raw_ip_send_socket(&provision.peer_ns);
    let frame_injector = packet_capture_socket(&provision.peer_ns);
    let capture_socket = packet_capture_socket(&provision.redir_ns);
    let main_capture = main_capture_socket();
    let hand_ifindex = nix::net::if_::if_nametoindex(provision.hand_main.as_str())
        .expect("resolve hand-off ifindex");

    let ike500 = UdpSocket::bind("0.0.0.0:500").expect("bind UDP/500");
    ike500
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set timeout");
    let natt4500 = UdpSocket::bind("0.0.0.0:4500").expect("bind UDP/4500");
    natt4500
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set timeout");
    // The replacement stage bursts hundreds of datagrams into this socket
    // before draining; give it headroom so no verdict is lost to the
    // receive-buffer watermark.
    nix::sys::socket::setsockopt(
        &natt4500,
        nix::sys::socket::sockopt::RcvBuf,
        &(16 * 1024 * 1024),
    )
    .expect("raise UDP/4500 receive buffer");
    let other9999 = UdpSocket::bind("0.0.0.0:9999").expect("bind UDP/9999");
    other9999
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set timeout");

    let config = HostXdpSteeringBackendConfig {
        bpffs_pin_root: provision.pin_root.clone(),
        self_shard: ShardId::new(SELF_SHARD),
        routing_domain: RoutingDomainTag::new(DOMAIN),
        fence_domain: HostXdpFenceDomain::Global,
        redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
            ifindex: NonZeroU32::new(hand_ifindex).expect("nonzero hand-off ifindex"),
        },
        // Generic attach mode so the veth hand-off delivers redirected frames
        // to the peer stack without a peer XDP consumer.
        attach_mode: HostXdpAttachMode::Generic,
    };

    // --- Stage A0: attach-time validation rejects an unusable hand-off. ---
    // A hand-off interface that is down or is the attached interface itself
    // must fail attach with a typed error: the helper-level return check
    // cannot catch every redirect failure (some kernels defer transmit
    // failures past the helper return), so validation is the enforceable
    // guard against a silently dropping redirect channel.
    let down_ifindex =
        nix::net::if_::if_nametoindex(provision.down_main.as_str()).expect("resolve down ifindex");
    let rejected = HostXdpSteeringBackend::new(
        provision.pub_main.clone(),
        HostXdpSteeringBackendConfig {
            redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
                ifindex: NonZeroU32::new(down_ifindex).expect("nonzero ifindex"),
            },
            ..config.clone()
        },
    );
    assert!(
        matches!(
            runtime.block_on(rejected.attach()),
            Err(opc_ipsec_lb::IpsecLbError::InvalidConfig { .. })
        ),
        "a down hand-off interface must reject attach"
    );
    let pub_ifindex =
        nix::net::if_::if_nametoindex(provision.pub_main.as_str()).expect("resolve public ifindex");
    let self_rejected = HostXdpSteeringBackend::new(
        provision.pub_main.clone(),
        HostXdpSteeringBackendConfig {
            redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
                ifindex: NonZeroU32::new(pub_ifindex).expect("nonzero ifindex"),
            },
            ..config.clone()
        },
    );
    assert!(
        matches!(
            runtime.block_on(self_rejected.attach()),
            Err(opc_ipsec_lb::IpsecLbError::InvalidConfig { .. })
        ),
        "a hand-off equal to the attached interface must reject attach"
    );

    let mut backend = HostXdpSteeringBackend::new(provision.pub_main.clone(), config.clone());
    runtime
        .block_on(backend.attach())
        .expect("attach XDP datapath");

    // Install owner records and raise the fence above the stale entry.
    let installs = [
        (established_ike_key(), SELF_SHARD, 5_u64),
        (esp_udp_key(SPI_REMOTE_ESP_UDP), REMOTE_SHARD, 5),
        (esp_udp_key(SPI_LOCAL_ESP_UDP), SELF_SHARD, 5),
        (native_esp_key(SPI_LOCAL_NATIVE_ESP), SELF_SHARD, 5),
        (esp_udp_key(SPI_STALE_ESP_UDP), SELF_SHARD, 2),
    ];
    for (key, owner, generation) in installs {
        runtime
            .block_on(backend.install_owner(&key, ShardId::new(owner), generation))
            .expect("install owner");
    }
    runtime
        .block_on(backend.advance_fence(5))
        .expect("advance fence");

    // --- Stage A: classification of all three classes and every verdict. ---
    let established_ike = ike_header(IKE_INIT_SPI, IKE_RESP_SPI, 35, &[0xaa; 12]);
    send_udp(&sender, 500, &established_ike);
    let (ethernet_template, peer_link_address) = capture_peer_udp_frame(&frame_injector, 500);
    let unclassifiable_before_extension = runtime
        .block_on(backend.counters())
        .expect("pre-extension counters")
        .unclassifiable;
    send_ipv6_extension_frame(
        &frame_injector,
        &peer_link_address,
        &ethernet_template,
        0, // Hop-by-Hop Options
        &established_ike,
    );
    send_ipv6_extension_frame(
        &frame_injector,
        &peer_link_address,
        &ethernet_template,
        140, // Shim6
        &established_ike,
    );
    let extension_deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let observed = runtime
            .block_on(backend.counters())
            .expect("extension counters")
            .unclassifiable;
        if observed >= unclassifiable_before_extension + 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < extension_deadline,
            "real IPv6 extension-bearing frame did not reach the unclassifiable slow path"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut marked_ike = vec![0, 0, 0, 0];
    marked_ike.extend_from_slice(&ike_header(IKE_INIT_SPI, IKE_RESP_SPI, 35, &[]));
    send_udp(&sender, 4500, &marked_ike);
    send_udp(
        &sender,
        4500,
        &esp_packet(SPI_REMOTE_ESP_UDP, 1, &[0x55; 24]),
    );
    send_udp(
        &sender,
        4500,
        &esp_packet(SPI_LOCAL_ESP_UDP, 1, &[0x56; 24]),
    );
    send_esp(
        &esp_sender,
        &esp_packet(SPI_LOCAL_NATIVE_ESP, 1, &[0x77; 24]),
    );
    send_esp(
        &esp_sender,
        &esp_packet(SPI_UNKNOWN_NATIVE_ESP, 1, &[0x78; 24]),
    );
    send_udp(
        &sender,
        4500,
        &esp_packet(SPI_STALE_ESP_UDP, 1, &[0x57; 24]),
    );
    send_udp(&sender, 4500, &[0x01, 0x02]);
    send_udp(&sender, 4500, &[0xff]);
    send_udp(&sender, 9999, &[0x42; 8]);

    // Give the stacks a moment, then collect.
    std::thread::sleep(Duration::from_millis(200));
    let udp500_received = drain_udp(&ike500);
    let udp4500_received = drain_udp(&natt4500);
    let udp9999_received = drain_udp(&other9999);
    let esp_received = drain_fd(&main_capture);
    let captured = drain_fd(&capture_socket);

    assert!(
        udp500_received
            .iter()
            .any(|payload| payload == &established_ike),
        "self-owned UDP/500 IKE must reach the local stack"
    );
    assert!(
        udp4500_received
            .iter()
            .any(|payload| payload == &marked_ike),
        "self-owned UDP/4500 marker IKE must reach the local stack"
    );
    assert!(
        udp4500_received
            .iter()
            .any(|payload| payload.starts_with(&SPI_LOCAL_ESP_UDP.to_be_bytes())),
        "self-owned ESP-in-UDP must reach the local stack"
    );
    assert!(
        esp_received
            .iter()
            .any(|frame| capture_esp_spi(frame) == Some(SPI_LOCAL_NATIVE_ESP)),
        "self-owned native ESP must reach the local stack"
    );
    assert!(
        esp_received
            .iter()
            .any(|frame| capture_esp_spi(frame) == Some(SPI_UNKNOWN_NATIVE_ESP)),
        "unknown native ESP must fail closed to the local stack, never drop"
    );
    assert!(
        udp4500_received
            .iter()
            .any(|payload| payload.starts_with(&SPI_STALE_ESP_UDP.to_be_bytes())),
        "stale-generation ESP-in-UDP must fail closed to the local stack"
    );
    assert!(
        udp4500_received
            .iter()
            .any(|payload| payload == &[0x01, 0x02]),
        "unclassifiable UDP/4500 candidate must reach the slow path"
    );
    assert!(
        udp4500_received.iter().any(|payload| payload == &[0xff]),
        "NAT-T keepalive must reach the local stack"
    );
    assert!(
        udp9999_received.iter().any(|payload| payload == &[0x42; 8]),
        "non-SWu traffic must pass untouched"
    );
    assert!(
        captured.iter().any(|frame| {
            frame
                .windows(4)
                .any(|window| window == SPI_REMOTE_ESP_UDP.to_be_bytes())
        }),
        "remote-owned ESP-in-UDP must arrive on the redirect hand-off interface"
    );
    assert!(
        !udp4500_received
            .iter()
            .any(|payload| payload.starts_with(&SPI_REMOTE_ESP_UDP.to_be_bytes())),
        "remote-owned ESP-in-UDP must NOT reach the local stack"
    );

    let counters = runtime.block_on(backend.counters()).expect("counters");
    assert_eq!(counters.local, 4, "local verdicts: {counters:?}");
    assert_eq!(counters.redirect, 1, "redirect verdicts: {counters:?}");
    assert_eq!(counters.miss, 1, "miss verdicts: {counters:?}");
    assert_eq!(counters.stale, 1, "stale verdicts: {counters:?}");
    assert!(
        counters.unclassifiable >= unclassifiable_before_extension + 3,
        "the extension-bearing and malformed UDP fixtures must all be unclassifiable: {counters:?}"
    );
    assert_eq!(counters.error, 0, "error verdicts: {counters:?}");
    assert_eq!(counters.natt_keepalive, 1, "keepalives: {counters:?}");
    assert!(
        counters.pass_non_swu >= 1,
        "pass-through (background ND traffic may add more): {counters:?}"
    );

    // --- Stage A1: a second writer's attach conflicts without touching state. ---
    // Writer B uses a different self shard: if its config leaked into the
    // pinned config map, writer A's remote-owned traffic would start
    // verdicting LOCAL. The attach must fail before any map is touched.
    let writer_b = HostXdpSteeringBackend::new(
        provision.pub_main.clone(),
        HostXdpSteeringBackendConfig {
            bpffs_pin_root: provision.pin_root.join("writer-b"),
            self_shard: ShardId::new(REMOTE_SHARD),
            routing_domain: RoutingDomainTag::new(DOMAIN),
            fence_domain: HostXdpFenceDomain::Global,
            redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
                ifindex: NonZeroU32::new(hand_ifindex).expect("nonzero hand-off ifindex"),
            },
            attach_mode: HostXdpAttachMode::Generic,
        },
    );
    assert!(
        matches!(
            runtime.block_on(writer_b.attach()),
            Err(opc_ipsec_lb::IpsecLbError::AlreadyExists)
        ),
        "a second writer on an occupied interface must conflict"
    );
    let rejected_pin_dir = provision
        .pin_root
        .join("writer-b")
        .join(&provision.pub_main);
    let rejected_entries = fs::read_dir(&rejected_pin_dir)
        .expect("read rejected writer pin directory")
        .map(|entry| entry.expect("read rejected writer pin entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        rejected_entries,
        [CONTROL_DIRECTORY],
        "the rejected writer may retain only its permanent lifecycle directory"
    );
    send_udp(
        &sender,
        4500,
        &esp_packet(SPI_REMOTE_ESP_UDP, 3, &[0x5c; 24]),
    );
    std::thread::sleep(Duration::from_millis(200));
    let captured_a1 = drain_fd(&capture_socket);
    assert!(
        captured_a1.iter().any(|frame| {
            frame
                .windows(4)
                .any(|window| window == SPI_REMOTE_ESP_UDP.to_be_bytes())
        }),
        "writer A must keep steering remote-owned traffic to the hand-off"
    );
    let counters = runtime.block_on(backend.counters()).expect("counters");
    assert_eq!(
        counters.local, 4,
        "the rejected writer's self shard must not leak: {counters:?}"
    );
    assert_eq!(counters.redirect, 2, "{counters:?}");

    // --- Stage B: atomic per-key update under concurrent traffic. ---
    let atomic_key = esp_udp_key(SPI_ATOMIC_ESP_UDP);
    runtime
        .block_on(backend.install_owner(&atomic_key, ShardId::new(SELF_SHARD), 1_000))
        .expect("install atomic key");
    let stop = Arc::new(AtomicBool::new(false));
    let writer = std::thread::spawn({
        let backend = backend.clone();
        let stop = stop.clone();
        move || {
            for round in 0_u64..200 {
                let (owner, generation) = if round % 2 == 0 {
                    (SELF_SHARD, 1_000 + round)
                } else {
                    (REMOTE_SHARD, 2_000 + round)
                };
                block_on(backend.install_owner(&atomic_key, ShardId::new(owner), generation))
                    .expect("atomic update");
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    });
    let reader = std::thread::spawn({
        let backend = backend.clone();
        let stop = stop.clone();
        move || {
            while !stop.load(Ordering::Relaxed) {
                if let Some((owner, generation)) =
                    block_on(backend.owner_record(&atomic_key)).expect("owner readback")
                {
                    let consistent = (owner.get() == SELF_SHARD
                        && (1_000..2_000).contains(&generation))
                        || (owner.get() == REMOTE_SHARD && generation >= 2_000);
                    assert!(
                        consistent,
                        "unexpected owner/generation pair observed: shard {} generation {}",
                        owner.get(),
                        generation
                    );
                }
            }
        }
    });
    for index in 0..200_u32 {
        send_udp(
            &sender,
            4500,
            &esp_packet(SPI_ATOMIC_ESP_UDP, index + 1, &[0x58; 24]),
        );
    }
    std::thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("writer thread");
    reader.join().expect("reader thread");

    // Exercise the kernel publication primitive directly, bypassing the
    // backend's userspace operation gate. Both maps are BPF_MAP_TYPE_HASH:
    // replacement publishes an immutable element, so every concurrent raw
    // read must equal one complete old or new value.
    let pin_dir = provision
        .pin_root
        .join(&provision.pub_main)
        .join(MAP_SLOT_A);
    let raw_atomic_key = fixed_owner_map_key(&atomic_key);
    let owner_a = XdpOwnerValue {
        owner_shard: SELF_SHARD,
        generation: 4_000,
    }
    .encode();
    let owner_b = XdpOwnerValue {
        owner_shard: REMOTE_SHARD,
        generation: 5_000,
    }
    .encode();
    {
        let mut owners = pinned_owner_map(&pin_dir);
        owners
            .insert(raw_atomic_key, owner_a, 0)
            .expect("seed owner publication stress");
        let mut fence = pinned_fence_map(&pin_dir);
        fence
            .insert(FENCE_KEY, 5_u64, 0)
            .expect("seed fence publication stress");
    }
    let publication_stop = Arc::new(AtomicBool::new(false));
    let publication_barrier = Arc::new(std::sync::Barrier::new(2));
    let publication_writer = std::thread::spawn({
        let pin_dir = pin_dir.clone();
        let publication_stop = publication_stop.clone();
        let publication_barrier = publication_barrier.clone();
        move || {
            let mut owners = pinned_owner_map(&pin_dir);
            let mut fence = pinned_fence_map(&pin_dir);
            publication_barrier.wait();
            for round in 0..50_000_u32 {
                let owner = if round & 1 == 0 { owner_a } else { owner_b };
                let fence_generation = if round & 1 == 0 { 5_u64 } else { 6_u64 };
                owners
                    .insert(raw_atomic_key, owner, 0)
                    .expect("replace owner element");
                fence
                    .insert(FENCE_KEY, fence_generation, 0)
                    .expect("replace fence element");
            }
            publication_stop.store(true, Ordering::Release);
        }
    });
    let publication_reader = std::thread::spawn({
        let pin_dir = pin_dir.clone();
        let publication_stop = publication_stop.clone();
        let publication_barrier = publication_barrier.clone();
        move || {
            let owners = pinned_owner_map(&pin_dir);
            let fence = pinned_fence_map(&pin_dir);
            let mut observations = 0_u64;
            publication_barrier.wait();
            while !publication_stop.load(Ordering::Acquire) || observations < 1_000 {
                let owner = owners
                    .get(&raw_atomic_key, 0)
                    .expect("read owner publication");
                assert!(
                    owner == owner_a || owner == owner_b,
                    "owner hash replacement exposed neither complete published value"
                );
                let fence_generation = fence.get(&FENCE_KEY, 0).expect("read fence publication");
                assert!(
                    fence_generation == 5 || fence_generation == 6,
                    "fence hash replacement exposed neither complete published value"
                );
                observations += 1;
            }
            observations
        }
    });
    publication_writer.join().expect("publication writer");
    let publication_observations = publication_reader.join().expect("publication reader");
    assert!(
        publication_observations >= 1_000,
        "publication stress must make repeated concurrent observations"
    );

    let udp4500_atomic = drain_udp(&natt4500)
        .into_iter()
        .filter(|payload| payload.starts_with(&SPI_ATOMIC_ESP_UDP.to_be_bytes()))
        .count();
    let captured_atomic = drain_fd(&capture_socket)
        .into_iter()
        .filter(|frame| {
            frame
                .windows(4)
                .any(|window| window == SPI_ATOMIC_ESP_UDP.to_be_bytes())
        })
        .count();
    assert_eq!(
        udp4500_atomic + captured_atomic,
        200,
        "every atomic-stage packet must arrive locally or on the hand-off interface"
    );
    let counters = runtime.block_on(backend.counters()).expect("counters");
    assert_eq!(
        counters.error, 0,
        "valid old-or-new publications must not surface as map errors: {counters:?}"
    );
    assert_eq!(
        counters.local + counters.redirect + counters.miss + counters.stale,
        4 + 2 + 1 + 1 + 200,
        "classified verdicts after the atomic stage: {counters:?}"
    );

    // --- Stage C: graceful process handoff under continuous traffic. ---
    let replace_key = esp_udp_key(SPI_REPLACE_ESP_UDP);
    runtime
        .block_on(backend.install_owner(&replace_key, ShardId::new(SELF_SHARD), 3_000))
        .expect("install replace key");
    let stop_sending = Arc::new(AtomicBool::new(false));
    let sender_thread = std::thread::spawn({
        let stop_sending = stop_sending.clone();
        let peer_ns = provision.peer_ns.clone();
        move || {
            let sender = udp_send_socket(&peer_ns);
            let mut sent = 0_u32;
            while !stop_sending.load(Ordering::Relaxed) {
                send_udp(
                    &sender,
                    4500,
                    &esp_packet(SPI_REPLACE_ESP_UDP, sent + 1, &[0x59; 24]),
                );
                sent += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
            sent
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    for _ in 0..3 {
        runtime
            .block_on(backend.prepare_upgrade_handoff())
            .expect("prepare graceful process handoff");
        let successor = HostXdpSteeringBackend::new(provision.pub_main.clone(), config.clone());
        let outcome = runtime
            .block_on(successor.adopt_upgrade_handoff())
            .expect("adopt graceful process handoff");
        assert!(matches!(
            outcome,
            HostXdpUpgradeOutcome::Applied | HostXdpUpgradeOutcome::AppliedCleanupPending { .. }
        ));
        backend = successor;
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(100));
    stop_sending.store(true, Ordering::Relaxed);
    let sent = sender_thread.join().expect("sender thread");
    std::thread::sleep(Duration::from_millis(300));

    let received = drain_udp(&natt4500)
        .into_iter()
        .filter(|payload| payload.starts_with(&SPI_REPLACE_ESP_UDP.to_be_bytes()))
        .count();
    assert_eq!(
        received as u32, sent,
        "no verdict gap across program replacement: sent {sent} received {received}"
    );
    let after = runtime.block_on(backend.counters()).expect("counters");
    assert_eq!(after.error, 0, "no errors across replacement: {after:?}");
    assert!(
        after.miss > 0,
        "the adopted empty-owner datapath must hand traffic to the slow path"
    );

    // --- Stage D: SIGKILL closes bpf_link; restart adopts only safe state. ---
    let crash_key = esp_udp_key(SPI_CRASH_ESP_UDP);
    runtime
        .block_on(backend.detach())
        .expect("detach before crash child");
    drop(backend);
    let config_template = HostXdpSteeringBackendConfig {
        bpffs_pin_root: provision.pin_root.clone(),
        self_shard: ShardId::new(SELF_SHARD),
        routing_domain: RoutingDomainTag::new(DOMAIN),
        fence_domain: HostXdpFenceDomain::Global,
        redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
            ifindex: NonZeroU32::new(hand_ifindex).expect("nonzero hand-off ifindex"),
        },
        attach_mode: HostXdpAttachMode::Generic,
    };

    let crash_ready = std::env::temp_dir().join(format!(
        "opc-xdp-crash-ready-{}-{}",
        std::process::id(),
        provision.pub_main
    ));
    let _ = fs::remove_file(&crash_ready);
    let mut crash_child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "xdp_keyless_classification_and_owner_steering",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CRASH_CHILD_ENV, "1")
        .env(CRASH_INTERFACE_ENV, &provision.pub_main)
        .env(CRASH_PIN_ROOT_ENV, &provision.pin_root)
        .env(CRASH_HANDOFF_ENV, hand_ifindex.to_string())
        .env(CRASH_READY_ENV, &crash_ready)
        .spawn()
        .expect("spawn crash owner process");
    let ready_deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !crash_ready.exists() && std::time::Instant::now() < ready_deadline {
        if crash_child.try_wait().expect("poll crash child").is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !crash_ready.exists() {
        let _ = crash_child.kill();
        let _ = crash_child.wait();
        panic!("crash child did not publish readiness");
    }

    // Prove that the child owns the live bpf_link and that its fresh remote
    // owner record is executing before termination.
    send_udp(
        &sender,
        4500,
        &esp_packet(SPI_CRASH_ESP_UDP, 1, &[0x5a; 24]),
    );
    std::thread::sleep(Duration::from_millis(200));
    let before_kill_local = drain_udp(&natt4500)
        .iter()
        .any(|payload| payload.starts_with(&SPI_CRASH_ESP_UDP.to_be_bytes()));
    let before_kill_redirect = drain_fd(&capture_socket).iter().any(|frame| {
        frame
            .windows(4)
            .any(|window| window == SPI_CRASH_ESP_UDP.to_be_bytes())
    });

    crash_child.kill().expect("SIGKILL crash owner process");
    let crash_status = crash_child.wait().expect("reap crash owner process");
    let _ = fs::remove_file(&crash_ready);
    assert!(
        !crash_status.success(),
        "crash proof requires abnormal exit"
    );
    assert!(
        before_kill_redirect,
        "the child-owned live datapath must execute the remote-owner verdict"
    );
    assert!(
        !before_kill_local,
        "the child-owned remote record must not pass to the local stack"
    );

    // SIGKILL closes the unpinned bpf_link but leaves the pinned maps. Verify
    // the exact crash residue before the replacement process adopts it.
    let pin_dir = provision
        .pin_root
        .join(&provision.pub_main)
        .join(MAP_SLOT_A);
    let raw_crash_key = fixed_owner_map_key(&crash_key);
    let crash_owner = pinned_owner_map(&pin_dir)
        .get(&raw_crash_key, 0)
        .expect("read crash-residue owner");
    assert_eq!(
        crash_owner,
        XdpOwnerValue {
            owner_shard: REMOTE_SHARD,
            generation: 7,
        }
        .encode(),
        "the killed process must leave its exact pinned owner record"
    );
    assert_eq!(
        pinned_fence_map(&pin_dir)
            .get(&FENCE_KEY, 0)
            .expect("read crash-residue fence"),
        6,
        "the killed process must leave its committed fence pinned"
    );

    // The restarted process adopts the pins: owners are flushed and the
    // persisted fence is honored, so the killed process's owner cannot steer.
    let restarted = HostXdpSteeringBackend::new(provision.pub_main.clone(), config_template);
    let attach_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match runtime.block_on(restarted.attach()) {
            Ok(()) => break,
            Err(opc_ipsec_lb::IpsecLbError::AlreadyExists)
                if std::time::Instant::now() < attach_deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("re-attach after killed bpf_link failed: {error}"),
        }
    }
    assert_eq!(
        runtime
            .block_on(restarted.owner_record(&crash_key))
            .expect("readback"),
        None,
        "adopted pins must not carry the crashed process's owners"
    );
    let fence_regression = runtime.block_on(restarted.advance_fence(6));
    assert!(
        matches!(
            fence_regression,
            Err(opc_ipsec_lb::IpsecLbError::OwnershipConflict { .. })
        ),
        "the persisted fence must survive the restart"
    );
    send_udp(
        &sender,
        4500,
        &esp_packet(SPI_CRASH_ESP_UDP, 2, &[0x5b; 24]),
    );
    std::thread::sleep(Duration::from_millis(200));
    let udp4500_restart = drain_udp(&natt4500);
    assert!(
        udp4500_restart
            .iter()
            .any(|payload| payload.starts_with(&SPI_CRASH_ESP_UDP.to_be_bytes())),
        "re-attached datapath must fail closed to the slow path"
    );
    let redirect_after_restart = drain_fd(&capture_socket).iter().any(|frame| {
        frame
            .windows(4)
            .any(|window| window == SPI_CRASH_ESP_UDP.to_be_bytes())
    });
    assert!(
        !redirect_after_restart,
        "a killed process's flushed owner must never redirect after adoption"
    );
    let after_restart = runtime.block_on(restarted.counters()).expect("counters");
    assert_eq!(
        after_restart.local, 0,
        "the killed process's entry must never produce a LOCAL verdict"
    );
    assert_eq!(
        after_restart.redirect, 0,
        "a fresh crash-recovery namespace must not inherit the killed program's counters"
    );
    assert_eq!(
        after_restart.miss, 1,
        "flushed owners verdict as map miss (slow path)"
    );

    runtime.block_on(restarted.detach()).expect("detach");
}
