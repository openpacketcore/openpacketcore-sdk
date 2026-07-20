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
//! - atomic per-key owner updates: a concurrent reader never observes a torn
//!   owner/generation pair, and no packet is dropped or mis-verdicted;
//! - graceful program replacement under continuous traffic: counters persist
//!   through the swap and no verdict gap appears.
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
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::socket::{recv, sendto, MsgFlags, SockaddrIn};
use nix::sys::time::TimeVal;
use opc_ipsec_lb::model::{IpAddress, ShardId};
use opc_ipsec_lb::ownership::{
    DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi, EstablishedIkeOwnershipKey,
    IkeSpi, RoutingDomainTag, SessionOwnershipKey,
};
use opc_ipsec_lb::{
    HostXdpAttachMode, HostXdpRedirectHandoff, HostXdpSteeringBackend, HostXdpSteeringBackendConfig,
};

const VIP4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const PEER4: [u8; 4] = [203, 0, 113, 9];
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

static PROVISION_SEQ: AtomicU32 = AtomicU32::new(0);

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
        provision
    }
}

impl Drop for Provision {
    fn drop(&mut self) {
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

/// Drive the async backend API from plain threads.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("ad-hoc runtime")
        .block_on(future)
}

#[test]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
fn xdp_keyless_classification_and_owner_steering() {
    if env::var("OPC_IPSEC_LB_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_IPSEC_LB_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let provision = Provision::new();

    let sender = udp_send_socket(&provision.peer_ns);
    let esp_sender = raw_ip_send_socket(&provision.peer_ns);
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
        redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
            ifindex: NonZeroU32::new(hand_ifindex).expect("nonzero hand-off ifindex"),
        },
        // Generic attach mode so the veth hand-off delivers redirected frames
        // to the peer stack without a peer XDP consumer.
        attach_mode: HostXdpAttachMode::Generic,
    };
    let backend = HostXdpSteeringBackend::new(provision.pub_main.clone(), config);
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
    assert_eq!(
        counters.unclassifiable, 1,
        "unclassifiable verdicts: {counters:?}"
    );
    assert_eq!(counters.error, 0, "error verdicts: {counters:?}");
    assert_eq!(counters.natt_keepalive, 1, "keepalives: {counters:?}");
    assert!(
        counters.pass_non_swu >= 1,
        "pass-through (background ND traffic may add more): {counters:?}"
    );

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
                        "torn owner/generation pair observed: shard {} generation {}",
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
        "no torn values may surface: {counters:?}"
    );
    assert_eq!(
        counters.local + counters.redirect + counters.miss + counters.stale,
        4 + 1 + 1 + 1 + 200,
        "classified verdicts after the atomic stage: {counters:?}"
    );

    // --- Stage C: graceful program replacement under continuous traffic. ---
    let replace_key = esp_udp_key(SPI_REPLACE_ESP_UDP);
    runtime
        .block_on(backend.install_owner(&replace_key, ShardId::new(SELF_SHARD), 3_000))
        .expect("install replace key");
    let before = runtime.block_on(backend.counters()).expect("counters");
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
            .block_on(backend.replace())
            .expect("graceful program replacement");
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
        after.local >= before.local + u64::from(sent),
        "counters persist and keep accumulating across replacement"
    );

    runtime.block_on(backend.detach()).expect("detach");
}
