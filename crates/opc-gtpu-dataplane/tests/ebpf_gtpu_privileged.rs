//! Privileged end-to-end proof of the eBPF tc GTP-U datapath.
//!
//! Topology (all created inside the fresh netns the CI harness provides):
//!
//! ```text
//!   [ue netns]            [main netns = ePDG]              [pgw netns]
//!   ue1 10.45.0.2 ─veth─ ue0 10.45.0.1   192.0.2.1 s2bu ─veth─ s2bup 192.0.2.10
//!                         (forwarding, tc clsact eBPF on s2bu)
//! ```
//!
//! - **Uplink**: a plain UDP datagram sent from the UE address to 8.8.8.8 is
//!   forwarded by the ePDG netns to `s2bu`, where the tc egress program must
//!   GTP-U-encapsulate it toward the PGW. The PGW netns receives it on
//!   UDP/2152 and the test asserts the exact TS 29.281 bytes: outer source,
//!   GTP-U flags/type/length, the PGW-assigned O-TEID, and the intact inner
//!   packet. This is precisely the direction the mainline `gtp` netdevice
//!   cannot serve.
//! - **Downlink**: a G-PDU sent from the PGW on the ePDG's I-TEID must be
//!   decapsulated by the tc ingress program and *forwarded through the ePDG
//!   stack* (the position where XFRM policy applies) to the UE netns, which
//!   receives the inner UDP payload on an ordinary socket. Sequence-numbered
//!   G-PDUs (S flag) must decapsulate too; unknown TEIDs must be dropped;
//!   GTP-U echo requests must pass through to the local control plane.
//! - **Restore**: a second backend instance adopts the provisioned interface
//!   via `resolve_device`, re-installs the session idempotently, and the
//!   datapath keeps forwarding.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use aya::maps::MapInfo;
use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, DscpCodepoint, EbpfGtpuDataplaneBackend,
    EbpfGtpuDataplaneBackendConfig, GtpPdpContext, GtpVersion, GtpuCapability,
    GtpuDataplaneBackend, RemovePdpContextRequest, Teid,
};
use opc_gtpu_ebpf_common::{ipv4_header_checksum, MAP_UPLINK_DSCP, MAP_UPLINK_FAR};

const EPDG_S2BU_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PGW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const UE_PAA: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);
const REMOTE_HOST: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const LOCAL_TEID: u32 = 0x1000_0001;
const PEER_TEID: u32 = 0x2000_0001;
const GTPU_PORT: u16 = 2152;

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

/// Kernel-visible tc filter listing for one hook of the S2b-U interface.
fn tc_filters(direction: &str) -> String {
    let output = Command::new("tc")
        .args(["filter", "show", "dev", "s2bu", direction])
        .output()
        .expect("run tc filter show");
    assert!(output.status.success(), "tc filter show {direction} failed");
    String::from_utf8_lossy(&output.stdout).into_owned()
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

struct TestNet {
    pgw_ns: String,
    ue_ns: String,
    pin_root: PathBuf,
}

impl TestNet {
    fn provision() -> Self {
        let pid = std::process::id();
        let pgw_ns = format!("opc-pgw-{pid}");
        let ue_ns = format!("opc-ue-{pid}");
        let pin_root = PathBuf::from(format!("/sys/fs/bpf/opc-gtpu-test-{pid}"));

        run("ip", &["netns", "add", &pgw_ns]);
        run("ip", &["netns", "add", &ue_ns]);

        run(
            "ip",
            &[
                "link", "add", "s2bu", "type", "veth", "peer", "name", "s2bup",
            ],
        );
        run("ip", &["link", "set", "s2bup", "netns", &pgw_ns]);
        run(
            "ip",
            &["link", "add", "ue0", "type", "veth", "peer", "name", "ue1"],
        );
        run("ip", &["link", "set", "ue1", "netns", &ue_ns]);

        run("ip", &["addr", "add", "192.0.2.1/24", "dev", "s2bu"]);
        run("ip", &["link", "set", "s2bu", "up"]);
        run("ip", &["addr", "add", "10.45.0.1/24", "dev", "ue0"]);
        run("ip", &["link", "set", "ue0", "up"]);
        run("ip", &["route", "add", "8.8.8.8/32", "via", "192.0.2.10"]);

        run(
            "ip",
            &[
                "-n",
                &pgw_ns,
                "addr",
                "add",
                "192.0.2.10/24",
                "dev",
                "s2bup",
            ],
        );
        run("ip", &["-n", &pgw_ns, "link", "set", "s2bup", "up"]);
        run("ip", &["-n", &pgw_ns, "link", "set", "lo", "up"]);

        run(
            "ip",
            &["-n", &ue_ns, "addr", "add", "10.45.0.2/24", "dev", "ue1"],
        );
        run("ip", &["-n", &ue_ns, "link", "set", "ue1", "up"]);
        run("ip", &["-n", &ue_ns, "link", "set", "lo", "up"]);
        run(
            "ip",
            &["-n", &ue_ns, "route", "add", "default", "via", "10.45.0.1"],
        );

        fs::write("/proc/sys/net/ipv4/ip_forward", "1").expect("enable forwarding");
        for interface in ["all", "default", "s2bu", "ue0"] {
            let path = format!("/proc/sys/net/ipv4/conf/{interface}/rp_filter");
            fs::write(&path, "0").expect("relax rp_filter");
        }

        Self {
            pgw_ns,
            ue_ns,
            pin_root,
        }
    }
}

impl Drop for TestNet {
    fn drop(&mut self) {
        // Best-effort teardown; the CI netns is discarded anyway.
        let _ = Command::new("ip").args(["link", "del", "s2bu"]).output();
        let _ = Command::new("ip").args(["link", "del", "ue0"]).output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.pgw_ns])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.ue_ns])
            .output();
        let _ = fs::remove_dir_all(&self.pin_root);
    }
}

fn session_context(link_ifindex: u32) -> GtpPdpContext {
    GtpPdpContext {
        local_teid: Teid::new(LOCAL_TEID).expect("nonzero"),
        peer_teid: Teid::new(PEER_TEID).expect("nonzero"),
        ms_address: IpAddr::V4(UE_PAA),
        peer_address: IpAddr::V4(PGW_IP),
        link_ifindex,
        gtp_version: GtpVersion::V1,
        egress_dscp: None,
    }
}

fn marked_session_context(link_ifindex: u32) -> GtpPdpContext {
    let mut context = session_context(link_ifindex);
    context.egress_dscp = Some(DscpCodepoint::new(46).expect("valid EF codepoint"));
    context
}

/// Build an inner IPv4/UDP packet as it would leave the PGW toward the UE.
fn build_inner_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let mut header = [0_u8; 20];
    header.copy_from_slice(&packet[..20]);
    packet[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
    packet[20..22].copy_from_slice(&sport.to_be_bytes());
    packet[22..24].copy_from_slice(&dport.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

/// Build a G-PDU UDP payload (GTPv1-U header + inner packet) with optional
/// sequence-number block.
fn build_gpdu(teid: u32, sequence: Option<u16>, inner: &[u8]) -> Vec<u8> {
    let mut gpdu = Vec::with_capacity(12 + inner.len());
    match sequence {
        None => {
            gpdu.push(0x30);
            gpdu.push(0xFF);
            gpdu.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            gpdu.extend_from_slice(&teid.to_be_bytes());
        }
        Some(sequence) => {
            gpdu.push(0x32); // S flag
            gpdu.push(0xFF);
            gpdu.extend_from_slice(&((inner.len() + 4) as u16).to_be_bytes());
            gpdu.extend_from_slice(&teid.to_be_bytes());
            gpdu.extend_from_slice(&sequence.to_be_bytes());
            gpdu.push(0); // N-PDU number (ignored)
            gpdu.push(0); // no next extension header
        }
    }
    gpdu.extend_from_slice(inner);
    gpdu
}

/// Send `send()` up to ten times until `recv` yields a datagram; retries
/// absorb one-time neighbour resolution latency.
fn send_until_received(
    send: impl Fn(),
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> Option<(usize, SocketAddr)> {
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set timeout");
    for _ in 0..10 {
        send();
        if let Ok((len, from)) = socket.recv_from(buffer) {
            return Some((len, from));
        }
    }
    None
}

/// Receive one UDP datagram together with the kernel-reported outer IPv4 ToS.
fn send_until_received_with_tos(
    send: impl Fn(),
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> Option<(usize, SocketAddr, u8)> {
    use nix::sys::socket::{
        recvmsg, setsockopt, sockopt, ControlMessageOwned, MsgFlags, SockaddrIn,
    };

    setsockopt(socket, sockopt::IpRecvTos, &true).expect("enable IP_RECVTOS");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set timeout");
    for _ in 0..10 {
        send();
        let mut cmsg_space = nix::cmsg_space!(u8);
        let mut iov = [IoSliceMut::new(buffer)];
        if let Ok(message) = recvmsg::<SockaddrIn>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        ) {
            let from = SocketAddr::from(message.address?);
            let tos = message.cmsgs().ok()?.find_map(|control| match control {
                ControlMessageOwned::Ipv4Tos(value) => Some(value),
                _ => None,
            })?;
            return Some((message.bytes, from, tos));
        }
    }
    None
}

fn expect_no_datagram(socket: &UdpSocket) {
    let mut buffer = [0_u8; 2048];
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set timeout");
    match socket.recv_from(&mut buffer) {
        Ok((len, from)) => panic!("unexpected datagram ({len} bytes from {from})"),
        Err(error) => assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "unexpected recv error: {error}"
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_uplink_and_downlink_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let net = TestNet::provision();

    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let probe = backend.probe().await?;
    assert!(
        probe.mutation_ready,
        "probe must be mutation_ready in the privileged environment: {probe:?}"
    );

    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    assert_eq!(
        backend.probe().await?.egress_dscp_marking,
        GtpuCapability::Available,
        "loaded datapath must expose a usable DSCP map"
    );
    assert!(
        tc_filters("egress").contains("opc_gtpu_uplink"),
        "uplink program must be attached at tc egress"
    );
    assert!(
        tc_filters("ingress").contains("opc_gtpu_downlink"),
        "downlink program must be attached at tc ingress"
    );

    // A second live reconciler must not interleave map operations with the
    // current owner. Kernel-owned abstract socket lifetime makes this work
    // across independent backend instances and processes.
    let competing = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    assert!(matches!(
        competing.resolve_device("s2bu").await,
        Err(opc_gtpu_dataplane::GtpuError::AlreadyExists)
    ));
    drop(competing);
    let pin_alias = PathBuf::from(format!("/run/opc-gtpu-pin-alias-{}", std::process::id()));
    std::os::unix::fs::symlink(&net.pin_root, &pin_alias)
        .expect("create lexical alias for pin root");
    let aliased = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: pin_alias.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    assert!(matches!(
        aliased.resolve_device("s2bu").await,
        Err(opc_gtpu_dataplane::GtpuError::AlreadyExists)
    ));
    drop(aliased);
    fs::remove_file(&pin_alias).expect("remove pin-root alias");
    assert!(
        tc_filters("egress").contains("opc_gtpu_uplink")
            && tc_filters("ingress").contains("opc_gtpu_downlink"),
        "failed competing ownership and competitor drop must preserve both original filters"
    );

    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;
    // Re-install of identical absent-DSCP state must be idempotent success.
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;

    // Sockets living in the peer namespaces.
    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5000)).expect("bind UE socket")
    });
    // Local control-plane socket that must still see non-G-PDU GTP-U.
    let epdg_cp_socket = UdpSocket::bind((EPDG_S2BU_IP, GTPU_PORT))?;

    // --- Uplink: UE -> 8.8.8.8 must arrive at the PGW as a G-PDU. ---
    let mut buffer = [0_u8; 2048];
    let (_, from, outer_tos) = send_until_received_with_tos(
        || {
            let _ = ue_socket.send_to(b"opc-uplink-unmarked", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("unmarked uplink G-PDU must reach the PGW");
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
    assert_eq!(
        outer_tos, 0,
        "egress_dscp=None must preserve the legacy outer IPv4 ToS"
    );

    // Reconcile the exact FAR/PDR identity from absent to fixed EF marking.
    backend
        .install_pdp_context(marked_session_context(device.ifindex))
        .await?;
    backend
        .install_pdp_context(marked_session_context(device.ifindex))
        .await?;
    let (len, from, outer_tos) = send_until_received_with_tos(
        || {
            let _ = ue_socket.send_to(b"opc-uplink", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("uplink G-PDU must reach the PGW");
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
    assert_eq!(outer_tos >> 2, 46, "outer IPv4 DSCP must be EF");
    assert_eq!(outer_tos & 0x03, 0, "outer ECN bits must be preserved");
    let gpdu = &buffer[..len];
    assert_eq!(
        gpdu[0], 0x30,
        "GTP-U flags must be version 1, PT=1, no opts"
    );
    assert_eq!(gpdu[1], 0xFF, "message type must be G-PDU");
    let inner = &gpdu[8..];
    assert_eq!(
        u16::from_be_bytes([gpdu[2], gpdu[3]]) as usize,
        inner.len(),
        "GTP-U length must cover exactly the T-PDU"
    );
    assert_eq!(
        u32::from_be_bytes([gpdu[4], gpdu[5], gpdu[6], gpdu[7]]),
        PEER_TEID
    );
    assert_eq!(inner[0], 0x45);
    assert_eq!(
        &inner[12..16],
        &UE_PAA.octets(),
        "inner source must be the UE PAA"
    );
    assert_eq!(&inner[16..20], &REMOTE_HOST.octets());
    assert_eq!(inner[9], 17);
    assert_eq!(u16::from_be_bytes([inner[22], inner[23]]), 53);
    assert!(
        inner.ends_with(b"opc-uplink"),
        "inner payload must be intact"
    );

    // --- Downlink: G-PDU on our I-TEID must decap and forward to the UE. ---
    let inner_downlink = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"opc-downlink");
    let gpdu_downlink = build_gpdu(LOCAL_TEID, None, &inner_downlink);
    let (len, from) = send_until_received(
        || {
            let _ = pgw_socket.send_to(&gpdu_downlink, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &ue_socket,
        &mut buffer,
    )
    .expect("downlink inner packet must be forwarded to the UE");
    assert_eq!(&buffer[..len], b"opc-downlink");
    assert_eq!(from, SocketAddr::from((REMOTE_HOST, 53)));

    // Sequence-numbered G-PDU (S flag) must decapsulate as well.
    let inner_seq = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"opc-downlink-seq");
    let gpdu_seq = build_gpdu(LOCAL_TEID, Some(7), &inner_seq);
    let (len, _) = send_until_received(
        || {
            let _ = pgw_socket.send_to(&gpdu_seq, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &ue_socket,
        &mut buffer,
    )
    .expect("sequence-numbered downlink G-PDU must decapsulate");
    assert_eq!(&buffer[..len], b"opc-downlink-seq");

    // Unknown TEID must be dropped, not forwarded.
    let gpdu_unknown = build_gpdu(0xDEAD_BEEF, None, &inner_downlink);
    pgw_socket.send_to(&gpdu_unknown, (EPDG_S2BU_IP, GTPU_PORT))?;
    expect_no_datagram(&ue_socket);

    // GTP-U echo request (non-G-PDU) must pass through to the control plane.
    let echo_request: [u8; 12] = [0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0x00, 0x2A, 0x00, 0x00];
    let (len, from) = send_until_received(
        || {
            let _ = pgw_socket.send_to(&echo_request, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &epdg_cp_socket,
        &mut buffer,
    )
    .expect("GTP-U echo must reach the local control plane");
    assert_eq!(&buffer[..len], &echo_request);
    assert_eq!(from, SocketAddr::from((PGW_IP, GTPU_PORT)));

    // --- Restore: a fresh backend adopts the interface and state. ---
    drop(backend);
    let restored = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let adopted = restored.resolve_device("s2bu").await?;
    assert_eq!(adopted.ifindex, device.ifindex);
    restored
        .install_pdp_context(marked_session_context(adopted.ifindex))
        .await?;
    let (_, from) = send_until_received(
        || {
            let _ = ue_socket.send_to(b"opc-uplink-2", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("uplink must keep working after restore/adoption");
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));

    // --- Teardown: session removal is idempotent; device detaches. ---
    restored
        .remove_pdp_context(RemovePdpContextRequest::from_context(&session_context(
            adopted.ifindex,
        )))
        .await?;
    restored
        .remove_pdp_context(RemovePdpContextRequest::from_context(&session_context(
            adopted.ifindex,
        )))
        .await?;
    restored.remove_device(&adopted).await?;
    drop(restored);

    // Cleanup must be kernel-visible: no datapath filters on either hook and
    // no pinned map state left behind.
    for direction in ["egress", "ingress"] {
        let filters = tc_filters(direction);
        assert!(
            !filters.contains("opc_gtpu"),
            "no opc_gtpu filter may remain at tc {direction} after remove_device: {filters}"
        );
    }
    assert!(
        !net.pin_root.join("s2bu").exists(),
        "pinned maps must be removed with the device"
    );

    // --- Static pin-path replacement safety. ---
    // Swap two exact named pin paths while this test is the only writer. The
    // backend must fail closed before detaching either filter, preserve the
    // replacement at each path, and succeed once the original paths return.
    let pin_owner = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut pin_request = CreateGtpDeviceRequest::new("s2bu");
    pin_request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let pin_device = pin_owner.create_device(pin_request).await?;
    let pin_dir = net.pin_root.join("s2bu");
    let far_pin = pin_dir.join(MAP_UPLINK_FAR);
    let dscp_pin = pin_dir.join(MAP_UPLINK_DSCP);
    let swap_pin = pin_dir.join("static-pin-swap");
    let far_id = MapInfo::from_pin(&far_pin).expect("open FAR pin").id();
    let dscp_id = MapInfo::from_pin(&dscp_pin).expect("open DSCP pin").id();
    fs::rename(&far_pin, &swap_pin).expect("stage FAR pin swap");
    fs::rename(&dscp_pin, &far_pin).expect("replace FAR pin path");
    fs::rename(&swap_pin, &dscp_pin).expect("replace DSCP pin path");
    assert!(matches!(
        pin_owner.remove_device(&pin_device).await,
        Err(opc_gtpu_dataplane::GtpuError::AlreadyExists)
    ));
    assert_eq!(
        MapInfo::from_pin(&far_pin)
            .expect("replacement FAR path must survive")
            .id(),
        dscp_id
    );
    assert_eq!(
        MapInfo::from_pin(&dscp_pin)
            .expect("replacement DSCP path must survive")
            .id(),
        far_id
    );
    for direction in ["egress", "ingress"] {
        assert!(
            tc_filters(direction).contains("opc_gtpu"),
            "pin mismatch must preserve the {direction} filter"
        );
    }
    fs::rename(&far_pin, &swap_pin).expect("stage pin-path restore");
    fs::rename(&dscp_pin, &far_pin).expect("restore FAR pin path");
    fs::rename(&swap_pin, &dscp_pin).expect("restore DSCP pin path");
    pin_owner.remove_device(&pin_device).await?;
    drop(pin_owner);

    // --- External same-slot replacement safety. ---
    // Aya's netlink tc links identify a filter by slot. If an external actor
    // replaces both programs at that slot, neither remove_device nor dropping
    // the old loader may delete those replacements through stale link drops.
    let replacement_owner = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut replacement_request = CreateGtpDeviceRequest::new("s2bu");
    replacement_request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let replacement_device = replacement_owner.create_device(replacement_request).await?;
    for direction in ["egress", "ingress"] {
        run(
            "tc",
            &[
                "filter", "del", "dev", "s2bu", direction, "handle", "0x1", "pref", "50", "bpf",
            ],
        );
        run(
            "tc",
            &[
                "filter", "add", "dev", "s2bu", direction, "handle", "0x1", "pref", "50",
                "protocol", "all", "matchall", "action", "pass",
            ],
        );
    }
    assert_eq!(
        replacement_owner.probe().await?.egress_dscp_marking,
        GtpuCapability::Missing
    );
    assert!(matches!(
        replacement_owner
            .install_pdp_context(marked_session_context(replacement_device.ifindex))
            .await,
        Err(opc_gtpu_dataplane::GtpuError::Io {
            operation: "ebpf_dscp_datapath",
            ..
        })
    ));
    assert!(matches!(
        replacement_owner.remove_device(&replacement_device).await,
        Err(opc_gtpu_dataplane::GtpuError::AlreadyExists)
    ));
    for direction in ["egress", "ingress"] {
        assert!(
            tc_filters(direction).contains("matchall"),
            "remove_device must preserve the external {direction} replacement"
        );
    }
    drop(replacement_owner);
    for direction in ["egress", "ingress"] {
        assert!(
            tc_filters(direction).contains("matchall"),
            "old loader drop must preserve the external {direction} replacement"
        );
        run(
            "tc",
            &[
                "filter", "del", "dev", "s2bu", direction, "handle", "0x1", "pref", "50",
                "protocol", "all", "matchall",
            ],
        );
    }
    fs::remove_dir_all(net.pin_root.join("s2bu"))
        .expect("remove pins after external replacement proof");

    // With the datapath removed, uplink packets are no longer encapsulated.
    ue_socket.send_to(b"opc-uplink-3", (REMOTE_HOST, 53))?;
    expect_no_datagram(&pgw_socket);

    // --- Foreign-filter safety: cleanup/replace only touches our own. ---
    // Occupy the datapath's exact ingress priority/handle slot with a filter
    // that is not ours; provisioning must refuse (AlreadyExists), leave the
    // foreign filter untouched, and roll back its own partial attach.
    run(
        "tc",
        &[
            "filter", "add", "dev", "s2bu", "ingress", "handle", "0x1", "pref", "50", "protocol",
            "all", "matchall", "action", "pass",
        ],
    );
    let blocked = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut blocked_request = CreateGtpDeviceRequest::new("s2bu");
    blocked_request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let error = blocked
        .create_device(blocked_request)
        .await
        .expect_err("a foreign filter in our slot must block provisioning");
    assert!(
        matches!(error, opc_gtpu_dataplane::GtpuError::AlreadyExists),
        "foreign occupant must surface as AlreadyExists, got {error:?}"
    );
    assert!(
        tc_filters("ingress").contains("matchall"),
        "the foreign filter must never be removed"
    );
    assert!(
        !tc_filters("egress").contains("opc_gtpu"),
        "partial attach must be rolled back when provisioning fails"
    );
    assert!(
        !net.pin_root.join("s2bu").exists(),
        "fresh pins must be rolled back when provisioning fails"
    );
    run(
        "tc",
        &[
            "filter", "del", "dev", "s2bu", "ingress", "handle", "0x1", "pref", "50", "protocol",
            "all", "matchall",
        ],
    );

    // Once a pin set carries durable schema evidence, loss of the additive
    // map is corruption, not a one-time legacy migration. Adoption must fail
    // before Aya can silently recreate an empty pinned-by-name map.
    let owner = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut owner_request = CreateGtpDeviceRequest::new("s2bu");
    owner_request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    owner.create_device(owner_request).await?;
    let dscp_pin = net.pin_root.join("s2bu").join(MAP_UPLINK_DSCP);
    assert!(dscp_pin.exists(), "DSCP map must be pinned after adoption");
    drop(owner);
    fs::remove_file(&dscp_pin).expect("remove DSCP pin to model durable state loss");
    let after_loss = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    assert!(matches!(
        after_loss.resolve_device("s2bu").await,
        Err(opc_gtpu_dataplane::GtpuError::Io {
            operation: "ebpf_dscp_schema",
            ..
        })
    ));
    assert!(
        !dscp_pin.exists(),
        "failed adoption must not recreate the missing DSCP pin"
    );

    drop(net);
    Ok(())
}
