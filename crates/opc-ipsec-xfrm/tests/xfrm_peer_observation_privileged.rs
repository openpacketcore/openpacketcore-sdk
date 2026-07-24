//! Privileged production-kernel proof for authenticated ESP peer observation.
//!
//! The test uses real network namespaces, Linux XFRM state, the committed
//! production CO-RE object, and an authenticated ESP-in-UDP packet stream. It
//! is opt-in locally and mandatory in the repository's supported CI kernel.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

use nix::libc;
use nix::net::if_::if_nametoindex;
use nix::sys::socket::{
    recvfrom, sendto, setsockopt, socket, sockopt, AddressFamily, LinkAddr, MsgFlags, SockFlag,
    SockProtocol, SockType,
};
use nix::sys::time::TimeVal;
use nix::{setsockopt_impl, sockopt_impl};
use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, EspPeerAddressFamily, EspPeerObservationKey, EspPeerObservationLoss,
    InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
    LinuxEspPeerObservationConfig, LinuxEspPeerObservationHandle, LinuxEspPeerObservationMonitor,
    LinuxXfrmBackend, NamespaceBoundLinuxXfrmBackend, PolicyParameters, QuerySaRequest,
    RemoveSaRequest, SaParameters, UdpEncap, XfrmAction, XfrmBackend, XfrmDirection, XfrmError,
    XfrmId, XfrmMode, XfrmSelector, XfrmTemplate,
};

const OUTER_LOCAL: [u8; 4] = [192, 0, 2, 1];
const OUTER_PEER: [u8; 4] = [192, 0, 2, 2];
const OBSERVED_OUTER_PEER: [u8; 4] = [198, 51, 100, 77];
const INNER_LOCAL: [u8; 4] = [203, 0, 113, 1];
const INNER_PEER: [u8; 4] = [203, 0, 113, 2];
const OBSERVATION_SPI: u32 = 0x4830_0001;
const WRONG_SPI: u32 = 0x4830_00ff;
const OBSERVATION_PORT: u16 = 33_483;
const CURRENT_OUTER_PORT: u16 = 4_500;
const OBSERVED_OUTER_PORT: u16 = 62_483;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ESP: u8 = 50;
const UDP_ENCAP_SOCKET_OPTION: libc::c_int = 100;
const UDP_ENCAP_ESPINUDP_VALUE: libc::c_int = 2;
const CURRENT_PAYLOAD: &[u8] = b"opc-esp-peer-current";
const CHANGED_PAYLOAD: &[u8] = b"opc-esp-peer-changed";
const AFTER_TEARDOWN_PAYLOAD: &[u8] = b"opc-esp-peer-after-teardown";

sockopt_impl!(
    UdpEncapsulation,
    SetOnly,
    libc::SOL_UDP,
    UDP_ENCAP_SOCKET_OPTION,
    libc::c_int
);

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

fn command_stdout(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_else(|error| format!("diagnostic command failed: {error}"))
}

fn in_netns<T: Send + 'static>(namespace: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let path = format!("/run/netns/{namespace}");
    std::thread::spawn(move || {
        let file = fs::File::open(path).expect("open peer netns");
        nix::sched::setns(file, nix::sched::CloneFlags::CLONE_NEWNET).expect("join peer netns");
        f()
    })
    .join()
    .expect("peer netns thread")
}

fn in_netns_async<T: Send + 'static>(
    namespace: &str,
    f: impl FnOnce(&tokio::runtime::Runtime, NamespaceBoundLinuxXfrmBackend) -> Result<T, XfrmError>
        + Send
        + 'static,
) -> Result<T, XfrmError> {
    in_netns(namespace, move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build peer XFRM runtime");
        let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
        f(&runtime, backend)
    })
}

struct TestNet {
    peer_ns: String,
}

impl TestNet {
    fn provision() -> Self {
        let peer_ns = format!("opc-xfrm-peer-observation-{}", std::process::id());
        run("ip", &["netns", "add", &peer_ns]);
        run(
            "ip",
            &[
                "link",
                "add",
                "obs0",
                "address",
                "02:00:00:00:48:31",
                "type",
                "veth",
                "peer",
                "name",
                "obsp",
                "address",
                "02:00:00:00:48:32",
            ],
        );
        run("ip", &["link", "set", "obsp", "netns", &peer_ns]);
        run("ip", &["addr", "add", "192.0.2.1/24", "dev", "obs0"]);
        run("ip", &["link", "set", "obs0", "up"]);
        run("ip", &["addr", "add", "203.0.113.1/32", "dev", "lo"]);
        run("ip", &["link", "set", "lo", "up"]);
        run("sysctl", &["-q", "-w", "net.ipv4.conf.obs0.rp_filter=0"]);
        run(
            "ip",
            &[
                "route",
                "add",
                "203.0.113.2/32",
                "via",
                "192.0.2.2",
                "dev",
                "obs0",
                "src",
                "203.0.113.1",
            ],
        );
        run(
            "ip",
            &[
                "route",
                "add",
                "198.51.100.77/32",
                "via",
                "192.0.2.2",
                "dev",
                "obs0",
            ],
        );
        run(
            "ip",
            &[
                "neigh",
                "add",
                "192.0.2.2",
                "lladdr",
                "02:00:00:00:48:32",
                "nud",
                "permanent",
                "dev",
                "obs0",
            ],
        );

        run(
            "ip",
            &["-n", &peer_ns, "addr", "add", "192.0.2.2/24", "dev", "obsp"],
        );
        run("ip", &["-n", &peer_ns, "link", "set", "obsp", "up"]);
        run("ip", &["-n", &peer_ns, "link", "set", "lo", "up"]);
        run(
            "ip",
            &["-n", &peer_ns, "addr", "add", "203.0.113.2/32", "dev", "lo"],
        );
        run(
            "ip",
            &[
                "-n",
                &peer_ns,
                "route",
                "add",
                "203.0.113.1/32",
                "via",
                "192.0.2.1",
                "dev",
                "obsp",
                "src",
                "203.0.113.2",
            ],
        );
        run(
            "ip",
            &[
                "-n",
                &peer_ns,
                "route",
                "add",
                "198.51.100.77/32",
                "dev",
                "obsp",
            ],
        );
        run(
            "ip",
            &[
                "-n",
                &peer_ns,
                "neigh",
                "add",
                "192.0.2.1",
                "lladdr",
                "02:00:00:00:48:31",
                "nud",
                "permanent",
                "dev",
                "obsp",
            ],
        );

        Self { peer_ns }
    }

    fn capture_socket(&self) -> OwnedFd {
        in_netns(&self.peer_ns, packet_socket)
    }

    fn send(&self, payload: &'static [u8]) {
        in_netns(&self.peer_ns, move || {
            let sender =
                UdpSocket::bind((Ipv4Addr::from(INNER_PEER), 0)).expect("bind protected sender");
            sender
                .send_to(payload, (Ipv4Addr::from(INNER_LOCAL), OBSERVATION_PORT))
                .expect("send protected peer packet");
        });
    }
}

impl Drop for TestNet {
    fn drop(&mut self) {
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", "obs0", "clsact"])
            .output();
        let _ = Command::new("ip").args(["link", "del", "obs0"]).output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.peer_ns])
            .output();
    }
}

fn ip(value: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(value)
}

fn selector() -> XfrmSelector {
    XfrmSelector::new(ip(INNER_PEER), ip(INNER_LOCAL), IPPROTO_UDP)
}

fn observation_sa() -> SaParameters {
    SaParameters {
        selector: selector(),
        id: XfrmId {
            destination: ip(OUTER_LOCAL),
            spi: OBSERVATION_SPI,
            protocol: IPPROTO_ESP,
        },
        source_address: ip(OUTER_PEER),
        request_id: None,
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x48; 32]),
        )),
        crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: Some(UdpEncap::esp_in_udp(CURRENT_OUTER_PORT, CURRENT_OUTER_PORT)),
        mark: None,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    }
}

fn observation_policy(direction: XfrmDirection) -> PolicyParameters {
    PolicyParameters {
        selector: selector(),
        direction,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: XfrmId {
                destination: ip(OUTER_LOCAL),
                spi: OBSERVATION_SPI,
                protocol: IPPROTO_ESP,
            },
            source_address: ip(OUTER_PEER),
            request_id: None,
            mode: XfrmMode::Tunnel,
        }],
        mark: None,
        if_id: None,
    }
}

fn observation_key() -> EspPeerObservationKey {
    EspPeerObservationKey {
        id: XfrmId {
            destination: ip(OUTER_LOCAL),
            spi: OBSERVATION_SPI,
            protocol: IPPROTO_ESP,
        },
        mark: None,
        if_id: None,
        direction: XfrmDirection::In,
    }
}

async fn install(
    backend: &NamespaceBoundLinuxXfrmBackend,
    direction: XfrmDirection,
) -> Result<(), XfrmError> {
    backend
        .install_sa(InstallSaRequest {
            parameters: observation_sa(),
        })
        .await?;
    backend
        .install_policy(InstallPolicyRequest {
            parameters: observation_policy(direction),
        })
        .await
}

fn udp_encapsulation_listener(address: Ipv4Addr) -> UdpSocket {
    let socket =
        UdpSocket::bind((address, CURRENT_OUTER_PORT)).expect("bind ESP-in-UDP decap socket");
    setsockopt(&socket, UdpEncapsulation, &UDP_ENCAP_ESPINUDP_VALUE)
        .expect("enable ESP-in-UDP decapsulation");
    socket
}

fn packet_socket() -> OwnedFd {
    let socket = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthAll,
    )
    .expect("open AF_PACKET socket");
    setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::new(3, 0)).expect("set capture timeout");
    socket
}

fn capture_udp_esp(socket: &OwnedFd, expected_payload: &[u8]) -> (Vec<u8>, LinkAddr) {
    let mut buffer = vec![0_u8; 65_536];
    for _ in 0..64 {
        let (len, address) =
            recvfrom::<LinkAddr>(socket.as_raw_fd(), &mut buffer).expect("capture peer frame");
        let frame = &buffer[..len];
        if frame.len() < 14 + 20 + 8 + 8
            || frame[12..14] != [0x08, 0x00]
            || frame[23] != IPPROTO_UDP
        {
            continue;
        }
        let ihl = usize::from(frame[14] & 0x0f) * 4;
        let esp_offset = 14 + ihl + 8;
        if ihl < 20 || esp_offset + 8 > frame.len() {
            continue;
        }
        let spi = u32::from_be_bytes([
            frame[esp_offset],
            frame[esp_offset + 1],
            frame[esp_offset + 2],
            frame[esp_offset + 3],
        ]);
        if spi == OBSERVATION_SPI
            && frame
                .windows(expected_payload.len())
                .any(|window| window == expected_payload)
        {
            return (frame.to_vec(), address.expect("captured AF_PACKET address"));
        }
    }
    panic!("did not capture expected ESP-in-UDP packet")
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

fn rewrite_outer_source(frame: &[u8]) -> Vec<u8> {
    let mut rewritten = frame.to_vec();
    let ihl = usize::from(rewritten[14] & 0x0f) * 4;
    let udp_offset = 14 + ihl;
    rewritten[26..30].copy_from_slice(&OBSERVED_OUTER_PEER);
    rewritten[udp_offset..udp_offset + 2].copy_from_slice(&OBSERVED_OUTER_PORT.to_be_bytes());
    // An IPv4 UDP checksum of zero is explicitly "not computed"; this avoids
    // inheriting transmit-offload metadata from the AF_PACKET capture.
    rewritten[udp_offset + 6..udp_offset + 8].fill(0);
    rewritten[24..26].fill(0);
    let checksum = ipv4_checksum(&rewritten[14..14 + ihl]);
    rewritten[24..26].copy_from_slice(&checksum.to_be_bytes());
    rewritten
}

fn with_wrong_spi(frame: &[u8]) -> Vec<u8> {
    let mut wrong = rewrite_outer_source(frame);
    let ihl = usize::from(wrong[14] & 0x0f) * 4;
    let esp_offset = 14 + ihl + 8;
    wrong[esp_offset..esp_offset + 4].copy_from_slice(&WRONG_SPI.to_be_bytes());
    wrong
}

fn with_invalid_authentication(frame: &[u8]) -> Vec<u8> {
    let mut invalid = rewrite_outer_source(frame);
    let ihl = usize::from(invalid[14] & 0x0f) * 4;
    let esp_payload_offset = 14 + ihl + 8 + 8;
    invalid[esp_payload_offset] ^= 0x80;
    invalid
}

fn for_peer_namespace(frame: &[u8]) -> Vec<u8> {
    let mut scoped = rewrite_outer_source(frame);
    scoped[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x48, 0x32]);
    scoped[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x48, 0x31]);
    scoped
}

fn inject_frame(socket: &OwnedFd, address: &LinkAddr, frame: &[u8]) {
    let sent =
        sendto(socket.as_raw_fd(), frame, address, MsgFlags::empty()).expect("inject peer frame");
    assert_eq!(sent, frame.len());
}

fn hold_inbound_packets() {
    run("tc", &["qdisc", "replace", "dev", "obs0", "clsact"]);
    run(
        "tc",
        &[
            "filter", "replace", "dev", "obs0", "ingress", "pref", "10", "protocol", "all",
            "matchall", "action", "drop",
        ],
    );
}

fn release_inbound_packets() {
    run(
        "tc",
        &["filter", "del", "dev", "obs0", "ingress", "pref", "10"],
    );
}

fn receive_exact(receiver: &UdpSocket, expected: &[u8], peer_ns: &str) {
    let mut buffer = [0_u8; 256];
    let (received, source) = receiver.recv_from(&mut buffer).unwrap_or_else(|error| {
        panic!(
            "receive protected packet failed: {error}\nlocal-state-count={}\nlocal-policy={}\nlocal-xfrm-stat={}\nlocal-udp={}\npeer-state-count={}\npeer-policy={}",
            command_stdout("ip", &["xfrm", "state", "count"]),
            command_stdout("ip", &["-s", "xfrm", "policy"]),
            fs::read_to_string("/proc/net/xfrm_stat")
                .unwrap_or_else(|read_error| format!("read failed: {read_error}")),
            command_stdout("ss", &["-u", "-a", "-n"]),
            command_stdout("ip", &["-n", peer_ns, "xfrm", "state", "count"]),
            command_stdout("ip", &["-n", peer_ns, "-s", "xfrm", "policy"]),
        )
    });
    assert_eq!(&buffer[..received], expected);
    assert_eq!(source.ip(), Ipv4Addr::from(INNER_PEER));
}

fn assert_receive_timeout(receiver: &UdpSocket) {
    let mut buffer = [0_u8; 256];
    let error = receiver
        .recv_from(&mut buffer)
        .expect_err("unexpected protected packet");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
}

async fn assert_monitor_quiet(
    monitor: &mut LinuxEspPeerObservationMonitor,
    handle: LinuxEspPeerObservationHandle,
) -> Result<(), XfrmError> {
    for _ in 0..5 {
        let tally = monitor.poll_available().await?;
        assert_eq!(tally.observations_queued, 0);
        assert_eq!(tally.source_terminal, None);
        assert!(monitor.drain(handle).is_none());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

async fn wait_for_observation(
    monitor: &mut LinuxEspPeerObservationMonitor,
    handle: LinuxEspPeerObservationHandle,
) -> Result<opc_ipsec_xfrm::EspPeerObservation, XfrmError> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let tally = monitor.poll_available().await?;
        assert_eq!(tally.source_terminal, None);
        if let Some(observation) = monitor.drain(handle) {
            return Ok(observation);
        }
        if Instant::now() >= deadline {
            return Err(XfrmError::StateIndeterminate {
                operation: "peer_observation_privileged_timeout",
            });
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn peer_inbound_sequence(peer_ns: &str) -> Result<u32, XfrmError> {
    let peer_ns = peer_ns.to_owned();
    in_netns_async(&peer_ns.clone(), move |runtime, backend| {
        runtime
            .block_on(backend.query_sa(QuerySaRequest::new(
                ip(OUTER_LOCAL),
                IPPROTO_ESP,
                OBSERVATION_SPI,
            )))
            .map(|state| state.replay_state.inbound_sequence)
    })
}

fn wait_for_peer_inbound_sequence(
    peer_ns: &str,
    baseline: u32,
) -> Result<u32, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let sequence = peer_inbound_sequence(peer_ns)?;
        if sequence > baseline {
            return Ok(sequence);
        }
        if Instant::now() >= deadline {
            return Err("peer namespace did not authenticate the scoped packet".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn monitor_unavailable(error: &XfrmError) -> bool {
    matches!(
        error,
        XfrmError::UnsupportedPlatform | XfrmError::UnsupportedFeature { .. }
    )
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, CAP_NET_RAW, BTF, XFRM, tracing BPF, and a fresh netns"]
async fn production_monitor_observes_only_authenticated_replay_winning_new_sources(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_XFRM_RUN_PEER_OBSERVATION_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!(
            "skipping: set OPC_XFRM_RUN_PEER_OBSERVATION_PRIVILEGED=1 in a fresh privileged netns"
        );
        return Ok(());
    }
    let require_monitor = env::var("OPC_XFRM_REQUIRE_PEER_OBSERVATION").as_deref() == Ok("1");

    let network = TestNet::provision();
    let _encapsulation_listener = udp_encapsulation_listener(Ipv4Addr::from(OUTER_LOCAL));
    let peer_ns = network.peer_ns.clone();
    let _peer_encapsulation_listener = in_netns(&peer_ns, || {
        udp_encapsulation_listener(Ipv4Addr::from(OUTER_PEER))
    });
    let receiver = UdpSocket::bind((Ipv4Addr::from(INNER_LOCAL), OBSERVATION_PORT))?;
    receiver.set_read_timeout(Some(Duration::from_millis(250)))?;
    let capture = network.capture_socket();
    let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
    install(&backend, XfrmDirection::In).await?;
    let peer_ns = network.peer_ns.clone();
    in_netns_async(&peer_ns.clone(), move |runtime, peer_backend| {
        runtime.block_on(install(&peer_backend, XfrmDirection::Out))
    })?;

    let config = LinuxEspPeerObservationConfig::new(4)?
        .with_poll_record_budget(4)?
        .with_watchdog_interval(Duration::from_millis(5))?
        .with_teardown_wait(Duration::from_secs(2), Duration::from_millis(5))?;
    let mut monitor = match backend.create_esp_peer_observation_monitor(config).await {
        Ok(monitor) => monitor,
        Err(error) if !require_monitor && monitor_unavailable(&error) => {
            eprintln!("skipping unsupported peer-observation kernel: {error}");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let handle = monitor.register_sa(observation_key()).await?;
    assert_eq!(handle.key(), observation_key());
    assert_eq!(monitor.tracked_len(), 1);

    // The SDK's generic SA install intentionally omits XFRMA_SA_DIR. Successful
    // registration therefore proves the legacy direction-zero GETSA path is
    // admitted as inbound, while outbound traffic in the peer namespace does
    // not itself create an observation.
    network.send(CURRENT_PAYLOAD);
    let (_current_frame, _current_address) = capture_udp_esp(&capture, CURRENT_PAYLOAD);
    receive_exact(&receiver, CURRENT_PAYLOAD, &network.peer_ns);
    eprintln!("peer-observation phase: current-source accepted");
    assert_monitor_quiet(&mut monitor, handle).await?;

    // Capture a future sequence without letting the receiver consume it.
    hold_inbound_packets();
    network.send(CHANGED_PAYLOAD);
    let (future_frame, address) = capture_udp_esp(&capture, CHANGED_PAYLOAD);
    release_inbound_packets();

    // Neither a different SA identity nor a packet that loses integrity
    // authentication is allowed to produce routing authority.
    inject_frame(&capture, &address, &with_wrong_spi(&future_frame));
    inject_frame(
        &capture,
        &address,
        &with_invalid_authentication(&future_frame),
    );
    assert_receive_timeout(&receiver);
    assert_monitor_quiet(&mut monitor, handle).await?;
    eprintln!("peer-observation phase: invalid candidates rejected");

    let changed_source_frame = rewrite_outer_source(&future_frame);
    inject_frame(&capture, &address, &changed_source_frame);
    inject_frame(&capture, &address, &changed_source_frame);
    receive_exact(&receiver, CHANGED_PAYLOAD, &network.peer_ns);
    assert_receive_timeout(&receiver);

    let observation = wait_for_observation(&mut monitor, handle).await?;
    eprintln!("peer-observation phase: changed-source observation drained");
    assert_eq!(observation.key, observation_key());
    assert_eq!(observation.epoch, handle.epoch());
    assert_eq!(observation.address_family, EspPeerAddressFamily::Ipv4);
    assert_eq!(observation.outer_source, ip(OBSERVED_OUTER_PEER));
    assert_eq!(observation.outer_source_port, OBSERVED_OUTER_PORT);
    assert_eq!(observation.generation, 1);
    assert_eq!(observation.loss, EspPeerObservationLoss::None);
    let expected_ifindex = if_nametoindex("obs0")?;
    assert_eq!(observation.ingress_ifindex, expected_ifindex);
    assert_monitor_quiet(&mut monitor, handle).await?;
    eprintln!("peer-observation phase: replay duplicate excluded");

    // Capture one more sequence while it is held before the current
    // namespace's XFRM path.
    let current_injector = packet_socket();
    hold_inbound_packets();
    network.send(AFTER_TEARDOWN_PAYLOAD);
    let (after_teardown_frame, after_teardown_address) =
        capture_udp_esp(&capture, AFTER_TEARDOWN_PAYLOAD);
    let (_current_copy, current_address) =
        capture_udp_esp(&current_injector, AFTER_TEARDOWN_PAYLOAD);
    release_inbound_packets();

    // Make the same destination and UDP decapsulation endpoint local in the
    // peer namespace, then deliver the same authenticated SA identity there.
    // The peer's inbound replay advance proves the packet reached the final
    // authenticated hook, while the current-namespace monitor must remain
    // empty because its opaque netns-cookie scope does not match.
    run(
        "ip",
        &[
            "-n",
            &network.peer_ns,
            "addr",
            "add",
            "192.0.2.1/32",
            "dev",
            "lo",
        ],
    );
    let peer_ns = network.peer_ns.clone();
    let _peer_scope_listener = in_netns(&peer_ns, || {
        udp_encapsulation_listener(Ipv4Addr::from(OUTER_LOCAL))
    });
    let peer_sequence = peer_inbound_sequence(&network.peer_ns)?;
    inject_frame(
        &current_injector,
        &current_address,
        &for_peer_namespace(&after_teardown_frame),
    );
    assert!(
        wait_for_peer_inbound_sequence(&network.peer_ns, peer_sequence)? > peer_sequence,
        "peer namespace replay state must advance"
    );
    assert_monitor_quiet(&mut monitor, handle).await?;
    eprintln!("peer-observation phase: namespace scope isolated");

    // Unpublish while that sequence remains unconsumed in the current
    // namespace. Once teardown reconciles generation/loss and removes the
    // registration, acceptance here must not appear late.
    let teardown = monitor.teardown(handle).await?;
    eprintln!("peer-observation phase: teardown reconciled");
    assert_eq!(teardown.key, observation_key());
    assert_eq!(teardown.epoch, handle.epoch());
    assert_eq!(teardown.final_generation, 1);
    assert!(teardown.drained.is_none());
    assert_eq!(teardown.residual_loss, EspPeerObservationLoss::None);
    assert_eq!(monitor.tracked_len(), 0);

    inject_frame(
        &capture,
        &after_teardown_address,
        &rewrite_outer_source(&after_teardown_frame),
    );
    receive_exact(&receiver, AFTER_TEARDOWN_PAYLOAD, &network.peer_ns);
    let tally = monitor.poll_available().await?;
    assert_eq!(tally.observations_queued, 0);
    assert!(monitor.drain_all().is_empty());

    // A kernel lifecycle mutation after re-registration must make subsequent
    // polling fail closed rather than reporting a trustworthy empty result.
    let mutation_handle = monitor.register_sa(observation_key()).await?;
    eprintln!("peer-observation phase: mutation registration established");
    backend
        .remove_sa(RemoveSaRequest::new(
            ip(OUTER_LOCAL),
            IPPROTO_ESP,
            OBSERVATION_SPI,
        ))
        .await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(
        monitor.poll_available().await.is_err(),
        "removed kernel SA must terminate observation authority"
    );
    assert!(monitor.drain(mutation_handle).is_none());

    Ok(())
}
