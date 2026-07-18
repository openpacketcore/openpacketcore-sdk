//! Privileged Linux proof for bidirectional authenticated-only ESP.
//!
//! The test captures an SDK-installed ENCR_NULL/HMAC outbound packet before a
//! peer SA exists, installs the peer inbound SA, injects a tampered copy, and
//! proves the kernel rejects it without consuming the sequence number. The
//! original authenticated packet then passes, as does a fresh reverse packet.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::socket::{
    recvfrom, sendto, setsockopt, socket, sockopt, AddressFamily, LinkAddr, MsgFlags, SockFlag,
    SockProtocol, SockType,
};
use nix::sys::time::TimeVal;
use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial,
    LifetimeConfig, LinuxXfrmBackend, PolicyParameters, QuerySaRequest, SaParameters, SaState,
    XfrmAction, XfrmBackend, XfrmDirection, XfrmId, XfrmMode, XfrmSelector, XfrmTemplate,
};

const OUTER_LOCAL: [u8; 4] = [192, 0, 2, 1];
const OUTER_PEER: [u8; 4] = [192, 0, 2, 2];
const INNER_LOCAL: [u8; 4] = [10, 60, 0, 1];
const INNER_PEER: [u8; 4] = [10, 60, 0, 2];
const LOCAL_TO_PEER_SPI: u32 = 0x3320_0001;
const PEER_TO_LOCAL_SPI: u32 = 0x3320_0002;
const LOCAL_TO_PEER_KEY: u8 = 0xa1;
const PEER_TO_LOCAL_KEY: u8 = 0xb2;
const TEST_PORT: u16 = 33_200;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ESP: u8 = 50;
const TEST_PAYLOAD: &[u8] = b"opc-xfrm-auth-only";

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
    f: impl FnOnce(&tokio::runtime::Runtime, LinuxXfrmBackend) -> Result<T, opc_ipsec_xfrm::XfrmError>
        + Send
        + 'static,
) -> Result<T, opc_ipsec_xfrm::XfrmError> {
    in_netns(namespace, move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build peer XFRM runtime");
        f(&runtime, LinuxXfrmBackend::new())
    })
}

struct TestNet {
    peer_ns: String,
}

impl TestNet {
    fn provision() -> Self {
        let peer_ns = format!("opc-xfrm-auth-only-{}", std::process::id());
        run("ip", &["netns", "add", &peer_ns]);
        run(
            "ip",
            &[
                "link",
                "add",
                "null0",
                "address",
                "02:00:00:00:33:01",
                "type",
                "veth",
                "peer",
                "name",
                "nullp",
                "address",
                "02:00:00:00:33:02",
            ],
        );
        run("ip", &["link", "set", "nullp", "netns", &peer_ns]);
        run("ip", &["addr", "add", "192.0.2.1/24", "dev", "null0"]);
        run("ip", &["link", "set", "null0", "up"]);
        run("ip", &["addr", "add", "10.60.0.1/32", "dev", "lo"]);
        run("ip", &["link", "set", "lo", "up"]);
        run(
            "ip",
            &[
                "route",
                "add",
                "10.60.0.2/32",
                "via",
                "192.0.2.2",
                "dev",
                "null0",
                "src",
                "10.60.0.1",
            ],
        );
        run(
            "ip",
            &[
                "neigh",
                "add",
                "192.0.2.2",
                "lladdr",
                "02:00:00:00:33:02",
                "nud",
                "permanent",
                "dev",
                "null0",
            ],
        );

        run(
            "ip",
            &[
                "-n",
                &peer_ns,
                "addr",
                "add",
                "192.0.2.2/24",
                "dev",
                "nullp",
            ],
        );
        run("ip", &["-n", &peer_ns, "link", "set", "nullp", "up"]);
        run("ip", &["-n", &peer_ns, "link", "set", "lo", "up"]);
        run(
            "ip",
            &["-n", &peer_ns, "addr", "add", "10.60.0.2/32", "dev", "lo"],
        );
        run(
            "ip",
            &[
                "-n",
                &peer_ns,
                "route",
                "add",
                "10.60.0.1/32",
                "via",
                "192.0.2.1",
                "dev",
                "nullp",
                "src",
                "10.60.0.2",
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
                "02:00:00:00:33:01",
                "nud",
                "permanent",
                "dev",
                "nullp",
            ],
        );

        Self { peer_ns }
    }

    fn peer_receiver(&self) -> UdpSocket {
        in_netns(&self.peer_ns, || {
            let receiver = UdpSocket::bind((Ipv4Addr::from(INNER_PEER), TEST_PORT))
                .expect("bind peer protected receiver");
            receiver
                .set_read_timeout(Some(Duration::from_millis(400)))
                .expect("set peer receive timeout");
            receiver
        })
    }

    fn peer_send(&self) {
        in_netns(&self.peer_ns, || {
            let sender = UdpSocket::bind((Ipv4Addr::from(INNER_PEER), 0))
                .expect("bind peer protected sender");
            sender
                .send_to(TEST_PAYLOAD, (Ipv4Addr::from(INNER_LOCAL), TEST_PORT))
                .expect("send peer authenticated-only ESP packet");
        });
    }
}

impl Drop for TestNet {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", "null0"]).output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.peer_ns])
            .output();
    }
}

fn ip(value: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(value)
}

fn selector(source: [u8; 4], destination: [u8; 4]) -> XfrmSelector {
    XfrmSelector::new(ip(source), ip(destination), IPPROTO_UDP)
}

fn auth_only_sa(
    source_outer: [u8; 4],
    destination_outer: [u8; 4],
    source_inner: [u8; 4],
    destination_inner: [u8; 4],
    spi: u32,
    key_byte: u8,
) -> SaParameters {
    SaParameters {
        selector: selector(source_inner, destination_inner),
        id: XfrmId {
            destination: ip(destination_outer),
            spi,
            protocol: IPPROTO_ESP,
        },
        source_address: ip(source_outer),
        request_id: None,
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![key_byte; 32]),
        )),
        // Linux represents RFC 8221 ENCR_NULL as this explicit zero-key
        // transform. Omitting XFRMA_ALG_CRYPT makes NEWSA fail with EINVAL.
        crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark: None,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    }
}

fn policy(
    source_outer: [u8; 4],
    destination_outer: [u8; 4],
    source_inner: [u8; 4],
    destination_inner: [u8; 4],
    spi: u32,
    direction: XfrmDirection,
) -> PolicyParameters {
    PolicyParameters {
        selector: selector(source_inner, destination_inner),
        direction,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: XfrmId {
                destination: ip(destination_outer),
                spi,
                protocol: IPPROTO_ESP,
            },
            source_address: ip(source_outer),
            request_id: None,
            mode: XfrmMode::Tunnel,
        }],
        mark: None,
        if_id: None,
    }
}

async fn install(
    backend: &LinuxXfrmBackend,
    sa: SaParameters,
    policy: PolicyParameters,
) -> Result<(), opc_ipsec_xfrm::XfrmError> {
    backend
        .install_sa(InstallSaRequest { parameters: sa })
        .await?;
    backend
        .install_policy(InstallPolicyRequest { parameters: policy })
        .await
}

fn capture_socket() -> OwnedFd {
    let socket = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthAll,
    )
    .expect("open AF_PACKET capture socket");
    setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::new(3, 0)).expect("set capture timeout");
    socket
}

fn capture_esp(socket: &OwnedFd, expected_spi: u32) -> (Vec<u8>, LinkAddr) {
    let mut buffer = vec![0_u8; 65_536];
    for _ in 0..32 {
        let (len, address) =
            recvfrom::<LinkAddr>(socket.as_raw_fd(), &mut buffer).expect("capture outbound frame");
        let frame = &buffer[..len];
        if frame.len() < 14 + 20 + 8 || frame[12..14] != [0x08, 0x00] || frame[23] != IPPROTO_ESP {
            continue;
        }
        let ihl = usize::from(frame[14] & 0x0f) * 4;
        let esp_offset = 14 + ihl;
        if ihl < 20 || esp_offset + 8 > frame.len() {
            continue;
        }
        let spi = u32::from_be_bytes([
            frame[esp_offset],
            frame[esp_offset + 1],
            frame[esp_offset + 2],
            frame[esp_offset + 3],
        ]);
        if spi != expected_spi {
            continue;
        }
        return (
            frame.to_vec(),
            address.expect("captured AF_PACKET frame address"),
        );
    }
    panic!("did not capture expected ESP SPI {expected_spi:#x}")
}

fn inject_frame(socket: &OwnedFd, address: &LinkAddr, frame: &[u8]) {
    let sent = sendto(socket.as_raw_fd(), frame, address, MsgFlags::empty())
        .expect("inject captured ESP frame");
    assert_eq!(sent, frame.len());
}

fn peer_sa_state(peer_ns: &str, destination: [u8; 4], spi: u32) -> SaState {
    let peer_ns = peer_ns.to_owned();
    in_netns_async(&peer_ns.clone(), move |runtime, backend| {
        runtime.block_on(backend.query_sa(QuerySaRequest::new(ip(destination), IPPROTO_ESP, spi)))
    })
    .unwrap_or_else(|error| panic!("query peer authenticated-only SA failed: {error:?}"))
}

fn wait_for_integrity_failure(peer_ns: &str, baseline: u32) -> SaState {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let state = peer_sa_state(peer_ns, OUTER_PEER, LOCAL_TO_PEER_SPI);
        if state.statistics.integrity_failures > baseline {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "tampered ESP did not increment integrity failures"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, CAP_NET_RAW, XFRM, and a fresh network namespace"]
async fn bidirectional_authenticated_only_esp_accepts_valid_and_rejects_tampered_packets(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_XFRM_RUN_AUTH_ONLY_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!(
            "skipping: set OPC_XFRM_RUN_AUTH_ONLY_PRIVILEGED=1 inside a fresh privileged netns"
        );
        return Ok(());
    }

    let network = TestNet::provision();
    let peer_receiver = network.peer_receiver();
    let capture = capture_socket();
    let backend = LinuxXfrmBackend::new();

    install(
        &backend,
        auth_only_sa(
            OUTER_LOCAL,
            OUTER_PEER,
            INNER_LOCAL,
            INNER_PEER,
            LOCAL_TO_PEER_SPI,
            LOCAL_TO_PEER_KEY,
        ),
        policy(
            OUTER_LOCAL,
            OUTER_PEER,
            INNER_LOCAL,
            INNER_PEER,
            LOCAL_TO_PEER_SPI,
            XfrmDirection::Out,
        ),
    )
    .await?;

    let sender = UdpSocket::bind((Ipv4Addr::from(INNER_LOCAL), 0))?;
    sender.send_to(TEST_PAYLOAD, (Ipv4Addr::from(INNER_PEER), TEST_PORT))?;
    let (original_frame, address) = capture_esp(&capture, LOCAL_TO_PEER_SPI);

    let peer_ns = network.peer_ns.clone();
    in_netns_async(&peer_ns.clone(), move |runtime, peer_backend| {
        runtime.block_on(install(
            &peer_backend,
            auth_only_sa(
                OUTER_LOCAL,
                OUTER_PEER,
                INNER_LOCAL,
                INNER_PEER,
                LOCAL_TO_PEER_SPI,
                LOCAL_TO_PEER_KEY,
            ),
            policy(
                OUTER_LOCAL,
                OUTER_PEER,
                INNER_LOCAL,
                INNER_PEER,
                LOCAL_TO_PEER_SPI,
                XfrmDirection::In,
            ),
        ))
    })?;
    let baseline = peer_sa_state(&network.peer_ns, OUTER_PEER, LOCAL_TO_PEER_SPI)
        .statistics
        .integrity_failures;

    let mut tampered = original_frame.clone();
    let ihl = usize::from(tampered[14] & 0x0f) * 4;
    let authenticated_payload_offset = 14 + ihl + 8;
    tampered[authenticated_payload_offset] ^= 0x80;
    inject_frame(&capture, &address, &tampered);

    let mut receive_buffer = [0_u8; 128];
    let receive_error = peer_receiver
        .recv_from(&mut receive_buffer)
        .expect_err("tampered authenticated-only ESP unexpectedly delivered");
    assert!(matches!(
        receive_error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    let rejected = wait_for_integrity_failure(&network.peer_ns, baseline);
    assert_eq!(rejected.lifetime_current.packets, 0);

    inject_frame(&capture, &address, &original_frame);
    let (received, source) = peer_receiver.recv_from(&mut receive_buffer)?;
    assert_eq!(&receive_buffer[..received], TEST_PAYLOAD);
    assert_eq!(source.ip(), Ipv4Addr::from(INNER_LOCAL));
    let accepted = peer_sa_state(&network.peer_ns, OUTER_PEER, LOCAL_TO_PEER_SPI);
    assert_eq!(accepted.lifetime_current.packets, 1);

    install(
        &backend,
        auth_only_sa(
            OUTER_PEER,
            OUTER_LOCAL,
            INNER_PEER,
            INNER_LOCAL,
            PEER_TO_LOCAL_SPI,
            PEER_TO_LOCAL_KEY,
        ),
        policy(
            OUTER_PEER,
            OUTER_LOCAL,
            INNER_PEER,
            INNER_LOCAL,
            PEER_TO_LOCAL_SPI,
            XfrmDirection::In,
        ),
    )
    .await?;
    let peer_ns = network.peer_ns.clone();
    in_netns_async(&peer_ns.clone(), move |runtime, peer_backend| {
        runtime.block_on(install(
            &peer_backend,
            auth_only_sa(
                OUTER_PEER,
                OUTER_LOCAL,
                INNER_PEER,
                INNER_LOCAL,
                PEER_TO_LOCAL_SPI,
                PEER_TO_LOCAL_KEY,
            ),
            policy(
                OUTER_PEER,
                OUTER_LOCAL,
                INNER_PEER,
                INNER_LOCAL,
                PEER_TO_LOCAL_SPI,
                XfrmDirection::Out,
            ),
        ))
    })?;

    let local_receiver = UdpSocket::bind((Ipv4Addr::from(INNER_LOCAL), TEST_PORT))?;
    local_receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
    network.peer_send();
    let (received, source) = local_receiver.recv_from(&mut receive_buffer)?;
    assert_eq!(&receive_buffer[..received], TEST_PAYLOAD);
    assert_eq!(source.ip(), Ipv4Addr::from(INNER_PEER));

    let local_outbound = backend
        .query_sa(QuerySaRequest::new(
            ip(OUTER_PEER),
            IPPROTO_ESP,
            LOCAL_TO_PEER_SPI,
        ))
        .await?;
    let local_inbound = backend
        .query_sa(QuerySaRequest::new(
            ip(OUTER_LOCAL),
            IPPROTO_ESP,
            PEER_TO_LOCAL_SPI,
        ))
        .await?;
    assert_eq!(local_outbound.lifetime_current.packets, 1);
    assert_eq!(local_inbound.lifetime_current.packets, 1);

    Ok(())
}
