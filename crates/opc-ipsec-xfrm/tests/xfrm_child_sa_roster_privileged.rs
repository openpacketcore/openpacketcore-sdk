//! Real installed selection, independently captured ESP SPIs and writer fences.
#![cfg(target_os = "linux")]

#[cfg(feature = "ikev2")]
#[path = "support/mobike.rs"]
mod mobike;
#[cfg(feature = "ikev2")]
#[path = "support/mobike_roster.rs"]
mod mobike_roster;

use hmac::{Hmac, KeyInit, Mac};
use nix::sys::socket::{
    recvfrom, setsockopt, socket, sockopt, AddressFamily, LinkAddr, SockFlag, SockProtocol,
    SockType,
};
use nix::sys::time::TimeVal;
use nix::{libc, setsockopt_impl, sockopt_impl};
use opc_ipsec_xfrm::child_sa::*;
use opc_ipsec_xfrm::*;
use opc_linux_xfrm_sys::XfrmUserPolicyInfo;
use std::{
    fs,
    net::{Ipv4Addr, UdpSocket},
    os::fd::{AsRawFd, OwnedFd},
    process::Command,
    time::Duration,
};

const OUTER_LOCAL: [u8; 4] = [192, 0, 2, 1];
const OUTER_PEER: [u8; 4] = [192, 0, 2, 2];
const INNER_LOCAL: [u8; 4] = [203, 0, 113, 1];
const INNER_PEER: [u8; 4] = [203, 0, 113, 2];
const PORT: u16 = 34793;

const UDP_ENCAP_OPTION: libc::c_int = 100;
sockopt_impl!(
    UdpEncapsulation,
    SetOnly,
    libc::SOL_UDP,
    UDP_ENCAP_OPTION,
    libc::c_int
);
sockopt_impl!(
    SocketXfrmPolicy,
    SetOnly,
    libc::SOL_IP,
    libc::IP_XFRM_POLICY,
    XfrmUserPolicyInfo
);

fn command(args: &[&str]) {
    let result = Command::new("ip").args(args).output().unwrap();
    assert!(
        result.status.success(),
        "network setup failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn peer<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let path = format!("/run/netns/{name}");
    std::thread::spawn(move || {
        nix::sched::setns(
            fs::File::open(path).unwrap(),
            nix::sched::CloneFlags::CLONE_NEWNET,
        )
        .unwrap();
        f()
    })
    .join()
    .unwrap()
}

struct Network {
    peer: String,
}
impl Network {
    fn new() -> Self {
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap(),
            fs::read_link("/proc/1/ns/net").unwrap(),
            "native proof requires a fresh network namespace"
        );
        // libtest may run several cases in this process. Each current-thread
        // Tokio test owns another private namespace, including loopback and
        // the XFRM database, so one case cannot leave state in the next.
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let peer = format!("opc-childsa-{}", std::process::id());
        command(&["netns", "add", &peer]);
        command(&[
            "link", "add", "n3c0", "type", "veth", "peer", "name", "n3cp",
        ]);
        command(&["link", "set", "n3cp", "netns", &peer]);
        for args in [
            vec!["addr", "add", "192.0.2.1/24", "dev", "n3c0"],
            vec!["addr", "add", "203.0.113.1/32", "dev", "lo"],
            vec!["link", "set", "n3c0", "up"],
            vec!["link", "set", "lo", "up"],
            vec![
                "route",
                "add",
                "203.0.113.2/32",
                "via",
                "192.0.2.2",
                "dev",
                "n3c0",
                "src",
                "203.0.113.1",
            ],
        ] {
            command(&args);
        }
        for args in [
            vec!["addr", "add", "192.0.2.2/24", "dev", "n3cp"],
            vec!["addr", "add", "203.0.113.2/32", "dev", "lo"],
            vec!["link", "set", "n3cp", "up"],
            vec!["link", "set", "lo", "up"],
            vec![
                "route",
                "add",
                "203.0.113.1/32",
                "via",
                "192.0.2.1",
                "dev",
                "n3cp",
                "src",
                "203.0.113.2",
            ],
        ] {
            let mut full = vec!["-n", peer.as_str()];
            full.extend(args);
            command(&full);
        }
        Self { peer }
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", "n3c0"]).output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.peer])
            .output();
    }
}

fn ip(address: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(address)
}
fn child(id: u64) -> ChildSaId {
    ChildSaId::new(id).unwrap()
}
fn class(id: u64) -> ChildSaClass {
    ChildSaClass::new(id).unwrap()
}
fn spi(id: u64, incarnation: u64, inbound: bool) -> u32 {
    0x7930_0000 + id as u32 * 0x100 + incarnation as u32 * 2 + u32::from(!inbound)
}

fn sa(id: u64, incarnation: u64, inbound: bool) -> SaParameters {
    let (outer_src, outer_dst) = if inbound {
        (OUTER_PEER, OUTER_LOCAL)
    } else {
        (OUTER_LOCAL, OUTER_PEER)
    };
    let mut selector = XfrmSelector::new(ip([0; 4]), ip([0; 4]), 0);
    selector.source_prefix_len = 0;
    selector.destination_prefix_len = 0;
    SaParameters {
        selector,
        id: XfrmId {
            destination: ip(outer_dst),
            spi: spi(id, incarnation, inbound),
            protocol: 50,
        },
        source_address: ip(outer_src),
        request_id: XfrmRequestId::new(793),
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![
                0x50 + id as u8 + incarnation as u8 + u8::from(inbound);
                32
            ]),
        )),
        crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: Some(UdpEncap::esp_in_udp(4500, 4500)),
        mark: (!inbound).then(|| XfrmLookupMark::full(id as u32)),
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    }
}

fn policy(sa: &SaParameters, direction: XfrmDirection) -> PolicyParameters {
    let mut id = sa.id;
    if direction == XfrmDirection::In {
        id.spi = 0;
    }
    PolicyParameters {
        selector: sa.selector.clone(),
        direction,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id,
            source_address: sa.source_address,
            request_id: sa.request_id,
            mode: sa.mode,
        }],
        mark: sa.mark,
        if_id: None,
    }
}

fn pair(id: u64, incarnation: u64, selected: bool) -> ChildSaInstalledPairRequest {
    let inbound_sa = sa(id, incarnation, true);
    let outbound_sa = sa(id, incarnation, false);
    ChildSaInstalledPairRequest {
        pair: ChildSaPair::new(
            child(id),
            ChildSaIncarnation::new(incarnation).unwrap(),
            ChildSaTrafficIdentity::new(inbound_sa.id, inbound_sa.mark, None).unwrap(),
            ChildSaTrafficIdentity::new(outbound_sa.id, outbound_sa.mark, None).unwrap(),
            if selected {
                ChildSaOutboundUse::Selected
            } else {
                ChildSaOutboundUse::ReceiveOnly
            },
        ),
        inbound_policy: policy(&inbound_sa, XfrmDirection::In),
        outbound_policy: selected.then(|| policy(&outbound_sa, XfrmDirection::Out)),
        inbound_sa,
        outbound_sa,
    }
}

fn request(overlap: bool) -> ChildSaInstalledRosterRequest {
    let mut pairs = vec![pair(1, 1, true), pair(2, 1, !overlap), pair(3, 1, true)];
    if overlap {
        pairs.push(pair(2, 2, true));
    }
    let plan = ChildSaSelectionPlan::new(
        pairs.iter().map(|pair| pair.pair.clone()).collect(),
        [(10, 1), (11, 1), (20, 2), (21, 2), (30, 3), (31, 3)]
            .into_iter()
            .map(|(flow, id)| ChildSaClassBinding::new(class(flow), child(id)))
            .collect(),
        child(3),
        ChildSaSelectionLimits {
            max_pairs: 4,
            max_classes: 6,
        },
    )
    .unwrap();
    ChildSaInstalledRosterRequest { plan, pairs }
}

fn encapsulation(address: [u8; 4]) -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::from(address), 4500)).unwrap();
    // Linux checks the outer UDP socket's inbound policy before ESP decapsulation.
    // Scope the empty-template allow policy to this encapsulation socket only;
    // the inner receivers still enforce the all-packet tunnel policy and ICV.
    let mut outer_policy = XfrmUserPolicyInfo::default();
    outer_policy.selector.family = libc::AF_INET as u16;
    outer_policy.lifetime_config.soft_byte_limit = u64::MAX;
    outer_policy.lifetime_config.hard_byte_limit = u64::MAX;
    outer_policy.lifetime_config.soft_packet_limit = u64::MAX;
    outer_policy.lifetime_config.hard_packet_limit = u64::MAX;
    setsockopt(&socket, SocketXfrmPolicy, &outer_policy).unwrap();
    setsockopt(&socket, UdpEncapsulation, &2).unwrap();
    socket
}

fn receiver(address: [u8; 4]) -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::from(address), PORT)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}

fn capture() -> OwnedFd {
    let fd = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthAll,
    )
    .unwrap();
    setsockopt(&fd, sockopt::ReceiveTimeout, &TimeVal::new(3, 0)).unwrap();
    fd
}

fn captured_spi(fd: &OwnedFd, payload: &[u8], destination: [u8; 4]) -> u32 {
    let mut bytes = [0u8; 65536];
    for _ in 0..128 {
        let (length, _) = recvfrom::<LinkAddr>(fd.as_raw_fd(), &mut bytes).unwrap();
        let frame = &bytes[..length];
        if length < 50 || frame[12..14] != [8, 0] || frame[23] != 17 || frame[30..34] != destination
        {
            continue;
        }
        let udp = 14 + usize::from(frame[14] & 15) * 4;
        if udp + 16 > length || frame[udp + 2..udp + 4] != 4500u16.to_be_bytes() {
            continue;
        }
        if frame.windows(payload.len()).any(|window| window == payload) {
            return u32::from_be_bytes(frame[udp + 8..udp + 12].try_into().unwrap());
        }
    }
    panic!("authenticated tunnel frame absent");
}

fn received(socket: &UdpSocket, payload: &[u8], source: [u8; 4]) {
    let mut bytes = [0u8; 256];
    let (len, peer) = socket.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..len], payload);
    assert_eq!(peer.ip(), Ipv4Addr::from(source));
}

async fn install_local(backend: &NamespaceBoundLinuxXfrmBackend) -> Result<(), XfrmError> {
    for pair in request(false).pairs {
        backend
            .install_sa(InstallSaRequest {
                parameters: pair.inbound_sa,
            })
            .await?;
        backend
            .install_sa(InstallSaRequest {
                parameters: pair.outbound_sa,
            })
            .await?;
        if pair.pair.child() == child(1) {
            backend
                .install_policy(InstallPolicyRequest {
                    parameters: pair.inbound_policy,
                })
                .await?;
        }
        backend
            .install_policy(InstallPolicyRequest {
                parameters: pair.outbound_policy.unwrap(),
            })
            .await?;
    }
    Ok(())
}

// Independently construct authentication-only ESP transport bytes. The kernel
// receiver, not a round trip through the SDK encoder, verifies these packets.
fn authenticated_packet(id: u64, incarnation: u64, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let inner_length = 20 + 8 + payload.len();
    let mut inner = vec![0_u8; inner_length];
    inner[0] = 0x45;
    inner[2..4].copy_from_slice(&(inner_length as u16).to_be_bytes());
    inner[8] = 64;
    inner[9] = 17;
    inner[12..16].copy_from_slice(&INNER_PEER);
    inner[16..20].copy_from_slice(&INNER_LOCAL);
    let mut sum: u32 = inner[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes(*pair)))
        .sum();
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    inner[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    inner[20..22].copy_from_slice(&34567_u16.to_be_bytes());
    inner[22..24].copy_from_slice(&PORT.to_be_bytes());
    inner[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    // IPv4 UDP permits the literal zero checksum used by this synthetic peer.
    inner[28..].copy_from_slice(payload);
    let mut esp = spi(id, incarnation, true).to_be_bytes().to_vec();
    esp.extend_from_slice(&sequence.to_be_bytes());
    esp.extend_from_slice(&inner);
    let padding = (4 - (inner.len() + 2) % 4) % 4;
    esp.extend(1..=padding as u8);
    esp.extend_from_slice(&[padding as u8, 4]);
    let key = vec![0x50 + id as u8 + incarnation as u8 + 1; 32];
    let mut authentication = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
    authentication.update(&esp);
    esp.extend_from_slice(&authentication.finalize().into_bytes()[..16]);
    esp
}

fn send_authenticated(network: &Network, source_port: u16, packet: &[u8]) {
    let sender = peer(&network.peer, move || {
        UdpSocket::bind((Ipv4Addr::from(OUTER_PEER), source_port)).unwrap()
    });
    sender
        .send_to(packet, (Ipv4Addr::from(OUTER_LOCAL), 4500))
        .unwrap();
}

async fn sealed_observation(
    monitor: &mut LinuxEspPeerObservationMonitor,
    handle: &InstalledChildSaObservationHandle,
) -> Result<AuthenticatedChildSaPeerObservation, XfrmError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(observation) = monitor.poll_installed_child_sa(handle).await? {
                return Ok(observation);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| XfrmError::Unavailable)?
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, CAP_NET_RAW, BPF tracing and a fresh netns"]
async fn installed_child_sa_provenance_seals_exact_inbound_pair_and_publication(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED=1 in a fresh netns");
        return Ok(());
    }
    let network = Network::new();
    let _encapsulation = encapsulation(OUTER_LOCAL);
    let receiver = receiver(INNER_LOCAL);
    let capture = capture();
    let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
    install_local(&backend).await?;
    let publication = backend
        .publish_child_sa_roster(
            backend.begin_child_sa_roster_update().await?,
            request(false),
        )
        .await?;
    let config = LinuxEspPeerObservationConfig::new(4)?;
    let mut monitor = backend.create_esp_peer_observation_monitor(config).await?;
    let mut handles = Vec::new();
    for id in 1..=3 {
        handles.push(
            monitor
                .register_installed_child_sa(
                    &publication,
                    child(id),
                    ChildSaIncarnation::new(1).unwrap(),
                )
                .await?,
        );
    }
    assert!(monitor
        .register_installed_child_sa(&publication, child(99), ChildSaIncarnation::new(1).unwrap(),)
        .await
        .is_err());
    // Identical first registration keys/epochs on the same actor must not let
    // a handle cross the monitors' private source scopes.
    let mut other_monitor = backend.create_esp_peer_observation_monitor(config).await?;
    let other_handle = other_monitor
        .register_installed_child_sa(&publication, child(1), ChildSaIncarnation::new(1).unwrap())
        .await?;
    assert_eq!(other_handle.registration(), handles[0].registration());
    assert!(matches!(
        other_monitor.poll_installed_child_sa(&handles[0]).await,
        Err(XfrmError::StateMismatch {
            operation: "installed_child_sa_observation_scope"
        })
    ));
    other_monitor.close().await?;
    let foreign = LinuxXfrmBackend::new().bind_current_network_namespace()?;
    let mut foreign_monitor = foreign.create_esp_peer_observation_monitor(config).await?;
    assert!(foreign_monitor
        .register_installed_child_sa(&publication, child(1), ChildSaIncarnation::new(1).unwrap(),)
        .await
        .is_err());
    assert!(foreign_monitor
        .poll_installed_child_sa(&handles[0])
        .await
        .is_err());
    foreign_monitor.close().await?;

    for (index, handle) in handles.iter().enumerate() {
        let id = index as u64 + 1;
        for sequence in 1..=2 {
            let payload = format!("n3-sealed-in-{id}-{sequence}");
            let packet = authenticated_packet(id, 1, sequence, payload.as_bytes());
            let source_port = 4500 + sequence as u16;
            send_authenticated(&network, source_port, &packet);
            assert_eq!(
                captured_spi(&capture, payload.as_bytes(), OUTER_LOCAL),
                spi(id, 1, true)
            );
            received(&receiver, payload.as_bytes(), INNER_PEER);
            let receipt = sealed_observation(&mut monitor, handle).await?;
            assert_eq!(receipt.pair().child(), child(id));
            assert_eq!(receipt.pair().incarnation().get(), 1);
            assert_eq!(receipt.roster_generation(), publication.generation());
            assert_eq!(receipt.observation().key.id.spi, spi(id, 1, true));
            assert_eq!(receipt.observation().epoch, handle.registration().epoch());
            assert_eq!(receipt.observation().outer_source_port, source_port);
            assert_eq!(receipt.observation().loss, EspPeerObservationLoss::None);
            assert_eq!(
                format!("{receipt:?}"),
                "AuthenticatedChildSaPeerObservation(<redacted>)"
            );
            // Raw public observations remain editable data. Editing a copy
            // cannot alter the sealed pair or the retained trusted facts.
            let mut edited = *receipt.observation();
            edited.key.id.spi ^= 1;
            assert_ne!(edited.key, receipt.observation().key);
        }
    }
    let mut invalid = authenticated_packet(2, 1, 3, b"n3-invalid-icv");
    *invalid.last_mut().unwrap() ^= 1;
    send_authenticated(&network, 4503, &invalid);
    send_authenticated(
        &network,
        4503,
        &authenticated_packet(2, 1, 2, b"n3-replayed"),
    );
    receiver.set_read_timeout(Some(Duration::from_millis(100)))?;
    assert!(receiver.recv_from(&mut [0_u8; 256]).is_err());
    assert!(monitor
        .poll_installed_child_sa(&handles[1])
        .await?
        .is_none());

    // Queue an authenticated event under the old publication, then rekey.
    // Neither the old handle nor a new publication may relabel that event.
    send_authenticated(
        &network,
        4510,
        &authenticated_packet(1, 1, 3, b"n3-old-publication"),
    );
    received(&receiver, b"n3-old-publication", INNER_PEER);
    backend
        .install_sa(InstallSaRequest {
            parameters: sa(2, 2, true),
        })
        .await?;
    backend
        .install_sa(InstallSaRequest {
            parameters: sa(2, 2, false),
        })
        .await?;
    backend
        .rekey_policy(RekeyPolicyRequest {
            parameters: policy(&sa(2, 2, false), XfrmDirection::Out),
        })
        .await?;
    assert!(matches!(
        monitor.poll_installed_child_sa(&handles[0]).await,
        Err(XfrmError::StateMismatch {
            operation: "installed_child_sa_roster_generation"
        })
    ));
    let successor = backend
        .publish_child_sa_roster(backend.begin_child_sa_roster_update().await?, request(true))
        .await?;
    assert!(monitor
        .register_installed_child_sa(&successor, child(1), ChildSaIncarnation::new(1).unwrap(),)
        .await
        .is_err());
    monitor.close().await?;
    let mut monitor = backend.create_esp_peer_observation_monitor(config).await?;
    for incarnation in 1..=2 {
        let handle = monitor
            .register_installed_child_sa(
                &successor,
                child(2),
                ChildSaIncarnation::new(incarnation).unwrap(),
            )
            .await?;
        assert!(monitor.poll_installed_child_sa(&handle).await?.is_none());
        let payload = format!("n3-overlap-in-{incarnation}");
        let sequence = if incarnation == 1 { 3 } else { 1 };
        send_authenticated(
            &network,
            4510 + incarnation as u16,
            &authenticated_packet(2, incarnation, sequence, payload.as_bytes()),
        );
        received(&receiver, payload.as_bytes(), INNER_PEER);
        let receipt = sealed_observation(&mut monitor, &handle).await?;
        assert_eq!(receipt.pair().incarnation().get(), incarnation);
        assert_eq!(receipt.roster_generation(), successor.generation());
        assert_eq!(
            receipt.pair().outbound_use(),
            if incarnation == 1 {
                ChildSaOutboundUse::ReceiveOnly
            } else {
                ChildSaOutboundUse::Selected
            }
        );
        monitor.teardown(handle.registration()).await?;
        assert!(monitor.poll_installed_child_sa(&handle).await.is_err());
    }
    monitor.close().await?;
    eprintln!("N3_CHILD_SA_INBOUND_PROOF_OK");
    Ok(())
}

fn install_peer(name: &str, overlap: bool) -> Result<(), XfrmError> {
    peer(name, move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
            for (id, incarnation) in if overlap {
                vec![(2, 2)]
            } else {
                vec![(1, 1), (2, 1), (3, 1)]
            } {
                let mut inbound = sa(id, incarnation, false);
                inbound.mark = None;
                let mut outbound = sa(id, incarnation, true);
                outbound.mark = Some(XfrmLookupMark::full(id as u32));
                backend
                    .install_sa(InstallSaRequest {
                        parameters: inbound.clone(),
                    })
                    .await?;
                backend
                    .install_sa(InstallSaRequest {
                        parameters: outbound.clone(),
                    })
                    .await?;
                if id == 1 {
                    backend
                        .install_policy(InstallPolicyRequest {
                            parameters: policy(&inbound, XfrmDirection::In),
                        })
                        .await?;
                }
                if overlap {
                    backend
                        .rekey_policy(RekeyPolicyRequest {
                            parameters: policy(&outbound, XfrmDirection::Out),
                        })
                        .await?;
                } else {
                    backend
                        .install_policy(InstallPolicyRequest {
                            parameters: policy(&outbound, XfrmDirection::Out),
                        })
                        .await?;
                }
            }
            Ok(())
        })
    })
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, CAP_NET_RAW, XFRM and a fresh netns"]
async fn installed_child_sa_roster_selects_exact_marked_spis_and_fences_replacement(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED=1 in a fresh netns");
        return Ok(());
    }
    let network = Network::new();
    let _local_encapsulation = encapsulation(OUTER_LOCAL);
    let _peer_encapsulation = peer(&network.peer, || encapsulation(OUTER_PEER));
    let local_receiver = receiver(INNER_LOCAL);
    let peer_receiver = peer(&network.peer, || receiver(INNER_PEER));
    let capture = capture();
    let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
    install_local(&backend).await?;
    install_peer(&network.peer, false)?;
    let pending = backend.begin_child_sa_roster_update().await?;
    let publication = backend
        .publish_child_sa_roster(
            backend.begin_child_sa_roster_update().await?,
            request(false),
        )
        .await?;
    assert!(backend
        .publish_child_sa_roster(pending, request(false))
        .await
        .is_err());

    for (flow, id) in [(10, 1), (11, 1), (20, 2), (21, 2), (30, 3), (31, 3), (0, 3)] {
        let choice = if flow == 0 {
            ChildSaOutboundSelection::Default
        } else {
            ChildSaOutboundSelection::Class(class(flow))
        };
        let selected = backend
            .select_installed_child_sa(&publication, choice)
            .await?;
        assert_eq!(selected.pair().child(), child(id));
        let payload = format!("n3-childsa-out-{flow}");
        let sender = UdpSocket::bind((Ipv4Addr::from(INNER_LOCAL), 0))?;
        setsockopt(
            &sender,
            sockopt::Mark,
            &selected.pair().outbound().query().mark.unwrap().value(),
        )?;
        sender.send_to(payload.as_bytes(), (Ipv4Addr::from(INNER_PEER), PORT))?;
        assert_eq!(
            captured_spi(&capture, payload.as_bytes(), OUTER_PEER),
            spi(id, 1, false)
        );
        received(&peer_receiver, payload.as_bytes(), INNER_LOCAL);
    }
    for id in 1..=3 {
        let sender = peer(&network.peer, move || {
            let socket = UdpSocket::bind((Ipv4Addr::from(INNER_PEER), 0)).unwrap();
            setsockopt(&socket, sockopt::Mark, &(id as u32)).unwrap();
            socket
        });
        for flow in 0..2 {
            let payload = format!("n3-childsa-in-{id}-{flow}");
            sender.send_to(payload.as_bytes(), (Ipv4Addr::from(INNER_LOCAL), PORT))?;
            assert_eq!(
                captured_spi(&capture, payload.as_bytes(), OUTER_LOCAL),
                spi(id, 1, true)
            );
            received(&local_receiver, payload.as_bytes(), INNER_PEER);
        }
    }

    // Rekey keeps both directional predecessor SAs installed. One concrete
    // outbound policy selects the successor; the shared inbound reqid policy
    // continues accepting the predecessor until its caller-owned retirement.
    backend
        .install_sa(InstallSaRequest {
            parameters: sa(2, 2, true),
        })
        .await?;
    backend
        .install_sa(InstallSaRequest {
            parameters: sa(2, 2, false),
        })
        .await?;
    backend
        .rekey_policy(RekeyPolicyRequest {
            parameters: policy(&sa(2, 2, false), XfrmDirection::Out),
        })
        .await?;
    install_peer(&network.peer, true)?;
    assert!(backend
        .select_installed_child_sa(&publication, ChildSaOutboundSelection::Default)
        .await
        .is_err());
    let publication = backend
        .publish_child_sa_roster(backend.begin_child_sa_roster_update().await?, request(true))
        .await?;
    let selected = backend
        .select_installed_child_sa(&publication, ChildSaOutboundSelection::Class(class(20)))
        .await?;
    assert_eq!(selected.pair().incarnation().get(), 2);
    let sender = UdpSocket::bind((Ipv4Addr::from(INNER_LOCAL), 0))?;
    setsockopt(&sender, sockopt::Mark, &2)?;
    sender.send_to(b"n3-childsa-rekey", (Ipv4Addr::from(INNER_PEER), PORT))?;
    assert_eq!(
        captured_spi(&capture, b"n3-childsa-rekey", OUTER_PEER),
        spi(2, 2, false)
    );
    received(&peer_receiver, b"n3-childsa-rekey", INNER_LOCAL);

    // Remove/reinstall with identical declaration must not revive the old
    // publication. No packet is sent with reset sequence state: counter/key
    // continuity remains governed by the existing custody/resume APIs.
    backend
        .remove_sa(RemoveSaRequest {
            destination: ip(OUTER_PEER),
            protocol: 50,
            spi: spi(2, 2, false),
            mark: Some(XfrmLookupMark::full(2)),
        })
        .await?;
    backend
        .install_sa(InstallSaRequest {
            parameters: sa(2, 2, false),
        })
        .await?;
    assert!(backend
        .select_installed_child_sa(&publication, ChildSaOutboundSelection::Default)
        .await
        .is_err());
    let publication = backend
        .publish_child_sa_roster(backend.begin_child_sa_roster_update().await?, request(true))
        .await?;
    // An intentionally foreign policy writer bypasses the actor solely as a
    // negative detector: exact whole-roster readback must catch the conflict.
    let raw = LinuxXfrmBackend::new();
    let original = policy(&sa(1, 1, false), XfrmDirection::Out);
    let mut conflict = original.clone();
    conflict.templates[0].id.spi ^= 0x10;
    raw.rekey_policy(RekeyPolicyRequest {
        parameters: conflict,
    })
    .await?;
    assert!(backend
        .select_installed_child_sa(&publication, ChildSaOutboundSelection::Default)
        .await
        .is_err());
    raw.rekey_policy(RekeyPolicyRequest {
        parameters: original,
    })
    .await?;
    assert!(backend
        .select_installed_child_sa(&publication, ChildSaOutboundSelection::Default)
        .await
        .is_err());
    eprintln!("N3_CHILD_SA_INSTALLED_PACKET_PROOF_OK");
    Ok(())
}
