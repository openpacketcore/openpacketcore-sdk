//! Privileged end-to-end proof for fixed outer DSCP on Linux XFRM.
//!
//! The test runs inside the fresh network namespace provided by CI. It
//! installs real tunnel-mode ESP state and policy through the SDK, captures
//! the encrypted packet in a peer namespace, and verifies the outer IPv4 DS
//! field and checksum. It also proves the absent path, kernel-state query,
//! capability transition, and gap-free adoption of an existing tc slot.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Barrier};

use aya::maps::MapInfo;
use aya::programs::SchedClassifier;
use nix::sys::socket::{
    recv, setsockopt, socket, sockopt, AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType,
};
use nix::sys::time::TimeVal;
use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, DscpCodepoint, InstallPolicyRequest, InstallSaRequest, IpAddress,
    KeyMaterial, LifetimeConfig, LinuxXfrmBackend, LinuxXfrmDscpMarkingConfig, PolicyParameters,
    QuerySaRequest, RekeySaRequest, RemovePolicyRequest, RemoveSaRequest, SaParameters, XfrmAction,
    XfrmBackend, XfrmCapability, XfrmDirection, XfrmId, XfrmMark, XfrmMode, XfrmSelector,
    XfrmTemplate,
};
use opc_ipsec_xfrm_ebpf_common::{MAP_MARK_CONFIG, PROG_EGRESS_DSCP};

const OUTER_LOCAL: [u8; 4] = [192, 0, 2, 1];
const OUTER_PEER: [u8; 4] = [192, 0, 2, 2];
const INNER_LOCAL: [u8; 4] = [10, 45, 0, 1];
const INNER_MARKED: [u8; 4] = [10, 45, 0, 2];
const INNER_UNMARKED: [u8; 4] = [10, 45, 0, 3];
const MARKED_SPI: u32 = 0x1000_0001;
const UNMARKED_SPI: u32 = 0x1000_0002;
const MARKED_LOOKUP: XfrmMark = XfrmMark {
    value: 0x0000_0042,
    mask: 0x0000_00ff,
};
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ESP: u8 = 50;

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

struct TestNet {
    peer_ns: String,
    pin_root: PathBuf,
}

impl TestNet {
    fn provision() -> Self {
        let pid = std::process::id();
        let peer_ns = format!("opc-xfrm-peer-{pid}");
        let pin_root = PathBuf::from(format!("/sys/fs/bpf/opc-xfrm-dscp-test-{pid}"));

        run("ip", &["netns", "add", &peer_ns]);
        run(
            "ip",
            &[
                "link",
                "add",
                "swu0",
                "address",
                "02:00:00:00:00:01",
                "type",
                "veth",
                "peer",
                "name",
                "swup",
                "address",
                "02:00:00:00:00:02",
            ],
        );
        run("ip", &["link", "set", "swup", "netns", &peer_ns]);
        run("ip", &["addr", "add", "192.0.2.1/24", "dev", "swu0"]);
        run("ip", &["link", "set", "swu0", "up"]);
        run("ip", &["addr", "add", "10.45.0.1/32", "dev", "lo"]);
        run("ip", &["link", "set", "lo", "up"]);
        run(
            "ip",
            &["-n", &peer_ns, "addr", "add", "192.0.2.2/24", "dev", "swup"],
        );
        run("ip", &["-n", &peer_ns, "link", "set", "swup", "up"]);
        run("ip", &["-n", &peer_ns, "link", "set", "lo", "up"]);
        run(
            "ip",
            &[
                "neigh",
                "add",
                "192.0.2.2",
                "lladdr",
                "02:00:00:00:00:02",
                "nud",
                "permanent",
                "dev",
                "swu0",
            ],
        );
        for destination in ["10.45.0.2/32", "10.45.0.3/32"] {
            run(
                "ip",
                &[
                    "route",
                    "add",
                    destination,
                    "via",
                    "192.0.2.2",
                    "dev",
                    "swu0",
                    "src",
                    "10.45.0.1",
                ],
            );
        }

        Self { peer_ns, pin_root }
    }

    fn capture_socket(&self) -> OwnedFd {
        in_netns(&self.peer_ns, || {
            let socket = socket(
                AddressFamily::Packet,
                SockType::Raw,
                SockFlag::SOCK_CLOEXEC,
                SockProtocol::EthAll,
            )
            .expect("open AF_PACKET capture socket");
            setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::new(3, 0))
                .expect("set capture timeout");
            socket
        })
    }
}

impl Drop for TestNet {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", "swu0"]).output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.peer_ns])
            .output();
        let _ = fs::remove_dir_all(&self.pin_root);
    }
}

fn ip(value: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(value)
}

fn selector(inner_destination: [u8; 4]) -> XfrmSelector {
    XfrmSelector::new(ip(INNER_LOCAL), ip(inner_destination), IPPROTO_UDP)
}

fn sa_parameters(
    inner_destination: [u8; 4],
    spi: u32,
    mark: Option<XfrmMark>,
    egress_dscp: Option<DscpCodepoint>,
) -> SaParameters {
    SaParameters {
        selector: selector(inner_destination),
        id: XfrmId {
            destination: ip(OUTER_PEER),
            spi,
            protocol: IPPROTO_ESP,
        },
        source_address: ip(OUTER_LOCAL),
        request_id: None,
        auth: Some((
            AuthAlgorithm::hmac_sha256(96),
            KeyMaterial::new(vec![0xab; 32]),
        )),
        crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0xcd; 16]))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark,
        if_id: None,
        egress_dscp,
    }
}

fn policy_parameters(
    inner_destination: [u8; 4],
    spi: u32,
    mark: Option<XfrmMark>,
) -> PolicyParameters {
    PolicyParameters {
        selector: selector(inner_destination),
        direction: XfrmDirection::Out,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: XfrmId {
                destination: ip(OUTER_PEER),
                spi,
                protocol: IPPROTO_ESP,
            },
            source_address: ip(OUTER_LOCAL),
            request_id: None,
            mode: XfrmMode::Tunnel,
        }],
        mark,
        if_id: None,
    }
}

async fn install_path(
    backend: &LinuxXfrmBackend,
    inner_destination: [u8; 4],
    spi: u32,
    mark: Option<XfrmMark>,
    egress_dscp: Option<DscpCodepoint>,
) -> Result<(), opc_ipsec_xfrm::XfrmError> {
    backend
        .install_sa(InstallSaRequest {
            parameters: sa_parameters(inner_destination, spi, mark, egress_dscp),
        })
        .await?;
    backend
        .install_policy(InstallPolicyRequest {
            parameters: policy_parameters(inner_destination, spi, mark),
        })
        .await
}

fn tc_filters() -> String {
    let output = Command::new("tc")
        .args(["filter", "show", "dev", "swu0", "egress"])
        .output()
        .expect("show tc egress filters");
    assert!(output.status.success(), "tc filter show must succeed");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn pinned_program_and_map_ids(pin_root: &std::path::Path) -> (u32, u32) {
    let interface_root = pin_root.join("swu0");
    let program = SchedClassifier::from_pin(interface_root.join(PROG_EGRESS_DSCP))
        .expect("open pinned XFRM DSCP classifier");
    let program_info = program.info().expect("read pinned classifier info");
    let map_id = MapInfo::from_pin(interface_root.join(MAP_MARK_CONFIG))
        .expect("open pinned XFRM DSCP config map")
        .id();
    assert!(
        program_info
            .map_ids()
            .expect("read classifier map ids")
            .expect("kernel supports classifier map ids")
            .contains(&map_id),
        "the pinned classifier must reference the exact pinned config map"
    );
    (program_info.id(), map_id)
}

fn capture_esp(capture: &OwnedFd, expected_spi: u32) -> Vec<u8> {
    let mut frame = vec![0_u8; 65_536];
    loop {
        let length = recv(capture.as_raw_fd(), &mut frame, MsgFlags::empty()).unwrap_or_else(
            |error| {
                let state = Command::new("ip")
                    .args(["-s", "xfrm", "state"])
                    .output()
                    .expect("inspect XFRM state after capture timeout");
                let policy = Command::new("ip")
                    .args(["-s", "xfrm", "policy"])
                    .output()
                    .expect("inspect XFRM policy after capture timeout");
                panic!(
                    "receive outer ESP frame with SPI {expected_spi:#010x} before timeout: {error}; state:\n{}\npolicy:\n{}",
                    String::from_utf8_lossy(&state.stdout),
                    String::from_utf8_lossy(&policy.stdout)
                );
            },
        );
        if length < 14 + 20 || frame[12..14] != [0x08, 0x00] {
            continue;
        }
        let ip = &frame[14..length];
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        if ip[0] >> 4 != 4
            || ihl < 20
            || ip.len() < ihl + 4
            || ip[9] != IPPROTO_ESP
            || ip[12..16] != OUTER_LOCAL
            || ip[16..20] != OUTER_PEER
            || u32::from_be_bytes(ip[ihl..ihl + 4].try_into().expect("ESP SPI")) != expected_spi
        {
            continue;
        }
        return ip[..ihl].to_vec();
    }
}

fn send_protected(destination: [u8; 4], tos: i32, mark: Option<u32>) {
    let socket =
        UdpSocket::bind((Ipv4Addr::from(INNER_LOCAL), 0)).expect("bind protected inner source");
    setsockopt(&socket, sockopt::Ipv4Tos, &tos).expect("set inner ToS");
    if let Some(mark) = mark {
        setsockopt(&socket, sockopt::Mark, &mark).expect("set XFRM lookup mark");
    }
    socket
        .send_to(b"opc-xfrm-dscp", (Ipv4Addr::from(destination), 5_000))
        .expect("send protected packet");
}

fn ipv4_checksum_is_valid(header: &[u8]) -> bool {
    header.chunks_exact(2).fold(0_u32, |sum, word| {
        let sum = sum + u32::from(u16::from_be_bytes([word[0], word[1]]));
        (sum & 0xffff) + (sum >> 16)
    }) == 0xffff
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root, CAP_BPF/CAP_NET_ADMIN, XFRM, bpffs, and a fresh netns"]
async fn fixed_outer_dscp_is_visible_on_real_esp_and_survives_adoption(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_XFRM_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let net = TestNet::provision();
    let mut config = LinuxXfrmDscpMarkingConfig::new([String::from("swu0")], 25)?;
    config.bpffs_pin_root = net.pin_root.clone();

    // A lexical child of /sys/fs/bpf is not sufficient: production setup must
    // reject a real symlink component before any tc program is attached.
    fs::create_dir_all(&net.pin_root)?;
    let symlink_root = PathBuf::from(format!("{}-symlink", net.pin_root.display()));
    std::os::unix::fs::symlink(&net.pin_root, &symlink_root)?;
    let mut symlink_config = config.clone();
    symlink_config.bpffs_pin_root = symlink_root.clone();
    assert!(
        LinuxXfrmBackend::with_dscp_marking(symlink_config).is_err(),
        "a symlinked bpffs descendant must fail closed"
    );
    fs::remove_file(symlink_root)?;

    // Race the first two constructors. Both must converge on one pinned map,
    // one pinned classifier, and one tc slot rather than loading half-owned
    // companions.
    let barrier = Arc::new(Barrier::new(3));
    let mut constructors = Vec::new();
    for _ in 0..2 {
        let barrier = barrier.clone();
        let config = config.clone();
        constructors.push(std::thread::spawn(move || {
            barrier.wait();
            LinuxXfrmBackend::with_dscp_marking(config)
        }));
    }
    barrier.wait();
    let mut backends = constructors
        .into_iter()
        .map(|constructor| constructor.join().expect("constructor thread"))
        .collect::<Result<Vec<_>, _>>()?;
    let backend = backends.pop().expect("first concurrent backend");
    let concurrent_peer = backends.pop().expect("second concurrent backend");
    let concurrent_filters = tc_filters();
    let concurrent_ids = pinned_program_and_map_ids(&net.pin_root);
    drop(concurrent_peer);
    assert_eq!(tc_filters(), concurrent_filters);
    assert_eq!(pinned_program_and_map_ids(&net.pin_root), concurrent_ids);

    let foreign_root = PathBuf::from(format!("{}-foreign", net.pin_root.display()));
    let mut foreign_config = config.clone();
    foreign_config.bpffs_pin_root = foreign_root.clone();
    assert!(matches!(
        LinuxXfrmBackend::with_dscp_marking(foreign_config),
        Err(opc_ipsec_xfrm::XfrmError::AlreadyExists)
    ));
    assert_eq!(
        tc_filters(),
        concurrent_filters,
        "same-name classifier backed by a different map/program must not be adopted or replace the live slot"
    );
    assert_eq!(pinned_program_and_map_ids(&net.pin_root), concurrent_ids);
    fs::remove_dir_all(foreign_root)?;
    assert_eq!(
        backend.probe().await?.egress_dscp_marking,
        XfrmCapability::Unknown,
        "tc readiness alone must not claim kernel output-mark support"
    );

    let ef = DscpCodepoint::new(46)?;
    install_path(
        &backend,
        INNER_MARKED,
        MARKED_SPI,
        Some(MARKED_LOOKUP),
        Some(ef),
    )
    .await?;
    let marked_state = backend
        .query_sa(QuerySaRequest {
            destination: ip(OUTER_PEER),
            protocol: IPPROTO_ESP,
            spi: MARKED_SPI,
            mark: Some(MARKED_LOOKUP),
        })
        .await?;
    assert_eq!(marked_state.egress_dscp, Some(ef));
    assert_eq!(
        backend.probe().await?.egress_dscp_marking,
        XfrmCapability::Available
    );

    install_path(&backend, INNER_UNMARKED, UNMARKED_SPI, None, None).await?;
    let unmarked_state = backend
        .query_sa(QuerySaRequest {
            destination: ip(OUTER_PEER),
            protocol: IPPROTO_ESP,
            spi: UNMARKED_SPI,
            mark: None,
        })
        .await?;
    assert_eq!(unmarked_state.egress_dscp, None);

    let capture = net.capture_socket();
    // Linux applies its own ECN tunnel mapping before tc egress. Capture that
    // exact legacy value, then prove the DSCP companion preserves it.
    send_protected(INNER_UNMARKED, 0x03, None);
    let legacy_ecn = capture_esp(&capture, UNMARKED_SPI)[1] & 0x03;
    send_protected(INNER_MARKED, 0x03, Some(MARKED_LOOKUP.value));
    let marked_header = capture_esp(&capture, MARKED_SPI);
    assert_eq!(marked_header[1] >> 2, 46, "outer DSCP must be EF");
    assert_eq!(
        marked_header[1] & 0x03,
        legacy_ecn,
        "companion must preserve the outer ECN produced by XFRM"
    );
    assert!(
        ipv4_checksum_is_valid(&marked_header),
        "tc rewrite must leave a valid IPv4 checksum"
    );

    send_protected(INNER_UNMARKED, 0, None);
    let unmarked_header = capture_esp(&capture, UNMARKED_SPI);
    assert_eq!(unmarked_header[1], 0, "None must retain legacy outer ToS");

    let filters_before_adoption = tc_filters();
    let ids_before_adoption = pinned_program_and_map_ids(&net.pin_root);
    assert!(filters_before_adoption.contains(PROG_EGRESS_DSCP));
    let restarted = LinuxXfrmBackend::with_dscp_marking(config)?;
    drop(backend);
    let filters_after_adoption = tc_filters();
    assert_eq!(
        filters_after_adoption, filters_before_adoption,
        "restart adoption and old-loader drop must not detach or replace the live filter"
    );
    assert_eq!(
        pinned_program_and_map_ids(&net.pin_root),
        ids_before_adoption,
        "restart adoption must preserve the exact program and map IDs"
    );
    assert_eq!(
        restarted
            .query_sa(QuerySaRequest {
                destination: ip(OUTER_PEER),
                protocol: IPPROTO_ESP,
                spi: MARKED_SPI,
                mark: Some(MARKED_LOOKUP),
            })
            .await?
            .egress_dscp,
        Some(ef)
    );
    let mut rekeyed = sa_parameters(INNER_MARKED, MARKED_SPI, Some(MARKED_LOOKUP), Some(ef));
    rekeyed.crypt = Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0xef; 16])));
    restarted
        .rekey_sa(RekeySaRequest {
            parameters: rekeyed,
        })
        .await?;
    assert_eq!(
        restarted
            .query_sa(
                QuerySaRequest::new(ip(OUTER_PEER), IPPROTO_ESP, MARKED_SPI)
                    .with_mark(MARKED_LOOKUP)
            )
            .await?
            .egress_dscp,
        Some(ef),
        "marked SA must remain addressable after mandatory rekey readback"
    );
    send_protected(INNER_MARKED, 0x03, Some(MARKED_LOOKUP.value));
    assert_eq!(capture_esp(&capture, MARKED_SPI)[1] >> 2, 46);

    for (inner_destination, spi) in [(INNER_MARKED, MARKED_SPI), (INNER_UNMARKED, UNMARKED_SPI)] {
        restarted
            .remove_policy(RemovePolicyRequest {
                selector: selector(inner_destination),
                direction: XfrmDirection::Out,
                mark: (spi == MARKED_SPI).then_some(MARKED_LOOKUP),
            })
            .await?;
        restarted
            .remove_sa(RemoveSaRequest {
                destination: ip(OUTER_PEER),
                protocol: IPPROTO_ESP,
                spi,
                mark: (spi == MARKED_SPI).then_some(MARKED_LOOKUP),
            })
            .await?;
    }
    Ok(())
}
