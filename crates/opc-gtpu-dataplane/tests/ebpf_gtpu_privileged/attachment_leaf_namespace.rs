//! A workload may attach on the leaf of a device in another namespace.
//! Foreign lower-link indices must not identify unrelated local interfaces.

use super::attachment_receive_interface::{ordinary_request, Attachment};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Macvlan,
    Ipvlan,
    Veth,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Macvlan => "macvlan",
            Self::Ipvlan => "ipvlan",
            Self::Veth => "veth",
        }
    }

    fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::Macvlan => &["macvlan", "mode", "bridge"],
            Self::Ipvlan => &["ipvlan", "mode", "l2"],
            Self::Veth => &["veth"],
        }
    }
}

struct WorkloadNamespace(String);

impl WorkloadNamespace {
    fn new() -> Self {
        let sequence = PRIVILEGED_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = format!("opc-leaf-{}-{sequence}", std::process::id());
        run("ip", &["netns", "add", &name]);
        Self(name)
    }
}

impl Drop for WorkloadNamespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).output();
    }
}

fn link(namespace: Option<&str>, name: &str) -> serde_json::Value {
    let mut arguments = Vec::new();
    if let Some(namespace) = namespace {
        arguments.extend(["-n", namespace]);
    }
    arguments.extend(["-j", "-d", "link", "show", "dev", name]);
    let output = Command::new("ip")
        .args(&arguments)
        .output()
        .expect("read link");
    assert!(output.status.success(), "ip {arguments:?}: {output:?}");
    let mut links: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("link JSON");
    assert_eq!(links.len(), 1, "one interface named {name}");
    links.remove(0)
}

fn index(link: &serde_json::Value) -> u32 {
    u32::try_from(link["ifindex"].as_u64().expect("interface index"))
        .expect("32-bit interface index")
}

/// Only a missing kernel device kind may skip a case. Permission, syntax,
/// addressing and other fixture failures remain failures.
fn optional_device(arguments: &[&str]) -> Option<String> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .expect("run ip link add");
    if output.status.success() {
        return None;
    }
    let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    assert!(
        reason.contains("Operation not supported") || reason.contains("Unknown device type"),
        "ip {arguments:?} failed: {reason}"
    );
    Some(format!("kernel device kind unavailable: {reason}"))
}

fn create_leaf(kind: Kind, first: &str, leaf: &str, peer: &str) -> Option<String> {
    let mut arguments = vec!["-n", first, "link", "add"];
    if kind != Kind::Veth {
        arguments.extend(["link", "lower0"]);
    }
    arguments.extend(["name", leaf, "type"]);
    arguments.extend(kind.arguments());
    if kind == Kind::Veth {
        arguments.extend(["peer", "name", peer]);
    }
    optional_device(&arguments)
}

/// Keep the foreign lower index ahead of the fresh workload's allocator, so
/// the collision is made by ordinary kernel allocation, not an index override.
fn pad_first_namespace(first: &str) {
    for number in 0..32 {
        let name = format!("pad{number}");
        run("ip", &["-n", first, "link", "add", &name, "type", "dummy"]);
        if index(&link(Some(first), &name)) >= 16 {
            return;
        }
    }
    panic!("fresh first namespace did not reach interface index 16");
}

fn create_collision(lower_index: u32) -> String {
    for number in 0..32 {
        let name = format!("idx{number}");
        run("ip", &["link", "add", &name, "type", "dummy"]);
        let found = index(&link(None, &name));
        assert!(
            found <= lower_index,
            "local index allocator passed {lower_index}"
        );
        if found == lower_index {
            run("ip", &["link", "set", &name, "up"]);
            run("ip", &["addr", "add", "198.51.100.1/24", "dev", &name]);
            return name;
        }
    }
    panic!("fresh workload did not reach foreign lower index {lower_index}");
}

fn assert_foreign_lower(name: &str, first: &str, lower: &str, kind: Kind) -> u32 {
    let leaf = link(None, name);
    let lower_index = index(&link(Some(first), lower));
    assert_eq!(leaf["linkinfo"]["info_kind"], kind.name());
    assert_eq!(leaf["link_index"].as_u64(), Some(u64::from(lower_index)));
    assert!(
        leaf["link_netnsid"].as_i64().is_some_and(|id| id >= 0),
        "the lower link of {name} must be identified as foreign: {leaf}"
    );
    lower_index
}

async fn forward_both_directions(
    net: &TestNet,
    backend: &EbpfGtpuDataplaneBackend,
    device: &GtpDevice,
) -> Result<(), Box<dyn std::error::Error>> {
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;
    let pgw = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let ue = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5000)).expect("bind UE socket")
    });
    let mut buffer = [0_u8; 2048];
    let payload = b"foreign-lower-uplink";
    let (length, from) = send_until_received(
        || {
            let _ = ue.send_to(payload, (REMOTE_HOST, 53));
        },
        &pgw,
        &mut buffer,
    )
    .expect("uplink must cross the leaf and arrive as GTP-U");
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
    assert!(length >= 8 + 28 + payload.len());
    assert_eq!(&buffer[..2], &[0x30, 0xff]);
    assert_eq!(
        usize::from(u16::from_be_bytes([buffer[2], buffer[3]])),
        length - 8
    );
    assert_eq!(
        u32::from_be_bytes(buffer[4..8].try_into().unwrap()),
        PEER_TEID
    );
    let inner = &buffer[8..length];
    assert_eq!(inner[0], 0x45);
    assert_eq!(inner[9], 17);
    assert_eq!(&inner[12..16], &UE_PAA.octets());
    assert_eq!(&inner[16..20], &REMOTE_HOST.octets());
    assert_eq!(u16::from_be_bytes([inner[22], inner[23]]), 53);
    assert_eq!(&inner[28..], payload);

    let payload = b"foreign-lower-downlink";
    let inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, payload);
    let gpdu = build_gpdu(LOCAL_TEID, None, &inner);
    let (length, from) = send_until_received(
        || {
            let _ = pgw.send_to(&gpdu, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &ue,
        &mut buffer,
    )
    .expect("downlink must cross the leaf, decapsulate and reach the UE");
    assert_eq!(from, SocketAddr::from((REMOTE_HOST, 53)));
    assert_eq!(&buffer[..length], payload);
    let counters = backend.datapath_snapshot(device).await?.counters;
    assert!(counters.uplink_encapsulated > 0);
    assert!(counters.downlink_decapsulated > 0);
    Ok(())
}

async fn qualify_case(
    kind: Kind,
    case: &str,
    second: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    run("ip", &["link", "set", "lo", "up"]);
    let net = TestNet::provision();
    let first = if kind == Kind::Veth {
        &net.pgw_ns
    } else {
        &net.auth_ns
    };
    if kind == Kind::Veth {
        // Rebuild the pair in the peer namespace, then move only the leaf.
        run("ip", &["link", "del", "s2bu"]);
    } else {
        run("ip", &["addr", "flush", "dev", "s2bu"]);
        run("ip", &["link", "set", "s2bu", "name", "lower0"]);
    }
    pad_first_namespace(first);
    if kind != Kind::Veth {
        run("ip", &["link", "set", "lower0", "netns", first]);
        run("ip", &["-n", first, "link", "set", "lower0", "up"]);
    }
    if let Some(reason) = create_leaf(kind, first, "s2bu", "s2bup") {
        return Ok(Some(reason));
    }
    let lower = if kind == Kind::Veth {
        "s2bup"
    } else {
        "lower0"
    };
    let lower_index = index(&link(Some(first), lower));
    let unrelated = (case == "collision").then(|| create_collision(lower_index));
    run("ip", &["-n", first, "link", "set", "s2bu", "netns", second]);
    run("ip", &["link", "set", "s2bu", "up"]);
    run("ip", &["addr", "add", "192.0.2.1/24", "dev", "s2bu"]);
    run("ethtool", &["-K", "s2bu", "tx", "off"]);
    fs::write("/proc/sys/net/ipv4/conf/s2bu/rp_filter", "0")?;
    if kind == Kind::Veth {
        run("ip", &["-n", first, "link", "set", "s2bup", "up"]);
        run(
            "ip",
            &["-n", first, "addr", "add", "192.0.2.10/24", "dev", "s2bup"],
        );
        run(
            "ip",
            &[
                "netns", "exec", first, "ethtool", "-K", "s2bup", "tx", "off",
            ],
        );
    }
    run(
        "ip",
        &["route", "replace", "8.8.8.8/32", "via", "192.0.2.10"],
    );
    assert_eq!(
        assert_foreign_lower("s2bu", first, lower, kind),
        lower_index
    );
    let leaf_index = index(&link(None, "s2bu"));

    if case == "siblings" {
        // A veth end has one peer, not a shareable parent. Its equivalent
        // arrangement is two pairs with both peers in the first namespace.
        assert_eq!(create_leaf(kind, first, "leaf1", "peer1"), None);
        run(
            "ip",
            &["-n", first, "link", "set", "leaf1", "netns", second],
        );
        run("ip", &["link", "set", "leaf1", "up"]);
        let sibling_lower = if kind == Kind::Veth { "peer1" } else { lower };
        let sibling_index = assert_foreign_lower("leaf1", first, sibling_lower, kind);
        if kind != Kind::Veth {
            assert_eq!(
                sibling_index, lower_index,
                "both leaves share the foreign parent"
            );
        } else {
            run("ip", &["-n", first, "link", "set", "peer1", "up"]);
        }
    }
    if case == "vrf" {
        if let Some(reason) =
            optional_device(&["link", "add", "leafvrf", "type", "vrf", "table", "4219"])
        {
            return Ok(Some(reason));
        }
        run("ip", &["link", "set", "leafvrf", "up"]);
        // Both fixture legs belong to this routing domain, so forwarding
        // exercises the leaf without relying on routes in the default VRF.
        for interface in ["s2bu", "ue0"] {
            run("ip", &["link", "set", interface, "master", "leafvrf"]);
        }
        run(
            "ip",
            &[
                "route",
                "replace",
                "table",
                "4219",
                "8.8.8.8/32",
                "via",
                "192.0.2.10",
            ],
        );
        assert_eq!(link(None, "s2bu")["master"], "leafvrf");
        assert_eq!(
            assert_foreign_lower("s2bu", first, lower, kind),
            lower_index
        );
    }
    // Only the macvlan and ipvlan collisions discriminate the link-namespace
    // check. The veth collision and all sibling cases are valid positive tests
    // that also pass without that check.
    if let Some(unrelated) = &unrelated {
        let local = link(None, unrelated);
        assert_eq!(
            index(&local),
            lower_index,
            "assert the real index collision before attachment"
        );
        assert_ne!(leaf_index, lower_index);
        assert_eq!(local["linkinfo"]["info_kind"], "dummy");
        assert!(
            local.get("master").is_none(),
            "unrelated interface is not enslaved"
        );
        write_marker(format_args!("OPC_GTPU_ATTACHMENT_LEAF_COLLISION: kind={} leaf_ifindex={leaf_index} foreign_lower_ifindex={lower_index} unrelated_ifindex={} link_netnsid={}", kind.name(), index(&local), link(None, "s2bu")["link_netnsid"]));
    }

    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let device = backend.create_device(ordinary_request()).await?;
    assert_eq!(device.name, "s2bu");
    assert_eq!(device.ifindex, leaf_index);
    let pin_dir = net.pin_root.join("s2bu");
    assert!(Attachment::observe(&pin_dir).is_complete());
    forward_both_directions(&net, &backend, &device).await?;
    backend.remove_device(&device).await?;
    assert!(Attachment::observe(&pin_dir).is_absent());

    if let Some(unrelated) = unrelated {
        // This dummy has no receive handler or upper device. The foreign
        // leaf must not make it appear to be below a local stacked device.
        let mut request = CreateGtpDeviceRequest::new(&unrelated);
        request.bind_address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let device = backend.create_device(request).await?;
        assert_eq!(device.name, unrelated);
        assert_eq!(device.ifindex, lower_index);
        for direction in ["ingress", "egress"] {
            assert!(
                command_stdout("tc", &["filter", "show", "dev", &unrelated, direction])
                    .contains("opc_gtpu")
            );
        }
        backend.remove_device(&device).await?;
        for direction in ["ingress", "egress"] {
            assert!(
                !command_stdout("tc", &["filter", "show", "dev", &unrelated, direction])
                    .contains("opc_gtpu")
            );
        }
        match fs::read_dir(net.pin_root.join(&unrelated)) {
            Ok(mut entries) => assert!(
                entries.next().is_none(),
                "unrelated attachment pins removed"
            ),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
        }
    }
    Ok(None)
}

// libtest writes stdout concurrently with these stderr proofs. Format the
// complete short line first so a pipe write cannot split a marker around a
// test-result line and make the lane lose a successfully executed case.
fn write_marker(arguments: std::fmt::Arguments<'_>) {
    let line = format!("{arguments}\n");
    io::stderr()
        .write_all(line.as_bytes())
        .expect("write leaf proof marker");
}

pub(super) fn qualify() {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return;
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let total = Instant::now();
    for kind in [Kind::Macvlan, Kind::Ipvlan, Kind::Veth] {
        for case in ["plain", "vrf", "collision", "siblings"] {
            let start = Instant::now();
            write_marker(format_args!(
                "OPC_GTPU_ATTACHMENT_LEAF_BEGIN: kind={} case={case}",
                kind.name()
            ));
            let namespace = WorkloadNamespace::new();
            let second = namespace.0.clone();
            let skipped = in_netns(&namespace.0, move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("leaf namespace runtime")
                    .block_on(qualify_case(kind, case, &second))
                    .unwrap_or_else(|error| panic!("{} {case}: {error:?}", kind.name()))
            });
            drop(namespace);
            let elapsed_ms = start.elapsed().as_millis();
            if let Some(reason) = skipped {
                write_marker(format_args!("OPC_GTPU_ATTACHMENT_LEAF_SKIPPED: kind={} case={case} elapsed_ms={elapsed_ms} reason={reason}", kind.name()));
            } else {
                write_marker(format_args!(
                    "OPC_GTPU_ATTACHMENT_LEAF_PASSED: kind={} case={case} elapsed_ms={elapsed_ms}",
                    kind.name()
                ));
            }
        }
    }
    write_marker(format_args!(
        "OPC_GTPU_ATTACHMENT_LEAF_MATRIX_COMPLETE: cases=12 elapsed_ms={}",
        total.elapsed().as_millis()
    ));
}
