//! An attachment needs the interface on which IP input receives: a device
//! stacked on the interface, on a real kernel (#1019).
//!
//! tc decides a hand-off on the device it is attached to. It looks for the
//! consumer there, and where it cannot settle the consumer it relies on the
//! frame's type reaching UDP input. Both assume that IP input receives the
//! datagram on that same device.
//!
//! A macvlan and an ipvlan above the interface break that without becoming
//! its master. Each registers a receive handler on the interface, which runs
//! after tc and moves a frame to the stacked device: a macvlan by the frame's
//! destination address, or every frame in passthru mode, and an ipvlan by the
//! packet's destination address. A macvlan also sets the frame's type back to
//! "host". The VRF of the stacked device and the sockets bound to it then
//! decide the delivery, which tc's lookup on the lower interface does not
//! see:
//!
//! - a fragmented hand-off passes its first-fragment check because of a
//!   consumer on the lower interface, and the host answers the reassembled
//!   datagram, which the stacked device receives, with ICMP Port Unreachable;
//! - with the stacked device in a VRF and an unrelated socket in the default
//!   VRF, a hand-off is assigned to that socket across the VRF boundary, or
//!   answered with ICMP Port Unreachable.
//!
//! The contract: the backend refuses an interface that another device of the
//! namespace names as its lower link, unless that device is of a kind that
//! leaves the frames of the lower interface alone: a VLAN device with a VLAN
//! ID other than 0, a tunnel that is bound to the interface, the other end of
//! a veth pair. It does not attach to a refused interface and does not adopt
//! a retained attachment on it, and it changes nothing when it refuses. If a device is stacked on the interface of an
//! attachment later, the backend refuses to open the control port, to hand
//! the attachment out again and to activate it after a cleanup; the process
//! that made the attachment still removes it.

use super::attachment_receive_interface::{
    not_activated_while, ordinary_request, outcome, Attachment,
};
use super::backend_hand_off_consumer::ipv4_reassembly_queues;
use super::backend_hand_off_vrf::{
    udp_socket, Legs, VrfSlave, FRAGMENTED_PAYLOAD, UNKNOWN_TEID, VRF_DEVICE,
};
use super::*;

/// The feature that the refusal names.
const REFUSED: &str = "attachment_below_stacked_device";
const MACVLAN: &str = "opcmv0";
const IPVLAN: &str = "opciv0";
const VLAN_ZERO: &str = "opcvl0";
const VLAN: &str = "opcvl100";
const TUNNEL: &str = "opcgre0";
/// A veth pair with both ends in this namespace.
const PAIR: (&str, &str) = ("opcva", "opcvb");
const PAIR_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);

/// A device stacked on the attachment's interface, for the life of this
/// value.
struct Stacked {
    name: &'static str,
}

impl Stacked {
    /// A device of `kind`, with the options that follow it, above the
    /// attachment's interface.
    fn above_the_interface(name: &'static str, kind: &[&str]) -> Self {
        let mut arguments = vec!["link", "add", "link", "s2bu", "name", name, "type"];
        arguments.extend_from_slice(kind);
        run("ip", &arguments);
        let stacked = Self { name };
        run("ip", &["link", "set", name, "up"]);
        stacked
    }

    /// Move the endpoint addresses from the interface to this device.
    fn take_the_endpoints(&self) {
        run("ip", &["addr", "flush", "dev", "s2bu"]);
        run("ip", &["addr", "add", "192.0.2.1/24", "dev", self.name]);
        run(
            "ip",
            &[
                "-6",
                "addr",
                "replace",
                "2001:db8:2::1/64",
                "dev",
                self.name,
                "nodad",
            ],
        );
    }
}

impl Drop for Stacked {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", self.name]).output();
    }
}

fn refused<T>(result: &Result<T, GtpuError>) -> bool {
    matches!(result, Err(GtpuError::UnsupportedFeature { feature }) if *feature == REFUSED)
}

/// The hand-offs that the core sends, as frames for the link address of the
/// attachment's interface.
struct Frames<'a> {
    net: &'a TestNet,
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
}

impl<'a> Frames<'a> {
    fn new(net: &'a TestNet) -> Self {
        Self {
            net,
            destination_mac: main_link_address("s2bu"),
            source_mac: net.pgw_link_address("s2bup"),
        }
    }

    /// A G-PDU for no tunnel.
    fn gpdu(&self, tag: u8, payload: usize) -> Vec<u8> {
        build_gpdu(
            UNKNOWN_TEID,
            None,
            &build_inner_udp(REMOTE_HOST, UE_PAA, 5060, 5060, &vec![tag; payload]),
        )
    }

    fn ipv4(&self, gpdu: &[u8]) -> Vec<u8> {
        build_outer_gtpu_frame(self.destination_mac, self.source_mac, &[], gpdu, true, 0)
    }

    fn ipv6(&self, gpdu: &[u8]) -> Vec<u8> {
        build_outer_ipv6_gtpu_frame(
            self.destination_mac,
            self.source_mac,
            PGW_IPV6,
            EPDG_S2BU_IPV6,
            gpdu,
            OuterIpv6Extension::None,
        )
    }

    fn send(&self, frame: &[u8]) {
        send_raw_gtpu_frame(
            &self.net.pgw_ns,
            "s2bup",
            frame,
            RawChecksumMetadata::Unverified,
        );
    }

    /// Both fragments of a datagram leave in one burst, in the given order.
    fn send_fragments(&self, gpdu: &[u8], identification: u16, reverse: bool) {
        let (head, tail) = build_outer_fragments(&self.ipv4(gpdu), 1_000, identification);
        let burst = if reverse { [tail, head] } else { [head, tail] };
        send_raw_gtpu_frames(&self.net.pgw_ns, "s2bup", &burst);
    }
}

/// The reassembly counts of the packet legs must be this test's own.
pub(super) fn wait_for_reassembly_leftovers() {
    let deadline = Instant::now() + Duration::from_secs(35);
    while ipv4_reassembly_queues() != 0 {
        assert!(
            Instant::now() < deadline,
            "reassembly queues left by an earlier test did not expire"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn backend_for(net: &TestNet) -> Arc<EbpfGtpuDataplaneBackend> {
    Arc::new(EbpfGtpuDataplaneBackend::with_config(
        EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..EbpfGtpuDataplaneBackendConfig::default()
        },
    ))
}

/// Each entry point refuses the interface below `case`, and no hook or pin
/// exists afterwards. `accepted` runs with the attachment that
/// `create_device_with_endpoints` made, if it made one after all, and reports
/// what that attachment then does with hand-offs.
async fn refused_before_anything_is_attached<Accepted>(
    net: &TestNet,
    case: &str,
    violations: &mut Vec<String>,
    accepted: Accepted,
) -> Result<(), Box<dyn std::error::Error>>
where
    Accepted: FnOnce(&Path) -> Result<Vec<String>, Box<dyn std::error::Error>>,
{
    let backend = backend_for(net);
    let pins = [
        net.pin_root.join("s2bu"),
        grouped_pin_directory(&net.pin_root, grouped_device_id()),
    ];
    let untouched = |entry: &str, violations: &mut Vec<String>| {
        for pin in &pins {
            let found = Attachment::observe(pin);
            if !found.is_absent() || pin.exists() {
                violations.push(format!(
                    "{entry} below {case}: a hook or a pin exists: {found:?}"
                ));
            }
        }
    };

    let grouped = backend
        .create_device_with_endpoints(grouped_device_request(grouped_mtu_policy()))
        .await;
    if !refused(&grouped) {
        violations.push(format!(
            "create_device_with_endpoints below {case}: {}",
            outcome(&grouped)
        ));
    }
    match grouped {
        Ok(device) => {
            let pin_dir = grouped_pin_directory(&net.pin_root, grouped_device_id());
            violations.extend(accepted(&pin_dir)?);
            backend.remove_device(&device).await?;
        }
        Err(_) => untouched("create_device_with_endpoints", violations),
    }

    let ordinary = backend.create_device(ordinary_request()).await;
    if !refused(&ordinary) {
        violations.push(format!(
            "create_device below {case}: {}",
            outcome(&ordinary)
        ));
    }
    match ordinary {
        Ok(device) => backend.remove_device(&device).await?,
        Err(_) => untouched("create_device", violations),
    }

    // Nothing is retained here, so there is nothing to adopt; the interface
    // is refused all the same, before the backend looks for a retained graph.
    let resolved = backend.resolve_device("s2bu").await;
    if !refused(&resolved) {
        violations.push(format!(
            "resolve_device below {case}: {}",
            outcome(&resolved)
        ));
    }
    Ok(())
}

/// What an accepted attachment does with the hand-offs of a consumer on its
/// interface, while `case` holds the endpoint. tc finds that consumer by a
/// lookup on the interface; the stacked device receives the datagrams.
fn hand_offs_of_a_consumer_on_the_interface(
    net: &TestNet,
    pin_dir: &Path,
    case: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use nix::sys::socket::AddressFamily;

    wait_for_reassembly_leftovers();
    let capture = packet_capture_socket(&net.pgw_ns);
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    let frames = Frames::new(net);
    let core = SocketAddr::from((PGW_IP, GTPU_PORT));
    let consumer = udp_socket(AddressFamily::Inet, GTPU_PORT, false, Some("s2bu"))?;
    let mut legs = Legs {
        capture: &capture,
        pin_dir,
        counted: 0,
        unanswered: 0,
        violations: Vec::new(),
    };

    let unknown = frames.gpdu(0x60, 64);
    let before = legs.begin();
    frames.send(&frames.ipv4(&unknown));
    legs.delivered(
        &format!("G-PDU for no tunnel, consumer on the interface below {case}"),
        before,
        &consumer,
        &unknown,
        core,
        false,
        &[],
    );
    let fragmented = frames.gpdu(0x61, FRAGMENTED_PAYLOAD);
    let before = legs.begin();
    frames.send_fragments(&fragmented, 0x1b00, false);
    legs.delivered(
        &format!("outer-fragmented G-PDU, consumer on the interface below {case}"),
        before,
        &consumer,
        &fragmented,
        core,
        true,
        &[],
    );
    Ok(legs.violations)
}

/// What an accepted attachment does with hand-offs while the stacked device
/// that holds the endpoint is in a VRF without a consumer, and an unrelated
/// socket listens in the default VRF on every address.
fn hand_offs_next_to_a_listener_in_the_default_vrf(
    net: &TestNet,
    pin_dir: &Path,
    case: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use nix::sys::socket::AddressFamily;

    wait_for_reassembly_leftovers();
    let capture = packet_capture_socket(&net.pgw_ns);
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
    let frames = Frames::new(net);
    let bystander_v4 = udp_socket(AddressFamily::Inet, GTPU_PORT, false, None)?;
    let bystander_v6 = udp_socket(AddressFamily::Inet6, GTPU_PORT, false, None)?;
    let bystanders = [&bystander_v4, &bystander_v6];
    let mut legs = Legs {
        capture: &capture,
        pin_dir,
        counted: 0,
        unanswered: 0,
        violations: Vec::new(),
    };

    let before = legs.begin();
    frames.send(&frames.ipv4(&frames.gpdu(0x70, 64)));
    legs.refused(
        &format!("G-PDU for no tunnel below {case}, listener in the default VRF"),
        before,
        1,
        false,
        &bystanders,
    );
    let before = legs.begin();
    frames.send(&frames.ipv6(&frames.gpdu(0x71, 64)));
    legs.refused(
        &format!("G-PDU for no tunnel over IPv6 below {case}, listener in the default VRF"),
        before,
        1,
        false,
        &bystanders,
    );
    let before = legs.begin();
    frames.send_fragments(&frames.gpdu(0x72, FRAGMENTED_PAYLOAD), 0x1b10, false);
    legs.refused(
        &format!("outer-fragmented G-PDU below {case}, listener in the default VRF"),
        before,
        1,
        true,
        &bystanders,
    );
    let before = legs.begin();
    frames.send_fragments(&frames.gpdu(0x73, FRAGMENTED_PAYLOAD), 0x1b11, true);
    legs.refused(
        &format!(
            "outer-fragmented G-PDU in reverse order below {case}, listener in the default VRF"
        ),
        before,
        1,
        true,
        &bystanders,
    );
    Ok(legs.violations)
}

fn skipped() -> bool {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return true;
    }
    false
}

// The serial guard is deliberately held for the entire body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify() -> Result<(), Box<dyn std::error::Error>> {
    if skipped() {
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut violations = Vec::new();
    refused_below_a_macvlan(&mut violations).await?;
    refused_below_an_ipvlan(&mut violations).await?;
    refused_below_a_vlan_for_untagged_frames(&mut violations).await?;
    refused_once_stacked(&mut violations).await?;
    accepted_below_devices_that_leave_its_frames(&mut violations).await?;
    not_activated_while(
        "a macvlan is stacked on the interface",
        refused::<GtpDevice>,
        || Stacked::above_the_interface(MACVLAN, &["macvlan", "mode", "bridge"]),
        &mut violations,
    )
    .await?;
    assert!(
        violations.is_empty(),
        "an interface below a stacked device was not refused:\n{}",
        violations.join("\n")
    );
    eprintln!(
        "OPC_GTPU_ATTACHMENT_BELOW_STACKED_DEVICE_PROVEN: an interface below a passthru macvlan, below an ipvlan and below a VLAN device with the ID 0 is refused by create_device_with_endpoints, create_device and resolve_device before any hook or pin exists; once a macvlan is stacked on the interface of an attachment, the control port and the hand-out are refused and neither hook nor pin changes, and the process that made the attachment still removes it; an interface that a VLAN device, a tunnel and the other end of a veth pair name as their link is accepted; a cleanup-only attachment is fenced but not activated while a macvlan is stacked on the interface, and activated after it is gone"
    );
    Ok(())
}

/// A passthru macvlan above the interface holds the endpoint. It takes every
/// frame of the interface.
async fn refused_below_a_macvlan(
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let macvlan = Stacked::above_the_interface(MACVLAN, &["macvlan", "mode", "passthru"]);
    macvlan.take_the_endpoints();
    let case = "a passthru macvlan";
    refused_before_anything_is_attached(&net, case, violations, |pin_dir| {
        hand_offs_of_a_consumer_on_the_interface(&net, pin_dir, case)
    })
    .await
}

/// An ipvlan above the interface holds the endpoint. It takes the packets for
/// its own addresses.
async fn refused_below_an_ipvlan(
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let ipvlan = Stacked::above_the_interface(IPVLAN, &["ipvlan", "mode", "l2"]);
    ipvlan.take_the_endpoints();
    let case = "an ipvlan";
    refused_before_anything_is_attached(&net, case, violations, |pin_dir| {
        hand_offs_of_a_consumer_on_the_interface(&net, pin_dir, case)
    })
    .await
}

/// A VLAN device with the ID 0 above the interface takes the frames that
/// carry a priority tag, which tc treats as the interface's own.
async fn refused_below_a_vlan_for_untagged_frames(
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let _vlan = Stacked::above_the_interface(VLAN_ZERO, &["vlan", "id", "0"]);
    refused_before_anything_is_attached(&net, "a VLAN device with the ID 0", violations, |_| {
        Ok(Vec::new())
    })
    .await
}

/// A device that names the interface as its link and leaves its frames alone
/// does not refuse it: a VLAN device with a VLAN ID, a tunnel that is bound
/// to the interface, and the other end of a veth pair.
async fn accepted_below_devices_that_leave_its_frames(
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let backend = backend_for(&net);
    {
        let _vlan = Stacked::above_the_interface(VLAN, &["vlan", "id", "100"]);
        run(
            "ip",
            &[
                "link",
                "add",
                TUNNEL,
                "type",
                "gre",
                "local",
                "192.0.2.1",
                "remote",
                "192.0.2.10",
                "dev",
                "s2bu",
            ],
        );
        let _tunnel = Stacked { name: TUNNEL };
        let grouped = backend
            .create_device_with_endpoints(grouped_device_request(grouped_mtu_policy()))
            .await;
        match grouped {
            Ok(device) => {
                // The control port opens as well, and the attachment is
                // handed out again.
                let port = backend.open_gtpu_control_port(&device).await;
                if port.is_err() {
                    violations.push(format!(
                        "open_gtpu_control_port below a VLAN device and a tunnel: {}",
                        outcome(&port)
                    ));
                }
                drop(port);
                backend.remove_device(&device).await?;
            }
            Err(error) => violations.push(format!(
                "create_device_with_endpoints below a VLAN device and a tunnel: {error:?}"
            )),
        }
    }

    // Both ends of this pair are in the namespace, so each names the other
    // as its link.
    run(
        "ip",
        &[
            "link", "add", PAIR.0, "type", "veth", "peer", "name", PAIR.1,
        ],
    );
    let _pair = Stacked { name: PAIR.0 };
    for end in [PAIR.0, PAIR.1] {
        run("ip", &["link", "set", end, "up"]);
    }
    let address = format!("{PAIR_IP}/24");
    run("ip", &["addr", "add", &address, "dev", PAIR.0]);
    let mut request = CreateGtpDeviceRequest::new(PAIR.0);
    request.bind_address = IpAddr::V4(PAIR_IP);
    match backend.create_device(request).await {
        Ok(device) => {
            let resolved = backend.resolve_device(PAIR.0).await;
            if resolved.is_err() {
                violations.push(format!(
                    "resolve_device on one end of a veth pair: {}",
                    outcome(&resolved)
                ));
            }
            backend.remove_device(&device).await?;
        }
        Err(error) => violations.push(format!(
            "create_device on one end of a veth pair: {error:?}"
        )),
    }
    Ok(())
}

/// A macvlan is stacked on the interface of an existing attachment, while the
/// pinned programs keep running and the process that made it is still there.
async fn refused_once_stacked(
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let backend = backend_for(&net);
    // On its own interface the attachment is made and its port opens.
    let device = backend.create_device(ordinary_request()).await?;
    let pin_dir = net.pin_root.join("s2bu");
    drop(backend.open_gtpu_control_port(&device).await?);
    let attached = Attachment::observe(&pin_dir);
    assert!(attached.is_complete(), "{attached:?}");

    let _macvlan = Stacked::above_the_interface(MACVLAN, &["macvlan", "mode", "bridge"]);
    let unchanged = |entry: &str, violations: &mut Vec<String>| {
        let found = Attachment::observe(&pin_dir);
        if found != attached {
            violations.push(format!(
                "{entry} after a macvlan was stacked on the interface: the attachment was changed from {attached:?} to {found:?}"
            ));
        }
    };
    let port = backend.open_gtpu_control_port(&device).await;
    if !refused(&port) {
        violations.push(format!(
            "open_gtpu_control_port after a macvlan was stacked on the interface: {}",
            outcome(&port)
        ));
    }
    drop(port);
    unchanged("open_gtpu_control_port", violations);
    let resolved = backend.resolve_device("s2bu").await;
    if !refused(&resolved) {
        violations.push(format!(
            "resolve_device after a macvlan was stacked on the interface: {}",
            outcome(&resolved)
        ));
    }
    unchanged("resolve_device", violations);

    // The backend that made the attachment still removes it.
    backend.remove_device(&device).await?;
    let left = Attachment::observe(&pin_dir);
    if !left.is_absent() || pin_dir.exists() {
        violations.push(format!(
            "remove_device after a macvlan was stacked on the interface: the attachment is still there: {left:?}"
        ));
    }
    Ok(())
}

/// The sequence of the review: a passthru macvlan above the interface holds
/// the endpoint and is enslaved to a VRF, nothing in that VRF consumes
/// UDP/2152, and an unrelated socket in the default VRF listens on that port
/// on every address.
// The serial guard is deliberately held for the entire body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_macvlan_in_a_vrf() -> Result<(), Box<dyn std::error::Error>> {
    if skipped() {
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let macvlan = Stacked::above_the_interface(MACVLAN, &["macvlan", "mode", "passthru"]);
    macvlan.take_the_endpoints();
    let vrf = VrfSlave::enslave_device(MACVLAN);
    vrf.accept_unbound_sockets(false);
    let case = "a passthru macvlan in a VRF";
    let mut violations = Vec::new();
    refused_before_anything_is_attached(&net, case, &mut violations, |pin_dir| {
        hand_offs_next_to_a_listener_in_the_default_vrf(&net, pin_dir, case)
    })
    .await?;
    assert!(
        violations.is_empty(),
        "an interface below a macvlan in a VRF was not refused:\n{}",
        violations.join("\n")
    );
    eprintln!(
        "OPC_GTPU_ATTACHMENT_BELOW_MACVLAN_IN_VRF_PROVEN: with a passthru macvlan above the interface that holds the endpoint and is enslaved to a VRF, create_device_with_endpoints, create_device and resolve_device refuse the interface before any hook or pin exists"
    );
    Ok(())
}
