#![cfg(target_os = "linux")]

//! A locked route MTU installed through the backend makes the forwarding
//! kernel signal an oversized packet back to its sender: an ICMPv6 Packet Too
//! Big (RFC 4443 section 3.2) for IPv6 and an ICMP Fragmentation Needed with
//! the next-hop MTU (RFC 1191) for IPv4 with DF set.
//!
//! The test process's network namespace is the router. A sender and a
//! receiver namespace hang off it on veth pairs; the backend installs a
//! host route toward the receiver that carries the locked MTU.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use opc_route_steering::{
    IpPrefix, LinuxRouteSteeringBackend, OwnedRouteRuleScope, OwnedRouteRuleSet,
    RouteConvergenceOutcome, RouteMismatch, RouteMtu, RouteReadback, RouteRequest,
    RouteSteeringBackend, RouteSteeringIpFamily,
};

const MAIN_TABLE: u32 = 254;
const PROBE_PORT: u16 = 9999;
const IPV4_ROUTE_MTU: u32 = 1200;
const IPV6_ROUTE_MTU: u32 = 1300;
const SMALL_PAYLOAD: usize = 100;
const LARGE_PAYLOAD: usize = 1400;

/// Sender probe. It sends one small and one large DF datagram on a
/// connected UDP socket, reads the first ICMP error from a raw socket, then
/// reports the path MTU the sender kernel learned from it.
const SENDER: &str = r#"
import json, select, socket, struct, sys, time
family, destination, small, large, port = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
if family == "6":
    icmp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp.setsockopt(socket.IPPROTO_IPV6, 23, 2)  # IPV6_MTU_DISCOVER = IPV6_PMTUDISC_DO
    mtu_option = (socket.IPPROTO_IPV6, 24)  # IPV6_MTU
else:
    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_MTU_DISCOVER = IP_PMTUDISC_DO
    mtu_option = (socket.IPPROTO_IP, 14)  # IP_MTU
udp.connect((destination, port))
udp.send(b"s" * small)
udp.send(b"l" * large)
error = None
deadline = time.monotonic() + 2.0
while error is None and time.monotonic() < deadline:
    ready, _, _ = select.select([icmp], [], [], max(0.0, deadline - time.monotonic()))
    if not ready:
        break
    packet, source = icmp.recvfrom(65535)
    if family == "6":
        kind, code = packet[0], packet[1]
        if kind != 2:
            continue
        mtu = struct.unpack("!I", packet[4:8])[0]
        quoted = packet[8:]
        quoted_destination = socket.inet_ntop(socket.AF_INET6, quoted[24:40])
    else:
        header = (packet[0] & 0x0F) * 4
        body = packet[header:]
        kind, code = body[0], body[1]
        if kind != 3:
            continue
        mtu = struct.unpack("!H", body[6:8])[0]
        quoted = body[8:]
        quoted_destination = socket.inet_ntop(socket.AF_INET, quoted[16:20])
    error = {"type": kind, "code": code, "mtu": mtu, "source": source[0],
             "quoted_destination": quoted_destination}
# The ICMP error reaches raw sockets before the transport error handler
# finishes the path MTU update; let that update land first.
time.sleep(0.05)
try:
    udp.send(b"l" * large)
    resend = "sent"
except OSError as failure:
    resend = failure.errno
print(json.dumps({"icmp": error, "resend": resend,
                  "path_mtu": udp.getsockopt(*mtu_option)}))
"#;

/// Receiver probe: reports the length of every datagram that arrives.
const RECEIVER: &str = r#"
import json, socket, sys, time
family = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.bind(("::" if sys.argv[1] == "6" else "0.0.0.0", int(sys.argv[2])))
sock.settimeout(0.2)
print("ready", flush=True)
lengths = []
deadline = time.monotonic() + 3.0
while time.monotonic() < deadline:
    try:
        lengths.append(len(sock.recv(65535)))
    except socket.timeout:
        pass
print(json.dumps(lengths), flush=True)
"#;

fn run(program: &str, args: &[&str]) -> Output {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn ip(args: &[&str]) -> String {
    String::from_utf8(run("ip", args).stdout).unwrap()
}

fn ifindex(name: &str) -> u32 {
    ip(&["-o", "link", "show", "dev", name])
        .split_once(':')
        .unwrap()
        .0
        .trim()
        .parse()
        .unwrap()
}

/// Minimal JSON field extraction for the probe's flat output.
fn json_field<'a>(json: &'a str, key: &str) -> &'a str {
    let start = json
        .find(&format!("\"{key}\": "))
        .unwrap_or_else(|| panic!("probe output lacks {key}: {json}"))
        + key.len()
        + 4;
    let rest = &json[start..];
    let end = rest.find([',', '}']).unwrap();
    rest[..end].trim_matches('"')
}

struct Topology {
    sender: String,
    receiver: String,
    receiver_link: u32,
}

impl Topology {
    fn provision() -> Self {
        let pid = std::process::id();
        let sender = format!("opc-mtu-snd-{pid}");
        let receiver = format!("opc-mtu-rcv-{pid}");
        run("ip", &["netns", "add", &sender]);
        run("ip", &["netns", "add", &receiver]);
        run("sysctl", &["-qw", "net.ipv4.ip_forward=1"]);
        run("sysctl", &["-qw", "net.ipv6.conf.all.forwarding=1"]);
        for (router_if, peer_if, namespace) in
            [("mtus1", "mtus0", &sender), ("mtur1", "mtur0", &receiver)]
        {
            ip(&[
                "link", "add", router_if, "type", "veth", "peer", "name", peer_if, "netns",
                namespace,
            ]);
            // No DAD, so link-local sources exist before the first send.
            run(
                "sysctl",
                &["-qw", &format!("net.ipv6.conf.{router_if}.accept_dad=0")],
            );
            run(
                "ip",
                &[
                    "netns",
                    "exec",
                    namespace,
                    "sysctl",
                    "-qw",
                    &format!("net.ipv6.conf.{peer_if}.accept_dad=0"),
                ],
            );
        }
        let configure =
            |namespace: &str, device: &str, v4: &str, v6: &str, gw4: &str, gw6: &str| {
                let exec = |args: &[&str]| {
                    let mut full = vec!["netns", "exec", namespace, "ip"];
                    full.extend_from_slice(args);
                    ip(&full);
                };
                exec(&["addr", "add", v4, "dev", device]);
                exec(&["-6", "addr", "add", v6, "dev", device, "nodad"]);
                exec(&["link", "set", device, "up"]);
                exec(&["link", "set", "lo", "up"]);
                exec(&["route", "add", "default", "via", gw4]);
                exec(&["-6", "route", "add", "default", "via", gw6]);
            };
        configure(
            &sender,
            "mtus0",
            "192.0.2.2/24",
            "2001:db8:1::2/64",
            "192.0.2.1",
            "2001:db8:1::1",
        );
        configure(
            &receiver,
            "mtur0",
            "198.51.100.9/24",
            "2001:db8:2::9/64",
            "198.51.100.1",
            "2001:db8:2::1",
        );
        ip(&["addr", "add", "192.0.2.1/24", "dev", "mtus1"]);
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            "mtus1",
            "nodad",
        ]);
        ip(&["addr", "add", "198.51.100.1/24", "dev", "mtur1"]);
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:2::1/64",
            "dev",
            "mtur1",
            "nodad",
        ]);
        ip(&["link", "set", "mtus1", "up"]);
        ip(&["link", "set", "mtur1", "up"]);
        // Resolve every neighbour before the exact probes.
        for (namespace, target) in [
            (&sender, "192.0.2.1"),
            (&sender, "2001:db8:1::1"),
            (&receiver, "198.51.100.1"),
            (&receiver, "2001:db8:2::1"),
        ] {
            run(
                "ip",
                &[
                    "netns", "exec", namespace, "ping", "-c", "1", "-W", "2", target,
                ],
            );
        }
        let receiver_link = ifindex("mtur1");
        Self {
            sender,
            receiver,
            receiver_link,
        }
    }

    /// Send one small and one large DF datagram toward `destination`; return
    /// the sender report and the datagram lengths the receiver saw.
    fn probe(&self, family: &str, destination: &str) -> (String, String) {
        let mut receiver: Child = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.receiver,
                "python3",
                "-c",
                RECEIVER,
                family,
                &PROBE_PORT.to_string(),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = receiver.stdout.take().unwrap();
        let mut ready = [0_u8; 6];
        std::io::Read::read_exact(&mut stdout, &mut ready).unwrap();
        assert_eq!(&ready, b"ready\n");
        let sender = run(
            "ip",
            &[
                "netns",
                "exec",
                &self.sender,
                "python3",
                "-c",
                SENDER,
                family,
                destination,
                &SMALL_PAYLOAD.to_string(),
                &LARGE_PAYLOAD.to_string(),
                &PROBE_PORT.to_string(),
            ],
        );
        let mut received = String::new();
        std::io::Read::read_to_string(&mut stdout, &mut received).unwrap();
        assert!(receiver.wait().unwrap().success());
        (
            String::from_utf8(sender.stdout).unwrap().trim().to_owned(),
            received.trim().to_owned(),
        )
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        for namespace in [&self.sender, &self.receiver] {
            let _ = Command::new("ip")
                .args(["netns", "del", namespace])
                .status();
        }
    }
}

fn locked_route(destination: IpAddr, prefix_len: u8, oif: u32, mtu: u32) -> RouteRequest {
    RouteRequest {
        destination: IpPrefix::new(destination, prefix_len),
        oif_ifindex: oif,
        table: MAIN_TABLE,
        priority: Some(10),
        locked_mtu: Some(RouteMtu::new(mtu).unwrap()),
    }
}

#[tokio::test]
#[ignore = "requires root in an isolated network namespace, iproute2 and python3"]
async fn live_locked_route_mtu_makes_the_kernel_signal_oversized_packets_for_both_families() {
    let topology = Topology::provision();
    let backend = LinuxRouteSteeringBackend::new();
    let cases = [
        (
            "4",
            "198.51.100.9",
            locked_route(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                32,
                topology.receiver_link,
                IPV4_ROUTE_MTU,
            ),
            IPV4_ROUTE_MTU,
            "3",
            "4",
            "192.0.2.1",
            "90", // EMSGSIZE
        ),
        (
            "6",
            "2001:db8:2::9",
            locked_route(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 9)),
                128,
                topology.receiver_link,
                IPV6_ROUTE_MTU,
            ),
            IPV6_ROUTE_MTU,
            "2",
            "0",
            "2001:db8:1::1",
            "90",
        ),
    ];

    for (family, destination, route, mtu, icmp_type, icmp_code, router, emsgsize) in cases {
        // Control: through the 1500-byte link alone, every datagram (including
        // the resend) arrives and no ICMP error is raised.
        let (sender, received) = topology.probe(family, destination);
        assert!(sender.contains("\"icmp\": null"), "{family}: {sender}");
        assert_eq!(json_field(&sender, "resend"), "sent", "{family}: {sender}");
        assert_eq!(
            received,
            format!("[{SMALL_PAYLOAD}, {LARGE_PAYLOAD}, {LARGE_PAYLOAD}]"),
            "{family}"
        );

        assert_eq!(
            backend.converge_route(route.clone()).await.unwrap(),
            RouteConvergenceOutcome::Installed
        );
        assert_eq!(
            backend.converge_route(route.clone()).await.unwrap(),
            RouteConvergenceOutcome::ExactAlreadyPresent
        );
        let shown = ip(&[&format!("-{family}"), "route", "show", destination]);
        assert!(
            shown.contains(&format!("mtu lock {mtu}")),
            "{family}: kernel route lacks the locked MTU: {shown}"
        );
        for other in [None, RouteMtu::new(mtu + 8)] {
            let desired = RouteRequest {
                locked_mtu: other,
                ..route.clone()
            };
            let conflict = match backend.read_route(&desired).await.unwrap() {
                RouteReadback::Conflict(conflict) => conflict,
                unexpected => panic!("{family}: unexpected readback {unexpected:?}"),
            };
            assert_eq!(
                conflict.mismatch(),
                RouteMismatch {
                    output_interface: false,
                    table: false,
                    priority: false,
                    mtu: true,
                    kernel_semantics: false,
                }
            );
        }

        // The small datagram is forwarded; the large one is answered with one
        // well-formed ICMP error carrying the route MTU, from the router's
        // ingress address, quoting the invoking packet. The sender kernel
        // accepts it: its path MTU drops and the resend fails locally.
        let (sender, received) = topology.probe(family, destination);
        assert_eq!(json_field(&sender, "type"), icmp_type, "{family}: {sender}");
        assert_eq!(json_field(&sender, "code"), icmp_code, "{family}: {sender}");
        assert_eq!(
            json_field(&sender, "mtu"),
            mtu.to_string(),
            "{family}: {sender}"
        );
        assert_eq!(json_field(&sender, "source"), router, "{family}: {sender}");
        assert_eq!(
            json_field(&sender, "quoted_destination"),
            destination,
            "{family}: {sender}"
        );
        assert_eq!(
            json_field(&sender, "resend"),
            emsgsize,
            "{family}: {sender}"
        );
        assert_eq!(
            json_field(&sender, "path_mtu"),
            mtu.to_string(),
            "{family}: {sender}"
        );
        assert_eq!(received, format!("[{SMALL_PAYLOAD}]"), "{family}");

        backend.remove_converged_route(route.clone()).await.unwrap();
        assert_eq!(
            backend.read_route(&route).await.unwrap(),
            RouteReadback::Absent
        );

        // The owned-collection API installs, snapshots and removes the same
        // locked route exactly.
        let ip_family = if family == "4" {
            RouteSteeringIpFamily::Ipv4
        } else {
            RouteSteeringIpFamily::Ipv6
        };
        let scope = OwnedRouteRuleScope::new(
            ip_family,
            MAIN_TABLE,
            topology.receiver_link,
            Some(10),
            1000,
        )
        .unwrap();
        let owned = OwnedRouteRuleSet::new(scope, vec![route.clone()], Vec::new()).unwrap();
        let installed = backend.reconcile_owned_route_rules(owned).await.unwrap();
        assert_eq!(installed.installed_routes, 1, "{family}");
        assert_eq!(
            backend
                .snapshot_owned_route_rules(scope)
                .await
                .unwrap()
                .routes(),
            std::slice::from_ref(&route),
            "{family}"
        );
        let emptied = backend
            .reconcile_owned_route_rules(
                OwnedRouteRuleSet::new(scope, Vec::new(), Vec::new()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(emptied.removed_routes, 1, "{family}");
        assert_eq!(
            backend.read_route(&route).await.unwrap(),
            RouteReadback::Absent
        );
        // Let the next family's probe start from a quiet link.
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "OPC_ROUTE_LOCKED_MTU_ICMP_PROVEN: IPv4 Fragmentation Needed and IPv6 Packet Too Big"
    );
}
