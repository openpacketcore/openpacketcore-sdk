//! Privileged end-to-end proof of the eBPF tc GTP-U datapath.
//!
//! Topology (all created inside the fresh netns the CI harness provides):
//!
//! ```text
//!   [ue netns]            [main netns = ePDG]              [pgw netns]
//!   ue1 10.45.0.2 ─veth─ ue0 10.45.0.1   192.0.2.1 s2bu ─veth─ s2bup 192.0.2.10
//!                         (forwarding, tc clsact eBPF on s2bu)     │
//!                                                       wgp ─ authenticated ─ [auth netns]
//! ```
//!
//! - **Uplink**: a plain UDP datagram sent from the UE address to 8.8.8.8 is
//!   forwarded by the ePDG netns to `s2bu`, where the tc egress program must
//!   GTP-U-encapsulate it toward the PGW. The PGW netns receives it on
//!   UDP/2152 and the test asserts the exact TS 29.281 bytes: outer source,
//!   GTP-U flags/type/length, the PGW-assigned O-TEID, and the intact inner
//!   packet. This is precisely the direction the mainline `gtp` netdevice
//!   cannot serve.
//!   The production-boundary case sends ESP-in-UDP/4500 through one of two
//!   shared-request-ID inbound SAs; the dedicated SA's output mark must survive
//!   decrypt and forwarding and select the dedicated uplink TEID.
//! - **Downlink**: a G-PDU sent from the PGW on the ePDG's I-TEID must be
//!   decapsulated by the tc ingress program and *forwarded through the ePDG
//!   stack* (the position where XFRM policy applies) to the UE netns, which
//!   receives the inner UDP payload on an ordinary socket. Sequence-numbered
//!   G-PDUs (S flag) must decapsulate too; unknown TEIDs must be dropped;
//!   GTP-U echo requests must pass through to the local control plane.
//!   The production-boundary case installs disjoint default and dedicated
//!   XFRM OUT policies/SAs; a marked dedicated G-PDU must leave under the
//!   dedicated SPI, never the default SPI.
//!   Independently authored raw envelopes cover exact IPv4/UDP/GTP nesting,
//!   padding, checksums, and options. A WireGuard-authenticated packet supplies
//!   genuine `CHECKSUM_UNNECESSARY`; veth injections prove legal zero/nonzero
//!   NONE and rejection of zero/nonzero PARTIAL. The zero-field probe must
//!   restore the exact bytes. Malformed candidates never reach PDR/decap maps.
//! - **Identity/counters**: the attached tc program map-ID sets must equal the
//!   exact bpffs pins. The public diagnostic snapshot must report those live
//!   program/map IDs and correctly aggregate the exact per-CPU counter map.
//! - **Restore**: a second backend instance adopts the provisioned interface
//!   via `resolve_device`, re-installs the session idempotently, and the
//!   datapath keeps forwarding.

#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::env;
use std::fs;
use std::io::{self, IoSliceMut, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aya::maps::{Array, HashMap as BpfHashMap, Map, MapData, MapInfo, PerCpuArray};
use aya::programs::tc::{NlOptions, TcAttachOptions, TcHandle};
use aya::programs::{loaded_programs, SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader};
use nix::libc;
use nix::{setsockopt_impl, sockopt_impl};
use opc_gtpu_dataplane::{
    reassembly_commit_authorizes_graph, CreateGtpDeviceEndpointSetRequest, CreateGtpDeviceRequest,
    CurrentEbpfGraphDrainProof, CurrentEbpfGraphRecoveryOutcome, CurrentEbpfGraphRecoveryRefusal,
    CurrentEbpfGraphRecoveryRequest, CurrentEbpfGraphWriterProof, DrainedV2TeardownOutcome,
    DrainedV2TeardownRefusal, DrainedV2TeardownRequest, DscpCodepoint, EbpfGtpuDataplaneBackend,
    EbpfGtpuDataplaneBackendConfig, GtpBearerMark, GtpDevice, GtpPdpContext, GtpVersion,
    GtpuCapability, GtpuDataplaneBackend, GtpuDownlinkFragmentContract, GtpuError,
    GtpuLocalEndpointSet, GtpuOuterFragmentPolicy, GtpuReassemblyConsumer, GtpuReassemblyDrop,
    GtpuReassemblyGraphIdentity, GtpuReassemblyOutcome, GtpuReassemblyPdr, GtpuReassemblySelector,
    GtpuReassemblySocket, GtpuSessionAttachmentSelector, GtpuSessionDeviceId, GtpuSessionEntry,
    GtpuSessionGroup, GtpuSessionGroupId, GtpuSessionGroupReadback,
    GtpuSessionGroupReconcileOutcome, GtpuSessionGroupReconcileRequest,
    GtpuSessionGroupRemovalOutcome, GtpuSessionGroupSelector, GtpuSessionSelectorProvenance,
    GtpuSourcePortPolicy, GtpuUplinkChecksumOffloadContract, GtpuUplinkMtuPolicy,
    GtpuUplinkSourcePortPolicy, GtpuV2DrainProof, PdpContextIndeterminateReason,
    PdpContextInstallOutcome, PdpContextLocalTeidSelector, PdpContextReadback,
    PdpContextRemovalOutcome, PdpContextSelector, PdpContextSelectorOccupancy,
    PdpContextUplinkSelector, RemovePdpContextRequest, Teid,
};
use opc_gtpu_ebpf_common::{
    internet_checksum, ipv4_header_checksum, udp_ipv4_checksum, udp_ipv6_checksum,
    udp_ipv6_checksum_is_valid, DownlinkEndpointBinding, DownlinkPdr, GtpuEndpointAddress,
    MarkedBearerOwner, MarkedBearerOwnerPhase, MarkedDownlinkPdr, PdpContextCommit, UplinkFar,
    UplinkFarKey, COUNTER_DL_BINDING_FAMILY_MISMATCH, COUNTER_DL_BINDING_INGRESS_MISMATCH,
    COUNTER_DL_BINDING_INVALID, COUNTER_DL_BINDING_LOCAL_MISMATCH,
    COUNTER_DL_BINDING_PEER_MISMATCH, COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH, COUNTER_DL_DECAP,
    COUNTER_DL_DST_MISMATCH, COUNTER_DL_MALFORMED, COUNTER_DL_UNKNOWN_TEID, COUNTER_SLOTS,
    COUNTER_UL_ENCAP, COUNTER_UL_FAR_MISS, COUNTER_UL_MTU_REJECT, COUNTER_UL_PMTU_CORRUPT,
    COUNTER_UL_REDIRECT_RESOLVED, DOWNLINK_ENDPOINT_BINDING_VALUE_LEN, DOWNLINK_PDR_VALUE_LEN,
    ETH_HDR_LEN, GTPU_MANDATORY_HDR_LEN, IPV4_MIN_HDR_LEN, MAP_CONFIG, MAP_CONFIG_IPV6,
    MAP_COUNTERS, MAP_DOWNLINK_BINDING_COUNTERS, MAP_DOWNLINK_ENDPOINT_BINDING,
    MAP_DOWNLINK_MARK_PDR, MAP_DOWNLINK_PDR, MAP_MARKED_BEARER_OWNER, MAP_SESSION_DOWNLINK_INDEX,
    MAP_SESSION_GROUPS, MAP_SESSION_UPLINK_INDEX, MAP_UPLINK_DSCP, MAP_UPLINK_FAR,
    MAP_UPLINK_MARK_DSCP, MAP_UPLINK_MARK_FAR, MAP_UPLINK_MARK_SOURCE_PORT, MAP_UPLINK_PMTU,
    MAP_UPLINK_PMTU_COUNTERS, MAP_UPLINK_SOURCE_PORT, MARKED_BEARER_OWNER_VALUE_LEN,
    MARKED_DOWNLINK_PDR_VALUE_LEN, PROG_DOWNLINK, PROG_UPLINK, UDP_HDR_LEN,
    UPLINK_BEARER_SCHEMA_MARKER_VALUE, UPLINK_DSCP_SCHEMA_MARKER_KEY,
    UPLINK_DSCP_SCHEMA_MARKER_VALUE, UPLINK_DSCP_VALUE_LEN, UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE,
    UPLINK_FAR_VALUE_LEN, UPLINK_MARK_KEY_LEN, UPLINK_PMTU_SCHEMA_MARKER_VALUE,
    UPLINK_PMTU_VALUE_LEN, UPLINK_SOURCE_PORT_VALUE_LEN,
};
use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial,
    LifetimeConfig, LinuxXfrmBackend, PolicyParameters, SaParameters, UdpEncap, XfrmAction,
    XfrmBackend, XfrmDirection, XfrmId, XfrmLookupMark, XfrmMark, XfrmMode, XfrmRequestId,
    XfrmSelector, XfrmTemplate,
};

sockopt_impl!(
    UdpEspInUdp,
    SetOnly,
    nix::libc::SOL_UDP,
    nix::libc::UDP_ENCAP,
    i32
);

const EPDG_S2BU_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const EPDG_S2BU_ALT_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const PGW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const PGW_ALT_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
const EPDG_S2BU_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1);
const PGW_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0x10);
const PGW_ALT_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0x11);
const EPDG_SWU_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const UE_SWU_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const AUTH_GTP_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const UE_PAA: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);
const UE_PAA_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 2);
const REMOTE_HOST: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const REMOTE_HOST_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 8);
/// Outer destination with no route at all in the harness netns.
const UNROUTABLE_PGW_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 99);
/// The prefix covering [`UNROUTABLE_PGW_IP`], used to install a route whose
/// next hop can never be resolved.
const UNROUTABLE_PGW_PREFIX: &str = "203.0.113.0/24";
/// Unassigned address on the S2b-U link; nothing ever answers ARP for it.
const DEAD_NEXT_HOP: &str = "192.0.2.199";
/// Datagrams sent per redirect-outcome scenario.
const REDIRECT_PROBE_PACKETS: u32 = 3;
const LOCAL_TEID: u32 = 0x1000_0001;
const PEER_TEID: u32 = 0x2000_0001;
const MARK_A: u32 = 0x0001_0001;
const MARK_B: u32 = 0x0001_0002;
const UNKNOWN_MARK: u32 = 0x0001_FFFF;
const OUTER_SENTINEL_MARK: u32 = 0x55AA_00FF;
const LOCAL_TEID_A: u32 = 0x1000_0002;
const LOCAL_TEID_B: u32 = 0x1000_0003;
const PEER_TEID_A: u32 = 0x2000_0002;
const PEER_TEID_B: u32 = 0x2000_0003;
const GROUP_LOCAL_TEID_V4_INITIAL: u32 = 0x6100_0001;
const GROUP_PEER_TEID_V4_INITIAL: u32 = 0x6200_0001;
const GROUP_LOCAL_TEID_V6_INITIAL: u32 = 0x6100_0002;
const GROUP_PEER_TEID_V6_INITIAL: u32 = 0x6200_0002;
const GROUP_LOCAL_TEID_V4_CROSSED: u32 = 0x7100_0001;
const GROUP_PEER_TEID_V4_CROSSED: u32 = 0x7200_0001;
const GROUP_LOCAL_TEID_V6_CROSSED: u32 = 0x7100_0002;
const GROUP_PEER_TEID_V6_CROSSED: u32 = 0x7200_0002;
const INBOUND_SPI_DEFAULT: u32 = 0x3000_0000;
const INBOUND_SPI_A: u32 = 0x3000_0001;
const OUTBOUND_SPI_DEFAULT: u32 = 0x4000_0001;
const OUTBOUND_SPI_A: u32 = 0x4000_0002;
const XFRM_SESSION_REQUEST_ID: u32 = 0x0a00_0001;
const GTPU_PORT: u16 = 2152;
const NAT_T_PORT: u16 = 4500;
const XFRM_INNER_SOURCE_PORT: u16 = 5004;
const XFRM_INNER_DESTINATION_PORT: u16 = 53;
const XFRM_DOWNLINK_SOURCE_PORT: u16 = 53;
const XFRM_DOWNLINK_DESTINATION_PORT: u16 = 5005;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ESP: u8 = 50;
const FROZEN_V1_OBJECT: &[u8] = include_bytes!("../bpf/opc-gtpu-datapath-v1.bpf.o");
const FROZEN_V2_OBJECT: &[u8] = include_bytes!("../bpf/opc-gtpu-datapath-v2.bpf.o");
const CURRENT_OBJECT: &[u8] = include_bytes!("../bpf/opc-gtpu-datapath.bpf.o");
/// `GTPU_COUNTERS.max_entries` in the datapath object built immediately before
/// the uplink redirect counter was added (`6778bd53`).
const PRE_REDIRECT_COUNTER_SLOTS: u32 = 6;
/// A `GTPU_DOWNLINK_PDR` capacity no build of this datapath ever shipped,
/// standing in for a retained session map whose shape is not this build's.
const FOREIGN_DOWNLINK_PDR_ENTRIES: u32 = 1_024;
const SDK_TC_HANDLE: TcHandle = TcHandle::new(0, 1);
const LEGACY_V2_OWNER_VALUE_LEN: usize = 20;

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

/// Serializes the privileged tests in this process. The netns names, bpffs
/// pin root, and nft table are unique per provision, but the host-side veth
/// ends (`s2bu`, `ue0`) and their tc clsact attachments live in the shared
/// harness netns and cannot vary per test without renaming the interface
/// through the entire suite. Every privileged test holds this guard for its
/// whole body, so N tests on parallel threads cannot interleave provisioning
/// or datapath assertions. This scopes serialization to this binary's
/// privileged tests only; CI keeps its existing test-thread settings.
static PRIVILEGED_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Per-process provision sequence keeping every PID-derived harness name
/// unique across tests in the same process (the PID already keeps them
/// unique across processes sharing one harness netns).
static PRIVILEGED_TEST_SEQ: AtomicU32 = AtomicU32::new(0);

fn parse_link_address(value: &str) -> [u8; 6] {
    let mut address = [0_u8; 6];
    let mut components = value.trim().split(':');
    for octet in &mut address {
        let component = components.next().expect("link address octet");
        *octet = u8::from_str_radix(component, 16).expect("hexadecimal link address octet");
    }
    assert!(
        components.next().is_none(),
        "link address must have six octets"
    );
    address
}

fn main_link_address(interface: &str) -> [u8; 6] {
    let output = Command::new("ip")
        .args(["link", "show", "dev", interface])
        .output()
        .expect("read main-namespace link address");
    assert!(output.status.success(), "main link-address read failed");
    let value = std::str::from_utf8(&output.stdout).expect("UTF-8 main link output");
    let address = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|fields| (fields[0] == "link/ether").then_some(fields[1]))
        .expect("main link output must contain an Ethernet address");
    parse_link_address(address)
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

fn ipv6_host_discard_total() -> u64 {
    fs::read_to_string("/proc/net/snmp6")
        .expect("read IPv6 host counters")
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let value = fields.next()?.parse::<u64>().ok()?;
            matches!(
                name,
                "Ip6InHdrErrors" | "Ip6InDiscards" | "Ip6InUnknownProtos"
            )
            .then_some(value)
        })
        .fold(0_u64, u64::saturating_add)
}

fn command_stdout(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn {program}: {error}"));
    format!(
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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
    auth_ns: String,
    pgw_ns: String,
    ue_ns: String,
    pin_root: PathBuf,
    nft_table: String,
}

/// Executes one best-effort partial-provision cleanup command.
trait PartialProvisionCleanupExecutor {
    fn execute(&self, program: &str, args: &[&str]);
}

struct HostPartialProvisionCleanupExecutor;

impl PartialProvisionCleanupExecutor for HostPartialProvisionCleanupExecutor {
    fn execute(&self, program: &str, args: &[&str]) {
        let _ = Command::new(program).args(args).output();
    }
}

/// Best-effort cleanup for a test network whose provisioning panicked
/// partway. An nft table is owned immediately after its successful creation;
/// that table, recorded child namespaces, and root-netns veth ends are
/// removed while the guard is armed (deleting one veth end removes the pair),
/// so a retry or a later test in the same process does not inherit wedged
/// state. `TestNet::provision` disarms the guard once the complete topology
/// exists; steady-state teardown stays with `TestNet::drop`.
struct PartialProvisionCleanup<Executor: PartialProvisionCleanupExecutor> {
    netns: Vec<String>,
    root_links: Vec<&'static str>,
    nft_table: Option<String>,
    executor: Executor,
    armed: bool,
}

impl PartialProvisionCleanup<HostPartialProvisionCleanupExecutor> {
    fn new() -> Self {
        Self::with_executor(HostPartialProvisionCleanupExecutor)
    }
}

impl<Executor: PartialProvisionCleanupExecutor> PartialProvisionCleanup<Executor> {
    fn with_executor(executor: Executor) -> Self {
        Self {
            netns: Vec::new(),
            root_links: Vec::new(),
            nft_table: None,
            executor,
            armed: true,
        }
    }

    fn own_nft_table(&mut self, nft_table: &str) {
        self.nft_table = Some(nft_table.to_owned());
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<Executor: PartialProvisionCleanupExecutor> Drop for PartialProvisionCleanup<Executor> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(nft_table) = self.nft_table.as_deref() {
            self.executor
                .execute("nft", &["delete", "table", "inet", nft_table]);
        }
        for link in &self.root_links {
            self.executor.execute("ip", &["link", "del", link]);
        }
        for namespace in &self.netns {
            self.executor.execute("ip", &["netns", "del", namespace]);
        }
    }
}

fn provision_nft_rules<Executor, Run>(
    cleanup: &mut PartialProvisionCleanup<Executor>,
    nft_table: &str,
    mut run_command: Run,
) where
    Executor: PartialProvisionCleanupExecutor,
    Run: FnMut(&str, &[&str]),
{
    run_command("nft", &["add", "table", "inet", nft_table]);
    // From the first successful creation onward, every unwind path owns and
    // removes the table. No chain or later topology command may run between
    // creation and recording that ownership.
    cleanup.own_nft_table(nft_table);
    run_command(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            nft_table,
            "forward",
            "{ type filter hook forward priority -300; policy accept; }",
        ],
    );
    run_command(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            nft_table,
            "input",
            "{ type filter hook input priority -300; policy accept; }",
        ],
    );
}

#[derive(Clone)]
struct RecordingPartialProvisionCleanupExecutor {
    commands: RecordedCleanupCommands,
}

type RecordedCleanupCommands = Rc<RefCell<Vec<(String, Vec<String>)>>>;

impl PartialProvisionCleanupExecutor for RecordingPartialProvisionCleanupExecutor {
    fn execute(&self, program: &str, args: &[&str]) {
        self.commands.borrow_mut().push((
            program.to_owned(),
            args.iter().map(|argument| (*argument).to_owned()).collect(),
        ));
    }
}

#[test]
fn partial_provision_cleanup_executes_nft_delete_after_chain_failure() {
    let commands = Rc::new(RefCell::new(Vec::new()));
    let recorded_commands = Rc::clone(&commands);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let executor = RecordingPartialProvisionCleanupExecutor {
            commands: recorded_commands,
        };
        let mut cleanup = PartialProvisionCleanup::with_executor(executor);
        let mut attempt = 0_u8;
        provision_nft_rules(&mut cleanup, "opc_gtpu_failure_probe", |_, _| {
            attempt = attempt.saturating_add(1);
            if attempt == 2 {
                panic!("injected chain-creation failure");
            }
        });
        cleanup.disarm();
    }));

    assert!(
        result.is_err(),
        "chain-creation failure must unwind provision"
    );
    assert_eq!(
        commands.borrow().as_slice(),
        &[(
            "nft".to_owned(),
            vec![
                "delete".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                "opc_gtpu_failure_probe".to_owned(),
            ],
        )]
    );
}

impl TestNet {
    fn provision() -> Self {
        let pid = std::process::id();
        let sequence = PRIVILEGED_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let auth_ns = format!("opc-auth-{pid}-{sequence}");
        let pgw_ns = format!("opc-pgw-{pid}-{sequence}");
        let ue_ns = format!("opc-ue-{pid}-{sequence}");
        let pin_root = PathBuf::from(format!("/sys/fs/bpf/opc-gtpu-test-{pid}-{sequence}"));
        let nft_table = format!("opc_gtpu_{pid}_{sequence}");
        let mut cleanup = PartialProvisionCleanup::new();

        run("ip", &["netns", "add", &auth_ns]);
        cleanup.netns.push(auth_ns.clone());
        run("ip", &["netns", "add", &pgw_ns]);
        cleanup.netns.push(pgw_ns.clone());
        run("ip", &["netns", "add", &ue_ns]);
        cleanup.netns.push(ue_ns.clone());

        run(
            "ip",
            &[
                "link", "add", "s2bu", "type", "veth", "peer", "name", "s2bup",
            ],
        );
        cleanup.root_links.push("s2bu");
        run("ip", &["link", "set", "s2bup", "netns", &pgw_ns]);
        run(
            "ip",
            &["link", "add", "ue0", "type", "veth", "peer", "name", "ue1"],
        );
        cleanup.root_links.push("ue0");
        run("ip", &["link", "set", "ue1", "netns", &ue_ns]);

        run("ip", &["addr", "add", "192.0.2.1/24", "dev", "s2bu"]);
        run("ip", &["addr", "add", "192.0.2.2/32", "dev", "s2bu"]);
        run(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8:2::1/64",
                "dev",
                "s2bu",
                "nodad",
            ],
        );
        run("ip", &["link", "set", "s2bu", "up"]);
        run("ethtool", &["-K", "s2bu", "tx", "off"]);
        run("ip", &["addr", "add", "10.45.0.1/24", "dev", "ue0"]);
        run("ip", &["addr", "add", "198.18.0.1/24", "dev", "ue0"]);
        run(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8:45::1/64",
                "dev",
                "ue0",
                "nodad",
            ],
        );
        run("ip", &["link", "set", "ue0", "up"]);
        run("ethtool", &["-K", "ue0", "tx", "off"]);
        run("tc", &["qdisc", "add", "dev", "ue0", "clsact"]);
        for (priority, source_port, mark) in [
            (10_u16, 5001_u16, MARK_A),
            (11, 5002, MARK_B),
            (12, 5003, UNKNOWN_MARK),
        ] {
            let priority = priority.to_string();
            let source_port = source_port.to_string();
            let mark = format!("0x{mark:08x}");
            run(
                "tc",
                &[
                    "filter",
                    "add",
                    "dev",
                    "ue0",
                    "ingress",
                    "pref",
                    &priority,
                    "protocol",
                    "ip",
                    "flower",
                    "ip_proto",
                    "udp",
                    "src_port",
                    &source_port,
                    "action",
                    "skbedit",
                    "mark",
                    &mark,
                    "continue",
                ],
            );
        }
        run("ip", &["route", "add", "8.8.8.8/32", "via", "192.0.2.10"]);
        run(
            "ip",
            &[
                "-6",
                "route",
                "add",
                "2001:db8:ffff::8/128",
                "via",
                "2001:db8:2::10",
            ],
        );

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
        run(
            "ip",
            &[
                "-n",
                &pgw_ns,
                "-6",
                "addr",
                "add",
                "2001:db8:2::10/64",
                "dev",
                "s2bup",
                "nodad",
            ],
        );
        run("ip", &["-n", &pgw_ns, "link", "set", "s2bup", "up"]);
        run(
            "ip",
            &[
                "-n",
                &pgw_ns,
                "addr",
                "add",
                "192.0.2.11/32",
                "dev",
                "s2bup",
            ],
        );
        run(
            "ip",
            &[
                "-n",
                &pgw_ns,
                "-6",
                "addr",
                "add",
                "2001:db8:2::11/128",
                "dev",
                "s2bup",
                "nodad",
            ],
        );
        // A veth peer can otherwise present locally generated UDP at tc
        // ingress as CHECKSUM_PARTIAL, whose on-frame checksum bytes are not
        // yet verifiable. Emit completed wire-equivalent checksums so this
        // test exercises the datapath's software-validation path.
        run(
            "ip",
            &[
                "netns", "exec", &pgw_ns, "ethtool", "-K", "s2bup", "tx", "off",
            ],
        );
        run("ip", &["-n", &pgw_ns, "link", "set", "lo", "up"]);
        run(
            "ip",
            &["-n", &pgw_ns, "addr", "add", "8.8.8.8/32", "dev", "lo"],
        );
        run(
            "ip",
            &[
                "-n",
                &pgw_ns,
                "-6",
                "addr",
                "add",
                "2001:db8:ffff::8/128",
                "dev",
                "lo",
                "nodad",
            ],
        );

        run(
            "ip",
            &["-n", &ue_ns, "addr", "add", "10.45.0.2/24", "dev", "ue1"],
        );
        run(
            "ip",
            &["-n", &ue_ns, "addr", "add", "198.18.0.2/24", "dev", "ue1"],
        );
        run(
            "ip",
            &[
                "-n",
                &ue_ns,
                "-6",
                "addr",
                "add",
                "2001:db8:45::2/64",
                "dev",
                "ue1",
                "nodad",
            ],
        );
        run("ip", &["-n", &ue_ns, "link", "set", "ue1", "up"]);
        run(
            "ip",
            &["netns", "exec", &ue_ns, "ethtool", "-K", "ue1", "tx", "off"],
        );
        run("ip", &["-n", &ue_ns, "link", "set", "lo", "up"]);
        run(
            "ip",
            &["-n", &ue_ns, "route", "add", "default", "via", "10.45.0.1"],
        );
        run(
            "ip",
            &[
                "-n",
                &ue_ns,
                "-6",
                "route",
                "add",
                "default",
                "via",
                "2001:db8:45::1",
            ],
        );

        fs::write("/proc/sys/net/ipv4/ip_forward", "1").expect("enable forwarding");
        fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").expect("enable IPv6 forwarding");
        for interface in ["all", "default", "s2bu", "ue0"] {
            let path = format!("/proc/sys/net/ipv4/conf/{interface}/rp_filter");
            fs::write(&path, "0").expect("relax rp_filter");
        }

        provision_nft_rules(&mut cleanup, &nft_table, run);

        let provisioned = Self {
            auth_ns,
            pgw_ns,
            ue_ns,
            pin_root,
            nft_table,
        };
        cleanup.disarm();
        provisioned
    }

    fn require_forward_mark(&self, mark: u32) {
        run(
            "nft",
            &["flush", "chain", "inet", &self.nft_table, "forward"],
        );
        let mark = format!("0x{mark:08x}");
        run(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                &self.nft_table,
                "forward",
                "meta",
                "mark",
                "!=",
                &mark,
                "counter",
                "drop",
            ],
        );
    }

    fn allow_all_forward_marks(&self) {
        run(
            "nft",
            &["flush", "chain", "inet", &self.nft_table, "forward"],
        );
    }

    fn require_input_mark(&self, mark: u32) {
        run("nft", &["flush", "chain", "inet", &self.nft_table, "input"]);
        let mark = format!("0x{mark:08x}");
        run(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                &self.nft_table,
                "input",
                "meta",
                "mark",
                "!=",
                &mark,
                "counter",
                "drop",
            ],
        );
    }

    fn allow_all_input_marks(&self) {
        run("nft", &["flush", "chain", "inet", &self.nft_table, "input"]);
    }

    fn install_outer_mark_injector(&self) {
        let mark = format!("0x{OUTER_SENTINEL_MARK:08x}");
        run(
            "tc",
            &[
                "filter", "add", "dev", "s2bu", "ingress", "pref", "10", "protocol", "ip",
                "flower", "ip_proto", "udp", "dst_port", "2152", "action", "skbedit", "mark",
                &mark, "continue",
            ],
        );
    }

    fn set_pgw_tx_checksum_offload(&self, enabled: bool) {
        let state = if enabled { "on" } else { "off" };
        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.pgw_ns,
                "ethtool",
                "-K",
                "s2bup",
                "tx",
                state,
            ],
        );
    }

    fn pgw_link_address(&self, interface: &str) -> [u8; 6] {
        let output = Command::new("ip")
            .args(["-n", &self.pgw_ns, "link", "show", "dev", interface])
            .output()
            .expect("read PGW link address");
        assert!(output.status.success(), "PGW link-address read failed");
        let value = std::str::from_utf8(&output.stdout).expect("UTF-8 PGW link output");
        let address = value
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .find_map(|fields| (fields[0] == "link/ether").then_some(fields[1]))
            .expect("PGW link output must contain an Ethernet address");
        parse_link_address(address)
    }
}

impl Drop for TestNet {
    fn drop(&mut self) {
        // Best-effort teardown; the CI netns is discarded anyway.
        let _ = Command::new("ip").args(["link", "del", "s2bu"]).output();
        let _ = Command::new("ip").args(["link", "del", "ue0"]).output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.auth_ns])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.pgw_ns])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.ue_ns])
            .output();
        let _ = fs::remove_dir_all(&self.pin_root);
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &self.nft_table])
            .output();
    }
}

fn session_context(link_ifindex: u32) -> GtpPdpContext {
    GtpPdpContext {
        local_teid: Teid::new(LOCAL_TEID).expect("nonzero"),
        peer_teid: Teid::new(PEER_TEID).expect("nonzero"),
        ms_address: IpAddr::V4(UE_PAA),
        peer_address: IpAddr::V4(PGW_IP),
        link_ifindex,
        downlink_source_port_policy: GtpuSourcePortPolicy::Exact(GTPU_PORT),
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
        uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
    }
}

fn grouped_device_id() -> GtpuSessionDeviceId {
    GtpuSessionDeviceId::new([0x34; 16]).expect("nonzero grouped device ID")
}

fn grouped_group_id() -> GtpuSessionGroupId {
    GtpuSessionGroupId::new([0x44; 16]).expect("nonzero grouped session ID")
}

fn grouped_endpoints() -> GtpuLocalEndpointSet {
    GtpuLocalEndpointSet::new(IpAddr::V4(EPDG_S2BU_IP), Some(IpAddr::V6(EPDG_S2BU_IPV6)))
        .expect("canonical dual-stack endpoint authority")
}

fn grouped_device_request(policy: GtpuUplinkMtuPolicy) -> CreateGtpDeviceEndpointSetRequest {
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.uplink_mtu_policy = Some(policy);
    CreateGtpDeviceEndpointSetRequest::new(request, grouped_device_id(), grouped_endpoints())
        .expect("canonical grouped device request")
}

/// A second attachment authority for the same grouped device -- same device
/// ID, and therefore the same pin namespace, but a different local endpoint
/// set. This is the grouped equivalent of a second process bound to a
/// different local address: the pin directory is keyed by the device ID, so a
/// conflicting *endpoint set* is the shape an ownership conflict actually
/// takes here.
fn conflicting_grouped_device_request(
    policy: GtpuUplinkMtuPolicy,
) -> CreateGtpDeviceEndpointSetRequest {
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.uplink_mtu_policy = Some(policy);
    CreateGtpDeviceEndpointSetRequest::new(
        request,
        grouped_device_id(),
        GtpuLocalEndpointSet::new(
            IpAddr::V4(EPDG_S2BU_ALT_IP),
            Some(IpAddr::V6(EPDG_S2BU_IPV6)),
        )
        .expect("canonical conflicting dual-stack endpoint authority"),
    )
    .expect("canonical conflicting grouped device request")
}

/// The pin directory the backend derives from a grouped device ID.
fn grouped_pin_dir(pin_root: &std::path::Path) -> PathBuf {
    let mut namespace = String::from("v6-");
    for byte in grouped_device_id().to_bytes() {
        namespace.push_str(&format!("{byte:02x}"));
    }
    pin_root.join(namespace)
}

fn grouped_entry(
    link_ifindex: u32,
    inner: IpAddr,
    local_outer: IpAddr,
    peer_outer: IpAddr,
    local_teid: u32,
    peer_teid: u32,
) -> GtpuSessionEntry {
    GtpuSessionEntry::new(
        GtpPdpContext {
            local_teid: Teid::new(local_teid).expect("nonzero grouped local TEID"),
            peer_teid: Teid::new(peer_teid).expect("nonzero grouped peer TEID"),
            ms_address: inner,
            peer_address: peer_outer,
            link_ifindex,
            downlink_source_port_policy: GtpuSourcePortPolicy::Exact(GTPU_PORT),
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        },
        local_outer,
    )
    .expect("canonical grouped entry")
}

fn initial_grouped_session(link_ifindex: u32) -> GtpuSessionGroup {
    GtpuSessionGroup::new(
        grouped_group_id(),
        grouped_device_id(),
        vec![
            grouped_entry(
                link_ifindex,
                IpAddr::V4(UE_PAA),
                IpAddr::V4(EPDG_S2BU_IP),
                IpAddr::V4(PGW_IP),
                GROUP_LOCAL_TEID_V4_INITIAL,
                GROUP_PEER_TEID_V4_INITIAL,
            ),
            grouped_entry(
                link_ifindex,
                IpAddr::V6(UE_PAA_IPV6),
                IpAddr::V6(EPDG_S2BU_IPV6),
                IpAddr::V6(PGW_IPV6),
                GROUP_LOCAL_TEID_V6_INITIAL,
                GROUP_PEER_TEID_V6_INITIAL,
            ),
        ],
    )
    .expect("canonical initial dual-stack group")
}

fn crossed_grouped_session(link_ifindex: u32) -> GtpuSessionGroup {
    GtpuSessionGroup::new(
        grouped_group_id(),
        grouped_device_id(),
        vec![
            grouped_entry(
                link_ifindex,
                IpAddr::V4(UE_PAA),
                IpAddr::V6(EPDG_S2BU_IPV6),
                IpAddr::V6(PGW_ALT_IPV6),
                GROUP_LOCAL_TEID_V4_CROSSED,
                GROUP_PEER_TEID_V4_CROSSED,
            ),
            grouped_entry(
                link_ifindex,
                IpAddr::V6(UE_PAA_IPV6),
                IpAddr::V4(EPDG_S2BU_IP),
                IpAddr::V4(PGW_ALT_IP),
                GROUP_LOCAL_TEID_V6_CROSSED,
                GROUP_PEER_TEID_V6_CROSSED,
            ),
        ],
    )
    .expect("canonical crossed dual-stack group")
}

fn fresh_grouped_reconcile(group: GtpuSessionGroup) -> GtpuSessionGroupReconcileRequest {
    GtpuSessionGroupReconcileRequest::new(group, GtpuSessionSelectorProvenance::Fresh)
        .expect("fresh grouped selector provenance")
}

fn grouped_attachment(device: &GtpDevice) -> GtpuSessionAttachmentSelector {
    GtpuSessionAttachmentSelector::new(grouped_device_id(), device.clone(), grouped_endpoints())
        .expect("exact grouped attachment selector")
}

fn marked_session_context(link_ifindex: u32) -> GtpPdpContext {
    let mut context = session_context(link_ifindex);
    context.egress_dscp = Some(DscpCodepoint::new(46).expect("valid EF codepoint"));
    context
}

fn dedicated_session_context(
    link_ifindex: u32,
    mark: u32,
    local_teid: u32,
    peer_teid: u32,
) -> GtpPdpContext {
    let mut context = session_context(link_ifindex);
    context.local_teid = Teid::new(local_teid).expect("nonzero local TEID");
    context.peer_teid = Teid::new(peer_teid).expect("nonzero peer TEID");
    context.bearer_mark = Some(GtpBearerMark::new(mark).expect("nonzero bearer mark"));
    context
}

fn xfrm_ip(address: Ipv4Addr) -> IpAddress {
    IpAddress::Ipv4(address.octets())
}

fn xfrm_session_request_id() -> XfrmRequestId {
    XfrmRequestId::new(XFRM_SESSION_REQUEST_ID).expect("nonzero session request ID")
}

fn marked_inner_selector() -> XfrmSelector {
    let mut selector = XfrmSelector::new(xfrm_ip(UE_PAA), xfrm_ip(REMOTE_HOST), IPPROTO_UDP);
    selector.source_port = XFRM_INNER_SOURCE_PORT;
    selector.destination_port = XFRM_INNER_DESTINATION_PORT;
    selector
}

fn downlink_selector() -> XfrmSelector {
    let mut selector = XfrmSelector::new(xfrm_ip(REMOTE_HOST), xfrm_ip(UE_PAA), IPPROTO_UDP);
    selector.source_port = XFRM_DOWNLINK_SOURCE_PORT;
    selector.destination_port = XFRM_DOWNLINK_DESTINATION_PORT;
    selector
}

fn inbound_sa_parameters(spi: u32, output_mark: XfrmMark) -> SaParameters {
    SaParameters {
        selector: marked_inner_selector(),
        id: XfrmId {
            destination: xfrm_ip(EPDG_SWU_IP),
            spi,
            protocol: IPPROTO_ESP,
        },
        source_address: xfrm_ip(UE_SWU_IP),
        request_id: Some(xfrm_session_request_id()),
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
        encap: Some(UdpEncap::esp_in_udp(NAT_T_PORT, NAT_T_PORT)),
        mark: None,
        output_mark: Some(output_mark),
        if_id: None,
        egress_dscp: None,
    }
}

fn outbound_sa_parameters() -> SaParameters {
    let mut parameters = inbound_sa_parameters(
        INBOUND_SPI_A,
        XfrmMark {
            value: MARK_A,
            mask: u32::MAX,
        },
    );
    parameters.id.destination = xfrm_ip(EPDG_SWU_IP);
    parameters.source_address = xfrm_ip(UE_SWU_IP);
    parameters.output_mark = None;
    parameters
}

fn downlink_sa_parameters(spi: u32, mark: Option<XfrmLookupMark>) -> SaParameters {
    SaParameters {
        selector: downlink_selector(),
        id: XfrmId {
            destination: xfrm_ip(UE_SWU_IP),
            spi,
            protocol: IPPROTO_ESP,
        },
        source_address: xfrm_ip(EPDG_SWU_IP),
        request_id: Some(xfrm_session_request_id()),
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
        encap: Some(UdpEncap::esp_in_udp(NAT_T_PORT, NAT_T_PORT)),
        mark,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    }
}

fn downlink_policy_parameters(spi: u32, mark: XfrmLookupMark) -> PolicyParameters {
    PolicyParameters {
        selector: downlink_selector(),
        direction: XfrmDirection::Out,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: XfrmId {
                destination: xfrm_ip(UE_SWU_IP),
                spi,
                protocol: IPPROTO_ESP,
            },
            source_address: xfrm_ip(EPDG_SWU_IP),
            request_id: Some(xfrm_session_request_id()),
            mode: XfrmMode::Tunnel,
        }],
        mark: Some(mark),
        if_id: None,
    }
}

fn inbound_policy_parameters(direction: XfrmDirection) -> PolicyParameters {
    PolicyParameters {
        selector: marked_inner_selector(),
        direction,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: XfrmId {
                destination: xfrm_ip(EPDG_SWU_IP),
                spi: 0,
                protocol: IPPROTO_ESP,
            },
            source_address: xfrm_ip(UE_SWU_IP),
            request_id: Some(xfrm_session_request_id()),
            mode: XfrmMode::Tunnel,
        }],
        mark: None,
        if_id: None,
    }
}

async fn install_real_marked_inbound_xfrm(
    ue_namespace: &str,
) -> Result<(), opc_ipsec_xfrm::XfrmError> {
    let backend = LinuxXfrmBackend::new();
    for (spi, output_mark) in [
        (
            INBOUND_SPI_DEFAULT,
            XfrmMark {
                value: 0,
                mask: u32::MAX,
            },
        ),
        (
            INBOUND_SPI_A,
            XfrmMark {
                value: MARK_A,
                mask: u32::MAX,
            },
        ),
    ] {
        backend
            .install_sa(InstallSaRequest {
                parameters: inbound_sa_parameters(spi, output_mark),
            })
            .await?;
    }
    for direction in [XfrmDirection::In, XfrmDirection::Forward] {
        backend
            .install_policy(InstallPolicyRequest {
                parameters: inbound_policy_parameters(direction),
            })
            .await?;
    }

    let ue_namespace = ue_namespace.to_owned();
    in_netns(&ue_namespace, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build UE XFRM runtime");
        runtime.block_on(async {
            let peer_backend = LinuxXfrmBackend::new();
            peer_backend
                .install_sa(InstallSaRequest {
                    parameters: outbound_sa_parameters(),
                })
                .await
                .expect("install UE outbound SA");
            peer_backend
                .install_policy(InstallPolicyRequest {
                    parameters: PolicyParameters {
                        direction: XfrmDirection::Out,
                        ..inbound_policy_parameters(XfrmDirection::Out)
                    },
                })
                .await
                .expect("install UE outbound policy");
        });
    });
    Ok(())
}

async fn install_real_marked_outbound_xfrm() -> Result<(), opc_ipsec_xfrm::XfrmError> {
    let backend = LinuxXfrmBackend::new();
    let default_mark = XfrmLookupMark::full(0);
    let dedicated_mark = XfrmLookupMark::full(MARK_A);
    for (spi, sa_mark, policy_mark) in [
        (OUTBOUND_SPI_DEFAULT, None, default_mark),
        (OUTBOUND_SPI_A, Some(dedicated_mark), dedicated_mark),
    ] {
        backend
            .install_sa(InstallSaRequest {
                parameters: downlink_sa_parameters(spi, sa_mark),
            })
            .await?;
        backend
            .install_policy(InstallPolicyRequest {
                parameters: downlink_policy_parameters(spi, policy_mark),
            })
            .await?;
    }
    Ok(())
}

fn nat_t_socket(address: Ipv4Addr) -> UdpSocket {
    use nix::sys::socket::setsockopt;

    let socket = UdpSocket::bind((address, NAT_T_PORT)).expect("bind NAT-T socket");
    setsockopt(
        &socket,
        UdpEspInUdp,
        &i32::from(opc_ipsec_xfrm::UDP_ENCAP_ESPINUDP),
    )
    .expect("enable ESP-in-UDP decapsulation");
    socket
}

fn packet_capture_socket(namespace: &str) -> OwnedFd {
    use nix::sys::socket::{
        setsockopt, socket, sockopt, AddressFamily, SockFlag, SockProtocol, SockType,
    };
    use nix::sys::time::TimeVal;

    let namespace = namespace.to_owned();
    in_netns(&namespace, || {
        let socket = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::EthAll,
        )
        .expect("open UE AF_PACKET capture socket");
        setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::new(3, 0))
            .expect("set packet-capture timeout");
        socket
    })
}

fn capture_nat_t_esp_spi(capture: &OwnedFd) -> u32 {
    use nix::sys::socket::{recv, MsgFlags};

    let mut frame = vec![0_u8; 65_536];
    loop {
        let length = recv(capture.as_raw_fd(), &mut frame, MsgFlags::empty())
            .expect("receive outbound ESP-in-UDP frame before timeout");
        if length < 14 + 20 + 8 + 4 || frame[12..14] != [0x08, 0x00] {
            continue;
        }
        let ip = &frame[14..length];
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        if ip[0] >> 4 != 4
            || ihl < 20
            || ip.len() < ihl + 12
            || ip[9] != IPPROTO_UDP
            || ip[12..16] != EPDG_SWU_IP.octets()
            || ip[16..20] != UE_SWU_IP.octets()
        {
            continue;
        }
        let udp = &ip[ihl..];
        if u16::from_be_bytes([udp[0], udp[1]]) != NAT_T_PORT
            || u16::from_be_bytes([udp[2], udp[3]]) != NAT_T_PORT
        {
            continue;
        }
        return u32::from_be_bytes(udp[8..12].try_into().expect("ESP SPI bytes"));
    }
}

fn capture_grouped_outer_ipv6(
    capture: &OwnedFd,
    expected_source: Ipv6Addr,
    expected_destination: Ipv6Addr,
    expected_teid: u32,
    expected_inner: &[u8],
) {
    use nix::sys::socket::{recv, MsgFlags};

    let expected_gpdu = build_gpdu(expected_teid, None, expected_inner);
    let mut frame = vec![0_u8; 65_536];
    loop {
        let length = recv(capture.as_raw_fd(), &mut frame, MsgFlags::empty())
            .expect("receive grouped outer IPv6 frame before timeout");
        if length < ETH_HDR_LEN + 40 + UDP_HDR_LEN + GTPU_MANDATORY_HDR_LEN
            || frame[12..14] != 0x86dd_u16.to_be_bytes()
        {
            continue;
        }
        let ip = ETH_HDR_LEN;
        if frame[ip] >> 4 != 6
            || frame[ip + 6] != IPPROTO_UDP
            || frame[ip + 8..ip + 24] != expected_source.octets()
            || frame[ip + 24..ip + 40] != expected_destination.octets()
        {
            continue;
        }
        let payload_length = usize::from(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]));
        let ip_end = ip + 40 + payload_length;
        if ip_end > length {
            continue;
        }
        let udp = ip + 40;
        let udp_length = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
        if frame[udp..udp + 2] != GTPU_PORT.to_be_bytes()
            || frame[udp + 2..udp + 4] != GTPU_PORT.to_be_bytes()
            || udp + udp_length != ip_end
            || frame[udp + UDP_HDR_LEN..ip_end] != expected_gpdu
        {
            continue;
        }
        let checksum = u16::from_be_bytes([frame[udp + 6], frame[udp + 7]]);
        assert_ne!(checksum, 0, "outer IPv6 UDP checksum is mandatory");
        let mut checksum_input = frame[udp..ip_end].to_vec();
        checksum_input[6..8].fill(0);
        let expected_checksum = udp_ipv6_checksum(
            expected_source.octets(),
            expected_destination.octets(),
            &checksum_input,
        )
        .expect("captured bounded IPv6 UDP datagram");
        assert_eq!(
            checksum, expected_checksum,
            "captured outer IPv6 UDP checksum must equal independent recomputation"
        );
        assert!(
            udp_ipv6_checksum_is_valid(
                expected_source.octets(),
                expected_destination.octets(),
                &frame[udp..ip_end],
            ),
            "captured outer IPv6 UDP checksum must independently validate"
        );
        return;
    }
}

fn capture_inner_udp_packet(
    capture: &OwnedFd,
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    expected_payload: &[u8],
) -> Vec<u8> {
    use nix::sys::socket::{recv, MsgFlags};

    let mut frame = vec![0_u8; 65_536];
    loop {
        let length = recv(capture.as_raw_fd(), &mut frame, MsgFlags::empty())
            .expect("receive inner packet before timeout");
        if length < ETH_HDR_LEN + IPV4_MIN_HDR_LEN + UDP_HDR_LEN {
            continue;
        }
        let ip = ETH_HDR_LEN;
        let (ip_end, udp) = match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination))
                if frame[12..14] == 0x0800_u16.to_be_bytes()
                    && frame[ip] >> 4 == 4
                    && frame[ip + 12..ip + 16] == source.octets()
                    && frame[ip + 16..ip + 20] == destination.octets() =>
            {
                let ihl = usize::from(frame[ip] & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]));
                (ip + total, ip + ihl)
            }
            (IpAddr::V6(source), IpAddr::V6(destination))
                if frame[12..14] == 0x86dd_u16.to_be_bytes()
                    && frame[ip] >> 4 == 6
                    && frame[ip + 6] == IPPROTO_UDP
                    && frame[ip + 8..ip + 24] == source.octets()
                    && frame[ip + 24..ip + 40] == destination.octets() =>
            {
                let payload = usize::from(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]));
                (ip + 40 + payload, ip + 40)
            }
            _ => continue,
        };
        if ip_end > length
            || udp + UDP_HDR_LEN > ip_end
            || frame[udp..udp + 2] != source_port.to_be_bytes()
            || frame[udp + 2..udp + 4] != destination_port.to_be_bytes()
            || &frame[udp + UDP_HDR_LEN..ip_end] != expected_payload
        {
            continue;
        }
        let mut packet = frame[ip..ip_end].to_vec();
        match packet[0] >> 4 {
            4 => {
                assert!(packet[8] > 0, "captured IPv4 packet has usable TTL");
                packet[8] -= 1;
                let header_len = usize::from(packet[0] & 0x0f) * 4;
                packet[10..12].fill(0);
                let checksum = internet_checksum(&packet[..header_len]);
                packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            6 => {
                assert!(packet[7] > 0, "captured IPv6 packet has usable hop limit");
                packet[7] -= 1;
            }
            _ => unreachable!("capture filter accepts only IPv4 or IPv6"),
        }
        return packet;
    }
}

fn assert_exact_gpdu(payload: &[u8], expected_teid: u32, expected_inner: &[u8]) {
    assert_eq!(
        payload,
        build_gpdu(expected_teid, None, expected_inner),
        "received G-PDU must preserve the selected TEID and exact inner packet"
    );
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

/// Build an inner IPv6/UDP packet with the mandatory UDP checksum
/// independently materialized before it reaches the datapath.
fn build_inner_udp_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = UDP_HDR_LEN + payload.len();
    let mut packet = vec![0_u8; 40 + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("bounded synthetic inner IPv6 payload")
            .to_be_bytes(),
    );
    packet[6] = IPPROTO_UDP;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet[40..42].copy_from_slice(&sport.to_be_bytes());
    packet[42..44].copy_from_slice(&dport.to_be_bytes());
    packet[44..46].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("bounded synthetic inner UDP length")
            .to_be_bytes(),
    );
    packet[48..].copy_from_slice(payload);
    let checksum = udp_ipv6_checksum(src.octets(), dst.octets(), &packet[40..])
        .expect("bounded synthetic inner IPv6 UDP checksum");
    packet[46..48].copy_from_slice(&checksum.to_be_bytes());
    assert!(
        udp_ipv6_checksum_is_valid(src.octets(), dst.octets(), &packet[40..]),
        "synthetic inner IPv6 UDP checksum must validate independently"
    );
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

#[derive(Clone, Copy)]
enum RawChecksumMetadata {
    Unverified,
    Partial,
}

impl RawChecksumMetadata {
    const fn argument(self) -> &'static str {
        match self {
            Self::Unverified => "none",
            Self::Partial => "partial",
        }
    }
}

/// Inject one complete Ethernet frame through AF_PACKET with explicit virtio
/// checksum metadata. The frame is delivered over the PGW veth to the real tc
/// ingress hook. Payload bytes and endpoint addresses never enter arguments,
/// stdout, stderr, or failure text.
fn send_raw_gtpu_frame(
    namespace: &str,
    interface: &str,
    frame: &[u8],
    metadata: RawChecksumMetadata,
) {
    const PYTHON_SENDER: &str = r#"
import socket
import struct
import sys

SOL_PACKET = 263
PACKET_VNET_HDR = 15
VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

mode = sys.argv[1]
interface = sys.argv[2]
frame = sys.stdin.buffer.read()
flags = {
    "none": 0,
    "partial": VIRTIO_NET_HDR_F_NEEDS_CSUM,
}[mode]
checksum_start = 14 + ((frame[14] & 0x0f) * 4) if mode == "partial" else 0
checksum_offset = 6 if mode == "partial" else 0
vnet = struct.pack("=BBHHHH", flags, 0, 0, 0, checksum_start, checksum_offset)

sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sender.setsockopt(SOL_PACKET, PACKET_VNET_HDR, struct.pack("=I", 1))
sender.bind((interface, 0))
if sender.send(vnet + frame) != len(vnet) + len(frame):
    raise SystemExit(1)
"#;

    let mut child = Command::new("ip")
        .args([
            "netns",
            "exec",
            namespace,
            "python3",
            "-c",
            PYTHON_SENDER,
            metadata.argument(),
            interface,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn redaction-safe raw frame sender");
    let mut stdin = child.stdin.take().expect("raw frame sender stdin");
    stdin
        .write_all(frame)
        .expect("write synthetic frame to raw sender");
    drop(stdin);
    assert!(
        child.wait().expect("wait for raw frame sender").success(),
        "raw frame sender failed"
    );
}

/// Inject several synthetic frames through one redaction-safe AF_PACKET
/// sender. Keeping one socket/process lets the pressure proof exceed a small
/// fragment-memory threshold before the timeout can evict early queues.
fn send_raw_gtpu_frames(namespace: &str, interface: &str, frames: &[Vec<u8>]) {
    const PYTHON_SENDER: &str = r#"
import socket
import struct
import sys

SOL_PACKET = 263
PACKET_VNET_HDR = 15

interface = sys.argv[1]
stream = sys.stdin.buffer
sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sender.setsockopt(SOL_PACKET, PACKET_VNET_HDR, struct.pack("=I", 1))
sender.bind((interface, 0))
vnet = struct.pack("=BBHHHH", 0, 0, 0, 0, 0, 0)
while True:
    encoded_length = stream.read(4)
    if not encoded_length:
        break
    if len(encoded_length) != 4:
        raise SystemExit(1)
    length = struct.unpack("!I", encoded_length)[0]
    frame = stream.read(length)
    if len(frame) != length or sender.send(vnet + frame) != len(vnet) + length:
        raise SystemExit(1)
"#;

    let mut child = Command::new("ip")
        .args([
            "netns",
            "exec",
            namespace,
            "python3",
            "-c",
            PYTHON_SENDER,
            interface,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn redaction-safe raw frame batch sender");
    let mut stdin = child.stdin.take().expect("raw frame batch sender stdin");
    for frame in frames {
        let length = u32::try_from(frame.len()).expect("synthetic frame length fits u32");
        stdin
            .write_all(&length.to_be_bytes())
            .and_then(|()| stdin.write_all(frame))
            .expect("write synthetic frame to raw batch sender");
    }
    drop(stdin);
    assert!(
        child
            .wait()
            .expect("wait for raw frame batch sender")
            .success(),
        "raw frame batch sender failed"
    );
}

struct EphemeralWireGuardPrivateKey(Vec<u8>);

impl AsRef<[u8]> for EphemeralWireGuardPrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for EphemeralWireGuardPrivateKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn wireguard_keypair() -> (EphemeralWireGuardPrivateKey, String) {
    let private = Command::new("wg")
        .arg("genkey")
        .output()
        .expect("generate ephemeral WireGuard private key");
    assert!(
        private.status.success(),
        "ephemeral WireGuard key generation failed"
    );
    let private = EphemeralWireGuardPrivateKey(private.stdout);
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("derive ephemeral WireGuard public key");
    child
        .stdin
        .take()
        .expect("WireGuard pubkey stdin")
        .write_all(private.as_ref())
        .expect("write ephemeral private key to pubkey derivation");
    let public = child
        .wait_with_output()
        .expect("wait for WireGuard public-key derivation");
    assert!(
        public.status.success(),
        "ephemeral WireGuard public-key derivation failed"
    );
    (
        private,
        String::from_utf8(public.stdout)
            .expect("WireGuard public key must be UTF-8")
            .trim()
            .to_owned(),
    )
}

fn configure_wireguard_peer(
    namespace: &str,
    interface: &str,
    private_key: &[u8],
    listen_port: &str,
    peer_public_key: &str,
    allowed_ips: &str,
    endpoint: &str,
) {
    let mut child = Command::new("ip")
        .args([
            "netns",
            "exec",
            namespace,
            "wg",
            "set",
            interface,
            "private-key",
            "/dev/stdin",
            "listen-port",
            listen_port,
            "peer",
            peer_public_key,
            "allowed-ips",
            allowed_ips,
            "endpoint",
            endpoint,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("configure ephemeral WireGuard peer");
    child
        .stdin
        .take()
        .expect("WireGuard configuration stdin")
        .write_all(private_key)
        .expect("write ephemeral WireGuard private key");
    assert!(
        child
            .wait()
            .expect("wait for WireGuard peer configuration")
            .success(),
        "ephemeral WireGuard peer configuration failed"
    );
}

/// Configure an authenticated L3 path that decrypts in the PGW namespace and
/// forwards the verified inner IPv4 packet over `s2bup` to the production tc
/// ingress hook. WireGuard marks successfully authenticated inner packets as
/// CHECKSUM_UNNECESSARY for every encapsulation level.
fn configure_checksum_metadata_path(net: &TestNet) {
    run(
        "ip",
        &[
            "link", "add", "wgauth", "type", "veth", "peer", "name", "wgpgw",
        ],
    );
    run("ip", &["link", "set", "wgauth", "netns", &net.auth_ns]);
    run("ip", &["link", "set", "wgpgw", "netns", &net.pgw_ns]);
    run(
        "ip",
        &[
            "-n",
            &net.auth_ns,
            "addr",
            "add",
            "203.0.113.2/24",
            "dev",
            "wgauth",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &net.pgw_ns,
            "addr",
            "add",
            "203.0.113.1/24",
            "dev",
            "wgpgw",
        ],
    );
    for (namespace, interface) in [(&net.auth_ns, "wgauth"), (&net.pgw_ns, "wgpgw")] {
        run("ip", &["-n", namespace, "link", "set", interface, "up"]);
    }
    run("ip", &["-n", &net.auth_ns, "link", "set", "lo", "up"]);
    run(
        "ip",
        &[
            "-n",
            &net.auth_ns,
            "link",
            "add",
            "wg0",
            "type",
            "wireguard",
        ],
    );
    run(
        "ip",
        &["-n", &net.pgw_ns, "link", "add", "wgp", "type", "wireguard"],
    );
    run(
        "ip",
        &[
            "-n",
            &net.auth_ns,
            "addr",
            "add",
            "198.51.100.10/32",
            "dev",
            "wg0",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &net.pgw_ns,
            "addr",
            "add",
            "10.255.0.1/32",
            "dev",
            "wgp",
        ],
    );

    let (auth_private, auth_public) = wireguard_keypair();
    let (pgw_private, pgw_public) = wireguard_keypair();
    configure_wireguard_peer(
        &net.auth_ns,
        "wg0",
        auth_private.as_ref(),
        "51821",
        &pgw_public,
        "192.0.2.1/32",
        "203.0.113.1:51820",
    );
    configure_wireguard_peer(
        &net.pgw_ns,
        "wgp",
        pgw_private.as_ref(),
        "51820",
        &auth_public,
        "198.51.100.10/32",
        "203.0.113.2:51821",
    );
    run("ip", &["-n", &net.auth_ns, "link", "set", "wg0", "up"]);
    run("ip", &["-n", &net.pgw_ns, "link", "set", "wgp", "up"]);
    run(
        "ip",
        &[
            "-n",
            &net.auth_ns,
            "route",
            "add",
            "192.0.2.1/32",
            "dev",
            "wg0",
        ],
    );
    for setting in [
        "net.ipv4.ip_forward=1",
        "net.ipv4.conf.all.rp_filter=0",
        "net.ipv4.conf.default.rp_filter=0",
        "net.ipv4.conf.wgp.rp_filter=0",
        "net.ipv4.conf.s2bup.rp_filter=0",
    ] {
        run(
            "ip",
            &["netns", "exec", &net.pgw_ns, "sysctl", "-q", "-w", setting],
        );
    }
}

/// Send one complete IPv4 packet through the authenticated metadata path.
/// Packet bytes remain on stdin and are never included in diagnostics.
fn send_wireguard_ipv4_packet(namespace: &str, packet: &[u8]) {
    const PYTHON_SENDER: &str = r#"
import socket
import sys

packet = sys.stdin.buffer.read()
destination = socket.inet_ntoa(packet[16:20])
sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
if sender.sendto(packet, (destination, 0)) != len(packet):
    raise SystemExit(1)
"#;

    let mut child = Command::new("ip")
        .args(["netns", "exec", namespace, "python3", "-c", PYTHON_SENDER])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn authenticated raw IPv4 sender");
    child
        .stdin
        .take()
        .expect("authenticated raw IPv4 sender stdin")
        .write_all(packet)
        .expect("write synthetic IPv4 packet to authenticated sender");
    assert!(
        child
            .wait()
            .expect("wait for authenticated raw IPv4 sender")
            .success(),
        "authenticated raw IPv4 sender failed"
    );
}

/// Send one fully materialized IPv6 packet through the UE namespace. The
/// explicit header and UDP checksum make this the positive path for the
/// backend's `MaterializedOnly` outer-IPv6 checksum capability.
fn send_raw_ipv6_packet(namespace: &str, packet: &[u8]) {
    const PYTHON_SENDER: &str = r#"
import socket
import sys

packet = sys.stdin.buffer.read()
destination = socket.inet_ntop(socket.AF_INET6, packet[24:40])
sender = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
# Linux UAPI IPV6_HDRINCL; Python does not expose this constant on every
# distribution even though the kernel option is stable.
sender.setsockopt(socket.IPPROTO_IPV6, 36, 1)
if sender.sendto(packet, (destination, 0, 0, 0)) != len(packet):
    raise SystemExit(1)
"#;

    let mut child = Command::new("ip")
        .args(["netns", "exec", namespace, "python3", "-c", PYTHON_SENDER])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn materialized raw IPv6 sender");
    child
        .stdin
        .take()
        .expect("materialized raw IPv6 sender stdin")
        .write_all(packet)
        .expect("write synthetic IPv6 packet to materialized sender");
    assert!(
        child
            .wait()
            .expect("wait for materialized raw IPv6 sender")
            .success(),
        "materialized raw IPv6 sender failed"
    );
}

fn forwarded_ipv6_packet(mut packet: Vec<u8>) -> Vec<u8> {
    assert_eq!(packet[0] >> 4, 6);
    assert!(packet[7] > 0, "synthetic IPv6 packet has usable hop limit");
    packet[7] -= 1;
    packet
}

fn build_outer_gtpu_frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    ip_options: &[u8],
    gtpu: &[u8],
    udp_checksum_present: bool,
    padding_len: usize,
) -> Vec<u8> {
    assert_eq!(ip_options.len() % 4, 0);
    assert!(ip_options.len() <= 40);
    let ip_header_len = IPV4_MIN_HDR_LEN + ip_options.len();
    let udp_len = UDP_HDR_LEN + gtpu.len();
    let ip_total_len = ip_header_len + udp_len;
    let ip_end = ETH_HDR_LEN + ip_total_len;
    let mut frame = vec![0xa5_u8; ip_end + padding_len];
    frame[..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

    let ip = ETH_HDR_LEN;
    frame[ip] = 0x40 | u8::try_from(ip_header_len / 4).expect("bounded IHL");
    frame[ip + 2..ip + 4].copy_from_slice(
        &u16::try_from(ip_total_len)
            .expect("bounded outer IPv4 length")
            .to_be_bytes(),
    );
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = IPPROTO_UDP;
    frame[ip + 10..ip + 12].fill(0);
    frame[ip + 12..ip + 16].copy_from_slice(&PGW_IP.octets());
    frame[ip + 16..ip + 20].copy_from_slice(&EPDG_S2BU_IP.octets());
    frame[ip + IPV4_MIN_HDR_LEN..ip + ip_header_len].copy_from_slice(ip_options);

    let udp = ip + ip_header_len;
    frame[udp..udp + 2].copy_from_slice(&GTPU_PORT.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&GTPU_PORT.to_be_bytes());
    frame[udp + 4..udp + 6].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("bounded outer UDP length")
            .to_be_bytes(),
    );
    frame[udp + 6..udp + 8].fill(0);
    frame[udp + UDP_HDR_LEN..ip_end].copy_from_slice(gtpu);

    let ip_checksum = internet_checksum(&frame[ip..udp]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());
    if udp_checksum_present {
        let udp_checksum =
            udp_ipv4_checksum(PGW_IP.octets(), EPDG_S2BU_IP.octets(), &frame[udp..ip_end])
                .expect("bounded outer UDP checksum input");
        frame[udp + 6..udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    }
    frame
}

#[derive(Clone, Copy)]
enum OuterIpv6Extension {
    None,
    AtomicFragment { identification: u32 },
    DiscardRequiredDestinationOption,
}

fn outer_ipv6_extension(extension: OuterIpv6Extension) -> (u8, Vec<u8>) {
    match extension {
        OuterIpv6Extension::None => (IPPROTO_UDP, Vec::new()),
        OuterIpv6Extension::AtomicFragment { identification } => {
            let mut header = vec![0_u8; 8];
            header[0] = IPPROTO_UDP;
            header[4..8].copy_from_slice(&identification.to_be_bytes());
            (44, header)
        }
        OuterIpv6Extension::DiscardRequiredDestinationOption => {
            // Action bits 01 require an IPv6 node to discard this unknown
            // option. It is intentionally outside the SDK's bounded GTP-U
            // parser, which must return host-pass without moving SDK counters.
            (60, vec![IPPROTO_UDP, 0, 0x40, 0, 1, 2, 0, 0])
        }
    }
}

fn build_outer_ipv6_gtpu_frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    gtpu: &[u8],
    extension: OuterIpv6Extension,
) -> Vec<u8> {
    let (next_header, extension) = outer_ipv6_extension(extension);
    let udp_len = UDP_HDR_LEN + gtpu.len();
    let payload_len = extension.len() + udp_len;
    let ip_end = ETH_HDR_LEN + 40 + payload_len;
    let mut frame = vec![0_u8; ip_end];
    frame[..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());

    let ip = ETH_HDR_LEN;
    frame[ip] = 0x60;
    frame[ip + 4..ip + 6].copy_from_slice(
        &u16::try_from(payload_len)
            .expect("bounded synthetic outer IPv6 payload")
            .to_be_bytes(),
    );
    frame[ip + 6] = next_header;
    frame[ip + 7] = 64;
    frame[ip + 8..ip + 24].copy_from_slice(&source.octets());
    frame[ip + 24..ip + 40].copy_from_slice(&destination.octets());
    frame[ip + 40..ip + 40 + extension.len()].copy_from_slice(&extension);

    let udp = ip + 40 + extension.len();
    frame[udp..udp + 2].copy_from_slice(&GTPU_PORT.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&GTPU_PORT.to_be_bytes());
    frame[udp + 4..udp + 6].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("bounded synthetic outer IPv6 UDP length")
            .to_be_bytes(),
    );
    frame[udp + UDP_HDR_LEN..ip_end].copy_from_slice(gtpu);
    let checksum = udp_ipv6_checksum(source.octets(), destination.octets(), &frame[udp..ip_end])
        .expect("bounded synthetic outer IPv6 UDP checksum");
    frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
    assert_ne!(checksum, 0, "outer IPv6 UDP checksum is mandatory");
    assert!(
        udp_ipv6_checksum_is_valid(source.octets(), destination.octets(), &frame[udp..ip_end],),
        "synthetic outer IPv6 UDP checksum must validate independently"
    );
    frame
}

fn build_outer_ipv6_fragment_pair(
    complete: &[u8],
    first_fragmentable_len: usize,
    identification: u32,
) -> (Vec<u8>, Vec<u8>) {
    let ip = ETH_HDR_LEN;
    assert!(complete.len() >= ip + 40 + UDP_HDR_LEN);
    assert_eq!(complete[12..14], 0x86dd_u16.to_be_bytes());
    assert_eq!(complete[ip + 6], IPPROTO_UDP);
    assert!(first_fragmentable_len > 0 && first_fragmentable_len.is_multiple_of(8));
    let complete_payload_len =
        usize::from(u16::from_be_bytes([complete[ip + 4], complete[ip + 5]]));
    let fragmentable = &complete[ip + 40..ip + 40 + complete_payload_len];
    assert!(first_fragmentable_len < fragmentable.len());

    let build = |offset: usize, more: bool, payload: &[u8]| {
        let mut frame = vec![0_u8; ETH_HDR_LEN + 40 + 8 + payload.len()];
        frame[..ETH_HDR_LEN].copy_from_slice(&complete[..ETH_HDR_LEN]);
        frame[ip..ip + 40].copy_from_slice(&complete[ip..ip + 40]);
        frame[ip + 4..ip + 6].copy_from_slice(
            &u16::try_from(8 + payload.len())
                .expect("bounded synthetic IPv6 fragment payload")
                .to_be_bytes(),
        );
        frame[ip + 6] = 44;
        let fragment = ip + 40;
        frame[fragment] = IPPROTO_UDP;
        let offset_units = u16::try_from(offset / 8).expect("bounded fragment offset");
        let offset_and_flags = (offset_units << 3) | u16::from(more);
        frame[fragment + 2..fragment + 4].copy_from_slice(&offset_and_flags.to_be_bytes());
        frame[fragment + 4..fragment + 8].copy_from_slice(&identification.to_be_bytes());
        frame[fragment + 8..].copy_from_slice(payload);
        frame
    };

    (
        build(0, true, &fragmentable[..first_fragmentable_len]),
        build(
            first_fragmentable_len,
            false,
            &fragmentable[first_fragmentable_len..],
        ),
    )
}

fn outer_ipv6_udp_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < ETH_HDR_LEN + 40 || frame[12..14] != 0x86dd_u16.to_be_bytes() {
        return None;
    }
    let mut next_header = frame[ETH_HDR_LEN + 6];
    let mut cursor = ETH_HDR_LEN + 40;
    for _ in 0..4 {
        match next_header {
            IPPROTO_UDP => return Some(cursor),
            44 => {
                next_header = *frame.get(cursor)?;
                cursor = cursor.checked_add(8)?;
            }
            0 | 43 | 60 => {
                next_header = *frame.get(cursor)?;
                let length = usize::from(*frame.get(cursor + 1)?)
                    .checked_add(1)?
                    .checked_mul(8)?;
                cursor = cursor.checked_add(length)?;
            }
            _ => return None,
        }
        if cursor > frame.len() {
            return None;
        }
    }
    None
}

fn outer_udp_offset(frame: &[u8]) -> usize {
    ETH_HDR_LEN + usize::from(frame[ETH_HDR_LEN] & 0x0f) * 4
}

fn outer_gtpu_offset(frame: &[u8]) -> usize {
    outer_udp_offset(frame) + UDP_HDR_LEN
}

fn refresh_outer_ipv4_checksum(frame: &mut [u8]) {
    let ip = ETH_HDR_LEN;
    let ip_header_len = usize::from(frame[ip] & 0x0f) * 4;
    frame[ip + 10..ip + 12].fill(0);
    let checksum = internet_checksum(&frame[ip..ip + ip_header_len]);
    frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
}

fn refresh_outer_udp_checksum(frame: &mut [u8]) {
    let ip = ETH_HDR_LEN;
    let udp = outer_udp_offset(frame);
    let udp_len = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
    frame[udp + 6..udp + 8].fill(0);
    let checksum = udp_ipv4_checksum(
        frame[ip + 12..ip + 16]
            .try_into()
            .expect("outer source IPv4 bytes"),
        frame[ip + 16..ip + 20]
            .try_into()
            .expect("outer destination IPv4 bytes"),
        &frame[udp..udp + udp_len],
    )
    .expect("bounded outer UDP checksum input");
    frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
}

fn set_partial_outer_udp_checksum(frame: &mut [u8]) {
    let udp = outer_udp_offset(frame);
    let udp_len = [frame[udp + 4], frame[udp + 5]];
    let mut pseudo_header = [0_u8; 12];
    pseudo_header[..4].copy_from_slice(&PGW_IP.octets());
    pseudo_header[4..8].copy_from_slice(&EPDG_S2BU_IP.octets());
    pseudo_header[9] = IPPROTO_UDP;
    pseudo_header[10..12].copy_from_slice(&udp_len);
    let seed = internet_checksum(&pseudo_header);
    frame[udp + 6..udp + 8].copy_from_slice(&seed.to_be_bytes());
}

fn build_extension_gpdu(teid: u32, inner: &[u8]) -> Vec<u8> {
    let post_header_len = 8 + inner.len();
    let mut gpdu = Vec::with_capacity(GTPU_MANDATORY_HDR_LEN + post_header_len);
    gpdu.extend_from_slice(&[
        0x34,
        0xff,
        (post_header_len >> 8) as u8,
        post_header_len as u8,
    ]);
    gpdu.extend_from_slice(&teid.to_be_bytes());
    gpdu.extend_from_slice(&[0, 7, 0, 0x85]);
    gpdu.extend_from_slice(&[1, 0x11, 0x22, 0]);
    gpdu.extend_from_slice(inner);
    gpdu
}

fn receive_raw_downlink(socket: &UdpSocket, expected: &[u8]) {
    let mut buffer = [0_u8; 2048];
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set raw downlink receive timeout");
    let (length, source) = socket
        .recv_from(&mut buffer)
        .expect("validated raw GTP-U frame must decapsulate");
    assert_eq!(&buffer[..length], expected);
    assert_eq!(source, SocketAddr::from((REMOTE_HOST, 53)));
}

fn receive_grouped_downlink(
    socket: &UdpSocket,
    expected_source: SocketAddr,
    expected_payload: &[u8],
) {
    let mut buffer = [0_u8; 2048];
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set grouped downlink receive timeout");
    let (length, source) = socket
        .recv_from(&mut buffer)
        .expect("authorized grouped G-PDU must decapsulate");
    assert_eq!(source, expected_source);
    assert_eq!(&buffer[..length], expected_payload);
}

fn receive_grouped_uplink(
    socket: &UdpSocket,
    expected_source: SocketAddr,
    expected_teid: u32,
    expected_inner: &[u8],
) {
    let mut buffer = vec![0_u8; 65_536];
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set grouped uplink receive timeout");
    let (length, source) = socket.recv_from(&mut buffer).unwrap_or_else(|error| {
        panic!("authorized grouped uplink TEID {expected_teid:#010x} must encapsulate: {error}")
    });
    assert_eq!(source, expected_source);
    assert_exact_gpdu(&buffer[..length], expected_teid, expected_inner);
}

async fn exercise_outer_envelope_validation(
    net: &TestNet,
    backend: &EbpfGtpuDataplaneBackend,
    device: &GtpDevice,
    ue_socket: &UdpSocket,
) {
    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");
    let build_frame = |payload: &[u8], options: &[u8], checksum: bool, padding: usize| {
        let inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, payload);
        let gpdu = build_gpdu(LOCAL_TEID, None, &inner);
        build_outer_gtpu_frame(
            destination_mac,
            source_mac,
            options,
            &gpdu,
            checksum,
            padding,
        )
    };

    let valid_cases = [
        (
            build_frame(b"z0", &[], false, 0),
            RawChecksumMetadata::Unverified,
            b"z0".as_slice(),
        ),
        (
            build_frame(b"o", &[], true, 0),
            RawChecksumMetadata::Unverified,
            b"o".as_slice(),
        ),
        (
            build_frame(b"ev", &[], true, 0),
            RawChecksumMetadata::Unverified,
            b"ev".as_slice(),
        ),
        (
            build_frame(b"options-padding", &[1, 1, 0, 0], true, 23),
            RawChecksumMetadata::Unverified,
            b"options-padding".as_slice(),
        ),
    ];
    let valid_before = backend
        .datapath_snapshot(device)
        .await
        .expect("snapshot before valid outer-envelope cases")
        .counters
        .downlink_decapsulated;
    for (frame, metadata, expected) in &valid_cases {
        drain_datagrams(ue_socket);
        send_raw_gtpu_frame(&net.pgw_ns, "s2bup", frame, *metadata);
        receive_raw_downlink(ue_socket, expected);
    }

    let extension_payload = b"extension-boundary";
    let extension_inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, extension_payload);
    let extension_gpdu = build_extension_gpdu(LOCAL_TEID, &extension_inner);
    let extension_frame =
        build_outer_gtpu_frame(destination_mac, source_mac, &[], &extension_gpdu, true, 0);
    drain_datagrams(ue_socket);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &extension_frame,
        RawChecksumMetadata::Unverified,
    );
    receive_raw_downlink(ue_socket, extension_payload);

    let valid_after = backend
        .datapath_snapshot(device)
        .await
        .expect("snapshot after valid outer-envelope cases")
        .counters
        .downlink_decapsulated;
    assert_eq!(
        valid_after,
        valid_before + u64::try_from(valid_cases.len() + 1).expect("bounded valid case count"),
        "every exact zero/nonzero/options/padding/extension envelope must decapsulate once",
    );

    // WireGuard authenticates the complete inner packet before publishing
    // CHECKSUM_UNNECESSARY for every encapsulation level. The PGW namespace
    // forwards that authenticated packet over the existing veth to this exact
    // tc ingress hook. A deliberately non-matching UDP checksum proves that
    // only the positive kernel query bypasses byte verification. Structural
    // boundaries remain mandatory and are still rejected before PDR lookup.
    configure_checksum_metadata_path(net);
    // This checksum-evidence path is injected by the authenticated helper
    // namespace rather than the PGW namespace. Bind the PDR to that exact
    // source for this phase; provenance remains mandatory even when the
    // kernel supplies CHECKSUM_UNNECESSARY evidence.
    let authenticated_binding = DownlinkEndpointBinding::new(
        GtpuEndpointAddress::Ipv4(AUTH_GTP_IP.octets()),
        GtpuEndpointAddress::Ipv4(EPDG_S2BU_IP.octets()),
        device.ifindex,
        GtpuSourcePortPolicy::Exact(GTPU_PORT),
    )
    .expect("canonical authenticated-source binding")
    .encode();
    let pin_dir = net.pin_root.join("s2bu");
    let pgw_binding =
        replace_pinned_default_binding_transaction(&pin_dir, LOCAL_TEID, authenticated_binding);
    let verified_payload = b"kernel-verified";
    let mut verified_frame = build_frame(verified_payload, &[], true, 0);
    verified_frame[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16].copy_from_slice(&AUTH_GTP_IP.octets());
    refresh_outer_ipv4_checksum(&mut verified_frame);
    refresh_outer_udp_checksum(&mut verified_frame);
    let verified_udp = outer_udp_offset(&verified_frame);
    verified_frame[verified_udp + 6] ^= 0x5a;
    let verified_before = backend
        .datapath_snapshot(device)
        .await
        .expect("snapshot before CHECKSUM_UNNECESSARY cases")
        .counters;
    drain_datagrams(ue_socket);
    send_wireguard_ipv4_packet(&net.auth_ns, &verified_frame[ETH_HDR_LEN..]);
    receive_raw_downlink(ue_socket, verified_payload);

    let verified_zero_payload = b"kernel-verified-zero";
    let mut verified_zero_frame = build_frame(verified_zero_payload, &[], false, 0);
    verified_zero_frame[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16].copy_from_slice(&AUTH_GTP_IP.octets());
    refresh_outer_ipv4_checksum(&mut verified_zero_frame);
    drain_datagrams(ue_socket);
    send_wireguard_ipv4_packet(&net.auth_ns, &verified_zero_frame[ETH_HDR_LEN..]);
    receive_raw_downlink(ue_socket, verified_zero_payload);

    let mut verified_bad_boundary = verified_frame;
    let verified_gtpu = outer_gtpu_offset(&verified_bad_boundary);
    let verified_gtpu_len = u16::from_be_bytes([
        verified_bad_boundary[verified_gtpu + 2],
        verified_bad_boundary[verified_gtpu + 3],
    ]);
    verified_bad_boundary[verified_gtpu + 2..verified_gtpu + 4]
        .copy_from_slice(&(verified_gtpu_len + 1).to_be_bytes());
    drain_datagrams(ue_socket);
    send_wireguard_ipv4_packet(&net.auth_ns, &verified_bad_boundary[ETH_HDR_LEN..]);
    expect_no_datagram(ue_socket);
    let verified_after = backend
        .datapath_snapshot(device)
        .await
        .expect("snapshot after CHECKSUM_UNNECESSARY cases")
        .counters;
    assert_eq!(
        verified_after.downlink_decapsulated,
        verified_before.downlink_decapsulated + 2,
        "kernel-verified nonzero and exactly restored zero checksums must decapsulate once each",
    );
    assert_eq!(
        verified_after.downlink_malformed,
        verified_before.downlink_malformed + 1,
        "kernel-verified checksum metadata must not bypass structural validation",
    );
    assert_eq!(
        verified_after.downlink_unknown_teid, verified_before.downlink_unknown_teid,
        "kernel-verified malformed structure must not reach PDR lookup",
    );
    replace_pinned_default_binding_transaction(&pin_dir, LOCAL_TEID, pgw_binding);

    let invalid_base = build_frame(b"invalid-envelope", &[], true, 0);
    let ip = ETH_HDR_LEN;
    let udp = outer_udp_offset(&invalid_base);
    let gtpu = outer_gtpu_offset(&invalid_base);
    let ip_total = u16::from_be_bytes([invalid_base[ip + 2], invalid_base[ip + 3]]);
    let udp_len = u16::from_be_bytes([invalid_base[udp + 4], invalid_base[udp + 5]]);
    let gtpu_len = u16::from_be_bytes([invalid_base[gtpu + 2], invalid_base[gtpu + 3]]);
    let mut invalid_cases = Vec::new();

    let mut bad_ip_checksum = invalid_base.clone();
    bad_ip_checksum[ip + 8] ^= 1;
    invalid_cases.push((bad_ip_checksum, RawChecksumMetadata::Unverified));

    let mut too_small_ip = invalid_base.clone();
    too_small_ip[ip + 2..ip + 4].copy_from_slice(&35_u16.to_be_bytes());
    refresh_outer_ipv4_checksum(&mut too_small_ip);
    invalid_cases.push((too_small_ip, RawChecksumMetadata::Unverified));

    let mut short_ip = invalid_base.clone();
    short_ip[ip + 2..ip + 4].copy_from_slice(&(ip_total - 1).to_be_bytes());
    refresh_outer_ipv4_checksum(&mut short_ip);
    invalid_cases.push((short_ip, RawChecksumMetadata::Unverified));

    let mut long_ip = invalid_base.clone();
    long_ip[ip + 2..ip + 4].copy_from_slice(&(ip_total + 1).to_be_bytes());
    refresh_outer_ipv4_checksum(&mut long_ip);
    invalid_cases.push((long_ip, RawChecksumMetadata::Unverified));

    let mut tiny_udp = invalid_base.clone();
    tiny_udp[udp + 4..udp + 6].copy_from_slice(&7_u16.to_be_bytes());
    invalid_cases.push((tiny_udp, RawChecksumMetadata::Unverified));

    for declared in [udp_len - 1, udp_len + 1] {
        let mut inconsistent_udp = invalid_base.clone();
        inconsistent_udp[udp + 4..udp + 6].copy_from_slice(&declared.to_be_bytes());
        invalid_cases.push((inconsistent_udp, RawChecksumMetadata::Unverified));
    }

    for payload in [&b"x"[..], &b"yz"[..]] {
        let mut bad_udp_checksum = build_frame(payload, &[], true, 0);
        let checksum = outer_udp_offset(&bad_udp_checksum) + 6;
        bad_udp_checksum[checksum] ^= 1;
        invalid_cases.push((bad_udp_checksum, RawChecksumMetadata::Unverified));
    }

    for declared in [gtpu_len - 1, gtpu_len + 1] {
        let mut inconsistent_gtpu = invalid_base.clone();
        inconsistent_gtpu[gtpu + 2..gtpu + 4].copy_from_slice(&declared.to_be_bytes());
        refresh_outer_udp_checksum(&mut inconsistent_gtpu);
        invalid_cases.push((inconsistent_gtpu, RawChecksumMetadata::Unverified));
    }

    let trailing_inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"gtpu-trailing");
    let mut trailing_gpdu = build_gpdu(LOCAL_TEID, None, &trailing_inner);
    trailing_gpdu.push(0xee);
    invalid_cases.push((
        build_outer_gtpu_frame(destination_mac, source_mac, &[], &trailing_gpdu, true, 0),
        RawChecksumMetadata::Unverified,
    ));

    let mut truncated_optional = vec![0x32, 0xff, 0, 3];
    truncated_optional.extend_from_slice(&LOCAL_TEID.to_be_bytes());
    truncated_optional.extend_from_slice(&[1, 2, 3]);
    invalid_cases.push((
        build_outer_gtpu_frame(
            destination_mac,
            source_mac,
            &[],
            &truncated_optional,
            true,
            0,
        ),
        RawChecksumMetadata::Unverified,
    ));

    for extension_prefix in [[0_u8, 0, 0, 0], [10, 0, 0, 0]] {
        let inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"bad-extension");
        let post_header_len = 4 + extension_prefix.len() + inner.len();
        let mut invalid_extension = vec![
            0x34,
            0xff,
            (post_header_len >> 8) as u8,
            post_header_len as u8,
        ];
        invalid_extension.extend_from_slice(&LOCAL_TEID.to_be_bytes());
        invalid_extension.extend_from_slice(&[0, 1, 0, 0x85]);
        invalid_extension.extend_from_slice(&extension_prefix);
        invalid_extension.extend_from_slice(&inner);
        invalid_cases.push((
            build_outer_gtpu_frame(
                destination_mac,
                source_mac,
                &[],
                &invalid_extension,
                true,
                0,
            ),
            RawChecksumMetadata::Unverified,
        ));
    }

    let truncated_inner_gpdu = build_gpdu(LOCAL_TEID, None, &[0x45; IPV4_MIN_HDR_LEN - 1]);
    invalid_cases.push((
        build_outer_gtpu_frame(
            destination_mac,
            source_mac,
            &[],
            &truncated_inner_gpdu,
            true,
            0,
        ),
        RawChecksumMetadata::Unverified,
    ));

    let mut unverified_partial_bytes = build_frame(b"unverified-partial", &[], true, 0);
    set_partial_outer_udp_checksum(&mut unverified_partial_bytes);
    invalid_cases.push((unverified_partial_bytes, RawChecksumMetadata::Unverified));

    let partial_inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"partial-metadata");
    let partial_gpdu = build_gpdu(0xdead_beef, None, &partial_inner);
    let mut partial_frame =
        build_outer_gtpu_frame(destination_mac, source_mac, &[], &partial_gpdu, false, 0);
    set_partial_outer_udp_checksum(&mut partial_frame);

    // Even checksum bytes that already satisfy the final wire equation are
    // not authoritative while the skb still advertises CHECKSUM_PARTIAL. This
    // proves the datapath detects the metadata state instead of relying on a
    // coincidental software-checksum failure.
    let partial_complete_inner =
        build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"partial-complete-bytes");
    let partial_complete_gpdu = build_gpdu(LOCAL_TEID, None, &partial_complete_inner);
    let partial_complete_frame = build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &partial_complete_gpdu,
        true,
        0,
    );

    // Linux CHECKSUM_PARTIAL permits a zero on-frame seed. Prove that this
    // unfinished metadata state cannot be mistaken for IPv4's legal zero
    // checksum omission before it reaches the PDR lookup.
    let partial_zero_inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"partial-zero-seed");
    let partial_zero_gpdu = build_gpdu(LOCAL_TEID, None, &partial_zero_inner);
    let partial_zero_frame = build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &partial_zero_gpdu,
        false,
        0,
    );

    drain_datagrams(ue_socket);
    let invalid_before = backend
        .datapath_snapshot(device)
        .await
        .expect("snapshot before invalid outer-envelope cases")
        .counters;
    for (frame, metadata) in &invalid_cases {
        send_raw_gtpu_frame(&net.pgw_ns, "s2bup", frame, *metadata);
    }
    net.set_pgw_tx_checksum_offload(true);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &partial_frame,
        RawChecksumMetadata::Partial,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &partial_complete_frame,
        RawChecksumMetadata::Partial,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &partial_zero_frame,
        RawChecksumMetadata::Partial,
    );
    net.set_pgw_tx_checksum_offload(false);
    expect_no_datagram(ue_socket);

    let invalid_after = backend
        .datapath_snapshot(device)
        .await
        .expect("snapshot after invalid outer-envelope cases")
        .counters;
    let invalid_count = u64::try_from(invalid_cases.len() + 3).expect("bounded invalid case count");
    assert_eq!(
        invalid_after.downlink_malformed,
        invalid_before.downlink_malformed + invalid_count,
        "every malformed or unverified-partial candidate must be counted exactly once",
    );
    assert_eq!(
        invalid_after.downlink_unknown_teid, invalid_before.downlink_unknown_teid,
        "malformed and CHECKSUM_PARTIAL candidates must not reach the TEID lookup",
    );
    assert_eq!(
        invalid_after.downlink_decapsulated, invalid_before.downlink_decapsulated,
        "malformed and CHECKSUM_PARTIAL candidates must not decapsulate",
    );
    assert_eq!(
        invalid_after.downlink_destination_mismatches,
        invalid_before.downlink_destination_mismatches,
        "malformed and CHECKSUM_PARTIAL candidates must not reach inner-destination validation",
    );
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

fn expect_no_reassembled_datagram(socket: &GtpuReassemblySocket) {
    let mut buffer = [0_u8; 2048];
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set sealed reassembly timeout");
    match socket.receive(&mut buffer) {
        Ok((len, _)) => panic!("unexpected reassembled datagram ({len} bytes)"),
        Err(error) => assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "unexpected sealed reassembly recv error: {error}"
        ),
    }
}

const IPFRAG_TIME_PATH: &str = "/proc/sys/net/ipv4/ipfrag_time";
const IPFRAG_HIGH_THRESH_PATH: &str = "/proc/sys/net/ipv4/ipfrag_high_thresh";
const IPFRAG_LOW_THRESH_PATH: &str = "/proc/sys/net/ipv4/ipfrag_low_thresh";

trait FragmentSysctlStore: Clone {
    fn read(&self, path: &str) -> io::Result<String>;
    fn write(&self, path: &str, value: &str) -> io::Result<()>;
}

#[derive(Clone, Copy)]
struct ProcFragmentSysctlStore;

impl FragmentSysctlStore for ProcFragmentSysctlStore {
    fn read(&self, path: &str) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn write(&self, path: &str, value: &str) -> io::Result<()> {
        fs::write(path, value)
    }
}

/// Restores this test netns's fragment sysctls after success, partial
/// configuration failure, or an assertion unwind.
struct FragmentSysctlGuard<S: FragmentSysctlStore = ProcFragmentSysctlStore> {
    store: S,
    original_time: String,
    original_high_thresh: String,
    original_low_thresh: Option<String>,
}

impl FragmentSysctlGuard<ProcFragmentSysctlStore> {
    fn configure(timeout_seconds: u32, high_threshold_bytes: u32) -> io::Result<Self> {
        Self::configure_with(
            ProcFragmentSysctlStore,
            timeout_seconds,
            high_threshold_bytes,
        )
    }
}

impl<S: FragmentSysctlStore> FragmentSysctlGuard<S> {
    fn configure_with(
        store: S,
        timeout_seconds: u32,
        high_threshold_bytes: u32,
    ) -> io::Result<Self> {
        // Read every value before the first mutation. Construct the guard
        // before applying any writes so `?` and unwinding both restore every
        // value that may already have changed.
        let original_time = store.read(IPFRAG_TIME_PATH)?;
        let original_high_thresh = store.read(IPFRAG_HIGH_THRESH_PATH)?;
        let original_low_thresh = store.read(IPFRAG_LOW_THRESH_PATH).ok();
        let guard = Self {
            store,
            original_time,
            original_high_thresh,
            original_low_thresh,
        };
        guard
            .store
            .write(IPFRAG_TIME_PATH, &timeout_seconds.to_string())?;
        if guard.original_low_thresh.is_some() {
            guard.store.write(
                IPFRAG_LOW_THRESH_PATH,
                &(high_threshold_bytes / 2).to_string(),
            )?;
        }
        guard
            .store
            .write(IPFRAG_HIGH_THRESH_PATH, &high_threshold_bytes.to_string())?;
        Ok(guard)
    }

    fn set_timeout_seconds(&self, timeout_seconds: u32) -> io::Result<()> {
        self.store
            .write(IPFRAG_TIME_PATH, &timeout_seconds.to_string())
    }
}

impl<S: FragmentSysctlStore> Drop for FragmentSysctlGuard<S> {
    fn drop(&mut self) {
        // Restore the high watermark before the low watermark so the
        // original low value cannot transiently exceed a reduced high value.
        let _ = self
            .store
            .write(IPFRAG_HIGH_THRESH_PATH, &self.original_high_thresh);
        if let Some(original_low_thresh) = &self.original_low_thresh {
            let _ = self
                .store
                .write(IPFRAG_LOW_THRESH_PATH, original_low_thresh);
        }
        let _ = self.store.write(IPFRAG_TIME_PATH, &self.original_time);
    }
}

#[derive(Clone)]
struct TestFragmentSysctlStore {
    values: Arc<Mutex<std::collections::BTreeMap<String, String>>>,
    writes: Arc<AtomicUsize>,
    fail_write: usize,
    panic_on_failure: bool,
}

impl TestFragmentSysctlStore {
    fn with_failure(fail_write: usize, panic_on_failure: bool) -> Self {
        Self {
            values: Arc::new(Mutex::new(std::collections::BTreeMap::from([
                (IPFRAG_TIME_PATH.to_owned(), "30\n".to_owned()),
                (IPFRAG_HIGH_THRESH_PATH.to_owned(), "4194304\n".to_owned()),
                (IPFRAG_LOW_THRESH_PATH.to_owned(), "3145728\n".to_owned()),
            ]))),
            writes: Arc::new(AtomicUsize::new(0)),
            fail_write,
            panic_on_failure,
        }
    }

    fn value(&self, path: &str) -> String {
        self.values
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(path)
            .cloned()
            .expect("test sysctl exists")
    }
}

impl FragmentSysctlStore for TestFragmentSysctlStore {
    fn read(&self, path: &str) -> io::Result<String> {
        self.values
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "test sysctl missing"))
    }

    fn write(&self, path: &str, value: &str) -> io::Result<()> {
        let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if write == self.fail_write {
            assert!(!self.panic_on_failure, "injected test sysctl write panic");
            return Err(io::Error::other("injected test sysctl write failure"));
        }
        self.values
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(path.to_owned(), value.to_owned());
        Ok(())
    }
}

#[test]
fn fragment_sysctl_guard_rolls_back_partial_configuration_failure() {
    let store = TestFragmentSysctlStore::with_failure(3, false);
    let result = FragmentSysctlGuard::configure_with(store.clone(), 1, 65_536);
    assert!(result.is_err(), "the injected third write must fail");
    assert_eq!(store.value(IPFRAG_TIME_PATH), "30\n");
    assert_eq!(store.value(IPFRAG_HIGH_THRESH_PATH), "4194304\n");
    assert_eq!(store.value(IPFRAG_LOW_THRESH_PATH), "3145728\n");

    let panic_store = TestFragmentSysctlStore::with_failure(2, true);
    let panic_result = std::panic::catch_unwind(AssertUnwindSafe({
        let panic_store = panic_store.clone();
        move || {
            let _guard = FragmentSysctlGuard::configure_with(panic_store, 1, 65_536);
        }
    }));
    assert!(
        panic_result.is_err(),
        "the injected second write must panic"
    );
    assert_eq!(panic_store.value(IPFRAG_TIME_PATH), "30\n");
    assert_eq!(panic_store.value(IPFRAG_HIGH_THRESH_PATH), "4194304\n");
    assert_eq!(panic_store.value(IPFRAG_LOW_THRESH_PATH), "3145728\n");
}

fn ipv4_reassembly_stat(name: &str) -> u64 {
    let snmp = fs::read_to_string("/proc/net/snmp").expect("read IPv4 reassembly counters");
    let mut lines = snmp.lines();
    while let Some(header) = lines.next() {
        if !header.starts_with("Ip:") {
            continue;
        }
        let values = lines.next().expect("IPv4 SNMP values follow header");
        let headers = header.split_whitespace().skip(1);
        let values = values.split_whitespace().skip(1);
        return headers
            .zip(values)
            .find_map(|(field, value)| {
                (field == name).then(|| value.parse::<u64>().expect("numeric IPv4 SNMP counter"))
            })
            .unwrap_or_else(|| panic!("IPv4 SNMP counter {name} must exist"));
    }
    panic!("IPv4 SNMP counters must exist");
}

fn wait_for_ipv4_reassembly_stat_increment(name: &str, before: u64, timeout: Duration) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        let current = ipv4_reassembly_stat(name);
        if current > before {
            return current;
        }
        assert!(
            Instant::now() < deadline,
            "IPv4 {name} did not increment from {before} before the bounded deadline"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn drain_datagrams(socket: &UdpSocket) {
    let mut buffer = [0_u8; 2048];
    socket
        .set_nonblocking(true)
        .expect("make socket nonblocking for drain");
    while socket.recv_from(&mut buffer).is_ok() {}
    socket
        .set_nonblocking(false)
        .expect("restore blocking socket mode");
}

fn attach_prior_generation_program(ebpf: &mut Ebpf, name: &str, attach_type: TcAttachType) -> u32 {
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .expect("prior generation program")
        .try_into()
        .expect("prior generation program is a tc classifier");
    program.load().expect("load prior generation classifier");
    let program_id = program.info().expect("prior generation program info").id();
    let link_id = program
        .attach_with_options(
            "s2bu",
            attach_type,
            TcAttachOptions::Netlink(NlOptions {
                priority: 50,
                handle: SDK_TC_HANDLE,
                classid: None,
            }),
        )
        .expect("attach prior generation classifier");
    let link = program
        .take_link(link_id)
        .expect("own prior generation tc link");
    // Model a prior loader exiting while kernel-owned tc filters and pinned
    // maps survive. Dropping this netlink link would detach the live filter.
    std::mem::forget(link);
    program_id
}

fn install_frozen_v1_datapath(pin_dir: &std::path::Path) -> (u32, u32) {
    fs::create_dir_all(pin_dir).expect("create frozen v1 pin directory");
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_dir)
        .load(FROZEN_V1_OBJECT)
        .expect("load frozen v1 object");
    {
        let map = ebpf.map_mut(MAP_CONFIG).expect("v1 config map");
        let mut config = Array::<_, [u8; 4]>::try_from(map).expect("typed v1 config");
        config
            .set(0, EPDG_S2BU_IP.octets(), 0)
            .expect("seed v1 config");
    }
    {
        let map = ebpf.map_mut(MAP_UPLINK_FAR).expect("v1 FAR map");
        let mut far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
            .expect("typed v1 FAR");
        far.insert(
            UPLINK_DSCP_SCHEMA_MARKER_KEY,
            UPLINK_DSCP_SCHEMA_MARKER_VALUE,
            0,
        )
        .expect("seed committed v1 marker");
        far.insert(
            UE_PAA.octets(),
            UplinkFar {
                peer_ip: PGW_IP.octets(),
                // Exercise the retained config fallback, making an early
                // config overwrite externally observable.
                local_ip: [0; 4],
                o_teid: PEER_TEID.to_be_bytes(),
            }
            .encode(),
            0,
        )
        .expect("seed v1 FAR");
    }
    {
        let map = ebpf.map_mut(MAP_DOWNLINK_PDR).expect("v1 PDR map");
        let mut pdr = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
            .expect("typed v1 PDR");
        pdr.insert(
            LOCAL_TEID.to_be_bytes(),
            DownlinkPdr {
                ue_ip: UE_PAA.octets(),
            }
            .encode(),
            0,
        )
        .expect("seed v1 PDR");
    }
    let uplink_id = attach_prior_generation_program(&mut ebpf, PROG_UPLINK, TcAttachType::Egress);
    let downlink_id =
        attach_prior_generation_program(&mut ebpf, PROG_DOWNLINK, TcAttachType::Ingress);
    drop(ebpf);
    (uplink_id, downlink_id)
}

fn frozen_v1_map_ids(pin_dir: &std::path::Path) -> Vec<u32> {
    [
        MAP_UPLINK_FAR,
        MAP_UPLINK_DSCP,
        MAP_DOWNLINK_PDR,
        MAP_COUNTERS,
        MAP_CONFIG,
    ]
    .into_iter()
    .map(|name| {
        MapInfo::from_pin(pin_dir.join(name))
            .unwrap_or_else(|error| panic!("open retained {name}: {error}"))
            .id()
    })
    .collect()
}

fn install_drained_frozen_v2_datapath(pin_dir: &std::path::Path) -> (u32, u32) {
    fs::create_dir_all(pin_dir).expect("create frozen v2 pin directory");
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_dir)
        .load(FROZEN_V2_OBJECT)
        .expect("load frozen v2 object in isolated qualification netns");
    {
        let map = ebpf.map_mut(MAP_CONFIG).expect("v2 config map");
        let mut config = Array::<_, [u8; 4]>::try_from(map).expect("typed v2 config");
        config
            .set(0, EPDG_S2BU_IP.octets(), 0)
            .expect("seed v2 config");
    }
    {
        let map = ebpf.map_mut(MAP_UPLINK_FAR).expect("v2 FAR map");
        let mut far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
            .expect("typed v2 FAR");
        far.insert(
            UPLINK_DSCP_SCHEMA_MARKER_KEY,
            UPLINK_BEARER_SCHEMA_MARKER_VALUE,
            0,
        )
        .expect("seed committed v2 marker");
    }
    let uplink_id = attach_prior_generation_program(&mut ebpf, PROG_UPLINK, TcAttachType::Egress);
    let downlink_id =
        attach_prior_generation_program(&mut ebpf, PROG_DOWNLINK, TcAttachType::Ingress);
    drop(ebpf);
    (uplink_id, downlink_id)
}

fn create_drained_legacy_v2_pins(pin_dir: &std::path::Path) {
    fs::create_dir_all(pin_dir).expect("create legacy v2 pin directory");

    let mut far = BpfHashMap::<MapData, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::create(65_536, 0)
        .expect("create legacy v2 FAR");
    far.insert(
        UPLINK_DSCP_SCHEMA_MARKER_KEY,
        UPLINK_BEARER_SCHEMA_MARKER_VALUE,
        0,
    )
    .expect("seed legacy v2 marker");
    far.pin(pin_dir.join(MAP_UPLINK_FAR))
        .expect("pin legacy v2 FAR");

    let marked_far =
        BpfHashMap::<MapData, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_FAR_VALUE_LEN]>::create(
            65_536, 0,
        )
        .expect("create legacy v2 marked FAR");
    marked_far
        .pin(pin_dir.join(MAP_UPLINK_MARK_FAR))
        .expect("pin legacy v2 marked FAR");

    let dscp = BpfHashMap::<MapData, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::create(65_536, 0)
        .expect("create legacy v2 DSCP");
    dscp.pin(pin_dir.join(MAP_UPLINK_DSCP))
        .expect("pin legacy v2 DSCP");

    let marked_dscp =
        BpfHashMap::<MapData, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_DSCP_VALUE_LEN]>::create(
            65_536, 0,
        )
        .expect("create legacy v2 marked DSCP");
    marked_dscp
        .pin(pin_dir.join(MAP_UPLINK_MARK_DSCP))
        .expect("pin legacy v2 marked DSCP");

    let pdr = BpfHashMap::<MapData, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::create(65_536, 0)
        .expect("create legacy v2 PDR");
    pdr.pin(pin_dir.join(MAP_DOWNLINK_PDR))
        .expect("pin legacy v2 PDR");

    let marked_pdr =
        BpfHashMap::<MapData, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::create(65_536, 0)
            .expect("create legacy v2 marked PDR");
    marked_pdr
        .pin(pin_dir.join(MAP_DOWNLINK_MARK_PDR))
        .expect("pin legacy v2 marked PDR");

    let owner =
        BpfHashMap::<MapData, [u8; UPLINK_MARK_KEY_LEN], [u8; LEGACY_V2_OWNER_VALUE_LEN]>::create(
            65_536, 0,
        )
        .expect("create legacy v2 owner journal");
    owner
        .pin(pin_dir.join(MAP_MARKED_BEARER_OWNER))
        .expect("pin legacy v2 owner journal");

    let counters =
        PerCpuArray::<MapData, u64>::create(6, 0).expect("create legacy v2 counter array");
    counters
        .pin(pin_dir.join(MAP_COUNTERS))
        .expect("pin legacy v2 counter array");

    let mut config =
        Array::<MapData, [u8; 4]>::create(1, 0).expect("create legacy v2 config array");
    config
        .set(0, EPDG_S2BU_IP.octets(), 0)
        .expect("seed legacy v2 config");
    config
        .pin(pin_dir.join(MAP_CONFIG))
        .expect("pin legacy v2 config array");
}

fn drained_v2_request(ifindex: u32) -> DrainedV2TeardownRequest {
    DrainedV2TeardownRequest::new(
        GtpDevice {
            name: "s2bu".to_string(),
            ifindex,
        },
        GtpuV2DrainProof::sessions_and_traffic_drained(),
    )
}

fn pinned_config(pin_dir: &std::path::Path) -> [u8; 4] {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_CONFIG)).expect("open pinned config"),
    )
    .expect("identify pinned config map");
    let config = Array::<_, [u8; 4]>::try_from(map).expect("typed pinned config");
    config.get(&0, 0).expect("read pinned config")
}

fn pinned_schema_marker(pin_dir: &std::path::Path) -> [u8; UPLINK_FAR_VALUE_LEN] {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_FAR)).expect("open pinned FAR"),
    )
    .expect("identify pinned FAR map");
    let far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
        .expect("typed pinned FAR");
    far.get(&UPLINK_DSCP_SCHEMA_MARKER_KEY, 0)
        .expect("read pinned schema marker")
}

/// Regress the durable bearer schema marker to an earlier generation's value,
/// leaving every pin exactly as it was. Only the marker moves, which is
/// precisely the difference between a graph a v3-era process left behind and
/// one this build left behind.
fn write_pinned_schema_marker(pin_dir: &std::path::Path, value: [u8; UPLINK_FAR_VALUE_LEN]) {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_FAR)).expect("open pinned FAR for marker write"),
    )
    .expect("identify pinned FAR map");
    let mut far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
        .expect("typed pinned FAR");
    far.insert(UPLINK_DSCP_SCHEMA_MARKER_KEY, value, 0)
        .expect("write pinned schema marker");
}

/// Re-pin `GTPU_COUNTERS` at an earlier build's slot count, leaving every
/// other pin -- and every hook -- untouched.
fn repin_counters_at(pin_dir: &std::path::Path, slots: u32) {
    fs::remove_file(pin_dir.join(MAP_COUNTERS)).expect("unpin the current counters map");
    drop(
        EbpfLoader::new()
            .default_map_pin_directory(pin_dir)
            .map_max_entries(MAP_COUNTERS, slots)
            .load(CURRENT_OBJECT)
            .expect("re-pin the retained graph at an earlier counter ABI"),
    );
    assert_eq!(
        pinned_map_entries(pin_dir, MAP_COUNTERS),
        slots,
        "the retained graph must carry the requested counter ABI"
    );
}

fn pinned_map_entries(pin_dir: &std::path::Path, name: &str) -> u32 {
    MapInfo::from_pin(pin_dir.join(name))
        .unwrap_or_else(|error| panic!("open pinned {name}: {error}"))
        .max_entries()
}

/// Every pin name in the directory, sorted. What a refusal does to the *shape*
/// of a retained graph is only visible against the whole set.
fn pinned_names(pin_dir: &std::path::Path) -> Vec<String> {
    let mut names = fs::read_dir(pin_dir)
        .expect("read pin directory")
        .map(|entry| {
            entry
                .expect("pin directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// The four maps introduced after the endpoint-bound v3 schema. A graph a v3
/// generation left behind does not have them; a current-build load creates
/// them.
const POST_V3_MAPS: [&str; 4] = [
    MAP_UPLINK_SOURCE_PORT,
    MAP_UPLINK_MARK_SOURCE_PORT,
    MAP_UPLINK_PMTU,
    MAP_UPLINK_PMTU_COUNTERS,
];

/// Regress a current-build graph to the pin *set* a v3 generation leaves
/// behind, not just its marker.
///
/// Rewriting only the marker on a current-build directory leaves all
/// twenty-one pins in place, which cannot observe what a migration does to a
/// graph that is genuinely short of four of them.
fn make_v3_shaped(pin_dir: &std::path::Path) {
    for name in POST_V3_MAPS {
        fs::remove_file(pin_dir.join(name))
            .unwrap_or_else(|error| panic!("unpin post-v3 map {name}: {error}"));
    }
}

fn pinned_source_port_entries(pin_dir: &std::path::Path) -> usize {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_SOURCE_PORT))
            .expect("open pinned uplink source-port policy"),
    )
    .expect("identify pinned uplink source-port policy map");
    BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
        .expect("typed pinned uplink source-port policy")
        .iter()
        .count()
}

/// Leave behind exactly what a process from before the uplink redirect counter
/// leaves behind: a pinned map graph whose `GTPU_COUNTERS` still has the old
/// slot count, and two kernel-owned tc filters bound to that graph.
///
/// The pin graphs of `6778bd53` and this build differ in exactly one field:
/// `GTPU_COUNTERS.max_entries`, 6 -> 7. Every other entry in the committed
/// object's `maps` section -- name, type, key size, value size, flags and
/// pinning -- is byte-identical between the two objects, so re-pinning that one
/// map through the loader's own `max_entries` override reproduces precisely the
/// bpffs graph an old process leaves behind, without carrying a second copy of
/// an 800 KiB historical artifact in-tree.
///
/// The hooks are re-established from that same load rather than left as the
/// caller's own generation attached them, because the loader identifies a hook
/// occupant partly by its map-ID set (`owner_matches_artifact`). A real
/// pre-growth process leaves filters bound to the very pins it also leaves
/// behind; a test that swapped the counter pin out from under a still-attached
/// program would instead be asserting on an artefact of its own seeding.
///
/// Nothing else is touched: the FAR/PDR/session pins, the schema marker and the
/// config the previous generation committed all stay exactly as they were,
/// because those are the pins high availability actually depends on.
fn retain_pre_redirect_datapath(pin_dir: &std::path::Path) {
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);
    fs::remove_file(pin_dir.join(MAP_COUNTERS)).expect("unpin the current counters map");
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_dir)
        .map_max_entries(MAP_COUNTERS, PRE_REDIRECT_COUNTER_SLOTS)
        .load(CURRENT_OBJECT)
        .expect("re-pin the retained graph at the pre-redirect counter ABI");
    assert_eq!(
        pinned_map_entries(pin_dir, MAP_COUNTERS),
        PRE_REDIRECT_COUNTER_SLOTS,
        "the retained graph must carry the pre-redirect counter ABI"
    );
    attach_prior_generation_program(&mut ebpf, PROG_UPLINK, TcAttachType::Egress);
    attach_prior_generation_program(&mut ebpf, PROG_DOWNLINK, TcAttachType::Ingress);
    drop(ebpf);
}

fn pinned_counter(pin_dir: &std::path::Path, index: u32) -> u64 {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_COUNTERS)).expect("open pinned counters"),
    )
    .expect("identify pinned counters map");
    let counters = PerCpuArray::<_, u64>::try_from(map).expect("typed pinned counters");
    counters
        .get(&index, 0)
        .expect("read per-CPU counter")
        .iter()
        .copied()
        .sum()
}

fn pinned_binding_counter(pin_dir: &std::path::Path, index: u32) -> u64 {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_DOWNLINK_BINDING_COUNTERS))
            .expect("open pinned binding counters"),
    )
    .expect("identify pinned binding counters map");
    let counters = PerCpuArray::<_, u64>::try_from(map).expect("typed pinned binding counters");
    counters
        .get(&index, 0)
        .expect("read per-CPU binding counter")
        .iter()
        .copied()
        .sum()
}

fn replace_pinned_binding(
    pin_dir: &std::path::Path,
    local_teid: u32,
    replacement: Option<[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>,
) -> Option<[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_DOWNLINK_ENDPOINT_BINDING))
            .expect("open pinned downlink binding"),
    )
    .expect("identify pinned downlink binding map");
    let mut bindings =
        BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(map)
            .expect("typed pinned downlink binding map");
    let key = local_teid.to_be_bytes();
    let previous = bindings.get(&key, 0).ok();
    match replacement {
        Some(value) => bindings
            .insert(key, value, 0)
            .expect("replace pinned downlink binding"),
        None => bindings
            .remove(&key)
            .expect("remove pinned downlink binding"),
    }
    previous
}

fn replace_pinned_default_binding_transaction(
    pin_dir: &std::path::Path,
    local_teid: u32,
    replacement: [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
) -> [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN] {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_SOURCE_PORT))
            .expect("open pinned default commit map"),
    )
    .expect("identify pinned default commit map");
    let mut commits = BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
        .expect("typed pinned default commit map");
    let key = UE_PAA.octets();
    let encoded = commits.get(&key, 0).expect("read active default commit");
    let active = PdpContextCommit::decode(&encoded);
    assert!(active.is_valid(), "default commit must be canonical");
    assert_eq!(
        active.phase(),
        MarkedBearerOwnerPhase::Active,
        "default commit must be active before a test transaction"
    );
    assert_eq!(
        active.local_teid(),
        local_teid.to_be_bytes(),
        "default commit must own the binding TEID"
    );

    let replacement_binding = DownlinkEndpointBinding::decode(&replacement);
    let (GtpuEndpointAddress::Ipv4(replacement_peer), GtpuEndpointAddress::Ipv4(replacement_local)) = (
        replacement_binding.peer_address(),
        replacement_binding.local_address(),
    ) else {
        panic!("default test transaction requires an IPv4 endpoint binding");
    };
    let replacement_far = UplinkFar {
        peer_ip: replacement_peer,
        local_ip: replacement_local,
        ..active.uplink_far()
    };
    let next = PdpContextCommit::new(
        active.local_teid(),
        replacement_far,
        active.egress_dscp(),
        replacement_binding,
        active.uplink_source_port_policy(),
        MarkedBearerOwnerPhase::Active,
    )
    .expect("replacement endpoint must produce a canonical active commit");

    commits
        .insert(
            key,
            active.with_phase(MarkedBearerOwnerPhase::Pending).encode(),
            0,
        )
        .expect("publish pending default commit");
    let far_map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_FAR)).expect("open pinned default FAR"),
    )
    .expect("identify pinned default FAR map");
    let mut fars = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(far_map)
        .expect("typed pinned default FAR map");
    let previous_far = fars.get(&key, 0).expect("read live default FAR");
    assert_eq!(
        previous_far,
        active.uplink_far().encode(),
        "live FAR must match the active commit"
    );
    fars.insert(key, replacement_far.encode(), 0)
        .expect("replace pinned default FAR");
    let previous = replace_pinned_binding(pin_dir, local_teid, Some(replacement))
        .expect("default binding must exist before a test transaction");
    assert_eq!(
        previous,
        active.downlink_binding().encode(),
        "live binding must match the active commit"
    );
    commits
        .insert(key, next.encode(), 0)
        .expect("publish active default commit last");
    previous
}

fn set_marked_owner_phase(pin_dir: &std::path::Path, mark: u32, phase: MarkedBearerOwnerPhase) {
    let selector = UplinkFarKey {
        ue_ip: UE_PAA.octets(),
        bearer_mark: mark.to_be_bytes(),
    }
    .encode();
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_MARKED_BEARER_OWNER))
            .expect("open pinned marked-owner journal"),
    )
    .expect("identify pinned marked-owner journal");
    let mut owners =
        BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; MARKED_BEARER_OWNER_VALUE_LEN]>::try_from(
            map,
        )
        .expect("typed marked-owner journal");
    let current = MarkedBearerOwner::decode(
        &owners
            .get(&selector, 0)
            .expect("read dedicated-bearer owner"),
    );
    assert!(
        current.is_valid(),
        "owner must be canonical before phase test"
    );
    let updated = MarkedBearerOwner::new(
        current.local_teid,
        current.uplink_far,
        current.egress_dscp(),
        current.downlink_binding,
        phase,
    );
    let commit_map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_MARK_SOURCE_PORT))
            .expect("open pinned marked commit map"),
    )
    .expect("identify pinned marked commit map");
    let mut commits =
        BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(
            commit_map,
        )
        .expect("typed pinned marked commit map");
    let commit = PdpContextCommit::decode(
        &commits
            .get(&selector, 0)
            .expect("read dedicated-bearer commit"),
    );
    assert!(
        commit.is_valid(),
        "commit must be canonical before phase test"
    );
    assert_eq!(
        commit.marked_owner(),
        current,
        "owner journal and complete commit must agree before phase test"
    );
    let updated_commit = commit.with_phase(phase).encode();

    if phase == MarkedBearerOwnerPhase::Active {
        owners
            .insert(selector, updated.encode(), 0)
            .expect("replace marked-owner phase");
        commits
            .insert(selector, updated_commit, 0)
            .expect("publish active marked commit last");
    } else {
        commits
            .insert(selector, updated_commit, 0)
            .expect("publish non-active marked commit first");
        owners
            .insert(selector, updated.encode(), 0)
            .expect("replace marked-owner phase");
    }
}

fn take_marked_far(pin_dir: &std::path::Path, mark: u32) -> [u8; UPLINK_FAR_VALUE_LEN] {
    let selector = UplinkFarKey {
        ue_ip: UE_PAA.octets(),
        bearer_mark: mark.to_be_bytes(),
    }
    .encode();
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_MARK_FAR)).expect("open pinned marked FAR"),
    )
    .expect("identify pinned marked FAR");
    let mut fars =
        BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
            .expect("typed pinned marked FAR");
    let value = fars.get(&selector, 0).expect("read dedicated-bearer FAR");
    fars.remove(&selector).expect("remove dedicated-bearer FAR");
    value
}

fn replace_pinned_source_port(
    pin_dir: &std::path::Path,
    value: [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
) {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_SOURCE_PORT))
            .expect("open pinned source-port map"),
    )
    .expect("identify pinned source-port map");
    let mut ports = BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
        .expect("typed pinned source-port map");
    ports
        .insert(UE_PAA.octets(), value, 0)
        .expect("replace pinned source-port entry");
}

fn read_pinned_default_commit(pin_dir: &std::path::Path) -> PdpContextCommit {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_SOURCE_PORT))
            .expect("open pinned source-port map"),
    )
    .expect("identify pinned source-port map");
    let commits = BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
        .expect("typed pinned source-port map");
    let encoded = commits
        .get(&UE_PAA.octets(), 0)
        .expect("read pinned default commit");
    PdpContextCommit::decode(&encoded)
}

fn take_pinned_source_port(pin_dir: &std::path::Path) -> [u8; UPLINK_SOURCE_PORT_VALUE_LEN] {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_SOURCE_PORT))
            .expect("open pinned source-port map"),
    )
    .expect("identify pinned source-port map");
    let mut ports = BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
        .expect("typed pinned source-port map");
    let value = ports
        .get(&UE_PAA.octets(), 0)
        .expect("read pinned source-port entry");
    ports
        .remove(&UE_PAA.octets())
        .expect("remove pinned source-port entry");
    value
}

fn replace_pinned_default_pdr(
    pin_dir: &std::path::Path,
    local_teid: u32,
    value: Option<[u8; DOWNLINK_PDR_VALUE_LEN]>,
) -> Option<[u8; DOWNLINK_PDR_VALUE_LEN]> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_DOWNLINK_PDR)).expect("open pinned downlink PDR"),
    )
    .expect("identify pinned downlink PDR map");
    let mut pdrs = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
        .expect("typed pinned downlink PDR map");
    let key = local_teid.to_be_bytes();
    let previous = pdrs.get(&key, 0).ok();
    match value {
        Some(value) => pdrs
            .insert(key, value, 0)
            .expect("replace pinned downlink PDR"),
        None => {
            let _ = pdrs.remove(&key);
        }
    }
    previous
}

fn tc_program_id(direction: &str) -> u32 {
    let filters = tc_filters(direction);
    let fields: Vec<_> = filters.split_whitespace().collect();
    fields
        .windows(2)
        .find_map(|window| {
            (window[0] == "id")
                .then(|| window[1].parse::<u32>().ok())
                .flatten()
        })
        .unwrap_or_else(|| panic!("tc {direction} filter has no BPF program ID: {filters}"))
}

fn attached_program_map_ids(direction: &str) -> Vec<u32> {
    let program_id = tc_program_id(direction);
    let program = loaded_programs()
        .find_map(|result| match result {
            Ok(info) if info.id() == program_id => Some(info),
            Ok(_) | Err(_) => None,
        })
        .unwrap_or_else(|| panic!("tc {direction} program ID {program_id} is not loaded"));
    let mut map_ids = program
        .map_ids()
        .unwrap_or_else(|error| panic!("read tc {direction} program map IDs: {error}"))
        .unwrap_or_else(|| panic!("kernel did not report tc {direction} program map IDs"));
    map_ids.sort_unstable();
    map_ids
}

fn exact_pinned_map_ids(pin_dir: &std::path::Path, names: &[&str]) -> Vec<u32> {
    let mut map_ids = names
        .iter()
        .map(|name| {
            MapInfo::from_pin(pin_dir.join(name))
                .unwrap_or_else(|error| panic!("open pinned {name}: {error}"))
                .id()
        })
        .collect::<Vec<_>>();
    map_ids.sort_unstable();
    map_ids
}

#[tokio::test(flavor = "multi_thread")]
// The serial guard is deliberately held for the entire test body: the
// root-netns veth pairs and tc attachments are shared harness state, so the
// whole privileged scenario (not just provisioning) is the critical section.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_uplink_and_downlink_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let marked_pin_dir = net.pin_root.join("s2bu");
    // veth namespace crossing scrubs socket marks. Inject the distinct outer
    // sentinel in the ePDG namespace at an earlier, non-SDK tc priority.
    net.install_outer_mark_injector();
    assert_eq!(
        backend.probe().await?.egress_dscp_marking,
        GtpuCapability::Available,
        "loaded datapath must expose a usable DSCP map"
    );
    assert_eq!(
        backend.probe().await?.per_bearer_marking,
        GtpuCapability::Available,
        "both exact hooks and all marked maps must be live"
    );
    assert_eq!(
        backend.probe().await?.downlink_endpoint_binding,
        GtpuCapability::Available,
        "the exact binding map, counter map, and downlink hook must be live"
    );
    assert!(
        tc_filters("egress").contains("opc_gtpu_uplink"),
        "uplink program must be attached at tc egress"
    );
    assert!(
        tc_filters("ingress").contains("opc_gtpu_downlink"),
        "downlink program must be attached at tc ingress"
    );
    assert_eq!(
        attached_program_map_ids("egress"),
        exact_pinned_map_ids(
            &marked_pin_dir,
            &[
                MAP_UPLINK_FAR,
                MAP_UPLINK_MARK_FAR,
                MAP_UPLINK_DSCP,
                MAP_UPLINK_MARK_DSCP,
                MAP_UPLINK_SOURCE_PORT,
                MAP_UPLINK_MARK_SOURCE_PORT,
                MAP_UPLINK_PMTU,
                MAP_UPLINK_PMTU_COUNTERS,
                MAP_DOWNLINK_PDR,
                MAP_DOWNLINK_MARK_PDR,
                MAP_DOWNLINK_ENDPOINT_BINDING,
                MAP_MARKED_BEARER_OWNER,
                MAP_COUNTERS,
                MAP_CONFIG,
                MAP_SESSION_GROUPS,
                MAP_SESSION_UPLINK_INDEX,
                MAP_CONFIG_IPV6,
            ],
        ),
        "the live uplink program must reference the exact pinned maps read by diagnostics",
    );
    assert_eq!(
        attached_program_map_ids("ingress"),
        exact_pinned_map_ids(
            &marked_pin_dir,
            &[
                MAP_DOWNLINK_PDR,
                MAP_DOWNLINK_MARK_PDR,
                MAP_DOWNLINK_ENDPOINT_BINDING,
                MAP_UPLINK_FAR,
                MAP_UPLINK_MARK_FAR,
                MAP_UPLINK_DSCP,
                MAP_UPLINK_MARK_DSCP,
                MAP_UPLINK_SOURCE_PORT,
                MAP_UPLINK_MARK_SOURCE_PORT,
                MAP_DOWNLINK_BINDING_COUNTERS,
                MAP_MARKED_BEARER_OWNER,
                MAP_COUNTERS,
                MAP_SESSION_GROUPS,
                MAP_SESSION_DOWNLINK_INDEX,
                MAP_CONFIG_IPV6,
            ],
        ),
        "the live downlink program must reference the exact pinned maps read by diagnostics",
    );
    let initial_snapshot = backend.datapath_snapshot(&device).await?;
    assert_eq!(initial_snapshot.uplink_program_id, tc_program_id("egress"));
    assert_eq!(
        initial_snapshot.downlink_program_id,
        tc_program_id("ingress")
    );
    assert_eq!(
        initial_snapshot.counters_map_id,
        MapInfo::from_pin(marked_pin_dir.join(MAP_COUNTERS))?.id()
    );
    assert_eq!(
        initial_snapshot.downlink_binding_counters_map_id,
        MapInfo::from_pin(marked_pin_dir.join(MAP_DOWNLINK_BINDING_COUNTERS))?.id()
    );
    for (reported, index) in [
        (
            initial_snapshot.counters.uplink_encapsulated,
            COUNTER_UL_ENCAP,
        ),
        (
            initial_snapshot.counters.uplink_far_misses,
            COUNTER_UL_FAR_MISS,
        ),
        (
            initial_snapshot.counters.downlink_decapsulated,
            COUNTER_DL_DECAP,
        ),
        (
            initial_snapshot.counters.downlink_unknown_teid,
            COUNTER_DL_UNKNOWN_TEID,
        ),
        (
            initial_snapshot.counters.downlink_malformed,
            COUNTER_DL_MALFORMED,
        ),
        (
            initial_snapshot.counters.downlink_destination_mismatches,
            COUNTER_DL_DST_MISMATCH,
        ),
        (
            initial_snapshot.counters.uplink_redirects_resolved,
            COUNTER_UL_REDIRECT_RESOLVED,
        ),
    ] {
        assert_eq!(
            reported,
            pinned_counter(&marked_pin_dir, index),
            "the public snapshot must aggregate every per-CPU value from the exact pinned map",
        );
    }
    for (reported, index) in [
        (
            initial_snapshot.counters.downlink_binding_invalid,
            COUNTER_DL_BINDING_INVALID,
        ),
        (
            initial_snapshot.counters.downlink_binding_family_mismatches,
            COUNTER_DL_BINDING_FAMILY_MISMATCH,
        ),
        (
            initial_snapshot.counters.downlink_binding_peer_mismatches,
            COUNTER_DL_BINDING_PEER_MISMATCH,
        ),
        (
            initial_snapshot.counters.downlink_binding_local_mismatches,
            COUNTER_DL_BINDING_LOCAL_MISMATCH,
        ),
        (
            initial_snapshot
                .counters
                .downlink_binding_ingress_mismatches,
            COUNTER_DL_BINDING_INGRESS_MISMATCH,
        ),
        (
            initial_snapshot
                .counters
                .downlink_binding_source_port_mismatches,
            COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH,
        ),
    ] {
        assert_eq!(
            reported,
            pinned_binding_counter(&marked_pin_dir, index),
            "the public snapshot must aggregate the exact fixed binding counter map",
        );
    }

    // A second live reconciler must not interleave map operations with the
    // current owner. The host-global persistent control-directory flock,
    // keyed by canonical pin namespace, makes this work across independent
    // backend instances and processes.
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

    // Aya exposes an absent BPF hash delete as syscall ENOENT, not
    // MapError::KeyNotFound. Prove a default bearer that never had optional
    // DSCP state still removes cleanly after its FAR delete.
    let mut no_dscp_removal = session_context(device.ifindex);
    no_dscp_removal.local_teid = Teid::new(0x1000_0010).expect("nonzero local TEID");
    no_dscp_removal.peer_teid = Teid::new(0x2000_0010).expect("nonzero peer TEID");
    no_dscp_removal.ms_address = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 3));
    backend.install_pdp_context(no_dscp_removal.clone()).await?;
    let no_dscp_remove = RemovePdpContextRequest::from_context(&no_dscp_removal);
    backend.remove_pdp_context(no_dscp_remove.clone()).await?;
    backend.remove_pdp_context(no_dscp_remove).await?;

    // Sockets living in the peer namespaces.
    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let pgw_wrong_peer_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_ALT_IP, GTPU_PORT)).expect("bind alternate-peer GTP-U socket")
    });
    let pgw_wrong_source_port_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT + 1)).expect("bind alternate-port GTP-U socket")
    });
    let pgw_plaintext_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((REMOTE_HOST, 53)).expect("bind PGW plaintext-leak detector")
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5000)).expect("bind UE socket")
    });
    let ue_mark_a_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5001)).expect("bind mark-A UE socket")
    });
    let ue_mark_b_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5002)).expect("bind mark-B UE socket")
    });
    let ue_unknown_mark_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5003)).expect("bind unknown-mark UE socket")
    });
    let ue_xfrm_mark_a_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, XFRM_INNER_SOURCE_PORT)).expect("bind XFRM mark-A UE socket")
    });
    // Local control-plane socket that must still see non-G-PDU GTP-U.
    let epdg_cp_socket = UdpSocket::bind((EPDG_S2BU_IP, GTPU_PORT))?;

    exercise_outer_envelope_validation(&net, &backend, &device, &ue_socket).await;

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

    // Two dedicated bearers share the same PAA but select distinct exact
    // marked FARs. Arrival also proves the consumed mark was cleared before
    // neighbour redirect; otherwise the re-emitted outer packet would hit a
    // nonzero FAR miss for the local S2b-U source and self-drop.
    let bearer_a = dedicated_session_context(device.ifindex, MARK_A, LOCAL_TEID_A, PEER_TEID_A);
    let bearer_b = dedicated_session_context(device.ifindex, MARK_B, LOCAL_TEID_B, PEER_TEID_B);
    backend.install_pdp_context(bearer_a.clone()).await?;
    backend.install_pdp_context(bearer_b.clone()).await?;

    // Reproduce SDK #269's exact kernel signature: a committed Removing
    // owner with its marked FAR already absent. The first install attempt
    // must finish the old removal without claiming the bearer is present or
    // resurrecting it in the same call; the next attempt publishes a fresh
    // Active owner/FAR pair.
    set_marked_owner_phase(&marked_pin_dir, MARK_B, MarkedBearerOwnerPhase::Removing);
    let removed_far = UplinkFar::decode(&take_marked_far(&marked_pin_dir, MARK_B));
    assert_eq!(removed_far.o_teid, PEER_TEID_B.to_be_bytes());
    let recovery = backend
        .install_pdp_context(bearer_b.clone())
        .await
        .expect_err("Removing owner must require a fresh install retry");
    assert!(
        matches!(
            &recovery,
            GtpuError::RetryRequired {
                operation: "ebpf_install_after_removal"
            }
        ),
        "unexpected recovery result: {recovery:?}"
    );
    backend.install_pdp_context(bearer_b.clone()).await?;

    // Exercise the production boundary omitted by the tc-injected cases
    // below: the peer emits a real tunnel-mode ESP packet, the SDK-installed
    // inbound SA decrypts it and applies its full-width output mark, Linux
    // forwards the inner packet, and tc egress must select the dedicated FAR.
    let _epdg_nat_t_socket = nat_t_socket(EPDG_SWU_IP);
    let _ue_nat_t_socket = in_netns(&net.ue_ns, || nat_t_socket(UE_SWU_IP));
    install_real_marked_inbound_xfrm(&net.ue_ns).await?;
    drain_datagrams(&pgw_socket);
    let xfrm_uplink_encap_before = backend
        .datapath_snapshot(&device)
        .await?
        .counters
        .uplink_encapsulated;
    let (len, from) = send_until_received(
        || {
            let _ = ue_xfrm_mark_a_socket.send_to(
                b"opc-xfrm-mark-a",
                (REMOTE_HOST, XFRM_INNER_DESTINATION_PORT),
            );
        },
        &pgw_socket,
        &mut buffer,
    )
    .unwrap_or_else(|| {
        panic!(
            "decrypted ESP uplink must select the dedicated FAR\nxfrm-state={}\nxfrm-policy={}\ntc={}",
            command_stdout("ip", &["-s", "xfrm", "state"]),
            command_stdout("ip", &["-s", "xfrm", "policy"]),
            command_stdout("tc", &["-s", "filter", "show", "dev", "s2bu", "egress"]),
        )
    });
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
    assert_eq!(
        u32::from_be_bytes(buffer[4..8].try_into().expect("GTP-U TEID bytes")),
        PEER_TEID_A,
        "the post-decrypt mark must select the dedicated uplink TEID",
    );
    assert!(buffer[..len].ends_with(b"opc-xfrm-mark-a"));
    assert!(
        backend
            .datapath_snapshot(&device)
            .await?
            .counters
            .uplink_encapsulated
            > xfrm_uplink_encap_before,
        "the committed per-CPU counter must observe the ESP-decrypted marked encapsulation",
    );

    // Prove the reverse production boundary with two otherwise-identical OUT
    // policies and SAs. A dedicated G-PDU must be decapsulated, stamped with
    // MARK_A, and encrypted under the marked SA rather than the default SA.
    install_real_marked_outbound_xfrm().await?;
    let outbound_capture = packet_capture_socket(&net.ue_ns);
    let xfrm_downlink_decap_before = backend
        .datapath_snapshot(&device)
        .await?
        .counters
        .downlink_decapsulated;
    let xfrm_downlink_inner = build_inner_udp(
        REMOTE_HOST,
        UE_PAA,
        XFRM_DOWNLINK_SOURCE_PORT,
        XFRM_DOWNLINK_DESTINATION_PORT,
        b"opc-xfrm-downlink-mark-a",
    );
    let xfrm_downlink_gpdu = build_gpdu(LOCAL_TEID_A, None, &xfrm_downlink_inner);
    pgw_socket.send_to(&xfrm_downlink_gpdu, (EPDG_S2BU_IP, GTPU_PORT))?;
    assert_eq!(
        capture_nat_t_esp_spi(&outbound_capture),
        OUTBOUND_SPI_A,
        "the marked downlink must select the dedicated outbound Child SA",
    );
    assert!(
        backend
            .datapath_snapshot(&device)
            .await?
            .counters
            .downlink_decapsulated
            > xfrm_downlink_decap_before,
        "the committed per-CPU counter must observe the marked GTP-U decapsulation",
    );

    for (socket, payload, expected_teid) in [
        (&ue_mark_a_socket, b"opc-mark-a".as_slice(), PEER_TEID_A),
        (&ue_mark_b_socket, b"opc-mark-b".as_slice(), PEER_TEID_B),
    ] {
        drain_datagrams(&pgw_socket);
        let (len, from) = send_until_received(
            || {
                let _ = socket.send_to(payload, (REMOTE_HOST, 53));
            },
            &pgw_socket,
            &mut buffer,
        )
        .expect("marked uplink G-PDU must reach the PGW");
        assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
        assert_eq!(
            u32::from_be_bytes(buffer[4..8].try_into().expect("GTP-U TEID bytes")),
            expected_teid
        );
        assert!(buffer[..len].ends_with(payload));
    }

    // An unknown nonzero mark is fail-closed. Prove both sides of the
    // boundary: no GTP-U packet and no raw inner UDP packet leaks to the PGW.
    drain_datagrams(&pgw_socket);
    drain_datagrams(&pgw_plaintext_socket);
    for _ in 0..3 {
        ue_unknown_mark_socket.send_to(b"must-not-leak", (REMOTE_HOST, 53))?;
    }
    expect_no_datagram(&pgw_socket);
    expect_no_datagram(&pgw_plaintext_socket);

    // A non-G-PDU retains the priority-10 injected outer sentinel and passes
    // to the local control plane. This exact-mark INPUT gate proves the
    // injector matched before the default G-PDU test relies on the SDK
    // overwriting the same sentinel with zero.
    net.require_input_mark(OUTER_SENTINEL_MARK);
    let echo_request: [u8; 12] = [0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0x00, 0x2A, 0x00, 0x00];
    let (len, from) = send_until_received(
        || {
            let _ = pgw_socket.send_to(&echo_request, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &epdg_cp_socket,
        &mut buffer,
    )
    .expect("GTP-U echo must retain the injected mark and reach the control plane");
    assert_eq!(&buffer[..len], &echo_request);
    assert_eq!(from, SocketAddr::from((PGW_IP, GTPU_PORT)));
    net.allow_all_input_marks();

    // --- Downlink: G-PDU on our I-TEID must decap and forward to the UE. ---
    // Give every outer G-PDU a distinct infrastructure mark. The nft forward
    // gate accepts exactly the expected post-decap mark, proving that the
    // default PDR clears to zero and marked PDRs overwrite with A/B.
    net.require_forward_mark(0);
    let inner_downlink = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"opc-downlink");
    let gpdu_downlink = build_gpdu(LOCAL_TEID, None, &inner_downlink);
    let default_downlink = send_until_received(
        || {
            let _ = pgw_socket.send_to(&gpdu_downlink, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &ue_socket,
        &mut buffer,
    );
    let (len, from) = default_downlink.unwrap_or_else(|| {
        panic!(
            "downlink inner packet must be forwarded to the UE\ntc={}\nnft={}",
            command_stdout("tc", &["-s", "filter", "show", "dev", "s2bu", "ingress"]),
            command_stdout("nft", &["list", "chain", "inet", &net.nft_table, "forward"])
        )
    });
    assert_eq!(&buffer[..len], b"opc-downlink");
    assert_eq!(from, SocketAddr::from((REMOTE_HOST, 53)));

    // Every provenance dimension is independently fail-closed and reported
    // through one fixed-cardinality aggregate. No diagnostic includes the
    // rejected endpoint, port, TEID, or UE address.
    let binding_counters_before = backend.datapath_snapshot(&device).await?.counters;
    drain_datagrams(&ue_socket);
    for _ in 0..3 {
        pgw_wrong_peer_socket.send_to(&gpdu_downlink, (EPDG_S2BU_IP, GTPU_PORT))?;
    }
    expect_no_datagram(&ue_socket);

    drain_datagrams(&ue_socket);
    for _ in 0..3 {
        pgw_socket.send_to(&gpdu_downlink, (EPDG_S2BU_ALT_IP, GTPU_PORT))?;
    }
    expect_no_datagram(&ue_socket);

    drain_datagrams(&ue_socket);
    for _ in 0..3 {
        pgw_wrong_source_port_socket.send_to(&gpdu_downlink, (EPDG_S2BU_IP, GTPU_PORT))?;
    }
    expect_no_datagram(&ue_socket);

    let canonical_binding = replace_pinned_binding(&marked_pin_dir, LOCAL_TEID, None)
        .expect("installed default binding");
    drain_datagrams(&ue_socket);
    for _ in 0..3 {
        pgw_socket.send_to(&gpdu_downlink, (EPDG_S2BU_IP, GTPU_PORT))?;
    }
    expect_no_datagram(&ue_socket);
    replace_pinned_binding(&marked_pin_dir, LOCAL_TEID, Some(canonical_binding));

    let ipv6_binding = DownlinkEndpointBinding::new(
        GtpuEndpointAddress::Ipv6([1; 16]),
        GtpuEndpointAddress::Ipv6([2; 16]),
        device.ifindex,
        GtpuSourcePortPolicy::Exact(GTPU_PORT),
    )
    .expect("canonical IPv6 binding")
    .encode();
    replace_pinned_binding(&marked_pin_dir, LOCAL_TEID, Some(ipv6_binding));
    drain_datagrams(&ue_socket);
    for _ in 0..3 {
        pgw_socket.send_to(&gpdu_downlink, (EPDG_S2BU_IP, GTPU_PORT))?;
    }
    expect_no_datagram(&ue_socket);
    replace_pinned_binding(&marked_pin_dir, LOCAL_TEID, Some(canonical_binding));

    let wrong_ingress_binding = DownlinkEndpointBinding::new(
        GtpuEndpointAddress::Ipv4(PGW_IP.octets()),
        GtpuEndpointAddress::Ipv4(EPDG_S2BU_IP.octets()),
        device.ifindex + 1,
        GtpuSourcePortPolicy::Exact(GTPU_PORT),
    )
    .expect("canonical alternate-ingress binding")
    .encode();
    replace_pinned_binding(&marked_pin_dir, LOCAL_TEID, Some(wrong_ingress_binding));
    drain_datagrams(&ue_socket);
    for _ in 0..3 {
        pgw_socket.send_to(&gpdu_downlink, (EPDG_S2BU_IP, GTPU_PORT))?;
    }
    expect_no_datagram(&ue_socket);
    replace_pinned_binding(&marked_pin_dir, LOCAL_TEID, Some(canonical_binding));

    let binding_counters_after = backend.datapath_snapshot(&device).await?.counters;
    for (before, after, reason) in [
        (
            binding_counters_before.downlink_binding_invalid,
            binding_counters_after.downlink_binding_invalid,
            "invalid",
        ),
        (
            binding_counters_before.downlink_binding_family_mismatches,
            binding_counters_after.downlink_binding_family_mismatches,
            "family",
        ),
        (
            binding_counters_before.downlink_binding_peer_mismatches,
            binding_counters_after.downlink_binding_peer_mismatches,
            "peer",
        ),
        (
            binding_counters_before.downlink_binding_local_mismatches,
            binding_counters_after.downlink_binding_local_mismatches,
            "local",
        ),
        (
            binding_counters_before.downlink_binding_ingress_mismatches,
            binding_counters_after.downlink_binding_ingress_mismatches,
            "ingress",
        ),
        (
            binding_counters_before.downlink_binding_source_port_mismatches,
            binding_counters_after.downlink_binding_source_port_mismatches,
            "source-port",
        ),
    ] {
        assert!(after > before, "{reason} binding counter must advance");
    }

    let (len, _) = send_until_received(
        || {
            let _ = pgw_socket.send_to(&gpdu_downlink, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &ue_socket,
        &mut buffer,
    )
    .expect("restoring the exact binding must resume downlink");
    assert_eq!(&buffer[..len], b"opc-downlink");

    for (expected_mark, local_teid, payload) in [
        (MARK_A, LOCAL_TEID_A, b"opc-downlink-mark-a".as_slice()),
        (MARK_B, LOCAL_TEID_B, b"opc-downlink-mark-b".as_slice()),
    ] {
        net.require_forward_mark(expected_mark);
        let inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, payload);
        let gpdu = build_gpdu(local_teid, None, &inner);
        let (len, from) = send_until_received(
            || {
                let _ = pgw_socket.send_to(&gpdu, (EPDG_S2BU_IP, GTPU_PORT));
            },
            &ue_socket,
            &mut buffer,
        )
        .expect("downlink must carry the exact dedicated-bearer mark");
        assert_eq!(&buffer[..len], payload);
        assert_eq!(from, SocketAddr::from((REMOTE_HOST, 53)));
    }

    // The durable owner is the forwarding commit point, not merely loader
    // metadata. Pending and Removing must gate both directions even while
    // every FAR/DSCP/PDR entry remains present and exact.
    let owner_pin_dir = net.pin_root.join("s2bu");
    let gated_downlink_inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"owner-phase-gate");
    let gated_downlink_gpdu = build_gpdu(LOCAL_TEID_A, None, &gated_downlink_inner);
    for phase in [
        MarkedBearerOwnerPhase::Pending,
        MarkedBearerOwnerPhase::Removing,
    ] {
        set_marked_owner_phase(&owner_pin_dir, MARK_A, phase);

        drain_datagrams(&pgw_socket);
        drain_datagrams(&pgw_plaintext_socket);
        for _ in 0..3 {
            ue_mark_a_socket.send_to(b"owner-phase-uplink", (REMOTE_HOST, 53))?;
        }
        expect_no_datagram(&pgw_socket);
        expect_no_datagram(&pgw_plaintext_socket);

        net.require_forward_mark(MARK_A);
        drain_datagrams(&ue_socket);
        for _ in 0..3 {
            pgw_socket.send_to(&gated_downlink_gpdu, (EPDG_S2BU_IP, GTPU_PORT))?;
        }
        expect_no_datagram(&ue_socket);
    }

    set_marked_owner_phase(&owner_pin_dir, MARK_A, MarkedBearerOwnerPhase::Active);
    drain_datagrams(&pgw_socket);
    let (len, _) = send_until_received(
        || {
            let _ = ue_mark_a_socket.send_to(b"owner-active-uplink", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("restored Active owner must resume marked uplink");
    assert_eq!(
        u32::from_be_bytes(buffer[4..8].try_into().expect("GTP-U TEID bytes")),
        PEER_TEID_A
    );
    assert!(buffer[..len].ends_with(b"owner-active-uplink"));
    net.require_forward_mark(MARK_A);
    drain_datagrams(&ue_socket);
    let (len, _) = send_until_received(
        || {
            let _ = pgw_socket.send_to(&gated_downlink_gpdu, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &ue_socket,
        &mut buffer,
    )
    .expect("restored Active owner must resume marked downlink");
    assert_eq!(&buffer[..len], b"owner-phase-gate");
    net.require_forward_mark(0);

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

    net.allow_all_forward_marks();

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

    let adopted_default = marked_session_context(adopted.ifindex);
    let adopted_marked =
        dedicated_session_context(adopted.ifindex, MARK_A, LOCAL_TEID_A, PEER_TEID_A);
    for expected in [&adopted_default, &adopted_marked] {
        assert_eq!(
            restored
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(expected)
                        .ok_or("local selector requires nonzero ifindex")?,
                ))
                .await?,
            PdpContextReadback::Present(expected.clone())
        );
        assert_eq!(
            restored
                .read_pdp_context(PdpContextSelector::Uplink(
                    PdpContextUplinkSelector::from_context(expected)
                        .ok_or("uplink selector requires canonical context")?,
                ))
                .await?,
            PdpContextReadback::Present(expected.clone())
        );
        assert_eq!(
            restored
                .install_pdp_context_classified(expected.clone())
                .await?,
            PdpContextInstallOutcome::ExactAlreadyPresent
        );
    }

    for expected in [&adopted_default, &adopted_marked] {
        let mut uplink_collision = expected.clone();
        uplink_collision.local_teid =
            Teid::new(expected.local_teid.get() + 0x100).ok_or("conflict TEID must be nonzero")?;
        uplink_collision.peer_teid =
            Teid::new(expected.peer_teid.get() + 0x100).ok_or("conflict TEID must be nonzero")?;
        assert!(matches!(
            restored
                .install_pdp_context_classified(uplink_collision)
                .await?,
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == PdpContextSelectorOccupancy::Uplink
        ));

        let mut local_collision = expected.clone();
        local_collision.ms_address = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 99));
        local_collision.peer_address = IpAddr::V4(PGW_ALT_IP);
        assert!(matches!(
            restored
                .install_pdp_context_classified(local_collision)
                .await?,
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == PdpContextSelectorOccupancy::LocalTeid
        ));
    }

    let saved_binding = replace_pinned_binding(&marked_pin_dir, LOCAL_TEID, None)
        .ok_or("default binding must exist before corruption proof")?;
    assert!(matches!(
        restored
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&adopted_default)
                    .ok_or("local selector requires nonzero ifindex")?,
            ))
            .await,
        Err(GtpuError::StateIndeterminate { .. })
    ));
    assert_eq!(
        restored
            .install_pdp_context_classified(adopted_default.clone())
            .await?,
        PdpContextInstallOutcome::Indeterminate(PdpContextIndeterminateReason::IncompleteState)
    );
    let _ = replace_pinned_binding(&marked_pin_dir, LOCAL_TEID, Some(saved_binding));

    set_marked_owner_phase(&marked_pin_dir, MARK_A, MarkedBearerOwnerPhase::Pending);
    assert!(matches!(
        restored
            .read_pdp_context(PdpContextSelector::Uplink(
                PdpContextUplinkSelector::from_context(&adopted_marked)
                    .ok_or("uplink selector requires canonical context")?,
            ))
            .await,
        Err(GtpuError::StateIndeterminate { .. })
    ));
    assert_eq!(
        restored
            .install_pdp_context_classified(adopted_marked.clone())
            .await?,
        PdpContextInstallOutcome::Indeterminate(PdpContextIndeterminateReason::IncompleteState)
    );
    set_marked_owner_phase(&marked_pin_dir, MARK_A, MarkedBearerOwnerPhase::Active);

    for expected in [&adopted_default, &adopted_marked] {
        assert_eq!(
            restored.remove_pdp_context_exact(expected.clone()).await?,
            PdpContextRemovalOutcome::Removed
        );
        assert_eq!(
            restored
                .install_pdp_context_classified(expected.clone())
                .await?,
            PdpContextInstallOutcome::Installed
        );
    }
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

    // --- Populated endpoint-unbound v1 rejection and config preservation. ---
    // Build the exact prior-generation state: five retained pins, committed
    // v1 marker, populated default session, and both old tc programs live.
    let v1_pin_dir = net.pin_root.join("s2bu");
    let (v1_uplink_id, v1_downlink_id) = install_frozen_v1_datapath(&v1_pin_dir);
    let retained_map_ids = frozen_v1_map_ids(&v1_pin_dir);
    assert_eq!(pinned_config(&v1_pin_dir), EPDG_S2BU_IP.octets());
    assert_eq!(
        pinned_schema_marker(&v1_pin_dir),
        UPLINK_DSCP_SCHEMA_MARKER_VALUE
    );
    assert_eq!(tc_program_id("egress"), v1_uplink_id);
    assert_eq!(tc_program_id("ingress"), v1_downlink_id);

    // A create request with a different retained local address must fail
    // before any config, marker, map-ID, or hook mutation. Loading the current
    // object may create its additive empty pins, which is safe and expected.
    let rejected_migration =
        EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..EbpfGtpuDataplaneBackendConfig::default()
        });
    let mut conflicting_request = CreateGtpDeviceRequest::new("s2bu");
    conflicting_request.bind_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
    assert!(matches!(
        rejected_migration.create_device(conflicting_request).await,
        Err(opc_gtpu_dataplane::GtpuError::AlreadyExists)
    ));
    drop(rejected_migration);
    assert_eq!(pinned_config(&v1_pin_dir), EPDG_S2BU_IP.octets());
    assert_eq!(
        pinned_schema_marker(&v1_pin_dir),
        UPLINK_DSCP_SCHEMA_MARKER_VALUE,
        "rejected create must not advance the durable marker"
    );
    assert_eq!(frozen_v1_map_ids(&v1_pin_dir), retained_map_ids);
    assert_eq!(tc_program_id("egress"), v1_uplink_id);
    assert_eq!(tc_program_id("ingress"), v1_downlink_id);

    // The rejected migration must leave the actual v1 forwarding service
    // intact. Its FAR deliberately uses local_ip=0, so this packet also proves
    // the retained config value was not overwritten.
    drain_datagrams(&pgw_socket);
    let (len, from) = send_until_received(
        || {
            let _ = ue_socket.send_to(b"opc-v1-after-reject", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("frozen v1 uplink must survive rejected migration");
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
    assert_eq!(
        u32::from_be_bytes(buffer[4..8].try_into().expect("v1 TEID bytes")),
        PEER_TEID
    );
    assert!(buffer[..len].ends_with(b"opc-v1-after-reject"));

    let v1_inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"opc-v1-downlink");
    let v1_gpdu = build_gpdu(LOCAL_TEID, None, &v1_inner);
    let (len, _) = send_until_received(
        || {
            let _ = pgw_socket.send_to(&v1_gpdu, (EPDG_S2BU_IP, GTPU_PORT));
        },
        &ue_socket,
        &mut buffer,
    )
    .expect("frozen v1 downlink must survive rejected migration");
    assert_eq!(&buffer[..len], b"opc-v1-downlink");

    // A populated endpoint-unbound v1 graph cannot be inferred as `Any` and
    // upgraded silently. Adoption must reject it before replacing either
    // live v1 hook or advancing the schema marker. Draining/reprovisioning is
    // the explicit operator-safe migration for these old pins.
    let rejected_endpoint_migration =
        EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..EbpfGtpuDataplaneBackendConfig::default()
        });
    assert!(matches!(
        rejected_endpoint_migration.resolve_device("s2bu").await,
        Err(GtpuError::StateIndeterminate {
            operation: "ebpf_marked_owner_rebuild"
        })
    ));
    drop(rejected_endpoint_migration);
    assert_eq!(frozen_v1_map_ids(&v1_pin_dir), retained_map_ids);
    assert_eq!(
        pinned_schema_marker(&v1_pin_dir),
        UPLINK_DSCP_SCHEMA_MARKER_VALUE,
        "failed adoption must not claim endpoint-bound schema"
    );
    assert_eq!(tc_program_id("egress"), v1_uplink_id);
    assert_eq!(tc_program_id("ingress"), v1_downlink_id);
    for direction in ["egress", "ingress"] {
        run(
            "tc",
            &[
                "filter", "del", "dev", "s2bu", direction, "handle", "0x1", "pref", "50", "bpf",
            ],
        );
    }
    fs::remove_dir_all(&v1_pin_dir).expect("drain endpoint-unbound v1 pins");

    // --- Explicit drained bearer-v2 teardown before source-port-v4. ---
    // A map-only same-shape namespace has no positive program-to-map binding
    // and must never be accepted as SDK-owned.
    create_drained_legacy_v2_pins(&v1_pin_dir);
    let v2_maintenance = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    assert_eq!(
        v2_maintenance
            .teardown_drained_v2(drained_v2_request(adopted.ifindex))
            .await?,
        DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
    );
    assert!(v1_pin_dir.exists(), "unproven pins must survive refusal");
    assert!(
        !v1_pin_dir.join("GTPU_V2_TEARDOWN").exists(),
        "hook identity refusal must precede proof mutation"
    );
    fs::remove_dir_all(&v1_pin_dir).expect("remove unproven map-only graph");

    // The exact hash-pinned historical object is loaded only in this isolated
    // qualification netns. No traffic is sent while either v2 program is
    // attached. Production parses these bytes solely as identity authority.
    let (v2_uplink_id, v2_downlink_id) = install_drained_frozen_v2_datapath(&v1_pin_dir);
    assert_eq!(tc_program_id("egress"), v2_uplink_id);
    assert_eq!(tc_program_id("ingress"), v2_downlink_id);
    let replaced_pin = v1_pin_dir.join(MAP_MARKED_BEARER_OWNER);
    fs::remove_file(&replaced_pin).expect("remove exact owner pin before replacement");
    let replacement_id = {
        let replacement = Array::<MapData, [u8; LEGACY_V2_OWNER_VALUE_LEN]>::create(1, 0)
            .expect("create ABI-incompatible replacement pin");
        replacement
            .pin(&replaced_pin)
            .expect("pin ABI-incompatible replacement");
        MapInfo::from_pin(&replaced_pin)
            .expect("replacement pin info")
            .id()
    };
    assert_eq!(
        v2_maintenance
            .teardown_drained_v2(drained_v2_request(adopted.ifindex))
            .await?,
        DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
    );
    assert_eq!(
        MapInfo::from_pin(&replaced_pin)
            .expect("foreign replacement pin must survive")
            .id(),
        replacement_id
    );
    assert!(v1_pin_dir.exists(), "refusal must preserve the v2 graph");
    assert_eq!(tc_program_id("egress"), v2_uplink_id);
    assert_eq!(tc_program_id("ingress"), v2_downlink_id);
    for direction in ["egress", "ingress"] {
        run(
            "tc",
            &[
                "filter", "del", "dev", "s2bu", direction, "handle", "0x1", "pref", "50", "bpf",
            ],
        );
    }
    fs::remove_dir_all(&v1_pin_dir).expect("remove negative replacement graph");

    let (_v2_uplink_id, v2_downlink_id) = install_drained_frozen_v2_datapath(&v1_pin_dir);
    run(
        "tc",
        &[
            "filter", "del", "dev", "s2bu", "egress", "handle", "0x1", "pref", "50", "bpf",
        ],
    );
    run(
        "tc",
        &[
            "filter", "add", "dev", "s2bu", "egress", "handle", "0x1", "pref", "50", "protocol",
            "all", "matchall", "action", "pass",
        ],
    );
    assert_eq!(
        v2_maintenance
            .teardown_drained_v2(drained_v2_request(adopted.ifindex))
            .await?,
        DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
    );
    assert!(
        tc_filters("egress").contains("matchall"),
        "foreign exact-slot hook must survive v2 teardown refusal"
    );
    assert_eq!(tc_program_id("ingress"), v2_downlink_id);
    assert!(
        !v1_pin_dir.join("GTPU_V2_TEARDOWN").exists(),
        "identity refusal must precede teardown-proof mutation"
    );
    run(
        "tc",
        &[
            "filter", "del", "dev", "s2bu", "egress", "handle", "0x1", "pref", "50", "protocol",
            "all", "matchall",
        ],
    );
    run(
        "tc",
        &[
            "filter", "del", "dev", "s2bu", "ingress", "handle", "0x1", "pref", "50", "bpf",
        ],
    );
    fs::remove_dir_all(&v1_pin_dir).expect("remove negative foreign-hook graph");

    let (v2_uplink_id, v2_downlink_id) = install_drained_frozen_v2_datapath(&v1_pin_dir);
    {
        let map = Map::from_map_data(
            MapData::from_pin(v1_pin_dir.join(MAP_UPLINK_FAR))
                .expect("open legacy v2 FAR for population"),
        )
        .expect("identify legacy v2 FAR");
        let mut far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
            .expect("typed legacy v2 FAR");
        far.insert(UE_PAA.octets(), [0x5a; UPLINK_FAR_VALUE_LEN], 0)
            .expect("populate legacy v2 FAR");
    }
    let v2_maintenance = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    assert_eq!(
        v2_maintenance
            .teardown_drained_v2(drained_v2_request(adopted.ifindex))
            .await?,
        DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::PopulatedState)
    );
    {
        let map = Map::from_map_data(
            MapData::from_pin(v1_pin_dir.join(MAP_UPLINK_FAR))
                .expect("reopen populated legacy v2 FAR"),
        )
        .expect("identify populated legacy v2 FAR");
        let mut far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
            .expect("typed populated legacy v2 FAR");
        assert_eq!(
            far.get(&UE_PAA.octets(), 0)
                .expect("populated entry must survive refusal"),
            [0x5a; UPLINK_FAR_VALUE_LEN]
        );
        far.remove(&UE_PAA.octets())
            .expect("drain populated legacy v2 FAR");
    }
    assert_eq!(tc_program_id("egress"), v2_uplink_id);
    assert_eq!(tc_program_id("ingress"), v2_downlink_id);

    assert_eq!(
        v2_maintenance
            .teardown_drained_v2(drained_v2_request(adopted.ifindex))
            .await?,
        DrainedV2TeardownOutcome::Removed
    );
    assert_eq!(
        v2_maintenance
            .teardown_drained_v2(drained_v2_request(adopted.ifindex))
            .await?,
        DrainedV2TeardownOutcome::AlreadyAbsent
    );
    assert!(!v1_pin_dir.exists(), "all v2 pins must be removed");
    assert!(!tc_filters("egress").contains(PROG_UPLINK));
    assert!(!tc_filters("ingress").contains(PROG_DOWNLINK));

    let mut current_request = CreateGtpDeviceRequest::new("s2bu");
    current_request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let current_device = v2_maintenance.create_device(current_request).await?;
    assert!(
        v1_pin_dir.join(MAP_DOWNLINK_ENDPOINT_BINDING).exists(),
        "fresh provisioning after v2 teardown must create the endpoint-binding pin"
    );
    assert!(
        v1_pin_dir.join(MAP_UPLINK_SOURCE_PORT).exists()
            && v1_pin_dir.join(MAP_UPLINK_MARK_SOURCE_PORT).exists(),
        "fresh provisioning after v2 teardown must create source-port-v4 pins"
    );
    assert!(
        v1_pin_dir.join(MAP_UPLINK_PMTU).exists()
            && v1_pin_dir.join(MAP_UPLINK_PMTU_COUNTERS).exists(),
        "fresh provisioning after v2 teardown must create the MTU policy pins"
    );
    assert_eq!(
        pinned_schema_marker(&v1_pin_dir),
        UPLINK_PMTU_SCHEMA_MARKER_VALUE,
        "fresh provisioning after v2 teardown must commit the current v5 schema"
    );
    v2_maintenance.remove_device(&current_device).await?;
    drop(v2_maintenance);

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
    let replacement_probe = replacement_owner.probe().await?;
    assert_eq!(
        replacement_probe.egress_dscp_marking,
        GtpuCapability::Missing
    );
    assert_eq!(
        replacement_probe.downlink_endpoint_binding,
        GtpuCapability::Missing
    );
    assert!(matches!(
        replacement_owner
            .install_pdp_context(marked_session_context(replacement_device.ifindex))
            .await,
        Err(opc_gtpu_dataplane::GtpuError::Io {
            operation: "ebpf_downlink_endpoint_datapath",
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
            operation: "ebpf_bearer_schema",
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

const SELECTED_SOURCE_PORT: u16 = 40_000;

#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_uplink_selected_source_port_on_the_wire(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    let pin_dir = net.pin_root.join("s2bu");
    assert_eq!(
        backend.probe().await?.uplink_source_port_selection,
        GtpuCapability::Available,
        "loaded datapath must expose usable source-port maps"
    );

    let mut selected = session_context(device.ifindex);
    selected.uplink_source_port_policy =
        GtpuUplinkSourcePortPolicy::selected(SELECTED_SOURCE_PORT).expect("nonzero selected port");
    backend.install_pdp_context(selected.clone()).await?;

    // This socket is bound to the fixed TS 29.281 destination service port;
    // receiving here at all proves the destination stayed 2152.
    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5000)).expect("bind UE socket")
    });

    let mut buffer = [0_u8; 2048];
    let (len, from) = send_until_received(
        || {
            let _ = ue_socket.send_to(b"opc-uplink-sport", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("selected-source-port uplink G-PDU must reach the PGW");
    assert_eq!(
        from,
        SocketAddr::from((EPDG_S2BU_IP, SELECTED_SOURCE_PORT)),
        "outer UDP source must be the selected per-context port"
    );
    assert!(buffer[..len].ends_with(b"opc-uplink-sport"));

    // Missing policy is corrupt committed v4 state: it must drop rather than
    // silently transition this selected context to legacy 2152.
    let committed = take_pinned_source_port(&pin_dir);
    let encap_before = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    for _ in 0..3 {
        let _ = ue_socket.send_to(b"opc-uplink-missing-policy", (REMOTE_HOST, 53));
    }
    expect_no_datagram(&pgw_socket);
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_UL_ENCAP),
        encap_before,
        "a missing source-port policy must drop before encapsulation accounting"
    );

    // Restore the captured exact authority before testing a separately
    // corrupted policy. Missing authority is intentionally not reconstructed
    // from component maps by the backend.
    replace_pinned_source_port(&pin_dir, committed);
    let mut zero_port = committed;
    zero_port[64] = 0;
    zero_port[65] = 0;
    replace_pinned_source_port(&pin_dir, zero_port);
    let encap_before = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    for _ in 0..3 {
        let _ = ue_socket.send_to(b"opc-uplink-dropped", (REMOTE_HOST, 53));
    }
    expect_no_datagram(&pgw_socket);
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_UL_ENCAP),
        encap_before,
        "a zero source-port entry must drop before encapsulation accounting"
    );

    // Restoring the record alone is insufficient: uplink authorization also
    // requires the exact downlink half of the same committed graph.
    replace_pinned_source_port(&pin_dir, committed);
    let committed_binding = replace_pinned_binding(&pin_dir, LOCAL_TEID, None)
        .ok_or("default binding must exist before whole-graph proof")?;
    let encap_before = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    for _ in 0..3 {
        let _ = ue_socket.send_to(b"opc-uplink-missing-binding", (REMOTE_HOST, 53));
    }
    expect_no_datagram(&pgw_socket);
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_UL_ENCAP),
        encap_before,
        "an incomplete downlink binding must gate uplink before encapsulation"
    );
    replace_pinned_binding(&pin_dir, LOCAL_TEID, Some(committed_binding));

    let committed_pdr = replace_pinned_default_pdr(&pin_dir, LOCAL_TEID, None)
        .ok_or("default PDR must exist before whole-graph proof")?;
    let encap_before = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    for _ in 0..3 {
        let _ = ue_socket.send_to(b"opc-uplink-missing-pdr", (REMOTE_HOST, 53));
    }
    expect_no_datagram(&pgw_socket);
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_UL_ENCAP),
        encap_before,
        "an incomplete downlink PDR must gate uplink before encapsulation"
    );
    replace_pinned_default_pdr(&pin_dir, LOCAL_TEID, Some(committed_pdr));

    // The complete restored graph is authoritative again; an exact backend
    // retry is then idempotent.
    backend.install_pdp_context(selected).await?;
    let (len, from) = send_until_received(
        || {
            let _ = ue_socket.send_to(b"opc-uplink-sport-restored", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("reconciled uplink G-PDU must reach the PGW again");
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, SELECTED_SOURCE_PORT)));
    assert!(buffer[..len].ends_with(b"opc-uplink-sport-restored"));

    drop(net);
    Ok(())
}

fn pinned_pmtu_policy(pin_dir: &std::path::Path) -> [u8; UPLINK_PMTU_VALUE_LEN] {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_PMTU)).expect("open pinned MTU policy map"),
    )
    .expect("identify pinned MTU policy map");
    let policy = Array::<_, [u8; UPLINK_PMTU_VALUE_LEN]>::try_from(map)
        .expect("typed pinned MTU policy map");
    policy.get(&0, 0).expect("read pinned MTU policy")
}

fn replace_pinned_pmtu_policy(pin_dir: &std::path::Path, value: [u8; UPLINK_PMTU_VALUE_LEN]) {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_PMTU)).expect("open pinned MTU policy map"),
    )
    .expect("identify pinned MTU policy map");
    let mut policy = Array::<_, [u8; UPLINK_PMTU_VALUE_LEN]>::try_from(map)
        .expect("typed pinned MTU policy map");
    policy.set(0, value, 0).expect("replace pinned MTU policy");
}

fn pinned_pmtu_drop_counter(pin_dir: &std::path::Path) -> u64 {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_PMTU_COUNTERS))
            .expect("open pinned MTU-drop counters"),
    )
    .expect("identify pinned MTU-drop counter map");
    let counters = PerCpuArray::<_, u64>::try_from(map).expect("typed pinned MTU-drop counters");
    counters
        .get(&COUNTER_UL_MTU_REJECT, 0)
        .expect("read per-CPU MTU-drop counter")
        .iter()
        .copied()
        .sum()
}

fn pinned_pmtu_corrupt_counter(pin_dir: &std::path::Path) -> u64 {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_UPLINK_PMTU_COUNTERS))
            .expect("open pinned MTU-drop counters"),
    )
    .expect("identify pinned MTU-drop counter map");
    let counters = PerCpuArray::<_, u64>::try_from(map).expect("typed pinned MTU-drop counters");
    counters
        .get(&COUNTER_UL_PMTU_CORRUPT, 0)
        .expect("read per-CPU corrupt-policy counter")
        .iter()
        .copied()
        .sum()
}

/// Read the exact pinned default/marked PDR the tc downlink program would
/// consult for `teid`, with the tc path's corruption semantics: a TEID in
/// both maps is corrupt duplicate ownership, and a marked PDR with the
/// reserved zero mark is corrupt.
fn read_pinned_downlink_pdr(pin_dir: &std::path::Path, teid: [u8; 4]) -> Option<GtpuReassemblyPdr> {
    let legacy = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_DOWNLINK_PDR)).expect("open pinned downlink PDR"),
    )
    .expect("identify pinned downlink PDR map");
    let legacy = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(legacy)
        .expect("typed pinned downlink PDR map");
    let legacy = legacy.get(&teid, 0).ok();
    let marked = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_DOWNLINK_MARK_PDR))
            .expect("open pinned marked downlink PDR"),
    )
    .expect("identify pinned marked downlink PDR map");
    let marked = BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(marked)
        .expect("typed pinned marked downlink PDR map");
    let marked = marked.get(&teid, 0).ok();
    match (legacy, marked) {
        (Some(_), Some(_)) => Some(GtpuReassemblyPdr::Corrupt),
        (Some(value), None) => Some(GtpuReassemblyPdr::Configured(MarkedDownlinkPdr {
            ue_ip: DownlinkPdr::decode(&value).ue_ip,
            bearer_mark: [0; 4],
        })),
        (None, Some(value)) => {
            let pdr = MarkedDownlinkPdr::decode(&value);
            if pdr.bearer_mark == [0; 4] {
                Some(GtpuReassemblyPdr::Corrupt)
            } else {
                Some(GtpuReassemblyPdr::Configured(pdr))
            }
        }
        (None, None) => None,
    }
}

/// Authorize one delivery against the complete pinned graph. Component maps
/// are observed first and the authoritative commit is read last, mirroring the
/// tc publication fence across install, replace, remove, and crash cuts.
fn pinned_complete_graph_authorizes_downlink(
    pin_dir: &std::path::Path,
    teid: [u8; 4],
    pdr: MarkedDownlinkPdr,
    binding: &DownlinkEndpointBinding,
) -> bool {
    let Some(observed_selector) = GtpuReassemblySelector::from_pdr(pdr) else {
        return false;
    };
    let marked = observed_selector.is_marked();
    let selector = observed_selector
        .marked_map_key()
        .unwrap_or([0; UPLINK_MARK_KEY_LEN]);
    let ue_ip = observed_selector.ue_ip();

    let far_map_name = if marked {
        MAP_UPLINK_MARK_FAR
    } else {
        MAP_UPLINK_FAR
    };
    let far_map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(far_map_name)).expect("open pinned uplink FAR"),
    )
    .expect("identify pinned uplink FAR");
    let far = if marked {
        let map = BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(
            far_map,
        )
        .expect("typed pinned marked FAR");
        map.get(&selector, 0)
            .ok()
            .map(|value| UplinkFar::decode(&value))
    } else {
        let map = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(far_map)
            .expect("typed pinned default FAR");
        map.get(&ue_ip, 0)
            .ok()
            .map(|value| UplinkFar::decode(&value))
    };
    let Some(far) = far else {
        return false;
    };
    let dscp_map_name = if marked {
        MAP_UPLINK_MARK_DSCP
    } else {
        MAP_UPLINK_DSCP
    };
    let dscp_map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(dscp_map_name)).expect("open pinned uplink DSCP"),
    )
    .expect("identify pinned uplink DSCP");
    let dscp = if marked {
        let map =
            BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(
                dscp_map,
            )
            .expect("typed pinned marked DSCP");
        map.get(&selector, 0).ok().map(|value| value[0])
    } else {
        let map = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(dscp_map)
            .expect("typed pinned default DSCP");
        map.get(&ue_ip, 0).ok().map(|value| value[0])
    };

    let owner = if marked {
        let map = Map::from_map_data(
            MapData::from_pin(pin_dir.join(MAP_MARKED_BEARER_OWNER))
                .expect("open pinned marked-owner journal"),
        )
        .expect("identify pinned marked-owner journal");
        let owners = BpfHashMap::<
            _,
            [u8; UPLINK_MARK_KEY_LEN],
            [u8; MARKED_BEARER_OWNER_VALUE_LEN],
        >::try_from(map)
        .expect("typed pinned marked-owner journal");
        owners
            .get(&selector, 0)
            .ok()
            .map(|value| MarkedBearerOwner::decode(&value))
    } else {
        None
    };

    // Publication fence: the commit is deliberately the final map read.
    let commit_map_name = if marked {
        MAP_UPLINK_MARK_SOURCE_PORT
    } else {
        MAP_UPLINK_SOURCE_PORT
    };
    let commit_map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(commit_map_name)).expect("open pinned PDP commit"),
    )
    .expect("identify pinned PDP commit");
    let commit = if marked {
        let map = BpfHashMap::<
            _,
            [u8; UPLINK_MARK_KEY_LEN],
            [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
        >::try_from(commit_map)
        .expect("typed pinned marked commit");
        map.get(&selector, 0)
            .ok()
            .map(|value| PdpContextCommit::decode(&value))
    } else {
        let map =
            BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(commit_map)
                .expect("typed pinned default commit");
        map.get(&ue_ip, 0)
            .ok()
            .map(|value| PdpContextCommit::decode(&value))
    };
    let Some(commit) = commit else {
        return false;
    };
    let Some(identity) = GtpuReassemblyGraphIdentity::new(observed_selector, teid, pdr) else {
        return false;
    };
    reassembly_commit_authorizes_graph(&commit, identity, binding, &far, dscp, owner.as_ref())
}

/// Read the exact pinned outer-endpoint binding the tc downlink program
/// would consult for `teid`.
fn read_pinned_downlink_binding(
    pin_dir: &std::path::Path,
    teid: [u8; 4],
) -> Option<DownlinkEndpointBinding> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_DOWNLINK_ENDPOINT_BINDING))
            .expect("open pinned downlink binding"),
    )
    .expect("identify pinned downlink binding map");
    let bindings =
        BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(map)
            .expect("typed pinned downlink binding map");
    bindings.get(&teid, 0).ok().map(|value| {
        let binding = DownlinkEndpointBinding::decode(&value);
        assert!(binding.is_valid(), "pinned binding must be canonical");
        binding
    })
}

/// Split a complete outer GTP-U frame into two IPv4 fragments at an 8-byte
/// boundary inside the IPv4 payload, sharing one fragment ID. The first
/// fragment carries the MF flag; DF is never set on a fragment.
fn build_outer_fragments(frame: &[u8], first_payload_len: usize, id: u16) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(first_payload_len % 8, 0);
    let ip = ETH_HDR_LEN;
    let ihl = usize::from(frame[ip] & 0x0f) * 4;
    assert_eq!(
        ihl, IPV4_MIN_HDR_LEN,
        "fragment builder needs option-free IPv4"
    );
    let total = usize::from(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]));
    let payload = &frame[ip + ihl..ip + total];
    assert!(
        first_payload_len >= UDP_HDR_LEN + GTPU_MANDATORY_HDR_LEN
            && first_payload_len < payload.len()
    );
    let make_fragment = |fragment_payload: &[u8], offset_units: u16, more_fragments: bool| {
        let mut fragment = Vec::with_capacity(ip + ihl + fragment_payload.len());
        fragment.extend_from_slice(&frame[..ETH_HDR_LEN]);
        let mut header = frame[ip..ip + ihl].to_vec();
        header[2..4].copy_from_slice(
            &(u16::try_from(ihl + fragment_payload.len())
                .unwrap()
                .to_be_bytes()),
        );
        header[4..6].copy_from_slice(&id.to_be_bytes());
        let flags_offset = (offset_units & 0x1FFF) | (u16::from(more_fragments) * 0x2000);
        header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        header[10..12].fill(0);
        let checksum = internet_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
        fragment.extend_from_slice(&header);
        fragment.extend_from_slice(fragment_payload);
        fragment
    };
    (
        make_fragment(&payload[..first_payload_len], 0, true),
        make_fragment(
            &payload[first_payload_len..],
            u16::try_from(first_payload_len / 8).unwrap(),
            false,
        ),
    )
}

/// Receive AF_PACKET frames until the outer GTP-U UDP/2152 packet toward the
/// PGW arrives; return its IPv4 flags/fragment-offset high byte.
fn capture_gtpu_outer_flags(capture: &OwnedFd) -> u8 {
    use nix::sys::socket::{recv, MsgFlags};

    let mut frame = vec![0_u8; 65_536];
    loop {
        let length = recv(capture.as_raw_fd(), &mut frame, MsgFlags::empty())
            .expect("receive emitted uplink frame before timeout");
        let ip = &frame[14..length];
        if length < 14 + 20 + 8 || frame[12..14] != [0x08, 0x00] {
            continue;
        }
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        if ip[0] >> 4 != 4
            || ihl < 20
            || ip.len() < ihl + 8
            || ip[9] != IPPROTO_UDP
            || ip[16..20] != PGW_IP.octets()
        {
            continue;
        }
        let udp = &ip[ihl..];
        if u16::from_be_bytes([udp[2], udp[3]]) != GTPU_PORT {
            continue;
        }
        return ip[6];
    }
}

#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_downlink_outer_fragments_reenter_sdk_consumer_exactly_once(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The CI harness runs this test inside a fresh private network namespace,
    // so these strict limits affect only this proof and are restored on
    // unwind. A one-second timeout makes late-tail behavior observable; the
    // small global threshold makes pressure eviction deterministic.
    let fragment_limits = FragmentSysctlGuard::configure(1, 65_536)?;
    let net = TestNet::provision();
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    let pin_dir = net.pin_root.join("s2bu");
    assert!(
        matches!(
            backend.probe().await?.downlink_outer_fragment_handling,
            opc_gtpu_dataplane::GtpuDownlinkFragmentContract::KernelReassemblyHandoff { .. }
        ),
        "the eBPF backend must report the kernel-reassembly handoff contract"
    );
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;

    // The SDK post-reassembly consumer: a sealed, device-bound UDP/2152 socket
    // on the concrete local S2b-U endpoint in the ePDG (root) netns. tc passes
    // every outer fragment to the stack; the kernel reassembles under its
    // bounded ipfrag accounting and delivers one complete datagram here.
    let consumer_socket = GtpuReassemblySocket::bind(EPDG_S2BU_IP, "s2bu")?;
    assert_eq!(consumer_socket.ingress_ifindex(), device.ifindex);
    assert_eq!(
        consumer_socket
            .set_receive_buffer_size(0)
            .expect_err("zero receive buffer must fail")
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(consumer_socket.set_receive_buffer_size(256 * 1024)? > 0);
    let socket_debug = format!("{consumer_socket:?}");
    assert!(socket_debug.contains("<redacted>"));
    assert!(!socket_debug.contains("s2bu"));
    assert!(!socket_debug.contains(&EPDG_S2BU_IP.to_string()));
    assert!(!socket_debug.contains(&device.ifindex.to_string()));
    // The consumer authorizes against the exact pinned PDR/binding/owner
    // state the tc fast path consults, with the tc path's corruption and
    // owner-journal semantics.
    let mut consumer = GtpuReassemblyConsumer::new(
        |teid| read_pinned_downlink_pdr(&pin_dir, teid),
        |teid| read_pinned_downlink_binding(&pin_dir, teid),
        |teid, pdr, binding| {
            pinned_complete_graph_authorizes_downlink(&pin_dir, teid, pdr, binding)
        },
    );

    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");
    let mut receive_buffer = [0_u8; 2048];
    let send_set = |payload: &[u8; 180], id: u16, reorder: bool, duplicate_first: bool| {
        let inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, payload);
        let gpdu = build_gpdu(LOCAL_TEID, None, &inner);
        let frame = build_outer_gtpu_frame(destination_mac, source_mac, &[], &gpdu, true, 0);
        let (first, second) = build_outer_fragments(&frame, 32, id);
        let (leading, trailing) = if reorder {
            (second, first)
        } else {
            (first, second)
        };
        send_raw_gtpu_frame(
            &net.pgw_ns,
            "s2bup",
            &leading,
            RawChecksumMetadata::Unverified,
        );
        if duplicate_first {
            send_raw_gtpu_frame(
                &net.pgw_ns,
                "s2bup",
                &leading,
                RawChecksumMetadata::Unverified,
            );
        }
        send_raw_gtpu_frame(
            &net.pgw_ns,
            "s2bup",
            &trailing,
            RawChecksumMetadata::Unverified,
        );
    };
    let expect_decapsulated = |consumer: &mut GtpuReassemblyConsumer<_, _, _>,
                               buffer: &mut [u8; 2048],
                               expected_inner_payload: &[u8]| {
        consumer_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set consumer receive timeout");
        // Provenance is extracted from IP_PKTINFO, never hardcoded.
        let (length, provenance) = consumer_socket
            .receive(buffer)
            .expect("reassembled G-PDU must re-enter the SDK consumer");
        assert_eq!(provenance.peer_address(), PGW_IP);
        assert_eq!(provenance.local_address(), EPDG_S2BU_IP);
        assert_eq!(provenance.ingress_ifindex(), device.ifindex);
        assert_eq!(provenance.source_port(), GTPU_PORT);
        let outcome = consumer.process(&buffer[..length], &provenance);
        let GtpuReassemblyOutcome::Decapsulated {
            inner_packet,
            bearer_mark,
        } = outcome
        else {
            panic!("authorized reassembled G-PDU must decapsulate, got {outcome:?}");
        };
        assert_eq!(bearer_mark, None, "default bearer carries no output mark");
        assert_eq!(
            inner_packet,
            build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, expected_inner_payload),
            "decapsulated inner packet must equal the exact fragmented original"
        );
    };

    // A complete valid fragmented downlink packet is delivered exactly once.
    let mut payload = [b'a'; 180];
    payload[..8].copy_from_slice(b"in-order");
    send_set(&payload, 0x3450, false, false);
    expect_decapsulated(&mut consumer, &mut receive_buffer, &payload);
    expect_no_reassembled_datagram(&consumer_socket);

    // Reordered fragments reassemble into the same single delivery.
    payload[..8].copy_from_slice(b"reordere");
    send_set(&payload, 0x3451, true, false);
    expect_decapsulated(&mut consumer, &mut receive_buffer, &payload);
    expect_no_reassembled_datagram(&consumer_socket);

    // A duplicated first fragment must not duplicate the delivery.
    payload[..8].copy_from_slice(b"duplicat");
    send_set(&payload, 0x3452, false, true);
    expect_decapsulated(&mut consumer, &mut receive_buffer, &payload);
    expect_no_reassembled_datagram(&consumer_socket);

    // A complete reassembled datagram larger than the caller's receive
    // buffer is consumed with MSG_TRUNC and rejected before provenance can be
    // constructed or any GTP-U bytes can be processed.
    payload[..8].copy_from_slice(b"truncate");
    send_set(&payload, 0x3457, false, false);
    consumer_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut undersized = [0_u8; 8];
    let truncation = consumer_socket
        .receive(&mut undersized)
        .expect_err("undersized receive buffer must fail closed");
    assert_eq!(truncation.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        truncation.to_string(),
        "truncated reassembly datagram envelope"
    );

    // The socket path must observe the same Active commit fence as tc. A
    // complete fragmented packet can still reach UDP while the graph is
    // Pending, but it must not be delivered to the embedding ePDG.
    let active_commit = read_pinned_default_commit(&pin_dir);
    replace_pinned_source_port(
        &pin_dir,
        active_commit
            .with_phase(MarkedBearerOwnerPhase::Pending)
            .encode(),
    );
    payload[..8].copy_from_slice(b"pending!");
    send_set(&payload, 0x3456, false, false);
    consumer_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set Pending-graph receive timeout");
    let (length, provenance) = consumer_socket.receive(&mut receive_buffer)?;
    assert_eq!(
        consumer.process(&receive_buffer[..length], &provenance),
        GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
            opc_gtpu_ebpf_common::DownlinkBindingMismatch::Invalid
        ))
    );
    replace_pinned_source_port(&pin_dir, active_commit.encode());

    // The qualified production kernel rejects a conflicting overlap before
    // socket delivery. This is deliberately fail closed rather than accepting
    // first- or last-arriving bytes.
    let inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, &payload);
    let gpdu = build_gpdu(LOCAL_TEID, None, &inner);
    let frame = build_outer_gtpu_frame(destination_mac, source_mac, &[], &gpdu, true, 0);
    let (first, second) = build_outer_fragments(&frame, 40, 0x3453);
    // Restart the second fragment 16 bytes earlier so its leading bytes
    // overlap the first fragment with conflicting content.
    let overlapping_second = {
        let ip = ETH_HDR_LEN;
        let ihl = IPV4_MIN_HDR_LEN;
        let mut overlap = Vec::with_capacity(second.len() + 16);
        overlap.extend_from_slice(&second[..ip + ihl]);
        overlap.extend_from_slice(&frame[ip + ihl + 24..]);
        // The leading byte is inside the 16-byte overlap with the first
        // fragment. Flip it so this fixture is a genuinely conflicting
        // overlap rather than two identical copies of the same bytes.
        overlap[ip + ihl] ^= 0xff;
        assert_ne!(overlap[ip + ihl], frame[ip + ihl + 24]);
        let overlap_total = u16::try_from(overlap.len() - ip).unwrap();
        overlap[ip + 2..ip + 4].copy_from_slice(&overlap_total.to_be_bytes());
        overlap[ip + 6..ip + 8].copy_from_slice(&(24_u16 / 8).to_be_bytes());
        overlap[ip + 10..ip + 12].fill(0);
        let checksum = internet_checksum(&overlap[ip..ip + ihl]);
        overlap[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
        overlap
    };
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &first,
        RawChecksumMetadata::Unverified,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &overlapping_second,
        RawChecksumMetadata::Unverified,
    );
    expect_no_reassembled_datagram(&consumer_socket);

    // A fragment set from an unauthorized outer peer reassembles and reaches
    // the socket (the kernel does not enforce SDK policy), but the consumer
    // must reject it against the canonical binding, exactly like the tc
    // binding-drop path.
    let mut wrong_peer_frame = frame.clone();
    let ip = ETH_HDR_LEN;
    wrong_peer_frame[ip + 12..ip + 16].copy_from_slice(&PGW_ALT_IP.octets());
    refresh_outer_ipv4_checksum(&mut wrong_peer_frame);
    refresh_outer_udp_checksum(&mut wrong_peer_frame);
    let (wrong_first, wrong_second) = build_outer_fragments(&wrong_peer_frame, 32, 0x3455);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &wrong_first,
        RawChecksumMetadata::Unverified,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &wrong_second,
        RawChecksumMetadata::Unverified,
    );
    consumer_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set wrong-peer receive timeout");
    let (length, provenance) = consumer_socket.receive(&mut receive_buffer)?;
    assert_eq!(provenance.peer_address(), PGW_ALT_IP);
    let binding_drops_before = consumer.counters().binding_drops;
    assert_eq!(
        consumer.process(&receive_buffer[..length], &provenance),
        GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
            opc_gtpu_ebpf_common::DownlinkBindingMismatch::PeerAddress
        ))
    );
    assert_eq!(consumer.counters().binding_drops, binding_drops_before + 1);

    // An incomplete fragment set is actually evicted at the configured
    // one-second timeout. Its late tail cannot resurrect or deliver the set.
    let timeout_before = ipv4_reassembly_stat("ReasmTimeout");
    let (incomplete_first, late_tail) = build_outer_fragments(&frame, 32, 0x3454);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &incomplete_first,
        RawChecksumMetadata::Unverified,
    );
    wait_for_ipv4_reassembly_stat_increment("ReasmTimeout", timeout_before, Duration::from_secs(4));
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &late_tail,
        RawChecksumMetadata::Unverified,
    );
    expect_no_reassembled_datagram(&consumer_socket);

    // Hold incomplete queues long enough to pressure the deliberately small
    // global fragment-memory bound. A single AF_PACKET sender injects them
    // quickly; the kernel must increment ReasmFails instead of growing an
    // unbounded cache or delivering an incomplete datagram.
    fragment_limits.set_timeout_seconds(30)?;
    let pressure_payload = vec![b'p'; 1_200];
    let pressure_inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, &pressure_payload);
    let pressure_gpdu = build_gpdu(LOCAL_TEID, None, &pressure_inner);
    let pressure_frame =
        build_outer_gtpu_frame(destination_mac, source_mac, &[], &pressure_gpdu, true, 0);
    let pressure_fragments = (0_u16..256)
        .map(|offset| build_outer_fragments(&pressure_frame, 1_024, 0x5000 + offset).0)
        .collect::<Vec<_>>();
    let failures_before = ipv4_reassembly_stat("ReasmFails");
    send_raw_gtpu_frames(&net.pgw_ns, "s2bup", &pressure_fragments);
    wait_for_ipv4_reassembly_stat_increment("ReasmFails", failures_before, Duration::from_secs(5));
    expect_no_reassembled_datagram(&consumer_socket);

    let counters = consumer.counters();
    assert_eq!(
        counters.decapsulated, 3,
        "exactly the three valid sets decapsulated, once each"
    );
    assert_eq!(counters.malformed, 0);

    drop(net);
    Ok(())
}

#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_grouped_dual_stack_live_contract() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };
    let policy = GtpuUplinkMtuPolicy::new(1500, GtpuOuterFragmentPolicy::SignalPacketTooBig)
        .expect("canonical dual-stack PMTU policy");
    let backend = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let device = backend
        .create_device_with_endpoints(grouped_device_request(policy))
        .await?;
    let capabilities = backend
        .gtpu_ip_family_capabilities(grouped_attachment(&device))
        .await?;
    assert_eq!(capabilities.inner_ipv4, GtpuCapability::Available);
    assert_eq!(capabilities.inner_ipv6, GtpuCapability::Available);
    assert_eq!(capabilities.outer_ipv4, GtpuCapability::Available);
    assert_eq!(capabilities.outer_ipv6, GtpuCapability::Available);
    assert_eq!(
        capabilities.grouped_atomic_reconciliation,
        GtpuCapability::Available
    );
    assert_eq!(capabilities.local_endpoint_sets, GtpuCapability::Available);
    assert_eq!(capabilities.ipv6_udp_checksum, GtpuCapability::Available);
    assert_eq!(
        capabilities.uplink_checksum_offload,
        GtpuUplinkChecksumOffloadContract::MaterializedOnly
    );
    assert_eq!(
        capabilities.downlink_outer_ipv4_fragment_handling,
        GtpuDownlinkFragmentContract::Unsupported
    );
    assert_eq!(
        capabilities.downlink_outer_ipv6_fragment_handling,
        GtpuDownlinkFragmentContract::Unsupported
    );

    let initial = initial_grouped_session(device.ifindex);
    assert_eq!(
        backend
            .reconcile_pdp_context_group(fresh_grouped_reconcile(initial.clone()))
            .await?,
        GtpuSessionGroupReconcileOutcome::Activated
    );
    assert_eq!(
        backend
            .read_pdp_context_group(GtpuSessionGroupSelector::new(
                grouped_group_id(),
                grouped_device_id(),
            ))
            .await?,
        GtpuSessionGroupReadback::Active(initial.clone())
    );

    // Resolve outer neighbours before opening capture sockets so every
    // subsequent single send is an exact one-packet counter assertion.
    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    run("ping", &["-6", "-c", "1", "-W", "1", "2001:db8:2::10"]);

    let pgw_v4 = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind initial PGW IPv4 GTP-U socket")
    });
    let pgw_v6 = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IPV6, GTPU_PORT)).expect("bind initial PGW IPv6 GTP-U socket")
    });
    let ue_v4 = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5600)).expect("bind grouped UE IPv4 socket")
    });
    let ue_v6 = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA_IPV6, 5601)).expect("bind grouped UE IPv6 socket")
    });
    let ue_capture = packet_capture_socket(&net.ue_ns);
    let pgw_capture = packet_capture_socket(&net.pgw_ns);

    // Initial group: both inner and outer families are live simultaneously.
    let v4_uplink_payload = b"grouped-v4-inner-v4-outer";
    ue_v4.send_to(v4_uplink_payload, (REMOTE_HOST, 53))?;
    let v4_uplink_inner = capture_inner_udp_packet(
        &ue_capture,
        IpAddr::V4(UE_PAA),
        IpAddr::V4(REMOTE_HOST),
        5600,
        53,
        v4_uplink_payload,
    );
    receive_grouped_uplink(
        &pgw_v4,
        SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)),
        GROUP_PEER_TEID_V4_INITIAL,
        &v4_uplink_inner,
    );

    let v6_uplink_payload = b"grouped-v6-inner-v6-outer";
    let v6_uplink_before = backend.datapath_snapshot(&device).await?;
    let v6_uplink_sent =
        build_inner_udp_v6(UE_PAA_IPV6, REMOTE_HOST_IPV6, 5601, 53, v6_uplink_payload);
    send_raw_ipv6_packet(&net.ue_ns, &v6_uplink_sent);
    let v6_uplink_inner = forwarded_ipv6_packet(v6_uplink_sent);
    std::thread::sleep(Duration::from_millis(50));
    let v6_uplink_after = backend.datapath_snapshot(&device).await?;
    assert_eq!(
        v6_uplink_after.counters.uplink_encapsulated,
        v6_uplink_before.counters.uplink_encapsulated + 1,
        "outer-IPv6 uplink must reach successful encapsulation: before={v6_uplink_before:?} after={v6_uplink_after:?}"
    );
    capture_grouped_outer_ipv6(
        &pgw_capture,
        EPDG_S2BU_IPV6,
        PGW_IPV6,
        GROUP_PEER_TEID_V6_INITIAL,
        &v6_uplink_inner,
    );
    receive_grouped_uplink(
        &pgw_v6,
        SocketAddr::from((EPDG_S2BU_IPV6, GTPU_PORT)),
        GROUP_PEER_TEID_V6_INITIAL,
        &v6_uplink_inner,
    );
    // The PGW has now received the frame, so its neighbour redirect provably
    // resolved and re-entered this egress hook. Read the counter after that
    // proof rather than on a timer: outer-IPv6 re-entry is recognized through
    // the fixed 40-byte header and GTPU_CONFIG6's local endpoint, and a lagging
    // neighbour resolution would otherwise make the assertion flaky.
    let v6_uplink_delivered = backend.datapath_snapshot(&device).await?;
    assert_eq!(
        v6_uplink_delivered.counters.uplink_redirects_resolved,
        v6_uplink_before.counters.uplink_redirects_resolved + 1,
        "a delivered outer-IPv6 uplink must count exactly one resolved redirect: before={v6_uplink_before:?} delivered={v6_uplink_delivered:?}"
    );
    assert_eq!(
        v6_uplink_delivered.counters.uplink_far_misses,
        v6_uplink_before.counters.uplink_far_misses,
        "a delivered outer-IPv6 uplink is not a FAR miss: before={v6_uplink_before:?} delivered={v6_uplink_delivered:?}"
    );

    let destination_mac = main_link_address("s2bu");
    let source_mac = net.pgw_link_address("s2bup");

    let v4_downlink_payload = b"grouped-downlink-v4";
    let v4_downlink_inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5600, v4_downlink_payload);
    let v4_downlink = build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &build_gpdu(GROUP_LOCAL_TEID_V4_INITIAL, None, &v4_downlink_inner),
        true,
        0,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &v4_downlink,
        RawChecksumMetadata::Unverified,
    );
    receive_grouped_downlink(
        &ue_v4,
        SocketAddr::from((REMOTE_HOST, 53)),
        v4_downlink_payload,
    );

    let v6_downlink_payload = b"grouped-downlink-v6";
    let v6_downlink_inner =
        build_inner_udp_v6(REMOTE_HOST_IPV6, UE_PAA_IPV6, 53, 5601, v6_downlink_payload);
    let v6_gpdu = build_gpdu(GROUP_LOCAL_TEID_V6_INITIAL, None, &v6_downlink_inner);
    let v6_downlink = build_outer_ipv6_gtpu_frame(
        destination_mac,
        source_mac,
        PGW_IPV6,
        EPDG_S2BU_IPV6,
        &v6_gpdu,
        OuterIpv6Extension::None,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &v6_downlink,
        RawChecksumMetadata::Unverified,
    );
    receive_grouped_downlink(
        &ue_v6,
        SocketAddr::from((REMOTE_HOST_IPV6, 53)),
        v6_downlink_payload,
    );

    // An atomic IPv6 Fragment header is safe to parse without reassembly and
    // must decapsulate through the same exact grouped selector.
    let atomic_payload = b"grouped-atomic-fragment";
    let atomic_inner = build_inner_udp_v6(REMOTE_HOST_IPV6, UE_PAA_IPV6, 53, 5601, atomic_payload);
    let atomic = build_outer_ipv6_gtpu_frame(
        destination_mac,
        source_mac,
        PGW_IPV6,
        EPDG_S2BU_IPV6,
        &build_gpdu(GROUP_LOCAL_TEID_V6_INITIAL, None, &atomic_inner),
        OuterIpv6Extension::AtomicFragment {
            identification: 0x3440_0001,
        },
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &atomic,
        RawChecksumMetadata::Unverified,
    );
    receive_grouped_downlink(
        &ue_v6,
        SocketAddr::from((REMOTE_HOST_IPV6, 53)),
        atomic_payload,
    );

    // A zero or corrupt mandatory outer IPv6 UDP checksum is a counted
    // malformed drop before selector authorization.
    let malformed_before = backend.datapath_snapshot(&device).await?;
    let mut zero_checksum = v6_downlink.clone();
    let zero_udp = outer_ipv6_udp_offset(&zero_checksum).expect("outer IPv6 UDP offset");
    zero_checksum[zero_udp + 6..zero_udp + 8].fill(0);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &zero_checksum,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v6);

    let mut corrupt_checksum = v6_downlink.clone();
    let corrupt_udp = outer_ipv6_udp_offset(&corrupt_checksum).expect("outer IPv6 UDP offset");
    corrupt_checksum[corrupt_udp + 6] ^= 0x80;
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &corrupt_checksum,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v6);
    let malformed_after = backend.datapath_snapshot(&device).await?;
    assert_eq!(
        malformed_after.counters.downlink_malformed,
        malformed_before.counters.downlink_malformed + 2
    );
    assert_eq!(
        malformed_after.counters.downlink_decapsulated,
        malformed_before.counters.downlink_decapsulated
    );

    // A valid non-atomic fragment pair is passed to the host: Linux
    // reassembles it and delivers the exact UDP/GTP payload to a local
    // consumer. A discard-required option reaches the host IPv6 parser and
    // moves a host discard counter. Neither path moves any SDK counter.
    let host_pass_before = backend.datapath_snapshot(&device).await?;
    let host_consumer =
        UdpSocket::bind((EPDG_S2BU_IPV6, GTPU_PORT)).expect("bind host IPv6 GTP-U consumer");
    host_consumer
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set host IPv6 GTP-U timeout");
    let (non_atomic_first, non_atomic_second) =
        build_outer_ipv6_fragment_pair(&v6_downlink, 48, 0x3440_0002);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &non_atomic_first,
        RawChecksumMetadata::Unverified,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &non_atomic_second,
        RawChecksumMetadata::Unverified,
    );
    let mut reassembled = vec![0_u8; 65_536];
    let (reassembled_len, reassembled_source) = host_consumer
        .recv_from(&mut reassembled)
        .expect("host must receive reassembled outer IPv6 UDP/GTP");
    assert_eq!(reassembled_source, SocketAddr::from((PGW_IPV6, GTPU_PORT)));
    assert_eq!(&reassembled[..reassembled_len], v6_gpdu);

    let host_discards_before = ipv6_host_discard_total();
    let discard_option = build_outer_ipv6_gtpu_frame(
        destination_mac,
        source_mac,
        PGW_IPV6,
        EPDG_S2BU_IPV6,
        &v6_gpdu,
        OuterIpv6Extension::DiscardRequiredDestinationOption,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &discard_option,
        RawChecksumMetadata::Unverified,
    );
    let discard_deadline = Instant::now() + Duration::from_secs(1);
    while ipv6_host_discard_total() == host_discards_before && Instant::now() < discard_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ipv6_host_discard_total() > host_discards_before,
        "discard-required option must reach the host IPv6 parser"
    );
    let host_pass_after = backend.datapath_snapshot(&device).await?;
    assert_eq!(host_pass_after.counters, host_pass_before.counters);
    expect_no_datagram(&ue_v6);

    // Exact and one-byte-over PMTU boundaries use the selected outer family:
    // 1500-36 for outer IPv4 and 1500-56 for outer IPv6.
    let pmtu_before = backend.datapath_snapshot(&device).await?;
    let exact_v4_payload = vec![b'4'; 1436];
    ue_v4.send_to(&exact_v4_payload, (REMOTE_HOST, 53))?;
    let exact_v4_inner = capture_inner_udp_packet(
        &ue_capture,
        IpAddr::V4(UE_PAA),
        IpAddr::V4(REMOTE_HOST),
        5600,
        53,
        &exact_v4_payload,
    );
    assert_eq!(exact_v4_inner.len(), 1500 - 36);
    receive_grouped_uplink(
        &pgw_v4,
        SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)),
        GROUP_PEER_TEID_V4_INITIAL,
        &exact_v4_inner,
    );

    let exact_v6_payload = vec![b'6'; 1396];
    let exact_v6_sent =
        build_inner_udp_v6(UE_PAA_IPV6, REMOTE_HOST_IPV6, 5601, 53, &exact_v6_payload);
    send_raw_ipv6_packet(&net.ue_ns, &exact_v6_sent);
    let exact_v6_inner = forwarded_ipv6_packet(exact_v6_sent);
    assert_eq!(exact_v6_inner.len(), 1500 - 56);
    receive_grouped_uplink(
        &pgw_v6,
        SocketAddr::from((EPDG_S2BU_IPV6, GTPU_PORT)),
        GROUP_PEER_TEID_V6_INITIAL,
        &exact_v6_inner,
    );
    capture_grouped_outer_ipv6(
        &pgw_capture,
        EPDG_S2BU_IPV6,
        PGW_IPV6,
        GROUP_PEER_TEID_V6_INITIAL,
        &exact_v6_inner,
    );
    let exact_after = backend.datapath_snapshot(&device).await?;
    assert_eq!(
        exact_after.counters.uplink_mtu_rejected,
        pmtu_before.counters.uplink_mtu_rejected
    );
    assert_eq!(
        exact_after.counters.uplink_encapsulated,
        pmtu_before.counters.uplink_encapsulated + 2
    );

    let over_v4_payload = vec![b'x'; 1437];
    ue_v4.send_to(&over_v4_payload, (REMOTE_HOST, 53))?;
    expect_no_datagram(&pgw_v4);
    let over_v6_payload = vec![b'y'; 1397];
    let over_v6_sent =
        build_inner_udp_v6(UE_PAA_IPV6, REMOTE_HOST_IPV6, 5601, 53, &over_v6_payload);
    send_raw_ipv6_packet(&net.ue_ns, &over_v6_sent);
    expect_no_datagram(&pgw_v6);
    let over_after = backend.datapath_snapshot(&device).await?;
    assert_eq!(
        over_after.counters.uplink_mtu_rejected,
        exact_after.counters.uplink_mtu_rejected + 2
    );
    assert_eq!(
        over_after.counters.uplink_encapsulated,
        exact_after.counters.uplink_encapsulated
    );

    // One atomic N -> N+1 reconciliation crosses both outer families, rotates
    // both TEIDs, and relocates both peers while preserving one logical group.
    let crossed = crossed_grouped_session(device.ifindex);
    assert_eq!(
        backend
            .reconcile_pdp_context_group(fresh_grouped_reconcile(crossed.clone()))
            .await?,
        GtpuSessionGroupReconcileOutcome::Activated
    );
    assert_eq!(
        backend
            .read_pdp_context_group(GtpuSessionGroupSelector::new(
                grouped_group_id(),
                grouped_device_id(),
            ))
            .await?,
        GtpuSessionGroupReadback::Active(crossed.clone())
    );
    run("ping", &["-c", "1", "-W", "1", "192.0.2.11"]);
    run("ping", &["-6", "-c", "1", "-W", "1", "2001:db8:2::11"]);
    let pgw_alt_v4 = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_ALT_IP, GTPU_PORT)).expect("bind relocated PGW IPv4 GTP-U socket")
    });
    let pgw_alt_v6 = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_ALT_IPV6, GTPU_PORT)).expect("bind relocated PGW IPv6 GTP-U socket")
    });

    let crossed_v4_payload = b"grouped-v4-inner-v6-outer";
    ue_v4.send_to(crossed_v4_payload, (REMOTE_HOST, 53))?;
    let crossed_v4_inner = capture_inner_udp_packet(
        &ue_capture,
        IpAddr::V4(UE_PAA),
        IpAddr::V4(REMOTE_HOST),
        5600,
        53,
        crossed_v4_payload,
    );
    receive_grouped_uplink(
        &pgw_alt_v6,
        SocketAddr::from((EPDG_S2BU_IPV6, GTPU_PORT)),
        GROUP_PEER_TEID_V4_CROSSED,
        &crossed_v4_inner,
    );
    capture_grouped_outer_ipv6(
        &pgw_capture,
        EPDG_S2BU_IPV6,
        PGW_ALT_IPV6,
        GROUP_PEER_TEID_V4_CROSSED,
        &crossed_v4_inner,
    );

    let crossed_v6_payload = b"grouped-v6-inner-v4-outer";
    let crossed_v6_sent =
        build_inner_udp_v6(UE_PAA_IPV6, REMOTE_HOST_IPV6, 5601, 53, crossed_v6_payload);
    send_raw_ipv6_packet(&net.ue_ns, &crossed_v6_sent);
    let crossed_v6_inner = forwarded_ipv6_packet(crossed_v6_sent);
    receive_grouped_uplink(
        &pgw_alt_v4,
        SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)),
        GROUP_PEER_TEID_V6_CROSSED,
        &crossed_v6_inner,
    );

    let crossed_v4_down_payload = b"crossed-downlink-v4";
    let crossed_v4_down_inner =
        build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5600, crossed_v4_down_payload);
    let old_v4 = build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &build_gpdu(GROUP_LOCAL_TEID_V4_INITIAL, None, &crossed_v4_down_inner),
        true,
        0,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &old_v4,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v4);
    let old_v4_on_new_peer = build_outer_ipv6_gtpu_frame(
        destination_mac,
        source_mac,
        PGW_ALT_IPV6,
        EPDG_S2BU_IPV6,
        &build_gpdu(GROUP_LOCAL_TEID_V4_INITIAL, None, &crossed_v4_down_inner),
        OuterIpv6Extension::None,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &old_v4_on_new_peer,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v4);
    let new_v4_on_old_peer = build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &build_gpdu(GROUP_LOCAL_TEID_V4_CROSSED, None, &crossed_v4_down_inner),
        true,
        0,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &new_v4_on_old_peer,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v4);
    let new_v4 = build_outer_ipv6_gtpu_frame(
        destination_mac,
        source_mac,
        PGW_ALT_IPV6,
        EPDG_S2BU_IPV6,
        &build_gpdu(GROUP_LOCAL_TEID_V4_CROSSED, None, &crossed_v4_down_inner),
        OuterIpv6Extension::None,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &new_v4,
        RawChecksumMetadata::Unverified,
    );
    receive_grouped_downlink(
        &ue_v4,
        SocketAddr::from((REMOTE_HOST, 53)),
        crossed_v4_down_payload,
    );

    let crossed_v6_down_payload = b"crossed-downlink-v6";
    let crossed_v6_down_inner = build_inner_udp_v6(
        REMOTE_HOST_IPV6,
        UE_PAA_IPV6,
        53,
        5601,
        crossed_v6_down_payload,
    );
    let old_v6 = build_outer_ipv6_gtpu_frame(
        destination_mac,
        source_mac,
        PGW_IPV6,
        EPDG_S2BU_IPV6,
        &build_gpdu(GROUP_LOCAL_TEID_V6_INITIAL, None, &crossed_v6_down_inner),
        OuterIpv6Extension::None,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &old_v6,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v6);
    let new_v6_on_old_peer = build_outer_ipv6_gtpu_frame(
        destination_mac,
        source_mac,
        PGW_IPV6,
        EPDG_S2BU_IPV6,
        &build_gpdu(GROUP_LOCAL_TEID_V6_CROSSED, None, &crossed_v6_down_inner),
        OuterIpv6Extension::None,
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &new_v6_on_old_peer,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v6);
    let mut old_v6_on_new_peer = build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &build_gpdu(GROUP_LOCAL_TEID_V6_INITIAL, None, &crossed_v6_down_inner),
        true,
        0,
    );
    let outer_ip = ETH_HDR_LEN;
    old_v6_on_new_peer[outer_ip + 12..outer_ip + 16].copy_from_slice(&PGW_ALT_IP.octets());
    refresh_outer_ipv4_checksum(&mut old_v6_on_new_peer);
    refresh_outer_udp_checksum(&mut old_v6_on_new_peer);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &old_v6_on_new_peer,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v6);
    let mut new_v6 = build_outer_gtpu_frame(
        destination_mac,
        source_mac,
        &[],
        &build_gpdu(GROUP_LOCAL_TEID_V6_CROSSED, None, &crossed_v6_down_inner),
        true,
        0,
    );
    new_v6[outer_ip + 12..outer_ip + 16].copy_from_slice(&PGW_ALT_IP.octets());
    refresh_outer_ipv4_checksum(&mut new_v6);
    refresh_outer_udp_checksum(&mut new_v6);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &new_v6,
        RawChecksumMetadata::Unverified,
    );
    receive_grouped_downlink(
        &ue_v6,
        SocketAddr::from((REMOTE_HOST_IPV6, 53)),
        crossed_v6_down_payload,
    );

    // Drop all process-local loader state, then adopt the exact retained
    // grouped attachment through the public stable-ID/endpoint-set create
    // boundary. Readback, capabilities, and live traffic must survive without
    // raw-map intervention.
    drop(backend);
    let adopted_backend = EbpfGtpuDataplaneBackend::with_config(config);
    let adopted = adopted_backend
        .create_device_with_endpoints(grouped_device_request(policy))
        .await?;
    assert_eq!(adopted, device);
    assert_eq!(
        adopted_backend
            .read_pdp_context_group(GtpuSessionGroupSelector::new(
                grouped_group_id(),
                grouped_device_id(),
            ))
            .await?,
        GtpuSessionGroupReadback::Active(crossed.clone())
    );
    let adopted_capabilities = adopted_backend
        .gtpu_ip_family_capabilities(grouped_attachment(&adopted))
        .await?;
    assert_eq!(
        adopted_capabilities, capabilities,
        "restart adoption must preserve the complete attachment-scoped capability report"
    );
    assert_eq!(
        adopted_capabilities.grouped_atomic_reconciliation,
        GtpuCapability::Available
    );
    assert_eq!(
        adopted_capabilities.local_endpoint_sets,
        GtpuCapability::Available
    );
    assert_eq!(
        adopted_capabilities.ipv6_udp_checksum,
        GtpuCapability::Available
    );
    assert_eq!(
        adopted_capabilities.uplink_checksum_offload,
        GtpuUplinkChecksumOffloadContract::MaterializedOnly
    );
    assert_eq!(
        adopted_capabilities.downlink_outer_ipv4_fragment_handling,
        GtpuDownlinkFragmentContract::Unsupported
    );
    assert_eq!(
        adopted_capabilities.downlink_outer_ipv6_fragment_handling,
        GtpuDownlinkFragmentContract::Unsupported
    );
    let adopted_payload = b"grouped-adopted-live";
    ue_v4.send_to(adopted_payload, (REMOTE_HOST, 53))?;
    let adopted_inner = capture_inner_udp_packet(
        &ue_capture,
        IpAddr::V4(UE_PAA),
        IpAddr::V4(REMOTE_HOST),
        5600,
        53,
        adopted_payload,
    );
    receive_grouped_uplink(
        &pgw_alt_v6,
        SocketAddr::from((EPDG_S2BU_IPV6, GTPU_PORT)),
        GROUP_PEER_TEID_V4_CROSSED,
        &adopted_inner,
    );
    let adopted_v6_payload = b"grouped-adopted-v6-live";
    let adopted_v6_sent =
        build_inner_udp_v6(UE_PAA_IPV6, REMOTE_HOST_IPV6, 5601, 53, adopted_v6_payload);
    send_raw_ipv6_packet(&net.ue_ns, &adopted_v6_sent);
    let adopted_v6_inner = forwarded_ipv6_packet(adopted_v6_sent);
    receive_grouped_uplink(
        &pgw_alt_v4,
        SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)),
        GROUP_PEER_TEID_V6_CROSSED,
        &adopted_v6_inner,
    );
    capture_grouped_outer_ipv6(
        &pgw_capture,
        EPDG_S2BU_IPV6,
        PGW_ALT_IPV6,
        GROUP_PEER_TEID_V4_CROSSED,
        &adopted_inner,
    );

    assert_eq!(
        adopted_backend
            .remove_pdp_context_group_exact(crossed.clone())
            .await?,
        GtpuSessionGroupRemovalOutcome::Removed
    );
    assert_eq!(
        adopted_backend
            .read_pdp_context_group(GtpuSessionGroupSelector::new(
                grouped_group_id(),
                grouped_device_id(),
            ))
            .await?,
        GtpuSessionGroupReadback::Absent
    );
    assert_eq!(
        adopted_backend
            .remove_pdp_context_group_exact(crossed)
            .await?,
        GtpuSessionGroupRemovalOutcome::AlreadyAbsent
    );

    ue_v4.send_to(b"grouped-removed-uplink", (REMOTE_HOST, 53))?;
    expect_no_datagram(&pgw_alt_v6);
    let removed_v6 = build_inner_udp_v6(
        UE_PAA_IPV6,
        REMOTE_HOST_IPV6,
        5601,
        53,
        b"grouped-removed-v6-uplink",
    );
    send_raw_ipv6_packet(&net.ue_ns, &removed_v6);
    expect_no_datagram(&pgw_alt_v4);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &new_v4,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v4);
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &new_v6,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue_v6);

    drop(net);
    Ok(())
}

#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_uplink_mtu_policy_enforced_on_the_wire() -> Result<(), Box<dyn std::error::Error>>
{
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let strict = GtpuUplinkMtuPolicy::new(1400, GtpuOuterFragmentPolicy::SignalPacketTooBig)
        .expect("canonical strict policy");
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    request.uplink_mtu_policy = Some(strict);
    let device = backend.create_device(request).await?;
    let pin_dir = net.pin_root.join("s2bu");
    assert_eq!(
        backend.probe().await?.uplink_pmtu_enforcement,
        GtpuCapability::Available,
        "loaded datapath must expose usable MTU policy maps"
    );
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_PMTU_SCHEMA_MARKER_VALUE
    );
    assert_eq!(pinned_pmtu_policy(&pin_dir), strict.map_value());
    assert_eq!(
        backend.effective_uplink_mtu_policy(&device).await?,
        Some(strict),
        "read-back must return the effective configured policy"
    );
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;

    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5000)).expect("bind UE socket")
    });
    let capture = packet_capture_socket(&net.pgw_ns);

    // Over-MTU under the strict policy: 20+8+1352 = 1380 inner, +36 encap =
    // 1416 > 1400. The tc program must drop fail closed: nothing reaches the
    // PGW, nothing leaks unencapsulated, and the bounded drop counter moves.
    let over_mtu = vec![b'x'; 1352];
    for _ in 0..3 {
        let _ = ue_socket.send_to(&over_mtu, (REMOTE_HOST, 53));
    }
    expect_no_datagram(&pgw_socket);
    assert_eq!(pinned_pmtu_drop_counter(&pin_dir), 3);
    assert_eq!(
        pinned_counter(&pin_dir, COUNTER_UL_ENCAP),
        0,
        "a rejected packet is never accounted as encapsulated"
    );

    // Fitting under the strict policy: 20+8+1300 = 1328 inner, +36 = 1364 <=
    // 1400. The packet is emitted with DF stamped on the outer header.
    let fitting = vec![b'y'; 1300];
    let mut buffer = [0_u8; 2048];
    let (len, from) = send_until_received(
        || {
            let _ = ue_socket.send_to(&fitting, (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("fitting uplink G-PDU must reach the PGW");
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
    assert!(buffer[..len].ends_with(&fitting));
    let outer_flags = capture_gtpu_outer_flags(&capture);
    assert_eq!(
        outer_flags & 0x40,
        0x40,
        "the strict policy must stamp DF on emitted outer headers"
    );

    // Host callers can receive a typed fragmentation-required action, but tc
    // cannot execute it: bpf_redirect_neigh bypasses ip_fragment. The eBPF
    // boundary must reject that policy without changing the strict map slot.
    let host_only =
        GtpuUplinkMtuPolicy::new(1400, GtpuOuterFragmentPolicy::RequireOuterFragmentation)
            .expect("canonical host-only fragment policy");
    assert!(matches!(
        backend
            .set_uplink_mtu_policy(&device, Some(host_only))
            .await,
        Err(GtpuError::InvalidConfig {
            field: "device.uplink_mtu_policy.fragmentation",
            ..
        })
    ));
    assert_eq!(
        backend.effective_uplink_mtu_policy(&device).await?,
        Some(strict),
        "a rejected host-only policy must leave the strict slot unchanged"
    );
    let drops_before = pinned_pmtu_drop_counter(&pin_dir);
    let _ = ue_socket.send_to(&over_mtu, (REMOTE_HOST, 53));
    expect_no_datagram(&pgw_socket);
    assert_eq!(pinned_pmtu_drop_counter(&pin_dir), drops_before + 1);

    // An out-of-band writer can publish a globally canonical host policy, but
    // tc still cannot execute it. Even a fitting packet must fail closed into
    // the external-writer canary rather than silently adopting weaker
    // semantics.
    replace_pinned_pmtu_policy(&pin_dir, host_only.map_value());
    assert!(matches!(
        backend.effective_uplink_mtu_policy(&device).await,
        Err(GtpuError::StateIndeterminate {
            operation: "ebpf_pmtu_policy_readback"
        })
    ));
    assert_eq!(
        backend.probe().await?.uplink_pmtu_enforcement,
        GtpuCapability::Missing,
        "a host-only live map policy is not executable by tc"
    );
    let corrupt_before = pinned_pmtu_corrupt_counter(&pin_dir);
    let _ = ue_socket.send_to(b"opc-host-only-policy", (REMOTE_HOST, 53));
    expect_no_datagram(&pgw_socket);
    assert_eq!(pinned_pmtu_corrupt_counter(&pin_dir), corrupt_before + 1);

    // Structurally corrupt persisted bytes also drop every uplink packet into
    // the same dedicated canary; neither case moves the over-MTU counter.
    replace_pinned_pmtu_policy(&pin_dir, [0x05, 0x78, 0x02, 0]);
    assert!(matches!(
        backend.effective_uplink_mtu_policy(&device).await,
        Err(GtpuError::StateIndeterminate {
            operation: "ebpf_pmtu_policy_readback"
        })
    ));
    assert_eq!(
        backend.probe().await?.uplink_pmtu_enforcement,
        GtpuCapability::Missing,
        "corrupt live map bytes must fail the PMTU capability closed"
    );
    let corrupt_before = pinned_pmtu_corrupt_counter(&pin_dir);
    for _ in 0..2 {
        let _ = ue_socket.send_to(b"opc-corrupt-policy", (REMOTE_HOST, 53));
    }
    expect_no_datagram(&pgw_socket);
    assert_eq!(pinned_pmtu_corrupt_counter(&pin_dir), corrupt_before + 2);
    assert_eq!(
        pinned_pmtu_drop_counter(&pin_dir),
        drops_before + 1,
        "corrupt policy must not conflate with over-MTU rejects"
    );

    // The supported mutation restores a canonical policy.
    backend.set_uplink_mtu_policy(&device, None).await?;
    assert_eq!(backend.effective_uplink_mtu_policy(&device).await?, None);

    drop(net);
    Ok(())
}

#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn current_graph_recovery_fences_live_owner_and_recovers_after_interface_loss(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };
    let owner = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut create = CreateGtpDeviceRequest::new("s2bu");
    create.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let old_device = owner.create_device(create).await?;
    let pin_dir = net.pin_root.join("s2bu");
    let recovery = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let request = CurrentEbpfGraphRecoveryRequest::new(
        "s2bu",
        CurrentEbpfGraphWriterProof::previous_writer_stopped(),
    )
    .with_replacement_device(old_device.clone());

    assert_eq!(
        recovery
            .recover_orphaned_current_ebpf_graph(request)
            .await?,
        CurrentEbpfGraphRecoveryOutcome::Refused(CurrentEbpfGraphRecoveryRefusal::ActiveOwner),
        "the live backend's host-global namespace lease must fence recovery"
    );
    assert!(
        pin_dir.is_dir(),
        "a refused recovery must preserve every pin"
    );

    // Releasing the stable namespace lease is not sufficient while the old
    // interface still holds the loaded tc programs. This call has no
    // replacement, so ActiveOwner is proven by the complete loaded-program
    // map-reference scan rather than by the lease or replacement hook check.
    drop(owner);
    assert_eq!(
        recovery
            .recover_orphaned_current_ebpf_graph(CurrentEbpfGraphRecoveryRequest::new(
                "s2bu",
                CurrentEbpfGraphWriterProof::previous_writer_stopped(),
            ))
            .await?,
        CurrentEbpfGraphRecoveryOutcome::Refused(CurrentEbpfGraphRecoveryRefusal::ActiveOwner),
        "surviving loaded programs that reference the pinned graph must fence recovery"
    );
    assert!(pin_dir.is_dir(), "program-reference refusal preserves pins");

    // Model abrupt pod/netns loss: deleting the old interface removes both tc
    // hooks while the bpffs graph survives. The replacement deliberately
    // receives a new ifindex and is validated separately from the persistent
    // pin namespace.
    run("ip", &["link", "del", "s2bu"]);
    run("ip", &["link", "add", "s2bu-repl", "type", "dummy"]);
    struct LinkCleanup(&'static str);
    impl Drop for LinkCleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "del", self.0]).output();
        }
    }
    let _replacement_cleanup = LinkCleanup("s2bu-repl");
    run("ip", &["link", "set", "s2bu-repl", "up"]);
    let replacement_ifindex = nix::net::if_::if_nametoindex("s2bu-repl")?;
    assert_ne!(replacement_ifindex, old_device.ifindex);
    let replacement = GtpDevice {
        name: "s2bu-repl".to_string(),
        ifindex: replacement_ifindex,
    };
    let request = || {
        CurrentEbpfGraphRecoveryRequest::new(
            "s2bu",
            CurrentEbpfGraphWriterProof::previous_writer_stopped(),
        )
        .with_replacement_device(replacement.clone())
    };

    assert_eq!(
        recovery
            .recover_orphaned_current_ebpf_graph(request())
            .await?,
        CurrentEbpfGraphRecoveryOutcome::Removed
    );
    assert!(!pin_dir.exists());
    assert_eq!(
        recovery
            .recover_orphaned_current_ebpf_graph(request())
            .await?,
        CurrentEbpfGraphRecoveryOutcome::AlreadyAbsent
    );

    drop(net);
    Ok(())
}

/// The redirect-outcome counter must move with real delivery, not with
/// submission.
///
/// `bpf_redirect_neigh` returns `TC_ACT_REDIRECT` unconditionally at this call
/// shape, so a counter derived from its return value is permanently zero -- the
/// defect that made an earlier attempt at issue 564 a no-op. What is real is
/// the re-entry: a redirect that resolves puts the outer frame back on this
/// same tc egress hook (`skb_do_redirect` -> `__bpf_redirect_neigh_v4` ->
/// `bpf_out_neigh_v4` -> `neigh_output` -> `dev_queue_xmit` ->
/// `sch_handle_egress`), and one that does not is `kfree_skb`'d inside
/// `skb_do_redirect` before it gets there.
///
/// This drives real subscriber traffic through the real datapath against three
/// outer destinations and asserts the distinction end to end:
///
/// - on-link and reachable: `uplink_redirects_resolved` rises 1:1 with
///   `uplink_encapsulated`;
/// - no route covering the outer destination: `uplink_encapsulated` keeps
///   rising and `uplink_redirects_resolved` stays flat;
/// - route present but the next hop never answers ARP: same, and still flat
///   after the neighbour's solicitation budget is spent, so the signal is a
///   real failure rather than an early read of a queued skb;
/// - back to reachable: the counter resumes, proving it was never wedged.
///
/// `uplink_far_misses` must stay flat throughout. Before the re-entry was
/// recognized, the re-emitted frame's outer source (the local S2b-U address,
/// never a UE PAA) missed the FAR, so that counter rose once per *successfully
/// delivered* uplink packet and reported a healthy uplink as session-state
/// corruption.
#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_uplink_redirect_counter_tracks_delivery_not_submission(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    let pin_dir = net.pin_root.join("s2bu");

    let reachable = session_context(device.ifindex);
    let mut black_holed = session_context(device.ifindex);
    black_holed.peer_address = IpAddr::V4(UNROUTABLE_PGW_IP);
    backend.install_pdp_context(reachable.clone()).await?;

    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5000)).expect("bind UE socket")
    });

    // Resolve the PGW neighbour before any exact accounting. The very first
    // redirected frame would otherwise wait in the neighbour's arp_queue and be
    // counted after resolution completes rather than in this window.
    let mut buffer = [0_u8; 2048];
    send_until_received(
        || {
            let _ = ue_socket.send_to(b"opc-redirect-warmup", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("warm-up uplink must reach the PGW");
    drain_datagrams(&pgw_socket);

    // Reachable outer destination: every submission is also a delivery.
    let reachable_before = backend.datapath_snapshot(&device).await?.counters;
    for index in 0..REDIRECT_PROBE_PACKETS {
        ue_socket.send_to(
            format!("opc-redirect-healthy-{index}").as_bytes(),
            (REMOTE_HOST, 53),
        )?;
    }
    pgw_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set PGW read timeout");
    for index in 0..REDIRECT_PROBE_PACKETS {
        let (len, from) = pgw_socket.recv_from(&mut buffer).unwrap_or_else(|error| {
            panic!("healthy uplink G-PDU {index} must reach the PGW: {error}")
        });
        assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
        assert!(buffer[..len].ends_with(format!("opc-redirect-healthy-{index}").as_bytes()));
    }
    let reachable_after = backend.datapath_snapshot(&device).await?.counters;
    assert_eq!(
        reachable_after.uplink_encapsulated,
        reachable_before.uplink_encapsulated + u64::from(REDIRECT_PROBE_PACKETS),
        "every subscriber packet must be encapsulated: before={reachable_before:?} after={reachable_after:?}"
    );
    assert_eq!(
        reachable_after.uplink_redirects_resolved,
        reachable_before.uplink_redirects_resolved + u64::from(REDIRECT_PROBE_PACKETS),
        "a delivered uplink must count one resolved redirect per encapsulation: before={reachable_before:?} after={reachable_after:?}"
    );
    assert_eq!(
        reachable_after.uplink_far_misses, reachable_before.uplink_far_misses,
        "a successfully delivered uplink packet is not a FAR miss: before={reachable_before:?} after={reachable_after:?}"
    );
    assert_eq!(
        reachable_after.uplink_redirects_resolved,
        pinned_counter(&pin_dir, COUNTER_UL_REDIRECT_RESOLVED),
        "the public snapshot must aggregate the exact pinned redirect counter"
    );

    // Same session state, same subscriber traffic, unroutable outer
    // destination. `ip_route_output_flow()` fails inside
    // `__bpf_redirect_neigh_v4` and the frame is freed before it can re-enter
    // this hook.
    backend
        .remove_pdp_context(RemovePdpContextRequest::from_context(&reachable))
        .await?;
    backend.install_pdp_context(black_holed.clone()).await?;
    let no_route_before = backend.datapath_snapshot(&device).await?.counters;
    for index in 0..REDIRECT_PROBE_PACKETS {
        ue_socket.send_to(
            format!("opc-redirect-no-route-{index}").as_bytes(),
            (REMOTE_HOST, 53),
        )?;
    }
    expect_no_datagram(&pgw_socket);
    let no_route_after = backend.datapath_snapshot(&device).await?.counters;
    assert_eq!(
        no_route_after.uplink_encapsulated,
        no_route_before.uplink_encapsulated + u64::from(REDIRECT_PROBE_PACKETS),
        "a black-holed uplink still encapsulates every packet: before={no_route_before:?} after={no_route_after:?}"
    );
    assert_eq!(
        no_route_after.uplink_redirects_resolved, no_route_before.uplink_redirects_resolved,
        "a redirect with no route to the outer destination must never count as resolved: before={no_route_before:?} after={no_route_after:?}"
    );
    assert_eq!(
        no_route_after.uplink_far_misses, no_route_before.uplink_far_misses,
        "a dropped redirect is not a FAR miss either: before={no_route_before:?} after={no_route_after:?}"
    );

    // A route now exists, but its next hop is unassigned and never answers
    // ARP. `bpf_out_neigh_v4()` hands the skb to `neigh_output()`, which parks
    // it in the neighbour's arp_queue; it reaches `dev_queue_xmit` only if
    // resolution succeeds, so the counter stays flat here rather than
    // reporting a delivery that never happens.
    run(
        "ip",
        &[
            "route",
            "add",
            UNROUTABLE_PGW_PREFIX,
            "via",
            DEAD_NEXT_HOP,
            "dev",
            "s2bu",
        ],
    );
    let no_neigh_before = backend.datapath_snapshot(&device).await?.counters;
    for index in 0..REDIRECT_PROBE_PACKETS {
        ue_socket.send_to(
            format!("opc-redirect-no-neigh-{index}").as_bytes(),
            (REMOTE_HOST, 53),
        )?;
    }
    expect_no_datagram(&pgw_socket);
    let no_neigh_after = backend.datapath_snapshot(&device).await?.counters;
    assert_eq!(
        no_neigh_after.uplink_encapsulated,
        no_neigh_before.uplink_encapsulated + u64::from(REDIRECT_PROBE_PACKETS),
        "an unresolvable next hop still encapsulates every packet: before={no_neigh_before:?} after={no_neigh_after:?}"
    );
    assert_eq!(
        no_neigh_after.uplink_redirects_resolved, no_neigh_before.uplink_redirects_resolved,
        "a redirect whose neighbour never resolves must not count as resolved: before={no_neigh_before:?} after={no_neigh_after:?}"
    );
    // Past the neighbour's solicitation budget the queued skbs are gone for
    // good. Re-reading here separates "permanently unreachable" from "counted
    // late", which is the one honest ambiguity in this signal.
    std::thread::sleep(Duration::from_secs(6));
    let no_neigh_settled = backend.datapath_snapshot(&device).await?.counters;
    assert_eq!(
        no_neigh_settled.uplink_redirects_resolved, no_neigh_before.uplink_redirects_resolved,
        "an unresolvable neighbour must stay flat once its arp_queue is drained: before={no_neigh_before:?} settled={no_neigh_settled:?}"
    );
    assert_eq!(
        no_neigh_settled.uplink_far_misses, no_neigh_before.uplink_far_misses,
        "queued-then-dropped frames are not FAR misses: before={no_neigh_before:?} settled={no_neigh_settled:?}"
    );

    // Restore reachability: the counter must resume, not stay wedged at the
    // value a broken uplink left it at.
    run(
        "ip",
        &[
            "route",
            "del",
            UNROUTABLE_PGW_PREFIX,
            "via",
            DEAD_NEXT_HOP,
            "dev",
            "s2bu",
        ],
    );
    backend
        .remove_pdp_context(RemovePdpContextRequest::from_context(&black_holed))
        .await?;
    backend.install_pdp_context(reachable).await?;
    let recovered_before = backend.datapath_snapshot(&device).await?.counters;
    for index in 0..REDIRECT_PROBE_PACKETS {
        ue_socket.send_to(
            format!("opc-redirect-recovered-{index}").as_bytes(),
            (REMOTE_HOST, 53),
        )?;
    }
    for index in 0..REDIRECT_PROBE_PACKETS {
        let (len, _) = pgw_socket.recv_from(&mut buffer).unwrap_or_else(|error| {
            panic!("recovered uplink G-PDU {index} must reach the PGW: {error}")
        });
        assert!(buffer[..len].ends_with(format!("opc-redirect-recovered-{index}").as_bytes()));
    }
    let recovered_after = backend.datapath_snapshot(&device).await?.counters;
    assert_eq!(
        recovered_after.uplink_redirects_resolved,
        recovered_before.uplink_redirects_resolved + u64::from(REDIRECT_PROBE_PACKETS),
        "the counter must resume once the outer destination is reachable again: before={recovered_before:?} after={recovered_after:?}"
    );
    assert_eq!(
        recovered_after.uplink_encapsulated,
        recovered_before.uplink_encapsulated + u64::from(REDIRECT_PROBE_PACKETS),
        "recovery must not change the encapsulation accounting: before={recovered_before:?} after={recovered_after:?}"
    );
    assert_eq!(
        recovered_after.uplink_far_misses, recovered_before.uplink_far_misses,
        "recovery must not report FAR misses: before={recovered_before:?} after={recovered_after:?}"
    );

    drop(net);
    Ok(())
}

/// A pin graph retained across an upgrade that grew the counter map must never
/// be adopted at its old ABI.
///
/// This is the one path every other privileged test here structurally cannot
/// reach: they all start from a fresh bpffs, so they only ever exercise a pin
/// graph this build created itself. Retaining the graph is the whole point of
/// pinning (see the `ebpf` module docs), and it is what a real upgrade does.
///
/// Aya routes each `pinning = ByName` map through
/// `MapData::create_pinned_by_name`, which on an existing pin returns the
/// adopted fd without comparing a single dimension against the object's map
/// definition. Nothing downstream closes that gap on the attach path either:
/// the bearer schema marker is unchanged by a counter-slot growth, so the
/// retained graph classifies as the current schema, and the attach-time pin
/// identity check compares only kernel map IDs -- both sides read the same
/// adopted map, so they always agree.
///
/// The result is silent and operator-visible in the worst way. The 7-slot
/// program loads fine against a 6-entry `PERCPU_ARRAY`; `GTPU_COUNTERS
/// .get_ptr_mut(COUNTER_UL_REDIRECT_RESOLVED)` simply returns `None` and the
/// increment is dropped. `uplink_encapsulated` rises while
/// `uplink_redirects_resolved` stays at zero -- which this datapath documents
/// as the signature of a total uplink outage, on a link that is in fact
/// healthy.
///
/// So: bring a generation up, retain its graph at the pre-growth counter ABI,
/// start this build against it, and require that healthy subscriber traffic
/// still moves the counter -- while the session state the previous generation
/// committed survives, because that is what the retained graph is for.
#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_retained_pin_graph_is_never_adopted_at_a_stale_counter_abi(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let pin_dir = net.pin_root.join("s2bu");

    // --- Generation 1: the deployment already in service. ---
    let previous = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = previous.create_device(request).await?;
    let session = session_context(device.ifindex);
    previous.install_pdp_context(session.clone()).await?;
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS,
        "a graph this build creates itself must carry this build's counter ABI"
    );

    // The process exits. bpffs keeps the graph so session state survives the
    // restart -- that is the designed high-availability behaviour.
    drop(previous);
    retain_pre_redirect_datapath(&pin_dir);
    println!(
        "retained pin graph: GTPU_COUNTERS max_entries={} (this build indexes {} slots)",
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS
    );

    // --- Generation 2: this build starts against that retained graph. ---
    let upgraded = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let adopted = upgraded.resolve_device("s2bu").await?;
    assert_eq!(adopted.ifindex, device.ifindex);

    // High availability is the reason the graph was retained at all: the
    // session the previous generation committed must still be installed, and
    // the schema marker and bound local address must be untouched.
    assert_eq!(
        upgraded
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&session)
                    .ok_or("local selector requires nonzero ifindex")?,
            ))
            .await?,
        PdpContextReadback::Present(session.clone()),
        "reconciling a stale counter ABI must not discard live session state"
    );
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_PMTU_SCHEMA_MARKER_VALUE,
        "the retained bearer schema must survive the upgrade"
    );
    assert_eq!(
        pinned_config(&pin_dir),
        EPDG_S2BU_IP.octets(),
        "the retained device config must survive the upgrade"
    );
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS,
        "a counter map narrower than this build's index space must never be \
         adopted: every write to the slots past its end is silently dropped"
    );

    // --- Healthy subscriber traffic over the adopted graph. ---
    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5000)).expect("bind UE socket")
    });

    // Resolve the PGW neighbour first: the very first redirected frame would
    // otherwise sit in the neighbour's arp_queue and be counted outside the
    // measured window.
    let mut buffer = [0_u8; 2048];
    send_until_received(
        || {
            let _ = ue_socket.send_to(b"opc-upgrade-warmup", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("uplink must reach the PGW after the upgrade");
    drain_datagrams(&pgw_socket);

    let before = upgraded.datapath_snapshot(&adopted).await?.counters;
    for index in 0..REDIRECT_PROBE_PACKETS {
        ue_socket.send_to(
            format!("opc-upgrade-healthy-{index}").as_bytes(),
            (REMOTE_HOST, 53),
        )?;
    }
    pgw_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set PGW read timeout");
    for index in 0..REDIRECT_PROBE_PACKETS {
        let (len, from) = pgw_socket
            .recv_from(&mut buffer)
            .unwrap_or_else(|error| panic!("uplink G-PDU {index} must reach the PGW: {error}"));
        assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
        assert!(buffer[..len].ends_with(format!("opc-upgrade-healthy-{index}").as_bytes()));
    }
    let after = upgraded.datapath_snapshot(&adopted).await?.counters;
    println!("post-upgrade counters before={before:?}");
    println!("post-upgrade counters after={after:?}");

    assert_eq!(
        after.uplink_encapsulated,
        before.uplink_encapsulated + u64::from(REDIRECT_PROBE_PACKETS),
        "every subscriber packet must still be encapsulated after the upgrade: \
         before={before:?} after={after:?}"
    );
    assert_eq!(
        after.uplink_redirects_resolved,
        before.uplink_redirects_resolved + u64::from(REDIRECT_PROBE_PACKETS),
        "a delivered uplink must count one resolved redirect per encapsulation \
         after adopting a retained graph too -- a counter flat against a rising \
         uplink_encapsulated is this datapath's published signature of a total \
         uplink outage: before={before:?} after={after:?}"
    );
    assert_eq!(
        after.uplink_redirects_resolved,
        pinned_counter(&pin_dir, COUNTER_UL_REDIRECT_RESOLVED),
        "the public snapshot must aggregate the exact pinned redirect counter"
    );
    assert_eq!(
        after.uplink_far_misses, before.uplink_far_misses,
        "a successfully delivered uplink packet is not a FAR miss: \
         before={before:?} after={after:?}"
    );

    // --- A state-bearing pin at a foreign ABI is refused, not adopted. ---
    // Counters are the only pins whose contents this loader is entitled to
    // discard. A session map whose shape is not this build's is a schema
    // break, and refusing it must leave every retained pin untouched --
    // including the counter pins the same pass would otherwise have rebuilt.
    drop(upgraded);
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);
    for name in [MAP_DOWNLINK_PDR, MAP_COUNTERS, MAP_UPLINK_PMTU_COUNTERS] {
        fs::remove_file(pin_dir.join(name)).unwrap_or_else(|error| panic!("unpin {name}: {error}"));
    }
    drop(
        EbpfLoader::new()
            .default_map_pin_directory(&pin_dir)
            .map_max_entries(MAP_DOWNLINK_PDR, FOREIGN_DOWNLINK_PDR_ENTRIES)
            .map_max_entries(MAP_COUNTERS, PRE_REDIRECT_COUNTER_SLOTS)
            .map_max_entries(MAP_UPLINK_PMTU_COUNTERS, 1)
            .load(CURRENT_OBJECT)
            .expect("re-pin the graph with a foreign session-map ABI"),
    );

    let refusing = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let refusal = refusing.resolve_device("s2bu").await;
    assert!(
        matches!(
            refusal,
            Err(GtpuError::Io {
                operation: "ebpf_pin_map_abi",
                kind: io::ErrorKind::InvalidData,
                ..
            })
        ),
        "a session-bearing pin at a foreign ABI must be refused, not adopted: {refusal:?}"
    );
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_DOWNLINK_PDR),
        FOREIGN_DOWNLINK_PDR_ENTRIES,
        "a refused attach must not rewrite the pin it refused"
    );
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        PRE_REDIRECT_COUNTER_SLOTS,
        "a refused attach must not rebuild the counter pins the same pass \
         would otherwise have reconciled"
    );
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_UPLINK_PMTU_COUNTERS),
        1,
        "a refused attach must not rebuild a counter pin classified before the \
         pin it refused"
    );
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_PMTU_SCHEMA_MARKER_VALUE,
        "a refused attach must leave the retained schema marker alone"
    );

    drop(net);
    Ok(())
}

/// A retained graph that is missing only its counter pins must be restored by
/// the next attach, never refused forever.
///
/// `reconcile_retained_pin_map_abi` unpins a counter map and relies on the load
/// below it to recreate one at this build's ABI. Between those two points the
/// pin directory holds twenty of its twenty-one pins, and that window is not
/// hypothetical: the process can die in it, and `attach` returns immediately
/// without restoring the pin when `load_pinned` fails over a pre-existing pin
/// set (memlock, ENOMEM, ENOSPC, a verifier rejection).
///
/// `bearer_schema_preflight` runs first on every subsequent attach, so if it
/// treats a counter pin as a pin whose absence proves durable state loss, the
/// reconciliation manufactures a state the preflight behind it refuses on every
/// entry point -- and the only remedy left is deleting the pin directory, which
/// destroys exactly the sessions the retained graph exists to preserve.
///
/// Counter pins carry no durable state; that is the entire premise on which
/// this loader is allowed to rebuild them at all. So their absence must be
/// self-healing.
#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_retained_graph_missing_only_counter_pins_is_restored_not_wedged(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let pin_dir = net.pin_root.join("s2bu");
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };

    let previous = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = previous.create_device(request).await?;
    let session = session_context(device.ifindex);
    previous.install_pdp_context(session.clone()).await?;
    drop(previous);
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);

    // Exactly what the reconciliation leaves behind between its unpin and the
    // load recreating the map.
    let tear = |pin_dir: &std::path::Path| {
        fs::remove_file(pin_dir.join(MAP_COUNTERS)).expect("unpin the counters map");
        fs::read_dir(pin_dir).expect("read pin directory").count()
    };
    println!("torn state: pins present = {}", tear(&pin_dir));

    let resolver = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let resolved = resolver.resolve_device("s2bu").await;
    println!(
        "REPRO resolve_device after torn state    = {:?}",
        resolved.as_ref().map(|device| device.ifindex)
    );
    let resolved = resolved?;
    assert_eq!(resolved.ifindex, device.ifindex);
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS,
        "the restored counter pin must carry this build's ABI"
    );
    assert_eq!(
        resolver
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&session)
                    .ok_or("local selector requires nonzero ifindex")?,
            ))
            .await?,
        PdpContextReadback::Present(session.clone()),
        "restoring a counter pin must not disturb live session state"
    );
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_PMTU_SCHEMA_MARKER_VALUE,
        "restoring a counter pin must not disturb the durable schema marker"
    );
    drop(resolver);
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);

    // The same torn directory must also be recoverable through create, which
    // is the entry point a restarting deployment actually uses.
    println!("torn state: pins present = {}", tear(&pin_dir));
    let creator = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let created = creator.create_device(request).await;
    println!(
        "REPRO create_device after torn state     = {:?}",
        created.as_ref().map(|device| device.ifindex)
    );
    created?;
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS,
        "create must restore the counter pin at this build's ABI"
    );
    assert_eq!(
        creator
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&session)
                    .ok_or("local selector requires nonzero ifindex")?,
            ))
            .await?,
        PdpContextReadback::Present(session),
        "a create that restores a counter pin must not discard sessions"
    );
    drop(creator);
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);

    // Absence heals; an entry that is not a pin at all must not be read as
    // absence. The classifier learns each pin's shape through
    // `symlink_metadata` and `MapInfo::from_pin`, and an unreadable entry
    // treated as an absent pin would be handed straight to Aya, which creates a
    // fresh pinned-by-name map -- precisely the concealment of durable state
    // loss the preflights exist to prevent. bpffs admits directories, so that
    // state is constructible.
    fs::remove_file(pin_dir.join(MAP_COUNTERS)).expect("unpin the counters map");
    fs::create_dir(pin_dir.join(MAP_COUNTERS)).expect("occupy a pin path with a directory");
    let occupied = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let refusal = occupied.resolve_device("s2bu").await;
    println!("REPRO resolve_device with a non-pin at a pin path = {refusal:?}");
    assert!(
        matches!(
            refusal,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pin_map_abi"
            })
        ),
        "an entry at a pin path that is not a readable map is indeterminate \
         state, never an absent pin: {refusal:?}"
    );
    drop(occupied);
    fs::remove_dir(pin_dir.join(MAP_COUNTERS)).expect("clear the occupied pin path");

    drop(net);
    Ok(())
}

/// A graph retained from a generation before the current bearer schema must
/// never have this build's programs bound to a counter map narrower than they
/// index.
///
/// The reconciliation before the load is not entitled to reshape such a graph:
/// its migration can still refuse after the load, for reasons only the loaded
/// maps can show, and removing a counter pin before that decision would swap it
/// out from under the live legacy datapath the refusal deliberately leaves
/// running. But the object loaded against a legacy graph is always the current
/// one -- `load_pinned` has no legacy variant -- so without a second check the
/// migration adopts the old counter map, advances the durable marker to
/// `OPC-PMTU-v5`, and leaves a graph that claims to be current while
/// `datapath_snapshot` cannot read a single counter from it.
///
/// `require_current_pin_map_abi` is that check, and it runs where the harm
/// would occur: at the top of `attach_programs`, before either program is
/// verified and bound, and after every migration decision has been made. So the
/// migration refuses, having committed nothing -- and the same graph migrates
/// normally once its counter pin is at this build's ABI, which is what proves
/// the refusal is about the ABI and not about legacy graphs.
#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_pre_v5_retained_graph_is_never_migrated_at_a_stale_counter_abi(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let pin_dir = net.pin_root.join("s2bu");
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };

    let previous = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = previous.create_device(request).await?;
    let session = session_context(device.ifindex);
    previous.install_pdp_context(session.clone()).await?;
    drop(previous);
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);

    // Regress the graph to what an endpoint-bound v3 generation leaves behind:
    // its durable marker and its counter ABI.
    write_pinned_schema_marker(&pin_dir, UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE);
    repin_counters_at(&pin_dir, PRE_REDIRECT_COUNTER_SLOTS);
    let retained_pdr_id = exact_pinned_map_ids(&pin_dir, &[MAP_DOWNLINK_PDR]);
    println!(
        "pre-v5 retained graph: marker={:?} GTPU_COUNTERS max_entries={}",
        String::from_utf8_lossy(&pinned_schema_marker(&pin_dir)),
        pinned_map_entries(&pin_dir, MAP_COUNTERS)
    );

    let refusing = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let refusal = refusing.resolve_device("s2bu").await;
    println!("REPRO pre-v5 resolve_device   = {refusal:?}");
    println!(
        "REPRO after refusal: marker={:?} max_entries={} (build indexes {})",
        String::from_utf8_lossy(&pinned_schema_marker(&pin_dir)),
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS
    );
    assert!(
        matches!(
            refusal,
            Err(GtpuError::Io {
                operation: "ebpf_program_pin_map_abi",
                kind: io::ErrorKind::InvalidData,
                ..
            })
        ),
        "this build's programs must never be bound to a counter map narrower \
         than they index: {refusal:?}"
    );
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE,
        "a refused migration must not advance the durable schema marker"
    );
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        PRE_REDIRECT_COUNTER_SLOTS,
        "a legacy graph's counter pin must not be swapped out from under the \
         datapath a refused migration leaves in place"
    );
    assert_eq!(
        exact_pinned_map_ids(&pin_dir, &[MAP_DOWNLINK_PDR]),
        retained_pdr_id,
        "a refused migration must not rebuild a retained session pin"
    );
    assert!(
        !tc_filters("egress").contains(PROG_UPLINK)
            && !tc_filters("ingress").contains(PROG_DOWNLINK),
        "a refused migration must not attach either program"
    );
    drop(refusing);

    // Bring the counter pin to this build's ABI -- what draining and
    // reprovisioning the graph achieves -- and the very same legacy graph
    // migrates.
    repin_counters_at(&pin_dir, COUNTER_SLOTS);
    let upgraded = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let adopted = upgraded.resolve_device("s2bu").await;
    println!(
        "REPRO pre-v5 resolve_device at this build's counter ABI = {:?}",
        adopted.as_ref().map(|device| device.ifindex)
    );
    let adopted = adopted?;
    let snapshot = upgraded.datapath_snapshot(&adopted).await;
    println!(
        "REPRO datapath_snapshot       = {:?}",
        snapshot.as_ref().map(|snapshot| snapshot.counters)
    );
    snapshot?;
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_PMTU_SCHEMA_MARKER_VALUE,
        "a completed migration must commit the current schema marker"
    );
    assert_eq!(
        upgraded
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&session)
                    .ok_or("local selector requires nonzero ifindex")?,
            ))
            .await?,
        PdpContextReadback::Present(session),
        "migrating a legacy graph must not discard live session state"
    );

    drop(upgraded);
    drop(net);
    Ok(())
}

/// A refused attach must never disconnect a live previous generation from the
/// counters an operator reads.
///
/// The counter reconciliation runs before the load, and the config-ownership
/// check that refuses a second process bound to a different local address runs
/// after it. A routine misconfiguration -- two processes, one pin namespace,
/// different `bind_address` -- therefore rebuilds and re-pins the counter map
/// and then refuses. The previous generation is still attached and still
/// forwarding into the old map, which is no longer pinned, so every observer
/// reads a permanently flat counter on a healthy link: this datapath's
/// published signature of a total uplink outage.
///
/// A refused attach must leave the retained counter pins exactly as it found
/// them.
#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_refused_attach_leaves_a_live_generation_counting(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let pin_dir = net.pin_root.join("s2bu");
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };

    let previous = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = previous.create_device(request).await?;
    previous
        .install_pdp_context(session_context(device.ifindex))
        .await?;
    drop(previous);
    // Generation 1: still attached, still forwarding, at the pre-growth ABI.
    retain_pre_redirect_datapath(&pin_dir);

    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5000)).expect("bind UE socket")
    });
    let mut buffer = [0_u8; 2048];
    send_until_received(
        || {
            let _ = ue_socket.send_to(b"opc-gen1-serving", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("generation 1 must be forwarding before the refused attach");
    drain_datagrams(&pgw_socket);
    let serving_encapsulated = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    println!(
        "gen1 serving: pinned GTPU_COUNTERS max_entries={}  encap slot={serving_encapsulated}",
        pinned_map_entries(&pin_dir, MAP_COUNTERS)
    );
    assert!(
        serving_encapsulated > 0,
        "generation 1 must be counting into the pinned map before the refusal"
    );

    let intruder = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut conflicting = CreateGtpDeviceRequest::new("s2bu");
    conflicting.bind_address = IpAddr::V4(EPDG_S2BU_ALT_IP);
    let refusal = intruder.create_device(conflicting).await;
    println!("REPRO refused create_device  = {refusal:?}");
    assert!(
        matches!(refusal, Err(GtpuError::AlreadyExists)),
        "a second process bound to a different local address is an ownership \
         conflict: {refusal:?}"
    );
    drop(intruder);
    println!(
        "REPRO after refusal: pinned max_entries={}  encap slot={}",
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        pinned_counter(&pin_dir, COUNTER_UL_ENCAP)
    );
    println!(
        "REPRO egress filter still: {}",
        tc_filters("egress").contains(PROG_UPLINK)
    );

    assert!(
        tc_filters("egress").contains(PROG_UPLINK),
        "a refused attach must leave generation 1's hooks alone"
    );
    let before = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    let mut delivered = 0;
    for index in 0..REDIRECT_PROBE_PACKETS {
        ue_socket.send_to(
            format!("opc-gen1-after-refusal-{index}").as_bytes(),
            (REMOTE_HOST, 53),
        )?;
    }
    pgw_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set PGW read timeout");
    for _ in 0..REDIRECT_PROBE_PACKETS {
        if pgw_socket.recv_from(&mut buffer).is_ok() {
            delivered += 1;
        }
    }
    let after = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    println!(
        "REPRO traffic after refusal: delivered={delivered}  pinned uplink_encapsulated \
         {before} -> {after}"
    );

    assert_eq!(
        delivered, REDIRECT_PROBE_PACKETS,
        "generation 1 must still be forwarding after the refusal"
    );
    assert_eq!(
        after,
        before + u64::from(REDIRECT_PROBE_PACKETS),
        "a refused attach must leave the live generation's counters readable \
         at their pin: a flat counter against live traffic is this datapath's \
         published signature of a total uplink outage"
    );
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        PRE_REDIRECT_COUNTER_SLOTS,
        "a refused attach must not rebuild the retained counter pin"
    );

    // The published remediation for a graph whose writer is gone must work on
    // the graph it is published for. A stale counter slot count is exactly the
    // state that sends an operator here, so recovery must not read it as a
    // foreign identity and refuse the remedy for the condition it treats.
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);
    let recovery = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let recovered = recovery
        .recover_orphaned_current_ebpf_graph(
            CurrentEbpfGraphRecoveryRequest::new(
                "s2bu",
                CurrentEbpfGraphWriterProof::previous_writer_stopped(),
            )
            .with_drain_proof(CurrentEbpfGraphDrainProof::sessions_and_traffic_drained())
            .with_replacement_device(device.clone()),
        )
        .await;
    println!("REPRO recover_orphaned on a stale counter ABI = {recovered:?}");
    assert_eq!(
        recovered?,
        CurrentEbpfGraphRecoveryOutcome::Removed,
        "a counter map's width is not this graph's identity"
    );
    assert!(!pin_dir.exists(), "recovery must remove every pin");

    drop(net);
    Ok(())
}

/// What a refused pre-v5 migration actually does to a graph that is genuinely
/// v3-shaped, and what it takes to move that graph forward afterwards.
///
/// `ebpf_gtpu_pre_v5_retained_graph_is_never_migrated_at_a_stale_counter_abi`
/// regresses a current-build directory's marker and counter ABI but leaves all
/// twenty-one pins in place, so it cannot see the additive half of a migration
/// at all. A directory a v3 generation actually left behind is short of the
/// four maps the source-port-v4 and PMTU-v5 schemas added, and `load_pinned`
/// runs -- creating and pinning them -- long before `require_current_pin_map_abi`
/// refuses at the top of `attach_programs`. `materialize_legacy_source_port_policies`
/// then writes the legacy policy of every retained session into one of them.
///
/// So "refused with everything untouched" is not the property. The property is
/// that everything *load-bearing* is untouched -- the durable marker, the
/// retained session pins and their kernel identities, and both tc slots -- while
/// the additive current pins are created and populated. That is the same
/// distinction `ebpf_gtpu_uplink_and_downlink_round_trip` already draws for the
/// v1 path ("loading the current object may create its additive empty pins,
/// which is safe and expected"), and it is what the crate README and changelog
/// must say.
///
/// The remedy matters more than the wording. A counter pin's absence is
/// self-healing by construction, so unlinking that one pin -- and nothing else
/// -- lets the very same graph migrate with every session intact. Prescribing a
/// drained reprovision here would cost an operator every session on a graph one
/// `rm` recovers.
#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_v3_shaped_retained_graph_refuses_then_heals_without_a_drain(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let pin_dir = net.pin_root.join("s2bu");
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };

    let previous = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = previous.create_device(request).await?;
    let session = session_context(device.ifindex);
    previous.install_pdp_context(session.clone()).await?;
    drop(previous);
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);

    // Exactly what a v3 generation leaves behind: its durable marker, its
    // counter ABI, and its pin set.
    write_pinned_schema_marker(&pin_dir, UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE);
    repin_counters_at(&pin_dir, PRE_REDIRECT_COUNTER_SLOTS);
    make_v3_shaped(&pin_dir);

    let retained_names = pinned_names(&pin_dir);
    let retained_session_ids = exact_pinned_map_ids(
        &pin_dir,
        &[
            MAP_UPLINK_FAR,
            MAP_UPLINK_MARK_FAR,
            MAP_DOWNLINK_PDR,
            MAP_DOWNLINK_MARK_PDR,
            MAP_DOWNLINK_ENDPOINT_BINDING,
            MAP_MARKED_BEARER_OWNER,
            MAP_CONFIG,
        ],
    );
    let retained_counter_id = exact_pinned_map_ids(&pin_dir, &[MAP_COUNTERS]);
    println!(
        "REPRO v3 graph before refusal: {} pins {retained_names:?}",
        retained_names.len()
    );
    assert_eq!(
        retained_names.len(),
        17,
        "a v3-shaped graph is short of the four post-v3 maps: {retained_names:?}"
    );
    for name in POST_V3_MAPS {
        assert!(
            !retained_names.iter().any(|pinned| pinned == name),
            "a v3 generation never pinned {name}"
        );
    }

    let refusing = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let refusal = refusing.resolve_device("s2bu").await;
    println!("REPRO v3-shaped resolve_device = {refusal:?}");
    assert!(
        matches!(
            refusal,
            Err(GtpuError::Io {
                operation: "ebpf_program_pin_map_abi",
                kind: io::ErrorKind::InvalidData,
                ..
            })
        ),
        "this build's programs must never be bound to a counter map narrower \
         than they index: {refusal:?}"
    );
    drop(refusing);

    // The additive half, stated rather than assumed. `load_pinned` created and
    // pinned every current map the v3 graph was short of, and the legacy
    // materialization wrote the retained session's uplink source-port policy
    // into one of them, all before the refusal.
    let after_names = pinned_names(&pin_dir);
    println!(
        "REPRO v3 graph after refusal: {} pins, added {:?}",
        after_names.len(),
        after_names
            .iter()
            .filter(|name| !retained_names.contains(name))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        after_names.len(),
        21,
        "a refused migration still leaves the current object's additive pins \
         behind: {after_names:?}"
    );
    for name in POST_V3_MAPS {
        assert!(
            after_names.iter().any(|pinned| pinned == name),
            "load_pinned creates and pins {name} before the refusal"
        );
    }
    assert_eq!(
        pinned_source_port_entries(&pin_dir),
        1,
        "the retained session's legacy uplink source-port policy is \
         materialized into the newly created pin before the refusal"
    );

    // Everything load-bearing, on the other hand, is exactly as it was.
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE,
        "a refused migration must not advance the durable schema marker"
    );
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        PRE_REDIRECT_COUNTER_SLOTS,
        "a legacy graph's counter pin must not be swapped out from under the \
         datapath a refused migration leaves in place"
    );
    assert_eq!(
        exact_pinned_map_ids(&pin_dir, &[MAP_COUNTERS]),
        retained_counter_id,
        "nor may it be rebuilt under a new kernel identity"
    );
    assert_eq!(
        exact_pinned_map_ids(
            &pin_dir,
            &[
                MAP_UPLINK_FAR,
                MAP_UPLINK_MARK_FAR,
                MAP_DOWNLINK_PDR,
                MAP_DOWNLINK_MARK_PDR,
                MAP_DOWNLINK_ENDPOINT_BINDING,
                MAP_MARKED_BEARER_OWNER,
                MAP_CONFIG,
            ],
        ),
        retained_session_ids,
        "a refused migration must not rebuild a single retained session, \
         bearer or device pin"
    );
    assert!(
        !tc_filters("egress").contains(PROG_UPLINK)
            && !tc_filters("ingress").contains(PROG_DOWNLINK),
        "a refused migration must not attach either program"
    );

    // The published remedy, run exactly as an operator would run it: unlink
    // the one pin whose absence this datapath guarantees is self-healing, and
    // nothing else. No drain, no re-signalling, no session loss.
    fs::remove_file(pin_dir.join(MAP_COUNTERS)).expect("unlink only the counter pin");
    let healed = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let adopted = healed.resolve_device("s2bu").await;
    println!(
        "REPRO after `rm GTPU_COUNTERS`, resolve_device = {:?}",
        adopted.as_ref().map(|device| device.ifindex)
    );
    let adopted = adopted?;
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS,
        "the load must recreate the counter pin at this build's ABI"
    );
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_PMTU_SCHEMA_MARKER_VALUE,
        "the migration the stale counter ABI refused must now complete"
    );
    let snapshot = healed.datapath_snapshot(&adopted).await;
    println!(
        "REPRO healed datapath_snapshot = {:?}",
        snapshot.as_ref().map(|snapshot| snapshot.counters)
    );
    snapshot?;
    assert_eq!(
        healed
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&session)
                    .ok_or("local selector requires nonzero ifindex")?,
            ))
            .await?,
        PdpContextReadback::Present(session.clone()),
        "the non-destructive remedy must preserve every session the drained \
         reprovision would have destroyed"
    );
    drop(healed);
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);

    // The same remedy must work through `create_device`, which is the entry
    // point a restarting deployment actually uses. Put the graph back the way
    // the v3 generation left it, apply the remedy, and start a new process.
    write_pinned_schema_marker(&pin_dir, UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE);
    repin_counters_at(&pin_dir, PRE_REDIRECT_COUNTER_SLOTS);
    make_v3_shaped(&pin_dir);
    fs::remove_file(pin_dir.join(MAP_COUNTERS)).expect("unlink only the counter pin");
    let restarting = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let created = restarting.create_device(request).await;
    println!(
        "REPRO create_device after the same remedy = {:?}",
        created.as_ref().map(|device| device.ifindex)
    );
    created?;
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS,
        "create must restore the counter pin at this build's ABI"
    );
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_PMTU_SCHEMA_MARKER_VALUE,
        "create must complete the migration the stale counter ABI refused"
    );
    assert_eq!(
        restarting
            .read_pdp_context(PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&session)
                    .ok_or("local selector requires nonzero ifindex")?,
            ))
            .await?,
        PdpContextReadback::Present(session),
        "a restarting deployment must keep every session the remedy preserved"
    );

    drop(restarting);
    drop(net);
    Ok(())
}

/// A populated endpoint-unbound v1 graph is the case where the drain really is
/// required, and it is required for a reason the counter ABI cannot reach.
///
/// Such a graph cannot be inferred as endpoint-bound, so adoption refuses it in
/// `ebpf_marked_owner_rebuild` -- after the load, and therefore before
/// `require_current_pin_map_abi` ever sees the graph. Bringing its counter pin
/// to this build's ABI changes nothing, which is exactly what distinguishes it
/// from the v3 case above: there, one `rm` recovers every session; here, no pin
/// surgery does, and the drained reprovision is the only way forward.
///
/// The two remedies are documented side by side, so both are pinned side by
/// side.
#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_populated_v1_graph_still_requires_a_drain_at_this_counter_abi(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let pin_dir = net.pin_root.join("s2bu");
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };

    // Bring the interface and its clsact qdisc up the way a deployment does,
    // then hand the namespace to a frozen v1 generation.
    let bootstrap = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = bootstrap.create_device(request).await?;
    bootstrap.remove_device(&device).await?;
    drop(bootstrap);
    let (v1_uplink_id, v1_downlink_id) = install_frozen_v1_datapath(&pin_dir);
    // Every retained v1 pin except the counter map, which this test unlinks on
    // purpose and whose rebuild is the documented self-healing behaviour.
    let retained_v1_state = exact_pinned_map_ids(
        &pin_dir,
        &[
            MAP_UPLINK_FAR,
            MAP_UPLINK_DSCP,
            MAP_DOWNLINK_PDR,
            MAP_CONFIG,
        ],
    );
    println!(
        "REPRO populated endpoint-unbound v1: marker={:?} GTPU_COUNTERS max_entries={} \
         (build indexes {COUNTER_SLOTS})",
        String::from_utf8_lossy(&pinned_schema_marker(&pin_dir)),
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
    );
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        PRE_REDIRECT_COUNTER_SLOTS,
        "the frozen v1 object declares the pre-growth counter ABI"
    );

    let stale = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let stale_refusal = stale.resolve_device("s2bu").await;
    println!("REPRO v1 resolve_device at a stale counter ABI = {stale_refusal:?}");
    assert!(
        matches!(
            stale_refusal,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_marked_owner_rebuild"
            })
        ),
        "a populated endpoint-unbound v1 graph is refused before the ABI check \
         is reached: {stale_refusal:?}"
    );
    drop(stale);

    // The remedy that recovers a v3 graph does not recover this one. The pin
    // heals -- counter pins always do -- and the refusal is unchanged.
    fs::remove_file(pin_dir.join(MAP_COUNTERS)).expect("unlink only the counter pin");
    let healed = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let healed_refusal = healed.resolve_device("s2bu").await;
    println!("REPRO v1 resolve_device after `rm GTPU_COUNTERS` = {healed_refusal:?}");
    assert!(
        matches!(
            healed_refusal,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_marked_owner_rebuild"
            })
        ),
        "no counter-pin surgery makes a populated endpoint-unbound v1 graph \
         adoptable; only a drained reprovision does: {healed_refusal:?}"
    );
    drop(healed);
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS,
        "the counter pin still heals at this build's ABI, which is precisely \
         why it is not what refuses this graph"
    );
    assert_eq!(
        pinned_schema_marker(&pin_dir),
        UPLINK_DSCP_SCHEMA_MARKER_VALUE,
        "a refused adoption must not advance the durable marker"
    );
    assert_eq!(
        exact_pinned_map_ids(
            &pin_dir,
            &[
                MAP_UPLINK_FAR,
                MAP_UPLINK_DSCP,
                MAP_DOWNLINK_PDR,
                MAP_CONFIG
            ],
        ),
        retained_v1_state,
        "a refused adoption must not rebuild a retained state-bearing v1 pin"
    );
    assert_eq!(tc_program_id("egress"), v1_uplink_id);
    assert_eq!(tc_program_id("ingress"), v1_downlink_id);

    for direction in ["egress", "ingress"] {
        run(
            "tc",
            &[
                "filter", "del", "dev", "s2bu", direction, "handle", "0x1", "pref", "50", "bpf",
            ],
        );
    }
    drop(net);
    Ok(())
}

/// Two entry points asking the same question about the same graph must report
/// the same answer.
///
/// The reconciliation answers "do I own this graph?" out of `GTPU_CONFIG`
/// itself on the `create_device` path. A `GTPU_CONFIG` pin whose shape is not
/// this build's cannot answer it -- but if ownership is evaluated before the
/// graph is classified, the typed read fails first and the schema break is
/// reported as `ebpf_pin_config_read` with `ErrorKind::Other`, while
/// `resolve_device`, which inherits its configuration and never performs that
/// read, reports the same graph as `ebpf_pin_map_abi` with
/// `ErrorKind::InvalidData`. One condition, two operations, two kinds, and
/// neither the crate README nor an operator matching on the documented contract
/// would recognise the first.
///
/// Classifying the whole graph before evaluating ownership fixes both: the
/// break is reported as a break wherever it is met, and the removal that
/// ownership actually gates still runs last and still runs only for the owner.
#[tokio::test]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_divergent_config_pin_is_refused_identically_on_every_entry_point(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let pin_dir = net.pin_root.join("s2bu");
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };

    let previous = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = previous.create_device(request).await?;
    previous
        .install_pdp_context(session_context(device.ifindex))
        .await?;
    drop(previous);
    run("tc", &["filter", "del", "dev", "s2bu", "egress"]);
    run("tc", &["filter", "del", "dev", "s2bu", "ingress"]);

    // A `GTPU_CONFIG` pin at a shape this build never declared: a per-CPU
    // eight-byte array where the specification calls for a one-slot four-byte
    // array. Nothing in the crate can read a bound address out of it.
    fs::remove_file(pin_dir.join(MAP_CONFIG)).expect("unpin the current config map");
    MapData::from_pin(pin_dir.join(MAP_DOWNLINK_BINDING_COUNTERS))
        .expect("open a donor map of a different shape")
        .pin(pin_dir.join(MAP_CONFIG))
        .expect("pin a foreign-shaped GTPU_CONFIG");
    let divergent = MapInfo::from_pin(pin_dir.join(MAP_CONFIG)).expect("read the divergent pin");
    println!(
        "REPRO hand-built GTPU_CONFIG: key_size {} value_size {} (spec 4/4)",
        divergent.key_size(),
        divergent.value_size(),
    );
    assert_ne!(
        divergent.value_size(),
        4,
        "the divergent pin must not be readable as this build's config map"
    );
    let retained_pin_count = pinned_names(&pin_dir).len();

    let creating = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut owner_request = CreateGtpDeviceRequest::new("s2bu");
    owner_request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let created = creating.create_device(owner_request).await;
    println!("REPRO create_device  = {created:?}");
    drop(creating);

    let conflicting = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut intruder_request = CreateGtpDeviceRequest::new("s2bu");
    intruder_request.bind_address = IpAddr::V4(EPDG_S2BU_ALT_IP);
    let contested = conflicting.create_device(intruder_request).await;
    println!("REPRO create_device (conflicting owner) = {contested:?}");
    drop(conflicting);

    let resolving = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let resolved = resolving.resolve_device("s2bu").await;
    println!("REPRO resolve_device = {resolved:?}");
    drop(resolving);

    // A graph at a foreign ABI is terminal for every process, so the
    // classification that reports it is deliberately not gated on ownership --
    // a conflicting attach meets the schema break, not `AlreadyExists`.
    for (entry_point, outcome) in [
        ("create_device", created),
        ("create_device (conflicting owner)", contested),
        ("resolve_device", resolved),
    ] {
        assert!(
            matches!(
                outcome,
                Err(GtpuError::Io {
                    operation: "ebpf_pin_map_abi",
                    kind: io::ErrorKind::InvalidData,
                    ..
                })
            ),
            "{entry_point} must report a divergent GTPU_CONFIG as the schema \
             break it is, under the operation and kind the crate documents: \
             {outcome:?}"
        );
    }

    // Fail-closed on both, which is what makes the shared contract safe to
    // publish: the counter pins the same pass would otherwise have rebuilt are
    // untouched, and nothing was removed.
    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        COUNTER_SLOTS,
        "a refused attach must not rebuild a counter pin"
    );
    assert_eq!(
        pinned_names(&pin_dir).len(),
        retained_pin_count,
        "a refused attach must not remove a pin"
    );

    drop(net);
    Ok(())
}

/// The grouped attach path proves ownership from the pins before it touches
/// them, exactly as the bound-address path does.
///
/// Nothing else in the suite exercises that gate. Every grouped test starts
/// from a fresh bpffs, so `grouped_schema_preflight` reports `Fresh` and the
/// recorded-configuration arm the gate is made of is never evaluated against a
/// retained graph that belongs to somebody else -- forcing it to "this request
/// matches" survives the whole suite, including the live dual-stack contract.
///
/// The harm it guards is the same one the bound-address path guards, and it is
/// not hypothetical: a grouped generation is still attached and still
/// forwarding when a second process attaches the same pin namespace with a
/// different grouped device authority. If the reconciliation believed that
/// request owned the graph, it would unpin and rebuild the counter map, the
/// load would recreate it at this build's ABI with a new kernel ID, and only
/// then would the configuration arbitration refuse with `AlreadyExists`. The
/// live generation keeps writing to a map that is no longer pinned, so every
/// observer reads a permanently flat counter on a healthy link: this datapath's
/// published signature of a total uplink outage.
#[tokio::test(flavor = "multi_thread")]
// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
#[ignore = "requires root (CAP_BPF/CAP_NET_ADMIN), a fresh netns, and bpffs"]
async fn ebpf_gtpu_refused_grouped_attach_leaves_a_live_generation_counting(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }

    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let pin_dir = grouped_pin_dir(&net.pin_root);
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };
    let policy = GtpuUplinkMtuPolicy::new(1500, GtpuOuterFragmentPolicy::SignalPacketTooBig)
        .expect("canonical dual-stack PMTU policy");

    let previous = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let device = previous
        .create_device_with_endpoints(grouped_device_request(policy))
        .await?;
    assert_eq!(
        previous
            .reconcile_pdp_context_group(fresh_grouped_reconcile(initial_grouped_session(
                device.ifindex
            )))
            .await?,
        GtpuSessionGroupReconcileOutcome::Activated
    );
    drop(previous);
    // Generation 1: still attached, still forwarding, at the pre-growth ABI.
    retain_pre_redirect_datapath(&pin_dir);

    run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW GTP-U socket")
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        UdpSocket::bind((UE_PAA, 5600)).expect("bind grouped UE socket")
    });
    let mut buffer = [0_u8; 2048];
    let (_, from) = send_until_received(
        || {
            let _ = ue_socket.send_to(b"opc-grouped-gen1-serving", (REMOTE_HOST, 53));
        },
        &pgw_socket,
        &mut buffer,
    )
    .expect("grouped generation 1 must be forwarding before the refused attach");
    assert_eq!(from, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
    drain_datagrams(&pgw_socket);
    let serving_encapsulated = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    let serving_counter_id = exact_pinned_map_ids(&pin_dir, &[MAP_COUNTERS]);
    println!(
        "grouped gen1 serving: pinned GTPU_COUNTERS max_entries={} encap slot={serving_encapsulated}",
        pinned_map_entries(&pin_dir, MAP_COUNTERS)
    );
    assert!(
        serving_encapsulated > 0,
        "grouped generation 1 must be counting into the pinned map before the refusal"
    );

    let intruder = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let refusal = intruder
        .create_device_with_endpoints(conflicting_grouped_device_request(policy))
        .await;
    println!(
        "REPRO refused grouped create_device_with_endpoints = {:?}",
        refusal.as_ref().map(|device| device.ifindex)
    );
    assert!(
        matches!(refusal, Err(GtpuError::AlreadyExists)),
        "a second process claiming the same pin namespace under a different \
         grouped device authority is an ownership conflict: {refusal:?}"
    );
    drop(intruder);

    assert_eq!(
        pinned_map_entries(&pin_dir, MAP_COUNTERS),
        PRE_REDIRECT_COUNTER_SLOTS,
        "a refused grouped attach must not rebuild the retained counter pin"
    );
    assert_eq!(
        exact_pinned_map_ids(&pin_dir, &[MAP_COUNTERS]),
        serving_counter_id,
        "a refused grouped attach must leave the live generation's counter map \
         at its pin, kernel identity included"
    );
    assert!(
        tc_filters("egress").contains(PROG_UPLINK),
        "a refused grouped attach must leave generation 1's hooks alone"
    );

    let before = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    let mut delivered = 0;
    for index in 0..REDIRECT_PROBE_PACKETS {
        ue_socket.send_to(
            format!("opc-grouped-gen1-after-refusal-{index}").as_bytes(),
            (REMOTE_HOST, 53),
        )?;
    }
    pgw_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set PGW read timeout");
    for _ in 0..REDIRECT_PROBE_PACKETS {
        if pgw_socket.recv_from(&mut buffer).is_ok() {
            delivered += 1;
        }
    }
    let after = pinned_counter(&pin_dir, COUNTER_UL_ENCAP);
    println!(
        "REPRO grouped traffic after refusal: delivered={delivered} pinned \
         uplink_encapsulated {before} -> {after}"
    );
    assert_eq!(
        delivered, REDIRECT_PROBE_PACKETS,
        "grouped generation 1 must still be forwarding after the refusal"
    );
    assert_eq!(
        after,
        before + u64::from(REDIRECT_PROBE_PACKETS),
        "a refused grouped attach must leave the live generation's counters \
         readable at their pin: a flat counter against live traffic is this \
         datapath's published signature of a total uplink outage"
    );

    drop(net);
    Ok(())
}
