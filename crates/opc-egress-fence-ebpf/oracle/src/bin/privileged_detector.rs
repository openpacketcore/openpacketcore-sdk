//! True-root-cgroup-v2, multiprocess fencing detector.
//!
//! This binary deliberately bypasses the SDK send preflight. Child processes
//! issue ordinary and raw socket syscalls from replacement network namespaces
//! while the parent drives only the frozen kernel control ABI.

use std::{
    env,
    error::Error,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, RawFd},
        unix::{fs::OpenOptionsExt, net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::atomic::{AtomicU32, AtomicU8, Ordering},
    thread,
    time::{Duration, Instant},
};

use aya::{
    maps::{Array, Map, MapData},
    programs::{CgroupSkb, CgroupSkbAttachType, SchedClassifier, TestRun, TestRunOptions},
    Ebpf, EbpfLoader,
};
use opc_linux_gtpu_sys::{
    attach_cgroup_skb_egress, detach_cgroup_skb_egress, freeze_bpf_map, query_cgroup_skb_egress,
    socket_kernel_identity,
};

const RUN_ENV: &str = "OPC_EGRESS_FENCE_RUN_PRIVILEGED";
const DIAGNOSTIC_ENV: &str = "OPC_EGRESS_FENCE_DETECTOR_DIAGNOSTIC";
const ROOT_CGROUP: &str = "/sys/fs/cgroup";
const ROOT_CGROUP_MUTATION_LOCK: &str = "/run/lock/opc-egress-fence-root-cgroup.lock";
const ROOT_CGROUP_ID: u64 = 1;
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;

const PROGRAM_GATE: &str = "opc_egress_gate";
const PROGRAM_CONTROL: &str = "opc_fence_ctl";
const PROGRAM_VIEW: &str = "opc_fence_view";
const MAP_CONFIG: &str = "OPC_FENCE_CFG";
const MAP_COOKIES: &str = "OPC_FENCE_CKS";
const MAP_COUNTERS: &str = "OPC_FENCE_CTR";
const MAP_CURRENT: &str = "OPC_FENCE_CUR";
const MAP_LOCK: &str = "OPC_FENCE_LOCK";
const MAP_MUTATION: &str = "OPC_FENCE_MUT";

const ABI_VERSION: u16 = 5;
const CONFIG_LEN: usize = 40;
const COMMAND_LEN: usize = 48;
const VIEW_LEN: usize = 128;
const CAPACITY: u32 = 4_096;
const CONTROL_FIXED: u64 = u32::from_le_bytes(*b"OEC1") as u64 | (ABI_VERSION as u64) << 32;

const OP_PUBLISH_LIFECYCLE: u8 = 1;
const OP_REGISTER: u8 = 2;
const OP_ACTIVATE: u8 = 3;
const OP_CLOSE: u8 = 5;
const OP_RECLAIM: u8 = 6;
const OP_INSPECT: u8 = 7;
const OP_PUBLISH_RETIREMENT: u8 = 8;
const RESULT_APPLIED: u32 = 0;
const CURRENT_OPEN: u32 = 0x4f45_0201;
const CURRENT_CLOSED: u32 = 0x4f45_0202;
const COOKIE_ACTIVE: u32 = 0x4f45_0102;
const COOKIE_TERMINAL: u32 = 0x4f45_0103;

const PROTECTED_PORT: u16 = 0x1235;
const UNRELATED_SOURCE_PORT: u16 = 0x1237;
const OLD_TRAFFIC_PORT: u16 = 0x4101;
const SUCCESSOR_TRAFFIC_PORT: u16 = 0x4103;
const UNREGISTERED_TRAFFIC_PORT: u16 = 0x4105;
const UNRELATED_TRAFFIC_PORT: u16 = 0x4107;
const RAW_PROTECTED_PORT: u16 = 0x4109;
const RAW_UNRELATED_PORT: u16 = 0x410b;
const TRANSFER_ROUNDS: usize = 64;

const IPV4_PROTECTED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 37);
const IPV4_UNRELATED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 91);
const IPV4_OLD_DESTINATION: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 37);
const IPV4_NEW_DESTINATION: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 91);
const IPV6_PROTECTED: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 0x9abc);
const IPV6_UNRELATED: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x8765, 0x4321, 0, 0, 0, 0xcba9);
const IPV6_OLD_DESTINATION: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 1, 0, 0, 0, 0x2468);
const IPV6_NEW_DESTINATION: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xef01, 2, 0, 0, 0, 0x1357);

const CHILD_READY: u8 = 0x51;
const CHILD_SEND_PROTECTED_OLD: u8 = 0x61;
const CHILD_SEND_PROTECTED_SUCCESSOR: u8 = 0x62;
const CHILD_SEND_PROTECTED_UNREGISTERED: u8 = 0x63;
const CHILD_SEND_UNRELATED: u8 = 0x64;
const CHILD_SEND_RAW_PROTECTED: u8 = 0x65;
const CHILD_SEND_RAW_UNRELATED: u8 = 0x66;
const CHILD_EXIT: u8 = 0x6f;
const CHILD_SEND_OK: u8 = 0x71;
const CHILD_SEND_DENIED: u8 = 0x72;
const CHILD_SEND_FAILED: u8 = 0x73;

static DETECTOR_STAGE: AtomicU8 = AtomicU8::new(0);
static CLEANUP_FAULT: AtomicU8 = AtomicU8::new(0);
static CLEANUP_CHILD_PID: AtomicU32 = AtomicU32::new(0);
const CLEANUP_FAULT_NONE: u8 = 0;
const CLEANUP_FAULT_POST_ATTACH: u8 = 1;
const CLEANUP_FAULT_POST_VETH: u8 = 2;
const CLEANUP_FAULT_POST_CHILD: u8 = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn argument(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "v4" => Some(Self::V4),
            "v6" => Some(Self::V6),
            _ => None,
        }
    }

    fn protected_address(self) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::V4(SocketAddrV4::new(IPV4_PROTECTED, PROTECTED_PORT)),
            Self::V6 => SocketAddr::V6(SocketAddrV6::new(IPV6_PROTECTED, PROTECTED_PORT, 0, 0)),
        }
    }

    fn unrelated_address(self) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::V4(SocketAddrV4::new(IPV4_UNRELATED, UNRELATED_SOURCE_PORT)),
            Self::V6 => SocketAddr::V6(SocketAddrV6::new(
                IPV6_UNRELATED,
                UNRELATED_SOURCE_PORT,
                0,
                0,
            )),
        }
    }

    fn destination(self, replacement: bool, port: u16) -> SocketAddr {
        match (self, replacement) {
            (Self::V4, false) => SocketAddr::V4(SocketAddrV4::new(IPV4_OLD_DESTINATION, port)),
            (Self::V4, true) => SocketAddr::V4(SocketAddrV4::new(IPV4_NEW_DESTINATION, port)),
            (Self::V6, false) => {
                SocketAddr::V6(SocketAddrV6::new(IPV6_OLD_DESTINATION, port, 0, 0))
            }
            (Self::V6, true) => SocketAddr::V6(SocketAddrV6::new(IPV6_NEW_DESTINATION, port, 0, 0)),
        }
    }

    fn config(self) -> [u8; CONFIG_LEN] {
        let mut value = [0_u8; CONFIG_LEN];
        value[0..4].copy_from_slice(b"OEF1");
        value[4..6].copy_from_slice(&ABI_VERSION.to_le_bytes());
        value[6] = match self {
            Self::V4 => 4,
            Self::V6 => 6,
        };
        value[8..10].copy_from_slice(&PROTECTED_PORT.to_be_bytes());
        value[12..16].copy_from_slice(&CAPACITY.to_le_bytes());
        value[16..24].copy_from_slice(&ROOT_CGROUP_ID.to_le_bytes());
        match self {
            Self::V4 => value[24..28].copy_from_slice(&IPV4_PROTECTED.octets()),
            Self::V6 => value[24..40].copy_from_slice(&IPV6_PROTECTED.octets()),
        }
        value
    }
}

fn topology_namespace_names(family: Family) -> (String, String) {
    let suffix = format!(
        "{:x}{}",
        std::process::id(),
        match family {
            Family::V4 => "4",
            Family::V6 => "6",
        }
    );
    (format!("oefs{suffix}"), format!("oefr{suffix}"))
}

fn topology_link_names(replacement: bool) -> (String, String) {
    let phase = if replacement { "n" } else { "o" };
    let suffix = format!("{:x}", std::process::id());
    (format!("es{phase}{suffix}"), format!("er{phase}{suffix}"))
}

fn all_topology_link_names() -> [String; 4] {
    let (old_sender, old_receiver) = topology_link_names(false);
    let (new_sender, new_receiver) = topology_link_names(true);
    [old_sender, old_receiver, new_sender, new_receiver]
}

#[derive(Clone, Copy)]
enum Role {
    Old,
    Successor,
}

impl Role {
    fn argument(self) -> &'static str {
        match self {
            Self::Old => "old",
            Self::Successor => "successor",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "old" => Some(Self::Old),
            "successor" => Some(Self::Successor),
            _ => None,
        }
    }

    fn replacement(self) -> bool {
        matches!(self, Self::Successor)
    }
}

#[derive(Default)]
struct DetectorVerdict {
    unregistered_observed: bool,
    stale_observed: bool,
    expired_observed: bool,
    successor_missing: bool,
    fragment_failed: bool,
}

impl DetectorVerdict {
    fn merge(&mut self, other: Self) {
        self.unregistered_observed |= other.unregistered_observed;
        self.stale_observed |= other.stale_observed;
        self.expired_observed |= other.expired_observed;
        self.successor_missing |= other.successor_missing;
        self.fragment_failed |= other.fragment_failed;
    }

    fn is_pass(&self) -> bool {
        !self.unregistered_observed
            && !self.stale_observed
            && !self.expired_observed
            && !self.successor_missing
            && !self.fragment_failed
    }
}

#[derive(Debug)]
struct Defective;

impl std::fmt::Display for Defective {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("privileged_detector_defective")
    }
}

impl Error for Defective {}

type DetectorResult<T> = Result<T, Defective>;

fn ensure(condition: bool) -> DetectorResult<()> {
    if condition {
        Ok(())
    } else {
        Err(Defective)
    }
}

fn inject_cleanup_failure(point: u8) -> DetectorResult<()> {
    match CLEANUP_FAULT.compare_exchange(
        point,
        CLEANUP_FAULT_NONE,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => Err(Defective),
        Err(_) => Ok(()),
    }
}

fn main() -> ExitCode {
    match dispatch() {
        Ok(Dispatch::Child) => ExitCode::SUCCESS,
        Ok(Dispatch::Probe) => ExitCode::SUCCESS,
        Ok(Dispatch::CleanupPostAttach) => {
            println!("egress-fence privileged cleanup detector: PASS (post-attach)");
            ExitCode::SUCCESS
        }
        Ok(Dispatch::CleanupPostVeth) => {
            println!("egress-fence privileged cleanup detector: PASS (post-veth)");
            ExitCode::SUCCESS
        }
        Ok(Dispatch::CleanupPostChild) => {
            println!("egress-fence privileged cleanup detector: PASS (post-child)");
            ExitCode::SUCCESS
        }
        Ok(Dispatch::Detector(verdict)) if verdict.is_pass() => {
            println!("egress-fence privileged detector: PASS");
            ExitCode::SUCCESS
        }
        Ok(Dispatch::Detector(verdict)) => {
            if verdict.stale_observed {
                println!(
                    "egress-fence privileged detector: RED (stale-authority traffic observed)"
                );
            } else if verdict.expired_observed {
                println!(
                    "egress-fence privileged detector: RED (expired-authority traffic observed)"
                );
            } else if verdict.unregistered_observed {
                println!(
                    "egress-fence privileged detector: RED (unregistered protected traffic observed)"
                );
            } else {
                println!("egress-fence privileged detector: RED (kernel policy mismatch)");
            }
            ExitCode::from(1)
        }
        Err(_) => {
            if env::var_os(DIAGNOSTIC_ENV).as_deref() == Some("1".as_ref()) {
                eprintln!(
                    "egress-fence privileged detector diagnostic: stage-{}",
                    DETECTOR_STAGE.load(Ordering::Relaxed)
                );
            }
            println!("egress-fence privileged detector: DEFECTIVE (host validation incomplete)");
            ExitCode::from(2)
        }
    }
}

enum Dispatch {
    Child,
    Probe,
    CleanupPostAttach,
    CleanupPostVeth,
    CleanupPostChild,
    Detector(DetectorVerdict),
}

fn dispatch() -> DetectorResult<Dispatch> {
    let arguments = env::args().collect::<Vec<_>>();
    match arguments.get(1).map(String::as_str) {
        Some("--sender-child") => {
            let fd = arguments
                .get(2)
                .and_then(|value| value.parse::<RawFd>().ok())
                .ok_or(Defective)?;
            let family = arguments
                .get(3)
                .and_then(|value| Family::parse(value))
                .ok_or(Defective)?;
            let role = arguments
                .get(4)
                .and_then(|value| Role::parse(value))
                .ok_or(Defective)?;
            sender_child(fd, family, role)?;
            Ok(Dispatch::Child)
        }
        Some("--lock-probe") => {
            lock_probe()?;
            Ok(Dispatch::Probe)
        }
        Some("--production" | "--mutation") => {
            ensure(env::var_os(RUN_ENV).as_deref() == Some("1".as_ref()))?;
            ensure(unsafe { libc::geteuid() } == 0)?;
            let object = arguments.get(2).map(PathBuf::from).ok_or(Defective)?;
            ensure(object.is_absolute() && object.is_file())?;
            DETECTOR_STAGE.store(1, Ordering::Relaxed);
            let _lock = DetectorLock::acquire()?;
            verify_parallel_lock()?;
            DETECTOR_STAGE.store(2, Ordering::Relaxed);
            isolate_mount_namespace()?;
            let mut verdict = DetectorVerdict::default();
            for family in [Family::V4, Family::V6] {
                verdict.merge(run_family(&object, family)?);
            }
            Ok(Dispatch::Detector(verdict))
        }
        Some(
            mode @ ("--cleanup-fault-attach" | "--cleanup-fault-veth" | "--cleanup-fault-child"),
        ) => {
            ensure(env::var_os(RUN_ENV).as_deref() == Some("1".as_ref()))?;
            ensure(unsafe { libc::geteuid() } == 0)?;
            let object = arguments.get(2).map(PathBuf::from).ok_or(Defective)?;
            ensure(object.is_absolute() && object.is_file())?;
            DETECTOR_STAGE.store(40, Ordering::Relaxed);
            let _lock = DetectorLock::acquire()?;
            verify_parallel_lock()?;
            isolate_mount_namespace()?;
            let point = match mode {
                "--cleanup-fault-attach" => CLEANUP_FAULT_POST_ATTACH,
                "--cleanup-fault-veth" => CLEANUP_FAULT_POST_VETH,
                "--cleanup-fault-child" => CLEANUP_FAULT_POST_CHILD,
                _ => return Err(Defective),
            };
            run_cleanup_fault(&object, point)?;
            Ok(match point {
                CLEANUP_FAULT_POST_ATTACH => Dispatch::CleanupPostAttach,
                CLEANUP_FAULT_POST_VETH => Dispatch::CleanupPostVeth,
                CLEANUP_FAULT_POST_CHILD => Dispatch::CleanupPostChild,
                _ => return Err(Defective),
            })
        }
        _ => Err(Defective),
    }
}

struct DetectorLock {
    file: File,
}

impl DetectorLock {
    fn acquire() -> DetectorResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(ROOT_CGROUP_MUTATION_LOCK)
            .map_err(|_| Defective)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        ensure(result == 0)?;
        Ok(Self { file })
    }
}

impl Drop for DetectorLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn lock_probe() -> DetectorResult<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(ROOT_CGROUP_MUTATION_LOCK)
        .map_err(|_| Defective)?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    ensure(result != 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock)
}

fn verify_parallel_lock() -> DetectorResult<()> {
    let executable = env::current_exe().map_err(|_| Defective)?;
    let status = Command::new(executable)
        .arg("--lock-probe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Defective)?;
    ensure(status.success())
}

fn isolate_mount_namespace() -> DetectorResult<()> {
    ensure(unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0)?;
    let root = CString::new("/").map_err(|_| Defective)?;
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    ensure(result == 0)
}

fn run_cleanup_fault(object: &Path, point: u8) -> DetectorResult<()> {
    ensure(matches!(
        point,
        CLEANUP_FAULT_POST_ATTACH | CLEANUP_FAULT_POST_VETH | CLEANUP_FAULT_POST_CHILD
    ))?;
    let family = Family::V4;
    verify_cleanup_inventory(family)?;
    CLEANUP_CHILD_PID.store(0, Ordering::SeqCst);
    ensure(
        CLEANUP_FAULT
            .compare_exchange(
                CLEANUP_FAULT_NONE,
                point,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok(),
    )?;

    let result = match point {
        CLEANUP_FAULT_POST_ATTACH => Installation::install(object, family).map(drop),
        CLEANUP_FAULT_POST_VETH | CLEANUP_FAULT_POST_CHILD => (|| {
            let _installation = Installation::install(object, family)?;
            let _topology = Topology::create(family)?;
            Ok(())
        })(),
        _ => Err(Defective),
    };
    let remaining_fault = CLEANUP_FAULT.swap(CLEANUP_FAULT_NONE, Ordering::SeqCst);
    ensure(result.is_err() && remaining_fault == CLEANUP_FAULT_NONE)?;
    if point == CLEANUP_FAULT_POST_CHILD {
        verify_cleanup_child_reaped()?;
    } else {
        ensure(CLEANUP_CHILD_PID.load(Ordering::SeqCst) == 0)?;
    }
    verify_cleanup_inventory(family)
}

fn verify_cleanup_child_reaped() -> DetectorResult<()> {
    let pid = CLEANUP_CHILD_PID.swap(0, Ordering::SeqCst);
    ensure(pid != 0 && pid <= i32::MAX as u32)?;
    let pid = pid as libc::pid_t;
    let mut status = 0_i32;
    let wait_result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    ensure(wait_result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))?;
    let kill_result = unsafe { libc::kill(pid, 0) };
    ensure(kill_result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
}

fn verify_cleanup_inventory(family: Family) -> DetectorResult<()> {
    let root = RootCgroup::open()?;
    let inventory = query_cgroup_skb_egress(root.file.as_fd()).map_err(|_| Defective)?;
    ensure(inventory.attachments().is_empty() && inventory.attach_flags() == 0)?;

    let (sender_namespace, receiver_namespace) = topology_namespace_names(family);
    for namespace in [sender_namespace, receiver_namespace] {
        ensure_path_absent(&Path::new("/run/netns").join(namespace))?;
    }
    for link in all_topology_link_names() {
        ensure_path_absent(&Path::new("/sys/class/net").join(link))?;
    }

    let pin_directory = PinMount::directory();
    ensure_path_absent(&pin_directory)?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(|_| Defective)?;
    let pin_target = pin_directory.to_str().ok_or(Defective)?;
    ensure(
        !mountinfo
            .lines()
            .any(|line| line.split_whitespace().nth(4) == Some(pin_target)),
    )
}

fn ensure_path_absent(path: &Path) -> DetectorResult<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(Defective),
    }
}

struct PinMount {
    directory: PathBuf,
    mounted: bool,
    directory_present: bool,
}

impl PinMount {
    fn directory() -> PathBuf {
        PathBuf::from(format!(
            "/run/opc-egress-fence-detector-bpffs-{}",
            std::process::id()
        ))
    }

    fn create() -> DetectorResult<Self> {
        let directory = Self::directory();
        if directory.exists() {
            fs::remove_dir(&directory).map_err(|_| Defective)?;
        }
        fs::create_dir(&directory).map_err(|_| Defective)?;
        let mut pin_mount = Self {
            directory,
            mounted: false,
            directory_present: true,
        };
        let source = CString::new("bpf").map_err(|_| Defective)?;
        let target = CString::new(pin_mount.directory.as_os_str().as_encoded_bytes())
            .map_err(|_| Defective)?;
        let filesystem = CString::new("bpf").map_err(|_| Defective)?;
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
                std::ptr::null(),
            )
        };
        ensure(result == 0)?;
        pin_mount.mounted = true;
        Ok(pin_mount)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn unmount(mut self) -> DetectorResult<()> {
        ensure(unsafe { libc::umount2(c_path(&self.directory)?.as_ptr(), libc::MNT_DETACH) } == 0)?;
        self.mounted = false;
        fs::remove_dir(&self.directory).map_err(|_| Defective)?;
        self.directory_present = false;
        Ok(())
    }
}

impl Drop for PinMount {
    fn drop(&mut self) {
        if self.mounted {
            if let Ok(path) = c_path(&self.directory) {
                unsafe {
                    libc::umount2(path.as_ptr(), libc::MNT_DETACH);
                }
            }
            self.mounted = false;
        }
        if self.directory_present && fs::remove_dir(&self.directory).is_ok() {
            self.directory_present = false;
        }
    }
}

fn c_path(path: &Path) -> DetectorResult<CString> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Defective)
}

struct RootCgroup {
    file: File,
}

impl RootCgroup {
    fn open() -> DetectorResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .open(ROOT_CGROUP)
            .map_err(|_| Defective)?;
        let mut filesystem = unsafe { std::mem::zeroed::<libc::statfs>() };
        ensure(unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } == 0)?;
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        ensure(unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) } == 0)?;
        ensure(
            filesystem.f_type as u64 == CGROUP2_SUPER_MAGIC
                && metadata.st_ino == ROOT_CGROUP_ID
                && metadata.st_mode & libc::S_IFMT == libc::S_IFDIR,
        )?;
        Ok(Self { file })
    }
}

#[derive(Clone, Copy)]
struct CommandInput {
    operation: u8,
    cookie: u64,
    token: u64,
    deadline: u64,
    epoch: u64,
}

impl CommandInput {
    fn encode(self) -> [u8; COMMAND_LEN] {
        let mut value = [0_u8; COMMAND_LEN];
        let header = CONTROL_FIXED | u64::from(self.operation) << 48;
        value[0..8].copy_from_slice(&header.to_le_bytes());
        value[8..16].copy_from_slice(&ROOT_CGROUP_ID.to_le_bytes());
        value[16..24].copy_from_slice(&self.cookie.to_le_bytes());
        value[24..32].copy_from_slice(&self.token.to_le_bytes());
        value[32..40].copy_from_slice(&self.deadline.to_le_bytes());
        value[40..48].copy_from_slice(&self.epoch.to_le_bytes());
        value
    }
}

#[derive(Clone, Copy)]
struct CurrentSnapshot {
    control: u32,
    token: u64,
    cookie: u64,
}

#[derive(Clone, Copy)]
struct EntrySnapshot {
    control: u32,
    cookie: u64,
    token: u64,
    deadline: u64,
    epoch: u64,
}

struct KernelControl {
    mutation: SchedClassifier,
    view: SchedClassifier,
}

impl KernelControl {
    fn mutate(&self, command: CommandInput) -> DetectorResult<u32> {
        let input = command.encode();
        let mut output = [0_u8; COMMAND_LEN];
        let result = self
            .mutation
            .test_run(TestRunOptions {
                data_in: Some(&input),
                data_out: Some(&mut output),
                repeat: 1,
                ..TestRunOptions::default()
            })
            .map_err(|_| Defective)?;
        ensure(
            result.data_size_out == COMMAND_LEN as u32
                && result.ctx_size_out == 0
                && output == input,
        )?;
        Ok(result.return_value)
    }

    fn applied(&self, command: CommandInput) -> DetectorResult<()> {
        ensure(self.mutate(command)? == RESULT_APPLIED)
    }

    fn inspect(
        &self,
        cookie: u64,
        token: u64,
    ) -> DetectorResult<(CurrentSnapshot, Option<EntrySnapshot>)> {
        let command = CommandInput {
            operation: OP_INSPECT,
            cookie,
            token,
            deadline: 0,
            epoch: 0,
        }
        .encode();
        let mut input = [0_u8; VIEW_LEN];
        input[..COMMAND_LEN].copy_from_slice(&command);
        let mut output = [0_u8; VIEW_LEN];
        let result = self
            .view
            .test_run(TestRunOptions {
                data_in: Some(&input),
                data_out: Some(&mut output),
                repeat: 1,
                ..TestRunOptions::default()
            })
            .map_err(|_| Defective)?;
        ensure(
            result.return_value == RESULT_APPLIED
                && result.data_size_out == VIEW_LEN as u32
                && result.ctx_size_out == 0
                && get_u32(&output, 0) == u32::from_le_bytes(*b"OEI1")
                && get_u16(&output, 4) == ABI_VERSION
                && output[7] == 0,
        )?;
        ensure(get_u64(&output, 40) == 0)?;
        let current = CurrentSnapshot {
            control: get_u32(&output, 12),
            token: get_u64(&output, 16),
            cookie: get_u64(&output, 24),
        };
        let entry = if output[6] == 0 {
            None
        } else {
            Some(EntrySnapshot {
                control: get_u32(&output, 52),
                cookie: get_u64(&output, 56),
                token: get_u64(&output, 64),
                deadline: get_u64(&output, 72),
                epoch: get_u64(&output, 80),
            })
        };
        Ok((current, entry))
    }

    fn emergency_close(&self) -> DetectorResult<()> {
        self.applied(CommandInput {
            operation: OP_PUBLISH_LIFECYCLE,
            cookie: 0,
            token: u64::MAX,
            deadline: 0,
            epoch: 0,
        })
    }
}

struct Installation {
    root: RootCgroup,
    gate: CgroupSkb,
    control: KernelControl,
    program_id: u32,
    attached_revision: u64,
    detached: bool,
    orderly_closed: bool,
}

impl Installation {
    fn install(object: &Path, family: Family) -> DetectorResult<Self> {
        DETECTOR_STAGE.store(10, Ordering::Relaxed);
        let root = RootCgroup::open()?;
        let before = query_cgroup_skb_egress(root.file.as_fd()).map_err(|_| Defective)?;
        ensure(
            before.attachments().is_empty()
                && before.attach_flags() == 0
                && before.revision() != u64::MAX,
        )?;

        DETECTOR_STAGE.store(11, Ordering::Relaxed);
        let pins = PinMount::create()?;
        let gate_pin = pins.path("gate");
        let control_pin = pins.path("control");
        let view_pin = pins.path("view");
        DETECTOR_STAGE.store(12, Ordering::Relaxed);
        let mut ebpf = EbpfLoader::new().load_file(object).map_err(|_| Defective)?;
        verify_inventory(&ebpf)?;
        DETECTOR_STAGE.store(13, Ordering::Relaxed);
        {
            let map = ebpf.map_mut(MAP_CONFIG).ok_or(Defective)?;
            let mut config: Array<_, [u8; CONFIG_LEN]> =
                Array::try_from(map).map_err(|_| Defective)?;
            config.set(0, family.config(), 0).map_err(|_| Defective)?;
        }
        for name in [
            MAP_CONFIG,
            MAP_COOKIES,
            MAP_COUNTERS,
            MAP_CURRENT,
            MAP_MUTATION,
        ] {
            let map = ebpf.map(name).ok_or(Defective)?;
            let data = map_data(map).ok_or(Defective)?;
            freeze_bpf_map(data.fd().as_fd()).map_err(|_| Defective)?;
        }
        {
            let gate: &mut CgroupSkb = ebpf
                .program_mut(PROGRAM_GATE)
                .ok_or(Defective)?
                .try_into()
                .map_err(|_| Defective)?;
            gate.load().map_err(|_| Defective)?;
            gate.pin(&gate_pin).map_err(|_| Defective)?;
        }
        {
            let control: &mut SchedClassifier = ebpf
                .program_mut(PROGRAM_CONTROL)
                .ok_or(Defective)?
                .try_into()
                .map_err(|_| Defective)?;
            control.load().map_err(|_| Defective)?;
            control.pin(&control_pin).map_err(|_| Defective)?;
        }
        {
            let view: &mut SchedClassifier = ebpf
                .program_mut(PROGRAM_VIEW)
                .ok_or(Defective)?
                .try_into()
                .map_err(|_| Defective)?;
            view.load().map_err(|_| Defective)?;
            view.pin(&view_pin).map_err(|_| Defective)?;
        }

        DETECTOR_STAGE.store(14, Ordering::Relaxed);
        let gate =
            CgroupSkb::from_pin(&gate_pin, CgroupSkbAttachType::Egress).map_err(|_| Defective)?;
        let control = SchedClassifier::from_pin(&control_pin).map_err(|_| Defective)?;
        let view = SchedClassifier::from_pin(&view_pin).map_err(|_| Defective)?;
        let program_id = gate.info().map_err(|_| Defective)?.id();
        ensure(program_id != 0)?;

        let original_gate: &CgroupSkb = ebpf
            .program(PROGRAM_GATE)
            .ok_or(Defective)?
            .try_into()
            .map_err(|_| Defective)?;
        let expected_revision = before.revision().checked_add(1).ok_or(Defective)?;
        DETECTOR_STAGE.store(15, Ordering::Relaxed);
        attach_cgroup_skb_egress(
            root.file.as_fd(),
            original_gate.fd().map_err(|_| Defective)?.as_fd(),
            before.revision(),
        )
        .map_err(|_| Defective)?;
        let installation = Self {
            root,
            gate,
            control: KernelControl {
                mutation: control,
                view,
            },
            program_id,
            attached_revision: expected_revision,
            detached: false,
            orderly_closed: false,
        };
        inject_cleanup_failure(CLEANUP_FAULT_POST_ATTACH)?;

        let after =
            query_cgroup_skb_egress(installation.root.file.as_fd()).map_err(|_| Defective)?;
        ensure(exact_attachment(&after, expected_revision, program_id))?;

        DETECTOR_STAGE.store(16, Ordering::Relaxed);
        drop(ebpf);
        let after_loader_fd_loss =
            query_cgroup_skb_egress(installation.root.file.as_fd()).map_err(|_| Defective)?;
        ensure(exact_attachment(
            &after_loader_fd_loss,
            expected_revision,
            program_id,
        ))?;
        fs::remove_file(&gate_pin).map_err(|_| Defective)?;
        fs::remove_file(&control_pin).map_err(|_| Defective)?;
        fs::remove_file(&view_pin).map_err(|_| Defective)?;
        let after_pin_loss =
            query_cgroup_skb_egress(installation.root.file.as_fd()).map_err(|_| Defective)?;
        ensure(exact_attachment(
            &after_pin_loss,
            expected_revision,
            program_id,
        ))?;
        pins.unmount()?;
        DETECTOR_STAGE.store(17, Ordering::Relaxed);

        Ok(installation)
    }

    fn verify_attachment(&self) -> DetectorResult<()> {
        let query = query_cgroup_skb_egress(self.root.file.as_fd()).map_err(|_| Defective)?;
        ensure(exact_attachment(
            &query,
            self.attached_revision,
            self.program_id,
        ))
    }

    fn detach_exact(&mut self) -> DetectorResult<()> {
        self.verify_attachment()?;
        ensure(self.orderly_closed)?;
        detach_cgroup_skb_egress(
            self.root.file.as_fd(),
            self.gate.fd().map_err(|_| Defective)?.as_fd(),
            self.attached_revision,
        )
        .map_err(|_| Defective)?;
        let after = query_cgroup_skb_egress(self.root.file.as_fd()).map_err(|_| Defective)?;
        ensure(
            after.attachments().is_empty()
                && after.attach_flags() == 0
                && after.revision() == self.attached_revision + 1,
        )?;
        self.detached = true;
        Ok(())
    }
}

impl Drop for Installation {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        let _ = self.control.emergency_close();
        self.orderly_closed = true;
        if self.verify_attachment().is_ok() {
            if let Ok(gate_fd) = self.gate.fd() {
                if detach_cgroup_skb_egress(
                    self.root.file.as_fd(),
                    gate_fd.as_fd(),
                    self.attached_revision,
                )
                .is_ok()
                {
                    self.detached = true;
                }
            }
        }
    }
}

fn exact_attachment(
    query: &opc_linux_gtpu_sys::BpfCgroupProgramQuery,
    revision: u64,
    program_id: u32,
) -> bool {
    query.revision() == revision
        && query.attach_flags() == BPF_F_ALLOW_MULTI
        && query.attachments().len() == 1
        && query.attachments()[0].program_id() == program_id
        && query.attachments()[0].program_attach_flags() == BPF_F_ALLOW_MULTI
}

fn verify_inventory(ebpf: &Ebpf) -> DetectorResult<()> {
    let names = ebpf.programs().map(|(name, _)| name).collect::<Vec<_>>();
    ensure(
        names.len() == 3
            && names.contains(&PROGRAM_GATE)
            && names.contains(&PROGRAM_CONTROL)
            && names.contains(&PROGRAM_VIEW),
    )?;
    verify_map(ebpf, MAP_CONFIG, 4, CONFIG_LEN as u32, 1)?;
    verify_map(ebpf, MAP_COOKIES, 16, 40, CAPACITY)?;
    verify_map(ebpf, MAP_COUNTERS, 4, 8, 8)?;
    verify_map(ebpf, MAP_CURRENT, 4, 24, 1)?;
    verify_map(ebpf, MAP_LOCK, 4, 4, 1)?;
    verify_map(ebpf, MAP_MUTATION, 4, 16, 1)
}

fn verify_map(
    ebpf: &Ebpf,
    name: &str,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> DetectorResult<()> {
    let map = ebpf.map(name).ok_or(Defective)?;
    let data = map_data(map).ok_or(Defective)?;
    let info = data.info().map_err(|_| Defective)?;
    ensure(
        info.key_size() == key_size
            && info.value_size() == value_size
            && info.max_entries() == max_entries
            && info.map_flags() == 0,
    )
}

fn map_data(map: &Map) -> Option<&MapData> {
    match map {
        Map::Array(data) | Map::HashMap(data) | Map::PerCpuArray(data) => Some(data),
        _ => None,
    }
}

struct HostLinkGuard {
    host_name: Option<String>,
}

impl HostLinkGuard {
    fn new(host_name: String) -> Self {
        Self {
            host_name: Some(host_name),
        }
    }

    fn track(&mut self, host_name: String) {
        self.host_name = Some(host_name);
    }

    fn disarm(&mut self) {
        self.host_name = None;
    }
}

impl Drop for HostLinkGuard {
    fn drop(&mut self) {
        if let Some(host_name) = self.host_name.take() {
            let _ = quiet_ip(&["link", "del", &host_name]);
        }
    }
}

struct Topology {
    sender_namespace: String,
    receiver_namespace: String,
    old: Option<SenderProcess>,
    successor: Option<SenderProcess>,
}

impl Topology {
    fn create(family: Family) -> DetectorResult<Self> {
        let (sender_namespace, receiver_namespace) = topology_namespace_names(family);
        run_ip(&["netns", "add", &sender_namespace])?;
        if let Err(error) = run_ip(&["netns", "add", &receiver_namespace]) {
            let _ = quiet_ip(&["netns", "del", &sender_namespace]);
            return Err(error);
        }
        let mut topology = Self {
            sender_namespace,
            receiver_namespace,
            old: None,
            successor: None,
        };
        topology.provision_link(family, false)?;
        topology.old = Some(SenderProcess::spawn(
            &topology.sender_namespace,
            family,
            Role::Old,
        )?);
        Ok(topology)
    }

    fn provision_link(&self, family: Family, replacement: bool) -> DetectorResult<()> {
        let (host_sender, host_receiver) = topology_link_names(replacement);
        ensure(host_sender.len() < libc::IFNAMSIZ)?;
        ensure(host_receiver.len() < libc::IFNAMSIZ)?;
        run_ip(&[
            "link",
            "add",
            &host_sender,
            "type",
            "veth",
            "peer",
            "name",
            &host_receiver,
        ])?;
        let mut link_guard = HostLinkGuard::new(host_sender.clone());
        inject_cleanup_failure(CLEANUP_FAULT_POST_VETH)?;
        run_ip(&["link", "set", &host_sender, "netns", &self.sender_namespace])?;
        link_guard.track(host_receiver.clone());
        run_ip(&[
            "link",
            "set",
            &host_receiver,
            "netns",
            &self.receiver_namespace,
        ])?;
        link_guard.disarm();
        run_ip(&["-n", &self.sender_namespace, "link", "set", "lo", "up"])?;
        run_ip(&["-n", &self.receiver_namespace, "link", "set", "lo", "up"])?;
        run_ip(&[
            "-n",
            &self.sender_namespace,
            "link",
            "set",
            &host_sender,
            "name",
            "fence0",
        ])?;
        run_ip(&["-n", &self.sender_namespace, "link", "set", "fence0", "up"])?;
        run_ip(&[
            "-n",
            &self.receiver_namespace,
            "link",
            "set",
            &host_receiver,
            "up",
        ])?;
        match family {
            Family::V4 => {
                let destination = if replacement {
                    IPV4_NEW_DESTINATION
                } else {
                    IPV4_OLD_DESTINATION
                };
                run_ip(&[
                    "-n",
                    &self.sender_namespace,
                    "address",
                    "add",
                    &format!("{IPV4_PROTECTED}/32"),
                    "dev",
                    "fence0",
                ])?;
                run_ip(&[
                    "-n",
                    &self.sender_namespace,
                    "address",
                    "add",
                    &format!("{IPV4_UNRELATED}/32"),
                    "dev",
                    "fence0",
                ])?;
                run_ip(&[
                    "-n",
                    &self.receiver_namespace,
                    "address",
                    "add",
                    &format!("{destination}/32"),
                    "dev",
                    &host_receiver,
                ])?;
                run_ip(&[
                    "-n",
                    &self.sender_namespace,
                    "route",
                    "add",
                    &format!("{destination}/32"),
                    "dev",
                    "fence0",
                ])?;
                quiet_command(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.receiver_namespace,
                        "sysctl",
                        "-q",
                        "-w",
                        "net.ipv4.conf.all.rp_filter=0",
                    ],
                )?;
                let receiver_rp_filter = format!("net.ipv4.conf.{host_receiver}.rp_filter=0");
                quiet_command(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.receiver_namespace,
                        "sysctl",
                        "-q",
                        "-w",
                        &receiver_rp_filter,
                    ],
                )?;
            }
            Family::V6 => {
                let destination = if replacement {
                    IPV6_NEW_DESTINATION
                } else {
                    IPV6_OLD_DESTINATION
                };
                run_ip(&[
                    "-n",
                    &self.sender_namespace,
                    "-6",
                    "address",
                    "add",
                    &format!("{IPV6_PROTECTED}/128"),
                    "dev",
                    "fence0",
                    "nodad",
                ])?;
                run_ip(&[
                    "-n",
                    &self.sender_namespace,
                    "-6",
                    "address",
                    "add",
                    &format!("{IPV6_UNRELATED}/128"),
                    "dev",
                    "fence0",
                    "nodad",
                ])?;
                run_ip(&[
                    "-n",
                    &self.receiver_namespace,
                    "-6",
                    "address",
                    "add",
                    &format!("{destination}/128"),
                    "dev",
                    &host_receiver,
                    "nodad",
                ])?;
                run_ip(&[
                    "-n",
                    &self.sender_namespace,
                    "-6",
                    "route",
                    "add",
                    &format!("{destination}/128"),
                    "dev",
                    "fence0",
                ])?;
            }
        }
        Ok(())
    }

    fn replace_sender(&mut self, family: Family) -> DetectorResult<()> {
        run_ip(&["netns", "del", &self.sender_namespace])?;
        run_ip(&["netns", "add", &self.sender_namespace])?;
        self.provision_link(family, true)?;
        self.successor = Some(SenderProcess::spawn(
            &self.sender_namespace,
            family,
            Role::Successor,
        )?);
        Ok(())
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        self.old.take();
        self.successor.take();
        let _ = quiet_ip(&["netns", "del", &self.sender_namespace]);
        let _ = quiet_ip(&["netns", "del", &self.receiver_namespace]);
        for link in all_topology_link_names() {
            let _ = quiet_ip(&["link", "del", &link]);
        }
    }
}

struct SenderProcess {
    child: Child,
    channel: UnixStream,
    cookie: u64,
    stopped: bool,
}

impl SenderProcess {
    fn spawn(namespace: &str, family: Family, role: Role) -> DetectorResult<Self> {
        let namespace_file =
            File::open(format!("/run/netns/{namespace}")).map_err(|_| Defective)?;
        let namespace_fd = namespace_file.as_raw_fd();
        let (parent_channel, child_channel) = UnixStream::pair().map_err(|_| Defective)?;
        let child_fd = child_channel.as_raw_fd();
        ensure(unsafe { libc::fcntl(child_fd, libc::F_SETFD, 0) } == 0)?;
        let executable = env::current_exe().map_err(|_| Defective)?;
        let mut command = Command::new(executable);
        command
            .arg("--sender-child")
            .arg(child_fd.to_string())
            .arg(family.argument())
            .arg(role.argument())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if libc::setns(namespace_fd, libc::CLONE_NEWNET) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|_| Defective)?;
        drop(child_channel);
        drop(namespace_file);
        let mut process = Self {
            child,
            channel: parent_channel,
            cookie: 0,
            stopped: false,
        };
        if CLEANUP_FAULT.load(Ordering::SeqCst) == CLEANUP_FAULT_POST_CHILD {
            CLEANUP_CHILD_PID.store(process.child.id(), Ordering::SeqCst);
        }
        inject_cleanup_failure(CLEANUP_FAULT_POST_CHILD)?;
        process
            .channel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| Defective)?;
        let mut ready = [0_u8; 9];
        process
            .channel
            .read_exact(&mut ready)
            .map_err(|_| Defective)?;
        ensure(ready[0] == CHILD_READY)?;
        process.cookie = u64::from_le_bytes(ready[1..9].try_into().map_err(|_| Defective)?);
        ensure(process.cookie != 0)?;
        Ok(process)
    }

    fn send(&mut self, command: u8) -> DetectorResult<u8> {
        self.channel.write_all(&[command]).map_err(|_| Defective)?;
        let mut response = [0_u8; 1];
        self.channel
            .read_exact(&mut response)
            .map_err(|_| Defective)?;
        ensure(matches!(
            response[0],
            CHILD_SEND_OK | CHILD_SEND_DENIED | CHILD_SEND_FAILED
        ))?;
        if response[0] == CHILD_SEND_FAILED {
            return Err(Defective);
        }
        Ok(response[0])
    }

    fn stop(&mut self) -> DetectorResult<()> {
        ensure(!self.stopped)?;
        ensure(unsafe { libc::kill(self.child.id() as i32, libc::SIGSTOP) } == 0)?;
        let mut status = 0_i32;
        ensure(
            unsafe { libc::waitpid(self.child.id() as i32, &mut status, libc::WUNTRACED) }
                == self.child.id() as i32,
        )?;
        ensure(libc::WIFSTOPPED(status))?;
        self.stopped = true;
        Ok(())
    }

    fn resume(&mut self) -> DetectorResult<()> {
        ensure(self.stopped)?;
        ensure(unsafe { libc::kill(self.child.id() as i32, libc::SIGCONT) } == 0)?;
        self.stopped = false;
        Ok(())
    }
}

impl Drop for SenderProcess {
    fn drop(&mut self) {
        if self.stopped {
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGCONT);
            }
            self.stopped = false;
        }
        let _ = self.channel.write_all(&[CHILD_EXIT]);
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

struct Receivers {
    old: UdpSocket,
    successor: UdpSocket,
    unregistered: UdpSocket,
    unrelated: UdpSocket,
    raw_protected: UdpSocket,
    raw_unrelated: UdpSocket,
}

impl Receivers {
    fn bind(namespace: &str, family: Family) -> DetectorResult<Self> {
        let namespace = namespace.to_owned();
        thread::Builder::new()
            .name("egress-fence-receiver".to_owned())
            .spawn(move || {
                let namespace =
                    File::open(format!("/run/netns/{namespace}")).map_err(|_| Defective)?;
                ensure(unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == 0)?;
                Ok(Self {
                    old: bind_receiver(family, OLD_TRAFFIC_PORT)?,
                    successor: bind_receiver(family, SUCCESSOR_TRAFFIC_PORT)?,
                    unregistered: bind_receiver(family, UNREGISTERED_TRAFFIC_PORT)?,
                    unrelated: bind_receiver(family, UNRELATED_TRAFFIC_PORT)?,
                    raw_protected: bind_receiver(family, RAW_PROTECTED_PORT)?,
                    raw_unrelated: bind_receiver(family, RAW_UNRELATED_PORT)?,
                })
            })
            .map_err(|_| Defective)?
            .join()
            .map_err(|_| Defective)?
    }
}

fn bind_receiver(family: Family, port: u16) -> DetectorResult<UdpSocket> {
    let address = match family {
        Family::V4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
        Family::V6 => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)),
    };
    let socket = UdpSocket::bind(address).map_err(|_| Defective)?;
    socket.set_nonblocking(true).map_err(|_| Defective)?;
    Ok(socket)
}

fn run_family(object: &Path, family: Family) -> DetectorResult<DetectorVerdict> {
    let mut installation = Installation::install(object, family)?;
    DETECTOR_STAGE.store(20, Ordering::Relaxed);
    let mut topology = Topology::create(family)?;
    DETECTOR_STAGE.store(21, Ordering::Relaxed);
    let receivers = Receivers::bind(&topology.receiver_namespace, family)?;
    let old_cookie = topology.old.as_ref().ok_or(Defective)?.cookie;
    let mut verdict = DetectorVerdict::default();

    DETECTOR_STAGE.store(22, Ordering::Relaxed);
    topology
        .old
        .as_mut()
        .ok_or(Defective)?
        .send(CHILD_SEND_PROTECTED_UNREGISTERED)?;
    verdict.unregistered_observed =
        collect(&receivers.unregistered, Duration::from_millis(150))? != 0;

    DETECTOR_STAGE.store(23, Ordering::Relaxed);
    topology
        .old
        .as_mut()
        .ok_or(Defective)?
        .send(CHILD_SEND_UNRELATED)?;
    let unrelated_count = collect_until(&receivers.unrelated, 1, Duration::from_secs(1))?;
    DETECTOR_STAGE.store(36, Ordering::Relaxed);
    ensure(unrelated_count == 1)?;

    topology
        .old
        .as_mut()
        .ok_or(Defective)?
        .send(CHILD_SEND_RAW_PROTECTED)?;
    let protected_fragments = collect(&receivers.raw_protected, Duration::from_millis(200))?;
    topology
        .old
        .as_mut()
        .ok_or(Defective)?
        .send(CHILD_SEND_RAW_UNRELATED)?;
    let unrelated_fragments = collect_until(&receivers.raw_unrelated, 1, Duration::from_secs(1))?;
    verdict.fragment_failed = protected_fragments != 0 || unrelated_fragments != 1;

    DETECTOR_STAGE.store(24, Ordering::Relaxed);
    installation.control.applied(CommandInput {
        operation: OP_PUBLISH_LIFECYCLE,
        cookie: 0,
        token: 1,
        deadline: 0,
        epoch: 0,
    })?;
    DETECTOR_STAGE.store(29, Ordering::Relaxed);
    installation.control.applied(CommandInput {
        operation: OP_REGISTER,
        cookie: old_cookie,
        token: 1,
        deadline: 0,
        epoch: 0,
    })?;
    DETECTOR_STAGE.store(30, Ordering::Relaxed);
    let old_deadline = boottime_ns()?.checked_add(500_000_000).ok_or(Defective)?;
    installation.control.applied(CommandInput {
        operation: OP_ACTIVATE,
        cookie: old_cookie,
        token: 1,
        deadline: old_deadline,
        epoch: 1,
    })?;
    DETECTOR_STAGE.store(31, Ordering::Relaxed);
    let (current, entry) = installation.control.inspect(old_cookie, 1)?;
    ensure(
        current.control == CURRENT_OPEN
            && current.token == 1
            && current.cookie == old_cookie
            && entry
                .map(|entry| {
                    entry.control == COOKIE_ACTIVE
                        && entry.cookie == old_cookie
                        && entry.token == 1
                        && entry.deadline == old_deadline
                        && entry.epoch == 2
                })
                .unwrap_or(false),
    )?;
    DETECTOR_STAGE.store(32, Ordering::Relaxed);
    installation.verify_attachment()?;

    DETECTOR_STAGE.store(33, Ordering::Relaxed);
    topology
        .old
        .as_mut()
        .ok_or(Defective)?
        .send(CHILD_SEND_PROTECTED_OLD)?;
    DETECTOR_STAGE.store(34, Ordering::Relaxed);
    let old_count = collect_until(&receivers.old, 1, Duration::from_secs(1))?;
    DETECTOR_STAGE.store(35, Ordering::Relaxed);
    ensure(old_count == 1)?;

    DETECTOR_STAGE.store(25, Ordering::Relaxed);
    topology.old.as_mut().ok_or(Defective)?.stop()?;
    while boottime_ns()? <= old_deadline {
        thread::sleep(Duration::from_millis(5));
    }

    // Prove the live classifier's deadline independently of ownership
    // transfer: CURRENT and the cookie entry still identify the old active
    // lifecycle while the stopped sender is resumed after absolute expiry.
    DETECTOR_STAGE.store(37, Ordering::Relaxed);
    drain(&receivers.old)?;
    topology.old.as_mut().ok_or(Defective)?.resume()?;
    for _ in 0..TRANSFER_ROUNDS {
        topology
            .old
            .as_mut()
            .ok_or(Defective)?
            .send(CHILD_SEND_PROTECTED_OLD)?;
    }
    let expired_count = collect(&receivers.old, Duration::from_millis(250))?;
    verdict.expired_observed = expired_count != 0;
    topology.old.as_mut().ok_or(Defective)?.stop()?;
    DETECTOR_STAGE.store(38, Ordering::Relaxed);

    topology.replace_sender(family)?;
    let successor_cookie = topology.successor.as_ref().ok_or(Defective)?.cookie;

    DETECTOR_STAGE.store(26, Ordering::Relaxed);
    installation.control.applied(CommandInput {
        operation: OP_PUBLISH_LIFECYCLE,
        cookie: 0,
        token: 3,
        deadline: 0,
        epoch: 0,
    })?;
    installation.control.applied(CommandInput {
        operation: OP_REGISTER,
        cookie: successor_cookie,
        token: 3,
        deadline: 0,
        epoch: 0,
    })?;
    let successor_deadline = boottime_ns()?
        .checked_add(30_000_000_000)
        .ok_or(Defective)?;
    installation.control.applied(CommandInput {
        operation: OP_ACTIVATE,
        cookie: successor_cookie,
        token: 3,
        deadline: successor_deadline,
        epoch: 1,
    })?;
    topology.old.as_mut().ok_or(Defective)?.resume()?;

    DETECTOR_STAGE.store(27, Ordering::Relaxed);
    drain(&receivers.old)?;
    drain(&receivers.successor)?;
    for _ in 0..TRANSFER_ROUNDS {
        topology
            .successor
            .as_mut()
            .ok_or(Defective)?
            .send(CHILD_SEND_PROTECTED_SUCCESSOR)?;
        topology
            .old
            .as_mut()
            .ok_or(Defective)?
            .send(CHILD_SEND_PROTECTED_OLD)?;
    }
    let successor_count = collect_until(
        &receivers.successor,
        TRANSFER_ROUNDS,
        Duration::from_secs(2),
    )?;
    let stale_count = collect(&receivers.old, Duration::from_millis(250))?;
    verdict.successor_missing = successor_count != TRANSFER_ROUNDS;
    verdict.stale_observed = stale_count != 0;

    DETECTOR_STAGE.store(28, Ordering::Relaxed);
    installation.control.applied(CommandInput {
        operation: OP_CLOSE,
        cookie: old_cookie,
        token: 1,
        deadline: 0,
        epoch: 2,
    })?;
    let (_, old_entry) = installation.control.inspect(old_cookie, 1)?;
    ensure(
        old_entry
            .map(|entry| entry.control == COOKIE_TERMINAL && entry.epoch == 3)
            .unwrap_or(false),
    )?;
    installation.control.applied(CommandInput {
        operation: OP_RECLAIM,
        cookie: old_cookie,
        token: 1,
        deadline: 0,
        epoch: 3,
    })?;
    installation.control.applied(CommandInput {
        operation: OP_CLOSE,
        cookie: successor_cookie,
        token: 3,
        deadline: 0,
        epoch: 2,
    })?;
    let (_, successor_entry) = installation.control.inspect(successor_cookie, 3)?;
    ensure(
        successor_entry
            .map(|entry| entry.control == COOKIE_TERMINAL && entry.epoch == 3)
            .unwrap_or(false),
    )?;
    installation.control.applied(CommandInput {
        operation: OP_PUBLISH_RETIREMENT,
        cookie: 0,
        token: 4,
        deadline: 0,
        epoch: 0,
    })?;
    let (retired, _) = installation.control.inspect(0, 0)?;
    ensure(retired.control == CURRENT_CLOSED && retired.token == 4 && retired.cookie == 0)?;
    installation.control.applied(CommandInput {
        operation: OP_RECLAIM,
        cookie: successor_cookie,
        token: 3,
        deadline: 0,
        epoch: 3,
    })?;
    let (_, missing) = installation.control.inspect(successor_cookie, 3)?;
    ensure(missing.is_none())?;

    topology.old.take();
    topology.successor.take();
    installation.orderly_closed = true;
    installation.detach_exact()?;
    Ok(verdict)
}

fn collect(socket: &UdpSocket, duration: Duration) -> DetectorResult<usize> {
    let deadline = Instant::now() + duration;
    let mut count = 0_usize;
    let mut buffer = [0_u8; 64];
    loop {
        match socket.recv(&mut buffer) {
            Ok(_) => count = count.checked_add(1).ok_or(Defective)?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Ok(count);
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(Defective),
        }
    }
}

fn collect_until(socket: &UdpSocket, expected: usize, duration: Duration) -> DetectorResult<usize> {
    let deadline = Instant::now() + duration;
    let mut count = 0_usize;
    let mut buffer = [0_u8; 64];
    while count < expected && Instant::now() < deadline {
        match socket.recv(&mut buffer) {
            Ok(_) => count += 1,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(Defective),
        }
    }
    Ok(count)
}

fn drain(socket: &UdpSocket) -> DetectorResult<()> {
    let mut buffer = [0_u8; 64];
    loop {
        match socket.recv(&mut buffer) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(_) => return Err(Defective),
        }
    }
}

fn boottime_ns() -> DetectorResult<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0)?;
    let seconds = u64::try_from(value.tv_sec).map_err(|_| Defective)?;
    let nanoseconds = u64::try_from(value.tv_nsec).map_err(|_| Defective)?;
    ensure(nanoseconds < 1_000_000_000)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanoseconds))
        .ok_or(Defective)
}

fn run_ip(arguments: &[&str]) -> DetectorResult<()> {
    quiet_command("ip", arguments)
}

fn quiet_ip(arguments: &[&str]) -> DetectorResult<()> {
    quiet_command("ip", arguments)
}

fn quiet_command(program: &str, arguments: &[&str]) -> DetectorResult<()> {
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Defective)?;
    ensure(status.success())
}

fn sender_child(fd: RawFd, family: Family, role: Role) -> DetectorResult<()> {
    let mut channel = unsafe { UnixStream::from_raw_fd(fd) };
    let protected = UdpSocket::bind(family.protected_address()).map_err(|_| Defective)?;
    let unrelated = UdpSocket::bind(family.unrelated_address()).map_err(|_| Defective)?;
    let cookie = socket_kernel_identity(protected.as_fd())
        .map_err(|_| Defective)?
        .socket_cookie();
    let mut ready = [0_u8; 9];
    ready[0] = CHILD_READY;
    ready[1..9].copy_from_slice(&cookie.to_le_bytes());
    channel.write_all(&ready).map_err(|_| Defective)?;
    loop {
        let mut command = [0_u8; 1];
        channel.read_exact(&mut command).map_err(|_| Defective)?;
        if command[0] == CHILD_EXIT {
            return Ok(());
        }
        let result = match command[0] {
            CHILD_SEND_PROTECTED_OLD => {
                send_udp(&protected, family.destination(false, OLD_TRAFFIC_PORT))
            }
            CHILD_SEND_PROTECTED_SUCCESSOR => {
                send_udp(&protected, family.destination(true, SUCCESSOR_TRAFFIC_PORT))
            }
            CHILD_SEND_PROTECTED_UNREGISTERED => send_udp(
                &protected,
                family.destination(role.replacement(), UNREGISTERED_TRAFFIC_PORT),
            ),
            CHILD_SEND_UNRELATED => send_udp(
                &unrelated,
                family.destination(role.replacement(), UNRELATED_TRAFFIC_PORT),
            ),
            CHILD_SEND_RAW_PROTECTED => {
                send_raw_fragments(family, role.replacement(), true, RAW_PROTECTED_PORT)
            }
            CHILD_SEND_RAW_UNRELATED => {
                send_raw_fragments(family, role.replacement(), false, RAW_UNRELATED_PORT)
            }
            _ => CHILD_SEND_FAILED,
        };
        channel.write_all(&[result]).map_err(|_| Defective)?;
    }
}

fn send_udp(socket: &UdpSocket, destination: SocketAddr) -> u8 {
    match socket.send_to(&[], destination) {
        Ok(0) => CHILD_SEND_OK,
        Err(error) if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
            CHILD_SEND_DENIED
        }
        _ => CHILD_SEND_FAILED,
    }
}

fn send_raw_fragments(
    family: Family,
    replacement: bool,
    protected: bool,
    destination_port: u16,
) -> u8 {
    let result = match family {
        Family::V4 => send_ipv4_fragments(replacement, protected, destination_port),
        Family::V6 => send_ipv6_fragments(replacement, protected, destination_port),
    };
    match result {
        Ok(()) => CHILD_SEND_OK,
        Err(error) if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
            CHILD_SEND_DENIED
        }
        Err(_) => CHILD_SEND_FAILED,
    }
}

fn send_ipv4_fragments(
    replacement: bool,
    protected: bool,
    destination_port: u16,
) -> io::Result<()> {
    let source = if protected {
        IPV4_PROTECTED
    } else {
        IPV4_UNRELATED
    };
    let destination = if replacement {
        IPV4_NEW_DESTINATION
    } else {
        IPV4_OLD_DESTINATION
    };
    let mut udp = [0_u8; 24];
    udp[0..2].copy_from_slice(&PROTECTED_PORT.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&24_u16.to_be_bytes());
    let first = ipv4_fragment(source, destination, 0x2000, &udp[..16]);
    let second = ipv4_fragment(source, destination, 2, &udp[16..]);
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { File::from_raw_fd(fd) };
    let enabled = 1_i32;
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            (&raw const enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(destination.octets()),
        },
        sin_zero: [0; 8],
    };
    send_raw(socket.as_raw_fd(), &first, &address)?;
    send_raw(socket.as_raw_fd(), &second, &address)
}

fn ipv4_fragment(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    fragment: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0_u8; 20 + payload.len()];
    let packet_len = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[4..6].copy_from_slice(&0x5a3c_u16.to_be_bytes());
    packet[6..8].copy_from_slice(&fragment.to_be_bytes());
    packet[8] = 64;
    packet[9] = libc::IPPROTO_UDP as u8;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..].copy_from_slice(payload);
    packet
}

fn send_raw<T>(fd: RawFd, packet: &[u8], address: &T) -> io::Result<()> {
    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (address as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if sent == packet.len() as isize {
        Ok(())
    } else if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("raw_send_short"))
    }
}

fn send_ipv6_fragments(
    replacement: bool,
    protected: bool,
    destination_port: u16,
) -> io::Result<()> {
    let source = if protected {
        IPV6_PROTECTED
    } else {
        IPV6_UNRELATED
    };
    let destination = if replacement {
        IPV6_NEW_DESTINATION
    } else {
        IPV6_OLD_DESTINATION
    };
    let mut udp = [0_u8; 24];
    udp[0..2].copy_from_slice(&PROTECTED_PORT.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&24_u16.to_be_bytes());
    let checksum = udp_ipv6_checksum(source, destination, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    let first = ipv6_fragment(source, destination, 1, &udp[..16]);
    let second = ipv6_fragment(source, destination, 16, &udp[16..]);
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { File::from_raw_fd(fd) };
    let address = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: destination.octets(),
        },
        sin6_scope_id: 0,
    };
    send_raw(socket.as_raw_fd(), &first, &address)?;
    send_raw(socket.as_raw_fd(), &second, &address)
}

fn ipv6_fragment(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    fragment_field: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0_u8; 48 + payload.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[6] = 44;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40] = libc::IPPROTO_UDP as u8;
    packet[42..44].copy_from_slice(&fragment_field.to_be_bytes());
    packet[44..48].copy_from_slice(&0x6b4d_2f19_u32.to_be_bytes());
    packet[48..].copy_from_slice(payload);
    packet
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        let word = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_ipv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, libc::IPPROTO_UDP as u8]);
    pseudo.extend_from_slice(udp);
    let checksum = internet_checksum(&pseudo);
    if checksum == 0 {
        u16::MAX
    } else {
        checksum
    }
}

fn get_u32(value: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn get_u16(value: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(value[offset..offset + 2].try_into().unwrap_or([0; 2]))
}

fn get_u64(value: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(value[offset..offset + 8].try_into().unwrap_or([0; 8]))
}
