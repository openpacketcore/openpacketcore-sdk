//! Linux process-lifecycle supervision for the BIRD adapter.
//!
//! The production BIRD adapter is only admitted when the SDK owns the BIRD
//! process through [`BirdProcessConfig`]. A dedicated OS thread spawns the
//! SDK helper, performs a nonce-bound handshake after the helper installs its
//! parent-death signal, and remains the child's Linux parent thread for the
//! complete lifetime. The opaque admission in this module has no public
//! constructor and is invalidated immediately when the child or supervisor
//! exits.

use std::fmt;
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rand::{rngs::SysRng, TryRng};

use crate::error::IpsecLbError;
use crate::routing::RoutingProcessSupervision;

const SUPERVISOR_HANDSHAKE_VERSION: u8 = 1;
const SUPERVISOR_HANDSHAKE_LINE_MAX: usize = 160;
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(10);
const BIRD_PROCESS_PATH_MAX: usize = 4_096;
const BIRD_PROCESS_STARTUP_TIMEOUT_MAX: Duration = Duration::from_secs(30);
const BIRD_PROCESS_SHUTDOWN_TIMEOUT_MAX: Duration = Duration::from_secs(30);

/// SDK-owned BIRD process configuration.
///
/// There is deliberately no arbitrary argument vector. The SDK helper always
/// executes exactly `bird -f -c <config> -s <socket>`: `-f` is forced so BIRD
/// cannot daemonize away from the parent-death and wait boundary. Peer, ASN,
/// policy, BFD, privilege, and timer choices remain in the product-owned BIRD
/// configuration file.
#[derive(Clone, PartialEq, Eq)]
pub struct BirdProcessConfig {
    /// Absolute path to the SDK's `opc-bird-supervisor` helper executable.
    pub supervisor_helper_path: PathBuf,
    /// Absolute path to the BIRD 2 executable.
    pub bird_executable_path: PathBuf,
    /// Absolute path to the product-owned BIRD configuration file.
    pub bird_config_path: PathBuf,
    /// Maximum time for the helper handshake and BIRD control readiness.
    pub startup_timeout: Duration,
    /// Maximum time allowed for supervised BIRD termination.
    pub shutdown_timeout: Duration,
}

impl fmt::Debug for BirdProcessConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BirdProcessConfig")
            .field("supervisor_helper_path", &"<redacted-path>")
            .field("bird_executable_path", &"<redacted-path>")
            .field("bird_config_path", &"<redacted-path>")
            .field("startup_timeout", &self.startup_timeout)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish()
    }
}

impl BirdProcessConfig {
    /// Validate all bounded process-launch inputs.
    pub fn validate(&self) -> Result<(), IpsecLbError> {
        self.validate_timeouts()?;
        #[cfg(target_os = "linux")]
        {
            // Validation opens the candidates without following their final
            // path components. Production startup repeats this operation and
            // retains those exact descriptors through exec.
            let _ = PinnedLaunchFiles::open(self)?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            validate_executable_path("supervisor_helper_path", &self.supervisor_helper_path)?;
            validate_executable_path("bird_executable_path", &self.bird_executable_path)?;
            validate_regular_path("bird_config_path", &self.bird_config_path)?;
        }
        Ok(())
    }

    fn validate_timeouts(&self) -> Result<(), IpsecLbError> {
        if self.startup_timeout.is_zero() || self.startup_timeout > BIRD_PROCESS_STARTUP_TIMEOUT_MAX
        {
            return Err(IpsecLbError::invalid_config(
                "startup_timeout",
                "BIRD process startup timeout is zero or exceeds the production bound",
            ));
        }
        if self.shutdown_timeout.is_zero()
            || self.shutdown_timeout > BIRD_PROCESS_SHUTDOWN_TIMEOUT_MAX
        {
            return Err(IpsecLbError::invalid_config(
                "shutdown_timeout",
                "BIRD process shutdown timeout is zero or exceeds the production bound",
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct PinnedLaunchFile {
    _descriptor: OwnedFd,
    proc_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl PinnedLaunchFile {
    fn open(field: &'static str, path: &Path, executable: bool) -> Result<Self, IpsecLbError> {
        use rustix::fs::{fstat, openat, FileType, Mode, OFlags, CWD};

        validate_path_syntax(field, path)?;
        // Deliberately omit CLOEXEC: the trusted helper and then BIRD resolve
        // these procfd paths in the child. The descriptor, not the mutable
        // pathname, is the launch authority.
        // NONBLOCK is immaterial for regular files but prevents a hostile or
        // accidentally configured FIFO from blocking admission before fstat
        // can reject it. Other special files are likewise rejected below.
        let descriptor = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| IpsecLbError::io("bird_process_path_open", error.into()))?;
        let metadata = fstat(&descriptor)
            .map_err(|error| IpsecLbError::io("bird_process_path_stat", error.into()))?;
        if !FileType::from_raw_mode(metadata.st_mode).is_file() {
            return Err(IpsecLbError::invalid_config(
                field,
                "process path is not a regular file",
            ));
        }
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.st_uid != 0 && metadata.st_uid != effective_uid {
            return Err(IpsecLbError::invalid_config(
                field,
                "process file must be owned by root or the effective user",
            ));
        }
        if metadata.st_mode & 0o022 != 0 {
            return Err(IpsecLbError::invalid_config(
                field,
                "process file must not be group- or world-writable",
            ));
        }
        if executable {
            if metadata.st_mode & 0o111 == 0 {
                return Err(IpsecLbError::invalid_config(
                    field,
                    "process executable has no execute bit",
                ));
            }
            if metadata.st_mode & 0o6000 != 0 {
                return Err(IpsecLbError::invalid_config(
                    field,
                    "set-ID executables cannot preserve the parent-death boundary",
                ));
            }
            let mut capability = [0_u8; 256];
            match rustix::fs::fgetxattr(&descriptor, "security.capability", &mut capability) {
                Ok(capability_len) if capability_len != 0 => {
                    return Err(IpsecLbError::invalid_config(
                        field,
                        "file-capability executables cannot preserve the parent-death boundary",
                    ));
                }
                Ok(_) | Err(rustix::io::Errno::NODATA) => {}
                Err(error) => {
                    return Err(IpsecLbError::io(
                        "bird_process_capability_check",
                        io::Error::from(error),
                    ));
                }
            }
        }
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
        Ok(Self {
            _descriptor: descriptor,
            proc_path,
        })
    }
}

#[cfg(target_os = "linux")]
struct PinnedLaunchFiles {
    supervisor_helper: PinnedLaunchFile,
    bird_executable: PinnedLaunchFile,
    bird_config: PinnedLaunchFile,
}

#[cfg(target_os = "linux")]
impl PinnedLaunchFiles {
    fn open(config: &BirdProcessConfig) -> Result<Self, IpsecLbError> {
        Ok(Self {
            supervisor_helper: PinnedLaunchFile::open(
                "supervisor_helper_path",
                &config.supervisor_helper_path,
                true,
            )?,
            bird_executable: PinnedLaunchFile::open(
                "bird_executable_path",
                &config.bird_executable_path,
                true,
            )?,
            bird_config: PinnedLaunchFile::open(
                "bird_config_path",
                &config.bird_config_path,
                false,
            )?,
        })
    }
}

fn validate_path_syntax(field: &'static str, path: &Path) -> Result<(), IpsecLbError> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(IpsecLbError::invalid_config(
            field,
            "process path must be non-empty and absolute",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().len() > BIRD_PROCESS_PATH_MAX {
            return Err(IpsecLbError::invalid_config(
                field,
                "process path exceeds the production bound",
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_regular_path(field: &'static str, path: &Path) -> Result<(), IpsecLbError> {
    validate_path_syntax(field, path)?;
    let metadata =
        std::fs::metadata(path).map_err(|error| IpsecLbError::io("bird_process_path", error))?;
    if !metadata.is_file() {
        return Err(IpsecLbError::invalid_config(
            field,
            "process path is not a regular file",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_executable_path(field: &'static str, path: &Path) -> Result<(), IpsecLbError> {
    validate_regular_path(field, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .map_err(|error| IpsecLbError::io("bird_process_path", error))?;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(IpsecLbError::invalid_config(
                field,
                "process executable has no execute bit",
            ));
        }
        if metadata.permissions().mode() & 0o6000 != 0 {
            return Err(IpsecLbError::invalid_config(
                field,
                "set-ID executables cannot preserve the parent-death boundary",
            ));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut capability = vec![0_u8; 256];
        match rustix::fs::getxattr(path, "security.capability", &mut capability) {
            Ok(capability_len) if capability_len != 0 => {
                return Err(IpsecLbError::invalid_config(
                    field,
                    "file-capability executables cannot preserve the parent-death boundary",
                ));
            }
            Ok(_) | Err(rustix::io::Errno::NODATA) => {}
            Err(error) => {
                return Err(IpsecLbError::io(
                    "bird_process_capability_check",
                    io::Error::from(error),
                ));
            }
        }
    }
    Ok(())
}

/// Non-forgeable process-lifecycle admission held by the production adapter.
///
/// The value is intentionally non-`Clone` and has no public constructor. An
/// adapter may share it only behind an `Arc`, so the supervisor guard remains
/// alive until the last adapter clone is dropped.
pub(crate) struct RoutingLifecycleAdmission {
    supervisor: BirdSupervisorGuard,
    process_supervision: RoutingProcessSupervision,
    control_socket_path: PathBuf,
}

#[cfg(target_os = "linux")]
pub(crate) struct PreparedBirdProcess {
    config: BirdProcessConfig,
    launch_files: PinnedLaunchFiles,
    socket_namespace: SocketNamespaceGuard,
    pinned_control_socket: PathBuf,
}

#[cfg(target_os = "linux")]
impl PreparedBirdProcess {
    pub(crate) fn set_startup_timeout(
        &mut self,
        startup_timeout: Duration,
    ) -> Result<(), IpsecLbError> {
        if startup_timeout.is_zero() {
            return Err(IpsecLbError::invalid_config(
                "startup_timeout",
                "remaining BIRD startup timeout must be non-zero",
            ));
        }
        self.config.startup_timeout = startup_timeout;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) struct PreparedBirdProcess;

#[cfg(not(target_os = "linux"))]
impl PreparedBirdProcess {
    pub(crate) fn set_startup_timeout(
        &mut self,
        _startup_timeout: Duration,
    ) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }
}

impl fmt::Debug for RoutingLifecycleAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingLifecycleAdmission")
            .field("live", &self.is_live())
            .field("process_supervision", &self.process_supervision)
            .finish()
    }
}

impl RoutingLifecycleAdmission {
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare(
        config: BirdProcessConfig,
        control_socket: PathBuf,
    ) -> Result<PreparedBirdProcess, IpsecLbError> {
        config.validate_timeouts()?;
        validate_socket_path(&control_socket)?;
        let launch_files = PinnedLaunchFiles::open(&config)?;
        let socket_namespace = SocketNamespaceGuard::admit(&control_socket)?;
        let pinned_control_socket = socket_namespace.control_socket_path().to_owned();
        Ok(PreparedBirdProcess {
            config,
            launch_files,
            socket_namespace,
            pinned_control_socket,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn prepare(
        _config: BirdProcessConfig,
        _control_socket: PathBuf,
    ) -> Result<PreparedBirdProcess, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn start(prepared: PreparedBirdProcess) -> Result<Arc<Self>, IpsecLbError> {
        let PreparedBirdProcess {
            config,
            launch_files,
            socket_namespace,
            pinned_control_socket,
        } = prepared;
        let supervisor_control_socket = pinned_control_socket.clone();
        let process_supervision = RoutingProcessSupervision::admitted();
        let supervisor = tokio::task::spawn_blocking(move || {
            BirdSupervisorGuard::start(
                config,
                supervisor_control_socket,
                socket_namespace,
                launch_files,
            )
        })
        .await
        .map_err(|_| {
            IpsecLbError::io(
                "bird_supervisor_start",
                io::Error::other("BIRD supervisor startup task failed"),
            )
        })??;
        Ok(Arc::new(Self {
            supervisor,
            process_supervision,
            control_socket_path: pinned_control_socket,
        }))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) async fn start(_prepared: PreparedBirdProcess) -> Result<Arc<Self>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    #[cfg(test)]
    pub(crate) fn conformance() -> Arc<Self> {
        Arc::new(Self {
            supervisor: BirdSupervisorGuard::conformance(),
            process_supervision: RoutingProcessSupervision::conformance(),
            control_socket_path: PathBuf::from("/conformance/bird.ctl"),
        })
    }

    pub(crate) fn ensure_live(&self) -> Result<(), IpsecLbError> {
        if self.is_live() {
            Ok(())
        } else {
            Err(IpsecLbError::io(
                "bird_supervision",
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "BIRD lifecycle admission is not live",
                ),
            ))
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        self.supervisor.is_live()
    }

    pub(crate) const fn process_supervision(&self) -> &RoutingProcessSupervision {
        &self.process_supervision
    }

    pub(crate) fn control_socket_path(&self) -> &Path {
        &self.control_socket_path
    }

    pub(crate) async fn shutdown(self: &Arc<Self>) -> Result<(), IpsecLbError> {
        let admission = Arc::clone(self);
        tokio::task::spawn_blocking(move || admission.supervisor.shutdown())
            .await
            .map_err(|_| {
                IpsecLbError::io(
                    "bird_supervisor_shutdown",
                    io::Error::other("BIRD supervisor shutdown task failed"),
                )
            })?
    }

    /// Invalidate mutation readiness and request immediate child fail-stop
    /// without waiting for kernel wait status. Used when a bounded adapter
    /// mutation itself exceeded its contract.
    pub(crate) fn request_fail_stop(&self) {
        self.supervisor.request_fail_stop();
    }
}

fn validate_socket_path(path: &Path) -> Result<(), IpsecLbError> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(IpsecLbError::invalid_config(
            "socket_path",
            "supervised BIRD control socket path must be non-empty and absolute",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().len() > BIRD_PROCESS_PATH_MAX {
            return Err(IpsecLbError::invalid_config(
                "socket_path",
                "supervised BIRD control socket path exceeds the production bound",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct SocketNamespaceGuard {
    /// Keeps the private directory pinned against path replacement.
    _directory: OwnedFd,
    /// Keeps the cross-process supervisor lock held for the child lifetime.
    _lock: OwnedFd,
    /// Procfd-relative socket path anchored to `_directory`.
    control_socket_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for SocketNamespaceGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketNamespaceGuard")
            .field("admitted", &true)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl SocketNamespaceGuard {
    fn admit(socket_path: &Path) -> Result<Self, IpsecLbError> {
        use rustix::fs::{
            flock, fstat, openat, statat, unlinkat, AtFlags, FileType, FlockOperation, Mode,
            OFlags, CWD,
        };

        let parent = socket_path.parent().ok_or_else(|| {
            IpsecLbError::invalid_config("socket_path", "BIRD socket has no parent directory")
        })?;
        let leaf = socket_path.file_name().ok_or_else(|| {
            IpsecLbError::invalid_config("socket_path", "BIRD socket has no leaf name")
        })?;
        let before = statat(CWD, parent, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| IpsecLbError::io("bird_socket_directory_lstat", error.into()))?;
        validate_private_socket_directory(&before)?;
        let directory = openat(
            CWD,
            parent,
            // Deliberately inherited by the trusted helper/BIRD so `-s` can
            // remain descriptor-relative across a parent-directory rename.
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| IpsecLbError::io("bird_socket_directory_open", error.into()))?;
        let after = fstat(&directory)
            .map_err(|error| IpsecLbError::io("bird_socket_directory_fstat", error.into()))?;
        validate_private_socket_directory(&after)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(IpsecLbError::invalid_config(
                "socket_path",
                "BIRD socket directory changed during admission",
            ));
        }

        let lock = openat(
            &directory,
            ".opc-ipsec-lb-supervisor.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| IpsecLbError::io("bird_socket_lock_open", error.into()))?;
        let lock_stat = fstat(&lock)
            .map_err(|error| IpsecLbError::io("bird_socket_lock_stat", error.into()))?;
        if !FileType::from_raw_mode(lock_stat.st_mode).is_file()
            || lock_stat.st_uid != rustix::process::geteuid().as_raw()
        {
            return Err(IpsecLbError::invalid_config(
                "socket_path",
                "BIRD socket lock must be a regular file owned by the effective user",
            ));
        }
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| IpsecLbError::io("bird_socket_lock", io::Error::from(error)))?;

        let mut control_socket_path =
            PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        control_socket_path.push(leaf);

        match statat(&directory, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => {
                if !FileType::from_raw_mode(metadata.st_mode).is_socket()
                    || metadata.st_uid != rustix::process::geteuid().as_raw()
                {
                    return Err(IpsecLbError::invalid_config(
                        "socket_path",
                        "existing BIRD socket candidate is not an owned socket",
                    ));
                }
                match probe_existing_socket(&control_socket_path)? {
                    ExistingSocketState::Active => {
                        return Err(IpsecLbError::invalid_config(
                            "socket_path",
                            "an active BIRD control socket already exists",
                        ));
                    }
                    ExistingSocketState::Dead => {
                        unlinkat(&directory, leaf, AtFlags::empty()).map_err(|error| {
                            IpsecLbError::io("bird_socket_stale_cleanup", error.into())
                        })?;
                    }
                }
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(IpsecLbError::io("bird_socket_preflight", error.into())),
        }

        Ok(Self {
            _directory: directory,
            _lock: lock,
            control_socket_path,
        })
    }

    fn control_socket_path(&self) -> &Path {
        &self.control_socket_path
    }
}

#[cfg(target_os = "linux")]
enum ExistingSocketState {
    Active,
    Dead,
}

#[cfg(target_os = "linux")]
fn probe_existing_socket(path: &Path) -> Result<ExistingSocketState, IpsecLbError> {
    use rustix::net::{
        connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
    };

    let address = SocketAddrUnix::new(path)
        .map_err(|error| IpsecLbError::io("bird_socket_active_probe", error.into()))?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| IpsecLbError::io("bird_socket_active_probe", error.into()))?;
    match connect(&socket, &address) {
        Ok(()) => Ok(ExistingSocketState::Active),
        // A connect still in progress or blocked by a full listen backlog is
        // indeterminate and therefore active. Never unlink it.
        Err(
            rustix::io::Errno::AGAIN | rustix::io::Errno::INPROGRESS | rustix::io::Errno::ALREADY,
        ) => Ok(ExistingSocketState::Active),
        Err(rustix::io::Errno::CONNREFUSED | rustix::io::Errno::NOENT) => {
            Ok(ExistingSocketState::Dead)
        }
        Err(error) => Err(IpsecLbError::io(
            "bird_socket_active_probe",
            io::Error::from(error),
        )),
    }
}

#[cfg(target_os = "linux")]
fn validate_private_socket_directory(metadata: &rustix::fs::Stat) -> Result<(), IpsecLbError> {
    if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o700 != 0o700
        || metadata.st_mode & 0o077 != 0
    {
        return Err(IpsecLbError::invalid_config(
            "socket_path",
            "BIRD socket directory must be mode 0700 and owned by the effective user",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct SupervisorTerminal {
    done: Mutex<bool>,
    changed: Condvar,
}

struct SupervisorThreadExit {
    live: Arc<AtomicBool>,
    terminal: Arc<SupervisorTerminal>,
}

impl Drop for SupervisorThreadExit {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Release);
        self.terminal.mark();
    }
}

impl SupervisorTerminal {
    fn new() -> Self {
        Self {
            done: Mutex::new(false),
            changed: Condvar::new(),
        }
    }

    fn mark(&self) {
        *self
            .done
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.changed.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let done = self
            .done
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *done {
            return true;
        }
        let (done, _) = self
            .changed
            .wait_timeout_while(done, timeout, |done| !*done)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *done
    }
}

struct BirdSupervisorGuard {
    live: Arc<AtomicBool>,
    shutdown: mpsc::SyncSender<()>,
    terminal: Arc<SupervisorTerminal>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    shutdown_timeout: Duration,
    #[cfg(target_os = "linux")]
    socket_namespace: Mutex<Option<SocketNamespaceGuard>>,
}

impl fmt::Debug for BirdSupervisorGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BirdSupervisorGuard")
            .field("live", &self.is_live())
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish()
    }
}

impl BirdSupervisorGuard {
    #[cfg(target_os = "linux")]
    fn start(
        config: BirdProcessConfig,
        control_socket: PathBuf,
        socket_namespace: SocketNamespaceGuard,
        launch_files: PinnedLaunchFiles,
    ) -> Result<Self, IpsecLbError> {
        let mut nonce = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| IpsecLbError::EntropyUnavailable)?;
        let nonce = encode_hex(&nonce);
        let live = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(SupervisorTerminal::new());
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
        let (handshake_tx, handshake_rx) = mpsc::sync_channel(1);
        let thread_live = Arc::clone(&live);
        let thread_terminal = Arc::clone(&terminal);
        let shutdown_timeout = config.shutdown_timeout;
        let startup_timeout = config.startup_timeout;
        let handle = thread::Builder::new()
            .name("opc-bird-supervisor".to_owned())
            .spawn(move || {
                let _exit = SupervisorThreadExit {
                    live: Arc::clone(&thread_live),
                    terminal: Arc::clone(&thread_terminal),
                };
                supervise_child(SuperviseChildInput {
                    config,
                    launch_files,
                    control_socket,
                    nonce,
                    shutdown_rx,
                    handshake_tx,
                    live: thread_live,
                    terminal: thread_terminal,
                });
            })
            .map_err(|error| IpsecLbError::io("bird_supervisor_thread", error))?;
        let guard = Self {
            live,
            shutdown: shutdown_tx,
            terminal,
            thread: Mutex::new(Some(handle)),
            shutdown_timeout,
            socket_namespace: Mutex::new(Some(socket_namespace)),
        };
        match handshake_rx.recv_timeout(startup_timeout) {
            Ok(Ok(())) if guard.is_live() => Ok(guard),
            Ok(Ok(())) => {
                let _ = guard.shutdown();
                Err(IpsecLbError::io(
                    "bird_supervisor_handshake",
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "BIRD supervisor exited after handshake",
                    ),
                ))
            }
            Ok(Err(error)) => {
                let _ = guard.shutdown();
                Err(error)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = guard.shutdown();
                Err(IpsecLbError::io(
                    "bird_supervisor_handshake",
                    io::Error::new(io::ErrorKind::TimedOut, "BIRD helper handshake timed out"),
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = guard.shutdown();
                Err(IpsecLbError::io(
                    "bird_supervisor_handshake",
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "BIRD helper handshake channel closed",
                    ),
                ))
            }
        }
    }

    #[cfg(test)]
    fn conformance() -> Self {
        let (shutdown, _receiver) = mpsc::sync_channel(1);
        Self {
            live: Arc::new(AtomicBool::new(true)),
            shutdown,
            terminal: Arc::new(SupervisorTerminal::new()),
            thread: Mutex::new(None),
            shutdown_timeout: Duration::from_secs(1),
            #[cfg(target_os = "linux")]
            socket_namespace: Mutex::new(None),
        }
    }

    fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    fn request_fail_stop(&self) {
        self.live.store(false, Ordering::Release);
        let _ = self.shutdown.try_send(());
    }

    fn shutdown(&self) -> Result<(), IpsecLbError> {
        self.request_fail_stop();
        if !self.terminal.wait(self.shutdown_timeout) {
            return Err(IpsecLbError::io(
                "bird_supervisor_shutdown",
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "BIRD supervisor termination is ambiguous",
                ),
            ));
        }
        if let Some(handle) = self
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            handle.join().map_err(|_| {
                IpsecLbError::io(
                    "bird_supervisor_thread",
                    io::Error::other("BIRD supervisor thread panicked"),
                )
            })?;
        }
        Ok(())
    }
}

impl Drop for BirdSupervisorGuard {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Release);
        let _ = self.shutdown.try_send(());
        let handle = self
            .thread
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            #[cfg(target_os = "linux")]
            let socket_namespace = self
                .socket_namespace
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            // Never block an async executor in Drop. The original spawning
            // thread remains the helper/BIRD parent until it terminates; this
            // short reaper merely joins it outside the caller's context.
            let _ = thread::Builder::new()
                .name("opc-bird-supervisor-reaper".to_owned())
                .spawn(move || {
                    let _ = handle.join();
                    #[cfg(target_os = "linux")]
                    drop(socket_namespace);
                });
        }
    }
}

#[cfg(target_os = "linux")]
struct SuperviseChildInput {
    config: BirdProcessConfig,
    launch_files: PinnedLaunchFiles,
    control_socket: PathBuf,
    nonce: String,
    shutdown_rx: mpsc::Receiver<()>,
    handshake_tx: mpsc::SyncSender<Result<(), IpsecLbError>>,
    live: Arc<AtomicBool>,
    terminal: Arc<SupervisorTerminal>,
}

#[cfg(target_os = "linux")]
fn supervise_child(input: SuperviseChildInput) {
    let SuperviseChildInput {
        config,
        launch_files,
        control_socket,
        nonce,
        shutdown_rx,
        handshake_tx,
        live,
        terminal,
    } = input;
    let result = spawn_and_handshake(&config, &launch_files, &control_socket, &nonce);
    let mut child = match result {
        Ok(child) => child,
        Err(error) => {
            let _ = handshake_tx.send(Err(error));
            live.store(false, Ordering::Release);
            terminal.mark();
            return;
        }
    };
    live.store(true, Ordering::Release);
    if handshake_tx.send(Ok(())).is_err() {
        live.store(false, Ordering::Release);
        terminate_child(child, config.shutdown_timeout);
        terminal.mark();
        return;
    }

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                live.store(false, Ordering::Release);
                break;
            }
            Ok(None) => {}
            Err(_) => {
                // Losing authoritative wait status is not evidence that the
                // child exited. Fail readiness immediately, then retain the
                // owned child through the mandatory kill/reap path.
                live.store(false, Ordering::Release);
                terminate_child(child, config.shutdown_timeout);
                break;
            }
        }
        match shutdown_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                live.store(false, Ordering::Release);
                terminate_child(child, config.shutdown_timeout);
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        thread::sleep(SUPERVISOR_POLL_INTERVAL);
    }
    terminal.mark();
}

#[cfg(target_os = "linux")]
fn spawn_and_handshake(
    config: &BirdProcessConfig,
    launch_files: &PinnedLaunchFiles,
    control_socket: &Path,
    nonce: &str,
) -> Result<Child, IpsecLbError> {
    let expected_parent = rustix::process::getpid().as_raw_pid().to_string();
    let child = Command::new(&launch_files.supervisor_helper.proc_path)
        .arg("--expected-parent-pid")
        .arg(expected_parent)
        .arg("--bird-executable")
        .arg(&launch_files.bird_executable.proc_path)
        .arg("--config")
        .arg(&launch_files.bird_config.proc_path)
        .arg("--control-socket")
        .arg(control_socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| IpsecLbError::io("bird_supervisor_helper_spawn", error))?;
    let mut child = SpawnedChildGuard::new(child, config.shutdown_timeout);

    let challenge = format!("OPC_BIRD_SUPERVISOR {SUPERVISOR_HANDSHAKE_VERSION} {nonce}\n");
    let write_result = child
        .child_mut()?
        .stdin
        .take()
        .ok_or_else(|| {
            IpsecLbError::io(
                "bird_supervisor_handshake",
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "BIRD helper stdin is unavailable",
                ),
            )
        })
        .and_then(|mut stdin| {
            stdin
                .write_all(challenge.as_bytes())
                .and_then(|()| stdin.flush())
                .map_err(|error| IpsecLbError::io("bird_supervisor_handshake", error))
        });
    write_result?;

    let mut stdout = match child.child_mut()?.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err(IpsecLbError::io(
                "bird_supervisor_handshake",
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "BIRD helper stdout is unavailable",
                ),
            ));
        }
    };
    configure_handshake_stdout_nonblocking(&stdout)?;
    let deadline = Instant::now()
        .checked_add(config.startup_timeout)
        .ok_or_else(|| {
            IpsecLbError::invalid_config(
                "startup_timeout",
                "BIRD process startup deadline overflowed",
            )
        })?;
    let response = read_handshake(&mut stdout, child.child_mut()?, deadline)
        .map_err(|error| IpsecLbError::io("bird_supervisor_handshake", error));
    let response = response?;
    let expected = format!("OPC_BIRD_SUPERVISOR_READY {SUPERVISOR_HANDSHAKE_VERSION} {nonce}");
    if response != expected {
        return Err(IpsecLbError::io(
            "bird_supervisor_handshake",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "BIRD helper handshake is invalid",
            ),
        ));
    }
    child.disarm()
}

#[cfg(target_os = "linux")]
struct SpawnedChildGuard {
    child: Option<Child>,
    termination_timeout: Duration,
}

#[cfg(target_os = "linux")]
impl SpawnedChildGuard {
    fn new(child: Child, termination_timeout: Duration) -> Self {
        Self {
            child: Some(child),
            termination_timeout,
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, IpsecLbError> {
        self.child.as_mut().ok_or_else(|| {
            IpsecLbError::io(
                "bird_supervisor_handshake",
                io::Error::other("spawned child guard is not armed"),
            )
        })
    }

    fn disarm(mut self) -> Result<Child, IpsecLbError> {
        self.child.take().ok_or_else(|| {
            IpsecLbError::io(
                "bird_supervisor_handshake",
                io::Error::other("spawned child guard is not armed"),
            )
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for SpawnedChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            terminate_child(child, self.termination_timeout);
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_handshake_stdout_nonblocking(
    stdout: &std::process::ChildStdout,
) -> Result<(), IpsecLbError> {
    configure_handshake_stdout_nonblocking_with(stdout, |stdout, flags| {
        rustix::fs::fcntl_setfl(stdout, flags).map_err(io::Error::from)
    })
}

#[cfg(target_os = "linux")]
fn configure_handshake_stdout_nonblocking_with<F>(
    stdout: &std::process::ChildStdout,
    set_flags: F,
) -> Result<(), IpsecLbError>
where
    F: FnOnce(&std::process::ChildStdout, rustix::fs::OFlags) -> io::Result<()>,
{
    let flags = rustix::fs::fcntl_getfl(stdout)
        .map_err(|error| IpsecLbError::io("bird_supervisor_handshake", io::Error::from(error)))?;
    set_flags(stdout, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|error| IpsecLbError::io("bird_supervisor_handshake", error))
}

#[cfg(target_os = "linux")]
fn read_handshake(
    stdout: &mut std::process::ChildStdout,
    child: &mut Child,
    deadline: Instant,
) -> io::Result<String> {
    let mut received = Vec::new();
    let mut buffer = [0u8; 64];
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "BIRD helper closed its handshake pipe",
                ));
            }
            Ok(read) => {
                if received.len().saturating_add(read) > SUPERVISOR_HANDSHAKE_LINE_MAX {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "BIRD helper handshake exceeds its bound",
                    ));
                }
                received.extend_from_slice(&buffer[..read]);
                if let Some(newline) = received.iter().position(|byte| *byte == b'\n') {
                    if received[newline + 1..]
                        .iter()
                        .any(|byte| !byte.is_ascii_whitespace())
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "BIRD helper sent trailing handshake data",
                        ));
                    }
                    let line = &received[..newline];
                    return std::str::from_utf8(line).map(str::to_owned).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "BIRD helper handshake is not UTF-8",
                        )
                    });
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "BIRD helper exited before handshake",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "BIRD helper handshake timed out",
            ));
        }
        thread::sleep(SUPERVISOR_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn terminate_child(mut child: Child, timeout: Duration) {
    let _ = child.kill();
    let deadline = Instant::now().checked_add(timeout);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => {
                let _ = child.wait();
                return;
            }
        }
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            // SIGKILL has already made local process termination fail-stop.
            // Continue into wait instead of dropping `Child`: every startup
            // and handshake failure path must reap its direct child even if
            // the configured supervision deadline was exceeded.
            let _ = child.wait();
            return;
        }
        thread::sleep(SUPERVISOR_POLL_INTERVAL);
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_directory(name: &str) -> PathBuf {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "opc-bird-supervisor-{name}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn process_config_debug_redacts_every_path() {
        let config = BirdProcessConfig {
            supervisor_helper_path: PathBuf::from("/private/helper-canary"),
            bird_executable_path: PathBuf::from("/private/bird-canary"),
            bird_config_path: PathBuf::from("/private/config-canary"),
            startup_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("canary"));
        assert_eq!(debug.matches("<redacted-path>").count(), 3);
    }

    #[test]
    fn hex_encoding_is_fixed_width_and_lowercase() {
        assert_eq!(encode_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_files_are_nofollow_private_and_descriptor_pinned() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = test_directory("launch-pin");
        let candidate = root.join("candidate");
        std::fs::write(&candidate, b"original-executable").unwrap();
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = PinnedLaunchFile::open("candidate", &candidate, true).unwrap();

        let archived = root.join("archived");
        std::fs::rename(&candidate, &archived).unwrap();
        std::fs::write(&candidate, b"replacement-executable").unwrap();
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            std::fs::read(&pinned.proc_path).unwrap(),
            b"original-executable"
        );

        let symlink_candidate = root.join("symlink");
        symlink(&candidate, &symlink_candidate).unwrap();
        assert!(PinnedLaunchFile::open("candidate", &symlink_candidate, true).is_err());

        let writable_candidate = root.join("writable");
        std::fs::write(&writable_candidate, b"writable").unwrap();
        std::fs::set_permissions(&writable_candidate, std::fs::Permissions::from_mode(0o722))
            .unwrap();
        assert!(PinnedLaunchFile::open("candidate", &writable_candidate, true).is_err());

        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_file_admission_rejects_fifo_and_special_files_without_blocking() {
        use std::sync::{mpsc, Barrier};

        use rustix::fs::{mkfifoat, Mode, OFlags, CWD};

        let root = test_directory("launch-special-file");
        let fifo = root.join("candidate.fifo");
        mkfifoat(CWD, &fifo, Mode::from_raw_mode(0o600)).unwrap();
        let started = Arc::new(Barrier::new(2));
        let worker_started = Arc::clone(&started);
        let candidate = fifo.clone();
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            worker_started.wait();
            let rejected = PinnedLaunchFile::open("candidate", &candidate, false).is_err();
            let _ = result_tx.send(rejected);
        });
        started.wait();

        let prompt_result = result_rx.recv_timeout(Duration::from_secs(1));
        if prompt_result.is_err() {
            // Release a regressed blocking FIFO open before failing the test,
            // so the worker cannot leak into the remaining test process.
            let _release = rustix::fs::openat(
                CWD,
                &fifo,
                OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let _ = result_rx.recv_timeout(Duration::from_secs(1));
        }
        worker.join().unwrap();
        assert!(prompt_result.unwrap());

        assert!(PinnedLaunchFile::open("candidate", Path::new("/dev/null"), false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_namespace_remains_anchored_after_parent_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_directory("socket-pin");
        let namespace = root.join("runtime");
        std::fs::create_dir(&namespace).unwrap();
        std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = namespace.join("bird.ctl");
        let guard = SocketNamespaceGuard::admit(&socket).unwrap();

        let anchored = root.join("anchored");
        std::fs::rename(&namespace, &anchored).unwrap();
        std::fs::create_dir(&namespace).unwrap();
        std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(guard.control_socket_path()).unwrap();
        assert!(anchored.join("bird.ctl").exists());
        assert!(!namespace.join("bird.ctl").exists());

        drop(listener);
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_socket_backlog_probe_is_immediate_fail_closed_and_fd_bounded() {
        const CHILD_ENV: &str = "OPC_IPSEC_LB_SOCKET_PROBE_FD_CHILD";
        const TEST_NAME: &str =
            "routing::bird_supervisor::tests::full_socket_backlog_probe_is_immediate_fail_closed_and_fd_bounded";

        if std::env::var_os(CHILD_ENV).is_none() {
            // The workspace runs unit tests concurrently, so a process-wide
            // descriptor count can otherwise observe unrelated tests opening
            // or closing descriptors. Re-run only this test in a dedicated
            // process to make the leak assertion deterministic.
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(TEST_NAME)
                .arg("--test-threads=1")
                .env(CHILD_ENV, "1")
                .status()
                .unwrap();
            assert!(status.success(), "isolated socket-probe check failed");
            return;
        }

        use rustix::net::{
            bind, connect, listen, socket_with, AddressFamily, SocketAddrUnix, SocketFlags,
            SocketType,
        };

        let root = test_directory("socket-backlog");
        let path = root.join("bird.ctl");
        let address = SocketAddrUnix::new(&path).unwrap();
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind(&listener, &address).unwrap();
        listen(&listener, 1).unwrap();

        let mut clients = Vec::new();
        let mut backlog_full = false;
        for _ in 0..256 {
            let client = socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            match connect(&client, &address) {
                Ok(()) | Err(rustix::io::Errno::INPROGRESS | rustix::io::Errno::ALREADY) => {
                    clients.push(client);
                }
                Err(rustix::io::Errno::AGAIN) => {
                    backlog_full = true;
                    break;
                }
                Err(error) => panic!("unexpected backlog setup failure: {error}"),
            }
        }
        assert!(backlog_full, "test must exercise a full AF_UNIX backlog");

        let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
        for _ in 0..128 {
            assert!(matches!(
                probe_existing_socket(&path).unwrap(),
                ExistingSocketState::Active
            ));
        }
        let after = std::fs::read_dir("/proc/self/fd").unwrap().count();
        assert_eq!(
            after, before,
            "socket probes must not retain descriptors: before={before}, after={after}"
        );

        drop(clients);
        drop(listener);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn injected_fcntl_failure_kills_and_reaps_the_armed_child() {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec sleep 60")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
        let result = (|| {
            let mut guarded = SpawnedChildGuard::new(child, Duration::from_secs(1));
            let stdout = guarded.child_mut()?.stdout.take().ok_or_else(|| {
                IpsecLbError::io(
                    "bird_supervisor_handshake",
                    io::Error::new(io::ErrorKind::BrokenPipe, "missing synthetic stdout"),
                )
            })?;
            configure_handshake_stdout_nonblocking_with(&stdout, |_stdout, _flags| {
                Err(io::Error::other("injected fcntl failure"))
            })?;
            let _ = guarded.disarm()?;
            Ok::<(), IpsecLbError>(())
        })();

        assert!(result.is_err());
        assert!(rustix::process::test_kill_process(pid).is_err());
    }
}
