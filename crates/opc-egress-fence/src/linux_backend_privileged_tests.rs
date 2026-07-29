use std::{
    fs::{self, File, OpenOptions},
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    num::NonZeroU64,
    os::{
        fd::AsFd,
        unix::{fs::OpenOptionsExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use opc_session_store::{
    FakeSessionBackend, LeaseGuard, OwnerId, SessionKey, SessionKeyType, SessionLeaseManager,
    StableId,
};
use opc_types::{NetworkFunctionKind, TenantId};
use rustix::fs::{flock, FlockOperation};

use super::*;
use crate::install_manifest::INSTALL_PIN_OBJECT_NAMES;
use crate::lifecycle::{
    DurablePriorFenceState, EgressFenceLeaseAuthority, FenceLeaseGrant, LeaseFenceTiming,
    TerminalClosureEvidence,
};

const HOST_CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";
const HOST_BPFFS_ROOT: &str = "/sys/fs/bpf";
const ROOT_CGROUP_MUTATION_LOCK: &str = "/run/lock/opc-egress-fence-root-cgroup.lock";
const FIRST_SOCKET_TOKEN: u64 = 101;
const FIRST_RETIREMENT_TOKEN: u64 = 102;
const SECOND_SOCKET_TOKEN: u64 = 103;
const SECOND_RETIREMENT_TOKEN: u64 = 104;
// Linux's internal ENOTSUPP is distinct from the userspace EOPNOTSUPP value.
// bpf_map_freeze() returns this exact internal errno for special-field maps.
const KERNEL_ENOTSUPP: i32 = 524;

static NEXT_CASE: AtomicU64 = AtomicU64::new(1);

struct RootTestLock(File);

impl RootTestLock {
    fn acquire() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(ROOT_CGROUP_MUTATION_LOCK)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(io::Error::from)?;
        Ok(Self(file))
    }
}

impl Drop for RootTestLock {
    fn drop(&mut self) {
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}

struct PrivilegedCase {
    pin_root: PathBuf,
    root: Arc<HostCgroupV2Root>,
    cleanup_gate: Option<ProgramInfo>,
    cleaned: bool,
}

impl PrivilegedCase {
    fn create() -> Result<Self, &'static str> {
        let root = Arc::new(
            HostCgroupV2Root::open(Path::new(HOST_CGROUP_V2_ROOT))
                .map_err(|_| "privileged_case_root_open")?,
        );
        let initial = query_root(&root).map_err(|_| "privileged_case_root_query")?;
        if !initial.program_ids().is_empty() || initial.attach_flags() != 0 {
            return Err("privileged_case_root_not_empty");
        }

        for _ in 0..16 {
            let sequence = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
            let pin_root = Path::new(HOST_BPFFS_ROOT).join(format!(
                "opc-egress-fence-backend-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&pin_root) {
                Ok(()) => {
                    if fs::set_permissions(&pin_root, fs::Permissions::from_mode(0o700)).is_err() {
                        let _ = fs::remove_dir(&pin_root);
                        return Err("privileged_case_pin_mode");
                    }
                    return Ok(Self {
                        pin_root,
                        root,
                        cleanup_gate: None,
                        cleaned: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("privileged_case_pin_create"),
            }
        }
        Err("privileged_case_pin_namespace")
    }

    fn config(
        &self,
        endpoint: SocketAddr,
    ) -> Result<LinuxEgressFenceConfig, LinuxEgressFenceError> {
        LinuxEgressFenceConfig::new(endpoint, HOST_CGROUP_V2_ROOT, self.pin_root.clone())
    }

    fn cleanup_exact(&mut self) -> Result<(), &'static str> {
        let before = opc_linux_gtpu_sys::query_cgroup_skb_egress(self.root.as_fd())
            .map_err(|_| "privileged_cleanup_query")?;
        if before.attachments().len() > 1 {
            return Err("privileged_cleanup_foreign_attachment");
        }
        if let Some(attachment) = before.attachments().first() {
            if self
                .cleanup_gate
                .as_ref()
                .is_some_and(|gate| gate.id() != attachment.program_id())
            {
                return Err("privileged_cleanup_gate_identity");
            }
            if self.cleanup_gate.is_none() {
                self.cleanup_gate = self.find_exact_gate(attachment.program_id())?;
            }
            let gate = self
                .cleanup_gate
                .as_ref()
                .ok_or("privileged_cleanup_gate_pin_missing")?;
            opc_linux_gtpu_sys::detach_cgroup_skb_egress(
                self.root.as_fd(),
                gate.fd().map_err(|_| "privileged_cleanup_gate_fd")?.as_fd(),
                before.revision(),
            )
            .map_err(|_| "privileged_cleanup_detach")?;
            let after = opc_linux_gtpu_sys::query_cgroup_skb_egress(self.root.as_fd())
                .map_err(|_| "privileged_cleanup_post_query")?;
            if !after.attachments().is_empty()
                || after.attach_flags() != 0
                || after.revision() != before.revision().checked_add(1).unwrap_or(0)
            {
                return Err("privileged_cleanup_post_inventory");
            }
        } else if before.attach_flags() != 0 {
            return Err("privileged_cleanup_empty_flags");
        }

        for generation in self.generation_directories()? {
            for object_name in INSTALL_PIN_OBJECT_NAMES {
                match fs::remove_file(generation.join(object_name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return Err("privileged_cleanup_object"),
                }
            }
            if fs::read_dir(&generation)
                .map_err(|_| "privileged_cleanup_generation_scan")?
                .next()
                .is_some()
            {
                return Err("privileged_cleanup_foreign_object");
            }
            fs::remove_dir(&generation).map_err(|_| "privileged_cleanup_generation")?;
        }
        if fs::read_dir(&self.pin_root)
            .map_err(|_| "privileged_cleanup_root_scan")?
            .next()
            .is_some()
        {
            return Err("privileged_cleanup_foreign_generation");
        }
        fs::remove_dir(&self.pin_root).map_err(|_| "privileged_cleanup_root")?;
        self.cleaned = true;
        Ok(())
    }

    fn retain_exact_gate_for_cleanup(&mut self) -> Result<(), &'static str> {
        let inventory = opc_linux_gtpu_sys::query_cgroup_skb_egress(self.root.as_fd())
            .map_err(|_| "privileged_retain_gate_query")?;
        let [attachment] = inventory.attachments() else {
            return Err("privileged_retain_gate_inventory");
        };
        self.cleanup_gate = self.find_exact_gate(attachment.program_id())?;
        if self.cleanup_gate.is_none() {
            return Err("privileged_retain_gate_missing");
        }
        Ok(())
    }

    fn committed_object_path(&self, object_name: &str) -> Result<PathBuf, &'static str> {
        if !INSTALL_PIN_OBJECT_NAMES.contains(&object_name) {
            return Err("privileged_committed_object_name");
        }
        let mut committed = self
            .generation_directories()?
            .into_iter()
            .filter(|generation| {
                generation
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.starts_with("committed-"))
            });
        let generation = committed
            .next()
            .ok_or("privileged_committed_generation_missing")?;
        if committed.next().is_some() {
            return Err("privileged_committed_generation_ambiguous");
        }
        Ok(generation.join(object_name))
    }

    fn find_exact_gate(&self, program_id: u32) -> Result<Option<ProgramInfo>, &'static str> {
        let mut matched = None;
        for generation in self.generation_directories()? {
            let path = generation.join(EGRESS_FENCE_PROGRAM_NAME);
            if !path.exists() {
                continue;
            }
            let candidate =
                ProgramInfo::from_pin(path).map_err(|_| "privileged_cleanup_gate_open")?;
            if candidate.id() == program_id && matched.replace(candidate).is_some() {
                return Err("privileged_cleanup_duplicate_gate");
            }
        }
        Ok(matched)
    }

    fn generation_directories(&self) -> Result<Vec<PathBuf>, &'static str> {
        let mut generations = Vec::new();
        for entry in fs::read_dir(&self.pin_root).map_err(|_| "privileged_generation_scan")? {
            let entry = entry.map_err(|_| "privileged_generation_entry")?;
            if !entry
                .file_type()
                .map_err(|_| "privileged_generation_type")?
                .is_dir()
                || !valid_generation_name(&entry.file_name())
                || generations.len() >= 32
            {
                return Err("privileged_generation_invalid");
            }
            generations.push(entry.path());
        }
        Ok(generations)
    }
}

impl Drop for PrivilegedCase {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup_exact();
        }
    }
}

fn valid_generation_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let hexadecimal = ["staging-", "prepared-", "committed-"]
        .into_iter()
        .find_map(|prefix| name.strip_prefix(prefix));
    hexadecimal.is_some_and(|value| {
        value.len() == 32
            && value.bytes().any(|byte| byte != b'0')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn unused_loopback_endpoint() -> Result<SocketAddr, &'static str> {
    let probe =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| "privileged_endpoint_probe")?;
    let endpoint = probe
        .local_addr()
        .map_err(|_| "privileged_endpoint_readback")?;
    drop(probe);
    if endpoint.port() == 0 {
        return Err("privileged_endpoint_zero");
    }
    Ok(endpoint)
}

fn prepared_generation(
    case: &PrivilegedCase,
    endpoint: SocketAddr,
    check_lock_freeze_rejection: bool,
) -> Result<(GenerationDirectory, InstallManifest), LinuxEgressFenceError> {
    let protected = canonical_endpoint(endpoint)?;
    let config_bytes = FenceConfig::new(protected, ROOT_CGROUP_ID, EGRESS_FENCE_MAX_COOKIE_ENTRIES)
        .ok_or(LinuxEgressFenceError::InvalidConfiguration)?
        .encode();
    let mut loaded = load_embedded_artifact(config_bytes)?;
    if check_lock_freeze_rejection {
        let lock = Array::<_, u32>::try_from(
            loaded
                .ebpf
                .map(EGRESS_FENCE_LOCK_MAP_NAME)
                .ok_or(LinuxEgressFenceError::EmbeddedObject)?,
        )
        .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
        let error = opc_linux_gtpu_sys::freeze_bpf_map(lock.map().fd().as_fd())
            .expect_err("kernel must reject freezing the BTF spin-lock map");
        assert_eq!(error.raw_os_error(), Some(KERNEL_ENOTSUPP));
    }
    let store = FencePinStore::open(&case.pin_root).map_err(|_| LinuxEgressFenceError::PinStore)?;
    let guard = store.lock().map_err(|_| LinuxEgressFenceError::PinStore)?;
    cleanup_staging(&guard, &case.root)?;
    prepare_fresh_generation(
        &guard,
        &case.root,
        &mut loaded.ebpf,
        loaded.identity,
        config_bytes,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivilegedAuthorityError {
    Contract,
    Store,
}

struct PrivilegedAuthority {
    backend: FakeSessionBackend,
    prior: Mutex<Option<DurablePriorFenceState>>,
    expected_attachment: FenceAttachmentIdentity,
    socket_token: NonZeroU64,
    retirement_token: NonZeroU64,
    durable_generation: NonZeroU64,
}

impl PrivilegedAuthority {
    fn new(
        backend: FakeSessionBackend,
        prior: DurablePriorFenceState,
        expected_attachment: FenceAttachmentIdentity,
        socket_token: u64,
        retirement_token: u64,
        durable_generation: u64,
    ) -> Self {
        Self {
            backend,
            prior: Mutex::new(Some(prior)),
            expected_attachment,
            socket_token: NonZeroU64::new(socket_token).expect("nonzero socket token"),
            retirement_token: NonZeroU64::new(retirement_token).expect("nonzero retirement token"),
            durable_generation: NonZeroU64::new(durable_generation)
                .expect("nonzero durable generation"),
        }
    }
}

#[async_trait]
impl EgressFenceLeaseAuthority for PrivilegedAuthority {
    type Error = PrivilegedAuthorityError;

    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
        current_attachment: FenceAttachmentIdentity,
        current_gate_lifetime: Duration,
    ) -> Result<FenceLeaseGrant, Self::Error> {
        if current_attachment != self.expected_attachment || current_gate_lifetime.is_zero() {
            return Err(PrivilegedAuthorityError::Contract);
        }
        let guard = SessionLeaseManager::acquire(&self.backend, key, owner, ttl)
            .await
            .map_err(|_| PrivilegedAuthorityError::Store)?;
        let prior = self
            .prior
            .lock()
            .map_err(|_| PrivilegedAuthorityError::Contract)?
            .take()
            .ok_or(PrivilegedAuthorityError::Contract)?;
        FenceLeaseGrant::from_verified_authority_transaction(
            guard,
            self.socket_token,
            self.retirement_token,
            prior,
            self.durable_generation,
        )
        .map_err(|_| PrivilegedAuthorityError::Contract)
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, Self::Error> {
        SessionLeaseManager::renew(&self.backend, lease, ttl)
            .await
            .map_err(|_| PrivilegedAuthorityError::Store)
    }

    async fn release_with_terminal(
        &self,
        lease: LeaseGuard,
        evidence: TerminalClosureEvidence,
    ) -> Result<(), Self::Error> {
        if evidence.attachment() != self.expected_attachment
            || evidence.socket_lifecycle_token() != self.socket_token
            || evidence.retirement_lifecycle_token() != self.retirement_token
        {
            return Err(PrivilegedAuthorityError::Contract);
        }
        SessionLeaseManager::release(&self.backend, lease)
            .await
            .map_err(|_| PrivilegedAuthorityError::Store)
    }
}

fn fixture_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("egress-fence-test").expect("fixture tenant"),
        nf_kind: NetworkFunctionKind::from_static("upf"),
        key_type: SessionKeyType::PduSession,
        stable_id: StableId::new(Bytes::from_static(b"egress-fence-test"))
            .expect("fixture stable id"),
    }
}

fn fixture_owner(value: &'static str) -> OwnerId {
    OwnerId::new(value).expect("fixture owner")
}

async fn expect_empty_datagram(receiver: &tokio::net::UdpSocket) -> Result<(), &'static str> {
    let mut buffer = [0_u8; 1];
    let (bytes, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buffer))
        .await
        .map_err(|_| "privileged_receive_timeout")?
        .map_err(|_| "privileged_receive")?;
    if bytes != 0 {
        return Err("privileged_receive_nonempty");
    }
    Ok(())
}

async fn expect_no_datagram(receiver: &tokio::net::UdpSocket) -> Result<(), &'static str> {
    let mut buffer = [0_u8; 1];
    match tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut buffer)).await {
        Err(_) => Ok(()),
        Ok(_) => Err("privileged_unexpected_datagram"),
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires root, bpffs, cgroup-v2 revision UAPI, and BPF authority"]
async fn production_backend_fresh_expiry_adoption_and_prepared_recovery() {
    let _root_lock = RootTestLock::acquire().expect("privileged root-test lock");

    {
        let mut case = PrivilegedCase::create().expect("prepared-pre case");
        let endpoint = unused_loopback_endpoint().expect("prepared-pre endpoint");
        let config = case.config(endpoint).expect("prepared-pre config");
        let before = query_root(&case.root).expect("prepared-pre root");
        let (prepared, manifest) =
            prepared_generation(&case, endpoint, true).expect("prepared-pre generation");
        assert!(manifest.validates_root_pre_attach(&before));
        drop(prepared);

        let recovered =
            install_or_adopt_linux_egress_fence(&config).expect("prepared-pre recovery");
        let after = query_root(&case.root).expect("prepared-pre post root");
        assert!(manifest.validates_root_adoption(&after));
        assert!(
            before
                .revision()
                .checked_add(1)
                .is_some_and(|expected| after.revision() == expected),
            "prepared-pre root revision did not advance exactly once"
        );
        drop(recovered);
        case.cleanup_exact().expect("prepared-pre cleanup");
    }

    {
        let mut case = PrivilegedCase::create().expect("prepared-post case");
        let endpoint = unused_loopback_endpoint().expect("prepared-post endpoint");
        let config = case.config(endpoint).expect("prepared-post config");
        let (prepared, manifest) =
            prepared_generation(&case, endpoint, false).expect("prepared-post generation");
        let before = query_root(&case.root).expect("prepared-post root");
        assert!(manifest.validates_root_pre_attach(&before));
        verify_initial_closed_state(
            &prepared,
            FenceConfig::new(
                canonical_endpoint(endpoint).expect("prepared-post canonical endpoint"),
                ROOT_CGROUP_ID,
                EGRESS_FENCE_MAX_COOKIE_ENTRIES,
            )
            .expect("prepared-post fence config")
            .encode(),
        )
        .expect("prepared-post initial pre-attach");
        {
            let gate = ProgramInfo::from_pin(
                prepared
                    .object_path(EGRESS_FENCE_PROGRAM_NAME)
                    .expect("prepared-post gate path"),
            )
            .expect("prepared-post gate");
            opc_linux_gtpu_sys::attach_cgroup_skb_egress(
                case.root.as_fd(),
                gate.fd().expect("prepared-post gate fd").as_fd(),
                before.revision(),
            )
            .expect("prepared-post attach");
        }
        let attached = query_root(&case.root).expect("prepared-post attached root");
        assert!(manifest.validates_root_adoption(&attached));
        drop(prepared);

        let recovered =
            install_or_adopt_linux_egress_fence(&config).expect("prepared-post recovery");
        let promoted = query_root(&case.root).expect("prepared-post promoted root");
        assert!(manifest.validates_root_adoption(&promoted));
        assert!(
            promoted.revision() == attached.revision(),
            "prepared-post recovery changed the attached root revision"
        );
        drop(recovered);
        case.cleanup_exact().expect("prepared-post cleanup");
    }

    {
        let mut case = PrivilegedCase::create().expect("committed-pre-authority case");
        let endpoint = unused_loopback_endpoint().expect("committed-pre-authority endpoint");
        let config = case
            .config(endpoint)
            .expect("committed-pre-authority config");
        let installed = install_or_adopt_linux_egress_fence(&config)
            .expect("committed-pre-authority production install");
        let attachment = installed.attachment_identity();
        let (socket_before_authority, installed_attachment) = installed.into_parts();
        assert_eq!(installed_attachment, attachment);

        // Simulate process loss after the generation is durably committed and
        // attached closed, but before durable lease authority is contacted.
        drop(socket_before_authority);

        let restarted = install_or_adopt_linux_egress_fence(&config)
            .expect("committed-pre-authority restart adoption");
        assert_eq!(restarted.attachment_identity(), attachment);
        let (mut socket, restarted_attachment) = restarted.into_parts();
        assert_eq!(restarted_attachment, attachment);
        let authority = PrivilegedAuthority::new(
            FakeSessionBackend::new(),
            DurablePriorFenceState::fresh_install(
                NonZeroU64::new(1).expect("committed-pre-authority bootstrap generation"),
            ),
            attachment,
            81,
            82,
            2,
        );
        let timing = LeaseFenceTiming::new(Duration::from_secs(2), Duration::from_secs(1))
            .expect("committed-pre-authority timing");
        let lease = socket
            .acquire(
                &authority,
                &fixture_key(),
                fixture_owner("egress-fence-committed-pre-authority"),
                timing,
            )
            .await
            .expect("committed-pre-authority fresh activation");
        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("committed-pre-authority receiver bind");
        let destination = receiver
            .local_addr()
            .expect("committed-pre-authority receiver address");
        assert_eq!(
            socket
                .send_to(&[], destination)
                .await
                .expect("committed-pre-authority active send"),
            0
        );
        expect_empty_datagram(&receiver)
            .await
            .expect("committed-pre-authority active receive");
        socket
            .close_then_release(&authority, lease)
            .await
            .expect("committed-pre-authority orderly release");
        drop(socket);
        case.cleanup_exact()
            .expect("committed-pre-authority cleanup");
    }

    {
        let mut case = PrivilegedCase::create().expect("fresh-adoption case");
        let endpoint = unused_loopback_endpoint().expect("fresh-adoption endpoint");
        let config = case.config(endpoint).expect("fresh-adoption config");
        let installed =
            install_or_adopt_linux_egress_fence(&config).expect("fresh production install");
        let attachment = installed.attachment_identity();
        let (mut socket, returned_attachment) = installed.into_parts();
        assert_eq!(returned_attachment, attachment);
        let backend = FakeSessionBackend::new();
        let timing = LeaseFenceTiming::new(Duration::from_secs(2), Duration::from_secs(1))
            .expect("fresh timing");
        let first_authority = PrivilegedAuthority::new(
            backend.clone(),
            DurablePriorFenceState::fresh_install(
                NonZeroU64::new(1).expect("bootstrap generation"),
            ),
            attachment,
            FIRST_SOCKET_TOKEN,
            FIRST_RETIREMENT_TOKEN,
            2,
        );
        let lease = socket
            .acquire(
                &first_authority,
                &fixture_key(),
                fixture_owner("egress-fence-first"),
                timing,
            )
            .await
            .expect("fresh activation");
        assert!(socket.is_active());

        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("receiver bind");
        let destination = receiver.local_addr().expect("receiver address");
        assert_eq!(
            socket.send_to(&[], destination).await.expect("active send"),
            0
        );
        expect_empty_datagram(&receiver)
            .await
            .expect("active receive");

        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let expired = socket
            .send_to(&[], destination)
            .await
            .expect_err("expired send must fail closed");
        assert_eq!(expired.kind(), io::ErrorKind::PermissionDenied);
        assert!(!socket.is_active());
        drop(lease);
        drop(socket);
        tokio::time::sleep(Duration::from_millis(1_000)).await;

        let adopted = install_or_adopt_linux_egress_fence(&config).expect("restart exact adoption");
        assert_eq!(adopted.attachment_identity(), attachment);
        let (mut successor, successor_attachment) = adopted.into_parts();
        assert_eq!(successor_attachment, attachment);
        let prior = DurablePriorFenceState::last_attachment(
            attachment,
            NonZeroU64::new(FIRST_SOCKET_TOKEN).expect("first socket token"),
            NonZeroU64::new(FIRST_RETIREMENT_TOKEN).expect("first retirement token"),
            timing.active_gate_lifetime(),
            NonZeroU64::new(2).expect("prior generation"),
        )
        .expect("exact prior attachment");
        let second_authority = PrivilegedAuthority::new(
            backend,
            prior,
            attachment,
            SECOND_SOCKET_TOKEN,
            SECOND_RETIREMENT_TOKEN,
            3,
        );
        let successor_lease = successor
            .acquire(
                &second_authority,
                &fixture_key(),
                fixture_owner("egress-fence-second"),
                timing,
            )
            .await
            .expect("successor activation");
        assert_eq!(
            successor
                .send_to(&[], destination)
                .await
                .expect("successor send"),
            0
        );
        expect_empty_datagram(&receiver)
            .await
            .expect("successor receive");
        successor
            .close_then_release(&second_authority, successor_lease)
            .await
            .expect("successor orderly release");
        drop(successor);
        case.cleanup_exact().expect("fresh-adoption cleanup");
    }

    for (drop_mutation, socket_token, retirement_token, owner_value) in [
        (true, 301, 302, "egress-fence-mutation-fd-loss"),
        (false, 303, 304, "egress-fence-view-fd-loss"),
    ] {
        let mut case = PrivilegedCase::create().expect("control-fd-loss case");
        let endpoint = unused_loopback_endpoint().expect("control-fd-loss endpoint");
        let config = case.config(endpoint).expect("control-fd-loss config");
        let installed = install_or_adopt_linux_egress_fence(&config)
            .expect("control-fd-loss production install");
        let attachment = installed.attachment_identity();
        let (mut socket, _) = installed.into_parts();
        let timing = LeaseFenceTiming::new(Duration::from_secs(2), Duration::from_secs(1))
            .expect("control-fd-loss timing");
        let authority = PrivilegedAuthority::new(
            FakeSessionBackend::new(),
            DurablePriorFenceState::fresh_install(
                NonZeroU64::new(1).expect("control-fd-loss bootstrap generation"),
            ),
            attachment,
            socket_token,
            retirement_token,
            2,
        );
        let lease = socket
            .acquire(
                &authority,
                &fixture_key(),
                fixture_owner(owner_value),
                timing,
            )
            .await
            .expect("control-fd-loss activation");
        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("control-fd-loss receiver bind");
        let destination = receiver
            .local_addr()
            .expect("control-fd-loss receiver address");
        assert_eq!(
            socket
                .send_to(&[], destination)
                .await
                .expect("control-fd-loss baseline send"),
            0
        );
        expect_empty_datagram(&receiver)
            .await
            .expect("control-fd-loss baseline receive");

        // These crate-test-only hooks independently drop one production
        // adapter program descriptor. They are absent from non-test builds and
        // from the public API.
        if drop_mutation {
            socket
                .test_drop_private_mutation_program_fd()
                .expect("mutation-fd-loss injection");
        } else {
            socket
                .test_drop_private_view_program_fd()
                .expect("view-fd-loss injection");
        }
        let denied = socket
            .send_to(&[], destination)
            .await
            .expect_err("control fd loss must fail send closed");
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        assert!(!socket.is_active());
        assert_eq!(
            socket
                .local_addr()
                .expect_err("control fd loss must close socket")
                .kind(),
            io::ErrorKind::NotConnected
        );
        expect_no_datagram(&receiver)
            .await
            .expect("control-fd-loss no datagram");
        drop(lease);
        drop(socket);

        // The committed pins remain intact, so a restarted process can reopen
        // the exact programs and compose a new closed socket immediately.
        // Durable authority still governs any later activation.
        let adopted = install_or_adopt_linux_egress_fence(&config)
            .expect("control-fd-loss restart exact adoption");
        assert_eq!(adopted.attachment_identity(), attachment);
        let (adopted_socket, adopted_attachment) = adopted.into_parts();
        assert_eq!(adopted_attachment, attachment);
        assert!(
            adopted_socket
                .local_addr()
                .is_ok_and(|observed| observed == endpoint),
            "control-fd-loss adoption did not retain the protected endpoint"
        );
        drop(adopted_socket);

        tokio::time::sleep(Duration::from_millis(1_200)).await;
        case.cleanup_exact().expect("control-fd-loss cleanup");
    }

    {
        let mut case = PrivilegedCase::create().expect("pin-loss case");
        let endpoint = unused_loopback_endpoint().expect("pin-loss endpoint");
        let config = case.config(endpoint).expect("pin-loss config");
        let installed =
            install_or_adopt_linux_egress_fence(&config).expect("pin-loss production install");
        let attachment = installed.attachment_identity();
        let (mut socket, _) = installed.into_parts();
        let timing = LeaseFenceTiming::new(Duration::from_secs(2), Duration::from_secs(1))
            .expect("pin-loss timing");
        let authority = PrivilegedAuthority::new(
            FakeSessionBackend::new(),
            DurablePriorFenceState::fresh_install(
                NonZeroU64::new(1).expect("pin-loss bootstrap generation"),
            ),
            attachment,
            201,
            202,
            2,
        );
        let lease = socket
            .acquire(
                &authority,
                &fixture_key(),
                fixture_owner("egress-fence-pin-loss"),
                timing,
            )
            .await
            .expect("pin-loss activation");
        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("pin-loss receiver bind");
        let destination = receiver.local_addr().expect("pin-loss receiver address");
        assert_eq!(
            socket
                .send_to(&[], destination)
                .await
                .expect("pin-loss baseline send"),
            0
        );
        expect_empty_datagram(&receiver)
            .await
            .expect("pin-loss baseline receive");

        // Retain an exact test-only gate fd solely so cleanup can detach after
        // its pin is removed. The live production composition independently
        // retains private control/view fds. Removing the gate pin must still
        // make its integrity preflight fail, proving those retained fds cannot
        // substitute for the exact committed pin inventory.
        case.retain_exact_gate_for_cleanup()
            .expect("pin-loss cleanup gate");
        fs::remove_file(
            case.committed_object_path(EGRESS_FENCE_PROGRAM_NAME)
                .expect("pin-loss committed gate"),
        )
        .expect("pin-loss unlink gate");

        let denied = socket
            .send_to(&[], destination)
            .await
            .expect_err("pin loss must fail send closed");
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        expect_no_datagram(&receiver)
            .await
            .expect("pin-loss no datagram");
        drop(lease);
        drop(socket);

        assert!(matches!(
            install_or_adopt_linux_egress_fence(&config),
            Err(LinuxEgressFenceError::KernelObject)
        ));
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        case.cleanup_exact().expect("pin-loss cleanup");
    }
}
