//! Explicit production installer and adopter for the Linux root-cgroup fence.

use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::{AsFd, BorrowedFd},
    path::PathBuf,
    sync::Arc,
};

use aya::{
    maps::{Array, HashMap as AyaHashMap, IterableMap, Map, MapData, MapInfo, PerCpuArray},
    programs::{CgroupSkb, ProgramInfo, SchedClassifier},
    Ebpf, EbpfLoader,
};
use nix::{
    ifaddrs::getifaddrs,
    net::if_::{if_nametoindex, InterfaceFlags},
};
use opc_egress_fence_common::{
    CurrentFenceToken, FenceConfig, FenceCookieKey, FenceCookieValue, FenceEntryState,
    FenceMutationAuthority, ProtectedEndpoint, EGRESS_FENCE_CONFIG_MAP_NAME,
    EGRESS_FENCE_CONFIG_VALUE_LEN, EGRESS_FENCE_CONTROL_PROGRAM_NAME, EGRESS_FENCE_COOKIE_KEY_LEN,
    EGRESS_FENCE_COOKIE_MAP_NAME, EGRESS_FENCE_COOKIE_VALUE_LEN, EGRESS_FENCE_COUNTER_MAP_NAME,
    EGRESS_FENCE_CURRENT_MAP_NAME, EGRESS_FENCE_CURRENT_VALUE_LEN,
    EGRESS_FENCE_INSPECT_PROGRAM_NAME, EGRESS_FENCE_LOCK_MAP_NAME, EGRESS_FENCE_MAX_COOKIE_ENTRIES,
    EGRESS_FENCE_MUTATION_MAP_NAME, EGRESS_FENCE_PROGRAM_NAME,
};
use opc_runtime::{bind_udp_socket_with_destination_metadata_and_options, UdpSocketOptions};
use sha2::{Digest, Sha256};

use crate::lifecycle::LeaseBoundFence;
use crate::{
    install_manifest::{
        InstallManifest, KernelObjectName, ManifestMap, ManifestProgram, MapFreezePolicy,
        INSTALL_MANIFEST_BYTES, INSTALL_MAP_COUNT, INSTALL_PROGRAM_COUNT, MANIFEST_MAP_NAME,
        MAX_PROGRAM_MAPS, OBJECT_MAP_COUNT,
    },
    lifecycle::{
        AttachmentIdentity, AttachmentInventory, FenceAttachmentIdentity, KernelEntryState,
        KernelFailure, KernelFenceEntry,
    },
    linux_control::{InstallationIntegrity, LinuxBootClock, LinuxKernelControl},
    pin_store::{
        FencePinStore, FencePinStoreGuard, GenerationDirectory, GenerationInventoryEntry,
        GenerationPhase,
    },
    root_cgroup::HostCgroupV2Root,
    root_inventory::RootInventory,
    socket::FencedUdpSocket,
};

const ROOT_CGROUP_ID: u64 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const MANIFEST_MAP_KEY_SIZE: u32 = 4;
const IDENTITY_DOMAIN: &[u8] = b"opc-egress-fence-attachment-v2";
const EMBEDDED_OBJECT: &[u8] = aya::include_bytes_aligned!("../bpf/opc-egress-fence.bpf.o");

const PROGRAM_NAMES: [&str; INSTALL_PROGRAM_COUNT] = [
    EGRESS_FENCE_PROGRAM_NAME,
    EGRESS_FENCE_CONTROL_PROGRAM_NAME,
    EGRESS_FENCE_INSPECT_PROGRAM_NAME,
];

const OBJECT_MAP_NAMES: [&str; OBJECT_MAP_COUNT] = [
    EGRESS_FENCE_COOKIE_MAP_NAME,
    EGRESS_FENCE_CONFIG_MAP_NAME,
    EGRESS_FENCE_COUNTER_MAP_NAME,
    EGRESS_FENCE_CURRENT_MAP_NAME,
    EGRESS_FENCE_LOCK_MAP_NAME,
    EGRESS_FENCE_MUTATION_MAP_NAME,
];

const ALL_MAP_NAMES: [&str; INSTALL_MAP_COUNT] = [
    EGRESS_FENCE_COOKIE_MAP_NAME,
    EGRESS_FENCE_CONFIG_MAP_NAME,
    EGRESS_FENCE_COUNTER_MAP_NAME,
    EGRESS_FENCE_CURRENT_MAP_NAME,
    EGRESS_FENCE_LOCK_MAP_NAME,
    EGRESS_FENCE_MUTATION_MAP_NAME,
    MANIFEST_MAP_NAME,
];

/// Explicit host paths and exact local UDP endpoint for one Linux fence.
///
/// There are no deployment defaults: callers must supply the operator-mounted
/// true cgroup-v2 root and a root-owned bpffs directory dedicated to this
/// endpoint. Formatting never emits the endpoint or paths.
#[derive(Clone, PartialEq, Eq)]
pub struct LinuxEgressFenceConfig {
    endpoint: SocketAddr,
    host_cgroup_v2_root: PathBuf,
    bpffs_pin_root: PathBuf,
}

impl LinuxEgressFenceConfig {
    /// Construct one explicit installer/adopter request.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxEgressFenceError::InvalidConfiguration`] unless the
    /// endpoint is a canonical exact nonzero unicast address and both paths
    /// are absolute. Filesystem and live local-assignment proofs occur during
    /// installation.
    pub fn new(
        endpoint: SocketAddr,
        host_cgroup_v2_root: impl Into<PathBuf>,
        bpffs_pin_root: impl Into<PathBuf>,
    ) -> Result<Self, LinuxEgressFenceError> {
        let host_cgroup_v2_root = host_cgroup_v2_root.into();
        let bpffs_pin_root = bpffs_pin_root.into();
        canonical_endpoint(endpoint)?;
        if !host_cgroup_v2_root.is_absolute() || !bpffs_pin_root.is_absolute() {
            return Err(LinuxEgressFenceError::InvalidConfiguration);
        }
        Ok(Self {
            endpoint,
            host_cgroup_v2_root,
            bpffs_pin_root,
        })
    }
}

impl fmt::Debug for LinuxEgressFenceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxEgressFenceConfig")
            .field("endpoint", &"<redacted>")
            .field("host_cgroup_v2_root", &"<redacted>")
            .field("bpffs_pin_root", &"<redacted>")
            .finish()
    }
}

/// Completed opt-in Linux composition.
///
/// Create bounded channels and ports with [`crate::fenced_udp_channels`], then
/// move the socket and ports into [`crate::run_fenced_udp_guardian`]. The
/// durable attachment identity is retained separately so the lease authority
/// can persist it. This type exposes no descriptor, map, program, cookie,
/// endpoint, or pin path.
pub struct LinuxEgressFenceSocket {
    socket: FencedUdpSocket,
    attachment_identity: FenceAttachmentIdentity,
}

impl LinuxEgressFenceSocket {
    /// Exact opaque identity to persist with durable lease authority.
    #[must_use]
    pub const fn attachment_identity(&self) -> FenceAttachmentIdentity {
        self.attachment_identity
    }

    /// Consume the composition into its guardian-ready socket and identity.
    #[must_use]
    pub fn into_parts(self) -> (FencedUdpSocket, FenceAttachmentIdentity) {
        (self.socket, self.attachment_identity)
    }
}

impl fmt::Debug for LinuxEgressFenceSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxEgressFenceSocket")
            .field("socket", &self.socket)
            .field("attachment_identity", &"<redacted>")
            .finish()
    }
}

/// Value-free Linux installer, adoption, and composition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinuxEgressFenceError {
    /// Endpoint or path syntax is not canonical.
    InvalidConfiguration,
    /// The endpoint does not have exactly one UP local interface assignment.
    EndpointOwnership,
    /// Exact exclusive socket admission failed.
    SocketAdmission,
    /// The supplied cgroup path is not the true host cgroup-v2 root.
    HostRoot,
    /// The dedicated bpffs store could not be locked or proved.
    PinStore,
    /// The embedded production object could not be loaded exactly.
    EmbeddedObject,
    /// A pinned or loaded kernel object failed exact identity readback.
    KernelObject,
    /// Existing root, generation, or upgrade state is foreign or ambiguous.
    Conflict,
    /// Direct attachment or mandatory post-attachment readback failed.
    Attachment,
    /// Static installation integrity could not be reproved.
    Integrity,
    /// The safe userspace lifecycle could not be composed.
    Composition,
}

impl LinuxEgressFenceError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "egress_fence_linux_invalid_configuration",
            Self::EndpointOwnership => "egress_fence_linux_endpoint_ownership",
            Self::SocketAdmission => "egress_fence_linux_socket_admission",
            Self::HostRoot => "egress_fence_linux_host_root",
            Self::PinStore => "egress_fence_linux_pin_store",
            Self::EmbeddedObject => "egress_fence_linux_embedded_object",
            Self::KernelObject => "egress_fence_linux_kernel_object",
            Self::Conflict => "egress_fence_linux_conflict",
            Self::Attachment => "egress_fence_linux_attachment",
            Self::Integrity => "egress_fence_linux_integrity",
            Self::Composition => "egress_fence_linux_composition",
        }
    }
}

impl fmt::Display for LinuxEgressFenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for LinuxEgressFenceError {}

/// Bind, install or exactly adopt, and compose one Linux egress fence.
///
/// This is the only production construction path. It creates and consumes the
/// UDP socket internally before any descriptor or cookie can escape. Existing
/// committed state is adopted only after complete live readback. A prepared
/// generation is resumed only at one of its two exact crash points. No foreign
/// attachment is detached and no installed generation is replaced.
///
/// # Errors
///
/// Returns a value-free [`LinuxEgressFenceError`] on every uncertain state.
pub fn install_or_adopt_linux_egress_fence(
    config: &LinuxEgressFenceConfig,
) -> Result<LinuxEgressFenceSocket, LinuxEgressFenceError> {
    let protected_endpoint = canonical_endpoint(config.endpoint)?;
    let assignment = exact_local_assignment(config.endpoint)?;
    let socket_options = if config.endpoint.is_ipv6() {
        UdpSocketOptions::default().with_ipv6_only()
    } else {
        UdpSocketOptions::default()
    };
    let socket =
        bind_udp_socket_with_destination_metadata_and_options(config.endpoint, &socket_options)
            .map_err(|_| LinuxEgressFenceError::SocketAdmission)?;
    socket
        .verify_fence_admission()
        .map_err(|_| LinuxEgressFenceError::SocketAdmission)?;
    if socket
        .local_addr()
        .map_err(|_| LinuxEgressFenceError::SocketAdmission)?
        != config.endpoint
        || exact_local_assignment(config.endpoint)? != assignment
    {
        return Err(LinuxEgressFenceError::EndpointOwnership);
    }
    let socket_identity = socket
        .socket_kernel_identity()
        .map_err(|_| LinuxEgressFenceError::SocketAdmission)?;

    let root = Arc::new(
        HostCgroupV2Root::open(&config.host_cgroup_v2_root)
            .map_err(|_| LinuxEgressFenceError::HostRoot)?,
    );
    let store =
        FencePinStore::open(&config.bpffs_pin_root).map_err(|_| LinuxEgressFenceError::PinStore)?;
    let fence_config = FenceConfig::new(
        protected_endpoint,
        ROOT_CGROUP_ID,
        EGRESS_FENCE_MAX_COOKIE_ENTRIES,
    )
    .ok_or(LinuxEgressFenceError::InvalidConfiguration)?;
    let config_bytes = fence_config.encode();
    let mut loaded = load_embedded_artifact(config_bytes)?;
    let artifact = loaded.identity;

    let (generation_id, manifest, inventory_mode) = {
        let guard = store.lock().map_err(|_| LinuxEgressFenceError::PinStore)?;
        cleanup_staging(&guard, &root)?;
        let recovery = guard
            .recovery_inventory()
            .map_err(|_| LinuxEgressFenceError::PinStore)?;
        match (recovery.committed, recovery.prepared) {
            (None, None) => install_fresh(&guard, &root, &mut loaded.ebpf, artifact, config_bytes)?,
            (Some(entry), None) => {
                let generation = guard
                    .open_existing(entry)
                    .map_err(|_| LinuxEgressFenceError::PinStore)?;
                let manifest = verify_generation_static(&generation, artifact, config_bytes)?;
                let observed = query_root(&root)?;
                if !manifest.validates_root_adoption(&observed) {
                    return Err(LinuxEgressFenceError::Conflict);
                }
                let inventory = match classify_committed_dynamic_state(&generation, config_bytes)? {
                    CommittedDynamicState::NeverActivated => {
                        AttachmentInventory::AdoptedNeverActivated
                    }
                    CommittedDynamicState::CanonicalNonInitial => AttachmentInventory::AdoptedExact,
                };
                (generation.generation_id(), manifest, inventory)
            }
            (None, Some(entry)) => recover_prepared(&guard, &root, entry, artifact, config_bytes)?,
            (Some(_), Some(_)) => return Err(LinuxEgressFenceError::Conflict),
        }
    };
    drop(loaded);

    if exact_local_assignment(config.endpoint)? != assignment {
        return Err(LinuxEgressFenceError::EndpointOwnership);
    }
    let durable = attachment_identity(&manifest)?;
    let attachment = AttachmentIdentity {
        durable,
        inventory: inventory_mode,
    };
    let integrity = Arc::new(LiveInstallationIntegrity {
        store: store.clone(),
        root: Arc::clone(&root),
        generation_id,
        manifest,
        artifact,
        config_bytes,
        endpoint: config.endpoint,
        assignment,
        attachment,
    });
    integrity
        .verify(attachment)
        .map_err(|_| LinuxEgressFenceError::Integrity)?;

    let generation = committed_generation(&store, generation_id)?;
    let mutation = SchedClassifier::from_pin(
        generation
            .object_path(EGRESS_FENCE_CONTROL_PROGRAM_NAME)
            .map_err(|_| LinuxEgressFenceError::PinStore)?,
    )
    .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let view = SchedClassifier::from_pin(
        generation
            .object_path(EGRESS_FENCE_INSPECT_PROGRAM_NAME)
            .map_err(|_| LinuxEgressFenceError::PinStore)?,
    )
    .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let kernel = Arc::new(
        LinuxKernelControl::new(mutation, view, integrity, ROOT_CGROUP_ID)
            .map_err(|_| LinuxEgressFenceError::Composition)?,
    );
    let fence = LeaseBoundFence::from_unregistered(
        kernel,
        Arc::new(LinuxBootClock),
        attachment,
        socket_identity.socket_cookie(),
    )
    .map_err(|_| LinuxEgressFenceError::Composition)?;
    let socket = FencedUdpSocket::from_unregistered(socket, fence, config.endpoint)
        .map_err(|_| LinuxEgressFenceError::Composition)?;
    Ok(LinuxEgressFenceSocket {
        socket,
        attachment_identity: durable,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct LocalAssignment {
    interface_index: u32,
}

impl fmt::Debug for LocalAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAssignment(<redacted>)")
    }
}

fn canonical_endpoint(endpoint: SocketAddr) -> Result<ProtectedEndpoint, LinuxEgressFenceError> {
    match endpoint {
        SocketAddr::V4(value) => ProtectedEndpoint::ipv4(value.ip().octets(), value.port()),
        SocketAddr::V6(value) if value.flowinfo() == 0 && value.scope_id() == 0 => {
            ProtectedEndpoint::ipv6(value.ip().octets(), value.port())
        }
        SocketAddr::V6(_) => None,
    }
    .ok_or(LinuxEgressFenceError::InvalidConfiguration)
}

fn exact_local_assignment(endpoint: SocketAddr) -> Result<LocalAssignment, LinuxEgressFenceError> {
    let expected = endpoint.ip();
    let mut matches = Vec::new();
    for interface in getifaddrs().map_err(|_| LinuxEgressFenceError::EndpointOwnership)? {
        if !interface.flags.contains(InterfaceFlags::IFF_UP) {
            continue;
        }
        let Some(address) = interface.address.as_ref() else {
            continue;
        };
        let observed = if let Some(address) = address.as_sockaddr_in() {
            Some(IpAddr::V4(address.ip()))
        } else {
            address
                .as_sockaddr_in6()
                .map(|address| IpAddr::V6(address.ip()))
        };
        if observed == Some(expected) {
            if let IpAddr::V4(expected) = expected {
                let netmask = interface
                    .netmask
                    .as_ref()
                    .and_then(|netmask| netmask.as_sockaddr_in())
                    .map(|netmask| netmask.ip())
                    .ok_or(LinuxEgressFenceError::EndpointOwnership)?;
                let broadcast = interface
                    .broadcast
                    .as_ref()
                    .and_then(|broadcast| broadcast.as_sockaddr_in())
                    .map(|broadcast| broadcast.ip());
                if !ipv4_assignment_is_canonical_unicast(
                    expected,
                    netmask,
                    broadcast,
                    interface.flags.contains(InterfaceFlags::IFF_BROADCAST),
                ) {
                    return Err(LinuxEgressFenceError::EndpointOwnership);
                }
            }
            let index = if_nametoindex(interface.interface_name.as_str())
                .map_err(|_| LinuxEgressFenceError::EndpointOwnership)?;
            matches.push(index);
        }
    }
    select_exact_assignment(&matches)
}

fn ipv4_assignment_is_canonical_unicast(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    interface_broadcast: Option<Ipv4Addr>,
    broadcast_capable: bool,
) -> bool {
    let mask = u32::from(netmask);
    let prefix_length = mask.leading_ones();
    let canonical_mask = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (u32::BITS - prefix_length)
    };
    if mask != canonical_mask {
        return false;
    }

    // RFC 3021 makes both host values usable on a /31, and a /32 has no host
    // portion. Shorter prefixes retain distinct subnet-number and directed-
    // broadcast values, neither of which is a canonical unicast source.
    if prefix_length >= 31 {
        return true;
    }
    let host_mask = !mask;
    let address = u32::from(address);
    let host = address & host_mask;
    if host == 0 || host == host_mask {
        return false;
    }
    let canonical_broadcast = Ipv4Addr::from(address | host_mask);
    match interface_broadcast {
        Some(observed) => observed == canonical_broadcast,
        None => !broadcast_capable,
    }
}

fn select_exact_assignment(matches: &[u32]) -> Result<LocalAssignment, LinuxEgressFenceError> {
    match matches {
        [interface_index] if *interface_index != 0 => Ok(LocalAssignment {
            interface_index: *interface_index,
        }),
        _ => Err(LinuxEgressFenceError::EndpointOwnership),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ArtifactProgram {
    name: &'static str,
    program_type: u32,
    tag: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ArtifactIdentity {
    digest: [u8; 32],
    programs: [ArtifactProgram; INSTALL_PROGRAM_COUNT],
}

struct LoadedArtifact {
    ebpf: Ebpf,
    identity: ArtifactIdentity,
}

fn load_embedded_artifact(
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
) -> Result<LoadedArtifact, LinuxEgressFenceError> {
    let mut ebpf = EbpfLoader::new()
        .load(EMBEDDED_OBJECT)
        .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    require_exact_loaded_names(&ebpf)?;
    {
        let map = ebpf
            .map_mut(EGRESS_FENCE_CONFIG_MAP_NAME)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?;
        let mut config = Array::<_, [u8; EGRESS_FENCE_CONFIG_VALUE_LEN]>::try_from(map)
            .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
        config
            .set(0, config_bytes, 0)
            .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
        if config
            .get(&0, 0)
            .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?
            != config_bytes
        {
            return Err(LinuxEgressFenceError::EmbeddedObject);
        }
    }
    freeze_loaded_maps(&ebpf)?;
    load_programs(&mut ebpf)?;
    let programs = artifact_programs(&ebpf)?;
    Ok(LoadedArtifact {
        ebpf,
        identity: ArtifactIdentity {
            digest: embedded_artifact_digest(),
            programs,
        },
    })
}

fn require_exact_loaded_names(ebpf: &Ebpf) -> Result<(), LinuxEgressFenceError> {
    let maps = ebpf.maps().map(|(name, _)| name).collect::<BTreeSet<_>>();
    let programs = ebpf
        .programs()
        .map(|(name, _)| name)
        .collect::<BTreeSet<_>>();
    if maps != OBJECT_MAP_NAMES.into_iter().collect()
        || programs != PROGRAM_NAMES.into_iter().collect()
    {
        return Err(LinuxEgressFenceError::EmbeddedObject);
    }
    Ok(())
}

fn freeze_loaded_maps(ebpf: &Ebpf) -> Result<(), LinuxEgressFenceError> {
    let cookies = AyaHashMap::<
        _,
        [u8; EGRESS_FENCE_COOKIE_KEY_LEN],
        [u8; EGRESS_FENCE_COOKIE_VALUE_LEN],
    >::try_from(
        ebpf.map(EGRESS_FENCE_COOKIE_MAP_NAME)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?,
    )
    .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    freeze_map(cookies.map().fd().as_fd())?;

    let config = Array::<_, [u8; EGRESS_FENCE_CONFIG_VALUE_LEN]>::try_from(
        ebpf.map(EGRESS_FENCE_CONFIG_MAP_NAME)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?,
    )
    .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    freeze_map(config.map().fd().as_fd())?;

    let counters = PerCpuArray::<_, u64>::try_from(
        ebpf.map(EGRESS_FENCE_COUNTER_MAP_NAME)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?,
    )
    .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    freeze_map(counters.map().fd().as_fd())?;

    let current = Array::<_, [u8; EGRESS_FENCE_CURRENT_VALUE_LEN]>::try_from(
        ebpf.map(EGRESS_FENCE_CURRENT_MAP_NAME)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?,
    )
    .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    freeze_map(current.map().fd().as_fd())?;

    // Do not freeze OPC_FENCE_LOCK. Linux rejects BPF_MAP_FREEZE for BTF
    // maps whose values contain special fields such as bpf_spin_lock. The
    // manifest and initial-state verifier still bind its exact identity,
    // schema, program references, and canonical zero value.
    let mutation = Array::<_, [u8; 16]>::try_from(
        ebpf.map(EGRESS_FENCE_MUTATION_MAP_NAME)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?,
    )
    .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    freeze_map(mutation.map().fd().as_fd())
}

fn freeze_map(map: BorrowedFd<'_>) -> Result<(), LinuxEgressFenceError> {
    opc_linux_gtpu_sys::freeze_bpf_map(map).map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    opc_linux_gtpu_sys::verify_bpf_map_frozen(map)
        .map_err(|_| LinuxEgressFenceError::EmbeddedObject)
}

fn load_programs(ebpf: &mut Ebpf) -> Result<(), LinuxEgressFenceError> {
    let gate: &mut CgroupSkb = ebpf
        .program_mut(EGRESS_FENCE_PROGRAM_NAME)
        .ok_or(LinuxEgressFenceError::EmbeddedObject)?
        .try_into()
        .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    gate.load()
        .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    for name in [
        EGRESS_FENCE_CONTROL_PROGRAM_NAME,
        EGRESS_FENCE_INSPECT_PROGRAM_NAME,
    ] {
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?
            .try_into()
            .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
        program
            .load()
            .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    }
    Ok(())
}

fn artifact_programs(
    ebpf: &Ebpf,
) -> Result<[ArtifactProgram; INSTALL_PROGRAM_COUNT], LinuxEgressFenceError> {
    let mut programs = [ArtifactProgram {
        name: "",
        program_type: 0,
        tag: 0,
    }; INSTALL_PROGRAM_COUNT];
    for (index, name) in PROGRAM_NAMES.into_iter().enumerate() {
        let info = ebpf
            .program(name)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?
            .info()
            .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
        if info.id() == 0 || info.tag() == 0 || info.name_as_str() != Some(name) {
            return Err(LinuxEgressFenceError::EmbeddedObject);
        }
        programs[index] = ArtifactProgram {
            name,
            program_type: info.program_type() as u32,
            tag: info.tag(),
        };
    }
    Ok(programs)
}

fn cleanup_staging(
    guard: &FencePinStoreGuard<'_>,
    root: &HostCgroupV2Root,
) -> Result<(), LinuxEgressFenceError> {
    let inventory = guard
        .recovery_inventory()
        .map_err(|_| LinuxEgressFenceError::PinStore)?;
    if !inventory.cleanup_candidates.is_empty() {
        let root_inventory = query_root(root)?;
        if !root_inventory.program_ids().is_empty() || root_inventory.attach_flags() != 0 {
            // An unpublished directory must never be removed while the root
            // carries an attachment: the directory may be the only surviving
            // evidence needed to classify an interrupted installation.
            return Err(LinuxEgressFenceError::Conflict);
        }
    }
    for entry in inventory.cleanup_candidates {
        let generation = guard
            .open_existing(entry)
            .map_err(|_| LinuxEgressFenceError::PinStore)?;
        guard
            .remove_staging(generation)
            .map_err(|_| LinuxEgressFenceError::PinStore)?;
    }
    if !guard
        .recovery_inventory()
        .map_err(|_| LinuxEgressFenceError::PinStore)?
        .cleanup_candidates
        .is_empty()
    {
        return Err(LinuxEgressFenceError::Conflict);
    }
    Ok(())
}

fn install_fresh(
    guard: &FencePinStoreGuard<'_>,
    root: &HostCgroupV2Root,
    ebpf: &mut Ebpf,
    artifact: ArtifactIdentity,
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
) -> Result<
    (
        crate::install_manifest::InstallGenerationId,
        InstallManifest,
        AttachmentInventory,
    ),
    LinuxEgressFenceError,
> {
    let (prepared, manifest) = prepare_fresh_generation(guard, root, ebpf, artifact, config_bytes)?;
    resume_prepared_attach(guard, root, prepared, manifest, artifact, config_bytes)
}

fn prepare_fresh_generation(
    guard: &FencePinStoreGuard<'_>,
    root: &HostCgroupV2Root,
    ebpf: &mut Ebpf,
    artifact: ArtifactIdentity,
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
) -> Result<(GenerationDirectory, InstallManifest), LinuxEgressFenceError> {
    let before = query_root(root)?;
    let gate_info = ebpf
        .program(EGRESS_FENCE_PROGRAM_NAME)
        .ok_or(LinuxEgressFenceError::EmbeddedObject)?
        .info()
        .map_err(|_| LinuxEgressFenceError::EmbeddedObject)?;
    let plan = before
        .plan_closed_direct_attach(gate_info.id())
        .map_err(|_| LinuxEgressFenceError::Conflict)?;
    if !before.exact_match(&query_root(root)?) {
        return Err(LinuxEgressFenceError::Conflict);
    }
    let staging = guard
        .create_staging()
        .map_err(|_| LinuxEgressFenceError::PinStore)?;
    pin_loaded_object(ebpf, &staging)?;
    let programs = manifest_programs(&staging)?;
    let mut maps = [empty_manifest_map()?; INSTALL_MAP_COUNT];
    maps[..OBJECT_MAP_COUNT].copy_from_slice(&manifest_object_maps(&staging)?);

    let mut manifest_map = create_manifest_map()?;
    maps[OBJECT_MAP_COUNT] = manifest_map_identity(&manifest_map)?;
    let manifest = InstallManifest::new(
        staging.generation_id(),
        artifact.digest,
        config_digest(config_bytes),
        &before,
        plan.expected_post_revision(),
        programs,
        maps,
    )
    .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let manifest_bytes = manifest
        .encode()
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    manifest_map
        .set(0, manifest_bytes, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    if manifest_map
        .get(&0, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?
        != manifest_bytes
    {
        return Err(LinuxEgressFenceError::KernelObject);
    }
    opc_linux_gtpu_sys::freeze_bpf_map(manifest_map.map().fd().as_fd())
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    opc_linux_gtpu_sys::verify_bpf_map_frozen(manifest_map.map().fd().as_fd())
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    manifest_map
        .map()
        .pin(
            staging
                .object_path(MANIFEST_MAP_NAME)
                .map_err(|_| LinuxEgressFenceError::PinStore)?,
        )
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;

    let verified = verify_generation_static(&staging, artifact, config_bytes)?;
    if verified != manifest {
        return Err(LinuxEgressFenceError::KernelObject);
    }
    verify_initial_closed_state(&staging, config_bytes)?;
    let prepared = staging
        .publish_prepared(guard)
        .map_err(|_| LinuxEgressFenceError::PinStore)?;
    Ok((prepared, manifest))
}

fn recover_prepared(
    guard: &FencePinStoreGuard<'_>,
    root: &HostCgroupV2Root,
    entry: GenerationInventoryEntry,
    artifact: ArtifactIdentity,
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
) -> Result<
    (
        crate::install_manifest::InstallGenerationId,
        InstallManifest,
        AttachmentInventory,
    ),
    LinuxEgressFenceError,
> {
    if entry.phase != GenerationPhase::Prepared {
        return Err(LinuxEgressFenceError::Conflict);
    }
    let prepared = guard
        .open_existing(entry)
        .map_err(|_| LinuxEgressFenceError::PinStore)?;
    let manifest = verify_generation_static(&prepared, artifact, config_bytes)?;
    verify_initial_closed_state(&prepared, config_bytes)?;
    resume_prepared_attach(guard, root, prepared, manifest, artifact, config_bytes)
}

fn resume_prepared_attach(
    guard: &FencePinStoreGuard<'_>,
    root: &HostCgroupV2Root,
    prepared: GenerationDirectory,
    manifest: InstallManifest,
    artifact: ArtifactIdentity,
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
) -> Result<
    (
        crate::install_manifest::InstallGenerationId,
        InstallManifest,
        AttachmentInventory,
    ),
    LinuxEgressFenceError,
> {
    let observed = query_root(root)?;
    if manifest.validates_root_pre_attach(&observed) {
        let plan = observed
            .plan_closed_direct_attach(manifest.programs[0].id)
            .map_err(|_| LinuxEgressFenceError::Conflict)?;
        if plan.expected_pre_revision() != manifest.pre_revision
            || plan.expected_post_revision() != manifest.post_revision
        {
            return Err(LinuxEgressFenceError::Conflict);
        }
        verify_initial_closed_state(&prepared, config_bytes)?;
        let gate = ProgramInfo::from_pin(
            prepared
                .object_path(EGRESS_FENCE_PROGRAM_NAME)
                .map_err(|_| LinuxEgressFenceError::PinStore)?,
        )
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
        let gate_fd = gate.fd().map_err(|_| LinuxEgressFenceError::KernelObject)?;
        opc_linux_gtpu_sys::attach_cgroup_skb_egress(
            root.as_fd(),
            gate_fd.as_fd(),
            manifest.pre_revision,
        )
        .map_err(|_| LinuxEgressFenceError::Attachment)?;
        let after = query_root(root)?;
        if plan.validate_post(&after).is_err() || !manifest.validates_root_adoption(&after) {
            return Err(LinuxEgressFenceError::Attachment);
        }
    } else if !manifest.validates_root_adoption(&observed) {
        return Err(LinuxEgressFenceError::Conflict);
    }
    verify_initial_closed_state(&prepared, config_bytes)?;
    let verified = verify_generation_static(&prepared, artifact, config_bytes)?;
    if verified != manifest {
        return Err(LinuxEgressFenceError::KernelObject);
    }
    let generation_id = prepared.generation_id();
    let committed = prepared
        .publish_committed(guard)
        .map_err(|_| LinuxEgressFenceError::PinStore)?;
    if committed.phase() != GenerationPhase::Committed
        || verify_generation_static(&committed, artifact, config_bytes)? != manifest
        || !manifest.validates_root_adoption(&query_root(root)?)
    {
        return Err(LinuxEgressFenceError::Integrity);
    }
    Ok((
        generation_id,
        manifest,
        AttachmentInventory::InstalledClosedWithExactReadback,
    ))
}

fn pin_loaded_object(
    ebpf: &mut Ebpf,
    staging: &GenerationDirectory,
) -> Result<(), LinuxEgressFenceError> {
    for name in OBJECT_MAP_NAMES {
        ebpf.map(name)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?
            .pin(
                staging
                    .object_path(name)
                    .map_err(|_| LinuxEgressFenceError::PinStore)?,
            )
            .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    }
    for name in PROGRAM_NAMES {
        ebpf.program_mut(name)
            .ok_or(LinuxEgressFenceError::EmbeddedObject)?
            .pin(
                staging
                    .object_path(name)
                    .map_err(|_| LinuxEgressFenceError::PinStore)?,
            )
            .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    }
    Ok(())
}

fn create_manifest_map(
) -> Result<Array<MapData, [u8; INSTALL_MANIFEST_BYTES]>, LinuxEgressFenceError> {
    let definition = aya_obj::Map::new_from_params(
        BPF_MAP_TYPE_ARRAY,
        MANIFEST_MAP_KEY_SIZE,
        INSTALL_MANIFEST_BYTES as u32,
        1,
        0,
    );
    let data = MapData::create(definition, MANIFEST_MAP_NAME, None)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let map = Map::from_map_data(data).map_err(|_| LinuxEgressFenceError::KernelObject)?;
    Array::try_from(map).map_err(|_| LinuxEgressFenceError::KernelObject)
}

fn manifest_map_identity(
    manifest: &Array<MapData, [u8; INSTALL_MANIFEST_BYTES]>,
) -> Result<ManifestMap, LinuxEgressFenceError> {
    map_info_to_manifest(
        MANIFEST_MAP_NAME,
        &manifest
            .map()
            .info()
            .map_err(|_| LinuxEgressFenceError::KernelObject)?,
    )
}

fn manifest_programs(
    generation: &GenerationDirectory,
) -> Result<[ManifestProgram; INSTALL_PROGRAM_COUNT], LinuxEgressFenceError> {
    let mut programs = [empty_manifest_program()?; INSTALL_PROGRAM_COUNT];
    for (index, name) in PROGRAM_NAMES.into_iter().enumerate() {
        let info = ProgramInfo::from_pin(
            generation
                .object_path(name)
                .map_err(|_| LinuxEgressFenceError::PinStore)?,
        )
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
        programs[index] = program_info_to_manifest(name, &info)?;
    }
    Ok(programs)
}

fn manifest_object_maps(
    generation: &GenerationDirectory,
) -> Result<[ManifestMap; OBJECT_MAP_COUNT], LinuxEgressFenceError> {
    let mut maps = [empty_manifest_map()?; OBJECT_MAP_COUNT];
    for (index, name) in OBJECT_MAP_NAMES.into_iter().enumerate() {
        let info = MapInfo::from_pin(
            generation
                .object_path(name)
                .map_err(|_| LinuxEgressFenceError::PinStore)?,
        )
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
        maps[index] = map_info_to_manifest(name, &info)?;
    }
    Ok(maps)
}

fn manifest_all_maps(
    generation: &GenerationDirectory,
) -> Result<[ManifestMap; INSTALL_MAP_COUNT], LinuxEgressFenceError> {
    let mut maps = [empty_manifest_map()?; INSTALL_MAP_COUNT];
    for (index, name) in ALL_MAP_NAMES.into_iter().enumerate() {
        let info = MapInfo::from_pin(
            generation
                .object_path(name)
                .map_err(|_| LinuxEgressFenceError::PinStore)?,
        )
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
        maps[index] = map_info_to_manifest(name, &info)?;
    }
    Ok(maps)
}

fn program_info_to_manifest(
    expected_name: &str,
    info: &ProgramInfo,
) -> Result<ManifestProgram, LinuxEgressFenceError> {
    let map_ids = info
        .map_ids()
        .map_err(|_| LinuxEgressFenceError::KernelObject)?
        .ok_or(LinuxEgressFenceError::KernelObject)?;
    if info.id() == 0
        || info.tag() == 0
        || info.name_as_str() != Some(expected_name)
        || map_ids.len() > MAX_PROGRAM_MAPS
    {
        return Err(LinuxEgressFenceError::KernelObject);
    }
    let mut encoded_map_ids = [0_u32; MAX_PROGRAM_MAPS];
    encoded_map_ids[..map_ids.len()].copy_from_slice(&map_ids);
    Ok(ManifestProgram {
        name: KernelObjectName::new(expected_name)
            .map_err(|_| LinuxEgressFenceError::KernelObject)?,
        id: info.id(),
        program_type: info.program_type() as u32,
        tag: info.tag(),
        map_ids: encoded_map_ids,
        map_count: u32::try_from(map_ids.len()).map_err(|_| LinuxEgressFenceError::KernelObject)?,
    })
}

fn map_info_to_manifest(
    expected_name: &str,
    info: &MapInfo,
) -> Result<ManifestMap, LinuxEgressFenceError> {
    if info.id() == 0 || info.name_as_str() != Some(expected_name) {
        return Err(LinuxEgressFenceError::KernelObject);
    }
    Ok(ManifestMap {
        name: KernelObjectName::new(expected_name)
            .map_err(|_| LinuxEgressFenceError::KernelObject)?,
        id: info.id(),
        map_type: info
            .map_type()
            .map_err(|_| LinuxEgressFenceError::KernelObject)? as u32,
        key_size: info.key_size(),
        value_size: info.value_size(),
        max_entries: info.max_entries(),
        map_flags: info.map_flags(),
        freeze_policy: MapFreezePolicy::for_map_name(expected_name)
            .map_err(|_| LinuxEgressFenceError::KernelObject)?,
    })
}

fn empty_manifest_program() -> Result<ManifestProgram, LinuxEgressFenceError> {
    Ok(ManifestProgram {
        name: KernelObjectName::new("empty").map_err(|_| LinuxEgressFenceError::KernelObject)?,
        id: 0,
        program_type: 0,
        tag: 0,
        map_ids: [0; MAX_PROGRAM_MAPS],
        map_count: 0,
    })
}

fn empty_manifest_map() -> Result<ManifestMap, LinuxEgressFenceError> {
    Ok(ManifestMap {
        name: KernelObjectName::new("empty").map_err(|_| LinuxEgressFenceError::KernelObject)?,
        id: 0,
        map_type: 0,
        key_size: 0,
        value_size: 0,
        max_entries: 0,
        map_flags: 0,
        freeze_policy: MapFreezePolicy::KernelUnsupportedSpecialField,
    })
}

fn verify_generation_static(
    generation: &GenerationDirectory,
    artifact: ArtifactIdentity,
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
) -> Result<InstallManifest, LinuxEgressFenceError> {
    generation
        .verify_exact_object_set()
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let manifest = read_manifest(generation)?;
    if manifest.generation_id != generation.generation_id()
        || manifest.artifact_digest != artifact.digest
        || manifest.config_digest != config_digest(config_bytes)
        || manifest_programs(generation)? != manifest.programs
        || manifest_all_maps(generation)? != manifest.maps
    {
        return Err(LinuxEgressFenceError::Conflict);
    }
    for (expected, actual) in artifact.programs.iter().zip(manifest.programs) {
        if expected.name != actual.name.as_str()
            || expected.program_type != actual.program_type
            || expected.tag != actual.tag
        {
            return Err(LinuxEgressFenceError::Conflict);
        }
    }
    for map in manifest
        .maps
        .iter()
        .filter(|map| map.freeze_policy.requires_userspace_freeze())
    {
        let data = pinned_map_data(generation, map.name.as_str())?;
        opc_linux_gtpu_sys::verify_bpf_map_frozen(data.fd().as_fd())
            .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    }
    let observed_config = pinned_array::<[u8; EGRESS_FENCE_CONFIG_VALUE_LEN]>(
        generation,
        EGRESS_FENCE_CONFIG_MAP_NAME,
    )?
    .get(&0, 0)
    .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    if observed_config != config_bytes
        || FenceConfig::decode(&observed_config) != FenceConfig::decode(&config_bytes)
    {
        return Err(LinuxEgressFenceError::Conflict);
    }
    if manifest
        .encode()
        .map_err(|_| LinuxEgressFenceError::KernelObject)?
        != read_manifest_bytes(generation)?
    {
        return Err(LinuxEgressFenceError::KernelObject);
    }
    Ok(manifest)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommittedDynamicState {
    NeverActivated,
    CanonicalNonInitial,
}

fn verify_initial_closed_state(
    generation: &GenerationDirectory,
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
) -> Result<(), LinuxEgressFenceError> {
    if classify_committed_dynamic_state(generation, config_bytes)?
        != CommittedDynamicState::NeverActivated
    {
        return Err(LinuxEgressFenceError::Conflict);
    }
    Ok(())
}

fn classify_committed_dynamic_state(
    generation: &GenerationDirectory,
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
) -> Result<CommittedDynamicState, LinuxEgressFenceError> {
    let mutation_map = pinned_array::<[u8; 16]>(generation, EGRESS_FENCE_MUTATION_MAP_NAME)?;
    let mutation_before = mutation_map
        .get(&0, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let mutation_before =
        FenceMutationAuthority::decode(&mutation_before).ok_or(LinuxEgressFenceError::Conflict)?;

    let lock_map = pinned_array::<u32>(generation, EGRESS_FENCE_LOCK_MAP_NAME)?;
    let lock_before = lock_map
        .get(&0, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;

    let current_map = pinned_array::<[u8; EGRESS_FENCE_CURRENT_VALUE_LEN]>(
        generation,
        EGRESS_FENCE_CURRENT_MAP_NAME,
    )?;
    let current_before = current_map
        .get(&0, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let current =
        CurrentFenceToken::decode(&current_before).ok_or(LinuxEgressFenceError::Conflict)?;

    let cookies = pinned_hash_map(generation, EGRESS_FENCE_COOKIE_MAP_NAME)?;
    let mut cookie_count = 0_usize;
    let mut seen_lifecycle_tokens = BTreeSet::new();
    let mut current_entry_seen = false;
    for item in cookies.iter() {
        cookie_count = cookie_count
            .checked_add(1)
            .ok_or(LinuxEgressFenceError::Conflict)?;
        if cookie_count > EGRESS_FENCE_MAX_COOKIE_ENTRIES as usize {
            return Err(LinuxEgressFenceError::Conflict);
        }
        let (encoded_key, encoded_value) = item.map_err(|_| LinuxEgressFenceError::KernelObject)?;
        let key = FenceCookieKey::decode(&encoded_key).ok_or(LinuxEgressFenceError::Conflict)?;
        let value =
            FenceCookieValue::decode(&encoded_value).ok_or(LinuxEgressFenceError::Conflict)?;
        if value.key() != key || key.durable_fence_token() > current.durable_fence_token() {
            return Err(LinuxEgressFenceError::Conflict);
        }
        record_cookie_lifecycle_token(&mut seen_lifecycle_tokens, key.durable_fence_token())?;
        if key.durable_fence_token() == current.durable_fence_token() {
            if !current.is_lifecycle_open()
                || current.registered_socket_cookie() != key.socket_cookie()
                || value.entry().state() == FenceEntryState::Reclaiming
                || current_entry_seen
            {
                return Err(LinuxEgressFenceError::Conflict);
            }
            current_entry_seen = true;
        }
    }
    if current.registered_socket_cookie() != 0 && !current_entry_seen {
        return Err(LinuxEgressFenceError::Conflict);
    }

    let current_after = current_map
        .get(&0, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let mutation_after = mutation_map
        .get(&0, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let lock_after = lock_map
        .get(&0, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    if current_after != current_before
        || FenceMutationAuthority::decode(&mutation_after) != Some(mutation_before)
        || lock_after != lock_before
    {
        return Err(LinuxEgressFenceError::Conflict);
    }

    let config = pinned_array::<[u8; EGRESS_FENCE_CONFIG_VALUE_LEN]>(
        generation,
        EGRESS_FENCE_CONFIG_MAP_NAME,
    )?
    .get(&0, 0)
    .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    if config != config_bytes {
        return Err(LinuxEgressFenceError::Conflict);
    }
    let manifest = read_manifest(generation)?;
    for expected in manifest
        .maps
        .iter()
        .filter(|map| map.freeze_policy.requires_userspace_freeze())
    {
        let map = pinned_map_data(generation, expected.name.as_str())?;
        opc_linux_gtpu_sys::verify_bpf_map_frozen(map.fd().as_fd())
            .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    }

    classify_committed_snapshot(current, mutation_before, cookie_count, lock_before)
}

fn classify_committed_snapshot(
    current: CurrentFenceToken,
    mutation: FenceMutationAuthority,
    cookie_count: usize,
    lock_value: u32,
) -> Result<CommittedDynamicState, LinuxEgressFenceError> {
    if mutation.in_flight_claim() != 0 || mutation.generation() == u64::MAX || lock_value != 0 {
        return Err(LinuxEgressFenceError::Conflict);
    }
    let cookie_count = u64::try_from(cookie_count).map_err(|_| LinuxEgressFenceError::Conflict)?;
    if cookie_count > mutation.generation() {
        return Err(LinuxEgressFenceError::Conflict);
    }
    if current == CurrentFenceToken::initial() {
        return if cookie_count == 0 && mutation == FenceMutationAuthority::initial() {
            Ok(CommittedDynamicState::NeverActivated)
        } else {
            Err(LinuxEgressFenceError::Conflict)
        };
    }
    // Publishing the first lifecycle token does not reserve a structural
    // mutation generation. Publishing its consecutive retirement token before
    // registration is likewise canonical. Both states therefore have a
    // noninitial unregistered CURRENT with an empty cookie map and generation
    // zero; exact durable LastAttachment evidence can recover either one.
    if mutation.generation() == 0 && (cookie_count != 0 || current.registered_socket_cookie() != 0)
    {
        Err(LinuxEgressFenceError::Conflict)
    } else {
        Ok(CommittedDynamicState::CanonicalNonInitial)
    }
}

fn record_cookie_lifecycle_token(
    seen: &mut BTreeSet<u64>,
    lifecycle_token: u64,
) -> Result<(), LinuxEgressFenceError> {
    if lifecycle_token == 0 || !seen.insert(lifecycle_token) {
        Err(LinuxEgressFenceError::Conflict)
    } else {
        Ok(())
    }
}

fn read_manifest(
    generation: &GenerationDirectory,
) -> Result<InstallManifest, LinuxEgressFenceError> {
    InstallManifest::decode(&read_manifest_bytes(generation)?)
        .map_err(|_| LinuxEgressFenceError::Conflict)
}

fn read_manifest_bytes(
    generation: &GenerationDirectory,
) -> Result<[u8; INSTALL_MANIFEST_BYTES], LinuxEgressFenceError> {
    pinned_array::<[u8; INSTALL_MANIFEST_BYTES]>(generation, MANIFEST_MAP_NAME)?
        .get(&0, 0)
        .map_err(|_| LinuxEgressFenceError::KernelObject)
}

fn pinned_map_data(
    generation: &GenerationDirectory,
    name: &str,
) -> Result<MapData, LinuxEgressFenceError> {
    MapData::from_pin(
        generation
            .object_path(name)
            .map_err(|_| LinuxEgressFenceError::PinStore)?,
    )
    .map_err(|_| LinuxEgressFenceError::KernelObject)
}

fn pinned_array<V: aya::Pod>(
    generation: &GenerationDirectory,
    name: &str,
) -> Result<Array<MapData, V>, LinuxEgressFenceError> {
    let map = Map::from_map_data(pinned_map_data(generation, name)?)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    Array::try_from(map).map_err(|_| LinuxEgressFenceError::KernelObject)
}

fn pinned_hash_map(
    generation: &GenerationDirectory,
    name: &str,
) -> Result<
    AyaHashMap<MapData, [u8; EGRESS_FENCE_COOKIE_KEY_LEN], [u8; EGRESS_FENCE_COOKIE_VALUE_LEN]>,
    LinuxEgressFenceError,
> {
    let map = Map::from_map_data(pinned_map_data(generation, name)?)
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    AyaHashMap::try_from(map).map_err(|_| LinuxEgressFenceError::KernelObject)
}

fn query_root(root: &HostCgroupV2Root) -> Result<RootInventory, LinuxEgressFenceError> {
    let query = opc_linux_gtpu_sys::query_cgroup_skb_egress(root.as_fd())
        .map_err(|_| LinuxEgressFenceError::Attachment)?;
    RootInventory::from_query(&query).map_err(|_| LinuxEgressFenceError::Conflict)
}

fn config_digest(config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN]) -> [u8; 32] {
    Sha256::digest(config_bytes).into()
}

fn embedded_artifact_digest() -> [u8; 32] {
    Sha256::digest(EMBEDDED_OBJECT).into()
}

fn attachment_identity(
    manifest: &InstallManifest,
) -> Result<FenceAttachmentIdentity, LinuxEgressFenceError> {
    let encoded = manifest
        .encode()
        .map_err(|_| LinuxEgressFenceError::KernelObject)?;
    let mut digest = Sha256::new();
    digest.update(IDENTITY_DOMAIN);
    digest.update(encoded);
    FenceAttachmentIdentity::from_live_digest(digest.finalize().into())
        .ok_or(LinuxEgressFenceError::KernelObject)
}

fn committed_generation(
    store: &FencePinStore,
    expected_generation: crate::install_manifest::InstallGenerationId,
) -> Result<GenerationDirectory, LinuxEgressFenceError> {
    let guard = store.lock().map_err(|_| LinuxEgressFenceError::PinStore)?;
    let recovery = guard
        .recovery_inventory()
        .map_err(|_| LinuxEgressFenceError::PinStore)?;
    if recovery.prepared.is_some() || !recovery.cleanup_candidates.is_empty() {
        return Err(LinuxEgressFenceError::Conflict);
    }
    let entry = recovery
        .committed
        .filter(|entry| entry.generation_id == expected_generation)
        .ok_or(LinuxEgressFenceError::Conflict)?;
    guard
        .open_existing(entry)
        .map_err(|_| LinuxEgressFenceError::PinStore)
}

struct LiveInstallationIntegrity {
    store: FencePinStore,
    root: Arc<HostCgroupV2Root>,
    generation_id: crate::install_manifest::InstallGenerationId,
    manifest: InstallManifest,
    artifact: ArtifactIdentity,
    config_bytes: [u8; EGRESS_FENCE_CONFIG_VALUE_LEN],
    endpoint: SocketAddr,
    assignment: LocalAssignment,
    attachment: AttachmentIdentity,
}

impl fmt::Debug for LiveInstallationIntegrity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveInstallationIntegrity(<redacted>)")
    }
}

impl LiveInstallationIntegrity {
    fn verify_exact(&self, expected: AttachmentIdentity) -> Result<(), LinuxEgressFenceError> {
        if expected != self.attachment
            || attachment_identity(&self.manifest)? != expected.durable
            || self.artifact.digest != embedded_artifact_digest()
            || config_digest(self.config_bytes) != self.manifest.config_digest
            || exact_local_assignment(self.endpoint)? != self.assignment
        {
            return Err(LinuxEgressFenceError::Integrity);
        }
        self.store
            .verify_visible_identity()
            .map_err(|_| LinuxEgressFenceError::Integrity)?;
        let guard = self
            .store
            .lock()
            .map_err(|_| LinuxEgressFenceError::Integrity)?;
        let recovery = guard
            .recovery_inventory()
            .map_err(|_| LinuxEgressFenceError::Integrity)?;
        if recovery.prepared.is_some() || !recovery.cleanup_candidates.is_empty() {
            return Err(LinuxEgressFenceError::Integrity);
        }
        let entry = recovery
            .committed
            .filter(|entry| entry.generation_id == self.generation_id)
            .ok_or(LinuxEgressFenceError::Integrity)?;
        let generation = guard
            .open_existing(entry)
            .map_err(|_| LinuxEgressFenceError::Integrity)?;
        let observed = verify_generation_static(&generation, self.artifact, self.config_bytes)
            .map_err(|_| LinuxEgressFenceError::Integrity)?;
        if observed != self.manifest
            || !self
                .manifest
                .validates_root_adoption(&query_root(&self.root)?)
        {
            return Err(LinuxEgressFenceError::Integrity);
        }
        Ok(())
    }

    fn superseded(
        &self,
        expected: AttachmentIdentity,
        lifecycle_token: u64,
    ) -> Result<Vec<KernelFenceEntry>, LinuxEgressFenceError> {
        if lifecycle_token == 0 {
            return Err(LinuxEgressFenceError::Integrity);
        }
        self.verify_exact(expected)?;
        let generation = committed_generation(&self.store, self.generation_id)?;
        let cookies = pinned_hash_map(&generation, EGRESS_FENCE_COOKIE_MAP_NAME)?;
        let mut entries = Vec::new();
        let mut seen = 0_usize;
        for item in cookies.iter() {
            seen = seen
                .checked_add(1)
                .ok_or(LinuxEgressFenceError::Integrity)?;
            if seen > EGRESS_FENCE_MAX_COOKIE_ENTRIES as usize {
                return Err(LinuxEgressFenceError::Integrity);
            }
            let (encoded_key, encoded_value) =
                item.map_err(|_| LinuxEgressFenceError::Integrity)?;
            let key =
                FenceCookieKey::decode(&encoded_key).ok_or(LinuxEgressFenceError::Integrity)?;
            let value =
                FenceCookieValue::decode(&encoded_value).ok_or(LinuxEgressFenceError::Integrity)?;
            if value.key() != key {
                return Err(LinuxEgressFenceError::Integrity);
            }
            let entry = value.entry();
            let token = key.durable_fence_token();
            require_strictly_superseded_token(token, lifecycle_token)?;
            entries.push(KernelFenceEntry {
                state: match entry.state() {
                    FenceEntryState::InitialClosed => KernelEntryState::InitialClosed,
                    FenceEntryState::Active => KernelEntryState::Active,
                    FenceEntryState::TerminalClosed => KernelEntryState::TerminalClosed,
                    FenceEntryState::Reclaiming => KernelEntryState::Reclaiming,
                },
                socket_cookie: key.socket_cookie(),
                lifecycle_token: token,
                deadline_boot_ns: entry.deadline_boot_ns(),
                control_epoch: entry.control_epoch(),
            });
        }
        self.verify_exact(expected)?;
        Ok(entries)
    }
}

fn require_strictly_superseded_token(
    observed: u64,
    current: u64,
) -> Result<(), LinuxEgressFenceError> {
    if observed == 0 || current == 0 || observed >= current {
        Err(LinuxEgressFenceError::Integrity)
    } else {
        Ok(())
    }
}

impl InstallationIntegrity for LiveInstallationIntegrity {
    fn verify(&self, expected: AttachmentIdentity) -> Result<(), KernelFailure> {
        self.verify_exact(expected)
            .map_err(|_| KernelFailure::Readback)
    }

    fn superseded_entries(
        &self,
        expected: AttachmentIdentity,
        lifecycle_token: u64,
    ) -> Result<Vec<KernelFenceEntry>, KernelFailure> {
        self.superseded(expected, lifecycle_token)
            .map_err(|_| KernelFailure::Readback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_requires_one_nonzero_match() {
        assert_eq!(
            select_exact_assignment(&[7]).expect("one assignment"),
            LocalAssignment { interface_index: 7 }
        );
        for matches in [vec![], vec![0], vec![1, 2], vec![9, 9]] {
            assert_eq!(
                select_exact_assignment(&matches),
                Err(LinuxEgressFenceError::EndpointOwnership)
            );
        }
    }

    #[test]
    fn ipv4_assignment_rejects_subnet_and_directed_broadcast_sources() {
        let prefix_24 = Ipv4Addr::new(255, 255, 255, 0);
        assert!(ipv4_assignment_is_canonical_unicast(
            Ipv4Addr::new(192, 0, 2, 37),
            prefix_24,
            Some(Ipv4Addr::new(192, 0, 2, 255)),
            true,
        ));
        assert!(!ipv4_assignment_is_canonical_unicast(
            Ipv4Addr::new(192, 0, 2, 0),
            prefix_24,
            Some(Ipv4Addr::new(192, 0, 2, 255)),
            true,
        ));
        assert!(!ipv4_assignment_is_canonical_unicast(
            Ipv4Addr::new(192, 0, 2, 255),
            prefix_24,
            Some(Ipv4Addr::new(192, 0, 2, 255)),
            true,
        ));
        assert!(!ipv4_assignment_is_canonical_unicast(
            Ipv4Addr::new(192, 0, 2, 37),
            prefix_24,
            Some(Ipv4Addr::new(192, 0, 2, 37)),
            true,
        ));
        assert!(!ipv4_assignment_is_canonical_unicast(
            Ipv4Addr::new(192, 0, 2, 37),
            prefix_24,
            None,
            true,
        ));
        assert!(ipv4_assignment_is_canonical_unicast(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(255, 0, 0, 0),
            None,
            false,
        ));
    }

    #[test]
    fn ipv4_assignment_accepts_both_31_and_32_endpoint_forms() {
        for address in [Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(192, 0, 2, 1)] {
            assert!(ipv4_assignment_is_canonical_unicast(
                address,
                Ipv4Addr::new(255, 255, 255, 254),
                Some(address),
                true,
            ));
        }
        assert!(ipv4_assignment_is_canonical_unicast(
            Ipv4Addr::new(192, 0, 2, 255),
            Ipv4Addr::BROADCAST,
            Some(Ipv4Addr::new(192, 0, 2, 255)),
            true,
        ));
    }

    #[test]
    fn ipv4_assignment_rejects_noncontiguous_netmasks() {
        assert!(!ipv4_assignment_is_canonical_unicast(
            Ipv4Addr::new(192, 0, 2, 37),
            Ipv4Addr::new(255, 0, 255, 0),
            Some(Ipv4Addr::new(192, 0, 2, 255)),
            true,
        ));
    }

    #[test]
    fn public_errors_and_debug_are_value_free() {
        for error in [
            LinuxEgressFenceError::InvalidConfiguration,
            LinuxEgressFenceError::EndpointOwnership,
            LinuxEgressFenceError::SocketAdmission,
            LinuxEgressFenceError::HostRoot,
            LinuxEgressFenceError::PinStore,
            LinuxEgressFenceError::EmbeddedObject,
            LinuxEgressFenceError::KernelObject,
            LinuxEgressFenceError::Conflict,
            LinuxEgressFenceError::Attachment,
            LinuxEgressFenceError::Integrity,
            LinuxEgressFenceError::Composition,
        ] {
            assert!(error.to_string().starts_with("egress_fence_linux_"));
            assert!(!format!("{error:?}").contains('/'));
        }
    }

    #[test]
    fn identity_domain_is_nonempty_and_stable() {
        assert_eq!(IDENTITY_DOMAIN, b"opc-egress-fence-attachment-v2");
        assert!(!EMBEDDED_OBJECT.is_empty());
    }

    #[test]
    fn pre_registration_cleanup_accepts_only_strictly_superseded_entries() {
        assert_eq!(require_strictly_superseded_token(8, 9), Ok(()));
        for (observed, current) in [(0, 9), (9, 9), (10, 9), (8, 0)] {
            assert_eq!(
                require_strictly_superseded_token(observed, current),
                Err(LinuxEgressFenceError::Integrity)
            );
        }
    }

    #[test]
    fn never_activated_classification_requires_every_initial_dynamic_field() {
        let initial_current = CurrentFenceToken::initial();
        let initial_mutation = FenceMutationAuthority::initial();
        assert_eq!(
            classify_committed_snapshot(initial_current, initial_mutation, 0, 0),
            Ok(CommittedDynamicState::NeverActivated)
        );

        let completed_mutation =
            FenceMutationAuthority::new(1, 0).expect("canonical completed mutation");
        let in_flight_mutation =
            FenceMutationAuthority::new(1, 2).expect("canonical in-flight mutation");
        let exhausted_mutation =
            FenceMutationAuthority::new(u64::MAX, 0).expect("canonical exhausted mutation");
        for (mutation, cookie_count, lock_value) in [
            (completed_mutation, 0, 0),
            (initial_mutation, 1, 0),
            (initial_mutation, 0, 1),
            (in_flight_mutation, 0, 0),
        ] {
            assert_eq!(
                classify_committed_snapshot(initial_current, mutation, cookie_count, lock_value,),
                Err(LinuxEgressFenceError::Conflict)
            );
        }

        let lifecycle_current =
            CurrentFenceToken::lifecycle_open(3).expect("canonical lifecycle current");
        assert_eq!(
            classify_committed_snapshot(lifecycle_current, initial_mutation, 0, 0),
            Ok(CommittedDynamicState::CanonicalNonInitial)
        );
        assert_eq!(
            classify_committed_snapshot(lifecycle_current, initial_mutation, 1, 0),
            Err(LinuxEgressFenceError::Conflict)
        );
        assert_eq!(
            classify_committed_snapshot(lifecycle_current, completed_mutation, 0, 0),
            Ok(CommittedDynamicState::CanonicalNonInitial)
        );
        assert_eq!(
            classify_committed_snapshot(lifecycle_current, completed_mutation, 1, 0),
            Ok(CommittedDynamicState::CanonicalNonInitial)
        );
        assert_eq!(
            classify_committed_snapshot(lifecycle_current, completed_mutation, 2, 0),
            Err(LinuxEgressFenceError::Conflict)
        );
        assert_eq!(
            classify_committed_snapshot(lifecycle_current, exhausted_mutation, 0, 0),
            Err(LinuxEgressFenceError::Conflict)
        );
        let registered_current =
            CurrentFenceToken::registered(3, 7).expect("canonical registered current");
        assert_eq!(
            classify_committed_snapshot(registered_current, initial_mutation, 1, 0),
            Err(LinuxEgressFenceError::Conflict)
        );
        let retirement_current =
            CurrentFenceToken::retirement_closed(4).expect("canonical retirement current");
        assert_eq!(
            classify_committed_snapshot(retirement_current, initial_mutation, 0, 0),
            Ok(CommittedDynamicState::CanonicalNonInitial)
        );
    }

    #[test]
    fn committed_inventory_rejects_duplicate_cookie_lifecycle_tokens() {
        let mut seen = BTreeSet::new();
        assert_eq!(record_cookie_lifecycle_token(&mut seen, 1), Ok(()));
        assert_eq!(
            record_cookie_lifecycle_token(&mut seen, 1),
            Err(LinuxEgressFenceError::Conflict)
        );
        assert_eq!(record_cookie_lifecycle_token(&mut seen, 3), Ok(()));
        assert_eq!(
            record_cookie_lifecycle_token(&mut seen, 0),
            Err(LinuxEgressFenceError::Conflict)
        );
    }
}

#[cfg(test)]
#[path = "linux_backend_privileged_tests.rs"]
mod privileged_tests;
