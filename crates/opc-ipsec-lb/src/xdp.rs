//! Host-XDP steering backend: keyless classification with owner steering.
//!
//! This backend loads the committed CO-RE XDP object
//! (`bpf/opc-ipsec-lb-xdp.bpf.o`) and maintains its pinned owner map from
//! userspace. The kernel program executes the same branch-bounded keyless
//! classification as [`crate::classifier`] and looks each classified packet up
//! by its canonical destination-scoped ownership key
//! ([`crate::ownership::SessionOwnershipKey`]). The backend only programs
//! packet-header routing identities, owner identities, and ownership
//! generations; no IPsec key material is accepted by the API or written to
//! kernel maps.
//!
//! # Kernel/userspace split
//!
//! - owner = self: `XDP_PASS` to the local stack.
//! - owner = remote: the authenticated steering encapsulation (AES-GCM /
//!   HMAC over the redirect transport) cannot be built in the kernel — the
//!   crypto is a userspace concern and a deliberate non-goal of this layer —
//!   so the program hands the raw packet to the userspace redirector through
//!   an explicit, observable channel: `XDP_REDIRECT` into a dedicated
//!   hand-off interface whose peer the redirector captures on.
//! - map miss, stale ownership generation (entry older than the configured
//!   fence), unclassifiable packets, and internal errors: fail-closed
//!   `XDP_PASS` to the userspace slow path, each with a distinct per-CPU
//!   counter. The program never silently drops a packet.
//!
//! # Kernel feature floor (enforced at load with a typed error)
//!
//! - Load/attach: Linux >= 5.18 with kernel BTF
//!   (`/sys/kernel/btf/vmlinux`), XDP `bpf_link`, bpffs map pinning, per-CPU
//!   arrays, `bpf_redirect`, `bpf_xdp_load_bytes`, plus effective
//!   `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`. The helper is probed and
//!   the loader verifies that attach created a BPF link; legacy netlink
//!   fallback is detached and rejected.
//! - Graceful cross-process handoff uses `bpf_link_update` with
//!   `BPF_F_REPLACE` and the exact expected old program. It initializes and
//!   validates a fresh versioned map namespace before the atomic update, so
//!   packets observe either the old program or the new fail-closed empty-owner
//!   state, never an unattached window.
//!
//! The owner map is a kernel hash map. Each `bpf_map_update_elem` publishes a
//! complete replacement element, so concurrent kernel readers observe either
//! the old or new 16-byte owner/generation value, never a mixed pair. Strict
//! decoding separately rejects structurally invalid values.
//!
//! The ownership fence generation lives in its own single-entry hash map, so
//! replacement similarly publishes an old-or-new `u64`. Attach adopts pinned
//! maps across process restarts but flushes the owner map and rewrites the
//! config before the program is attached; the persisted fence is honored so
//! entries installed by a crashed owner cannot be re-armed.
//!
//! The per-interface directory and its `.control` subdirectory are permanent
//! lifecycle-lock identity. Operators must never remove or rename either
//! while any backend process may still be alive: doing so can create two
//! independently locked inodes. Use SDK detach/recovery to clean documented
//! map/link pins. Manual recovery requires first quiescing every backend
//! process, then removing only those documented pins; the fully quiesced
//! deployment owner may remove the directory afterward. Lease descriptors
//! are close-on-exec, but a raw `fork` child that neither `exec`s nor closes
//! inherited descriptors retains the lease and is unsupported.

use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opc_ipsec_lb_ebpf_common::{
    XdpDatapathConfig, XdpOwnerValue, CONFIG_KEY, CONFIG_VALUE_LEN, COUNTER_ERROR, COUNTER_LOCAL,
    COUNTER_MISS, COUNTER_NATT_KEEPALIVE, COUNTER_PASS_NON_SWU, COUNTER_REDIRECT, COUNTER_SLOTS,
    COUNTER_STALE, COUNTER_UNCLASSIFIABLE, FENCE_KEY, MAP_CONFIG, MAP_COUNTERS, MAP_FENCE,
    MAP_OWNERS, OWNERSHIP_KEY_MAX_ENCODED_BYTES, OWNER_KEY_LEN, OWNER_VALUE_LEN, PROG_SWU_XDP,
    XDP_CONFIG_ABI_VERSION, XDP_MIN_KERNEL_RELEASE,
};

use crate::error::IpsecLbError;
use crate::model::{ShardId, SteeringBackendKind, SteeringProbe};
use crate::ownership::{RoutingDomainTag, SessionOwnershipKey};

/// Default bpffs directory under which per-interface map pins are created.
pub const DEFAULT_BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/opc-ipsec-lb";

/// Runtime behavior for the Host-XDP steering backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct HostXdpEnvironment {
    /// The platform can run the Host-XDP datapath.
    pub platform_supported: bool,
    /// The configured pin root resolves inside a bpffs mount.
    pub configured_bpffs_present: bool,
    /// Kernel BTF is exposed at `/sys/kernel/btf/vmlinux`.
    pub btf_present: bool,
    /// `CAP_NET_ADMIN` is effective.
    pub net_admin_capable: bool,
    /// The effective capability set includes `CAP_SYS_ADMIN`, which this
    /// runtime requires for exact BPF link/program enumeration and ID opens.
    /// `CAP_BPF` alone is not sufficient for this backend.
    pub bpf_capable: bool,
    /// Running kernel release (major, minor), when it can be determined.
    pub kernel_release: Option<(u16, u16)>,
    /// `bpf_xdp_load_bytes` is usable from an XDP program in this environment.
    pub xdp_load_bytes_supported: bool,
    /// The configured attachment interface exists and is administratively up.
    pub target_interface_ready: bool,
    /// The configured redirect hand-off is disabled or names a distinct,
    /// administratively-up interface.
    pub redirect_handoff_ready: bool,
}

/// Kernel-link disposition after a fallible lifecycle mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostXdpLinkDisposition {
    /// The attachment that existed before the operation is unchanged.
    Unchanged,
    /// No live attachment owned by the runtime remains.
    Detached,
    /// The runtime cannot prove whether a live attachment remains.
    Indeterminate,
}

/// Redaction-safe lifecycle failure with exact kernel-link disposition.
#[derive(Debug)]
pub(crate) struct HostXdpRuntimeFailure {
    error: IpsecLbError,
    disposition: HostXdpLinkDisposition,
}

impl HostXdpRuntimeFailure {
    fn new(error: IpsecLbError, disposition: HostXdpLinkDisposition) -> Self {
        Self { error, disposition }
    }
}

#[derive(Debug)]
pub(crate) struct HostXdpRuntimeAdoption {
    fence_generation: u64,
    link_pin_cleanup_error: Option<IpsecLbError>,
    obsolete_cleanup_error: Option<IpsecLbError>,
}

/// Narrow synchronous port to the kernel XDP machinery.
pub(crate) trait HostXdpRuntime: Send + Sync + fmt::Debug {
    /// Acquire the process-shared lifetime lease for one interface namespace.
    ///
    /// The returned guard must keep the lock held until it is dropped. This
    /// serializes ownership, fence, and hook mutation across cooperating
    /// processes. Successful attach/adoption retains the guard until detach
    /// or terminal handoff preparation. The descriptor is close-on-exec. A
    /// raw `fork` child that does not immediately `exec` or close inherited
    /// descriptors retains the lease and is outside the supported process
    /// lifecycle contract.
    fn lifecycle_lock(
        &self,
        pin_root: &Path,
    ) -> Result<Box<dyn HostXdpLifecycleLock>, IpsecLbError>;

    /// Resolve an interface index by name in the current netns.
    fn ifindex_by_name(&self, name: &str) -> Result<u32, IpsecLbError>;

    /// Report whether `ifindex` names an existing interface that is
    /// administratively up in the current netns.
    fn link_is_up(&self, ifindex: u32) -> Result<bool, IpsecLbError>;

    /// Kernel id of the XDP program already attached to `ifindex`, when
    /// any. Used to reject cross-writer attach collisions before any map
    /// state is touched.
    fn attached_prog_id(&self, ifindex: u32) -> Result<Option<u32>, IpsecLbError>;

    /// Exact live XDP attachment mode, when one program is attached.
    fn attached_mode(&self, ifindex: u32) -> Result<Option<HostXdpAttachMode>, IpsecLbError>;

    /// Load the pinned maps, write the datapath config, and attach the XDP
    /// program for `interface`.
    ///
    /// Implementations must flush the owner map when adopting pre-existing
    /// pins and write `config` before the program is attached, so the
    /// datapath never verdicts with a previous process's state.
    fn attach(
        &self,
        interface: &str,
        ifindex: u32,
        pin_dir: &Path,
        mode: HostXdpAttachMode,
        config: [u8; CONFIG_VALUE_LEN],
        lease: Box<dyn HostXdpLifecycleLock>,
    ) -> Result<(), IpsecLbError>;

    /// Quiesce owner mutation, empty and verify the owner map, pin a duplicate
    /// reference to the live link, and release the lifetime lease.
    fn prepare_upgrade_handoff(
        &self,
        ifindex: u32,
        pin_dir: &Path,
    ) -> Result<u64, HostXdpRuntimeFailure>;

    /// Adopt a strictly validated handoff link and atomically update it to the
    /// trusted embedded object with fresh versioned maps.
    fn adopt_upgrade_handoff(
        &self,
        ifindex: u32,
        attached_program_id: u32,
        pin_dir: &Path,
        mode: HostXdpAttachMode,
        config: [u8; CONFIG_VALUE_LEN],
        lease: Box<dyn HostXdpLifecycleLock>,
    ) -> Result<HostXdpRuntimeAdoption, HostXdpRuntimeFailure>;

    /// Retry removal of the temporary handoff-link pin and retire obsolete
    /// map namespaces while the adopted link FD and lifetime lease remain
    /// held.
    fn complete_upgrade_handoff_cleanup(
        &self,
        ifindex: u32,
        pin_dir: &Path,
    ) -> Result<Option<IpsecLbError>, HostXdpRuntimeFailure>;

    /// Detach the XDP program and remove pins owned by this backend.
    fn detach(
        &self,
        interface: &str,
        ifindex: u32,
        pin_dir: &Path,
    ) -> Result<(), HostXdpRuntimeFailure>;

    /// Read an owner-map entry.
    fn owner_get(
        &self,
        ifindex: u32,
        key: [u8; OWNER_KEY_LEN],
    ) -> Result<Option<[u8; OWNER_VALUE_LEN]>, IpsecLbError>;

    /// Insert or replace an owner-map entry atomically.
    fn owner_insert(
        &self,
        ifindex: u32,
        key: [u8; OWNER_KEY_LEN],
        value: [u8; OWNER_VALUE_LEN],
    ) -> Result<(), IpsecLbError>;

    /// Remove an owner-map entry; returns whether it existed.
    fn owner_remove(&self, ifindex: u32, key: [u8; OWNER_KEY_LEN]) -> Result<bool, IpsecLbError>;

    /// Read the persisted ownership fence generation.
    fn fence_read(&self, ifindex: u32) -> Result<u64, IpsecLbError>;

    /// Write the ownership fence generation.
    fn fence_write(&self, ifindex: u32, generation: u64) -> Result<(), IpsecLbError>;

    /// Read the aggregated per-CPU per-verdict counters.
    fn counters_read(&self, ifindex: u32) -> Result<[u64; COUNTER_SLOTS as usize], IpsecLbError>;

    /// Probe the environment for XDP readiness.
    fn probe_environment(
        &self,
        interface: &str,
        pin_root: &Path,
        redirect_handoff: HostXdpRedirectHandoff,
    ) -> HostXdpEnvironment;
}

/// Opaque guard for the process-shared Host-XDP lifecycle lock.
pub(crate) trait HostXdpLifecycleLock: Send + fmt::Debug {}

/// Explicit channel for packets owned by a remote shard.
///
/// The authenticated steering encapsulation cannot be built in the kernel
/// (AEAD crypto is a userspace concern), so the only fast-path channel is an
/// observable hand-off to the userspace redirector.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum HostXdpRedirectHandoff {
    /// Disable the XDP redirect channel. Remote-owner packets fail closed to
    /// the userspace slow path instead of being sent to a fabricated target.
    #[default]
    Disabled,
    /// `XDP_REDIRECT` remote-owned packets into a dedicated interface whose
    /// peer is captured by the userspace redirector, which applies the
    /// authenticated steering encapsulation (`crate::redirect`) and forwards
    /// toward the owner.
    ///
    /// Deployment note: when Aya's default zero-flag request selects driver
    /// mode and the hand-off interface is a veth, the kernel only delivers
    /// redirected frames when the peer runs an XDP consumer; use
    /// [`HostXdpAttachMode::Generic`] for veth hand-off interfaces without a
    /// peer program.
    UserspaceRedirector {
        /// Hand-off interface index in the attached netns.
        ifindex: NonZeroU32,
    },
}

impl HostXdpRedirectHandoff {
    fn ifindex(self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::UserspaceRedirector { ifindex } => ifindex.get(),
        }
    }
}

impl fmt::Debug for HostXdpRedirectHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("Disabled"),
            Self::UserspaceRedirector { .. } => f
                .debug_struct("UserspaceRedirector")
                .field("ifindex", &"<redacted>")
                .finish(),
        }
    }
}

/// XDP attach mode for the datapath program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostXdpAttachMode {
    /// Use Aya's zero-flag/default XDP mode and let the kernel select the
    /// supported attachment mode. This is not a strict
    /// `XDP_FLAGS_DRV_MODE` request. On devices where the kernel selects
    /// driver mode — including veth — redirecting into a veth requires an XDP
    /// consumer on its peer; select [`HostXdpAttachMode::Generic`] when a
    /// veth hand-off peer has no XDP consumer.
    #[default]
    Native,
    /// Generic (SKB) mode, executed by the kernel network stack. Redirect
    /// into a veth hand-off delivers to the peer stack without a peer
    /// program. This is the interoperable choice for veth topologies.
    Generic,
}

fn mode_accepts_live(configured: HostXdpAttachMode, live: Option<HostXdpAttachMode>) -> bool {
    matches!(
        (configured, live),
        (HostXdpAttachMode::Native, Some(HostXdpAttachMode::Native))
            | (HostXdpAttachMode::Native, Some(HostXdpAttachMode::Generic))
            | (HostXdpAttachMode::Generic, Some(HostXdpAttachMode::Generic))
    )
}

/// Host-XDP backend configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct HostXdpSteeringBackendConfig {
    /// bpffs directory under which per-interface pin directories are created.
    pub bpffs_pin_root: PathBuf,
    /// Shard identity of this node; entries owned by it pass locally.
    pub self_shard: ShardId,
    /// Routing-domain tag mixed into every ownership key. Installed owner
    /// records must carry the same tag.
    pub routing_domain: RoutingDomainTag,
    /// Channel for remote-owned packets. The default is [`HostXdpRedirectHandoff::Disabled`];
    /// production redirect requires an explicit interface.
    pub redirect_handoff: HostXdpRedirectHandoff,
    /// XDP attach mode.
    pub attach_mode: HostXdpAttachMode,
}

impl Default for HostXdpSteeringBackendConfig {
    fn default() -> Self {
        Self {
            bpffs_pin_root: PathBuf::from(DEFAULT_BPFFS_PIN_ROOT),
            self_shard: ShardId::new(1),
            routing_domain: RoutingDomainTag::new(0),
            redirect_handoff: HostXdpRedirectHandoff::Disabled,
            attach_mode: HostXdpAttachMode::default(),
        }
    }
}

impl fmt::Debug for HostXdpSteeringBackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostXdpSteeringBackendConfig")
            .field("bpffs_pin_root", &"<redacted>")
            .field("self_shard", &"<redacted>")
            .field("routing_domain", &"<redacted>")
            .field("redirect_handoff", &self.redirect_handoff)
            .field("attach_mode", &self.attach_mode)
            .finish()
    }
}

/// Aggregated per-CPU verdict counters exported by the XDP datapath.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XdpVerdictCounters {
    /// Packets passed untouched because they were not SWu IKE/ESP traffic.
    pub pass_non_swu: u64,
    /// Packets whose fresh owner is this shard (local pass).
    pub local: u64,
    /// Packets handed to the userspace redirector (remote owner).
    pub redirect: u64,
    /// Classified packets with no owner-map entry (slow-path hand-off).
    pub miss: u64,
    /// Packets whose entry is older than the fence (slow-path hand-off).
    pub stale: u64,
    /// SWu-candidate packets the bounded parser could not classify.
    pub unclassifiable: u64,
    /// Internal errors and invalid config/value encodings.
    pub error: u64,
    /// RFC 3948 NAT-T keepalives passed to the stack.
    pub natt_keepalive: u64,
}

/// Result of adopting an explicitly prepared cross-process XDP upgrade
/// handoff.
#[derive(Debug)]
#[non_exhaustive]
pub enum HostXdpUpgradeOutcome {
    /// The new embedded program and its fresh map namespace are active and all
    /// obsolete pins were retired.
    Applied,
    /// The atomic program update was applied and remains live, but retirement
    /// of an obsolete pin failed and requires a later cleanup attempt.
    AppliedCleanupPending {
        /// Redaction-safe cleanup failure. The active program must not be
        /// rolled back or detached in response to this error.
        error: IpsecLbError,
    },
    /// The new program is active with empty owners, but the temporary
    /// handoff-link pin could not be removed. The backend remains quiesced and
    /// rejects owner/fence mutations until
    /// [`HostXdpSteeringBackend::complete_upgrade_handoff_cleanup`] succeeds.
    AppliedHandoffCleanupRequired {
        /// Redaction-safe cleanup failure.
        error: IpsecLbError,
    },
}

impl HostXdpUpgradeOutcome {
    /// Return whether the new program is live but obsolete-pin cleanup is
    /// still pending.
    #[must_use]
    pub const fn cleanup_pending(&self) -> bool {
        matches!(
            self,
            Self::AppliedCleanupPending { .. } | Self::AppliedHandoffCleanupRequired { .. }
        )
    }
}

impl XdpVerdictCounters {
    fn from_slots(slots: &[u64; COUNTER_SLOTS as usize]) -> Self {
        Self {
            pass_non_swu: slots[COUNTER_PASS_NON_SWU as usize],
            local: slots[COUNTER_LOCAL as usize],
            redirect: slots[COUNTER_REDIRECT as usize],
            miss: slots[COUNTER_MISS as usize],
            stale: slots[COUNTER_STALE as usize],
            unclassifiable: slots[COUNTER_UNCLASSIFIABLE as usize],
            error: slots[COUNTER_ERROR as usize],
            natt_keepalive: slots[COUNTER_NATT_KEEPALIVE as usize],
        }
    }

    /// Total number of packets that received any verdict.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.pass_non_swu
            + self.local
            + self.redirect
            + self.miss
            + self.stale
            + self.unclassifiable
            + self.error
            + self.natt_keepalive
    }
}

struct HostXdpSteeringBackendInner {
    interface: String,
    runtime: Arc<dyn HostXdpRuntime>,
    config: HostXdpSteeringBackendConfig,
    operation_gate: Mutex<()>,
    state: Mutex<HostXdpState>,
}

#[derive(Debug, Default)]
struct HostXdpState {
    attachment: HostXdpAttachmentState,
    current_fence: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum HostXdpAttachmentState {
    #[default]
    Detached,
    AwaitingFence {
        ifindex: u32,
        mode: HostXdpAttachMode,
    },
    Ready {
        ifindex: u32,
        mode: HostXdpAttachMode,
    },
    HandoffPrepared {
        ifindex: u32,
        mode: HostXdpAttachMode,
    },
    UpgradeCleanupPending {
        ifindex: u32,
        mode: HostXdpAttachMode,
    },
    Indeterminate {
        ifindex: u32,
        mode: HostXdpAttachMode,
    },
}

fn apply_link_disposition(
    state: &mut HostXdpState,
    disposition: HostXdpLinkDisposition,
    ifindex: u32,
    mode: HostXdpAttachMode,
) {
    state.attachment = match disposition {
        HostXdpLinkDisposition::Detached => HostXdpAttachmentState::Detached,
        HostXdpLinkDisposition::Unchanged => state.attachment,
        HostXdpLinkDisposition::Indeterminate => {
            HostXdpAttachmentState::Indeterminate { ifindex, mode }
        }
    };
}

/// Steering backend that programs destination-scoped owner records into the
/// Host-XDP datapath.
#[derive(Clone)]
pub struct HostXdpSteeringBackend {
    inner: Arc<HostXdpSteeringBackendInner>,
}

impl fmt::Debug for HostXdpSteeringBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostXdpSteeringBackend")
            .field("interface", &"<redacted>")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl HostXdpSteeringBackend {
    /// Create a Linux Host-XDP backend with the committed CO-RE object.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn new(interface: impl Into<String>, config: HostXdpSteeringBackendConfig) -> Self {
        Self::from_runtime_and_config(
            interface,
            Arc::new(aya_runtime::AyaHostXdpRuntime::new()),
            config,
        )
    }

    /// Create a fail-closed Host-XDP backend placeholder.
    ///
    /// This is useful for composition roots that want a concrete backend value
    /// before kernel support is enabled; probes report unsupported and all
    /// mutating operations fail closed.
    #[must_use]
    pub fn unsupported(interface: impl Into<String>, config: HostXdpSteeringBackendConfig) -> Self {
        Self::from_runtime_and_config(interface, Arc::new(UnsupportedHostXdpRuntime), config)
    }

    fn from_runtime_and_config(
        interface: impl Into<String>,
        runtime: Arc<dyn HostXdpRuntime>,
        config: HostXdpSteeringBackendConfig,
    ) -> Self {
        Self {
            inner: Arc::new(HostXdpSteeringBackendInner {
                interface: interface.into(),
                runtime,
                config,
                operation_gate: Mutex::new(()),
                state: Mutex::new(HostXdpState::default()),
            }),
        }
    }

    /// Create a backend from an explicit runtime. This is primarily used by
    /// tests and by downstream integration adapters.
    #[cfg(test)]
    pub(crate) fn with_runtime_and_config(
        interface: impl Into<String>,
        runtime: Arc<dyn HostXdpRuntime>,
        config: HostXdpSteeringBackendConfig,
    ) -> Self {
        Self::from_runtime_and_config(interface, runtime, config)
    }

    /// Attach the XDP datapath to the configured interface, enforcing the
    /// documented kernel feature floor with a typed error.
    pub async fn attach(&self) -> Result<(), IpsecLbError> {
        self.run_blocking("host_xdp_attach", |backend| {
            backend.ensure_attached_sync().map(|_| ())
        })
        .await
    }

    /// Detach this backend's XDP state from the configured interface.
    pub async fn detach(&self) -> Result<(), IpsecLbError> {
        self.run_blocking("host_xdp_detach", |backend| backend.detach_sync())
            .await
    }

    /// Prepare a terminal, fail-closed handoff to a newer SDK process.
    ///
    /// The backend stops accepting ownership mutations, drains the serialized
    /// mutation boundary, empties and verifies the owner map so every SWu
    /// packet takes the userspace slow path, pins a duplicate reference to the
    /// live XDP link, and releases its per-interface lifetime lease. The old
    /// process must keep its userspace slow path available until the new
    /// process reports readiness. This backend cannot be resumed after a
    /// successful call.
    pub async fn prepare_upgrade_handoff(&self) -> Result<(), IpsecLbError> {
        self.run_blocking("host_xdp_prepare_upgrade_handoff", |backend| {
            backend.prepare_upgrade_handoff_sync()
        })
        .await
    }

    /// Adopt a handoff prepared by an older SDK process and atomically update
    /// it to this binary's trusted embedded program.
    ///
    /// The handoff link, attached program, interface, and datapath identity are
    /// validated before mutation. A fresh bounded map namespace is initialized
    /// with the non-regressing migrated fence and no owners before
    /// `BPF_LINK_UPDATE`; packets therefore observe either the old verdict or a
    /// fail-closed map-miss slow-path verdict. A foreign occupied hook is never
    /// adopted.
    pub async fn adopt_upgrade_handoff(&self) -> Result<HostXdpUpgradeOutcome, IpsecLbError> {
        self.run_blocking("host_xdp_adopt_upgrade_handoff", |backend| {
            backend.adopt_upgrade_handoff_sync()
        })
        .await
    }

    /// Complete cleanup after
    /// [`HostXdpUpgradeOutcome::AppliedHandoffCleanupRequired`].
    ///
    /// Owner and fence mutations remain disabled until this succeeds. The
    /// runtime retains both the live link descriptor and the per-interface
    /// lifetime lease while retrying removal of the temporary handoff pin, so
    /// a retry cannot create an unowned attachment window.
    pub async fn complete_upgrade_handoff_cleanup(
        &self,
    ) -> Result<HostXdpUpgradeOutcome, IpsecLbError> {
        self.run_blocking("host_xdp_complete_upgrade_handoff_cleanup", |backend| {
            backend.complete_upgrade_handoff_cleanup_sync()
        })
        .await
    }

    /// Install or replace the owner record for one ownership key.
    ///
    /// The update is atomic per key: a packet in flight sees either the
    /// previous or the new owner/generation pair, never a torn mix. A zero
    /// generation or a routing domain different from the backend's fails
    /// validation.
    pub async fn install_owner(
        &self,
        key: &SessionOwnershipKey,
        owner: ShardId,
        generation: u64,
    ) -> Result<(), IpsecLbError> {
        let key = *key;
        self.run_blocking("host_xdp_install_owner", move |backend| {
            backend.install_owner_sync(&key, owner, generation)
        })
        .await
    }

    /// Remove the owner record for one ownership key.
    pub async fn remove_owner(&self, key: &SessionOwnershipKey) -> Result<(), IpsecLbError> {
        let key = *key;
        self.run_blocking("host_xdp_remove_owner", move |backend| {
            backend.remove_owner_sync(&key)
        })
        .await
    }

    /// Read back the owner record installed for one ownership key.
    ///
    /// The returned pair is the decoded owner shard and ownership generation,
    /// or `None` when no entry exists. A value that fails strict decoding is
    /// reported as an error, never silently ignored.
    pub async fn owner_record(
        &self,
        key: &SessionOwnershipKey,
    ) -> Result<Option<(ShardId, u64)>, IpsecLbError> {
        let key = *key;
        self.run_blocking("host_xdp_owner_record", move |backend| {
            backend.owner_record_sync(&key)
        })
        .await
    }

    /// Advance the ownership fence generation.
    ///
    /// Entries older than the fence are stale and handed to the slow path.
    /// The fence is strictly monotonic; a regression is rejected as an
    /// ownership conflict.
    pub async fn advance_fence(&self, generation: u64) -> Result<(), IpsecLbError> {
        self.run_blocking("host_xdp_advance_fence", move |backend| {
            backend.advance_fence_sync(generation)
        })
        .await
    }

    /// Snapshot the aggregated per-CPU verdict counters.
    pub async fn counters(&self) -> Result<XdpVerdictCounters, IpsecLbError> {
        self.run_blocking("host_xdp_counters", |backend| backend.counters_sync())
            .await
    }

    /// Probe the platform and kernel for Host-XDP readiness.
    pub async fn probe(&self) -> Result<SteeringProbe, IpsecLbError> {
        self.run_blocking("host_xdp_probe", |backend| Ok(backend.probe_sync()))
            .await
    }

    async fn run_blocking<T, F>(&self, operation: &'static str, f: F) -> Result<T, IpsecLbError>
    where
        T: Send + 'static,
        F: FnOnce(Self) -> Result<T, IpsecLbError> + Send + 'static,
    {
        let backend = self.clone();
        tokio::task::spawn_blocking(move || f(backend))
            .await
            .map_err(|_| {
                IpsecLbError::io(
                    operation,
                    io::Error::new(io::ErrorKind::Interrupted, "host XDP blocking task failed"),
                )
            })?
    }

    fn pin_dir(&self) -> PathBuf {
        self.inner.config.bpffs_pin_root.join(&self.inner.interface)
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, HostXdpState>, IpsecLbError> {
        self.inner
            .state
            .lock()
            .map_err(|_| IpsecLbError::io("host_xdp_state", poisoned_lock()))
    }

    fn operation_gate(&self) -> Result<std::sync::MutexGuard<'_, ()>, IpsecLbError> {
        self.inner
            .operation_gate
            .lock()
            .map_err(|_| IpsecLbError::io("host_xdp_operation_gate", poisoned_lock()))
    }

    fn datapath_config(&self) -> [u8; CONFIG_VALUE_LEN] {
        XdpDatapathConfig {
            self_shard: self.inner.config.self_shard.get(),
            routing_domain: self.inner.config.routing_domain.get(),
            handoff_ifindex: self.inner.config.redirect_handoff.ifindex(),
        }
        .encode()
    }

    fn validate_handoff_ifindex(&self, attach_ifindex: u32) -> Result<(), IpsecLbError> {
        let handoff = self.inner.config.redirect_handoff.ifindex();
        if handoff == 0 {
            return Ok(());
        }
        if handoff == attach_ifindex {
            return Err(IpsecLbError::invalid_config(
                "redirect_handoff.ifindex",
                "hand-off interface must differ from the attached interface",
            ));
        }
        if !self.inner.runtime.link_is_up(handoff)? {
            return Err(IpsecLbError::invalid_config(
                "redirect_handoff.ifindex",
                "hand-off interface does not exist or is not up",
            ));
        }
        Ok(())
    }

    fn ensure_attached_sync(&self) -> Result<u32, IpsecLbError> {
        let _operation = self.operation_gate()?;
        self.ensure_attached_under_gate()
    }

    fn ensure_attached_under_gate(&self) -> Result<u32, IpsecLbError> {
        validate_interface_name(&self.inner.interface)?;
        {
            let mut state = self.state()?;
            match state.attachment {
                HostXdpAttachmentState::Ready { ifindex, .. } => return Ok(ifindex),
                HostXdpAttachmentState::AwaitingFence { ifindex, mode } => {
                    let persisted_fence = self.inner.runtime.fence_read(ifindex)?;
                    if persisted_fence > state.current_fence {
                        state.current_fence = persisted_fence;
                    }
                    state.attachment = HostXdpAttachmentState::Ready { ifindex, mode };
                    return Ok(ifindex);
                }
                HostXdpAttachmentState::Indeterminate { .. } => {
                    return Err(IpsecLbError::io(
                        "host_xdp_attachment_indeterminate",
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "detach is required before another attachment attempt",
                        ),
                    ));
                }
                HostXdpAttachmentState::HandoffPrepared { .. } => {
                    return Err(IpsecLbError::io(
                        "host_xdp_handoff_terminal",
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "upgrade handoff is terminal for this backend",
                        ),
                    ));
                }
                HostXdpAttachmentState::UpgradeCleanupPending { .. } => {
                    return Err(IpsecLbError::XdpUpgradeRequiresDrain);
                }
                HostXdpAttachmentState::Detached => {}
            }
        }
        enforce_kernel_floor(&self.inner.runtime.probe_environment(
            &self.inner.interface,
            &self.inner.config.bpffs_pin_root,
            self.inner.config.redirect_handoff,
        ))?;
        let ifindex = self.inner.runtime.ifindex_by_name(&self.inner.interface)?;
        if ifindex == 0 {
            return Err(IpsecLbError::invalid_config(
                "interface.ifindex",
                "ifindex must be nonzero",
            ));
        }
        self.validate_handoff_ifindex(ifindex)?;
        let lifecycle = self.inner.runtime.lifecycle_lock(&self.pin_dir())?;
        // Reject cross-writer collisions before any map state is touched: if
        // another writer's program occupies the hook, flushing owners or
        // writing our config would silently re-configure their datapath.
        if self.inner.runtime.attached_prog_id(ifindex)?.is_some() {
            return Err(IpsecLbError::AlreadyExists);
        }
        // The runtime flushes adopted owner pins and writes the config before
        // attaching the program, so the datapath never verdicts with a
        // previous process's state. The fence map is deliberately not
        // rewritten: a persisted fence survives process restarts.
        let mut state = self.state()?;
        self.inner.runtime.attach(
            &self.inner.interface,
            ifindex,
            &self.pin_dir(),
            self.inner.config.attach_mode,
            self.datapath_config(),
            lifecycle,
        )?;
        state.attachment = HostXdpAttachmentState::AwaitingFence {
            ifindex,
            mode: self.inner.config.attach_mode,
        };
        match self.inner.runtime.fence_read(ifindex) {
            Ok(persisted_fence) => {
                if persisted_fence > state.current_fence {
                    state.current_fence = persisted_fence;
                }
                state.attachment = HostXdpAttachmentState::Ready {
                    ifindex,
                    mode: self.inner.config.attach_mode,
                };
                Ok(ifindex)
            }
            Err(fence_error) => {
                match self
                    .inner
                    .runtime
                    .detach(&self.inner.interface, ifindex, &self.pin_dir())
                {
                    Ok(()) => {
                        state.attachment = HostXdpAttachmentState::Detached;
                        Err(fence_error)
                    }
                    Err(rollback) => {
                        apply_link_disposition(
                            &mut state,
                            rollback.disposition,
                            ifindex,
                            self.inner.config.attach_mode,
                        );
                        Err(rollback.error)
                    }
                }
            }
        }
    }

    fn detach_sync(&self) -> Result<(), IpsecLbError> {
        let _operation = self.operation_gate()?;
        validate_interface_name(&self.inner.interface)?;
        let (ifindex, mode) = match self.state()?.attachment {
            HostXdpAttachmentState::Detached => return Ok(()),
            HostXdpAttachmentState::AwaitingFence { ifindex, mode }
            | HostXdpAttachmentState::Ready { ifindex, mode }
            | HostXdpAttachmentState::UpgradeCleanupPending { ifindex, mode }
            | HostXdpAttachmentState::Indeterminate { ifindex, mode } => (ifindex, mode),
            HostXdpAttachmentState::HandoffPrepared { .. } => {
                return Err(IpsecLbError::io(
                    "host_xdp_handoff_terminal",
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "prepared upgrade handoff cannot be detached by the old backend",
                    ),
                ));
            }
        };
        let mut state = self.state()?;
        match self
            .inner
            .runtime
            .detach(&self.inner.interface, ifindex, &self.pin_dir())
        {
            Ok(()) => {
                state.attachment = HostXdpAttachmentState::Detached;
                Ok(())
            }
            Err(failure) => {
                apply_link_disposition(&mut state, failure.disposition, ifindex, mode);
                Err(failure.error)
            }
        }
    }

    fn prepare_upgrade_handoff_sync(&self) -> Result<(), IpsecLbError> {
        let _operation = self.operation_gate()?;
        validate_interface_name(&self.inner.interface)?;
        let (ifindex, mode) = match self.state()?.attachment {
            HostXdpAttachmentState::Ready { ifindex, mode } => (ifindex, mode),
            HostXdpAttachmentState::HandoffPrepared { .. } => return Ok(()),
            HostXdpAttachmentState::Detached => return Err(IpsecLbError::NotFound),
            HostXdpAttachmentState::AwaitingFence { .. }
            | HostXdpAttachmentState::UpgradeCleanupPending { .. }
            | HostXdpAttachmentState::Indeterminate { .. } => {
                return Err(IpsecLbError::io(
                    "host_xdp_prepare_upgrade_state",
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "attachment is not ready for upgrade handoff",
                    ),
                ));
            }
        };
        match self
            .inner
            .runtime
            .prepare_upgrade_handoff(ifindex, &self.pin_dir())
        {
            Ok(persisted_fence) => {
                let mut state = self.state()?;
                state.current_fence = state.current_fence.max(persisted_fence);
                state.attachment = HostXdpAttachmentState::HandoffPrepared { ifindex, mode };
                Ok(())
            }
            Err(failure) => {
                let mut state = self.state()?;
                apply_link_disposition(&mut state, failure.disposition, ifindex, mode);
                Err(failure.error)
            }
        }
    }

    fn adopt_upgrade_handoff_sync(&self) -> Result<HostXdpUpgradeOutcome, IpsecLbError> {
        let _operation = self.operation_gate()?;
        validate_interface_name(&self.inner.interface)?;
        if !matches!(self.state()?.attachment, HostXdpAttachmentState::Detached) {
            return Err(IpsecLbError::AlreadyExists);
        }
        let environment = self.inner.runtime.probe_environment(
            &self.inner.interface,
            &self.inner.config.bpffs_pin_root,
            self.inner.config.redirect_handoff,
        );
        enforce_kernel_floor(&environment)?;
        let ifindex = self.inner.runtime.ifindex_by_name(&self.inner.interface)?;
        if ifindex == 0 {
            return Err(IpsecLbError::invalid_config(
                "interface.ifindex",
                "ifindex must be nonzero",
            ));
        }
        self.validate_handoff_ifindex(ifindex)?;
        let lifecycle = self.inner.runtime.lifecycle_lock(&self.pin_dir())?;
        let attached_program_id = self
            .inner
            .runtime
            .attached_prog_id(ifindex)?
            .ok_or(IpsecLbError::NotFound)?;
        if !mode_accepts_live(
            self.inner.config.attach_mode,
            self.inner.runtime.attached_mode(ifindex)?,
        ) {
            return Err(IpsecLbError::XdpUpgradeRequiresDrain);
        }
        let result = self.inner.runtime.adopt_upgrade_handoff(
            ifindex,
            attached_program_id,
            &self.pin_dir(),
            self.inner.config.attach_mode,
            self.datapath_config(),
            lifecycle,
        );
        match result {
            Ok(adoption) => {
                let mut state = self.state()?;
                state.current_fence = state.current_fence.max(adoption.fence_generation);
                if let Some(error) = adoption.link_pin_cleanup_error {
                    state.attachment = HostXdpAttachmentState::UpgradeCleanupPending {
                        ifindex,
                        mode: self.inner.config.attach_mode,
                    };
                    Ok(HostXdpUpgradeOutcome::AppliedHandoffCleanupRequired { error })
                } else {
                    state.attachment = HostXdpAttachmentState::Ready {
                        ifindex,
                        mode: self.inner.config.attach_mode,
                    };
                    Ok(match adoption.obsolete_cleanup_error {
                        Some(error) => HostXdpUpgradeOutcome::AppliedCleanupPending { error },
                        None => HostXdpUpgradeOutcome::Applied,
                    })
                }
            }
            Err(failure) => {
                let mut state = self.state()?;
                apply_link_disposition(
                    &mut state,
                    failure.disposition,
                    ifindex,
                    self.inner.config.attach_mode,
                );
                Err(failure.error)
            }
        }
    }

    fn complete_upgrade_handoff_cleanup_sync(&self) -> Result<HostXdpUpgradeOutcome, IpsecLbError> {
        let _operation = self.operation_gate()?;
        let (ifindex, mode) = match self.state()?.attachment {
            HostXdpAttachmentState::UpgradeCleanupPending { ifindex, mode } => (ifindex, mode),
            HostXdpAttachmentState::Ready { .. } => return Ok(HostXdpUpgradeOutcome::Applied),
            _ => return Err(IpsecLbError::XdpUpgradeRequiresDrain),
        };
        match self
            .inner
            .runtime
            .complete_upgrade_handoff_cleanup(ifindex, &self.pin_dir())
        {
            Ok(cleanup_error) => {
                self.state()?.attachment = HostXdpAttachmentState::Ready { ifindex, mode };
                Ok(match cleanup_error {
                    Some(error) => HostXdpUpgradeOutcome::AppliedCleanupPending { error },
                    None => HostXdpUpgradeOutcome::Applied,
                })
            }
            Err(failure) => {
                let mut state = self.state()?;
                apply_link_disposition(&mut state, failure.disposition, ifindex, mode);
                Err(failure.error)
            }
        }
    }

    fn install_owner_sync(
        &self,
        key: &SessionOwnershipKey,
        owner: ShardId,
        generation: u64,
    ) -> Result<(), IpsecLbError> {
        if generation == 0 {
            return Err(IpsecLbError::invalid_config(
                "ownership.generation",
                "ownership generation must be non-zero",
            ));
        }
        if key.destination().routing_domain() != self.inner.config.routing_domain {
            return Err(IpsecLbError::invalid_config(
                "ownership.routing_domain",
                "ownership key routing domain does not match the backend",
            ));
        }
        let _operation = self.operation_gate()?;
        // Attach first so a persisted fence is adopted before this generation
        // is validated. The operation gate also serializes the check and map
        // write against every fence advance.
        let ifindex = self.ensure_attached_under_gate()?;
        let current_fence = self.state()?.current_fence;
        if generation < current_fence {
            return Err(IpsecLbError::invalid_config(
                "ownership.generation",
                "generation predates the current ownership fence; generations are minted only by the fenced ownership authority",
            ));
        }
        let map_key = owner_map_key(key);
        let value = XdpOwnerValue {
            owner_shard: owner.get(),
            generation,
        }
        .encode();
        self.inner.runtime.owner_insert(ifindex, map_key, value)
    }

    fn remove_owner_sync(&self, key: &SessionOwnershipKey) -> Result<(), IpsecLbError> {
        if key.destination().routing_domain() != self.inner.config.routing_domain {
            return Err(IpsecLbError::invalid_config(
                "ownership.routing_domain",
                "ownership key routing domain does not match the backend",
            ));
        }
        let map_key = owner_map_key(key);
        let _operation = self.operation_gate()?;
        let ifindex = self.ensure_attached_under_gate()?;
        if self.inner.runtime.owner_remove(ifindex, map_key)? {
            Ok(())
        } else {
            Err(IpsecLbError::NotFound)
        }
    }

    fn owner_record_sync(
        &self,
        key: &SessionOwnershipKey,
    ) -> Result<Option<(ShardId, u64)>, IpsecLbError> {
        let _operation = self.operation_gate()?;
        let map_key = owner_map_key(key);
        let ifindex = match self.state()?.attachment {
            HostXdpAttachmentState::Ready { ifindex, .. } => ifindex,
            HostXdpAttachmentState::Detached => return Err(IpsecLbError::NotFound),
            HostXdpAttachmentState::AwaitingFence { .. }
            | HostXdpAttachmentState::HandoffPrepared { .. }
            | HostXdpAttachmentState::UpgradeCleanupPending { .. }
            | HostXdpAttachmentState::Indeterminate { .. } => {
                return Err(IpsecLbError::io(
                    "host_xdp_owner_record_state",
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "attachment is not ready for owner readback",
                    ),
                ));
            }
        };
        let Some(raw) = self.inner.runtime.owner_get(ifindex, map_key)? else {
            return Ok(None);
        };
        let value = XdpOwnerValue::decode(&raw).ok_or_else(|| {
            IpsecLbError::io(
                "host_xdp_owner_record",
                io::Error::new(io::ErrorKind::InvalidData, "invalid owner-map value"),
            )
        })?;
        Ok(Some((ShardId::new(value.owner_shard), value.generation)))
    }

    fn advance_fence_sync(&self, generation: u64) -> Result<(), IpsecLbError> {
        if generation == 0 {
            return Err(IpsecLbError::invalid_config(
                "fence.generation",
                "fence generation must be non-zero",
            ));
        }
        let _operation = self.operation_gate()?;
        let ifindex = self.ensure_attached_under_gate()?;
        // One critical section across the monotonicity check, the kernel
        // write, and the state store: a concurrent advance can never leave
        // the kernel fence behind the recorded one.
        let mut state = self.state()?;
        let current = state.current_fence;
        if generation <= current {
            return Err(IpsecLbError::ownership_conflict(
                "fence generation must advance monotonically",
            ));
        }
        self.inner.runtime.fence_write(ifindex, generation)?;
        state.current_fence = generation;
        Ok(())
    }

    fn counters_sync(&self) -> Result<XdpVerdictCounters, IpsecLbError> {
        let _operation = self.operation_gate()?;
        let ifindex = match self.state()?.attachment {
            HostXdpAttachmentState::Ready { ifindex, .. } => ifindex,
            HostXdpAttachmentState::Detached => return Err(IpsecLbError::NotFound),
            HostXdpAttachmentState::AwaitingFence { .. }
            | HostXdpAttachmentState::HandoffPrepared { .. }
            | HostXdpAttachmentState::UpgradeCleanupPending { .. }
            | HostXdpAttachmentState::Indeterminate { .. } => {
                return Err(IpsecLbError::io(
                    "host_xdp_counters_state",
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "attachment is not ready for counter readback",
                    ),
                ));
            }
        };
        let slots = self.inner.runtime.counters_read(ifindex)?;
        Ok(XdpVerdictCounters::from_slots(&slots))
    }

    fn probe_sync(&self) -> SteeringProbe {
        let env = self.inner.runtime.probe_environment(
            &self.inner.interface,
            &self.inner.config.bpffs_pin_root,
            self.inner.config.redirect_handoff,
        );
        let floor_met = kernel_release_at_least(env.kernel_release, XDP_MIN_KERNEL_RELEASE);
        let mutation_ready = env.platform_supported
            && env.configured_bpffs_present
            && env.btf_present
            && env.net_admin_capable
            && env.bpf_capable
            && env.xdp_load_bytes_supported
            && env.target_interface_ready
            && env.redirect_handoff_ready
            && floor_met;
        let details = if !env.platform_supported {
            Some("Host-XDP steering unsupported on this platform")
        } else if !floor_met {
            Some("kernel release is below the Host-XDP feature floor")
        } else if !env.configured_bpffs_present {
            Some("configured pin root is not inside a bpffs mount")
        } else if !env.btf_present {
            Some("kernel BTF is not present")
        } else if !env.net_admin_capable {
            Some("CAP_NET_ADMIN is not effective")
        } else if !env.bpf_capable {
            Some("CAP_SYS_ADMIN is not effective")
        } else if !env.xdp_load_bytes_supported {
            Some("bpf_xdp_load_bytes is unavailable to XDP programs")
        } else if !env.target_interface_ready {
            Some("configured XDP attachment interface is absent or down")
        } else if !env.redirect_handoff_ready {
            Some("configured redirect hand-off interface is absent, down, or conflicts with the attachment interface")
        } else {
            Some("Host-XDP steering mutation ready")
        };
        SteeringProbe {
            kind: SteeringBackendKind::HostXdp,
            platform_supported: env.platform_supported,
            mutation_ready,
            key_material_free: true,
            details,
        }
    }
}

/// Wrap one canonical ownership key in the fixed-width owner-map key.
fn owner_map_key(key: &SessionOwnershipKey) -> [u8; OWNER_KEY_LEN] {
    let canonical = key.to_canonical_bytes();
    debug_assert!(canonical.len() <= OWNERSHIP_KEY_MAX_ENCODED_BYTES);
    let mut map_key = [0_u8; OWNER_KEY_LEN];
    map_key[0] = canonical.len() as u8;
    map_key[1..1 + canonical.len()].copy_from_slice(&canonical);
    map_key
}

fn kernel_release_at_least(release: Option<(u16, u16)>, floor: (u16, u16)) -> bool {
    matches!(release, Some(release) if release >= floor)
}

fn enforce_kernel_floor(environment: &HostXdpEnvironment) -> Result<(), IpsecLbError> {
    if !environment.platform_supported {
        return Err(IpsecLbError::Unsupported);
    }
    if !kernel_release_at_least(environment.kernel_release, XDP_MIN_KERNEL_RELEASE) {
        return Err(IpsecLbError::xdp_kernel_floor(
            "kernel >= 5.18 with XDP bpf_link, pinned maps, per-CPU arrays, bpf_redirect, and bpf_xdp_load_bytes",
        ));
    }
    if !environment.btf_present {
        return Err(IpsecLbError::xdp_kernel_floor(
            "kernel BTF exposed at /sys/kernel/btf/vmlinux",
        ));
    }
    if !environment.configured_bpffs_present {
        return Err(IpsecLbError::xdp_kernel_floor(
            "configured pin root inside a bpffs mount",
        ));
    }
    if !environment.net_admin_capable || !environment.bpf_capable {
        return Err(IpsecLbError::xdp_kernel_floor(
            "effective CAP_NET_ADMIN and CAP_SYS_ADMIN",
        ));
    }
    if !environment.xdp_load_bytes_supported {
        return Err(IpsecLbError::xdp_kernel_floor(
            "bpf_xdp_load_bytes helper available to XDP programs",
        ));
    }
    if !environment.target_interface_ready {
        return Err(IpsecLbError::invalid_config(
            "interface",
            "configured XDP attachment interface does not exist or is not up",
        ));
    }
    if !environment.redirect_handoff_ready {
        return Err(IpsecLbError::invalid_config(
            "redirect_handoff.ifindex",
            "configured hand-off interface does not exist, is not up, or conflicts with the attachment interface",
        ));
    }
    Ok(())
}

const IFNAMSIZ: usize = 16;

fn validate_interface_name(name: &str) -> Result<(), IpsecLbError> {
    if name.is_empty() {
        return Err(IpsecLbError::invalid_config(
            "interface.name",
            "name must be nonempty",
        ));
    }
    if name.len() >= IFNAMSIZ {
        return Err(IpsecLbError::invalid_config(
            "interface.name",
            "name must fit Linux IFNAMSIZ",
        ));
    }
    if name.as_bytes().contains(&0) || name.contains('/') || name == "." || name == ".." {
        return Err(IpsecLbError::invalid_config(
            "interface.name",
            "name must not contain NUL or path separators and must not be . or ..",
        ));
    }
    Ok(())
}

fn poisoned_lock() -> io::Error {
    io::Error::other("host XDP backend mutex poisoned")
}

#[derive(Debug, Clone, Copy, Default)]
struct UnsupportedHostXdpRuntime;

impl HostXdpRuntime for UnsupportedHostXdpRuntime {
    fn lifecycle_lock(
        &self,
        _pin_root: &Path,
    ) -> Result<Box<dyn HostXdpLifecycleLock>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn ifindex_by_name(&self, _name: &str) -> Result<u32, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn link_is_up(&self, _ifindex: u32) -> Result<bool, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn attached_prog_id(&self, _ifindex: u32) -> Result<Option<u32>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn attached_mode(&self, _ifindex: u32) -> Result<Option<HostXdpAttachMode>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn attach(
        &self,
        _interface: &str,
        _ifindex: u32,
        _pin_dir: &Path,
        _mode: HostXdpAttachMode,
        _config: [u8; CONFIG_VALUE_LEN],
        _lease: Box<dyn HostXdpLifecycleLock>,
    ) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn prepare_upgrade_handoff(
        &self,
        _ifindex: u32,
        _pin_dir: &Path,
    ) -> Result<u64, HostXdpRuntimeFailure> {
        Err(HostXdpRuntimeFailure::new(
            IpsecLbError::Unsupported,
            HostXdpLinkDisposition::Unchanged,
        ))
    }

    fn complete_upgrade_handoff_cleanup(
        &self,
        _ifindex: u32,
        _pin_dir: &Path,
    ) -> Result<Option<IpsecLbError>, HostXdpRuntimeFailure> {
        Err(HostXdpRuntimeFailure::new(
            IpsecLbError::Unsupported,
            HostXdpLinkDisposition::Unchanged,
        ))
    }

    fn adopt_upgrade_handoff(
        &self,
        _ifindex: u32,
        _attached_program_id: u32,
        _pin_dir: &Path,
        _mode: HostXdpAttachMode,
        _config: [u8; CONFIG_VALUE_LEN],
        _lease: Box<dyn HostXdpLifecycleLock>,
    ) -> Result<HostXdpRuntimeAdoption, HostXdpRuntimeFailure> {
        Err(HostXdpRuntimeFailure::new(
            IpsecLbError::Unsupported,
            HostXdpLinkDisposition::Unchanged,
        ))
    }

    fn detach(
        &self,
        _interface: &str,
        _ifindex: u32,
        _pin_dir: &Path,
    ) -> Result<(), HostXdpRuntimeFailure> {
        Err(HostXdpRuntimeFailure::new(
            IpsecLbError::Unsupported,
            HostXdpLinkDisposition::Indeterminate,
        ))
    }

    fn owner_get(
        &self,
        _ifindex: u32,
        _key: [u8; OWNER_KEY_LEN],
    ) -> Result<Option<[u8; OWNER_VALUE_LEN]>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn owner_insert(
        &self,
        _ifindex: u32,
        _key: [u8; OWNER_KEY_LEN],
        _value: [u8; OWNER_VALUE_LEN],
    ) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn owner_remove(&self, _ifindex: u32, _key: [u8; OWNER_KEY_LEN]) -> Result<bool, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn fence_read(&self, _ifindex: u32) -> Result<u64, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn fence_write(&self, _ifindex: u32, _generation: u64) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn counters_read(&self, _ifindex: u32) -> Result<[u64; COUNTER_SLOTS as usize], IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn probe_environment(
        &self,
        _interface: &str,
        _pin_root: &Path,
        _redirect_handoff: HostXdpRedirectHandoff,
    ) -> HostXdpEnvironment {
        HostXdpEnvironment::default()
    }
}

#[cfg(target_os = "linux")]
mod aya_runtime {
    //! aya-based Host-XDP runtime.

    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File};
    use std::io;
    use std::os::fd::AsFd;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use aya::maps::{Array, HashMap as BpfHashMap, Map, MapData, MapError, MapType, PerCpuArray};
    use aya::programs::links::{LinkError, LinkType};
    use aya::programs::{
        loaded_links, loaded_programs, ProgramError, ProgramInfo, ProgramType, Xdp, XdpMode,
    };
    use aya::sys::{is_helper_supported, BpfHelper};
    use aya::{Ebpf, EbpfLoader};
    use opc_linux_gtpu_sys as sys;

    use super::{
        mode_accepts_live, HostXdpAttachMode, HostXdpEnvironment, HostXdpLifecycleLock,
        HostXdpLinkDisposition, HostXdpRedirectHandoff, HostXdpRuntime, HostXdpRuntimeAdoption,
        HostXdpRuntimeFailure, CONFIG_KEY, CONFIG_VALUE_LEN, COUNTER_SLOTS, FENCE_KEY, MAP_CONFIG,
        MAP_COUNTERS, MAP_FENCE, MAP_OWNERS, OWNER_KEY_LEN, OWNER_VALUE_LEN, PROG_SWU_XDP,
        XDP_CONFIG_ABI_VERSION,
    };
    use crate::IpsecLbError;

    const DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-ipsec-lb-xdp.bpf.o"
    ));

    const CAP_NET_ADMIN: u32 = 12;
    const CAP_SYS_ADMIN: u32 = 21;
    const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
    const CONTROL_DIRECTORY: &str = ".control";
    const MAP_SLOT_A: &str = "maps-v4-a";
    const MAP_SLOT_B: &str = "maps-v4-b";
    const HANDOFF_LINK: &str = "upgrade-link";

    #[derive(Debug, Default)]
    pub(super) struct AyaHostXdpRuntime {
        devices: Mutex<BTreeMap<u32, LoadedDevice>>,
    }

    #[derive(Debug)]
    struct LoadedDevice {
        ebpf: Ebpf,
        link: sys::BpfXdpLink,
        map_pin_dir: PathBuf,
        link_pin_path: Option<PathBuf>,
        lease: Box<dyn HostXdpLifecycleLock>,
    }

    #[derive(Debug)]
    struct FileLifecycleLock {
        _directory: File,
    }

    impl HostXdpLifecycleLock for FileLifecycleLock {}

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MapNamespaceSlot {
        Legacy,
        A,
        B,
    }

    impl MapNamespaceSlot {
        fn path(self, interface_dir: &Path) -> PathBuf {
            match self {
                Self::Legacy => interface_dir.to_path_buf(),
                Self::A => interface_dir.join(MAP_SLOT_A),
                Self::B => interface_dir.join(MAP_SLOT_B),
            }
        }

        const fn remove_directory(self) -> bool {
            !matches!(self, Self::Legacy)
        }
    }

    #[derive(Debug)]
    struct PinnedMapNamespace {
        slot: MapNamespaceSlot,
        version: u8,
        config: [u8; CONFIG_VALUE_LEN],
        fence_generation: u64,
        map_ids: BTreeSet<u32>,
    }

    #[derive(Debug)]
    struct PartialPinnedMapNamespace {
        slot: MapNamespaceSlot,
        fence_generation: u64,
        map_ids: BTreeSet<u32>,
    }

    #[derive(Debug, Default)]
    struct PinnedNamespaceInventory {
        complete: Vec<PinnedMapNamespace>,
        partial: Vec<PartialPinnedMapNamespace>,
    }

    impl PinnedNamespaceInventory {
        fn max_fence(&self) -> u64 {
            self.complete
                .iter()
                .map(|namespace| namespace.fence_generation)
                .chain(
                    self.partial
                        .iter()
                        .map(|namespace| namespace.fence_generation),
                )
                .max()
                .unwrap_or(0)
        }

        fn fence_sources(&self) -> impl Iterator<Item = (MapNamespaceSlot, u64)> + '_ {
            self.complete
                .iter()
                .map(|namespace| (namespace.slot, namespace.fence_generation))
                .chain(
                    self.partial
                        .iter()
                        .map(|namespace| (namespace.slot, namespace.fence_generation)),
                )
        }
    }

    impl AyaHostXdpRuntime {
        pub(super) fn new() -> Self {
            Self::default()
        }

        fn load_fresh(map_pin_dir: &Path) -> Result<Ebpf, IpsecLbError> {
            fs::create_dir_all(map_pin_dir)
                .map_err(|error| IpsecLbError::io("xdp_pin_dir_create", error))?;
            EbpfLoader::new()
                .default_map_pin_directory(map_pin_dir)
                .load(DATAPATH_OBJECT)
                .map_err(|_| {
                    IpsecLbError::io(
                        "xdp_object_load",
                        invalid_data("trusted XDP object load failed in a fresh map namespace"),
                    )
                })
        }

        fn xdp_program(ebpf: &mut Ebpf) -> Result<&mut Xdp, IpsecLbError> {
            ebpf.program_mut(PROG_SWU_XDP)
                .ok_or_else(|| {
                    IpsecLbError::io("xdp_program_lookup", invalid_data("program missing"))
                })?
                .try_into()
                .map_err(|_: ProgramError| {
                    IpsecLbError::io("xdp_program_type", invalid_data("not an XDP program"))
                })
        }

        fn owners_map(
            ebpf: &mut Ebpf,
        ) -> Result<
            BpfHashMap<&mut aya::maps::MapData, [u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]>,
            IpsecLbError,
        > {
            let map = ebpf
                .map_mut(MAP_OWNERS)
                .ok_or_else(|| IpsecLbError::io("xdp_owners_map", invalid_data("map missing")))?;
            BpfHashMap::<_, [u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("xdp_owners_map", error))
        }

        fn owners_flush_map(ebpf: &mut Ebpf) -> Result<(), IpsecLbError> {
            let mut hash = Self::owners_map(ebpf)?;
            let keys: Vec<[u8; OWNER_KEY_LEN]> = hash
                .keys()
                .collect::<Result<_, _>>()
                .map_err(|error| map_error("xdp_owners_flush", error))?;
            for key in keys {
                hash.remove(&key)
                    .map_err(|error| map_error("xdp_owners_flush", error))?;
            }
            Self::owners_empty_map(ebpf)
        }

        fn owners_empty_map(ebpf: &mut Ebpf) -> Result<(), IpsecLbError> {
            let hash = Self::owners_map(ebpf)?;
            match hash.keys().next() {
                None => Ok(()),
                Some(Ok(_)) => Err(IpsecLbError::XdpUpgradeRequiresDrain),
                Some(Err(error)) => Err(map_error("xdp_owners_verify_empty", error)),
            }
        }

        fn config_write_map(
            ebpf: &mut Ebpf,
            value: [u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let map = ebpf
                .map_mut(MAP_CONFIG)
                .ok_or_else(|| IpsecLbError::io("xdp_config_map", invalid_data("map missing")))?;
            let mut hash = BpfHashMap::<_, u32, [u8; CONFIG_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("xdp_config_map", error))?;
            hash.insert(CONFIG_KEY, value, 0)
                .map_err(|error| map_error("xdp_config_write", error))
        }

        fn fence_map(
            ebpf: &mut Ebpf,
        ) -> Result<BpfHashMap<&mut aya::maps::MapData, u32, u64>, IpsecLbError> {
            let map = ebpf
                .map_mut(MAP_FENCE)
                .ok_or_else(|| IpsecLbError::io("xdp_fence_map", invalid_data("map missing")))?;
            BpfHashMap::<_, u32, u64>::try_from(map)
                .map_err(|error| map_error("xdp_fence_map", error))
        }

        fn unpin_namespace(map_pin_dir: &Path, remove_directory: bool) -> Result<(), IpsecLbError> {
            // Delete fencing evidence last. V1 stores its fence inline in the
            // config map and has no fence pin; v2-v4 store it in the fence
            // map. This order therefore leaves a readable non-regression
            // witness after every interrupted SDK-produced cleanup until the
            // namespace is otherwise empty.
            for map_name in [MAP_OWNERS, MAP_COUNTERS, MAP_CONFIG, MAP_FENCE] {
                match fs::remove_file(map_pin_dir.join(map_name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(IpsecLbError::io("xdp_map_unpin", error)),
                }
            }
            if remove_directory {
                match fs::remove_dir(map_pin_dir) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(IpsecLbError::io("xdp_map_namespace_remove", error)),
                }
            }
            Ok(())
        }

        fn namespace_has_any_pin(path: &Path) -> bool {
            [MAP_OWNERS, MAP_CONFIG, MAP_FENCE, MAP_COUNTERS]
                .iter()
                .any(|name| path.join(name).exists())
        }

        fn audit_interface_directory(interface_dir: &Path) -> Result<(), IpsecLbError> {
            let entries = fs::read_dir(interface_dir)
                .map_err(|error| IpsecLbError::io("xdp_interface_namespace_read", error))?;
            for entry in entries {
                let entry = entry
                    .map_err(|error| IpsecLbError::io("xdp_interface_namespace_read", error))?;
                let name = entry.file_name();
                let allowed = [
                    CONTROL_DIRECTORY,
                    MAP_SLOT_A,
                    MAP_SLOT_B,
                    HANDOFF_LINK,
                    MAP_OWNERS,
                    MAP_CONFIG,
                    MAP_FENCE,
                    MAP_COUNTERS,
                ]
                .iter()
                .any(|allowed| name == std::ffi::OsStr::new(allowed));
                if !allowed {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
            }
            Ok(())
        }

        fn audit_map_slot(map_pin_dir: &Path) -> Result<(), IpsecLbError> {
            if !map_pin_dir.exists() {
                return Ok(());
            }
            let entries = fs::read_dir(map_pin_dir)
                .map_err(|error| IpsecLbError::io("xdp_map_namespace_read", error))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| IpsecLbError::io("xdp_map_namespace_read", error))?;
                let name = entry.file_name();
                let allowed = [MAP_OWNERS, MAP_CONFIG, MAP_FENCE, MAP_COUNTERS]
                    .iter()
                    .any(|allowed| name == std::ffi::OsStr::new(allowed));
                if !allowed {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
            }
            Ok(())
        }

        fn map_schema(
            path: &Path,
            operation: &'static str,
            expected_type: MapType,
            expected_key_size: u32,
            expected_value_size: u32,
            expected_max_entries: u32,
        ) -> Result<(MapData, u32), IpsecLbError> {
            let map = MapData::from_pin(path).map_err(|error| map_error(operation, error))?;
            let info = map.info().map_err(|error| map_error(operation, error))?;
            let map_type = info
                .map_type()
                .map_err(|error| map_error(operation, error))?;
            if map_type != expected_type
                || info.key_size() != expected_key_size
                || info.value_size() != expected_value_size
                || info.max_entries() != expected_max_entries
                || info.map_flags() != 0
            {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            let id = info.id();
            Ok((map, id))
        }

        fn read_config_map(
            path: &Path,
        ) -> Result<([u8; CONFIG_VALUE_LEN], MapType, u32), IpsecLbError> {
            let map = MapData::from_pin(path)
                .map_err(|error| map_error("xdp_upgrade_config_open", error))?;
            let info = map
                .info()
                .map_err(|error| map_error("xdp_upgrade_config_info", error))?;
            let map_type = info
                .map_type()
                .map_err(|error| map_error("xdp_upgrade_config_info", error))?;
            if info.key_size() != 4
                || info.value_size() != CONFIG_VALUE_LEN as u32
                || info.max_entries() != 1
                || info.map_flags() != 0
            {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            let id = info.id();
            let value = match map_type {
                MapType::Array => Array::<_, [u8; CONFIG_VALUE_LEN]>::try_from(Map::Array(map))
                    .map_err(|error| map_error("xdp_upgrade_config_array", error))?
                    .get(&CONFIG_KEY, 0)
                    .map_err(|error| map_error("xdp_upgrade_config_read", error))?,
                MapType::Hash => {
                    let hash =
                        BpfHashMap::<_, u32, [u8; CONFIG_VALUE_LEN]>::try_from(Map::HashMap(map))
                            .map_err(|error| map_error("xdp_upgrade_config_hash", error))?;
                    let mut keys = hash.keys();
                    match keys.next() {
                        Some(Ok(CONFIG_KEY)) if keys.next().is_none() => {}
                        _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
                    }
                    hash.get(&CONFIG_KEY, 0)
                        .map_err(|error| map_error("xdp_upgrade_config_read", error))?
                }
                _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
            };
            Ok((value, map_type, id))
        }

        fn config_identity_matches(
            value: &[u8; CONFIG_VALUE_LEN],
            expected: &[u8; CONFIG_VALUE_LEN],
        ) -> bool {
            value[1] == 0
                && value[2..12] == expected[2..12]
                && value[20..24] == expected[20..24]
                && value[24..].iter().all(|byte| *byte == 0)
                && (value[0] == 1 || value[12..20].iter().all(|byte| *byte == 0))
        }

        fn partial_config_pin(
            path: &Path,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(Option<[u8; CONFIG_VALUE_LEN]>, MapType, u32), IpsecLbError> {
            let map = MapData::from_pin(path)
                .map_err(|error| map_error("xdp_partial_config_open", error))?;
            let info = map
                .info()
                .map_err(|error| map_error("xdp_partial_config_info", error))?;
            let map_type = info
                .map_type()
                .map_err(|error| map_error("xdp_partial_config_info", error))?;
            if !matches!(map_type, MapType::Array | MapType::Hash)
                || info.key_size() != 4
                || info.value_size() != CONFIG_VALUE_LEN as u32
                || info.max_entries() != 1
                || info.map_flags() != 0
            {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            let id = info.id();
            let value = match map_type {
                MapType::Array => Some(
                    Array::<_, [u8; CONFIG_VALUE_LEN]>::try_from(Map::Array(map))
                        .map_err(|error| map_error("xdp_partial_config_array", error))?
                        .get(&CONFIG_KEY, 0)
                        .map_err(|error| map_error("xdp_partial_config_read", error))?,
                ),
                MapType::Hash => {
                    let hash =
                        BpfHashMap::<_, u32, [u8; CONFIG_VALUE_LEN]>::try_from(Map::HashMap(map))
                            .map_err(|error| map_error("xdp_partial_config_hash", error))?;
                    let mut keys = hash.keys();
                    match keys.next() {
                        None => None,
                        Some(Ok(CONFIG_KEY)) if keys.next().is_none() => Some(
                            hash.get(&CONFIG_KEY, 0)
                                .map_err(|error| map_error("xdp_partial_config_read", error))?,
                        ),
                        _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
                    }
                }
                _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
            };
            if let Some(value) = value {
                if !(1..=XDP_CONFIG_ABI_VERSION).contains(&value[0])
                    || !Self::config_identity_matches(&value, expected_config)
                {
                    return Err(IpsecLbError::XdpUpgradeRequiresDrain);
                }
                let expected_type = if value[0] == XDP_CONFIG_ABI_VERSION {
                    MapType::Hash
                } else {
                    MapType::Array
                };
                if map_type != expected_type {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
            }
            Ok((value, map_type, id))
        }

        fn partial_fence_pin(path: &Path) -> Result<(u64, MapType, u32), IpsecLbError> {
            let map = MapData::from_pin(path)
                .map_err(|error| map_error("xdp_partial_fence_open", error))?;
            let info = map
                .info()
                .map_err(|error| map_error("xdp_partial_fence_info", error))?;
            let map_type = info
                .map_type()
                .map_err(|error| map_error("xdp_partial_fence_info", error))?;
            if !matches!(map_type, MapType::Array | MapType::Hash)
                || info.key_size() != 4
                || info.value_size() != 8
                || info.max_entries() != 1
                || info.map_flags() != 0
            {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            let id = info.id();
            let generation = match map_type {
                MapType::Array => Array::<_, u64>::try_from(Map::Array(map))
                    .map_err(|error| map_error("xdp_partial_fence_array", error))?
                    .get(&FENCE_KEY, 0)
                    .map_err(|error| map_error("xdp_partial_fence_read", error))?,
                MapType::Hash => {
                    let hash = BpfHashMap::<_, u32, u64>::try_from(Map::HashMap(map))
                        .map_err(|error| map_error("xdp_partial_fence_hash", error))?;
                    let mut keys = hash.keys();
                    match keys.next() {
                        None => 0,
                        Some(Ok(FENCE_KEY)) if keys.next().is_none() => hash
                            .get(&FENCE_KEY, 0)
                            .map_err(|error| map_error("xdp_partial_fence_read", error))?,
                        _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
                    }
                }
                _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
            };
            Ok((generation, map_type, id))
        }

        fn inspect_partial_namespace(
            interface_dir: &Path,
            slot: MapNamespaceSlot,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<PartialPinnedMapNamespace, IpsecLbError> {
            let path = slot.path(interface_dir);
            let mut map_ids = BTreeSet::new();
            let mut config = None;
            let mut config_type = None;
            if path.join(MAP_CONFIG).exists() {
                let (value, map_type, id) =
                    Self::partial_config_pin(&path.join(MAP_CONFIG), expected_config)?;
                config = value;
                config_type = Some(map_type);
                map_ids.insert(id);
            }
            if path.join(MAP_OWNERS).exists() {
                let (_, id) = Self::map_schema(
                    &path.join(MAP_OWNERS),
                    "xdp_partial_owners_schema",
                    MapType::Hash,
                    OWNER_KEY_LEN as u32,
                    OWNER_VALUE_LEN as u32,
                    65_536,
                )?;
                map_ids.insert(id);
            }
            if path.join(MAP_COUNTERS).exists() {
                let (_, id) = Self::map_schema(
                    &path.join(MAP_COUNTERS),
                    "xdp_partial_counters_schema",
                    MapType::PerCpuArray,
                    4,
                    8,
                    COUNTER_SLOTS,
                )?;
                map_ids.insert(id);
            }
            let fence = if path.join(MAP_FENCE).exists() {
                let (generation, map_type, id) = Self::partial_fence_pin(&path.join(MAP_FENCE))?;
                map_ids.insert(id);
                Some((generation, map_type))
            } else {
                None
            };
            if map_ids.is_empty() {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }

            let fence_generation = match config {
                Some(value) if value[0] == 1 => {
                    if fence.is_some() || config_type != Some(MapType::Array) {
                        return Err(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                    u64::from_be_bytes([
                        value[12], value[13], value[14], value[15], value[16], value[17],
                        value[18], value[19],
                    ])
                }
                Some(value) => {
                    let (generation, map_type) =
                        fence.ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                    let expected_type = if value[0] == 2 {
                        MapType::Array
                    } else {
                        MapType::Hash
                    };
                    if map_type != expected_type {
                        return Err(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                    generation
                }
                None => fence
                    .map(|(generation, _)| generation)
                    .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?,
            };

            Ok(PartialPinnedMapNamespace {
                slot,
                fence_generation,
                map_ids,
            })
        }

        fn inspect_namespace(
            interface_dir: &Path,
            slot: MapNamespaceSlot,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<Option<PinnedMapNamespace>, IpsecLbError> {
            let path = slot.path(interface_dir);
            if slot.remove_directory() {
                Self::audit_map_slot(&path)?;
            }
            if !Self::namespace_has_any_pin(&path) {
                return Ok(None);
            }
            for required in [MAP_OWNERS, MAP_CONFIG, MAP_COUNTERS] {
                if !path.join(required).is_file() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
            }

            let (config, config_type, config_id) = Self::read_config_map(&path.join(MAP_CONFIG))?;
            let version = config[0];
            if !(1..=XDP_CONFIG_ABI_VERSION).contains(&version)
                || !Self::config_identity_matches(&config, expected_config)
            {
                return Err(IpsecLbError::XdpUpgradeRequiresDrain);
            }
            let expected_config_type = if version == XDP_CONFIG_ABI_VERSION {
                MapType::Hash
            } else {
                MapType::Array
            };
            if config_type != expected_config_type {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }

            let (_, owners_id) = Self::map_schema(
                &path.join(MAP_OWNERS),
                "xdp_upgrade_owners_schema",
                MapType::Hash,
                OWNER_KEY_LEN as u32,
                OWNER_VALUE_LEN as u32,
                65_536,
            )?;
            let (_, counters_id) = Self::map_schema(
                &path.join(MAP_COUNTERS),
                "xdp_upgrade_counters_schema",
                MapType::PerCpuArray,
                4,
                8,
                COUNTER_SLOTS,
            )?;

            let mut map_ids = BTreeSet::from([config_id, owners_id, counters_id]);
            let fence_generation = if version == 1 {
                if path.join(MAP_FENCE).exists() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                u64::from_be_bytes([
                    config[12], config[13], config[14], config[15], config[16], config[17],
                    config[18], config[19],
                ])
            } else {
                if !path.join(MAP_FENCE).is_file() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                let fence_type = if version == 2 {
                    MapType::Array
                } else {
                    MapType::Hash
                };
                let (fence_map, fence_id) = Self::map_schema(
                    &path.join(MAP_FENCE),
                    "xdp_upgrade_fence_schema",
                    fence_type,
                    4,
                    8,
                    1,
                )?;
                map_ids.insert(fence_id);
                match fence_type {
                    MapType::Array => Array::<_, u64>::try_from(Map::Array(fence_map))
                        .map_err(|error| map_error("xdp_upgrade_fence_array", error))?
                        .get(&FENCE_KEY, 0)
                        .map_err(|error| map_error("xdp_upgrade_fence_read", error))?,
                    MapType::Hash => {
                        let hash = BpfHashMap::<_, u32, u64>::try_from(Map::HashMap(fence_map))
                            .map_err(|error| map_error("xdp_upgrade_fence_hash", error))?;
                        let mut keys = hash.keys();
                        match keys.next() {
                            None => 0,
                            Some(Ok(FENCE_KEY)) if keys.next().is_none() => hash
                                .get(&FENCE_KEY, 0)
                                .map_err(|error| map_error("xdp_upgrade_fence_read", error))?,
                            _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
                        }
                    }
                    _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
                }
            };

            Ok(Some(PinnedMapNamespace {
                slot,
                version,
                config,
                fence_generation,
                map_ids,
            }))
        }

        fn inspect_namespaces(
            interface_dir: &Path,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<PinnedNamespaceInventory, IpsecLbError> {
            Self::audit_interface_directory(interface_dir)?;
            let mut inventory = PinnedNamespaceInventory::default();
            for slot in [
                MapNamespaceSlot::Legacy,
                MapNamespaceSlot::A,
                MapNamespaceSlot::B,
            ] {
                match Self::inspect_namespace(interface_dir, slot, expected_config) {
                    Ok(Some(namespace)) => inventory.complete.push(namespace),
                    Ok(None) => {}
                    Err(_) if Self::namespace_has_any_pin(&slot.path(interface_dir)) => {
                        inventory.partial.push(Self::inspect_partial_namespace(
                            interface_dir,
                            slot,
                            expected_config,
                        )?);
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(inventory)
        }

        fn staging_slot(inventory: &PinnedNamespaceInventory) -> MapNamespaceSlot {
            let max_fence = inventory.max_fence();
            let mut max_sources = inventory
                .fence_sources()
                .filter(|(_, generation)| *generation == max_fence);
            let first = max_sources.next().map(|(slot, _)| slot);
            let unique_max = first.filter(|_| max_sources.next().is_none());
            match unique_max {
                Some(MapNamespaceSlot::A) => MapNamespaceSlot::B,
                Some(MapNamespaceSlot::B | MapNamespaceSlot::Legacy) | None => MapNamespaceSlot::A,
            }
        }

        fn persist_namespace_fence(
            interface_dir: &Path,
            namespace: &PinnedMapNamespace,
            generation: u64,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let path = namespace.slot.path(interface_dir);
            match namespace.version {
                1 => {
                    let (map, _) = Self::map_schema(
                        &path.join(MAP_CONFIG),
                        "xdp_upgrade_config_schema",
                        MapType::Array,
                        4,
                        CONFIG_VALUE_LEN as u32,
                        1,
                    )?;
                    let mut value = namespace.config;
                    value[12..20].copy_from_slice(&generation.to_be_bytes());
                    let mut config = Array::<_, [u8; CONFIG_VALUE_LEN]>::try_from(Map::Array(map))
                        .map_err(|error| map_error("xdp_upgrade_config_array", error))?;
                    config
                        .set(CONFIG_KEY, value, 0)
                        .map_err(|error| map_error("xdp_upgrade_fence_persist", error))?;
                }
                2 => {
                    let (map, _) = Self::map_schema(
                        &path.join(MAP_FENCE),
                        "xdp_upgrade_fence_schema",
                        MapType::Array,
                        4,
                        8,
                        1,
                    )?;
                    let mut fence = Array::<_, u64>::try_from(Map::Array(map))
                        .map_err(|error| map_error("xdp_upgrade_fence_array", error))?;
                    fence
                        .set(FENCE_KEY, generation, 0)
                        .map_err(|error| map_error("xdp_upgrade_fence_persist", error))?;
                }
                3 | 4 => {
                    let (map, _) = Self::map_schema(
                        &path.join(MAP_FENCE),
                        "xdp_upgrade_fence_schema",
                        MapType::Hash,
                        4,
                        8,
                        1,
                    )?;
                    let mut fence = BpfHashMap::<_, u32, u64>::try_from(Map::HashMap(map))
                        .map_err(|error| map_error("xdp_upgrade_fence_hash", error))?;
                    fence
                        .insert(FENCE_KEY, generation, 0)
                        .map_err(|error| map_error("xdp_upgrade_fence_persist", error))?;
                }
                _ => return Err(IpsecLbError::XdpUpgradeRequiresDrain),
            }
            let persisted =
                Self::inspect_namespace(interface_dir, namespace.slot, expected_config)?
                    .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
            if persisted.fence_generation != generation {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            Ok(())
        }

        fn verify_staged_namespace(
            interface_dir: &Path,
            slot: MapNamespaceSlot,
            expected_config: &[u8; CONFIG_VALUE_LEN],
            expected_fence: u64,
            program: &ProgramInfo,
        ) -> Result<(), IpsecLbError> {
            let staged = Self::inspect_namespace(interface_dir, slot, expected_config)?
                .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
            if staged.version != XDP_CONFIG_ABI_VERSION
                || staged.config != *expected_config
                || staged.fence_generation != expected_fence
            {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            Self::pinned_owners_empty(&slot.path(interface_dir))?;
            let _ = Self::active_namespace(std::slice::from_ref(&staged), program)?;
            Ok(())
        }

        fn active_namespace<'a>(
            namespaces: &'a [PinnedMapNamespace],
            program: &ProgramInfo,
        ) -> Result<&'a PinnedMapNamespace, IpsecLbError> {
            let program_map_ids = program
                .map_ids()
                .map_err(|error| program_error("xdp_upgrade_program_maps", &error))?
                .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let mut matching = namespaces
                .iter()
                .filter(|namespace| namespace.map_ids == program_map_ids);
            let active = matching
                .next()
                .ok_or(IpsecLbError::XdpUpgradeRequiresDrain)?;
            if matching.next().is_some() {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            Ok(active)
        }

        fn program_info(program_id: u32) -> Result<ProgramInfo, IpsecLbError> {
            for result in loaded_programs() {
                let info =
                    result.map_err(|error| program_error("xdp_upgrade_program_info", &error))?;
                if info.id() == program_id {
                    return Ok(info);
                }
            }
            Err(IpsecLbError::XdpUpgradeIndeterminate)
        }

        fn unique_xdp_link_id(program_id: u32, ifindex: u32) -> Result<u32, IpsecLbError> {
            let mut found = None;
            for result in loaded_links() {
                let info = result.map_err(|error| link_error("xdp_upgrade_link_info", &error))?;
                if info.program_id() != program_id {
                    continue;
                }
                if info
                    .link_type()
                    .map_err(|error| link_error("xdp_upgrade_link_type", &error))?
                    != LinkType::Xdp
                {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                let identity = sys::open_xdp_link_by_id(info.id())
                    .and_then(|link| link.info())
                    .map_err(|error| IpsecLbError::io("xdp_link_identity", error))?;
                if identity.program_id != program_id || identity.link_id != info.id() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                if identity.ifindex != ifindex {
                    continue;
                }
                if found.replace(info.id()).is_some() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
            }
            found.ok_or(IpsecLbError::XdpUpgradeRequiresDrain)
        }

        fn pinned_owners_empty(map_pin_dir: &Path) -> Result<(), IpsecLbError> {
            let (map, _) = Self::map_schema(
                &map_pin_dir.join(MAP_OWNERS),
                "xdp_upgrade_owners_schema",
                MapType::Hash,
                OWNER_KEY_LEN as u32,
                OWNER_VALUE_LEN as u32,
                65_536,
            )?;
            let owners = BpfHashMap::<_, [u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]>::try_from(
                Map::HashMap(map),
            )
            .map_err(|error| map_error("xdp_upgrade_owners_open", error))?;
            match owners.keys().next() {
                None => Ok(()),
                Some(Ok(_)) => Err(IpsecLbError::XdpUpgradeRequiresDrain),
                Some(Err(error)) => Err(map_error("xdp_upgrade_owners_verify_empty", error)),
            }
        }

        fn cleanup_namespaces_except(
            interface_dir: &Path,
            keep: MapNamespaceSlot,
        ) -> Option<IpsecLbError> {
            let mut first_error = None;
            for slot in [
                MapNamespaceSlot::Legacy,
                MapNamespaceSlot::A,
                MapNamespaceSlot::B,
            ] {
                if slot == keep {
                    continue;
                }
                if let Err(error) =
                    Self::unpin_namespace(&slot.path(interface_dir), slot.remove_directory())
                {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
            first_error
        }

        fn with_device<T>(
            &self,
            ifindex: u32,
            operation: &'static str,
            f: impl FnOnce(&mut LoadedDevice) -> Result<T, IpsecLbError>,
        ) -> Result<T, IpsecLbError> {
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| IpsecLbError::io(operation, super::poisoned_lock()))?;
            let device = devices.get_mut(&ifindex).ok_or(IpsecLbError::NotFound)?;
            let _lease = device.lease.as_ref();
            f(device)
        }
    }

    impl HostXdpRuntime for AyaHostXdpRuntime {
        fn lifecycle_lock(
            &self,
            interface_dir: &Path,
        ) -> Result<Box<dyn HostXdpLifecycleLock>, IpsecLbError> {
            fs::create_dir_all(interface_dir)
                .map_err(|error| IpsecLbError::io("xdp_lifecycle_lock_dir", error))?;
            let control_dir = interface_dir.join(CONTROL_DIRECTORY);
            fs::create_dir_all(&control_dir)
                .map_err(|error| IpsecLbError::io("xdp_lifecycle_control_dir", error))?;
            let directory = rustix::fs::open(
                &control_dir,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| IpsecLbError::io("xdp_lifecycle_lock_open", error.into()))?;
            let fd_flags = rustix::io::fcntl_getfd(&directory)
                .map_err(|error| IpsecLbError::io("xdp_lifecycle_lock_flags", error.into()))?;
            if !fd_flags.contains(rustix::io::FdFlags::CLOEXEC) {
                return Err(IpsecLbError::io(
                    "xdp_lifecycle_lock_flags",
                    invalid_data("lifecycle lease descriptor is not close-on-exec"),
                ));
            }
            match rustix::fs::flock(
                &directory,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            ) {
                Ok(()) => {}
                Err(rustix::io::Errno::AGAIN) => return Err(IpsecLbError::XdpLifecycleBusy),
                Err(error) => {
                    return Err(IpsecLbError::io("xdp_lifecycle_lock", error.into()));
                }
            }
            Ok(Box::new(FileLifecycleLock {
                _directory: directory,
            }))
        }

        fn ifindex_by_name(&self, name: &str) -> Result<u32, IpsecLbError> {
            sys::ifindex_by_name(name).map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => IpsecLbError::NotFound,
                _ => IpsecLbError::io("ifindex_lookup", error),
            })
        }

        fn link_is_up(&self, ifindex: u32) -> Result<bool, IpsecLbError> {
            link_is_up(ifindex)
        }

        fn attached_prog_id(&self, ifindex: u32) -> Result<Option<u32>, IpsecLbError> {
            attached_prog_id(ifindex)
        }

        fn attached_mode(&self, ifindex: u32) -> Result<Option<HostXdpAttachMode>, IpsecLbError> {
            attached_mode(ifindex)
        }

        fn attach(
            &self,
            interface: &str,
            ifindex: u32,
            interface_dir: &Path,
            mode: HostXdpAttachMode,
            config: [u8; CONFIG_VALUE_LEN],
            lease: Box<dyn HostXdpLifecycleLock>,
        ) -> Result<(), IpsecLbError> {
            if config[0] != XDP_CONFIG_ABI_VERSION {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| IpsecLbError::io("xdp_attach", super::poisoned_lock()))?;
            if devices.contains_key(&ifindex) {
                return Err(IpsecLbError::AlreadyExists);
            }
            if attached_prog_id(ifindex)?.is_some() {
                return Err(IpsecLbError::AlreadyExists);
            }
            if interface_dir.join(HANDOFF_LINK).exists() {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }

            let inventory = Self::inspect_namespaces(interface_dir, &config)?;
            let fence_generation = inventory.max_fence();
            let map_slot = Self::staging_slot(&inventory);
            let map_pin_dir = map_slot.path(interface_dir);
            Self::unpin_namespace(&map_pin_dir, map_slot.remove_directory())?;
            let mut ebpf = Self::load_fresh(&map_pin_dir)?;
            let stage_result = (|| {
                Self::owners_empty_map(&mut ebpf)?;
                Self::config_write_map(&mut ebpf, config)?;
                let mut fence = Self::fence_map(&mut ebpf)?;
                fence
                    .insert(FENCE_KEY, fence_generation, 0)
                    .map_err(|error| map_error("xdp_fence_initialize", error))?;
                let program = Self::xdp_program(&mut ebpf)?;
                program
                    .load()
                    .map_err(|error| program_error("xdp_program_load", &error))?;
                program
                    .info()
                    .map_err(|error| program_error("xdp_program_info", &error))
            })();
            let staged_program = match stage_result {
                Ok(program) => program,
                Err(error) => {
                    drop(ebpf);
                    let _ = Self::unpin_namespace(&map_pin_dir, true);
                    return Err(error);
                }
            };
            if let Err(error) = Self::verify_staged_namespace(
                interface_dir,
                map_slot,
                &config,
                fence_generation,
                &staged_program,
            ) {
                drop(ebpf);
                let _ = Self::unpin_namespace(&map_pin_dir, true);
                return Err(error);
            }
            let attach_result = (|| {
                let program = Self::xdp_program(&mut ebpf)?;
                let xdp_mode = match mode {
                    HostXdpAttachMode::Native => XdpMode::default(),
                    HostXdpAttachMode::Generic => XdpMode::Skb,
                };
                let link_id = program
                    .attach(interface, xdp_mode)
                    .map_err(|error| program_error("xdp_program_attach", &error))?;
                let program_id = program
                    .info()
                    .map_err(|error| program_error("xdp_program_info", &error))?
                    .id();
                let kernel_link_id = match Self::unique_xdp_link_id(program_id, ifindex) {
                    Ok(link_id) => link_id,
                    Err(_) => {
                        program
                            .detach(link_id)
                            .map_err(|error| program_error("xdp_legacy_detach", &error))?;
                        if attached_prog_id(ifindex)? == Some(program_id) {
                            return Err(IpsecLbError::XdpUpgradeIndeterminate);
                        }
                        return Err(IpsecLbError::xdp_kernel_floor(
                            "XDP bpf_link attachment support",
                        ));
                    }
                };
                let link = sys::open_xdp_link_by_id(kernel_link_id)
                    .map_err(|error| IpsecLbError::io("xdp_link_open", error))?;
                let identity = link
                    .info()
                    .map_err(|error| IpsecLbError::io("xdp_link_identity", error))?;
                if identity.link_id != kernel_link_id
                    || identity.program_id != program_id
                    || identity.ifindex != ifindex
                {
                    program
                        .detach(link_id)
                        .map_err(|error| program_error("xdp_legacy_detach", &error))?;
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                Ok((link_id, link))
            })();
            let (_aya_link_id, link) = match attach_result {
                Ok(link) => link,
                Err(error) => {
                    drop(ebpf);
                    let _ = Self::unpin_namespace(&map_pin_dir, true);
                    return Err(error);
                }
            };
            let live_mode = attached_mode(ifindex);
            if !matches!(&live_mode, Ok(live) if mode_accepts_live(mode, *live)) {
                drop(ebpf);
                drop(link);
                let cleanup = Self::unpin_namespace(&map_pin_dir, true);
                return match (live_mode, cleanup) {
                    (Err(error), Ok(())) => Err(error),
                    (_, Err(error)) => Err(error),
                    (Ok(_), Ok(())) => Err(IpsecLbError::XdpUpgradeRequiresDrain),
                };
            }
            devices.insert(
                ifindex,
                LoadedDevice {
                    ebpf,
                    link,
                    map_pin_dir,
                    link_pin_path: None,
                    lease,
                },
            );
            Ok(())
        }

        fn prepare_upgrade_handoff(
            &self,
            ifindex: u32,
            interface_dir: &Path,
        ) -> Result<u64, HostXdpRuntimeFailure> {
            let mut devices = self.devices.lock().map_err(|_| {
                HostXdpRuntimeFailure::new(
                    IpsecLbError::io("xdp_upgrade_prepare", super::poisoned_lock()),
                    HostXdpLinkDisposition::Unchanged,
                )
            })?;
            let mut device = devices.remove(&ifindex).ok_or_else(|| {
                HostXdpRuntimeFailure::new(
                    IpsecLbError::XdpUpgradeIndeterminate,
                    HostXdpLinkDisposition::Indeterminate,
                )
            })?;
            let prepare_result = (|| {
                let _lease = device.lease.as_ref();
                if device.link_pin_path.is_some() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                let program = Self::xdp_program(&mut device.ebpf)?;
                let program_id = program
                    .info()
                    .map_err(|error| program_error("xdp_upgrade_program_info", &error))?
                    .id();
                let link_identity = device
                    .link
                    .info()
                    .map_err(|error| IpsecLbError::io("xdp_upgrade_link_identity", error))?;
                if link_identity.program_id != program_id
                    || link_identity.ifindex != ifindex
                    || attached_prog_id(ifindex)? != Some(program_id)
                {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                Self::owners_flush_map(&mut device.ebpf)?;
                Self::owners_empty_map(&mut device.ebpf)?;
                let fence_generation = {
                    let fence = Self::fence_map(&mut device.ebpf)?;
                    match fence.get(&FENCE_KEY, 0) {
                        Ok(value) => value,
                        Err(MapError::KeyNotFound) => 0,
                        Err(error) => return Err(map_error("xdp_fence_read", error)),
                    }
                };
                let handoff_path = interface_dir.join(HANDOFF_LINK);
                if handoff_path.exists() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                device
                    .link
                    .pin_duplicate(&handoff_path)
                    .map_err(|error| IpsecLbError::io("xdp_upgrade_link_pin", error))?;
                Ok(fence_generation)
            })();
            match prepare_result {
                Ok(fence_generation) => {
                    let LoadedDevice {
                        ebpf,
                        link,
                        map_pin_dir: _,
                        link_pin_path: _,
                        lease,
                    } = device;
                    drop(ebpf);
                    drop(link);
                    drop(lease);
                    Ok(fence_generation)
                }
                Err(error) => {
                    devices.insert(ifindex, device);
                    Err(HostXdpRuntimeFailure::new(
                        error,
                        HostXdpLinkDisposition::Unchanged,
                    ))
                }
            }
        }

        fn adopt_upgrade_handoff(
            &self,
            ifindex: u32,
            attached_program_id: u32,
            interface_dir: &Path,
            mode: HostXdpAttachMode,
            config: [u8; CONFIG_VALUE_LEN],
            lease: Box<dyn HostXdpLifecycleLock>,
        ) -> Result<HostXdpRuntimeAdoption, HostXdpRuntimeFailure> {
            let unchanged =
                |error| HostXdpRuntimeFailure::new(error, HostXdpLinkDisposition::Unchanged);
            if config[0] != XDP_CONFIG_ABI_VERSION {
                return Err(unchanged(IpsecLbError::XdpUpgradeIndeterminate));
            }
            let mut devices = self.devices.lock().map_err(|_| {
                unchanged(IpsecLbError::io(
                    "xdp_upgrade_adopt",
                    super::poisoned_lock(),
                ))
            })?;
            if devices.contains_key(&ifindex) {
                return Err(unchanged(IpsecLbError::AlreadyExists));
            }

            let handoff_path = interface_dir.join(HANDOFF_LINK);
            let link = sys::open_xdp_link_from_pin(&handoff_path)
                .map_err(|error| unchanged(IpsecLbError::io("xdp_upgrade_link_open", error)))?;
            let link_identity = link
                .info()
                .map_err(|error| unchanged(IpsecLbError::io("xdp_upgrade_link_info", error)))?;
            if link_identity.program_id != attached_program_id
                || link_identity.ifindex != ifindex
                || !mode_accepts_live(mode, attached_mode(ifindex).map_err(unchanged)?)
            {
                return Err(unchanged(IpsecLbError::XdpUpgradeRequiresDrain));
            }

            let old_program = sys::open_xdp_program_by_id(attached_program_id)
                .map_err(|error| unchanged(IpsecLbError::io("xdp_upgrade_program_open", error)))?;
            let old_program_info = Self::program_info(attached_program_id).map_err(unchanged)?;
            let inventory = Self::inspect_namespaces(interface_dir, &config).map_err(unchanged)?;
            let active = Self::active_namespace(&inventory.complete, &old_program_info)
                .map_err(unchanged)?;
            if inventory
                .partial
                .iter()
                .any(|partial| !partial.map_ids.is_disjoint(&active.map_ids))
            {
                return Err(unchanged(IpsecLbError::XdpUpgradeIndeterminate));
            }
            Self::pinned_owners_empty(&active.slot.path(interface_dir)).map_err(unchanged)?;
            let fence_generation = inventory.max_fence();
            if active.fence_generation < fence_generation {
                Self::persist_namespace_fence(interface_dir, active, fence_generation, &config)
                    .map_err(unchanged)?;
            }
            let target_slot = match active.slot {
                MapNamespaceSlot::A => MapNamespaceSlot::B,
                MapNamespaceSlot::Legacy | MapNamespaceSlot::B => MapNamespaceSlot::A,
            };
            let target_dir = target_slot.path(interface_dir);
            Self::unpin_namespace(&target_dir, target_slot.remove_directory())
                .map_err(unchanged)?;
            let mut new_ebpf = Self::load_fresh(&target_dir).map_err(unchanged)?;

            let initialize_result = (|| {
                Self::owners_empty_map(&mut new_ebpf)?;
                Self::config_write_map(&mut new_ebpf, config)?;
                let mut fence = Self::fence_map(&mut new_ebpf)?;
                fence
                    .insert(FENCE_KEY, fence_generation, 0)
                    .map_err(|error| map_error("xdp_upgrade_fence_initialize", error))?;
                let new_program = Self::xdp_program(&mut new_ebpf)?;
                new_program
                    .load()
                    .map_err(|error| program_error("xdp_upgrade_program_load", &error))?;
                new_program
                    .info()
                    .map_err(|error| program_error("xdp_upgrade_program_info", &error))
            })();
            let staged_program = match initialize_result {
                Ok(program) => program,
                Err(error) => {
                    drop(new_ebpf);
                    let _ = Self::unpin_namespace(&target_dir, true);
                    return Err(unchanged(error));
                }
            };
            let new_program_id = staged_program.id();
            if let Err(error) = Self::verify_staged_namespace(
                interface_dir,
                target_slot,
                &config,
                fence_generation,
                &staged_program,
            ) {
                drop(new_ebpf);
                let _ = Self::unpin_namespace(&target_dir, true);
                return Err(unchanged(error));
            }
            let update_result = (|| {
                let new_program = Self::xdp_program(&mut new_ebpf)?;
                let new_program_fd = new_program
                    .fd()
                    .map_err(|error| program_error("xdp_upgrade_program_fd", &error))?;
                link.replace_program(new_program_fd.as_fd(), &old_program)
                    .map_err(|error| IpsecLbError::io("xdp_upgrade_link_update", error))
            })();
            match update_result {
                Ok(()) => {}
                Err(error) => {
                    drop(new_ebpf);
                    let _ = Self::unpin_namespace(&target_dir, true);
                    return Err(unchanged(error));
                }
            }

            let post_update_identity = link.info();
            let post_update_valid = post_update_identity.as_ref().is_ok_and(|identity| {
                identity.link_id == link_identity.link_id
                    && identity.ifindex == ifindex
                    && identity.program_id == new_program_id
            });

            devices.insert(
                ifindex,
                LoadedDevice {
                    ebpf: new_ebpf,
                    link,
                    map_pin_dir: target_dir,
                    link_pin_path: Some(handoff_path.clone()),
                    lease,
                },
            );

            if !post_update_valid {
                let error = post_update_identity.map_or_else(
                    |error| IpsecLbError::io("xdp_upgrade_link_verify", error),
                    |_| IpsecLbError::XdpUpgradeIndeterminate,
                );
                return Err(HostXdpRuntimeFailure::new(
                    error,
                    HostXdpLinkDisposition::Indeterminate,
                ));
            }

            let mut link_pin_cleanup_error = None;
            match fs::remove_file(&handoff_path) {
                Ok(()) => {
                    if let Some(device) = devices.get_mut(&ifindex) {
                        device.link_pin_path = None;
                    } else {
                        link_pin_cleanup_error = Some(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                }
                Err(error) => {
                    link_pin_cleanup_error =
                        Some(IpsecLbError::io("xdp_upgrade_link_unpin", error));
                }
            }
            let obsolete_cleanup_error =
                Self::cleanup_namespaces_except(interface_dir, target_slot);

            Ok(HostXdpRuntimeAdoption {
                fence_generation,
                link_pin_cleanup_error,
                obsolete_cleanup_error,
            })
        }

        fn complete_upgrade_handoff_cleanup(
            &self,
            ifindex: u32,
            interface_dir: &Path,
        ) -> Result<Option<IpsecLbError>, HostXdpRuntimeFailure> {
            let mut devices = self.devices.lock().map_err(|_| {
                HostXdpRuntimeFailure::new(
                    IpsecLbError::io("xdp_upgrade_cleanup", super::poisoned_lock()),
                    HostXdpLinkDisposition::Unchanged,
                )
            })?;
            let device = devices.get_mut(&ifindex).ok_or_else(|| {
                HostXdpRuntimeFailure::new(
                    IpsecLbError::XdpUpgradeIndeterminate,
                    HostXdpLinkDisposition::Indeterminate,
                )
            })?;
            let _lease = device.lease.as_ref();
            let link_pin_path = device.link_pin_path.as_ref().ok_or_else(|| {
                HostXdpRuntimeFailure::new(
                    IpsecLbError::XdpUpgradeIndeterminate,
                    HostXdpLinkDisposition::Unchanged,
                )
            })?;
            match fs::remove_file(link_pin_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(HostXdpRuntimeFailure::new(
                        IpsecLbError::io("xdp_upgrade_link_unpin", error),
                        HostXdpLinkDisposition::Unchanged,
                    ));
                }
            }
            if link_pin_path.exists() {
                return Err(HostXdpRuntimeFailure::new(
                    IpsecLbError::XdpUpgradeIndeterminate,
                    HostXdpLinkDisposition::Unchanged,
                ));
            }
            device.link_pin_path = None;
            let keep = if device.map_pin_dir == MapNamespaceSlot::A.path(interface_dir) {
                MapNamespaceSlot::A
            } else if device.map_pin_dir == MapNamespaceSlot::B.path(interface_dir) {
                MapNamespaceSlot::B
            } else {
                return Err(HostXdpRuntimeFailure::new(
                    IpsecLbError::XdpUpgradeIndeterminate,
                    HostXdpLinkDisposition::Indeterminate,
                ));
            };
            Ok(Self::cleanup_namespaces_except(interface_dir, keep))
        }

        fn detach(
            &self,
            _interface: &str,
            ifindex: u32,
            interface_dir: &Path,
        ) -> Result<(), HostXdpRuntimeFailure> {
            let mut devices = self.devices.lock().map_err(|_| {
                HostXdpRuntimeFailure::new(
                    IpsecLbError::io("xdp_detach", super::poisoned_lock()),
                    HostXdpLinkDisposition::Indeterminate,
                )
            })?;
            let device = devices.get_mut(&ifindex).ok_or_else(|| {
                HostXdpRuntimeFailure::new(
                    IpsecLbError::XdpUpgradeIndeterminate,
                    HostXdpLinkDisposition::Indeterminate,
                )
            })?;
            let _lease = device.lease.as_ref();
            if let Some(link_pin_path) = &device.link_pin_path {
                fs::remove_file(link_pin_path).map_err(|error| {
                    HostXdpRuntimeFailure::new(
                        IpsecLbError::io("xdp_detach_link_unpin", error),
                        HostXdpLinkDisposition::Unchanged,
                    )
                })?;
                device.link_pin_path = None;
            }
            let held = devices.remove(&ifindex).ok_or_else(|| {
                HostXdpRuntimeFailure::new(
                    IpsecLbError::XdpUpgradeIndeterminate,
                    HostXdpLinkDisposition::Indeterminate,
                )
            })?;
            drop(devices);
            let LoadedDevice {
                ebpf,
                link,
                map_pin_dir,
                link_pin_path: _,
                lease,
            } = held;
            drop(ebpf);
            drop(link);

            let mut cleanup_error = Self::unpin_namespace(&map_pin_dir, true).err();
            for slot in [
                MapNamespaceSlot::Legacy,
                MapNamespaceSlot::A,
                MapNamespaceSlot::B,
            ] {
                let slot_path = slot.path(interface_dir);
                if slot_path == map_pin_dir {
                    continue;
                }
                if let Err(error) = Self::unpin_namespace(&slot_path, slot.remove_directory()) {
                    if cleanup_error.is_none() {
                        cleanup_error = Some(error);
                    }
                }
            }
            drop(lease);
            match cleanup_error {
                Some(error) => Err(HostXdpRuntimeFailure::new(
                    error,
                    HostXdpLinkDisposition::Detached,
                )),
                None => Ok(()),
            }
        }

        fn owner_get(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<Option<[u8; OWNER_VALUE_LEN]>, IpsecLbError> {
            self.with_device(ifindex, "xdp_owner_get", |device| {
                let map = device.ebpf.map(MAP_OWNERS).ok_or_else(|| {
                    IpsecLbError::io("xdp_owners_map", invalid_data("map missing"))
                })?;
                let hash =
                    BpfHashMap::<_, [u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("xdp_owners_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("xdp_owner_get", error)),
                }
            })
        }

        fn owner_insert(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
            value: [u8; OWNER_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            self.with_device(ifindex, "xdp_owner_insert", |device| {
                let map = device.ebpf.map_mut(MAP_OWNERS).ok_or_else(|| {
                    IpsecLbError::io("xdp_owners_map", invalid_data("map missing"))
                })?;
                let mut hash =
                    BpfHashMap::<_, [u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("xdp_owners_map", error))?;
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("xdp_owner_insert", error))
            })
        }

        fn owner_remove(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<bool, IpsecLbError> {
            self.with_device(ifindex, "xdp_owner_remove", |device| {
                let map = device.ebpf.map_mut(MAP_OWNERS).ok_or_else(|| {
                    IpsecLbError::io("xdp_owners_map", invalid_data("map missing"))
                })?;
                let mut hash =
                    BpfHashMap::<_, [u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("xdp_owners_map", error))?;
                match hash.remove(&key) {
                    Ok(()) => Ok(true),
                    Err(MapError::KeyNotFound) => Ok(false),
                    Err(error) => Err(map_error("xdp_owner_remove", error)),
                }
            })
        }

        fn fence_read(&self, ifindex: u32) -> Result<u64, IpsecLbError> {
            self.with_device(ifindex, "xdp_fence_read", |device| {
                let hash = Self::fence_map(&mut device.ebpf)?;
                match hash.get(&FENCE_KEY, 0) {
                    Ok(generation) => Ok(generation),
                    Err(MapError::KeyNotFound) => Ok(0),
                    Err(error) => Err(map_error("xdp_fence_read", error)),
                }
            })
        }

        fn fence_write(&self, ifindex: u32, generation: u64) -> Result<(), IpsecLbError> {
            self.with_device(ifindex, "xdp_fence_write", |device| {
                let mut hash = Self::fence_map(&mut device.ebpf)?;
                hash.insert(FENCE_KEY, generation, 0)
                    .map_err(|error| map_error("xdp_fence_write", error))
            })
        }

        fn counters_read(
            &self,
            ifindex: u32,
        ) -> Result<[u64; COUNTER_SLOTS as usize], IpsecLbError> {
            self.with_device(ifindex, "xdp_counters_read", |device| {
                let map = device.ebpf.map(MAP_COUNTERS).ok_or_else(|| {
                    IpsecLbError::io("xdp_counters_map", invalid_data("map missing"))
                })?;
                let counters = PerCpuArray::<_, u64>::try_from(map)
                    .map_err(|error| map_error("xdp_counters_map", error))?;
                let mut totals = [0_u64; COUNTER_SLOTS as usize];
                for (slot, total) in totals.iter_mut().enumerate() {
                    let values = counters
                        .get(&(slot as u32), 0)
                        .map_err(|error| map_error("xdp_counters_read", error))?;
                    *total = values
                        .iter()
                        .fold(0_u64, |sum, value| sum.saturating_add(*value));
                }
                Ok(totals)
            })
        }

        fn probe_environment(
            &self,
            interface: &str,
            pin_root: &Path,
            redirect_handoff: HostXdpRedirectHandoff,
        ) -> HostXdpEnvironment {
            let target_ifindex = sys::ifindex_by_name(interface)
                .ok()
                .filter(|ifindex| *ifindex != 0);
            let target_interface_ready =
                target_ifindex.is_some_and(|ifindex| link_is_up(ifindex).unwrap_or(false));
            let redirect_handoff_ready = match redirect_handoff {
                HostXdpRedirectHandoff::Disabled => true,
                HostXdpRedirectHandoff::UserspaceRedirector { ifindex } => {
                    Some(ifindex.get()) != target_ifindex
                        && link_is_up(ifindex.get()).unwrap_or(false)
                }
            };
            HostXdpEnvironment {
                platform_supported: true,
                configured_bpffs_present: configured_bpffs_present(pin_root),
                btf_present: Path::new("/sys/kernel/btf/vmlinux").exists(),
                net_admin_capable: effective_capability(CAP_NET_ADMIN).unwrap_or(false),
                bpf_capable: effective_capability(CAP_SYS_ADMIN).unwrap_or(false),
                kernel_release: kernel_release(),
                xdp_load_bytes_supported: is_helper_supported(
                    ProgramType::Xdp,
                    BpfHelper::BPF_FUNC_xdp_load_bytes,
                )
                .unwrap_or(false),
                target_interface_ready,
                redirect_handoff_ready,
            }
        }
    }

    fn configured_bpffs_present(pin_root: &Path) -> bool {
        if !pin_root.is_absolute() {
            return false;
        }
        let mut candidate = Some(pin_root);
        while let Some(path) = candidate {
            match rustix::fs::statfs(path) {
                Ok(status) => return status.f_type as u64 == BPF_FS_MAGIC,
                Err(rustix::io::Errno::NOENT) => candidate = path.parent(),
                Err(_) => return false,
            }
        }
        false
    }

    fn kernel_release() -> Option<(u16, u16)> {
        let release = fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
        let mut components = release.trim().split(|ch: char| !(ch.is_ascii_digit()));
        let major = components.find(|part| !part.is_empty())?.parse().ok()?;
        let minor = components.find(|part| !part.is_empty())?.parse().ok()?;
        Some((major, minor))
    }

    const RTM_GETLINK: u16 = 18;
    const RTM_NEWLINK: u16 = 16;
    const NLMSG_NOOP: u16 = 1;
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_OVERRUN: u16 = 4;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_MULTI: u16 = 2;
    const NLM_F_DUMP_INTR: u16 = 0x10;
    const NLM_F_DUMP: u16 = 0x300;
    const LINK_DUMP_SEQUENCE: u32 = 1;
    const MAX_LINK_DUMP_DATAGRAMS: usize = 256;
    const MAX_LINK_DUMP_MESSAGES: usize = 8_192;
    const MAX_LINK_DUMP_BYTES: usize = 16 * 1024 * 1024;
    const MAX_LINK_DUMP_EMPTY_ATTEMPTS: u32 = 50;
    const IFF_UP: u32 = 0x1;
    const NLMSG_HDR_LEN: usize = 16;
    const IFINFOMSG_LEN: usize = 16;
    const IFLA_XDP: u16 = 43;
    const IFLA_XDP_ATTACHED: u16 = 2;
    const IFLA_XDP_PROG_ID: u16 = 4;
    const XDP_ATTACHED_NONE: u8 = 0;
    const XDP_ATTACHED_DRIVER: u8 = 1;
    const XDP_ATTACHED_SKB: u8 = 2;
    const XDP_ATTACHED_HARDWARE: u8 = 3;
    const XDP_ATTACHED_MULTI: u8 = 4;

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct ParsedXdp {
        program_id: Option<u32>,
        attach_kind: Option<u8>,
    }

    /// Link state for one interface from an `RTM_GETLINK` dump.
    #[derive(Debug, Default, Clone, Copy)]
    struct LinkQuery {
        /// The interface exists in the current netns.
        found: bool,
        /// The interface is administratively up.
        is_up: bool,
        /// Kernel id of the attached XDP program, when one is attached.
        xdp_prog_id: Option<u32>,
        /// Kernel-reported XDP attachment kind for the program.
        xdp_attach_kind: Option<u8>,
    }

    /// Report whether `ifindex` names an existing interface that is
    /// administratively up, via an `RTM_GETLINK` dump in the current netns.
    fn link_is_up(ifindex: u32) -> Result<bool, IpsecLbError> {
        let query = link_query(ifindex)?;
        Ok(query.found && query.is_up)
    }

    /// Kernel id of the XDP program attached to `ifindex`, when any.
    fn attached_prog_id(ifindex: u32) -> Result<Option<u32>, IpsecLbError> {
        Ok(link_query(ifindex)?.xdp_prog_id)
    }

    fn attached_mode(ifindex: u32) -> Result<Option<HostXdpAttachMode>, IpsecLbError> {
        match link_query(ifindex)?.xdp_attach_kind {
            None | Some(XDP_ATTACHED_NONE) => Ok(None),
            Some(XDP_ATTACHED_DRIVER) => Ok(Some(HostXdpAttachMode::Native)),
            Some(XDP_ATTACHED_SKB) => Ok(Some(HostXdpAttachMode::Generic)),
            Some(XDP_ATTACHED_HARDWARE | XDP_ATTACHED_MULTI) | Some(_) => {
                Err(IpsecLbError::XdpUpgradeRequiresDrain)
            }
        }
    }

    /// Query link state for `ifindex` via an `RTM_GETLINK` dump in the
    /// current netns.
    fn link_query(ifindex: u32) -> Result<LinkQuery, IpsecLbError> {
        let socket = sys::open_route_netlink_socket()
            .map_err(|error| IpsecLbError::io("xdp_link_query_open", error))?;
        let local_port_id = socket.port_id();
        let mut request = [0_u8; NLMSG_HDR_LEN + IFINFOMSG_LEN];
        let request_len = request.len() as u32;
        request[0..4].copy_from_slice(&request_len.to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
        request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request[8..12].copy_from_slice(&LINK_DUMP_SEQUENCE.to_ne_bytes());
        request[12..16].copy_from_slice(&local_port_id.to_ne_bytes());
        let sent = sys::send_message(&socket, &request)
            .map_err(|error| IpsecLbError::io("xdp_link_query_send", error))?;
        if sent != request.len() {
            return Err(IpsecLbError::io(
                "xdp_link_query_send",
                io::Error::new(io::ErrorKind::WriteZero, "short netlink request send"),
            ));
        }

        let mut query = LinkQuery::default();
        let mut buffer = [0_u8; 65_536];
        let mut empty_attempts = 0_u32;
        let mut datagrams = 0_usize;
        let mut messages = 0_usize;
        let mut total_bytes = 0_usize;
        loop {
            match sys::receive_message(&socket, &mut buffer) {
                Ok(0) => {
                    empty_attempts = empty_attempts.saturating_add(1);
                    if empty_attempts > MAX_LINK_DUMP_EMPTY_ATTEMPTS {
                        return Err(incomplete_link_dump());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Ok(length) => {
                    empty_attempts = 0;
                    datagrams = datagrams.checked_add(1).ok_or_else(link_dump_limit)?;
                    total_bytes = total_bytes
                        .checked_add(length)
                        .ok_or_else(link_dump_limit)?;
                    if datagrams > MAX_LINK_DUMP_DATAGRAMS || total_bytes > MAX_LINK_DUMP_BYTES {
                        return Err(link_dump_limit());
                    }
                    if parse_link_dump_datagram(
                        &buffer[..length],
                        LINK_DUMP_SEQUENCE,
                        local_port_id,
                        ifindex,
                        &mut messages,
                        &mut query,
                    )? {
                        return Ok(query);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    empty_attempts = empty_attempts.saturating_add(1);
                    if empty_attempts > MAX_LINK_DUMP_EMPTY_ATTEMPTS {
                        return Err(incomplete_link_dump());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) => return Err(IpsecLbError::io("xdp_link_query_recv", error)),
            }
        }
    }

    fn parse_link_dump_datagram(
        datagram: &[u8],
        expected_sequence: u32,
        expected_port_id: u32,
        requested_ifindex: u32,
        messages: &mut usize,
        query: &mut LinkQuery,
    ) -> Result<bool, IpsecLbError> {
        let mut cursor = 0_usize;
        let mut done = false;
        while cursor < datagram.len() {
            if done || datagram.len() - cursor < NLMSG_HDR_LEN {
                return Err(malformed_link_dump());
            }
            let msg_len = read_u32_ne(datagram, cursor)? as usize;
            let msg_end = cursor
                .checked_add(msg_len)
                .ok_or_else(malformed_link_dump)?;
            if msg_len < NLMSG_HDR_LEN || msg_end > datagram.len() {
                return Err(malformed_link_dump());
            }
            *messages = messages.checked_add(1).ok_or_else(link_dump_limit)?;
            if *messages > MAX_LINK_DUMP_MESSAGES {
                return Err(link_dump_limit());
            }
            let msg_type = read_u16_ne(datagram, cursor + 4)?;
            let flags = read_u16_ne(datagram, cursor + 6)?;
            let sequence = read_u32_ne(datagram, cursor + 8)?;
            let port_id = read_u32_ne(datagram, cursor + 12)?;
            if sequence != expected_sequence || port_id != expected_port_id {
                return Err(incomplete_link_dump());
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                return Err(incomplete_link_dump());
            }
            let body = &datagram[cursor + NLMSG_HDR_LEN..msg_end];
            match msg_type {
                NLMSG_DONE => {
                    if flags & NLM_F_MULTI == 0 {
                        return Err(malformed_link_dump());
                    }
                    parse_link_dump_done(body)?;
                    done = true;
                }
                NLMSG_ERROR | NLMSG_OVERRUN => return Err(incomplete_link_dump()),
                NLMSG_NOOP => {
                    if flags & NLM_F_MULTI == 0 || !body.is_empty() {
                        return Err(malformed_link_dump());
                    }
                }
                RTM_NEWLINK => {
                    if flags & NLM_F_MULTI == 0 || body.len() < IFINFOMSG_LEN {
                        return Err(malformed_link_dump());
                    }
                    let index = read_i32_ne(body, 4)?;
                    if index > 0 && index as u32 == requested_ifindex {
                        if query.found {
                            return Err(malformed_link_dump());
                        }
                        query.found = true;
                        query.is_up = read_u32_ne(body, 8)? & IFF_UP != 0;
                        let xdp = parse_xdp_state(&body[IFINFOMSG_LEN..])?;
                        query.xdp_prog_id = xdp.program_id;
                        query.xdp_attach_kind = xdp.attach_kind;
                    } else {
                        // Attribute corruption on any dump member still makes
                        // the absence/collision conclusion non-authoritative.
                        let _ = parse_xdp_state(&body[IFINFOMSG_LEN..])?;
                    }
                }
                _ => return Err(malformed_link_dump()),
            }
            let aligned = msg_len.checked_add(3).ok_or_else(malformed_link_dump)? & !3;
            let aligned_end = cursor
                .checked_add(aligned)
                .ok_or_else(malformed_link_dump)?;
            if aligned_end > datagram.len()
                || datagram[msg_end..aligned_end].iter().any(|byte| *byte != 0)
            {
                return Err(malformed_link_dump());
            }
            cursor = aligned_end;
        }
        Ok(done)
    }

    fn parse_link_dump_done(body: &[u8]) -> Result<(), IpsecLbError> {
        if body.is_empty() {
            return Ok(());
        }
        if body.len() != 4 || read_i32_ne(body, 0)? != 0 {
            return Err(incomplete_link_dump());
        }
        Ok(())
    }

    /// Parse the nested `IFLA_XDP` program id from a link's attribute area.
    fn parse_xdp_state(attributes: &[u8]) -> Result<ParsedXdp, IpsecLbError> {
        let mut cursor = 0_usize;
        let mut xdp = None;
        while cursor < attributes.len() {
            if attributes.len() - cursor < 4 {
                return Err(malformed_link_dump());
            }
            let rta_len = usize::from(read_u16_ne(attributes, cursor)?);
            let rta_type = read_u16_ne(attributes, cursor + 2)? & 0x3fff;
            let rta_end = cursor
                .checked_add(rta_len)
                .ok_or_else(malformed_link_dump)?;
            if rta_len < 4 || rta_end > attributes.len() {
                return Err(malformed_link_dump());
            }
            if rta_type == IFLA_XDP {
                if xdp.is_some() {
                    return Err(malformed_link_dump());
                }
                xdp = Some(parse_xdp_nested(&attributes[cursor + 4..rta_end])?);
            }
            let aligned = rta_len.checked_add(3).ok_or_else(malformed_link_dump)? & !3;
            let aligned_end = cursor
                .checked_add(aligned)
                .ok_or_else(malformed_link_dump)?;
            if aligned_end > attributes.len()
                || attributes[rta_end..aligned_end]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(malformed_link_dump());
            }
            cursor = aligned_end;
        }
        Ok(xdp.unwrap_or_default())
    }

    /// Parse the program id (or attached flag) inside an `IFLA_XDP` nest.
    fn parse_xdp_nested(nest: &[u8]) -> Result<ParsedXdp, IpsecLbError> {
        let mut cursor = 0_usize;
        let mut attached = None;
        let mut program_id = None;
        while cursor < nest.len() {
            if nest.len() - cursor < 4 {
                return Err(malformed_link_dump());
            }
            let rta_len = usize::from(read_u16_ne(nest, cursor)?);
            let rta_type = read_u16_ne(nest, cursor + 2)? & 0x3fff;
            let rta_end = cursor
                .checked_add(rta_len)
                .ok_or_else(malformed_link_dump)?;
            if rta_len < 4 || rta_end > nest.len() {
                return Err(malformed_link_dump());
            }
            match rta_type {
                IFLA_XDP_PROG_ID => {
                    if rta_len != 8 || program_id.is_some() {
                        return Err(malformed_link_dump());
                    }
                    program_id = Some(read_u32_ne(nest, cursor + 4)?);
                }
                IFLA_XDP_ATTACHED => {
                    if rta_len != 5 || attached.is_some() {
                        return Err(malformed_link_dump());
                    }
                    attached = Some(nest[cursor + 4]);
                }
                _ => {}
            }
            let aligned = rta_len.checked_add(3).ok_or_else(malformed_link_dump)? & !3;
            let aligned_end = cursor
                .checked_add(aligned)
                .ok_or_else(malformed_link_dump)?;
            if aligned_end > nest.len() || nest[rta_end..aligned_end].iter().any(|byte| *byte != 0)
            {
                return Err(malformed_link_dump());
            }
            cursor = aligned_end;
        }
        match (attached, program_id.filter(|id| *id != 0)) {
            (Some(XDP_ATTACHED_NONE), Some(_)) => Err(malformed_link_dump()),
            (Some(kind @ (XDP_ATTACHED_DRIVER..=XDP_ATTACHED_MULTI)), Some(id)) => Ok(ParsedXdp {
                program_id: Some(id),
                attach_kind: Some(kind),
            }),
            (Some(XDP_ATTACHED_NONE) | None, None) => Ok(ParsedXdp::default()),
            (Some(_), _) => Err(malformed_link_dump()),
            (None, Some(_)) => Err(malformed_link_dump()),
        }
    }

    fn read_u16_ne(bytes: &[u8], offset: usize) -> Result<u16, IpsecLbError> {
        let raw = bytes
            .get(offset..offset + 2)
            .ok_or_else(malformed_link_dump)?;
        Ok(u16::from_ne_bytes([raw[0], raw[1]]))
    }

    fn read_u32_ne(bytes: &[u8], offset: usize) -> Result<u32, IpsecLbError> {
        let raw = bytes
            .get(offset..offset + 4)
            .ok_or_else(malformed_link_dump)?;
        Ok(u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn read_i32_ne(bytes: &[u8], offset: usize) -> Result<i32, IpsecLbError> {
        let raw = bytes
            .get(offset..offset + 4)
            .ok_or_else(malformed_link_dump)?;
        Ok(i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn malformed_link_dump() -> IpsecLbError {
        IpsecLbError::io(
            "xdp_link_query",
            invalid_data("malformed netlink link dump"),
        )
    }

    fn incomplete_link_dump() -> IpsecLbError {
        IpsecLbError::io(
            "xdp_link_query",
            invalid_data("incomplete netlink link dump"),
        )
    }

    fn link_dump_limit() -> IpsecLbError {
        IpsecLbError::io(
            "xdp_link_query",
            invalid_data("netlink link dump processing limit exceeded"),
        )
    }

    fn effective_capability(capability: u32) -> Result<bool, IpsecLbError> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|error| IpsecLbError::io("capability_probe", error))?;
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                let caps = u64::from_str_radix(hex.trim(), 16).map_err(|_| {
                    IpsecLbError::io("capability_probe", invalid_data("invalid CapEff"))
                })?;
                let mask = 1_u64.checked_shl(capability).ok_or_else(|| {
                    IpsecLbError::io("capability_probe", invalid_data("invalid capability index"))
                })?;
                return Ok((caps & mask) != 0);
            }
        }
        Ok(false)
    }

    fn invalid_data(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn map_error(operation: &'static str, _error: MapError) -> IpsecLbError {
        IpsecLbError::io(operation, invalid_data("BPF map operation failed"))
    }

    fn program_error(operation: &'static str, _error: &ProgramError) -> IpsecLbError {
        IpsecLbError::io(operation, invalid_data("BPF program operation failed"))
    }

    fn link_error(operation: &'static str, _error: &LinkError) -> IpsecLbError {
        IpsecLbError::io(operation, invalid_data("BPF link operation failed"))
    }

    #[cfg(test)]
    mod netlink_tests {
        use super::*;

        const SEQUENCE: u32 = 91;
        const PORT_ID: u32 = 7_321;
        const IFINDEX: u32 = 17;

        fn route_attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
            let length = 4 + payload.len();
            let aligned = (length + 3) & !3;
            let mut attribute = vec![0_u8; aligned];
            attribute[0..2].copy_from_slice(&(length as u16).to_ne_bytes());
            attribute[2..4].copy_from_slice(&kind.to_ne_bytes());
            attribute[4..length].copy_from_slice(payload);
            attribute
        }

        fn netlink_message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
            let length = NLMSG_HDR_LEN + body.len();
            let aligned = (length + 3) & !3;
            let mut message = vec![0_u8; aligned];
            message[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
            message[4..6].copy_from_slice(&kind.to_ne_bytes());
            message[6..8].copy_from_slice(&flags.to_ne_bytes());
            message[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
            message[12..16].copy_from_slice(&PORT_ID.to_ne_bytes());
            message[16..length].copy_from_slice(body);
            message
        }

        fn link_message(ifindex: u32, xdp_program_id: Option<u32>) -> Vec<u8> {
            let mut body = vec![0_u8; IFINFOMSG_LEN];
            body[4..8].copy_from_slice(&(ifindex as i32).to_ne_bytes());
            body[8..12].copy_from_slice(&IFF_UP.to_ne_bytes());
            if let Some(program_id) = xdp_program_id {
                let mut nested = route_attribute(IFLA_XDP_ATTACHED, &[1]);
                nested.extend_from_slice(&route_attribute(
                    IFLA_XDP_PROG_ID,
                    &program_id.to_ne_bytes(),
                ));
                body.extend_from_slice(&route_attribute(IFLA_XDP | 0x8000, &nested));
            }
            netlink_message(RTM_NEWLINK, NLM_F_MULTI, &body)
        }

        fn done_message(status: Option<i32>) -> Vec<u8> {
            let body = status.map_or_else(Vec::new, |status| status.to_ne_bytes().to_vec());
            netlink_message(NLMSG_DONE, NLM_F_MULTI, &body)
        }

        fn parse(datagram: &[u8]) -> Result<(bool, LinkQuery, usize), IpsecLbError> {
            let mut messages = 0;
            let mut query = LinkQuery::default();
            let done = parse_link_dump_datagram(
                datagram,
                SEQUENCE,
                PORT_ID,
                IFINDEX,
                &mut messages,
                &mut query,
            )?;
            Ok((done, query, messages))
        }

        fn assert_query_error(result: Result<(bool, LinkQuery, usize), IpsecLbError>) {
            assert!(matches!(
                result,
                Err(IpsecLbError::Io {
                    operation: "xdp_link_query",
                    ..
                })
            ));
        }

        #[test]
        fn complete_dump_reports_requested_link_and_xdp_program() {
            let mut datagram = link_message(IFINDEX, Some(4_209));
            datagram.extend_from_slice(&link_message(IFINDEX + 1, None));
            datagram.extend_from_slice(&done_message(Some(0)));

            let (done, query, messages) = parse(&datagram).expect("complete link dump");
            assert!(done);
            assert_eq!(messages, 3);
            assert!(query.found);
            assert!(query.is_up);
            assert_eq!(query.xdp_prog_id, Some(4_209));
        }

        #[test]
        fn dump_without_done_never_yields_an_authoritative_result() {
            let datagram = link_message(IFINDEX, None);
            let (done, query, messages) = parse(&datagram).expect("valid partial dump");
            assert!(!done);
            assert!(query.found);
            assert_eq!(messages, 1);
        }

        #[test]
        fn sequence_and_port_mismatch_fail_closed() {
            let mut sequence_mismatch = link_message(IFINDEX, None);
            sequence_mismatch[8..12].copy_from_slice(&(SEQUENCE + 1).to_ne_bytes());
            assert_query_error(parse(&sequence_mismatch));

            let mut port_mismatch = link_message(IFINDEX, None);
            port_mismatch[12..16].copy_from_slice(&(PORT_ID + 1).to_ne_bytes());
            assert_query_error(parse(&port_mismatch));
        }

        #[test]
        fn interrupted_overrun_and_error_dumps_fail_closed() {
            let mut interrupted = link_message(IFINDEX, None);
            interrupted[6..8].copy_from_slice(&(NLM_F_MULTI | NLM_F_DUMP_INTR).to_ne_bytes());
            assert_query_error(parse(&interrupted));

            assert_query_error(parse(&netlink_message(NLMSG_OVERRUN, NLM_F_MULTI, &[])));
            assert_query_error(parse(&netlink_message(NLMSG_ERROR, NLM_F_MULTI, &[0; 4])));
        }

        #[test]
        fn done_requires_multi_and_success_status() {
            assert_query_error(parse(&netlink_message(NLMSG_DONE, 0, &[])));
            assert_query_error(parse(&done_message(Some(-5))));
            let mut trailing = done_message(Some(0));
            trailing.extend_from_slice(&[0, 0, 0, 0]);
            assert_query_error(parse(&trailing));
        }

        #[test]
        fn malformed_lengths_padding_and_duplicate_link_fail_closed() {
            let short_header = vec![0_u8; NLMSG_HDR_LEN - 1];
            assert_query_error(parse(&short_header));

            let mut invalid_length = link_message(IFINDEX, None);
            invalid_length[0..4].copy_from_slice(&((NLMSG_HDR_LEN - 1) as u32).to_ne_bytes());
            assert_query_error(parse(&invalid_length));

            let mut padded = netlink_message(NLMSG_NOOP, NLM_F_MULTI, &[1]);
            *padded.last_mut().expect("alignment padding") = 1;
            assert_query_error(parse(&padded));

            let mut duplicate = link_message(IFINDEX, None);
            duplicate.extend_from_slice(&link_message(IFINDEX, None));
            assert_query_error(parse(&duplicate));
        }

        #[test]
        fn malformed_or_contradictory_xdp_attributes_fail_closed() {
            let mut truncated = vec![0_u8; IFINFOMSG_LEN];
            truncated[4..8].copy_from_slice(&(IFINDEX as i32).to_ne_bytes());
            truncated.extend_from_slice(&[8, 0, IFLA_XDP as u8, 0, 1]);
            assert_query_error(parse(&netlink_message(
                RTM_NEWLINK,
                NLM_F_MULTI,
                &truncated,
            )));

            let attached = route_attribute(IFLA_XDP_ATTACHED, &[0]);
            let program_id = route_attribute(IFLA_XDP_PROG_ID, &9_u32.to_ne_bytes());
            let mut contradictory = vec![0_u8; IFINFOMSG_LEN];
            contradictory[4..8].copy_from_slice(&(IFINDEX as i32).to_ne_bytes());
            let mut nested = attached;
            nested.extend_from_slice(&program_id);
            contradictory.extend_from_slice(&route_attribute(IFLA_XDP | 0x8000, &nested));
            assert_query_error(parse(&netlink_message(
                RTM_NEWLINK,
                NLM_F_MULTI,
                &contradictory,
            )));
        }

        #[test]
        fn message_budget_is_enforced_before_parsing_another_record() {
            let datagram = link_message(IFINDEX, None);
            let mut messages = MAX_LINK_DUMP_MESSAGES;
            let mut query = LinkQuery::default();
            let result = parse_link_dump_datagram(
                &datagram,
                SEQUENCE,
                PORT_ID,
                IFINDEX,
                &mut messages,
                &mut query,
            );
            assert!(matches!(
                result,
                Err(IpsecLbError::Io {
                    operation: "xdp_link_query",
                    ..
                })
            ));
        }

        #[test]
        fn configured_bpffs_probe_rejects_relative_and_non_bpffs_paths() {
            assert!(!configured_bpffs_present(Path::new("relative/pins")));
            assert!(!configured_bpffs_present(&std::env::temp_dir()));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::process::Command;
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    use super::*;
    use crate::model::IpAddress;
    use crate::ownership::{
        DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi,
        EstablishedIkeOwnershipKey, IkeSpi,
    };

    #[derive(Debug, Default)]
    struct TestRuntime {
        state: Mutex<TestState>,
        delay_attach: AtomicBool,
        active_attaches: AtomicUsize,
        max_active_attaches: AtomicUsize,
        #[cfg(target_os = "linux")]
        file_lifecycle_lock: bool,
        #[cfg(target_os = "linux")]
        attach_entered_path: Option<PathBuf>,
        #[cfg(target_os = "linux")]
        attach_release_path: Option<PathBuf>,
    }

    #[derive(Debug)]
    struct TestState {
        ifindex: u32,
        env: HostXdpEnvironment,
        attached: Vec<(String, u32, PathBuf)>,
        prepared_handoffs: usize,
        adopted_handoffs: usize,
        detached: Vec<(String, u32, PathBuf)>,
        config: Option<[u8; CONFIG_VALUE_LEN]>,
        owners: HashMap<(u32, [u8; OWNER_KEY_LEN]), [u8; OWNER_VALUE_LEN]>,
        fences: HashMap<u32, u64>,
        leases: HashMap<u32, Box<dyn HostXdpLifecycleLock>>,
        fence_writes: Vec<u64>,
        link_up: bool,
        foreign_prog_attached: bool,
        live_attached: bool,
        live_mode: HostXdpAttachMode,
        fence_read_error: Option<&'static str>,
        prepare_error: Option<&'static str>,
        adopt_error: Option<&'static str>,
        detach_error_before_drop: Option<&'static str>,
        detach_error_after_drop: Option<&'static str>,
        counters: [u64; COUNTER_SLOTS as usize],
    }

    impl Default for TestState {
        fn default() -> Self {
            Self {
                ifindex: 7,
                env: HostXdpEnvironment {
                    platform_supported: true,
                    configured_bpffs_present: true,
                    btf_present: true,
                    net_admin_capable: true,
                    bpf_capable: true,
                    kernel_release: Some((6, 1)),
                    xdp_load_bytes_supported: true,
                    target_interface_ready: true,
                    redirect_handoff_ready: true,
                },
                attached: Vec::new(),
                prepared_handoffs: 0,
                adopted_handoffs: 0,
                detached: Vec::new(),
                config: None,
                owners: HashMap::new(),
                fences: HashMap::new(),
                leases: HashMap::new(),
                fence_writes: Vec::new(),
                link_up: true,
                foreign_prog_attached: false,
                live_attached: false,
                live_mode: HostXdpAttachMode::Native,
                fence_read_error: None,
                prepare_error: None,
                adopt_error: None,
                detach_error_before_drop: None,
                detach_error_after_drop: None,
                counters: [0; COUNTER_SLOTS as usize],
            }
        }
    }

    impl TestRuntime {
        fn with_env(env: HostXdpEnvironment) -> Self {
            Self {
                state: Mutex::new(TestState {
                    env,
                    ..TestState::default()
                }),
                ..Self::default()
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, TestState> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        #[cfg(target_os = "linux")]
        fn with_process_shared_lifecycle(
            attach_entered_path: PathBuf,
            attach_release_path: Option<PathBuf>,
        ) -> Self {
            Self {
                file_lifecycle_lock: true,
                attach_entered_path: Some(attach_entered_path),
                attach_release_path,
                ..Self::default()
            }
        }
    }

    impl HostXdpRuntime for TestRuntime {
        fn lifecycle_lock(
            &self,
            pin_root: &Path,
        ) -> Result<Box<dyn HostXdpLifecycleLock>, IpsecLbError> {
            #[cfg(target_os = "linux")]
            if self.file_lifecycle_lock {
                return aya_runtime::AyaHostXdpRuntime::new().lifecycle_lock(pin_root);
            }

            #[derive(Debug)]
            struct TestLifecycleLock;
            impl HostXdpLifecycleLock for TestLifecycleLock {}
            Ok(Box::new(TestLifecycleLock))
        }

        fn ifindex_by_name(&self, _name: &str) -> Result<u32, IpsecLbError> {
            Ok(self.state().ifindex)
        }

        fn link_is_up(&self, _ifindex: u32) -> Result<bool, IpsecLbError> {
            Ok(self.state().link_up)
        }

        fn attached_prog_id(&self, _ifindex: u32) -> Result<Option<u32>, IpsecLbError> {
            let state = self.state();
            Ok((state.foreign_prog_attached || state.live_attached).then_some(1))
        }

        fn attached_mode(&self, _ifindex: u32) -> Result<Option<HostXdpAttachMode>, IpsecLbError> {
            let state = self.state();
            Ok((state.foreign_prog_attached || state.live_attached).then_some(state.live_mode))
        }

        fn attach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            mode: HostXdpAttachMode,
            config: [u8; CONFIG_VALUE_LEN],
            lease: Box<dyn HostXdpLifecycleLock>,
        ) -> Result<(), IpsecLbError> {
            let active = self.active_attaches.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_attaches.fetch_max(active, Ordering::SeqCst);
            #[cfg(target_os = "linux")]
            if let Some(entered) = &self.attach_entered_path {
                fs::write(entered, b"entered")
                    .map_err(|error| IpsecLbError::io("xdp_test_attach_entered", error))?;
                if let Some(release) = &self.attach_release_path {
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while !release.exists() {
                        if Instant::now() >= deadline {
                            return Err(IpsecLbError::io(
                                "xdp_test_attach_release",
                                io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "cross-process lifecycle test release timed out",
                                ),
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
            if self.delay_attach.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let mut state = self.state();
            state
                .attached
                .push((interface.to_owned(), ifindex, pin_dir.to_path_buf()));
            state.config = Some(config);
            state.live_attached = true;
            state.live_mode = mode;
            state.leases.insert(ifindex, lease);
            self.active_attaches.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }

        fn prepare_upgrade_handoff(
            &self,
            ifindex: u32,
            _pin_dir: &Path,
        ) -> Result<u64, HostXdpRuntimeFailure> {
            let mut state = self.state();
            if let Some(operation) = state.prepare_error {
                return Err(HostXdpRuntimeFailure::new(
                    IpsecLbError::io(
                        operation,
                        io::Error::new(io::ErrorKind::InvalidData, "injected replace failure"),
                    ),
                    HostXdpLinkDisposition::Unchanged,
                ));
            }
            state
                .owners
                .retain(|(owner_ifindex, _), _| *owner_ifindex != ifindex);
            let fence = state.fences.get(&ifindex).copied().unwrap_or(0);
            state.leases.remove(&ifindex);
            state.prepared_handoffs += 1;
            Ok(fence)
        }

        fn adopt_upgrade_handoff(
            &self,
            ifindex: u32,
            _attached_program_id: u32,
            _pin_dir: &Path,
            _mode: HostXdpAttachMode,
            config: [u8; CONFIG_VALUE_LEN],
            lease: Box<dyn HostXdpLifecycleLock>,
        ) -> Result<HostXdpRuntimeAdoption, HostXdpRuntimeFailure> {
            let mut state = self.state();
            if let Some(operation) = state.adopt_error {
                return Err(HostXdpRuntimeFailure::new(
                    IpsecLbError::io(
                        operation,
                        io::Error::new(io::ErrorKind::InvalidData, "injected adoption failure"),
                    ),
                    HostXdpLinkDisposition::Unchanged,
                ));
            }
            state.config = Some(config);
            state.live_attached = true;
            state.leases.insert(ifindex, lease);
            state.adopted_handoffs += 1;
            Ok(HostXdpRuntimeAdoption {
                fence_generation: state.fences.get(&ifindex).copied().unwrap_or(0),
                link_pin_cleanup_error: None,
                obsolete_cleanup_error: None,
            })
        }

        fn complete_upgrade_handoff_cleanup(
            &self,
            _ifindex: u32,
            _pin_dir: &Path,
        ) -> Result<Option<IpsecLbError>, HostXdpRuntimeFailure> {
            Ok(None)
        }

        fn detach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
        ) -> Result<(), HostXdpRuntimeFailure> {
            let mut state = self.state();
            if let Some(operation) = state.detach_error_before_drop {
                return Err(HostXdpRuntimeFailure::new(
                    IpsecLbError::io(
                        operation,
                        io::Error::new(io::ErrorKind::InvalidData, "injected detach failure"),
                    ),
                    HostXdpLinkDisposition::Unchanged,
                ));
            }
            state
                .detached
                .push((interface.to_owned(), ifindex, pin_dir.to_path_buf()));
            state.live_attached = false;
            state.leases.remove(&ifindex);
            if let Some(operation) = state.detach_error_after_drop {
                return Err(HostXdpRuntimeFailure::new(
                    IpsecLbError::io(
                        operation,
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "injected post-detach cleanup failure",
                        ),
                    ),
                    HostXdpLinkDisposition::Detached,
                ));
            }
            Ok(())
        }

        fn owner_get(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<Option<[u8; OWNER_VALUE_LEN]>, IpsecLbError> {
            Ok(self.state().owners.get(&(ifindex, key)).copied())
        }

        fn owner_insert(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
            value: [u8; OWNER_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            self.state().owners.insert((ifindex, key), value);
            Ok(())
        }

        fn owner_remove(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<bool, IpsecLbError> {
            Ok(self.state().owners.remove(&(ifindex, key)).is_some())
        }

        fn fence_read(&self, ifindex: u32) -> Result<u64, IpsecLbError> {
            let state = self.state();
            if let Some(operation) = state.fence_read_error {
                return Err(IpsecLbError::io(
                    operation,
                    io::Error::new(io::ErrorKind::InvalidData, "injected fence-read failure"),
                ));
            }
            Ok(state.fences.get(&ifindex).copied().unwrap_or(0))
        }

        fn fence_write(&self, ifindex: u32, generation: u64) -> Result<(), IpsecLbError> {
            let mut state = self.state();
            state.fences.insert(ifindex, generation);
            state.fence_writes.push(generation);
            Ok(())
        }

        fn counters_read(
            &self,
            _ifindex: u32,
        ) -> Result<[u64; COUNTER_SLOTS as usize], IpsecLbError> {
            Ok(self.state().counters)
        }

        fn probe_environment(
            &self,
            _interface: &str,
            _pin_root: &Path,
            _redirect_handoff: HostXdpRedirectHandoff,
        ) -> HostXdpEnvironment {
            self.state().env
        }
    }

    fn config() -> HostXdpSteeringBackendConfig {
        HostXdpSteeringBackendConfig {
            self_shard: ShardId::new(1),
            routing_domain: RoutingDomainTag::new(7),
            redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
                ifindex: NonZeroU32::new(42).expect("nonzero"),
            },
            ..HostXdpSteeringBackendConfig::default()
        }
    }

    fn esp_key(spi: u32) -> SessionOwnershipKey {
        SessionOwnershipKey::Esp(EspOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([203, 0, 113, 7]), RoutingDomainTag::new(7)),
            EspEncapsulationKind::UdpEncapsulated,
            EspSpi::new(spi).expect("allocatable SPI"),
        ))
    }

    fn established_key() -> SessionOwnershipKey {
        SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([203, 0, 113, 7]), RoutingDomainTag::new(7)),
            IkeSpi::new(0x1111).expect("nonzero"),
            IkeSpi::new(0x2222).expect("nonzero"),
        ))
    }

    #[tokio::test]
    async fn attach_writes_versioned_config_and_detach_releases() {
        let runtime = Arc::new(TestRuntime::default());
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.attach().await.expect("attach");
        assert_eq!(runtime.state().attached.len(), 1);

        let written = runtime.state().config.expect("config written");
        let decoded = XdpDatapathConfig::decode(&written).expect("valid config encoding");
        assert_eq!(decoded.self_shard, 1);
        assert_eq!(decoded.routing_domain, 7);
        assert_eq!(decoded.handoff_ifindex, 42);

        backend.detach().await.expect("detach");
        assert_eq!(runtime.state().detached.len(), 1);
        assert_eq!(
            backend.counters().await,
            Err(IpsecLbError::NotFound),
            "detached backend must not report counters"
        );
    }

    #[tokio::test]
    async fn default_config_disables_redirect_without_fabricating_an_ifindex() {
        let runtime = Arc::new(TestRuntime::default());
        // An explicit redirect target would consult this value and fail.
        // Disabled must not reinterpret any placeholder as an interface.
        runtime.state().link_up = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            HostXdpSteeringBackendConfig::default(),
        );

        backend
            .attach()
            .await
            .expect("attach with redirect disabled");
        let written = runtime.state().config.expect("config written");
        let decoded = XdpDatapathConfig::decode(&written).expect("valid config encoding");
        assert_eq!(decoded.handoff_ifindex, 0);
    }

    #[tokio::test]
    async fn kernel_floor_is_enforced_with_typed_errors() {
        let mut env = TestState::default().env;

        env.kernel_release = Some((5, 17));
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::XdpKernelFloorNotMet { .. })
        ));

        env = TestState::default().env;
        env.kernel_release = Some((5, 18));
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        backend.attach().await.expect("Linux 5.18 floor");

        env = TestState::default().env;
        env.xdp_load_bytes_supported = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::XdpKernelFloorNotMet { .. })
        ));

        env = TestState::default().env;
        env.btf_present = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::XdpKernelFloorNotMet { .. })
        ));

        env = TestState::default().env;
        env.configured_bpffs_present = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::XdpKernelFloorNotMet { .. })
        ));

        env = TestState::default().env;
        env.target_interface_ready = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::InvalidConfig {
                field: "interface",
                ..
            })
        ));

        env = TestState::default().env;
        env.redirect_handoff_ready = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::InvalidConfig {
                field: "redirect_handoff.ifindex",
                ..
            })
        ));

        env = TestState::default().env;
        env.platform_supported = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert_eq!(backend.attach().await, Err(IpsecLbError::Unsupported));
    }

    #[tokio::test]
    async fn owner_install_readback_update_and_remove_round_trip() {
        let runtime = Arc::new(TestRuntime::default());
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        let key = esp_key(0x00ca_fe00);

        backend
            .install_owner(&key, ShardId::new(2), 5)
            .await
            .expect("install");
        assert_eq!(
            backend.owner_record(&key).await.expect("readback"),
            Some((ShardId::new(2), 5))
        );

        // Upsert: the same key takes a new owner/generation atomically.
        backend
            .install_owner(&key, ShardId::new(1), 6)
            .await
            .expect("update");
        assert_eq!(
            backend.owner_record(&key).await.expect("readback"),
            Some((ShardId::new(1), 6))
        );

        backend.remove_owner(&key).await.expect("remove");
        assert_eq!(backend.owner_record(&key).await.expect("readback"), None);
        assert_eq!(
            backend.remove_owner(&key).await,
            Err(IpsecLbError::NotFound)
        );
    }

    #[tokio::test]
    async fn owner_install_rejects_zero_generation_and_wrong_domain() {
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::default()),
            config(),
        );
        assert!(matches!(
            backend
                .install_owner(&esp_key(0x100), ShardId::new(2), 0)
                .await,
            Err(IpsecLbError::InvalidConfig { .. })
        ));

        let wrong_domain = SessionOwnershipKey::Esp(EspOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([203, 0, 113, 7]), RoutingDomainTag::new(9)),
            EspEncapsulationKind::Native,
            EspSpi::new(0x100).expect("allocatable"),
        ));
        assert!(matches!(
            backend
                .install_owner(&wrong_domain, ShardId::new(2), 1)
                .await,
            Err(IpsecLbError::InvalidConfig { .. })
        ));
    }

    #[tokio::test]
    async fn fence_advances_monotonically_and_rewrites_config() {
        let runtime = Arc::new(TestRuntime::default());
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.advance_fence(5).await.expect("advance");
        assert_eq!(runtime.state().fences.get(&7).copied(), Some(5));
        assert!(matches!(
            backend.advance_fence(5).await,
            Err(IpsecLbError::OwnershipConflict { .. })
        ));
        assert!(matches!(
            backend.advance_fence(4).await,
            Err(IpsecLbError::OwnershipConflict { .. })
        ));
        backend.advance_fence(6).await.expect("advance");
        assert_eq!(runtime.state().fences.get(&7).copied(), Some(6));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_fence_advances_never_regress_the_kernel_fence() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = Arc::new(HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            config(),
        ));
        backend.attach().await.expect("attach");

        let mut tasks = Vec::new();
        for round in 0_u64..16 {
            let backend = backend.clone();
            // Interleave high and low candidates so the monotonicity check
            // races the kernel write on every round.
            let high = 1_000 + round * 2 + 1;
            let low = 1_000 + round * 2;
            tasks.push(tokio::spawn({
                let backend = backend.clone();
                async move { backend.advance_fence(high).await }
            }));
            tasks.push(tokio::spawn(
                async move { backend.advance_fence(low).await },
            ));
        }
        let mut advances = 0_u64;
        for task in tasks {
            if task.await.expect("fence task").is_ok() {
                advances += 1;
            }
        }
        assert!(advances >= 1, "at least one advance must succeed");

        // Every fence value the kernel observed is part of a non-decreasing
        // sequence: no check-then-write race can regress it.
        let writes = runtime.state().fence_writes.clone();
        assert!(!writes.is_empty());
        assert!(
            writes.windows(2).all(|pair| pair[0] < pair[1]),
            "kernel fence writes must be strictly increasing: {writes:?}"
        );
        assert_eq!(
            writes.last().copied(),
            Some(1_000 + 15 * 2 + 1),
            "the highest candidate always wins"
        );
    }

    #[tokio::test]
    async fn install_owner_rejects_generation_older_than_fence() {
        let runtime = Arc::new(TestRuntime::default());
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.advance_fence(10).await.expect("advance");
        assert!(matches!(
            backend
                .install_owner(&esp_key(0x100), ShardId::new(2), 9)
                .await,
            Err(IpsecLbError::InvalidConfig { .. })
        ));
        backend
            .install_owner(&esp_key(0x100), ShardId::new(2), 10)
            .await
            .expect("fence-equal generation is fresh");
    }

    #[tokio::test]
    async fn attach_adopts_persisted_fence() {
        let runtime = Arc::new(TestRuntime::default());
        runtime.state().fences.insert(7, 42);
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.attach().await.expect("attach");
        assert!(matches!(
            backend.advance_fence(42).await,
            Err(IpsecLbError::OwnershipConflict { .. })
        ));
        backend.advance_fence(43).await.expect("advance");
    }

    #[tokio::test]
    async fn lazy_owner_install_adopts_persisted_fence_before_validation() {
        let runtime = Arc::new(TestRuntime::default());
        runtime.state().fences.insert(7, 42);
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        let key = esp_key(0x100);

        assert!(matches!(
            backend.install_owner(&key, ShardId::new(2), 5).await,
            Err(IpsecLbError::InvalidConfig {
                field: "ownership.generation",
                ..
            })
        ));
        assert_eq!(runtime.state().attached.len(), 1);
        assert!(runtime.state().owners.is_empty());

        backend
            .install_owner(&key, ShardId::new(2), 42)
            .await
            .expect("fence-equal generation is fresh after lazy attach");
        assert_eq!(
            backend.owner_record(&key).await.expect("readback"),
            Some((ShardId::new(2), 42))
        );
    }

    #[tokio::test]
    async fn failed_handoff_prepare_preserves_ready_attachment_for_retry() {
        let runtime = Arc::new(TestRuntime::default());
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.attach().await.expect("attach");
        assert_eq!(runtime.state().attached.len(), 1);

        runtime.state().prepare_error = Some("xdp_upgrade_prepare");
        let error = backend
            .prepare_upgrade_handoff()
            .await
            .expect_err("injected failure");
        assert_eq!(error.raw_os_error(), None);

        // A pre-pin failure leaves the original bpf_link live and tracked.
        // Attach is idempotent and does not collide with or duplicate it.
        backend
            .attach()
            .await
            .expect("existing attachment remains ready");
        assert_eq!(runtime.state().attached.len(), 1);
        assert!(runtime.state().live_attached);

        runtime.state().prepare_error = None;
        backend
            .prepare_upgrade_handoff()
            .await
            .expect("prepare retry");
        assert_eq!(runtime.state().prepared_handoffs, 1);

        let successor =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        assert!(matches!(
            successor
                .adopt_upgrade_handoff()
                .await
                .expect("adopt prepared handoff"),
            HostXdpUpgradeOutcome::Applied
        ));
        assert_eq!(runtime.state().adopted_handoffs, 1);
        successor.detach().await.expect("detach adopted attachment");
        assert!(!runtime.state().live_attached);
    }

    #[tokio::test]
    async fn failed_handoff_adopt_before_link_update_is_retryable() {
        let runtime = Arc::new(TestRuntime::default());
        let predecessor =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        predecessor.attach().await.expect("attach");
        predecessor
            .prepare_upgrade_handoff()
            .await
            .expect("prepare handoff");

        let successor =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        runtime.state().adopt_error = Some("xdp_upgrade_stage");
        let error = successor
            .adopt_upgrade_handoff()
            .await
            .expect_err("injected pre-update adoption failure");
        assert_eq!(error.raw_os_error(), None);
        assert_eq!(runtime.state().adopted_handoffs, 0);
        assert!(runtime.state().live_attached);

        runtime.state().adopt_error = None;
        assert!(matches!(
            successor
                .adopt_upgrade_handoff()
                .await
                .expect("adoption retry"),
            HostXdpUpgradeOutcome::Applied
        ));
        assert_eq!(runtime.state().adopted_handoffs, 1);
    }

    #[test]
    fn configured_attach_mode_accepts_only_compatible_live_modes() {
        assert!(mode_accepts_live(
            HostXdpAttachMode::Native,
            Some(HostXdpAttachMode::Native)
        ));
        assert!(mode_accepts_live(
            HostXdpAttachMode::Native,
            Some(HostXdpAttachMode::Generic)
        ));
        assert!(mode_accepts_live(
            HostXdpAttachMode::Generic,
            Some(HostXdpAttachMode::Generic)
        ));
        assert!(!mode_accepts_live(
            HostXdpAttachMode::Generic,
            Some(HostXdpAttachMode::Native)
        ));
        assert!(!mode_accepts_live(HostXdpAttachMode::Native, None));
        assert!(!mode_accepts_live(HostXdpAttachMode::Generic, None));
    }

    #[tokio::test]
    async fn handoff_rejects_incompatible_live_mode_without_adoption_mutation() {
        let runtime = Arc::new(TestRuntime::default());
        let predecessor =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        predecessor
            .attach()
            .await
            .expect("attach native predecessor");
        predecessor
            .prepare_upgrade_handoff()
            .await
            .expect("prepare handoff");

        let mut successor_config = config();
        successor_config.attach_mode = HostXdpAttachMode::Generic;
        let successor = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            successor_config,
        );
        assert!(matches!(
            successor.adopt_upgrade_handoff().await,
            Err(IpsecLbError::XdpUpgradeRequiresDrain)
        ));
        assert_eq!(runtime.state().adopted_handoffs, 0);
        assert!(runtime.state().live_attached);
        assert_eq!(runtime.state().live_mode, HostXdpAttachMode::Native);
    }

    #[tokio::test]
    async fn native_default_adopts_a_kernel_selected_generic_link() {
        let runtime = Arc::new(TestRuntime::default());
        let mut predecessor_config = config();
        predecessor_config.attach_mode = HostXdpAttachMode::Generic;
        let predecessor = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            predecessor_config,
        );
        predecessor
            .attach()
            .await
            .expect("attach generic predecessor");
        predecessor
            .prepare_upgrade_handoff()
            .await
            .expect("prepare handoff");

        let successor =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        assert!(matches!(
            successor
                .adopt_upgrade_handoff()
                .await
                .expect("native/default accepts live SKB mode"),
            HostXdpUpgradeOutcome::Applied
        ));
        assert_eq!(runtime.state().live_mode, HostXdpAttachMode::Generic);
    }

    #[tokio::test]
    async fn failed_initial_fence_read_rolls_back_live_attachment() {
        let runtime = Arc::new(TestRuntime::default());
        runtime.state().fence_read_error = Some("xdp_fence_read");
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());

        backend
            .attach()
            .await
            .expect_err("injected fence read must fail attach");
        {
            let state = runtime.state();
            assert!(!state.live_attached, "rollback must drop the live bpf_link");
            assert_eq!(state.detached.len(), 1);
        }

        runtime.state().fence_read_error = None;
        backend.attach().await.expect("clean retry after rollback");
        assert_eq!(runtime.state().attached.len(), 2);
    }

    #[tokio::test]
    async fn failed_initial_fence_read_retains_live_attachment_when_rollback_cannot_drop_it() {
        let runtime = Arc::new(TestRuntime::default());
        {
            let mut state = runtime.state();
            state.fence_read_error = Some("xdp_fence_read");
            state.detach_error_before_drop = Some("xdp_detach");
        }
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());

        backend
            .attach()
            .await
            .expect_err("fence failure with failed rollback must be visible");
        assert!(runtime.state().live_attached);

        // The attachment is tracked as awaiting its persisted fence. Once the
        // read path recovers it is adopted, never attached a second time.
        {
            let mut state = runtime.state();
            state.fence_read_error = None;
            state.detach_error_before_drop = None;
        }
        backend.attach().await.expect("adopt retained attachment");
        assert_eq!(runtime.state().attached.len(), 1);
        backend.detach().await.expect("detach retained attachment");
        assert!(!runtime.state().live_attached);
    }

    #[tokio::test]
    async fn post_detach_cleanup_failure_clears_host_attachment_state() {
        let runtime = Arc::new(TestRuntime::default());
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.attach().await.expect("attach");
        runtime.state().detach_error_after_drop = Some("xdp_map_unpin");

        backend
            .detach()
            .await
            .expect_err("pin cleanup failure remains observable");
        assert!(!runtime.state().live_attached);

        runtime.state().detach_error_after_drop = None;
        backend
            .attach()
            .await
            .expect("host state must permit a clean reattach");
        assert_eq!(runtime.state().attached.len(), 2);
    }

    #[tokio::test]
    async fn attach_rejects_invalid_handoff_ifindex() {
        let runtime = Arc::new(TestRuntime::default());
        runtime.state().link_up = false;
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::InvalidConfig {
                field: "redirect_handoff.ifindex",
                ..
            })
        ));
        assert!(runtime.state().attached.is_empty());

        let runtime = Arc::new(TestRuntime::default());
        runtime.state().ifindex = 42;
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::InvalidConfig {
                field: "redirect_handoff.ifindex",
                ..
            })
        ));
        assert!(runtime.state().attached.is_empty());
    }

    #[tokio::test]
    async fn attach_on_occupied_interface_conflicts_without_touching_state() {
        let runtime = Arc::new(TestRuntime::default());
        runtime.state().foreign_prog_attached = true;
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        assert_eq!(backend.attach().await, Err(IpsecLbError::AlreadyExists));
        let state = runtime.state();
        assert!(
            state.attached.is_empty(),
            "runtime.attach must never run for an occupied interface"
        );
        assert!(state.config.is_none(), "no config write may leak through");
        assert!(state.owners.is_empty(), "no owner flush may leak through");
        assert!(state.fence_writes.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_attach_calls_execute_one_lifecycle_mutation() {
        let runtime = Arc::new(TestRuntime::default());
        runtime.delay_attach.store(true, Ordering::SeqCst);
        let backend = Arc::new(HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            config(),
        ));
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let backend = backend.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                backend.attach().await
            }));
        }
        barrier.wait().await;
        for task in tasks {
            task.await.expect("attach task").expect("attach");
        }

        assert_eq!(runtime.state().attached.len(), 1);
        assert_eq!(runtime.max_active_attaches.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_shared_lifecycle_lock_is_busy_then_retryable() {
        const CHILD_ROOT_ENV: &str = "OPC_XDP_LIFECYCLE_LOCK_CHILD_ROOT";
        const EXACT_TEST: &str = "xdp::tests::process_shared_lifecycle_lock_is_busy_then_retryable";

        if let Some(root) = std::env::var_os(CHILD_ROOT_ENV) {
            let root = PathBuf::from(root);
            let runtime = Arc::new(TestRuntime::with_process_shared_lifecycle(
                root.join("child-entered"),
                Some(root.join("release-child")),
            ));
            let mut backend_config = config();
            backend_config.bpffs_pin_root = root;
            let backend =
                HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime, backend_config);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("child runtime")
                .block_on(backend.attach())
                .expect("child attach after release");
            return;
        }

        let root =
            std::env::temp_dir().join(format!("opc-xdp-process-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create lifecycle test root");
        let child_entered = root.join("child-entered");
        let parent_entered = root.join("parent-entered");
        let release_child = root.join("release-child");

        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args(["--exact", EXACT_TEST, "--nocapture", "--test-threads=1"])
            .env(CHILD_ROOT_ENV, &root)
            .spawn()
            .expect("spawn lifecycle-lock child");

        let child_deadline = Instant::now() + Duration::from_secs(10);
        while !child_entered.exists() && Instant::now() < child_deadline {
            if child.try_wait().expect("poll child").is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !child_entered.exists() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&root);
            panic!("child never entered the attach mutation while holding flock");
        }

        let parent_runtime = Arc::new(TestRuntime::with_process_shared_lifecycle(
            parent_entered.clone(),
            None,
        ));
        let mut parent_config = config();
        parent_config.bpffs_pin_root = root.clone();
        let parent_backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", parent_runtime, parent_config);
        let parent_tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("parent runtime");
        let first_result = parent_tokio.block_on(parent_backend.attach());
        assert_eq!(first_result, Err(IpsecLbError::XdpLifecycleBusy));
        assert!(
            !parent_entered.exists(),
            "a busy contender must not enter the lifecycle mutation"
        );

        fs::write(&release_child, b"release").expect("release child attach");
        let child_status = child.wait().expect("wait for lifecycle-lock child");
        assert!(child_status.success(), "lock-holder child must succeed");

        parent_tokio
            .block_on(parent_backend.attach())
            .expect("fresh retry after child releases flock");
        assert!(
            parent_entered.exists(),
            "the retry must enter only after the lease is released"
        );
        parent_tokio
            .block_on(parent_backend.detach())
            .expect("detach parent before harness cleanup");
        assert!(
            root.join("swu0").join(".control").is_dir(),
            "SDK detach must preserve the permanent lifecycle-lock inode"
        );
        drop(parent_backend);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_lease_is_not_inherited_across_exec() {
        let root =
            std::env::temp_dir().join(format!("opc-xdp-lifecycle-cloexec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create lifecycle test root");
        let interface_dir = root.join("swu0");
        let runtime = aya_runtime::AyaHostXdpRuntime::new();
        let lease = runtime
            .lifecycle_lock(&interface_dir)
            .expect("acquire initial lease");
        let mut child = Command::new("sh")
            .args(["-c", "sleep 2"])
            .spawn()
            .expect("spawn exec child");

        drop(lease);
        let replacement = runtime
            .lifecycle_lock(&interface_dir)
            .expect("exec child must not retain close-on-exec lease");
        assert!(
            child.try_wait().expect("poll exec child").is_none(),
            "the replacement lease must be acquired while the exec child remains alive"
        );

        drop(replacement);
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn attach_enforces_capability_floor() {
        let mut env = TestState::default().env;
        env.net_admin_capable = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::XdpKernelFloorNotMet { .. })
        ));

        let mut env = TestState::default().env;
        env.bpf_capable = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        assert!(matches!(
            backend.attach().await,
            Err(IpsecLbError::XdpKernelFloorNotMet { .. })
        ));
    }

    #[test]
    fn interface_name_rejects_dot_segments() {
        assert!(validate_interface_name(".").is_err());
        assert!(validate_interface_name("..").is_err());
        assert!(validate_interface_name("swu0").is_ok());
    }

    #[tokio::test]
    async fn counters_map_slots_to_named_verdicts() {
        let runtime = Arc::new(TestRuntime::default());
        {
            let mut state = runtime.state();
            state.counters[COUNTER_PASS_NON_SWU as usize] = 1;
            state.counters[COUNTER_LOCAL as usize] = 2;
            state.counters[COUNTER_REDIRECT as usize] = 3;
            state.counters[COUNTER_MISS as usize] = 4;
            state.counters[COUNTER_STALE as usize] = 5;
            state.counters[COUNTER_UNCLASSIFIABLE as usize] = 6;
            state.counters[COUNTER_ERROR as usize] = 7;
            state.counters[COUNTER_NATT_KEEPALIVE as usize] = 8;
        }
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.attach().await.expect("attach");
        let counters = backend.counters().await.expect("counters");
        assert_eq!(counters.pass_non_swu, 1);
        assert_eq!(counters.local, 2);
        assert_eq!(counters.redirect, 3);
        assert_eq!(counters.miss, 4);
        assert_eq!(counters.stale, 5);
        assert_eq!(counters.unclassifiable, 6);
        assert_eq!(counters.error, 7);
        assert_eq!(counters.natt_keepalive, 8);
        assert_eq!(counters.total(), 36);
    }

    #[tokio::test]
    async fn handoff_requires_attach_and_adopts_the_prepared_link() {
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::default()),
            config(),
        );
        assert_eq!(
            backend.prepare_upgrade_handoff().await,
            Err(IpsecLbError::NotFound)
        );

        let runtime = Arc::new(TestRuntime::default());
        let predecessor =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        predecessor.attach().await.expect("attach");
        predecessor
            .prepare_upgrade_handoff()
            .await
            .expect("prepare");
        let successor =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        assert!(matches!(
            successor.adopt_upgrade_handoff().await.expect("adopt"),
            HostXdpUpgradeOutcome::Applied
        ));
        let state = runtime.state();
        assert_eq!(state.prepared_handoffs, 1);
        assert_eq!(state.adopted_handoffs, 1);
    }

    #[tokio::test]
    async fn probe_reports_floor_and_capability_details() {
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::default()),
            config(),
        );
        let probe = backend.probe().await.expect("probe");
        assert_eq!(probe.kind, SteeringBackendKind::HostXdp);
        assert!(probe.mutation_ready);
        assert!(probe.key_material_free);

        let mut env = TestState::default().env;
        env.kernel_release = Some((4, 19));
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        let probe = backend.probe().await.expect("probe");
        assert!(!probe.mutation_ready);

        let mut env = TestState::default().env;
        env.configured_bpffs_present = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        let probe = backend.probe().await.expect("probe");
        assert!(!probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some("configured pin root is not inside a bpffs mount")
        );

        let mut env = TestState::default().env;
        env.target_interface_ready = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        let probe = backend.probe().await.expect("probe");
        assert!(!probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some("configured XDP attachment interface is absent or down")
        );

        let mut env = TestState::default().env;
        env.redirect_handoff_ready = false;
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::with_env(env)),
            config(),
        );
        let probe = backend.probe().await.expect("probe");
        assert!(!probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some(
                "configured redirect hand-off interface is absent, down, or conflicts with the attachment interface"
            )
        );
    }

    #[test]
    fn public_host_xdp_debug_redacts_topology() {
        let unique_interface = "swu-secret-936104";
        let unique_pin_root = PathBuf::from("/secret/pins/718204");
        let mut backend_config = config();
        backend_config.bpffs_pin_root = unique_pin_root.clone();
        backend_config.self_shard = ShardId::new(61_283);
        backend_config.routing_domain = RoutingDomainTag::new(9_304_701_823);
        backend_config.redirect_handoff = HostXdpRedirectHandoff::UserspaceRedirector {
            ifindex: NonZeroU32::new(97_531).expect("nonzero"),
        };

        let config_debug = format!("{backend_config:?}");
        let unique_pin_root = unique_pin_root.to_string_lossy().into_owned();
        for secret in [unique_pin_root.as_str(), "61283", "9304701823", "97531"] {
            assert!(!config_debug.contains(secret), "debug leaked {secret}");
        }

        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            unique_interface,
            Arc::new(TestRuntime::default()),
            backend_config,
        );
        let backend_debug = format!("{backend:?}");
        assert!(!backend_debug.contains(unique_interface));
    }

    #[test]
    fn owner_map_key_wraps_canonical_bytes() {
        let key = established_key();
        let canonical = key.to_canonical_bytes();
        let map_key = owner_map_key(&key);
        assert_eq!(usize::from(map_key[0]), canonical.len());
        assert_eq!(&map_key[1..1 + canonical.len()], canonical.as_slice());
        assert!(map_key[1 + canonical.len()..].iter().all(|byte| *byte == 0));
    }
}
