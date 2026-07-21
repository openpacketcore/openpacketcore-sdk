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
//! The legacy global fence and destination-scoped fences live in separate
//! maps, so each replacement publishes an old-or-new `u64`. Attach adopts
//! pinned maps across process restarts without re-arming them: global mode
//! stages no owners, while destination-scoped mode turns every complete
//! owner/fence pair into a stale owner-only activation witness and preserves
//! owner-only or fence-only conflict witnesses. The config and normalized
//! recovery state are read back before the program is attached.
//!
//! The per-interface directory and its `control` subdirectory are permanent
//! lifecycle-lock identity. Operators must never remove or rename either
//! while any backend process may still be alive: doing so can create two
//! independently locked inodes. Use SDK detach/recovery to clean documented
//! map/link pins. Manual recovery requires first quiescing every backend
//! process, then removing only those documented pins; the fully quiesced
//! deployment owner may remove the directory afterward. Lease descriptors
//! are close-on-exec, but a raw `fork` child that neither `exec`s nor closes
//! inherited descriptors retains the lease and is unsupported.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use opc_ipsec_lb_ebpf_common::{
    XdpDatapathConfig, XdpFenceMode, XdpOwnerValue, CONFIG_KEY, CONFIG_VALUE_LEN, COUNTER_ERROR,
    COUNTER_LOCAL, COUNTER_MISS, COUNTER_NATT_KEEPALIVE, COUNTER_PASS_NON_SWU, COUNTER_REDIRECT,
    COUNTER_SLOTS, COUNTER_STALE, COUNTER_UNCLASSIFIABLE, FENCE_KEY, MAP_CONFIG, MAP_COUNTERS,
    MAP_FENCE, MAP_KEY_FENCES, MAP_OWNERS, OWNERSHIP_KEY_MAX_ENCODED_BYTES, OWNER_KEY_LEN,
    OWNER_VALUE_LEN, PROG_SWU_XDP, XDP_CONFIG_ABI_VERSION, XDP_MIN_KERNEL_RELEASE,
};
use sha2::{Digest, Sha256};

use crate::error::IpsecLbError;
use crate::model::{ShardId, SteeringBackendKind, SteeringProbe};
use crate::ownership::{RoutingDomainTag, SessionOwnershipKey};
use crate::ports::{RePinSteeringBackend, RePinSteeringRetirementBackend};
use crate::repin::{OwnershipRetirementGrant, RePinSteeringOperationPermit, RePinSteeringUpdate};

/// Default bpffs directory under which per-interface map pins are created.
pub const DEFAULT_BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/opc-ipsec-lb";

/// Fixed bound on process-local per-key operation serialization state.
const REPIN_OPERATION_STRIPES: usize = 256;

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
    /// Implementations must normalize every adopted owner into a non-live
    /// state and write `config` before the program is attached. Global mode
    /// stages no owners; destination-scoped mode may retain owner-only or
    /// fence-only recovery witnesses, but never a live pair.
    fn attach(
        &self,
        interface: &str,
        ifindex: u32,
        pin_dir: &Path,
        mode: HostXdpAttachMode,
        config: [u8; CONFIG_VALUE_LEN],
        lease: Box<dyn HostXdpLifecycleLock>,
    ) -> Result<(), IpsecLbError>;

    /// Quiesce owner mutation, make every owner record non-live and verify the
    /// recovery witnesses, pin a duplicate reference to the live link, and
    /// release the lifetime lease.
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

    /// Read one destination-scoped ownership fence generation.
    fn key_fence_read(
        &self,
        ifindex: u32,
        key: [u8; OWNER_KEY_LEN],
    ) -> Result<Option<u64>, IpsecLbError>;

    /// Publish one destination-scoped ownership fence generation.
    fn key_fence_write(
        &self,
        ifindex: u32,
        key: [u8; OWNER_KEY_LEN],
        generation: u64,
    ) -> Result<(), IpsecLbError>;

    /// Remove one destination-scoped ownership fence; returns whether it existed.
    ///
    /// This is deliberately private to the runtime boundary. Public callers
    /// cannot delete fencing evidence outside the backend's fail-closed
    /// activation and retirement protocols.
    fn key_fence_remove(
        &self,
        ifindex: u32,
        key: [u8; OWNER_KEY_LEN],
    ) -> Result<bool, IpsecLbError>;

    /// Remove and prove absent the current v5 config entry, forcing every
    /// packet through the datapath's fail-closed missing-config path.
    ///
    /// This is an emergency backend-wide cut used only when an indeterminate
    /// dual map failure could otherwise leave an old owner/fence pair live.
    fn quiesce_repin(&self, ifindex: u32) -> Result<(), IpsecLbError>;

    /// Prove that pinned state can be admitted or migrated for keyed re-pin.
    fn repin_pins_feasible(
        &self,
        pin_dir: &Path,
        config: &[u8; CONFIG_VALUE_LEN],
    ) -> Result<(), IpsecLbError>;

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

/// Ownership-generation domain enforced by the Host-XDP writer.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostXdpFenceDomain {
    /// Legacy deployment-wide floor advanced explicitly with
    /// [`HostXdpSteeringBackend::advance_fence`].
    #[default]
    Global,
    /// Independent monotonic generations for each destination-scoped key.
    ///
    /// The backend holds the exclusive per-interface lifecycle lease and
    /// resets the legacy global datapath floor to zero. Restart recovery keeps
    /// exact owner identities but withholds their per-key fence, so every
    /// recovered entry remains stale until the same authoritative transition
    /// completes fence-last activation. Generation regression and ambiguous
    /// same-generation ownership fail closed. This domain is required by
    /// [`crate::RePinCoordinator`] because one session contains multiple
    /// independently fenced SAs.
    PerOwnershipKey,
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
    /// Generation domain for owner replacement.
    pub fence_domain: HostXdpFenceDomain,
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
            fence_domain: HostXdpFenceDomain::Global,
            redirect_handoff: HostXdpRedirectHandoff::Disabled,
            attach_mode: HostXdpAttachMode::default(),
        }
    }
}

impl HostXdpSteeringBackendConfig {
    /// Select destination-scoped fencing required by same-SPI re-pin.
    ///
    /// The default remains the legacy global floor for compatibility. A
    /// composition root that wires [`crate::RePinCoordinator`] to Host-XDP
    /// must opt in through this constructor and admit
    /// [`HostXdpSteeringBackend::probe_repin`] rather than the generic
    /// steering probe.
    #[must_use]
    pub fn for_destination_scoped_repin(mut self) -> Self {
        self.fence_domain = HostXdpFenceDomain::PerOwnershipKey;
        self
    }
}

impl fmt::Debug for HostXdpSteeringBackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostXdpSteeringBackendConfig")
            .field("bpffs_pin_root", &"<redacted>")
            .field("self_shard", &"<redacted>")
            .field("routing_domain", &"<redacted>")
            .field("fence_domain", &self.fence_domain)
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
    repin_identity: Arc<()>,
    repin_stripes: Vec<Arc<HostXdpRePinStripe>>,
    state: Mutex<HostXdpState>,
}

struct HostXdpRePinStripe {
    gate: Arc<tokio::sync::Mutex<()>>,
    poisoned: AtomicBool,
}

struct HostXdpRePinPermitEvidence {
    backend_identity: Arc<()>,
    stripe: Arc<HostXdpRePinStripe>,
    ownership_key: SessionOwnershipKey,
    _guards: Arc<HostXdpRePinGuardSet>,
    poison_if_unclassified: bool,
    retirement_classified: bool,
}

struct HostXdpRePinGuardSet {
    _guards: Vec<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for HostXdpRePinPermitEvidence {
    fn drop(&mut self) {
        if self.poison_if_unclassified && !self.retirement_classified {
            self.stripe.poisoned.store(true, Ordering::Release);
        }
    }
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
        let repin_stripes = (0..REPIN_OPERATION_STRIPES)
            .map(|_| {
                Arc::new(HostXdpRePinStripe {
                    gate: Arc::new(tokio::sync::Mutex::new(())),
                    poisoned: AtomicBool::new(false),
                })
            })
            .collect();
        Self {
            inner: Arc::new(HostXdpSteeringBackendInner {
                interface: interface.into(),
                runtime,
                config,
                operation_gate: Mutex::new(()),
                repin_identity: Arc::new(()),
                repin_stripes,
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
    /// mutation boundary, and verifies every owner is non-live. Global mode
    /// empties the owner map; destination-scoped mode removes matching fences
    /// and retains owner-only recovery witnesses. It then pins a duplicate
    /// reference to the live XDP link and releases its per-interface lifetime
    /// lease. The old process must keep its userspace slow path available until
    /// the new process reports readiness. This backend cannot be resumed after
    /// a successful call.
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
    /// with non-regressing, non-live recovery witnesses before
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

    /// Remove one legacy/global-fence owner record.
    ///
    /// Destination-scoped mode rejects this unfenced operation. Keyed owner
    /// and fence retirement requires the authoritative durable retirement
    /// boundary; deleting only the owner would leak fencing state and make a
    /// partial failure impossible to recover safely.
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

    /// Converge one coordinator-issued fenced re-pin owner and verify exact
    /// kernel-map readback before reporting success.
    ///
    /// The operation first removes and proves the keyed fence absent, then
    /// removes the old owner, stages and reads back the new owner while fence
    /// absence keeps the datapath stale, and finally publishes and reads back
    /// the exact destination-scoped fence as the activation point. Every step
    /// runs under the same serialized writer gate. Equal-generation conflicts
    /// retain a non-live map witness so the same grant can never overwrite a
    /// different owner. Exact retry is idempotent.
    pub async fn apply_fenced_repin_owner(
        &self,
        update: RePinSteeringUpdate,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        self.run_blocking("host_xdp_apply_fenced_repin_owner", move |backend| {
            backend.apply_fenced_repin_owner_sync(update, permit)
        })
        .await
    }

    async fn acquire_host_repin_permit(
        &self,
        ownership_key: SessionOwnershipKey,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        self.validate_repin_key(&ownership_key)?;
        let stripe = self.repin_stripe(&ownership_key);
        if stripe.poisoned.load(Ordering::Acquire) {
            return Err(IpsecLbError::adapter_contract_violation(
                "host_xdp_repin_operation_stripe_poisoned",
            ));
        }
        let guard = Arc::clone(&stripe.gate).lock_owned().await;
        if stripe.poisoned.load(Ordering::Acquire) {
            return Err(IpsecLbError::adapter_contract_violation(
                "host_xdp_repin_operation_stripe_poisoned",
            ));
        }
        let guards = Arc::new(HostXdpRePinGuardSet {
            _guards: vec![guard],
        });
        let evidence = HostXdpRePinPermitEvidence {
            backend_identity: Arc::clone(&self.inner.repin_identity),
            stripe,
            ownership_key,
            _guards: guards,
            poison_if_unclassified: false,
            retirement_classified: false,
        };
        let permit = RePinSteeringOperationPermit::guarded(ownership_key, evidence);
        self.run_blocking("host_xdp_repin_permit_preflight", move |backend| {
            backend.ensure_repin_ready_sync(&ownership_key)?;
            Ok(permit)
        })
        .await
    }

    async fn acquire_host_repin_retirement_permits(
        &self,
        ownership_keys: Vec<SessionOwnershipKey>,
    ) -> Result<Vec<RePinSteeringOperationPermit>, IpsecLbError> {
        if ownership_keys.is_empty()
            || ownership_keys.len() > crate::session_repin::MAX_SESSION_REPIN_SAS
        {
            return Err(IpsecLbError::invalid_config(
                "session_repin.ownership_keys",
                "retirement permit batch is empty or exceeds the session bound",
            ));
        }
        let mut unique_keys = BTreeSet::new();
        for key in &ownership_keys {
            self.validate_repin_key(key)?;
            if !unique_keys.insert(*key) {
                return Err(IpsecLbError::adapter_contract_violation(
                    "host_xdp_repin_retirement_duplicate_key",
                ));
            }
        }
        let mut stripe_indexes = ownership_keys
            .iter()
            .map(|key| self.repin_stripe_index(key))
            .collect::<Vec<_>>();
        stripe_indexes.sort_unstable();
        stripe_indexes.dedup();

        for index in &stripe_indexes {
            if self.inner.repin_stripes[*index]
                .poisoned
                .load(Ordering::Acquire)
            {
                return Err(IpsecLbError::adapter_contract_violation(
                    "host_xdp_repin_operation_stripe_poisoned",
                ));
            }
        }
        let mut guards = Vec::with_capacity(stripe_indexes.len());
        for index in &stripe_indexes {
            guards.push(
                Arc::clone(&self.inner.repin_stripes[*index])
                    .gate
                    .clone()
                    .lock_owned()
                    .await,
            );
        }
        for index in &stripe_indexes {
            if self.inner.repin_stripes[*index]
                .poisoned
                .load(Ordering::Acquire)
            {
                return Err(IpsecLbError::adapter_contract_violation(
                    "host_xdp_repin_operation_stripe_poisoned",
                ));
            }
        }

        let guards = Arc::new(HostXdpRePinGuardSet { _guards: guards });
        let mut permits = Vec::with_capacity(ownership_keys.len());
        for key in ownership_keys {
            let evidence = HostXdpRePinPermitEvidence {
                backend_identity: Arc::clone(&self.inner.repin_identity),
                stripe: self.repin_stripe(&key),
                ownership_key: key,
                _guards: Arc::clone(&guards),
                poison_if_unclassified: false,
                retirement_classified: false,
            };
            permits.push(RePinSteeringOperationPermit::guarded(key, evidence));
        }

        if let Some(first) = permits.first() {
            let key = first.ownership_key();
            self.run_blocking("host_xdp_repin_permit_preflight", move |backend| {
                backend.ensure_repin_ready_sync(&key)?;
                Ok(())
            })
            .await?;
        }
        Ok(permits)
    }

    fn validate_repin_key(&self, key: &SessionOwnershipKey) -> Result<(), IpsecLbError> {
        if key.destination().routing_domain() != self.inner.config.routing_domain {
            return Err(IpsecLbError::invalid_config(
                "ownership.routing_domain",
                "ownership key routing domain does not match the backend",
            ));
        }
        if self.inner.config.fence_domain != HostXdpFenceDomain::PerOwnershipKey {
            return Err(IpsecLbError::invalid_config(
                "fence_domain",
                "same-SPI re-pin requires destination-scoped datapath fencing",
            ));
        }
        Ok(())
    }

    fn repin_stripe(&self, key: &SessionOwnershipKey) -> Arc<HostXdpRePinStripe> {
        Arc::clone(&self.inner.repin_stripes[self.repin_stripe_index(key)])
    }

    fn repin_stripe_index(&self, key: &SessionOwnershipKey) -> usize {
        let digest = Sha256::digest(key.to_canonical_bytes());
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&digest[..8]);
        (u64::from_be_bytes(prefix) % self.inner.repin_stripes.len() as u64) as usize
    }

    fn ensure_repin_ready_sync(&self, key: &SessionOwnershipKey) -> Result<(), IpsecLbError> {
        self.validate_repin_key(key)?;
        let _operation = self.operation_gate()?;
        self.ensure_attached_under_gate().map(|_| ())
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

    /// Probe the exact destination-scoped re-pin composition path.
    ///
    /// This is stricter than [`Self::probe`]: Global fence mode, a foreign
    /// attachment, an unavailable lifecycle lease, or pinned-state migration
    /// that cannot preserve keyed evidence reports `mutation_ready = false`.
    pub async fn probe_repin(&self) -> Result<SteeringProbe, IpsecLbError> {
        self.run_blocking("host_xdp_repin_probe", |backend| {
            Ok(backend.probe_repin_sync())
        })
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
            fence_mode: match self.inner.config.fence_domain {
                HostXdpFenceDomain::Global => XdpFenceMode::Global,
                HostXdpFenceDomain::PerOwnershipKey => XdpFenceMode::PerOwnershipKey,
            },
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
        // The runtime normalizes adopted pins into a non-live state and writes
        // the config before attaching the program. Global mode stages no
        // owners; destination-scoped mode may retain stale owner-only or
        // fence-only witnesses. Persisted authority is never silently rearmed.
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
        if self.inner.config.fence_domain == HostXdpFenceDomain::PerOwnershipKey {
            return Err(IpsecLbError::invalid_config(
                "fence_domain",
                "destination-scoped owner installation requires an authoritative re-pin permit",
            ));
        }
        let _operation = self.operation_gate()?;
        // Attach first so persisted fencing evidence is adopted before this
        // generation is validated. The operation gate also serializes the
        // check and map writes against every fence advance.
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
        if self.inner.config.fence_domain == HostXdpFenceDomain::PerOwnershipKey {
            return Err(IpsecLbError::invalid_config(
                "fence_domain",
                "destination-scoped owner removal requires authoritative retirement",
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

    fn apply_fenced_repin_owner_sync(
        &self,
        update: RePinSteeringUpdate,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        let key = update.ownership_key();
        let generation = update.generation().get();
        self.validate_repin_key(&key)?;
        let (permit, counter_guard) =
            permit.into_guarded_with_esp_counter_publication::<HostXdpRePinPermitEvidence>()?;
        let counter_publication_required = counter_guard.is_some();
        let expected_stripe = self.repin_stripe(&key);
        if !Arc::ptr_eq(&permit.backend_identity, &self.inner.repin_identity)
            || permit.ownership_key != key
            || !Arc::ptr_eq(&permit.stripe, &expected_stripe)
            || permit.poison_if_unclassified
            || permit.stripe.poisoned.load(Ordering::Acquire)
        {
            return Err(IpsecLbError::adapter_contract_violation(
                "host_xdp_repin_operation_permit_mismatched",
            ));
        }

        let _operation = self.operation_gate()?;
        let ifindex = self.ensure_attached_under_gate()?;
        self.apply_keyed_owner_under_gate(
            ifindex,
            &key,
            update.owner(),
            generation,
            counter_guard,
        )?;
        if counter_publication_required {
            Ok(RePinSteeringOperationPermit::guarded_after_counter_publication(key, permit))
        } else {
            Ok(RePinSteeringOperationPermit::guarded(key, permit))
        }
    }

    fn consume_host_repin_permit(
        &self,
        permit: RePinSteeringOperationPermit,
        expected_key: &SessionOwnershipKey,
        retirement: bool,
    ) -> Result<HostXdpRePinPermitEvidence, IpsecLbError> {
        if permit.ownership_key() != *expected_key {
            return Err(IpsecLbError::adapter_contract_violation(
                "host_xdp_repin_operation_permit_key_mismatch",
            ));
        }
        let evidence = permit.into_guarded::<HostXdpRePinPermitEvidence>()?;
        let expected_stripe = self.repin_stripe(expected_key);
        if !Arc::ptr_eq(&evidence.backend_identity, &self.inner.repin_identity)
            || evidence.ownership_key != *expected_key
            || !Arc::ptr_eq(&evidence.stripe, &expected_stripe)
            || evidence.poison_if_unclassified != retirement
            || evidence.stripe.poisoned.load(Ordering::Acquire)
        {
            return Err(IpsecLbError::adapter_contract_violation(
                "host_xdp_repin_operation_permit_mismatched",
            ));
        }
        Ok(evidence)
    }

    fn retire_fenced_repin_owner_sync(
        &self,
        grant: OwnershipRetirementGrant,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        let request = grant.request();
        let key = request.ownership_key();
        self.validate_repin_key(&key)?;
        crate::repin::validate_ownership_key_matches_sa(request.sa(), key)?;
        let active_fence = request.active_fence().get();
        let retirement_fence = grant.retirement_fence().get();
        if retirement_fence <= active_fence {
            return Err(IpsecLbError::adapter_contract_violation(
                "host_xdp_retirement_fence_did_not_advance",
            ));
        }

        let mut evidence = self.consume_host_repin_permit(permit, &key, true)?;
        // An exact Retiring grant classifies the cancellation-ambiguous store
        // CAS before any map mutation. From this point the durable store state
        // rejects ordinary activation even if this blocking operation fails.
        evidence.retirement_classified = true;

        let _operation = self.operation_gate()?;
        let ifindex = self.ensure_attached_under_gate()?;
        let map_key = owner_map_key(&key);
        let expected_owner = XdpOwnerValue {
            owner_shard: request.map_owner().get(),
            generation: active_fence,
        }
        .encode();

        let observed_fence = self.inner.runtime.key_fence_read(ifindex, map_key);
        let observed_owner = self.inner.runtime.owner_get(ifindex, map_key);
        if matches!(&observed_fence, Ok(Some(fence)) if *fence > retirement_fence)
            || matches!(&observed_owner, Ok(Some(raw)) if XdpOwnerValue::decode(raw)
                .is_some_and(|owner| owner.generation > retirement_fence))
        {
            return Err(IpsecLbError::ownership_conflict(
                "retirement cannot replace newer destination-scoped authority",
            ));
        }
        let (observed_fence, observed_owner) = match (observed_fence, observed_owner) {
            (Ok(fence), Ok(owner)) => (fence, owner),
            (fence, owner) => {
                let error = fence.err().or_else(|| owner.err()).unwrap_or_else(|| {
                    IpsecLbError::adapter_contract_violation(
                        "host_xdp_retirement_initial_read_indeterminate",
                    )
                });
                return Err(self.contain_indeterminate_keyed_state(
                    ifindex,
                    map_key,
                    retirement_fence,
                    error,
                ));
            }
        };
        if let Some(value) = observed_fence {
            if value != active_fence && value != retirement_fence {
                return Err(self.contain_indeterminate_keyed_state(
                    ifindex,
                    map_key,
                    retirement_fence,
                    IpsecLbError::ownership_conflict(
                        "retirement found a foreign destination-scoped fence",
                    ),
                ));
            }
        }
        match observed_owner {
            None => {}
            Some(value) if value == expected_owner => {}
            Some(_) => {
                return Err(self.contain_indeterminate_keyed_state(
                    ifindex,
                    map_key,
                    retirement_fence,
                    IpsecLbError::ownership_conflict(
                        "retirement found a foreign destination-scoped owner",
                    ),
                ));
            }
        }

        if observed_fence.is_none() && observed_owner.is_none() {
            return Ok(RePinSteeringOperationPermit::guarded(key, evidence));
        }

        if observed_fence != Some(retirement_fence) {
            let publish = self
                .inner
                .runtime
                .key_fence_write(ifindex, map_key, retirement_fence);
            match self.inner.runtime.key_fence_read(ifindex, map_key) {
                Ok(Some(value)) if value == retirement_fence => {}
                Ok(_) => {
                    let error = publish.err().unwrap_or_else(|| {
                        IpsecLbError::adapter_contract_violation(
                            "host_xdp_retirement_fence_readback_mismatch",
                        )
                    });
                    return Err(self.contain_indeterminate_keyed_state(
                        ifindex,
                        map_key,
                        retirement_fence,
                        error,
                    ));
                }
                Err(error) => {
                    return Err(self.contain_indeterminate_keyed_state(
                        ifindex,
                        map_key,
                        retirement_fence,
                        error,
                    ));
                }
            }
        }

        if observed_owner.is_some() {
            let remove = self.inner.runtime.owner_remove(ifindex, map_key);
            match self.inner.runtime.owner_get(ifindex, map_key) {
                Ok(None) => {}
                Ok(Some(_)) => {
                    return Err(remove.err().unwrap_or_else(|| {
                        IpsecLbError::adapter_contract_violation(
                            "host_xdp_retirement_owner_readback_mismatch",
                        )
                    }));
                }
                Err(error) => return Err(error),
            }
        }

        let remove_fence = self.inner.runtime.key_fence_remove(ifindex, map_key);
        match self.inner.runtime.key_fence_read(ifindex, map_key) {
            Ok(None) => {}
            Ok(Some(_)) => {
                return Err(remove_fence.err().unwrap_or_else(|| {
                    IpsecLbError::adapter_contract_violation(
                        "host_xdp_retirement_fence_removal_readback_mismatch",
                    )
                }));
            }
            Err(error) => return Err(error),
        }

        if self.inner.runtime.owner_get(ifindex, map_key)?.is_some()
            || self
                .inner
                .runtime
                .key_fence_read(ifindex, map_key)?
                .is_some()
        {
            return Err(IpsecLbError::adapter_contract_violation(
                "host_xdp_retirement_final_readback_mismatch",
            ));
        }
        Ok(RePinSteeringOperationPermit::guarded(key, evidence))
    }

    fn apply_keyed_owner_under_gate(
        &self,
        ifindex: u32,
        key: &SessionOwnershipKey,
        owner: ShardId,
        generation: u64,
        counter_guard: Option<opc_ipsec_xfrm::EspCounterPublicationGuard>,
    ) -> Result<(), IpsecLbError> {
        let map_key = owner_map_key(key);
        let expected = XdpOwnerValue {
            owner_shard: owner.get(),
            generation,
        }
        .encode();

        let observed_fence = self.inner.runtime.key_fence_read(ifindex, map_key);
        let observed_owner = self.inner.runtime.owner_get(ifindex, map_key);
        if matches!(&observed_fence, Ok(Some(current)) if *current > generation)
            || matches!(&observed_owner, Ok(Some(raw)) if XdpOwnerValue::decode(raw)
                .is_some_and(|value| value.generation > generation))
        {
            // A newer complete activation or a newer owner staged before its
            // fence-last cut belongs to another transition. An older retry
            // must leave it untouched.
            return Err(IpsecLbError::ownership_conflict(
                "destination-scoped owner or fence generation cannot regress",
            ));
        }
        let (observed_fence, observed_owner) = match (observed_fence, observed_owner) {
            (Ok(fence), Ok(owner)) => (fence, owner),
            (fence, owner) => {
                let read_error = fence.err().or_else(|| owner.err()).unwrap_or_else(|| {
                    IpsecLbError::adapter_contract_violation(
                        "host_xdp_repin_initial_read_indeterminate",
                    )
                });
                // Retry the paired read once. Exact desired state resolves a
                // lost read acknowledgement, but the final ESP counter guard
                // must still be consumed before treating it as published.
                match (
                    self.inner.runtime.key_fence_read(ifindex, map_key),
                    self.inner.runtime.owner_get(ifindex, map_key),
                ) {
                    (Ok(Some(fence)), Ok(Some(owner)))
                        if fence == generation && owner == expected =>
                    {
                        if let Some(guard) = counter_guard {
                            guard
                                .publish(|| Ok::<(), IpsecLbError>(()))
                                .map_err(|error| {
                                    IpsecLbError::applied_counter_proof_rejected(error.code())
                                })??;
                        }
                        return Ok(());
                    }
                    (Ok(fence), Ok(owner))
                        if fence.is_some_and(|observed| observed > generation)
                            || owner.as_ref().is_some_and(|raw| {
                                XdpOwnerValue::decode(raw)
                                    .is_some_and(|owner| owner.generation > generation)
                            }) =>
                    {
                        return Err(IpsecLbError::ownership_conflict(
                            "destination-scoped authority advanced concurrently",
                        ));
                    }
                    (Ok(Some(fence)), Ok(owner))
                        if fence == generation
                            && owner.as_ref().is_none_or(|raw| {
                                XdpOwnerValue::decode(raw)
                                    .is_none_or(|value| value.generation >= generation)
                                    && *raw != expected
                            }) =>
                    {
                        let equal_owner_witness = owner.as_ref().is_some_and(|raw| {
                            *raw != expected
                                && XdpOwnerValue::decode(raw)
                                    .is_some_and(|value| value.generation == generation)
                        });
                        if equal_owner_witness {
                            return self.quarantine_equal_generation_conflict(
                                ifindex, map_key, generation, true, true,
                            );
                        }
                        return Err(IpsecLbError::ownership_conflict(
                            "destination-scoped generation names a different owner",
                        ));
                    }
                    (Ok(fence), Ok(owner))
                        if !matches!(
                            (owner, fence),
                            (Some(raw), Some(fence))
                                if fence != 0
                                    && XdpOwnerValue::decode(&raw)
                                        .is_some_and(|owner| owner.generation == fence)
                        ) =>
                    {
                        return Err(read_error);
                    }
                    (Ok(_), Ok(_)) => {
                        return Err(self.contain_indeterminate_keyed_state(
                            ifindex, map_key, generation, read_error,
                        ));
                    }
                    (Err(_), _) | (_, Err(_)) => {
                        return Err(self.quiesce_indeterminate_backend(ifindex));
                    }
                }
            }
        };

        let equal_generation_different_owner = observed_owner
            .as_ref()
            .and_then(XdpOwnerValue::decode)
            .is_some_and(|value| value.generation == generation)
            && observed_owner != Some(expected);
        if observed_fence == Some(0) {
            if equal_generation_different_owner {
                // The zero fence is invalid but non-live. Remove only that
                // invalid value and retain the same-generation owner as the
                // durable conflict witness; clearing both would let an exact
                // retry publish a different owner at the same generation.
                let remove = self.inner.runtime.key_fence_remove(ifindex, map_key);
                return match self.inner.runtime.key_fence_read(ifindex, map_key) {
                    Ok(None) => Err(IpsecLbError::ownership_conflict(
                        "destination-scoped generation names a different owner",
                    )),
                    Ok(Some(_)) => Err(remove.err().unwrap_or_else(|| {
                        IpsecLbError::adapter_contract_violation(
                            "host_xdp_repin_zero_fence_removal_indeterminate",
                        )
                    })),
                    Err(error) => Err(error),
                };
            }
            let invalid = IpsecLbError::adapter_contract_violation("host_xdp_repin_key_fence_zero");
            return match self.clear_keyed_state(ifindex, map_key) {
                Ok(()) => Err(invalid),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
        if observed_fence == Some(generation) && observed_owner == Some(expected) {
            if let Some(guard) = counter_guard {
                guard
                    .publish(|| Ok::<(), IpsecLbError>(()))
                    .map_err(|error| {
                        IpsecLbError::applied_counter_proof_rejected(error.code())
                    })??;
            }
            return Ok(());
        }
        let same_fence_conflicting_owner = observed_fence == Some(generation)
            && observed_owner.as_ref().is_none_or(|raw| {
                XdpOwnerValue::decode(raw).is_none_or(|value| value.generation >= generation)
                    && *raw != expected
            });
        if same_fence_conflicting_owner || equal_generation_different_owner {
            return self.quarantine_equal_generation_conflict(
                ifindex,
                map_key,
                generation,
                observed_fence == Some(generation),
                equal_generation_different_owner,
            );
        }

        // Activation is deliberately fence-last:
        // 1. delete the keyed fence and prove absence (the fail-closed cut);
        // 2. remove the old owner and prove absence;
        // 3. stage and read back the new owner while the datapath is stale;
        // 4. publish and read back the exact authoritative fence.
        if let Err(error) = self.clear_keyed_state(ifindex, map_key) {
            return Err(self.contain_indeterminate_keyed_state(ifindex, map_key, generation, error));
        }
        self.insert_keyed_owner_with_readback(ifindex, map_key, expected, generation)?;

        if let Some(guard) = counter_guard {
            return match guard.publish(|| {
                self.publish_keyed_owner_with_readback(ifindex, map_key, expected, generation)
            }) {
                Ok(result) => result,
                Err(error) => {
                    let expired = IpsecLbError::applied_counter_proof_rejected(error.code());
                    match self.clear_keyed_state(ifindex, map_key) {
                        Ok(()) => Err(expired),
                        Err(cleanup_error) => Err(self.contain_indeterminate_keyed_state(
                            ifindex,
                            map_key,
                            generation,
                            cleanup_error,
                        )),
                    }
                }
            };
        }

        self.publish_keyed_owner_with_readback(ifindex, map_key, expected, generation)
    }

    /// Attempt an emergency per-key stale cut, then a backend-wide CONFIG cut
    /// and detach. `host_xdp_repin_containment_unproven` is a fatal outcome:
    /// readiness remains false and an operator must contain the node because
    /// neither datapath quiescence nor detach was authoritatively proven.
    fn contain_indeterminate_keyed_state(
        &self,
        ifindex: u32,
        map_key: [u8; OWNER_KEY_LEN],
        generation: u64,
        original_error: IpsecLbError,
    ) -> IpsecLbError {
        let observed_owner = self.inner.runtime.owner_get(ifindex, map_key);
        let observed_fence = self.inner.runtime.key_fence_read(ifindex, map_key);
        if matches!(&observed_fence, Ok(Some(fence)) if *fence > generation)
            || matches!(&observed_owner, Ok(Some(raw)) if XdpOwnerValue::decode(raw)
                .is_some_and(|owner| owner.generation > generation))
        {
            return IpsecLbError::ownership_conflict(
                "destination-scoped authority advanced concurrently",
            );
        }
        match (&observed_owner, &observed_fence) {
            (Ok(owner), Ok(fence))
                if !matches!(
                    (owner, fence),
                    (Some(raw), Some(fence))
                        if *fence != 0
                            && XdpOwnerValue::decode(raw)
                                .is_some_and(|owner| owner.generation == *fence)
                ) =>
            {
                return original_error;
            }
            (Ok(_), Ok(_)) => {}
            // A failed retry read leaves the current generation unknown. Never
            // overwrite it with a possibly older emergency fence; skip
            // directly to backend-wide quiescence and detach containment.
            (Err(_), _) | (_, Err(_)) => return self.quiesce_indeterminate_backend(ifindex),
        }

        // A failed fence removal and failed owner removal can leave the old
        // pair live. Publish the already committed higher generation as an
        // emergency fail-closed cut: the old owner immediately becomes stale,
        // and an exact retry can remove that older-owner residue normally.
        let _write = self
            .inner
            .runtime
            .key_fence_write(ifindex, map_key, generation);
        if let (Ok(Some(observed_fence)), Ok(observed_owner)) = (
            self.inner.runtime.key_fence_read(ifindex, map_key),
            self.inner.runtime.owner_get(ifindex, map_key),
        ) {
            let owner_is_live = observed_owner.as_ref().is_some_and(|raw| {
                XdpOwnerValue::decode(raw).is_some_and(|owner| owner.generation == observed_fence)
            });
            if observed_fence >= generation && !owner_is_live {
                return original_error;
            }
        }

        self.quiesce_indeterminate_backend(ifindex)
    }

    /// Remove CONFIG and prove absence so the live program has no
    /// classification authority, latch the backend indeterminate, and then
    /// best-effort detach it.
    fn quiesce_indeterminate_backend(&self, ifindex: u32) -> IpsecLbError {
        let config_absent = self.inner.runtime.quiesce_repin(ifindex).is_ok();
        if let Ok(mut state) = self.state() {
            state.attachment = HostXdpAttachmentState::Indeterminate {
                ifindex,
                mode: self.inner.config.attach_mode,
            };
        }
        let detached =
            match self
                .inner
                .runtime
                .detach(&self.inner.interface, ifindex, &self.pin_dir())
            {
                Ok(()) => {
                    if let Ok(mut state) = self.state() {
                        state.attachment = HostXdpAttachmentState::Detached;
                    }
                    true
                }
                Err(failure) => {
                    let detached = failure.disposition == HostXdpLinkDisposition::Detached;
                    if let Ok(mut state) = self.state() {
                        apply_link_disposition(
                            &mut state,
                            failure.disposition,
                            ifindex,
                            self.inner.config.attach_mode,
                        );
                    }
                    detached
                }
            };
        if config_absent || detached {
            IpsecLbError::adapter_contract_violation("host_xdp_repin_backend_quarantined")
        } else {
            IpsecLbError::adapter_contract_violation("host_xdp_repin_containment_unproven")
        }
    }

    fn publish_keyed_owner_with_readback(
        &self,
        ifindex: u32,
        map_key: [u8; OWNER_KEY_LEN],
        expected: [u8; OWNER_VALUE_LEN],
        generation: u64,
    ) -> Result<(), IpsecLbError> {
        let fence_write = self
            .inner
            .runtime
            .key_fence_write(ifindex, map_key, generation);
        let fence_readback = self.inner.runtime.key_fence_read(ifindex, map_key);
        let owner_readback = self.inner.runtime.owner_get(ifindex, map_key);
        if matches!(&fence_readback, Ok(Some(observed)) if *observed == generation)
            && matches!(&owner_readback, Ok(Some(observed)) if *observed == expected)
        {
            // Exact readback resolves an acknowledgement lost after apply.
            return Ok(());
        }

        let newer_generation = match &fence_readback {
            Ok(Some(observed)) if *observed > generation => Some(*observed),
            Ok(_) | Err(_) => None,
        };
        let newer_owner_generation = match &owner_readback {
            Ok(Some(raw)) => XdpOwnerValue::decode(raw)
                .map(|value| value.generation)
                .filter(|owner_generation| *owner_generation > generation),
            Ok(None) | Err(_) => None,
        };
        if newer_generation.is_some() || newer_owner_generation.is_some() {
            return Err(IpsecLbError::ownership_conflict(
                "destination-scoped owner or fence generation advanced concurrently",
            ));
        }

        // The fence write may already have made the staged owner live. A
        // partial final read cannot distinguish that state from a failed
        // write, so invalidate both maps and escalate through containment if
        // cleanup is not authoritatively proven. Equal-generation conflict
        // witnesses are preserved only when both reads succeeded.
        if fence_readback.is_err() || owner_readback.is_err() {
            let final_error = IpsecLbError::adapter_contract_violation(
                "host_xdp_repin_activation_readback_indeterminate",
            );
            return match self.clear_keyed_state(ifindex, map_key) {
                Ok(()) => Err(final_error),
                Err(cleanup_error) => Err(self.contain_indeterminate_keyed_state(
                    ifindex,
                    map_key,
                    generation,
                    cleanup_error,
                )),
            };
        }

        let final_equal_fence = matches!(
            &fence_readback,
            Ok(Some(observed)) if *observed == generation
        );
        let final_equal_different_owner = matches!(&owner_readback, Ok(Some(raw)) if *raw != expected
            && XdpOwnerValue::decode(raw).is_some_and(|value| value.generation == generation));
        if (final_equal_fence
            && matches!(&owner_readback, Ok(observed) if *observed != Some(expected)))
            || final_equal_different_owner
        {
            return self.quarantine_equal_generation_conflict(
                ifindex,
                map_key,
                generation,
                final_equal_fence,
                final_equal_different_owner,
            );
        }

        let final_error = fence_write.err().unwrap_or_else(|| {
            IpsecLbError::adapter_contract_violation(
                "host_xdp_repin_activation_readback_indeterminate",
            )
        });
        match self.clear_keyed_state(ifindex, map_key) {
            Ok(()) => Err(final_error),
            Err(cleanup_error) => Err(self.contain_indeterminate_keyed_state(
                ifindex,
                map_key,
                generation,
                cleanup_error,
            )),
        }
    }

    fn insert_keyed_owner_with_readback(
        &self,
        ifindex: u32,
        map_key: [u8; OWNER_KEY_LEN],
        expected: [u8; OWNER_VALUE_LEN],
        generation: u64,
    ) -> Result<(), IpsecLbError> {
        let insert = self.inner.runtime.owner_insert(ifindex, map_key, expected);
        match self.inner.runtime.owner_get(ifindex, map_key) {
            Ok(Some(observed)) if observed == expected => Ok(()),
            _ => {
                let insert_error = insert.err().unwrap_or_else(|| {
                    IpsecLbError::adapter_contract_violation(
                        "host_xdp_repin_owner_readback_mismatch",
                    )
                });
                match self.clear_keyed_state(ifindex, map_key) {
                    Ok(()) => Err(insert_error),
                    Err(cleanup_error) => Err(self.contain_indeterminate_keyed_state(
                        ifindex,
                        map_key,
                        generation,
                        cleanup_error,
                    )),
                }
            }
        }
    }

    fn remove_keyed_owner_with_readback(
        &self,
        ifindex: u32,
        map_key: [u8; OWNER_KEY_LEN],
    ) -> Result<(), IpsecLbError> {
        let remove = self.inner.runtime.owner_remove(ifindex, map_key);
        match self.inner.runtime.owner_get(ifindex, map_key) {
            Ok(None) => Ok(()),
            _ => Err(remove.err().unwrap_or_else(|| {
                IpsecLbError::adapter_contract_violation(
                    "host_xdp_repin_owner_invalidation_indeterminate",
                )
            })),
        }
    }

    fn quarantine_equal_generation_conflict(
        &self,
        ifindex: u32,
        map_key: [u8; OWNER_KEY_LEN],
        generation: u64,
        fence_is_witness: bool,
        owner_is_witness: bool,
    ) -> Result<(), IpsecLbError> {
        let conflict = || {
            IpsecLbError::ownership_conflict(
                "destination-scoped generation names a different owner",
            )
        };
        if owner_is_witness && fence_is_witness {
            // Prefer fence absence as the immediate fail-closed cut while
            // retaining the mismatching owner as a durable retry witness.
            let _remove = self.inner.runtime.key_fence_remove(ifindex, map_key);
            return match self.inner.runtime.key_fence_read(ifindex, map_key) {
                Ok(None) => Err(conflict()),
                Ok(Some(observed)) if observed == generation => {
                    match self.remove_keyed_owner_with_readback(ifindex, map_key) {
                        Ok(()) => Err(conflict()),
                        Err(error) => Err(self.contain_indeterminate_keyed_state(
                            ifindex, map_key, generation, error,
                        )),
                    }
                }
                Ok(Some(_)) => Err(conflict()),
                Err(error) => {
                    Err(self.contain_indeterminate_keyed_state(ifindex, map_key, generation, error))
                }
            };
        }

        // One stale witness is already sufficient. Leaving it in place makes
        // every retry of this same corrupted grant conflict; only a genuinely
        // higher authoritative generation may clear and replace it.
        Err(conflict())
    }

    fn remove_keyed_fence_with_readback(
        &self,
        ifindex: u32,
        map_key: [u8; OWNER_KEY_LEN],
    ) -> Result<(), IpsecLbError> {
        let remove = self.inner.runtime.key_fence_remove(ifindex, map_key);
        match self.inner.runtime.key_fence_read(ifindex, map_key) {
            Ok(None) => Ok(()),
            _ => Err(remove.err().unwrap_or_else(|| {
                IpsecLbError::adapter_contract_violation(
                    "host_xdp_repin_key_fence_removal_indeterminate",
                )
            })),
        }
    }

    fn clear_keyed_state(
        &self,
        ifindex: u32,
        map_key: [u8; OWNER_KEY_LEN],
    ) -> Result<(), IpsecLbError> {
        let fence_result = self.remove_keyed_fence_with_readback(ifindex, map_key);
        let owner_result = self.remove_keyed_owner_with_readback(ifindex, map_key);
        match (fence_result, owner_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(fence_error), Ok(())) => Err(fence_error),
            (Ok(()), Err(owner_error)) => Err(owner_error),
            (Err(_), Err(_)) => Err(IpsecLbError::adapter_contract_violation(
                "host_xdp_repin_quarantine_indeterminate",
            )),
        }
    }

    fn advance_fence_sync(&self, generation: u64) -> Result<(), IpsecLbError> {
        if generation == 0 {
            return Err(IpsecLbError::invalid_config(
                "fence.generation",
                "fence generation must be non-zero",
            ));
        }
        if self.inner.config.fence_domain == HostXdpFenceDomain::PerOwnershipKey {
            return Err(IpsecLbError::invalid_config(
                "fence_domain",
                "global fence advancement is unavailable in destination-scoped mode",
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

    fn probe_repin_sync(&self) -> SteeringProbe {
        let mut probe = self.probe_sync();
        if !probe.mutation_ready {
            return probe;
        }
        if self.inner.config.fence_domain != HostXdpFenceDomain::PerOwnershipKey {
            probe.mutation_ready = false;
            probe.details = Some("Host-XDP re-pin requires destination-scoped ownership fencing");
            return probe;
        }
        if self
            .inner
            .repin_stripes
            .iter()
            .any(|stripe| stripe.poisoned.load(Ordering::Acquire))
        {
            probe.mutation_ready = false;
            probe.details = Some("Host-XDP re-pin operation state is indeterminate");
            return probe;
        }

        let feasible = (|| {
            validate_interface_name(&self.inner.interface)?;
            match self.state()?.attachment {
                HostXdpAttachmentState::Ready { .. } => return Ok(()),
                HostXdpAttachmentState::Detached => {}
                HostXdpAttachmentState::AwaitingFence { .. }
                | HostXdpAttachmentState::HandoffPrepared { .. }
                | HostXdpAttachmentState::UpgradeCleanupPending { .. }
                | HostXdpAttachmentState::Indeterminate { .. } => {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
            }
            let ifindex = self.inner.runtime.ifindex_by_name(&self.inner.interface)?;
            if ifindex == 0 || self.inner.runtime.attached_prog_id(ifindex)?.is_some() {
                return Err(IpsecLbError::XdpUpgradeRequiresDrain);
            }
            let _lease = self.inner.runtime.lifecycle_lock(&self.pin_dir())?;
            let config = self.datapath_config();
            self.inner
                .runtime
                .repin_pins_feasible(&self.pin_dir(), &config)?;
            Ok(())
        })();
        if feasible.is_err() {
            probe.mutation_ready = false;
            probe.details = Some("Host-XDP re-pin lifecycle or keyed migration is unavailable");
        } else {
            probe.details = Some("Host-XDP destination-scoped re-pin mutation ready");
        }
        probe
    }
}

#[async_trait]
impl RePinSteeringBackend for HostXdpSteeringBackend {
    async fn acquire_repin_permit(
        &self,
        ownership_key: SessionOwnershipKey,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        self.acquire_host_repin_permit(ownership_key).await
    }

    async fn apply_fenced_repin(
        &self,
        update: RePinSteeringUpdate,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        self.apply_fenced_repin_owner(update, permit).await
    }
}

#[async_trait]
impl RePinSteeringRetirementBackend for HostXdpSteeringBackend {
    async fn acquire_repin_retirement_permits(
        &self,
        ownership_keys: Vec<SessionOwnershipKey>,
    ) -> Result<Vec<RePinSteeringOperationPermit>, IpsecLbError> {
        self.acquire_host_repin_retirement_permits(ownership_keys)
            .await
    }

    fn arm_repin_retirement_permit(
        &self,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        let key = permit.ownership_key();
        let mut evidence = self.consume_host_repin_permit(permit, &key, false)?;
        evidence.poison_if_unclassified = true;
        Ok(RePinSteeringOperationPermit::guarded(key, evidence))
    }

    fn release_classified_repin_retirement_permit(
        &self,
        permit: RePinSteeringOperationPermit,
    ) -> Result<(), IpsecLbError> {
        let key = permit.ownership_key();
        let mut evidence = self.consume_host_repin_permit(permit, &key, true)?;
        evidence.retirement_classified = true;
        Ok(())
    }

    async fn retire_fenced_repin(
        &self,
        grant: &OwnershipRetirementGrant,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        let grant = grant.clone();
        self.run_blocking("host_xdp_retire_fenced_repin_owner", move |backend| {
            backend.retire_fenced_repin_owner_sync(grant, permit)
        })
        .await
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

    fn key_fence_read(
        &self,
        _ifindex: u32,
        _key: [u8; OWNER_KEY_LEN],
    ) -> Result<Option<u64>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn key_fence_write(
        &self,
        _ifindex: u32,
        _key: [u8; OWNER_KEY_LEN],
        _generation: u64,
    ) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn key_fence_remove(
        &self,
        _ifindex: u32,
        _key: [u8; OWNER_KEY_LEN],
    ) -> Result<bool, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn quiesce_repin(&self, _ifindex: u32) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn repin_pins_feasible(
        &self,
        _pin_dir: &Path,
        _config: &[u8; CONFIG_VALUE_LEN],
    ) -> Result<(), IpsecLbError> {
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

    use aya::maps::{
        Array, HashMap as BpfHashMap, Map, MapData, MapError, MapInfo, MapType, PerCpuArray,
    };
    use aya::programs::links::{LinkError, LinkType};
    use aya::programs::{
        loaded_links, loaded_programs, ProgramError, ProgramInfo, ProgramType, Xdp, XdpMode,
    };
    use aya::sys::{is_helper_supported, BpfHelper};
    use aya::{Ebpf, EbpfLoader};
    use opc_linux_gtpu_sys as sys;

    use super::{
        mode_accepts_live, owner_map_key, HostXdpAttachMode, HostXdpEnvironment,
        HostXdpLifecycleLock, HostXdpLinkDisposition, HostXdpRedirectHandoff, HostXdpRuntime,
        HostXdpRuntimeAdoption, HostXdpRuntimeFailure, XdpOwnerValue, CONFIG_KEY, CONFIG_VALUE_LEN,
        COUNTER_SLOTS, FENCE_KEY, MAP_CONFIG, MAP_COUNTERS, MAP_FENCE, MAP_KEY_FENCES, MAP_OWNERS,
        OWNERSHIP_KEY_MAX_ENCODED_BYTES, OWNER_KEY_LEN, OWNER_VALUE_LEN, PROG_SWU_XDP,
        XDP_CONFIG_ABI_VERSION,
    };
    use crate::{IpsecLbError, SessionOwnershipKey};

    const DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-ipsec-lb-xdp.bpf.o"
    ));

    const CAP_NET_ADMIN: u32 = 12;
    const CAP_SYS_ADMIN: u32 = 21;
    const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
    // bpffs rejects dentry names containing `.` with EPERM. Keep this name
    // deliberately plain so lifecycle locking works on the real filesystem.
    pub(super) const CONTROL_DIRECTORY: &str = "control";
    const MAP_SLOT_A: &str = "maps-v4-a";
    const MAP_SLOT_B: &str = "maps-v4-b";
    const HANDOFF_LINK: &str = "upgrade-link";
    const AUXILIARY_RODATA_MAP: &[u8] = b".rodata.cst4";
    const AUXILIARY_RODATA_FLAGS: u32 = 1 << 7; // Linux UAPI BPF_F_RDONLY_PROG.

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

    type PinnedOwners = BTreeMap<[u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]>;
    type PinnedKeyFences = BTreeMap<[u8; OWNER_KEY_LEN], u64>;

    #[derive(Debug)]
    struct PinnedMapNamespace {
        slot: MapNamespaceSlot,
        version: u8,
        config: [u8; CONFIG_VALUE_LEN],
        fence_generation: u64,
        owners: PinnedOwners,
        key_fences: PinnedKeyFences,
        map_ids: BTreeSet<u32>,
    }

    #[derive(Debug)]
    struct PartialPinnedMapNamespace {
        slot: MapNamespaceSlot,
        version: Option<u8>,
        fence_generation: u64,
        owners: PinnedOwners,
        owners_map_present: bool,
        key_fences: PinnedKeyFences,
        key_fence_map_present: bool,
        counters_map_present: bool,
        map_ids: BTreeSet<u32>,
    }

    impl PartialPinnedMapNamespace {
        fn is_empty_v5_cleanup_residue(&self) -> bool {
            self.version == Some(XDP_CONFIG_ABI_VERSION)
                && self.owners.is_empty()
                && !self.owners_map_present
                && self.key_fences.is_empty()
                && !self.key_fence_map_present
                && !self.counters_map_present
                && self.map_ids.len() == 2
        }

        fn is_scalar_fence_only_cleanup_residue(&self) -> bool {
            self.version.is_none()
                && self.owners.is_empty()
                && !self.owners_map_present
                && self.key_fences.is_empty()
                && !self.key_fence_map_present
                && !self.counters_map_present
                && self.map_ids.len() == 1
        }
    }

    #[derive(Debug, Default)]
    struct PinnedNamespaceInventory {
        complete: Vec<PinnedMapNamespace>,
        partial: Vec<PartialPinnedMapNamespace>,
    }

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct DestinationScopedRecoveryMaps {
        owners: PinnedOwners,
        key_fences: PinnedKeyFences,
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

        fn recovery_maps(&self) -> Result<DestinationScopedRecoveryMaps, IpsecLbError> {
            self.recovery_maps_without(None)
        }

        fn recovery_maps_for_config(
            &self,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<DestinationScopedRecoveryMaps, IpsecLbError> {
            self.recovery_maps_for_config_without(expected_config, None)
        }

        fn recovery_maps_for_config_without(
            &self,
            expected_config: &[u8; CONFIG_VALUE_LEN],
            omitted: Option<MapNamespaceSlot>,
        ) -> Result<DestinationScopedRecoveryMaps, IpsecLbError> {
            let mut recovered = match omitted {
                Some(slot) => self.recovery_maps_without(Some(slot))?,
                None => self.recovery_maps()?,
            };
            match expected_config[1] {
                0 => {
                    let global_floor = omitted
                        .map_or_else(|| self.max_fence(), |slot| self.max_fence_without(slot));
                    let owners = std::mem::take(&mut recovered.owners);
                    for (key, raw_owner) in owners {
                        let owner = XdpOwnerValue::decode(&raw_owner)
                            .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                        merge_recovery_fence(
                            &mut recovered,
                            key,
                            owner.generation.max(global_floor),
                        )?;
                    }
                    Ok(recovered)
                }
                1 => Ok(recovered),
                _ => Err(IpsecLbError::XdpUpgradeIndeterminate),
            }
        }

        fn recovery_maps_without(
            &self,
            omitted: Option<MapNamespaceSlot>,
        ) -> Result<DestinationScopedRecoveryMaps, IpsecLbError> {
            let mut recovered = DestinationScopedRecoveryMaps::default();
            for namespace in self
                .complete
                .iter()
                .filter(|namespace| Some(namespace.slot) != omitted)
            {
                merge_recovery_namespace(
                    &mut recovered,
                    Some(namespace.version),
                    &namespace.owners,
                    &namespace.key_fences,
                    namespace.fence_generation,
                )?;
            }
            for namespace in self
                .partial
                .iter()
                .filter(|namespace| Some(namespace.slot) != omitted)
            {
                merge_recovery_namespace(
                    &mut recovered,
                    namespace.version,
                    &namespace.owners,
                    &namespace.key_fences,
                    namespace.fence_generation,
                )?;
            }
            Ok(recovered)
        }

        fn max_fence_without(&self, omitted: MapNamespaceSlot) -> u64 {
            self.complete
                .iter()
                .filter(|namespace| namespace.slot != omitted)
                .map(|namespace| namespace.fence_generation)
                .chain(
                    self.partial
                        .iter()
                        .filter(|namespace| namespace.slot != omitted)
                        .map(|namespace| namespace.fence_generation),
                )
                .max()
                .unwrap_or(0)
        }

        fn target_overwrite_is_redundant(
            &self,
            target: MapNamespaceSlot,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<bool, IpsecLbError> {
            Ok(self.max_fence_without(target) == self.max_fence()
                && self.recovery_maps_for_config_without(expected_config, Some(target))?
                    == self.recovery_maps_for_config(expected_config)?)
        }

        fn has_slot(&self, slot: MapNamespaceSlot) -> bool {
            self.complete.iter().any(|namespace| namespace.slot == slot)
                || self.partial.iter().any(|namespace| namespace.slot == slot)
        }

        fn validate_destination_scoped_migration(
            &self,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            if expected_config[1] != 1 {
                return Ok(());
            }
            for namespace in &self.complete {
                if namespace.version < 5
                    && namespace.fence_generation != 0
                    && namespace.owners.is_empty()
                {
                    return Err(IpsecLbError::XdpUpgradeRequiresDrain);
                }
            }
            for namespace in &self.partial {
                match namespace.version {
                    Some(version)
                        if version >= 5
                            && !namespace.key_fence_map_present
                            && !namespace.is_empty_v5_cleanup_residue() =>
                    {
                        return Err(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                    Some(version)
                        if version < 5
                            && namespace.fence_generation != 0
                            && namespace.owners.is_empty() =>
                    {
                        return Err(IpsecLbError::XdpUpgradeRequiresDrain);
                    }
                    None if namespace.is_scalar_fence_only_cleanup_residue() => {}
                    None => {
                        return Err(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                    _ => {}
                }
            }
            Ok(())
        }
    }

    fn merge_recovery_namespace(
        recovered: &mut DestinationScopedRecoveryMaps,
        version: Option<u8>,
        owners: &PinnedOwners,
        key_fences: &PinnedKeyFences,
        legacy_floor: u64,
    ) -> Result<(), IpsecLbError> {
        match version {
            Some(version) if version < 5 => {
                for (key, generation) in key_fences {
                    merge_recovery_fence(recovered, *key, *generation)?;
                }
                for (key, raw_owner) in owners {
                    let owner = XdpOwnerValue::decode(raw_owner)
                        .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                    merge_recovery_fence(recovered, *key, owner.generation.max(legacy_floor))?;
                }
                Ok(())
            }
            Some(_) => {
                for (key, raw_owner) in owners {
                    let owner = XdpOwnerValue::decode(raw_owner)
                        .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                    if key_fences
                        .get(key)
                        .is_some_and(|fence| *fence != owner.generation)
                    {
                        return Err(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                    merge_recovery_owner(recovered, *key, *raw_owner)?;
                }
                for (key, generation) in key_fences {
                    if !owners.contains_key(key) {
                        merge_recovery_fence(recovered, *key, *generation)?;
                    }
                }
                Ok(())
            }
            None if owners.is_empty() && key_fences.is_empty() => Ok(()),
            None => Err(IpsecLbError::XdpUpgradeIndeterminate),
        }
    }

    fn merge_recovery_owner(
        recovered: &mut DestinationScopedRecoveryMaps,
        key: [u8; OWNER_KEY_LEN],
        raw_owner: [u8; OWNER_VALUE_LEN],
    ) -> Result<(), IpsecLbError> {
        let owner =
            XdpOwnerValue::decode(&raw_owner).ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
        if let Some(fence) = recovered.key_fences.get(&key).copied() {
            if fence >= owner.generation {
                return Ok(());
            }
            recovered.key_fences.remove(&key);
        }
        match recovered.owners.get(&key).copied() {
            None => {
                if recovered.owners.len() + recovered.key_fences.len() >= 65_536 {
                    return Err(IpsecLbError::XdpUpgradeRequiresDrain);
                }
                recovered.owners.insert(key, raw_owner);
            }
            Some(existing) => {
                let existing = XdpOwnerValue::decode(&existing)
                    .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                match existing.generation.cmp(&owner.generation) {
                    std::cmp::Ordering::Less => {
                        recovered.owners.insert(key, raw_owner);
                    }
                    std::cmp::Ordering::Equal if existing.owner_shard != owner.owner_shard => {
                        return Err(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                    std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {}
                }
            }
        }
        Ok(())
    }

    fn merge_recovery_fence(
        recovered: &mut DestinationScopedRecoveryMaps,
        key: [u8; OWNER_KEY_LEN],
        generation: u64,
    ) -> Result<(), IpsecLbError> {
        if generation == 0 {
            return Err(IpsecLbError::XdpUpgradeIndeterminate);
        }
        if let Some(raw_owner) = recovered.owners.get(&key).copied() {
            let owner =
                XdpOwnerValue::decode(&raw_owner).ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
            if owner.generation > generation {
                return Ok(());
            }
            recovered.owners.remove(&key);
        }
        if !recovered.key_fences.contains_key(&key)
            && recovered.owners.len() + recovered.key_fences.len() >= 65_536
        {
            return Err(IpsecLbError::XdpUpgradeRequiresDrain);
        }
        recovered
            .key_fences
            .entry(key)
            .and_modify(|current| *current = (*current).max(generation))
            .or_insert(generation);
        Ok(())
    }

    impl AyaHostXdpRuntime {
        pub(super) fn new() -> Self {
            Self::default()
        }

        pub(super) fn repin_pins_feasible(
            interface_dir: &Path,
            config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let inventory = Self::inspect_namespaces(interface_dir, config)?;
            inventory.validate_destination_scoped_migration(config)?;
            let _ = Self::staging_slot(&inventory, config)?;
            Ok(())
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

        fn config_read_map(ebpf: &mut Ebpf) -> Result<[u8; CONFIG_VALUE_LEN], IpsecLbError> {
            let map = ebpf
                .map(MAP_CONFIG)
                .ok_or_else(|| IpsecLbError::io("xdp_config_map", invalid_data("map missing")))?;
            let hash = BpfHashMap::<_, u32, [u8; CONFIG_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("xdp_config_map", error))?;
            hash.get(&CONFIG_KEY, 0)
                .map_err(|error| map_error("xdp_config_read", error))
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

        fn key_fences_map(
            ebpf: &mut Ebpf,
        ) -> Result<BpfHashMap<&mut aya::maps::MapData, [u8; OWNER_KEY_LEN], u64>, IpsecLbError>
        {
            let map = ebpf.map_mut(MAP_KEY_FENCES).ok_or_else(|| {
                IpsecLbError::io("xdp_key_fences_map", invalid_data("map missing"))
            })?;
            BpfHashMap::<_, [u8; OWNER_KEY_LEN], u64>::try_from(map)
                .map_err(|error| map_error("xdp_key_fences_map", error))
        }

        fn read_pinned_owners(
            path: &Path,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(PinnedOwners, u32), IpsecLbError> {
            let (map, id) = Self::map_schema(
                path,
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
            let mut values = BTreeMap::new();
            for key in owners.keys() {
                let key = key.map_err(|error| map_error("xdp_upgrade_owners_read", error))?;
                Self::validate_pinned_owner_key(key, expected_config)?;
                let raw = owners
                    .get(&key, 0)
                    .map_err(|error| map_error("xdp_upgrade_owners_read", error))?;
                XdpOwnerValue::decode(&raw).ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                values.insert(key, raw);
            }
            Ok((values, id))
        }

        fn read_pinned_key_fences(
            path: &Path,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(BTreeMap<[u8; OWNER_KEY_LEN], u64>, u32), IpsecLbError> {
            let (map, id) = Self::map_schema(
                path,
                "xdp_upgrade_key_fences_schema",
                MapType::Hash,
                OWNER_KEY_LEN as u32,
                8,
                65_536,
            )?;
            let fences = BpfHashMap::<_, [u8; OWNER_KEY_LEN], u64>::try_from(Map::HashMap(map))
                .map_err(|error| map_error("xdp_upgrade_key_fences_open", error))?;
            let mut generations = BTreeMap::new();
            for key in fences.keys() {
                let key = key.map_err(|error| map_error("xdp_upgrade_key_fences_read", error))?;
                Self::validate_pinned_owner_key(key, expected_config)?;
                let generation = fences
                    .get(&key, 0)
                    .map_err(|error| map_error("xdp_upgrade_key_fences_read", error))?;
                if generation == 0 {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                generations.insert(key, generation);
            }
            Ok((generations, id))
        }

        fn validate_pinned_owner_key(
            map_key: [u8; OWNER_KEY_LEN],
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let encoded_len = usize::from(map_key[0]);
            if encoded_len == 0
                || encoded_len > OWNERSHIP_KEY_MAX_ENCODED_BYTES
                || map_key[encoded_len + 1..].iter().any(|byte| *byte != 0)
            {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            let key = SessionOwnershipKey::from_canonical_bytes(&map_key[1..=encoded_len])
                .map_err(|_| IpsecLbError::XdpUpgradeIndeterminate)?;
            let expected_domain = u64::from_be_bytes([
                expected_config[4],
                expected_config[5],
                expected_config[6],
                expected_config[7],
                expected_config[8],
                expected_config[9],
                expected_config[10],
                expected_config[11],
            ]);
            if key.destination().routing_domain().get() != expected_domain
                || owner_map_key(&key) != map_key
            {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            Ok(())
        }

        fn write_key_fences_map(
            ebpf: &mut Ebpf,
            fences: &BTreeMap<[u8; OWNER_KEY_LEN], u64>,
        ) -> Result<(), IpsecLbError> {
            let mut map = Self::key_fences_map(ebpf)?;
            for (key, generation) in fences {
                if *generation == 0 {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                map.insert(*key, *generation, 0)
                    .map_err(|error| map_error("xdp_key_fences_initialize", error))?;
            }
            Ok(())
        }

        fn write_owners_map(
            ebpf: &mut Ebpf,
            owners: &BTreeMap<[u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]>,
        ) -> Result<(), IpsecLbError> {
            let mut map = Self::owners_map(ebpf)?;
            for (key, raw_owner) in owners {
                XdpOwnerValue::decode(raw_owner).ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                map.insert(*key, *raw_owner, 0)
                    .map_err(|error| map_error("xdp_owners_initialize", error))?;
            }
            Ok(())
        }

        fn seed_live_key_fences_from_owners(
            ebpf: &mut Ebpf,
            legacy_floor: u64,
            config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let owner_generations = {
                let owners = Self::owners_map(ebpf)?;
                let mut observed = BTreeMap::new();
                for key in owners.keys() {
                    let key = key.map_err(|error| map_error("xdp_handoff_owners_read", error))?;
                    Self::validate_pinned_owner_key(key, config)?;
                    let raw = owners
                        .get(&key, 0)
                        .map_err(|error| map_error("xdp_handoff_owners_read", error))?;
                    let value =
                        XdpOwnerValue::decode(&raw).ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                    observed.insert(key, value.generation.max(legacy_floor));
                }
                observed
            };
            let mut fences = Self::key_fences_map(ebpf)?;
            for (key, generation) in owner_generations {
                let current = match fences.get(&key, 0) {
                    Ok(current) => current,
                    Err(MapError::KeyNotFound) => 0,
                    Err(error) => return Err(map_error("xdp_handoff_key_fence_read", error)),
                };
                if current < generation {
                    fences
                        .insert(key, generation, 0)
                        .map_err(|error| map_error("xdp_handoff_key_fence_write", error))?;
                }
                if fences
                    .get(&key, 0)
                    .map_err(|error| map_error("xdp_handoff_key_fence_readback", error))?
                    != current.max(generation)
                {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
            }
            Ok(())
        }

        fn prepare_live_per_key_handoff(
            ebpf: &mut Ebpf,
            config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let owners = {
                let owners = Self::owners_map(ebpf)?;
                let mut observed = BTreeMap::new();
                for key in owners.keys() {
                    let key = key.map_err(|error| map_error("xdp_handoff_owners_read", error))?;
                    Self::validate_pinned_owner_key(key, config)?;
                    let raw = owners
                        .get(&key, 0)
                        .map_err(|error| map_error("xdp_handoff_owners_read", error))?;
                    let value =
                        XdpOwnerValue::decode(&raw).ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                    observed.insert(key, value.generation);
                }
                observed
            };
            let mut fences = Self::key_fences_map(ebpf)?;
            for (key, owner_generation) in owners {
                match fences.get(&key, 0) {
                    Ok(fence_generation) if fence_generation == owner_generation => {
                        fences
                            .remove(&key)
                            .map_err(|error| map_error("xdp_handoff_key_fence_remove", error))?;
                        match fences.get(&key, 0) {
                            Err(MapError::KeyNotFound) => {}
                            Ok(_) => return Err(IpsecLbError::XdpUpgradeIndeterminate),
                            Err(error) => {
                                return Err(map_error("xdp_handoff_key_fence_readback", error));
                            }
                        }
                    }
                    Err(MapError::KeyNotFound) => {}
                    Ok(_) => {
                        return Err(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                    Err(error) => return Err(map_error("xdp_handoff_key_fence_read", error)),
                }
            }
            Ok(())
        }

        fn unpin_namespace(map_pin_dir: &Path, remove_directory: bool) -> Result<(), IpsecLbError> {
            // Remove authority-bearing state before its schema, but retain the
            // scalar fence as the final crash witness. Every interrupted SDK
            // cleanup is therefore either self-describing or the narrowly
            // recognized, exact-schema scalar-fence tail.
            for map_name in [
                MAP_OWNERS,
                MAP_COUNTERS,
                MAP_KEY_FENCES,
                MAP_CONFIG,
                MAP_FENCE,
            ] {
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
            [
                MAP_OWNERS,
                MAP_CONFIG,
                MAP_FENCE,
                MAP_KEY_FENCES,
                MAP_COUNTERS,
            ]
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
                    MAP_KEY_FENCES,
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
                let allowed = [
                    MAP_OWNERS,
                    MAP_CONFIG,
                    MAP_FENCE,
                    MAP_KEY_FENCES,
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
            let fence_mode_matches = if value[0] >= 5 {
                value[1] == expected[1]
            } else {
                value[1] == 0
            };
            fence_mode_matches
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
                let expected_type = if value[0] >= 4 {
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
            let mut owners = BTreeMap::new();
            let mut key_fences = BTreeMap::new();
            let owners_map_present = path.join(MAP_OWNERS).exists();
            let key_fence_map_present = path.join(MAP_KEY_FENCES).exists();
            let counters_map_present = path.join(MAP_COUNTERS).exists();
            if path.join(MAP_CONFIG).exists() {
                let (value, map_type, id) =
                    Self::partial_config_pin(&path.join(MAP_CONFIG), expected_config)?;
                config = value;
                config_type = Some(map_type);
                map_ids.insert(id);
            }
            if path.join(MAP_OWNERS).exists() {
                let (observed, id) =
                    Self::read_pinned_owners(&path.join(MAP_OWNERS), expected_config)?;
                owners = observed;
                map_ids.insert(id);
            }
            if path.join(MAP_KEY_FENCES).exists() {
                let (observed, id) =
                    Self::read_pinned_key_fences(&path.join(MAP_KEY_FENCES), expected_config)?;
                key_fences = observed;
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
                version: config.map(|value| value[0]),
                fence_generation,
                owners,
                owners_map_present,
                key_fences,
                key_fence_map_present,
                counters_map_present,
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
            let expected_config_type = if version >= 4 {
                MapType::Hash
            } else {
                MapType::Array
            };
            if config_type != expected_config_type {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }

            let (owners, owners_id) =
                Self::read_pinned_owners(&path.join(MAP_OWNERS), expected_config)?;
            let (_, counters_id) = Self::map_schema(
                &path.join(MAP_COUNTERS),
                "xdp_upgrade_counters_schema",
                MapType::PerCpuArray,
                4,
                8,
                COUNTER_SLOTS,
            )?;

            let mut map_ids = BTreeSet::from([config_id, owners_id, counters_id]);
            let key_fences = if version >= 5 {
                if !path.join(MAP_KEY_FENCES).is_file() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                let (key_fences, key_fences_id) =
                    Self::read_pinned_key_fences(&path.join(MAP_KEY_FENCES), expected_config)?;
                map_ids.insert(key_fences_id);
                key_fences
            } else {
                if path.join(MAP_KEY_FENCES).exists() {
                    return Err(IpsecLbError::XdpUpgradeIndeterminate);
                }
                BTreeMap::new()
            };
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

            if version >= 5 && config[1] == 1 {
                for (key, raw_owner) in &owners {
                    let owner = XdpOwnerValue::decode(raw_owner)
                        .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
                    if key_fences
                        .get(key)
                        .is_some_and(|fence| *fence != owner.generation)
                    {
                        return Err(IpsecLbError::XdpUpgradeIndeterminate);
                    }
                }
            }

            Ok(Some(PinnedMapNamespace {
                slot,
                version,
                config,
                fence_generation,
                owners,
                key_fences,
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

        fn staging_slot(
            inventory: &PinnedNamespaceInventory,
            expected_config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<MapNamespaceSlot, IpsecLbError> {
            for candidate in [MapNamespaceSlot::A, MapNamespaceSlot::B] {
                if !inventory.has_slot(candidate)
                    || inventory.target_overwrite_is_redundant(candidate, expected_config)?
                {
                    return Ok(candidate);
                }
            }
            Err(IpsecLbError::XdpUpgradeIndeterminate)
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
                3..=5 => {
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
            expected_owners: &PinnedOwners,
            expected_key_fences: &PinnedKeyFences,
            program: &ProgramInfo,
        ) -> Result<(), IpsecLbError> {
            let staged = Self::inspect_namespace(interface_dir, slot, expected_config)?
                .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
            if staged.version != XDP_CONFIG_ABI_VERSION
                || staged.config != *expected_config
                || staged.fence_generation != expected_fence
                || staged.owners != *expected_owners
                || staged.key_fences != *expected_key_fences
            {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
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
            let (active, auxiliary_map_id) =
                Self::select_active_namespace(namespaces, &program_map_ids)?;
            let auxiliary = MapInfo::from_id(auxiliary_map_id)
                .map_err(|error| map_error("xdp_upgrade_auxiliary_map_info", error))?;
            let auxiliary_type = auxiliary
                .map_type()
                .map_err(|error| map_error("xdp_upgrade_auxiliary_map_info", error))?;
            if !auxiliary_rodata_schema_matches(
                auxiliary.name(),
                auxiliary_type,
                auxiliary.key_size(),
                auxiliary.value_size(),
                auxiliary.max_entries(),
                auxiliary.map_flags(),
            ) {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            Ok(active)
        }

        fn select_active_namespace<'a>(
            namespaces: &'a [PinnedMapNamespace],
            program_map_ids: &BTreeSet<u32>,
        ) -> Result<(&'a PinnedMapNamespace, u32), IpsecLbError> {
            let mut matching = namespaces
                .iter()
                .filter(|namespace| namespace.map_ids.is_subset(program_map_ids));
            let active = matching
                .next()
                .ok_or(IpsecLbError::XdpUpgradeRequiresDrain)?;
            if matching.next().is_some() {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            let mut auxiliary = program_map_ids.difference(&active.map_ids).copied();
            let auxiliary_map_id = auxiliary
                .next()
                .ok_or(IpsecLbError::XdpUpgradeIndeterminate)?;
            if auxiliary.next().is_some() {
                return Err(IpsecLbError::XdpUpgradeIndeterminate);
            }
            Ok((active, auxiliary_map_id))
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
            inventory.validate_destination_scoped_migration(&config)?;
            let fence_generation = inventory.max_fence();
            let recovery_maps = inventory.recovery_maps_for_config(&config)?;
            let map_slot = Self::staging_slot(&inventory, &config)?;
            let map_pin_dir = map_slot.path(interface_dir);
            Self::unpin_namespace(&map_pin_dir, map_slot.remove_directory())?;
            let mut ebpf = Self::load_fresh(&map_pin_dir)?;
            let stage_result = (|| {
                Self::config_write_map(&mut ebpf, config)?;
                let mut fence = Self::fence_map(&mut ebpf)?;
                fence
                    .insert(FENCE_KEY, fence_generation, 0)
                    .map_err(|error| map_error("xdp_fence_initialize", error))?;
                Self::write_owners_map(&mut ebpf, &recovery_maps.owners)?;
                Self::write_key_fences_map(&mut ebpf, &recovery_maps.key_fences)?;
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
                &recovery_maps.owners,
                &recovery_maps.key_fences,
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
                let fence_generation = {
                    let fence = Self::fence_map(&mut device.ebpf)?;
                    match fence.get(&FENCE_KEY, 0) {
                        Ok(value) => value,
                        Err(MapError::KeyNotFound) => 0,
                        Err(error) => return Err(map_error("xdp_fence_read", error)),
                    }
                };
                let config = Self::config_read_map(&mut device.ebpf)?;
                match config[1] {
                    0 => {
                        Self::seed_live_key_fences_from_owners(
                            &mut device.ebpf,
                            fence_generation,
                            &config,
                        )?;
                        Self::owners_flush_map(&mut device.ebpf)?;
                        Self::owners_empty_map(&mut device.ebpf)?;
                    }
                    1 => Self::prepare_live_per_key_handoff(&mut device.ebpf, &config)?,
                    _ => return Err(IpsecLbError::XdpUpgradeIndeterminate),
                }
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
            let mut inventory =
                Self::inspect_namespaces(interface_dir, &config).map_err(unchanged)?;
            inventory
                .validate_destination_scoped_migration(&config)
                .map_err(unchanged)?;
            let active = Self::active_namespace(&inventory.complete, &old_program_info)
                .map_err(unchanged)?;
            if inventory
                .partial
                .iter()
                .any(|partial| !partial.map_ids.is_disjoint(&active.map_ids))
            {
                return Err(unchanged(IpsecLbError::XdpUpgradeIndeterminate));
            }
            let fence_generation = inventory.max_fence();
            let target_slot = match active.slot {
                MapNamespaceSlot::A => MapNamespaceSlot::B,
                MapNamespaceSlot::Legacy | MapNamespaceSlot::B => MapNamespaceSlot::A,
            };
            if active.fence_generation < fence_generation {
                Self::persist_namespace_fence(interface_dir, active, fence_generation, &config)
                    .map_err(unchanged)?;
                // Re-read all pins after carrying the scalar maximum into the
                // live namespace. A disjoint scalar-only target is now
                // redundant, but unique owner/keyed-fence evidence must still
                // prevent target erasure.
                inventory = Self::inspect_namespaces(interface_dir, &config).map_err(unchanged)?;
                inventory
                    .validate_destination_scoped_migration(&config)
                    .map_err(unchanged)?;
                let refreshed_active =
                    Self::active_namespace(&inventory.complete, &old_program_info)
                        .map_err(unchanged)?;
                if refreshed_active.slot == target_slot
                    || inventory
                        .partial
                        .iter()
                        .any(|partial| !partial.map_ids.is_disjoint(&refreshed_active.map_ids))
                {
                    return Err(unchanged(IpsecLbError::XdpUpgradeIndeterminate));
                }
            }
            if !inventory
                .target_overwrite_is_redundant(target_slot, &config)
                .map_err(unchanged)?
            {
                return Err(unchanged(IpsecLbError::XdpUpgradeRequiresDrain));
            }
            let recovery_maps = inventory
                .recovery_maps_for_config(&config)
                .map_err(unchanged)?;
            let target_dir = target_slot.path(interface_dir);
            Self::unpin_namespace(&target_dir, target_slot.remove_directory())
                .map_err(unchanged)?;
            let mut new_ebpf = Self::load_fresh(&target_dir).map_err(unchanged)?;

            let initialize_result = (|| {
                Self::config_write_map(&mut new_ebpf, config)?;
                let mut fence = Self::fence_map(&mut new_ebpf)?;
                fence
                    .insert(FENCE_KEY, fence_generation, 0)
                    .map_err(|error| map_error("xdp_upgrade_fence_initialize", error))?;
                Self::write_owners_map(&mut new_ebpf, &recovery_maps.owners)?;
                Self::write_key_fences_map(&mut new_ebpf, &recovery_maps.key_fences)?;
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
                &recovery_maps.owners,
                &recovery_maps.key_fences,
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

        fn key_fence_read(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<Option<u64>, IpsecLbError> {
            self.with_device(ifindex, "xdp_key_fence_read", |device| {
                let hash = Self::key_fences_map(&mut device.ebpf)?;
                match hash.get(&key, 0) {
                    Ok(generation) => Ok(Some(generation)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("xdp_key_fence_read", error)),
                }
            })
        }

        fn key_fence_write(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
            generation: u64,
        ) -> Result<(), IpsecLbError> {
            self.with_device(ifindex, "xdp_key_fence_write", |device| {
                let mut hash = Self::key_fences_map(&mut device.ebpf)?;
                hash.insert(key, generation, 0)
                    .map_err(|error| map_error("xdp_key_fence_write", error))
            })
        }

        fn key_fence_remove(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<bool, IpsecLbError> {
            self.with_device(ifindex, "xdp_key_fence_remove", |device| {
                let mut hash = Self::key_fences_map(&mut device.ebpf)?;
                match hash.remove(&key) {
                    Ok(()) => Ok(true),
                    Err(MapError::KeyNotFound) => Ok(false),
                    Err(error) => Err(map_error("xdp_key_fence_remove", error)),
                }
            })
        }

        fn quiesce_repin(&self, ifindex: u32) -> Result<(), IpsecLbError> {
            self.with_device(ifindex, "xdp_repin_quiesce", |device| {
                let map = device.ebpf.map_mut(MAP_CONFIG).ok_or_else(|| {
                    IpsecLbError::io("xdp_config_map", invalid_data("map missing"))
                })?;
                let mut hash = BpfHashMap::<_, u32, [u8; CONFIG_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("xdp_config_map", error))?;
                let remove = hash
                    .remove(&CONFIG_KEY)
                    .map_err(|error| map_error("xdp_repin_quiesce", error));
                match hash.get(&CONFIG_KEY, 0) {
                    Err(MapError::KeyNotFound) => Ok(()),
                    Ok(_) => Err(remove.err().unwrap_or_else(|| {
                        IpsecLbError::adapter_contract_violation(
                            "host_xdp_repin_quiesce_readback_mismatch",
                        )
                    })),
                    Err(error) => Err(map_error("xdp_repin_quiesce_readback", error)),
                }
            })
        }

        fn repin_pins_feasible(
            &self,
            pin_dir: &Path,
            config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            Self::repin_pins_feasible(pin_dir, config)
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
    // Four total attempts bound transient kernel inconsistency without turning
    // sustained link churn into an unbounded lifecycle stall.
    const MAX_LINK_DUMP_RETRIES: u32 = 3;
    const LINK_DUMP_RETRY_DELAY_MILLIS: u64 = 2;
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
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LinkDumpProgress {
        More,
        Done,
        Interrupted,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LinkQueryAttempt {
        Complete(LinkQuery),
        Interrupted,
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
        retry_interrupted_link_query(
            || link_query_once(ifindex),
            |retry| {
                std::thread::sleep(std::time::Duration::from_millis(
                    LINK_DUMP_RETRY_DELAY_MILLIS.saturating_mul(u64::from(retry)),
                ));
            },
        )
    }

    fn retry_interrupted_link_query(
        mut attempt: impl FnMut() -> Result<LinkQueryAttempt, IpsecLbError>,
        mut wait_before_retry: impl FnMut(u32),
    ) -> Result<LinkQuery, IpsecLbError> {
        let mut retries = 0_u32;
        loop {
            match attempt()? {
                LinkQueryAttempt::Complete(query) => return Ok(query),
                LinkQueryAttempt::Interrupted if retries < MAX_LINK_DUMP_RETRIES => {
                    retries = retries.saturating_add(1);
                    wait_before_retry(retries);
                }
                LinkQueryAttempt::Interrupted => return Err(incomplete_link_dump()),
            }
        }
    }

    fn link_query_once(ifindex: u32) -> Result<LinkQueryAttempt, IpsecLbError> {
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

        collect_link_query(LINK_DUMP_SEQUENCE, local_port_id, ifindex, |buffer| {
            sys::receive_message(&socket, buffer)
        })
    }

    fn collect_link_query(
        expected_sequence: u32,
        expected_port_id: u32,
        requested_ifindex: u32,
        mut receive: impl FnMut(&mut [u8]) -> io::Result<usize>,
    ) -> Result<LinkQueryAttempt, IpsecLbError> {
        let mut query = LinkQuery::default();
        let mut buffer = [0_u8; 65_536];
        let mut empty_attempts = 0_u32;
        let mut datagrams = 0_usize;
        let mut messages = 0_usize;
        let mut total_bytes = 0_usize;
        loop {
            match receive(&mut buffer) {
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
                    match parse_link_dump_datagram(
                        &buffer[..length],
                        expected_sequence,
                        expected_port_id,
                        requested_ifindex,
                        &mut messages,
                        &mut query,
                    )? {
                        LinkDumpProgress::More => {}
                        LinkDumpProgress::Done => {
                            return Ok(LinkQueryAttempt::Complete(query));
                        }
                        LinkDumpProgress::Interrupted => {
                            return Ok(LinkQueryAttempt::Interrupted);
                        }
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
    ) -> Result<LinkDumpProgress, IpsecLbError> {
        let mut cursor = 0_usize;
        let mut done = false;
        let mut interrupted = false;
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
                interrupted = true;
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
                NLMSG_ERROR => return Err(incomplete_link_dump()),
                NLMSG_OVERRUN => {
                    if !body.is_empty() {
                        return Err(malformed_link_dump());
                    }
                    interrupted = true;
                }
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
        Ok(if interrupted {
            LinkDumpProgress::Interrupted
        } else if done {
            LinkDumpProgress::Done
        } else {
            LinkDumpProgress::More
        })
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

    fn auxiliary_rodata_schema_matches(
        name: &[u8],
        map_type: MapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> bool {
        name == AUXILIARY_RODATA_MAP
            && map_type == MapType::Array
            && key_size == 4
            && value_size == 4
            && max_entries == 1
            && map_flags == AUXILIARY_RODATA_FLAGS
    }

    #[cfg(test)]
    mod namespace_tests {
        use super::*;

        fn namespace(slot: MapNamespaceSlot, map_ids: &[u32]) -> PinnedMapNamespace {
            PinnedMapNamespace {
                slot,
                version: XDP_CONFIG_ABI_VERSION,
                config: [0; CONFIG_VALUE_LEN],
                fence_generation: 0,
                owners: BTreeMap::new(),
                key_fences: BTreeMap::new(),
                map_ids: map_ids.iter().copied().collect(),
            }
        }

        fn raw_owner(owner_shard: u16, generation: u64) -> [u8; OWNER_VALUE_LEN] {
            XdpOwnerValue {
                owner_shard,
                generation,
            }
            .encode()
        }

        fn config(fence_mode: u8) -> [u8; CONFIG_VALUE_LEN] {
            let mut config = [0; CONFIG_VALUE_LEN];
            config[0] = XDP_CONFIG_ABI_VERSION;
            config[1] = fence_mode;
            config
        }

        fn partial_namespace(
            version: Option<u8>,
            owners: PinnedOwners,
            owners_map_present: bool,
            key_fences: PinnedKeyFences,
            key_fence_map_present: bool,
            counters_map_present: bool,
            map_ids: &[u32],
        ) -> PartialPinnedMapNamespace {
            PartialPinnedMapNamespace {
                slot: MapNamespaceSlot::A,
                version,
                fence_generation: 19,
                owners,
                owners_map_present,
                key_fences,
                key_fence_map_present,
                counters_map_present,
                map_ids: map_ids.iter().copied().collect(),
            }
        }

        #[test]
        fn v5_cleanup_prefixes_preserve_every_remaining_authority_witness() {
            let key = [7; OWNER_KEY_LEN];
            let destination_scoped = config(1);
            let mut complete = namespace(MapNamespaceSlot::A, &[1, 2, 3, 4, 5]);
            complete.fence_generation = 19;
            complete.owners.insert(key, raw_owner(2, 17));
            complete.key_fences.insert(key, 17);
            let complete_inventory = PinnedNamespaceInventory {
                complete: vec![complete],
                partial: Vec::new(),
            };
            assert_eq!(
                complete_inventory.validate_destination_scoped_migration(&destination_scoped),
                Ok(()),
                "complete cut 0 must remain recoverable"
            );
            assert_eq!(complete_inventory.max_fence(), 19);
            let recovered = complete_inventory
                .recovery_maps_for_config(&destination_scoped)
                .expect("recover complete v5 namespace");
            assert_eq!(recovered.owners.get(&key), Some(&raw_owner(2, 17)));
            assert!(!recovered.key_fences.contains_key(&key));

            let prefixes = [
                partial_namespace(
                    Some(XDP_CONFIG_ABI_VERSION),
                    BTreeMap::new(),
                    false,
                    BTreeMap::from([(key, 17)]),
                    true,
                    true,
                    &[1, 2, 3, 4],
                ),
                partial_namespace(
                    Some(XDP_CONFIG_ABI_VERSION),
                    BTreeMap::new(),
                    false,
                    BTreeMap::from([(key, 17)]),
                    true,
                    false,
                    &[1, 2, 3],
                ),
                partial_namespace(
                    Some(XDP_CONFIG_ABI_VERSION),
                    BTreeMap::new(),
                    false,
                    BTreeMap::new(),
                    false,
                    false,
                    &[1, 2],
                ),
                partial_namespace(
                    None,
                    BTreeMap::new(),
                    false,
                    BTreeMap::new(),
                    false,
                    false,
                    &[1],
                ),
            ];

            for (index, partial) in prefixes.into_iter().enumerate() {
                let inventory = PinnedNamespaceInventory {
                    complete: Vec::new(),
                    partial: vec![partial],
                };
                assert_eq!(
                    inventory.validate_destination_scoped_migration(&destination_scoped),
                    Ok(()),
                    "cleanup cut {} must remain recoverable",
                    index + 1
                );
                assert_eq!(inventory.max_fence(), 19);
                let recovered = inventory
                    .recovery_maps_for_config(&destination_scoped)
                    .expect("recover exact cleanup prefix");
                if index < 2 {
                    assert_eq!(recovered.key_fences.get(&key), Some(&17));
                } else {
                    assert!(recovered.key_fences.is_empty());
                }
                assert!(recovered.owners.is_empty());
            }

            let empty = PinnedNamespaceInventory::default();
            assert_eq!(
                empty.validate_destination_scoped_migration(&destination_scoped),
                Ok(())
            );
        }

        #[test]
        fn v5_cleanup_residue_classifier_rejects_ambiguous_pin_mixtures() {
            let key = [7; OWNER_KEY_LEN];
            let destination_scoped = config(1);
            let ambiguous = [
                partial_namespace(
                    Some(XDP_CONFIG_ABI_VERSION),
                    BTreeMap::new(),
                    true,
                    BTreeMap::new(),
                    false,
                    false,
                    &[1, 2, 3],
                ),
                partial_namespace(
                    Some(XDP_CONFIG_ABI_VERSION),
                    BTreeMap::new(),
                    false,
                    BTreeMap::new(),
                    false,
                    true,
                    &[1, 2, 3],
                ),
                partial_namespace(
                    Some(XDP_CONFIG_ABI_VERSION),
                    BTreeMap::from([(key, raw_owner(2, 17))]),
                    false,
                    BTreeMap::new(),
                    false,
                    false,
                    &[1, 2],
                ),
                partial_namespace(
                    Some(XDP_CONFIG_ABI_VERSION),
                    BTreeMap::new(),
                    false,
                    BTreeMap::from([(key, 17)]),
                    false,
                    false,
                    &[1, 2],
                ),
                partial_namespace(
                    Some(XDP_CONFIG_ABI_VERSION),
                    BTreeMap::new(),
                    false,
                    BTreeMap::new(),
                    false,
                    false,
                    &[1, 2, 3],
                ),
                partial_namespace(
                    None,
                    BTreeMap::new(),
                    false,
                    BTreeMap::new(),
                    false,
                    false,
                    &[1, 2],
                ),
                partial_namespace(
                    None,
                    BTreeMap::new(),
                    false,
                    BTreeMap::new(),
                    false,
                    true,
                    &[1, 2],
                ),
            ];

            for partial in ambiguous {
                let inventory = PinnedNamespaceInventory {
                    complete: Vec::new(),
                    partial: vec![partial],
                };
                assert_eq!(
                    inventory.validate_destination_scoped_migration(&destination_scoped),
                    Err(IpsecLbError::XdpUpgradeIndeterminate)
                );
            }
        }

        #[test]
        fn v5_restart_preserves_owner_only_and_fence_only_witnesses() {
            let live_key = [1; OWNER_KEY_LEN];
            let staged_key = [2; OWNER_KEY_LEN];
            let wrong_owner_key = [3; OWNER_KEY_LEN];
            let fence_only_key = [4; OWNER_KEY_LEN];
            let mut pinned = namespace(MapNamespaceSlot::A, &[1, 2, 3, 4, 5]);
            pinned.owners.insert(live_key, raw_owner(2, 10));
            pinned.key_fences.insert(live_key, 10);
            pinned.owners.insert(staged_key, raw_owner(3, 11));
            pinned.owners.insert(wrong_owner_key, raw_owner(4, 12));
            pinned.key_fences.insert(fence_only_key, 13);
            let inventory = PinnedNamespaceInventory {
                complete: vec![pinned],
                partial: Vec::new(),
            };

            let recovered = inventory.recovery_maps().expect("normalize v5 restart");
            assert_eq!(recovered.owners.get(&live_key), Some(&raw_owner(2, 10)));
            assert_eq!(recovered.owners.get(&staged_key), Some(&raw_owner(3, 11)));
            assert_eq!(
                recovered.owners.get(&wrong_owner_key),
                Some(&raw_owner(4, 12))
            );
            assert!(!recovered.key_fences.contains_key(&live_key));
            assert_eq!(recovered.key_fences.get(&fence_only_key), Some(&13));
        }

        #[test]
        fn v5_restart_rejects_mismatched_owner_and_fence_pair() {
            let key = [1; OWNER_KEY_LEN];
            let mut pinned = namespace(MapNamespaceSlot::A, &[1, 2, 3, 4, 5]);
            pinned.owners.insert(key, raw_owner(2, 10));
            pinned.key_fences.insert(key, 11);
            let inventory = PinnedNamespaceInventory {
                complete: vec![pinned],
                partial: Vec::new(),
            };

            assert_eq!(
                inventory.recovery_maps(),
                Err(IpsecLbError::XdpUpgradeIndeterminate)
            );
        }

        #[test]
        fn legacy_restart_seeds_only_a_fence_witness() {
            let key = [1; OWNER_KEY_LEN];
            let mut pinned = namespace(MapNamespaceSlot::Legacy, &[1, 2, 3, 4]);
            pinned.version = 4;
            pinned.fence_generation = 12;
            pinned.owners.insert(key, raw_owner(2, 10));
            let inventory = PinnedNamespaceInventory {
                complete: vec![pinned],
                partial: Vec::new(),
            };

            let recovered = inventory.recovery_maps().expect("normalize legacy restart");
            assert!(recovered.owners.is_empty());
            assert_eq!(recovered.key_fences.get(&key), Some(&12));
        }

        #[test]
        fn partial_legacy_evidence_cannot_coexist_with_a_recovered_owner() {
            let key = [1; OWNER_KEY_LEN];
            for (legacy_generation, expected_owner, expected_fence) in [
                (9, true, None),
                (10, false, Some(10)),
                (11, false, Some(11)),
            ] {
                let mut current = namespace(MapNamespaceSlot::A, &[1, 2, 3, 4, 5]);
                current.owners.insert(key, raw_owner(2, 10));
                let partial = PartialPinnedMapNamespace {
                    slot: MapNamespaceSlot::B,
                    version: Some(4),
                    fence_generation: 0,
                    owners: BTreeMap::from([(key, raw_owner(3, legacy_generation))]),
                    owners_map_present: true,
                    key_fences: BTreeMap::new(),
                    key_fence_map_present: false,
                    counters_map_present: false,
                    map_ids: BTreeSet::new(),
                };
                let inventory = PinnedNamespaceInventory {
                    complete: vec![current],
                    partial: vec![partial],
                };

                let recovered = inventory.recovery_maps().expect("merge legacy witness");
                assert_eq!(recovered.owners.contains_key(&key), expected_owner);
                assert_eq!(recovered.key_fences.get(&key).copied(), expected_fence);
                assert!(recovered
                    .owners
                    .keys()
                    .all(|owner_key| !recovered.key_fences.contains_key(owner_key)));
            }
        }

        #[test]
        fn global_attach_and_adoption_never_rearm_persisted_owners() {
            let key = [1; OWNER_KEY_LEN];
            let mut active = namespace(MapNamespaceSlot::A, &[1, 2, 3, 4, 5]);
            active.fence_generation = 10;
            active.owners.insert(key, raw_owner(2, 10));
            active.key_fences.insert(key, 10);
            let inventory = PinnedNamespaceInventory {
                complete: vec![active],
                partial: Vec::new(),
            };
            let global_config = config(0);

            let recovered = inventory
                .recovery_maps_for_config(&global_config)
                .expect("normalize global restart");
            assert!(recovered.owners.is_empty());
            assert_eq!(recovered.key_fences.get(&key), Some(&10));
            assert_eq!(
                AyaHostXdpRuntime::staging_slot(&inventory, &global_config),
                Ok(MapNamespaceSlot::B)
            );
            assert_eq!(
                inventory.target_overwrite_is_redundant(MapNamespaceSlot::B, &global_config),
                Ok(true)
            );
        }

        #[test]
        fn scalar_only_target_becomes_redundant_after_active_fence_carry_forward() {
            let mut active = namespace(MapNamespaceSlot::Legacy, &[1, 2, 3, 4, 5]);
            active.fence_generation = 83;
            let scalar_only_target = PartialPinnedMapNamespace {
                slot: MapNamespaceSlot::A,
                version: None,
                fence_generation: 84,
                owners: BTreeMap::new(),
                owners_map_present: false,
                key_fences: BTreeMap::new(),
                key_fence_map_present: false,
                counters_map_present: false,
                map_ids: BTreeSet::from([6]),
            };
            let mut inventory = PinnedNamespaceInventory {
                complete: vec![active],
                partial: vec![scalar_only_target],
            };
            let global_config = config(0);

            assert_eq!(
                inventory.target_overwrite_is_redundant(MapNamespaceSlot::A, &global_config,),
                Ok(false),
                "the unique scalar maximum must not be erased"
            );

            let max_fence = inventory.max_fence();
            inventory.complete[0].fence_generation = max_fence;
            assert_eq!(
                inventory.target_overwrite_is_redundant(MapNamespaceSlot::A, &global_config,),
                Ok(true),
                "a target is disposable only after the live namespace carries its maximum"
            );
        }

        #[test]
        fn adoption_refuses_to_unpin_unique_owner_or_fence_witness() {
            let owner_key = [1; OWNER_KEY_LEN];
            let fence_key = [2; OWNER_KEY_LEN];
            let active = namespace(MapNamespaceSlot::A, &[1, 2, 3, 4, 5]);
            let destination_scoped_config = config(1);

            let mut unique_owner = namespace(MapNamespaceSlot::B, &[6, 7, 8, 9, 10]);
            unique_owner.owners.insert(owner_key, raw_owner(2, 10));
            let owner_inventory = PinnedNamespaceInventory {
                complete: vec![active],
                partial: vec![PartialPinnedMapNamespace {
                    slot: MapNamespaceSlot::B,
                    version: Some(unique_owner.version),
                    fence_generation: unique_owner.fence_generation,
                    owners: unique_owner.owners,
                    owners_map_present: true,
                    key_fences: unique_owner.key_fences,
                    key_fence_map_present: true,
                    counters_map_present: false,
                    map_ids: unique_owner.map_ids,
                }],
            };
            assert_eq!(
                owner_inventory.target_overwrite_is_redundant(
                    MapNamespaceSlot::B,
                    &destination_scoped_config,
                ),
                Ok(false)
            );

            let active = namespace(MapNamespaceSlot::A, &[1, 2, 3, 4, 5]);
            let mut unique_fence = namespace(MapNamespaceSlot::B, &[6, 7, 8, 9, 10]);
            unique_fence.key_fences.insert(fence_key, 11);
            let fence_inventory = PinnedNamespaceInventory {
                complete: vec![active, unique_fence],
                partial: Vec::new(),
            };
            assert_eq!(
                fence_inventory.target_overwrite_is_redundant(
                    MapNamespaceSlot::B,
                    &destination_scoped_config,
                ),
                Ok(false)
            );
        }

        #[test]
        fn active_namespace_accepts_exactly_one_auxiliary_map() {
            let namespaces = [namespace(MapNamespaceSlot::A, &[1, 2, 3, 4])];
            let program_map_ids = BTreeSet::from([1, 2, 3, 4, 5]);

            let (active, auxiliary) =
                AyaHostXdpRuntime::select_active_namespace(&namespaces, &program_map_ids)
                    .expect("select namespace with compiler rodata map");

            assert_eq!(active.slot, MapNamespaceSlot::A);
            assert_eq!(auxiliary, 5);
        }

        #[test]
        fn active_namespace_rejects_missing_multiple_and_ambiguous_auxiliary_maps() {
            let namespaces = [namespace(MapNamespaceSlot::A, &[1, 2, 3, 4])];
            for program_map_ids in [
                BTreeSet::from([1, 2, 3, 4]),
                BTreeSet::from([1, 2, 3, 4, 5, 6]),
            ] {
                assert!(matches!(
                    AyaHostXdpRuntime::select_active_namespace(&namespaces, &program_map_ids),
                    Err(IpsecLbError::XdpUpgradeIndeterminate)
                ));
            }

            let ambiguous = [
                namespace(MapNamespaceSlot::A, &[1, 2, 3, 4]),
                namespace(MapNamespaceSlot::B, &[5, 6, 7, 8]),
            ];
            assert!(matches!(
                AyaHostXdpRuntime::select_active_namespace(
                    &ambiguous,
                    &BTreeSet::from([1, 2, 3, 4, 5, 6, 7, 8, 9]),
                ),
                Err(IpsecLbError::XdpUpgradeIndeterminate)
            ));
        }

        #[test]
        fn auxiliary_rodata_schema_is_exact() {
            assert!(auxiliary_rodata_schema_matches(
                AUXILIARY_RODATA_MAP,
                MapType::Array,
                4,
                4,
                1,
                AUXILIARY_RODATA_FLAGS,
            ));
            assert!(!auxiliary_rodata_schema_matches(
                b"other",
                MapType::Array,
                4,
                4,
                1,
                AUXILIARY_RODATA_FLAGS,
            ));
            assert!(!auxiliary_rodata_schema_matches(
                AUXILIARY_RODATA_MAP,
                MapType::Hash,
                4,
                4,
                1,
                AUXILIARY_RODATA_FLAGS,
            ));
            assert!(!auxiliary_rodata_schema_matches(
                AUXILIARY_RODATA_MAP,
                MapType::Array,
                4,
                4,
                1,
                0,
            ));
        }
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

        fn parse(datagram: &[u8]) -> Result<(LinkDumpProgress, LinkQuery, usize), IpsecLbError> {
            let mut messages = 0;
            let mut query = LinkQuery::default();
            let progress = parse_link_dump_datagram(
                datagram,
                SEQUENCE,
                PORT_ID,
                IFINDEX,
                &mut messages,
                &mut query,
            )?;
            Ok((progress, query, messages))
        }

        fn collect(datagrams: Vec<Vec<u8>>) -> Result<LinkQueryAttempt, IpsecLbError> {
            let mut datagrams = datagrams.into_iter();
            collect_link_query(SEQUENCE, PORT_ID, IFINDEX, |buffer| {
                let datagram = datagrams.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "missing test datagram")
                })?;
                buffer[..datagram.len()].copy_from_slice(&datagram);
                Ok(datagram.len())
            })
        }

        fn assert_query_error(result: Result<(LinkDumpProgress, LinkQuery, usize), IpsecLbError>) {
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

            let (progress, query, messages) = parse(&datagram).expect("complete link dump");
            assert_eq!(progress, LinkDumpProgress::Done);
            assert_eq!(messages, 3);
            assert!(query.found);
            assert!(query.is_up);
            assert_eq!(query.xdp_prog_id, Some(4_209));
        }

        #[test]
        fn dump_without_done_never_yields_an_authoritative_result() {
            let datagram = link_message(IFINDEX, None);
            let (progress, query, messages) = parse(&datagram).expect("valid partial dump");
            assert_eq!(progress, LinkDumpProgress::More);
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
        fn interrupted_and_overrun_dumps_request_a_fresh_snapshot() {
            let mut interrupted = link_message(IFINDEX, None);
            interrupted[6..8].copy_from_slice(&(NLM_F_MULTI | NLM_F_DUMP_INTR).to_ne_bytes());
            assert_eq!(
                parse(&interrupted).expect("classify interrupted dump").0,
                LinkDumpProgress::Interrupted
            );

            assert_eq!(
                parse(&netlink_message(NLMSG_OVERRUN, 0, &[]))
                    .expect("classify overrun dump")
                    .0,
                LinkDumpProgress::Interrupted
            );
        }

        #[test]
        fn interruption_never_masks_malformed_dump_content() {
            assert_query_error(parse(&netlink_message(
                0x7fff,
                NLM_F_MULTI | NLM_F_DUMP_INTR,
                &[],
            )));
            assert_query_error(parse(&netlink_message(NLMSG_DONE, NLM_F_DUMP_INTR, &[])));

            let mut trailing = link_message(IFINDEX, None);
            trailing[6..8].copy_from_slice(&(NLM_F_MULTI | NLM_F_DUMP_INTR).to_ne_bytes());
            trailing.extend_from_slice(&[0; 4]);
            assert_query_error(parse(&trailing));
        }

        #[test]
        fn netlink_error_dump_remains_terminal() {
            assert_query_error(parse(&netlink_message(NLMSG_ERROR, NLM_F_MULTI, &[0; 4])));
        }

        #[test]
        fn interrupted_query_retries_from_a_fresh_snapshot() {
            let expected = LinkQuery {
                found: true,
                is_up: true,
                xdp_prog_id: Some(41),
                xdp_attach_kind: Some(XDP_ATTACHED_DRIVER),
            };
            let mut attempts = 0_u32;
            let mut waits = Vec::new();
            let mut interrupted_done = done_message(Some(0));
            interrupted_done[6..8].copy_from_slice(&(NLM_F_MULTI | NLM_F_DUMP_INTR).to_ne_bytes());
            let first_attempt = vec![link_message(IFINDEX, Some(99)), interrupted_done];
            let mut complete = link_message(IFINDEX, expected.xdp_prog_id);
            complete.extend_from_slice(&done_message(Some(0)));
            let second_attempt = vec![complete];
            let mut replies = [first_attempt, second_attempt].into_iter();

            let result = retry_interrupted_link_query(
                || {
                    attempts = attempts.saturating_add(1);
                    collect(replies.next().ok_or_else(incomplete_link_dump)?)
                },
                |retry| waits.push(retry),
            )
            .expect("second complete snapshot");

            assert_eq!(result, expected);
            assert_eq!(attempts, 2);
            assert_eq!(waits, vec![1]);
        }

        #[test]
        fn interrupted_query_exhaustion_is_bounded_and_fail_closed() {
            let mut attempts = 0_u32;
            let mut waits = Vec::new();

            let result = retry_interrupted_link_query(
                || {
                    attempts = attempts.saturating_add(1);
                    Ok(LinkQueryAttempt::Interrupted)
                },
                |retry| waits.push(retry),
            );

            assert_query_error(result.map(|query| (LinkDumpProgress::Done, query, 0)));
            assert_eq!(attempts, MAX_LINK_DUMP_RETRIES + 1);
            assert_eq!(waits, (1..=MAX_LINK_DUMP_RETRIES).collect::<Vec<_>>());
        }

        #[test]
        fn malformed_query_is_not_retried() {
            let mut attempts = 0_u32;
            let mut waits = 0_u32;

            let result = retry_interrupted_link_query(
                || {
                    attempts = attempts.saturating_add(1);
                    Err(malformed_link_dump())
                },
                |_| waits = waits.saturating_add(1),
            );

            assert_query_error(result.map(|query| (LinkDumpProgress::Done, query, 0)));
            assert_eq!(attempts, 1);
            assert_eq!(waits, 0);
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
    use std::sync::MutexGuard;

    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::process::Command;
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    use super::*;
    use crate::failover::{
        AntiReplayResume, SendIvCounterMode, SendIvForwardJump, MIN_SEND_IV_FORWARD_JUMP,
    };
    use crate::mock::{MockOwnershipFencer, MockOwnershipSource, MockRePinAuditSink};
    use crate::model::IpAddress;
    use crate::ownership::{
        DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi,
        EstablishedIkeOwnershipKey, IkeSpi,
    };
    use crate::repin::{
        OwnershipFence, OwnershipRetirementRequest, OwnershipTransitionId, RePinCoordinator,
        RePinRequest, RePinRetryStage, ResumeKeySource, SameSpiOutboundIvResume, SameSpiResume,
    };
    use opc_ipsec_lb_ebpf_common::{decide_owner_verdict_with_keyed_fence, XdpVerdict};
    use opc_ipsec_xfrm::OutboundSaBindingId;

    #[cfg(target_os = "linux")]
    static PROCESS_SPAWN_TEST_GUARD: Mutex<()> = Mutex::new(());

    #[cfg(target_os = "linux")]
    fn lock_process_spawn_tests() -> MutexGuard<'static, ()> {
        match PROCESS_SPAWN_TEST_GUARD.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

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
        key_fences: HashMap<(u32, [u8; OWNER_KEY_LEN]), u64>,
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
        owner_get_calls: usize,
        owner_get_failures: usize,
        owner_get_failure_on_call: Option<usize>,
        owner_get_override_on_call: Option<(usize, Option<[u8; OWNER_VALUE_LEN]>)>,
        owner_remove_calls: usize,
        owner_remove_failures: usize,
        owner_remove_failure_on_call: Option<usize>,
        owner_insert_error_after_apply: bool,
        key_fence_read_failures: usize,
        key_fence_read_calls: usize,
        key_fence_read_failure_on_call: Option<usize>,
        key_fence_write_failures: usize,
        key_fence_write_error_after_apply: bool,
        key_fence_remove_failures: usize,
        key_fence_remove_error_after_apply: bool,
        key_fence_read_failure_after_remove: bool,
        quiesce_failures: usize,
        repin_pins_error: Option<&'static str>,
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
                key_fences: HashMap::new(),
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
                owner_get_calls: 0,
                owner_get_failures: 0,
                owner_get_failure_on_call: None,
                owner_get_override_on_call: None,
                owner_remove_calls: 0,
                owner_remove_failures: 0,
                owner_remove_failure_on_call: None,
                owner_insert_error_after_apply: false,
                key_fence_read_failures: 0,
                key_fence_read_calls: 0,
                key_fence_read_failure_on_call: None,
                key_fence_write_failures: 0,
                key_fence_write_error_after_apply: false,
                key_fence_remove_failures: 0,
                key_fence_remove_error_after_apply: false,
                key_fence_read_failure_after_remove: false,
                quiesce_failures: 0,
                repin_pins_error: None,
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
            if XdpDatapathConfig::decode(&config)
                .is_some_and(|config| config.fence_mode == XdpFenceMode::PerOwnershipKey)
            {
                // Mirror production v5 recovery: a complete matching pair is
                // made non-live before the program is attached, retaining the
                // owner as an exact-retry witness while removing its fence.
                let live_keys: Vec<_> = state
                    .owners
                    .iter()
                    .filter_map(|(&(owner_ifindex, key), raw)| {
                        let owner = XdpOwnerValue::decode(raw)?;
                        (state.key_fences.get(&(owner_ifindex, key)) == Some(&owner.generation))
                            .then_some((owner_ifindex, key))
                    })
                    .collect();
                for key in live_keys {
                    state.key_fences.remove(&key);
                }
            }
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
            // Successful production detach unpins the namespace maps. Model
            // that cleanup so a proven Detached state can be probed and
            // reattached from a clean namespace.
            state.config = None;
            state
                .owners
                .retain(|(owner_ifindex, _), _| *owner_ifindex != ifindex);
            state
                .key_fences
                .retain(|(fence_ifindex, _), _| *fence_ifindex != ifindex);
            state.fences.remove(&ifindex);
            Ok(())
        }

        fn owner_get(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<Option<[u8; OWNER_VALUE_LEN]>, IpsecLbError> {
            let mut state = self.state();
            state.owner_get_calls = state.owner_get_calls.saturating_add(1);
            if state.owner_get_failure_on_call == Some(state.owner_get_calls) {
                state.owner_get_failure_on_call = None;
                return Err(IpsecLbError::io(
                    "xdp_test_owner_get",
                    io::Error::other("injected owner readback failure"),
                ));
            }
            if state.owner_get_failures > 0 {
                state.owner_get_failures -= 1;
                return Err(IpsecLbError::io(
                    "xdp_test_owner_get",
                    io::Error::other("injected owner readback failure"),
                ));
            }
            if state
                .owner_get_override_on_call
                .is_some_and(|(call, _)| call == state.owner_get_calls)
            {
                return Ok(state
                    .owner_get_override_on_call
                    .take()
                    .and_then(|(_, value)| value));
            }
            Ok(state.owners.get(&(ifindex, key)).copied())
        }

        fn owner_insert(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
            value: [u8; OWNER_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let mut state = self.state();
            state.owners.insert((ifindex, key), value);
            if state.owner_insert_error_after_apply {
                state.owner_insert_error_after_apply = false;
                return Err(IpsecLbError::io(
                    "xdp_test_owner_insert",
                    io::Error::other("injected owner insert acknowledgement failure"),
                ));
            }
            Ok(())
        }

        fn owner_remove(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<bool, IpsecLbError> {
            let mut state = self.state();
            state.owner_remove_calls = state.owner_remove_calls.saturating_add(1);
            if state.owner_remove_failure_on_call == Some(state.owner_remove_calls) {
                state.owner_remove_failure_on_call = None;
                return Err(IpsecLbError::io(
                    "xdp_test_owner_remove",
                    io::Error::other("injected owner rollback failure"),
                ));
            }
            if state.owner_remove_failures > 0 {
                state.owner_remove_failures -= 1;
                return Err(IpsecLbError::io(
                    "xdp_test_owner_remove",
                    io::Error::other("injected owner rollback failure"),
                ));
            }
            Ok(state.owners.remove(&(ifindex, key)).is_some())
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

        fn key_fence_read(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<Option<u64>, IpsecLbError> {
            let mut state = self.state();
            state.key_fence_read_calls = state.key_fence_read_calls.saturating_add(1);
            if state.key_fence_read_failure_on_call == Some(state.key_fence_read_calls) {
                state.key_fence_read_failure_on_call = None;
                return Err(IpsecLbError::io(
                    "xdp_test_key_fence_read",
                    io::Error::other("injected keyed-fence readback failure"),
                ));
            }
            if state.key_fence_read_failures > 0 {
                state.key_fence_read_failures -= 1;
                return Err(IpsecLbError::io(
                    "xdp_test_key_fence_read",
                    io::Error::other("injected keyed-fence readback failure"),
                ));
            }
            Ok(state.key_fences.get(&(ifindex, key)).copied())
        }

        fn key_fence_write(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
            generation: u64,
        ) -> Result<(), IpsecLbError> {
            let mut state = self.state();
            if state.key_fence_write_failures > 0 {
                state.key_fence_write_failures -= 1;
                return Err(IpsecLbError::io(
                    "xdp_test_key_fence_write",
                    io::Error::other("injected keyed-fence write failure"),
                ));
            }
            state.key_fences.insert((ifindex, key), generation);
            if state.key_fence_write_error_after_apply {
                state.key_fence_write_error_after_apply = false;
                return Err(IpsecLbError::io(
                    "xdp_test_key_fence_write",
                    io::Error::other("injected keyed-fence acknowledgement failure"),
                ));
            }
            Ok(())
        }

        fn key_fence_remove(
            &self,
            ifindex: u32,
            key: [u8; OWNER_KEY_LEN],
        ) -> Result<bool, IpsecLbError> {
            let mut state = self.state();
            if state.key_fence_remove_failures > 0 {
                state.key_fence_remove_failures -= 1;
                return Err(IpsecLbError::io(
                    "xdp_test_key_fence_remove",
                    io::Error::other("injected keyed-fence remove failure"),
                ));
            }
            let removed = state.key_fences.remove(&(ifindex, key)).is_some();
            if state.key_fence_read_failure_after_remove {
                state.key_fence_read_failure_after_remove = false;
                state.key_fence_read_failures = state.key_fence_read_failures.saturating_add(1);
            }
            if state.key_fence_remove_error_after_apply {
                state.key_fence_remove_error_after_apply = false;
                return Err(IpsecLbError::io(
                    "xdp_test_key_fence_remove",
                    io::Error::other("injected keyed-fence remove acknowledgement failure"),
                ));
            }
            Ok(removed)
        }

        fn quiesce_repin(&self, _ifindex: u32) -> Result<(), IpsecLbError> {
            let mut state = self.state();
            if state.quiesce_failures > 0 {
                state.quiesce_failures -= 1;
                return Err(IpsecLbError::io(
                    "xdp_test_repin_quiesce",
                    io::Error::other("injected repin quiesce failure"),
                ));
            }
            state.config = None;
            Ok(())
        }

        fn repin_pins_feasible(
            &self,
            _pin_dir: &Path,
            _config: &[u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            match self.state().repin_pins_error {
                Some(operation) => Err(IpsecLbError::io(
                    operation,
                    io::Error::other("injected keyed migration failure"),
                )),
                None => Ok(()),
            }
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

    fn repin_config() -> HostXdpSteeringBackendConfig {
        config().for_destination_scoped_repin()
    }

    fn apply_keyed_test_update(
        backend: &HostXdpSteeringBackend,
        key: &SessionOwnershipKey,
        owner: ShardId,
        generation: u64,
    ) -> Result<(), IpsecLbError> {
        let _operation = backend.operation_gate()?;
        let ifindex = backend.ensure_attached_under_gate()?;
        backend.apply_keyed_owner_under_gate(ifindex, key, owner, generation, None)
    }

    fn esp_key(spi: u32) -> SessionOwnershipKey {
        SessionOwnershipKey::Esp(EspOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([203, 0, 113, 7]), RoutingDomainTag::new(7)),
            EspEncapsulationKind::UdpEncapsulated,
            EspSpi::new(spi).expect("allocatable SPI"),
        ))
    }

    fn test_outbound_sa_binding_id(spi: u32) -> OutboundSaBindingId {
        let mut bytes = [0x66; 32];
        bytes[..4].copy_from_slice(&spi.to_be_bytes());
        OutboundSaBindingId::from_bytes(bytes)
    }

    fn owner_value(owner_shard: u16, generation: u64) -> [u8; OWNER_VALUE_LEN] {
        XdpOwnerValue {
            owner_shard,
            generation,
        }
        .encode()
    }

    fn coordinator_repin_request(
        spi: u32,
        ownership_key: SessionOwnershipKey,
        transition_id: u128,
    ) -> RePinRequest {
        let sa = crate::SaId::Esp { spi };
        RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(transition_id).expect("nonzero"),
            previous_fence: OwnershipFence::new(1).expect("nonzero"),
            previous_owner: crate::ClusterNode::new("source"),
            new_owner: crate::ClusterNode::new("target"),
            rule: crate::SteeringRule {
                shard: ShardId::new(7),
                owner: ShardId::new(3),
                key: crate::SteerKey::EspSpi(spi),
            },
            ownership_key,
            outbound_sa_binding_id: Some(test_outbound_sa_binding_id(spi)),
            resume: SameSpiResume {
                previous_sa: sa,
                resumed_sa: sa,
                outbound_iv: SameSpiOutboundIvResume::CounterBased {
                    checkpointed_send_iv_next: 10,
                    restored_send_iv_next: 10 + MIN_SEND_IV_FORWARD_JUMP,
                    forward_jump: Some(SendIvForwardJump {
                        forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                            max_peer_sequence_lag: 0,
                        },
                    }),
                },
                anti_replay: AntiReplayResume::ExactWindowRestore {
                    checkpoint_highest_accepted: 9,
                    restored_highest_accepted: 9,
                },
                key_source: ResumeKeySource::LiveMirrored,
            },
        }
    }

    fn deterministic_host_test_permit(
        backend: &HostXdpSteeringBackend,
        key: SessionOwnershipKey,
        retirement_armed: bool,
    ) -> RePinSteeringOperationPermit {
        let stripe = backend.repin_stripe(&key);
        let evidence = HostXdpRePinPermitEvidence {
            backend_identity: Arc::clone(&backend.inner.repin_identity),
            stripe,
            ownership_key: key,
            _guards: Arc::new(HostXdpRePinGuardSet {
                _guards: Vec::new(),
            }),
            poison_if_unclassified: retirement_armed,
            retirement_classified: false,
        };
        RePinSteeringOperationPermit::guarded(key, evidence)
    }

    #[derive(Debug, Clone, Copy)]
    struct IndeterminateRetirementAuthority;

    #[async_trait]
    impl crate::OwnershipFencer for IndeterminateRetirementAuthority {
        async fn recover_fence_grant(
            &self,
            _request: &crate::OwnershipFenceRequest,
        ) -> Result<Option<crate::OwnershipFenceGrant>, IpsecLbError> {
            Err(IpsecLbError::Unsupported)
        }

        async fn fence_sa_owner(
            &self,
            _request: crate::OwnershipFenceRequest,
        ) -> Result<crate::OwnershipFenceGrant, IpsecLbError> {
            Err(IpsecLbError::Unsupported)
        }

        async fn validate_retry_proof(
            &self,
            _proof: &crate::OwnershipRetryProof,
        ) -> Result<(), IpsecLbError> {
            Err(IpsecLbError::Unsupported)
        }
    }

    #[async_trait]
    impl crate::OwnershipRetirementAuthority for IndeterminateRetirementAuthority {
        async fn begin_ownership_retirement(
            &self,
            _request: OwnershipRetirementRequest,
        ) -> Result<crate::OwnershipRetirementAdmission, IpsecLbError> {
            Err(IpsecLbError::OwnershipRetirementIndeterminate)
        }

        async fn finalize_ownership_retirement(
            &self,
            _cleanup: &crate::OwnershipCleanupCompleteProof,
        ) -> Result<crate::OwnershipRetirementFinalization, IpsecLbError> {
            Err(IpsecLbError::Unsupported)
        }
    }

    fn keyed_test_verdict(runtime: &TestRuntime, map_key: [u8; OWNER_KEY_LEN]) -> XdpVerdict {
        let state = runtime.state();
        let config = XdpDatapathConfig {
            fence_mode: XdpFenceMode::PerOwnershipKey,
            self_shard: 3,
            routing_domain: 7,
            handoff_ifindex: 42,
        };
        decide_owner_verdict_with_keyed_fence(
            state.owners.get(&(7, map_key)).copied(),
            &config,
            u64::MAX,
            state.key_fences.get(&(7, map_key)).copied(),
        )
    }

    fn established_key() -> SessionOwnershipKey {
        SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([203, 0, 113, 7]), RoutingDomainTag::new(7)),
            IkeSpi::new(0x1111).expect("nonzero"),
            IkeSpi::new(0x2222).expect("nonzero"),
        ))
    }

    fn retirement_grant(
        spi: u32,
        active_fence: u64,
        retirement_fence: u64,
    ) -> OwnershipRetirementGrant {
        let sa = crate::SaId::Esp { spi };
        let request = RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(77).expect("nonzero"),
            previous_fence: OwnershipFence::new(active_fence - 1).expect("nonzero"),
            previous_owner: crate::ClusterNode::new("source"),
            new_owner: crate::ClusterNode::new("target"),
            rule: crate::SteeringRule {
                shard: ShardId::new(7),
                owner: ShardId::new(3),
                key: crate::SteerKey::EspSpi(spi),
            },
            ownership_key: esp_key(spi),
            outbound_sa_binding_id: Some(test_outbound_sa_binding_id(spi)),
            resume: SameSpiResume {
                previous_sa: sa,
                resumed_sa: sa,
                outbound_iv: SameSpiOutboundIvResume::CounterBased {
                    checkpointed_send_iv_next: 10,
                    restored_send_iv_next: 10 + MIN_SEND_IV_FORWARD_JUMP,
                    forward_jump: Some(SendIvForwardJump {
                        forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                            max_peer_sequence_lag: 0,
                        },
                    }),
                },
                anti_replay: AntiReplayResume::ExactWindowRestore {
                    checkpoint_highest_accepted: 9,
                    restored_highest_accepted: 9,
                },
                key_source: ResumeKeySource::LiveMirrored,
            },
        };
        OwnershipRetirementGrant::new(
            OwnershipRetirementRequest::from_committed(
                &request,
                OwnershipFence::new(active_fence).expect("nonzero"),
            ),
            OwnershipFence::new(retirement_fence).expect("nonzero"),
        )
    }

    async fn retire_with_fresh_permit(
        backend: &HostXdpSteeringBackend,
        grant: &OwnershipRetirementGrant,
    ) -> Result<(), IpsecLbError> {
        let mut permits = backend
            .acquire_repin_retirement_permits(vec![grant.request().ownership_key()])
            .await?;
        let permit = permits.pop().ok_or_else(|| {
            IpsecLbError::adapter_contract_violation("test_retirement_permit_missing")
        })?;
        let permit = backend.arm_repin_retirement_permit(permit)?;
        let permit = backend.retire_fenced_repin(grant, permit).await?;
        drop(permit);
        Ok(())
    }

    #[tokio::test]
    async fn retirement_batch_is_bounded_and_deduplicates_colliding_stripes() {
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::default()),
            repin_config(),
        );
        assert!(backend
            .acquire_repin_retirement_permits(Vec::new())
            .await
            .is_err());
        let oversized = (0..=crate::session_repin::MAX_SESSION_REPIN_SAS)
            .map(|offset| esp_key(0x1000 + offset as u32))
            .collect();
        assert!(backend
            .acquire_repin_retirement_permits(oversized)
            .await
            .is_err());

        let first = esp_key(0x2000);
        let first_stripe = backend.repin_stripe_index(&first);
        let second = (0x2001..0x4000)
            .map(esp_key)
            .find(|key| backend.repin_stripe_index(key) == first_stripe)
            .expect("bounded search finds a colliding stripe");
        let permits = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            backend.acquire_repin_retirement_permits(vec![first, second]),
        )
        .await
        .expect("colliding batch must not self-deadlock")
        .expect("colliding batch is valid");
        assert_eq!(permits.len(), 2);

        let blocked_backend = backend.clone();
        let blocked =
            tokio::spawn(async move { blocked_backend.acquire_repin_permit(first).await });
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());
        drop(permits);
        let activation_permit = tokio::time::timeout(std::time::Duration::from_secs(2), blocked)
            .await
            .expect("dropping the complete shared batch releases the stripe")
            .expect("activation task joins")
            .expect("activation permit acquires");
        drop(activation_permit);
    }

    #[tokio::test]
    async fn indeterminate_retirement_poison_fails_readiness_and_same_stripe_admission() {
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::default()),
            repin_config(),
        );
        let key = esp_key(0x2f00);
        let mut permits = backend
            .acquire_repin_retirement_permits(vec![key])
            .await
            .expect("retirement batch acquires");
        let permit = permits.pop().expect("one permit");
        let armed = backend
            .arm_repin_retirement_permit(permit)
            .expect("permit arms");
        drop(armed);

        let probe = backend.probe_repin().await.expect("probe completes");
        assert!(!probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some("Host-XDP re-pin operation state is indeterminate")
        );
        assert!(backend.acquire_repin_permit(key).await.is_err());
    }

    #[tokio::test]
    async fn indeterminate_authority_result_is_not_classified_as_safe_permit_release() {
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::default()),
            repin_config(),
        );
        let request = coordinator_repin_request(0x2f01, esp_key(0x2f01), 401);
        let coordinator = RePinCoordinator::new(
            backend.clone(),
            IndeterminateRetirementAuthority,
            MockOwnershipSource::default(),
            MockRePinAuditSink::new(),
        )
        .with_test_applied_esp_counter_proof();
        let mut permits = coordinator
            .acquire_retirement_permits(std::slice::from_ref(&request))
            .await
            .expect("Host permit batch acquires");
        let permit = permits.pop().expect("one Host permit");

        let error = match coordinator
            .cleanup_committed_for_retirement(
                &request,
                OwnershipFence::new(2).expect("nonzero"),
                permit,
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("ambiguous authority cannot authorize Host cleanup"),
        };
        assert_eq!(error, IpsecLbError::OwnershipRetirementIndeterminate);
        let probe = backend.probe_repin().await.expect("probe completes");
        assert!(!probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some("Host-XDP re-pin operation state is indeterminate")
        );
        assert!(backend
            .acquire_repin_permit(request.ownership_key)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn public_repin_coordinator_reaches_exact_host_key_owner_and_generation() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let fencer = MockOwnershipFencer::new();
        let ownership = MockOwnershipSource::default();
        ownership.set_shard_owner(ShardId::new(3), crate::ClusterNode::new("target"));
        let coordinator = RePinCoordinator::new(
            backend,
            fencer.clone(),
            ownership,
            MockRePinAuditSink::new(),
        )
        .with_test_applied_esp_counter_proof();

        let spi = 0x3001;
        let key = esp_key(spi);
        let request = coordinator_repin_request(spi, key, 301);
        fencer.set_owner(key, request.previous_owner.clone());
        let outcome = coordinator
            .repin(request)
            .await
            .expect("typed coordinator publishes Host owner");
        let map_key = owner_map_key(&key);
        {
            let state = runtime.state();
            assert_eq!(
                state.owners.get(&(7, map_key)),
                Some(&owner_value(3, outcome.fence().get()))
            );
            assert_eq!(
                state.key_fences.get(&(7, map_key)),
                Some(&outcome.fence().get())
            );
        }

        let foreign_domain_key = SessionOwnershipKey::Esp(EspOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([203, 0, 113, 7]), RoutingDomainTag::new(8)),
            EspEncapsulationKind::UdpEncapsulated,
            EspSpi::new(0x3002).expect("allocatable"),
        ));
        assert!(coordinator
            .repin(coordinator_repin_request(0x3002, foreign_domain_key, 302))
            .await
            .is_err());
        assert!(!runtime
            .state()
            .owners
            .contains_key(&(7, owner_map_key(&foreign_domain_key))));

        let stale_generation_key = esp_key(0x3003);
        let stale_map_key = owner_map_key(&stale_generation_key);
        {
            let mut state = runtime.state();
            state.owners.insert((7, stale_map_key), owner_value(4, 99));
            state.key_fences.insert((7, stale_map_key), 99);
        }
        fencer.set_owner(stale_generation_key, crate::ClusterNode::new("source"));
        assert!(coordinator
            .repin(coordinator_repin_request(0x3003, stale_generation_key, 303,))
            .await
            .is_err());
        let state = runtime.state();
        assert_eq!(
            state.owners.get(&(7, stale_map_key)),
            Some(&owner_value(4, 99))
        );
        assert_eq!(state.key_fences.get(&(7, stale_map_key)), Some(&99));
    }

    #[tokio::test]
    async fn fresh_repin_rejects_counter_advance_at_final_guard_before_host_publication() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let fencer = MockOwnershipFencer::new();
        let ownership = MockOwnershipSource::default();
        ownership.set_shard_owner(ShardId::new(3), crate::ClusterNode::new("target"));
        let coordinator = RePinCoordinator::new(
            backend,
            fencer.clone(),
            ownership,
            MockRePinAuditSink::new(),
        )
        .with_test_applied_esp_counter_proof()
        .with_test_counter_advance_before_first_publication();

        let spi = 0x3010;
        let key = esp_key(spi);
        let request = coordinator_repin_request(spi, key, 310);
        fencer.set_owner(key, request.previous_owner.clone());
        let error = coordinator
            .repin(request)
            .await
            .expect_err("counter advance between audit and final guard must reject");
        let partial = error
            .into_partial()
            .expect("ownership committed before the final guard");
        assert_eq!(partial.resume_at(), RePinRetryStage::SteeringInstall);
        assert!(matches!(
            partial.cause(),
            IpsecLbError::AppliedCounterProofRejected {
                code: "esp_counter_receipt_exact_state_changed"
            }
        ));
        let map_key = owner_map_key(&key);
        let state = runtime.state();
        assert!(!state.owners.contains_key(&(7, map_key)));
        assert!(!state.key_fences.contains_key(&(7, map_key)));
    }

    #[tokio::test]
    async fn transient_prepublication_proof_failure_retries_the_fenced_audit_first() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let fencer = MockOwnershipFencer::new();
        let ownership = MockOwnershipSource::default();
        ownership.set_shard_owner(ShardId::new(3), crate::ClusterNode::new("target"));
        let audit = MockRePinAuditSink::new();
        let coordinator = RePinCoordinator::new(backend, fencer.clone(), ownership, audit.clone())
            .with_test_applied_esp_counter_proof()
            .with_test_transient_first_publication_validation_failure();

        let spi = 0x3011;
        let key = esp_key(spi);
        let request = coordinator_repin_request(spi, key, 311);
        fencer.set_owner(key, request.previous_owner.clone());
        let partial = coordinator
            .repin(request)
            .await
            .expect_err("injected proof read fails after ownership commit")
            .into_partial()
            .expect("failure remains retryable");
        assert_eq!(partial.resume_at(), RePinRetryStage::FencedAudit);
        assert_eq!(
            audit
                .events()
                .iter()
                .map(|event| event.kind)
                .collect::<Vec<_>>(),
            vec![crate::RePinAuditEventKind::Attempt]
        );

        coordinator
            .retry(partial)
            .await
            .expect("retry emits fenced audit before publication");
        assert_eq!(
            audit
                .events()
                .iter()
                .map(|event| event.kind)
                .collect::<Vec<_>>(),
            vec![
                crate::RePinAuditEventKind::Attempt,
                crate::RePinAuditEventKind::Fenced,
                crate::RePinAuditEventKind::SteeringInstalled,
            ]
        );
        assert_eq!(
            keyed_test_verdict(&runtime, owner_map_key(&key)),
            XdpVerdict::Local
        );
    }

    #[tokio::test]
    async fn more_than_65536_activation_retirement_cycles_return_host_maps_to_baseline() {
        const CYCLES: u64 = 65_537;

        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x30ff);
        let request = coordinator_repin_request(0x30ff, key, 500);
        let baseline = {
            let state = runtime.state();
            (state.owners.len(), state.key_fences.len())
        };

        for cycle in 0..CYCLES {
            let active_generation = OwnershipFence::new(
                cycle
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(2))
                    .expect("bounded generation"),
            )
            .expect("nonzero active generation");
            let retirement_generation = OwnershipFence::new(
                active_generation
                    .get()
                    .checked_add(1)
                    .expect("bounded retirement generation"),
            )
            .expect("nonzero retirement generation");

            let activation_permit = deterministic_host_test_permit(&backend, key, false);
            let activation_permit = backend
                .apply_fenced_repin_owner_sync(
                    RePinSteeringUpdate::for_test(&request, active_generation),
                    activation_permit,
                )
                .expect("activation reaches Host maps");
            drop(activation_permit);

            let grant = OwnershipRetirementGrant::new(
                OwnershipRetirementRequest::from_committed(&request, active_generation),
                retirement_generation,
            );
            let retirement_permit = deterministic_host_test_permit(&backend, key, true);
            let retirement_permit = backend
                .retire_fenced_repin_owner_sync(grant, retirement_permit)
                .expect("retirement removes exact Host state");
            drop(retirement_permit);
        }

        let state = runtime.state();
        assert_eq!(state.owners.len(), baseline.0);
        assert_eq!(state.key_fences.len(), baseline.1);
        assert!(!state.owners.contains_key(&(7, owner_map_key(&key))));
        assert!(!state.key_fences.contains_key(&(7, owner_map_key(&key))));
        // Host cleanup is intentionally not the durable ABA barrier. The
        // paired session-store finalization test proves the per-key store
        // fence floor survives record deletion and remains authoritative.
    }

    #[tokio::test]
    async fn keyed_retirement_converges_every_acknowledgement_cut() {
        for cut in 0..5 {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let grant = retirement_grant(0x3000 + cut, 10, 11);
            let map_key = owner_map_key(&grant.request().ownership_key());
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner_value(3, 10));
                state.key_fences.insert((7, map_key), 10);
                match cut {
                    0 => state.key_fence_write_error_after_apply = true,
                    1 => state.owner_remove_failures = 1,
                    2 => state.key_fence_remove_failures = 1,
                    3 => state.key_fence_remove_error_after_apply = true,
                    4 => state.key_fence_read_failure_after_remove = true,
                    _ => unreachable!(),
                }
            }

            let first = retire_with_fresh_permit(&backend, &grant).await;
            if matches!(cut, 1 | 2 | 4) {
                assert!(first.is_err());
                retire_with_fresh_permit(&backend, &grant)
                    .await
                    .expect("retry converges a partial retirement");
            } else {
                first.expect("exact readback resolves a lost acknowledgement");
            }
            let state = runtime.state();
            assert!(!state.owners.contains_key(&(7, map_key)));
            assert!(!state.key_fences.contains_key(&(7, map_key)));
        }
    }

    #[tokio::test]
    async fn keyed_retirement_newer_initial_state_has_zero_mutation() {
        for (owner, fence) in [
            (owner_value(4, 12), 12),
            (owner_value(3, 10), 12),
            (owner_value(4, 12), 10),
        ] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let grant = retirement_grant(0x3500, 10, 11);
            let map_key = owner_map_key(&grant.request().ownership_key());
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner);
                state.key_fences.insert((7, map_key), fence);
            }
            assert!(retire_with_fresh_permit(&backend, &grant).await.is_err());
            let state = runtime.state();
            assert_eq!(state.owners.get(&(7, map_key)), Some(&owner));
            assert_eq!(state.key_fences.get(&(7, map_key)), Some(&fence));
            assert_eq!(state.owner_remove_calls, 0);
        }
    }

    #[tokio::test]
    async fn keyed_retirement_partial_read_preserves_any_known_newer_witness() {
        for newer_fence_is_known in [true, false] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let grant = retirement_grant(0x3500, 10, 11);
            let map_key = owner_map_key(&grant.request().ownership_key());
            let owner = if newer_fence_is_known {
                owner_value(3, 10)
            } else {
                owner_value(4, 12)
            };
            let fence = if newer_fence_is_known { 12 } else { 10 };
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner);
                state.key_fences.insert((7, map_key), fence);
                if newer_fence_is_known {
                    state.owner_get_failures = 1;
                } else {
                    state.key_fence_read_failures = 1;
                }
            }

            assert!(matches!(
                retire_with_fresh_permit(&backend, &grant).await,
                Err(IpsecLbError::OwnershipConflict { .. })
            ));
            let state = runtime.state();
            assert_eq!(state.owners.get(&(7, map_key)), Some(&owner));
            assert_eq!(state.key_fences.get(&(7, map_key)), Some(&fence));
            assert_eq!(state.owner_remove_calls, 0);
            assert!(state.live_attached);
            assert!(state.config.is_some());
        }
    }

    #[tokio::test]
    async fn keyed_retirement_same_generation_foreign_live_state_is_staled() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let grant = retirement_grant(0x3500, 10, 11);
        let map_key = owner_map_key(&grant.request().ownership_key());
        {
            let mut state = runtime.state();
            state.owners.insert((7, map_key), owner_value(4, 10));
            state.key_fences.insert((7, map_key), 10);
        }

        assert!(retire_with_fresh_permit(&backend, &grant).await.is_err());
        let state = runtime.state();
        assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(4, 10)));
        assert_eq!(state.key_fences.get(&(7, map_key)), Some(&11));
        drop(state);
        assert_eq!(
            keyed_test_verdict(&runtime, map_key),
            XdpVerdict::SlowPathStale
        );
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
    async fn keyed_repin_is_exact_per_key_and_preserves_unrelated_generations() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        let high = esp_key(0x0100);
        let low = esp_key(0x0101);

        apply_keyed_test_update(&backend, &high, ShardId::new(2), 100)
            .expect("publish high generation");
        apply_keyed_test_update(&backend, &low, ShardId::new(3), 2)
            .expect("publish independent low generation");
        apply_keyed_test_update(&backend, &high, ShardId::new(2), 100)
            .expect("exact retry is idempotent");

        let state = runtime.state();
        let high_map_key = owner_map_key(&high);
        let low_map_key = owner_map_key(&low);
        assert_eq!(state.key_fences.get(&(7, high_map_key)), Some(&100));
        assert_eq!(state.key_fences.get(&(7, low_map_key)), Some(&2));
        assert_eq!(
            state.owners.get(&(7, high_map_key)),
            Some(
                &XdpOwnerValue {
                    owner_shard: 2,
                    generation: 100,
                }
                .encode()
            )
        );
        assert_eq!(
            state.owners.get(&(7, low_map_key)),
            Some(
                &XdpOwnerValue {
                    owner_shard: 3,
                    generation: 2,
                }
                .encode()
            )
        );
    }

    #[tokio::test]
    async fn keyed_repin_recovers_staged_owner_but_preserves_fence_only_conflict() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let staged_key = esp_key(0x0100);
        let fenced_key = esp_key(0x0101);
        let staged_map_key = owner_map_key(&staged_key);
        let fenced_map_key = owner_map_key(&fenced_key);
        {
            let mut state = runtime.state();
            state.owners.insert((7, staged_map_key), owner_value(3, 10));
            state.key_fences.insert((7, fenced_map_key), 10);
        }

        apply_keyed_test_update(&backend, &staged_key, ShardId::new(3), 10)
            .expect("finish fence-last activation from staged owner");
        assert_eq!(
            keyed_test_verdict(&runtime, staged_map_key),
            XdpVerdict::Local
        );

        for _ in 0..2 {
            assert!(matches!(
                apply_keyed_test_update(&backend, &fenced_key, ShardId::new(3), 10),
                Err(IpsecLbError::OwnershipConflict { .. })
            ));
        }
        let state = runtime.state();
        assert!(!state.owners.contains_key(&(7, fenced_map_key)));
        assert_eq!(state.key_fences.get(&(7, fenced_map_key)), Some(&10));
    }

    #[tokio::test]
    async fn keyed_repin_equal_generation_different_owner_fails_closed() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        {
            let mut state = runtime.state();
            state.key_fences.insert((7, map_key), 10);
            state.owners.insert(
                (7, map_key),
                XdpOwnerValue {
                    owner_shard: 2,
                    generation: 10,
                }
                .encode(),
            );
        }

        for _ in 0..2 {
            assert!(matches!(
                apply_keyed_test_update(&backend, &key, ShardId::new(3), 10),
                Err(IpsecLbError::OwnershipConflict { .. })
            ));
        }
        let state = runtime.state();
        assert!(!state.key_fences.contains_key(&(7, map_key)));
        assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 10)));
    }

    #[tokio::test]
    async fn keyed_repin_initial_read_failures_publish_a_proven_stale_cut() {
        for fail_fence_read in [true, false] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let key = esp_key(0x0100);
            let map_key = owner_map_key(&key);
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner_value(2, 9));
                state.key_fences.insert((7, map_key), 9);
                if fail_fence_read {
                    state.key_fence_read_failures = 1;
                } else {
                    state.owner_get_failures = 1;
                }
            }

            assert!(apply_keyed_test_update(&backend, &key, ShardId::new(3), 10).is_err());
            let state = runtime.state();
            assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 9)));
            assert_eq!(state.key_fences.get(&(7, map_key)), Some(&10));
            drop(state);
            assert_eq!(
                keyed_test_verdict(&runtime, map_key),
                XdpVerdict::SlowPathStale
            );
        }
    }

    #[tokio::test]
    async fn keyed_repin_persistent_read_failure_never_overwrites_unknown_authority() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        {
            let mut state = runtime.state();
            state.owners.insert((7, map_key), owner_value(2, 9));
            state.key_fences.insert((7, map_key), 9);
            state.key_fence_read_failures = 2;
            state.detach_error_before_drop = Some("xdp_test_detach");
        }

        let error = apply_keyed_test_update(&backend, &key, ShardId::new(3), 10)
            .expect_err("persistent read failure must quarantine the backend");
        assert!(matches!(
            error,
            IpsecLbError::AdapterContractViolation {
                code: "host_xdp_repin_backend_quarantined"
            }
        ));
        {
            let state = runtime.state();
            assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 9)));
            assert_eq!(state.key_fences.get(&(7, map_key)), Some(&9));
            assert!(state.config.is_none());
            assert!(state.live_attached);
        }
        assert!(matches!(
            backend.probe_repin().await,
            Ok(SteeringProbe {
                mutation_ready: false,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn keyed_containment_preserves_any_known_newer_witness_on_partial_read() {
        for newer_owner_is_known in [true, false] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let map_key = owner_map_key(&esp_key(0x0100));
            let owner = if newer_owner_is_known {
                owner_value(4, 12)
            } else {
                owner_value(2, 9)
            };
            let fence = if newer_owner_is_known { 9 } else { 12 };
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner);
                state.key_fences.insert((7, map_key), fence);
                if newer_owner_is_known {
                    state.key_fence_read_failures = 1;
                } else {
                    state.owner_get_failures = 1;
                }
            }

            let error = backend.contain_indeterminate_keyed_state(
                7,
                map_key,
                10,
                IpsecLbError::adapter_contract_violation("injected_original_error"),
            );
            assert!(matches!(error, IpsecLbError::OwnershipConflict { .. }));
            let state = runtime.state();
            assert_eq!(state.owners.get(&(7, map_key)), Some(&owner));
            assert_eq!(state.key_fences.get(&(7, map_key)), Some(&fence));
            assert!(state.config.is_some());
            assert!(state.live_attached);
            assert!(state.detached.is_empty());
        }
    }

    #[tokio::test]
    async fn keyed_repin_indeterminate_reads_preserve_equal_generation_conflict_witnesses() {
        for fail_fence_read in [true, false] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let key = esp_key(0x0100);
            let map_key = owner_map_key(&key);
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner_value(2, 10));
                state.key_fences.insert((7, map_key), 10);
                if fail_fence_read {
                    state.key_fence_read_failures = 1;
                } else {
                    state.owner_get_failures = 1;
                }
            }

            assert!(apply_keyed_test_update(&backend, &key, ShardId::new(3), 10).is_err());
            for _ in 0..2 {
                assert!(matches!(
                    apply_keyed_test_update(&backend, &key, ShardId::new(3), 10),
                    Err(IpsecLbError::OwnershipConflict { .. })
                ));
            }
            let state = runtime.state();
            assert!(!state.key_fences.contains_key(&(7, map_key)));
            assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 10)));
        }
    }

    #[tokio::test]
    async fn keyed_repin_preserves_newer_staged_owner_without_a_matching_fence() {
        for fence in [None, Some(9)] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let key = esp_key(0x0100);
            let map_key = owner_map_key(&key);
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner_value(4, 11));
                if let Some(fence) = fence {
                    state.key_fences.insert((7, map_key), fence);
                }
            }

            assert!(matches!(
                apply_keyed_test_update(&backend, &key, ShardId::new(3), 10),
                Err(IpsecLbError::OwnershipConflict { .. })
            ));
            let state = runtime.state();
            assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(4, 11)));
            assert_eq!(state.key_fences.get(&(7, map_key)).copied(), fence);
        }
    }

    #[tokio::test]
    async fn keyed_repin_removal_failures_leave_the_key_non_live() {
        for fail_fence_remove in [true, false] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let key = esp_key(0x0100);
            let map_key = owner_map_key(&key);
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner_value(2, 9));
                state.key_fences.insert((7, map_key), 9);
                if fail_fence_remove {
                    state.key_fence_remove_failures = 1;
                } else {
                    state.owner_remove_failures = 1;
                }
            }

            assert!(apply_keyed_test_update(&backend, &key, ShardId::new(3), 10).is_err());
            assert!(matches!(
                keyed_test_verdict(&runtime, map_key),
                XdpVerdict::SlowPathMiss | XdpVerdict::SlowPathStale
            ));
            let state = runtime.state();
            if fail_fence_remove {
                assert_eq!(state.key_fences.get(&(7, map_key)), Some(&9));
                assert!(!state.owners.contains_key(&(7, map_key)));
            } else {
                assert!(!state.key_fences.contains_key(&(7, map_key)));
                assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 9)));
            }
        }
    }

    #[tokio::test]
    async fn keyed_repin_dual_removal_failure_publishes_emergency_stale_cut() {
        for lost_ack in [false, true] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let key = esp_key(0x0100);
            let map_key = owner_map_key(&key);
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner_value(2, 9));
                state.key_fences.insert((7, map_key), 9);
                state.key_fence_remove_failures = 1;
                state.owner_remove_failures = 1;
                state.key_fence_write_error_after_apply = lost_ack;
            }

            assert!(apply_keyed_test_update(&backend, &key, ShardId::new(3), 10).is_err());
            assert_eq!(
                keyed_test_verdict(&runtime, map_key),
                XdpVerdict::SlowPathStale
            );
            {
                let state = runtime.state();
                assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 9)));
                assert_eq!(state.key_fences.get(&(7, map_key)), Some(&10));
                assert!(state.live_attached);
                assert!(state.config.is_some());
            }

            apply_keyed_test_update(&backend, &key, ShardId::new(3), 10)
                .expect("exact retry replaces the older-owner residue");
            assert_eq!(keyed_test_verdict(&runtime, map_key), XdpVerdict::Local);
        }
    }

    #[tokio::test]
    async fn keyed_repin_unprovable_emergency_cut_quiesces_or_reports_fatal_state() {
        for (quiesce_fails, detach_fails, expected_code) in [
            (false, true, "host_xdp_repin_backend_quarantined"),
            (true, false, "host_xdp_repin_backend_quarantined"),
            (true, true, "host_xdp_repin_containment_unproven"),
        ] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let key = esp_key(0x0100);
            let map_key = owner_map_key(&key);
            {
                let mut state = runtime.state();
                state.owners.insert((7, map_key), owner_value(2, 9));
                state.key_fences.insert((7, map_key), 9);
                state.key_fence_remove_failures = 1;
                state.owner_remove_failures = 1;
                state.key_fence_write_failures = 1;
                state.quiesce_failures = usize::from(quiesce_fails);
                state.detach_error_before_drop = detach_fails.then_some("xdp_test_detach");
            }

            let error = apply_keyed_test_update(&backend, &key, ShardId::new(3), 10)
                .expect_err("fault injection must fail closed");
            assert!(matches!(
                error,
                IpsecLbError::AdapterContractViolation { code } if code == expected_code
            ));
            {
                let state = runtime.state();
                if !quiesce_fails {
                    assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 9)));
                    assert_eq!(state.key_fences.get(&(7, map_key)), Some(&9));
                    assert!(state.config.is_none(), "CONFIG absence is the proven cut");
                    assert!(
                        state.live_attached,
                        "injected detach failure preserves the link"
                    );
                } else if !detach_fails {
                    assert!(!state.owners.contains_key(&(7, map_key)));
                    assert!(!state.key_fences.contains_key(&(7, map_key)));
                    assert!(!state.live_attached, "detach is the proven cut");
                } else {
                    assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 9)));
                    assert_eq!(state.key_fences.get(&(7, map_key)), Some(&9));
                    assert!(state.config.is_some());
                    assert!(state.live_attached);
                }
            }
            let probe = backend.probe_repin().await.expect("probe completes");
            assert_eq!(probe.mutation_ready, quiesce_fails && !detach_fails);
            if quiesce_fails && !detach_fails {
                backend
                    .attach()
                    .await
                    .expect("reattach after proven detach");
                apply_keyed_test_update(&backend, &key, ShardId::new(3), 10)
                    .expect("exact retry converges after clean reattach");
                assert_eq!(keyed_test_verdict(&runtime, map_key), XdpVerdict::Local);
            }
        }
    }

    #[tokio::test]
    async fn keyed_repin_proven_detach_with_infeasible_pins_is_not_ready() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        {
            let mut state = runtime.state();
            state.owners.insert((7, map_key), owner_value(2, 9));
            state.key_fences.insert((7, map_key), 9);
            state.key_fence_remove_failures = 1;
            state.owner_remove_failures = 1;
            state.key_fence_write_failures = 1;
            state.quiesce_failures = 1;
            state.detach_error_after_drop = Some("xdp_test_detach_cleanup");
        }

        let error = apply_keyed_test_update(&backend, &key, ShardId::new(3), 10)
            .expect_err("post-detach cleanup ambiguity must fail closed");
        assert!(matches!(
            error,
            IpsecLbError::AdapterContractViolation {
                code: "host_xdp_repin_backend_quarantined"
            }
        ));
        runtime.state().repin_pins_error = Some("xdp_test_infeasible_residue");
        assert!(matches!(
            backend.probe_repin().await,
            Ok(SteeringProbe {
                mutation_ready: false,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn keyed_repin_equal_generation_lost_remove_ack_preserves_owner_witness() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        {
            let mut state = runtime.state();
            state.owners.insert((7, map_key), owner_value(2, 10));
            state.key_fences.insert((7, map_key), 10);
            state.key_fence_remove_error_after_apply = true;
        }

        for _ in 0..2 {
            assert!(matches!(
                apply_keyed_test_update(&backend, &key, ShardId::new(3), 10),
                Err(IpsecLbError::OwnershipConflict { .. })
            ));
        }
        let state = runtime.state();
        assert!(!state.key_fences.contains_key(&(7, map_key)));
        assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 10)));
    }

    #[tokio::test]
    async fn keyed_repin_equal_generation_fence_readback_failure_preserves_owner_witness() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        {
            let mut state = runtime.state();
            state.owners.insert((7, map_key), owner_value(2, 10));
            state.key_fences.insert((7, map_key), 10);
            state.key_fence_read_failure_after_remove = true;
        }

        assert!(apply_keyed_test_update(&backend, &key, ShardId::new(3), 10).is_err());
        assert!(matches!(
            apply_keyed_test_update(&backend, &key, ShardId::new(3), 10),
            Err(IpsecLbError::OwnershipConflict { .. })
        ));
        let state = runtime.state();
        assert!(!state.key_fences.contains_key(&(7, map_key)));
        assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 10)));
    }

    #[tokio::test]
    async fn keyed_repin_final_owner_read_failure_never_leaves_published_pair_live() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        runtime.state().owner_get_failure_on_call = Some(4);

        assert!(apply_keyed_test_update(&backend, &key, ShardId::new(3), 10).is_err());
        assert_eq!(
            keyed_test_verdict(&runtime, map_key),
            XdpVerdict::SlowPathMiss
        );
        let state = runtime.state();
        assert!(!state.owners.contains_key(&(7, map_key)));
        assert!(!state.key_fences.contains_key(&(7, map_key)));
    }

    #[tokio::test]
    async fn keyed_repin_final_fence_read_failure_never_leaves_equal_owner_live() {
        for observed_owner in [None, Some(owner_value(4, 10))] {
            let runtime = Arc::new(TestRuntime::default());
            let backend = HostXdpSteeringBackend::with_runtime_and_config(
                "swu0",
                runtime.clone(),
                repin_config(),
            );
            backend.attach().await.expect("attach");
            let key = esp_key(0x0100);
            let map_key = owner_map_key(&key);
            {
                let mut state = runtime.state();
                state.key_fence_read_failure_on_call = Some(3);
                if let Some(owner) = observed_owner {
                    state.owner_get_override_on_call = Some((4, Some(owner)));
                }
            }

            assert!(apply_keyed_test_update(&backend, &key, ShardId::new(3), 10).is_err());
            assert_eq!(
                keyed_test_verdict(&runtime, map_key),
                XdpVerdict::SlowPathMiss
            );
            let state = runtime.state();
            assert!(!state.owners.contains_key(&(7, map_key)));
            assert!(!state.key_fences.contains_key(&(7, map_key)));
        }
    }

    #[tokio::test]
    async fn keyed_repin_owner_readback_mismatch_and_remove_failure_stays_stale() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        {
            let mut state = runtime.state();
            state.owner_get_override_on_call = Some((3, Some(owner_value(4, 10))));
            state.owner_remove_failure_on_call = Some(2);
        }

        assert!(apply_keyed_test_update(&backend, &key, ShardId::new(3), 10).is_err());
        assert_eq!(
            keyed_test_verdict(&runtime, map_key),
            XdpVerdict::SlowPathStale
        );
        let state = runtime.state();
        assert!(!state.key_fences.contains_key(&(7, map_key)));
        assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(3, 10)));
    }

    #[test]
    fn keyed_repin_crash_cuts_remain_miss_or_stale_until_fence_last() {
        let config = XdpDatapathConfig {
            fence_mode: XdpFenceMode::PerOwnershipKey,
            self_shard: 3,
            routing_domain: 7,
            handoff_ifindex: 42,
        };
        let old = owner_value(2, 9);
        let new = owner_value(3, 10);
        for (owner, fence, expected) in [
            (Some(old), None, XdpVerdict::SlowPathStale),
            (None, None, XdpVerdict::SlowPathMiss),
            (Some(new), None, XdpVerdict::SlowPathStale),
            (Some(new), Some(10), XdpVerdict::Local),
        ] {
            assert_eq!(
                decide_owner_verdict_with_keyed_fence(owner, &config, u64::MAX, fence),
                expected
            );
        }
    }

    #[tokio::test]
    async fn keyed_repin_accepts_exact_apply_with_lost_acknowledgements() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        {
            let mut state = runtime.state();
            state.key_fence_write_error_after_apply = true;
            state.owner_insert_error_after_apply = true;
        }

        apply_keyed_test_update(&backend, &key, ShardId::new(2), 10)
            .expect("exact readback resolves both lost acknowledgements");
        assert_eq!(
            backend.owner_record(&key).await.expect("owner readback"),
            Some((ShardId::new(2), 10))
        );
    }

    #[tokio::test]
    async fn keyed_repin_zero_fence_is_rejected_with_no_live_owner() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        {
            let mut state = runtime.state();
            state.key_fences.insert((7, map_key), 0);
            state.owners.insert(
                (7, map_key),
                XdpOwnerValue {
                    owner_shard: 2,
                    generation: 9,
                }
                .encode(),
            );
        }

        assert!(matches!(
            apply_keyed_test_update(&backend, &key, ShardId::new(3), 10),
            Err(IpsecLbError::AdapterContractViolation { .. })
        ));
        assert!(!runtime.state().owners.contains_key(&(7, map_key)));
    }

    #[tokio::test]
    async fn keyed_repin_zero_fence_preserves_same_generation_owner_conflict() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        backend.attach().await.expect("attach");
        let key = esp_key(0x0100);
        let map_key = owner_map_key(&key);
        {
            let mut state = runtime.state();
            state.key_fences.insert((7, map_key), 0);
            state.owners.insert((7, map_key), owner_value(2, 10));
        }

        for _ in 0..2 {
            assert!(matches!(
                apply_keyed_test_update(&backend, &key, ShardId::new(3), 10),
                Err(IpsecLbError::OwnershipConflict { .. })
            ));
        }
        let state = runtime.state();
        assert!(!state.key_fences.contains_key(&(7, map_key)));
        assert_eq!(state.owners.get(&(7, map_key)), Some(&owner_value(2, 10)));
        drop(state);
        assert_eq!(
            keyed_test_verdict(&runtime, map_key),
            XdpVerdict::SlowPathStale
        );
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

        let _spawn_guard = lock_process_spawn_tests();

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
            root.join("swu0")
                .join(aya_runtime::CONTROL_DIRECTORY)
                .is_dir(),
            "SDK detach must preserve the permanent lifecycle-lock inode"
        );
        drop(parent_backend);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_control_directory_name_is_valid_for_bpffs() {
        let name = aya_runtime::CONTROL_DIRECTORY;
        assert!(!name.is_empty(), "control directory name must not be empty");
        assert!(
            !name.contains('.'),
            "bpffs reserves dots in directory entry names"
        );
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'),
            "control directory name must remain filesystem-safe"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_lease_is_not_inherited_across_exec() {
        let _spawn_guard = lock_process_spawn_tests();
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

    #[tokio::test]
    async fn repin_probe_requires_keyed_mode_and_runtime_specific_migration_proof() {
        let runtime = Arc::new(TestRuntime::default());
        let legacy =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        let probe = legacy.probe_repin().await.expect("legacy probe");
        assert!(!probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some("Host-XDP re-pin requires destination-scoped ownership fencing")
        );

        let keyed = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            repin_config(),
        );
        let probe = keyed.probe_repin().await.expect("keyed probe");
        assert!(probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some("Host-XDP destination-scoped re-pin mutation ready")
        );

        runtime.state().repin_pins_error = Some("xdp_test_repin_pins");
        let probe = keyed.probe_repin().await.expect("failed migration probe");
        assert!(!probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some("Host-XDP re-pin lifecycle or keyed migration is unavailable")
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
